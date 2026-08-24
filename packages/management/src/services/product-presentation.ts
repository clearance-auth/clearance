import {
	createHash,
	randomBytes,
	timingSafeEqual,
} from "node:crypto";
import { isIP } from "node:net";
import type { OperationContext } from "../application/context.js";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";
import {
	PRODUCT_EMAIL_TEMPLATE_KINDS,
	type ProductAuthDomainView,
	type ProductEmailTemplateKind,
	type ProductEmailTemplateView,
	type ProductEmailSenderView,
	type ProductPresentationView,
} from "../store/product-presentation-authority.js";
import type { ManagementStore } from "../store/types.js";
import { getDeliveryReadinessForManagement } from "./delivery-control.js";
import { ClearanceError } from "./errors.js";

const SCHEMA_VERSION = "v1" as const;
const LABEL_MAX = 64;
const SENDER_DISPLAY_NAME_MAX = 128;
const SENDER_ADDRESS_MAX = 320;
const SUBJECT_MAX = 200;
const BODY_MAX = 20_000;
const TEMPLATE_VARIABLES: Readonly<
	Record<ProductEmailTemplateKind, readonly string[]>
> = Object.freeze({
	verification: Object.freeze(["product_name", "user_name", "verification_url"]),
	"password-reset": Object.freeze(["product_name", "reset_url", "user_name"]),
	invitation: Object.freeze([
		"invitation_url",
		"inviter_name",
		"organization_name",
		"product_name",
		"role",
	]),
	"email-change": Object.freeze(["product_name", "email_change_url", "user_name"]),
});

export type ProductPresentationCandidate = Readonly<{
	productLabel: string;
	homeLabel: string;
	accentColor: string;
	logoUrl?: string | null;
}>;

export type ProductPresentationPlan = Readonly<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	expectedVersion: number;
	wouldChange: boolean;
	current: ProductPresentationView;
	candidate: ProductPresentationView;
}>;

export type ProductPresentationApplyResult = Readonly<{
	dryRun: boolean;
	result: ProductPresentationPlan & {
		changed?: boolean;
		previousVersion?: number;
		version?: number;
	};
}>;
export type ProductEmailSenderCandidate = Readonly<{ displayName: string; address: string }>;
export type ProductEmailSenderPlan = Readonly<{ schemaVersion: typeof SCHEMA_VERSION; scope: OperationContext["scope"]; expectedVersion: number; wouldChange: boolean; current: ProductEmailSenderView | null; candidate: ProductEmailSenderView }>;
export type ProductEmailSenderApplyResult = Readonly<{ dryRun: boolean; result: ProductEmailSenderPlan & { changed?: boolean; previousVersion?: number; version?: number } }>;

export type ProductDomainCreateResult =
	| Readonly<{
			schemaVersion: typeof SCHEMA_VERSION;
			scope: OperationContext["scope"];
			domain: ProductAuthDomainView;
			dnsChallenge: { name: string; value: string };
	  }>
	| Readonly<{
			schemaVersion: typeof SCHEMA_VERSION;
			scope: OperationContext["scope"];
			domain: ProductAuthDomainView;
			challengeAlreadyIssued: true;
			oneTimeSecretsOmitted: ["dnsChallenge.value"];
	  }>;

export type ProductDomainControlResult = Readonly<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	operation: "verify" | "activate" | "disable";
	dryRun: boolean;
	wouldChange: boolean;
	domain: ProductAuthDomainView;
}>;

export type ProductDomainReissueResult = Readonly<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	domain: ProductAuthDomainView;
	dnsChallenge: { name: string; value: string };
}> | Readonly<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	domain: ProductAuthDomainView;
	challengeAlreadyIssued: true;
	oneTimeSecretsOmitted: ["dnsChallenge.value"];
}>;

export type ProductTemplateCandidate = Readonly<{
	subject: string;
	plainText: string;
	html: string;
}>;

export type ProductTemplatePlan = Readonly<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	expectedVersion: number;
	wouldChange: boolean;
	current: ProductEmailTemplateView;
	candidate: ProductEmailTemplateView;
}>;

export type ProductTemplateApplyResult = Readonly<{
	dryRun: boolean;
	result: ProductTemplatePlan & {
		changed?: boolean;
		previousVersion?: number;
		version?: number;
	};
}>;

export interface ProductDomainResolver {
	resolveTxt(name: string): Promise<readonly (readonly string[])[]>;
	resolveCname(name: string): Promise<readonly string[]>;
}
export interface ProductEmailDomainResolver { resolveTxt(name: string): Promise<readonly (readonly string[])[]>; resolveCname(name: string): Promise<readonly string[]>; resolveMx(name: string): Promise<readonly { exchange: string; priority: number }[]>; }
type SenderDnsKind = "txt" | "cname" | "mx";
type SenderDnsRecord = Readonly<{ name: string; value: string }>;
/** Bounded parser for server-owned email-domain requirements; it never accepts request input. */
export function parseServerOwnedEmailDomainRecords(raw: string | undefined = process.env.CLEARANCE_EMAIL_DOMAIN_RECORDS_JSON): Record<SenderDnsKind, readonly SenderDnsRecord[]> {
	const empty = { txt: [], cname: [], mx: [] } as Record<SenderDnsKind, readonly SenderDnsRecord[]>;
	if (!raw || raw.trim() === "") return empty;
	let decoded: unknown; try { decoded = JSON.parse(raw); } catch { throw productError("PRODUCT_SENDER_DNS_CONFIGURATION_INVALID", "Email-domain DNS configuration is invalid.", "product_sender.dns", 503); }
	if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw productError("PRODUCT_SENDER_DNS_CONFIGURATION_INVALID", "Email-domain DNS configuration is invalid.", "product_sender.dns", 503);
	const config = decoded as Record<string, unknown>; const output = {} as Record<SenderDnsKind, readonly SenderDnsRecord[]>;
	for (const kind of ["txt", "cname", "mx"] as const) { const records = config[kind] ?? []; if (!Array.isArray(records) || records.length > 16) throw productError("PRODUCT_SENDER_DNS_CONFIGURATION_INVALID", "Email-domain DNS configuration exceeds its record limit.", "product_sender.dns", 503); output[kind] = records.map((entry) => { if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw productError("PRODUCT_SENDER_DNS_CONFIGURATION_INVALID", "Email-domain DNS configuration contains an invalid record.", "product_sender.dns", 503); const record = entry as Record<string, unknown>; if (typeof record.name !== "string" || typeof record.value !== "string" || record.name.length < 1 || record.name.length > 253 || record.value.length < 1 || record.value.length > 1024 || /[\u0000-\u001f\u007f]/.test(record.name) || /[\u0000\u007f]/.test(record.value)) throw productError("PRODUCT_SENDER_DNS_CONFIGURATION_INVALID", "Email-domain DNS configuration contains an invalid record.", "product_sender.dns", 503); return { name: record.name, value: record.value }; }); }
	return output;
}
/** Resolver injection keeps network access server-owned; response exposes statuses only. */
export async function getProductSenderDnsReadinessForManagement(store: ManagementStore, context: OperationContext, resolver: ProductEmailDomainResolver, raw: string | undefined = process.env.CLEARANCE_EMAIL_DOMAIN_RECORDS_JSON): Promise<{ schemaVersion: typeof SCHEMA_VERSION; scope: OperationContext["scope"]; ready: boolean; records: Record<SenderDnsKind, "not_checked" | "not_configured" | "ready" | "not_ready" | "unavailable"> }> {
	const authority = requireAuthority(store, "product_sender.dns"); const sender = await authority.getSender(context.scope); const unchecked = { txt: "not_checked", cname: "not_checked", mx: "not_checked" } as const; if (!sender) return { schemaVersion: SCHEMA_VERSION, scope: context.scope, ready: false, records: unchecked };
	if (!(await authority.listDomains(context.scope)).some((domain) => domain.hostname === sender.domain && (domain.state === "verified" || domain.state === "active"))) return { schemaVersion: SCHEMA_VERSION, scope: context.scope, ready: false, records: unchecked };
	let required: Record<SenderDnsKind, readonly SenderDnsRecord[]>; try { required = parseServerOwnedEmailDomainRecords(raw); } catch { return { schemaVersion: SCHEMA_VERSION, scope: context.scope, ready: false, records: { txt: "unavailable", cname: "unavailable", mx: "unavailable" } }; }
	const records = {} as Record<SenderDnsKind, "not_configured" | "ready" | "not_ready" | "unavailable">; for (const kind of ["txt", "cname", "mx"] as const) { if (!required[kind].length) { records[kind] = "not_configured"; continue; } try { let ready = true; for (const record of required[kind]) { const name = (record.name === "@" ? sender.domain : record.name.replaceAll("{domain}", sender.domain).replace(/\.$/, "")).toLowerCase(); if (!name.endsWith(sender.domain) || !/^[_a-z0-9.-]+$/.test(name)) throw new Error("unsafe"); const answers = kind === "txt" ? (await resolver.resolveTxt(name)).map((parts) => parts.join("")) : kind === "cname" ? (await resolver.resolveCname(name)).map((value) => value.toLowerCase().replace(/\.$/, "")) : (await resolver.resolveMx(name)).map((value) => value.exchange.toLowerCase().replace(/\.$/, "")); if (answers.length > 64 || !answers.includes(kind === "txt" ? record.value : record.value.toLowerCase().replace(/\.$/, ""))) ready = false; } records[kind] = ready ? "ready" : "not_ready"; } catch { records[kind] = "unavailable"; } }
	return { schemaVersion: SCHEMA_VERSION, scope: context.scope, ready: records.txt === "ready" && records.cname === "ready" && records.mx === "ready", records };
}

function productError(
	code: string,
	message: string,
	stage: string,
	status: number,
	remediation?: string,
): ClearanceError {
	return new ClearanceError({ code, message, stage, status, remediation });
}

function requireAuthority(store: ManagementStore, stage: string) {
	if (
		store.backend !== "postgres" ||
		!store.productPresentation ||
		typeof store.mutateCoordinated !== "function"
	) {
		throw productError(
			"PRODUCT_PRESENTATION_AUTHORITY_UNAVAILABLE",
			"Product presentation requires the normalized PostgreSQL authority.",
			stage,
			503,
			"Configure PostgreSQL and apply the store-v2 schema before retrying.",
		);
	}
	return store.productPresentation;
}

function transactionAuthority(
	context: {
		productPresentation?: import("../store/product-presentation-authority.js").ProductPresentationRepository;
	},
	stage: string,
) {
	if (!context.productPresentation) {
		throw productError(
			"PRODUCT_PRESENTATION_AUTHORITY_UNAVAILABLE",
			"Product presentation requires the normalized PostgreSQL authority.",
			stage,
			503,
			"Apply the store-v2 schema and retry.",
		);
	}
	return context.productPresentation;
}

function domainConflict(stage: string): ClearanceError {
	return productError(
		"PRODUCT_DOMAIN_CONFLICT",
		"Custom authentication domain changed concurrently.",
		stage,
		409,
		"Refresh the domain list and retry.",
	);
}

function translate(error: unknown, stage: string): never {
	if (error instanceof ClearanceError) throw error;
	const code =
		typeof error === "object" &&
		error !== null &&
		"code" in error &&
		typeof error.code === "string"
			? error.code
			: "";
	if (code === "23505") {
		throw productError(
			"PRODUCT_PRESENTATION_CONFLICT",
			"Product presentation state conflicts with another active resource.",
			stage,
			409,
			"Refresh the current state, then retry the exact scoped operation.",
		);
	}
	if (code === "42P01") {
		throw productError(
			"PRODUCT_PRESENTATION_SCHEMA_UNAVAILABLE",
			"Product presentation schema is unavailable.",
			stage,
			503,
			"Apply the store-v2 schema, then retry.",
		);
	}
	throw productError(
		"PRODUCT_PRESENTATION_OPERATION_FAILED",
		"Product presentation operation failed.",
		stage,
		500,
		"Inspect PostgreSQL authority health and retry.",
	);
}

function boundedLabel(value: unknown, field: string): string {
	if (
		typeof value !== "string" ||
		value.trim() !== value ||
		value.length < 1 ||
		value.length > LABEL_MAX ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		throw productError(
			"PRODUCT_PRESENTATION_INPUT_INVALID",
			`${field} must be a trimmed label between 1 and ${LABEL_MAX} characters.`,
			"product_presentation.validate",
			400,
		);
	}
	return value;
}

function presentationCandidate(
	input: ProductPresentationCandidate,
): Omit<ProductPresentationView, "version" | "updatedAt"> {
	if (typeof input !== "object" || input === null) {
		throw productError(
			"PRODUCT_PRESENTATION_INPUT_INVALID",
			"A complete presentation candidate is required.",
			"product_presentation.validate",
			400,
		);
	}
	if (typeof input.accentColor !== "string" || !/^#[0-9a-fA-F]{6}$/.test(input.accentColor)) {
		throw productError(
			"PRODUCT_PRESENTATION_INPUT_INVALID",
			"accentColor must be one six-digit hexadecimal color.",
			"product_presentation.validate",
			400,
		);
	}
	return {
		productLabel: boundedLabel(input.productLabel, "productLabel"),
		homeLabel: boundedLabel(input.homeLabel, "homeLabel"),
		accentColor: input.accentColor.toLowerCase(),
		logoUrl: logoUrl(input.logoUrl),
	};
}

function logoUrl(value: unknown): string | null {
	if (value === undefined || value === null) return null;
	if (typeof value !== "string" || value.length < 1 || value.length > 2_048 || /[\u0000-\u001f\u007f]/.test(value)) throw productError("PRODUCT_PRESENTATION_INPUT_INVALID", "logoUrl must be a bounded credential-free HTTPS URL.", "product_presentation.validate", 400);
	let parsed: URL; try { parsed = new URL(value); } catch { throw productError("PRODUCT_PRESENTATION_INPUT_INVALID", "logoUrl must be a valid HTTPS URL.", "product_presentation.validate", 400); }
	if (parsed.protocol !== "https:" || parsed.username ||
		parsed.password ||
		parsed.hash
	) {
		throw productError(
			"PRODUCT_PRESENTATION_INPUT_INVALID",
			"logoUrl must be a credential-free HTTPS URL without a fragment.",
			"product_presentation.validate",
			400,
		);
	}
	return parsed.toString();
}

function samePresentation(
	left: ProductPresentationView,
	right: ProductPresentationCandidate,
): boolean {
	return (
		left.productLabel === right.productLabel &&
		left.homeLabel === right.homeLabel &&
		left.accentColor === right.accentColor
		&& left.logoUrl === (right.logoUrl ?? null)
	);
}

function planPresentation(
	scope: OperationContext["scope"],
	current: ProductPresentationView,
	input: ProductPresentationCandidate,
): ProductPresentationPlan {
	const candidate = presentationCandidate(input);
	return {
		schemaVersion: SCHEMA_VERSION,
		scope,
		expectedVersion: current.version,
		wouldChange: !samePresentation(current, candidate),
		current,
		candidate: {
			...candidate,
			version: current.version + (samePresentation(current, candidate) ? 0 : 1),
			updatedAt: null,
		},
	};
}

export async function getProductPresentationForManagement(
	store: ManagementStore,
	context: OperationContext,
): Promise<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	presentation: ProductPresentationView;
}> {
	const stage = "product_presentation.get";
	try {
		return {
			schemaVersion: SCHEMA_VERSION,
			scope: context.scope,
			presentation: await requireAuthority(store, stage).getPresentation(context.scope),
		};
	} catch (error) {
		return translate(error, stage);
	}
}

export async function planProductPresentationForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: ProductPresentationCandidate,
): Promise<ProductPresentationPlan> {
	const stage = "product_presentation.plan";
	try {
		const current = await requireAuthority(store, stage).getPresentation(context.scope);
		return planPresentation(context.scope, current, input);
	} catch (error) {
		return translate(error, stage);
	}
}

export async function applyProductPresentationForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: ProductPresentationCandidate & {
		expectedVersion: number;
		dryRun?: boolean;
		confirm?: boolean;
	},
): Promise<ProductPresentationApplyResult> {
	const stage = "product_presentation.apply";
	try {
		const preview = await planProductPresentationForManagement(store, context, input);
		if (input.dryRun === true || input.confirm !== true) {
			return { dryRun: true, result: preview };
		}
		if (input.expectedVersion !== preview.current.version) {
			throw productError(
				"PRODUCT_PRESENTATION_VERSION_CONFLICT",
				"Product presentation version changed.",
				stage,
				409,
				"Create a fresh plan and retry with its expectedVersion.",
			);
		}
		if (!preview.wouldChange) {
			return {
				dryRun: false,
				result: {
					...preview,
					changed: false,
					previousVersion: preview.current.version,
					version: preview.current.version,
				},
			};
		}
		const result = await mutateCoordinatedWithRuntimeSql(store, async (coordinated) => {
			const authority = transactionAuthority(coordinated, stage);
			const current = await authority.getPresentation(context.scope);
			if (current.version !== input.expectedVersion) {
				throw productError(
					"PRODUCT_PRESENTATION_VERSION_CONFLICT",
					"Product presentation version changed.",
					stage,
					409,
					"Create a fresh plan and retry with its expectedVersion.",
				);
			}
			const nextPlan = planPresentation(context.scope, current, input);
			if (!nextPlan.wouldChange) return nextPlan;
			const applied = await authority.replacePresentation(context.scope, {
			...presentationCandidate(input),
				expectedVersion: input.expectedVersion,
			});
			if (!applied) {
				throw productError(
					"PRODUCT_PRESENTATION_VERSION_CONFLICT",
					"Product presentation version changed.",
					stage,
					409,
				);
			}
			coordinated.appendAudit({
				actor: context.actor,
				action: stage,
				subjectType: "product_presentation",
				subjectId: `${context.scope.projectId}:${context.scope.environmentId}`,
				outcome: "success",
				source: context.source,
				projectId: context.scope.projectId,
				environmentId: context.scope.environmentId,
				correlationId: context.correlationId,
				message: `Applied product presentation version ${applied.version}`,
				metadata: {
					previousVersion: current.version,
					version: applied.version,
					changedFields: [
						...(current.productLabel === applied.productLabel ? [] : ["productLabel"]),
						...(current.homeLabel === applied.homeLabel ? [] : ["homeLabel"]),
						...(current.accentColor === applied.accentColor ? [] : ["accentColor"]),
						...(current.logoUrl === applied.logoUrl ? [] : ["logoUrl"]),
					],
				},
			});
			return {
				...nextPlan,
				candidate: applied,
				changed: true,
				previousVersion: current.version,
				version: applied.version,
			};
		});
		return { dryRun: false, result };
	} catch (error) {
		return translate(error, stage);
	}
}

function senderCandidate(input: ProductEmailSenderCandidate): Omit<ProductEmailSenderView, "version" | "updatedAt"> {
	if (!input || typeof input !== "object" || typeof input.displayName !== "string" || input.displayName.trim() !== input.displayName || input.displayName.length < 1 || input.displayName.length > SENDER_DISPLAY_NAME_MAX || /[\u0000-\u001f\u007f]/.test(input.displayName)) throw productError("PRODUCT_SENDER_INPUT_INVALID", `displayName must be a trimmed label between 1 and ${SENDER_DISPLAY_NAME_MAX} characters.`, "product_sender.validate", 400);
	const value = input.address;
	if (typeof value !== "string" || value.trim() !== value || value.length < 3 || value.length > SENDER_ADDRESS_MAX || /[\u0000-\u001f\u007f\s]/.test(value)) throw productError("PRODUCT_SENDER_INPUT_INVALID", "address must be one bounded, whitespace-free email address.", "product_sender.validate", 400);
	const at = value.lastIndexOf("@");
	if (at < 1 || at !== value.indexOf("@")) throw productError("PRODUCT_SENDER_INPUT_INVALID", "address must contain one local part and one domain.", "product_sender.validate", 400);
	const local = value.slice(0, at); const domain = value.slice(at + 1).toLowerCase();
	if (local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..") || !/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local) || domain.length < 3 || domain.length > 253 || domain.endsWith(".") || isIP(domain) !== 0 || !domain.includes(".") || !/^[a-z0-9.-]+$/.test(domain) || domain.split(".").some((label) => label.length < 1 || label.length > 63 || label.startsWith("-") || label.endsWith("-"))) throw productError("PRODUCT_SENDER_INPUT_INVALID", "address must use one canonical public DNS domain.", "product_sender.validate", 400);
	return { displayName: input.displayName, address: `${local}@${domain}`, domain };
}
function planSender(scope: OperationContext["scope"], current: ProductEmailSenderView | null, input: ProductEmailSenderCandidate): ProductEmailSenderPlan { const candidate = senderCandidate(input); const wouldChange = current?.displayName !== candidate.displayName || current.address !== candidate.address || current.domain !== candidate.domain; return { schemaVersion: SCHEMA_VERSION, scope, expectedVersion: current?.version ?? 0, wouldChange, current, candidate: wouldChange ? { ...candidate, version: (current?.version ?? 0) + 1, updatedAt: null } : { ...current! } }; }
function ownedSenderDomain(domains: readonly ProductAuthDomainView[], domain: string, stage: string): void { if (!domains.some((item) => item.hostname === domain && (item.state === "verified" || item.state === "active"))) throw productError("PRODUCT_SENDER_DOMAIN_UNVERIFIED", "Email sender domain must match a verified or active authentication domain in this scope.", stage, 409); }
export async function getProductSenderForManagement(store: ManagementStore, context: OperationContext): Promise<{ schemaVersion: typeof SCHEMA_VERSION; scope: OperationContext["scope"]; sender: ProductEmailSenderView | null }> { const stage = "product_sender.get"; try { return { schemaVersion: SCHEMA_VERSION, scope: context.scope, sender: await requireAuthority(store, stage).getSender(context.scope) }; } catch (error) { return translate(error, stage); } }
export async function planProductSenderForManagement(store: ManagementStore, context: OperationContext, input: ProductEmailSenderCandidate): Promise<ProductEmailSenderPlan> { const stage = "product_sender.plan"; try { const authority = requireAuthority(store, stage); const candidate = senderCandidate(input); const [current, domains] = await Promise.all([authority.getSender(context.scope), authority.listDomains(context.scope)]); ownedSenderDomain(domains, candidate.domain, stage); return planSender(context.scope, current, input); } catch (error) { return translate(error, stage); } }
export async function applyProductSenderForManagement(store: ManagementStore, context: OperationContext, input: ProductEmailSenderCandidate & { expectedVersion: number; dryRun?: boolean; confirm?: boolean }): Promise<ProductEmailSenderApplyResult> { const stage = "product_sender.apply"; try { const preview = await planProductSenderForManagement(store, context, input); if (input.dryRun === true || input.confirm !== true) return { dryRun: true, result: preview }; if (input.expectedVersion !== preview.expectedVersion) throw productError("PRODUCT_SENDER_VERSION_CONFLICT", "Email sender version changed.", stage, 409); if (!preview.wouldChange) return { dryRun: false, result: { ...preview, changed: false, previousVersion: preview.expectedVersion, version: preview.expectedVersion } }; const result = await mutateCoordinatedWithRuntimeSql(store, async (coordinated) => { const authority = transactionAuthority(coordinated, stage); const current = await authority.getSender(context.scope); if ((current?.version ?? 0) !== input.expectedVersion) throw productError("PRODUCT_SENDER_VERSION_CONFLICT", "Email sender version changed.", stage, 409); const candidate = senderCandidate(input); const domain = await authority.getDomainForUpdate(context.scope, `https://${candidate.domain}`); if (!domain || (domain.state !== "verified" && domain.state !== "active")) throw productError("PRODUCT_SENDER_DOMAIN_UNVERIFIED", "Email sender domain must remain verified or active.", stage, 409); const applied = await authority.replaceSender(context.scope, { ...candidate, expectedVersion: input.expectedVersion }); if (!applied) throw productError("PRODUCT_SENDER_VERSION_CONFLICT", "Email sender version changed.", stage, 409); coordinated.appendAudit({ actor: context.actor, action: stage, subjectType: "email_sender", subjectId: `${context.scope.projectId}:${context.scope.environmentId}`, outcome: "success", source: context.source, projectId: context.scope.projectId, environmentId: context.scope.environmentId, correlationId: context.correlationId, message: `Applied email sender version ${applied.version}`, metadata: { domain: applied.domain, previousVersion: current?.version ?? 0, version: applied.version } }); return { ...preview, candidate: applied, changed: true, previousVersion: current?.version ?? 0, version: applied.version }; }); return { dryRun: false, result }; } catch (error) { return translate(error, stage); } }

function canonicalOrigin(value: unknown): { origin: string; hostname: string; dnsName: string } {
	if (typeof value !== "string" || value.trim() !== value || value.length > 253) {
		throw productError(
			"PRODUCT_DOMAIN_INVALID",
			"origin must be one canonical HTTPS hostname.",
			"product_domains.validate",
			400,
		);
	}
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		throw productError(
			"PRODUCT_DOMAIN_INVALID",
			"origin must be one canonical HTTPS hostname.",
			"product_domains.validate",
			400,
		);
	}
	const hostname = url.hostname.toLowerCase();
	const origin = `https://${hostname}`;
	if (
		url.protocol !== "https:" ||
		url.username ||
		url.password ||
		url.port ||
		url.pathname !== "/" ||
		url.search ||
		url.hash ||
		hostname.endsWith(".") ||
		hostname === "localhost" ||
		isIP(hostname) !== 0 ||
		!hostname.includes(".") ||
		hostname.length > 253 ||
		!/^[a-z0-9.-]+$/.test(hostname) ||
		["com", "net", "org", "edu", "gov", "io", "dev", "app", "co.uk", "org.uk", "com.au", "co.jp"].includes(hostname) ||
		hostname.split(".").some((label) =>
			label.length < 1 ||
			label.length > 63 ||
			label.startsWith("-") ||
			label.endsWith("-"),
		)
	) {
		throw productError(
			"PRODUCT_DOMAIN_INVALID",
			"origin must be a lowercase canonical HTTPS hostname without a port or path.",
			"product_domains.validate",
			400,
		);
	}
	return { origin, hostname, dnsName: `_clearance.${hostname}` };
}

function customDomainTarget(): string {
	const raw = process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET?.trim();
	if (!raw) throw productError("PRODUCT_DOMAIN_TARGET_UNAVAILABLE", "Custom-domain routing target is not configured.", "product_domains.verify", 503, "Set CLEARANCE_CUSTOM_DOMAIN_TARGET to the server-owned CNAME target.");
	const parsed = canonicalOrigin(`https://${raw}`);
	return parsed.hostname;
}

function challengeDigest(value: string): Buffer {
	return createHash("sha256").update(value, "utf8").digest();
}

function domainsNotFound(stage: string): ClearanceError {
	return productError(
		"PRODUCT_DOMAIN_NOT_FOUND",
		"Custom authentication domain not found.",
		stage,
		404,
		"List the active scope's domains and use one exact origin.",
	);
}

export async function listProductDomainsForManagement(
	store: ManagementStore,
	context: OperationContext,
): Promise<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	domains: ProductAuthDomainView[];
}> {
	const stage = "product_domains.list";
	try {
		return {
			schemaVersion: SCHEMA_VERSION,
			scope: context.scope,
			domains: await requireAuthority(store, stage).listDomains(context.scope),
		};
	} catch (error) {
		return translate(error, stage);
	}
}

export async function createProductDomainForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { origin: string },
): Promise<ProductDomainCreateResult> {
	const stage = "product_domains.create";
	try {
		requireAuthority(store, stage);
		const parsed = canonicalOrigin(input.origin);
		const token = randomBytes(32).toString("base64url");
		const dnsValue = `clearance-domain-verification=${token}`;
		return await mutateCoordinatedWithRuntimeSql(store, async (coordinated) => {
			const authority = transactionAuthority(coordinated, stage);
			const created = await authority.createDomain(context.scope, {
				...parsed,
				challengeDigest: challengeDigest(dnsValue),
			});
			if (!created) {
				const existing = (await authority.listDomains(context.scope)).find(
					(domain) => domain.origin === parsed.origin,
				);
			if (!existing) throw domainConflict(stage);
			if (existing.state === "disabled") {
				throw productError(
					"PRODUCT_DOMAIN_REISSUE_REQUIRED",
					"Disabled custom authentication domains must be reissued explicitly.",
					stage,
					409,
					"Use product domains reissue with the disabled domain's expectedVersion.",
				);
			}
			return {
					schemaVersion: SCHEMA_VERSION,
					scope: context.scope,
					domain: existing,
					challengeAlreadyIssued: true,
					oneTimeSecretsOmitted: ["dnsChallenge.value"],
				} as const;
			}
			coordinated.appendAudit({
				actor: context.actor,
				action: stage,
				subjectType: "auth_domain",
				subjectId: created.origin,
				outcome: "pending",
				source: context.source,
				projectId: context.scope.projectId,
				environmentId: context.scope.environmentId,
				correlationId: context.correlationId,
				message: "Created custom authentication domain challenge",
				metadata: {
					hostname: created.hostname,
					state: created.state,
					version: created.version,
				},
			});
			return {
				schemaVersion: SCHEMA_VERSION,
				scope: context.scope,
				domain: created,
				dnsChallenge: { name: created.dnsName, value: dnsValue },
			};
		});
	} catch (error) {
		return translate(error, stage);
	}
}

export async function reissueProductDomainForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { origin: string; expectedVersion: number },
): Promise<ProductDomainReissueResult> {
	const stage = "product_domains.reissue";
	try {
		const parsed = canonicalOrigin(input.origin);
		const visible = (await requireAuthority(store, stage).listDomains(context.scope))
			.find((domain) => domain.origin === parsed.origin);
		if (!visible) throw domainsNotFound(stage);
		if (visible.version !== input.expectedVersion) throw domainConflict(stage);
		if (visible.state !== "disabled") {
			throw productError(
				"PRODUCT_DOMAIN_REISSUE_INVALID_STATE",
				"Only disabled custom authentication domains can be reissued.",
				stage,
				409,
				"Disable the domain before reissuing its one-time DNS challenge.",
			);
		}
		const token = randomBytes(32).toString("base64url");
		const dnsValue = `clearance-domain-verification=${token}`;
		return await mutateCoordinatedWithRuntimeSql(store, async (coordinated) => {
			const authority = transactionAuthority(coordinated, stage);
			const current = await authority.getDomainForUpdate(context.scope, parsed.origin);
			if (!current) throw domainsNotFound(stage);
			if (current.version !== input.expectedVersion) throw domainConflict(stage);
			if (current.state !== "disabled") {
				throw productError(
					"PRODUCT_DOMAIN_REISSUE_INVALID_STATE",
					"Only disabled custom authentication domains can be reissued.",
					stage,
					409,
					"Refresh the domain list before retrying.",
				);
			}
			const reissued = await authority.reissueDisabledDomain(
				context.scope,
				parsed.origin,
				input.expectedVersion,
				challengeDigest(dnsValue),
			);
			if (!reissued) throw domainConflict(stage);
			coordinated.appendAudit({
				actor: context.actor,
				action: stage,
				subjectType: "auth_domain",
				subjectId: reissued.origin,
				outcome: "pending",
				source: context.source,
				projectId: context.scope.projectId,
				environmentId: context.scope.environmentId,
				correlationId: context.correlationId,
				message: "Reissued custom authentication domain challenge",
				metadata: { hostname: reissued.hostname, previousVersion: current.version, version: reissued.version },
			});
			return { schemaVersion: SCHEMA_VERSION, scope: context.scope, domain: reissued, dnsChallenge: { name: reissued.dnsName, value: dnsValue } };
		});
	} catch (error) {
		return translate(error, stage);
	}
}

export async function verifyProductDomainForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { origin: string },
	resolver: ProductDomainResolver,
): Promise<ProductDomainControlResult> {
	const stage = "product_domains.verify";
	try {
		const parsed = canonicalOrigin(input.origin);
		const listed = await requireAuthority(store, stage).listDomains(context.scope);
		const visible = listed.find((domain) => domain.origin === parsed.origin);
		if (!visible) throw domainsNotFound(stage);
		if (visible.state === "verified" || visible.state === "active") {
			return {
				schemaVersion: SCHEMA_VERSION,
				scope: context.scope,
				operation: "verify",
				dryRun: false,
				wouldChange: false,
				domain: visible,
			};
		}
		if (visible.state !== "pending") {
			throw productError(
				"PRODUCT_DOMAIN_STATE_INVALID",
				"Disabled domains cannot be verified.",
				stage,
				409,
				"Create a new domain challenge.",
			);
		}
		let records: readonly (readonly string[])[];
		let cname: readonly string[];
		try {
			records = await resolver.resolveTxt(visible.dnsName);
			cname = await resolver.resolveCname(visible.hostname);
		} catch {
			throw productError(
				"PRODUCT_DOMAIN_DNS_NOT_READY",
				"DNS verification evidence is not available.",
				stage,
				409,
				"Publish the one-time TXT challenge, wait for DNS propagation, then retry.",
			);
		}
		if (records.length > 32 || cname.length > 16) throw productError("PRODUCT_DOMAIN_DNS_NOT_READY", "DNS verification returned too many answers.", stage, 409, "Publish only the exact expected TXT and CNAME records.");
		const expectedTarget = customDomainTarget();
		const hasRouting = cname.some((answer) => answer.toLowerCase().replace(/\.$/, "") === expectedTarget);
		const observedDigests = records
			.map((parts) => parts.join(""))
			.map(challengeDigest);
		return await mutateCoordinatedWithRuntimeSql(store, async (coordinated) => {
			const authority = transactionAuthority(coordinated, stage);
			const current = await authority.getDomainForUpdate(context.scope, parsed.origin);
			if (!current) throw domainsNotFound(stage);
			if (current.state === "verified" || current.state === "active") {
				return {
					schemaVersion: SCHEMA_VERSION,
					scope: context.scope,
					operation: "verify",
					dryRun: false,
					wouldChange: false,
					domain: current,
				} as const;
			}
			if (
				current.state !== "pending" || !hasRouting ||
				!observedDigests.some(
					(digest) =>
						digest.length === current.challengeDigest.length &&
						timingSafeEqual(digest, current.challengeDigest),
				)
			) {
				throw productError(
					"PRODUCT_DOMAIN_DNS_NOT_READY",
					"DNS verification evidence does not match the issued challenge.",
					stage,
					409,
					"Publish the exact one-time TXT challenge and retry after propagation.",
				);
			}
			const verified = await authority.setDomainState(
				context.scope,
				parsed.origin,
				current.version,
				"verified",
			);
			if (!verified) throw domainConflict(stage);
			coordinated.appendAudit({
				actor: context.actor,
				action: stage,
				subjectType: "auth_domain",
				subjectId: verified.origin,
				outcome: "success",
				source: context.source,
				projectId: context.scope.projectId,
				environmentId: context.scope.environmentId,
				correlationId: context.correlationId,
				message: "Verified custom authentication domain",
				metadata: {
					hostname: verified.hostname,
					state: verified.state,
					version: verified.version,
				},
			});
			return {
				schemaVersion: SCHEMA_VERSION,
				scope: context.scope,
				operation: "verify",
				dryRun: false,
				wouldChange: true,
				domain: verified,
			} as const;
		});
	} catch (error) {
		return translate(error, stage);
	}
}

async function controlProductDomainForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { origin: string; expectedVersion: number; dryRun?: boolean; confirm?: boolean },
	operation: "activate" | "disable",
): Promise<ProductDomainControlResult> {
	const stage = `product_domains.${operation}`;
	try {
		const parsed = canonicalOrigin(input.origin);
		const domain = (
			await requireAuthority(store, stage).listDomains(context.scope)
		).find((candidate) => candidate.origin === parsed.origin);
		if (!domain) throw domainsNotFound(stage);
		if (domain.version !== input.expectedVersion) throw domainConflict(stage);
		const targetState = operation === "activate" ? "active" : "disabled";
		const wouldChange = domain.state !== targetState;
		if (operation === "activate" && domain.state !== "verified" && domain.state !== "active") {
			throw productError(
				"PRODUCT_DOMAIN_NOT_VERIFIED",
				"Custom authentication domain must be verified before activation.",
				stage,
				409,
				"Publish and verify the TXT challenge, then activate with explicit confirmation.",
			);
		}
		if (input.dryRun === true || input.confirm !== true || !wouldChange) {
			return {
				schemaVersion: SCHEMA_VERSION,
				scope: context.scope,
				operation,
				dryRun: input.dryRun === true || input.confirm !== true,
				wouldChange,
				domain,
			};
		}
		return await mutateCoordinatedWithRuntimeSql(store, async (coordinated) => {
			const authority = transactionAuthority(coordinated, stage);
			const current = await authority.getDomainForUpdate(context.scope, parsed.origin);
			if (!current) throw domainsNotFound(stage);
			if (current.version !== input.expectedVersion) throw domainConflict(stage);
			if (
				operation === "activate" &&
				current.state !== "verified" &&
				current.state !== "active"
			) {
				throw productError(
					"PRODUCT_DOMAIN_NOT_VERIFIED",
					"Custom authentication domain must be verified before activation.",
					stage,
					409,
				);
			}
			if (current.state === targetState) {
				return {
					schemaVersion: SCHEMA_VERSION,
					scope: context.scope,
					operation,
					dryRun: false,
					wouldChange: false,
					domain: current,
				} as const;
			}
			if (operation === "disable") {
				const sender = await authority.getSender(context.scope);
				if (sender?.domain === current.hostname) {
					throw productError(
						"PRODUCT_DOMAIN_SENDER_IN_USE",
						"The active email sender still uses this custom authentication domain.",
						stage,
						409,
						"Replace the email sender first, then disable this domain.",
					);
				}
			}
			const changed = await authority.setDomainState(
				context.scope,
				parsed.origin,
				input.expectedVersion,
				targetState,
			);
			if (!changed) throw domainConflict(stage);
			coordinated.appendAudit({
				actor: context.actor,
				action: stage,
				subjectType: "auth_domain",
				subjectId: changed.origin,
				outcome: "success",
				source: context.source,
				projectId: context.scope.projectId,
				environmentId: context.scope.environmentId,
				correlationId: context.correlationId,
				message: `${operation === "activate" ? "Activated" : "Disabled"} custom authentication domain`,
				metadata: {
					hostname: changed.hostname,
					previousState: current.state,
					state: changed.state,
					version: changed.version,
				},
			});
			return {
				schemaVersion: SCHEMA_VERSION,
				scope: context.scope,
				operation,
				dryRun: false,
				wouldChange: true,
				domain: changed,
			} as const;
		});
	} catch (error) {
		return translate(error, stage);
	}
}

export function activateProductDomainForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { origin: string; expectedVersion: number; dryRun?: boolean; confirm?: boolean },
): Promise<ProductDomainControlResult> {
	return controlProductDomainForManagement(store, context, input, "activate");
}

export function disableProductDomainForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { origin: string; expectedVersion: number; dryRun?: boolean; confirm?: boolean },
): Promise<ProductDomainControlResult> {
	return controlProductDomainForManagement(store, context, input, "disable");
}

function templateKind(value: unknown): ProductEmailTemplateKind {
	if (
		typeof value !== "string" ||
		!(PRODUCT_EMAIL_TEMPLATE_KINDS as readonly string[]).includes(value)
	) {
		throw productError(
			"PRODUCT_TEMPLATE_KIND_INVALID",
			"Template kind must be verification, password-reset, invitation, or email-change.",
			"product_templates.validate",
			400,
		);
	}
	return value as ProductEmailTemplateKind;
}

function templateHash(subject: string, plainText: string, html: string): string {
	return createHash("sha256")
		.update(subject, "utf8")
		.update("\0", "utf8")
		.update(plainText, "utf8").update("\0", "utf8").update(html, "utf8")
		.digest("hex");
}

function defaultTemplate(kind: ProductEmailTemplateKind): ProductEmailTemplateView {
	const value = {
		verification: {
			subject: "Verify your email",
			plainText: "Verify your email: {{verification_url}}", html: "<p>Verify your email: {{verification_url}}</p>",
		},
		"password-reset": {
			subject: "Reset your password",
			plainText: "Reset your password: {{reset_url}}", html: "<p>Reset your password: {{reset_url}}</p>",
		},
		invitation: {
			subject: "You have been invited",
			plainText: "Accept your invitation: {{invitation_url}}", html: "<p>Accept your invitation: {{invitation_url}}</p>",
		},
		"email-change": { subject: "Confirm your new email", plainText: "Confirm your new email: {{email_change_url}}", html: "<p>Confirm your new email: {{email_change_url}}</p>" },
	}[kind];
	return {
		kind,
		...value,
		variables: [...extractTemplateVariables(kind, value.subject, value.plainText, value.html)],
		version: 0,
		hash: templateHash(value.subject, value.plainText, value.html),
		updatedAt: null,
	};
}

function extractTemplateVariables(
	kind: ProductEmailTemplateKind,
	subject: string,
	plainText: string, html: string,
): string[] {
	const combined = `${subject}\n${plainText}\n${html}`;
	const htmlWithoutFormatting = html.replace(
		/<\/?(?:p|br|strong|em|ul|ol|li|code)>/gi,
		"",
	);
	if (
		/[<>]/.test(`${subject}\n${plainText}`) ||
		/[<>]/.test(htmlWithoutFormatting)
	) {
		throw productError(
			"PRODUCT_TEMPLATE_INPUT_INVALID",
			"Template HTML permits only inert formatting tags without attributes.",
			"product_templates.validate",
			400,
		);
	}
	const variables = new Set<string>();
	const placeholder = /\{\{([a-z][a-z0-9_]*)\}\}/g;
	let match: RegExpExecArray | null;
	while ((match = placeholder.exec(combined)) !== null) variables.add(match[1]!);
	const withoutPlaceholders = combined.replace(placeholder, "");
	if (withoutPlaceholders.includes("{{") || withoutPlaceholders.includes("}}")) {
		throw productError(
			"PRODUCT_TEMPLATE_INPUT_INVALID",
			"Template placeholders must use the exact {{variable_name}} form.",
			"product_templates.validate",
			400,
		);
	}
	const allowed = TEMPLATE_VARIABLES[kind];
	const invalid = [...variables].filter((variable) => !allowed.includes(variable));
	if (invalid.length > 0) {
		throw productError(
			"PRODUCT_TEMPLATE_VARIABLE_INVALID",
			`Template contains unsupported variables: ${invalid.sort().join(", ")}.`,
			"product_templates.validate",
			400,
			`Use only: ${allowed.join(", ")}.`,
		);
	}
	return [...variables].sort();
}

function templateCandidate(
	kind: ProductEmailTemplateKind,
	input: ProductTemplateCandidate,
	currentVersion: number,
): ProductEmailTemplateView {
	if (
		typeof input.subject !== "string" ||
		input.subject.trim() !== input.subject ||
		input.subject.length < 1 ||
		input.subject.length > SUBJECT_MAX ||
		/[\r\n\u0000-\u001f\u007f]/.test(input.subject)
	) {
		throw productError(
			"PRODUCT_TEMPLATE_INPUT_INVALID",
			`subject must be one trimmed line between 1 and ${SUBJECT_MAX} characters.`,
			"product_templates.validate",
			400,
		);
	}
	if (
		typeof input.plainText !== "string" || input.plainText.trim() !== input.plainText || input.plainText.length < 1 || input.plainText.length > BODY_MAX || /[\u0000\u000b\u000c\u007f]/.test(input.plainText) ||
		typeof input.html !== "string" || input.html.length < 1 || input.html.length > BODY_MAX
	) {
		throw productError(
			"PRODUCT_TEMPLATE_INPUT_INVALID",
			`plainText and html must be bounded template strings.`,
			"product_templates.validate",
			400,
		);
	}
	const variables = extractTemplateVariables(kind, input.subject, input.plainText, input.html);
	return {
		kind,
		subject: input.subject,
		plainText: input.plainText, html: input.html,
		variables,
		version: currentVersion + 1,
		hash: templateHash(input.subject, input.plainText, input.html),
		updatedAt: null,
	};
}

async function currentTemplate(
	store: ManagementStore,
	context: OperationContext,
	kind: ProductEmailTemplateKind,
	stage: string,
): Promise<ProductEmailTemplateView> {
	return (
		(await requireAuthority(store, stage).getTemplate(context.scope, kind)) ??
		defaultTemplate(kind)
	);
}

export async function getProductTemplateForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { kind: ProductEmailTemplateKind },
): Promise<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	template: ProductEmailTemplateView;
}> {
	const stage = "product_templates.get";
	try {
		const kind = templateKind(input.kind);
		return {
			schemaVersion: SCHEMA_VERSION,
			scope: context.scope,
			template: await currentTemplate(store, context, kind, stage),
		};
	} catch (error) {
		return translate(error, stage);
	}
}

function planTemplate(
	scope: OperationContext["scope"],
	kind: ProductEmailTemplateKind,
	current: ProductEmailTemplateView,
	input: ProductTemplateCandidate,
): ProductTemplatePlan {
	const candidate = templateCandidate(kind, input, current.version);
	const wouldChange = candidate.hash !== current.hash;
	return {
		schemaVersion: SCHEMA_VERSION,
		scope,
		expectedVersion: current.version,
		wouldChange,
		current,
		candidate: wouldChange ? candidate : { ...current },
	};
}

export async function planProductTemplateForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { kind: ProductEmailTemplateKind } & ProductTemplateCandidate,
): Promise<ProductTemplatePlan> {
	const stage = "product_templates.plan";
	try {
		const kind = templateKind(input.kind);
		const current = await currentTemplate(store, context, kind, stage);
		return planTemplate(context.scope, kind, current, input);
	} catch (error) {
		return translate(error, stage);
	}
}

export async function applyProductTemplateForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: {
		kind: ProductEmailTemplateKind;
		expectedVersion: number;
		dryRun?: boolean;
		confirm?: boolean;
	} & ProductTemplateCandidate,
): Promise<ProductTemplateApplyResult> {
	const stage = "product_templates.apply";
	try {
		const preview = await planProductTemplateForManagement(store, context, input);
		if (input.dryRun === true || input.confirm !== true) {
			return { dryRun: true, result: preview };
		}
		if (input.expectedVersion !== preview.current.version) {
			throw productError(
				"PRODUCT_TEMPLATE_VERSION_CONFLICT",
				"Email template version changed.",
				stage,
				409,
				"Create a fresh plan and retry with its expectedVersion.",
			);
		}
		if (!preview.wouldChange) {
			return {
				dryRun: false,
				result: {
					...preview,
					changed: false,
					previousVersion: preview.current.version,
					version: preview.current.version,
				},
			};
		}
		const result = await mutateCoordinatedWithRuntimeSql(store, async (coordinated) => {
			const authority = transactionAuthority(coordinated, stage);
			const kind = templateKind(input.kind);
			const current =
				(await authority.getTemplate(context.scope, kind)) ?? defaultTemplate(kind);
			if (current.version !== input.expectedVersion) {
				throw productError(
					"PRODUCT_TEMPLATE_VERSION_CONFLICT",
					"Email template version changed.",
					stage,
					409,
				);
			}
			const nextPlan = planTemplate(context.scope, kind, current, input);
			if (!nextPlan.wouldChange) return nextPlan;
			const applied = await authority.replaceTemplate(context.scope, {
				...nextPlan.candidate,
				expectedVersion: input.expectedVersion,
			});
			if (!applied) {
				throw productError(
					"PRODUCT_TEMPLATE_VERSION_CONFLICT",
					"Email template version changed.",
					stage,
					409,
				);
			}
			coordinated.appendAudit({
				actor: context.actor,
				action: stage,
				subjectType: "email_template",
				subjectId: kind,
				outcome: "success",
				source: context.source,
				projectId: context.scope.projectId,
				environmentId: context.scope.environmentId,
				correlationId: context.correlationId,
				message: `Applied ${kind} email template version ${applied.version}`,
				metadata: {
					kind,
					previousVersion: current.version,
					version: applied.version,
					hash: applied.hash,
					variables: applied.variables,
				},
			});
			return {
				...nextPlan,
				candidate: applied,
				changed: true,
				previousVersion: current.version,
				version: applied.version,
			};
		});
		return { dryRun: false, result };
	} catch (error) {
		return translate(error, stage);
	}
}

export async function getProductSenderReadinessForManagement(
	store: ManagementStore,
	context: OperationContext,
	input: { staleAfterMs?: number } = {},
): Promise<{
	schemaVersion: typeof SCHEMA_VERSION;
	scope: OperationContext["scope"];
	ready: boolean;
	schema: { isUpToDate: boolean; owner: string | null; installedVersion: number | null; expectedVersion: number };
	worker: { freshReady: number; lastSeenAt: string | null; staleAfterMs: number };
	keys: { checked: boolean; available: boolean; missingReferences: number };
	reasons: string[];
}> {
	const stage = "product_sender.readiness";
	try {
		const readiness = await getDeliveryReadinessForManagement(store, input);
		const reasons = readiness.reasons.filter((reason) =>
			[
				"schema_unavailable",
				"schema_outdated",
				"worker_unavailable",
				"key_unavailable",
			].includes(reason),
		);
		return {
			schemaVersion: SCHEMA_VERSION,
			scope: context.scope,
			ready:
				readiness.schema.isUpToDate &&
				readiness.workers.freshReady > 0 &&
				readiness.keys.available,
			schema: {
				isUpToDate: readiness.schema.isUpToDate,
				owner: readiness.schema.owner,
				installedVersion: readiness.schema.installedVersion,
				expectedVersion: readiness.schema.expectedVersion,
			},
			worker: {
				freshReady: readiness.workers.freshReady,
				lastSeenAt: readiness.workers.lastSeenAt,
				staleAfterMs: readiness.workers.staleAfterMs,
			},
			keys: readiness.keys,
			reasons,
		};
	} catch (error) {
		return translate(error, stage);
	}
}
