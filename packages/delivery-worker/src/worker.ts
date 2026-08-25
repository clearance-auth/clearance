import http, { type Server } from "node:http";
import { createHash } from "node:crypto";
import pg from "pg";
import { DELIVERY_SCHEMA_VERSION, DeliveryStore, qualifiedDeliveryTables, StaleDeliveryLeaseError } from "@clearance/delivery";
import {
	startObservability,
	type ObservabilityHandle,
} from "@clearance/observability-node";
import type { WorkerConfig } from "./config.js";
import { classifyEmailError, configuredEmailTransport, createEmailSender } from "./email.js";
import { createJsonLogger, type WorkerLogger } from "./logger.js";
import { DeliveryWorkerMetrics, type DeliveryMetricOutcome } from "./metrics.js";
import { renderEmailPayload, type EmailSender } from "./smtp.js";
import { formatDisplayMailbox, validateEmailPayload, type EmailPayload } from "./smtp.js";
import {
	classifyWebhookError,
	createWebhookSender,
	webhookDestination,
	type WebhookSender,
} from "./webhook.js";

const VERSION = "0.3.1";
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

type FirstPartyTemplateKind = "verification" | "password-reset" | "invitation" | "email-change";
type PresentationAuthorityState = "unknown" | "available" | "unavailable";
type RenderedPresentationState = "ready" | "absent";

export type ProductPresentationSnapshot = Readonly<{
	productLabel: string;
	sender: Readonly<{ displayName: string; address: string; domain: string; version: number }>;
	template: Readonly<{
		kind: FirstPartyTemplateKind; subject: string; plainText: string; html: string;
		variables: readonly string[]; version: number; hash: string;
	}>;
}>;

export type ProductPresentationLoader = {
	load(scope: { projectId: string; environmentId: string }, kind: FirstPartyTemplateKind): Promise<ProductPresentationSnapshot | null>;
};

const TEMPLATE_KIND_BY_JOB_TEMPLATE: Readonly<Record<string, FirstPartyTemplateKind>> = Object.freeze({
	"email-verification": "verification",
	"password-reset": "password-reset",
	"organization-invitation": "invitation",
	"email-change-confirmation": "email-change",
	"email-change-verification": "email-change",
});

const TEMPLATE_VARIABLES: Readonly<Record<FirstPartyTemplateKind, readonly string[]>> = Object.freeze({
	verification: ["product_name", "user_name", "verification_url"],
	"password-reset": ["product_name", "reset_url", "user_name"],
	invitation: ["invitation_url", "inviter_name", "organization_name", "product_name", "role"],
	"email-change": ["email_change_url", "product_name", "user_name"],
});

function identifier(value: string): string {
	if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(value)) throw new Error("presentation_identifier_invalid");
	return `"${value}"`;
}

function number(value: unknown, field: string): number {
	const parsed = typeof value === "number" ? value : Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`presentation_${field}_invalid`);
	return parsed;
}

function text(value: unknown, field: string, max: number): string {
	if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000\u007f]/.test(value)) {
		throw new Error(`presentation_${field}_invalid`);
	}
	return value;
}

function hash(value: unknown): string {
	if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) throw new Error("presentation_template_hash_invalid");
	return value;
}

function templateHash(subject: string, plainText: string, html: string): string {
	return createHash("sha256").update(subject, "utf8").update("\0", "utf8")
		.update(plainText, "utf8").update("\0", "utf8").update(html, "utf8").digest("hex");
}

function templateVariables(kind: FirstPartyTemplateKind, value: unknown): string[] {
	if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) throw new Error("presentation_template_variables_invalid");
	const variables = [...new Set(value)].sort();
	if (variables.some((item) => !TEMPLATE_VARIABLES[kind].includes(item))) throw new Error("presentation_template_variables_invalid");
	return variables;
}

/** Read normalized presentation records through one read-only, scope-bound statement. */
export function createProductPresentationLoader(
	pool: Pick<pg.Pool, "query">,
	config: Pick<WorkerConfig, "managementSchema" | "managementPrefix">,
): ProductPresentationLoader {
	const schema = identifier(config.managementSchema ?? "public");
	const prefix = config.managementPrefix ?? "mgmt_";
	if (!/^[a-z_][a-z0-9_]{0,29}$/.test(prefix)) throw new Error("presentation_identifier_invalid");
	const senderTable = `${schema}.${identifier(`${prefix}product_email_senders`)}`;
	const templateTable = `${schema}.${identifier(`${prefix}product_email_templates`)}`;
	const domainTable = `${schema}.${identifier(`${prefix}product_auth_domains`)}`;
	const presentationTable = `${schema}.${identifier(`${prefix}product_presentations`)}`;
	return {
		async load(scope, kind) {
			const result = await pool.query<Record<string, unknown>>(
				`SELECT COALESCE(p.product_label, 'Clearance') AS product_label,
				        s.display_name, s.address, s.domain, s.version AS sender_version,
				        t.kind, t.subject, t.plain_text, t.html, t.variables, t.version AS template_version, t.content_hash,
				        EXISTS(SELECT 1 FROM ${domainTable} d
				               WHERE d.project_id = $1 AND d.environment_id = $2 AND d.hostname = s.domain
				                 AND d.state IN ('verified', 'active')) AS sender_domain_ready
				 FROM (SELECT 1) AS scoped
				 LEFT JOIN LATERAL (
					SELECT product_label FROM ${presentationTable}
					WHERE project_id = $1 AND environment_id = $2
				 ) p ON true
				 LEFT JOIN LATERAL (
					SELECT display_name, address, domain, version FROM ${senderTable}
					WHERE project_id = $1 AND environment_id = $2
				 ) s ON true
				 LEFT JOIN LATERAL (
					SELECT kind, subject, plain_text, html, variables, version, content_hash FROM ${templateTable}
					WHERE project_id = $1 AND environment_id = $2 AND kind = $3
				 ) t ON true`,
				[scope.projectId, scope.environmentId, kind],
			);
			const row = result.rows[0];
			if (row?.sender_version !== undefined && row.sender_version !== null && row.sender_domain_ready !== true) {
				throw new Error("presentation_sender_domain_unverified");
			}
			if (!row?.display_name || !row.kind) return null;
			if (row.kind !== kind) throw new Error("presentation_template_kind_invalid");
			const senderAddress = text(row.address, "sender_address", 320);
			const senderDomain = text(row.domain, "sender_domain", 253).toLowerCase();
			if (senderAddress.slice(senderAddress.lastIndexOf("@") + 1).toLowerCase() !== senderDomain) {
				throw new Error("presentation_sender_domain_invalid");
			}
			const sender = Object.freeze({
				displayName: text(row.display_name, "sender_display_name", 128),
				address: senderAddress,
				domain: senderDomain,
				version: number(row.sender_version, "sender_version"),
			});
			const templateSubject = text(row.subject, "template_subject", 998);
			const templatePlainText = text(row.plain_text, "template_plain_text", 20_000);
			const templateHtml = text(row.html, "template_html", 20_000);
			const templateHashValue = hash(row.content_hash);
			if (templateHash(templateSubject, templatePlainText, templateHtml) !== templateHashValue) {
				throw new Error("presentation_template_hash_invalid");
			}
			const template = Object.freeze({
				kind,
				subject: templateSubject,
				plainText: templatePlainText,
				html: templateHtml,
				variables: Object.freeze(templateVariables(kind, row.variables)),
				version: number(row.template_version, "template_version"),
				hash: templateHashValue,
			});
			return Object.freeze({ productLabel: text(row.product_label, "product_label", 64), sender, template });
		},
	};
}

/** Verify configured management presentation tables are readable without inventing a tenant scope. */
export async function probeProductPresentationAuthority(
	pool: Pick<pg.Pool, "query">,
	config: Pick<WorkerConfig, "managementSchema" | "managementPrefix">,
): Promise<void> {
	const schema = identifier(config.managementSchema ?? "public");
	const prefix = config.managementPrefix ?? "mgmt_";
	if (!/^[a-z_][a-z0-9_]{0,29}$/.test(prefix)) throw new Error("presentation_identifier_invalid");
	const table = (name: string) => `${schema}.${identifier(`${prefix}${name}`)}`;
	await pool.query(
		`SELECT 1
		 FROM ${table("product_email_senders")} AS senders
		 FULL JOIN ${table("product_email_templates")} AS templates ON FALSE
		 FULL JOIN ${table("product_auth_domains")} AS domains ON FALSE
		 FULL JOIN ${table("product_presentations")} AS presentation ON FALSE
		 LIMIT 0`,
	);
}

function firstPartyKind(value: unknown): FirstPartyTemplateKind | undefined {
	if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
	const template = (value as Record<string, unknown>).template;
	return typeof template === "string" ? TEMPLATE_KIND_BY_JOB_TEMPLATE[template] : undefined;
}

function allowsLegacyPresentationFallback(config: Pick<WorkerConfig, "allowLegacyPresentationFallback">): boolean {
	return config.allowLegacyPresentationFallback ?? process.env.NODE_ENV !== "production";
}

function templateValue(value: unknown, field: string): string {
	if (typeof value !== "string" || /[\r\n\u0000\u007f]/.test(value) || !value.trim()) throw new Error(`presentation_${field}_invalid`);
	return value.trim();
}

function optionalUserName(value: unknown): string {
	if (value === undefined || value === null || value === "" || (typeof value === "string" && value.trim() === "")) return "";
	return templateValue(value, "user_name");
}

function placeholders(value: string): string[] {
	const found = new Set<string>();
	const matcher = /\{\{([a-z][a-z0-9_]*)\}\}/g;
	let match: RegExpExecArray | null;
	while ((match = matcher.exec(value)) !== null) found.add(match[1]!);
	if (value.replace(matcher, "").includes("{{") || value.replace(matcher, "").includes("}}")) {
		throw new Error("presentation_template_placeholder_invalid");
	}
	return [...found].sort();
}

function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

function interpolate(value: string, values: Readonly<Record<string, string>>, mode: "subject" | "text" | "html"): string {
	for (const placeholder of placeholders(value)) {
		if (!(placeholder in values)) throw new Error("presentation_template_unresolved_variable");
	}
	return value.replace(/\{\{([a-z][a-z0-9_]*)\}\}/g, (_match, variable: string) => {
		const replacement = values[variable];
		if (replacement === undefined) throw new Error("presentation_template_unresolved_variable");
		return mode === "html" ? escapeHtml(replacement) : replacement;
	});
}

function presentationValues(value: unknown, kind: FirstPartyTemplateKind, productLabel: string): Record<string, string> {
	const raw = value as Record<string, unknown>;
	const productName = templateValue(productLabel, "product_name");
	if (kind === "invitation") return {
		product_name: productName,
		invitation_url: templateValue(raw.acceptanceUrl, "invitation_url"),
		inviter_name: templateValue(raw.inviterName, "inviter_name"),
		organization_name: templateValue(raw.organizationName, "organization_name"),
		role: templateValue(raw.role, "role"),
	};
	const userName = optionalUserName(raw.userName);
	const url = templateValue(raw.url, kind === "password-reset" ? "reset_url" : kind === "email-change" ? "email_change_url" : "verification_url");
	return kind === "password-reset" ? { product_name: productName, reset_url: url, user_name: userName }
		: kind === "email-change" ? { product_name: productName, email_change_url: url, user_name: userName }
		: { product_name: productName, verification_url: url, user_name: userName };
}

/** Render a first-party job against a closed normalized snapshot after legacy validation. */
export function renderNormalizedEmailPayload(value: unknown, config: WorkerConfig, snapshot: ProductPresentationSnapshot): EmailPayload {
	const fallback = renderEmailPayload(value, config);
	const kind = firstPartyKind(value);
	if (!kind || kind !== snapshot.template.kind) throw new Error("presentation_template_kind_invalid");
	const values = presentationValues(value, kind, snapshot.productLabel);
	const extracted = [...new Set([
		...placeholders(snapshot.template.subject),
		...placeholders(snapshot.template.plainText),
		...placeholders(snapshot.template.html),
	])].sort();
	if (extracted.length !== snapshot.template.variables.length || extracted.some((item, index) => item !== snapshot.template.variables[index])) {
		throw new Error("presentation_template_variables_invalid");
	}
	if (extracted.some((item) => !TEMPLATE_VARIABLES[kind].includes(item))) throw new Error("presentation_template_variables_invalid");
	return validateEmailPayload({
		to: fallback.to,
		from: formatDisplayMailbox(snapshot.sender.displayName, snapshot.sender.address),
		subject: interpolate(snapshot.template.subject, values, "subject"),
		text: interpolate(snapshot.template.plainText, values, "text"),
		html: interpolate(snapshot.template.html, values, "html"),
	}, config.maxBodyBytes);
}

/** The leased-job rendering boundary; the loader is injectable for isolated verification. */
export async function renderWorkerEmailPayload(
	payload: unknown,
	scope: { projectId: string; environmentId: string },
	config: WorkerConfig,
	loader: ProductPresentationLoader,
): Promise<Readonly<{ payload: EmailPayload; presentation: RenderedPresentationState }>> {
	const kind = firstPartyKind(payload);
	if (!kind) return { payload: renderEmailPayload(payload, config), presentation: "absent" };
	let snapshot: ProductPresentationSnapshot | null;
	try {
		snapshot = await loader.load(scope, kind);
	} catch (error) {
		if (error instanceof Error && error.message.startsWith("presentation_")) throw error;
		throw new Error("presentation_unavailable");
	}
	if (snapshot) return { payload: renderNormalizedEmailPayload(payload, config, snapshot), presentation: "ready" };
	if (allowsLegacyPresentationFallback(config)) {
		return { payload: renderEmailPayload(payload, config), presentation: "absent" };
	}
	throw new Error("presentation_required");
}

class ProviderAcceptedUnconfirmedError extends Error {
	constructor(readonly cause: unknown) {
		super("Provider accepted the delivery but durable completion was not confirmed");
		this.name = "ProviderAcceptedUnconfirmedError";
	}
}

export class DeliveryDrainTimeoutError extends Error {
	constructor(readonly inFlight: number) {
		super(`Delivery worker drain timed out with ${inFlight} job(s) still in flight`);
		this.name = "DeliveryDrainTimeoutError";
	}
}

class DeliveryStopTimeoutError extends Error {
	constructor() {
		super("Delivery worker shutdown timed out");
		this.name = "DeliveryStopTimeoutError";
	}
}

function settleBeforeDeadline<T>(
	operation: () => T | Promise<T>,
	deadline: number,
	timeoutError: () => Error = () => new DeliveryStopTimeoutError(),
): Promise<T> {
	const pending = Promise.resolve().then(operation);
	// The deadline race owns the outcome; retain the late rejection so a hung
	// cleanup stage cannot produce an unhandled rejection after shutdown ends.
	void pending.catch(() => undefined);
	return new Promise<T>((resolve, reject) => {
		let settled = false;
		const timeout = setTimeout(() => {
			if (settled) return;
			settled = true;
			reject(timeoutError());
		}, Math.max(0, deadline - Date.now()));
		pending.then(
			(value) => {
				if (settled) return;
				settled = true;
				clearTimeout(timeout);
				resolve(value);
			},
			(error: unknown) => {
				if (settled) return;
				settled = true;
				clearTimeout(timeout);
				reject(error);
			},
		);
	});
}

export type WorkerReadiness = {
	ready: boolean;
	draining: boolean;
	database: boolean;
	schema: boolean;
	keyring: boolean;
	audit: boolean;
	heartbeat: boolean;
	email: boolean;
	emailTransport: "smtp" | "ses";
	smtp: boolean;
	ses: boolean;
	presentation: PresentationAuthorityState;
	presentationReason?: "normalized_presentation_unknown" | "normalized_presentation_unavailable";
	workerId: string;
};

export function workerHeartbeatState(input: Readonly<{
	draining: boolean;
	emailHealthy: boolean;
	schemaHealthy: boolean;
	presentation: PresentationAuthorityState;
}>): "ready" | "draining" | "failed" {
	if (input.draining) return "draining";
	return input.emailHealthy && input.schemaHealthy && input.presentation === "available"
		? "ready"
		: "failed";
}

export class DeliveryWorker {
	readonly pool: pg.Pool;
	readonly store: DeliveryStore;
	readonly config: WorkerConfig;
	private readonly sender: EmailSender;
	private readonly webhookSender: WebhookSender;
	private readonly presentationLoader: ProductPresentationLoader;
	private readonly logger: WorkerLogger;
	private stopping = false;
	private stopped = false;
	private draining = false;
	private initialized = false;
	private schemaHealthy = false;
	private emailHealthy = false;
	private presentationState: PresentationAuthorityState = "unknown";
	private lastHeartbeatAt = 0;
	private inFlight = new Set<Promise<unknown>>();
	private healthServer?: Server;
	private readonly metrics = new DeliveryWorkerMetrics();
	private heartbeatTimer?: NodeJS.Timeout;
	private maintenanceTimer?: NodeJS.Timeout;
	private maintenanceRunning = false;
	private observability?: ObservabilityHandle;
	private stopPromise?: Promise<void>;

	constructor(config: WorkerConfig, dependencies: {
		pool?: pg.Pool;
		sender?: EmailSender;
		webhookSender?: WebhookSender;
		presentationLoader?: ProductPresentationLoader;
		logger?: WorkerLogger;
	} = {}) {
		this.config = config;
		this.pool = dependencies.pool ?? new pg.Pool({
			connectionString: config.databaseUrl,
			max: Math.max(4, config.concurrency + 2),
			connectionTimeoutMillis: config.smtp?.connectionTimeoutMs ?? config.ses?.requestTimeoutMs ?? 10_000,
			application_name: `clearance-delivery:${config.workerId}`,
		});
		this.store = new DeliveryStore(this.pool, {
			schema: config.schema,
			prefix: config.prefix,
			legacyFingerprintKeyId: config.legacyFingerprintKeyId,
			...(config.runtimeAudit ? { runtimeAudit: config.runtimeAudit } : {}),
		});
		this.sender = dependencies.sender ?? createEmailSender(config);
		this.webhookSender = dependencies.webhookSender ?? createWebhookSender(config);
		this.presentationLoader = dependencies.presentationLoader ?? createProductPresentationLoader(this.pool, config);
		this.logger = dependencies.logger ?? createJsonLogger();
	}

	private async refreshPresentationAuthority(): Promise<void> {
		try {
			await probeProductPresentationAuthority(this.pool, this.config);
			this.presentationState = "available";
		} catch {
			this.presentationState = "unavailable";
		}
	}

	private durableHeartbeatState(): "ready" | "draining" | "failed" {
		return workerHeartbeatState({
			draining: this.draining,
			emailHealthy: this.emailHealthy,
			schemaHealthy: this.schemaHealthy,
			presentation: this.presentationState,
		});
	}

	async initialize(options: { verifyEmail?: boolean; verifySmtp?: boolean } = {}): Promise<void> {
		this.observability = await startObservability();
		await this.store.heartbeat({ workerId: this.config.workerId, version: VERSION, state: "starting" }).catch(() => undefined);
		const result = await this.store.migrate();
		await this.store.assertRuntimeAuditTableReady();
		await this.store.assertFingerprintKeysAvailable(this.config.keyring);
		this.schemaHealthy = result.version === DELIVERY_SCHEMA_VERSION;
		await this.refreshPresentationAuthority();
		const shouldVerifyEmail = options.verifyEmail ?? options.verifySmtp ?? true;
		if (shouldVerifyEmail) {
			try {
				await this.sender.verify();
				this.emailHealthy = true;
			} catch (error) {
				this.emailHealthy = false;
				await this.writeHeartbeat("failed").catch(() => undefined);
				throw error;
			}
		} else {
			this.emailHealthy = false;
		}
		await this.writeHeartbeat(this.durableHeartbeatState());
		this.initialized = true;
		const transport = configuredEmailTransport(this.config);
		this.logger.log(this.emailHealthy ? "info" : "warn", this.emailHealthy ? "worker.ready" : `worker.${transport}_unverified`, {
			workerId: this.config.workerId,
			schemaVersion: result.version,
			emailTransport: transport,
		});
	}

	private async writeHeartbeat(state: "ready" | "draining" | "stopped" | "failed"): Promise<void> {
		const durableState = state === "ready" && this.presentationState !== "available"
			? "failed"
			: state;
		await this.store.heartbeat({ workerId: this.config.workerId, version: VERSION, state: durableState });
		this.lastHeartbeatAt = Date.now();
	}

	async readiness(): Promise<WorkerReadiness> {
		const transport = configuredEmailTransport(this.config);
		await this.refreshPresentationAuthority();
		let database = false;
		let keyring = false;
		let audit = !this.config.runtimeAudit;
		try { await this.pool.query("SELECT 1"); database = true; } catch { database = false; }
		if (database) {
			try {
				const tables = qualifiedDeliveryTables(this.store.options);
				const expectedTableNames = Object.values(tables.names).filter(
					(name) => name !== tables.names.rejectMutationFunction,
				);
				const result = await this.pool.query<{ version: unknown; table_count: number; function_count: number }>(
					`SELECT
					 (SELECT value FROM ${tables.meta} WHERE key='schema_version') version,
					 (SELECT count(*)::int FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
					  WHERE n.nspname=$1 AND c.relname=ANY($2::text[]) AND c.relkind IN ('r','p')) table_count,
					 (SELECT count(*)::int FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
					  WHERE n.nspname=$1 AND p.proname=$3) function_count`,
					[tables.schema, expectedTableNames, tables.names.rejectMutationFunction],
				);
				const row = result.rows[0];
				this.schemaHealthy = Number(row?.version) === DELIVERY_SCHEMA_VERSION &&
					row?.table_count === expectedTableNames.length && row?.function_count === 1;
			} catch { this.schemaHealthy = false; }
			if (this.schemaHealthy) {
				try {
					await this.store.assertFingerprintKeysAvailable(this.config.keyring);
					keyring = true;
				} catch {
					keyring = false;
				}
			}
			if (this.schemaHealthy && this.config.runtimeAudit) {
				try {
					await this.store.assertRuntimeAuditTableReady();
					audit = true;
				} catch {
					audit = false;
				}
			}
		} else {
			this.schemaHealthy = false;
		}
		const heartbeat = this.lastHeartbeatAt > 0 && Date.now() - this.lastHeartbeatAt <= this.config.heartbeatMs * 3;
		const presentationReady = this.presentationState === "available";
		return {
			ready: this.initialized && !this.draining && database && this.schemaHealthy && keyring && audit && heartbeat && this.emailHealthy && presentationReady,
			draining: this.draining,
			database,
			schema: this.schemaHealthy,
			keyring,
			audit,
			heartbeat,
			email: this.emailHealthy,
			emailTransport: transport,
			smtp: transport === "smtp" && this.emailHealthy,
			ses: transport === "ses" && this.emailHealthy,
			presentation: this.presentationState,
			...(this.presentationState === "unknown" ? { presentationReason: "normalized_presentation_unknown" as const }
				: this.presentationState === "unavailable" ? { presentationReason: "normalized_presentation_unavailable" as const } : {}),
			workerId: this.config.workerId,
		};
	}

	private async processJob(): Promise<boolean> {
		if (this.draining || this.stopping) return false;
		const processed = await this.store.claimNextWithTrace(
			{ workerId: this.config.workerId, leaseMs: this.config.leaseMs },
			async (leased) => {
				const claimedAt = performance.now();
				let metricOutcome: DeliveryMetricOutcome = "finish_failed";
				this.metrics.recordClaim(leased.channel);
				this.logger.log("info", "delivery.claimed", { jobId: leased.id, eventId: leased.eventId, kind: leased.kind, attempt: leased.attemptCount });
				try {
					if (leased.channel !== "email" && leased.channel !== "webhook") {
						await this.store.dead({ jobId: leased.id, leaseToken: leased.leaseToken, workerId: this.config.workerId, errorClass: "transport.unsupported" });
						metricOutcome = "dead";
						return true;
					}
					const payload = await this.store.readLeasedPayload<unknown>({ jobId: leased.id, leaseToken: leased.leaseToken, keyring: this.config.keyring });
					let email: EmailPayload | undefined;
					if (leased.channel === "email") {
						let rendered: Awaited<ReturnType<typeof renderWorkerEmailPayload>>;
						try {
							rendered = await renderWorkerEmailPayload(payload, {
								projectId: leased.projectId,
								environmentId: leased.environmentId,
							}, this.config, this.presentationLoader);
						} catch (error) {
							if (!(error instanceof Error) || error.message !== "presentation_required") {
								this.presentationState = "unavailable";
							}
							throw error;
						}
						email = rendered.payload;
						this.presentationState = "available";
					}
					const destination = email?.to ??
						webhookDestination(payload);
					await this.store.assertLeasedDestination({
						jobId: leased.id,
						leaseToken: leased.leaseToken,
						destination,
						keyring: this.config.keyring,
					});
					const result = await this.sendWithLeaseRenewal(
						leased,
						email
							? () => this.sender.send(email, {
									jobId: leased.id,
									eventId: leased.eventId,
								})
							: () => this.webhookSender.send(payload, {
									jobId: leased.id,
									eventId: leased.eventId,
								}),
					);
					if (leased.channel === "email") this.emailHealthy = true;
					try {
						await this.store.markProviderAccepted({
							jobId: leased.id,
							leaseToken: leased.leaseToken,
							workerId: this.config.workerId,
							providerStatus: result.status,
							providerRequestId: result.requestId,
						});
						await this.store.complete({ jobId: leased.id, leaseToken: leased.leaseToken, workerId: this.config.workerId, providerStatus: result.status, providerRequestId: result.requestId });
					} catch (error) {
						throw new ProviderAcceptedUnconfirmedError(error);
					}
					this.logger.log("info", "delivery.delivered", { jobId: leased.id, eventId: leased.eventId, providerStatus: result.status });
					metricOutcome = "delivered";
				} catch (error) {
					if (error instanceof ProviderAcceptedUnconfirmedError) {
						metricOutcome = "accepted_unconfirmed";
						this.logger.log("error", "delivery.provider_accepted_unconfirmed", {
							jobId: leased.id,
							eventId: leased.eventId,
							error: error.cause,
						});
						return true;
					}
					if (error instanceof StaleDeliveryLeaseError) {
						metricOutcome = "stale_lease";
						this.logger.log("warn", "delivery.stale_lease", { jobId: leased.id, eventId: leased.eventId });
						return true;
					}
					const classified = leased.channel === "webhook"
						? classifyWebhookError(error)
						: classifyEmailError(this.config, error);
					if (leased.channel === "email" && /^(?:smtp|ses)\.(?:transport|timeout)$/.test(classified.errorClass)) {
						this.emailHealthy = false;
					}
					try {
						const result = classified.retryable
							? await this.store.retry({ jobId: leased.id, leaseToken: leased.leaseToken, workerId: this.config.workerId, errorClass: classified.errorClass, providerStatus: classified.providerStatus })
							: await this.store.dead({ jobId: leased.id, leaseToken: leased.leaseToken, workerId: this.config.workerId, errorClass: classified.errorClass, providerStatus: classified.providerStatus });
						this.logger.log(classified.retryable ? "warn" : "error", `delivery.${result.state}`, { jobId: leased.id, eventId: leased.eventId, errorClass: classified.errorClass, providerStatus: classified.providerStatus });
						metricOutcome = result.state === "retry" ? "retry"
							: result.state === "cancelled" ? "cancelled"
							: "dead";
					} catch (finishError) {
						this.logger.log("error", "delivery.finish_failed", { jobId: leased.id, error: finishError });
					}
				} finally {
					this.metrics.recordOutcome(leased.channel, metricOutcome, performance.now() - claimedAt);
				}
				return true;
			},
		);
		return processed ?? false;
	}

	private async sendWithLeaseRenewal(
		leased: { id: string; eventId: string; leaseToken: string },
		send: () => Promise<Awaited<ReturnType<EmailSender["send"]>>>,
	): Promise<Awaited<ReturnType<EmailSender["send"]>>> {
		let stopped = false;
		let renewalFailure: unknown;
		let pending = Promise.resolve();
		const intervalMs = Math.max(1_000, Math.floor(this.config.leaseMs / 3));
		const timer = setInterval(() => {
			pending = pending.then(async () => {
				if (stopped || renewalFailure) return;
				try {
					await this.store.renewLease({
						jobId: leased.id,
						leaseToken: leased.leaseToken,
						workerId: this.config.workerId,
						leaseMs: this.config.leaseMs,
					});
				} catch (error) { renewalFailure = error; }
			});
		}, intervalMs);
		try {
			const result = await send();
			stopped = true;
			clearInterval(timer);
			await pending;
			if (renewalFailure) {
				// Preserve the provider-accepted outcome. The following fenced
				// completion determines whether this worker still owns the lease.
				this.logger.log("warn", "delivery.lease_renewal_degraded", {
					jobId: leased.id,
					error: renewalFailure,
				});
			}
			return result;
		} catch (error) {
			stopped = true;
			clearInterval(timer);
			await pending;
			throw renewalFailure ?? error;
		}
	}

	async processOnce(limit = this.config.processOnceLimit): Promise<number> {
		if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new Error("processOnce limit must be between 1 and 10000");
		let processed = 0;
		while (processed < limit && !this.draining) {
			const batch = Math.min(this.config.concurrency, limit - processed);
			const tasks = Array.from({ length: batch }, () => this.track(this.processJob()));
			const results = await Promise.all(tasks);
			const count = results.filter(Boolean).length;
			processed += count;
			if (count === 0) break;
		}
		return processed;
	}

	private track<T>(promise: Promise<T>): Promise<T> {
		const tracked = promise.finally(() => this.inFlight.delete(tracked));
		this.inFlight.add(tracked);
		return tracked;
	}

	private async maintenance(): Promise<void> {
		if (this.maintenanceRunning) return;
		this.maintenanceRunning = true;
		try {
			const reclaimed = await this.store.reclaimExpired();
			const expired = await this.store.expireAndEraseUndeliverable();
			if (reclaimed || expired.deadJobs || expired.erasedPayloads) this.logger.log("info", "worker.maintenance", { reclaimed, ...expired });
		} catch (error) {
			this.schemaHealthy = false;
			this.logger.log("error", "worker.maintenance_failed", { error });
		}
		const wasHealthy = this.emailHealthy;
		const transport = configuredEmailTransport(this.config);
		try {
			await this.sender.verify();
			this.emailHealthy = true;
			if (!wasHealthy) this.logger.log("info", `worker.${transport}_recovered`);
		} catch (error) {
			this.emailHealthy = false;
			this.logger.log(wasHealthy ? "error" : "warn", `worker.${transport}_unavailable`, { error });
		}
		await this.refreshPresentationAuthority();
		await this.writeHeartbeat(this.durableHeartbeatState())
			.catch((error) => this.logger.log("error", "worker.heartbeat_failed", { error }));
		this.maintenanceRunning = false;
	}

	private startTimers(): void {
		this.heartbeatTimer = setInterval(() => {
			void this.refreshPresentationAuthority()
				.then(() => this.writeHeartbeat(this.durableHeartbeatState()))
				.catch((error) => this.logger.log("error", "worker.heartbeat_failed", { error }));
		}, this.config.heartbeatMs);
		this.heartbeatTimer.unref();
		this.maintenanceTimer = setInterval(() => void this.maintenance(), this.config.maintenanceMs);
		this.maintenanceTimer.unref();
	}

	async startHealthServer(): Promise<void> {
		if (this.healthServer) return;
		this.healthServer = http.createServer(async (request, response) => {
			response.setHeader("cache-control", "no-store");
			if (request.method !== "GET") { response.setHeader("content-type", "application/json"); response.statusCode = 405; response.end('{"error":"method_not_allowed"}'); return; }
			if (request.url === "/live") { response.setHeader("content-type", "application/json"); response.statusCode = this.stopping ? 503 : 200; response.end(JSON.stringify({ live: !this.stopping })); return; }
			if (request.url === "/ready") { response.setHeader("content-type", "application/json"); const state = await this.readiness(); response.statusCode = state.ready ? 200 : 503; response.end(JSON.stringify(state)); return; }
			if (request.url === "/metrics") {
				response.setHeader("content-type", "text/plain; version=0.0.4; charset=utf-8");
				response.statusCode = 200;
				response.end(this.metrics.render({
					inFlight: this.inFlight.size,
					draining: this.draining,
					schemaHealthy: this.schemaHealthy,
					emailHealthy: this.emailHealthy,
					emailTransport: configuredEmailTransport(this.config),
				}));
				return;
			}
			response.setHeader("content-type", "application/json");
			response.statusCode = 404; response.end('{"error":"not_found"}');
		});
		await new Promise<void>((resolve, reject) => { this.healthServer!.once("error", reject); this.healthServer!.listen(this.config.healthPort, this.config.healthHost, resolve); });
	}

	async run(): Promise<void> {
		await this.initialize();
		await this.startHealthServer();
		this.startTimers();
		while (!this.stopping) {
			if (this.draining) { await sleep(25); continue; }
			while (this.inFlight.size < this.config.concurrency && !this.draining) {
				this.track(this.processJob().then(async (worked) => { if (!worked) await sleep(this.config.pollMs); }));
			}
			await Promise.race(this.inFlight);
		}
	}

	async drain(deadline = Date.now() + this.config.drainTimeoutMs): Promise<void> {
		if (!this.draining) {
			this.draining = true;
			this.logger.log("info", "worker.draining", { workerId: this.config.workerId, inFlight: this.inFlight.size });
			await this.writeHeartbeat("draining").catch(() => undefined);
		}
		while (this.inFlight.size && Date.now() < deadline) await Promise.race([Promise.allSettled([...this.inFlight]), sleep(25)]);
		if (this.inFlight.size) {
			this.logger.log("error", "worker.drain_timeout", { inFlight: this.inFlight.size });
			throw new DeliveryDrainTimeoutError(this.inFlight.size);
		}
	}

	async stop(): Promise<void> {
		if (this.stopped) return;
		if (this.stopPromise) return this.stopPromise;
		this.stopPromise = this.stopWithinDeadline();
		return this.stopPromise;
	}

	private async stopWithinDeadline(): Promise<void> {
		const deadline = Date.now() + this.config.drainTimeoutMs;
		let firstError: unknown;
		const recordError = (error: unknown) => {
			firstError ??= error;
		};
		try {
			await settleBeforeDeadline(
				() => this.drain(deadline),
				deadline,
				() => new DeliveryDrainTimeoutError(this.inFlight.size),
			);
		} catch (error) {
			recordError(error);
		}
		this.stopping = true;
		if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
		if (this.maintenanceTimer) clearInterval(this.maintenanceTimer);
		const cleanup = this.finishStop([...this.inFlight]);
		// A timed-out stop returns at the absolute deadline while cleanup retains
		// the live pool until transport cancellation and captured work settle.
		void cleanup.catch(() => undefined);
		try {
			await settleBeforeDeadline(() => cleanup, deadline);
		} catch (error) {
			recordError(error);
		}
		if (firstError) throw firstError;
	}

	private async finishStop(capturedInFlight: readonly Promise<unknown>[]): Promise<void> {
		let firstError: unknown;
		const runCleanup = async (operation: () => unknown | Promise<unknown>) => {
			try {
				await operation();
			} catch (error) {
				firstError ??= error;
			}
		};
		await runCleanup(() => this.sender.close());
		await Promise.allSettled(capturedInFlight);
		await runCleanup(() => this.writeHeartbeat("stopped"));
		if (this.healthServer) {
			await runCleanup(
				() => new Promise<void>((resolve) => this.healthServer!.close(() => resolve())),
			);
		}
		await runCleanup(() => this.pool.end());
		await runCleanup(() => this.observability?.shutdown());
		if (firstError) throw firstError;
		this.stopped = true;
		this.logger.log("info", "worker.stopped", { workerId: this.config.workerId });
	}
}
