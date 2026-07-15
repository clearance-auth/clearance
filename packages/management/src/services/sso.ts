import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DiagnosticTrace, IdentityConnection } from "../types/resources.js";
import { deleteSsoProviderById } from "../auth-bridge.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import { encryptCredential, rotateCredential } from "./credentials.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganization } from "./core.js";
import { resolveEnterpriseConnection } from "./enterprise-connection-lifecycle.js";
import { publicIdentityConnection } from "./redact.js";
import {
	resolveOperatorScope,
	type ResourceScope,
} from "./scope.js";
import { validateSamlProviderConfig } from "./sso-real.js";
// Setup capabilities live in setup-links.ts (createSetupLink / redeem / revoke)

export type SsoActorSource = "cli" | "console" | "api" | "system";

export interface SsoMutationOpts {
	actor?: string;
	source?: SsoActorSource;
	scope?: ResourceScope;
}

/**
 * Resolve an SSO connection under principal-derived org scope.
 * Missing and cross-scope ids fail closed as SSO_NOT_FOUND.
 */
export function resolveSsoConnection(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope; stage?: string },
): IdentityConnection {
	return resolveEnterpriseConnection(store, id, {
		connections: store.snapshot.identityConnections,
		scope: opts?.scope,
		stage: opts?.stage ?? "sso.resolve",
		label: "SSO",
		idRequiredCode: "SSO_ID_REQUIRED",
		notFoundCode: "SSO_NOT_FOUND",
	});
}

/** Public inspect — never returns encrypted secret material. */
export function inspectSsoConnection(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope },
): IdentityConnection {
	const conn = resolveSsoConnection(store, id, {
		scope: opts?.scope,
		stage: "sso.inspect",
	});
	return publicIdentityConnection(conn) as IdentityConnection;
}

export interface SsoCreateInput {
	organizationId: string;
	protocol: "saml" | "oidc";
	provider: string;
	issuer?: string;
	audience?: string;
	metadataUrl?: string;
	clientId?: string;
	clientSecret?: string;
	samlEntryPoint?: string;
	samlCertificate?: string;
	domains?: string[];
	actor?: string;
}

export function createSsoConnection(
	store: ManagementStore,
	input: SsoCreateInput,
): IdentityConnection {
	const org = inspectOrganization(store, input.organizationId);
	const now = nowIso();
	let clientSecretFingerprint: string | undefined;
	let clientSecretEncrypted: string | undefined;
	let clientSecretKeyId: string | undefined;
	if (input.clientSecret) {
		const enc = encryptCredential(input.clientSecret);
		clientSecretFingerprint = enc.fingerprint;
		clientSecretEncrypted = enc.ciphertext;
		clientSecretKeyId = enc.keyId;
	}
	const saml = input.protocol === "saml"
		? validateSamlProviderConfig({
				entryPoint: input.samlEntryPoint,
				certificate: input.samlCertificate,
			})
		: undefined;
	const conn: IdentityConnection = {
		id: newId("sso"),
		organizationId: org.id,
		protocol: input.protocol,
		provider: input.provider,
		status: "draft",
		domains: input.domains ?? [],
		issuer: input.issuer,
		audience: input.audience,
		metadataUrl: input.metadataUrl,
		clientId: input.clientId,
		clientSecretFingerprint,
		clientSecretEncrypted,
		clientSecretKeyId,
		samlEntryPoint: saml?.entryPoint,
		samlCertificate: saml?.certificate,
		samlCertificateFingerprint: saml?.fingerprint,
		attributeMapping: {
			email: "email",
			name: "name",
		},
		createdAt: now,
		updatedAt: now,
	};
	store.mutate((data) => {
		data.identityConnections.push(conn);
	});
	recordEvent(store, {
		actor: input.actor ?? "operator",
		action: "sso.create",
		subjectType: "identity_connection",
		subjectId: conn.id,
		outcome: "success",
		source: "cli",
		organizationId: org.id,
		projectId: org.projectId,
		environmentId: org.environmentId,
		message: `Created ${conn.protocol} connection for ${conn.provider}`,
		metadata: {
			hasClientSecret: Boolean(input.clientSecret),
			clientSecretKeyId: clientSecretKeyId ?? null,
			samlCertificateFingerprint: saml?.fingerprint ?? null,
			// never: clientSecret plaintext or ciphertext in audit (redact handles encrypted keys)
		},
	});
	// Domain return is write-only for secret material
	return publicIdentityConnection(conn) as IdentityConnection;
}

/**
 * Configure an SSO connection under principal-derived scope (FOLLOW.md P2.3.5).
 * Missing and cross-scope ids fail closed as SSO_NOT_FOUND with no write —
 * the same scope contract as rotateSsoCredential / disableSsoConnection.
 * Validation + write + audit run in ONE store.mutate against the draft
 * (core.ts atomic mutation pattern), so Postgres FOR UPDATE commits the
 * configure and its audit event together or not at all.
 */
export function configureSsoConnection(
	store: ManagementStore,
	id: string,
	patch: Partial<
		Pick<
			IdentityConnection,
			| "issuer"
			| "audience"
			| "metadataUrl"
			| "clientId"
			| "domains"
			| "attributeMapping"
			| "status"
		>
	> & { clientSecret?: string },
	opts?: SsoMutationOpts,
): IdentityConnection {
	const stage = "sso.configure";
	// Fail closed BEFORE any mutation: missing/cross-scope → SSO_NOT_FOUND.
	const conn = resolveSsoConnection(store, id, {
		scope: opts?.scope,
		stage,
	});
	const org = inspectOrganization(
		store,
		conn.organizationId,
		opts?.scope ?? resolveOperatorScope(store),
	);
	// Encrypt outside the mutator: deterministic input, and the mutator must
	// stay replayable (Postgres re-runs it against the locked latest draft).
	const secretEnvelope = patch.clientSecret
		? encryptCredential(patch.clientSecret)
		: undefined;
	const { clientSecret: _cs, ...safePatch } = patch;
	const now = nowIso();
	let result: IdentityConnection | undefined;

	store.mutate((data) => {
		const idx = data.identityConnections.findIndex((c) => c.id === conn.id);
		if (idx < 0) {
			throw new ClearanceError({
				code: "SSO_NOT_FOUND",
				message: `SSO connection ${conn.id} not found`,
				stage,
				status: 404,
			});
		}
		const row = data.identityConnections[idx]!;
		const updated: IdentityConnection = {
			...row,
			...safePatch,
			clientSecretFingerprint:
				secretEnvelope?.fingerprint ?? row.clientSecretFingerprint,
			clientSecretEncrypted:
				secretEnvelope?.ciphertext ?? row.clientSecretEncrypted,
			clientSecretKeyId: secretEnvelope?.keyId ?? row.clientSecretKeyId,
			updatedAt: now,
		};
		data.identityConnections[idx] = updated;
		appendAuditEvent(data, {
			actor: opts?.actor ?? "operator",
			action: "sso.configure",
			subjectType: "identity_connection",
			subjectId: conn.id,
			outcome: "success",
			source: (opts?.source as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Configured SSO connection ${conn.id}`,
			metadata: { rotatedSecret: Boolean(patch.clientSecret) },
		});
		result = publicIdentityConnection(updated) as IdentityConnection;
	});

	if (!result) {
		throw new ClearanceError({
			code: "SSO_NOT_FOUND",
			message: `SSO connection ${conn.id} not found`,
			stage,
			status: 404,
		});
	}
	return result;
}

export function listSsoConnections(
	store: ManagementStore,
	organizationId?: string,
): IdentityConnection[] {
	return store.snapshot.identityConnections
		.filter((c) => (organizationId ? c.organizationId === organizationId : true))
		.map((c) => publicIdentityConnection(c) as IdentityConnection);
}

/**
 * Rotate stored SSO client secret envelope under the current credential key.
 * Plaintext is preserved; only AEAD key envelope / fingerprint metadata change.
 * Never returns encrypted material — fingerprints only.
 */
export function rotateSsoCredential(
	store: ManagementStore,
	id: string,
	opts?: SsoMutationOpts,
): IdentityConnection {
	const stage = "sso.rotate";
	const conn = resolveSsoConnection(store, id, {
		scope: opts?.scope,
		stage,
	});
	if (!conn.clientSecretEncrypted) {
		throw new ClearanceError({
			code: "SSO_NO_SECRET",
			message: "No encrypted client secret to rotate",
			stage,
			status: 400,
			remediation:
				"Configure a client secret with clearance sso configure --client-secret before rotating",
		});
	}
	const org = inspectOrganization(
		store,
		conn.organizationId,
		opts?.scope ?? resolveOperatorScope(store),
	);
	const rotated = rotateCredential(conn.clientSecretEncrypted);
	const now = nowIso();
	let result: IdentityConnection | undefined;
	store.mutate((data) => {
		const idx = data.identityConnections.findIndex((c) => c.id === conn.id);
		if (idx < 0) {
			throw new ClearanceError({
				code: "SSO_NOT_FOUND",
				message: `SSO connection ${conn.id} not found`,
				stage,
				status: 404,
			});
		}
		const updated: IdentityConnection = {
			...data.identityConnections[idx]!,
			clientSecretEncrypted: rotated.ciphertext,
			clientSecretKeyId: rotated.keyId,
			clientSecretFingerprint: rotated.fingerprint,
			updatedAt: now,
		};
		data.identityConnections[idx] = updated;
		appendAuditEvent(data, {
			actor: opts?.actor ?? "operator",
			action: "sso.rotate",
			subjectType: "identity_connection",
			subjectId: conn.id,
			outcome: "success",
			source: (opts?.source as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Rotated SSO credential key envelope for ${conn.id}`,
			metadata: {
				keyId: rotated.keyId,
				clientSecretFingerprint: rotated.fingerprint,
				// never: plaintext or ciphertext
			},
		});
		result = publicIdentityConnection(updated) as IdentityConnection;
	});
	if (!result) {
		throw new ClearanceError({
			code: "SSO_NOT_FOUND",
			message: `SSO connection ${conn.id} not found`,
			stage,
			status: 404,
		});
	}
	return result;
}

/**
 * Disable an SSO connection (status=disabled). Idempotent when already disabled.
 * Management-only path; prefer disableSsoConnectionReal when DATABASE_URL is set
 * so runtime ssoProvider rows stay coherent.
 */
export function disableSsoConnection(
	store: ManagementStore,
	id: string,
	opts?: SsoMutationOpts,
): { connection: IdentityConnection; idempotent: boolean } {
	const stage = "sso.disable";
	const conn = resolveSsoConnection(store, id, {
		scope: opts?.scope,
		stage,
	});
	const org = inspectOrganization(
		store,
		conn.organizationId,
		opts?.scope ?? resolveOperatorScope(store),
	);
	const now = nowIso();
	let result: { connection: IdentityConnection; idempotent: boolean } | undefined;
	store.mutate((data) => {
		const idx = data.identityConnections.findIndex((c) => c.id === conn.id);
		if (idx < 0) {
			throw new ClearanceError({
				code: "SSO_NOT_FOUND",
				message: `SSO connection ${conn.id} not found`,
				stage,
				status: 404,
			});
		}
		const row = data.identityConnections[idx]!;
		const alreadyDisabled = row.status === "disabled";
		if (!alreadyDisabled) {
			row.status = "disabled";
			row.updatedAt = now;
		}
		appendAuditEvent(data, {
			actor: opts?.actor ?? "operator",
			action: "sso.disable",
			subjectType: "identity_connection",
			subjectId: conn.id,
			outcome: "success",
			source: (opts?.source as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: alreadyDisabled
				? `SSO connection ${conn.id} already disabled`
				: `Disabled SSO connection ${conn.id}`,
			metadata: {
				idempotent: alreadyDisabled,
				previousStatus: conn.status,
				runtimeRemoved: false,
			},
		});
		result = {
			connection: publicIdentityConnection(row) as IdentityConnection,
			idempotent: alreadyDisabled,
		};
	});
	if (!result) {
		throw new ClearanceError({
			code: "SSO_NOT_FOUND",
			message: `SSO connection ${conn.id} not found`,
			stage,
			status: 404,
		});
	}
	return result;
}

/**
 * Disable SSO connection and remove the matching runtime ssoProvider row.
 * Uses mutateCoordinated when available (Postgres) so management + runtime
 * commit together; otherwise best-effort runtime delete then management disable.
 */
export async function disableSsoConnectionReal(
	store: ManagementStore,
	id: string,
	opts?: SsoMutationOpts,
): Promise<{
	connection: IdentityConnection;
	idempotent: boolean;
	runtimeRemoved: boolean;
}> {
	const stage = "sso.disable";
	const conn = resolveSsoConnection(store, id, {
		scope: opts?.scope,
		stage,
	});
	const org = inspectOrganization(
		store,
		conn.organizationId,
		opts?.scope ?? resolveOperatorScope(store),
	);
	const now = nowIso();

	if (typeof store.mutateCoordinated === "function") {
		return store.mutateCoordinated(async ({ data, query }) => {
			const deleted = await query(`delete from "ssoProvider" where id = $1`, [
				conn.id,
			]);
			const runtimeRemoved = (deleted.rowCount ?? 0) > 0;
			const idx = data.identityConnections.findIndex((c) => c.id === conn.id);
			if (idx < 0) {
				throw new ClearanceError({
					code: "SSO_NOT_FOUND",
					message: `SSO connection ${conn.id} not found`,
					stage,
					status: 404,
				});
			}
			const row = data.identityConnections[idx]!;
			const alreadyDisabled = row.status === "disabled";
			if (!alreadyDisabled) {
				row.status = "disabled";
				row.updatedAt = now;
			}
			appendAuditEvent(data, {
				actor: opts?.actor ?? "operator",
				action: "sso.disable",
				subjectType: "identity_connection",
				subjectId: conn.id,
				outcome: "success",
				source: (opts?.source as "cli") ?? "cli",
				organizationId: org.id,
				projectId: org.projectId,
				environmentId: org.environmentId,
				message: alreadyDisabled
					? `SSO connection ${conn.id} already disabled`
					: `Disabled SSO connection ${conn.id}`,
				metadata: {
					idempotent: alreadyDisabled && !runtimeRemoved,
					previousStatus: conn.status,
					runtimeRemoved,
				},
			});
			return {
				connection: publicIdentityConnection(row) as IdentityConnection,
				idempotent: alreadyDisabled && !runtimeRemoved,
				runtimeRemoved,
			};
		});
	}

	// Fallback: delete runtime first. Database errors must fail closed so the
	// management connection is never reported disabled while runtime stays active.
	await deleteSsoProviderById(conn.id);
	const result = disableSsoConnection(store, id, opts);
	return { ...result, runtimeRemoved: false };
}

export interface SsoTestOptions {
	/**
	 * Lab/fixture path — always simulation mode (not live IdP conformance).
	 * Fail-closed: unknown fixtures throw rather than pass.
	 */
	fixture?:
		| "ok"
		| "wrong-issuer"
		| "wrong-audience"
		| "malformed"
		| "expired"
		| "clock-skew"
		| "replay";
	assertionIssuer?: string;
	assertionAudience?: string;
}

/** All fixture-driven SSO tests are simulation (not live conformance). */
export const SSO_FIXTURE_MODE = "simulation" as const;

function pushTrace(store: ManagementStore, trace: DiagnosticTrace): DiagnosticTrace {
	store.mutate((data) => {
		data.traces.unshift(trace);
		if (data.traces.length > 2000) data.traces.length = 2000;
	});
	return trace;
}

export function testSsoConnection(
	store: ManagementStore,
	id: string,
	opts: SsoTestOptions = {},
): {
	pass: boolean;
	trace: DiagnosticTrace;
	connection: IdentityConnection;
	mode: "simulation";
} {
	const conn = store.snapshot.identityConnections.find((c) => c.id === id);
	if (!conn) {
		throw new ClearanceError({
			code: "SSO_NOT_FOUND",
			message: `SSO connection ${id} not found`,
			stage: "sso.test",
			status: 404,
		});
	}

	const fixture = opts.fixture ?? "ok";
	const allowed = new Set([
		"ok",
		"wrong-issuer",
		"wrong-audience",
		"malformed",
		"expired",
		"clock-skew",
		"replay",
	]);
	if (!allowed.has(fixture)) {
		throw new ClearanceError({
			code: "SSO_UNKNOWN_FIXTURE",
			message: `Unknown SSO fixture "${fixture}" — fail-closed (simulation mode)`,
			stage: "sso.test",
			remediation:
				"Use a known fixture: ok|wrong-issuer|wrong-audience|malformed|expired|clock-skew|replay",
		});
	}
	const corr = `corr_sso_${newId("t").slice(4)}`;
	const base = {
		id: newId("tr"),
		correlationId: corr,
		organizationId: conn.organizationId,
		connectionId: conn.id,
		subsystem: "sso" as const,
		mode: SSO_FIXTURE_MODE,
		createdAt: nowIso(),
	};

	// Stage: parse assertion
	if (fixture === "malformed") {
		const trace = pushTrace(store, {
			...base,
			stage: "assertion.parse",
			outcome: "fail",
			cause: "Malformed SAML/OIDC assertion payload",
			causeConfidence: 0.95,
			owner: "customer",
			remediation:
				"Re-export metadata from the IdP and re-run clearance sso configure; ensure assertion is valid XML/JWT",
			checks: [{ name: "parse", pass: false, detail: "invalid token structure" }],
		});
		recordEvent(store, {
			actor: "system",
			action: "sso.test",
			subjectType: "identity_connection",
			subjectId: id,
			outcome: "failure",
			source: "sso",
			organizationId: conn.organizationId,
			correlationId: corr,
			message: "SSO test failed at assertion.parse",
			metadata: { stage: "assertion.parse", remediation: trace.remediation },
		});
		throw new ClearanceError({
			code: "SSO_ASSERTION_MALFORMED",
			message: "Malformed assertion",
			stage: "assertion.parse",
			remediation: trace.remediation!,
		});
	}

	// Stage: issuer validation
	const effectiveIssuer = opts.assertionIssuer ?? conn.issuer ?? "https://idp.example.com";
	if (fixture === "wrong-issuer" || (conn.issuer && effectiveIssuer !== conn.issuer)) {
		const trace = pushTrace(store, {
			...base,
			stage: "assertion.issuer",
			outcome: "fail",
			cause: "Assertion issuer does not match configured connection issuer",
			causeConfidence: 0.99,
			owner: "customer",
			remediation:
				"Update IdP issuer or run clearance sso configure --issuer <correct-issuer>",
			checks: [
				{ name: "issuer_match", pass: false, detail: `got ${effectiveIssuer}, expected ${conn.issuer}` },
			],
			redactedRequest: { issuer: effectiveIssuer },
		});
		recordEvent(store, {
			actor: "system",
			action: "sso.test",
			subjectType: "identity_connection",
			subjectId: id,
			outcome: "failure",
			source: "sso",
			organizationId: conn.organizationId,
			correlationId: corr,
			message: "SSO test failed at assertion.issuer",
		});
		throw new ClearanceError({
			code: "SSO_WRONG_ISSUER",
			message: "Wrong issuer",
			stage: "assertion.issuer",
			remediation: trace.remediation!,
		});
	}

	// Stage: audience
	const effectiveAud = opts.assertionAudience ?? conn.audience ?? "clearance-sp";
	if (fixture === "wrong-audience" || (conn.audience && effectiveAud !== conn.audience)) {
		const trace = pushTrace(store, {
			...base,
			stage: "assertion.audience",
			outcome: "fail",
			cause: "Audience/EntityID mismatch",
			causeConfidence: 0.98,
			owner: "customer",
			remediation:
				"Align SP EntityID/audience in IdP app config with clearance sso configure --audience",
			checks: [
				{ name: "audience_match", pass: false, detail: `got ${effectiveAud}, expected ${conn.audience}` },
			],
		});
		recordEvent(store, {
			actor: "system",
			action: "sso.test",
			subjectType: "identity_connection",
			subjectId: id,
			outcome: "failure",
			source: "sso",
			organizationId: conn.organizationId,
			correlationId: corr,
			message: "SSO test failed at assertion.audience",
		});
		throw new ClearanceError({
			code: "SSO_WRONG_AUDIENCE",
			message: "Wrong audience",
			stage: "assertion.audience",
			remediation: trace.remediation!,
		});
	}

	if (fixture === "expired") {
		const trace = pushTrace(store, {
			...base,
			stage: "assertion.validity",
			outcome: "fail",
			cause: "Assertion NotOnOrAfter / exp is in the past",
			causeConfidence: 0.97,
			owner: "customer",
			remediation: "Retry sign-in; check IdP clock and assertion lifetime settings",
			checks: [{ name: "not_expired", pass: false }],
		});
		throw new ClearanceError({
			code: "SSO_EXPIRED",
			message: "Expired assertion",
			stage: "assertion.validity",
			remediation: trace.remediation!,
		});
	}

	if (fixture === "clock-skew") {
		const trace = pushTrace(store, {
			...base,
			stage: "assertion.clock",
			outcome: "fail",
			cause: "Clock skew between IdP and Clearance exceeds allowed window",
			causeConfidence: 0.9,
			owner: "customer",
			remediation: "Sync NTP on IdP and Clearance hosts; allowed skew is 120s",
			checks: [{ name: "clock_skew", pass: false, detail: "skew > 120s" }],
		});
		throw new ClearanceError({
			code: "SSO_CLOCK_SKEW",
			message: "Clock skew",
			stage: "assertion.clock",
			remediation: trace.remediation!,
		});
	}

	if (fixture === "replay") {
		const trace = pushTrace(store, {
			...base,
			stage: "assertion.replay",
			outcome: "fail",
			cause: "Assertion ID already consumed",
			causeConfidence: 0.99,
			owner: "application",
			remediation: "Do not reuse assertions; initiate a new IdP login",
			checks: [{ name: "replay_protection", pass: false }],
		});
		throw new ClearanceError({
			code: "SSO_REPLAY",
			message: "Replay detected",
			stage: "assertion.replay",
			remediation: trace.remediation!,
		});
	}

	// success path — require issuer at minimum for active testing
	if (!conn.issuer && conn.protocol === "oidc") {
		const trace = pushTrace(store, {
			...base,
			stage: "connection.config",
			outcome: "fail",
			cause: "OIDC connection missing issuer",
			causeConfidence: 1,
			owner: "application",
			remediation: "Run clearance sso configure --issuer https://idp.example.com",
			checks: [{ name: "issuer_present", pass: false }],
		});
		throw new ClearanceError({
			code: "SSO_CONFIG_INCOMPLETE",
			message: "Missing issuer",
			stage: "connection.config",
			remediation: trace.remediation!,
		});
	}

	const trace = pushTrace(store, {
		...base,
		stage: "assertion.accept",
		outcome: "pass",
		cause: "All protocol stages passed (simulation — fixture lab path)",
		causeConfidence: 1,
		owner: "application",
		checks: [
			{ name: "parse", pass: true },
			{ name: "issuer_match", pass: true },
			{ name: "audience_match", pass: true },
			{ name: "not_expired", pass: true },
			{ name: "replay_protection", pass: true },
			{ name: "mode", pass: true, detail: "simulation" },
		],
	});

	const updated = configureSsoConnection(store, id, { status: "testing" });
	recordEvent(store, {
		actor: "system",
		action: "sso.test",
		subjectType: "identity_connection",
		subjectId: id,
		outcome: "success",
		source: "sso",
		organizationId: conn.organizationId,
		correlationId: corr,
		message: "SSO simulation test passed (not live IdP conformance)",
		metadata: { mode: SSO_FIXTURE_MODE, fixture },
	});

	return { pass: true, trace, connection: updated, mode: SSO_FIXTURE_MODE };
}
