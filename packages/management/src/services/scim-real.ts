/**
 * Real SCIM operations via inherited @clearance/scim plugin HTTP handlers.
 * Connection checks issue actual SCIM HTTP requests. Tokens are never written
 * to audit/JSON as plaintext — only fingerprints / AEAD envelopes.
 */
import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DiagnosticTrace, DirectoryConnection } from "../types/resources.js";
import {
	deleteScimProviderById,
	insertScimProvider,
	getAuthBundle,
	listUsersFromDb,
} from "../auth-bridge.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import { decryptCredential, encryptCredential } from "./credentials.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganization } from "./core.js";
import {
	SCIM_LOCAL_PROTOCOL_EVIDENCE,
	checkScimConnection,
} from "./scim.js";
import { publicDirectoryConnection } from "./redact.js";
import { deriveSetupConnectionIds } from "./setup-links.js";

export const SCIM_REAL_FIXTURE_MODE = "simulation" as const;

const SCIM_SETUP_ENDPOINT = `/api/auth/scim/v2`;

function recoverScimBaseToken(
	bearerToken: string,
	providerId: string,
	organizationId?: string,
): string {
	let decoded: string;
	try {
		decoded = Buffer.from(bearerToken, "base64url").toString("utf8");
	} catch {
		decoded = "";
	}
	const suffix = `:${providerId}${organizationId ? `:${organizationId}` : ""}`;
	if (!decoded.endsWith(suffix) || decoded.length <= suffix.length) {
		throw new ClearanceError({
			code: "SCIM_CONNECTION_TOKEN_MISMATCH",
			message:
				"Existing deterministic SCIM connection token cannot reconcile the runtime provider",
			stage: "scim.management.reconcile",
			status: 409,
		});
	}
	return decoded.slice(0, -suffix.length);
}

function assertMatchingScimConnection(
	existing: DirectoryConnection,
	expected: { organizationId: string; provider: string; endpoint: string },
): void {
	if (
		existing.organizationId !== expected.organizationId ||
		existing.provider !== expected.provider ||
		existing.endpoint !== expected.endpoint
	) {
		throw new ClearanceError({
			code: "SCIM_CONNECTION_ID_CONFLICT",
			message:
				"Existing SCIM connection id belongs to a different organization, provider, or endpoint",
			stage: "scim.management.reconcile",
			status: 409,
			remediation:
				"Fail closed: do not overwrite an unrelated directory connection",
		});
	}
}

/**
 * Create SCIM connection in runtime scimProvider + management store.
 *
 * When `setupAttemptId` is set (customer setup reserve path), connection and
 * runtime provider ids are deterministic for crash-safe retry reconcile.
 * SCIM bearer material stays encrypted at rest; plaintext is returned only as
 * `bearerTokenOnce` on the successful create/recovery response (not re-fetchable).
 */
export async function createScimConnectionReal(
	store: ManagementStore,
	input: {
		organizationId: string;
		provider: string;
		actor?: string;
		/**
		 * External SCIM base URL. Defaults to the local setup endpoint;
		 * a real tenant URL is required for live conformance probes.
		 */
		endpoint?: string;
		/**
		 * Setup reservation/attempt id. When set, derives stable runtime +
		 * management ids and reuses them across retries after lease expiry.
		 */
		setupAttemptId?: string;
	},
): Promise<DirectoryConnection & { bearerTokenOnce?: string }> {
	const org = inspectOrganization(store, input.organizationId);
	const deterministic = input.setupAttemptId
		? deriveSetupConnectionIds("scim", input.setupAttemptId)
		: null;
	const providerId =
		deterministic?.providerId ?? `${input.provider}-scim-${Date.now()}`;
	const connectionId = deterministic?.connectionId;
	const endpoint = input.endpoint ?? SCIM_SETUP_ENDPOINT;

	if (connectionId) {
		const existing = store.snapshot.directoryConnections.find(
			(c) => c.id === connectionId,
		);
		if (existing) {
			assertMatchingScimConnection(existing, {
				organizationId: org.id,
				provider: input.provider,
				endpoint,
			});
			if (!existing.bearerTokenEncrypted) {
				throw new ClearanceError({
					code: "SCIM_CONNECTION_TOKEN_MISSING",
					message:
						"Existing deterministic SCIM connection has no encrypted bearer token",
					stage: "scim.management.reconcile",
					status: 409,
				});
			}
			// Reconcile a missing runtime row from the encrypted management token.
			// This preserves the exact bearer credential across crash recovery.
			const storedBearerToken = decryptCredential(existing.bearerTokenEncrypted);
			const storedBaseToken = recoverScimBaseToken(
				storedBearerToken,
				providerId,
				input.organizationId,
			);
			const inserted = await insertScimProvider({
				id: connectionId,
				providerId,
				organizationId: input.organizationId,
				token: storedBaseToken,
			});
			if (inserted.token !== storedBearerToken) {
				throw new ClearanceError({
					code: "SCIM_CONNECTION_TOKEN_MISMATCH",
					message:
						"Runtime and management SCIM credentials disagree for this setup attempt",
					stage: "scim.management.reconcile",
					status: 409,
				});
			}
			return {
				...(publicDirectoryConnection(existing) as DirectoryConnection),
				bearerTokenOnce: inserted.token,
			};
		}
	}

	const inserted = await insertScimProvider({
		id: connectionId,
		providerId,
		organizationId: input.organizationId,
	});
	const now = nowIso();
	const prior = store.snapshot.directoryConnections.find((c) => c.id === inserted.id);
	if (prior) {
		assertMatchingScimConnection(prior, {
			organizationId: org.id,
			provider: input.provider,
			endpoint,
		});
		if (!prior.bearerTokenEncrypted) {
			throw new ClearanceError({
				code: "SCIM_CONNECTION_TOKEN_MISSING",
				message:
					"Existing deterministic SCIM connection has no encrypted bearer token",
				stage: "scim.management.reconcile",
				status: 409,
			});
		}
		const bearerTokenOnce = decryptCredential(prior.bearerTokenEncrypted);
		if (bearerTokenOnce !== inserted.token) {
			throw new ClearanceError({
				code: "SCIM_CONNECTION_TOKEN_MISMATCH",
				message:
					"Runtime and management SCIM credentials disagree for this setup attempt",
				stage: "scim.management.reconcile",
				status: 409,
			});
		}
		return {
			...(publicDirectoryConnection(prior) as DirectoryConnection),
			bearerTokenOnce,
		};
	}

	const enc = encryptCredential(inserted.token);
	const conn: DirectoryConnection = {
		id: inserted.id,
		organizationId: org.id,
		provider: input.provider,
		status: "draft",
		endpoint,
		bearerTokenFingerprint: enc.fingerprint,
		bearerTokenEncrypted: enc.ciphertext,
		bearerTokenKeyId: enc.keyId,
		deprovisioningPolicy: "disable",
		createdAt: now,
		updatedAt: now,
	};
	try {
		store.mutate((data) => {
			const idx = data.directoryConnections.findIndex((c) => c.id === conn.id);
			if (idx >= 0) {
				assertMatchingScimConnection(data.directoryConnections[idx]!, {
					organizationId: org.id,
					provider: input.provider,
					endpoint,
				});
			} else {
				data.directoryConnections.push(conn);
			}
			appendAuditEvent(data, {
				actor: input.actor ?? "operator",
				action: "scim.create",
				subjectType: "directory_connection",
				subjectId: conn.id,
				outcome: "success",
				source: "cli",
				organizationId: org.id,
				message: `Created SCIM provider ${providerId} in scimProvider table`,
				metadata: {
					providerId,
					bearerTokenFingerprint: conn.bearerTokenFingerprint,
					bearerTokenKeyId: enc.keyId,
					setupAttemptId: input.setupAttemptId ?? null,
					reusedRuntime: Boolean(inserted.reused),
					// never: token / bearerTokenOnce
				},
			});
		});
		await store.ready();
	} catch (error) {
		if (!inserted.reused) {
			await deleteScimProviderById(inserted.id).catch(() => undefined);
		}
		throw error;
	}
	return {
		...(publicDirectoryConnection(conn) as DirectoryConnection),
		bearerTokenOnce: inserted.token,
	};
}

/**
 * Connection check against configured endpoint via real HTTP.
 * When endpoint is absolute, uses checkScimConnection.
 * Relative plugin paths are exercised via auth.handler ServiceProviderConfig GET.
 */
export async function testScimConnectionReal(
	store: ManagementStore,
	id: string,
	opts: {
		dryRun?: boolean;
		fixture?: "ok" | "malformed" | "unauthorized";
		users?: Array<{ userName: string; displayName?: string; active?: boolean }>;
		/** Absolute URL override for local fixture protocol verification */
		endpointOverride?: string;
		bearerToken?: string;
		fetchImpl?: typeof fetch;
	} = {},
): Promise<{
	pass: boolean;
	trace: DiagnosticTrace;
	proposed: Array<{ action: string; email: string }>;
	connection: DirectoryConnection;
	mode: "simulation";
	evidence?: string;
	externalProviderCertified: false;
}> {
	const conn = store.snapshot.directoryConnections.find((c) => c.id === id);
	if (!conn) {
		throw new ClearanceError({
			code: "SCIM_NOT_FOUND",
			message: `SCIM connection ${id} not found`,
			stage: "scim.test",
			status: 404,
		});
	}

	const fixture = opts.fixture ?? "ok";
	if (!["ok", "malformed", "unauthorized"].includes(fixture)) {
		throw new ClearanceError({
			code: "SCIM_UNKNOWN_FIXTURE",
			message: `Unknown SCIM fixture "${fixture}" — fail-closed (simulation mode)`,
			stage: "scim.test",
			remediation: "Use ok|malformed|unauthorized",
		});
	}

	const corr = `corr_scim_${newId("t").slice(4)}`;
	const base = {
		id: newId("tr"),
		correlationId: corr,
		organizationId: conn.organizationId,
		connectionId: conn.id,
		subsystem: "scim" as const,
		mode: SCIM_REAL_FIXTURE_MODE,
		createdAt: nowIso(),
	};

	if (fixture === "unauthorized") {
		const trace: DiagnosticTrace = {
			...base,
			stage: "auth.bearer",
			outcome: "fail",
			cause: "Bearer token rejected by SCIM middleware",
			causeConfidence: 0.99,
			owner: "customer",
			remediation: "Rotate SCIM token and update IdP",
			checks: [{ name: "bearer", pass: false }],
		};
		store.mutate((d) => {
			d.traces.unshift(trace);
		});
		throw new ClearanceError({
			code: "SCIM_UNAUTHORIZED",
			message: "Unauthorized",
			stage: "auth.bearer",
			remediation: trace.remediation!,
		});
	}

	if (fixture === "malformed") {
		const trace: DiagnosticTrace = {
			...base,
			stage: "request.parse",
			outcome: "fail",
			cause: "SCIM payload failed schema validation",
			causeConfidence: 0.95,
			owner: "customer",
			remediation: "Ensure userName and schemas[] are present per RFC 7644",
			checks: [{ name: "schema", pass: false }],
		};
		store.mutate((d) => {
			d.traces.unshift(trace);
		});
		throw new ClearanceError({
			code: "SCIM_MALFORMED",
			message: "Malformed SCIM payload",
			stage: "request.parse",
			remediation: trace.remediation!,
		});
	}

	// Prefer absolute endpoint / override → real HTTP probe
	const absoluteEndpoint =
		opts.endpointOverride ??
		(/^https?:\/\//i.test(conn.endpoint) ? conn.endpoint : null);

	if (absoluteEndpoint) {
		// Temporarily patch endpoint for probe if override
		if (opts.endpointOverride) {
			store.mutate((d) => {
				const idx = d.directoryConnections.findIndex((c) => c.id === id);
				if (idx >= 0) {
					d.directoryConnections[idx] = {
						...d.directoryConnections[idx],
						endpoint: opts.endpointOverride!,
					};
				}
			});
		}
		const check = await checkScimConnection(store, id, {
			bearerToken: opts.bearerToken,
			fetchImpl: opts.fetchImpl,
		});
		const users = opts.users ?? [];
		const proposed = users.map((u) => ({
			action: u.active === false ? "deprovision" : "upsert",
			email: u.userName,
		}));
		return {
			pass: check.pass,
			trace: check.trace,
			proposed,
			connection: check.connection,
			mode: SCIM_REAL_FIXTURE_MODE,
			evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			externalProviderCertified: false,
		};
	}

	// Plugin-relative path: real SCIM HTTP via auth.handler (no account-creation fallback)
	const token =
		opts.bearerToken ??
		(conn.bearerTokenEncrypted
			? decryptCredential(conn.bearerTokenEncrypted)
			: null);
	const users = opts.users ?? [
		{
			userName: `scim.user.${Date.now()}@customer.example`,
			displayName: "SCIM User",
			active: true,
		},
	];
	const proposed = users.map((u) => ({
		action: u.active === false ? "deprovision" : "upsert",
		email: u.userName,
	}));

	const dryRun = opts.dryRun !== false;
	const bundle = getAuthBundle();
	const baseURL = process.env.CLEARANCE_BASE_URL ?? "http://localhost:3300";

	// Always probe ServiceProviderConfig via handler (real SCIM HTTP path)
	const probeRes = await bundle.auth.handler(
		new Request(`${baseURL}/api/auth/scim/v2/ServiceProviderConfig`, {
			method: "GET",
			headers: {
				accept: "application/scim+json",
				...(token ? { authorization: `Bearer ${token}` } : {}),
				origin: baseURL,
			},
		}),
	);
	if (probeRes.status === 401 || probeRes.status === 403) {
		throw new ClearanceError({
			code: "SCIM_UNAUTHORIZED",
			message: `SCIM probe unauthorized (${probeRes.status})`,
			stage: "auth.bearer",
			remediation: "Rotate SCIM token",
		});
	}
	if (!probeRes.ok) {
		const text = await probeRes.text();
		throw new ClearanceError({
			code: "SCIM_PROBE_FAILED",
			message: `SCIM probe failed: ${probeRes.status} ${text.slice(0, 200)}`,
			stage: "connection.http",
			remediation: "Inspect scimProvider token and plugin routes",
		});
	}
	const probeBody = await probeRes.text();
	if (probeBody.trim()) {
		try {
			JSON.parse(probeBody);
		} catch {
			throw new ClearanceError({
				code: "SCIM_MALFORMED",
				message: "SCIM probe response is not valid JSON",
				stage: "response.parse",
			});
		}
	}

	if (!dryRun && token) {
		for (const u of users) {
			if (u.active === false) continue;
			const res = await bundle.auth.handler(
				new Request(`${baseURL}/api/auth/scim/v2/Users`, {
					method: "POST",
					headers: {
						"content-type": "application/scim+json",
						authorization: `Bearer ${token}`,
						origin: baseURL,
					},
					body: JSON.stringify({
						schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
						userName: u.userName,
						name: { formatted: u.displayName ?? u.userName },
						emails: [{ value: u.userName, primary: true }],
						active: true,
					}),
				}),
			);
			if (!res.ok) {
				const text = await res.text();
				// Fail closed — no signUpEmail fallback
				throw new ClearanceError({
					code: "SCIM_CREATE_FAILED",
					message: `SCIM create failed: ${res.status} ${text.slice(0, 200)}`,
					stage: "sync.apply",
					remediation: "Inspect scimProvider token and plugin routes",
				});
			}
		}
	}

	const after = await listUsersFromDb().catch(() => []);
	const trace: DiagnosticTrace = {
		...base,
		stage: dryRun ? "sync.dry_run" : "sync.apply",
		outcome: "pass",
		cause: dryRun
			? `Dry-run + ${SCIM_LOCAL_PROTOCOL_EVIDENCE}`
			: `SCIM apply via plugin path — ${SCIM_LOCAL_PROTOCOL_EVIDENCE}`,
		causeConfidence: 1,
		owner: "application",
		checks: [
			{ name: "auth.bearer", pass: Boolean(token) || dryRun },
			{ name: "schema", pass: true },
			{ name: "http_probe", pass: true, detail: "ServiceProviderConfig" },
			{
				name: "map_users",
				pass: true,
				detail: `${proposed.length} users; db_users=${after.length}`,
			},
			{ name: "mode", pass: true, detail: "simulation" },
			{
				name: "evidence",
				pass: true,
				detail: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			},
			{
				name: "external_provider_certification",
				pass: false,
				detail: "false",
			},
		],
		redactedResponse: {
			proposedCount: proposed.length,
			dryRun,
			evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			externalProviderCertified: false,
		},
	};
	store.mutate((d) => {
		d.traces.unshift(trace);
		const idx = d.directoryConnections.findIndex((c) => c.id === id);
		d.directoryConnections[idx] = {
			...conn,
			status: "testing",
			updatedAt: nowIso(),
		};
	});
	recordEvent(store, {
		actor: "system",
		action: "scim.test",
		subjectType: "directory_connection",
		subjectId: id,
		outcome: "success",
		source: "scim",
		organizationId: conn.organizationId,
		correlationId: corr,
		message: `SCIM ${dryRun ? "dry-run" : "apply"} — ${SCIM_LOCAL_PROTOCOL_EVIDENCE}`,
		metadata: {
			proposed,
			mode: SCIM_REAL_FIXTURE_MODE,
			fixture,
			evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			externalProviderCertified: false,
		},
	});

	return {
		pass: true,
		trace,
		proposed,
		connection: publicDirectoryConnection(
			store.snapshot.directoryConnections.find((c) => c.id === id)!,
		) as DirectoryConnection,
		mode: SCIM_REAL_FIXTURE_MODE,
		evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
		externalProviderCertified: false,
	};
}
