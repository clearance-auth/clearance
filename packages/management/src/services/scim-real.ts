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
	insertScimProviderInTransaction,
	applyScimUsersInTransaction,
	getAuthBundle,
	listUsersFromDb,
} from "../auth-bridge.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import { decryptCredential, encryptCredential } from "./credentials.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganizationAuthoritative } from "./core.js";
import {
	SCIM_LOCAL_PROTOCOL_EVIDENCE,
	resolveScimConnectionAuthoritative,
} from "./scim.js";
import { probeOutcomeToError, probeScimEndpoint } from "./scim-probe.js";
import { publicDirectoryConnection } from "./redact.js";
import type { ResourceScope } from "./scope.js";
import { deriveSetupConnectionIds } from "./setup-links.js";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";

export const SCIM_REAL_FIXTURE_MODE = "simulation" as const;

const SCIM_SETUP_ENDPOINT = `/api/auth/scim/v2`;

async function settleScimTestSuccess(
	store: ManagementStore,
	input: {
		connection: DirectoryConnection;
		trace: DiagnosticTrace;
		actor?: string;
		source?: "cli" | "console" | "api" | "system";
		scope?: ResourceScope;
		message: string;
		metadata: Record<string, unknown>;
	},
): Promise<DirectoryConnection> {
	const expectedOrganization = await inspectOrganizationAuthoritative(
		store,
		input.connection.organizationId,
		input.scope,
	);
	const scope = input.scope ?? {
		projectId: expectedOrganization.projectId,
		environmentId: expectedOrganization.environmentId,
	};
	if (store.backend === "postgres" && typeof store.mutateCoordinated === "function") {
		return mutateCoordinatedWithRuntimeSql(store, async ({
			data,
			topology,
			appendAudit,
		}) => {
			const organization = topology
				? await topology.lockOrganization({ scope, id: expectedOrganization.id })
				: data.organizations.find(
					(organization) =>
						organization.id === expectedOrganization.id &&
						organization.projectId === scope.projectId &&
						organization.environmentId === scope.environmentId,
				);
			if (!organization || organization.status === "archived") {
				throw new ClearanceError({
					code: "SCIM_NOT_FOUND",
					message: `SCIM connection ${input.connection.id} not found`,
					stage: "scim.test",
					status: 404,
				});
			}
			const index = data.directoryConnections.findIndex(
				(connection) =>
					connection.id === input.connection.id &&
					connection.organizationId === organization.id,
			);
			if (index < 0) {
				throw new ClearanceError({
					code: "SCIM_NOT_FOUND",
					message: `SCIM connection ${input.connection.id} not found`,
					stage: "scim.test",
					status: 404,
				});
			}
			const updated = {
				...data.directoryConnections[index]!,
				status: "testing" as const,
				updatedAt: nowIso(),
			};
			data.directoryConnections[index] = updated;
			data.traces.unshift({ ...input.trace, mode: SCIM_REAL_FIXTURE_MODE });
			appendAudit({
				actor: input.actor ?? "system",
				action: "scim.test",
				subjectType: "directory_connection",
				subjectId: updated.id,
				outcome: "success",
				source: input.source ?? "scim",
				organizationId: organization.id,
				projectId: organization.projectId,
				environmentId: organization.environmentId,
				correlationId: input.trace.correlationId,
				message: input.message,
				metadata: input.metadata,
			});
			return updated;
		});
	}

	store.mutate((data) => {
		const index = data.directoryConnections.findIndex(
			(connection) => connection.id === input.connection.id,
		);
		if (index >= 0) {
			data.directoryConnections[index] = {
				...data.directoryConnections[index],
				status: "testing",
				updatedAt: nowIso(),
			};
		}
		data.traces.unshift({ ...input.trace, mode: SCIM_REAL_FIXTURE_MODE });
	});
	recordEvent(store, {
		actor: input.actor ?? "system",
		action: "scim.test",
		subjectType: "directory_connection",
		subjectId: input.connection.id,
		outcome: "success",
		source: input.source ?? "scim",
		organizationId: input.connection.organizationId,
		correlationId: input.trace.correlationId,
		message: input.message,
		metadata: input.metadata,
	});
	return store.snapshot.directoryConnections.find(
		(connection) => connection.id === input.connection.id,
	)!;
}

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
		source?: "cli" | "console" | "api" | "system";
		/** Server-derived request scope; callers may not select it from client input. */
		scope?: ResourceScope;
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
	const org = await inspectOrganizationAuthoritative(
		store,
		input.organizationId,
		input.scope,
	);
	const deterministic = input.setupAttemptId
		? deriveSetupConnectionIds("scim", input.setupAttemptId)
		: null;
	const providerId =
		deterministic?.providerId ?? `${input.provider}-scim-${Date.now()}`;
	const connectionId = deterministic?.connectionId;
	const endpoint = input.endpoint ?? SCIM_SETUP_ENDPOINT;

	/* Keep provider credentials, management control state, and audit on the same
	 * PostgreSQL commit boundary. The active scoped lookup is repeated here so
	 * concurrent archive/re-scope rolls this work back rather than leaving a
	 * live SCIM provider behind. JsonStore keeps the explicit fixture/dev path. */
	if (store.backend === "postgres" && typeof store.mutateCoordinated === "function") {
		return mutateCoordinatedWithRuntimeSql(store, async ({
			data,
			topology,
			query,
			appendAudit,
		}) => {
			const active = topology
				? await topology.lockOrganization({
					scope: {
						projectId: org.projectId,
						environmentId: org.environmentId,
					},
					id: org.id,
				})
				: data.organizations.find(
					(organization) =>
						organization.id === org.id &&
						organization.projectId === org.projectId &&
						organization.environmentId === org.environmentId,
				);
			if (!active || active.status === "archived") {
				throw new ClearanceError({
					code: "ORG_NOT_FOUND",
					message: "Organization not found",
					stage: "scim.create",
					status: 404,
				});
			}

			const prior = connectionId
				? data.directoryConnections.find((connection) => connection.id === connectionId)
				: undefined;
			if (prior) {
				assertMatchingScimConnection(prior, {
					organizationId: active.id,
					provider: input.provider,
					endpoint,
				});
				if (!prior.bearerTokenEncrypted) {
					throw new ClearanceError({
						code: "SCIM_CONNECTION_TOKEN_MISSING",
						message: "Existing deterministic SCIM connection has no encrypted bearer token",
						stage: "scim.management.reconcile",
						status: 409,
					});
				}
				const storedBearerToken = decryptCredential(prior.bearerTokenEncrypted);
				const storedBaseToken = recoverScimBaseToken(
					storedBearerToken,
					providerId,
					active.id,
				);
				const inserted = await insertScimProviderInTransaction(query, {
					id: connectionId,
					providerId,
					organizationId: active.id,
					token: storedBaseToken,
				});
				if (inserted.token !== storedBearerToken) {
					throw new ClearanceError({
						code: "SCIM_CONNECTION_TOKEN_MISMATCH",
						message: "Runtime and management SCIM credentials disagree for this setup attempt",
						stage: "scim.management.reconcile",
						status: 409,
					});
				}
				return {
					...(publicDirectoryConnection(prior) as DirectoryConnection),
					bearerTokenOnce: inserted.token,
				};
			}

			const inserted = await insertScimProviderInTransaction(query, {
				id: connectionId,
				providerId,
				organizationId: active.id,
			});
			const raced = data.directoryConnections.find((connection) => connection.id === inserted.id);
			if (raced) {
				assertMatchingScimConnection(raced, {
					organizationId: active.id,
					provider: input.provider,
					endpoint,
				});
				if (!raced.bearerTokenEncrypted) {
					throw new ClearanceError({
						code: "SCIM_CONNECTION_TOKEN_MISSING",
						message: "Existing deterministic SCIM connection has no encrypted bearer token",
						stage: "scim.management.reconcile",
						status: 409,
					});
				}
				const bearerTokenOnce = decryptCredential(raced.bearerTokenEncrypted);
				if (bearerTokenOnce !== inserted.token) {
					throw new ClearanceError({
						code: "SCIM_CONNECTION_TOKEN_MISMATCH",
						message: "Runtime and management SCIM credentials disagree for this setup attempt",
						stage: "scim.management.reconcile",
						status: 409,
					});
				}
				return {
					...(publicDirectoryConnection(raced) as DirectoryConnection),
					bearerTokenOnce,
				};
			}

			const enc = encryptCredential(inserted.token);
			const now = nowIso();
			const conn: DirectoryConnection = {
				id: inserted.id,
				organizationId: active.id,
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
			data.directoryConnections.push(conn);
			appendAudit({
				actor: input.actor ?? "operator",
				action: "scim.create",
				subjectType: "directory_connection",
				subjectId: conn.id,
				outcome: "success",
				source: input.source ?? "cli",
				organizationId: active.id,
				message: `Created SCIM provider ${providerId} via coordinated provider/control settlement`,
				metadata: {
					providerId,
					bearerTokenFingerprint: conn.bearerTokenFingerprint,
					bearerTokenKeyId: enc.keyId,
					setupAttemptId: input.setupAttemptId ?? null,
					reusedRuntime: Boolean(inserted.reused),
				},
			});
			return {
				...(publicDirectoryConnection(conn) as DirectoryConnection),
				bearerTokenOnce: inserted.token,
			};
		});
	}

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
				source: input.source ?? "cli",
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
 * Probe computation occurs before the scoped coordinated settlement.
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
		actor?: string;
		source?: "cli" | "console" | "api" | "system";
		/** Server-derived operator scope. */
		scope?: ResourceScope;
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
	const conn = await resolveScimConnectionAuthoritative(store, id, {
		scope: opts.scope,
		stage: "scim.test",
	});

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
		const token =
			opts.bearerToken ??
			(conn.bearerTokenEncrypted
				? decryptCredential(conn.bearerTokenEncrypted)
				: undefined);
		const outcome = await probeScimEndpoint({
			endpoint: absoluteEndpoint,
			bearerToken: token,
			fetchImpl: opts.fetchImpl,
			path: "/ServiceProviderConfig",
		});
		if (!outcome.ok) throw probeOutcomeToError(outcome);
		const users = opts.users ?? [];
		const proposed = users.map((u) => ({
			action: u.active === false ? "deprovision" : "upsert",
			email: u.userName,
		}));
		const trace: DiagnosticTrace = {
			...base,
			stage: "connection.probe",
			outcome: "pass",
			cause: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			causeConfidence: 1,
			owner: "application",
			checks: [
				{ name: "http_probe", pass: true, detail: `HTTP ${outcome.status}` },
				{ name: "auth.bearer", pass: Boolean(token) },
			],
		};
		const connection = await settleScimTestSuccess(store, {
			connection: conn,
			trace,
			actor: opts.actor,
			source: opts.source,
			scope: opts.scope,
			message: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			metadata: {
				mode: SCIM_REAL_FIXTURE_MODE,
				evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
				externalProviderCertified: false,
			},
		});
		return {
			pass: true,
			trace,
			proposed,
			connection: publicDirectoryConnection(connection) as DirectoryConnection,
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
	if (
		!dryRun &&
		!(store.backend === "postgres" && typeof store.mutateCoordinated === "function")
	) {
		throw new ClearanceError({
			code: "SCIM_ATOMIC_APPLY_BACKEND_REQUIRED",
			message: "SCIM apply requires the coordinated PostgreSQL runtime backend",
			stage: "sync.apply",
			status: 500,
			remediation:
				"Use PostgreSQL with normalized principal and topology authority, or run a dry-run check",
		});
	}
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

	if (!dryRun) {
		if (!token) {
			throw new ClearanceError({
				code: "SCIM_UNAUTHORIZED",
				message: "SCIM apply requires a bearer token",
				stage: "sync.apply",
				status: 401,
			});
		}
		if (store.backend === "postgres" && typeof store.mutateCoordinated === "function") {
			const expectedOrganization = await inspectOrganizationAuthoritative(
				store,
				conn.organizationId,
				opts.scope,
			);
			const scope = opts.scope ?? {
				projectId: expectedOrganization.projectId,
				environmentId: expectedOrganization.environmentId,
			};
			return mutateCoordinatedWithRuntimeSql(store, async ({
				data,
				principals,
				topology,
				query,
				appendAudit,
			}) => {
				if (!principals || !topology) {
					throw new ClearanceError({
						code: "SCIM_ATOMIC_APPLY_BACKEND_REQUIRED",
						message: "SCIM apply requires normalized principal and topology authority",
						stage: "sync.apply",
						status: 500,
					});
				}
				const organization = await topology.lockOrganization({
					scope,
					id: expectedOrganization.id,
				});
				if (!organization || organization.status === "archived") {
					throw new ClearanceError({
						code: "SCIM_NOT_FOUND",
						message: `SCIM connection ${id} not found`,
						stage: "scim.test",
						status: 404,
					});
				}
				const connectionIndex = data.directoryConnections.findIndex(
					(connection) =>
						connection.id === id &&
						connection.organizationId === organization.id,
				);
				if (connectionIndex < 0) {
					throw new ClearanceError({
						code: "SCIM_NOT_FOUND",
						message: `SCIM connection ${id} not found`,
						stage: "scim.test",
						status: 404,
					});
				}
				const timestamp = nowIso();
				const applied = await applyScimUsersInTransaction({
					query,
					principals,
					data,
					connectionId: id,
					organization,
					bearerToken: token,
					users,
					timestamp,
				});
				const trace: DiagnosticTrace = {
					...base,
					stage: "sync.apply",
					outcome: "pass",
					cause: `SCIM apply via coordinated runtime path — ${SCIM_LOCAL_PROTOCOL_EVIDENCE}`,
					causeConfidence: 1,
					owner: "application",
					checks: [
						{ name: "auth.bearer", pass: true },
						{ name: "schema", pass: true },
						{ name: "http_probe", pass: true, detail: "ServiceProviderConfig" },
						{ name: "map_users", pass: true, detail: `${users.length} users` },
					],
					redactedResponse: { ...applied, dryRun: false },
				};
				const updated = {
					...data.directoryConnections[connectionIndex]!,
					status: "testing" as const,
					updatedAt: timestamp,
				};
				data.directoryConnections[connectionIndex] = updated;
				data.traces.unshift(trace);
				appendAudit({
					actor: opts.actor ?? "system",
					action: "scim.test",
					subjectType: "directory_connection",
					subjectId: id,
					outcome: "success",
					source: opts.source ?? "scim",
					organizationId: organization.id,
					projectId: organization.projectId,
					environmentId: organization.environmentId,
					correlationId: corr,
					message: `SCIM apply — ${SCIM_LOCAL_PROTOCOL_EVIDENCE}`,
					metadata: {
						mode: SCIM_REAL_FIXTURE_MODE,
						fixture,
						evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
						externalProviderCertified: false,
						applied,
					},
				});
				return {
					pass: true,
					trace,
					proposed,
					connection: publicDirectoryConnection(updated) as DirectoryConnection,
					mode: SCIM_REAL_FIXTURE_MODE,
					evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
					externalProviderCertified: false,
				};
			});
		}
		throw new ClearanceError({
			code: "SCIM_ATOMIC_APPLY_BACKEND_REQUIRED",
			message: "SCIM apply requires the coordinated PostgreSQL runtime backend",
			stage: "sync.apply",
			status: 500,
			remediation:
				"Use PostgreSQL with normalized principal and topology authority, or run a dry-run check",
		});
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
	const connection = await settleScimTestSuccess(store, {
		connection: conn,
		trace,
		actor: opts.actor,
		source: opts.source,
		scope: opts.scope,
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
		connection: publicDirectoryConnection(connection) as DirectoryConnection,
		mode: SCIM_REAL_FIXTURE_MODE,
		evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
		externalProviderCertified: false,
	};
}
