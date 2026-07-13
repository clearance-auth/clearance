import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DiagnosticTrace, DirectoryConnection } from "../types/resources.js";
import { deleteScimProviderById } from "../auth-bridge.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import {
	decryptCredential,
	encryptCredential,
	rotateCredential,
} from "./credentials.js";
import { ClearanceError } from "./errors.js";
import { addMember, createUser, inspectOrganization } from "./core.js";
import {
	probeOutcomeToError,
	probeScimEndpoint,
} from "./scim-probe.js";
import { publicDirectoryConnection } from "./redact.js";
import {
	resolveOperatorScope,
	type ResourceScope,
} from "./scope.js";

export type ScimActorSource = "cli" | "console" | "api" | "system";

export interface ScimMutationOpts {
	actor?: string;
	source?: ScimActorSource;
	scope?: ResourceScope;
}

/**
 * Resolve a SCIM directory connection under principal-derived org scope.
 * Missing and cross-scope ids fail closed as SCIM_NOT_FOUND.
 */
export function resolveScimConnection(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope; stage?: string },
): DirectoryConnection {
	const stage = opts?.stage ?? "scim.resolve";
	const connectionId = id?.trim();
	if (!connectionId) {
		throw new ClearanceError({
			code: "SCIM_ID_REQUIRED",
			message: "SCIM connection id is required",
			stage,
			status: 400,
		});
	}
	const conn = store.snapshot.directoryConnections.find(
		(c) => c.id === connectionId,
	);
	if (!conn) {
		throw new ClearanceError({
			code: "SCIM_NOT_FOUND",
			message: `SCIM connection ${connectionId} not found`,
			stage,
			status: 404,
		});
	}
	const scope = opts?.scope ?? resolveOperatorScope(store);
	// Fail closed: missing/cross-scope org must not leak as ORG_NOT_FOUND.
	try {
		inspectOrganization(store, conn.organizationId, scope);
	} catch (error) {
		if (
			error instanceof ClearanceError &&
			(error.code === "ORG_NOT_FOUND" || error.status === 404)
		) {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${connectionId} not found`,
				stage,
				status: 404,
			});
		}
		throw error;
	}
	return conn;
}

/** Public inspect — never returns encrypted bearer material. */
export function inspectScimConnection(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope },
): DirectoryConnection {
	const conn = resolveScimConnection(store, id, {
		scope: opts?.scope,
		stage: "scim.inspect",
	});
	return publicDirectoryConnection(conn) as DirectoryConnection;
}

export function createScimConnection(
	store: ManagementStore,
	input: {
		organizationId: string;
		provider: string;
		endpoint?: string;
		bearerToken?: string;
		deprovisioningPolicy?: DirectoryConnection["deprovisioningPolicy"];
		actor?: string;
	},
): DirectoryConnection {
	const org = inspectOrganization(store, input.organizationId);
	const now = nowIso();
	const token =
		input.bearerToken ??
		`scimtok_${newId("tok").replace(/^tok_/, "")}`;
	const enc = encryptCredential(token);
	const conn: DirectoryConnection = {
		id: newId("scim"),
		organizationId: org.id,
		provider: input.provider,
		status: "draft",
		endpoint: input.endpoint ?? `/scim/v2/${org.id}`,
		bearerTokenFingerprint: enc.fingerprint,
		bearerTokenEncrypted: enc.ciphertext,
		bearerTokenKeyId: enc.keyId,
		deprovisioningPolicy: input.deprovisioningPolicy ?? "disable",
		createdAt: now,
		updatedAt: now,
	};
	store.mutate((data) => {
		data.directoryConnections.push(conn);
	});
	recordEvent(store, {
		actor: input.actor ?? "operator",
		action: "scim.create",
		subjectType: "directory_connection",
		subjectId: conn.id,
		outcome: "success",
		source: "cli",
		organizationId: org.id,
		projectId: org.projectId,
		environmentId: org.environmentId,
		message: `Created SCIM connection for ${input.provider}`,
		metadata: {
			bearerTokenFingerprint: enc.fingerprint,
			bearerTokenKeyId: enc.keyId,
			// never: token
		},
	});
	return publicDirectoryConnection(conn) as DirectoryConnection;
}

export function listScimConnections(
	store: ManagementStore,
	organizationId?: string,
): DirectoryConnection[] {
	return store.snapshot.directoryConnections
		.filter((c) =>
			organizationId ? c.organizationId === organizationId : true,
		)
		.map((c) => publicDirectoryConnection(c) as DirectoryConnection);
}

/**
 * Rotate stored SCIM bearer envelope under the current credential key.
 * Plaintext token is preserved; only AEAD envelope / fingerprint metadata change.
 * Never returns encrypted material — fingerprints only.
 */
export function rotateScimCredential(
	store: ManagementStore,
	id: string,
	opts?: ScimMutationOpts,
): DirectoryConnection {
	const stage = "scim.rotate";
	const conn = resolveScimConnection(store, id, {
		scope: opts?.scope,
		stage,
	});
	if (!conn.bearerTokenEncrypted) {
		throw new ClearanceError({
			code: "SCIM_NO_TOKEN",
			message: "No encrypted bearer token to rotate",
			stage,
			status: 400,
			remediation: "Recreate the SCIM connection to mint a bearer token",
		});
	}
	const org = inspectOrganization(
		store,
		conn.organizationId,
		opts?.scope ?? resolveOperatorScope(store),
	);
	const rotated = rotateCredential(conn.bearerTokenEncrypted);
	const now = nowIso();
	let result: DirectoryConnection | undefined;
	store.mutate((data) => {
		const idx = data.directoryConnections.findIndex((c) => c.id === conn.id);
		if (idx < 0) {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${conn.id} not found`,
				stage,
				status: 404,
			});
		}
		const updated: DirectoryConnection = {
			...data.directoryConnections[idx]!,
			bearerTokenEncrypted: rotated.ciphertext,
			bearerTokenKeyId: rotated.keyId,
			bearerTokenFingerprint: rotated.fingerprint,
			updatedAt: now,
		};
		data.directoryConnections[idx] = updated;
		appendAuditEvent(data, {
			actor: opts?.actor ?? "operator",
			action: "scim.rotate",
			subjectType: "directory_connection",
			subjectId: conn.id,
			outcome: "success",
			source: (opts?.source as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Rotated SCIM credential envelope for ${conn.id}`,
			metadata: {
				keyId: rotated.keyId,
				bearerTokenFingerprint: rotated.fingerprint,
				// never: token plaintext or ciphertext
			},
		});
		result = publicDirectoryConnection(updated) as DirectoryConnection;
	});
	if (!result) {
		throw new ClearanceError({
			code: "SCIM_NOT_FOUND",
			message: `SCIM connection ${conn.id} not found`,
			stage,
			status: 404,
		});
	}
	return result;
}

/**
 * Disable a SCIM directory connection (status=disabled). Idempotent when already disabled.
 * Management-only path; prefer disableScimConnectionReal when DATABASE_URL is set
 * so runtime scimProvider rows stay coherent.
 */
export function disableScimConnection(
	store: ManagementStore,
	id: string,
	opts?: ScimMutationOpts,
): { connection: DirectoryConnection; idempotent: boolean } {
	const stage = "scim.disable";
	const conn = resolveScimConnection(store, id, {
		scope: opts?.scope,
		stage,
	});
	const org = inspectOrganization(
		store,
		conn.organizationId,
		opts?.scope ?? resolveOperatorScope(store),
	);
	const now = nowIso();
	let result: { connection: DirectoryConnection; idempotent: boolean } | undefined;
	store.mutate((data) => {
		const idx = data.directoryConnections.findIndex((c) => c.id === conn.id);
		if (idx < 0) {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${conn.id} not found`,
				stage,
				status: 404,
			});
		}
		const row = data.directoryConnections[idx]!;
		const alreadyDisabled = row.status === "disabled";
		if (!alreadyDisabled) {
			row.status = "disabled";
			row.updatedAt = now;
		}
		appendAuditEvent(data, {
			actor: opts?.actor ?? "operator",
			action: "scim.disable",
			subjectType: "directory_connection",
			subjectId: conn.id,
			outcome: "success",
			source: (opts?.source as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: alreadyDisabled
				? `SCIM connection ${conn.id} already disabled`
				: `Disabled SCIM connection ${conn.id}`,
			metadata: {
				idempotent: alreadyDisabled,
				previousStatus: conn.status,
				runtimeRemoved: false,
			},
		});
		result = {
			connection: publicDirectoryConnection(row) as DirectoryConnection,
			idempotent: alreadyDisabled,
		};
	});
	if (!result) {
		throw new ClearanceError({
			code: "SCIM_NOT_FOUND",
			message: `SCIM connection ${conn.id} not found`,
			stage,
			status: 404,
		});
	}
	return result;
}

/**
 * Disable SCIM connection and remove the matching runtime scimProvider row.
 * Coordinated when Postgres mutateCoordinated is available.
 */
export async function disableScimConnectionReal(
	store: ManagementStore,
	id: string,
	opts?: ScimMutationOpts,
): Promise<{
	connection: DirectoryConnection;
	idempotent: boolean;
	runtimeRemoved: boolean;
}> {
	const stage = "scim.disable";
	const conn = resolveScimConnection(store, id, {
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
			const deleted = await query(`delete from "scimProvider" where id = $1`, [
				conn.id,
			]);
			const runtimeRemoved = (deleted.rowCount ?? 0) > 0;
			const idx = data.directoryConnections.findIndex((c) => c.id === conn.id);
			if (idx < 0) {
				throw new ClearanceError({
					code: "SCIM_NOT_FOUND",
					message: `SCIM connection ${conn.id} not found`,
					stage,
					status: 404,
				});
			}
			const row = data.directoryConnections[idx]!;
			const alreadyDisabled = row.status === "disabled";
			if (!alreadyDisabled) {
				row.status = "disabled";
				row.updatedAt = now;
			}
			appendAuditEvent(data, {
				actor: opts?.actor ?? "operator",
				action: "scim.disable",
				subjectType: "directory_connection",
				subjectId: conn.id,
				outcome: "success",
				source: (opts?.source as "cli") ?? "cli",
				organizationId: org.id,
				projectId: org.projectId,
				environmentId: org.environmentId,
				message: alreadyDisabled
					? `SCIM connection ${conn.id} already disabled`
					: `Disabled SCIM connection ${conn.id}`,
				metadata: {
					idempotent: alreadyDisabled && !runtimeRemoved,
					previousStatus: conn.status,
					runtimeRemoved,
				},
			});
			return {
				connection: publicDirectoryConnection(row) as DirectoryConnection,
				idempotent: alreadyDisabled && !runtimeRemoved,
				runtimeRemoved,
			};
		});
	}

	// Delete runtime first. Database errors fail closed so management never
	// reports disabled while the runtime provider remains active.
	await deleteScimProviderById(conn.id);
	const result = disableScimConnection(store, id, opts);
	return { ...result, runtimeRemoved: false };
}

export interface ScimUserPayload {
	userName: string;
	displayName?: string;
	active?: boolean;
	externalId?: string;
}

/** Fixture-driven SCIM apply path is simulation (not live directory conformance). */
export const SCIM_FIXTURE_MODE = "simulation" as const;

/** Local HTTP protocol probe evidence label — not external provider certification. */
export const SCIM_LOCAL_PROTOCOL_EVIDENCE =
	"local protocol verification (not external IdP/directory certification)" as const;

/**
 * Perform an actual SCIM HTTP connection check against the configured endpoint.
 * Network / auth / malformed body / non-success status all fail.
 */
export async function checkScimConnection(
	store: ManagementStore,
	id: string,
	opts: {
		/** Override token (tests); otherwise decrypt stored envelope */
		bearerToken?: string;
		path?: string;
		fetchImpl?: typeof fetch;
	} = {},
): Promise<{
	pass: boolean;
	trace: DiagnosticTrace;
	connection: DirectoryConnection;
	mode: "simulation";
	evidence: typeof SCIM_LOCAL_PROTOCOL_EVIDENCE;
	externalProviderCertified: false;
}> {
	const conn = store.snapshot.directoryConnections.find((c) => c.id === id);
	if (!conn) {
		throw new ClearanceError({
			code: "SCIM_NOT_FOUND",
			message: `SCIM connection ${id} not found`,
			stage: "scim.check",
			status: 404,
		});
	}

	const corr = `corr_scim_chk_${newId("t").slice(4)}`;
	let token = opts.bearerToken;
	if (!token && conn.bearerTokenEncrypted) {
		token = decryptCredential(conn.bearerTokenEncrypted);
	}

	// Relative endpoints cannot be probed over the network
	if (!/^https?:\/\//i.test(conn.endpoint)) {
		const trace: DiagnosticTrace = {
			id: newId("tr"),
			correlationId: corr,
			organizationId: conn.organizationId,
			connectionId: conn.id,
			subsystem: "scim",
			mode: SCIM_FIXTURE_MODE,
			stage: "connection.endpoint",
			outcome: "fail",
			cause: "Endpoint is not an absolute http(s) URL",
			causeConfidence: 1,
			owner: "application",
			remediation: "Set an absolute SCIM base URL on the connection",
			createdAt: nowIso(),
			checks: [
				{ name: "absolute_url", pass: false, detail: conn.endpoint },
				{
					name: "evidence",
					pass: true,
					detail: SCIM_LOCAL_PROTOCOL_EVIDENCE,
				},
			],
		};
		store.mutate((d) => {
			d.traces.unshift(trace);
		});
		throw new ClearanceError({
			code: "SCIM_ENDPOINT_INVALID",
			message: "SCIM endpoint must be an absolute http(s) URL for connection checks",
			stage: "connection.endpoint",
			remediation: trace.remediation!,
		});
	}

	const outcome = await probeScimEndpoint({
		endpoint: conn.endpoint,
		bearerToken: token,
		path: opts.path ?? "/ServiceProviderConfig",
		fetchImpl: opts.fetchImpl,
	});

	if (!outcome.ok) {
		const err = probeOutcomeToError(outcome);
		const trace: DiagnosticTrace = {
			id: newId("tr"),
			correlationId: corr,
			organizationId: conn.organizationId,
			connectionId: conn.id,
			subsystem: "scim",
			mode: SCIM_FIXTURE_MODE,
			stage: err.stage,
			outcome: "fail",
			cause: outcome.message,
			causeConfidence: 0.95,
			owner: outcome.reason === "network" ? "customer" : "customer",
			remediation: err.remediation,
			createdAt: nowIso(),
			checks: [
				{ name: "http_probe", pass: false, detail: outcome.reason },
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
				status: outcome.status,
				reason: outcome.reason,
				evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			},
		};
		store.mutate((d) => {
			d.traces.unshift(trace);
		});
		recordEvent(store, {
			actor: "system",
			action: "scim.check",
			subjectType: "directory_connection",
			subjectId: id,
			outcome: "failure",
			source: "scim",
			organizationId: conn.organizationId,
			correlationId: corr,
			message: `SCIM connection check failed: ${outcome.reason}`,
			metadata: {
				reason: outcome.reason,
				evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
				externalProviderCertified: false,
			},
		});
		throw err;
	}

	const trace: DiagnosticTrace = {
		id: newId("tr"),
		correlationId: corr,
		organizationId: conn.organizationId,
		connectionId: conn.id,
		subsystem: "scim",
		mode: SCIM_FIXTURE_MODE,
		stage: "connection.probe",
		outcome: "pass",
		cause: SCIM_LOCAL_PROTOCOL_EVIDENCE,
		causeConfidence: 1,
		owner: "application",
		createdAt: nowIso(),
		checks: [
			{ name: "http_probe", pass: true, detail: `HTTP ${outcome.status}` },
			{ name: "auth.bearer", pass: Boolean(token) },
			{ name: "response.json", pass: true },
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
			status: outcome.status,
			path: outcome.path,
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
		action: "scim.check",
		subjectType: "directory_connection",
		subjectId: id,
		outcome: "success",
		source: "scim",
		organizationId: conn.organizationId,
		correlationId: corr,
		message: SCIM_LOCAL_PROTOCOL_EVIDENCE,
		metadata: {
			mode: SCIM_FIXTURE_MODE,
			evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			externalProviderCertified: false,
		},
	});

	return {
		pass: true,
		trace,
		connection: publicDirectoryConnection(
			store.snapshot.directoryConnections.find((c) => c.id === id)!,
		) as DirectoryConnection,
		mode: SCIM_FIXTURE_MODE,
		evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
		externalProviderCertified: false,
	};
}

export function testScimConnection(
	store: ManagementStore,
	id: string,
	opts: {
		dryRun?: boolean;
		users?: ScimUserPayload[];
		fixture?: "ok" | "malformed" | "unauthorized";
	} = {},
): {
	pass: boolean;
	trace: DiagnosticTrace;
	proposed: Array<{ action: string; email: string }>;
	connection: DirectoryConnection;
	mode: "simulation";
} {
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
			remediation: "Use a known fixture: ok|malformed|unauthorized",
		});
	}

	const corr = `corr_scim_${newId("t").slice(4)}`;
	if (fixture === "malformed") {
		const trace: DiagnosticTrace = {
			id: newId("tr"),
			correlationId: corr,
			organizationId: conn.organizationId,
			connectionId: conn.id,
			subsystem: "scim",
			mode: SCIM_FIXTURE_MODE,
			stage: "request.parse",
			outcome: "fail",
			cause: "SCIM payload failed schema validation",
			causeConfidence: 0.95,
			owner: "customer",
			remediation: "Ensure userName and schemas[] are present per RFC 7644",
			createdAt: nowIso(),
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

	if (fixture === "unauthorized") {
		const trace: DiagnosticTrace = {
			id: newId("tr"),
			correlationId: corr,
			organizationId: conn.organizationId,
			connectionId: conn.id,
			subsystem: "scim",
			mode: SCIM_FIXTURE_MODE,
			stage: "auth.bearer",
			outcome: "fail",
			cause: "Bearer token rejected",
			causeConfidence: 0.99,
			owner: "customer",
			remediation: "Rotate token with clearance scim rotate and update IdP",
			createdAt: nowIso(),
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

	const users = opts.users ?? [
		{ userName: "alice@customer.example", displayName: "Alice", active: true },
		{ userName: "bob@customer.example", displayName: "Bob", active: true },
	];

	const proposed = users.map((u) => ({
		action: u.active === false ? "deprovision" : "upsert",
		email: u.userName,
	}));

	const dryRun = opts.dryRun !== false;
	if (!dryRun) {
		for (const u of users) {
			if (u.active === false) continue;
			const existing = store.snapshot.principals.find(
				(p) => p.email === u.userName.toLowerCase(),
			);
			const principal =
				existing ??
				createUser(store, {
					email: u.userName,
					name: u.displayName ?? u.userName,
					externalId: u.externalId,
					source: "scim",
				});
			addMember(store, {
				organizationId: conn.organizationId,
				principalId: principal.id,
				role: "member",
				source: "scim",
			});
		}
	}

	const trace: DiagnosticTrace = {
		id: newId("tr"),
		correlationId: corr,
		organizationId: conn.organizationId,
		connectionId: conn.id,
		subsystem: "scim",
		mode: SCIM_FIXTURE_MODE,
		stage: dryRun ? "sync.dry_run" : "sync.apply",
		outcome: "pass",
		cause: dryRun
			? "Dry-run proposed changes (simulation)"
			: "Sync applied to local store (simulation — not live directory)",
		causeConfidence: 1,
		owner: "application",
		createdAt: nowIso(),
		checks: [
			{ name: "auth.bearer", pass: true },
			{ name: "schema", pass: true },
			{ name: "map_users", pass: true, detail: `${proposed.length} users` },
			{ name: "mode", pass: true, detail: "simulation" },
		],
		redactedResponse: { proposedCount: proposed.length, dryRun },
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
		message: `SCIM simulation ${dryRun ? "dry-run" : "apply"} passed (not live directory conformance)`,
		metadata: { proposed, mode: SCIM_FIXTURE_MODE, fixture },
	});

	return {
		pass: true,
		trace,
		proposed,
		connection: publicDirectoryConnection(
			store.snapshot.directoryConnections.find((c) => c.id === id)!,
		) as DirectoryConnection,
		mode: SCIM_FIXTURE_MODE,
	};
}

/**
 * Validate that a SCIM diagnostic trace is visible under principal scope.
 * Used by dry-run and by replay before mutation.
 */
export function inspectScimTrace(
	store: ManagementStore,
	traceId: string,
	opts?: { scope?: ResourceScope },
): DiagnosticTrace {
	const stage = "scim.replay";
	const id = traceId?.trim();
	if (!id) {
		throw new ClearanceError({
			code: "TRACE_ID_REQUIRED",
			message: "SCIM trace id is required",
			stage,
			status: 400,
		});
	}
	const original = store.snapshot.traces.find((t) => t.id === id);
	if (!original || original.subsystem !== "scim") {
		throw new ClearanceError({
			code: "TRACE_NOT_FOUND",
			message: `SCIM trace ${id} not found`,
			stage,
			status: 404,
		});
	}
	const scope = opts?.scope ?? resolveOperatorScope(store);
	// Prefer connection scope when present; otherwise org on the trace.
	if (original.connectionId) {
		resolveScimConnection(store, original.connectionId, { scope, stage });
	} else if (original.organizationId) {
		inspectOrganization(store, original.organizationId, scope);
	} else if (
		original.projectId &&
		original.environmentId &&
		(original.projectId !== scope.projectId ||
			original.environmentId !== scope.environmentId)
	) {
		throw new ClearanceError({
			code: "TRACE_NOT_FOUND",
			message: `SCIM trace ${id} not found`,
			stage,
			status: 404,
		});
	}
	return original;
}

/**
 * Replay a SCIM diagnostic trace under principal-derived scope.
 * Writes a new trace row + audit; never mutates directory connections or tokens.
 */
export function replayScimTrace(
	store: ManagementStore,
	traceId: string,
	opts?: ScimMutationOpts,
): DiagnosticTrace {
	const stage = "scim.replay";
	const original = inspectScimTrace(store, traceId, { scope: opts?.scope });
	const org = original.organizationId
		? inspectOrganization(
				store,
				original.organizationId,
				opts?.scope ?? resolveOperatorScope(store),
			)
		: original.connectionId
			? inspectOrganization(
					store,
					resolveScimConnection(store, original.connectionId, {
						scope: opts?.scope,
						stage,
					}).organizationId,
					opts?.scope ?? resolveOperatorScope(store),
				)
			: null;

	let replay: DiagnosticTrace | undefined;
	store.mutate((d) => {
		const next: DiagnosticTrace = {
			...original,
			id: newId("tr"),
			correlationId: `corr_replay_${newId("t").slice(4)}`,
			createdAt: nowIso(),
			stage: `${original.stage}.replay`,
		};
		d.traces.unshift(next);
		if (d.traces.length > 2000) d.traces.length = 2000;
		appendAuditEvent(d, {
			actor: opts?.actor ?? "operator",
			action: "scim.replay",
			subjectType: "diagnostic_trace",
			subjectId: next.id,
			outcome: "success",
			source: (opts?.source as "cli") ?? "cli",
			organizationId: org?.id ?? original.organizationId,
			projectId: org?.projectId ?? original.projectId,
			environmentId: org?.environmentId ?? original.environmentId,
			message: `Replayed SCIM trace ${original.id}`,
			metadata: {
				originalId: original.id,
				connectionId: original.connectionId ?? null,
				// never: tokens / secrets from redacted request/response
			},
		});
		replay = next;
	});
	if (!replay) {
		throw new ClearanceError({
			code: "TRACE_NOT_FOUND",
			message: `SCIM trace ${traceId} not found`,
			stage,
			status: 404,
		});
	}
	return replay;
}
