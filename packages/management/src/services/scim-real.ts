/**
 * Real SCIM operations via inherited @clearance/scim plugin HTTP handlers.
 * Connection checks issue actual SCIM HTTP requests. Tokens are never written
 * to audit/JSON as plaintext — only fingerprints / AEAD envelopes.
 */
import { timingSafeEqual } from "node:crypto";
import type { ClearanceKeyManagementFacade } from "@clearance/auth";
import type {
	ManagementCoordinatedQuery,
	ManagementStore,
} from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DiagnosticTrace, DirectoryConnection } from "../types/resources.js";
import {
	deleteScimProviderById,
	insertScimProvider,
	insertScimProviderInTransaction,
	applyScimUsersInTransaction,
	getAuthBundle,
} from "../auth-bridge.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import {
	decryptCredential,
	encryptCredential,
	type CredentialCipher,
} from "./credentials.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganizationAuthoritative } from "./core.js";
import {
	assertScimOperationReplayMatches,
	insertScimOperationReplayAuthority,
	lockScimOperationReplayAuthority,
	requiredScimOperationId,
	scimOperationReplayConnectionStateFingerprint,
	scimOperationReplayRequestFingerprint,
	scimOperationReplayTokenBinding,
	SCIM_LOCAL_PROTOCOL_EVIDENCE,
	resolveScimConnectionAuthoritative,
	type ScimOperationReplayCipher,
	type ScimOperationReplayRequest,
} from "./scim.js";
import { probeOutcomeToError, probeScimEndpoint } from "./scim-probe.js";
import { publicDirectoryConnection } from "./redact.js";
import type { ResourceScope } from "./scope.js";
import { deriveSetupConnectionIds } from "./setup-links.js";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";

export const SCIM_REAL_FIXTURE_MODE = "simulation" as const;
export type ScimTestScenario = "users" | "group-lifecycle";

export type ScimRealMutationGuard = Readonly<{
	authorizeMutation(input: {
		organizationId: string;
		query: ManagementCoordinatedQuery;
	}): Promise<void>;
	/** Exact-scope key-management capability injected by the tenant facade. */
	replayCipher?: ScimOperationReplayCipher;
	credentialCipher?: CredentialCipher;
	runtimeKeyManagement?: ClearanceKeyManagementFacade;
	/**
	 * Exact runtime that owns this tenant's SCIM route and key scope. Hosted
	 * callers inject it so a connection check never falls back to another
	 * host's process-global bundle.
	 */
	scimRuntime?: Readonly<{
		origin: string;
		handler(request: Request): Promise<Response>;
	}>;
}>;

function scimCredentialIdentity(organizationId: string, connectionId: string): Readonly<Record<string, string>> {
	return Object.freeze({ organizationId, connectionId });
}

async function openScimCredential(
	guard: ScimRealMutationGuard | undefined,
	envelope: string,
	organizationId: string,
	connectionId: string,
): Promise<string> {
	return guard?.credentialCipher
		? guard.credentialCipher.open(envelope, scimCredentialIdentity(organizationId, connectionId))
		: decryptCredential(envelope);
}

async function sealScimCredential(
	guard: ScimRealMutationGuard | undefined,
	plaintext: string,
	organizationId: string,
	connectionId: string,
) {
	return guard?.credentialCipher
		? guard.credentialCipher.seal(plaintext, scimCredentialIdentity(organizationId, connectionId))
		: encryptCredential(plaintext);
}

function scimTestRuntime(
	guard: ScimRealMutationGuard | undefined,
): NonNullable<ScimRealMutationGuard["scimRuntime"]> {
	if (guard?.scimRuntime) return guard.scimRuntime;
	const bundle = getAuthBundle();
	return Object.freeze({
		origin: process.env.CLEARANCE_BASE_URL ?? "http://localhost:3300",
		handler: (request: Request) => bundle.auth.handler(request),
	});
}

type GroupLifecycleEvidence = Readonly<{
	scenario: "group-lifecycle";
	group: Readonly<{ id: string; status: "deleted" }>;
	counts: Readonly<{ usersCreated: number; membersCreated: number; membersAfterPatch: number }>;
	actions: Readonly<{ create: number; patch: number; get: number; list: number; delete: number }>;
}>;

const SCIM_SETUP_ENDPOINT = `/api/auth/scim/v2`;

function scimOperationReplayUnavailable(stage: string): ClearanceError {
	return new ClearanceError({
		code: "SCIM_OPERATION_REPLAY_UNAVAILABLE",
		message: "SCIM credential response replay encryption is unavailable",
		stage,
		status: 503,
		remediation: "Restore the configured SCIM bearer-token key provider and retry.",
	});
}

function injectedScimOperationReplayCipher(
	guard: ScimRealMutationGuard | undefined,
	stage: string,
): ScimOperationReplayCipher {
	if (!guard?.replayCipher) throw scimOperationReplayUnavailable(stage);
	return guard.replayCipher;
}

function sameBearer(expected: string, supplied: string): boolean {
	const expectedBytes = Buffer.from(expected, "utf8");
	const suppliedBytes = Buffer.from(supplied, "utf8");
	return expectedBytes.length === suppliedBytes.length && timingSafeEqual(expectedBytes, suppliedBytes);
}

function scimSettlementFingerprint(connection: DirectoryConnection): string {
	return JSON.stringify({
		organizationId: connection.organizationId,
		provider: connection.provider,
		endpoint: connection.endpoint,
		status: connection.status,
		bearerTokenFingerprint: connection.bearerTokenFingerprint ?? null,
		bearerTokenKeyId: connection.bearerTokenKeyId ?? null,
		deprovisioningPolicy: connection.deprovisioningPolicy,
	});
}

function assertScimSettlementCurrent(
	expected: DirectoryConnection,
	current: DirectoryConnection | undefined,
): asserts current is DirectoryConnection {
	if (
		!current ||
		current.status === "disabled" ||
		scimSettlementFingerprint(current) !== scimSettlementFingerprint(expected)
	) {
		throw new ClearanceError({
			code: "SCIM_TEST_SETTLEMENT_CONFLICT",
			message: "SCIM connection changed or was disabled while its test was running",
			stage: "scim.test.settle",
			status: 409,
		});
	}
}

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
		guard?: ScimRealMutationGuard;
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
			query,
			appendAudit,
		}) => {
			await input.guard?.authorizeMutation({
				organizationId: expectedOrganization.id,
				query,
			});
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
			assertScimSettlementCurrent(
				input.connection,
				data.directoryConnections[index],
			);
			const updated = {
				...data.directoryConnections[index]!,
				status: "testing" as const,
				updatedAt: input.trace.createdAt,
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
		assertScimSettlementCurrent(input.connection, data.directoryConnections[index]);
		data.directoryConnections[index] = {
			...data.directoryConnections[index],
			status: "testing",
			updatedAt: input.trace.createdAt,
		};
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

/**
 * The Group scenario has to enter through the same PostgreSQL authorities as
 * a real runtime request. This lock is deliberately a validation-only
 * coordinated transaction: protocol requests below are handled by the
 * bundled runtime, which owns their individual rollback-capable transactions
 * and runtime-audit outbox writes.
 */
async function assertGroupLifecycleEntry(
	store: ManagementStore,
	connection: DirectoryConnection,
	scope: ResourceScope,
	bearerToken: string,
): Promise<void> {
	if (connection.status === "disabled") {
		throw new ClearanceError({
			code: "SCIM_NOT_FOUND",
			message: `SCIM connection ${connection.id} not found`,
			stage: "scim.test",
			status: 404,
		});
	}
	if (store.backend !== "postgres" || typeof store.mutateCoordinated !== "function") {
		throw new ClearanceError({
			code: "SCIM_ATOMIC_APPLY_BACKEND_REQUIRED",
			message: "SCIM group lifecycle requires the coordinated PostgreSQL runtime backend",
			stage: "sync.apply",
			status: 500,
		});
	}
	await mutateCoordinatedWithRuntimeSql(store, async ({ data, topology, query }) => {
		if (!topology) {
			throw new ClearanceError({
				code: "SCIM_ATOMIC_APPLY_BACKEND_REQUIRED",
				message: "SCIM group lifecycle requires normalized topology authority",
				stage: "sync.apply",
				status: 500,
			});
		}
		const organization = await topology.lockOrganization({ scope, id: connection.organizationId });
		const current = data.directoryConnections.find(
			(candidate) => candidate.id === connection.id && candidate.organizationId === connection.organizationId,
		);
		if (!organization || organization.status === "archived" || !current || current.status === "disabled") {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${connection.id} not found`,
				stage: "scim.test",
				status: 404,
			});
		}
		const provider = await query(
			`select id, "providerId", "organizationId" from "scimProvider" where id = $1 and "organizationId" = $2 for update`,
			[connection.id, organization.id],
		);
		if (provider.rows.length !== 1) {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${connection.id} not found`,
				stage: "scim.test",
				status: 404,
			});
		}
		const runtimeProvider = provider.rows[0] as { providerId?: unknown; organizationId?: unknown };
		if (
			typeof runtimeProvider.providerId !== "string" ||
			runtimeProvider.organizationId !== organization.id
		) {
			throw new ClearanceError({
				code: "SCIM_CONNECTION_TOKEN_MISMATCH",
				message: "Runtime SCIM provider identity does not match the requested connection",
				stage: "scim.test",
				status: 409,
			});
		}
		// The bearer encodes the runtime provider and organization. The
		// authenticated request below then proves the remaining base token.
		recoverScimBaseToken(bearerToken, runtimeProvider.providerId, organization.id);
	});
}

async function scimHandlerJson(
	runtime: NonNullable<ScimRealMutationGuard["scimRuntime"]>,
	path: string,
	method: "POST" | "PATCH" | "GET" | "DELETE",
	bearerToken: string,
	body?: Record<string, unknown>,
): Promise<{ status: number; body: Record<string, unknown> | undefined }> {
	const response = await runtime.handler(
		new Request(`${runtime.origin}/api/auth/scim/v2${path}`, {
			method,
			headers: {
				accept: "application/scim+json",
				...(body ? { "content-type": "application/scim+json" } : {}),
				authorization: `Bearer ${bearerToken}`,
				origin: runtime.origin,
			},
			...(body ? { body: JSON.stringify(body) } : {}),
		}),
	);
	if (!response.ok) {
		throw new ClearanceError({
			code: response.status === 401 || response.status === 403 ? "SCIM_UNAUTHORIZED" : "SCIM_GROUP_LIFECYCLE_FAILED",
			message: `SCIM Group lifecycle handler failed (${response.status})`,
			stage: "scim.group-lifecycle",
			status: response.status,
		});
	}
	if (response.status === 204) return { status: response.status, body: undefined };
	const parsed: unknown = await response.json().catch(() => undefined);
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new ClearanceError({
			code: "SCIM_GROUP_LIFECYCLE_FAILED",
			message: "SCIM Group lifecycle handler returned an invalid response",
			stage: "scim.group-lifecycle",
			status: 502,
		});
	}
	return { status: response.status, body: parsed as Record<string, unknown> };
}

async function getScimHandlerStatus(
	runtime: NonNullable<ScimRealMutationGuard["scimRuntime"]>,
	path: string,
	bearerToken: string,
	method: "GET" | "DELETE" = "GET",
): Promise<number> {
	const response = await runtime.handler(new Request(`${runtime.origin}/api/auth/scim/v2${path}`, {
		method,
		headers: { accept: "application/scim+json", authorization: `Bearer ${bearerToken}`, origin: runtime.origin },
	}));
	return response.status;
}

/**
 * Product-owned cleanup for the synthetic users created by this diagnostic.
 * SCIM DELETE first removes its provider/account, organization and team
 * references. Only then can this coordinated seam hard-delete the otherwise
 * global runtime user rows. It refuses any unexpected runtime reference.
 */
async function hardDeleteGeneratedLifecycleUsers(
	store: ManagementStore,
	userIds: readonly string[],
): Promise<void> {
	if (userIds.length === 0) return;
	await mutateCoordinatedWithRuntimeSql(store, async ({ query }) => {
		const users = await query(`select id, email from "user" where id = any($1::text[]) for update`, [userIds]);
		if (users.rows.length !== userIds.length) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_CLEANUP_FAILED", message: "Synthetic SCIM lifecycle user is missing during cleanup", stage: "scim.group-lifecycle", status: 500 });
		const references = await query(
			`select quote_ident(n.nspname) || '.' || quote_ident(c.relname) as relation, quote_ident(a.attname) as column
			 from pg_attribute a join pg_class c on c.oid = a.attrelid join pg_namespace n on n.oid = c.relnamespace
			 where a.attnum > 0 and not a.attisdropped and c.relkind = 'r' and n.nspname = current_schema()
			 and a.attname in ('userId', 'inviterId')`,
		);
		for (const reference of references.rows as Array<{ relation: string; column: string }>) {
			const count = await query(`select count(*)::int as count from ${reference.relation} where ${reference.column} = any($1::text[])`, [userIds]);
			if (Number(count.rows[0]?.count ?? 0) !== 0) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_CLEANUP_FAILED", message: "Synthetic SCIM lifecycle user still has runtime references", stage: "scim.group-lifecycle", status: 500 });
		}
		const emails = users.rows.map((row) => String(row.email).toLowerCase());
		const verification = await query(`select count(*)::int as count from verification where lower(identifier) = any($1::text[])`, [emails]);
		if (Number(verification.rows[0]?.count ?? 0) !== 0) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_CLEANUP_FAILED", message: "Synthetic SCIM lifecycle user still has verification references", stage: "scim.group-lifecycle", status: 500 });
		await query(`delete from "user" where id = any($1::text[])`, [userIds]);
		const remaining = await query(`select count(*)::int as count from "user" where id = any($1::text[])`, [userIds]);
		if (Number(remaining.rows[0]?.count ?? 0) !== 0) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_CLEANUP_FAILED", message: "Synthetic SCIM lifecycle users remain after cleanup", stage: "scim.group-lifecycle", status: 500 });
	});
}

async function applyGroupLifecycleScenario(
	store: ManagementStore,
	connection: DirectoryConnection,
	input: {
		bearerToken: string;
		scope: ResourceScope;
		correlationId: string;
		runtime: NonNullable<ScimRealMutationGuard["scimRuntime"]>;
	},
): Promise<GroupLifecycleEvidence> {
	await assertGroupLifecycleEntry(store, connection, input.scope, input.bearerToken);
	const stamp = input.correlationId.replace(/[^a-z0-9]/gi, "").slice(-18);
	const createdName = `SCIM Lifecycle ${stamp}`;
	const patchedName = `SCIM Lifecycle Updated ${stamp}`;
	let firstUserId: string | undefined;
	let secondUserId: string | undefined;
	let groupId: string | undefined;
	let evidence: GroupLifecycleEvidence | undefined;
	const createUser = async (ordinal: "one" | "two") => {
		const result = await scimHandlerJson(input.runtime, "/Users", "POST", input.bearerToken, {
			userName: `scim-group-${stamp}-${ordinal}@example.invalid`,
			name: { formatted: `SCIM Group ${ordinal}` },
		});
		const id = result.body?.id;
		if (result.status !== 201 || typeof id !== "string" || !id) {
			throw new ClearanceError({
				code: "SCIM_GROUP_LIFECYCLE_FAILED",
				message: "SCIM Group lifecycle user provisioning returned an invalid resource",
				stage: "scim.group-lifecycle",
				status: 502,
			});
		}
		return id;
	};
	const assertGroup = (body: Record<string, unknown> | undefined, id: string, name: string, members: readonly string[]) => {
		const actualMembers = Array.isArray(body?.members) ? body.members.map((member) => typeof member === "object" && member ? (member as { value?: unknown }).value : undefined) : [];
		if (body?.id !== id || body.displayName !== name || actualMembers.length !== members.length || !members.every((member) => actualMembers.includes(member))) {
			throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_FAILED", message: "SCIM Group lifecycle handler returned an unexpected resource", stage: "scim.group-lifecycle", status: 502 });
		}
		return actualMembers as string[];
	};
	try {
		firstUserId = await createUser("one");
		secondUserId = await createUser("two");
		const created = await scimHandlerJson(input.runtime, "/Groups", "POST", input.bearerToken, {
			schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"], displayName: createdName,
			externalId: `scim-lifecycle-${stamp}`, members: [{ value: firstUserId }],
		});
		groupId = typeof created.body?.id === "string" ? created.body.id : undefined;
		if (created.status !== 201 || !groupId) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_FAILED", message: "SCIM Group lifecycle creation returned an invalid resource", stage: "scim.group-lifecycle", status: 502 });
		const createdMembers = assertGroup(created.body, groupId, createdName, [firstUserId]);
		const patched = await scimHandlerJson(input.runtime, `/Groups/${encodeURIComponent(groupId)}`, "PATCH", input.bearerToken, {
			schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			Operations: [{ op: "replace", path: "urn:ietf:params:scim:schemas:core:2.0:Group:displayName", value: patchedName }, { op: "add", path: "members", value: [{ value: secondUserId }] }],
		});
		if (patched.status !== 200) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_FAILED", message: "SCIM Group lifecycle patch failed", stage: "scim.group-lifecycle", status: 502 });
		const patchedMembers = assertGroup(patched.body, groupId, patchedName, [firstUserId, secondUserId]);
		const fetched = await scimHandlerJson(input.runtime, `/Groups/${encodeURIComponent(groupId)}`, "GET", input.bearerToken);
		if (fetched.status !== 200) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_FAILED", message: "SCIM Group lifecycle read failed", stage: "scim.group-lifecycle", status: 502 });
		assertGroup(fetched.body, groupId, patchedName, [firstUserId, secondUserId]);
		const listed = await scimHandlerJson(input.runtime, "/Groups", "GET", input.bearerToken);
		const resources = Array.isArray(listed.body?.Resources) ? listed.body.Resources : [];
		const matching = resources.find((resource) => typeof resource === "object" && resource && (resource as { id?: unknown }).id === groupId) as Record<string, unknown> | undefined;
		if (listed.status !== 200 || typeof listed.body?.totalResults !== "number" || typeof listed.body?.itemsPerPage !== "number" || listed.body.totalResults < resources.length || listed.body.itemsPerPage !== resources.length || !matching) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_FAILED", message: "SCIM Group lifecycle list failed", stage: "scim.group-lifecycle", status: 502 });
		assertGroup(matching, groupId, patchedName, [firstUserId, secondUserId]);
		const deleted = await scimHandlerJson(input.runtime, `/Groups/${encodeURIComponent(groupId)}`, "DELETE", input.bearerToken);
		if (deleted.status !== 204) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_FAILED", message: "SCIM Group lifecycle delete failed", stage: "scim.group-lifecycle", status: 502 });
		const absent = await getScimHandlerStatus(input.runtime, `/Groups/${encodeURIComponent(groupId)}`, input.bearerToken);
		if (absent !== 404) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_FAILED", message: "SCIM Group lifecycle delete was not observable", stage: "scim.group-lifecycle", status: 502 });
		groupId = undefined;
		evidence = { scenario: "group-lifecycle", group: { id: created.body!.id as string, status: "deleted" }, counts: { usersCreated: [firstUserId, secondUserId].length, membersCreated: createdMembers.length, membersAfterPatch: patchedMembers.length }, actions: { create: created.status, patch: patched.status, get: fetched.status, list: listed.status, delete: deleted.status } };
		return evidence;
	} finally {
		const cleanup: string[] = [];
		const hardDeleteIds: string[] = [];
		if (groupId && (await getScimHandlerStatus(input.runtime, `/Groups/${encodeURIComponent(groupId)}`, input.bearerToken)) !== 404) {
			if ((await getScimHandlerStatus(input.runtime, `/Groups/${encodeURIComponent(groupId)}`, input.bearerToken, "DELETE")) !== 204) cleanup.push("group");
		}
		for (const userId of [secondUserId, firstUserId]) {
			if (!userId) continue;
			const deleted = await getScimHandlerStatus(input.runtime, `/Users/${encodeURIComponent(userId)}`, input.bearerToken, "DELETE");
			if (deleted !== 204 || (await getScimHandlerStatus(input.runtime, `/Users/${encodeURIComponent(userId)}`, input.bearerToken)) !== 404) cleanup.push("user");
			else hardDeleteIds.push(userId);
		}
		if (cleanup.length === 0) await hardDeleteGeneratedLifecycleUsers(store, hardDeleteIds);
		if (cleanup.length) throw new ClearanceError({ code: "SCIM_GROUP_LIFECYCLE_CLEANUP_FAILED", message: "SCIM Group lifecycle cleanup failed", stage: "scim.group-lifecycle", status: 500 });
	}
}

async function settleGroupLifecycleSuccess(
	store: ManagementStore,
	connection: DirectoryConnection,
	scope: ResourceScope,
	trace: DiagnosticTrace,
	evidence: GroupLifecycleEvidence,
	bearerToken: string,
	actor?: string,
	source?: "cli" | "console" | "api" | "system",
): Promise<DirectoryConnection> {
	await assertGroupLifecycleEntry(store, connection, scope, bearerToken);
	return mutateCoordinatedWithRuntimeSql(store, async ({ data, topology, query, appendAudit }) => {
		if (!topology) {
			throw new ClearanceError({
				code: "SCIM_ATOMIC_APPLY_BACKEND_REQUIRED",
				message: "SCIM group lifecycle requires normalized topology authority",
				stage: "sync.apply",
				status: 500,
			});
		}
		const organization = await topology.lockOrganization({ scope, id: connection.organizationId });
		const index = data.directoryConnections.findIndex(
			(candidate) => candidate.id === connection.id && candidate.organizationId === organization?.id && candidate.status !== "disabled",
		);
		if (!organization || organization.status === "archived" || index < 0) {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${connection.id} not found`,
				stage: "scim.test",
				status: 404,
			});
		}
		const provider = await query(`select id from "scimProvider" where id = $1 and "organizationId" = $2 for update`, [connection.id, organization.id]);
		if (provider.rows.length !== 1) {
			throw new ClearanceError({ code: "SCIM_NOT_FOUND", message: `SCIM connection ${connection.id} not found`, stage: "scim.test", status: 404 });
		}
		const updated = { ...data.directoryConnections[index]!, status: "testing" as const, updatedAt: nowIso() };
		data.directoryConnections[index] = updated;
		data.traces.unshift(trace);
		appendAudit({
			actor: actor ?? "system", action: "scim.test", subjectType: "directory_connection", subjectId: connection.id,
			outcome: "success", source: source ?? "scim", organizationId: organization.id,
			projectId: organization.projectId, environmentId: organization.environmentId, correlationId: trace.correlationId,
			message: "SCIM Group lifecycle applied through bundled runtime handler",
			metadata: { scenario: evidence.scenario, group: evidence.group, counts: evidence.counts, actions: evidence.actions },
		});
		return updated;
	});
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
		/** Required by tenant creation to recover a committed bearer after response loss. */
		operationId?: string;
	},
	guard?: ScimRealMutationGuard,
): Promise<DirectoryConnection & { bearerTokenOnce?: string }> {
	const operationId = input.operationId === undefined
		? undefined
		: requiredScimOperationId(input.operationId, "scim.create");
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
	const replayCipher = operationId
		? injectedScimOperationReplayCipher(guard, "scim.create")
		: undefined;

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
			await guard?.authorizeMutation({ organizationId: org.id, query });
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
			const actorId = input.actor ?? "operator";
			const source = input.source ?? "cli";
			const replayRequest: ScimOperationReplayRequest | undefined = operationId
				? {
					projectId: active.projectId,
					environmentId: active.environmentId,
					organizationId: active.id,
					operationId,
					operationKind: "create",
					actorId,
					source,
					provider: input.provider,
					endpoint,
				}
				: undefined;
			const replayAuthority = replayRequest
				? await lockScimOperationReplayAuthority(
					query,
					store.scimOperationReplayTable,
					replayRequest,
				)
				: null;
			if (replayAuthority && replayRequest) {
				assertScimOperationReplayMatches(replayAuthority, replayRequest, "scim.create");
				const existing = data.directoryConnections.find(
					(connection) => connection.id === replayAuthority.connectionId,
				);
				if (
					!existing ||
					existing.organizationId !== active.id ||
					existing.provider !== input.provider ||
					existing.endpoint !== endpoint ||
					existing.bearerTokenFingerprint !== replayAuthority.bearerTokenFingerprint ||
					scimOperationReplayConnectionStateFingerprint(existing) !== replayAuthority.connectionStateFingerprint
				) {
					throw new ClearanceError({
						code: "SCIM_OPERATION_REPLAY_CONFLICT",
						message: "SCIM operationId is already bound to a different request or connection state",
						stage: "scim.create",
						status: 409,
					});
				}
				const runtime = await query(
					`select "organizationId" from "scimProvider" where id = $1 for update`,
					[existing.id],
				);
				if (runtime.rows.length !== 1 || runtime.rows[0]?.organizationId !== active.id) {
					throw new ClearanceError({
						code: "SCIM_OPERATION_REPLAY_CONFLICT",
						message: "SCIM operationId is already bound to a different request or connection state",
						stage: "scim.create",
						status: 409,
					});
				}
				let bearerTokenOnce: string;
				try {
					bearerTokenOnce = await replayCipher!.open(
						replayAuthority.bearerTokenEncrypted,
						scimOperationReplayTokenBinding(replayAuthority),
					);
				} catch {
					throw new ClearanceError({
						code: "SCIM_OPERATION_REPLAY_CONFLICT",
						message: "SCIM operationId is already bound to a different request or connection state",
						stage: "scim.create",
						status: 409,
					});
				}
				return {
					...(publicDirectoryConnection(existing) as DirectoryConnection),
					bearerTokenOnce,
				};
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
				const storedBearerToken = await openScimCredential(
					guard,
					prior.bearerTokenEncrypted,
					active.id,
					prior.id,
				);
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
				}, guard?.runtimeKeyManagement);
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
			}, guard?.runtimeKeyManagement);
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
				const bearerTokenOnce = await openScimCredential(
					guard,
					raced.bearerTokenEncrypted,
					active.id,
					raced.id,
				);
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

			const enc = await sealScimCredential(
				guard,
				inserted.token,
				active.id,
				inserted.id,
			);
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
			if (replayRequest) {
				const replayAuthorityToInsert = {
					...replayRequest,
					connectionId: conn.id,
					requestFingerprint: scimOperationReplayRequestFingerprint(replayRequest),
					bearerTokenEncrypted: "",
					bearerTokenFingerprint: enc.fingerprint,
					bearerTokenKeyId: "",
					connectionStateFingerprint: scimOperationReplayConnectionStateFingerprint(conn),
				};
				let replayEnvelope: Readonly<{ envelope: string; keyId: string }>;
				try {
					replayEnvelope = await replayCipher!.seal(
						inserted.token,
						scimOperationReplayTokenBinding(replayAuthorityToInsert),
					);
				} catch {
					throw scimOperationReplayUnavailable("scim.create");
				}
				await insertScimOperationReplayAuthority(query, store.scimOperationReplayTable, {
					...replayAuthorityToInsert,
					bearerTokenEncrypted: replayEnvelope.envelope,
					bearerTokenKeyId: replayEnvelope.keyId,
				});
			}
			appendAudit({
				actor: actorId,
				action: "scim.create",
				subjectType: "directory_connection",
				subjectId: conn.id,
				outcome: "success",
				source,
				organizationId: active.id,
				projectId: active.projectId,
				environmentId: active.environmentId,
				message: `Created SCIM provider ${providerId} via coordinated provider/control settlement`,
				metadata: {
					providerId,
					operationId: operationId ?? null,
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
	if (guard) {
		throw new ClearanceError({
			code: "TENANT_PRODUCT_TRANSACTION_REQUIRED",
			message:
				"Tenant enterprise mutation requires the coordinated PostgreSQL backend",
			stage: "scim.create",
			status: 500,
		});
	}
	if (operationId) {
		throw new ClearanceError({
			code: "TENANT_PRODUCT_TRANSACTION_REQUIRED",
			message: "SCIM credential response replay requires the coordinated PostgreSQL backend",
			stage: "scim.create",
			status: 500,
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
		scenario?: ScimTestScenario;
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
	guard?: ScimRealMutationGuard,
): Promise<{
	pass: boolean;
	trace: DiagnosticTrace;
	proposed: Array<{ action: string; email: string }>;
	connection: DirectoryConnection;
	mode: "simulation";
	evidence?: string;
	groupLifecycle?: GroupLifecycleEvidence;
	externalProviderCertified: false;
}> {
	const conn = await resolveScimConnectionAuthoritative(store, id, {
		scope: opts.scope,
		stage: "scim.test",
	});

	const scenario = opts.scenario ?? "users";
	if (scenario !== "users" && scenario !== "group-lifecycle") {
		throw new ClearanceError({
			code: "SCIM_SCENARIO_INVALID",
			message: "SCIM scenario must be users or group-lifecycle",
			stage: "scim.test",
			status: 400,
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
	const absoluteEndpoint = scenario === "group-lifecycle"
		? null
		: opts.endpointOverride ??
			(/^https?:\/\//i.test(conn.endpoint) ? conn.endpoint : null);

	if (absoluteEndpoint) {
		const token =
			opts.bearerToken ??
			(conn.bearerTokenEncrypted
				? await openScimCredential(guard, conn.bearerTokenEncrypted, conn.organizationId, conn.id)
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
			...(guard ? { guard } : {}),
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
	const storedToken = conn.bearerTokenEncrypted
		? await openScimCredential(guard, conn.bearerTokenEncrypted, conn.organizationId, conn.id)
		: null;
	const token = scenario === "group-lifecycle"
		? (() => {
			if (!storedToken) {
				throw new ClearanceError({ code: "SCIM_UNAUTHORIZED", message: "SCIM group lifecycle requires the requested connection credential", stage: "sync.apply", status: 401 });
			}
			if (opts.bearerToken && !sameBearer(storedToken, opts.bearerToken)) {
				throw new ClearanceError({ code: "SCIM_UNAUTHORIZED", message: "SCIM group lifecycle credential does not match the requested connection", stage: "sync.apply", status: 401 });
			}
			return storedToken;
		})()
		: opts.bearerToken ?? storedToken;
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
		(!dryRun || scenario === "group-lifecycle") &&
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
	const runtime = scimTestRuntime(guard);

	// Always probe ServiceProviderConfig via handler (real SCIM HTTP path)
	const probeRes = await runtime.handler(
		new Request(`${runtime.origin}/api/auth/scim/v2/ServiceProviderConfig`, {
			method: "GET",
			headers: {
				accept: "application/scim+json",
				...(token ? { authorization: `Bearer ${token}` } : {}),
				origin: runtime.origin,
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
	if (scenario === "group-lifecycle" && dryRun) {
		if (!token) {
			throw new ClearanceError({
				code: "SCIM_UNAUTHORIZED",
				message: "SCIM group lifecycle requires the requested connection credential",
				stage: "auth.bearer",
				status: 401,
			});
		}
		const expectedOrganization = await inspectOrganizationAuthoritative(
			store,
			conn.organizationId,
			opts.scope,
		);
		await assertGroupLifecycleEntry(
			store,
			conn,
			opts.scope ?? {
				projectId: expectedOrganization.projectId,
				environmentId: expectedOrganization.environmentId,
			},
			token,
		);
	}
	const plannedGroups = scenario === "group-lifecycle" && dryRun
		? await scimHandlerJson(runtime, "/Groups", "GET", token ?? "")
		: undefined;

	if (scenario === "group-lifecycle") {
		if (dryRun) {
			const trace: DiagnosticTrace = {
				...base,
				stage: "sync.dry_run",
				outcome: "pass",
				cause: "SCIM Group lifecycle planned and unexecuted (dry-run)",
				causeConfidence: 1,
				owner: "application",
				checks: [
					{ name: "auth.bearer", pass: plannedGroups?.status === 200, detail: "authenticated Groups list" },
					{ name: "http_probe", pass: true, detail: "ServiceProviderConfig" },
					{ name: "group_lifecycle", pass: false, detail: "planned; unexecuted" },
				],
			};
			return {
				pass: true,
				trace,
				proposed: [],
				connection: publicDirectoryConnection(conn) as DirectoryConnection,
				mode: SCIM_REAL_FIXTURE_MODE,
				evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
				externalProviderCertified: false,
			};
		}
		if (!token) {
			throw new ClearanceError({
				code: "SCIM_UNAUTHORIZED",
				message: "SCIM apply requires a bearer token",
				stage: "sync.apply",
				status: 401,
			});
		}
		const expectedOrganization = await inspectOrganizationAuthoritative(store, conn.organizationId, opts.scope);
		const scope = opts.scope ?? {
			projectId: expectedOrganization.projectId,
			environmentId: expectedOrganization.environmentId,
		};
		const groupLifecycle = await applyGroupLifecycleScenario(store, conn, {
			bearerToken: token,
			scope,
			correlationId: corr,
			runtime,
		});
		const trace: DiagnosticTrace = {
			...base,
			stage: "sync.apply",
			outcome: "pass",
			cause: "SCIM Group lifecycle applied through bundled runtime handler",
			causeConfidence: 1,
			owner: "application",
			checks: [
				{ name: "auth.bearer", pass: true },
				{ name: "http_probe", pass: true, detail: "ServiceProviderConfig" },
				{ name: "group_lifecycle", pass: true, detail: "create, patch, get, list, delete" },
			],
			redactedResponse: groupLifecycle,
		};
		const connection = await settleGroupLifecycleSuccess(store, conn, scope, trace, groupLifecycle, token, opts.actor, opts.source);
		return {
			pass: true,
			trace,
			proposed: [],
			connection: publicDirectoryConnection(connection) as DirectoryConnection,
			mode: SCIM_REAL_FIXTURE_MODE,
			evidence: SCIM_LOCAL_PROTOCOL_EVIDENCE,
			groupLifecycle,
			externalProviderCertified: false,
		};
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
				detail: `${proposed.length} users planned`,
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
		...(guard ? { guard } : {}),
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
