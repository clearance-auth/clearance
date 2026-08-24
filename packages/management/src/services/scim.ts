import { createHash, randomBytes } from "node:crypto";
import type { ClearanceKeyManagementFacade } from "@clearance/auth";
import { parseKeyEnvelope } from "@clearance/key-management";
import type {
	ManagementCoordinatedQuery,
	ManagementStore,
} from "../store/types.js";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DiagnosticTrace, ScimConnection, Membership, User } from "../types/resources.js";
import {
	deleteScimProviderById,
	invalidateAuthBundles,
	insertScimProviderInTransaction,
} from "../auth-bridge.js";
import {
	appendAuditEvent,
	recordEvent,
	type AuditEventInput,
} from "./audit.js";
import {
	decryptCredential,
	encryptCredential,
	type CredentialCipher,
} from "./credentials.js";
import { ClearanceError } from "./errors.js";
import {
	resolveEnterpriseConnection,
	resolveEnterpriseConnectionAuthoritative,
} from "./enterprise-connection-lifecycle.js";
import { addMember, createUser, inspectOrganization, inspectOrganizationAuthoritative } from "./core.js";
import {
	probeOutcomeToError,
	probeScimEndpoint,
} from "./scim-probe.js";
import { publicDirectoryConnection } from "./redact.js";
import {
	resolveOperatorScope,
	resolveOperatorScopeAuthoritative,
	type ResourceScope,
} from "./scope.js";

export type ScimActorSource = "cli" | "console" | "api" | "system";

export interface ScimMutationOpts {
	actor?: string;
	source?: ScimActorSource;
	scope?: ResourceScope;
	operationId?: string;
}

export type ScimMutationGuard = Readonly<{
	authorizeMutation(input: {
		organizationId: string;
		query: ManagementCoordinatedQuery;
	}): Promise<void>;
	/** Exact-scope key-management capability injected by the runtime facade. */
	replayCipher?: ScimOperationReplayCipher;
	credentialCipher?: CredentialCipher;
	runtimeKeyManagement?: ClearanceKeyManagementFacade;
}>;

function scimCredentialIdentity(organizationId: string, connectionId: string): Readonly<Record<string, string>> {
	return Object.freeze({ organizationId, connectionId });
}

/**
 * Resolve a SCIM directory connection under principal-derived org scope.
 * Missing and cross-scope ids fail closed as SCIM_NOT_FOUND.
 */
export function resolveScimConnection(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope; stage?: string },
): ScimConnection {
	return resolveEnterpriseConnection(store, id, {
		connections: store.snapshot.scimConnections,
		scope: opts?.scope,
		stage: opts?.stage ?? "scim.resolve",
		label: "SCIM",
		idRequiredCode: "SCIM_ID_REQUIRED",
		notFoundCode: "SCIM_NOT_FOUND",
	});
}

export async function resolveScimConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope; stage?: string },
): Promise<ScimConnection> {
	return resolveEnterpriseConnectionAuthoritative(store, id, {
		connections: store.snapshot.scimConnections,
		scope: opts?.scope,
		stage: opts?.stage ?? "scim.resolve",
		label: "SCIM",
		idRequiredCode: "SCIM_ID_REQUIRED",
		notFoundCode: "SCIM_NOT_FOUND",
	});
}

/** Public inspect — never returns encrypted bearer material. */
export function inspectScimConnection(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope },
): ScimConnection {
	const conn = resolveScimConnection(store, id, {
		scope: opts?.scope,
		stage: "scim.inspect",
	});
	return publicDirectoryConnection(conn) as ScimConnection;
}

export async function inspectScimConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope },
): Promise<ScimConnection> {
	const conn = await resolveScimConnectionAuthoritative(store, id, {
		scope: opts?.scope,
		stage: "scim.inspect",
	});
	return publicDirectoryConnection(conn) as ScimConnection;
}

type CreateScimConnectionInput = {
	organizationId: string;
	provider: string;
	endpoint?: string;
	bearerToken?: string;
	deprovisioningPolicy?: ScimConnection["deprovisioningPolicy"];
	actor?: string;
	source?: ScimActorSource;
	/** Server-derived request scope for relational authority. */
	scope?: ResourceScope;
};

function buildScimConnection(
	input: CreateScimConnectionInput,
	org: { id: string; projectId: string; environmentId: string },
): ScimConnection {
	const now = nowIso();
	const token =
		input.bearerToken ??
		`scimtok_${newId("tok").replace(/^tok_/, "")}`;
	const enc = encryptCredential(token);
	const conn: ScimConnection = {
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
	return conn;
}

function scimCreateAuditInput(
	conn: ScimConnection,
	input: CreateScimConnectionInput,
	org: { id: string; projectId: string; environmentId: string },
): AuditEventInput {
	return {
		actor: input.actor ?? "operator",
		action: "scim.create",
		subjectType: "directory_connection",
		subjectId: conn.id,
		outcome: "success",
		source: input.source ?? "cli",
		organizationId: org.id,
		projectId: org.projectId,
		environmentId: org.environmentId,
		message: `Created SCIM connection for ${input.provider}`,
		metadata: {
			bearerTokenFingerprint: conn.bearerTokenFingerprint,
			bearerTokenKeyId: conn.bearerTokenKeyId,
			// never: token
		},
	};
}

export function createScimConnection(
	store: ManagementStore,
	input: CreateScimConnectionInput,
): ScimConnection {
	const organization = inspectOrganization(store, input.organizationId);
	const connection = buildScimConnection(input, organization);
	store.mutate((data) => {
		data.scimConnections.push(connection);
	});
	recordEvent(store, scimCreateAuditInput(connection, input, organization));
	return publicDirectoryConnection(connection) as ScimConnection;
}

export async function createScimConnectionAuthoritative(
	store: ManagementStore,
	input: CreateScimConnectionInput,
): Promise<ScimConnection> {
	if (!store.storeV2Topology?.authoritative) return createScimConnection(store, input);
	if (!store.mutateCoordinated) {
		throw new ClearanceError({
			code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
			message: "Relational topology authority requires a coordinated transaction",
			stage: "scim.create",
			status: 500,
		});
	}
	const scope = input.scope ?? await resolveOperatorScopeAuthoritative(store);
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const organization = topology
			? await topology.lockOrganization({ scope, id: input.organizationId })
			: null;
		if (!organization || organization.status === "archived") {
			throw new ClearanceError({
				code: "ORG_NOT_FOUND",
				message: "Organization not found",
				stage: "orgs.inspect",
				status: 404,
			});
		}
		const connection = buildScimConnection(input, organization);
		data.scimConnections.push(connection);
		appendAudit(scimCreateAuditInput(connection, input, organization));
		return publicDirectoryConnection(connection) as ScimConnection;
	});
}

export function listScimConnections(
	store: ManagementStore,
	organizationId?: string,
): ScimConnection[] {
	return store.snapshot.scimConnections
		.filter((c) =>
			organizationId ? c.organizationId === organizationId : true,
		)
		.map((c) => publicDirectoryConnection(c) as ScimConnection);
}

export type RotatedScimCredential = ScimConnection & Readonly<{
	/** Returned exactly once to the tenant caller; never persisted in audit. */
	bearerTokenOnce?: string;
	replayed: boolean;
}>;

export type ScimOperationReplayKind = "create" | "rotate";

export type ScimOperationReplayAuthority = Readonly<{
	projectId: string;
	environmentId: string;
	organizationId: string;
	operationId: string;
	operationKind: ScimOperationReplayKind;
	actorId: string;
	source: ScimActorSource;
	provider: string;
	endpoint: string;
	connectionId: string;
	requestFingerprint: string;
	bearerTokenEncrypted: string;
	bearerTokenFingerprint: string;
	bearerTokenKeyId: string;
	connectionStateFingerprint: string;
}>;

export type ScimOperationReplayRequest = Omit<
	ScimOperationReplayAuthority,
	| "connectionId"
	| "requestFingerprint"
	| "bearerTokenEncrypted"
	| "bearerTokenFingerprint"
	| "bearerTokenKeyId"
	| "connectionStateFingerprint"
> & Readonly<{
	connectionId?: string;
}>;

export function requiredScimOperationId(value: string | undefined, stage: string): string {
	if (!value || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
		throw new ClearanceError({ code: "TENANT_OPERATION_ID_REQUIRED", message: "A UUID operationId is required", stage, status: 400 });
	}
	return value;
}

function assertScimOperationReplayTable(table: string | undefined): asserts table is string {
	if (!table || !/^[a-z_][a-z0-9_]*$/i.test(table)) {
		throw new ClearanceError({
			code: "TENANT_PRODUCT_TRANSACTION_REQUIRED",
			message: "SCIM credential response replay requires the coordinated PostgreSQL backend",
			stage: "scim.operation-replay",
			status: 500,
		});
	}
}

export function scimOperationReplayRequestFingerprint(
	request: ScimOperationReplayRequest,
): string {
	return createHash("sha256").update(JSON.stringify({
		projectId: request.projectId,
		environmentId: request.environmentId,
		organizationId: request.organizationId,
		operationId: request.operationId,
		operationKind: request.operationKind,
		actorId: request.actorId,
		source: request.source,
		provider: request.provider,
		endpoint: request.endpoint,
		connectionId: request.connectionId ?? null,
	}), "utf8").digest("hex");
}

export function scimOperationReplayConnectionStateFingerprint(
	connection: ScimConnection,
): string {
	return createHash("sha256").update(JSON.stringify({
		organizationId: connection.organizationId,
		provider: connection.provider,
		endpoint: connection.endpoint,
		status: connection.status,
		deprovisioningPolicy: connection.deprovisioningPolicy,
		bearerTokenFingerprint: connection.bearerTokenFingerprint ?? null,
	}), "utf8").digest("hex");
}

function replayConflict(stage: string): ClearanceError {
	return new ClearanceError({
		code: "SCIM_OPERATION_REPLAY_CONFLICT",
		message: "SCIM operationId is already bound to a different request or connection state",
		stage,
		status: 409,
	});
}

function replayCipherUnavailable(stage: string): ClearanceError {
	return new ClearanceError({
		code: "SCIM_OPERATION_REPLAY_UNAVAILABLE",
		message: "SCIM credential response replay encryption is unavailable",
		stage,
		status: 503,
		remediation: "Restore the configured SCIM bearer-token key provider and retry.",
	});
}

function injectedScimOperationReplayCipher(
	guard: ScimMutationGuard | undefined,
	stage: string,
): ScimOperationReplayCipher {
	if (!guard?.replayCipher) throw replayCipherUnavailable(stage);
	return guard.replayCipher;
}

export function assertScimOperationReplayMatches(
	authority: ScimOperationReplayAuthority,
	request: ScimOperationReplayRequest,
	stage: string,
): void {
	if (
		authority.projectId !== request.projectId ||
		authority.environmentId !== request.environmentId ||
		authority.organizationId !== request.organizationId ||
		authority.operationId !== request.operationId ||
		authority.operationKind !== request.operationKind ||
		authority.actorId !== request.actorId ||
		authority.source !== request.source ||
		authority.provider !== request.provider ||
		authority.endpoint !== request.endpoint ||
		authority.requestFingerprint !== scimOperationReplayRequestFingerprint(request) ||
		(request.connectionId !== undefined && authority.connectionId !== request.connectionId)
	) {
		throw replayConflict(stage);
	}
}

export async function lockScimOperationReplayAuthority(
	query: ManagementCoordinatedQuery,
	table: string | undefined,
	request: ScimOperationReplayRequest,
): Promise<ScimOperationReplayAuthority | null> {
	assertScimOperationReplayTable(table);
	// The management snapshot lock serializes normal callers. This additional
	// transaction advisory lock keeps the replay authority safe even if two
	// independently configured management snapshots share one database.
	const lockKey = `${table}:${request.projectId}:${request.environmentId}:${request.organizationId}:${request.operationId}`;
	await query("select pg_advisory_xact_lock(hashtext($1))", [lockKey]);
	const result = await query(
		`select project_id, environment_id, organization_id, operation_id, operation_kind,
			actor_id, source, provider, endpoint, connection_id, request_fingerprint,
			bearer_token_encrypted, bearer_token_fingerprint, bearer_token_key_id, connection_state_fingerprint
		 from ${table}
		 where project_id = $1 and environment_id = $2 and organization_id = $3 and operation_id = $4
		 for update`,
		[request.projectId, request.environmentId, request.organizationId, request.operationId],
	);
	const row = result.rows[0];
	if (!row) return null;
	return {
		projectId: String(row.project_id),
		environmentId: String(row.environment_id),
		organizationId: String(row.organization_id),
		operationId: String(row.operation_id),
		operationKind: row.operation_kind === "rotate" ? "rotate" : "create",
		actorId: String(row.actor_id),
		source: String(row.source) as ScimActorSource,
		provider: String(row.provider),
		endpoint: String(row.endpoint),
		connectionId: String(row.connection_id),
		requestFingerprint: String(row.request_fingerprint),
		bearerTokenEncrypted: String(row.bearer_token_encrypted),
		bearerTokenFingerprint: String(row.bearer_token_fingerprint),
		bearerTokenKeyId: String(row.bearer_token_key_id),
		connectionStateFingerprint: String(row.connection_state_fingerprint),
	};
}

/**
 * Immutable authority used as AAD for the one-time SCIM bearer response.
 * Deliberately excludes mutable connection state and token fingerprints: those
 * are independently checked before a stored response is opened.
 */
export type ScimOperationReplayTokenBinding = Readonly<{
	projectId: string;
	environmentId: string;
	organizationId: string;
	connectionId: string;
	operationId: string;
	operationKind: ScimOperationReplayKind;
	actorId: string;
	source: ScimActorSource;
	provider: string;
	endpoint: string;
}>;

export type ScimOperationReplayCipher = Readonly<{
	seal(
		plaintext: string,
		binding: ScimOperationReplayTokenBinding,
	): Promise<Readonly<{ envelope: string; keyId: string }>>;
	open(envelope: string, binding: ScimOperationReplayTokenBinding): Promise<string>;
}>;

const SCIM_REPLAY_MAX_TEXT_BYTES = 16_384;
const SCIM_REPLAY_MAX_ENDPOINT_BYTES = 4_096;
const SCIM_REPLAY_BINDING_KEYS = [
	"actorId",
	"connectionId",
	"endpoint",
	"environmentId",
	"operationId",
	"operationKind",
	"organizationId",
	"projectId",
	"provider",
	"source",
] as const;

function canonicalScimOperationReplayText(
	value: unknown,
	label: string,
	maximumBytes = 512,
): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.trim() !== value ||
		Buffer.byteLength(value, "utf8") > maximumBytes ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		throw new Error(`SCIM operation replay ${label} is invalid`);
	}
	return value;
}

function canonicalScimOperationReplayToken(
	value: unknown,
): string {
	if (
		typeof value !== "string" ||
		Buffer.byteLength(value, "utf8") === 0 ||
		Buffer.byteLength(value, "utf8") > SCIM_REPLAY_MAX_TEXT_BYTES ||
		Buffer.from(value, "utf8").toString("utf8") !== value ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		throw new Error("SCIM operation replay token is invalid");
	}
	return value;
}

/** Returns the exact canonical AAD identity accepted by the replay cipher. */
export function canonicalScimOperationReplayTokenBinding(
	value: unknown,
): ScimOperationReplayTokenBinding {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("SCIM operation replay binding is invalid");
	}
	const candidate = value as Record<string, unknown>;
	if (
		Object.keys(candidate).sort().join("\u0000") !==
			[...SCIM_REPLAY_BINDING_KEYS].sort().join("\u0000")
	) {
		throw new Error("SCIM operation replay binding fields are invalid");
	}
	const binding = {
		projectId: canonicalScimOperationReplayText(candidate.projectId, "projectId"),
		environmentId: canonicalScimOperationReplayText(candidate.environmentId, "environmentId"),
		organizationId: canonicalScimOperationReplayText(candidate.organizationId, "organizationId"),
		connectionId: canonicalScimOperationReplayText(candidate.connectionId, "connectionId"),
		operationId: canonicalScimOperationReplayText(candidate.operationId, "operationId"),
		operationKind: candidate.operationKind,
		actorId: canonicalScimOperationReplayText(candidate.actorId, "actorId"),
		source: candidate.source,
		provider: canonicalScimOperationReplayText(candidate.provider, "provider"),
		endpoint: canonicalScimOperationReplayText(
			candidate.endpoint,
			"endpoint",
			SCIM_REPLAY_MAX_ENDPOINT_BYTES,
		),
	};
	if (
		(binding.operationKind !== "create" && binding.operationKind !== "rotate") ||
		(binding.source !== "cli" &&
			binding.source !== "console" &&
			binding.source !== "api" &&
			binding.source !== "system")
	) {
		throw new Error("SCIM operation replay binding is invalid");
	}
	return Object.freeze(binding as ScimOperationReplayTokenBinding);
}

function scimOperationReplayTokenResourceId(
	keyManagement: ClearanceKeyManagementFacade,
	binding: ScimOperationReplayTokenBinding,
): string {
	if (
		binding.projectId !== keyManagement.scope.projectId ||
		binding.environmentId !== keyManagement.scope.environmentId
	) {
		throw new Error("SCIM operation replay key scope does not match the authority");
	}
	return keyManagement.resourceId("scim-bearer-token", {
		operationReplayBinding: JSON.stringify(binding),
	});
}

/**
 * Creates the package-private replay cipher from the already-configured SCIM
 * bearer-token provider. It purpose-binds the envelope and makes the complete
 * immutable operation authority its resource/AAD identity.
 */
export function createScimOperationReplayCipher(
	keyManagement: ClearanceKeyManagementFacade,
): ScimOperationReplayCipher {
	const seal = async (
		plaintext: string,
		input: ScimOperationReplayTokenBinding,
	): Promise<Readonly<{ envelope: string; keyId: string }>> => {
		const binding = canonicalScimOperationReplayTokenBinding(input);
		const resourceId = scimOperationReplayTokenResourceId(keyManagement, binding);
		const envelope = await keyManagement.sealText(
			"scim-bearer-token",
			resourceId,
			canonicalScimOperationReplayToken(plaintext),
		);
		const parsed = parseKeyEnvelope(envelope);
		if (
			parsed.purpose !== "scim-bearer-token" ||
			parsed.projectId !== binding.projectId ||
			parsed.environmentId !== binding.environmentId ||
			parsed.resourceId !== resourceId
		) {
			throw new Error("SCIM operation replay envelope is invalid");
		}
		return Object.freeze({ envelope, keyId: parsed.keyId });
	};
	const open = async (
		envelope: string,
		input: ScimOperationReplayTokenBinding,
	): Promise<string> => {
		const binding = canonicalScimOperationReplayTokenBinding(input);
		const resourceId = scimOperationReplayTokenResourceId(keyManagement, binding);
		const parsed = parseKeyEnvelope(envelope);
		if (
			parsed.purpose !== "scim-bearer-token" ||
			parsed.projectId !== binding.projectId ||
			parsed.environmentId !== binding.environmentId ||
			parsed.resourceId !== resourceId
		) {
			throw new Error("SCIM operation replay envelope is invalid");
		}
		return canonicalScimOperationReplayToken(
			await keyManagement.openText("scim-bearer-token", resourceId, envelope),
		);
	};
	return Object.freeze({ seal, open });
}

export function scimOperationReplayTokenBinding(
	authority: Pick<ScimOperationReplayAuthority, keyof ScimOperationReplayTokenBinding>,
): ScimOperationReplayTokenBinding {
	return canonicalScimOperationReplayTokenBinding({
		projectId: authority.projectId,
		environmentId: authority.environmentId,
		organizationId: authority.organizationId,
		connectionId: authority.connectionId,
		operationId: authority.operationId,
		operationKind: authority.operationKind,
		actorId: authority.actorId,
		source: authority.source,
		provider: authority.provider,
		endpoint: authority.endpoint,
	});
}

export async function insertScimOperationReplayAuthority(
	query: ManagementCoordinatedQuery,
	table: string | undefined,
	authority: ScimOperationReplayAuthority,
): Promise<void> {
	assertScimOperationReplayTable(table);
	const result = await query(
		`insert into ${table}
			(project_id, environment_id, organization_id, operation_id, operation_kind, actor_id,
			 source, provider, endpoint, connection_id, request_fingerprint,
			 bearer_token_encrypted, bearer_token_fingerprint, bearer_token_key_id, connection_state_fingerprint)
		 values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		 on conflict do nothing`,
		[
			authority.projectId, authority.environmentId, authority.organizationId,
			authority.operationId, authority.operationKind, authority.actorId,
			authority.source, authority.provider, authority.endpoint, authority.connectionId,
			authority.requestFingerprint, authority.bearerTokenEncrypted,
			authority.bearerTokenFingerprint, authority.bearerTokenKeyId,
			authority.connectionStateFingerprint,
		],
	);
	if (result.rowCount !== 1) throw replayConflict(`scim.${authority.operationKind}`);
}

/**
 * Tenant SCIM rotation replaces the bearer credential. It cannot be performed
 * against the JSON store because the runtime provider and encrypted management
 * record must change in one transaction.
 */
export function rotateScimCredential(
	store: ManagementStore,
	id: string,
	opts?: ScimMutationOpts,
): never {
	// Retain the scope-safe missing-resource contract before refusing the
	// non-transactional backend.
	resolveScimConnection(store, id, { scope: opts?.scope, stage: "scim.rotate" });
	throw new ClearanceError({
		code: "TENANT_PRODUCT_TRANSACTION_REQUIRED",
		message: "SCIM credential replacement requires the coordinated PostgreSQL runtime backend",
		stage: "scim.rotate",
		status: 500,
	});
}

export async function rotateScimCredentialAuthoritative(
	store: ManagementStore,
	id: string,
	opts?: ScimMutationOpts,
	guard?: ScimMutationGuard,
): Promise<RotatedScimCredential> {
	const operationId = requiredScimOperationId(opts?.operationId, "scim.rotate");
	if (store.backend !== "postgres") {
		return rotateScimCredential(store, id, opts);
	}
	if (!store.mutateCoordinated) {
		throw new ClearanceError({
			code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
			message: "Relational topology authority requires a coordinated transaction",
			stage: "scim.rotate",
			status: 500,
		});
	}
	const connectionId = id?.trim();
	if (!connectionId) {
		throw new ClearanceError({
			code: "SCIM_ID_REQUIRED",
			message: "SCIM connection id is required",
			stage: "scim.rotate",
			status: 400,
		});
	}
	const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
	const actorId = opts?.actor ?? "operator";
	const source: ScimActorSource = opts?.source ?? "cli";
	const replayCipher = injectedScimOperationReplayCipher(guard, "scim.rotate");
	const result = await mutateCoordinatedWithRuntimeSql(store, async ({
		data,
		topology,
		appendAudit,
		query,
	}) => {
		const index = data.scimConnections.findIndex((connection) => connection.id === connectionId);
		const connection = index >= 0 ? data.scimConnections[index] : undefined;
		if (!connection) {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${connectionId} not found`,
				stage: "scim.rotate",
				status: 404,
			});
		}
		await guard?.authorizeMutation({ organizationId: connection.organizationId, query });
		const organization = connection
			? topology
				? await topology.lockOrganization({ scope, id: connection.organizationId })
				: data.organizations.find(
					(organization) =>
						organization.id === connection.organizationId &&
						organization.projectId === scope.projectId &&
						organization.environmentId === scope.environmentId,
				)
			: null;
		if (!connection || !organization || organization.status === "archived") {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${connectionId} not found`,
				stage: "scim.rotate",
				status: 404,
			});
		}
		const replayRequest: ScimOperationReplayRequest = {
			projectId: organization.projectId,
			environmentId: organization.environmentId,
			organizationId: organization.id,
			operationId,
			operationKind: "rotate",
			actorId,
			source,
			provider: connection.provider,
			endpoint: connection.endpoint,
			connectionId,
		};
		const replayAuthority = await lockScimOperationReplayAuthority(
			query,
			store.scimOperationReplayTable,
			replayRequest,
		);
		if (replayAuthority) {
			assertScimOperationReplayMatches(replayAuthority, replayRequest, "scim.rotate");
			if (
				connection.bearerTokenFingerprint !== replayAuthority.bearerTokenFingerprint ||
				connection.organizationId !== replayAuthority.organizationId ||
				connection.provider !== replayAuthority.provider ||
				connection.endpoint !== replayAuthority.endpoint ||
				scimOperationReplayConnectionStateFingerprint(connection) !== replayAuthority.connectionStateFingerprint
			) {
				throw replayConflict("scim.rotate");
			}
			const runtime = await query(
				`select "organizationId" from "scimProvider" where id = $1 for update`,
				[connectionId],
			);
			if (runtime.rows.length !== 1 || runtime.rows[0]?.organizationId !== organization.id) {
				throw replayConflict("scim.rotate");
			}
			let bearerTokenOnce: string;
			try {
				bearerTokenOnce = await replayCipher.open(
					replayAuthority.bearerTokenEncrypted,
					scimOperationReplayTokenBinding(replayAuthority),
				);
			} catch {
				throw replayConflict("scim.rotate");
			}
			return {
				...(publicDirectoryConnection(connection) as ScimConnection),
				bearerTokenOnce,
				replayed: true,
			};
		}
		const runtime = await query(
			`select "providerId", "organizationId" from "scimProvider" where id = $1 for update`,
			[connectionId],
		);
		const runtimeProvider = runtime.rows[0] as
			| { providerId?: unknown; organizationId?: unknown }
			| undefined;
		if (
			runtime.rows.length !== 1 ||
			typeof runtimeProvider?.providerId !== "string" ||
			runtimeProvider.organizationId !== organization.id
		) {
			throw new ClearanceError({
				code: "SCIM_ROTATION_CONFLICT",
				message: "Runtime SCIM provider does not match the requested connection",
				stage: "scim.rotate",
				status: 409,
			});
		}
		// A freshly minted base token invalidates the prior bearer at commit.
		const baseToken = `scimtok_${randomBytes(32).toString("base64url")}`;
		await query(`delete from "scimProvider" where id = $1`, [connectionId]);
		const replacement = await insertScimProviderInTransaction(query, {
			id: connectionId,
			providerId: runtimeProvider.providerId,
			organizationId: organization.id,
			token: baseToken,
		}, guard?.runtimeKeyManagement);
		if (replacement.reused) {
			throw new ClearanceError({
				code: "SCIM_ROTATION_CONFLICT",
				message: "SCIM runtime provider changed while replacing its credential",
				stage: "scim.rotate",
				status: 409,
			});
		}
		const encrypted = guard?.credentialCipher
			? await guard.credentialCipher.seal(
				replacement.token,
				scimCredentialIdentity(organization.id, connectionId),
			)
			: encryptCredential(replacement.token);
		const updated: ScimConnection = {
			...connection,
			bearerTokenEncrypted: encrypted.ciphertext,
			bearerTokenKeyId: encrypted.keyId,
			bearerTokenFingerprint: encrypted.fingerprint,
			updatedAt: nowIso(),
		};
		data.scimConnections[index] = updated;
		const replayAuthorityToInsert: ScimOperationReplayAuthority = {
			...replayRequest,
			connectionId,
			requestFingerprint: scimOperationReplayRequestFingerprint(replayRequest),
			bearerTokenEncrypted: "",
			bearerTokenFingerprint: encrypted.fingerprint,
			bearerTokenKeyId: "",
			connectionStateFingerprint: scimOperationReplayConnectionStateFingerprint(updated),
		};
		let replayEnvelope: Readonly<{ envelope: string; keyId: string }>;
		try {
			replayEnvelope = await replayCipher.seal(
				replacement.token,
				scimOperationReplayTokenBinding(replayAuthorityToInsert),
			);
		} catch {
			throw replayCipherUnavailable("scim.rotate");
		}
		await insertScimOperationReplayAuthority(query, store.scimOperationReplayTable, {
			...replayAuthorityToInsert,
			bearerTokenEncrypted: replayEnvelope.envelope,
			bearerTokenKeyId: replayEnvelope.keyId,
		});
		appendAudit({
			actor: actorId,
			action: "scim.rotate",
			subjectType: "directory_connection",
			subjectId: connectionId,
			outcome: "success",
			source,
			organizationId: organization.id,
			projectId: organization.projectId,
			environmentId: organization.environmentId,
			message: `Replaced SCIM bearer credential for ${connectionId}`,
			metadata: {
				operationId,
				keyId: encrypted.keyId,
				bearerTokenFingerprint: encrypted.fingerprint,
				replacement: true,
			},
		});
		return {
			...(publicDirectoryConnection(updated) as ScimConnection),
			bearerTokenOnce: replacement.token,
			replayed: false,
		};
	});
	// The runtime bundle caches provider configuration. Invalidate only after
	// the replacement transaction commits so the next request cannot accept the
	// superseded bearer from an in-memory provider snapshot. This must not wait
	// for a hosted request currently holding the prior runtime lease.
	if (!result.replayed) invalidateAuthBundles();
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
): { connection: ScimConnection; idempotent: boolean } {
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
	let result: { connection: ScimConnection; idempotent: boolean } | undefined;
	store.mutate((data) => {
		const idx = data.scimConnections.findIndex((c) => c.id === conn.id);
		if (idx < 0) {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${conn.id} not found`,
				stage,
				status: 404,
			});
		}
		const row = data.scimConnections[idx]!;
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
			connection: publicDirectoryConnection(row) as ScimConnection,
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

/** Management-only disable that remains topology-authoritative after cutover. */
export async function disableScimConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	opts?: ScimMutationOpts,
): Promise<{ connection: ScimConnection; idempotent: boolean }> {
	if (!store.storeV2Topology?.authoritative) return disableScimConnection(store, id, opts);
	if (!store.mutateCoordinated) {
		throw new ClearanceError({ code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED", message: "Relational topology authority requires a coordinated transaction", stage: "scim.disable", status: 500 });
	}
	const connectionId = id.trim();
	if (!connectionId) throw new ClearanceError({ code: "SCIM_ID_REQUIRED", message: "SCIM connection id is required", stage: "scim.disable", status: 400 });
	const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const index = data.scimConnections.findIndex((connection) => connection.id === connectionId);
		const connection = index >= 0 ? data.scimConnections[index] : undefined;
		const organization = connection && topology ? await topology.lockOrganization({ scope, id: connection.organizationId }) : null;
		if (!connection || !organization || organization.status === "archived") throw new ClearanceError({ code: "SCIM_NOT_FOUND", message: `SCIM connection ${connectionId} not found`, stage: "scim.disable", status: 404 });
		const alreadyDisabled = connection.status === "disabled";
		const updated = alreadyDisabled ? connection : { ...connection, status: "disabled" as const, updatedAt: nowIso() };
		data.scimConnections[index] = updated;
		appendAudit({ actor: opts?.actor ?? "operator", action: "scim.disable", subjectType: "directory_connection", subjectId: connectionId, outcome: "success", source: opts?.source ?? "cli", organizationId: organization.id, projectId: organization.projectId, environmentId: organization.environmentId, message: alreadyDisabled ? `SCIM connection ${connectionId} already disabled` : `Disabled SCIM connection ${connectionId}`, metadata: { idempotent: alreadyDisabled, previousStatus: connection.status, runtimeRemoved: false } });
		return { connection: publicDirectoryConnection(updated) as ScimConnection, idempotent: alreadyDisabled };
	});
}

/**
 * Disable SCIM connection and remove the matching runtime scimProvider row.
 * Coordinated when Postgres mutateCoordinated is available.
 */
export async function disableScimConnectionReal(
	store: ManagementStore,
	id: string,
	opts?: ScimMutationOpts,
	guard?: ScimMutationGuard,
): Promise<{
	connection: ScimConnection;
	idempotent: boolean;
	runtimeRemoved: boolean;
}> {
	const stage = "scim.disable";
	if (store.storeV2Topology?.authoritative) {
		if (!store.mutateCoordinated) {
			throw new ClearanceError({
				code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
				message: "Relational topology authority requires a coordinated transaction",
				stage,
				status: 500,
			});
		}
		const connectionId = id?.trim();
		if (!connectionId) {
			throw new ClearanceError({
				code: "SCIM_ID_REQUIRED",
				message: "SCIM connection id is required",
				stage,
				status: 400,
			});
		}
		const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
		return mutateCoordinatedWithRuntimeSql(store, async ({
			data,
			query,
			topology,
			appendAudit,
		}) => {
			const index = data.scimConnections.findIndex(
				(connection) => connection.id === connectionId,
			);
			const connection = index >= 0 ? data.scimConnections[index] : undefined;
			if (!connection) {
				throw new ClearanceError({ code: "SCIM_NOT_FOUND", message: `SCIM connection ${connectionId} not found`, stage, status: 404 });
			}
			await guard?.authorizeMutation({ organizationId: connection.organizationId, query });
			const organization = connection && topology
				? await topology.lockOrganization({ scope, id: connection.organizationId })
				: null;
			if (!connection || !organization || organization.status === "archived") {
				throw new ClearanceError({
					code: "SCIM_NOT_FOUND",
					message: `SCIM connection ${connectionId} not found`,
					stage,
					status: 404,
				});
			}
			const deleted = await query(`delete from "scimProvider" where id = $1`, [connectionId]);
			const runtimeRemoved = (deleted.rowCount ?? 0) > 0;
			const alreadyDisabled = connection.status === "disabled";
			const updated = alreadyDisabled
				? connection
				: { ...connection, status: "disabled" as const, updatedAt: nowIso() };
			data.scimConnections[index] = updated;
			appendAudit({
				actor: opts?.actor ?? "operator",
				action: "scim.disable",
				subjectType: "directory_connection",
				subjectId: connectionId,
				outcome: "success",
				source: opts?.source ?? "cli",
				organizationId: organization.id,
				projectId: organization.projectId,
				environmentId: organization.environmentId,
				message: alreadyDisabled
					? `SCIM connection ${connectionId} already disabled`
					: `Disabled SCIM connection ${connectionId}`,
				metadata: {
					idempotent: alreadyDisabled && !runtimeRemoved,
					previousStatus: connection.status,
					runtimeRemoved,
				},
			});
			return {
				connection: publicDirectoryConnection(updated) as ScimConnection,
				idempotent: alreadyDisabled && !runtimeRemoved,
				runtimeRemoved,
			};
		});
	}
	const conn = await resolveScimConnectionAuthoritative(store, id, {
		scope: opts?.scope,
		stage,
	});
	const org = await inspectOrganizationAuthoritative(
		store,
		conn.organizationId,
		opts?.scope ?? resolveOperatorScope(store),
	);
	const now = nowIso();

	if (typeof store.mutateCoordinated === "function") {
		return mutateCoordinatedWithRuntimeSql(store, async ({ data, query }) => {
			await guard?.authorizeMutation({
				organizationId: org.id,
				query,
			});
			const deleted = await query(`delete from "scimProvider" where id = $1`, [
				conn.id,
			]);
			const runtimeRemoved = (deleted.rowCount ?? 0) > 0;
			const idx = data.scimConnections.findIndex((c) => c.id === conn.id);
			if (idx < 0) {
				throw new ClearanceError({
					code: "SCIM_NOT_FOUND",
					message: `SCIM connection ${conn.id} not found`,
					stage,
					status: 404,
				});
			}
			const row = data.scimConnections[idx]!;
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
				connection: publicDirectoryConnection(row) as ScimConnection,
				idempotent: alreadyDisabled && !runtimeRemoved,
				runtimeRemoved,
			};
		});
	}
	if (guard) {
		throw new ClearanceError({
			code: "TENANT_PRODUCT_TRANSACTION_REQUIRED",
			message:
				"Tenant enterprise mutation requires the coordinated PostgreSQL backend",
			stage,
			status: 500,
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
export async function probeScimConnection(
	store: ManagementStore,
	id: string,
	opts: {
		/** Override token (tests); otherwise decrypt stored envelope */
		bearerToken?: string;
		path?: string;
		fetchImpl?: typeof fetch;
		actor?: string;
		source?: ScimActorSource;
		scope?: ResourceScope;
	} = {},
): Promise<{
	pass: boolean;
	trace: DiagnosticTrace;
	connection: ScimConnection;
	mode: "simulation";
	evidence: typeof SCIM_LOCAL_PROTOCOL_EVIDENCE;
	externalProviderCertified: false;
}> {
	const conn = await resolveScimConnectionAuthoritative(store, id, { scope: opts.scope, stage: "scim.check" });

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
			actor: opts.actor ?? "system",
			action: "scim.check",
			subjectType: "directory_connection",
			subjectId: id,
			outcome: "failure",
			source: opts.source ?? "scim",
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
		const idx = d.scimConnections.findIndex((c) => c.id === id);
		d.scimConnections[idx] = {
			...conn,
			status: "testing",
			updatedAt: nowIso(),
		};
	});
	recordEvent(store, {
		actor: opts.actor ?? "system",
		action: "scim.check",
		subjectType: "directory_connection",
		subjectId: id,
		outcome: "success",
		source: opts.source ?? "scim",
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
			store.snapshot.scimConnections.find((c) => c.id === id)!,
		) as ScimConnection,
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
		actor?: string;
		source?: ScimActorSource;
		scope?: ResourceScope;
	} = {},
): {
	pass: boolean;
	trace: DiagnosticTrace;
	proposed: Array<{ action: string; email: string }>;
	connection: ScimConnection;
	mode: "simulation";
} {
	const conn = resolveScimConnection(store, id, { scope: opts.scope, stage: "scim.test" });

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
					projectId: opts.scope?.projectId,
					environmentId: opts.scope?.environmentId,
				});
			addMember(store, {
				organizationId: conn.organizationId,
				principalId: principal.id,
				role: "member",
				source: "scim",
				scope: opts.scope,
			});
		}
	}

	const successTimestamp = nowIso();
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
		createdAt: successTimestamp,
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
		const idx = d.scimConnections.findIndex((c) => c.id === id);
		d.scimConnections[idx] = {
			...conn,
			status: "testing",
			updatedAt: successTimestamp,
		};
	});
	recordEvent(store, {
		actor: opts.actor ?? "system",
		action: "scim.test",
		subjectType: "directory_connection",
		subjectId: id,
		outcome: "success",
		source: opts.source ?? "scim",
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
			store.snapshot.scimConnections.find((c) => c.id === id)!,
		) as ScimConnection,
		mode: SCIM_FIXTURE_MODE,
	};
}

/** Fixture apply using the typed relational principal repository after cutover. */
export async function testScimConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	opts: {
		dryRun?: boolean;
		users?: ScimUserPayload[];
		fixture?: "ok" | "malformed" | "unauthorized";
		actor?: string;
		source?: ScimActorSource;
		scope?: ResourceScope;
	} = {},
): Promise<ReturnType<typeof testScimConnection>> {
	const topologyAuthoritative = store.storeV2Topology?.authoritative === true;
	const principalsAuthoritative = store.storeV2Principals?.authoritative === true;
	if (!topologyAuthoritative && !principalsAuthoritative) {
		return testScimConnection(store, id, opts);
	}
	if (!store.mutateCoordinated) {
		throw new ClearanceError({
			code: "STORE_V2_PRINCIPAL_TRANSACTION_REQUIRED",
			message: "Relational principal authority requires a coordinated transaction",
			stage: "scim.test",
			status: 500,
		});
	}
	await store.ready();
	const fixture = opts.fixture ?? "ok";
	if (!["ok", "malformed", "unauthorized"].includes(fixture)) {
		throw new ClearanceError({
			code: "SCIM_UNKNOWN_FIXTURE",
			message: `Unknown SCIM fixture "${fixture}" — fail-closed (simulation mode)`,
			stage: "scim.test",
			remediation: "Use a known fixture: ok|malformed|unauthorized",
		});
	}
	const users = opts.users ?? [
		{ userName: "alice@customer.example", displayName: "Alice", active: true },
		{ userName: "bob@customer.example", displayName: "Bob", active: true },
	];
	const proposed = users.map((user) => ({
		action: user.active === false ? "deprovision" : "upsert",
		email: user.userName,
	}));
	const corr = `corr_scim_${newId("t").slice(4)}`;
	const organizationScope = opts.scope ?? resolveOperatorScope(store);
	const outcome = await store.mutateCoordinated(async ({ data, principals, topology }) => {
		if (!principals && opts.dryRun === false) {
			throw new ClearanceError({
				code: "STORE_V2_PRINCIPAL_TRANSACTION_REQUIRED",
				message: "Relational principal repository is unavailable",
				stage: "scim.test",
				status: 500,
			});
		}
		const conn = data.scimConnections.find((candidate) => candidate.id === id);
		if (!conn) {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${id} not found`,
				stage: "scim.test",
				status: 404,
			});
		}
		const org = topology
			? await topology.lockOrganization({ scope: organizationScope, id: conn.organizationId })
			: await inspectOrganizationAuthoritative(store, conn.organizationId, organizationScope);
		if (!org || org.status === "archived") {
			throw new ClearanceError({
				code: "SCIM_NOT_FOUND",
				message: `SCIM connection ${id} not found`,
				stage: "scim.test",
				status: 404,
			});
		}
		const timestamp = nowIso();
		if (fixture !== "ok") {
			const malformed = fixture === "malformed";
			const trace: DiagnosticTrace = {
				id: newId("tr"),
				correlationId: corr,
				organizationId: conn.organizationId,
				connectionId: conn.id,
				subsystem: "scim",
				mode: SCIM_FIXTURE_MODE,
				stage: malformed ? "request.parse" : "auth.bearer",
				outcome: "fail",
				cause: malformed
					? "SCIM payload failed schema validation"
					: "Bearer token rejected",
				causeConfidence: malformed ? 0.95 : 0.99,
				owner: "customer",
				remediation: malformed
					? "Ensure userName and schemas[] are present per RFC 7644"
					: "Rotate token with clearance scim rotate and update IdP",
				createdAt: timestamp,
				checks: [{ name: malformed ? "schema" : "bearer", pass: false }],
			};
			data.traces.unshift(trace);
			appendAuditEvent(data, {
				actor: opts.actor ?? "system",
				action: "scim.test",
				subjectType: "directory_connection",
				subjectId: id,
				outcome: "failure",
				source: opts.source ?? "scim",
				projectId: org.projectId,
				environmentId: org.environmentId,
				organizationId: conn.organizationId,
				correlationId: corr,
				message: malformed ? "SCIM simulation apply rejected malformed input" : "SCIM simulation apply rejected unauthorized input",
				metadata: { mode: SCIM_FIXTURE_MODE, fixture },
			});
			return {
				kind: "failure" as const,
				code: malformed ? "SCIM_MALFORMED" : "SCIM_UNAUTHORIZED",
				message: malformed ? "Malformed SCIM payload" : "Unauthorized",
				stage: trace.stage,
				remediation: trace.remediation!,
			};
		}
		if (opts.dryRun !== false) {
			const trace: DiagnosticTrace = {
				id: newId("tr"), correlationId: corr, organizationId: conn.organizationId, connectionId: conn.id,
				subsystem: "scim", mode: SCIM_FIXTURE_MODE, stage: "sync.dry_run", outcome: "pass",
				cause: "Dry-run proposed changes (simulation)", causeConfidence: 1, owner: "application", createdAt: timestamp,
				checks: [{ name: "auth.bearer", pass: true }, { name: "schema", pass: true }, { name: "map_users", pass: true, detail: `${proposed.length} users` }, { name: "mode", pass: true, detail: "simulation" }],
				redactedResponse: { proposedCount: proposed.length, dryRun: true },
			};
			data.traces.unshift(trace);
			const connectionIndex = data.scimConnections.findIndex((candidate) => candidate.id === id);
			data.scimConnections[connectionIndex] = { ...conn, status: "testing", updatedAt: timestamp };
			appendAuditEvent(data, {
				actor: opts.actor ?? "system", action: "scim.test", subjectType: "directory_connection", subjectId: id,
				outcome: "success", source: opts.source ?? "scim", projectId: org.projectId, environmentId: org.environmentId,
				organizationId: conn.organizationId, correlationId: corr,
				message: "SCIM simulation dry-run passed (not live directory conformance)",
				metadata: { proposed, mode: SCIM_FIXTURE_MODE, fixture },
			});
			return { kind: "success" as const, trace: structuredClone(trace), connection: structuredClone(data.scimConnections[connectionIndex]!) };
		}
		if (!principals) {
			throw new ClearanceError({
				code: "STORE_V2_PRINCIPAL_TRANSACTION_REQUIRED",
				message: "Relational principal repository is unavailable",
				stage: "scim.test",
				status: 500,
			});
		}
		const principalScope = { projectId: org.projectId, environmentId: org.environmentId };
		for (const user of users) {
			if (user.active === false) continue;
			const email = user.userName.toLowerCase();
			let principal = await principals.findActiveByEmail({ scope: principalScope, email });
			if (!principal) {
				principal = await principals.insert({
					id: newId("user"),
					projectId: principalScope.projectId,
					environmentId: principalScope.environmentId,
					email,
					name: user.displayName?.trim() || email,
					status: "active",
					...(user.externalId ? { externalId: user.externalId } : {}),
					createdAt: timestamp,
					updatedAt: timestamp,
				} satisfies User);
			} else {
				const nextName = user.displayName?.trim() || email;
				const nextExternalId = user.externalId ?? principal.externalId;
				if (principal.name !== nextName || principal.externalId !== nextExternalId) {
					principal = (await principals.update(
						{
							...principal,
							name: nextName,
							...(nextExternalId === undefined
								? { externalId: undefined }
								: { externalId: nextExternalId }),
							updatedAt: timestamp,
						},
						{ expectedUpdatedAt: principal.updatedAt },
					))!;
				}
			}
			const existing = data.memberships.find(
				(membership) =>
					membership.organizationId === org.id &&
					membership.principalId === principal.id &&
					membership.status === "active",
			);
			if (!existing) {
				data.memberships.push({
					id: newId("mem"),
					organizationId: org.id,
					principalId: principal.id,
					role: "member",
					status: "active",
					source: "scim",
					createdAt: timestamp,
					updatedAt: timestamp,
				} satisfies Membership);
			}
		}
		const trace: DiagnosticTrace = {
			id: newId("tr"),
			correlationId: corr,
			organizationId: conn.organizationId,
			connectionId: conn.id,
			subsystem: "scim",
			mode: SCIM_FIXTURE_MODE,
			stage: "sync.apply",
			outcome: "pass",
			cause: "Sync applied to local store (simulation — not live directory)",
			causeConfidence: 1,
			owner: "application",
			createdAt: timestamp,
			checks: [
				{ name: "auth.bearer", pass: true },
				{ name: "schema", pass: true },
				{ name: "map_users", pass: true, detail: `${proposed.length} users` },
				{ name: "mode", pass: true, detail: "simulation" },
			],
			redactedResponse: { proposedCount: proposed.length, dryRun: false },
		};
		data.traces.unshift(trace);
		const connectionIndex = data.scimConnections.findIndex(
			(candidate) => candidate.id === id,
		);
		data.scimConnections[connectionIndex] = {
			...conn,
			status: "testing",
			updatedAt: timestamp,
		};
		appendAuditEvent(data, {
			actor: opts.actor ?? "system",
			action: "scim.test",
			subjectType: "directory_connection",
			subjectId: id,
			outcome: "success",
			source: opts.source ?? "scim",
			projectId: org.projectId,
			environmentId: org.environmentId,
			organizationId: conn.organizationId,
			correlationId: corr,
			message: "SCIM simulation apply passed (not live directory conformance)",
			metadata: { proposed, mode: SCIM_FIXTURE_MODE, fixture },
		});
		return {
			kind: "success" as const,
			trace: structuredClone(trace),
			connection: structuredClone(data.scimConnections[connectionIndex]!),
		};
	});
	if (outcome.kind === "failure") {
		throw new ClearanceError({
			code: outcome.code,
			message: outcome.message,
			stage: outcome.stage,
			remediation: outcome.remediation,
		});
	}
	return {
		pass: true,
		trace: outcome.trace,
		proposed,
		connection: publicDirectoryConnection(outcome.connection) as ScimConnection,
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
 * Authority-aware counterpart to inspectScimTrace. Trace and connection
 * envelopes remain management records; their organization boundary comes from
 * normalized topology after cutover. JSON callers intentionally retain the
 * synchronous implementation above.
 */
export async function inspectScimTraceAuthoritative(
	store: ManagementStore,
	traceId: string,
	opts?: { scope?: ResourceScope },
): Promise<DiagnosticTrace> {
	if (!store.storeV2Topology?.authoritative) {
		return inspectScimTrace(store, traceId, opts);
	}
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
	const original = store.snapshot.traces.find((trace) => trace.id === id);
	if (!original || original.subsystem !== "scim") {
		throw new ClearanceError({
			code: "TRACE_NOT_FOUND",
			message: `SCIM trace ${id} not found`,
			stage,
			status: 404,
		});
	}
	const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
	if (original.connectionId) {
		await resolveScimConnectionAuthoritative(store, original.connectionId, {
			scope,
			stage,
		});
	} else if (original.organizationId) {
		await inspectOrganizationAuthoritative(store, original.organizationId, scope);
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

/**
 * Re-record a trace with normalized-topology authority. The target is checked
 * once for preview and again from the transaction draft before trace/audit
 * mutation, so an archived or cross-scope organization cannot race replay.
 */
export async function replayScimTraceAuthoritative(
	store: ManagementStore,
	traceId: string,
	opts?: ScimMutationOpts,
): Promise<DiagnosticTrace> {
	if (!store.storeV2Topology?.authoritative) {
		return replayScimTrace(store, traceId, opts);
	}
	if (!store.mutateCoordinated) {
		throw new ClearanceError({
			code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
			message: "Relational topology authority requires a coordinated transaction",
			stage: "scim.replay",
			status: 500,
		});
	}
	const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
	const original = await inspectScimTraceAuthoritative(store, traceId, { scope });
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const current = data.traces.find((trace) => trace.id === original.id);
		if (!current || current.subsystem !== "scim") {
			throw new ClearanceError({
				code: "TRACE_NOT_FOUND",
				message: `SCIM trace ${original.id} not found`,
				stage: "scim.replay",
				status: 404,
			});
		}

		if (current.connectionId) {
			const connection = data.scimConnections.find(
				(candidate) => candidate.id === current.connectionId,
			);
			const organization = connection && topology
				? await topology.lockOrganization({ scope, id: connection.organizationId })
				: null;
			if (!organization || organization.status === "archived") {
				throw new ClearanceError({
					code: "SCIM_NOT_FOUND",
					message: `SCIM connection ${current.connectionId} not found`,
					stage: "scim.replay",
					status: 404,
				});
			}
		} else if (current.organizationId) {
			const organization = topology
				? await topology.lockOrganization({ scope, id: current.organizationId })
				: null;
			if (!organization || organization.status === "archived") {
				throw new ClearanceError({
					code: "TRACE_NOT_FOUND",
					message: `SCIM trace ${current.id} not found`,
					stage: "scim.replay",
					status: 404,
				});
			}
		} else if (
			current.projectId !== scope.projectId ||
			current.environmentId !== scope.environmentId
		) {
			throw new ClearanceError({
				code: "TRACE_NOT_FOUND",
				message: `SCIM trace ${current.id} not found`,
				stage: "scim.replay",
				status: 404,
			});
		}

		const next: DiagnosticTrace = {
			...current,
			id: newId("tr"),
			correlationId: `corr_replay_${newId("t").slice(4)}`,
			createdAt: nowIso(),
			stage: `${current.stage}.replay`,
		};
		data.traces.unshift(next);
		if (data.traces.length > 2000) data.traces.length = 2000;
		appendAudit({
			actor: opts?.actor ?? "operator",
			action: "scim.replay",
			subjectType: "diagnostic_trace",
			subjectId: next.id,
			outcome: "success",
			source: opts?.source ?? "cli",
			organizationId: current.organizationId,
			projectId: scope.projectId,
			environmentId: scope.environmentId,
			message: `Replayed SCIM trace ${current.id}`,
			metadata: { originalId: current.id, connectionId: current.connectionId ?? null },
		});
		return next;
	});
}
