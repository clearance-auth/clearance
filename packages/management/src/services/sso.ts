import type {
	ManagementCoordinatedQuery,
	ManagementStore,
	StoreV2TopologyRepository,
} from "../store/types.js";
import type { ClearanceKeyManagementFacade } from "@clearance/auth";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DiagnosticTrace, SsoConnection } from "../types/resources.js";
import {
	deleteSsoProviderById,
	invalidateAuthBundles,
	insertSsoProviderInTransaction,
} from "../auth-bridge.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import { encryptCredential, type CredentialCipher } from "./credentials.js";
import { ClearanceError } from "./errors.js";
import { inspectOrganization, inspectOrganizationAuthoritative } from "./core.js";
import {
	resolveEnterpriseConnection,
	resolveEnterpriseConnectionAuthoritative,
} from "./enterprise-connection-lifecycle.js";
import { publicIdentityConnection } from "./redact.js";
import {
	resolveOperatorScope,
	resolveOperatorScopeAuthoritative,
	type ResourceScope,
} from "./scope.js";
import { validateSamlProviderConfig } from "./sso-real.js";
// Setup capabilities live in setup-links.ts (createSetupLink / redeem / revoke)

export type SsoActorSource = "cli" | "console" | "api" | "system";

export interface SsoMutationOpts {
	actor?: string;
	source?: SsoActorSource;
	scope?: ResourceScope;
	/** OIDC client secret confirmed by the tenant for a replacement. */
	newClientSecret?: string;
	operationId?: string;
}

function requiredOperationId(value: string | undefined, stage: string): string {
	if (!value || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
		throw new ClearanceError({ code: "TENANT_OPERATION_ID_REQUIRED", message: "A UUID operationId is required", stage, status: 400 });
	}
	return value;
}

export type SsoMutationGuard = Readonly<{
	authorizeMutation(input: {
		organizationId: string;
		query: ManagementCoordinatedQuery;
	}): Promise<void>;
	credentialCipher?: CredentialCipher;
	runtimeKeyManagement?: ClearanceKeyManagementFacade;
}>;

function ssoCredentialIdentity(organizationId: string, connectionId: string): Readonly<Record<string, string>> {
	return Object.freeze({ organizationId, connectionId });
}

function topologyTransactionRequired(stage: string): ClearanceError {
	return new ClearanceError({
		code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
		message: "Relational topology authority requires a coordinated transaction",
		stage,
		status: 500,
	});
}

async function requireScopedOrganizationInTransaction(
	topology: StoreV2TopologyRepository | undefined,
	scope: ResourceScope,
	organizationId: string,
	stage: string,
	notFoundCode: "ORG_NOT_FOUND" | "SSO_NOT_FOUND",
): Promise<{ id: string; projectId: string; environmentId: string; status: string }> {
	if (!topology) throw topologyTransactionRequired(stage);
	const organization = await topology.lockOrganization({ scope, id: organizationId });
	if (!organization || organization.status === "archived") {
		throw new ClearanceError({
			code: notFoundCode,
			message: notFoundCode === "SSO_NOT_FOUND" ? "SSO connection not found" : "Organization not found",
			stage,
			status: 404,
		});
	}
	return organization;
}

/**
 * Resolve an SSO connection under principal-derived org scope.
 * Missing and cross-scope ids fail closed as SSO_NOT_FOUND.
 */
export function resolveSsoConnection(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope; stage?: string },
): SsoConnection {
	return resolveEnterpriseConnection(store, id, {
		connections: store.snapshot.ssoConnections,
		scope: opts?.scope,
		stage: opts?.stage ?? "sso.resolve",
		label: "SSO",
		idRequiredCode: "SSO_ID_REQUIRED",
		notFoundCode: "SSO_NOT_FOUND",
	});
}

export async function resolveSsoConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope; stage?: string },
): Promise<SsoConnection> {
	return resolveEnterpriseConnectionAuthoritative(store, id, {
		connections: store.snapshot.ssoConnections,
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
): SsoConnection {
	const conn = resolveSsoConnection(store, id, {
		scope: opts?.scope,
		stage: "sso.inspect",
	});
	return publicIdentityConnection(conn) as SsoConnection;
}

export async function inspectSsoConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope },
): Promise<SsoConnection> {
	const conn = await resolveSsoConnectionAuthoritative(store, id, {
		scope: opts?.scope,
		stage: "sso.inspect",
	});
	return publicIdentityConnection(conn) as SsoConnection;
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
	source?: SsoActorSource;
	/** Server-derived scope for authoritative API callers. */
	scope?: ResourceScope;
}

function buildSsoConnection(input: SsoCreateInput): {
	connection: SsoConnection;
	clientSecretKeyId?: string;
	samlCertificateFingerprint?: string;
} {
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
	const connection: SsoConnection = {
		id: newId("sso"),
		organizationId: input.organizationId,
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
	return { connection, clientSecretKeyId, samlCertificateFingerprint: saml?.fingerprint };
}

function createSsoConnectionResolved(
	store: ManagementStore,
	input: SsoCreateInput,
	org: { id: string; projectId: string; environmentId: string },
): SsoConnection {
	const { connection: conn, clientSecretKeyId, samlCertificateFingerprint } = buildSsoConnection(input);
	store.mutate((data) => {
		data.ssoConnections.push(conn);
	});
	recordEvent(store, {
		actor: input.actor ?? "operator",
		action: "sso.create",
		subjectType: "identity_connection",
		subjectId: conn.id,
		outcome: "success",
		source: input.source ?? "cli",
		organizationId: org.id,
		projectId: org.projectId,
		environmentId: org.environmentId,
		message: `Created ${conn.protocol} connection for ${conn.provider}`,
		metadata: {
			hasClientSecret: Boolean(input.clientSecret),
			clientSecretKeyId: clientSecretKeyId ?? null,
			samlCertificateFingerprint: samlCertificateFingerprint ?? null,
			// never: clientSecret plaintext or ciphertext in audit (redact handles encrypted keys)
		},
	});
	// Domain return is write-only for secret material
	return publicIdentityConnection(conn) as SsoConnection;
}

export function createSsoConnection(store: ManagementStore, input: SsoCreateInput): SsoConnection {
	return createSsoConnectionResolved(store, input, inspectOrganization(store, input.organizationId));
}

export async function createSsoConnectionAuthoritative(
	store: ManagementStore,
	input: SsoCreateInput,
): Promise<SsoConnection> {
	if (!store.storeV2Topology?.authoritative) {
		const organization = await inspectOrganizationAuthoritative(store, input.organizationId, input.scope);
		return createSsoConnectionResolved(store, input, organization);
	}
	if (!store.mutateCoordinated) throw topologyTransactionRequired("sso.create");
	const scope = input.scope ?? await resolveOperatorScopeAuthoritative(store);
	const { connection, clientSecretKeyId, samlCertificateFingerprint } = buildSsoConnection(input);
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const organization = await requireScopedOrganizationInTransaction(
			topology,
			scope,
			input.organizationId,
			"sso.create",
			"ORG_NOT_FOUND",
		);
		data.ssoConnections.push(connection);
		appendAudit({
			actor: input.actor ?? "operator",
			action: "sso.create",
			subjectType: "identity_connection",
			subjectId: connection.id,
			outcome: "success",
			source: input.source ?? "cli",
			organizationId: organization.id,
			projectId: organization.projectId,
			environmentId: organization.environmentId,
			message: `Created ${connection.protocol} connection for ${connection.provider}`,
			metadata: {
				hasClientSecret: Boolean(input.clientSecret),
				clientSecretKeyId: clientSecretKeyId ?? null,
				samlCertificateFingerprint: samlCertificateFingerprint ?? null,
			},
		});
		return publicIdentityConnection(connection) as SsoConnection;
	});
}

/**
 * Configure an SSO connection under principal-derived scope (FOLLOW.md P2.3.5).
 * Missing and cross-scope ids fail closed as SSO_NOT_FOUND with no write —
 * the same scope contract as rotateSsoCredential / disableSsoConnection.
 * Validation + write + audit run in ONE store.mutate against the draft
 * (core.ts atomic mutation pattern), so Postgres FOR UPDATE commits the
 * configure and its audit event together or not at all.
 */
function configureSsoConnectionResolved(
	store: ManagementStore,
	conn: SsoConnection,
	org: { id: string; projectId: string; environmentId: string },
	patch: Partial<
		Pick<
			SsoConnection,
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
): SsoConnection {
	const stage = "sso.configure";
	// Encrypt outside the mutator: deterministic input, and the mutator must
	// stay replayable (Postgres re-runs it against the locked latest draft).
	const secretEnvelope = patch.clientSecret
		? encryptCredential(patch.clientSecret)
		: undefined;
	const { clientSecret: _cs, ...safePatch } = patch;
	const now = nowIso();
	let result: SsoConnection | undefined;

	store.mutate((data) => {
		const idx = data.ssoConnections.findIndex((c) => c.id === conn.id);
		if (idx < 0) {
			throw new ClearanceError({
				code: "SSO_NOT_FOUND",
				message: `SSO connection ${conn.id} not found`,
				stage,
				status: 404,
			});
		}
		const row = data.ssoConnections[idx]!;
		const updated: SsoConnection = {
			...row,
			...safePatch,
			clientSecretFingerprint:
				secretEnvelope?.fingerprint ?? row.clientSecretFingerprint,
			clientSecretEncrypted:
				secretEnvelope?.ciphertext ?? row.clientSecretEncrypted,
			clientSecretKeyId: secretEnvelope?.keyId ?? row.clientSecretKeyId,
			updatedAt: now,
		};
		data.ssoConnections[idx] = updated;
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
		result = publicIdentityConnection(updated) as SsoConnection;
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

export function configureSsoConnection(
	store: ManagementStore, id: string, patch: Parameters<typeof configureSsoConnectionResolved>[3], opts?: SsoMutationOpts,
): SsoConnection {
	const connection = resolveSsoConnection(store, id, { scope: opts?.scope, stage: "sso.configure" });
	const organization = inspectOrganization(store, connection.organizationId, opts?.scope ?? resolveOperatorScope(store));
	return configureSsoConnectionResolved(store, connection, organization, patch, opts);
}

export async function configureSsoConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	patch: Parameters<typeof configureSsoConnection>[2],
	opts?: SsoMutationOpts,
): Promise<SsoConnection> {
	if (!store.storeV2Topology?.authoritative) {
		const connection = await resolveSsoConnectionAuthoritative(store, id, opts);
		const organization = await inspectOrganizationAuthoritative(store, connection.organizationId, opts?.scope ?? resolveOperatorScope(store));
		return configureSsoConnectionResolved(store, connection, organization, patch, opts);
	}
	if (!store.mutateCoordinated) throw topologyTransactionRequired("sso.configure");
	const connectionId = id.trim();
	if (!connectionId) {
		throw new ClearanceError({
			code: "SSO_ID_REQUIRED",
			message: "SSO connection id is required",
			stage: "sso.configure",
			status: 400,
		});
	}
	const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
	const secretEnvelope = patch.clientSecret
		? encryptCredential(patch.clientSecret)
		: undefined;
	const { clientSecret: _clientSecret, ...safePatch } = patch;
	const now = nowIso();
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const index = data.ssoConnections.findIndex((connection) => connection.id === connectionId);
		if (index < 0) {
			throw new ClearanceError({
				code: "SSO_NOT_FOUND",
				message: `SSO connection ${connectionId} not found`,
				stage: "sso.configure",
				status: 404,
			});
		}
		const row = data.ssoConnections[index]!;
		const organization = await requireScopedOrganizationInTransaction(
			topology,
			scope,
			row.organizationId,
			"sso.configure",
			"SSO_NOT_FOUND",
		);
		const updated: SsoConnection = {
			...row,
			...safePatch,
			clientSecretFingerprint: secretEnvelope?.fingerprint ?? row.clientSecretFingerprint,
			clientSecretEncrypted: secretEnvelope?.ciphertext ?? row.clientSecretEncrypted,
			clientSecretKeyId: secretEnvelope?.keyId ?? row.clientSecretKeyId,
			updatedAt: now,
		};
		data.ssoConnections[index] = updated;
		appendAudit({
			actor: opts?.actor ?? "operator",
			action: "sso.configure",
			subjectType: "identity_connection",
			subjectId: connectionId,
			outcome: "success",
			source: opts?.source ?? "cli",
			organizationId: organization.id,
			projectId: organization.projectId,
			environmentId: organization.environmentId,
			message: `Configured SSO connection ${connectionId}`,
			metadata: { rotatedSecret: Boolean(patch.clientSecret) },
		});
		return publicIdentityConnection(updated) as SsoConnection;
	});
}

export function listSsoConnections(
	store: ManagementStore,
	organizationId?: string,
): SsoConnection[] {
	return store.snapshot.ssoConnections
		.filter((c) => (organizationId ? c.organizationId === organizationId : true))
		.map((c) => publicIdentityConnection(c) as SsoConnection);
}

/**
 * Tenant SSO replacement must update the runtime provider and management
 * record together, so JSON-store envelope rewrites are deliberately rejected.
 */
export function rotateSsoCredential(
	store: ManagementStore,
	id: string,
	opts?: SsoMutationOpts,
): never {
	// Retain the scope-safe missing-resource contract before refusing the
	// non-transactional backend.
	resolveSsoConnection(store, id, { scope: opts?.scope, stage: "sso.rotate" });
	throw new ClearanceError({
		code: "TENANT_PRODUCT_TRANSACTION_REQUIRED",
		message: "SSO secret replacement requires the coordinated PostgreSQL runtime backend",
		stage: "sso.rotate",
		status: 500,
	});
}

export async function rotateSsoCredentialAuthoritative(
	store: ManagementStore,
	id: string,
	opts?: SsoMutationOpts,
	guard?: SsoMutationGuard,
): Promise<SsoConnection> {
	const operationId = requiredOperationId(opts?.operationId, "sso.rotate");
	if (store.backend !== "postgres") {
		return rotateSsoCredential(store, id, opts);
	}
	if (!store.mutateCoordinated) throw topologyTransactionRequired("sso.rotate");
	const connectionId = id.trim();
	if (!connectionId) {
		throw new ClearanceError({
			code: "SSO_ID_REQUIRED",
			message: "SSO connection id is required",
			stage: "sso.rotate",
			status: 400,
		});
	}
	const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
	const now = nowIso();
	const result = await mutateCoordinatedWithRuntimeSql(store, async ({
		data,
		topology,
		appendAudit,
		query,
	}) => {
		const index = data.ssoConnections.findIndex((connection) => connection.id === connectionId);
		if (index < 0) {
			throw new ClearanceError({
				code: "SSO_NOT_FOUND",
				message: `SSO connection ${connectionId} not found`,
				stage: "sso.rotate",
				status: 404,
			});
		}
		const row = data.ssoConnections[index]!;
		await guard?.authorizeMutation({
			organizationId: row.organizationId,
			query,
		});
		const prior = data.events.find((event) =>
			event.action === "sso.rotate" && event.subjectId === connectionId &&
			event.organizationId === row.organizationId &&
			event.metadata?.operationId === operationId,
		);
		if (prior) return publicIdentityConnection(row) as SsoConnection;
		const organization = topology
			? await requireScopedOrganizationInTransaction(
				topology,
				scope,
				row.organizationId,
				"sso.rotate",
				"SSO_NOT_FOUND",
			)
			: data.organizations.find(
				(organization) =>
					organization.id === row.organizationId &&
					organization.projectId === scope.projectId &&
					organization.environmentId === scope.environmentId,
			);
		if (!organization || organization.status === "archived") {
			throw new ClearanceError({
				code: "SSO_NOT_FOUND",
				message: `SSO connection ${connectionId} not found`,
				stage: "sso.rotate",
				status: 404,
			});
		}
		if (row.protocol === "saml") {
			throw new ClearanceError({
				code: "SSO_SECRET_REPLACEMENT_UNSUPPORTED",
				message: "SAML credentials are controlled by the identity provider and cannot be replaced here",
				stage: "sso.rotate",
				status: 422,
				remediation: "Update the SAML signing certificate through the SSO configuration flow",
			});
		}
		if (row.protocol !== "oidc") {
			throw new ClearanceError({
				code: "SSO_SECRET_REPLACEMENT_UNSUPPORTED",
				message: "Only OIDC client secrets can be replaced",
				stage: "sso.rotate",
				status: 422,
			});
		}
		const newClientSecret = opts?.newClientSecret;
		if (!newClientSecret?.trim()) {
			throw new ClearanceError({
				code: "SSO_NEW_SECRET_REQUIRED",
				message: "A confirmed replacement OIDC client secret is required",
				stage: "sso.rotate",
				status: 400,
				remediation: "Supply the newly issued OIDC client secret to replace the current credential",
			});
		}
		if (!row.clientId || !row.issuer) {
			throw new ClearanceError({
				code: "SSO_ROTATION_CONFLICT",
				message: "OIDC connection is missing runtime client configuration",
				stage: "sso.rotate",
				status: 409,
			});
		}
		const runtime = await query(
			`select "providerId", "organizationId", issuer, domain, "oidcConfig" from "ssoProvider" where id = $1 for update`,
			[connectionId],
		);
		const runtimeProvider = runtime.rows[0] as
			| {
				providerId?: unknown;
				organizationId?: unknown;
				issuer?: unknown;
				domain?: unknown;
				oidcConfig?: unknown;
			}
			| undefined;
		let runtimeClientId: string | undefined;
		try {
			const oidc = typeof runtimeProvider?.oidcConfig === "string"
				? JSON.parse(runtimeProvider.oidcConfig) as { clientId?: unknown }
				: null;
			runtimeClientId = typeof oidc?.clientId === "string" ? oidc.clientId : undefined;
		} catch {
			// The fail-closed conflict below keeps malformed runtime config from being replaced.
		}
		if (
			runtime.rows.length !== 1 ||
			typeof runtimeProvider?.providerId !== "string" ||
			runtimeProvider.organizationId !== organization.id ||
			runtimeProvider.issuer !== row.issuer ||
			typeof runtimeProvider.domain !== "string" ||
			!row.domains.includes(runtimeProvider.domain) ||
			runtimeClientId !== row.clientId
		) {
			throw new ClearanceError({
				code: "SSO_ROTATION_CONFLICT",
				message: "Runtime OIDC provider does not match the requested connection",
				stage: "sso.rotate",
				status: 409,
			});
		}
		await query(`delete from "ssoProvider" where id = $1`, [connectionId]);
		const replacement = await insertSsoProviderInTransaction(query, {
			id: connectionId,
			providerId: runtimeProvider.providerId,
			issuer: row.issuer,
			domain: runtimeProvider.domain,
			organizationId: organization.id,
			protocol: "oidc",
			oidc: { clientId: row.clientId, clientSecret: newClientSecret },
		}, guard?.runtimeKeyManagement);
		if (replacement.reused) {
			throw new ClearanceError({
				code: "SSO_ROTATION_CONFLICT",
				message: "OIDC runtime provider changed while replacing its client secret",
				stage: "sso.rotate",
				status: 409,
			});
		}
		const encrypted = guard?.credentialCipher
			? await guard.credentialCipher.seal(
				newClientSecret,
				ssoCredentialIdentity(organization.id, connectionId),
			)
			: encryptCredential(newClientSecret);
		const updated: SsoConnection = {
			...row,
			clientSecretEncrypted: encrypted.ciphertext,
			clientSecretKeyId: encrypted.keyId,
			clientSecretFingerprint: encrypted.fingerprint,
			updatedAt: now,
		};
		data.ssoConnections[index] = updated;
		appendAudit({
			actor: opts?.actor ?? "operator",
			action: "sso.rotate",
			subjectType: "identity_connection",
			subjectId: connectionId,
			outcome: "success",
			source: opts?.source ?? "cli",
			organizationId: organization.id,
			projectId: organization.projectId,
			environmentId: organization.environmentId,
			message: `Replaced OIDC client secret for ${connectionId}`,
			metadata: {
				operationId,
				keyId: encrypted.keyId,
				clientSecretFingerprint: encrypted.fingerprint,
				replacement: true,
			},
		});
		return publicIdentityConnection(updated) as SsoConnection;
	});
	// Runtime provider configuration is cached by the auth bundle. Invalidate
	// it after commit so subsequent OIDC requests use the confirmed secret,
	// without waiting for a hosted request holding the prior runtime lease.
	invalidateAuthBundles();
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
): { connection: SsoConnection; idempotent: boolean } {
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
	let result: { connection: SsoConnection; idempotent: boolean } | undefined;
	store.mutate((data) => {
		const idx = data.ssoConnections.findIndex((c) => c.id === conn.id);
		if (idx < 0) {
			throw new ClearanceError({
				code: "SSO_NOT_FOUND",
				message: `SSO connection ${conn.id} not found`,
				stage,
				status: 404,
			});
		}
		const row = data.ssoConnections[idx]!;
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
			connection: publicIdentityConnection(row) as SsoConnection,
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

/** Management-only disable that remains topology-authoritative after cutover. */
export async function disableSsoConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	opts?: SsoMutationOpts,
): Promise<{ connection: SsoConnection; idempotent: boolean }> {
	if (!store.storeV2Topology?.authoritative) return disableSsoConnection(store, id, opts);
	if (!store.mutateCoordinated) throw topologyTransactionRequired("sso.disable");
	const connectionId = id.trim();
	if (!connectionId) throw new ClearanceError({ code: "SSO_ID_REQUIRED", message: "SSO connection id is required", stage: "sso.disable", status: 400 });
	const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
	return store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const index = data.ssoConnections.findIndex((connection) => connection.id === connectionId);
		const connection = index >= 0 ? data.ssoConnections[index] : undefined;
		const organization = connection && topology ? await topology.lockOrganization({ scope, id: connection.organizationId }) : null;
		if (!connection || !organization || organization.status === "archived") throw new ClearanceError({ code: "SSO_NOT_FOUND", message: `SSO connection ${connectionId} not found`, stage: "sso.disable", status: 404 });
		const alreadyDisabled = connection.status === "disabled";
		const updated = alreadyDisabled ? connection : { ...connection, status: "disabled" as const, updatedAt: nowIso() };
		data.ssoConnections[index] = updated;
		appendAudit({ actor: opts?.actor ?? "operator", action: "sso.disable", subjectType: "identity_connection", subjectId: connectionId, outcome: "success", source: opts?.source ?? "cli", organizationId: organization.id, projectId: organization.projectId, environmentId: organization.environmentId, message: alreadyDisabled ? `SSO connection ${connectionId} already disabled` : `Disabled SSO connection ${connectionId}`, metadata: { idempotent: alreadyDisabled, previousStatus: connection.status, runtimeRemoved: false } });
		return { connection: publicIdentityConnection(updated) as SsoConnection, idempotent: alreadyDisabled };
	});
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
	guard?: SsoMutationGuard,
): Promise<{
	connection: SsoConnection;
	idempotent: boolean;
	runtimeRemoved: boolean;
}> {
	const stage = "sso.disable";
	if (store.storeV2Topology?.authoritative) {
		if (!store.mutateCoordinated) throw topologyTransactionRequired(stage);
		const connectionId = id.trim();
		if (!connectionId) {
			throw new ClearanceError({ code: "SSO_ID_REQUIRED", message: "SSO connection id is required", stage, status: 400 });
		}
		const scope = opts?.scope ?? await resolveOperatorScopeAuthoritative(store);
		return mutateCoordinatedWithRuntimeSql(store, async ({ data, query, topology, appendAudit }) => {
			const index = data.ssoConnections.findIndex((connection) => connection.id === connectionId);
			const connection = index >= 0 ? data.ssoConnections[index] : undefined;
			if (!connection) {
				throw new ClearanceError({ code: "SSO_NOT_FOUND", message: `SSO connection ${connectionId} not found`, stage, status: 404 });
			}
			await guard?.authorizeMutation({ organizationId: connection.organizationId, query });
			const organization = connection && topology
				? await topology.lockOrganization({ scope, id: connection.organizationId })
				: null;
			if (!connection || !organization || organization.status === "archived") {
				throw new ClearanceError({ code: "SSO_NOT_FOUND", message: `SSO connection ${connectionId} not found`, stage, status: 404 });
			}
			const deleted = await query(`delete from "ssoProvider" where id = $1`, [connectionId]);
			const runtimeRemoved = (deleted.rowCount ?? 0) > 0;
			const alreadyDisabled = connection.status === "disabled";
			const updated = alreadyDisabled ? connection : { ...connection, status: "disabled" as const, updatedAt: nowIso() };
			data.ssoConnections[index] = updated;
			appendAudit({
				actor: opts?.actor ?? "operator", action: "sso.disable", subjectType: "identity_connection", subjectId: connectionId,
				outcome: "success", source: opts?.source ?? "cli", organizationId: organization.id,
				projectId: organization.projectId, environmentId: organization.environmentId,
				message: alreadyDisabled ? `SSO connection ${connectionId} already disabled` : `Disabled SSO connection ${connectionId}`,
				metadata: { idempotent: alreadyDisabled && !runtimeRemoved, previousStatus: connection.status, runtimeRemoved },
			});
			return { connection: publicIdentityConnection(updated) as SsoConnection, idempotent: alreadyDisabled && !runtimeRemoved, runtimeRemoved };
		});
	}
	const conn = await resolveSsoConnectionAuthoritative(store, id, {
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
			const deleted = await query(`delete from "ssoProvider" where id = $1`, [
				conn.id,
			]);
			const runtimeRemoved = (deleted.rowCount ?? 0) > 0;
			const idx = data.ssoConnections.findIndex((c) => c.id === conn.id);
			if (idx < 0) {
				throw new ClearanceError({
					code: "SSO_NOT_FOUND",
					message: `SSO connection ${conn.id} not found`,
					stage,
					status: 404,
				});
			}
			const row = data.ssoConnections[idx]!;
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
				connection: publicIdentityConnection(row) as SsoConnection,
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
	actor?: string;
	source?: SsoActorSource;
	scope?: ResourceScope;
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
	connection: SsoConnection;
	mode: "simulation";
} {
	const conn = resolveSsoConnection(store, id, { scope: opts.scope, stage: "sso.test" });

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
			actor: opts.actor ?? "system",
			action: "sso.test",
			subjectType: "identity_connection",
			subjectId: id,
			outcome: "failure",
			source: opts.source ?? "sso",
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
			actor: opts.actor ?? "system",
			action: "sso.test",
			subjectType: "identity_connection",
			subjectId: id,
			outcome: "failure",
			source: opts.source ?? "sso",
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
			actor: opts.actor ?? "system",
			action: "sso.test",
			subjectType: "identity_connection",
			subjectId: id,
			outcome: "failure",
			source: opts.source ?? "sso",
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

	const trace: DiagnosticTrace = {
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
	};

	const updated = configureSsoConnection(
		store,
		id,
		{ status: "testing" },
		{ actor: opts.actor, source: opts.source, scope: opts.scope },
	);
	trace.createdAt = updated.updatedAt;
	pushTrace(store, trace);
	recordEvent(store, {
		actor: opts.actor ?? "system",
		action: "sso.test",
		subjectType: "identity_connection",
		subjectId: id,
		outcome: "success",
		source: opts.source ?? "sso",
		organizationId: conn.organizationId,
		correlationId: corr,
		message: "SSO simulation test passed (not live IdP conformance)",
		metadata: { mode: SSO_FIXTURE_MODE, fixture },
	});

	return { pass: true, trace, connection: updated, mode: SSO_FIXTURE_MODE };
}

/**
 * Transaction-owned fixture trace path once normalized topology is authority.
 * Fixture computation happens before the write unit; the connection and its
 * active scoped organization are re-read from the locked draft before any
 * trace, audit, or status change is persisted.
 */
export async function testSsoConnectionAuthoritative(
	store: ManagementStore,
	id: string,
	opts: SsoTestOptions & { scope?: ResourceScope } = {},
): Promise<ReturnType<typeof testSsoConnection>> {
	if (!store.storeV2Topology?.authoritative) return testSsoConnection(store, id, opts);
	if (!store.mutateCoordinated) throw topologyTransactionRequired("sso.test");
	const scope = opts.scope ?? await resolveOperatorScopeAuthoritative(store);
	const fixture = opts.fixture ?? "ok";
	const allowed = new Set(["ok", "wrong-issuer", "wrong-audience", "malformed", "expired", "clock-skew", "replay"]);
	if (!allowed.has(fixture)) throw new ClearanceError({ code: "SSO_UNKNOWN_FIXTURE", message: `Unknown SSO fixture "${fixture}" — fail-closed (simulation mode)`, stage: "sso.test" });
	const preliminary = store.snapshot.ssoConnections.find((connection) => connection.id === id);
	if (!preliminary) throw new ClearanceError({ code: "SSO_NOT_FOUND", message: `SSO connection ${id} not found`, stage: "sso.test", status: 404 });
	const effectiveIssuer = opts.assertionIssuer ?? preliminary.issuer ?? "https://idp.example.com";
	const effectiveAudience = opts.assertionAudience ?? preliminary.audience ?? "clearance-sp";
	const failure = fixture === "malformed"
		? { code: "SSO_ASSERTION_MALFORMED", stage: "assertion.parse", cause: "Malformed SAML/OIDC assertion payload", remediation: "Re-export metadata from the IdP and re-run clearance sso configure; ensure assertion is valid XML/JWT" }
		: fixture === "wrong-issuer" || (preliminary.issuer && effectiveIssuer !== preliminary.issuer)
			? { code: "SSO_WRONG_ISSUER", stage: "assertion.issuer", cause: "Assertion issuer does not match configured connection issuer", remediation: "Update IdP issuer or run clearance sso configure --issuer <correct-issuer>" }
			: fixture === "wrong-audience" || (preliminary.audience && effectiveAudience !== preliminary.audience)
				? { code: "SSO_WRONG_AUDIENCE", stage: "assertion.audience", cause: "Audience/EntityID mismatch", remediation: "Align SP EntityID/audience in IdP app config with clearance sso configure --audience" }
				: fixture === "expired"
					? { code: "SSO_EXPIRED", stage: "assertion.validity", cause: "Assertion NotOnOrAfter / exp is in the past", remediation: "Retry sign-in; check IdP clock and assertion lifetime settings" }
					: fixture === "clock-skew"
						? { code: "SSO_CLOCK_SKEW", stage: "assertion.clock", cause: "Clock skew between IdP and Clearance exceeds allowed window", remediation: "Sync NTP on IdP and Clearance hosts; allowed skew is 120s" }
						: fixture === "replay"
							? { code: "SSO_REPLAY", stage: "assertion.replay", cause: "Assertion ID already consumed", remediation: "Do not reuse assertions; initiate a new IdP login" }
							: preliminary.protocol === "oidc" && !preliminary.issuer
								? { code: "SSO_CONFIG_INCOMPLETE", stage: "connection.config", cause: "OIDC connection missing issuer", remediation: "Run clearance sso configure --issuer https://idp.example.com" }
								: null;
	const corr = `corr_sso_${newId("t").slice(4)}`;
	const outcome = await store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const index = data.ssoConnections.findIndex((connection) => connection.id === id);
		const connection = index >= 0 ? data.ssoConnections[index] : undefined;
		const organization = connection && topology ? await topology.lockOrganization({ scope, id: connection.organizationId }) : null;
		if (!connection || !organization || organization.status === "archived") throw new ClearanceError({ code: "SSO_NOT_FOUND", message: `SSO connection ${id} not found`, stage: "sso.test", status: 404 });
		const trace: DiagnosticTrace = {
			id: newId("tr"), correlationId: corr, organizationId: connection.organizationId, connectionId: id,
			subsystem: "sso", mode: SSO_FIXTURE_MODE, stage: failure?.stage ?? "assertion.accept",
			outcome: failure ? "fail" : "pass", cause: failure?.cause ?? "All protocol stages passed (simulation — fixture lab path)",
			causeConfidence: 1, owner: failure ? "customer" : "application", ...(failure ? { remediation: failure.remediation } : {}),
			createdAt: nowIso(), checks: [{ name: "mode", pass: true, detail: "simulation" }],
		};
		data.traces.unshift(trace);
		const updated = failure ? connection : { ...connection, status: "testing" as const, updatedAt: trace.createdAt };
		data.ssoConnections[index] = updated;
		appendAudit({ actor: opts.actor ?? "system", action: "sso.test", subjectType: "identity_connection", subjectId: id,
			outcome: failure ? "failure" : "success", source: opts.source ?? "sso", organizationId: organization.id, projectId: organization.projectId, environmentId: organization.environmentId,
			correlationId: corr, message: failure ? `SSO test failed at ${failure.stage}` : "SSO simulation test passed (not live IdP conformance)", metadata: { mode: SSO_FIXTURE_MODE, fixture } });
		return { trace, connection: updated };
	});
	if (failure) throw new ClearanceError({ code: failure.code, message: failure.cause, stage: failure.stage, remediation: failure.remediation });
	return { pass: true, trace: outcome.trace, connection: publicIdentityConnection(outcome.connection) as SsoConnection, mode: SSO_FIXTURE_MODE };
}
