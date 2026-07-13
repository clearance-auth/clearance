/**
 * Bridge from Clearance management plane to the real @clearance/auth runtime (Postgres).
 *
 * Runtime tables (Clearance user/organization/session/SSO/SCIM) are for the
 * sample auth product path and enterprise live connectors.
 *
 * Canonical identity: runtime user ids are the stable principal ids. Prefer
 * syncRuntimeUserToManagement / syncRuntimeUserToManagementDurable so a real
 * signup is visible in management with the identical id and project/env scope.
 *
 * Management CRUD (CLI + management API) still uses @clearance/management core
 * services + ManagementStore. createUserInAuth / createOrgInAuth remain for
 * runtime/operator/SSO FK support — after runtime create, sync into management.
 *
 * User lifecycle (update/disable/delete), membership lifecycle (add/update/
 * remove), and organization lifecycle (update/archive) with DATABASE_URL use
 * one Postgres transaction covering runtime tables + management snapshot +
 * uniqueness + audit when the store is PgStore.mutateCoordinated. JsonStore
 * remains management-only.
 */
import {
	createClearanceAuth,
	decryptRuntimeCredential,
	encryptRuntimeCredential,
	type ClearanceAuthBundle,
} from "@clearance/auth";
import { randomBytes } from "node:crypto";
import type {
	DataStoreSnapshot,
	Membership,
	Organization,
	Principal,
	SessionRecord,
} from "./types/resources.js";
import { fingerprint, newId, nowIso } from "./store/json-store.js";
import { ClearanceError } from "./services/errors.js";
import { assertProductionSecret, isForbiddenDefaultSecret } from "./services/secrets.js";
import {
	syncRuntimeUserToManagement,
	syncRuntimeUserToManagementDurable,
} from "./services/identity.js";
import {
	assertResourceInScope,
	resolveOperatorScope,
	type ResourceScope,
} from "./services/scope.js";
import { appendAuditEvent } from "./services/audit.js";
import {
	parseUserStatusInput,
	type ArchiveOrganizationResult,
} from "./services/core.js";
import {
	assertOwnerInvariant,
	type MembershipActorSource,
	type MembershipSource,
} from "./services/members.js";
import { resolveAssignableRole } from "./services/roles.js";
import {
	inspectSession,
	normalizeSessionLimit,
	sanitizeSessionView,
	toSessionView,
	type RevokeSessionResult,
	type SessionSource,
	type SessionView,
} from "./services/sessions.js";
import {
	decodePageCursor,
	encodePageCursor,
} from "./services/pagination.js";
import type { ManagementStore } from "./store/types.js";

export {
	syncRuntimeUserToManagement,
	syncRuntimeUserToManagementDurable,
} from "./services/identity.js";

let bundle: ClearanceAuthBundle | null = null;

export function getAuthBundle(): ClearanceAuthBundle {
	if (bundle) return bundle;
	const databaseUrl = process.env.DATABASE_URL;
	if (!databaseUrl) {
		throw new Error(
			"DATABASE_URL is required for auth runtime bridge. Local JSON management store does not use this path.",
		);
	}
	const secret = process.env.CLEARANCE_SECRET;
	assertProductionSecret(secret);
	if (!secret || secret.length < 16) {
		throw new Error(
			"CLEARANCE_SECRET missing or too short for auth runtime (min 16 chars)",
		);
	}
	if (
		(process.env.NODE_ENV === "production" || process.env.CLEARANCE_STRICT_SECRETS === "1") &&
		isForbiddenDefaultSecret(secret)
	) {
		throw new Error("Refusing default CLEARANCE_SECRET for auth runtime");
	}
	const baseURL = process.env.CLEARANCE_BASE_URL ?? "http://localhost:3300";
	bundle = createClearanceAuth({
		baseURL,
		secret,
		databaseUrl,
		enableSso: true,
		enableScim: true,
	});
	return bundle;
}

/** Test helper — reset singleton between suites */
export function resetAuthBundle(): void {
	bundle = null;
}

/** Release the shared runtime pool for short-lived callers such as the CLI. */
export async function closeAuthBundle(): Promise<void> {
	if (!bundle) return;
	const current = bundle;
	bundle = null;
	await current.pool.end();
}

export async function ensureAuthMigrated(): Promise<void> {
	const b = getAuthBundle();
	await b.migrate();
}

function projectEnv() {
	return {
		projectId: process.env.CLEARANCE_PROJECT_ID ?? "proj_default",
		environmentId: process.env.CLEARANCE_ENV_ID ?? "env_default",
	};
}

export async function listUsersFromDb(): Promise<Principal[]> {
	const b = getAuthBundle();
	const r = await b.pool.query(
		`select id, email, name, "createdAt", "updatedAt" from "user" order by "createdAt" desc limit 500`,
	);
	const { projectId, environmentId } = projectEnv();
	return r.rows.map((row) => ({
		id: row.id as string,
		projectId,
		environmentId,
		email: row.email as string,
		name: (row.name as string) ?? (row.email as string),
		status: "active" as const,
		createdAt: new Date(row.createdAt as string | Date).toISOString(),
		updatedAt: new Date(row.updatedAt as string | Date).toISOString(),
	}));
}

export async function createUserInAuth(input: {
	email: string;
	name: string;
	password: string;
	/** When set, persists the runtime user into management with the same stable id */
	managementStore?: ManagementStore;
}): Promise<Principal> {
	const b = getAuthBundle();
	const result = await b.auth.api.signUpEmail({
		body: {
			email: input.email,
			password: input.password,
			name: input.name,
		},
	});
	const user = result.user;
	const authContext = (await b.auth.$context) as {
		internalAdapter: {
			deleteUserSessions(userId: string): Promise<void>;
			deleteUser(userId: string): Promise<void>;
		};
	};
	try {
		// Administrative provisioning must never leave behind the authenticated
		// session that the public sign-up endpoint normally creates.
		await authContext.internalAdapter.deleteUserSessions(user.id);
	} catch (cause) {
		await authContext.internalAdapter.deleteUser(user.id).catch(() => undefined);
		throw cause;
	}
	const { projectId, environmentId } = projectEnv();
	const principal: Principal = {
		id: user.id,
		projectId,
		environmentId,
		email: user.email,
		name: user.name,
		status: "active",
		createdAt: new Date(user.createdAt).toISOString(),
		updatedAt: new Date(user.updatedAt).toISOString(),
	};

	if (input.managementStore) {
		// Durable canonical bridge — failures propagate (not swallowed)
		return syncRuntimeUserToManagementDurable(input.managementStore, {
			id: user.id,
			email: user.email,
			name: user.name,
			createdAt: user.createdAt,
			updatedAt: user.updatedAt,
		}, { source: "system" });
	}

	return principal;
}

export const PASSWORD_SETUP_TTL_SECONDS = 60 * 60;

export type PasswordSetupGrant = {
	token: string;
	expiresAt: string;
};

/**
 * Provision a user without issuing a reusable temporary credential.
 *
 * The inaccessible random password prevents the credential account from being
 * used directly. The returned reset token is single-use in the auth runtime and
 * expires after one hour; it can only establish a caller-chosen password.
 */
export async function createUserWithPasswordSetupInAuth(input: {
	email: string;
	name: string;
	managementStore?: ManagementStore;
}): Promise<{ user: Principal; passwordSetup: PasswordSetupGrant }> {
	const b = getAuthBundle();
	const inaccessiblePassword = `Clr!${randomBytes(32).toString("base64url")}aA1`;
	const user = await createUserInAuth({
		email: input.email,
		name: input.name,
		password: inaccessiblePassword,
	});
	const token = randomBytes(32).toString("base64url");
	const expiresAt = new Date(Date.now() + PASSWORD_SETUP_TTL_SECONDS * 1000);
	const identifier = `reset-password:${token}`;
	const authContext = (await b.auth.$context) as {
		internalAdapter: {
			createVerificationValue(input: {
				identifier: string;
				value: string;
				expiresAt: Date;
			}): Promise<unknown>;
			deleteVerificationByIdentifier(identifier: string): Promise<void>;
			deleteUser(userId: string): Promise<void>;
		};
	};

	try {
		await authContext.internalAdapter.createVerificationValue({
			identifier,
			value: user.id,
			expiresAt,
		});
		const durableUser = input.managementStore
			? await syncRuntimeUserToManagementDurable(input.managementStore, {
					id: user.id,
					email: user.email,
					name: user.name,
					createdAt: user.createdAt,
					updatedAt: user.updatedAt,
				}, { source: "system" })
			: user;
		return {
			user: durableUser,
			passwordSetup: { token, expiresAt: expiresAt.toISOString() },
		};
	} catch (cause) {
		await authContext.internalAdapter
			.deleteVerificationByIdentifier(identifier)
			.catch(() => undefined);
		await authContext.internalAdapter.deleteUser(user.id).catch(() => undefined);
		throw cause;
	}
}

/**
 * Map an already-created runtime user into management (same stable id + scope).
 * Prefer this after product signup so CLI/API/console see one identity.
 */
export async function bridgeRuntimeUserToManagement(
	store: ManagementStore,
	runtimeUser: {
		id: string;
		email: string;
		name: string;
		createdAt?: string | Date;
		updatedAt?: string | Date;
	},
	opts?: { projectId?: string; environmentId?: string },
): Promise<Principal> {
	const pe = projectEnv();
	return syncRuntimeUserToManagementDurable(store, runtimeUser, {
		projectId: opts?.projectId ?? pe.projectId,
		environmentId: opts?.environmentId ?? pe.environmentId,
		source: "system",
	});
}

export async function listOrgsFromDb(): Promise<Organization[]> {
	const b = getAuthBundle();
	const r = await b.pool.query(
		`select id, name, slug, "createdAt" from organization order by "createdAt" desc limit 500`,
	);
	const { projectId, environmentId } = projectEnv();
	return r.rows.map((row) => ({
		id: row.id as string,
		projectId,
		environmentId,
		name: row.name as string,
		slug: row.slug as string,
		status: "active" as const,
		createdAt: new Date(row.createdAt as string | Date).toISOString(),
		updatedAt: new Date(row.createdAt as string | Date).toISOString(),
	}));
}

/**
 * Create a runtime organization (and optional owner member). When userId is set,
 * returns the exact Clearance owner membership id so management sync can keep
 * the same stable membership id.
 */
export async function createOrgInAuth(input: {
	name: string;
	slug?: string;
	userId?: string;
}): Promise<Organization & { ownerMembershipId?: string }> {
	const b = getAuthBundle();
	const slug =
		input.slug ??
		input.name
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-|-$/g, "")
			.slice(0, 48);
	const id = newId("org").replace(/^org_/, "org");
	const now = new Date();
	await b.pool.query(
		`insert into organization (id, name, slug, "createdAt")
     values ($1, $2, $3, $4)
     on conflict (slug) do update set name = excluded.name`,
		[id, input.name, slug, now],
	);
	let ownerMembershipId: string | undefined;
	if (input.userId) {
		const memId = newId("mem").replace(/^mem_/, "mem");
		await b.pool.query(
			`insert into member (id, "organizationId", "userId", role, "createdAt")
       values ($1, $2, $3, $4, $5)`,
			[memId, id, input.userId, "owner", now],
		);
		ownerMembershipId = memId;
	}
	const { projectId, environmentId } = projectEnv();
	return {
		id,
		projectId,
		environmentId,
		name: input.name,
		slug,
		status: "active",
		createdAt: now.toISOString(),
		updatedAt: now.toISOString(),
		...(ownerMembershipId ? { ownerMembershipId } : {}),
	};
}

export async function countAuthTables(): Promise<Record<string, number>> {
	const b = getAuthBundle();
	const tables = [
		"user",
		"session",
		"account",
		"organization",
		"member",
		"ssoProvider",
		"scimProvider",
	] as const;
	const out: Record<string, number> = {};
	for (const t of tables) {
		try {
			const r = await b.pool.query(`select count(*)::int as c from "${t}"`);
			out[t] = r.rows[0]?.c ?? 0;
		} catch {
			out[t] = -1;
		}
	}
	return out;
}

/** Ensure a system operator user exists for FK-backed SSO provider rows. */
export async function ensureOperatorUser(): Promise<string> {
	const b = getAuthBundle();
	const email = "operator@clearance.local";
	const existing = await b.pool.query(
		`select id from "user" where email = $1 limit 1`,
		[email],
	);
	if (existing.rows[0]?.id) return existing.rows[0].id as string;
	// Ephemeral password — never logged or written to management store
	const password = `Op!${newId("op").slice(3, 18)}Aa1`;
	const user = await createUserInAuth({
		email,
		name: "Clearance Operator",
		password,
	});
	return user.id;
}

function isUniqueViolation(err: unknown): boolean {
	return (
		typeof err === "object" &&
		err !== null &&
		"code" in err &&
		(err as { code?: string }).code === "23505"
	);
}

type SsoProviderRow = {
	id: string;
	issuer: string;
	providerId: string;
	organizationId: string | null;
	domain: string;
	oidcConfig: string | null;
	samlConfig: string | null;
};

async function assertSsoRowScope(
	row: SsoProviderRow,
	input: {
		providerId: string;
		issuer: string;
		domain: string;
		organizationId?: string;
		protocol: "saml" | "oidc";
		oidc?: { clientId: string; clientSecret: string };
		saml?: { entryPoint: string; cert: string; audience?: string };
	},
): Promise<void> {
	const org = input.organizationId ?? null;
	const rowOrg = row.organizationId ?? null;
	const protocolOk =
		input.protocol === "oidc"
			? row.oidcConfig != null && row.samlConfig == null
			: row.samlConfig != null;
	if (
		row.providerId !== input.providerId ||
		rowOrg !== org ||
		row.issuer !== input.issuer ||
		row.domain !== input.domain ||
		!protocolOk
	) {
		throw new ClearanceError({
			code: "SSO_PROVIDER_ID_CONFLICT",
			message:
				"Existing SSO provider id belongs to a different organization, provider, protocol, or endpoint",
			stage: "sso.runtime.reconcile",
			status: 409,
			remediation:
				"Do not reuse a setup attempt id against a mismatched provider row; create a new setup capability",
		});
	}

	if (input.protocol === "oidc" && input.oidc) {
		let config: { clientId?: string; clientSecret?: string };
		try {
			config = JSON.parse(row.oidcConfig ?? "") as typeof config;
		} catch {
			throw new ClearanceError({
				code: "SSO_PROVIDER_ID_CONFLICT",
				message: "Existing OIDC provider configuration is malformed",
				stage: "sso.runtime.reconcile",
				status: 409,
			});
		}
		const prefix = "clr-sso:v1:";
		const storedSecret = config.clientSecret;
		if (
			config.clientId !== input.oidc.clientId ||
			!storedSecret?.startsWith(prefix)
		) {
			throw new ClearanceError({
				code: "SSO_PROVIDER_ID_CONFLICT",
				message: "Existing OIDC provider client configuration does not match",
				stage: "sso.runtime.reconcile",
				status: 409,
			});
		}
		const secret = process.env.CLEARANCE_SECRET;
		if (!secret) throw new Error("CLEARANCE_SECRET is required to reconcile OIDC secrets");
		const decrypted = await decryptRuntimeCredential(
			storedSecret.slice(prefix.length),
			secret,
		);
		if (fingerprint(decrypted) !== fingerprint(input.oidc.clientSecret)) {
			throw new ClearanceError({
				code: "SSO_PROVIDER_ID_CONFLICT",
				message: "Existing OIDC provider secret does not match this setup attempt",
				stage: "sso.runtime.reconcile",
				status: 409,
			});
		}
	}

	if (input.protocol === "saml" && input.saml) {
		let config: { entryPoint?: string; cert?: string; audience?: string };
		try {
			config = JSON.parse(row.samlConfig ?? "") as typeof config;
		} catch {
			throw new ClearanceError({
				code: "SSO_PROVIDER_ID_CONFLICT",
				message: "Existing SAML provider configuration is malformed",
				stage: "sso.runtime.reconcile",
				status: 409,
			});
		}
		if (
			config.entryPoint !== input.saml.entryPoint ||
			config.cert !== input.saml.cert ||
			(config.audience ?? "clearance-sp") !==
				(input.saml.audience ?? "clearance-sp")
		) {
			throw new ClearanceError({
				code: "SSO_PROVIDER_ID_CONFLICT",
				message: "Existing SAML provider configuration does not match",
				stage: "sso.runtime.reconcile",
				status: 409,
			});
		}
	}
}

/**
 * Insert SSO provider, or reconcile an existing deterministic row.
 * When `id` is provided (setup attempt path), retries read/reuse the same PK
 * and fail closed on organization/provider/protocol/domain mismatch.
 * Without `id`, generates a new id (CLI/operator path).
 */
export async function insertSsoProvider(input: {
	/** Deterministic runtime/management id for setup-attempt recovery */
	id?: string;
	providerId: string;
	issuer: string;
	domain: string;
	organizationId?: string;
	protocol: "saml" | "oidc";
	oidc?: { clientId: string; clientSecret: string };
	saml?: { entryPoint: string; cert: string; audience?: string };
}): Promise<{ id: string; clientSecretFingerprint?: string; reused?: boolean }> {
	const b = getAuthBundle();
	const userId = await ensureOperatorUser();
	const id = input.id ?? newId("sso").replace(/^sso_/, "sso");
	const secretFp = input.oidc ? fingerprint(input.oidc.clientSecret) : undefined;

	const loadById = async (lookupId: string): Promise<SsoProviderRow | null> => {
		const r = await b.pool.query(
			`select id, issuer, "providerId", "organizationId", domain, "oidcConfig", "samlConfig"
       from "ssoProvider" where id = $1 limit 1`,
			[lookupId],
		);
		return (r.rows[0] as SsoProviderRow | undefined) ?? null;
	};

	const loadByProviderId = async (
		providerId: string,
	): Promise<SsoProviderRow | null> => {
		const r = await b.pool.query(
			`select id, issuer, "providerId", "organizationId", domain, "oidcConfig", "samlConfig"
       from "ssoProvider" where "providerId" = $1 limit 1`,
			[providerId],
		);
		return (r.rows[0] as SsoProviderRow | undefined) ?? null;
	};

	if (input.id) {
		const existing =
			(await loadById(id)) ?? (await loadByProviderId(input.providerId));
		if (existing) {
			if (existing.id !== id) {
				throw new ClearanceError({
					code: "SSO_PROVIDER_ID_CONFLICT",
					message:
						"Existing SSO providerId is bound to a different runtime id",
					stage: "sso.runtime.reconcile",
					status: 409,
				});
			}
			await assertSsoRowScope(existing, input);
			return { id: existing.id, clientSecretFingerprint: secretFp, reused: true };
		}
	}

	let oidcConfig: string | null = null;
	if (input.oidc) {
		const secret = process.env.CLEARANCE_SECRET;
		if (!secret) throw new Error("CLEARANCE_SECRET is required to encrypt OIDC secrets");
		oidcConfig = JSON.stringify({
			clientId: input.oidc.clientId,
			clientSecret: `clr-sso:v1:${await encryptRuntimeCredential(
				input.oidc.clientSecret,
				secret,
			)}`,
			discoveryEndpoint: `${input.issuer}/.well-known/openid-configuration`,
		});
	}
	const samlConfig = input.saml
		? JSON.stringify({
				entryPoint: input.saml.entryPoint,
				cert: input.saml.cert,
				audience: input.saml.audience ?? "clearance-sp",
			})
		: null;

	try {
		await b.pool.query(
			`insert into "ssoProvider" (
      id, issuer, "oidcConfig", "samlConfig", "userId", "providerId",
      "organizationId", domain
    ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
			[
				id,
				input.issuer,
				oidcConfig,
				samlConfig,
				userId,
				input.providerId,
				input.organizationId ?? null,
				input.domain,
			],
		);
	} catch (err) {
		if (!input.id || !isUniqueViolation(err)) throw err;
		const raced =
			(await loadById(id)) ?? (await loadByProviderId(input.providerId));
		if (!raced || raced.id !== id) throw err;
		await assertSsoRowScope(raced, input);
		return { id: raced.id, clientSecretFingerprint: secretFp, reused: true };
	}
	return {
		id,
		clientSecretFingerprint: secretFp,
		reused: false,
	};
}

export async function deleteSsoProviderById(id: string): Promise<void> {
	const b = getAuthBundle();
	await b.pool.query(`delete from "ssoProvider" where id = $1`, [id]);
}

type ScimProviderRow = {
	id: string;
	providerId: string;
	scimToken: string;
	organizationId: string | null;
};

function assertScimRowScope(
	row: ScimProviderRow,
	input: { providerId: string; organizationId?: string },
): void {
	const org = input.organizationId ?? null;
	const rowOrg = row.organizationId ?? null;
	if (row.providerId !== input.providerId || rowOrg !== org) {
		throw new ClearanceError({
			code: "SCIM_PROVIDER_ID_CONFLICT",
			message:
				"Existing SCIM provider id belongs to a different organization or provider",
			stage: "scim.runtime.reconcile",
			status: 409,
			remediation:
				"Do not reuse a setup attempt id against a mismatched provider row; create a new setup capability",
		});
	}
}

async function scimBearerFromStoredBase(
	baseToken: string,
	providerId: string,
	organizationId?: string | null,
): Promise<string> {
	return Buffer.from(
		`${baseToken}:${providerId}${organizationId ? `:${organizationId}` : ""}`,
		"utf8",
	).toString("base64url");
}

/**
 * Insert SCIM provider, or reconcile an existing deterministic row.
 * On reuse, reconstructs the bearer handoff in-memory from encrypted stored
 * material only (never persists plaintext). Without `id`, generates new ids.
 */
export async function insertScimProvider(input: {
	/** Deterministic runtime/management id for setup-attempt recovery */
	id?: string;
	providerId: string;
	organizationId?: string;
	token?: string;
}): Promise<{ id: string; token: string; reused?: boolean }> {
	const b = getAuthBundle();
	const id = input.id ?? newId("scim").replace(/^scim_/, "scim");
	const secret = process.env.CLEARANCE_SECRET;
	if (!secret) throw new Error("CLEARANCE_SECRET is required to encrypt SCIM tokens");

	const loadById = async (lookupId: string): Promise<ScimProviderRow | null> => {
		const r = await b.pool.query(
			`select id, "providerId", "scimToken", "organizationId"
       from "scimProvider" where id = $1 limit 1`,
			[lookupId],
		);
		return (r.rows[0] as ScimProviderRow | undefined) ?? null;
	};

	const loadByProviderId = async (
		providerId: string,
	): Promise<ScimProviderRow | null> => {
		const r = await b.pool.query(
			`select id, "providerId", "scimToken", "organizationId"
       from "scimProvider" where "providerId" = $1 limit 1`,
			[providerId],
		);
		return (r.rows[0] as ScimProviderRow | undefined) ?? null;
	};

	if (input.id) {
		const existing =
			(await loadById(id)) ?? (await loadByProviderId(input.providerId));
		if (existing) {
			if (existing.id !== id) {
				throw new ClearanceError({
					code: "SCIM_PROVIDER_ID_CONFLICT",
					message:
						"Existing SCIM providerId is bound to a different runtime id",
					stage: "scim.runtime.reconcile",
					status: 409,
				});
			}
			assertScimRowScope(existing, input);
			// Decrypt only in-memory for one-time handoff reconstruction.
			const baseToken = await decryptRuntimeCredential(existing.scimToken, secret);
			const token = await scimBearerFromStoredBase(
				baseToken,
				existing.providerId,
				existing.organizationId,
			);
			return { id: existing.id, token, reused: true };
		}
	}

	const baseToken = input.token ?? newId("tok").replace(/^tok_/, "scimtok_");
	const token = await scimBearerFromStoredBase(
		baseToken,
		input.providerId,
		input.organizationId,
	);
	const storedToken = await encryptRuntimeCredential(baseToken, secret);

	try {
		await b.pool.query(
			`insert into "scimProvider" (id, "providerId", "scimToken", "organizationId")
     values ($1,$2,$3,$4)`,
			[id, input.providerId, storedToken, input.organizationId ?? null],
		);
	} catch (err) {
		if (!input.id || !isUniqueViolation(err)) throw err;
		const raced =
			(await loadById(id)) ?? (await loadByProviderId(input.providerId));
		if (!raced || raced.id !== id) throw err;
		assertScimRowScope(raced, input);
		const base = await decryptRuntimeCredential(raced.scimToken, secret);
		const recovered = await scimBearerFromStoredBase(
			base,
			raced.providerId,
			raced.organizationId,
		);
		return { id: raced.id, token: recovered, reused: true };
	}
	return { id, token, reused: false };
}

export async function deleteScimProviderById(id: string): Promise<void> {
	const b = getAuthBundle();
	await b.pool.query(`delete from "scimProvider" where id = $1`, [id]);
}

/**
 * Low-level runtime session rows. Never selects token / credential columns.
 * Prefer listSessionsInAuth for scoped operator listing.
 */
export async function listSessionsFromDb(): Promise<
	Array<{
		id: string;
		userId: string;
		createdAt: string;
		expiresAt?: string;
		ipAddress?: string;
		userAgent?: string;
	}>
> {
	const b = getAuthBundle();
	// Explicit column list — never SELECT * (token must not leave the database).
	const r = await b.pool.query(
		`select id, "userId", "createdAt", "expiresAt", "ipAddress", "userAgent"
     from session
     order by "createdAt" desc
     limit 100`,
	);
	return r.rows.map((row) => ({
		id: row.id as string,
		userId: row.userId as string,
		createdAt: new Date(row.createdAt as string | Date).toISOString(),
		expiresAt: row.expiresAt
			? new Date(row.expiresAt as string | Date).toISOString()
			: undefined,
		ipAddress: (row.ipAddress as string | null) ?? undefined,
		userAgent: (row.userAgent as string | null) ?? undefined,
	}));
}

/**
 * List active runtime sessions under principal-derived scope.
 * Only returns sessions whose userId maps to an in-scope management principal.
 * Never exposes token material.
 */
export async function listSessionsInAuth(
	store: ManagementStore,
	opts?: {
		scope?: ResourceScope;
		limit?: number;
	},
): Promise<SessionView[]> {
	await ensureAuthMigrated();
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const limit = normalizeSessionLimit(opts?.limit);
	const b = getAuthBundle();

	const principals = new Map(
		store.snapshot.principals
			.filter(
				(p) =>
					p.projectId === scope.projectId &&
					p.environmentId === scope.environmentId &&
					p.status !== "deleted",
			)
			.map((p) => [p.id, p]),
	);
	if (principals.size === 0) return [];

	const userIds = [...principals.keys()];
	// Explicit columns only — never token.
	const r = await b.pool.query(
		`select id, "userId", "createdAt", "expiresAt", "ipAddress", "userAgent"
     from session
     where "userId" = any($1::text[])
       and "expiresAt" > now()
     order by "createdAt" desc
     limit $2`,
		[userIds, limit],
	);

	const views: SessionView[] = [];
	for (const row of r.rows) {
		const principal = principals.get(String(row.userId));
		if (!principal) continue;
		views.push(
			sanitizeSessionView({
				id: String(row.id),
				principalId: principal.id,
				projectId: principal.projectId,
				environmentId: principal.environmentId,
				status: "active",
				createdAt: new Date(row.createdAt as string | Date).toISOString(),
				expiresAt: row.expiresAt
					? new Date(row.expiresAt as string | Date).toISOString()
					: undefined,
				ipAddress: (row.ipAddress as string | null) ?? undefined,
				userAgent: (row.userAgent as string | null) ?? undefined,
			}),
		);
	}
	return views;
}

/**
 * Cursor-paginated runtime sessions (FOLLOW.md P2.3.1), CLI/API parity with
 * the JSON-store listSessionsPage. Ordering: "createdAt" descending, then id
 * descending — the same documented keyset. The cursor carries the row's
 * full-precision createdAt text (Postgres microseconds), so the keyset row
 * comparison cannot skip same-millisecond sessions.
 */
export async function listSessionsPageInAuth(
	store: ManagementStore,
	opts?: {
		scope?: ResourceScope;
		limit?: number;
		/** Opaque cursor from a previous page's nextCursor (fail-closed). */
		cursor?: string;
	},
): Promise<{ sessions: SessionView[]; nextCursor: string | null }> {
	await ensureAuthMigrated();
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const limit = normalizeSessionLimit(opts?.limit);
	const cursor = decodePageCursor(opts?.cursor, "sessions", "sessions.list");
	const b = getAuthBundle();

	const principals = new Map(
		store.snapshot.principals
			.filter(
				(p) =>
					p.projectId === scope.projectId &&
					p.environmentId === scope.environmentId &&
					p.status !== "deleted",
			)
			.map((p) => [p.id, p]),
	);
	if (principals.size === 0) return { sessions: [], nextCursor: null };

	const userIds = [...principals.keys()];
	const params: unknown[] = [userIds];
	let keysetClause = "";
	if (cursor) {
		params.push(cursor.createdAt, cursor.id);
		keysetClause = ` and ("createdAt", id) < ($2::timestamptz, $3)`;
	}
	params.push(limit + 1); // fetch one extra row to learn whether more remain
	// Explicit columns only — never token. createdAt::text keeps microsecond
	// precision for the cursor keyset.
	const r = await b.pool.query(
		`select id, "userId", "createdAt", "createdAt"::text as created_at_raw,
            "expiresAt", "ipAddress", "userAgent"
     from session
     where "userId" = any($1::text[])
       and "expiresAt" > now()${keysetClause}
     order by "createdAt" desc, id desc
     limit $${params.length}`,
		params,
	);

	const hasMore = r.rows.length > limit;
	const pageRows = r.rows.slice(0, limit);
	const views: SessionView[] = [];
	for (const row of pageRows) {
		const principal = principals.get(String(row.userId));
		if (!principal) continue;
		views.push(
			sanitizeSessionView({
				id: String(row.id),
				principalId: principal.id,
				projectId: principal.projectId,
				environmentId: principal.environmentId,
				status: "active",
				createdAt: new Date(row.createdAt as string | Date).toISOString(),
				expiresAt: row.expiresAt
					? new Date(row.expiresAt as string | Date).toISOString()
					: undefined,
				ipAddress: (row.ipAddress as string | null) ?? undefined,
				userAgent: (row.userAgent as string | null) ?? undefined,
			}),
		);
	}
	const lastRow = pageRows[pageRows.length - 1];
	const nextCursor =
		hasMore && lastRow
			? encodePageCursor("sessions", {
					createdAt: String(lastRow.created_at_raw),
					id: String(lastRow.id),
				})
			: null;
	return { sessions: views, nextCursor };
}

/** Load one safe runtime or revoked-tombstone session view without mutation. */
export async function inspectSessionInAuth(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope },
): Promise<SessionView> {
	await ensureAuthMigrated();
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const sessionId = id?.trim();
	if (!sessionId) {
		throw new ClearanceError({
			code: "SESSION_ID_REQUIRED",
			message: "Session id is required",
			stage: "sessions.inspect",
			status: 400,
		});
	}
	const b = getAuthBundle();
	const result = await b.pool.query(
		`select id, "userId", "createdAt", "expiresAt", "ipAddress", "userAgent"
     from session where id = $1 limit 1`,
		[sessionId],
	);
	const row = result.rows[0] as
		| {
				id: string;
				userId: string;
				createdAt: string | Date;
				expiresAt?: string | Date | null;
				ipAddress?: string | null;
				userAgent?: string | null;
		  }
		| undefined;
	if (!row) return inspectSession(store, sessionId, { scope });

	const principal = store.snapshot.principals.find(
		(candidate) => candidate.id === String(row.userId),
	);
	if (!principal || principal.status === "deleted") {
		throw new ClearanceError({
			code: "SESSION_NOT_FOUND",
			message: "Session not found",
			stage: "sessions.inspect",
			status: 404,
		});
	}
	assertResourceInScope(principal, scope, {
		code: "SESSION_NOT_FOUND",
		stage: "sessions.inspect",
		label: "Session",
	});
	return sanitizeSessionView({
		id: String(row.id),
		principalId: principal.id,
		projectId: principal.projectId,
		environmentId: principal.environmentId,
		status: "active",
		createdAt: new Date(row.createdAt).toISOString(),
		...(row.expiresAt
			? { expiresAt: new Date(row.expiresAt).toISOString() }
			: {}),
		...(row.ipAddress ? { ipAddress: row.ipAddress } : {}),
		...(row.userAgent ? { userAgent: row.userAgent } : {}),
	});
}

/**
 * Revoke one runtime session by stable id, coordinated with management tombstone + audit.
 *
 * Idempotent under authorized contract:
 * - Active runtime row → delete + management revoked tombstone + audit
 * - Already revoked management tombstone (no runtime row) → success, idempotent=true
 * - Missing / cross-scope → SESSION_NOT_FOUND (fail closed)
 */
export async function revokeSessionInAuth(
	store: ManagementStore,
	id: string,
	input?: {
		actor?: string;
		source?: SessionSource;
		scope?: ResourceScope;
	},
): Promise<RevokeSessionResult> {
	await ensureAuthMigrated();
	const { mutateCoordinated } = requireCoordinatedStore(store);
	const scope = input?.scope ?? resolveOperatorScope(store);
	const now = nowIso();
	const sessionId = id?.trim();
	if (!sessionId) {
		throw new ClearanceError({
			code: "SESSION_ID_REQUIRED",
			message: "Session id is required",
			stage: "sessions.revoke",
			status: 400,
		});
	}

	return mutateCoordinated(async ({ data, query }) => {
		// Never select token.
		const runtime = await query(
			`select id, "userId", "createdAt", "expiresAt", "ipAddress", "userAgent"
       from session where id = $1 limit 1`,
			[sessionId],
		);
		const runtimeRow = runtime.rows[0] as
			| {
					id: string;
					userId: string;
					createdAt: string | Date;
					expiresAt?: string | Date | null;
					ipAddress?: string | null;
					userAgent?: string | null;
			  }
			| undefined;

		const mgmtIdx = data.sessions.findIndex((s) => s.id === sessionId);
		const mgmt = mgmtIdx >= 0 ? data.sessions[mgmtIdx] : undefined;

		const principalId = runtimeRow
			? String(runtimeRow.userId)
			: mgmt?.principalId;
		if (!principalId) {
			throw new ClearanceError({
				code: "SESSION_NOT_FOUND",
				message: "Session not found",
				stage: "sessions.revoke",
				status: 404,
			});
		}

		const principal = data.principals.find((p) => p.id === principalId);
		if (!principal || principal.status === "deleted") {
			throw new ClearanceError({
				code: "SESSION_NOT_FOUND",
				message: "Session not found",
				stage: "sessions.revoke",
				status: 404,
			});
		}
		assertResourceInScope(principal, scope, {
			code: "SESSION_NOT_FOUND",
			stage: "sessions.revoke",
			label: "Session",
		});
		if (mgmt && mgmt.environmentId !== scope.environmentId) {
			throw new ClearanceError({
				code: "SESSION_NOT_FOUND",
				message: "Session not found",
				stage: "sessions.revoke",
				status: 404,
			});
		}

		const alreadyRevoked =
			!runtimeRow && (!mgmt || mgmt.status === "revoked");

		if (runtimeRow) {
			await query(`delete from session where id = $1`, [sessionId]);
		}

		// Upsert management tombstone so subsequent revokes stay idempotent
		// without re-exposing that a foreign session ever existed.
		let record: SessionRecord;
		if (mgmt) {
			if (mgmt.status !== "revoked") {
				mgmt.status = "revoked";
				mgmt.revokedAt = now;
			} else if (!mgmt.revokedAt) {
				mgmt.revokedAt = now;
			}
			record = mgmt;
		} else {
			record = {
				id: sessionId,
				principalId: principal.id,
				environmentId: principal.environmentId,
				status: "revoked",
				createdAt: runtimeRow
					? new Date(runtimeRow.createdAt).toISOString()
					: now,
				revokedAt: now,
			};
			data.sessions.push(record);
		}

		const view = sanitizeSessionView({
			...toSessionView(record, principal.projectId),
			...(runtimeRow?.expiresAt
				? {
						expiresAt: new Date(
							runtimeRow.expiresAt as string | Date,
						).toISOString(),
					}
				: {}),
			...(runtimeRow?.ipAddress
				? { ipAddress: String(runtimeRow.ipAddress) }
				: {}),
			...(runtimeRow?.userAgent
				? { userAgent: String(runtimeRow.userAgent) }
				: {}),
		});

		appendAuditEvent(data, {
			actor: input?.actor ?? "operator",
			action: "sessions.revoke",
			subjectType: "session",
			subjectId: sessionId,
			outcome: "success",
			source: (input?.source as "cli") ?? "cli",
			projectId: principal.projectId,
			environmentId: principal.environmentId,
			message: alreadyRevoked
				? `Session ${sessionId} already revoked`
				: `Revoked session ${sessionId}`,
			metadata: {
				principalId: principal.id,
				idempotent: alreadyRevoked,
				runtimeDeleted: Boolean(runtimeRow),
			},
		});

		return { session: view, idempotent: alreadyRevoked };
	});
}

// ---------------------------------------------------------------------------
// Runtime + management coordinated user lifecycle
// ---------------------------------------------------------------------------

type CoordinatedQuery = (
	sql: string,
	params?: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;

type LifecycleSource = "cli" | "console" | "api" | "import" | "scim" | "system";

function requireCoordinatedStore(
	store: ManagementStore,
	stage = "users.lifecycle",
	code = "USER_LIFECYCLE_BACKEND",
): {
	mutateCoordinated: NonNullable<ManagementStore["mutateCoordinated"]>;
} {
	if (store.backend !== "postgres" || typeof store.mutateCoordinated !== "function") {
		throw new ClearanceError({
			code,
			message:
				"Runtime coordinated mutations require Postgres management store with coordinated transactions",
			stage,
			status: 500,
			remediation:
				"Set DATABASE_URL and use the Postgres management backend, or use JsonStore management-only mutations without runtime auth",
		});
	}
	return { mutateCoordinated: store.mutateCoordinated.bind(store) };
}

async function ensureRuntimeLifecycleSchema(): Promise<void> {
	const b = getAuthBundle();
	await b.migrate();
	// migrate() already adds banned columns; re-assert for safety when migrate skipped work
	await b.pool.query(
		`ALTER TABLE "user" ADD COLUMN IF NOT EXISTS banned boolean DEFAULT false`,
	);
	await b.pool.query(
		`ALTER TABLE "user" ADD COLUMN IF NOT EXISTS "banReason" text`,
	);
}

function findPrincipalInScope(
	data: DataStoreSnapshot,
	id: string,
	scope: ResourceScope,
	stage: string,
): Principal {
	const user = data.principals.find((p) => p.id === id);
	if (!user || user.status === "deleted") {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage,
			status: 404,
		});
	}
	assertResourceInScope(user, scope, {
		code: "USER_NOT_FOUND",
		stage,
		label: "User",
	});
	return user;
}

async function requireRuntimeUser(
	query: CoordinatedQuery,
	id: string,
	stage: string,
): Promise<{
	id: string;
	email: string;
	name: string;
	banned: boolean | null;
	banReason: string | null;
	createdAt: string | Date;
	updatedAt: string | Date;
}> {
	const r = await query(
		`select id, email, name, banned, "banReason", "createdAt", "updatedAt"
     from "user" where id = $1 limit 1`,
		[id],
	);
	const row = r.rows[0];
	if (!row) {
		throw new ClearanceError({
			code: "USER_RUNTIME_NOT_FOUND",
			message:
				"User not found in auth runtime; refusing management-only mutation that would diverge identity",
			stage,
			status: 404,
			remediation:
				"Repair runtime/management parity (doctor) before mutating this principal",
		});
	}
	return {
		id: String(row.id),
		email: String(row.email),
		name: String(row.name ?? row.email),
		banned: row.banned as boolean | null,
		banReason: (row.banReason as string | null) ?? null,
		createdAt: row.createdAt as string | Date,
		updatedAt: row.updatedAt as string | Date,
	};
}

async function revokeRuntimeSessions(
	query: CoordinatedQuery,
	userId: string,
): Promise<number> {
	const r = await query(`delete from session where "userId" = $1`, [userId]);
	return r.rowCount ?? 0;
}

async function stripRuntimeCredentials(
	query: CoordinatedQuery,
	userId: string,
): Promise<number> {
	const r = await query(`delete from account where "userId" = $1`, [userId]);
	return r.rowCount ?? 0;
}

function revokeManagementSessions(
	data: DataStoreSnapshot,
	principalId: string,
	now: string,
): number {
	let revoked = 0;
	for (const session of data.sessions) {
		if (session.principalId === principalId && session.status === "active") {
			session.status = "revoked";
			session.revokedAt = now;
			revoked += 1;
		}
	}
	return revoked;
}

/**
 * Update name/email/status with runtime tables first-class in the same TX as
 * the management principal snapshot (identical stable id).
 */
export async function updateUserInAuth(
	store: ManagementStore,
	id: string,
	input: {
		name?: string;
		email?: string;
		status?: "active" | "disabled" | string;
		actor?: string;
		source?: LifecycleSource;
		scope?: ResourceScope;
	},
): Promise<Principal> {
	await ensureRuntimeLifecycleSchema();
	const { mutateCoordinated } = requireCoordinatedStore(store);

	const hasName = input.name !== undefined;
	const hasEmail = input.email !== undefined;
	const status = parseUserStatusInput(input.status, "users.update");
	const hasStatus = status !== undefined;
	if (!hasName && !hasEmail && !hasStatus) {
		throw new ClearanceError({
			code: "USER_UPDATE_EMPTY",
			message: "At least one of name, email, or status is required",
			stage: "users.update",
			status: 400,
			remediation: "Pass --name, --email, and/or --status",
		});
	}
	if (hasName && !String(input.name).trim()) {
		throw new ClearanceError({
			code: "USER_NAME_REQUIRED",
			message: "Name must not be empty",
			stage: "users.update",
			status: 400,
		});
	}
	if (hasEmail && !String(input.email).trim()) {
		throw new ClearanceError({
			code: "USER_EMAIL_REQUIRED",
			message: "Email must not be empty",
			stage: "users.update",
			status: 400,
		});
	}

	const email = hasEmail ? String(input.email).toLowerCase().trim() : undefined;
	const name = hasName ? String(input.name).trim() : undefined;
	const scope = input.scope ?? resolveOperatorScope(store);
	const now = nowIso();

	return mutateCoordinated(async ({ data, query }) => {
		const user = findPrincipalInScope(data, id, scope, "users.update");
		const runtime = await requireRuntimeUser(query, id, "users.update");

		if (email && email !== user.email.toLowerCase()) {
			const conflict = data.principals.find(
				(p) =>
					p.id !== user.id &&
					p.email.toLowerCase() === email &&
					p.projectId === user.projectId &&
					p.environmentId === user.environmentId &&
					p.status !== "deleted",
			);
			if (conflict) {
				throw new ClearanceError({
					code: "USER_EXISTS",
					message: `User ${email} already exists`,
					stage: "users.update",
					status: 409,
				});
			}
			const runtimeConflict = await query(
				`select id from "user" where lower(email) = lower($1) and id <> $2 limit 1`,
				[email, id],
			);
			if (runtimeConflict.rows[0]) {
				throw new ClearanceError({
					code: "USER_EXISTS",
					message: `User ${email} already exists`,
					stage: "users.update",
					status: 409,
				});
			}
		}

		const nextEmail = email ?? user.email;
		const nextName = name ?? user.name;
		let nextBanned = Boolean(runtime.banned);
		let nextBanReason: string | null =
			nextBanned ? "disabled" : null;
		let revokedRuntimeSessions = 0;
		let revokedMgmtSessions = 0;

		if (status === "disabled") {
			nextBanned = true;
			nextBanReason = "disabled";
			revokedRuntimeSessions = await revokeRuntimeSessions(query, id);
			revokedMgmtSessions = revokeManagementSessions(data, user.id, now);
		} else if (status === "active") {
			// Soft-deleted management principals never reach here (NOT_FOUND).
			// Tombstoned runtime identities (delete) cannot be safely restored —
			// credentials were stripped and the email was anonymized.
			const tombstoned =
				runtime.banReason === "deleted" ||
				runtime.email.startsWith("deleted+");
			if (tombstoned) {
				throw new ClearanceError({
					code: "USER_REENABLE_UNSAFE",
					message:
						"Cannot re-enable a deleted runtime identity; create a new user instead",
					stage: "users.update",
					status: 409,
					remediation:
						"Re-enable is supported only for disabled (not deleted) users",
				});
			}
			nextBanned = false;
			nextBanReason = null;
		}

		const updated = await query(
			`update "user"
       set email = $1,
           name = $2,
           banned = $3,
           "banReason" = $4,
           "updatedAt" = $5
       where id = $6
       returning id, email, name, banned, "updatedAt"`,
			[nextEmail, nextName, nextBanned, nextBanReason, new Date(now), id],
		);
		if (!updated.rows[0]) {
			throw new ClearanceError({
				code: "USER_RUNTIME_NOT_FOUND",
				message: "Runtime user update affected zero rows",
				stage: "users.update",
				status: 404,
			});
		}

		if (email) user.email = nextEmail;
		if (name !== undefined) user.name = nextName;
		if (status !== undefined) user.status = status;
		user.updatedAt = now;

		const principal: Principal = { ...user };
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "users.update",
			subjectType: "principal",
			subjectId: user.id,
			outcome: "success",
			source: (input.source as "cli") ?? "cli",
			projectId: user.projectId,
			environmentId: user.environmentId,
			message: `Updated user ${user.email}`,
			metadata: {
				fields: [
					...(hasName ? ["name"] : []),
					...(hasEmail ? ["email"] : []),
					...(hasStatus ? ["status"] : []),
				],
				revokedRuntimeSessions,
				revokedManagementSessions: revokedMgmtSessions,
				runtimeBanned: nextBanned,
			},
		});
		return principal;
	});
}

/**
 * Disable principal: ban runtime user, revoke all runtime + management sessions,
 * set management status=disabled, single success audit — all one transaction.
 */
export async function disableUserInAuth(
	store: ManagementStore,
	id: string,
	input?: {
		actor?: string;
		source?: LifecycleSource;
		scope?: ResourceScope;
	},
): Promise<Principal> {
	await ensureRuntimeLifecycleSchema();
	const { mutateCoordinated } = requireCoordinatedStore(store);
	const scope = input?.scope ?? resolveOperatorScope(store);
	const now = nowIso();

	return mutateCoordinated(async ({ data, query }) => {
		const user = findPrincipalInScope(data, id, scope, "users.disable");
		await requireRuntimeUser(query, id, "users.disable");

		const alreadyDisabled = user.status === "disabled";
		const revokedRuntimeSessions = await revokeRuntimeSessions(query, id);
		const revokedMgmtSessions = revokeManagementSessions(data, user.id, now);

		await query(
			`update "user"
       set banned = true,
           "banReason" = 'disabled',
           "updatedAt" = $1
       where id = $2`,
			[new Date(now), id],
		);

		if (!alreadyDisabled) {
			user.status = "disabled";
			user.updatedAt = now;
		}

		const principal: Principal = { ...user };
		// Idempotent re-disable with no remaining sessions is a no-op (no audit).
		if (!alreadyDisabled || revokedRuntimeSessions > 0 || revokedMgmtSessions > 0) {
			appendAuditEvent(data, {
				actor: input?.actor ?? "operator",
				action: "users.disable",
				subjectType: "principal",
				subjectId: user.id,
				outcome: "success",
				source: (input?.source as "cli") ?? "cli",
				projectId: user.projectId,
				environmentId: user.environmentId,
				message: `Disabled user ${user.email}`,
				metadata: {
					revokedSessions: revokedMgmtSessions,
					revokedRuntimeSessions,
					idempotent: alreadyDisabled,
				},
			});
		}
		return principal;
	});
}

/**
 * Soft-delete management principal and make runtime auth impossible:
 * revoke sessions, strip credential accounts, ban + anonymize runtime email
 * (preserve original email only on the management audit snapshot).
 */
export async function deleteUserInAuth(
	store: ManagementStore,
	id: string,
	input?: {
		actor?: string;
		source?: LifecycleSource;
		scope?: ResourceScope;
	},
): Promise<Principal> {
	await ensureRuntimeLifecycleSchema();
	const { mutateCoordinated } = requireCoordinatedStore(store);
	const scope = input?.scope ?? resolveOperatorScope(store);
	const now = nowIso();

	return mutateCoordinated(async ({ data, query }) => {
		const user = findPrincipalInScope(data, id, scope, "users.delete");
		await requireRuntimeUser(query, id, "users.delete");

		const revokedRuntimeSessions = await revokeRuntimeSessions(query, id);
		const strippedAccounts = await stripRuntimeCredentials(query, id);
		// Free original email for re-create; keep row for FK stability (member/sso).
		const tombstoneEmail = `deleted+${id.replace(/[^a-zA-Z0-9_-]/g, "_")}@users.clearance.invalid`;
		await query(
			`update "user"
       set email = $1,
           banned = true,
           "banReason" = 'deleted',
           "updatedAt" = $2
       where id = $3`,
			[tombstoneEmail, new Date(now), id],
		);

		user.status = "deleted";
		user.updatedAt = now;

		const revokedMgmtSessions = revokeManagementSessions(data, user.id, now);
		for (const membership of data.memberships) {
			if (
				membership.principalId === user.id &&
				membership.status === "active"
			) {
				membership.status = "removed";
				membership.updatedAt = now;
			}
		}

		const principal: Principal = { ...user };
		appendAuditEvent(data, {
			actor: input?.actor ?? "operator",
			action: "users.delete",
			subjectType: "principal",
			subjectId: user.id,
			outcome: "success",
			source: (input?.source as "cli") ?? "cli",
			projectId: user.projectId,
			environmentId: user.environmentId,
			message: `Deleted user ${user.email}`,
			metadata: {
				revokedSessions: revokedMgmtSessions,
				revokedRuntimeSessions,
				strippedCredentialAccounts: strippedAccounts,
			},
		});
		return principal;
	});
}

// ---------------------------------------------------------------------------
// Runtime + management coordinated membership lifecycle
// ---------------------------------------------------------------------------

function findOrgInScope(
	data: DataStoreSnapshot,
	id: string,
	scope: ResourceScope,
	stage: string,
): Organization {
	const org = data.organizations.find((o) => o.id === id);
	if (!org || org.status === "archived") {
		throw new ClearanceError({
			code: "ORG_NOT_FOUND",
			message: "Organization not found",
			stage,
			status: 404,
		});
	}
	assertResourceInScope(org, scope, {
		code: "ORG_NOT_FOUND",
		stage,
		label: "Organization",
	});
	return org;
}

async function requireRuntimeOrg(
	query: CoordinatedQuery,
	id: string,
	stage: string,
): Promise<{ id: string; name: string; slug: string }> {
	const r = await query(
		`select id, name, slug from organization where id = $1 limit 1`,
		[id],
	);
	const row = r.rows[0];
	if (!row) {
		throw new ClearanceError({
			code: "ORG_RUNTIME_NOT_FOUND",
			message:
				"Organization not found in auth runtime; refusing management-only mutation that would diverge membership",
			stage,
			status: 404,
			remediation:
				"Repair runtime/management parity (doctor) before mutating memberships",
		});
	}
	return {
		id: String(row.id),
		name: String(row.name),
		slug: String(row.slug),
	};
}

async function loadRuntimeMember(
	query: CoordinatedQuery,
	organizationId: string,
	userId: string,
): Promise<{ id: string; role: string } | null> {
	const r = await query(
		`select id, role from member
     where "organizationId" = $1 and "userId" = $2
     limit 1`,
		[organizationId, userId],
	);
	const row = r.rows[0];
	if (!row) return null;
	return { id: String(row.id), role: String(row.role) };
}

async function loadRuntimeMemberById(
	query: CoordinatedQuery,
	id: string,
): Promise<{ id: string; organizationId: string; userId: string; role: string } | null> {
	const r = await query(
		`select id, "organizationId", "userId", role from member where id = $1 limit 1`,
		[id],
	);
	const row = r.rows[0];
	if (!row) return null;
	return {
		id: String(row.id),
		organizationId: String(row.organizationId),
		userId: String(row.userId),
		role: String(row.role),
	};
}

/**
 * Add membership with runtime member table + management snapshot + one audit
 * in a single coordinated transaction. Preserves runtime membership ids when
 * a matching Clearance row exists. Idempotent for active duplicates.
 */
export async function addMemberInAuth(
	store: ManagementStore,
	input: {
		organizationId: string;
		principalId: string;
		role?: string;
		source?: MembershipSource;
		actor?: string;
		auditSource?: MembershipActorSource;
		scope?: ResourceScope;
	},
): Promise<Membership> {
	await ensureAuthMigrated();
	const { mutateCoordinated } = requireCoordinatedStore(
		store,
		"orgs.members.add",
		"MEMBER_LIFECYCLE_BACKEND",
	);
	const stage = "orgs.members.add";
	const scope = input.scope ?? resolveOperatorScope(store);
	const now = nowIso();
	const roleInput = input.role ?? "member";

	// Role validation uses current snapshot (outside TX) then re-checks scope in TX
	const preResolved = resolveAssignableRole(store, roleInput, {
		scope,
		organizationId: input.organizationId,
		stage,
	});

	return mutateCoordinated(async ({ data, query }) => {
		const org = findOrgInScope(data, input.organizationId, scope, stage);
		const principal = findPrincipalInScope(data, input.principalId, scope, stage);
		if (
			org.projectId !== principal.projectId ||
			org.environmentId !== principal.environmentId
		) {
			throw new ClearanceError({
				code: "USER_NOT_FOUND",
				message: "User not found",
				stage,
				status: 404,
			});
		}

		// Re-resolve against draft roles for consistency inside TX
		const resolved = resolveAssignableRole(
			{ snapshot: data } as ManagementStore,
			roleInput,
			{
				scope: { projectId: org.projectId, environmentId: org.environmentId },
				organizationId: org.id,
				stage,
			},
		);

		await requireRuntimeOrg(query, org.id, stage);
		await requireRuntimeUser(query, principal.id, stage);

		const runtimeMember = await loadRuntimeMember(query, org.id, principal.id);
		const mgmtActive = data.memberships.find(
			(m) =>
				m.organizationId === org.id &&
				m.principalId === principal.id &&
				m.status === "active",
		);

		// Idempotent: both sides present with stable id → return without second audit
		if (mgmtActive && runtimeMember) {
			if (mgmtActive.id !== runtimeMember.id) {
				// Prefer runtime id as canonical; rewrite management id deterministically
				mgmtActive.id = runtimeMember.id;
				mgmtActive.updatedAt = now;
			}
			// Keep existing role on pure duplicate (do not silently change)
			if (runtimeMember.role !== mgmtActive.role) {
				await query(`update member set role = $1 where id = $2`, [
					mgmtActive.role,
					runtimeMember.id,
				]);
			}
			return { ...mgmtActive };
		}

		// Reconcile: runtime exists, management missing → adopt runtime id
		if (runtimeMember && !mgmtActive) {
			const membership: Membership = {
				id: runtimeMember.id,
				organizationId: org.id,
				principalId: principal.id,
				role: resolved.slug,
				status: "active",
				source: input.source ?? "manual",
				createdAt: now,
				updatedAt: now,
			};
			if (runtimeMember.role !== resolved.slug) {
				await query(`update member set role = $1 where id = $2`, [
					resolved.slug,
					runtimeMember.id,
				]);
			}
			data.memberships.push(membership);
			appendAuditEvent(data, {
				actor: input.actor ?? "operator",
				action: "orgs.members.add",
				subjectType: "membership",
				subjectId: membership.id,
				outcome: "success",
				source: (input.auditSource as "cli") ?? "cli",
				organizationId: org.id,
				projectId: org.projectId,
				environmentId: org.environmentId,
				message: `Added ${principal.email} to ${org.name} as ${membership.role}`,
				metadata: {
					role: membership.role,
					roleKind: resolved.kind,
					principalId: principal.id,
					reconciled: "runtime_to_management",
				},
			});
			return membership;
		}

		// Reconcile: management exists, runtime missing → create runtime with management id
		if (mgmtActive && !runtimeMember) {
			await query(
				`insert into member (id, "organizationId", "userId", role, "createdAt")
         values ($1, $2, $3, $4, $5)`,
				[
					mgmtActive.id,
					org.id,
					principal.id,
					mgmtActive.role,
					new Date(mgmtActive.createdAt),
				],
			);
			// No new audit — membership already existed in management
			return { ...mgmtActive };
		}

		// Fresh membership on both sides
		const membershipId = newId("mem");
		await query(
			`insert into member (id, "organizationId", "userId", role, "createdAt")
       values ($1, $2, $3, $4, $5)`,
			[membershipId, org.id, principal.id, resolved.slug, new Date(now)],
		);

		const membership: Membership = {
			id: membershipId,
			organizationId: org.id,
			principalId: principal.id,
			role: resolved.slug,
			status: "active",
			source: input.source ?? "manual",
			createdAt: now,
			updatedAt: now,
		};
		data.memberships.push(membership);
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "orgs.members.add",
			subjectType: "membership",
			subjectId: membership.id,
			outcome: "success",
			source: (input.auditSource as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Added ${principal.email} to ${org.name} as ${membership.role}`,
			metadata: {
				role: membership.role,
				roleKind: resolved.kind,
				principalId: principal.id,
			},
		});
		// silence unused preResolved when TX re-resolves
		void preResolved;
		return membership;
	});
}

/**
 * Update membership role with runtime + management + single audit in one TX.
 * Missing/divergent pairs fail closed after deterministic reconcile attempts.
 */
export async function updateMemberInAuth(
	store: ManagementStore,
	id: string,
	input: {
		role: string;
		actor?: string;
		auditSource?: MembershipActorSource;
		scope?: ResourceScope;
	},
): Promise<Membership> {
	await ensureAuthMigrated();
	const { mutateCoordinated } = requireCoordinatedStore(
		store,
		"orgs.members.update",
		"MEMBER_LIFECYCLE_BACKEND",
	);
	const stage = "orgs.members.update";
	const scope = input.scope ?? resolveOperatorScope(store);
	const now = nowIso();

	return mutateCoordinated(async ({ data, query }) => {
		const row = data.memberships.find((m) => m.id === id && m.status === "active");
		if (!row) {
			// Try runtime-only membership by id — fail closed (not auto-create on update)
			const runtimeOnly = await loadRuntimeMemberById(query, id);
			if (runtimeOnly) {
				throw new ClearanceError({
					code: "MEMBER_DIVERGED",
					message:
						"Membership exists in auth runtime but not in management; refusing update that would leave stores divergent",
					stage,
					status: 409,
					remediation:
						"Re-add the member through clearance orgs members add to reconcile, then update",
				});
			}
			throw new ClearanceError({
				code: "MEMBER_NOT_FOUND",
				message: "Membership not found",
				stage,
				status: 404,
			});
		}

		const org = findOrgInScope(data, row.organizationId, scope, stage);
		const principal = findPrincipalInScope(data, row.principalId, scope, stage);

		const resolved = resolveAssignableRole(
			{ snapshot: data } as ManagementStore,
			input.role,
			{
				scope: { projectId: org.projectId, environmentId: org.environmentId },
				organizationId: org.id,
				stage,
			},
		);

		if (row.role === resolved.slug) {
			// Still require runtime presence so we never report success while diverged
			const runtime = await loadRuntimeMember(query, org.id, principal.id);
			if (!runtime) {
				throw new ClearanceError({
					code: "MEMBER_RUNTIME_NOT_FOUND",
					message:
						"Membership not found in auth runtime; refusing no-op that would mask divergence",
					stage,
					status: 404,
					remediation: "Repair runtime/management membership parity before updating",
				});
			}
			if (runtime.id !== row.id) {
				row.id = runtime.id;
			}
			return { ...row };
		}

		assertOwnerInvariant(data, {
			organizationId: org.id,
			membership: row,
			nextRole: resolved.slug,
			stage,
		});

		await requireRuntimeOrg(query, org.id, stage);
		await requireRuntimeUser(query, principal.id, stage);

		let runtime = await loadRuntimeMember(query, org.id, principal.id);
		if (!runtime) {
			// Deterministic reconcile: create runtime row with management id
			await query(
				`insert into member (id, "organizationId", "userId", role, "createdAt")
         values ($1, $2, $3, $4, $5)`,
				[row.id, org.id, principal.id, resolved.slug, new Date(now)],
			);
			runtime = { id: row.id, role: resolved.slug };
		} else {
			if (runtime.id !== row.id) {
				// Prefer runtime id
				row.id = runtime.id;
			}
			await query(`update member set role = $1 where id = $2`, [
				resolved.slug,
				row.id,
			]);
		}

		const previousRole = row.role;
		row.role = resolved.slug;
		row.updatedAt = now;

		const membership: Membership = { ...row };
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "orgs.members.update",
			subjectType: "membership",
			subjectId: row.id,
			outcome: "success",
			source: (input.auditSource as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Updated membership role ${previousRole} → ${row.role}`,
			metadata: {
				previousRole,
				role: row.role,
				roleKind: resolved.kind,
				principalId: principal.id,
			},
		});
		return membership;
	});
}

/**
 * Remove membership: soft-remove management + hard-delete runtime member +
 * one success audit in a single coordinated transaction.
 */
export async function removeMemberInAuth(
	store: ManagementStore,
	id: string,
	input?: {
		actor?: string;
		auditSource?: MembershipActorSource;
		scope?: ResourceScope;
	},
): Promise<Membership> {
	await ensureAuthMigrated();
	const { mutateCoordinated } = requireCoordinatedStore(
		store,
		"orgs.members.remove",
		"MEMBER_LIFECYCLE_BACKEND",
	);
	const stage = "orgs.members.remove";
	const scope = input?.scope ?? resolveOperatorScope(store);
	const now = nowIso();

	return mutateCoordinated(async ({ data, query }) => {
		const row = data.memberships.find((m) => m.id === id && m.status === "active");
		if (!row) {
			const runtimeOnly = await loadRuntimeMemberById(query, id);
			if (runtimeOnly) {
				throw new ClearanceError({
					code: "MEMBER_DIVERGED",
					message:
						"Membership exists in auth runtime but not in management; refusing remove that would leave stores divergent",
					stage,
					status: 409,
					remediation:
						"Reconcile membership via doctor/add before remove, or delete the runtime row out-of-band after review",
				});
			}
			throw new ClearanceError({
				code: "MEMBER_NOT_FOUND",
				message: "Membership not found",
				stage,
				status: 404,
			});
		}

		const org = findOrgInScope(data, row.organizationId, scope, stage);
		// Principal may already be disabled; still allow remove if in scope
		const principal = data.principals.find((p) => p.id === row.principalId);
		if (principal) {
			assertResourceInScope(principal, scope, {
				code: "MEMBER_NOT_FOUND",
				stage,
				label: "Membership",
			});
		}

		assertOwnerInvariant(data, {
			organizationId: org.id,
			membership: row,
			stage,
		});

		await requireRuntimeOrg(query, org.id, stage);

		const runtime = await loadRuntimeMember(query, org.id, row.principalId);
		if (runtime) {
			const memberId = runtime.id;
			if (memberId !== row.id) {
				row.id = memberId;
			}
			await query(`delete from member where id = $1`, [memberId]);
		} else {
			// Fail closed: management active without runtime is divergence
			throw new ClearanceError({
				code: "MEMBER_RUNTIME_NOT_FOUND",
				message:
					"Membership not found in auth runtime; refusing remove that would leave stores divergent",
				stage,
				status: 404,
				remediation: "Repair runtime/management membership parity before removing",
			});
		}

		row.status = "removed";
		row.updatedAt = now;

		const membership: Membership = { ...row };
		appendAuditEvent(data, {
			actor: input?.actor ?? "operator",
			action: "orgs.members.remove",
			subjectType: "membership",
			subjectId: row.id,
			outcome: "success",
			source: (input?.auditSource as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Removed membership for principal ${row.principalId} from ${org.name}`,
			metadata: {
				role: row.role,
				principalId: row.principalId,
			},
		});
		return membership;
	});
}

// ---------------------------------------------------------------------------
// Runtime + management coordinated organization lifecycle
// ---------------------------------------------------------------------------

/** Matches management core ORG_SLUG_RE — keep in lockstep. */
const ORG_SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

type OrgLifecycleSource = "cli" | "console" | "api" | "import" | "system";

/**
 * Update organization name and/or slug with identical values in Clearance
 * runtime and management snapshot (stable organization id) in one transaction.
 *
 * Management values are authoritative for the intended final state. A true
 * idempotent no-op is allowed only when both runtime and management already
 * match those final values (returns current org, no audit). If runtime is
 * divergent, reconcile it to the management-authoritative finals in the same
 * coordinated transaction and emit exactly one update/reconcile audit.
 * Missing runtime org, cross-scope id, invalid slug, or slug conflict fails
 * closed with zero writes and no success audit.
 */
export async function updateOrganizationInAuth(
	store: ManagementStore,
	id: string,
	input: {
		name?: string;
		slug?: string;
		actor?: string;
		source?: OrgLifecycleSource;
		scope?: ResourceScope;
	},
): Promise<Organization> {
	await ensureAuthMigrated();
	const { mutateCoordinated } = requireCoordinatedStore(
		store,
		"orgs.update",
		"ORG_LIFECYCLE_BACKEND",
	);

	const hasName = input.name !== undefined;
	const hasSlug = input.slug !== undefined;
	if (!hasName && !hasSlug) {
		throw new ClearanceError({
			code: "ORG_UPDATE_EMPTY",
			message: "At least one of name or slug is required",
			stage: "orgs.update",
			status: 400,
			remediation: "Pass --name and/or --slug",
		});
	}
	if (hasName && !String(input.name).trim()) {
		throw new ClearanceError({
			code: "ORG_NAME_REQUIRED",
			message: "Name must not be empty",
			stage: "orgs.update",
			status: 400,
		});
	}
	let nextSlug: string | undefined;
	if (hasSlug) {
		nextSlug = String(input.slug).trim().toLowerCase();
		if (!nextSlug || !ORG_SLUG_RE.test(nextSlug) || nextSlug.length > 48) {
			throw new ClearanceError({
				code: "ORG_SLUG_INVALID",
				message:
					"Slug must be 1–48 chars of lowercase alphanumeric segments separated by single hyphens",
				stage: "orgs.update",
				status: 400,
				remediation: "Use a slug like acme-corp (lowercase, hyphens only)",
			});
		}
	}
	const nextName = hasName ? String(input.name).trim() : undefined;
	const scope = input.scope ?? resolveOperatorScope(store);
	const now = nowIso();

	return mutateCoordinated(async ({ data, query }) => {
		const org = findOrgInScope(data, id, scope, "orgs.update");
		const runtime = await requireRuntimeOrg(query, org.id, "orgs.update");

		// Intended final canonical values: request overlays management snapshot.
		const finalName = nextName !== undefined ? nextName : org.name;
		const finalSlug = nextSlug !== undefined ? nextSlug : org.slug;

		const before = { name: org.name, slug: org.slug };
		const runtimeBefore = { name: runtime.name, slug: runtime.slug };
		const managementChanged =
			org.name !== finalName || org.slug !== finalSlug;
		const runtimeDiverged =
			runtime.name !== finalName || runtime.slug !== finalSlug;

		// True no-op only when both planes already match the intended finals.
		if (!managementChanged && !runtimeDiverged) {
			return { ...org };
		}

		// Fail closed on slug uniqueness before any write.
		if (finalSlug !== org.slug) {
			const conflict = data.organizations.find(
				(o) =>
					o.id !== org.id &&
					o.slug === finalSlug &&
					o.projectId === org.projectId &&
					o.environmentId === org.environmentId &&
					o.status !== "archived",
			);
			if (conflict) {
				throw new ClearanceError({
					code: "ORG_SLUG_EXISTS",
					message: `Organization slug ${finalSlug} already exists in this environment`,
					stage: "orgs.update",
					status: 409,
				});
			}
		}
		if (finalSlug !== runtime.slug) {
			// Clearance organization.slug is globally unique in runtime DB.
			const runtimeConflict = await query(
				`select id from organization where slug = $1 and id <> $2 limit 1`,
				[finalSlug, org.id],
			);
			if (runtimeConflict.rows[0]) {
				throw new ClearanceError({
					code: "ORG_SLUG_EXISTS",
					message: `Organization slug ${finalSlug} already exists in this environment`,
					stage: "orgs.update",
					status: 409,
				});
			}
		}

		const fields: string[] = [];
		if (org.name !== finalName || runtime.name !== finalName) {
			fields.push("name");
		}
		if (org.slug !== finalSlug || runtime.slug !== finalSlug) {
			fields.push("slug");
		}

		const updated = await query(
			`update organization
       set name = $1, slug = $2
       where id = $3
       returning id, name, slug`,
			[finalName, finalSlug, org.id],
		);
		if (!updated.rows[0]) {
			throw new ClearanceError({
				code: "ORG_RUNTIME_NOT_FOUND",
				message: "Runtime organization update affected zero rows",
				stage: "orgs.update",
				status: 404,
				remediation:
					"Repair runtime/management parity (doctor) before mutating this organization",
			});
		}

		org.name = finalName;
		org.slug = finalSlug;
		org.updatedAt = now;

		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "orgs.update",
			subjectType: "organization",
			subjectId: org.id,
			outcome: "success",
			source: (input.source as "cli") ?? "cli",
			projectId: org.projectId,
			environmentId: org.environmentId,
			organizationId: org.id,
			message: runtimeDiverged && !managementChanged
				? `Reconciled organization ${org.name} runtime to management`
				: `Updated organization ${org.name}`,
			metadata: {
				fields,
				before,
				after: { name: org.name, slug: org.slug },
				...(runtimeDiverged
					? {
							runtimeBefore,
							reconciled: true,
						}
					: {}),
			},
		});

		return { ...org };
	});
}

/**
 * Archive organization with coordinated runtime + management transaction.
 *
 * Behavior (hard-delete runtime, management tombstone):
 * - Hard-delete all runtime `member` rows for the org, then the runtime
 *   `organization` row (invitations cascade via FK). Runtime org cannot be used.
 * - Preserve management organization row with status=archived (tombstone keeps
 *   the stable organization id for audit/recovery).
 * - Soft-remove all active management memberships for the org (status=removed).
 * - Exactly one success audit on first archive; re-archive is idempotent with
 *   no duplicate audit.
 * - Owner/last-owner membership invariants are intentionally not enforced: archive
 *   is a deliberate org-level lifecycle end, not a membership remove.
 * - Dry-run / missing confirm preview without mutation (same contract as management).
 * - Active org missing from runtime fails closed (ORG_RUNTIME_NOT_FOUND).
 * - Already-archived + missing runtime → success, idempotent=true.
 */
export async function archiveOrganizationInAuth(
	store: ManagementStore,
	id: string,
	input?: {
		dryRun?: boolean;
		/** Required for mutation. CLI maps --yes → confirm=true. */
		confirm?: boolean;
		actor?: string;
		source?: OrgLifecycleSource;
		scope?: ResourceScope;
	},
): Promise<ArchiveOrganizationResult> {
	const scope = input?.scope ?? resolveOperatorScope(store);
	const dryRun = input?.dryRun === true || input?.confirm !== true;
	const orgId = id?.trim();
	if (!orgId) {
		throw new ClearanceError({
			code: "ORG_ID_REQUIRED",
			message: "Organization id is required",
			stage: "orgs.archive",
			status: 400,
		});
	}

	// Locate including already-archived for idempotent re-archive under scope.
	const existing = store.snapshot.organizations.find((o) => o.id === orgId);
	if (!existing) {
		throw new ClearanceError({
			code: "ORG_NOT_FOUND",
			message: "Organization not found",
			stage: "orgs.archive",
			status: 404,
		});
	}
	assertResourceInScope(existing, scope, {
		code: "ORG_NOT_FOUND",
		stage: "orgs.archive",
		label: "Organization",
	});

	const alreadyArchived = existing.status === "archived";
	if (dryRun) {
		return {
			organization: { ...existing },
			dryRun: true,
			idempotent: alreadyArchived,
			wouldChange: !alreadyArchived,
		};
	}

	await ensureAuthMigrated();
	const { mutateCoordinated } = requireCoordinatedStore(
		store,
		"orgs.archive",
		"ORG_LIFECYCLE_BACKEND",
	);
	const now = nowIso();

	return mutateCoordinated(async ({ data, query }) => {
		const org = data.organizations.find((o) => o.id === orgId);
		if (!org) {
			throw new ClearanceError({
				code: "ORG_NOT_FOUND",
				message: "Organization not found",
				stage: "orgs.archive",
				status: 404,
			});
		}
		assertResourceInScope(org, scope, {
			code: "ORG_NOT_FOUND",
			stage: "orgs.archive",
			label: "Organization",
		});

		const wasArchived = org.status === "archived";

		// Runtime presence: required for first archive; optional heal on re-archive.
		const runtime = await query(
			`select id, name, slug from organization where id = $1 limit 1`,
			[orgId],
		);
		const runtimeRow = runtime.rows[0] as
			| { id: string; name: string; slug: string }
			| undefined;

		if (!wasArchived && !runtimeRow) {
			throw new ClearanceError({
				code: "ORG_RUNTIME_NOT_FOUND",
				message:
					"Organization not found in auth runtime; refusing management-only archive that would diverge organization state",
				stage: "orgs.archive",
				status: 404,
				remediation:
					"Repair runtime/management parity (doctor) before archiving this organization",
			});
		}

		if (runtimeRow) {
			// Prefer explicit member delete then org delete (documented order).
			// Invitations cascade via organization FK ON DELETE CASCADE.
			await query(`delete from member where "organizationId" = $1`, [orgId]);
			await query(`delete from organization where id = $1`, [orgId]);
		}

		if (!wasArchived) {
			org.status = "archived";
			org.updatedAt = now;

			// Soft-remove management memberships; do not enforce last-owner.
			for (const membership of data.memberships) {
				if (
					membership.organizationId === org.id &&
					membership.status === "active"
				) {
					membership.status = "removed";
					membership.updatedAt = now;
				}
			}

			appendAuditEvent(data, {
				actor: input?.actor ?? "operator",
				action: "orgs.archive",
				subjectType: "organization",
				subjectId: org.id,
				outcome: "success",
				source: (input?.source as "cli") ?? "cli",
				projectId: org.projectId,
				environmentId: org.environmentId,
				organizationId: org.id,
				message: `Archived organization ${org.name}`,
				metadata: {
					idempotent: false,
					runtimeDeleted: Boolean(runtimeRow),
					membershipsSoftRemoved: true,
				},
			});
		}

		return {
			organization: { ...org },
			dryRun: false,
			idempotent: wasArchived,
			wouldChange: !wasArchived,
		};
	});
}
