import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	PostgresAuthorizationAuthority,
	PostgresAuthorizationAuthorityError,
} from "./authorization-authority.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const probe = new pg.Pool({ connectionString: DATABASE_URL, connectionTimeoutMillis: 500 });
let available = false;
try {
	await probe.query("SELECT 1");
	available = true;
} catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
		throw new Error(`Authorization authority tests require Postgres at ${DATABASE_URL}`);
	}
} finally {
	await probe.end();
}

function table(schema: string, name: string): string {
	return `"${schema}"."${name}"`;
}

describe.sequential.skipIf(!available)("PostgreSQL authorization authority", () => {
	const schema = `authorization_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
	const identity = Object.freeze({ projectId: "project_7a", environmentId: "environment_7a" });
	const admin = new pg.Pool({ connectionString: DATABASE_URL });
	let pool: pg.Pool;
	let authority: PostgresAuthorizationAuthority;
	const n = (name: string) => table(schema, `clearance_authz_${name}`);

	async function seedRevision(organizationId: string, revision = 1): Promise<void> {
		await pool.query(`INSERT INTO ${n("revisions")} ("projectId", "environmentId", "organizationId", revision) VALUES ($1, $2, $3, $4) ON CONFLICT ("projectId", "environmentId", "organizationId") DO UPDATE SET revision = EXCLUDED.revision`, [identity.projectId, identity.environmentId, organizationId, revision]);
	}

	async function seedAction(actionId: string, projectId = identity.projectId, environmentId = identity.environmentId): Promise<void> {
		await pool.query(`INSERT INTO ${n("actions")} ("projectId", "environmentId", "actionId", "actionName") VALUES ($1, $2, $3, $3)`, [projectId, environmentId, actionId]);
	}

	async function seedRole(roleId: string, organizationId: string | null, status = "active", projectId = identity.projectId, environmentId = identity.environmentId): Promise<void> {
		await pool.query(`INSERT INTO ${n("roles")} ("projectId", "environmentId", "roleId", "organizationId", slug, name, status) VALUES ($1, $2, $3, $4, $5, $3, $6)`, [projectId, environmentId, roleId, organizationId, roleId.replaceAll(".", "-"), status]);
	}

	async function assign(roleId: string, subjectKind: "principal" | "service_account", subjectId: string, organizationId = "org_7a", projectId = identity.projectId, environmentId = identity.environmentId): Promise<void> {
		await pool.query(`INSERT INTO ${n("subject_role_assignments")} ("projectId", "environmentId", "organizationId", "subjectKind", "subjectId", "roleId") VALUES ($1, $2, $3, $4, $5, $6)`, [projectId, environmentId, organizationId, subjectKind, subjectId, roleId]);
	}

	beforeAll(async () => {
		await admin.query(`CREATE SCHEMA "${schema}"`);
		pool = new pg.Pool({ connectionString: DATABASE_URL, max: 4 });
		authority = new PostgresAuthorizationAuthority(pool, { ...identity, schema });
	});

	afterAll(async () => {
		await pool?.end();
		await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
		await admin.end();
	});

	it("plans, applies, validates its owned catalog, and is idempotent", async () => {
		const plan = await authority.planMigration();
		expect(plan.pendingTables).toBe(7);
		expect(plan.pendingFields).toBeGreaterThan(40);
		expect(plan.pendingSecurityMigrations).toEqual(["authorization-authority-v1"]);
		const sql = await plan.compileSql();
		expect(sql).toContain(`CREATE TABLE IF NOT EXISTS "${schema}"."clearance_authz_actions"`);
		expect(sql).toContain("authz_service_account_credentials");
		await plan.apply();
		await expect(authority.listRoles({})).resolves.toEqual(
			expect.arrayContaining([
				expect.objectContaining({ roleId: "role_builtin_owner", builtIn: true }),
				expect.objectContaining({ roleId: "role_builtin_admin", builtIn: true }),
				expect.objectContaining({ roleId: "role_builtin_member", builtIn: true }),
			]),
		);
		const installed = await authority.planMigration();
		expect(installed).toMatchObject({ pendingTables: 0, pendingFields: 0, pendingSecurityMigrations: [] });
		expect(await installed.compileSql()).toBe("");
		await installed.apply();
	});

	it("unions and stably sorts environment-wide and organization-bound roles for a principal", async () => {
		await seedRevision("org_7a", 7);
		await seedAction("action.read");
		await seedAction("action.audit");
		await seedAction("action.write");
		await seedRole("role.environment", null);
		await seedRole("role.organization", "org_7a");
		await pool.query(`INSERT INTO ${n("role_actions")} ("projectId", "environmentId", "roleId", "actionId") VALUES ($1, $2, $3, $4), ($1, $2, $5, $4), ($1, $2, $5, $6), ($1, $2, $3, $7)`, [identity.projectId, identity.environmentId, "role.environment", "action.read", "role.organization", "action.audit", "action.write"]);
		await assign("role.environment", "principal", "principal_7a");
		await assign("role.organization", "principal", "principal_7a");
		await expect(authority.readEffective({ organizationId: "org_7a", subject: { kind: "principal", id: "principal_7a" } })).resolves.toEqual({
			...identity, organizationId: "org_7a", subject: { kind: "principal", id: "principal_7a" },
			roleIds: ["role.environment", "role.organization"], actions: ["action.audit", "action.read", "action.write"], revision: "7",
		});
	});

	it("requires an active, same-scope service account and excludes disabled roles", async () => {
		await pool.query(`INSERT INTO ${n("service_accounts")} ("projectId", "environmentId", "organizationId", "serviceAccountId", name, status) VALUES ($1, $2, $3, $4, $4, 'active'), ($1, $2, $3, $5, $5, 'disabled')`, [identity.projectId, identity.environmentId, "org_7a", "service_active", "service_disabled"]);
		await assign("role.environment", "service_account", "service_active");
		await assign("role.environment", "service_account", "service_disabled");
		await seedRole("role.disabled", "org_7a", "disabled");
		await assign("role.disabled", "principal", "principal_disabled");
		await expect(authority.readEffective({ organizationId: "org_7a", subject: { kind: "service_account", id: "service_active" } })).resolves.toMatchObject({ roleIds: ["role.environment"], actions: ["action.read", "action.write"] });
		await expect(authority.readEffective({ organizationId: "org_7a", subject: { kind: "principal", id: "principal_disabled" } })).resolves.toMatchObject({ roleIds: [], actions: [] });
		await expect(authority.readEffective({ organizationId: "org_7a", subject: { kind: "service_account", id: "service_disabled" } })).rejects.toMatchObject({ code: "AUTHORIZATION_SUBJECT_NOT_FOUND" });
	});

	it("does not leak cross-project, environment, or organization assignments and fails closed without a revision", async () => {
		await seedRevision("org_other", 2);
		await assign("role.environment", "principal", "principal_7a", "org_other");
		await seedAction("action.cross", "project_other", identity.environmentId);
		await seedRole("role.cross", null, "active", "project_other", identity.environmentId);
		await pool.query(`INSERT INTO ${n("role_actions")} ("projectId", "environmentId", "roleId", "actionId") VALUES ($1, $2, $3, $4)`, ["project_other", identity.environmentId, "role.cross", "action.cross"]);
		await assign("role.cross", "principal", "principal_7a", "org_7a", "project_other", identity.environmentId);
		await seedAction("action.environment", identity.projectId, "environment_other");
		await seedRole("role.environment-other", null, "active", identity.projectId, "environment_other");
		await pool.query(`INSERT INTO ${n("role_actions")} ("projectId", "environmentId", "roleId", "actionId") VALUES ($1, $2, $3, $4)`, [identity.projectId, "environment_other", "role.environment-other", "action.environment"]);
		await assign("role.environment-other", "principal", "principal_7a", "org_7a", identity.projectId, "environment_other");
		await expect(authority.readEffective({ organizationId: "org_7a", subject: { kind: "principal", id: "principal_7a" } })).resolves.toMatchObject({ roleIds: ["role.environment", "role.organization"], actions: ["action.audit", "action.read", "action.write"] });
		await expect(authority.readEffective({ organizationId: "org_other", subject: { kind: "principal", id: "principal_7a" } })).resolves.toMatchObject({ roleIds: ["role.environment"], actions: ["action.read", "action.write"] });
		await expect(authority.readEffective({ organizationId: "org_without_revision", subject: { kind: "principal", id: "principal_7a" } })).rejects.toBeInstanceOf(PostgresAuthorizationAuthorityError);
		await expect(authority.readEffective({ organizationId: "org_without_revision", subject: { kind: "principal", id: "principal_7a" } })).rejects.toMatchObject({ code: "AUTHORIZATION_REVISION_NOT_FOUND" });
	});

	it("database-enforces organization-bound role assignment scope while preserving environment-wide roles", async () => {
		await seedRole("role.scope-bound", "org_7a");
		await expect(assign("role.scope-bound", "principal", "principal_scope_mismatch", "org_other")).rejects.toMatchObject({ code: "23514" });
		await assign("role.environment", "principal", "principal_environment_wide", "org_other");
		await expect(authority.readEffective({ organizationId: "org_other", subject: { kind: "principal", id: "principal_environment_wide" } })).resolves.toMatchObject({
			roleIds: ["role.environment"],
			actions: ["action.read", "action.write"],
		});
		await seedRole("role.scope-change", null);
		await assign("role.scope-change", "principal", "principal_scope_change_one", "org_7a");
		await assign("role.scope-change", "principal", "principal_scope_change_two", "org_other");
		await expect(pool.query(`UPDATE ${n("roles")} SET "organizationId" = $1 WHERE "projectId" = $2 AND "environmentId" = $3 AND "roleId" = $4`, ["org_7a", identity.projectId, identity.environmentId, "role.scope-change"])).rejects.toMatchObject({ code: "23514" });
	});

	it("owns role mutations with exact affected revisions and immutable built-in seeds", async () => {
		const organizationId = "org_mutation";
		await expect(authority.initializeOrganization({ organizationId })).resolves.toEqual({ organizationId, revision: "1", initialized: true });
		await expect(authority.initializeOrganization({ organizationId })).resolves.toEqual({ organizationId, revision: "1", initialized: false });
		await expect(authority.upsertRole({
			role: { roleId: "role.mutation", organizationId, slug: "mutation", name: "Mutation", description: null, builtIn: false, status: "active" },
			actions: ["a:a", "a.a", "thing:read"],
		})).resolves.toEqual({ changed: true, affectedOrganizations: [{ organizationId, previousRevision: "1", revision: "2" }] });
		await expect(authority.upsertRole({
			role: { roleId: "role.mutation", organizationId, slug: "mutation", name: "Mutation", description: "updated", builtIn: false, status: "active" },
			actions: ["a:a", "a.a", "thing:read", "thing:write"],
		})).resolves.toEqual({ changed: true, affectedOrganizations: [{ organizationId, previousRevision: "2", revision: "3" }] });
		await expect(authority.upsertRole({
			role: { roleId: "role.arbitrary-built-in", organizationId, slug: "arbitrary-built-in", name: "Arbitrary", description: null, builtIn: true, status: "active" },
			actions: ["thing:admin"],
		})).rejects.toMatchObject({ code: "AUTHORIZATION_ROLE_IMMUTABLE" });
		await expect(authority.upsertRole({
			role: { roleId: "role.too-many-actions", organizationId, slug: "too-many-actions", name: "Too many", description: null, builtIn: false, status: "active" },
			actions: Array.from({ length: 257 }, (_, index) => `limit:${index}`),
		})).rejects.toMatchObject({ code: "AUTHORIZATION_ACTION_LIMIT_EXCEEDED" });
		await expect(authority.listRoles({ organizationId })).resolves.toEqual(expect.arrayContaining([
			expect.objectContaining({ roleId: "role.mutation", actions: ["a.a", "a:a", "thing:read", "thing:write"] }),
			expect.objectContaining({
				roleId: "role_builtin_owner",
				organizationId: null,
				slug: "owner",
				name: "Owner",
				description: "Full organization control including delete and access-control management",
				builtIn: true,
				status: "active",
				actions: ["ac:create", "ac:delete", "ac:read", "ac:update", "invitation:cancel", "invitation:create", "member:create", "member:delete", "member:update", "organization:delete", "organization:update", "team:create", "team:delete", "team:update"],
			}),
		]));
		const sharedOrganizationId = "org_shared_role_mutation";
		await authority.initializeOrganization({ organizationId: sharedOrganizationId });
		await expect(authority.upsertRole({
			role: { roleId: "role.shared.mutation", organizationId: null, slug: "shared-mutation", name: "Shared mutation", description: null, builtIn: false, status: "active" },
			actions: ["thing:read"],
		})).resolves.toEqual({ changed: true, affectedOrganizations: [] });
		await authority.replaceSubjectRoles({ organizationId: sharedOrganizationId, subject: { kind: "principal", id: "principal_shared_mutation" }, roleIds: ["role.shared.mutation"] });
		await expect(authority.upsertRole({
			role: { roleId: "role.shared.mutation", organizationId: null, slug: "shared-mutation", name: "Shared mutation", description: null, builtIn: false, status: "active" },
			actions: ["thing:read", "thing:write"],
		})).resolves.toEqual({ changed: true, affectedOrganizations: [{ organizationId: sharedOrganizationId, previousRevision: "2", revision: "3" }] });
	});

	it("atomically replaces assignments with CAS, owner protection, and caller rollback", async () => {
		const organizationId = "org_mutation";
		const subject = { kind: "principal" as const, id: "principal_mutation" };
		await expect(authority.replaceSubjectRoles({ organizationId, subject, roleIds: ["role_builtin_owner", "role.mutation"], expectedRevision: "3" })).resolves.toEqual({
			changed: true,
			previousRevision: "3",
			revision: "4",
			roleIds: ["role.mutation", "role_builtin_owner"],
		});
		await expect(authority.readEffective({ organizationId, subject })).resolves.toMatchObject({
			roleIds: ["role.mutation", "role_builtin_owner"],
			actions: expect.arrayContaining(["ac:create", "organization:delete", "thing:read", "thing:write"]),
			revision: "4",
		});
		await expect(authority.replaceSubjectRoles({ organizationId, subject, roleIds: ["role.mutation", "role_builtin_owner"], expectedRevision: "4" })).resolves.toEqual({
			changed: false,
			previousRevision: "4",
			revision: "4",
			roleIds: ["role.mutation", "role_builtin_owner"],
		});
		await expect(authority.replaceSubjectRoles({ organizationId, subject, roleIds: ["role.mutation"], expectedRevision: "3" })).rejects.toMatchObject({ code: "AUTHORIZATION_REVISION_STALE" });
		await expect(authority.replaceSubjectRoles({ organizationId, subject, roleIds: [], expectedRevision: "4" })).rejects.toMatchObject({ code: "AUTHORIZATION_LAST_OWNER_PROTECTED" });
		const otherOrganizationId = "org_mutation_other";
		await authority.initializeOrganization({ organizationId: otherOrganizationId });
		await expect(authority.replaceSubjectRoles({ organizationId: otherOrganizationId, subject: { kind: "principal", id: "principal_other" }, roleIds: ["role.mutation"] })).rejects.toMatchObject({ code: "AUTHORIZATION_ROLE_SCOPE_MISMATCH" });
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await authority.replaceSubjectRoles({ organizationId, subject: { kind: "principal", id: "principal_rollback" }, roleIds: ["role.mutation"], transaction: { rawTransactionQuery: client.query.bind(client) } });
			await client.query("ROLLBACK");
		} finally {
			client.release();
		}
		await expect(authority.listSubjectAssignments({ organizationId, subject: { kind: "principal", id: "principal_rollback" } })).resolves.toEqual([]);
		await expect(authority.readEffective({ organizationId, subject })).resolves.toMatchObject({ revision: "4", roleIds: ["role.mutation", "role_builtin_owner"] });
	});

	it("supports a safe custom schema and prefix and rejects an incompatible partial installation", async () => {
		const customSchema = `authorization_custom_${randomUUID().replaceAll("-", "").slice(0, 8)}`;
		const partialSchema = `authorization_partial_${randomUUID().replaceAll("-", "").slice(0, 8)}`;
		try {
			await admin.query(`CREATE SCHEMA "${customSchema}"; CREATE SCHEMA "${partialSchema}"`);
			const custom = new PostgresAuthorizationAuthority(pool, { ...identity, schema: customSchema, prefix: "authority7a" });
			await (await custom.planMigration()).apply();
			await expect(custom.readEffective({ organizationId: "empty_org", subject: { kind: "principal", id: "principal_empty" } })).rejects.toMatchObject({ code: "AUTHORIZATION_REVISION_NOT_FOUND" });
			await pool.query(`DROP TRIGGER "authority7a_az_assignments_role_scope_trg" ON ${table(customSchema, "authority7a_authz_subject_role_assignments")}`);
			await expect(custom.planMigration()).rejects.toMatchObject({ code: "AUTHORIZATION_AUTHORITY_UNAVAILABLE" });
			await pool.query(`CREATE TABLE ${table(partialSchema, "clearance_authz_actions")} ("projectId" text PRIMARY KEY)`);
			const incompatible = new PostgresAuthorizationAuthority(pool, { ...identity, schema: partialSchema });
			await expect(incompatible.planMigration()).rejects.toMatchObject({ code: "AUTHORIZATION_AUTHORITY_UNAVAILABLE" });
		} finally {
			await admin.query(`DROP SCHEMA IF EXISTS "${customSchema}" CASCADE; DROP SCHEMA IF EXISTS "${partialSchema}" CASCADE`);
		}
	});

	it("creates digest-only service-account credentials, rotates them, and derives the exact sorted action union", async () => {
		const organizationId = "org_service_account";
		const serviceAccountId = "service_account_7c";
		await authority.initializeOrganization({ organizationId });
		await authority.upsertRole({
			role: { roleId: "role.service.account.one", organizationId, slug: "service-account-one", name: "Service account one", description: null, builtIn: false, status: "active" },
			actions: ["service:audit", "service:read"],
		});
		await authority.upsertRole({
			role: { roleId: "role.service.account.two", organizationId, slug: "service-account-two", name: "Service account two", description: null, builtIn: false, status: "active" },
			actions: ["service:read", "service:write"],
		});
		await expect(authority.createServiceAccount({ organizationId, serviceAccountId, name: "Release automation", roleIds: ["role.service.account.two", "role.service.account.one"] })).resolves.toMatchObject({
			serviceAccount: { organizationId, serviceAccountId, name: "Release automation", status: "active" },
		});
		const created = await authority.createServiceAccountCredential({ organizationId, serviceAccountId, credentialId: "credential_7c" });
		expect(created.secret).toMatch(/^clr_sac_v1_[A-Za-z0-9_-]{43}$/);
		const stored = await pool.query<{ credential_digest: string; credential_prefix: string; credential_fingerprint: string }>(`SELECT "credentialDigest" AS credential_digest, "credentialPrefix" AS credential_prefix, "credentialFingerprint" AS credential_fingerprint FROM ${n("service_account_credentials")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "credentialId" = $4`, [identity.projectId, identity.environmentId, organizationId, "credential_7c"]);
		expect(stored.rows).toHaveLength(1);
		expect(stored.rows[0]).toMatchObject({ credential_digest: expect.stringMatching(/^v1:[a-f0-9]{64}$/), credential_prefix: "clr_sac_v1", credential_fingerprint: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/) });
		expect(JSON.stringify(stored.rows[0])).not.toContain(created.secret);
		await expect(authority.authenticateServiceAccountCredential({ secret: created.secret })).resolves.toMatchObject({
			organizationId,
			subject: { kind: "service_account", id: serviceAccountId },
			roleIds: ["role.service.account.one", "role.service.account.two"],
			actions: ["service:audit", "service:read", "service:write"],
		});
		const rotated = await authority.rotateServiceAccountCredential({ organizationId, serviceAccountId, credentialId: "credential_7c" });
		expect(rotated.credential.version).toBe(2);
		await expect(authority.authenticateServiceAccountCredential({ secret: created.secret })).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
		await expect(authority.authenticateServiceAccountCredential({ secret: rotated.secret })).resolves.toMatchObject({ credential: { credentialId: rotated.credential.credentialId, version: 2 } });
		const disabled = await authority.setServiceAccountStatus({ organizationId, serviceAccountId, status: "disabled" });
		expect(BigInt(disabled.revision)).toBeGreaterThan(BigInt(rotated.revision));
		await expect(authority.authenticateServiceAccountCredential({ secret: rotated.secret })).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
		await authority.setServiceAccountStatus({ organizationId, serviceAccountId, status: "active" });
		const revoked = await authority.revokeServiceAccountCredential({ organizationId, serviceAccountId, credentialId: rotated.credential.credentialId });
		expect(BigInt(revoked.revision)).toBeGreaterThan(BigInt(revoked.previousRevision));
		await expect(authority.authenticateServiceAccountCredential({ secret: rotated.secret })).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
	});

	it("rejects cross-organization service-account mutations and rolls back callers atomically", async () => {
		const organizationId = "org_service_account_rollback";
		const otherOrganizationId = "org_service_account_other";
		await authority.initializeOrganization({ organizationId });
		await authority.initializeOrganization({ organizationId: otherOrganizationId });
		await authority.upsertRole({
			role: { roleId: "role.service.account.other", organizationId: otherOrganizationId, slug: "service-account-other", name: "Other service role", description: null, builtIn: false, status: "active" },
			actions: ["service:other"],
		});
		await authority.createServiceAccount({ organizationId: otherOrganizationId, serviceAccountId: "service_cross_org", name: "Other organization account", roleIds: ["role.service.account.other"] });
		await expect(authority.createServiceAccount({ organizationId, serviceAccountId: "service_cross_org", name: "Cross organization", roleIds: ["role.service.account.other"] })).rejects.toMatchObject({ code: "AUTHORIZATION_ROLE_SCOPE_MISMATCH" });
		await expect(authority.createServiceAccountCredential({ organizationId, serviceAccountId: "service_cross_org" })).rejects.toMatchObject({ code: "AUTHORIZATION_SERVICE_ACCOUNT_NOT_FOUND" });
		const foreignAuthority = new PostgresAuthorizationAuthority(pool, {
			projectId: "project_service_account_foreign",
			environmentId: identity.environmentId,
			schema,
		});
		await foreignAuthority.initializeOrganization({ organizationId });
		await foreignAuthority.createServiceAccount({
			organizationId,
			serviceAccountId: "service_foreign_scope",
			name: "Foreign scope account",
			roleIds: ["role_builtin_member"],
		});
		const foreignCredential = await foreignAuthority.createServiceAccountCredential({
			organizationId,
			serviceAccountId: "service_foreign_scope",
		});
		await expect(
			authority.authenticateServiceAccountCredential({ secret: foreignCredential.secret }),
		).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
		await expect(
			foreignAuthority.authenticateServiceAccountCredential({ secret: foreignCredential.secret }),
		).resolves.toMatchObject({
			projectId: "project_service_account_foreign",
			organizationId,
			actions: ["ac:read"],
		});
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await authority.createServiceAccount({ organizationId, serviceAccountId: "service_rolled_back", name: "Rolled back", roleIds: [], transaction: { rawTransactionQuery: client.query.bind(client) } });
			await client.query("ROLLBACK");
		} finally {
			client.release();
		}
		await expect(authority.listServiceAccounts({ organizationId })).resolves.not.toEqual(expect.arrayContaining([expect.objectContaining({ serviceAccountId: "service_rolled_back" })]));
		await expect(authority.readEffective({ organizationId, subject: { kind: "principal", id: "principal_rollback_check" } })).resolves.toMatchObject({ revision: "1" });
	});
});
