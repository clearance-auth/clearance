import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	PostgresAuthorizationAuthority,
	PostgresAuthorizationAuthorityError,
} from "./authorization-authority.js";

const replayCipher = Object.freeze({
	async seal(plaintext: string, binding: string): Promise<string> {
		const key = Buffer.alloc(32, 7);
		const iv = randomBytes(12);
		const cipher = createCipheriv("aes-256-gcm", key, iv);
		cipher.setAAD(Buffer.from(binding, "utf8"));
		const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
		return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url");
	},
	async open(envelope: string, binding: string): Promise<string> {
		const value = Buffer.from(envelope, "base64url");
		if (value.length < 29) throw new Error("replay envelope is invalid");
		const decipher = createDecipheriv("aes-256-gcm", Buffer.alloc(32, 7), value.subarray(0, 12));
		decipher.setAAD(Buffer.from(binding, "utf8"));
		decipher.setAuthTag(value.subarray(12, 28));
		return Buffer.concat([decipher.update(value.subarray(28)), decipher.final()]).toString("utf8");
	},
});

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
		authority = new PostgresAuthorizationAuthority(pool, { ...identity, schema, oneTimeSecretReplayCipher: replayCipher });
	});

	afterAll(async () => {
		await pool?.end();
		await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
		await admin.end();
	});

	it("plans, applies, validates its owned catalog, and is idempotent", async () => {
		const principalSubjectIndex = "clearance_az_assignments_principal_subject_idx";
		const plan = await authority.planMigration();
		expect(plan.pendingTables).toBe(8);
		expect(plan.pendingFields).toBeGreaterThan(40);
		expect(plan.pendingSecurityMigrations).toEqual(["authorization-authority-v2"]);
		const sql = await plan.compileSql();
		expect(sql).toContain(`CREATE TABLE IF NOT EXISTS "${schema}"."clearance_authz_actions"`);
		expect(sql).toContain("authz_service_account_credentials");
		expect(sql).toContain(`CREATE INDEX IF NOT EXISTS "${principalSubjectIndex}" ON "${schema}"."clearance_authz_subject_role_assignments" ("projectId", "environmentId", "subjectKind", "subjectId")`);
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
		const catalogIndex = await pool.query<{ columns: string[] }>(`SELECT array_agg(attribute_record.attname::text ORDER BY index_key.ordinality) AS columns
			FROM pg_index AS index_state
			JOIN pg_class AS table_record ON table_record.oid = index_state.indrelid
			JOIN pg_namespace AS namespace_record ON namespace_record.oid = table_record.relnamespace
			JOIN pg_class AS index_record ON index_record.oid = index_state.indexrelid
			JOIN unnest(index_state.indkey) WITH ORDINALITY AS index_key(attribute_number, ordinality) ON true
			JOIN pg_attribute AS attribute_record ON attribute_record.attrelid = table_record.oid AND attribute_record.attnum = index_key.attribute_number
			WHERE namespace_record.nspname = $1 AND table_record.relname = $2 AND index_record.relname = $3
			GROUP BY index_state.indexrelid`, [schema, "clearance_authz_subject_role_assignments", principalSubjectIndex]);
		expect(catalogIndex.rows).toEqual([{ columns: ["projectId", "environmentId", "subjectKind", "subjectId"] }]);
		await pool.query(`DROP INDEX "${schema}"."${principalSubjectIndex}"`);
		const indexUpgrade = await authority.planMigration();
		expect(indexUpgrade).toMatchObject({ pendingTables: 0, pendingFields: 0, pendingSecurityMigrations: ["authorization-authority-v2"] });
		expect(await indexUpgrade.compileSql()).toBe(`CREATE INDEX IF NOT EXISTS "${principalSubjectIndex}" ON "${schema}"."clearance_authz_subject_role_assignments" ("projectId", "environmentId", "subjectKind", "subjectId")`);
		await indexUpgrade.apply();
		expect(await authority.planMigration()).toMatchObject({ pendingTables: 0, pendingFields: 0, pendingSecurityMigrations: [] });
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
			const custom = new PostgresAuthorizationAuthority(pool, { ...identity, schema: customSchema, prefix: "authority7a", oneTimeSecretReplayCipher: replayCipher });
			await (await custom.planMigration()).apply();
			await expect(custom.readEffective({ organizationId: "empty_org", subject: { kind: "principal", id: "principal_empty" } })).rejects.toMatchObject({ code: "AUTHORIZATION_REVISION_NOT_FOUND" });
			await custom.initializeOrganization({ organizationId: "legacy_terminalization" });
			await pool.query(`ALTER TABLE ${table(customSchema, "authority7a_authz_revisions")} DROP COLUMN terminal`);
			const terminalizationUpgrade = await custom.planMigration();
			expect(terminalizationUpgrade).toMatchObject({ pendingTables: 0, pendingFields: 1, pendingSecurityMigrations: ["authorization-authority-v2"] });
			await terminalizationUpgrade.apply();
			await expect(custom.initializeOrganization({ organizationId: "legacy_terminalization" })).resolves.toEqual({ organizationId: "legacy_terminalization", revision: "1", initialized: false });
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
		const created = await authority.createServiceAccountCredential({ organizationId, actorId: "principal_service_account", operationId: randomUUID(), serviceAccountId, credentialId: "credential_7c" });
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
		const rotated = await authority.rotateServiceAccountCredential({ organizationId, actorId: "principal_service_account", operationId: randomUUID(), serviceAccountId, credentialId: "credential_7c" });
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

	it("durably replays response-loss credential creation and rotation without duplicate credentials or revocation", async () => {
		const organizationId = `org_replay_${randomUUID().slice(0, 8)}`;
		const serviceAccountId = `service_replay_${randomUUID().slice(0, 8)}`;
		const actorId = "principal_replay";
		await authority.initializeOrganization({ organizationId });
		await authority.createServiceAccount({ organizationId, serviceAccountId, name: "Replay automation", roleIds: ["role_builtin_member"] });

		const createOperationId = randomUUID();
		const created = await authority.createServiceAccountCredential({ organizationId, actorId, operationId: createOperationId, serviceAccountId });
		const createdReplay = await authority.createServiceAccountCredential({ organizationId, actorId, operationId: createOperationId, serviceAccountId });
		expect(createdReplay).toMatchObject({ credential: created.credential, secret: created.secret, previousRevision: created.previousRevision, revision: created.revision, replayed: true });
		expect(createdReplay.secret).toBe(created.secret);
		await expect(authority.createServiceAccountCredential({ organizationId, actorId, operationId: createOperationId, serviceAccountId, credentialId: "credential_replay_collision" })).rejects.toMatchObject({ code: "AUTHORIZATION_OPERATION_ID_CONFLICT" });
		expect(await pool.query(`SELECT 1 FROM ${n("service_account_credentials")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4`, [identity.projectId, identity.environmentId, organizationId, serviceAccountId])).toMatchObject({ rowCount: 1 });

		const rotateOperationId = randomUUID();
		const rotated = await authority.rotateServiceAccountCredential({ organizationId, actorId, operationId: rotateOperationId, serviceAccountId, credentialId: created.credential.credentialId });
		const rotatedReplay = await authority.rotateServiceAccountCredential({ organizationId, actorId, operationId: rotateOperationId, serviceAccountId, credentialId: created.credential.credentialId });
		expect(rotatedReplay).toMatchObject({ credential: rotated.credential, secret: rotated.secret, previousRevision: rotated.previousRevision, revision: rotated.revision, replayed: true });
		expect(rotatedReplay.secret).toBe(rotated.secret);
		const credentials = await pool.query<{ status: string }>(`SELECT status FROM ${n("service_account_credentials")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4 ORDER BY version`, [identity.projectId, identity.environmentId, organizationId, serviceAccountId]);
		expect(credentials.rows.map((row) => row.status)).toEqual(["revoked", "active"]);
		const storedReplay = await pool.query<{ envelope: string }>(`SELECT "resultEnvelope" AS envelope FROM ${n("one_time_secret_replays")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "operationId" = $3`, [identity.projectId, identity.environmentId, rotateOperationId]);
		expect(storedReplay.rows).toHaveLength(1);
		expect(storedReplay.rows[0]!.envelope).not.toContain(rotated.secret);
		await expect(authority.rotateServiceAccountCredential({ organizationId, actorId, operationId: rotateOperationId, serviceAccountId, credentialId: rotated.credential.credentialId })).rejects.toMatchObject({ code: "AUTHORIZATION_OPERATION_ID_CONFLICT" });
	});

	it("never discloses response-loss replay secrets after credential or authority invalidation", async () => {
		const actorId = "principal_replay_invalidation";
		const organizationId = `org_replay_invalidation_${randomUUID().slice(0, 8)}`;
		const serviceAccountId = `service_replay_invalidation_${randomUUID().slice(0, 8)}`;
		const state = async () => pool.query<{ revision: string; credentials: string }>(`SELECT revision::text AS revision, (SELECT count(*)::text FROM ${n("service_account_credentials")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4) AS credentials FROM ${n("revisions")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3`, [identity.projectId, identity.environmentId, organizationId, serviceAccountId]);
		await authority.initializeOrganization({ organizationId });
		await authority.createServiceAccount({ organizationId, serviceAccountId, name: "Invalidation replay automation", roleIds: ["role_builtin_member"] });

		const revokedOperationId = randomUUID();
		const revoked = await authority.createServiceAccountCredential({ organizationId, actorId, operationId: revokedOperationId, serviceAccountId });
		await authority.revokeServiceAccountCredential({ organizationId, serviceAccountId, credentialId: revoked.credential.credentialId });
		const afterRevocation = await state();
		await expect(authority.createServiceAccountCredential({ organizationId, actorId, operationId: revokedOperationId, serviceAccountId })).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
		expect(await state()).toEqual(afterRevocation);

		const source = await authority.createServiceAccountCredential({ organizationId, actorId, operationId: randomUUID(), serviceAccountId });
		const rotateOperationId = randomUUID();
		const rotated = await authority.rotateServiceAccountCredential({ organizationId, actorId, operationId: rotateOperationId, serviceAccountId, credentialId: source.credential.credentialId });
		await authority.rotateServiceAccountCredential({ organizationId, actorId, operationId: randomUUID(), serviceAccountId, credentialId: rotated.credential.credentialId });
		const afterReplacement = await state();
		await expect(authority.rotateServiceAccountCredential({ organizationId, actorId, operationId: rotateOperationId, serviceAccountId, credentialId: source.credential.credentialId })).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
		expect(await state()).toEqual(afterReplacement);

		const disabledOperationId = randomUUID();
		await authority.createServiceAccountCredential({ organizationId, actorId, operationId: disabledOperationId, serviceAccountId });
		await authority.setServiceAccountStatus({ organizationId, serviceAccountId, status: "disabled" });
		const afterDisable = await state();
		await expect(authority.createServiceAccountCredential({ organizationId, actorId, operationId: disabledOperationId, serviceAccountId })).rejects.toMatchObject({ code: "AUTHORIZATION_SERVICE_ACCOUNT_DISABLED" });
		expect(await state()).toEqual(afterDisable);

		const archivedOrganizationId = `org_replay_archived_${randomUUID().slice(0, 8)}`;
		const archivedServiceAccountId = `service_replay_archived_${randomUUID().slice(0, 8)}`;
		const archivedOperationId = randomUUID();
		await authority.initializeOrganization({ organizationId: archivedOrganizationId });
		await authority.createServiceAccount({ organizationId: archivedOrganizationId, serviceAccountId: archivedServiceAccountId, name: "Archived replay automation", roleIds: ["role_builtin_member"] });
		await authority.createServiceAccountCredential({ organizationId: archivedOrganizationId, actorId, operationId: archivedOperationId, serviceAccountId: archivedServiceAccountId });
		await authority.archiveOrganization({ organizationId: archivedOrganizationId });
		const archivedState = await pool.query<{ revision: string; credentials: string }>(`SELECT revision::text AS revision, (SELECT count(*)::text FROM ${n("service_account_credentials")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4) AS credentials FROM ${n("revisions")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3`, [identity.projectId, identity.environmentId, archivedOrganizationId, archivedServiceAccountId]);
		await expect(authority.createServiceAccountCredential({ organizationId: archivedOrganizationId, actorId, operationId: archivedOperationId, serviceAccountId: archivedServiceAccountId })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		expect(await pool.query<{ revision: string; credentials: string }>(`SELECT revision::text AS revision, (SELECT count(*)::text FROM ${n("service_account_credentials")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4) AS credentials FROM ${n("revisions")} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3`, [identity.projectId, identity.environmentId, archivedOrganizationId, archivedServiceAccountId])).toEqual(archivedState);
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
		await expect(authority.createServiceAccountCredential({ organizationId, actorId: "principal_service_account", operationId: randomUUID(), serviceAccountId: "service_cross_org" })).rejects.toMatchObject({ code: "AUTHORIZATION_SERVICE_ACCOUNT_NOT_FOUND" });
		const foreignAuthority = new PostgresAuthorizationAuthority(pool, {
			projectId: "project_service_account_foreign",
			environmentId: identity.environmentId,
			schema,
			oneTimeSecretReplayCipher: replayCipher,
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
			actorId: "principal_service_account",
			operationId: randomUUID(),
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

	it("terminalizes organization authorization atomically and fails every live authority path closed", async () => {
		const organizationId = "org_terminal";
		const principal = { kind: "principal" as const, id: "principal_terminal" };
		const serviceAccountId = "service_terminal";
		await authority.initializeOrganization({ organizationId });
		await authority.upsertRole({
			role: { roleId: "role.terminal", organizationId, slug: "terminal", name: "Terminal", description: null, builtIn: false, status: "active" },
			actions: ["terminal:read"],
		});
		await authority.replaceSubjectRoles({ organizationId, subject: principal, roleIds: ["role.terminal"] });
		await authority.createServiceAccount({ organizationId, serviceAccountId, name: "Terminal machine", roleIds: ["role.terminal"] });
		const credential = await authority.createServiceAccountCredential({ organizationId, actorId: "principal_service_account", operationId: randomUUID(), serviceAccountId, credentialId: "credential_terminal" });
		const before = await authority.readEffective({ organizationId, subject: principal });
		const archived = await authority.archiveOrganization({ organizationId });
		expect(archived).toEqual({
			organizationId,
			previousRevision: before.revision,
			revision: (BigInt(before.revision) + 1n).toString(),
			archived: true,
			removedAssignments: 2,
			disabledServiceAccounts: 1,
			revokedCredentials: 1,
		});
		await expect(authority.readEffective({ organizationId, subject: principal })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.listRoles({ organizationId })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.listSubjectAssignments({ organizationId })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.listServiceAccounts({ organizationId })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.listRoles({})).resolves.toEqual(expect.arrayContaining([expect.objectContaining({ roleId: "role_builtin_owner" })]));
		await expect(authority.authenticateServiceAccountCredential({ secret: credential.secret })).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
		await expect(authority.replaceSubjectRoles({ organizationId, subject: principal, roleIds: [] })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.upsertRole({
			role: { roleId: "role.terminal", organizationId, slug: "terminal", name: "Terminal updated", description: null, builtIn: false, status: "active" },
			actions: ["terminal:read"],
		})).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.createServiceAccount({ organizationId, serviceAccountId: "service_terminal_new", name: "Terminal new machine", roleIds: [] })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.setServiceAccountStatus({ organizationId, serviceAccountId, status: "active" })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.initializeOrganization({ organizationId })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
		await expect(authority.archiveOrganization({ organizationId })).resolves.toEqual({
			organizationId,
			previousRevision: archived.revision,
			revision: archived.revision,
			archived: true,
			removedAssignments: 0,
			disabledServiceAccounts: 0,
			revokedCredentials: 0,
		});

		const rollbackOrganizationId = "org_terminal_rollback";
		const rollbackPrincipal = { kind: "principal" as const, id: "principal_terminal_rollback" };
		await authority.initializeOrganization({ organizationId: rollbackOrganizationId });
		await authority.replaceSubjectRoles({ organizationId: rollbackOrganizationId, subject: rollbackPrincipal, roleIds: ["role_builtin_member"] });
		await authority.createServiceAccount({ organizationId: rollbackOrganizationId, serviceAccountId: "service_terminal_rollback", name: "Rollback machine", roleIds: ["role_builtin_member"] });
		const rollbackCredential = await authority.createServiceAccountCredential({ organizationId: rollbackOrganizationId, actorId: "principal_service_account", operationId: randomUUID(), serviceAccountId: "service_terminal_rollback" });
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await authority.archiveOrganization({ organizationId: rollbackOrganizationId, transaction: { rawTransactionQuery: client.query.bind(client) } });
			await client.query("ROLLBACK");
		} finally {
			client.release();
		}
		await expect(authority.readEffective({ organizationId: rollbackOrganizationId, subject: rollbackPrincipal })).resolves.toMatchObject({ actions: ["ac:read"] });
		await expect(authority.authenticateServiceAccountCredential({ secret: rollbackCredential.secret })).resolves.toMatchObject({ organizationId: rollbackOrganizationId, actions: ["ac:read"] });
		await expect(authority.archiveOrganization({ organizationId: "org_terminal_missing_revision" })).resolves.toEqual({
			organizationId: "org_terminal_missing_revision",
			previousRevision: "0",
			revision: "1",
			archived: true,
			removedAssignments: 0,
			disabledServiceAccounts: 0,
			revokedCredentials: 0,
		});
		await expect(authority.initializeOrganization({ organizationId: "org_terminal_missing_revision" })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
	});

	it("preserves active normalized organizations and terminalizes only organizations absent from both authorities", async () => {
		const reconciliationSchema = `authorization_reconcile_${randomUUID().replaceAll("-", "").slice(0, 8)}`;
		try {
			await admin.query(`CREATE SCHEMA "${reconciliationSchema}"; CREATE TABLE "${reconciliationSchema}"."organization" (id text PRIMARY KEY); CREATE TABLE "${reconciliationSchema}"."mgmt_organizations" (id text PRIMARY KEY, project_id text NOT NULL, environment_id text NOT NULL, status text NOT NULL)`);
			const reconciler = new PostgresAuthorizationAuthority(
				pool,
				{ ...identity, schema: reconciliationSchema, prefix: "reconcile7a", oneTimeSecretReplayCipher: replayCipher },
				{ schema: reconciliationSchema, table: "organization", management: { schema: reconciliationSchema, table: "mgmt_organizations" } },
			);
			await (await reconciler.planMigration()).apply();
			const activeOrganizationId = "org_reconcile_active";
			const managementOnlyOrganizationId = "org_reconcile_management_only";
			const absentOrganizationId = "org_reconcile_absent";
			await pool.query(`INSERT INTO "${reconciliationSchema}"."organization" (id) VALUES ($1)`, [activeOrganizationId]);
			await pool.query(`INSERT INTO "${reconciliationSchema}"."mgmt_organizations" (id, project_id, environment_id, status) VALUES ($1, $2, $3, 'active')`, [managementOnlyOrganizationId, identity.projectId, identity.environmentId]);
			await reconciler.initializeOrganization({ organizationId: activeOrganizationId });
			await reconciler.replaceSubjectRoles({ organizationId: activeOrganizationId, subject: { kind: "principal", id: "principal_reconcile_active" }, roleIds: ["role_builtin_member"] });
			await reconciler.initializeOrganization({ organizationId: managementOnlyOrganizationId });
			await reconciler.replaceSubjectRoles({ organizationId: managementOnlyOrganizationId, subject: { kind: "principal", id: "principal_reconcile_management_only" }, roleIds: ["role_builtin_member"] });
			await reconciler.initializeOrganization({ organizationId: absentOrganizationId });
			await reconciler.replaceSubjectRoles({ organizationId: absentOrganizationId, subject: { kind: "principal", id: "principal_reconcile_absent" }, roleIds: ["role_builtin_member"] });
			await reconciler.createServiceAccount({ organizationId: absentOrganizationId, serviceAccountId: "service_reconcile_absent", name: "Absent machine", roleIds: ["role_builtin_member"] });
			const absentCredential = await reconciler.createServiceAccountCredential({ organizationId: absentOrganizationId, actorId: "principal_service_account", operationId: randomUUID(), serviceAccountId: "service_reconcile_absent" });
			await pool.query(`ALTER TABLE "${reconciliationSchema}"."reconcile7a_authz_revisions" DROP COLUMN terminal`);
			await (await reconciler.planMigration()).apply();
			await expect(reconciler.reconcileRuntimeOrganizations()).resolves.toEqual({
				terminalizedOrganizations: 1,
				terminalizedOrganizationIds: [absentOrganizationId],
				removedAssignments: 2,
				disabledServiceAccounts: 1,
				revokedCredentials: 1,
			});
			await expect(reconciler.readEffective({ organizationId: activeOrganizationId, subject: { kind: "principal", id: "principal_reconcile_active" } })).resolves.toMatchObject({ actions: ["ac:read"] });
			await expect(reconciler.readEffective({ organizationId: managementOnlyOrganizationId, subject: { kind: "principal", id: "principal_reconcile_management_only" } })).resolves.toMatchObject({ actions: ["ac:read"] });
			await expect(reconciler.readEffective({ organizationId: absentOrganizationId, subject: { kind: "principal", id: "principal_reconcile_absent" } })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
			await expect(reconciler.authenticateServiceAccountCredential({ secret: absentCredential.secret })).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
			const archivedManagementOrganizationId = "org_reconcile_management_archived";
			await pool.query(`INSERT INTO "${reconciliationSchema}"."organization" (id) VALUES ($1)`, [archivedManagementOrganizationId]);
			await pool.query(`INSERT INTO "${reconciliationSchema}"."mgmt_organizations" (id, project_id, environment_id, status) VALUES ($1, $2, $3, 'archived')`, [archivedManagementOrganizationId, identity.projectId, identity.environmentId]);
			await reconciler.initializeOrganization({ organizationId: archivedManagementOrganizationId });
			await expect(reconciler.reconcileRuntimeOrganizations()).resolves.toEqual({ terminalizedOrganizations: 1, terminalizedOrganizationIds: [archivedManagementOrganizationId], removedAssignments: 0, disabledServiceAccounts: 0, revokedCredentials: 0 });
			await expect(reconciler.initializeOrganization({ organizationId: archivedManagementOrganizationId })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
			await expect(reconciler.reconcileRuntimeOrganizations()).resolves.toEqual({ terminalizedOrganizations: 0, terminalizedOrganizationIds: [], removedAssignments: 0, disabledServiceAccounts: 0, revokedCredentials: 0 });
		} finally {
			await admin.query(`DROP SCHEMA IF EXISTS "${reconciliationSchema}" CASCADE`);
		}
	});
});
