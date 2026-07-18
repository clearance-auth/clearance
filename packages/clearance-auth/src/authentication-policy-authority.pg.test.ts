import { randomUUID } from "node:crypto";
import type { RuntimeAuthenticationPolicy } from "../../core/src/types/authentication-policy.js";
import pg from "pg";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
	PostgresAuthenticationPolicyAuthority,
	PostgresAuthenticationPolicyAuthorityError,
} from "./authentication-policy-authority.js";
import {
	createClearanceAuth,
	type ClearanceAuthBundle,
} from "./create-auth.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const probe = new pg.Pool({
	connectionString: DATABASE_URL,
	connectionTimeoutMillis: 500,
});
let available = false;
try {
	await probe.query("SELECT 1");
	available = true;
} catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
		throw new Error(
			`Authentication-policy authority tests require Postgres at ${DATABASE_URL}`,
		);
	}
} finally {
	await probe.end();
}

const identity = Object.freeze({
	projectId: "project_policy",
	environmentId: "environment_policy",
});

const seed = Object.freeze({
	passwordLockout: Object.freeze({
		enabled: true,
		maxFailedAttempts: 10,
		durationSeconds: 900,
	}),
	factorLockout: Object.freeze({
		enabled: true,
		maxFailedAttempts: 5,
		durationSeconds: 600,
	}),
	minimumAssurance: "single_factor",
	allowedFactors: Object.freeze({ totp: true, passkey: true }),
	trustedDevice: Object.freeze({ enabled: true, maxAgeSeconds: 86_400 }),
	assuranceMaxAgeSeconds: null,
}) satisfies RuntimeAuthenticationPolicy;

function schemaUrl(schema: string): string {
	const url = new URL(DATABASE_URL);
	url.searchParams.set("options", `-csearch_path=${schema}`);
	return url.toString();
}

async function createRuntimeIdentityTables(pool: pg.Pool): Promise<void> {
	await pool.query(`
		CREATE TABLE "user" (id text PRIMARY KEY);
		CREATE TABLE organization (id text PRIMARY KEY);
		CREATE TABLE member (
			id text PRIMARY KEY,
			"organizationId" text NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
			"userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE
		)
	`);
}

describe.sequential.skipIf(!available)(
	"PostgreSQL authentication-policy authority",
	() => {
		const schema = `auth_policy_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
		const admin = new pg.Pool({ connectionString: DATABASE_URL });
		let pool: pg.Pool;
		let authority: PostgresAuthenticationPolicyAuthority;

		beforeAll(async () => {
			await admin.query(`CREATE SCHEMA "${schema}"`);
			pool = new pg.Pool({ connectionString: schemaUrl(schema), max: 6 });
			await createRuntimeIdentityTables(pool);
			authority = new PostgresAuthenticationPolicyAuthority(pool, identity, seed);
		});

		afterEach(async () => {
			await pool?.query(`DROP TABLE IF EXISTS "twoFactor", account`);
		});

		afterAll(async () => {
			await pool?.end();
			await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await admin.end();
		});

		it("plans, applies, verifies, and idempotently preserves the first seed", async () => {
			const plan = await authority.planMigration();
			expect(plan).toMatchObject({
				pendingTables: 2,
				pendingFields: 36,
				pendingSecurityMigrations: ["authentication-policy-authority-v1"],
			});
			const sql = await plan.compileSql();
			expect(await plan.compileSql()).toBe(sql);
			expect(sql).toContain('CREATE TABLE "authenticationPolicy"');
			expect(sql).toContain(
				'CREATE TABLE "authenticationPolicyOrganizationOverride"',
			);
			await pool.query(`BEGIN; ${sql} ROLLBACK;`);

			await plan.apply();
			const installed = await authority.planMigration();
			expect(installed).toMatchObject({
				pendingTables: 0,
				pendingFields: 0,
				pendingSecurityMigrations: [],
			});
			expect(await installed.compileSql()).toBe("");

			const catalog = await pool.query<{
				tableName: string;
				columns: string;
			}>(`SELECT c.relname AS "tableName", count(a.attname)::text AS columns
				FROM pg_class c
				JOIN pg_namespace n ON n.oid = c.relnamespace
				JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
				WHERE n.nspname = current_schema()
				  AND c.relname IN ('authenticationPolicy', 'authenticationPolicyOrganizationOverride')
				GROUP BY c.relname ORDER BY c.relname`);
			expect(catalog.rows).toEqual([
				{ tableName: "authenticationPolicy", columns: "17" },
				{
					tableName: "authenticationPolicyOrganizationOverride",
					columns: "19",
				},
			]);

			await pool.query(
				`UPDATE "authenticationPolicy"
				 SET revision = 2, "passwordLockoutMaxFailedAttempts" = 7
				 WHERE "projectId" = $1 AND "environmentId" = $2`,
				[identity.projectId, identity.environmentId],
			);
			const differentSeed: RuntimeAuthenticationPolicy = {
				...seed,
				passwordLockout: { ...seed.passwordLockout, maxFailedAttempts: 99 },
			};
			const replica = new PostgresAuthenticationPolicyAuthority(
				pool,
				identity,
				differentSeed,
			);
			await (await replica.planMigration()).apply();
			const persisted = await pool.query<{
				revision: string;
				maxFailedAttempts: number;
			}>(`SELECT revision::text AS revision,
			          "passwordLockoutMaxFailedAttempts" AS "maxFailedAttempts"
			   FROM "authenticationPolicy"
			   WHERE "projectId" = $1 AND "environmentId" = $2`, [
				identity.projectId,
				identity.environmentId,
			]);
			expect(persisted.rows[0]).toEqual({
				revision: "2",
				maxFailedAttempts: 7,
			});
		});

		it("uses one statement for exact subject, membership, override, and ambient reads", async () => {
			await pool.query(`WITH inserted_user AS (
				INSERT INTO "user" (id) VALUES ('user_policy') RETURNING id
			), inserted_organization AS (
				INSERT INTO organization (id) VALUES ('org_policy') RETURNING id
			), inserted_member AS (
				INSERT INTO member (id, "organizationId", "userId")
				SELECT 'member_policy', inserted_organization.id, inserted_user.id
				FROM inserted_organization, inserted_user
				RETURNING id
			)
				INSERT INTO "authenticationPolicyOrganizationOverride" (
					"projectId", "environmentId", "organizationId", revision,
					"minimumAssurance", "allowedFactorTotp",
					"assuranceMaxAgeSecondsSet", "assuranceMaxAgeSeconds"
				) SELECT $1, $2, 'org_policy', 2, 'multi_factor', true, true, NULL
				FROM inserted_member
			`, [identity.projectId, identity.environmentId]);

			const poolQuery = vi.spyOn(pool, "query");
			poolQuery.mockClear();
			const direct = await authority.readForSubject({
				subjectId: "user_policy",
				organizationId: "org_policy",
				minimumRevision: "2",
			});
			expect(poolQuery).toHaveBeenCalledTimes(1);
			expect(direct).toMatchObject({
				scope: identity,
				subjectId: "user_policy",
				revision: "2",
				organizationMembership: {
					subjectId: "user_policy",
					organizationId: "org_policy",
				},
				organizationOverride: {
					organizationId: "org_policy",
					revision: "2",
					policy: {
						minimumAssurance: "multi_factor",
						allowedFactors: { totp: true },
						assuranceMaxAgeSeconds: null,
					},
				},
				effective: {
					minimumAssurance: "multi_factor",
					assuranceMaxAgeSeconds: null,
				},
			});
			poolQuery.mockRestore();

			const client = await pool.connect();
			try {
				await client.query("BEGIN");
				const rawTransactionQuery = vi.fn(
					async (text: string, values: readonly unknown[] = []) => {
						const result = await client.query(text, [...values]);
						return { rows: result.rows, rowCount: result.rowCount };
					},
				);
				const ambient = await authority.readForSubject({
					subjectId: "user_policy",
					organizationId: "org_policy",
					transaction: { rawTransactionQuery } as never,
				});
				expect(rawTransactionQuery).toHaveBeenCalledTimes(1);
				expect(ambient.effective.minimumAssurance).toBe("multi_factor");
				await client.query("ROLLBACK");
			} finally {
				client.release();
			}
		});

		it("fails closed after membership loss and on an authority outage", async () => {
			await expect(
				authority.readForSubject({
					subjectId: "user_policy",
					organizationId: "org_policy",
				}),
			).resolves.toMatchObject({ revision: "2" });
			await pool.query(`DELETE FROM member WHERE id = 'member_policy'`);
			await expect(
				authority.readForSubject({
					subjectId: "user_policy",
					organizationId: "org_policy",
				}),
			).rejects.toThrow("returned no exact subject scope");

			const poolQuery = vi
				.spyOn(pool, "query")
				.mockRejectedValueOnce(new Error("simulated database outage") as never);
			await expect(
				authority.readForSubject({ subjectId: "user_policy" }),
			).rejects.toThrow("authentication-policy read failed");
			poolQuery.mockRestore();
		});

		it("manages revisioned policy and redacted password/factor unlock authority", async () => {
			const initial = await authority.get();
			expect(initial).toMatchObject({
				schemaVersion: "v1",
				scope: identity,
				revision: "2",
				organizationOverride: null,
			});
			const noOpPlan = await authority.plan({ policy: initial.environment });
			expect(noOpPlan).toMatchObject({
				expectedRevision: "2",
				candidateRevision: "2",
				wouldChange: false,
			});
			await expect(
				authority.apply({
					policy: initial.environment,
					expectedRevision: "2",
				}),
			).resolves.toMatchObject({ changed: false, revision: "2" });

			const environmentCandidate: RuntimeAuthenticationPolicy = {
				...initial.environment,
				passwordLockout: {
					...initial.environment.passwordLockout,
					maxFailedAttempts: 8,
				},
			};
			const environmentPlan = await authority.plan({ policy: environmentCandidate });
			expect(environmentPlan).toMatchObject({
				expectedRevision: "2",
				candidateRevision: "3",
				wouldChange: true,
			});
			const concurrentApplies = await Promise.allSettled([
				authority.apply({
					policy: environmentCandidate,
					expectedRevision: "2",
				}),
				authority.apply({
					policy: environmentCandidate,
					expectedRevision: "2",
				}),
			]);
			expect(concurrentApplies.filter((result) => result.status === "fulfilled"))
				.toHaveLength(1);
			const rejectedApply = concurrentApplies.find(
				(result) => result.status === "rejected",
			);
			expect(rejectedApply).toMatchObject({
				status: "rejected",
				reason: { code: "AUTHENTICATION_POLICY_REVISION_CONFLICT" },
			});
			await expect(authority.get()).resolves.toMatchObject({
				revision: "3",
				environment: environmentCandidate,
			});

			const organizationPolicy = {
				minimumAssurance: "multi_factor" as const,
				allowedFactors: { totp: true },
			};
			const organizationPlan = await authority.plan({
				organizationId: "org_policy",
				policy: organizationPolicy,
			});
			expect(organizationPlan).toMatchObject({
				expectedRevision: "3",
				candidateRevision: "4",
				wouldChange: true,
				candidate: { effective: { minimumAssurance: "multi_factor" } },
			});
			await authority.apply({
				organizationId: "org_policy",
				policy: organizationPolicy,
				expectedRevision: "3",
			});
			await expect(
				authority.get({ organizationId: "org_policy" }),
			).resolves.toMatchObject({
				revision: "4",
				organizationOverride: {
					organizationId: "org_policy",
					revision: "4",
					policy: organizationPolicy,
				},
				effective: { minimumAssurance: "multi_factor" },
			});
			const deletePlan = await authority.plan({
				organizationId: "org_policy",
				policy: null,
			});
			expect(deletePlan).toMatchObject({
				expectedRevision: "4",
				candidateRevision: "5",
				wouldChange: true,
			});
			await authority.apply({
				organizationId: "org_policy",
				policy: null,
				expectedRevision: "4",
			});
			await expect(
				authority.get({ organizationId: "org_policy" }),
			).resolves.toMatchObject({
				revision: "5",
				organizationOverride: null,
				effective: environmentCandidate,
			});

			await pool.query(`
				CREATE TABLE account (
					id text PRIMARY KEY,
					"userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
					"providerId" text NOT NULL,
					password text,
					"failedPasswordAttempts" integer,
					"activePasswordAttemptReservations" text,
					"passwordLockedUntil" timestamptz,
					"refreshToken" text
				);
				CREATE TABLE "twoFactor" (
					id text PRIMARY KEY,
					"userId" text NOT NULL UNIQUE REFERENCES "user"(id) ON DELETE CASCADE,
					secret text NOT NULL,
					"failedVerificationCount" integer,
					"activeVerificationReservations" text,
					"lockedUntil" timestamptz,
					"lastUsedTotpCounter" integer,
					"trustDeviceGeneration" text
				);
				INSERT INTO account (
					id, "userId", "providerId", password,
					"failedPasswordAttempts", "activePasswordAttemptReservations",
					"passwordLockedUntil", "refreshToken"
				) VALUES (
					'account_policy', 'user_policy', 'credential', 'password-digest',
					4, '[{"id":"password-reservation"}]', now() + interval '10 minutes',
					'refresh-preserved'
				);
				INSERT INTO "twoFactor" (
					id, "userId", secret, "failedVerificationCount",
					"activeVerificationReservations", "lockedUntil",
					"lastUsedTotpCounter", "trustDeviceGeneration"
				) VALUES (
					'factor_policy', 'user_policy', 'factor-secret-preserved', 3,
					'[{"id":"factor-reservation"}]', now() + interval '10 minutes',
					42, 'trust-generation-preserved'
				);
			`);
			const unlockPlan = await authority.planUnlock({
				userId: "user_policy",
				kind: "all",
			});
			expect(unlockPlan).toEqual({
				schemaVersion: "v1",
				userId: "user_policy",
				kind: "all",
				password: {
					matchedRows: 1,
					failedAttemptRows: 1,
					reservationRows: 1,
					lockedRows: 1,
					wouldChangeRows: 1,
				},
				factor: {
					matchedRows: 1,
					failedAttemptRows: 1,
					reservationRows: 1,
					lockedRows: 1,
					wouldChangeRows: 1,
				},
				wouldChange: true,
			});
			await expect(
				authority.unlock({ userId: "user_policy", kind: "all" }),
			).resolves.toMatchObject({ changed: true, wouldChange: true });
			const passwordState = await pool.query(
				`SELECT password, "refreshToken", "failedPasswordAttempts",
				        "activePasswordAttemptReservations", "passwordLockedUntil"
				 FROM account WHERE id = 'account_policy'`,
			);
			expect(passwordState.rows[0]).toEqual({
				password: "password-digest",
				refreshToken: "refresh-preserved",
				failedPasswordAttempts: 0,
				activePasswordAttemptReservations: "[]",
				passwordLockedUntil: null,
			});
			const factorState = await pool.query(
				`SELECT secret, "lastUsedTotpCounter", "trustDeviceGeneration",
				        "failedVerificationCount", "activeVerificationReservations", "lockedUntil"
				 FROM "twoFactor" WHERE id = 'factor_policy'`,
			);
			expect(factorState.rows[0]).toEqual({
				secret: "factor-secret-preserved",
				lastUsedTotpCounter: 42,
				trustDeviceGeneration: "trust-generation-preserved",
				failedVerificationCount: 0,
				activeVerificationReservations: "[]",
				lockedUntil: null,
			});
		});

		it("rejects incompatible authority and rolls back failed fresh installation", async () => {
			const incompatibleSchema = `auth_policy_bad_${randomUUID().replaceAll("-", "").slice(0, 10)}`;
			const rollbackSchema = `auth_policy_rb_${randomUUID().replaceAll("-", "").slice(0, 10)}`;
			await admin.query(`CREATE SCHEMA "${incompatibleSchema}"`);
			await admin.query(`CREATE SCHEMA "${rollbackSchema}"`);
			const incompatiblePool = new pg.Pool({
				connectionString: schemaUrl(incompatibleSchema),
			});
			const rollbackPool = new pg.Pool({
				connectionString: schemaUrl(rollbackSchema),
			});
			try {
				await incompatiblePool.query(
					`CREATE TABLE "authenticationPolicy" ("projectId" text)`,
				);
				const incompatible = new PostgresAuthenticationPolicyAuthority(
					incompatiblePool,
					identity,
					seed,
				);
				await expect(incompatible.planMigration()).rejects.toBeInstanceOf(
					PostgresAuthenticationPolicyAuthorityError,
				);
				const untouched = await incompatiblePool.query<{ columns: string }>(
					`SELECT count(*)::text AS columns
					 FROM information_schema.columns
					 WHERE table_schema = current_schema()
					   AND table_name = 'authenticationPolicy'`,
				);
				expect(untouched.rows[0]?.columns).toBe("1");

				await rollbackPool.query(`CREATE TABLE "user" (id text PRIMARY KEY)`);
				const rollbackAuthority = new PostgresAuthenticationPolicyAuthority(
					rollbackPool,
					identity,
					seed,
				);
				await expect(
					(await rollbackAuthority.planMigration()).apply(),
				).rejects.toThrow("migration failed");
				const rolledBack = await rollbackPool.query<{
					policy: string | null;
					override: string | null;
				}>(`SELECT
					to_regclass(format('%I.%I', current_schema(), 'authenticationPolicy'))::text AS policy,
					to_regclass(format('%I.%I', current_schema(), 'authenticationPolicyOrganizationOverride'))::text AS override`);
				expect(rolledBack.rows[0]).toEqual({ policy: null, override: null });
			} finally {
				await incompatiblePool.end();
				await rollbackPool.end();
				await admin.query(`DROP SCHEMA IF EXISTS "${incompatibleSchema}" CASCADE`);
				await admin.query(`DROP SCHEMA IF EXISTS "${rollbackSchema}" CASCADE`);
			}
		});

		it("rejects selectable collision tables without authority constraints on a direct read", async () => {
			const collisionSchema = `auth_policy_collision_${randomUUID().replaceAll("-", "").slice(0, 10)}`;
			await admin.query(`CREATE SCHEMA "${collisionSchema}"`);
			const collisionPool = new pg.Pool({
				connectionString: schemaUrl(collisionSchema),
			});
			try {
				await createRuntimeIdentityTables(collisionPool);
				await collisionPool.query(`
					CREATE TABLE "authenticationPolicy" (
						LIKE "${schema}"."authenticationPolicy" INCLUDING DEFAULTS
					);
					CREATE TABLE "authenticationPolicyOrganizationOverride" (
						LIKE "${schema}"."authenticationPolicyOrganizationOverride" INCLUDING DEFAULTS
					);
					INSERT INTO "user" (id) VALUES ('collision_user');
					INSERT INTO "authenticationPolicy"
					SELECT *
					FROM "${schema}"."authenticationPolicy"
					WHERE "projectId" = '${identity.projectId}'
						AND "environmentId" = '${identity.environmentId}';
				`);

				const selectable = await collisionPool.query<{ count: string }>(
					`SELECT count(*)::text AS count FROM "authenticationPolicy"`,
				);
				expect(selectable.rows[0]?.count).toBe("1");
				const authorityConstraints = await collisionPool.query<{ count: string }>(
					`SELECT count(*)::text AS count
					 FROM pg_constraint constraint_row
					 JOIN pg_class relation ON relation.oid = constraint_row.conrelid
					 JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
					 WHERE namespace.nspname = current_schema()
					   AND relation.relname IN (
						'authenticationPolicy',
						'authenticationPolicyOrganizationOverride'
					   )`,
				);
				expect(authorityConstraints.rows[0]?.count).toBe("0");

				const collisionAuthority = new PostgresAuthenticationPolicyAuthority(
					collisionPool,
					identity,
					seed,
				);
				await expect(
					collisionAuthority.readForSubject({ subjectId: "collision_user" }),
				).rejects.toThrow("returned no exact subject scope");
			} finally {
				await collisionPool.end();
				await admin.query(`DROP SCHEMA IF EXISTS "${collisionSchema}" CASCADE`);
			}
		});
	},
);

describe.sequential.skipIf(!available)(
	"managed authentication-policy product integration",
	() => {
		it("binds the exact product scope and migrates policy after runtime schema", async () => {
			const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
			const schema = `auth_policy_product_${suffix}`;
			const admin = new pg.Pool({ connectionString: DATABASE_URL });
			let bundle: ClearanceAuthBundle | undefined;
			let blockerPool: pg.Pool | undefined;
			let blocker: pg.PoolClient | undefined;
			try {
				await admin.query(`CREATE SCHEMA "${schema}"`);
				const databaseUrl = schemaUrl(schema);
				blockerPool = new pg.Pool({ connectionString: databaseUrl });
				blocker = await blockerPool.connect();
				bundle = createClearanceAuth({
					baseURL: "http://localhost:3300",
					secret: "managed-policy-product-integration-secret!!",
					databaseUrl,
					enableSso: false,
					enableScim: false,
					passkeys: false,
					authenticationPolicy: {
						projectId: `project_${suffix}`,
						environmentId: `environment_${suffix}`,
					},
					authenticationSecurity: {
						twoFactor: { enabled: false },
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: { enabled: false },
					},
				});
				const plan = await bundle.planMigrations();
				expect(plan.pendingSecurityMigrations).toContain(
					"authentication-policy-authority-v1",
				);

				await blocker.query(
					"SELECT pg_advisory_lock(hashtextextended(current_schema() || ':clearance:authentication-policy-authority:v1', 0))",
				);
				const migration = bundle.migrate();
				let phase = (await bundle.credentialAuthority.status()).phase;
				for (let attempt = 0; phase !== "migrating" && attempt < 100; attempt++) {
					await new Promise((resolve) => setTimeout(resolve, 10));
					phase = (await bundle.credentialAuthority.status()).phase;
				}
				expect(phase).toBe("migrating");
				expect(
					await Promise.race([
						migration.then(
							() => "settled",
							() => "settled",
						),
						new Promise<string>((resolve) =>
							setTimeout(() => resolve("blocked"), 25),
						),
					]),
				).toBe("blocked");
				await blocker.query(
					"SELECT pg_advisory_unlock(hashtextextended(current_schema() || ':clearance:authentication-policy-authority:v1', 0))",
				);
				await migration;
				expect(bundle.authenticationPolicy).toBeDefined();
				await expect(bundle.authenticationPolicy!.get()).resolves.toMatchObject({
					schemaVersion: "v1",
					scope: {
						projectId: `project_${suffix}`,
						environmentId: `environment_${suffix}`,
					},
					revision: "1",
				});
				const signup = await bundle.auth.api.signUpEmail({
					body: {
						email: `managed-policy-${suffix}@example.test`,
						password: "correct-horse-battery",
						name: "Managed Policy",
					},
				});
				expect(signup.token).toBeTruthy();
				const sessionAuthority = await bundle.pool.query<{
					projectId: string;
					environmentId: string;
					revision: string;
				}>(`SELECT "authenticationPolicyProjectId" AS "projectId",
				          "authenticationPolicyEnvironmentId" AS "environmentId",
				          "authenticationPolicyRevision" AS revision
				   FROM session WHERE "userId" = $1`, [signup.user.id]);
				expect(sessionAuthority.rows).toEqual([
					{
						projectId: `project_${suffix}`,
						environmentId: `environment_${suffix}`,
						revision: "1",
					},
				]);

				const persisted = await bundle.pool.query<{
					projectId: string;
					environmentId: string;
					revision: string;
					minimumAssurance: string;
					allowedFactorTotp: boolean;
					allowedFactorPasskey: boolean;
				}>(`SELECT "projectId", "environmentId", revision::text AS revision,
				          "minimumAssurance", "allowedFactorTotp", "allowedFactorPasskey"
				   FROM "authenticationPolicy"`);
				expect(persisted.rows).toEqual([
					{
						projectId: `project_${suffix}`,
						environmentId: `environment_${suffix}`,
						revision: "1",
						minimumAssurance: "single_factor",
						allowedFactorTotp: false,
						allowedFactorPasskey: false,
					},
				]);
				expect(
					(await bundle.planMigrations()).pendingSecurityMigrations,
				).not.toContain("authentication-policy-authority-v1");

				await bundle.pool.query(
					`ALTER TABLE "authenticationPolicy" RENAME TO "authenticationPolicyUnavailable"`,
				);
				await expect(
					bundle.auth.api.signUpEmail({
						body: {
							email: `managed-policy-outage-${suffix}@example.test`,
							password: "correct-horse-battery",
							name: "Managed Policy Outage",
						},
					}),
				).rejects.toThrow();
				const sessionCount = await bundle.pool.query<{ count: string }>(
					`SELECT count(*)::text AS count FROM session`,
				);
				expect(sessionCount.rows[0]?.count).toBe("1");
			} finally {
				if (blocker) {
					await blocker
						.query(
							"SELECT pg_advisory_unlock(hashtextextended(current_schema() || ':clearance:authentication-policy-authority:v1', 0))",
						)
						.catch(() => undefined);
					blocker.release();
				}
				await blockerPool?.end();
				await bundle?.destroy();
				await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await admin.end();
			}
		});
	},
);
