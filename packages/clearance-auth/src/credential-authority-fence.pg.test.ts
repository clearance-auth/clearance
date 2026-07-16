import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	PostgresCredentialAuthorityFence,
	bootstrapCredentialAuthorityFence,
} from "./credential-authority-fence.js";

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
			`Credential fence tests require Postgres at ${DATABASE_URL}`,
		);
	}
} finally {
	await probe.end();
}

describe.sequential.skipIf(!available)(
	"durable PostgreSQL credential-authority fence",
	() => {
		const schema = `credential_fence_${randomUUID().replaceAll("-", "").slice(0, 12)}`;
		const admin = new pg.Pool({ connectionString: DATABASE_URL });
		let pool: pg.Pool;
		let runtimeA: PostgresCredentialAuthorityFence;
		let runtimeB: PostgresCredentialAuthorityFence;
		let digestRuntime: PostgresCredentialAuthorityFence;

		beforeAll(async () => {
			await admin.query(`CREATE SCHEMA "${schema}"`);
			const url = new URL(DATABASE_URL);
			url.searchParams.set("options", `-csearch_path=${schema}`);
			pool = new pg.Pool({ connectionString: url.toString(), max: 8 });
			await bootstrapCredentialAuthorityFence(pool);
			runtimeA = new PostgresCredentialAuthorityFence(pool, {
				generation: "legacy-v1",
				deploymentId: "candidate-v03",
				instanceId: "runtime-a",
			});
			runtimeB = new PostgresCredentialAuthorityFence(pool, {
				generation: "legacy-v1",
				deploymentId: "candidate-v03",
				instanceId: "runtime-b",
			});
			digestRuntime = new PostgresCredentialAuthorityFence(pool, {
				generation: "digest-v1",
				deploymentId: "candidate-v03",
				instanceId: "runtime-digest",
			});
		});

		afterAll(async () => {
			await Promise.allSettled([
				runtimeA?.close(),
				runtimeB?.close(),
				digestRuntime?.close(),
			]);
			await pool?.end();
			await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await admin.end();
		});

		it("requires the exact bridge lease count before arming and draining", async () => {
			await runtimeA.assertRuntimeServing();
			await expect(
				runtimeA.arm({
					deploymentId: "candidate-v03",
					expectedRuntimeCount: 2,
				}),
			).rejects.toThrow("Expected 2 bridge runtime leases, found 1");

			const rogueRuntime = new PostgresCredentialAuthorityFence(pool, {
				generation: "legacy-v1",
				deploymentId: "other-candidate",
				instanceId: "runtime-rogue",
			});
			await rogueRuntime.assertRuntimeServing();
			await expect(
				runtimeA.arm({
					deploymentId: "candidate-v03",
					expectedRuntimeCount: 2,
				}),
			).rejects.toThrow("requested deployment cohort");
			await rogueRuntime.close();

			await runtimeB.assertRuntimeServing();
			const armed = await runtimeA.arm({
				deploymentId: "candidate-v03",
				expectedRuntimeCount: 2,
			});
			expect(armed).toMatchObject({
				phase: "legacy-open",
				generation: "legacy-v1",
				bridgeDeploymentId: "candidate-v03",
				expectedRuntimeCount: 2,
				activeRuntimeLeases: 2,
			});

			const draining = await runtimeA.beginDrain({
				deploymentId: "candidate-v03",
				drainId: "drain-v03",
			});
			expect(draining).toMatchObject({
				phase: "draining",
				drainId: "drain-v03",
				activeRuntimeLeases: 2,
			});
		});

		it("keeps paused runtimes fenced by session locks and resumes only the same drain", async () => {
			const migrator = new PostgresCredentialAuthorityFence(pool, {
				generation: "digest-v1",
				deploymentId: "candidate-v03",
				instanceId: "migrator",
			});
			await expect(
				migrator.withExclusiveMigrationLease({
					drainId: "drain-v03",
					allowUnarmedLegacyOpen: false,
					timeoutMs: 1_000,
					run: async () => undefined,
				}),
			).rejects.toThrow(
				"Timed out waiting for credential-capable runtimes to drain",
			);

			await Promise.all([
				runtimeA.releaseRuntimeLease(),
				runtimeB.releaseRuntimeLease(),
			]);
			await expect(
				migrator.withExclusiveMigrationLease({
					drainId: "stale-drain",
					allowUnarmedLegacyOpen: false,
					run: async () => undefined,
				}),
			).rejects.toThrow("is not authorized");

			await expect(digestRuntime.assertRuntimeServing()).rejects.toThrow(
				"cannot serve before digest publication",
			);
			await migrator.withExclusiveMigrationLease({
				drainId: "drain-v03",
				allowUnarmedLegacyOpen: false,
				run: async (client) => {
					const admission = await client.query<{
						drainId: string;
						exclusiveLocks: string;
					}>(`SELECT
						current_setting('clearance.credential_authority_drain_id', true) AS "drainId",
						(SELECT count(*)::text FROM pg_locks
						 WHERE pid = pg_backend_pid()
						   AND locktype = 'advisory'
						   AND mode = 'ExclusiveLock'
						   AND granted) AS "exclusiveLocks"`);
					expect(admission.rows[0]).toEqual({
						drainId: "drain-v03",
						exclusiveLocks: "1",
					});
				},
			});
			const afterLease = await pool.query<{ drainId: string | null }>(
				`SELECT nullif(current_setting('clearance.credential_authority_drain_id', true), '') AS "drainId"`,
			);
			expect(afterLease.rows[0]?.drainId).toBeNull();
			await expect(
				digestRuntime.assertRuntimeServing(),
			).resolves.toBeUndefined();
			await expect(runtimeA.assertRuntimeServing()).rejects.toThrow(
				"is fenced by digest-live/digest-v1",
			);
			await migrator.close();
		});

		it("rejects a same-named fence constraint with weaker semantics", async () => {
			const incompatibleSchema = `credential_fence_bad_${randomUUID().replaceAll("-", "").slice(0, 10)}`;
			await admin.query(`CREATE SCHEMA "${incompatibleSchema}"`);
			const url = new URL(DATABASE_URL);
			url.searchParams.set("options", `-csearch_path=${incompatibleSchema}`);
			const incompatiblePool = new pg.Pool({
				connectionString: url.toString(),
			});
			try {
				await bootstrapCredentialAuthorityFence(incompatiblePool);
				await incompatiblePool.query(`
					ALTER TABLE "credentialAuthorityFence"
						DROP CONSTRAINT "credentialAuthorityFence_state_v1";
					ALTER TABLE "credentialAuthorityFence"
						ADD CONSTRAINT "credentialAuthorityFence_state_v1" CHECK (true)
				`);
				await expect(
					bootstrapCredentialAuthorityFence(incompatiblePool),
				).rejects.toThrow("credentialAuthorityFence_state_v1 is incompatible");
			} finally {
				await incompatiblePool.end();
				await admin.query(
					`DROP SCHEMA IF EXISTS "${incompatibleSchema}" CASCADE`,
				);
			}
		});

		it("survives migrator backend loss and permits one same-drain racer to publish", async () => {
			const recoverySchema = `credential_fence_recovery_${randomUUID().replaceAll("-", "").slice(0, 10)}`;
			await admin.query(`CREATE SCHEMA "${recoverySchema}"`);
			const url = new URL(DATABASE_URL);
			url.searchParams.set("options", `-csearch_path=${recoverySchema}`);
			const recoveryPool = new pg.Pool({
				connectionString: url.toString(),
				max: 8,
			});
			const bridge = new PostgresCredentialAuthorityFence(recoveryPool, {
				generation: "legacy-v1",
				deploymentId: "recovery-deployment",
				instanceId: "recovery-bridge",
			});
			const killedMigrator = new PostgresCredentialAuthorityFence(
				recoveryPool,
				{
					generation: "digest-v1",
					deploymentId: "recovery-deployment",
					instanceId: "killed-migrator",
				},
			);
			const winner = new PostgresCredentialAuthorityFence(recoveryPool, {
				generation: "digest-v1",
				deploymentId: "recovery-deployment",
				instanceId: "winner-migrator",
			});
			const racer = new PostgresCredentialAuthorityFence(recoveryPool, {
				generation: "digest-v1",
				deploymentId: "recovery-deployment",
				instanceId: "racing-migrator",
			});
			try {
				await bootstrapCredentialAuthorityFence(recoveryPool);
				await bridge.assertRuntimeServing();
				await bridge.arm({
					deploymentId: "recovery-deployment",
					expectedRuntimeCount: 1,
				});
				await bridge.beginDrain({
					deploymentId: "recovery-deployment",
					drainId: "recovery-drain",
				});
				await bridge.releaseRuntimeLease();

				let killedPid = 0;
				await expect(
					killedMigrator.withExclusiveMigrationLease({
						drainId: "recovery-drain",
						allowUnarmedLegacyOpen: false,
						run: async (client) => {
							const result = await client.query<{ pid: number }>(
								"SELECT pg_backend_pid() AS pid",
							);
							killedPid = result.rows[0]!.pid;
							await admin.query("SELECT pg_terminate_backend($1)", [killedPid]);
							await client.query("SELECT 1");
						},
					}),
				).rejects.toThrow();
				expect(killedPid).toBeGreaterThan(0);
				expect(await killedMigrator.status()).toMatchObject({
					phase: "migrating",
					generation: "legacy-v1",
					drainId: "recovery-drain",
				});

				let releaseWinner!: () => void;
				const winnerRelease = new Promise<void>((resolve) => {
					releaseWinner = resolve;
				});
				let winnerEntered!: () => void;
				const entered = new Promise<void>((resolve) => {
					winnerEntered = resolve;
				});
				let winnerPid = 0;
				const winningMigration = winner.withExclusiveMigrationLease({
					drainId: "recovery-drain",
					allowUnarmedLegacyOpen: false,
					run: async (client) => {
						winnerPid = (
							await client.query<{ pid: number }>(
								"SELECT pg_backend_pid() AS pid",
							)
						).rows[0]!.pid;
						winnerEntered();
						await winnerRelease;
					},
				});
				await entered;
				const racingMigration = racer.withExclusiveMigrationLease({
					drainId: "recovery-drain",
					allowUnarmedLegacyOpen: false,
					timeoutMs: 5_000,
					run: async () => undefined,
				});
				releaseWinner();
				await winningMigration;
				await expect(racingMigration).rejects.toThrow("is not authorized");
				expect(winnerPid).toBeGreaterThan(0);
				expect(winnerPid).not.toBe(killedPid);
				expect(await winner.status()).toMatchObject({
					phase: "digest-live",
					generation: "digest-v1",
					drainId: "recovery-drain",
				});
			} finally {
				await Promise.allSettled([
					bridge.close(),
					killedMigrator.close(),
					winner.close(),
					racer.close(),
				]);
				await recoveryPool.end();
				await admin.query(`DROP SCHEMA IF EXISTS "${recoverySchema}" CASCADE`);
			}
		});
	},
);
