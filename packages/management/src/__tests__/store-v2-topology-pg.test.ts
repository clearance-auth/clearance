import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { initProject } from "../services/core.js";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { gatePostgresSuite } from "./pg-gate.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TABLE = `clearance_store_v2_topology_${process.pid}`;
const PREFIX = `${TABLE}_n_`;
const available = await gatePostgresSuite(DATABASE_URL, "store-v2-topology-pg");

describe.skipIf(!available)("PgStore store-v2 topology authority", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const store of stores) await store.destroy().catch(() => undefined);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			for (const table of [
				`${PREFIX}events`,
				`${PREFIX}principals`,
				`${PREFIX}organizations`,
				`${PREFIX}environments`,
				`${PREFIX}projects`,
				`${PREFIX}meta`,
				`${TABLE}_principal_email`,
				`${TABLE}_organization_slug`,
				`${TABLE}_idempotency`,
				TABLE,
			]) {
				await pool.query(`DROP TABLE IF EXISTS ${table}`);
			}
		} finally {
			await pool.end();
		}
	});

	it("imports, pages, fences, and rolls back the parent chain without snapshot caching", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TABLE,
			normalizedPrefix: PREFIX,
		});
		stores.push(store);
		const initialized = initProject(store, {
			name: "Topology Authority",
			source: "cli",
		});
		const now = "2026-07-18T00:00:00.000Z";
		await store.mutateDurable((data) => {
			data.organizations.push({
				id: "org_imported",
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
				name: "Imported",
				slug: "imported",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});

		await store.storeV2!.apply();
		const shadowStatePool = new pg.Pool({ connectionString: DATABASE_URL });
		let shadowCountBefore = 0;
		try {
			const result = await shadowStatePool.query<{ count: number }>(
				`SELECT (value->>'organizationCount')::integer AS count
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			shadowCountBefore = result.rows[0]!.count;
		} finally {
			await shadowStatePool.end();
		}
		await store.mutateDurable((data) => {
			data.organizations.push({
				id: "org_shadow",
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
				name: "Shadow Write",
				slug: "shadow-write",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});
		expect((await store.storeV2!.verify()).consistent).toBe(true);
		const shadowStateAfter = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			const result = await shadowStateAfter.query<{ count: number }>(
				`SELECT (value->>'organizationCount')::integer AS count
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			expect(result.rows).toEqual([{ count: shadowCountBefore + 1 }]);
		} finally {
			await shadowStateAfter.end();
		}
		await store.storeV2!.cutoverEvents();
		const cutover = await store.storeV2!.cutoverTopology();
		expect(cutover.authoritativeCollections).toEqual(
			expect.arrayContaining([
				"events",
				"projects",
				"environments",
				"organizations",
			]),
		);
		expect(store.storeV2Topology?.authoritative).toBe(true);
		expect(store.snapshot.projects).toEqual([]);
		expect(store.snapshot.environments).toEqual([]);
		expect(store.snapshot.organizations).toEqual([]);
		await expect(
			store.mutateDurable((data) => {
				data.projects.push({
					id: "project_legacy_writer",
					name: "Legacy Writer",
					slug: "legacy-writer",
					createdAt: now,
					updatedAt: now,
				});
			}),
		).rejects.toMatchObject({ code: "STORE_V2_TOPOLOGY_TYPED_MUTATION_REQUIRED" });

		const first = await store.storeV2Topology!.listProjectsPage({ limit: 1 });
		expect(first.projects).toEqual([
			expect.objectContaining({ id: initialized.project.id }),
		]);
		expect(
			await store.storeV2Topology!.listEnvironmentsPage({
				projectId: initialized.project.id,
				limit: 1,
			}),
		).toMatchObject({
			environments: [expect.objectContaining({ id: initialized.environment.id })],
		});

		const scope = {
			projectId: initialized.project.id,
			environmentId: initialized.environment.id,
		};
		const insertedTopology = await store.mutateStoreV2Topology!(async (topology) => ({
			project: await topology.upsertProject({
				id: "project_direct",
				name: "Direct Project",
				slug: "direct-project",
				createdAt: now,
				updatedAt: now,
			}),
			environment: await topology.upsertEnvironment({
				id: "environment_direct",
				projectId: "project_direct",
				name: "Direct Environment",
				slug: "direct-environment",
				kind: "development",
				createdAt: now,
				updatedAt: now,
			}),
		}));
		const directTopologyState = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			const result = await directTopologyState.query<{
				projects: number;
				environments: number;
				organizations: number;
			}>(
				`SELECT (value->>'projectCount')::integer AS projects,
				        (value->>'environmentCount')::integer AS environments,
				        (value->>'organizationCount')::integer AS organizations
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			expect(result.rows).toEqual([
				{ projects: 2, environments: 2, organizations: shadowCountBefore + 1 },
			]);
		} finally {
			await directTopologyState.end();
		}
		expect(
			(
				await store.storeV2Topology!.listOrganizationsPage({
					scope,
					limit: 10,
				})
			).organizations.map((organization) => organization.id),
		).toEqual(["org_imported", "org_shadow"]);

		const snapshotLocker = new pg.Pool({ connectionString: DATABASE_URL });
		const lockClient = await snapshotLocker.connect();
		try {
			await lockClient.query("BEGIN");
			await lockClient.query(`SELECT id FROM ${TABLE} WHERE id = 1 FOR UPDATE`);
			const writeOne = store.mutateStoreV2Topology!((topology) =>
				topology.upsertOrganization({
					id: "org_live_one",
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					name: "Live One",
					slug: "live-one",
					status: "active",
					createdAt: now,
					updatedAt: now,
				}),
			);
			const writeTwo = store.mutateStoreV2Topology!((topology) =>
				topology.upsertOrganization({
					id: "org_live_two",
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					name: "Live Two",
					slug: "live-two",
					status: "active",
					createdAt: now,
					updatedAt: now,
				}),
			);
			await expect(
				Promise.race([
					Promise.all([writeOne, writeTwo]).then(() => true),
					new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 500)),
				]),
			).resolves.toBe(true);
			await lockClient.query("COMMIT");
			const result = await lockClient.query<{
				projects: number;
				environments: number;
				organizations: number;
			}>(
				`SELECT (value->>'projectCount')::integer AS projects,
				        (value->>'environmentCount')::integer AS environments,
				        (value->>'organizationCount')::integer AS organizations
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			expect(result.rows).toEqual([
				{ projects: 2, environments: 2, organizations: shadowCountBefore + 3 },
			]);
		} finally {
			await lockClient.query("ROLLBACK").catch(() => undefined);
			lockClient.release();
			await snapshotLocker.end();
		}

		expect(store.snapshot.organizations).toEqual([]);
		const organizationPage = await store.storeV2Topology!.listOrganizationsPage({
			scope,
			limit: 1,
		});
		const organizationCursor = organizationPage.organizations[0]!;
		expect(
			(
				await store.storeV2Topology!.listOrganizationsPage({
					scope,
					limit: 10,
					cursor: {
						createdAt: organizationCursor.createdAt,
						id: organizationCursor.id,
					},
				})
			).organizations.map((organization) => organization.id),
		).toEqual(["org_live_one", "org_live_two", "org_shadow"]);

		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await pool.query(
				`UPDATE ${PREFIX}projects
				 SET created_at = '2026-07-18T00:00:00.111222Z'::timestamptz
				 WHERE id = 'project_direct'`,
			);
			await pool.query(
				`UPDATE ${PREFIX}environments
				 SET created_at = '2026-07-18T00:00:00.112222Z'::timestamptz
				 WHERE id = 'environment_direct'`,
			);
			const microsecondProject = await store.storeV2Topology!.getProjectById(
				insertedTopology.project.id,
			);
			const microsecondEnvironment =
				await store.storeV2Topology!.getEnvironment({
					projectId: insertedTopology.project.id,
					id: insertedTopology.environment.id,
				});
			expect(microsecondProject?.createdAt).toBe(
				"2026-07-18T00:00:00.111Z",
			);
			expect(microsecondEnvironment?.createdAt).toBe(
				"2026-07-18T00:00:00.112Z",
			);
			expect(
				(
					await store.storeV2Topology!.listProjectsPage({
						limit: 10,
						cursor: {
							createdAt: microsecondProject!.createdAt,
							id: microsecondProject!.id,
						},
					})
				).projects.map((project) => project.id),
			).not.toContain("project_direct");
			expect(
				(
					await store.storeV2Topology!.listEnvironmentsPage({
						projectId: insertedTopology.project.id,
						limit: 10,
						cursor: {
							createdAt: microsecondEnvironment!.createdAt,
							id: microsecondEnvironment!.id,
						},
					})
				).environments.map((environment) => environment.id),
			).not.toContain("environment_direct");
			await pool.query(
				`UPDATE ${PREFIX}organizations
				 SET created_at = '2026-07-18T00:00:00.123456Z'::timestamptz
				 WHERE id = 'org_live_one'`,
			);
			const microsecondMapped = await store.storeV2Topology!.getOrganization({
				scope,
				id: "org_live_one",
			});
			expect(microsecondMapped?.createdAt).toBe(
				"2026-07-18T00:00:00.123Z",
			);
			expect(
				(
					await store.storeV2Topology!.listOrganizationsPage({
						scope,
						limit: 10,
						cursor: {
							createdAt: microsecondMapped!.createdAt,
							id: microsecondMapped!.id,
						},
					})
				).organizations.map((organization) => organization.id),
			).not.toContain("org_live_one");
			const beforeNoOp = await pool.query<{ revision: number }>(
				`SELECT (value->>'revision')::integer AS revision
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			await store.mutateStoreV2Topology!(async (topology) => {
				await topology.upsertProject(microsecondProject!);
				await topology.upsertEnvironment(microsecondEnvironment!);
				await topology.upsertOrganization(microsecondMapped!);
			});
			expect(
				await pool.query(
					`SELECT (value->>'revision')::integer AS revision
					 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
				),
			).toMatchObject({ rows: beforeNoOp.rows });

			await expect(
				store.mutateStoreV2Topology!(async (topology) => {
					await topology.upsertOrganization({
						id: "org_rolled_back",
						projectId: scope.projectId,
						environmentId: scope.environmentId,
						name: "Rolled Back",
						slug: "rolled-back",
						status: "active",
						createdAt: now,
						updatedAt: now,
					});
					await topology.upsertEnvironment({
						id: "env_orphan",
						projectId: "project_missing",
						name: "Orphan",
						slug: "orphan",
						kind: "development",
						createdAt: now,
						updatedAt: now,
					});
				}),
			).rejects.toMatchObject({ code: "23503" });
			expect(
				await store.storeV2Topology!.getOrganization({
					scope,
					id: "org_rolled_back",
				}),
			).toBeNull();
			await expect(
				pool.query(
					`UPDATE ${PREFIX}meta SET value = '["events"]'::jsonb
					 WHERE key = 'store_v2_authoritative_collections'`,
				),
			).rejects.toThrow(
				/STORE_V2_TOPOLOGY_AUTHORITY_ROLLBACK_CAPABILITY_REQUIRED/,
			);
		} finally {
			await pool.end();
		}

		const rollback = await store.storeV2!.rollbackTopology();
		expect(rollback.authoritativeCollections).toEqual(["events"]);
		expect(rollback.collections.projects.consistent).toBe(true);
		expect(rollback.collections.environments.consistent).toBe(true);
		expect(rollback.collections.organizations.consistent).toBe(true);
		const rollbackStatePool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			const result = await rollbackStatePool.query<{
				projects: number;
				environments: number;
				organizations: number;
			}>(
				`SELECT (value->>'projectCount')::integer AS projects,
				        (value->>'environmentCount')::integer AS environments,
				        (value->>'organizationCount')::integer AS organizations
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			expect(result.rows).toEqual([
				{ projects: 2, environments: 2, organizations: shadowCountBefore + 3 },
			]);
		} finally {
			await rollbackStatePool.end();
		}
		expect(store.snapshot.projects).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: initialized.project.id }),
				expect.objectContaining({ id: "project_direct" }),
			]),
		);
		expect(store.snapshot.environments).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: "environment_direct" }),
			]),
		);
		expect(
			store.snapshot.organizations
				.map((organization) => organization.id)
				.sort(),
		).toEqual(["org_imported", "org_live_one", "org_live_two", "org_shadow"]);
	});
});
