import { performance } from "node:perf_hooks";
import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import {
	createEnvironmentAuthoritative,
	createProjectAuthoritative,
	createSessionAuthoritative,
	initProject,
} from "../services/core.js";
import { createManagementApplication } from "../application/management-application.js";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { syncRuntimeUserToManagementDurable } from "../services/identity.js";
import {
	storeV2TableNames,
} from "../store/store-v2-schema.js";
import {
	advanceStoreV2PrincipalState,
	readStoreV2PrincipalState,
} from "../store/store-v2-principals.js";
import {
	advanceStoreV2TopologyState,
	readStoreV2TopologyState,
} from "../store/store-v2-topology.js";
import { gatePostgresSuite } from "./pg-gate.js";
import type { PageCursorKey } from "../services/pagination.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TABLE = `clr_p_scale_${process.pid}`;
const PREFIX = `${TABLE}_n_`;
const TABLES = storeV2TableNames(PREFIX);
const COUNTS = [5_000, 50_000] as const;

const available = await gatePostgresSuite(
	DATABASE_URL,
	"store-v2-principals-scale",
);

function quantile(sorted: readonly number[], value: number): number {
	return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * value))]!;
}

describe.skipIf(!available)("store-v2 principal and topology production-path scale", () => {
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
			]) await pool.query(`DROP TABLE IF EXISTS ${table}`);
		} finally {
			await pool.end();
		}
	});

	it("holds bounded principal and topology lifecycle latency at 5k and 50k rows", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TABLE,
			normalizedPrefix: PREFIX,
		});
		stores.push(store);
		const initialized = initProject(store, { name: "User Scale", source: "cli" });
		await store.ready();
		await store.storeV2!.apply();
		await store.storeV2!.cutoverEvents();
		await store.storeV2!.cutoverPrincipals();
		await store.storeV2!.cutoverTopology();
		expect(store.storeV2Topology?.authoritative).toBe(true);
		expect(store.snapshot.projects).toEqual([]);
		expect(store.snapshot.environments).toEqual([]);
		expect(store.snapshot.organizations).toEqual([]);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		const scope = {
			projectId: initialized.project.id,
			environmentId: initialized.environment.id,
		};
		const otherProject = await createProjectAuthoritative(store, {
			name: "Other Scale",
			actor: "scale-proof",
			source: "cli",
		});
		const otherEnvironment = await createEnvironmentAuthoritative(store, {
			projectId: otherProject.id,
			name: "Other",
			kind: "preview",
			actor: "scale-proof",
			source: "cli",
		});
		const otherScope = {
			projectId: otherProject.id,
			environmentId: otherEnvironment.id,
		};
		const results: Array<{ count: number; p50Ms: number; p95Ms: number }> = [];
		const topologyResults: Array<{ count: number; p50Ms: number; p95Ms: number }> = [];
		const observer = await createPgStore(DATABASE_URL, {
			tableName: TABLE,
			normalizedPrefix: PREFIX,
		});
		stores.push(observer);

		try {
			for (const count of COUNTS) {
				await pool.query(`TRUNCATE ${PREFIX}principals`);
				await pool.query(`TRUNCATE ${PREFIX}organizations`);
				await pool.query(
					`INSERT INTO ${PREFIX}principals
					 (id, project_id, environment_id, email, name, status, external_id, created_at, updated_at)
					 SELECT 'scale_' || lpad(value::text, 6, '0'), $1, $2,
					        'scale-' || value::text || '@example.test',
					        'Scale ' || value::text, 'active', 'scale-external-' || value::text,
					        '2026-01-01T00:00:00Z'::timestamptz + value * interval '1 microsecond',
					        '2026-01-01T00:00:00Z'::timestamptz
					 FROM generate_series(1, $3::integer) AS value`,
					[scope.projectId, scope.environmentId, count],
				);
				await pool.query(
					`INSERT INTO ${PREFIX}principals
					 (id, project_id, environment_id, email, name, status, created_at, updated_at)
					 VALUES ($1, $2, $3, 'other@example.test', 'Other Scope', 'active',
					         '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z')`,
					[`other_${count}`, otherScope.projectId, otherScope.environmentId],
				);
				const stateClient = await pool.connect();
				try {
					await stateClient.query("BEGIN");
					const state = await readStoreV2PrincipalState(stateClient, TABLES, {
						forUpdate: true,
					});
					if (!state) throw new Error("principal state missing in scale setup");
					await advanceStoreV2PrincipalState(
						stateClient,
						TABLES,
						count + 1 - state.count,
					);
					const topologyState = await readStoreV2TopologyState(
						stateClient,
						TABLES,
						true,
					);
					if (!topologyState) {
						throw new Error("topology state missing in scale setup");
					}
					await stateClient.query(
						`INSERT INTO ${PREFIX}organizations
						 (id, project_id, environment_id, name, slug, status, created_at, updated_at)
						 SELECT 'topology_' || lpad(value::text, 6, '0'), $1, $2,
						        'Topology ' || value::text, 'topology-' || value::text, 'active',
						        '2026-01-01T00:00:00Z'::timestamptz + value * interval '1 millisecond',
						        '2026-01-01T00:00:00Z'::timestamptz
						 FROM generate_series(1, $3::integer) AS value`,
						[scope.projectId, scope.environmentId, count],
					);
					await advanceStoreV2TopologyState(stateClient, TABLES, {
						projectCountDelta: 0,
						environmentCountDelta: 0,
						organizationCountDelta: count - topologyState.organizationCount,
					});
					await stateClient.query("COMMIT");
				} catch (error) {
					await stateClient.query("ROLLBACK").catch(() => undefined);
					throw error;
				} finally {
					stateClient.release();
				}
				await store.refresh();
				const application = createManagementApplication({ store });
				const context = {
					scope,
					actor: "scale-proof",
					source: "cli" as const,
				};
				const otherContext = {
					scope: otherScope,
					actor: "scale-proof",
					source: "cli" as const,
				};
				await observer.refresh();
				const observerTopologyRevision =
					(await observer.storeV2!.status()).topologyRevision;
				const beforeProjection = await pool.query<{
					digest: string;
					companion: string;
					projects: number;
					environments: number;
					organizations: number;
				}>(
					`SELECT md5(snapshot.data::text) AS digest,
					        (SELECT count(*)::text FROM ${TABLE}_principal_email) AS companion,
					        jsonb_array_length(snapshot.data->'projects') AS projects,
					        jsonb_array_length(snapshot.data->'environments') AS environments,
					        jsonb_array_length(snapshot.data->'organizations') AS organizations
					 FROM ${TABLE} AS snapshot WHERE id = 1`,
				);
				expect(beforeProjection.rows[0]).toMatchObject({
					projects: 0,
					environments: 0,
					organizations: 0,
				});

				for (let warmup = 0; warmup < 5; warmup += 1) {
					await application.users.create(context, {
						email: `scale-warmup-${count}-${warmup}@example.test`,
						name: `Scale Warmup ${warmup}`,
					});
				}
				const samples: number[] = [];
				const createdIds: string[] = [];
				for (let sample = 0; sample < 50; sample += 1) {
					const started = performance.now();
					const created = await application.users.create(context, {
						email: `scale-create-${count}-${sample}@example.test`,
						name: `Scale Create ${sample}`,
					});
					samples.push(performance.now() - started);
					createdIds.push(created.user.id);
				}
				const durable = await pool.query<{ principals: string; audits: string }>(
					`SELECT
					   (SELECT count(*)::text FROM ${PREFIX}principals WHERE id = ANY($1::text[])) AS principals,
					   (SELECT count(*)::text FROM ${PREFIX}events
					      WHERE action = 'users.create' AND subject_id = ANY($1::text[])) AS audits`,
					[createdIds],
				);
				expect(durable.rows[0]).toEqual({ principals: "50", audits: "50" });

				const topologyCreatedIds: string[] = [];
				for (let warmup = 0; warmup < 5; warmup += 1) {
					await application.organizations.create(context, {
						name: `Topology Warmup ${count}-${warmup}`,
						slug: `topology-warmup-${count}-${warmup}`,
					});
				}
				const topologySamples: number[] = [];
				for (let sample = 0; sample < 50; sample += 1) {
					const started = performance.now();
					const created = await application.organizations.create(context, {
						name: `Topology Create ${count}-${sample}`,
						slug: `topology-create-${count}-${sample}`,
					});
					topologySamples.push(performance.now() - started);
					topologyCreatedIds.push(created.id);
				}
				const topologyDurable = await pool.query<{
					organizations: string;
					audits: string;
				}>(
					`SELECT
					   (SELECT count(*)::text FROM ${PREFIX}organizations WHERE id = ANY($1::text[])) AS organizations,
					   (SELECT count(*)::text FROM ${PREFIX}events
					      WHERE action = 'orgs.create' AND subject_id = ANY($1::text[])) AS audits`,
					[topologyCreatedIds],
				);
				expect(topologyDurable.rows[0]).toEqual({ organizations: "50", audits: "50" });
				await observer.refresh();
				expect(observer.resourceCounts()).toMatchObject({
					organizations: count + 55,
				});
				expect((await observer.storeV2!.status()).topologyRevision).toBe(
					observerTopologyRevision! + 55,
				);
				expect(observer.snapshot.organizations).toEqual([]);

				const snapshotLock = await pool.connect();
				let unrelated: Promise<unknown> | undefined;
				try {
					await snapshotLock.query("BEGIN");
					await snapshotLock.query(`SELECT id FROM ${TABLE} WHERE id = 1 FOR UPDATE`);
					unrelated = application.organizations.create(otherContext, {
						name: `Unrelated Topology ${count}`,
						slug: `unrelated-topology-${count}`,
					});
					const completed = await Promise.race([
						unrelated.then(() => true),
						new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 250)),
					]);
					expect(completed).toBe(true);
				} finally {
					await snapshotLock.query("ROLLBACK").catch(() => undefined);
					snapshotLock.release();
					await unrelated;
				}
				const parallelStarted = performance.now();
				const parallelCreated = await Promise.all(
					Array.from({ length: 10 }, (_, index) =>
						syncRuntimeUserToManagementDurable(store, {
							id: `scale-parallel-${count}-${index}`,
							email: `scale-parallel-${count}-${index}@example.test`,
							name: `Scale Parallel ${index}`,
						}, {
							projectId: scope.projectId,
							environmentId: scope.environmentId,
							actor: "scale-parallel-proof",
							source: "system",
						}),
					),
				);
				expect(parallelCreated).toHaveLength(10);
				expect((performance.now() - parallelStarted) / 10).toBeLessThan(50);
				expect(store.snapshot.principals).toEqual([]);
				const projection = await pool.query<{
					digest: string;
					principals: number;
					projects: number;
					environments: number;
					organizations: number;
					companion: string;
				}>(
					`SELECT md5(snapshot.data::text) AS digest,
					        jsonb_array_length(snapshot.data->'principals') AS principals,
					        jsonb_array_length(snapshot.data->'projects') AS projects,
					        jsonb_array_length(snapshot.data->'environments') AS environments,
					        jsonb_array_length(snapshot.data->'organizations') AS organizations,
					        (SELECT count(*)::text FROM ${TABLE}_principal_email) AS companion
					 FROM ${TABLE} AS snapshot WHERE id = 1`,
				);
				expect(projection.rows[0]).toEqual({
					digest: beforeProjection.rows[0]!.digest,
					principals: 0,
					projects: 0,
					environments: 0,
					organizations: 0,
					companion: beforeProjection.rows[0]!.companion,
				});

				const crossScope = await store.storeV2Principals!.listPage({
					scope: otherScope,
					limit: 10,
				});
				expect(crossScope).toEqual({
					principals: [expect.objectContaining({ id: `other_${count}` })],
					hasMore: false,
				});

				const occTarget = await store.storeV2Principals!.getById({
					scope,
					id: "scale_000001",
				});
				expect(occTarget).not.toBeNull();
				const mutatePrincipals = store.mutateStoreV2Principals!.bind(store);
				const occCandidateAt = new Date(
					new Date(occTarget!.updatedAt).getTime() + 1_000,
				).toISOString();
				const competing = await Promise.allSettled([
					mutatePrincipals((principals) => principals.update(
						{ ...occTarget!, name: "OCC winner A", updatedAt: occCandidateAt },
						{ expectedUpdatedAt: occTarget!.updatedAt },
					)),
					mutatePrincipals((principals) => principals.update(
						{ ...occTarget!, name: "OCC winner B", updatedAt: occCandidateAt },
						{ expectedUpdatedAt: occTarget!.updatedAt },
					)),
				]);
				expect(competing.filter((result) => result.status === "fulfilled")).toHaveLength(1);
				const rejected = competing.find(
					(result): result is PromiseRejectedResult => result.status === "rejected",
				);
				expect((rejected?.reason as { code?: string }).code).toBe(
					"STORE_V2_PRINCIPAL_CONFLICT",
				);

				const session = await createSessionAuthoritative(store, {
					principalId: "scale_000001",
					environmentId: scope.environmentId,
					scope,
				});
				const listedSessions = await application.sessions.list(context, { limit: 10 });
				expect(listedSessions.sessions).toContainEqual(
					expect.objectContaining({ id: session.id, principalId: "scale_000001" }),
				);

				const expectedScopedCount = count + 65;
				const seen = new Set<string>();
				let cursor: PageCursorKey | undefined;
				let firstId: string | undefined;
				let middleId: string | undefined;
				let tailId: string | undefined;
				let traversed = 0;
				do {
					const page = await store.storeV2Principals!.listPage({
						scope,
						limit: 1_000,
						...(cursor ? { cursor } : {}),
					});
					expect(page.principals.length).toBeGreaterThan(0);
					firstId ??= page.principals[0]!.id;
					for (const principal of page.principals) {
						expect(seen.has(principal.id)).toBe(false);
						seen.add(principal.id);
						traversed += 1;
						if (!middleId && traversed >= Math.floor(expectedScopedCount / 2)) {
							middleId = principal.id;
						}
						tailId = principal.id;
					}
					const last = page.principals[page.principals.length - 1]!;
					cursor = page.hasMore
						? { createdAt: last.createdAt, id: last.id }
						: undefined;
				} while (cursor);
				expect(traversed).toBe(expectedScopedCount);
				expect(seen.size).toBe(expectedScopedCount);
				expect(firstId).toBeTruthy();
				expect(middleId).toBeTruthy();
				expect(tailId).toBeTruthy();
				expect(new Set([firstId, middleId, tailId]).size).toBe(3);

				const explained = await pool.query<{ "QUERY PLAN": unknown }>(
					`EXPLAIN (FORMAT JSON)
					 SELECT id FROM ${PREFIX}principals
					 WHERE project_id = $1 AND environment_id = $2 AND status <> 'deleted'
					 ORDER BY created_at ASC, id ASC LIMIT 1000`,
					[scope.projectId, scope.environmentId],
				);
				const plan = JSON.stringify(explained.rows[0]?.["QUERY PLAN"] ?? null);
				expect(plan).toMatch(/Index(?: Only)? Scan/);
				expect(plan).not.toContain('"Node Type":"Seq Scan"');
				const externalIdExplained = await pool.query<{ "QUERY PLAN": unknown }>(
					`EXPLAIN (FORMAT JSON)
					 SELECT id FROM ${PREFIX}principals
					 WHERE project_id = $1 AND environment_id = $2
					   AND external_id = $3 AND status <> 'deleted'`,
					[scope.projectId, scope.environmentId, `scale-external-${count}`],
				);
				const externalIdPlan = JSON.stringify(
					externalIdExplained.rows[0]?.["QUERY PLAN"] ?? null,
				);
				expect(externalIdPlan).toMatch(/Index(?: Only)? Scan/);
				expect(externalIdPlan).not.toContain('"Node Type":"Seq Scan"');
				samples.sort((a, b) => a - b);
				topologySamples.sort((a, b) => a - b);
				results.push({
					count,
					p50Ms: quantile(samples, 0.5),
					p95Ms: quantile(samples, 0.95),
				});
				topologyResults.push({
					count,
					p50Ms: quantile(topologySamples, 0.5),
					p95Ms: quantile(topologySamples, 0.95),
				});
			}

			for (const result of [...results, ...topologyResults]) {
				expect(result.p50Ms).toBeLessThan(25);
				expect(result.p95Ms).toBeLessThan(50);
			}
			expect(results[1]!.p95Ms).toBeLessThanOrEqual(
				2 * results[0]!.p95Ms + 5,
			);
			expect(topologyResults[1]!.p95Ms).toBeLessThanOrEqual(
				2 * topologyResults[0]!.p95Ms + 5,
			);
			console.log(`STORE_V2_PRINCIPALS_SCALE ${JSON.stringify(results)}`);
			console.log(`STORE_V2_TOPOLOGY_SCALE ${JSON.stringify(topologyResults)}`);
		} finally {
			await pool.end();
		}
	}, 30_000);
});
