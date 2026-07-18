import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import {
	inspectEnvironmentAuthoritative,
	inspectOrganizationAuthoritative,
	inspectProjectAuthoritative,
	initProject,
	listEnvironmentsPageAuthoritative,
	listOrganizationsPageAuthoritative,
	overviewStatsAuthoritative,
} from "../services/core.js";
import { appendAuditEvent } from "../services/audit.js";
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
			data.principals.push({
				id: "principal_imported",
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
				email: "imported@example.com",
				name: "Imported Principal",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
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
		await expect(
			inspectProjectAuthoritative(store, "project_foreign", scope),
		).rejects.toMatchObject({ code: "PROJECT_NOT_FOUND" });
		expect(
			await inspectProjectAuthoritative(store, initialized.project.id, scope),
		).toMatchObject({ id: initialized.project.id });
		expect(
			await listEnvironmentsPageAuthoritative(store, { scope, limit: 1 }),
		).toMatchObject({
			environments: [expect.objectContaining({ id: initialized.environment.id })],
			nextCursor: null,
		});
		expect(
			await inspectEnvironmentAuthoritative(store, initialized.environment.id, { scope }),
		).toMatchObject({
			environment: { id: initialized.environment.id },
			project: { id: initialized.project.id },
			local: {
				resourceCounts: {
					organizations: 2,
					memberships: null,
					identityConnections: null,
					directoryConnections: null,
					events: null,
				},
			},
		});
		expect(
			await inspectOrganizationAuthoritative(store, "org_imported", scope),
		).toMatchObject({ id: "org_imported" });
		const organizationFirstPage = await listOrganizationsPageAuthoritative(store, {
			scope,
			limit: 1,
		});
		expect(organizationFirstPage.organizations).toEqual([
			expect.objectContaining({ id: "org_imported" }),
		]);
		await expect(
			listEnvironmentsPageAuthoritative(store, {
				scope,
				limit: 1,
				cursor: organizationFirstPage.nextCursor!,
			}),
		).rejects.toMatchObject({ code: "CURSOR_INVALID" });
		expect(
			await listOrganizationsPageAuthoritative(store, {
				scope,
				limit: 1,
				cursor: organizationFirstPage.nextCursor!,
			}),
		).toMatchObject({
			organizations: [expect.objectContaining({ id: "org_shadow" })],
			nextCursor: null,
		});
		const overview = await overviewStatsAuthoritative(store, scope);
		expect(overview).toMatchObject({
			organizations: 2,
			resourceCounts: { events: null },
		});
		const authorityShadow = (
			store as unknown as {
				storeV2Shadow: {
					loadSnapshot: (...args: never[]) => Promise<unknown>;
				};
			}
		).storeV2Shadow;
		const originalAuthorityLoadSnapshot = authorityShadow.loadSnapshot;
		const authorityLoadSnapshot = originalAuthorityLoadSnapshot.bind(authorityShadow);
		let signalStaleAuthorityRead!: () => void;
		let releaseStaleAuthorityRead!: () => void;
		const staleAuthorityRead = new Promise<void>((resolve) => {
			signalStaleAuthorityRead = resolve;
		});
		const staleAuthorityReadReleased = new Promise<void>((resolve) => {
			releaseStaleAuthorityRead = resolve;
		});
		let holdStaleAuthorityRead = true;
		authorityShadow.loadSnapshot = async (...args) => {
			const loaded = await authorityLoadSnapshot(...args);
			if (!holdStaleAuthorityRead) return loaded;
			holdStaleAuthorityRead = false;
			signalStaleAuthorityRead();
			await staleAuthorityReadReleased;
			return loaded;
		};
		try {
			const staleAuthorityRefresh = store.refresh();
			await staleAuthorityRead;
			await store.storeV2!.cutoverPrincipals();
			const principalAuthorityRevision = store.currentRevision;
			expect(store.snapshot.principals).toEqual([]);
			expect(store.resourceCounts()).toMatchObject({ principals: 1 });
			releaseStaleAuthorityRead();
			await staleAuthorityRefresh;
			expect(store.storeV2Principals?.authoritative).toBe(true);
			expect(store.currentRevision).toBe(principalAuthorityRevision);
			expect(store.snapshot.principals).toEqual([]);
			expect(store.resourceCounts()).toMatchObject({ principals: 1 });

			const originalPrincipalLoadSnapshot = authorityShadow.loadSnapshot;
			const principalLoadSnapshot = originalPrincipalLoadSnapshot.bind(authorityShadow);
			let signalStalePrincipalRead!: () => void;
			let releaseStalePrincipalRead!: () => void;
			const stalePrincipalRead = new Promise<void>((resolve) => {
				signalStalePrincipalRead = resolve;
			});
			const stalePrincipalReadReleased = new Promise<void>((resolve) => {
				releaseStalePrincipalRead = resolve;
			});
			authorityShadow.loadSnapshot = async (...args) => {
				const loaded = await principalLoadSnapshot(...args);
				signalStalePrincipalRead();
				await stalePrincipalReadReleased;
				return loaded;
			};
			try {
				const stalePrincipalRefresh = store.refresh();
				await stalePrincipalRead;
				let principalRefreshRaceAuditId = "";
				await store.mutateStoreV2Identity!(async ({ principals, appendAudit }) => {
					principalRefreshRaceAuditId = appendAudit({
						actor: "cli",
						action: "principal.created",
						projectId: scope.projectId,
						environmentId: scope.environmentId,
						subjectType: "principal",
						subjectId: "principal_refresh_race",
						outcome: "success",
						source: "cli",
						message: "Created principal during stale refresh",
					}).id;
					return principals.insert({
						id: "principal_refresh_race",
						projectId: scope.projectId,
						environmentId: scope.environmentId,
						email: "refresh-race@example.com",
						name: "Refresh Race Principal",
						status: "active",
						createdAt: now,
						updatedAt: now,
					});
				});
				releaseStalePrincipalRead();
				await stalePrincipalRefresh;
				expect(store.currentRevision).toBe(principalAuthorityRevision);
				expect(store.snapshot.principals).toEqual([]);
				expect(store.resourceCounts()).toMatchObject({ principals: 2 });
				expect(
					(
						await store.storeV2Events!.listPage({ scope, limit: 100 })
					).events.map((event) => event.id),
				).toContain(principalRefreshRaceAuditId);
				expect(
					await store.storeV2Principals!.getById({
						scope,
						id: "principal_refresh_race",
					}),
				).toMatchObject({ id: "principal_refresh_race" });
			} finally {
				releaseStalePrincipalRead();
				authorityShadow.loadSnapshot = originalPrincipalLoadSnapshot;
			}
			await store.storeV2!.rollbackPrincipals();
			expect(store.storeV2Principals?.authoritative).toBe(false);
		} finally {
			releaseStaleAuthorityRead();
			authorityShadow.loadSnapshot = originalAuthorityLoadSnapshot;
		}

		const topologyAudit = (subjectType: string, subjectId: string) => ({
			actor: "cli",
			action: "topology.updated",
			projectId: scope.projectId,
			environmentId: scope.environmentId,
			subjectType,
			subjectId,
			outcome: "success" as const,
			source: "cli" as const,
			message: `Updated ${subjectType} ${subjectId}`,
		});
		const observer = await createPgStore(DATABASE_URL, {
			tableName: TABLE,
			normalizedPrefix: PREFIX,
		});
		stores.push(observer);
		const observerSnapshotRevision = observer.currentRevision;
		const observerTopologyRevision =
			(await observer.storeV2!.status()).topologyRevision;
		const insertedTopology = await store.mutateStoreV2Topology!(async ({
			topology,
			appendAudit,
		}) => ({
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
			audit: appendAudit(topologyAudit("project", "project_direct")),
		}));
		expect(
			(
				await store.storeV2Events!.listPage({
					scope,
					limit: 100,
				})
			).events.map((event) => event.id),
		).toContain(insertedTopology.audit.id);
		expect(
			(await overviewStatsAuthoritative(store, scope)).recentEvents,
		).toContainEqual(expect.objectContaining({ id: insertedTopology.audit.id }));
		expect(store.resourceCounts()).toMatchObject({
			projects: 2,
			environments: 2,
			organizations: shadowCountBefore + 1,
		});
		await observer.refresh();
		expect(observer.currentRevision).toBe(observerSnapshotRevision);
		expect(observer.resourceCounts()).toMatchObject({
			projects: 2,
			environments: 2,
			organizations: shadowCountBefore + 1,
		});
		expect((await observer.storeV2!.status()).topologyRevision).toBe(
			observerTopologyRevision! + 1,
		);
		expect(observer.snapshot.projects).toEqual([]);
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

		const coordinatedTopologyRevision =
			(await store.storeV2!.status()).topologyRevision;
		let expiredTopology!: {
			getProjectById(id: string): Promise<unknown>;
		};
		const coordinated = await store.mutateCoordinated!(async ({
			data,
			topology,
			appendAudit,
		}) => {
			expect(topology).toBeDefined();
			expiredTopology = topology!;
			data.meta.config.coordinatedTopology = "committed";
			const project = await topology!.upsertProject({
					id: "project_coordinated",
					name: "Coordinated Project",
					slug: "coordinated-project",
					createdAt: now,
					updatedAt: now,
				});
			return {
				project,
				audit: appendAudit(topologyAudit("project", "project_coordinated")),
				directAudit: appendAuditEvent(
					data,
					topologyAudit("project", "project_coordinated_direct_audit"),
				),
			};
		});
		expect(
			await store.storeV2Topology!.getProjectById("project_coordinated"),
		).toMatchObject({ id: coordinated.project.id });
		expect((await store.storeV2!.status()).topologyRevision).toBe(
			coordinatedTopologyRevision! + 1,
		);
		expect(store.snapshot.projects).toEqual([]);
		expect(store.snapshot.environments).toEqual([]);
		expect(store.snapshot.organizations).toEqual([]);
		expect(store.snapshot.meta.config.coordinatedTopology).toBe("committed");
		expect(
			(await store.storeV2Events!.listPage({ scope, limit: 100 })).events,
		).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ id: coordinated.audit.id }),
				expect.objectContaining({ id: coordinated.directAudit.id }),
			]),
		);
		await expect(
			expiredTopology.getProjectById("project_coordinated"),
		).rejects.toMatchObject({ code: "STORE_V2_TOPOLOGY_REPOSITORY_REVOKED" });
		const coordinatedPool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			const result = await coordinatedPool.query<{
				data: {
					projects: unknown[];
					environments: unknown[];
					organizations: unknown[];
					meta: { config: Record<string, string> };
				};
			}>(`SELECT data FROM ${TABLE} WHERE id = 1`);
			expect(result.rows[0]?.data).toMatchObject({
				projects: [],
				environments: [],
				organizations: [],
				meta: { config: { coordinatedTopology: "committed" } },
			});
		} finally {
			await coordinatedPool.end();
		}

		await expect(
			store.mutateCoordinated!(async ({ data, topology, appendAudit }) => {
				data.meta.config.coordinatedTopology = "callback-rollback";
				appendAudit(topologyAudit("project", "project_coordinated_callback"));
				await topology!.upsertProject({
					id: "project_coordinated_callback",
					name: "Callback Rollback",
					slug: "callback-rollback",
					createdAt: now,
					updatedAt: now,
				});
				throw new Error("coordinated callback failure");
			}),
		).rejects.toThrow("coordinated callback failure");
		expect(
			await store.storeV2Topology!.getProjectById(
				"project_coordinated_callback",
			),
		).toBeNull();
		expect(store.snapshot.meta.config.coordinatedTopology).toBe("committed");

		await expect(
			store.mutateCoordinated!(({ data, topology, appendAudit }) => {
				data.meta.config.coordinatedTopology = "issued-rollback";
				appendAudit(topologyAudit("environment", "env_coordinated_issued"));
				void topology!.upsertEnvironment({
					id: "env_coordinated_issued",
					projectId: "project_missing",
					name: "Issued Rollback",
					slug: "issued-rollback",
					kind: "development",
					createdAt: now,
					updatedAt: now,
				});
			}),
		).rejects.toMatchObject({ code: "23503" });
		expect(
			await store.storeV2Topology!.getEnvironment({
				projectId: "project_missing",
				id: "env_coordinated_issued",
			}),
		).toBeNull();
		expect(store.snapshot.meta.config.coordinatedTopology).toBe("committed");

		await expect(
			store.mutateCoordinated!(async ({ topology }) => {
				await topology!.upsertProject({
					id: "project_coordinated_missing_audit",
					name: "Coordinated Missing Audit",
					slug: "coordinated-missing-audit",
					createdAt: now,
					updatedAt: now,
				});
			}),
		).rejects.toMatchObject({ code: "STORE_V2_TOPOLOGY_AUDIT_REQUIRED" });
		expect(
			await store.storeV2Topology!.getProjectById(
				"project_coordinated_missing_audit",
			),
		).toBeNull();

		const snapshotLocker = new pg.Pool({ connectionString: DATABASE_URL });
		const lockClient = await snapshotLocker.connect();
		try {
			await lockClient.query("BEGIN");
			await lockClient.query(`SELECT id FROM ${TABLE} WHERE id = 1 FOR UPDATE`);
			const writeOne = store.mutateStoreV2Topology!(({ topology, appendAudit }) => {
				appendAudit(topologyAudit("organization", "org_live_one"));
				return topology.upsertOrganization({
					id: "org_live_one",
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					name: "Live One",
					slug: "live-one",
					status: "active",
					createdAt: now,
					updatedAt: now,
				});
			});
			const writeTwo = store.mutateStoreV2Topology!(({ topology, appendAudit }) => {
				appendAudit(topologyAudit("organization", "org_live_two"));
				return topology.upsertOrganization({
					id: "org_live_two",
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					name: "Live Two",
					slug: "live-two",
					status: "active",
					createdAt: now,
					updatedAt: now,
				});
			});
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
				{ projects: 3, environments: 2, organizations: shadowCountBefore + 3 },
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

		const shadow = (
			store as unknown as {
				storeV2Shadow: {
					loadSnapshot: (...args: never[]) => Promise<unknown>;
				};
			}
		).storeV2Shadow;
		const originalLoadSnapshot = shadow.loadSnapshot;
		const loadSnapshot = originalLoadSnapshot.bind(shadow);
		let signalStaleRead!: () => void;
		let releaseStaleRead!: () => void;
		const staleRead = new Promise<void>((resolve) => {
			signalStaleRead = resolve;
		});
		const staleReadReleased = new Promise<void>((resolve) => {
			releaseStaleRead = resolve;
		});
		shadow.loadSnapshot = async (...args) => {
			const loaded = await loadSnapshot(...args);
			signalStaleRead();
			await staleReadReleased;
			return loaded;
		};
		try {
			const staleRefresh = store.refresh();
			await staleRead;
			await store.mutateStoreV2Topology!(({ topology, appendAudit }) => {
				appendAudit(topologyAudit("organization", "org_refresh_race"));
				return topology.upsertOrganization({
					id: "org_refresh_race",
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					name: "Refresh Race",
					slug: "refresh-race",
					status: "active",
					createdAt: now,
					updatedAt: now,
				});
			});
			releaseStaleRead();
			await staleRefresh;
		} finally {
			releaseStaleRead();
			shadow.loadSnapshot = originalLoadSnapshot;
		}
		expect(store.resourceCounts()).toMatchObject({
			organizations: shadowCountBefore + 4,
		});

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
			await store.mutateStoreV2Topology!(async ({ topology }) => {
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

			const beforeAuditRequired = await pool.query<{ revision: number }>(
				`SELECT (value->>'revision')::integer AS revision
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			await expect(
				store.mutateStoreV2Topology!(async ({ topology }) => {
					await topology.upsertProject({
						id: "project_missing_audit",
						name: "Missing Audit",
						slug: "missing-audit",
						createdAt: now,
						updatedAt: now,
					});
				}),
			).rejects.toMatchObject({ code: "STORE_V2_TOPOLOGY_AUDIT_REQUIRED" });
			expect(await store.storeV2Topology!.getProjectById("project_missing_audit")).toBeNull();
			expect(
				await pool.query(
					`SELECT (value->>'revision')::integer AS revision
					 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
				),
			).toMatchObject({ rows: beforeAuditRequired.rows });

			const beforeCallbackRollback = await pool.query<{ revision: number }>(
				`SELECT (value->>'revision')::integer AS revision
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			await expect(
				store.mutateStoreV2Topology!(async ({ topology, appendAudit }) => {
					appendAudit(topologyAudit("organization", "org_callback_rolled_back"));
					await topology.upsertOrganization({
						id: "org_callback_rolled_back",
						projectId: scope.projectId,
						environmentId: scope.environmentId,
						name: "Callback Rolled Back",
						slug: "callback-rolled-back",
						status: "active",
						createdAt: now,
						updatedAt: now,
					});
					throw new Error("callback failure");
				}),
			).rejects.toThrow("callback failure");
			expect(
				await store.storeV2Topology!.getOrganization({
					scope,
					id: "org_callback_rolled_back",
				}),
			).toBeNull();
			expect(
				(await store.storeV2Events!.listPage({ scope, limit: 100 })).events.some(
					(event) => event.subjectId === "org_callback_rolled_back",
				),
			).toBe(false);
			expect(
				await pool.query(
					`SELECT (value->>'revision')::integer AS revision
					 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
				),
			).toMatchObject({ rows: beforeCallbackRollback.rows });

			const beforeIssuedRollback = await pool.query<{ revision: number }>(
				`SELECT (value->>'revision')::integer AS revision
				 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
			);
			await expect(
				store.mutateStoreV2Topology!(({ topology, appendAudit }) => {
					appendAudit(topologyAudit("environment", "env_issued_rolled_back"));
					void topology.upsertEnvironment({
						id: "env_issued_rolled_back",
						projectId: "project_missing",
						name: "Issued Rolled Back",
						slug: "issued-rolled-back",
						kind: "development",
						createdAt: now,
						updatedAt: now,
					});
				}),
			).rejects.toMatchObject({ code: "23503" });
			expect(
				(await store.storeV2Events!.listPage({ scope, limit: 100 })).events.some(
					(event) => event.subjectId === "env_issued_rolled_back",
				),
			).toBe(false);
			expect(
				await store.storeV2Topology!.getEnvironment({
					projectId: "project_missing",
					id: "env_issued_rolled_back",
				}),
			).toBeNull();
			expect(
				await pool.query(
					`SELECT (value->>'revision')::integer AS revision
					 FROM ${PREFIX}meta WHERE key = 'store_v2_topology_state'`,
				),
			).toMatchObject({ rows: beforeIssuedRollback.rows });

			await expect(
				store.mutateStoreV2Topology!(async ({ topology, appendAudit }) => {
					appendAudit(topologyAudit("organization", "org_rolled_back"));
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
				{ projects: 3, environments: 2, organizations: shadowCountBefore + 4 },
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
		).toEqual([
			"org_imported",
			"org_live_one",
			"org_live_two",
			"org_refresh_race",
			"org_shadow",
		]);
	});
});
