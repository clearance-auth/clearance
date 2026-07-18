import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createManagementApplication } from "../application/management-application.js";
import {
	createSessionAuthoritative,
	createUser,
	exportUsersAuthoritative,
	initProject,
	inspectEnvironmentAuthoritative,
	overviewStatsAuthoritative,
} from "../services/core.js";
import { syncRuntimeUserToManagementDurable } from "../services/identity.js";
import {
	createScimConnection,
	testScimConnectionAuthoritative,
} from "../services/scim.js";
import {
	planMigrationDurable,
	rollbackMigrationDurable,
	runMigrationDurable,
	verifyMigrationDurable,
} from "../services/migration-postgres.js";
import type { LegacyExportFixture } from "../services/migration.js";
import {
	cutoverStoreV2Principals,
	cutoverStoreV2Topology,
	rollbackStoreV2Principals,
	rollbackStoreV2Topology,
} from "../services/store-v2.js";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { PgStoreV2Shadow } from "../store/store-v2-shadow.js";
import type { StoreV2PrincipalRepository } from "../store/types.js";
import type { Principal } from "../types/resources.js";
import { gatePostgresSuite } from "./pg-gate.js";
import { closeAuthBundle } from "../auth-bridge.js";
import {
	storeV2TableNames,
} from "../store/store-v2-schema.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TEST_TABLE = `clearance_store_v2_principals_${process.pid}`;
const PREFIX = `${TEST_TABLE}_n_`;
const RUNTIME_AUDIT_PREFIX = `rollback_audit_${process.pid}`;
const RUNTIME_AUDIT_TABLE = `${RUNTIME_AUDIT_PREFIX}_runtime_audit_events`;

const available = await gatePostgresSuite(
	DATABASE_URL,
	"store-v2-principals-pg",
);

describe.skipIf(!available)("PgStore store-v2 principal foundation", () => {
	const stores: PgStore[] = [];
	const previousRuntimeDatabaseUrl = process.env.DATABASE_URL;
	const previousRuntimeSecret = process.env.CLEARANCE_SECRET;
	const previousRuntimeAuditPrefix = process.env.CLEARANCE_RUNTIME_AUDIT_PREFIX;
	const previousRuntimeAuditSchema = process.env.CLEARANCE_RUNTIME_AUDIT_SCHEMA;

	beforeAll(() => {
		process.env.DATABASE_URL = DATABASE_URL;
		process.env.CLEARANCE_SECRET = "principal-authority-runtime-test-secret";
		process.env.CLEARANCE_RUNTIME_AUDIT_PREFIX = RUNTIME_AUDIT_PREFIX;
		process.env.CLEARANCE_RUNTIME_AUDIT_SCHEMA = "public";
	});

	afterAll(async () => {
		await closeAuthBundle().catch(() => undefined);
		if (previousRuntimeDatabaseUrl === undefined) delete process.env.DATABASE_URL;
		else process.env.DATABASE_URL = previousRuntimeDatabaseUrl;
		if (previousRuntimeSecret === undefined) delete process.env.CLEARANCE_SECRET;
		else process.env.CLEARANCE_SECRET = previousRuntimeSecret;
		if (previousRuntimeAuditPrefix === undefined) delete process.env.CLEARANCE_RUNTIME_AUDIT_PREFIX;
		else process.env.CLEARANCE_RUNTIME_AUDIT_PREFIX = previousRuntimeAuditPrefix;
		if (previousRuntimeAuditSchema === undefined) delete process.env.CLEARANCE_RUNTIME_AUDIT_SCHEMA;
		else process.env.CLEARANCE_RUNTIME_AUDIT_SCHEMA = previousRuntimeAuditSchema;
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
				`${TEST_TABLE}_principal_email`,
				`${TEST_TABLE}_organization_slug`,
				`${TEST_TABLE}_idempotency`,
				RUNTIME_AUDIT_TABLE,
				TEST_TABLE,
			]) {
				await pool.query(`DROP TABLE IF EXISTS ${table}`);
			}
		} finally {
			await pool.end();
		}
	});

	it("stages reversible principal authority with scoped typed persistence and fencing", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TEST_TABLE,
			normalizedPrefix: PREFIX,
		});
		stores.push(store);
		const initialized = initProject(store, {
			name: "Principal Authority",
			source: "cli",
		});
		const now = "2026-07-15T00:00:00.000Z";
		await store.mutateDurable((data) => {
			data.principals.push({
				id: "user_one",
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
				email: "one@example.test",
				name: "One",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});
		expect((await store.storeV2!.apply()).schemaVersion).toBe(2);

		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		const internal = new PgStoreV2Shadow(pool, TEST_TABLE, PREFIX);
		try {
			// An owned v1 shadow upgrades in place and preserves its verified rows.
			await pool.query(
				`UPDATE ${PREFIX}meta SET value = '1'::jsonb
				 WHERE key = 'store_v2_schema_version'`,
			);
			const upgraded = await store.storeV2!.apply();
			expect(upgraded.schemaVersion).toBe(2);
			expect(upgraded.collections.principals.relationalCount).toBe(1);

			await store.storeV2!.cutoverEvents();
			expect(store.storeV2!.cutoverPrincipals).toBeTypeOf("function");
			expect(store.storeV2!.rollbackPrincipals).toBeTypeOf("function");

			const beforeCutover = store.snapshot.principals;
			await expect(cutoverStoreV2Principals(store, {})).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPALS_CUTOVER_CONFIRMATION_REQUIRED",
			});
			const cutover = (await cutoverStoreV2Principals(store, { confirm: true })).status!;
			expect(cutover.authoritativeCollections).toEqual([
				"events",
				"principals",
			]);
			await store.refresh();
			expect(store.snapshot.principals).toEqual([]);
			expect(store.storeV2Principals?.authoritative).toBe(true);
			const scope = {
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
			};
			const context = { scope, actor: "principal-proof", source: "cli" as const };
			const application = createManagementApplication({ store });
			const organization = await application.organizations.create(context, {
				name: "Authority Organization",
			});
			const membership = await application.members.add(context, {
				organizationId: organization.id,
				principalId: "user_one",
				role: "owner",
			});
			expect(membership).toMatchObject({ principalId: "user_one", role: "owner" });
			const session = await createSessionAuthoritative(store, {
				principalId: "user_one",
				environmentId: scope.environmentId,
				scope,
			});
			await store.ready();
			expect((await application.sessions.list(context, { limit: 10 })).sessions)
				.toEqual([expect.objectContaining({ id: session.id, principalId: "user_one" })]);
			const inspectedEnvironment = await inspectEnvironmentAuthoritative(
				store,
				scope.environmentId,
				{ scope },
			);
			expect(inspectedEnvironment.local.resourceCounts).toMatchObject({
				principals: 1,
				organizations: 1,
				memberships: 1,
				sessions: 1,
			});
			const exported = await exportUsersAuthoritative(store, {
				scope,
				limit: 10,
				skipAudit: true,
			});
			expect(exported.users).toEqual([
				expect.objectContaining({ id: "user_one", email: "one@example.test" }),
			]);
			expect(await overviewStatsAuthoritative(store, scope)).toMatchObject({
				totalUsers: 1,
				activeUsers: 1,
				organizations: 1,
				activeSessions: 1,
			});
			const beforeLegacyRollback = await pool.query<{ revision: string }>(
				`SELECT revision::text AS revision FROM ${TEST_TABLE} WHERE id = 1`,
			);
			const legacy = await pool.connect();
			try {
				await legacy.query("BEGIN");
				await legacy.query(
					`UPDATE ${TEST_TABLE} SET revision = revision + 1 WHERE id = 1`,
				);
				await expect(
					legacy.query(
						`UPDATE ${PREFIX}meta SET value = '[]'::jsonb
						 WHERE key = 'store_v2_authoritative_collections'`,
					),
				).rejects.toThrow(/STORE_V2_PRINCIPAL_AUTHORITY_ROLLBACK_CAPABILITY_REQUIRED/);
				await legacy.query("ROLLBACK");
			} finally {
				legacy.release();
			}
			expect(
				(await pool.query<{ revision: string }>(
					`SELECT revision::text AS revision FROM ${TEST_TABLE} WHERE id = 1`,
				)).rows[0]?.revision,
			).toBe(beforeLegacyRollback.rows[0]?.revision);
			expect(() => createUser(store, {
				email: "legacy-writer@example.test",
				name: "Legacy Writer",
			})).toThrowError(expect.objectContaining({
				code: "STORE_V2_PRINCIPALS_TYPED_MUTATION_REQUIRED",
			}));

			const compact = await pool.query<{
				principals: number;
				events: number;
			}>(
				`SELECT jsonb_array_length(data->'principals') AS principals,
				        jsonb_array_length(data->'events') AS events
				 FROM ${TEST_TABLE} WHERE id = 1`,
			);
			expect(compact.rows[0]).toEqual({ principals: 0, events: 0 });

			await expect(
				store.mutateDurable((data) => {
					data.principals.push({
						...beforeCutover[0]!,
						id: "old_writer",
						email: "old-writer@example.test",
					});
				}),
			).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPALS_TYPED_MUTATION_REQUIRED",
			});

			await expect(
				pool.query(
					`UPDATE ${TEST_TABLE}
					 SET data = jsonb_set(data, '{principals}', $1::jsonb)
					 WHERE id = 1`,
					[JSON.stringify(beforeCutover)],
				),
			).rejects.toThrow(/STORE_V2_PRINCIPAL_PROJECTION_FORBIDDEN/);

			const revisionBeforeConflict = cutover.principalRevision;
			await expect(
				store.mutateStoreV2Principals!(async (principals) => {
					const current = await principals.getById({
						scope: {
							projectId: initialized.project.id,
							environmentId: initialized.environment.id,
						},
						id: "user_one",
					});
					await principals.update({
						...current!,
						name: "Must Roll Back",
						updatedAt: "2026-07-15T00:30:00.000Z",
					}, { expectedUpdatedAt: current!.updatedAt });
					await principals.insert({
						...beforeCutover[0]!,
						id: "user_conflict",
						email: "ONE@example.test",
					});
				}),
			).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPAL_EMAIL_CONFLICT",
			});
			expect((await internal.status()).principalRevision).toBe(
				revisionBeforeConflict!,
			);
			expect(
				await store.storeV2Principals!.getById({
					scope: {
						projectId: initialized.project.id,
						environmentId: initialized.environment.id,
					},
					id: "user_one",
				}),
			).toMatchObject({ name: "One" });
			await expect(
				store.mutateStoreV2Principals!((principals) =>
					principals.insert({
						...beforeCutover[0]!,
						email: "different@example.test",
					}),
				),
			).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPAL_ID_CONFLICT",
			});
			await expect(
				store.mutateStoreV2Principals!((principals) =>
					principals.insert({
						...beforeCutover[0]!,
						id: "user_bad_scope",
						environmentId: "env_missing",
						email: "bad-scope@example.test",
					}),
				),
			).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPAL_SCOPE_INVALID",
			});
			await expect(
				store.storeV2Principals!.listPage({
					scope: {
						projectId: initialized.project.id,
						environmentId: initialized.environment.id,
					},
					limit: 1,
					cursor: { createdAt: "0", id: "user_one" },
				}),
			).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPAL_CURSOR_INVALID",
			});

			const snapshotBeforeDirect = await pool.query<{
				revision: string;
				digest: string;
				xmin: string;
			}>(
				`SELECT revision::text, md5(data::text) AS digest, xmin::text
				 FROM ${TEST_TABLE} WHERE id = 1`,
			);
			const uniquenessBeforeDirect = await pool.query<{ xmin: string }>(
				`SELECT xmin::text FROM ${TEST_TABLE}_principal_email
				 WHERE principal_id = 'user_one'`,
			);
			let escapedRepository!: StoreV2PrincipalRepository;
			await store.mutateStoreV2Principals!((principals) => {
				escapedRepository = principals;
				void principals.insert({
					...beforeCutover[0]!,
					id: "user_dropped",
					email: "dropped@example.test",
					name: "Dropped Promise",
				}).then((created) => {
					created.name = "Cache Only Mutation";
				});
			});
			expect(Object.isFrozen(escapedRepository)).toBe(true);
			expect(Object.getOwnPropertyNames(escapedRepository).sort()).toEqual([
				"authoritative",
				"delete",
				"disable",
				"findActiveByEmail",
				"findActiveByExternalId",
				"getById",
				"insert",
				"listPage",
				"update",
			]);
			expect(Object.getPrototypeOf(escapedRepository)).toBe(Object.prototype);
			expect(Object.getOwnPropertySymbols(escapedRepository)).toEqual([]);
			expect(
				Object.getOwnPropertySymbols(Object.getPrototypeOf(escapedRepository)),
			).toEqual([]);
			expect("hardDeleteExactForRollback" in escapedRepository).toBe(false);
			const revisionBeforeRawDelete = (await internal.status()).principalRevision;
			await expect(store.mutateCoordinated!((context) =>
				(context as unknown as {
					query(sql: string): Promise<unknown>;
				}).query(`DELETE FROM ${PREFIX}principals WHERE id = 'user_one'`),
			)).rejects.toBeInstanceOf(TypeError);
			expect(await store.storeV2Principals!.getById({
				scope: {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				},
				id: "user_one",
			})).toBeDefined();
			expect((await internal.status()).principalRevision).toBe(
				revisionBeforeRawDelete,
			);
			expect(await store.storeV2Principals!.getById({
				scope: {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				},
				id: "user_dropped",
			})).toMatchObject({ name: "Dropped Promise" });
			expect(store.snapshot.principals).toEqual([]);
			await store.refresh();
			expect(store.snapshot.principals).toEqual([]);
			await expect(
				escapedRepository.getById({
					scope: {
						projectId: initialized.project.id,
						environmentId: initialized.environment.id,
					},
					id: "user_one",
				}),
			).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPAL_REPOSITORY_REVOKED",
			});
			const snapshotAfterDirect = await pool.query<{
				revision: string;
				digest: string;
				xmin: string;
			}>(
				`SELECT revision::text, md5(data::text) AS digest, xmin::text
				 FROM ${TEST_TABLE} WHERE id = 1`,
			);
			expect(snapshotAfterDirect.rows[0]).toEqual(snapshotBeforeDirect.rows[0]);
			const uniquenessAfterDirect = await pool.query<{ xmin: string }>(
				`SELECT xmin::text FROM ${TEST_TABLE}_principal_email
				 WHERE principal_id = 'user_one'`,
			);
			expect(uniquenessAfterDirect.rows[0]).toEqual(
				uniquenessBeforeDirect.rows[0],
			);

			const revisionBeforeDroppedRollback = (await internal.status()).principalRevision;
			await expect(
				store.mutateStoreV2Principals!((principals) => {
					void principals.insert({
						...beforeCutover[0]!,
						id: "user_dropped_rollback",
						email: "dropped-rollback@example.test",
					});
					throw new Error("abort dropped principal operation");
				}),
			).rejects.toThrow("abort dropped principal operation");
			expect((await internal.status()).principalRevision).toBe(
				revisionBeforeDroppedRollback!,
			);
			expect(
				await pool.query(
					`SELECT 1 FROM ${PREFIX}principals WHERE id = 'user_dropped_rollback'`,
				),
			).toMatchObject({ rowCount: 0 });

			await store.mutateStoreV2Principals!(async (principals) => {
				const current = await principals.getById({
					scope: {
						projectId: initialized.project.id,
						environmentId: initialized.environment.id,
					},
					id: "user_one",
				});
				expect(current).not.toBeNull();
				await principals.update({
					...current!,
					name: "One Updated",
					updatedAt: "2026-07-15T01:00:00.000Z",
				}, { expectedUpdatedAt: current!.updatedAt });
				await principals.insert({
					...current!,
					id: "user_two",
					email: "two@example.test",
					name: "Two",
				});
				await principals.insert({
					...current!,
					id: "user_three",
					email: "three@example.test",
					name: "Three",
				});
			});
			const equalTokenRead = await store.storeV2Principals!.getById({
				scope: {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				},
				id: "user_one",
			});
			await store.mutateStoreV2Principals!(async (principals) => {
				const updated = await principals.update({
					...equalTokenRead!,
					name: "Equal token advances",
					updatedAt: equalTokenRead!.updatedAt,
				}, { expectedUpdatedAt: equalTokenRead!.updatedAt });
				expect(new Date(updated!.updatedAt).getTime()).toBeGreaterThan(
					new Date(equalTokenRead!.updatedAt).getTime(),
				);
			});
			await expect(
				store.mutateStoreV2Principals!((principals) =>
					principals.update({
						...equalTokenRead!,
						name: "Equal token stale overwrite",
						updatedAt: equalTokenRead!.updatedAt,
					}, { expectedUpdatedAt: equalTokenRead!.updatedAt }),
				),
			).rejects.toMatchObject({ code: "STORE_V2_PRINCIPAL_CONFLICT" });
			expect(await store.storeV2Principals!.getById({
				scope: {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				},
				id: "user_one",
			})).toMatchObject({ name: "Equal token advances" });

			const firstPage = await store.storeV2Principals!.listPage({
				scope: {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				},
				limit: 2,
			});
			expect(firstPage.principals.map((principal) => principal.id)).toEqual([
				"user_dropped",
				"user_one",
			]);
			expect(firstPage.hasMore).toBe(true);
			const last = firstPage.principals[1]!;
			const secondPage = await store.storeV2Principals!.listPage({
				scope: {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				},
				limit: 2,
				cursor: { createdAt: last.createdAt, id: last.id },
			});
			expect(secondPage.principals.map((principal) => principal.id)).toEqual([
				"user_three",
				"user_two",
			]);
			const serviceCreated = await syncRuntimeUserToManagementDurable(store, {
				id: "user_service_path",
				email: "service-path@example.test",
				name: "Service Path",
			}, {
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
			});
			expect(serviceCreated).toMatchObject({ id: "user_service_path" });
			expect(store.snapshot.principals).toEqual([]);
			const serviceAudit = await internal.listEventsPage({
				scope,
				limit: 20,
				action: "users.sync_runtime",
			});
			expect(serviceAudit.events).toEqual([
				expect.objectContaining({
					subjectId: "user_service_path",
					outcome: "success",
				}),
			]);

			await store.mutateStoreV2Principals!((principals) =>
				principals.insert({
					...beforeCutover[0]!,
					id: "user_external_one",
					email: "external-one@example.test",
					externalId: "provider-user-1",
				}),
			);
			await expect(store.mutateStoreV2Principals!((principals) =>
				principals.insert({
					...beforeCutover[0]!,
					id: "user_external_two",
					email: "external-two@example.test",
					externalId: "provider-user-1",
				}),
			)).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPAL_EXTERNAL_ID_CONFLICT",
			});

			const scimConnection = createScimConnection(store, {
				organizationId: organization.id,
				provider: "fixture",
				source: "api",
			});
			await store.ready();
			const scimApplied = await testScimConnectionAuthoritative(
				store,
				scimConnection.id,
				{
					dryRun: false,
					actor: "scim-proof",
					source: "api",
					users: [
						{ userName: "scim-one@example.test", externalId: "scim-one" },
						{ userName: "scim-two@example.test", externalId: "scim-two" },
					],
				},
			);
			expect(scimApplied.trace).toMatchObject({
				stage: "sync.apply",
				outcome: "pass",
			});
			const scimSuccessEvents = await internal.listEventsPage({
				scope,
				limit: 20,
				action: "scim.test",
			});
			expect(scimSuccessEvents.events.filter(
				(event) => event.correlationId === scimApplied.trace.correlationId,
			)).toHaveLength(1);
			const beforeFailedScim = await pool.query<{
				principals: string;
				events: string;
			}>(
				`SELECT
				 (SELECT count(*)::text FROM ${PREFIX}principals) principals,
				 (SELECT count(*)::text FROM ${PREFIX}events WHERE visible=true) events`,
			);
			const snapshotBeforeFailedScim = await pool.query<{
				digest: string;
			}>(`SELECT md5(data::text) digest FROM ${TEST_TABLE} WHERE id=1`);
			await expect(testScimConnectionAuthoritative(
				store,
				scimConnection.id,
				{
					dryRun: false,
					users: [
						{ userName: "scim-rollback-one@example.test", externalId: "scim-collision" },
						{ userName: "scim-rollback-two@example.test", externalId: "scim-collision" },
					],
				},
			)).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPAL_EXTERNAL_ID_CONFLICT",
			});
			expect(await pool.query(
				`SELECT
				 (SELECT count(*)::text FROM ${PREFIX}principals) principals,
				 (SELECT count(*)::text FROM ${PREFIX}events WHERE visible=true) events`,
			)).toMatchObject({ rows: beforeFailedScim.rows });
			expect(await pool.query(
				`SELECT md5(data::text) digest FROM ${TEST_TABLE} WHERE id=1`,
			)).toMatchObject({ rows: snapshotBeforeFailedScim.rows });
			const topologyCutover = (await cutoverStoreV2Topology(store, {
				confirm: true,
			})).status!;
			expect(topologyCutover.authoritativeCollections).toEqual([
				"events",
				"principals",
				"projects",
				"environments",
				"organizations",
			]);
			expect(store.snapshot.projects).toEqual([]);
			expect(store.snapshot.environments).toEqual([]);
			expect(store.snapshot.organizations).toEqual([]);
			expect(store.storeV2Topology?.authoritative).toBe(true);

			const migrationUserSourceId = `legacy-principal-proof-${process.pid}`;
			const migrationOrganizationSourceId = `legacy-organization-proof-${process.pid}`;
			const migrationFixture: LegacyExportFixture = {
				source: "legacy",
				users: [{
					id: migrationUserSourceId,
					email: `${migrationUserSourceId}@example.test`,
					name: "Legacy Principal Proof",
				}],
				organizations: [{
					id: migrationOrganizationSourceId,
					name: "Legacy Organization Proof",
					slug: migrationOrganizationSourceId,
				}],
				members: [{
					userId: migrationUserSourceId,
					organizationId: migrationOrganizationSourceId,
					role: "member",
				}],
			};
			const firstMigrationPlan = await planMigrationDurable(store, migrationFixture);
			await store.ready();
			const firstMigration = await runMigrationDurable(
				store,
				firstMigrationPlan.id,
				migrationFixture,
			);
			await verifyMigrationDurable(store, firstMigration.id, migrationFixture);
			const importedPrincipalId = firstMigration.createdResourceIds!.users[0]!;
			expect(firstMigration.createdRuntimeResourceIds?.users).toEqual([
				importedPrincipalId,
			]);
			const importedOrganizationId = firstMigration.createdResourceIds!.organizations[0]!;
			expect(
				await store.storeV2Topology!.getOrganization({
					scope,
					id: importedOrganizationId,
				}),
			).toMatchObject({ id: importedOrganizationId });
			expect(store.snapshot.organizations).toEqual([]);
			await store.mutateDurable((data) => data.readinessReports.push({
				id: "rollback-dependent-readiness",
				organizationId: importedOrganizationId,
				generatedAt: "2026-07-18T00:00:00.000Z",
				checks: [],
				overall: "ready",
				conformance: {
					mode: "simulation",
					liveCertified: false,
					note: "rollback dependency proof",
				},
				remainingCustomerActions: [],
				signature: "rollback-dependent-readiness",
			}));
			await expect(
				rollbackMigrationDurable(store, firstMigration.id, migrationFixture),
			).rejects.toMatchObject({
				code: "CLEARANCE_IMPORT_ROLLBACK_ORGANIZATION_CHANGED",
			});
			await store.mutateDurable((data) => {
				data.readinessReports = data.readinessReports.filter((report) =>
					report.id !== "rollback-dependent-readiness");
			});
			await pool.query(
				`INSERT INTO clearance_authz_revisions ("projectId", "environmentId", "organizationId", revision)
				 VALUES ($1, $2, $3, 1)`,
				[scope.projectId, scope.environmentId, importedOrganizationId],
			);
			await expect(
				rollbackMigrationDurable(store, firstMigration.id, migrationFixture),
			).rejects.toMatchObject({
				code: "CLEARANCE_IMPORT_ROLLBACK_ORGANIZATION_CHANGED",
			});
			await pool.query(
				`DELETE FROM clearance_authz_revisions
				 WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3`,
				[scope.projectId, scope.environmentId, importedOrganizationId],
			);
			const rollbackDependentSessionId = `rollback-dependent-session-${process.pid}`;
			await pool.query(
				`INSERT INTO session (id, token, "userId", "activeOrganizationId", "expiresAt", "updatedAt")
				 VALUES ($1, $2, $3, $4, now() + interval '1 hour', now())`,
				[
					rollbackDependentSessionId,
					`clr_sid_rollback-dependent-${process.pid}`,
					importedPrincipalId,
					importedOrganizationId,
				],
			);
			await expect(
				rollbackMigrationDurable(store, firstMigration.id, migrationFixture),
			).rejects.toMatchObject({
				code: "CLEARANCE_IMPORT_ROLLBACK_ORGANIZATION_CHANGED",
			});
			await pool.query(`DELETE FROM session WHERE id = $1`, [rollbackDependentSessionId]);
			const rollbackDependentPasskeyId = `rollback-dependent-passkey-${process.pid}`;
			await pool.query(
				`INSERT INTO passkey (
					id, "userId", "credentialID", "publicKey", "userHandle", counter,
					"deviceType", "backedUp", "createdAt", "updatedAt"
				 ) VALUES ($1, $2, $3, 'public-key', 'user-handle', 0, 'singleDevice', false, now(), now())`,
				[
					rollbackDependentPasskeyId,
					importedPrincipalId,
					`credential-${process.pid}`,
				],
			);
			await expect(
				rollbackMigrationDurable(store, firstMigration.id, migrationFixture),
			).rejects.toMatchObject({
				code: "CLEARANCE_IMPORT_ROLLBACK_USER_CHANGED",
			});
			await pool.query(`DELETE FROM passkey WHERE id = $1`, [rollbackDependentPasskeyId]);
			const originalCreatedUserIds = [...firstMigration.createdResourceIds!.users];
			await store.mutateDurable((data) => {
				const migration = data.migrations.find((candidate) => candidate.id === firstMigration.id)!;
				migration.createdResourceIds = {
					...migration.createdResourceIds!,
					users: [...originalCreatedUserIds, originalCreatedUserIds[0]!],
				};
			});
			await expect(
				rollbackMigrationDurable(store, firstMigration.id, migrationFixture),
			).rejects.toMatchObject({
				code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE",
			});
			await store.mutateDurable((data) => {
				const migration = data.migrations.find((candidate) => candidate.id === firstMigration.id)!;
				migration.createdResourceIds = {
					...migration.createdResourceIds!,
					users: originalCreatedUserIds,
				};
			});
			const parentLock = await pool.connect();
			const concurrentInvitationId = `rollback-concurrent-invitation-${process.pid}`;
			let parentLockOpen = false;
			try {
				await parentLock.query("BEGIN");
				parentLockOpen = true;
				await parentLock.query(
					`SELECT id FROM organization WHERE id = $1 FOR UPDATE`,
					[importedOrganizationId],
				);
				const rollback = rollbackMigrationDurable(
					store,
					firstMigration.id,
					migrationFixture,
				);
				let rollbackWaiting = false;
				for (let attempt = 0; attempt < 100; attempt += 1) {
					const waiting = await pool.query(
						`SELECT 1 FROM pg_stat_activity
						 WHERE datname = current_database()
						   AND wait_event_type = 'Lock'
						   AND query LIKE $1
						 LIMIT 1`,
						["select id from organization where id = $1 for update%"],
					);
					if (waiting.rowCount === 1) {
						rollbackWaiting = true;
						break;
					}
					await new Promise((resolve) => setTimeout(resolve, 10));
				}
				expect(rollbackWaiting).toBe(true);
				const concurrentInvitation = pool.query(
					`INSERT INTO invitation (id, "organizationId", email, status, "expiresAt", "inviterId")
					 VALUES ($1, $2, 'concurrent@example.test', 'pending', now() + interval '1 hour', $3)`,
					[concurrentInvitationId, importedOrganizationId, importedPrincipalId],
				).then(
					() => ({ ok: true as const }),
					(error: unknown) => ({ ok: false as const, error }),
				);
				await parentLock.query("COMMIT");
				parentLockOpen = false;
				await expect(rollback).resolves.toMatchObject({ status: "rolled_back" });
				await expect(concurrentInvitation).resolves.toMatchObject({
					ok: false,
					error: { code: "23503" },
				});
			} finally {
				if (parentLockOpen) await parentLock.query("ROLLBACK").catch(() => undefined);
				parentLock.release();
			}
			expect(await store.storeV2Principals!.getById({
				scope,
				id: importedPrincipalId,
				includeDeleted: true,
			})).toBeNull();
			expect((await pool.query(
				`SELECT 1 FROM "user" WHERE id=$1`,
				[importedPrincipalId],
			)).rowCount).toBe(0);
			await expect(pool.query(
				`INSERT INTO "passkeyChallenge" (
					id, "digestId", ceremony, "rpID", origin, "stagedSubjectId",
					"expiresAt", "createdAt", "updatedAt"
				 ) VALUES ($1, $2, 'authentication', 'localhost', 'http://localhost', $3,
					now() + interval '1 hour', now(), now())`,
				[
					`rollback-fenced-challenge-${process.pid}`,
					`rollback-fenced-digest-${process.pid}`,
					importedPrincipalId,
				],
			)).rejects.toMatchObject({ code: "23503" });
			await expect(pool.query(
				`INSERT INTO ${RUNTIME_AUDIT_TABLE} (
					id, correlation_id, project_id, environment_id, organization_id,
					actor, action, outcome, source, message, created_at
				) VALUES ($1, $2, $3, $4, $5, 'runtime', 'auth.login.succeeded', 'success', 'system', 'rollback fence probe', now())`,
				[
					`rollback-fenced-audit-${process.pid}`,
					`rollback-fenced-audit-correlation-${process.pid}`,
					scope.projectId,
					scope.environmentId,
					importedOrganizationId,
				],
			)).rejects.toMatchObject({ code: "23503" });
			expect(
				await store.storeV2Topology!.getOrganization({
					scope,
					id: importedOrganizationId,
				}),
			).toBeNull();
			expect(store.snapshot.organizations).toEqual([]);
			const secondMigrationPlan = await planMigrationDurable(store, migrationFixture);
			await store.ready();
			const secondMigration = await runMigrationDurable(
				store,
				secondMigrationPlan.id,
				migrationFixture,
			);
			expect(secondMigration.createdResourceIds?.users).toHaveLength(1);
			await rollbackMigrationDurable(store, secondMigration.id, migrationFixture);
			await rollbackStoreV2Topology(store, { confirm: true });

			const second = await createPgStore(DATABASE_URL, {
				tableName: TEST_TABLE,
				normalizedPrefix: PREFIX,
			});
			stores.push(second);
			let writersAtBarrier = 0;
			let releaseFirstWriter!: () => void;
			let releaseSecondWriter!: () => void;
			let resolveBothWriters!: () => void;
			const bothWritersReached = new Promise<void>((resolve) => {
				resolveBothWriters = resolve;
			});
			const firstWriterMayCommit = new Promise<void>((resolve) => {
				releaseFirstWriter = resolve;
			});
			const secondWriterMayCommit = new Promise<void>((resolve) => {
				releaseSecondWriter = resolve;
			});
			const runParallelWriter = (
				target: PgStore,
				id: string,
				mayCommit: Promise<void>,
			) =>
				target.mutateStoreV2Principals!(async (principals) => {
					await principals.insert({
						...beforeCutover[0]!,
						id,
						email: `${id}@example.test`,
						name: id,
					});
					writersAtBarrier += 1;
					if (writersAtBarrier === 2) resolveBothWriters();
					await mayCommit;
				});
			const parallelOne = runParallelWriter(
				store,
				"user_parallel_one",
				firstWriterMayCommit,
			);
			const parallelTwo = runParallelWriter(
				second,
				"user_parallel_two",
				secondWriterMayCommit,
			);
			let barrierTimeout!: NodeJS.Timeout;
			try {
				await Promise.race([
					bothWritersReached,
					new Promise<never>((_, reject) => {
						barrierTimeout = setTimeout(
							() => reject(new Error("unrelated principal writers serialized")),
							2_000,
						);
					}),
				]);
			} finally {
				clearTimeout(barrierTimeout);
			}
			releaseFirstWriter();
			await parallelOne;
			releaseSecondWriter();
			await parallelTwo;
			expect(writersAtBarrier).toBe(2);
			await Promise.all([store.refresh(), second.refresh()]);
			const authoritativePrincipalCount = Number((await pool.query<{ count: string }>(
				`SELECT count(*)::text AS count FROM ${PREFIX}principals`,
			)).rows[0]?.count);
			expect(store.resourceCounts().principals).toBe(authoritativePrincipalCount);
			expect(second.resourceCounts().principals).toBe(authoritativePrincipalCount);
			const stale = await store.storeV2Principals!.getById({
				scope,
				id: "user_one",
			});
			await second.mutateStoreV2Principals!(async (principals) => {
				const current = await principals.getById({ scope, id: "user_one" });
				await principals.update({
					...current!,
					name: "Fresh cross-process update",
					updatedAt: "2026-07-15T01:30:00.000Z",
				}, { expectedUpdatedAt: current!.updatedAt });
			});
			await store.mutateStoreV2Principals!((principals) =>
				principals.insert({
					...beforeCutover[0]!,
					id: "user_stale_fallback",
					email: "stale-fallback@example.test",
					name: "Stale Fallback",
				}),
			);
			expect(await store.storeV2Principals!.getById({ scope, id: "user_one" }))
				.toMatchObject({ name: "Fresh cross-process update" });
			expect(await store.storeV2Principals!.getById({
				scope,
				id: "user_stale_fallback",
			})).toBeDefined();
			expect(store.snapshot.principals).toEqual([]);
			await expect(
				store.mutateStoreV2Principals!((principals) =>
					principals.update({
						...stale!,
						name: "Stale overwrite",
						updatedAt: "2026-07-15T02:00:00.000Z",
					}, { expectedUpdatedAt: stale!.updatedAt })
				),
			).rejects.toMatchObject({ code: "STORE_V2_PRINCIPAL_CONFLICT" });

			let releaseWriter!: () => void;
			const writerCanCommit = new Promise<void>((resolve) => {
				releaseWriter = resolve;
			});
			await expect(rollbackStoreV2Principals(store, {})).rejects.toMatchObject({
				code: "STORE_V2_PRINCIPALS_ROLLBACK_CONFIRMATION_REQUIRED",
			});
			let writerLocked!: () => void;
			const writerHasLock = new Promise<void>((resolve) => {
				writerLocked = resolve;
			});
			const racingPrincipal: Principal = {
				...beforeCutover[0]!,
				id: "user_rollback_race",
				email: "rollback-race@example.test",
				name: "Rollback Race",
				createdAt: "2026-07-15T02:30:00.000Z",
				updatedAt: "2026-07-15T02:30:00.000Z",
			};
			const writer = second.mutateStoreV2Principals!(async (principals) => {
				await principals.insert(racingPrincipal);
				writerLocked();
				await writerCanCommit;
			});
			await writerHasLock;
			const rollbackPromise = internal.rollbackPrincipals();
			const contender = await pool.connect();
			try {
				await contender.query("BEGIN");
				const lock = await contender.query<{ acquired: boolean }>(
					"SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0)) AS acquired",
					[`clearance:store-v2:principals:${TEST_TABLE}`],
				);
				expect(lock.rows[0]?.acquired).toBe(false);
				await contender.query("ROLLBACK");
			} finally {
				contender.release();
			}
			releaseWriter();
			await writer;
			const rollback = await rollbackPromise;
			expect(rollback.authoritativeCollections).toEqual(["events"]);
			await store.refresh();
			expect(store.snapshot.principals).toEqual(expect.arrayContaining([
				expect.objectContaining({ id: "user_rollback_race" }),
				expect.objectContaining({ id: "user_one", name: "Fresh cross-process update" }),
			]));
			expect(store.storeV2Principals?.authoritative).toBe(false);
			const restored = await pool.query<{ principals: number; events: number }>(
				`SELECT jsonb_array_length(data->'principals') AS principals,
				        jsonb_array_length(data->'events') AS events
				 FROM ${TEST_TABLE} WHERE id = 1`,
			);
			expect(restored.rows[0]).toEqual({
				principals: store.snapshot.principals.length,
				events: 0,
			});
			const companion = await pool.query<{ count: string }>(
				`SELECT count(*)::text AS count FROM ${TEST_TABLE}_principal_email`,
			);
			expect(Number(companion.rows[0]?.count)).toBe(
				store.snapshot.principals.filter((principal) => principal.status !== "deleted").length,
			);
		} finally {
			await pool.end();
		}
	});
});
