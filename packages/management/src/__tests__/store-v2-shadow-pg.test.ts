import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { initProject } from "../services/core.js";
import { appendAuditEvent, AUDIT_PRUNED_ACTION } from "../services/audit.js";
import { gatePostgresSuite } from "./pg-gate.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TEST_TABLE = `clearance_store_v2_${process.pid}`;
const NORMALIZED_PREFIX = `${TEST_TABLE}_n_`;
const DEFAULT_OFF_TABLE = `${TEST_TABLE}_off`;
const GUARD_TABLE = `${TEST_TABLE}_guard`;
const GUARD_PREFIX = `${GUARD_TABLE}_n_`;
const EVENTS_TABLE = `${TEST_TABLE}_events_authority`;
const EVENTS_PREFIX = `${EVENTS_TABLE}_n_`;

const available = await gatePostgresSuite(DATABASE_URL, "store-v2-shadow-pg");

describe.skipIf(!available)("PgStore store-v2 shadow", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const store of stores) await store.destroy().catch(() => undefined);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			for (const table of [
				`${EVENTS_PREFIX}events`,
				`${EVENTS_PREFIX}principals`,
				`${EVENTS_PREFIX}organizations`,
				`${EVENTS_PREFIX}environments`,
				`${EVENTS_PREFIX}projects`,
				`${EVENTS_PREFIX}meta`,
				`${EVENTS_TABLE}_principal_email`,
				`${EVENTS_TABLE}_organization_slug`,
				`${EVENTS_TABLE}_idempotency`,
				EVENTS_TABLE,
				`${NORMALIZED_PREFIX}events`,
				`${NORMALIZED_PREFIX}principals`,
				`${NORMALIZED_PREFIX}organizations`,
				`${NORMALIZED_PREFIX}environments`,
				`${NORMALIZED_PREFIX}projects`,
				`${NORMALIZED_PREFIX}meta`,
				`${TEST_TABLE}_principal_email`,
				`${TEST_TABLE}_organization_slug`,
				`${TEST_TABLE}_idempotency`,
				TEST_TABLE,
				`${DEFAULT_OFF_TABLE}_principal_email`,
				`${DEFAULT_OFF_TABLE}_organization_slug`,
					`${DEFAULT_OFF_TABLE}_idempotency`,
					DEFAULT_OFF_TABLE,
					`${GUARD_PREFIX}events`,
					`${GUARD_PREFIX}principals`,
					`${GUARD_PREFIX}organizations`,
					`${GUARD_PREFIX}environments`,
					`${GUARD_PREFIX}projects`,
					`${GUARD_PREFIX}meta`,
					`${GUARD_TABLE}_principal_email`,
					`${GUARD_TABLE}_organization_slug`,
					`${GUARD_TABLE}_idempotency`,
					GUARD_TABLE,
				]) {
				await pool.query(`DROP TABLE IF EXISTS ${table}`);
			}
		} finally {
			await pool.end();
		}
	});

	it("cuts events over atomically, retains and refreshes them, then reverses losslessly", async () => {
		const previousMax = process.env.CLEARANCE_AUDIT_MAX_EVENTS;
		process.env.CLEARANCE_AUDIT_MAX_EVENTS = "10";
		const first = await createPgStore(DATABASE_URL, {
			tableName: EVENTS_TABLE,
			normalizedPrefix: EVENTS_PREFIX,
		});
		stores.push(first);
		const initialized = initProject(first, {
			name: "Event Authority",
			source: "cli",
		});
		await first.ready();
		const applied = await first.storeV2!.apply();
		expect(applied.collections.events.relationalCount).toBe(
			first.snapshot.events.length,
		);
		expect(applied.consistent).toBe(true);

		const beforeCutoverChecksum = first.checksum();
		const cutover = await first.storeV2!.cutoverEvents();
		expect(cutover.phase).toBe("hybrid");
		expect(cutover.authoritativeCollections).toEqual(["events"]);
		expect(first.storeV2Events?.authoritative).toBe(true);
		expect(first.checksum()).toBe(beforeCutoverChecksum);

		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			const compact = await pool.query<{ event_count: number }>(
				`SELECT jsonb_array_length(data->'events') AS event_count FROM ${EVENTS_TABLE} WHERE id = 1`,
			);
			expect(compact.rows[0]?.event_count).toBe(0);

			await first.mutateDurable((data) => {
				data.projects[0]!.name = "Atomic event mutation";
				for (let index = 0; index < 12; index++) {
					appendAuditEvent(data, {
						actor: "operator",
						action: `events.authority.${index}`,
						subjectType: "store",
						outcome: "success",
						source: "cli",
						projectId: initialized.project.id,
						environmentId: initialized.environment.id,
						message: "event authority test",
					});
				}
			});
			expect(first.snapshot.events).toHaveLength(10);
			expect(
				first.snapshot.events.filter((event) => event.action === AUDIT_PRUNED_ACTION),
			).toHaveLength(1);
			const rows = await pool.query<{ count: string; archived: string }>(
				`SELECT count(*) FILTER (WHERE visible)::text AS count,
				        count(*) FILTER (WHERE NOT visible)::text AS archived
				 FROM ${EVENTS_PREFIX}events`,
			);
			expect(Number(rows.rows[0]?.count)).toBe(10);
			expect(Number(rows.rows[0]?.archived)).toBeGreaterThan(0);
			const compactAfter = await pool.query<{ event_count: number }>(
				`SELECT jsonb_array_length(data->'events') AS event_count FROM ${EVENTS_TABLE} WHERE id = 1`,
			);
			expect(compactAfter.rows[0]?.event_count).toBe(0);

			const beforeAtomicFailure = first.snapshot.projects[0]!.name;
			const duplicateEvent = structuredClone(first.snapshot.events[0]!);
			await expect(
				first.mutateDurable((data) => {
					data.projects[0]!.name = "must roll back with duplicate audit";
					data.events.unshift(duplicateEvent);
				}),
			).rejects.toThrow(/duplicate|unique/i);
			await first.refresh();
			expect(first.snapshot.projects[0]!.name).toBe(beforeAtomicFailure);

			const second = await createPgStore(DATABASE_URL, {
				tableName: EVENTS_TABLE,
				normalizedPrefix: EVENTS_PREFIX,
			});
			stores.push(second);
			expect(second.snapshot.events).toEqual(first.snapshot.events);
			await first.mutateDurable((data) => {
				appendAuditEvent(data, {
					actor: "operator",
					action: "events.authority.cross_process",
					subjectType: "store",
					outcome: "success",
					source: "cli",
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
					message: "cross process",
				});
			});
			await second.refresh();
			expect(second.snapshot.events).toEqual(first.snapshot.events);

			const firstPage = await first.storeV2Events!.listPage({
				scope: {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				},
				limit: 2,
			});
			expect(firstPage.events).toHaveLength(2);
			expect(firstPage.hasMore).toBe(true);
			const last = firstPage.events[1]!;
			const secondPage = await first.storeV2Events!.listPage({
				scope: {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				},
				limit: 2,
				cursor: { createdAt: last.createdAt, id: last.id },
			});
			expect(secondPage.events.map((event) => event.id)).not.toContain(
				firstPage.events[0]!.id,
			);

			const replacement = structuredClone(first.snapshot);
			first.replace(replacement);
			await expect(first.ready()).rejects.toMatchObject({
				code: "STORE_V2_REPLACE_REQUIRES_EVENTS_ROLLBACK",
			});

			const beforeRollbackChecksum = first.checksum();
			const rolledBack = await first.storeV2!.rollbackEvents();
			expect(rolledBack.phase).toBe("shadow");
			expect(first.storeV2Events?.authoritative).toBe(false);
			expect(first.checksum()).toBe(beforeRollbackChecksum);
			const restored = await pool.query<{ event_count: number }>(
				`SELECT jsonb_array_length(data->'events') AS event_count FROM ${EVENTS_TABLE} WHERE id = 1`,
			);
			expect(restored.rows[0]?.event_count).toBe(10);
			expect((await first.storeV2!.verify()).consistent).toBe(true);
		} finally {
			await pool.end();
			if (previousMax === undefined) delete process.env.CLEARANCE_AUDIT_MAX_EVENTS;
			else process.env.CLEARANCE_AUDIT_MAX_EVENTS = previousMax;
		}
	});

	it("keeps custom-table stores default-off without an explicit normalized prefix", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: DEFAULT_OFF_TABLE,
		});
		stores.push(store);

		expect(store.storeV2).toBeUndefined();
		initProject(store, { name: "Default Off", source: "cli" });
		await store.ready();
		expect(store.snapshot.projects).toHaveLength(1);
	});

	it("rejects unowned target tables and future schema versions", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: GUARD_TABLE,
			normalizedPrefix: GUARD_PREFIX,
		});
		stores.push(store);
		initProject(store, { name: "Guarded Store V2", source: "cli" });
		await store.ready();

		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await pool.query(
				`CREATE TABLE ${GUARD_PREFIX}projects (marker text NOT NULL)`,
			);
			await pool.query(
				`INSERT INTO ${GUARD_PREFIX}projects (marker) VALUES ('external')`,
			);
			await expect(store.storeV2!.apply()).rejects.toMatchObject({
				code: "STORE_V2_SCHEMA_COLLISION",
			});
			const untouched = await pool.query<{ marker: string }>(
				`SELECT marker FROM ${GUARD_PREFIX}projects`,
			);
			expect(untouched.rows).toEqual([{ marker: "external" }]);

			await pool.query(`DROP TABLE ${GUARD_PREFIX}projects`);
			expect((await store.storeV2!.apply()).consistent).toBe(true);
			await pool.query(
				`UPDATE ${GUARD_PREFIX}meta SET value = '2'::jsonb WHERE key = 'store_v2_schema_version'`,
			);
			await expect(store.storeV2!.apply()).rejects.toMatchObject({
				code: "STORE_V2_SCHEMA_VERSION_INVALID",
			});
		} finally {
			await pool.end();
		}
	});

	it("backfills atomically and dual-writes every PgStore mutation path", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TEST_TABLE,
			normalizedPrefix: NORMALIZED_PREFIX,
		});
		stores.push(store);
		const control = store.storeV2!;

		const initialized = initProject(store, {
			name: "Store V2",
			source: "cli",
		});
		await store.mutateDurable((data) => {
			data.principals.push({
				id: "user_store_v2",
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
				email: "store-v2@example.test",
				name: "Store V2 User",
				status: "active",
				createdAt: initialized.project.createdAt,
				updatedAt: initialized.project.updatedAt,
			});
		});

		const before = await control.status();
		expect(before.phase).toBe("absent");
		expect(before.consistent).toBe(false);
		const plan = await control.plan();
		expect(plan.canApply).toBe(true);
		expect(plan.rowCounts).toMatchObject({
			projects: 1,
			environments: 1,
			principals: 1,
			organizations: 0,
		});

		const applied = await control.apply();
		expect(applied.phase).toBe("shadow");
		expect(applied.consistent).toBe(true);

		// queueWrite / transactReplay
		store.mutate((data) => {
			data.projects[0]!.name = "Store V2 queued";
			data.projects[0]!.updatedAt = new Date().toISOString();
		});
		await store.ready();

		// mutateDurable / transactMutation
		await store.mutateDurable((data) => {
			data.principals[0]!.name = "Store V2 durable";
			data.principals[0]!.updatedAt = new Date().toISOString();
		});

		// mutateCoordinated / transactCoordinated
		await store.mutateCoordinated!(({ data }) => {
			data.organizations.push({
				id: "org_store_v2",
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
				name: "Store V2 Org",
				slug: "store-v2-org",
				status: "active",
				createdAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
			});
		});

		// replace through queueWrite / transactReplay
		const replacement = structuredClone(store.snapshot);
		replacement.environments[0]!.name = "Store V2 replacement";
		replacement.environments[0]!.updatedAt = new Date().toISOString();
		store.replace(replacement);
		await store.ready();

		const verified = await control.verify();
		expect(verified.consistent).toBe(true);
		expect(verified.snapshotRevision).toBe(verified.relationalRevision);
		expect(verified.collections.organizations.relationalCount).toBe(1);
	});

	it("coordinates phase and revisions across processes, disables safely, and reconciles", async () => {
		const first = await createPgStore(DATABASE_URL, {
			tableName: TEST_TABLE,
			normalizedPrefix: NORMALIZED_PREFIX,
		});
		const second = await createPgStore(DATABASE_URL, {
			tableName: TEST_TABLE,
			normalizedPrefix: NORMALIZED_PREFIX,
		});
		stores.push(first, second);

		expect((await second.storeV2!.status()).phase).toBe("shadow");
		await first.mutateDurable((data) => {
			data.principals[0]!.name = "Cross process";
			data.principals[0]!.updatedAt = new Date().toISOString();
		});
		expect((await second.storeV2!.verify()).consistent).toBe(true);

		const disabled = await second.storeV2!.disable();
		expect(disabled.phase).toBe("disabled");
		await first.mutateDurable((data) => {
			data.principals[0]!.name = "Snapshot only while disabled";
			data.principals[0]!.updatedAt = new Date().toISOString();
		});
		const drifted = await second.storeV2!.verify();
		expect(drifted.phase).toBe("disabled");
		expect(drifted.consistent).toBe(false);
		expect(drifted.collections.principals.differingIds).toEqual([
			"user_store_v2",
		]);

		const reconciled = await second.storeV2!.apply();
		expect(reconciled.phase).toBe("shadow");
		expect(reconciled.consistent).toBe(true);
	});

	it("supports atomic unique-value swaps across normalized collections", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TEST_TABLE,
			normalizedPrefix: NORMALIZED_PREFIX,
		});
		stores.push(store);
		const firstProject = store.snapshot.projects[0]!;
		const firstPrincipal = store.snapshot.principals[0]!;
		const firstOrganization = store.snapshot.organizations[0]!;
		await store.mutateDurable((data) => {
			data.projects.push({
				...firstProject,
				id: firstProject.id.toUpperCase(),
				name: "Store V2 swap",
				slug: "store-v2-swap",
			});
			data.principals.push({
				...firstPrincipal,
				id: firstPrincipal.id.toUpperCase(),
				email: "store-v2-swap@example.test",
			});
			data.organizations.push({
				...firstOrganization,
				id: firstOrganization.id.toUpperCase(),
				slug: "store-v2-swap",
			});
		});

		await store.mutateDurable((data) => {
			[data.projects[0]!.name, data.projects[1]!.name] = [
				data.projects[1]!.name,
				data.projects[0]!.name,
			];
			[data.projects[0]!.slug, data.projects[1]!.slug] = [
				data.projects[1]!.slug,
				data.projects[0]!.slug,
			];
			[data.principals[0]!.email, data.principals[1]!.email] = [
				data.principals[1]!.email,
				data.principals[0]!.email,
			];
			[data.organizations[0]!.slug, data.organizations[1]!.slug] = [
				data.organizations[1]!.slug,
				data.organizations[0]!.slug,
			];
		});
		expect((await store.storeV2!.verify()).consistent).toBe(true);

		await store.mutateDurable((data) => {
			const environment = data.environments[0]!;
			environment.projectId = data.projects[1]!.id;
			for (const principal of data.principals) {
				if (principal.environmentId === environment.id) {
					principal.projectId = environment.projectId;
				}
			}
			for (const organization of data.organizations) {
				if (organization.environmentId === environment.id) {
					organization.projectId = environment.projectId;
				}
			}
		});
		expect((await store.storeV2!.verify()).consistent).toBe(true);
	});

	it("fails closed when an old writer advances the snapshot without the shadow", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TEST_TABLE,
			normalizedPrefix: NORMALIZED_PREFIX,
		});
		stores.push(store);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await pool.query(`UPDATE ${TEST_TABLE} SET revision = revision + 1 WHERE id = 1`);
			await store.refresh();
			const staleRevision = store.currentRevision;
			await expect(
				store.mutateDurable((data) => {
					data.projects[0]!.name = "Must roll back";
				}),
			).rejects.toMatchObject({ code: "STORE_V2_REVISION_DIVERGED" });
			await store.refresh();
			expect(store.currentRevision).toBe(staleRevision);
			expect(store.snapshot.projects[0]!.name).not.toBe("Must roll back");
			expect((await store.storeV2!.apply()).consistent).toBe(true);
		} finally {
			await pool.end();
		}
	});

	it("reports bounded corruption evidence and rolls constraint failures back atomically", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TEST_TABLE,
			normalizedPrefix: NORMALIZED_PREFIX,
		});
		stores.push(store);
		const control = store.storeV2!;
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await pool.query(
				`UPDATE ${NORMALIZED_PREFIX}principals SET email = $1 WHERE id = $2`,
				["relational-corruption@example.test", "user_store_v2"],
			);
			const corrupted = await control.verify();
			expect(corrupted.consistent).toBe(false);
			expect(corrupted.collections.principals.differingIds).toEqual([
				"user_store_v2",
			]);
			expect(JSON.stringify(corrupted)).not.toContain("example.test");
			const previousVerify = process.env.CLEARANCE_STORE_V2_VERIFY;
			process.env.CLEARANCE_STORE_V2_VERIFY = "1";
			try {
				await expect(store.refresh()).rejects.toMatchObject({
					code: "STORE_V2_DIVERGENCE",
				});
			} finally {
				if (previousVerify === undefined) {
					delete process.env.CLEARANCE_STORE_V2_VERIFY;
				} else {
					process.env.CLEARANCE_STORE_V2_VERIFY = previousVerify;
				}
			}
		} finally {
			await pool.end();
		}

		await control.apply();
		const beforeRevision = store.currentRevision;
		await expect(
			store.mutateDurable((data) => {
				const original = data.principals[0]!;
				data.principals.push({
					...original,
					id: "user_store_v2_duplicate",
				});
			}),
		).rejects.toThrow(/duplicate|unique/i);
		await store.refresh();
		expect(store.currentRevision).toBe(beforeRevision);
		expect(
			store.snapshot.principals.some(
				(principal) => principal.id === "user_store_v2_duplicate",
			),
		).toBe(false);
		expect((await control.verify()).consistent).toBe(true);
	});
});
