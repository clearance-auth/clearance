import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { initProject } from "../services/core.js";
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

const available = await gatePostgresSuite(DATABASE_URL, "store-v2-shadow-pg");

describe.skipIf(!available)("PgStore store-v2 shadow", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const store of stores) await store.destroy().catch(() => undefined);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			for (const table of [
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
