import { afterAll, describe, expect, it } from "vitest";
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { initProject } from "../services/core.js";
import { createRole, listRoles, updateRole } from "../services/roles.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TABLE = `clearance_management_roles_test_${process.pid}`;


const available = await gatePostgresSuite(DATABASE_URL, "roles-pg");

describe.skipIf(!available)("roles on PgStore", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const store of stores) await store.destroy().catch(() => undefined);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		await pool.query(`DROP TABLE IF EXISTS ${TABLE}`);
		await pool.query(`DROP TABLE IF EXISTS ${TABLE}_principal_email`);
		await pool.query(`DROP TABLE IF EXISTS ${TABLE}_organization_slug`);
		await pool.end();
	});

	it("returns only committed role state and rejects a concurrent duplicate", async () => {
		const storeA = await createPgStore(DATABASE_URL, { tableName: TABLE });
		const storeB = await createPgStore(DATABASE_URL, { tableName: TABLE });
		stores.push(storeA, storeB);

		initProject(storeA, { name: "Role PG" });
		await storeA.ready();
		await storeB.refresh();

		const created = await createRole(storeA, {
			name: "Support",
			permissions: ["tickets:read"],
			source: "api",
		});
		expect(created.slug).toBe("support");

		const updated = await updateRole(storeA, created.id, {
			name: "Support Lead",
			permissions: ["tickets:assign", "tickets:read"],
			source: "api",
		});
		expect(updated).toMatchObject({
			id: created.id,
			name: "Support Lead",
			permissions: ["tickets:assign", "tickets:read"],
		});

		await storeB.refresh();
		expect(listRoles(storeB).find((role) => role.id === created.id)).toMatchObject({
			name: "Support Lead",
		});

		const results = await Promise.allSettled([
			createRole(storeA, {
				name: "Auditor A",
				slug: "auditor",
				permissions: ["audit:read"],
			}),
			createRole(storeB, {
				name: "Auditor B",
				slug: "auditor",
				permissions: ["audit:read"],
			}),
		]);
		expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);

		await storeA.refresh();
		expect(
			listRoles(storeA).filter(
				(role) => role.kind === "custom" && role.slug === "auditor",
			),
		).toHaveLength(1);
	});
});
