import { afterEach, describe, expect, it, vi } from "vitest";

const runtimePlan = vi.hoisted(() => ({
	current: {
		pendingTables: 0,
		pendingFields: 0,
		pendingSecurityMigrations: [] as string[],
	},
}));

vi.mock("../auth-bridge.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../auth-bridge.js")>();
	return {
		...actual,
		getAuthBundle: () => ({
			planMigrations: async () => ({
				...runtimePlan.current,
				compileSql: async () => "",
				apply: async () => {},
			}),
		}),
	};
});
import { getRuntimeSchemaStatus } from "../services/runtime-schema.js";

const originalDatabaseUrl = process.env.DATABASE_URL;

afterEach(() => {
	runtimePlan.current = {
		pendingTables: 0,
		pendingFields: 0,
		pendingSecurityMigrations: [],
	};
	if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
	else process.env.DATABASE_URL = originalDatabaseUrl;
});

describe("runtime schema status", () => {
	it("reports the Clearance runtime as unconfigured without DATABASE_URL", async () => {
		delete process.env.DATABASE_URL;
		await expect(getRuntimeSchemaStatus()).resolves.toEqual({
			configured: false,
			state: "unconfigured",
			pendingTables: 0,
			pendingFields: 0,
			pendingSecurityMigrations: [],
		});
	});

	it.each([
		[
			"configured runtime",
			{ pendingTables: 0, pendingFields: 0, pendingSecurityMigrations: [] as string[] },
			"configured",
		],
		[
			"any pending migration work",
			{ pendingTables: 1, pendingFields: 1, pendingSecurityMigrations: ["session-credential-digests-v1"] },
			"migration-required",
		],
	])("reports %s", async (_label, plan, state) => {
		process.env.DATABASE_URL = "postgres://runtime-schema-status.test/db";
		runtimePlan.current = plan;

		await expect(getRuntimeSchemaStatus()).resolves.toEqual({
			configured: true,
			state,
			...plan,
		});
	});
});
