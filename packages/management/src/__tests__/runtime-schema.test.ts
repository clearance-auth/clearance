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
		{
			label: "no pending work",
			plan: {
				pendingTables: 0,
				pendingFields: 0,
				pendingSecurityMigrations: [] as string[],
			},
			state: "configured",
		},
		{
			label: "a pending table only",
			plan: {
				pendingTables: 1,
				pendingFields: 0,
				pendingSecurityMigrations: [] as string[],
			},
			state: "migration-required",
		},
		{
			label: "a pending field only",
			plan: {
				pendingTables: 0,
				pendingFields: 1,
				pendingSecurityMigrations: [] as string[],
			},
			state: "migration-required",
		},
		{
			label: "a pending security migration only",
			plan: {
				pendingTables: 0,
				pendingFields: 0,
				pendingSecurityMigrations: ["session-credential-digests-v1"],
			},
			state: "migration-required",
		},
	])("reports $state for $label", async ({ plan, state }) => {
		process.env.DATABASE_URL = "postgres://runtime-schema-status.test/db";
		runtimePlan.current = plan;

		await expect(getRuntimeSchemaStatus()).resolves.toEqual({
			configured: true,
			state,
			...plan,
		});
	});

});
