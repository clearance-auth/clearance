import { afterEach, describe, expect, it } from "vitest";
import { getRuntimeSchemaStatus } from "../services/runtime-schema.js";

const originalDatabaseUrl = process.env.DATABASE_URL;

afterEach(() => {
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
		});
	});
});
