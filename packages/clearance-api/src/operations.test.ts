import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const dirs: string[] = [];
const OPERATOR = "test-operator-token-32chars!!";

afterEach(() => {
	for (const directory of dirs.splice(0)) rmSync(directory, { recursive: true, force: true });
	delete process.env.CLEARANCE_DATA_PATH;
	delete process.env.CLEARANCE_OPERATOR_TOKEN;
	delete process.env.DATABASE_URL;
	vi.resetModules();
});

describe("operational route authentication", () => {
	it("requires an operator bearer token before dispatching an operational route", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clr-api-operations-"));
		dirs.push(directory);
		process.env.CLEARANCE_DATA_PATH = join(directory, "data.json");
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
		process.env.NODE_ENV = "development";
		const { app } = await import("./server.js");

		const response = await app.request("/v1/schema/status");
		expect(response.status).toBe(401);
		expect(await response.json()).toMatchObject({ error: { code: "UNAUTHORIZED" } });
	});
});
