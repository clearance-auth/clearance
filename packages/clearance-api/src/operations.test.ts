import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dirs: string[] = [];
const OPERATOR = "test-operator-token-32chars!!";

afterEach(() => {
	for (const directory of dirs.splice(0)) {
		rmSync(directory, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_DATA_PATH;
	delete process.env.CLEARANCE_OPERATOR_TOKEN;
	delete process.env.DATABASE_URL;
	delete process.env.CLEARANCE_CORS_ORIGINS;
	delete process.env.CLEARANCE_BACKUP_DIR;
	vi.resetModules();
});

describe("authenticated operational API contracts", () => {
	let app: { request: typeof fetch };
	let headers: Record<string, string>;
	let directory: string;

	beforeEach(async () => {
		directory = mkdtempSync(join(tmpdir(), "clr-api-ops-"));
		dirs.push(directory);
		process.env.CLEARANCE_DATA_PATH = join(directory, "data.json");
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
		process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
		process.env.CLEARANCE_BACKUP_DIR = join(directory, "backups");
		process.env.NODE_ENV = "development";
		headers = {
			authorization: `Bearer ${OPERATOR}`,
			"content-type": "application/json",
		};
		app = (await import("./server.js")).app as { request: typeof fetch };
		const initialized = await app.request("/v1/init", {
			method: "POST",
			headers,
			body: JSON.stringify({ name: "Operational API" }),
		});
		expect(initialized.status).toBe(200);
	});

	it("requires operator authentication for every operational route", async () => {
		for (const [method, path, body] of [
			["GET", "/v1/dev", undefined],
			["POST", "/v1/backups", {}],
			["GET", "/v1/upgrades/check", undefined],
			["GET", "/v1/schema/status", undefined],
			["POST", "/v1/migrations/plan", { source: "legacy", fixture: {} }],
		] as const) {
			const response = await app.request(path, {
				method,
				...(body === undefined ? {} : {
					headers: { "content-type": "application/json" },
					body: JSON.stringify(body),
				}),
			});
			expect(response.status, `${method} ${path}`).toBe(401);
		}
	});

	it("preserves the legacy import CLI response contract through the API", async () => {
		const fixture = {
			source: "legacy",
			users: [{ id: "legacy-user", email: "legacy@example.test", name: "Legacy User" }],
			organizations: [{ id: "legacy-org", name: "Legacy Org", slug: "legacy-org" }],
			members: [{ userId: "legacy-user", organizationId: "legacy-org", role: "owner" }],
		};
		const dryRun = await app.request("/v1/import/legacy", {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture }),
		});
		expect(dryRun.status).toBe(200);
		expect(await dryRun.json()).toMatchObject({
			dryRun: true,
			storeBackend: "json",
			preview: { wouldCreate: { users: 1, organizations: 1, members: 1 } },
		});

		const applied = await app.request("/v1/import/legacy", {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture, confirm: true }),
		});
		expect(applied.status).toBe(200);
		expect(await applied.json()).toMatchObject({
			dryRun: false,
			storeBackend: "json",
			verification: { reconciled: true },
		});
	});

	it("runs legacy migration plan, apply, verify, status, and confirmed rollback through the API", async () => {
		const fixture = {
			source: "legacy",
			users: [{ id: "legacy-user", email: "legacy@example.test", name: "Legacy User" }],
			organizations: [{ id: "legacy-org", name: "Legacy Org", slug: "legacy-org" }],
			members: [{ userId: "legacy-user", organizationId: "legacy-org", role: "owner" }],
		};
		const planned = await app.request("/v1/migrations/plan", {
			method: "POST",
			headers,
			body: JSON.stringify({ source: "legacy", fixture }),
		});
		expect(planned.status).toBe(200);
		const planId = (await planned.json()).plan.id as string;

		const applied = await app.request(`/v1/migrations/${planId}/run`, {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture }),
		});
		expect(applied.status).toBe(200);
		expect((await applied.json()).plan.status).toBe("running");

		const verified = await app.request(`/v1/migrations/${planId}/verify`, {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture }),
		});
		expect(verified.status).toBe(200);
		expect((await verified.json()).reconciled).toBe(true);
		const status = await app.request(`/v1/migrations/${planId}`, { headers });
		expect(status.status).toBe(200);
		expect((await status.json()).plan.status).toBe("verified");

		const unconfirmed = await app.request(`/v1/migrations/${planId}/rollback`, {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture }),
		});
		expect(unconfirmed.status).toBe(400);
		expect((await unconfirmed.json()).error.code).toBe("MIGRATION_ROLLBACK_CONFIRM_REQUIRED");
		const rolledBack = await app.request(`/v1/migrations/${planId}/rollback`, {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture, confirm: true }),
		});
		expect(rolledBack.status).toBe(200);
		expect((await rolledBack.json()).plan.status).toBe("rolled_back");
	});

	it("creates, verifies, and only restores a development backup after confirmation", async () => {
		const clientSelectedDirectory = join(directory, "client-selected-backups");
		const rejectedDirectory = await app.request("/v1/backups", {
			method: "POST",
			headers,
			body: JSON.stringify({ dir: clientSelectedDirectory }),
		});
		expect(rejectedDirectory.status).toBe(400);
		expect((await rejectedDirectory.json()).error.code).toBe(
			"BACKUP_DIRECTORY_SERVER_MANAGED",
		);
		const created = await app.request("/v1/backups", {
			method: "POST",
			headers,
			body: "{}",
		});
		expect(created.status).toBe(201);
		const backupId = (await created.json()).backup.id as string;
		const verified = await app.request(`/v1/backups/${backupId}/verify`, {
			method: "POST",
			headers,
			body: "{}",
		});
		expect(verified.status).toBe(200);
		const target = join(directory, "restored.json");
		const unconfirmed = await app.request(`/v1/backups/${backupId}/restore`, {
			method: "POST",
			headers,
			body: JSON.stringify({ target }),
		});
		expect(unconfirmed.status).toBe(400);
		const restored = await app.request(`/v1/backups/${backupId}/restore`, {
			method: "POST",
			headers,
			body: JSON.stringify({ target, confirm: true }),
		});
		expect(restored.status).toBe(200);
		expect((await restored.json()).targetPath).toBe(target);
	});
});
