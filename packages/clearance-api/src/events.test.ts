/**
 * API tests for events export / inspect / replay.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dirs: string[] = [];
const OPERATOR = "test-operator-token-32chars!!";

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_DATA_PATH;
	delete process.env.CLEARANCE_OPERATOR_TOKEN;
	delete process.env.DATABASE_URL;
	delete process.env.CLEARANCE_CORS_ORIGINS;
	delete process.env.CLEARANCE_PROJECT_ID;
	delete process.env.CLEARANCE_ENV_ID;
	vi.resetModules();
});

describe("API /v1/events export and replay", () => {
	let authHeaders: Record<string, string>;
	let projectId: string;
	let environmentId: string;
	let traceId: string;

	beforeEach(async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-api-events-"));
		dirs.push(dir);
		delete process.env.DATABASE_URL;
		process.env.CLEARANCE_DATA_PATH = join(dir, "data.json");
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
		process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
		process.env.NODE_ENV = "development";

		authHeaders = {
			authorization: `Bearer ${OPERATOR}`,
			"content-type": "application/json",
		};

		const { app } = await import("./server.js");
		const init = await app.request("/v1/init", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Events API" }),
		});
		expect(init.status).toBe(200);
		const body = await init.json();
		projectId = body.project.id;
		environmentId = body.environment.id;

		const orgRes = await app.request("/v1/organizations", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Events Org" }),
		});
		expect(orgRes.status).toBe(201);
		const org = (await orgRes.json()).organization;

		const scimRes = await app.request("/v1/scim", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({
				organizationId: org.id,
				provider: "okta",
			}),
		});
		expect(scimRes.status).toBe(201);
		const scim = (await scimRes.json()).connection;

		const testRes = await app.request(`/v1/scim/${scim.id}/test`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ dryRun: true, fixture: "ok" }),
		});
		expect(testRes.status).toBe(200);
		const tested = await testRes.json();
		traceId = tested.trace.id;
	});

	async function loadApp() {
		return (await import("./server.js")).app;
	}

	it("exports bounded redacted envelope and refuses secrets", async () => {
		const app = await loadApp();
		const res = await app.request("/v1/events/export", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ limit: 20, format: "json" }),
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.kind).toBe("events.export");
		expect(body.schemaVersion).toBe(1);
		expect(body.scope.projectId).toBe(projectId);
		expect(body.scope.environmentId).toBe(environmentId);
		expect(body.count).toBeGreaterThan(0);
		expect(body.events.length).toBe(body.count);
		expect(JSON.stringify(body)).not.toMatch(/password|Bearer |sk_live/i);

		const badLimit = await app.request("/v1/events/export", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ limit: 99999 }),
		});
		expect(badLimit.status).toBe(400);
		expect((await badLimit.json()).error.code).toBe("EVENTS_EXPORT_LIMIT_INVALID");

		const nonNumericLimit = await app.request("/v1/events/export", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ limit: "many" }),
		});
		expect(nonNumericLimit.status).toBe(400);
		expect((await nonNumericLimit.json()).error.code).toBe(
			"EVENTS_EXPORT_LIMIT_INVALID",
		);
	});

	it("inspects events and replays SCIM traces with dry-run default", async () => {
		const app = await loadApp();

		const inspect = await app.request(`/v1/events/${traceId}`, {
			headers: authHeaders,
		});
		expect(inspect.status).toBe(200);
		const inspected = await inspect.json();
		expect(inspected.trace.id).toBe(traceId);
		expect(inspected.replayable).toBe(true);

		const dry = await app.request("/v1/events/replay", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ id: traceId }),
		});
		expect(dry.status).toBe(200);
		const dryBody = await dry.json();
		expect(dryBody.dryRun).toBe(true);
		expect(dryBody.wouldChange).toBe(true);

		const apply = await app.request("/v1/events/replay", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ id: traceId, confirm: true }),
		});
		expect(apply.status).toBe(200);
		const applied = await apply.json();
		expect(applied.dryRun).toBe(false);
		expect(applied.idempotent).toBe(false);
		expect(applied.trace.id).not.toBe(traceId);

		const again = await app.request("/v1/events/replay", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ id: traceId, confirm: true }),
		});
		expect(again.status).toBe(200);
		expect((await again.json()).idempotent).toBe(true);

		const nonReplay = await app.request("/v1/events/replay", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ id: "evt_not_real", confirm: true }),
		});
		expect(nonReplay.status).toBeGreaterThanOrEqual(400);

		const wrong = {
			...authHeaders,
			"x-clearance-project-id": "proj_wrong_scope_xxxxx",
		};
		const scoped = await app.request("/v1/events/export", {
			method: "POST",
			headers: wrong,
			body: JSON.stringify({ limit: 5 }),
		});
		expect(scoped.status).toBe(403);
	});
});
