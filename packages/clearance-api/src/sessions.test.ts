/**
 * API tests for /v1/sessions — principal-derived scope, revoke, no token leak.
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

describe("API /v1/sessions", () => {
	let authHeaders: Record<string, string>;
	let projectId: string;
	let environmentId: string;
	let sessionId: string;

	beforeEach(async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-api-sessions-"));
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
			body: JSON.stringify({ name: "Sessions API" }),
		});
		expect(init.status).toBe(200);
		const body = await init.json();
		projectId = body.project.id;
		environmentId = body.environment.id;

		// Create user + session via management helpers (JSON path)
		const { createManagementStore, createUser, createSession } =
			await import("@clearance/management");
		const store = await createManagementStore({
			dataPath: process.env.CLEARANCE_DATA_PATH,
		});
		await store.refresh();
		const user = createUser(store, {
			email: "api-sess@test.com",
			name: "API Sess",
			source: "api",
		});
		const session = createSession(store, {
			principalId: user.id,
			environmentId,
		});
		sessionId = session.id;
		await store.ready();
	});

	async function loadApp() {
		return (await import("./server.js")).app;
	}

	it("lists sessions under principal scope without client headers", async () => {
		const app = await loadApp();
		const res = await app.request("/v1/sessions", { headers: authHeaders });
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.scope.projectId).toBe(projectId);
		expect(body.scope.environmentId).toBe(environmentId);
		expect(body.sessions.some((s: { id: string }) => s.id === sessionId)).toBe(
			true,
		);
		const json = JSON.stringify(body);
		expect(json).not.toMatch(/"token"/);
	});

	it("revokes session with audit and is idempotent", async () => {
		const app = await loadApp();
		const revoke = await app.request(`/v1/sessions/${sessionId}/revoke`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(revoke.status).toBe(200);
		const body = await revoke.json();
		expect(body.session.id).toBe(sessionId);
		expect(body.session.status).toBe("revoked");
		expect(body.idempotent).toBe(false);
		expect(body.scope.projectId).toBe(projectId);

		const again = await app.request(`/v1/sessions/${sessionId}/revoke`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(again.status).toBe(200);
		const body2 = await again.json();
		expect(body2.idempotent).toBe(true);

		const events = await app.request("/v1/events?limit=20", {
			headers: authHeaders,
		});
		const eventsBody = await events.json();
		const revokes = eventsBody.events.filter(
			(e: { action: string; subjectId?: string }) =>
				e.action === "sessions.revoke" && e.subjectId === sessionId,
		);
		expect(revokes.length).toBeGreaterThanOrEqual(2);
		expect(JSON.stringify(revokes)).not.toMatch(/token|password/i);
	});

	it("rejects wrong scope headers and missing sessions", async () => {
		const app = await loadApp();
		const wrong = {
			...authHeaders,
			"x-clearance-project-id": "proj_other",
		};
		const list = await app.request("/v1/sessions", { headers: wrong });
		expect(list.status).toBe(403);

		const missing = await app.request("/v1/sessions/sess_nope/revoke", {
			method: "POST",
			headers: authHeaders,
		});
		expect(missing.status).toBe(404);
		const err = await missing.json();
		expect(err.error.code).toBe("SESSION_NOT_FOUND");
	});

	it("requires operator auth", async () => {
		const app = await loadApp();
		const unauth = await app.request("/v1/sessions");
		expect(unauth.status).toBe(401);
	});

	it("rejects invalid list limits with a stable error", async () => {
		const app = await loadApp();
		const res = await app.request("/v1/sessions?limit=wat", {
			headers: authHeaders,
		});
		expect(res.status).toBe(400);
		const body = await res.json();
		expect(body.error.code).toBe("SESSION_LIMIT_INVALID");
		expect(body.error.stage).toBe("sessions.list");
	});
});
