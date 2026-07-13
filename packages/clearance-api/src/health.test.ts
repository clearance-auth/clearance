import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
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
	vi.resetModules();
});

describe("clearance-api app", () => {
	beforeEach(() => {
		const dir = mkdtempSync(join(tmpdir(), "clr-api-"));
		dirs.push(dir);
		// Force JSON backend for isolated unit tests (no shared compose file state)
		delete process.env.DATABASE_URL;
		process.env.CLEARANCE_DATA_PATH = join(dir, "data.json");
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
		process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
		process.env.NODE_ENV = "development";
	});

	it("serves /health without auth and requires bearer for /v1", async () => {
		const { app } = await import("./server.js");

		const health = await app.request("/health");
		expect(health.status).toBe(200);
		const healthBody = await health.json();
		expect(healthBody.ok).toBe(true);
		expect(healthBody.service).toBe("clearance-api");
		expect(healthBody.version).toBe("0.1.4");
		expect(Object.keys(healthBody).sort()).toEqual(["ok", "service", "version"]);

		const unauth = await app.request("/v1/users");
		expect(unauth.status).toBe(401);

		const authHeaders = {
			authorization: `Bearer ${OPERATOR}`,
			"content-type": "application/json",
		};

		const init = await app.request("/v1/init", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "API Test" }),
		});
		expect(init.status).toBe(200);
		const initBody = await init.json();
		expect(initBody.project.id).toMatch(/^proj_/);

		const whoami = await app.request("/v1/whoami", { headers: authHeaders });
		expect(whoami.status).toBe(200);
		const whoamiBody = await whoami.json();
		expect(whoamiBody).toMatchObject({
			operator: { id: "operator", type: "operator", authenticated: true },
			projectId: initBody.project.id,
			environmentId: initBody.environment.id,
			storeBackend: "json",
		});
		expect(JSON.stringify(whoamiBody)).not.toContain(OPERATOR);

		const createUser = await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "api@test.com", name: "API User" }),
		});
		expect(createUser.status).toBe(201);
		const userBody = await createUser.json();
		expect(userBody.user.email).toBe("api@test.com");

		const list = await app.request("/v1/users", { headers: authHeaders });
		const listBody = await list.json();
		expect(listBody.users.some((u: { email: string }) => u.email === "api@test.com")).toBe(
			true,
		);
	});

	it("separates process liveness, dependency readiness, and Prometheus metrics", async () => {
		const { app } = await import("./server.js");
		const live = await app.request("/livez", {
			headers: { "x-request-id": "unsafe request id with spaces" },
		});
		expect(live.status).toBe(200);
		expect(live.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
		expect(await live.json()).toMatchObject({ ok: true, state: "live" });

		const ready = await app.request("/readyz");
		expect(ready.status).toBe(200);
		expect(await ready.json()).toMatchObject({
			ok: true,
			state: "ready",
			storeBackend: "json",
		});

		const metrics = await app.request("/metrics");
		expect(metrics.status).toBe(200);
		expect(metrics.headers.get("content-type")).toContain("version=0.0.4");
		const body = await metrics.text();
		expect(body).toContain("clearance_http_requests_total");
		expect(body).toContain("clearance_http_requests_in_flight");
		expect(body).not.toContain(OPERATOR);
	});

	it("drains the HTTP server and destroys the store without a stale timeout", async () => {
		const { installGracefulShutdown } = await import("./server.js");
		const httpServer = createServer((_req, res) => res.end("ok"));
		await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
		let readyCalled = 0;
		let destroyCalled = 0;
		const store = {
			ready: async () => {
				readyCalled += 1;
			},
			destroy: async () => {
				destroyCalled += 1;
			},
		};
		const previousExitCode = process.exitCode;
		process.exitCode = undefined;
		const shutdown = installGracefulShutdown(httpServer, store as never, {
			registerSignals: false,
			timeoutMs: 10,
		});
		await shutdown("SIGTERM");
		await new Promise((resolve) => setTimeout(resolve, 20));
		expect(httpServer.listening).toBe(false);
		expect(readyCalled).toBe(1);
		expect(destroyCalled).toBe(1);
		expect(process.exitCode).toBeUndefined();
		process.exitCode = previousExitCode;
	});

	it("rejects wrong bearer and enforces CORS allowlist", async () => {
		const { app } = await import("./server.js");

		const bad = await app.request("/v1/overview", {
			headers: { authorization: "Bearer wrong-token-value-here!!" },
		});
		expect(bad.status).toBe(401);
		const unauthenticatedWhoami = await app.request("/v1/whoami");
		expect(unauthenticatedWhoami.status).toBe(401);

		const preflight = await app.request("/v1/doctor", {
			method: "OPTIONS",
			headers: {
				origin: "http://evil.example",
				"access-control-request-method": "GET",
			},
		});
		// disallowed origin should not echo evil origin
		const acao = preflight.headers.get("access-control-allow-origin");
		expect(acao).not.toBe("http://evil.example");

		// doctor is authenticated and does not require principal scope (bootstrapping)
		const okOrigin = await app.request("/v1/doctor", {
			headers: {
				authorization: `Bearer ${OPERATOR}`,
				origin: "http://localhost:3100",
			},
		});
		expect(okOrigin.status).toBe(200);
		expect(okOrigin.headers.get("access-control-allow-origin")).toBe(
			"http://localhost:3100",
		);
	});
});
