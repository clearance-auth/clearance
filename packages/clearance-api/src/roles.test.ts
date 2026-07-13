/**
 * API tests for /v1/roles — principal-derived scope, validation, audit-backed mutations.
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

describe("API /v1/roles", () => {
	let authHeaders: Record<string, string>;
	let projectId: string;
	let environmentId: string;

	beforeEach(async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-api-roles-"));
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
			body: JSON.stringify({ name: "Roles API" }),
		});
		expect(init.status).toBe(200);
		const body = await init.json();
		projectId = body.project.id;
		environmentId = body.environment.id;
	});

	async function loadApp() {
		return (await import("./server.js")).app;
	}

	it("lists built-in roles under principal scope without client headers", async () => {
		const app = await loadApp();
		const res = await app.request("/v1/roles", { headers: authHeaders });
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.scope.projectId).toBe(projectId);
		expect(body.scope.environmentId).toBe(environmentId);
		expect(body.roles.length).toBeGreaterThanOrEqual(3);
		expect(body.roles.filter((r: { kind: string }) => r.kind === "built_in")).toHaveLength(
			3,
		);
		expect(body.roles.every((r: { projectId: string }) => r.projectId === projectId)).toBe(
			true,
		);
	});

	it("creates and updates roles with principal scope authority", async () => {
		const app = await loadApp();
		const create = await app.request("/v1/roles", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({
				name: "Billing",
				permissions: ["billing:read", "Billing:write"],
			}),
		});
		expect(create.status).toBe(201);
		const created = await create.json();
		expect(created.role.slug).toBe("billing");
		expect(created.role.permissions).toEqual(["billing:read", "billing:write"]);
		expect(created.role.kind).toBe("custom");
		expect(created.scope.projectId).toBe(projectId);

		const patch = await app.request(`/v1/roles/${created.role.id}`, {
			method: "PATCH",
			headers: authHeaders,
			body: JSON.stringify({
				name: "Billing Ops",
				permissions: ["billing:read", "billing:write", "billing:refund"],
			}),
		});
		expect(patch.status).toBe(200);
		const patched = await patch.json();
		expect(patched.role.name).toBe("Billing Ops");
		expect(patched.role.permissions).toEqual([
			"billing:read",
			"billing:refund",
			"billing:write",
		]);

		// Audit events present (no secret material)
		const events = await app.request("/v1/events?limit=20", {
			headers: authHeaders,
		});
		const eventBody = await events.json();
		const actions = eventBody.events.map((e: { action: string }) => e.action);
		expect(actions).toContain("roles.create");
		expect(actions).toContain("roles.update");
		expect(JSON.stringify(eventBody)).not.toMatch(/password|Bearer |sk_/i);
	});

	it("validates permissions without persisting", async () => {
		const app = await loadApp();
		const ok = await app.request("/v1/roles/validate", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({
				name: "Viewer",
				permissions: ["docs:read", "Docs:list"],
			}),
		});
		expect(ok.status).toBe(200);
		const body = await ok.json();
		expect(body.ok).toBe(true);
		expect(body.permissions).toEqual(["docs:list", "docs:read"]);

		const list = await app.request("/v1/roles", { headers: authHeaders });
		const listed = await list.json();
		expect(listed.roles.filter((r: { kind: string }) => r.kind === "custom")).toHaveLength(
			0,
		);

		const bad = await app.request("/v1/roles/validate", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ permissions: ["nope"] }),
		});
		expect(bad.status).toBe(400);
		expect((await bad.json()).error.code).toBe("ROLE_PERMISSION_MALFORMED");

		const reserved = await app.request("/v1/roles/validate", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ slug: "owner", permissions: ["ac:read"] }),
		});
		expect(reserved.status).toBe(409);
		expect((await reserved.json()).error.code).toBe("ROLE_RESERVED");
	});

	it("rejects wrong client scope headers on role routes", async () => {
		const app = await loadApp();
		const wrongProject = {
			...authHeaders,
			"x-clearance-project-id": "proj_wrong_roles_xxxxx",
		};
		const wrongEnv = {
			...authHeaders,
			"x-clearance-environment-id": "env_wrong_roles_xxxxxx",
		};

		const list = await app.request("/v1/roles", { headers: wrongProject });
		expect(list.status).toBe(403);
		expect((await list.json()).error.code).toBe("SCOPE_PROJECT");

		const create = await app.request("/v1/roles", {
			method: "POST",
			headers: wrongEnv,
			body: JSON.stringify({ name: "X", permissions: ["a:b"] }),
		});
		expect(create.status).toBe(403);
		expect((await create.json()).error.code).toBe("SCOPE_ENVIRONMENT");

		const validate = await app.request("/v1/roles/validate", {
			method: "POST",
			headers: wrongProject,
			body: JSON.stringify({ permissions: ["a:b"] }),
		});
		expect(validate.status).toBe(403);

		// Matching headers still work
		const okHeaders = {
			...authHeaders,
			"x-clearance-project-id": projectId,
			"x-clearance-environment-id": environmentId,
		};
		const okList = await app.request("/v1/roles", { headers: okHeaders });
		expect(okList.status).toBe(200);
	});

	it("rejects reserved built-in create and empty/malformed permissions", async () => {
		const app = await loadApp();

		const reserved = await app.request("/v1/roles", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Admin", slug: "admin", permissions: ["ac:read"] }),
		});
		expect(reserved.status).toBe(409);
		expect((await reserved.json()).error.code).toBe("ROLE_RESERVED");

		const empty = await app.request("/v1/roles", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Empty", permissions: [] }),
		});
		expect(empty.status).toBe(400);
		expect((await empty.json()).error.code).toBe("ROLE_PERMISSIONS_EMPTY");

		const malformed = await app.request("/v1/roles", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Bad", permissions: [":::"] }),
		});
		expect(malformed.status).toBe(400);
		expect((await malformed.json()).error.code).toBe("ROLE_PERMISSION_MALFORMED");

		const dup = await app.request("/v1/roles", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({
				name: "Dup",
				permissions: ["a:b", "A:B"],
			}),
		});
		expect(dup.status).toBe(400);
		expect((await dup.json()).error.code).toBe("ROLE_PERMISSION_DUPLICATE");
	});

	it("refuses built-in role updates", async () => {
		const app = await loadApp();
		const patch = await app.request("/v1/roles/role_builtin_owner", {
			method: "PATCH",
			headers: authHeaders,
			body: JSON.stringify({ name: "Nope" }),
		});
		expect(patch.status).toBe(403);
		expect((await patch.json()).error.code).toBe("ROLE_BUILT_IN");
	});
});
