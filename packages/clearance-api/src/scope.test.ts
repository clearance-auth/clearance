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

describe("API project/environment scope enforcement", () => {
	let authHeaders: Record<string, string>;
	let projectId: string;
	let environmentId: string;

	beforeEach(async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-scope-"));
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
			body: JSON.stringify({ name: "Scope Test" }),
		});
		expect(init.status).toBe(200);
		const body = await init.json();
		projectId = body.project.id;
		environmentId = body.environment.id;

		// Seed org for enterprise/readiness families
		const orgRes = await app.request("/v1/organizations", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Scoped Org" }),
		});
		expect(orgRes.status).toBe(201);
	});

	async function loadApp() {
		return (await import("./server.js")).app;
	}

	it("keeps init and health usable without scope headers", async () => {
		const app = await loadApp();
		const health = await app.request("/health");
		expect(health.status).toBe(200);

		const doctor = await app.request("/v1/doctor", { headers: authHeaders });
		expect(doctor.status).toBe(200);
	});

	it("rejects wrong project scope on resource route family", async () => {
		const app = await loadApp();
		const wrong = {
			...authHeaders,
			"x-clearance-project-id": "proj_wrong_scope_xxxxx",
		};

		const users = await app.request("/v1/users", { headers: wrong });
		expect(users.status).toBe(403);
		expect((await users.json()).error.code).toBe("SCOPE_PROJECT");

		const orgs = await app.request("/v1/organizations", { headers: wrong });
		expect(orgs.status).toBe(403);

		const overview = await app.request("/v1/overview", { headers: wrong });
		expect(overview.status).toBe(403);

		const events = await app.request("/v1/events", { headers: wrong });
		expect(events.status).toBe(403);

		const settings = await app.request("/v1/settings", { headers: wrong });
		expect(settings.status).toBe(403);

		const roles = await app.request("/v1/roles", { headers: wrong });
		expect(roles.status).toBe(403);
		expect((await roles.json()).error.code).toBe("SCOPE_PROJECT");

		const sessions = await app.request("/v1/sessions", { headers: wrong });
		expect(sessions.status).toBe(403);
		expect((await sessions.json()).error.code).toBe("SCOPE_PROJECT");
	});

	it("rejects wrong environment scope on resource routes", async () => {
		const app = await loadApp();
		const wrong = {
			...authHeaders,
			"x-clearance-environment-id": "env_wrong_scope_xxxxx",
		};
		const users = await app.request("/v1/users", { headers: wrong });
		expect(users.status).toBe(403);
		expect((await users.json()).error.code).toBe("SCOPE_ENVIRONMENT");
	});

	it("rejects wrong scope on enterprise route family (sso/scim)", async () => {
		const app = await loadApp();
		const wrong = {
			...authHeaders,
			"x-clearance-project-id": "proj_wrong_enterprise",
		};

		const sso = await app.request("/v1/sso", {
			method: "POST",
			headers: wrong,
			body: JSON.stringify({
				organizationId: "org_x",
				provider: "okta",
				protocol: "oidc",
			}),
		});
		expect(sso.status).toBe(403);

		const ssoTest = await app.request("/v1/sso/sso_fake/test", {
			method: "POST",
			headers: wrong,
			body: JSON.stringify({}),
		});
		expect(ssoTest.status).toBe(403);

		const scim = await app.request("/v1/scim", {
			method: "POST",
			headers: wrong,
			body: JSON.stringify({ organizationId: "org_x", provider: "okta" }),
		});
		expect(scim.status).toBe(403);

		const scimTest = await app.request("/v1/scim/scim_fake/test", {
			method: "POST",
			headers: wrong,
			body: JSON.stringify({}),
		});
		expect(scimTest.status).toBe(403);
	});

	it("rejects wrong scope on readiness route family", async () => {
		const app = await loadApp();
		const wrong = {
			...authHeaders,
			"x-clearance-project-id": "proj_wrong_readiness",
		};

		const check = await app.request("/v1/readiness/check", {
			method: "POST",
			headers: wrong,
			body: JSON.stringify({ organizationId: "org_x" }),
		});
		expect(check.status).toBe(403);

		const report = await app.request("/v1/readiness/org_x", {
			headers: wrong,
		});
		expect(report.status).toBe(403);
	});

	it("users update/disable/delete are scoped and audited", async () => {
		const app = await loadApp();
		const create = await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "api-ops@test.com", name: "Api Ops" }),
		});
		expect(create.status).toBe(201);
		const { user } = await create.json();

		const patch = await app.request(`/v1/users/${user.id}`, {
			method: "PATCH",
			headers: authHeaders,
			body: JSON.stringify({ name: "Api Renamed" }),
		});
		expect(patch.status).toBe(200);
		const patched = await patch.json();
		expect(patched.user.name).toBe("Api Renamed");
		expect(patched.scope.projectId).toBe(projectId);

		const wrong = {
			...authHeaders,
			"x-clearance-project-id": "proj_wrong_user_mut",
		};
		const badPatch = await app.request(`/v1/users/${user.id}`, {
			method: "PATCH",
			headers: wrong,
			body: JSON.stringify({ name: "No" }),
		});
		expect(badPatch.status).toBe(403);

		const disable = await app.request(`/v1/users/${user.id}/disable`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(disable.status).toBe(200);
		expect((await disable.json()).user.status).toBe("disabled");

		const del = await app.request(`/v1/users/${user.id}`, {
			method: "DELETE",
			headers: authHeaders,
		});
		expect(del.status).toBe(200);
		expect((await del.json()).user.status).toBe("deleted");

		const missing = await app.request(`/v1/users/${user.id}`, {
			method: "DELETE",
			headers: authHeaders,
		});
		expect(missing.status).toBe(404);
		expect((await missing.json()).error.code).toBe("USER_NOT_FOUND");

		const getGone = await app.request(`/v1/users/${user.id}`, {
			headers: authHeaders,
		});
		expect(getGone.status).toBe(404);
	});

	it("allows matching scope headers on resource routes", async () => {
		const app = await loadApp();
		const ok = {
			...authHeaders,
			"x-clearance-project-id": projectId,
			"x-clearance-environment-id": environmentId,
		};
		const users = await app.request("/v1/users", { headers: ok });
		expect(users.status).toBe(200);
		const settings = await app.request("/v1/settings", { headers: ok });
		expect(settings.status).toBe(200);
		const body = await settings.json();
		expect(body.tokenBoundary).toBe("principal-derived-scope");
		expect(body.scope.projectId).toBe(projectId);
	});

	it("uses principal scope without requiring client headers", async () => {
		const app = await loadApp();
		// No scope headers — authority is server-derived from store after init
		const users = await app.request("/v1/users", { headers: authHeaders });
		expect(users.status).toBe(200);
		const body = await users.json();
		expect(body.scope.projectId).toBe(projectId);
		expect(body.scope.environmentId).toBe(environmentId);
	});

	it("fails closed for cross-scope user ids", async () => {
		const app = await loadApp();
		// Seed a user in principal scope
		const created = await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "inscope@test.local", name: "In Scope" }),
		});
		expect(created.status).toBe(201);
		const { user } = await created.json();

		const ok = await app.request(`/v1/users/${user.id}`, {
			headers: authHeaders,
		});
		expect(ok.status).toBe(200);

		// Inject a foreign principal directly into the store (other project/env)
		const { createManagementStore, newId, nowIso } = await import(
			"@clearance/management"
		);
		const store = await createManagementStore({
			dataPath: process.env.CLEARANCE_DATA_PATH,
		});
		await store.refresh();
		const foreignId = newId("user");
		const now = nowIso();
		store.mutate((data) => {
			data.principals.push({
				id: foreignId,
				projectId: "proj_foreign_other",
				environmentId: "env_foreign_other",
				email: "foreign@other.local",
				name: "Foreign",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});
		await store.ready();

		const foreign = await app.request(`/v1/users/${foreignId}`, {
			headers: authHeaders,
		});
		expect(foreign.status).toBe(404);
		const err = await foreign.json();
		expect(err.error.code).toBe("USER_NOT_FOUND");
		// Must not leak foreign email or project
		expect(JSON.stringify(err)).not.toContain("foreign@other.local");
		expect(JSON.stringify(err)).not.toContain("proj_foreign_other");
	});
});
