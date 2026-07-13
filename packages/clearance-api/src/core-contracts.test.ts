/**
 * API contracts for env inspect/promote, orgs update/archive, users export.
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

describe("API core management contracts", () => {
	let authHeaders: Record<string, string>;
	let projectId: string;
	let environmentId: string;
	let orgId: string;
	let userId: string;

	beforeEach(async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-api-core-"));
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
			body: JSON.stringify({ name: "API Core", environment: "beta" }),
		});
		expect(init.status).toBe(200);
		const body = await init.json();
		projectId = body.project.id;
		environmentId = body.environment.id;

		const userRes = await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "api@ex.test", name: "API User" }),
		});
		expect(userRes.status).toBe(201);
		userId = (await userRes.json()).user.id;

		const orgRes = await app.request("/v1/organizations", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "API Org", slug: "api-org" }),
		});
		expect(orgRes.status).toBe(201);
		orgId = (await orgRes.json()).organization.id;
	});

	async function loadApp() {
		return (await import("./server.js")).app;
	}

	it("inspects environment without leaking secrets", async () => {
		const app = await loadApp();
		const res = await app.request(`/v1/environments/${environmentId}`, {
			headers: authHeaders,
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.environment.id).toBe(environmentId);
		expect(body.local.active).toBe(true);
		expect(body.local.config).toHaveProperty("hasClearanceSecret");
		expect(JSON.stringify(body)).not.toContain("unit-test-secret-value");
	});

	it("defaults project and environment inspection to the principal scope", async () => {
		const app = await loadApp();
		const project = await app.request("/v1/projects/current", { headers: authHeaders });
		expect(project.status).toBe(200);
		expect((await project.json()).project.id).toBe(projectId);
		const environment = await app.request("/v1/environments/current", { headers: authHeaders });
		expect(environment.status).toBe(200);
		const environmentBody = await environment.json();
		expect(environmentBody.environment.id).toBe(environmentId);
		expect(environmentBody.environment.slug).toBe("beta");
	});

	it("rejects malformed dry-run values before any mutation", async () => {
		const app = await loadApp();
		const before = await app.request("/v1/projects", { headers: authHeaders });
		const beforeCount = (await before.json()).projects.length;
		for (const field of ["dryRun", "confirm"] as const) {
			for (const value of ["true", 1, null]) {
				const response = await app.request("/v1/projects", {
					method: "POST",
					headers: authHeaders,
					body: JSON.stringify({ name: `Unsafe ${field} ${String(value)}`, [field]: value }),
				});
				expect(response.status).toBe(400);
				expect((await response.json()).error.code).toBe("API_BOOLEAN_INVALID");
			}
		}
		const after = await app.request("/v1/projects", { headers: authHeaders });
		expect((await after.json()).projects).toHaveLength(beforeCount);
	});

	it("previews representative creates through the API without mutating state", async () => {
		const app = await loadApp();
		const beforeProjects = await app.request("/v1/projects", { headers: authHeaders });
		const beforeUsers = await app.request("/v1/users", { headers: authHeaders });
		const projectPreview = await app.request("/v1/projects", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Preview Project", dryRun: true }),
		});
		expect(projectPreview.status).toBe(200);
		expect((await projectPreview.json()).dryRun).toBe(true);
		const userPreview = await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "preview@example.test", name: "Preview", dryRun: true }),
		});
		expect(userPreview.status).toBe(200);
		expect((await userPreview.json()).dryRun).toBe(true);
		const afterProjects = await app.request("/v1/projects", { headers: authHeaders });
		const afterUsers = await app.request("/v1/users", { headers: authHeaders });
		expect((await afterProjects.json()).projects).toHaveLength((await beforeProjects.json()).projects.length);
		expect((await afterUsers.json()).users).toHaveLength((await beforeUsers.json()).users.length);
	});

	it("rejects non-string config values at the HTTP boundary", async () => {
		const app = await loadApp();
		for (const value of [42, { nested: true }, ["x"], null]) {
			const response = await app.request("/v1/config/example", {
				method: "PATCH",
				headers: authHeaders,
				body: JSON.stringify({ value }),
			});
			expect(response.status).toBe(400);
			expect((await response.json()).error.code).toBe("CONFIG_VALUE_INVALID");
		}
	});

	it("promotes with dry-run plan and structured blocker; confirm audits", async () => {
		const app = await loadApp();
		// Create a second environment via management is only on store — use promote to same for idempotent, and dry-run for plan
		const dry = await app.request("/v1/environments/promote", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ to: environmentId, dryRun: true }),
		});
		expect(dry.status).toBe(200);
		const dryBody = await dry.json();
		expect(dryBody.dryRun).toBe(true);
		expect(dryBody.idempotent).toBe(true);

		// Missing target
		const bad = await app.request("/v1/environments/promote", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ to: "env_missing", dryRun: true }),
		});
		expect(bad.status).toBe(404);

		const confirm = await app.request("/v1/environments/promote", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ to: environmentId, confirm: true }),
		});
		expect(confirm.status).toBe(200);
		const confirmBody = await confirm.json();
		expect(confirmBody.dryRun).toBe(false);
		expect(confirmBody.auditAction).toBe("env.promote");
	});

	it("updates organization with validation and wrong-scope denial", async () => {
		const app = await loadApp();
		const res = await app.request(`/v1/organizations/${orgId}`, {
			method: "PATCH",
			headers: authHeaders,
			body: JSON.stringify({ name: "Renamed Org", slug: "renamed-org" }),
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.organization.name).toBe("Renamed Org");
		expect(body.organization.slug).toBe("renamed-org");

		const empty = await app.request(`/v1/organizations/${orgId}`, {
			method: "PATCH",
			headers: authHeaders,
			body: JSON.stringify({}),
		});
		expect(empty.status).toBe(400);

		const statusBody = await app.request(`/v1/organizations/${orgId}`, {
			method: "PATCH",
			headers: authHeaders,
			body: JSON.stringify({ status: "archived" }),
		});
		expect(statusBody.status).toBe(400);
		expect((await statusBody.json()).error.code).toBe("ORG_STATUS_IMMUTABLE");

		// Cross-scope header consistency fails closed
		const wrongHeader = await app.request(`/v1/organizations/${orgId}`, {
			method: "PATCH",
			headers: {
				...authHeaders,
				"x-clearance-project-id": "proj_other",
			},
			body: JSON.stringify({ name: "Nope" }),
		});
		expect(wrongHeader.status).toBe(403);
	});

	it("archives organization with dry-run/confirm and membership denial", async () => {
		const app = await loadApp();
		await app.request(`/v1/organizations/${orgId}/members`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ principalId: userId, role: "owner" }),
		});

		const dry = await app.request(`/v1/organizations/${orgId}/archive`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ dryRun: true }),
		});
		expect(dry.status).toBe(200);
		expect((await dry.json()).dryRun).toBe(true);

		const apply = await app.request(`/v1/organizations/${orgId}/archive`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ confirm: true }),
		});
		expect(apply.status).toBe(200);
		const applied = await apply.json();
		expect(applied.organization.status).toBe("archived");
		expect(applied.wouldChange).toBe(true);

		const inspect = await app.request(`/v1/organizations/${orgId}`, {
			headers: authHeaders,
		});
		expect(inspect.status).toBe(404);

		const members = await app.request(`/v1/organizations/${orgId}/members`, {
			headers: authHeaders,
		});
		expect(members.status).toBe(404);

		const again = await app.request(`/v1/organizations/${orgId}/archive`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ confirm: true }),
		});
		expect(again.status).toBe(200);
		expect((await again.json()).idempotent).toBe(true);
	});

	it("exports users in envelope and refuses filesystem paths", async () => {
		const app = await loadApp();
		const res = await app.request("/v1/users/export", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ limit: 10, format: "json" }),
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.kind).toBe("users.export");
		expect(body.schemaVersion).toBe(1);
		expect(body.count).toBeGreaterThanOrEqual(1);
		expect(body.users.every((u: { projectId: string }) => u.projectId === projectId)).toBe(
			true,
		);
		expect(body.outputPath).toBeUndefined();

		const pathDenied = await app.request("/v1/users/export", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ outputPath: "/tmp/users.json" }),
		});
		expect(pathDenied.status).toBe(400);
		expect((await pathDenied.json()).error.code).toBe("USERS_EXPORT_PATH_FORBIDDEN");

		const badLimit = await app.request("/v1/users/export", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ limit: 0 }),
		});
		expect(badLimit.status).toBe(400);
	});
});
