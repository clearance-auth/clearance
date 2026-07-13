/**
 * API tests for organization membership routes — principal-derived scope,
 * role validation, structured errors, JSON envelopes.
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

describe("API /v1/organizations/:id/members", () => {
	let authHeaders: Record<string, string>;
	let app: { request: typeof fetch };
	let orgId: string;
	let userId: string;
	let ownerId: string;

	beforeEach(async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-api-members-"));
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

		const mod = await import("./server.js");
		app = mod.app as { request: typeof fetch };

		const init = await app.request("/v1/init", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Members API" }),
		});
		expect(init.status).toBe(200);

		const owner = await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "owner@api.test", name: "Owner" }),
		});
		const ownerBody = await owner.json();
		ownerId = ownerBody.user.id;

		const user = await app.request("/v1/users", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ email: "member@api.test", name: "Member" }),
		});
		const userBody = await user.json();
		userId = userBody.user.id;

		const org = await app.request("/v1/organizations", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "API Org" }),
		});
		const orgBody = await org.json();
		orgId = orgBody.organization.id;

		// Seed owner membership so owner-invariant tests have a baseline
		const seed = await app.request(`/v1/organizations/${orgId}/members`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ principalId: ownerId, role: "owner" }),
		});
		expect(seed.status).toBe(201);
	});

	it("adds member with built-in role and lists under principal scope", async () => {
		const res = await app.request(`/v1/organizations/${orgId}/members`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ principalId: userId, role: "admin" }),
		});
		expect(res.status).toBe(201);
		const body = await res.json();
		expect(body.membership.role).toBe("admin");
		expect(body.membership.principalId).toBe(userId);
		expect(body.scope).toBeTruthy();

		const list = await app.request(`/v1/organizations/${orgId}/members`, {
			headers: authHeaders,
		});
		expect(list.status).toBe(200);
		const listed = await list.json();
		expect(
			listed.members.some((m: { principalId: string }) => m.principalId === userId),
		).toBe(true);
	});

	it("updates role and removes with structured JSON", async () => {
		const add = await app.request(`/v1/organizations/${orgId}/members`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ principalId: userId, role: "member" }),
		});
		const { membership } = await add.json();

		const patch = await app.request(
			`/v1/organizations/${orgId}/members/${membership.id}`,
			{
				method: "PATCH",
				headers: authHeaders,
				body: JSON.stringify({ role: "admin" }),
			},
		);
		expect(patch.status).toBe(200);
		const patched = await patch.json();
		expect(patched.membership.role).toBe("admin");

		const del = await app.request(
			`/v1/organizations/${orgId}/members/${membership.id}`,
			{
				method: "DELETE",
				headers: authHeaders,
			},
		);
		expect(del.status).toBe(200);
		const deleted = await del.json();
		expect(deleted.membership.status).toBe("removed");
	});

	it("rejects invalid role and missing principal with stable error codes", async () => {
		const missingPrincipal = await app.request(
			`/v1/organizations/${orgId}/members`,
			{
				method: "POST",
				headers: authHeaders,
				body: JSON.stringify({ role: "member" }),
			},
		);
		expect(missingPrincipal.status).toBe(400);
		const mp = await missingPrincipal.json();
		expect(mp.error.code).toBe("MEMBER_PRINCIPAL_REQUIRED");

		const badRole = await app.request(`/v1/organizations/${orgId}/members`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ principalId: userId, role: "not-real" }),
		});
		expect(badRole.status).toBe(404);
		const br = await badRole.json();
		expect(br.error.code).toBe("ROLE_NOT_FOUND");

		// No membership created
		const list = await app.request(`/v1/organizations/${orgId}/members`, {
			headers: authHeaders,
		});
		const listed = await list.json();
		expect(
			listed.members.filter(
				(m: { principalId: string }) => m.principalId === userId,
			),
		).toHaveLength(0);
	});

	it("rejects wrong client scope headers (cannot broaden authority)", async () => {
		const wrong = {
			...authHeaders,
			"x-clearance-project-id": "proj_wrong_members_xx",
			"x-clearance-environment-id": "env_wrong_members_xxx",
		};
		const res = await app.request(`/v1/organizations/${orgId}/members`, {
			method: "POST",
			headers: wrong,
			body: JSON.stringify({ principalId: userId, role: "member" }),
		});
		expect(res.status).toBeGreaterThanOrEqual(400);
		const body = await res.json();
		expect(body.error?.code).toBeTruthy();
	});

	it("blocks demoting the final owner", async () => {
		const list = await app.request(`/v1/organizations/${orgId}/members`, {
			headers: authHeaders,
		});
		const listed = await list.json();
		const ownerMem = listed.members.find(
			(m: { principalId: string; role: string }) =>
				m.principalId === ownerId && m.role === "owner",
		);
		expect(ownerMem).toBeTruthy();

		const demote = await app.request(
			`/v1/organizations/${orgId}/members/${ownerMem.id}`,
			{
				method: "PATCH",
				headers: authHeaders,
				body: JSON.stringify({ role: "admin" }),
			},
		);
		expect(demote.status).toBe(409);
		const body = await demote.json();
		expect(body.error.code).toBe("MEMBER_LAST_OWNER");
	});

	it("cross-org membership id fails closed as not found", async () => {
		const otherOrg = await app.request("/v1/organizations", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Other Org" }),
		});
		const otherId = (await otherOrg.json()).organization.id;

		const add = await app.request(`/v1/organizations/${orgId}/members`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ principalId: userId, role: "member" }),
		});
		const { membership } = await add.json();

		const patch = await app.request(
			`/v1/organizations/${otherId}/members/${membership.id}`,
			{
				method: "PATCH",
				headers: authHeaders,
				body: JSON.stringify({ role: "admin" }),
			},
		);
		expect(patch.status).toBe(404);
		expect((await patch.json()).error.code).toBe("MEMBER_NOT_FOUND");
	});
});
