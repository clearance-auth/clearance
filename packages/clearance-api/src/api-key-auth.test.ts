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
	delete process.env.CLEARANCE_PROJECT_ID;
	delete process.env.CLEARANCE_ENV_ID;
	vi.resetModules();
});

describe("managed API key authentication", () => {
	let projectId: string;
	let environmentId: string;
	let operatorHeaders: Record<string, string>;

	beforeEach(async () => {
		const directory = mkdtempSync(join(tmpdir(), "clr-api-key-auth-"));
		dirs.push(directory);
		delete process.env.DATABASE_URL;
		process.env.CLEARANCE_DATA_PATH = join(directory, "data.json");
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
		process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
		process.env.NODE_ENV = "development";
		operatorHeaders = {
			authorization: `Bearer ${OPERATOR}`,
			"content-type": "application/json",
		};

		const { app } = await import("./server.js");
		const response = await app.request("/v1/init", {
			method: "POST",
			headers: operatorHeaders,
			body: JSON.stringify({ name: "API Key Auth" }),
		});
		expect(response.status).toBe(200);
		const initialized = await response.json();
		projectId = initialized.project.id;
		environmentId = initialized.environment.id;
	});

	async function createKey(scopes: string[]) {
		const { app } = await import("./server.js");
		const response = await app.request("/v1/keys", {
			method: "POST",
			headers: operatorHeaders,
			body: JSON.stringify({ name: "automation", scopes }),
		});
		expect(response.status).toBe(201);
		return response.json() as Promise<{
			apiKey: { id: string; expiresAt?: string };
			secret: string;
		}>;
	}

	function keyHeaders(secret: string, extra: Record<string, string> = {}) {
		return { authorization: `Bearer ${secret}`, "content-type": "application/json", ...extra };
	}

	it("authenticates a valid digest-only key and attributes mutations to its id", async () => {
		const { app } = await import("./server.js");
		const created = await createKey(["system:read", "users:read", "users:write"]);

		const whoami = await app.request("/v1/whoami", { headers: keyHeaders(created.secret) });
		expect(whoami.status).toBe(200);
		expect(await whoami.json()).toMatchObject({
			operator: { id: created.apiKey.id, type: "api_key", authenticated: true },
			projectId,
			environmentId,
		});

		const createUser = await app.request("/v1/users", {
			method: "POST",
			headers: keyHeaders(created.secret),
			body: JSON.stringify({ email: "key-auth@example.test", name: "Key Auth" }),
		});
		expect(createUser.status).toBe(201);

		const events = await app.request("/v1/events?limit=100", { headers: operatorHeaders });
		expect(events.status).toBe(200);
		const body = await events.json();
		expect(body.events).toContainEqual(
			expect.objectContaining({ action: "users.create", actor: `api-key:${created.apiKey.id}` }),
		);
	});

	it("rejects unknown, revoked, and expired key material", async () => {
		const { app, getStore } = await import("./server.js");
		const revoked = await createKey(["users:read"]);
		const revoke = await app.request(`/v1/keys/${revoked.apiKey.id}/revoke`, {
			method: "POST",
			headers: operatorHeaders,
			body: "{}",
		});
		expect(revoke.status).toBe(200);

		for (const secret of ["clr_unknown-key-material", revoked.secret]) {
			const response = await app.request("/v1/users", { headers: keyHeaders(secret) });
			expect(response.status).toBe(401);
			expect((await response.json()).error.code).toBe("UNAUTHORIZED");
		}

		const expiring = await createKey(["users:read"]);
		const store = await getStore();
		await store.mutateDurable((snapshot) => {
			const key = snapshot.apiKeys.find((candidate) => candidate.id === expiring.apiKey.id);
			if (!key) throw new Error("seeded API key missing");
			key.expiresAt = new Date(Date.now() - 1_000).toISOString();
		});
		const expired = await app.request("/v1/users", { headers: keyHeaders(expiring.secret) });
		expect(expired.status).toBe(401);
		expect((await expired.json()).error.code).toBe("UNAUTHORIZED");
		const expiredDryRun = await app.request(`/v1/keys/${expiring.apiKey.id}/rotate`, {
			method: "POST",
			headers: operatorHeaders,
			body: JSON.stringify({ dryRun: true }),
		});
		expect(expiredDryRun.status).toBe(409);
		expect((await expiredDryRun.json()).error.code).toBe("API_KEY_EXPIRED");
	});

	it("enforces route scopes and project/environment boundaries", async () => {
		const { app } = await import("./server.js");
		const created = await createKey(["users:read"]);

		const allowed = await app.request("/v1/users", { headers: keyHeaders(created.secret) });
		expect(allowed.status).toBe(200);

		const denied = await app.request("/v1/users", {
			method: "POST",
			headers: keyHeaders(created.secret),
			body: JSON.stringify({ email: "denied@example.test", name: "Denied" }),
		});
		expect(denied.status).toBe(403);
		expect(await denied.json()).toMatchObject({
			error: { code: "API_KEY_SCOPE_FORBIDDEN", requiredScope: "users:write" },
		});

		const wrongProject = await app.request("/v1/users", {
			headers: keyHeaders(created.secret, { "x-clearance-project-id": "proj_other" }),
		});
		expect(wrongProject.status).toBe(403);
		expect((await wrongProject.json()).error.code).toBe("SCOPE_PROJECT");

		const wrongEnvironment = await app.request("/v1/users", {
			headers: keyHeaders(created.secret, { "x-clearance-environment-id": "env_other" }),
		});
		expect(wrongEnvironment.status).toBe(403);
		expect((await wrongEnvironment.json()).error.code).toBe("SCOPE_ENVIRONMENT");
	});

	it("keeps project topology, key lifecycle, and operator configuration operator-only", async () => {
		const { app } = await import("./server.js");
		const created = await createKey([
			"projects:write",
			"keys:write",
			"config:write",
			"delivery:read",
		]);
		const attempts = [
			app.request("/v1/projects", {
				method: "POST",
				headers: keyHeaders(created.secret),
				body: JSON.stringify({ name: "Denied project" }),
			}),
			app.request(`/v1/keys/${created.apiKey.id}/revoke`, {
				method: "POST",
				headers: keyHeaders(created.secret),
				body: "{}",
			}),
			app.request("/v1/config/projectId", {
				method: "PATCH",
				headers: keyHeaders(created.secret),
				body: JSON.stringify({ value: "proj_other" }),
			}),
			app.request("/v1/sso/sso_untrusted/test", {
				method: "POST",
				headers: keyHeaders(created.secret),
				body: JSON.stringify({ fixture: "ok" }),
			}),
			app.request("/v1/scim/scim_untrusted/test", {
				method: "POST",
				headers: keyHeaders(created.secret),
				body: JSON.stringify({ endpointOverride: "http://169.254.169.254" }),
			}),
			app.request("/v1/delivery/readiness", {
				headers: keyHeaders(created.secret),
			}),
		];
		for (const response of await Promise.all(attempts)) {
			expect(response.status).toBe(403);
			expect((await response.json()).error.code).toBe("OPERATOR_REQUIRED");
		}
	});

	it("owns enterprise audit attribution and redacts settings for delegated keys", async () => {
		const { app, getStore } = await import("./server.js");
		const created = await createKey([
			"organizations:write",
			"settings:read",
			"sso:write",
		]);
		const organizationResponse = await app.request("/v1/organizations", {
			method: "POST",
			headers: keyHeaders(created.secret),
			body: JSON.stringify({ name: "Delegated Enterprise", slug: "delegated-enterprise" }),
		});
		expect(organizationResponse.status).toBe(201);
		const { organization } = await organizationResponse.json();

		const ssoResponse = await app.request("/v1/sso", {
			method: "POST",
			headers: keyHeaders(created.secret),
			body: JSON.stringify({
				organizationId: organization.id,
				provider: "delegated-oidc",
				protocol: "oidc",
				issuer: "https://idp.example.test",
				actor: "forged-actor",
				source: "cli",
			}),
		});
		expect(ssoResponse.status).toBe(201);
		const { connection } = await ssoResponse.json();
		const testResponse = await app.request(`/v1/sso/${connection.id}/test`, {
			method: "POST",
			headers: operatorHeaders,
			body: JSON.stringify({ fixture: "ok" }),
		});
		expect(testResponse.status).toBe(200);

		const store = await getStore();
		await store.mutateDurable((data) => {
			data.meta.config.serviceToken = "secret-value-must-not-leak";
			data.meta.config.region = "test-region";
		});
		const settings = await app.request("/v1/settings", {
			headers: keyHeaders(created.secret),
		});
		expect(settings.status).toBe(200);
		const settingsBody = await settings.json();
		expect(settingsBody.config).toMatchObject({ region: "test-region" });
		expect(settingsBody.config).not.toHaveProperty("serviceToken");
		expect(settingsBody.redactedKeys).toContain("serviceToken");
		expect(settingsBody.auth).toEqual({ mode: "bearer-operator-or-managed-api-key" });
		expect(JSON.stringify(settingsBody)).not.toContain("secret-value-must-not-leak");

		const events = await app.request("/v1/events?limit=100", { headers: operatorHeaders });
		expect(events.status).toBe(200);
		const eventsBody = await events.json();
		expect(eventsBody.events).toContainEqual(
			expect.objectContaining({
				action: "sso.create",
				actor: `api-key:${created.apiKey.id}`,
				source: "api",
			}),
		);
		expect(eventsBody.events).toContainEqual(
			expect.objectContaining({
				action: "sso.test",
				actor: "api",
				source: "api",
			}),
		);
		expect(eventsBody.events).not.toContainEqual(
			expect.objectContaining({ action: "sso.create", actor: "forged-actor" }),
		);
	});
});
