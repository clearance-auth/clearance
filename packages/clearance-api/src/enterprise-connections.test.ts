/**
 * API tests for SSO/SCIM rotate, disable, and SCIM trace replay.
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
	delete process.env.CLEARANCE_CREDENTIAL_KEY;
	delete process.env.CLEARANCE_CREDENTIAL_KEY_ID;
	vi.resetModules();
});

describe("API enterprise connection rotate / disable / replay", () => {
	let authHeaders: Record<string, string>;
	let orgId: string;
	let ssoId: string;
	let scimId: string;
	let scimTraceId: string;

	beforeEach(async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-api-ent-"));
		dirs.push(dir);
		delete process.env.DATABASE_URL;
		process.env.CLEARANCE_DATA_PATH = join(dir, "data.json");
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
		process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
		process.env.CLEARANCE_CREDENTIAL_KEY =
			"unit-test-credential-key-material-32b!!";
		process.env.CLEARANCE_CREDENTIAL_KEY_ID = "k1";
		process.env.NODE_ENV = "development";

		authHeaders = {
			authorization: `Bearer ${OPERATOR}`,
			"content-type": "application/json",
		};

		const { app } = await import("./server.js");
		const init = await app.request("/v1/init", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Ent API" }),
		});
		expect(init.status).toBe(200);

		const orgRes = await app.request("/v1/organizations", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Customer" }),
		});
		expect(orgRes.status).toBe(201);
		orgId = (await orgRes.json()).organization.id;

		const ssoRes = await app.request("/v1/sso", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({
				organizationId: orgId,
				provider: "okta",
				protocol: "oidc",
				issuer: "https://idp.example/oauth2",
				clientSecret: "sso-secret-for-api-rotate",
			}),
		});
		expect(ssoRes.status).toBe(201);
		ssoId = (await ssoRes.json()).connection.id;

		const scimRes = await app.request("/v1/scim", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({
				organizationId: orgId,
				provider: "okta",
				bearerToken: "scim-token-for-api-rotate",
			}),
		});
		expect(scimRes.status).toBe(201);
		scimId = (await scimRes.json()).connection.id;

		const scimTest = await app.request(`/v1/scim/${scimId}/test`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ dryRun: true }),
		});
		expect(scimTest.status).toBe(200);
		scimTraceId = (await scimTest.json()).trace.id;
	});

	async function loadApp() {
		return (await import("./server.js")).app;
	}

	it("rotates SSO credential with fingerprint only and audit source api", async () => {
		const app = await loadApp();
		const res = await app.request(`/v1/sso/${ssoId}/rotate`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.connection.id).toBe(ssoId);
		expect(body.connection.clientSecretFingerprint).toBeTruthy();
		expect(body.connection.clientSecretEncrypted).toBeUndefined();
		expect(JSON.stringify(body)).not.toContain("sso-secret-for-api-rotate");
		expect(JSON.stringify(body)).not.toMatch(/clr\$v1\$/);

		const events = await app.request("/v1/events", { headers: authHeaders });
		const list = await events.json();
		expect(
			list.events.some(
				(e: { action: string; source: string }) =>
					e.action === "sso.rotate" && e.source === "api",
			),
		).toBe(true);
	});

	it("disables SSO connection and is fail-closed for missing ids", async () => {
		const app = await loadApp();
		const res = await app.request(`/v1/sso/${ssoId}/disable`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.connection.status).toBe("disabled");
		expect(body.idempotent).toBe(false);

		const again = await app.request(`/v1/sso/${ssoId}/disable`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(again.status).toBe(200);
		expect((await again.json()).idempotent).toBe(true);

		const missing = await app.request("/v1/sso/sso_missing/disable", {
			method: "POST",
			headers: authHeaders,
		});
		expect(missing.status).toBe(404);
		expect((await missing.json()).error.code).toBe("SSO_NOT_FOUND");
	});

	it("rotates and disables SCIM connection without token leakage", async () => {
		const app = await loadApp();
		const rotate = await app.request(`/v1/scim/${scimId}/rotate`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(rotate.status).toBe(200);
		const rotated = await rotate.json();
		expect(rotated.connection.bearerTokenFingerprint).toBeTruthy();
		expect(rotated.connection.bearerTokenEncrypted).toBeUndefined();
		expect(JSON.stringify(rotated)).not.toContain("scim-token-for-api-rotate");

		const disable = await app.request(`/v1/scim/${scimId}/disable`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(disable.status).toBe(200);
		expect((await disable.json()).connection.status).toBe("disabled");
	});

	it("replays SCIM diagnostic traces under scope", async () => {
		const app = await loadApp();
		const dryRun = await app.request(`/v1/scim/traces/${scimTraceId}/replay`, {
			method: "POST",
			headers: authHeaders,
		});
		expect(dryRun.status).toBe(200);
		expect(await dryRun.json()).toMatchObject({
			dryRun: true,
			idempotent: false,
			wouldChange: true,
		});

		const res = await app.request(`/v1/scim/traces/${scimTraceId}/replay`, {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ confirm: true }),
		});
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.trace.id).not.toBe(scimTraceId);
		expect(body.trace.stage).toMatch(/\.replay$/);

		const again = await app.request(
			`/v1/scim/traces/${scimTraceId}/replay`,
			{
				method: "POST",
				headers: authHeaders,
				body: JSON.stringify({ confirm: true }),
			},
		);
		expect(again.status).toBe(200);
		const repeated = await again.json();
		expect(repeated.idempotent).toBe(true);
		expect(repeated.trace.id).toBe(body.trace.id);

		const missing = await app.request("/v1/scim/traces/tr_missing/replay", {
			method: "POST",
			headers: authHeaders,
		});
		expect(missing.status).toBe(404);
	});

	it("rejects wrong project scope on rotate/disable/replay", async () => {
		const app = await loadApp();
		const wrong = {
			...authHeaders,
			"x-clearance-project-id": "proj_wrong_enterprise_ops",
		};

		const ssoRotate = await app.request(`/v1/sso/${ssoId}/rotate`, {
			method: "POST",
			headers: wrong,
		});
		expect(ssoRotate.status).toBe(403);

		const ssoDisable = await app.request(`/v1/sso/${ssoId}/disable`, {
			method: "POST",
			headers: wrong,
		});
		expect(ssoDisable.status).toBe(403);

		const scimRotate = await app.request(`/v1/scim/${scimId}/rotate`, {
			method: "POST",
			headers: wrong,
		});
		expect(scimRotate.status).toBe(403);

		const scimDisable = await app.request(`/v1/scim/${scimId}/disable`, {
			method: "POST",
			headers: wrong,
		});
		expect(scimDisable.status).toBe(403);

		const replay = await app.request(`/v1/scim/traces/${scimTraceId}/replay`, {
			method: "POST",
			headers: wrong,
		});
		expect(replay.status).toBe(403);
	});
});
