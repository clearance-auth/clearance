import { afterEach, describe, expect, it, vi } from "vitest";
import { createVaultClient } from "./client";
import { configureVaultEndpoints } from "./origins";
import { VaultApiError } from "./transport";

const OPERATION_ID = "018f0f51-74a3-7eab-8f8b-8a4db4f3f6c1";

function json(value: unknown, status = 200): Response {
	return new Response(JSON.stringify(value), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}

function ssoConnection(overrides: Record<string, unknown> = {}) {
	return {
		id: "sso_1",
		organizationId: "org_1",
		protocol: "oidc",
		provider: "okta",
		status: "active",
		domains: ["example.test"],
		issuer: "https://issuer.example.test",
		clientId: "client_1",
		hasClientSecret: true,
		attributeMapping: { email: "email" },
		createdAt: "2026-07-24T00:00:00.000Z",
		updatedAt: "2026-07-24T00:00:00.000Z",
		...overrides,
	};
}

function scimConnection(overrides: Record<string, unknown> = {}) {
	return {
		id: "scim_1",
		organizationId: "org_1",
		provider: "okta",
		status: "active",
		endpoint: "https://example.test/scim/v2",
		hasBearerToken: true,
		deprovisioningPolicy: "disable",
		createdAt: "2026-07-24T00:00:00.000Z",
		updatedAt: "2026-07-24T00:00:00.000Z",
		...overrides,
	};
}

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("Vault browser client", () => {
	it("models cookie authentication and refreshes the authoritative session", async () => {
		const requests: string[] = [];
		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const url = String(input);
			requests.push(url);
			if (url.endsWith("/sign-in/email")) {
				return json({
					redirect: false,
					token: "session-token-not-returned",
					user: { id: "user_1", email: "owner@example.test" },
				});
			}
			if (url.endsWith("/get-session")) {
				return json({
					user: { id: "user_1", email: "owner@example.test" },
					session: {
						id: "session_1",
						userId: "user_1",
						ipAddress: "",
						userAgent: "",
					},
				});
			}
			throw new Error(`Unexpected request: ${url}`);
		});
		const client = createVaultClient({
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});

		await expect(
			client.auth.signIn({
				email: "owner@example.test",
				password: "correct horse battery staple",
			}),
		).resolves.toEqual({
			kind: "authenticated",
			session: {
				user: { id: "user_1", email: "owner@example.test" },
				session: {
					id: "session_1",
					userId: "user_1",
					ipAddress: null,
					userAgent: null,
				},
			},
		});
		expect(requests.map((url) => new URL(url).pathname)).toEqual([
			"/api/auth/sign-in/email",
			"/api/auth/get-session",
		]);
	});

	it("models two-factor challenges and completes backup-code sign-in", async () => {
		const requests: string[] = [];
		vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
			const url = String(input);
			requests.push(url);
			if (url.endsWith("/sign-in/email")) {
				return json({
					twoFactorRedirect: true,
					twoFactorMethods: ["totp", "otp"],
				});
			}
			if (url.endsWith("/two-factor/verify-backup-code")) {
				return json({
					user: { id: "user_1", email: "owner@example.test" },
					session: { id: "session_1", userId: "user_1" },
				});
			}
			if (url.endsWith("/get-session")) {
				return json({
					user: { id: "user_1", email: "owner@example.test" },
					session: { id: "session_1", userId: "user_1" },
				});
			}
			throw new Error(`Unexpected request: ${url}`);
		});
		const client = createVaultClient({
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});

		await expect(
			client.auth.signIn({
				email: "owner@example.test",
				password: "correct horse battery staple",
			}),
		).resolves.toEqual({
			kind: "two_factor_required",
			methods: ["totp", "otp", "backup_code"],
		});
		await expect(
			client.auth.completeTwoFactor({
				method: "backup_code",
				code: "recovery-code",
			}),
		).resolves.toMatchObject({
			user: { id: "user_1" },
			session: { id: "session_1" },
		});
		expect(requests.some((url) => url.endsWith("/two-factor/verify-backup-code"))).toBe(
			true,
		);
	});

	it("builds encoded tenant URLs without an authorization header or retries", async () => {
		const requests: Array<{ url: string; init?: RequestInit }> = [];
		const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			requests.push({ url: String(input), init });
			return json({
				serviceAccount: {
					organizationId: "org/a b",
					serviceAccountId: "svc?#",
					name: "Build",
					status: "active",
				},
				assignments: [],
			});
		});
		vi.stubGlobal("fetch", fetcher);
		const client = createVaultClient({
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});

		await client.tenant.inspectServiceAccount("org/a b", "svc?#");

		expect(fetcher).toHaveBeenCalledTimes(1);
		expect(requests[0]?.url).toBe(
			"http://localhost:3000/api/auth/tenant/v1/organizations/org%2Fa%20b/service-accounts/svc%3F%23",
		);
		const headers = new Headers(requests[0]?.init?.headers);
		expect(headers.get("authorization")).toBeNull();
		expect(headers.get("accept")).toBe("application/json");
		expect(requests[0]?.init).toMatchObject({
			credentials: "same-origin",
			cache: "no-store",
			redirect: "error",
			method: "GET",
		});
	});

	it("returns a committed credential secret only in the immediate result", async () => {
		const localStorageWrite = vi.spyOn(Storage.prototype, "setItem");
		const fetcher = vi.fn(async () =>
			json({
				credential: {
					organizationId: "org_1",
					serviceAccountId: "svc_1",
					credentialId: "cred_1",
					credentialPrefix: "clr",
					credentialFingerprint: "fingerprint",
					expiresAt: null,
					version: 1,
					internalSecret: "must-not-escape",
				},
				secret: "clearance_secret_once",
				previousRevision: "1",
				revision: "2",
			}),
		);
		vi.stubGlobal("fetch", fetcher);
		const client = createVaultClient({
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});

		const result = await client.tenant.createCredential(
			"org_1",
			"svc_1",
			{ dryRun: false, operationId: OPERATION_ID },
		);

		expect(result.secret).toBe("clearance_secret_once");
		expect(result.credential).toEqual({
			organizationId: "org_1",
			serviceAccountId: "svc_1",
			credentialId: "cred_1",
			credentialPrefix: "clr",
			credentialFingerprint: "fingerprint",
			expiresAt: null,
			version: 1,
		});
		expect(localStorageWrite).not.toHaveBeenCalled();
		expect(fetcher).toHaveBeenCalledTimes(1);
		localStorageWrite.mockRestore();
	});

	it("rejects non-JSON success and preserves structured JSON errors", async () => {
		vi.stubGlobal(
			"fetch",
			async () =>
				new Response("ok", {
					status: 200,
					headers: { "content-type": "text/plain" },
				}),
		);
		const invalidClient = createVaultClient({
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});
		await expect(invalidClient.auth.getSession()).rejects.toMatchObject({
			name: "VaultApiError",
			message: "Vault expected a JSON response",
		});

		vi.stubGlobal(
			"fetch",
			async () =>
				new Response(
					JSON.stringify({
						error: { code: "TENANT_DENIED", message: "Access denied" },
					}),
					{
						status: 403,
						headers: {
							"content-type": "application/problem+json",
							"x-request-id": "req_1",
						},
					},
				),
		);
		const errorClient = createVaultClient({
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});
		const failure = await errorClient.auth.getSession().catch((error) => error);
		expect(failure).toBeInstanceOf(VaultApiError);
		expect(failure).toMatchObject({
			status: 403,
			code: "TENANT_DENIED",
			message: "Request failed with status 403",
			requestId: "req_1",
		});
	});

	it("creates organizations with the exact public body and validates name and slug", async () => {
		const requests: Array<{ path: string; method: string; body?: unknown }> = [];
		vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = new URL(String(input));
			requests.push({
				path: url.pathname,
				method: init?.method ?? "GET",
				...(init?.body ? { body: JSON.parse(String(init.body)) } : {}),
			});
			return json({ id: "org_1", name: "Acme", slug: "acme" });
		});
		const client = createVaultClient({
			authBaseURL: "http://localhost:3000/api/auth",
			development: true,
		});

		await expect(
			client.auth.createOrganization({ name: "Acme", slug: "acme" }),
		).resolves.toEqual({ id: "org_1", name: "Acme", slug: "acme" });
		expect(requests).toEqual([
			{
				path: "/api/auth/organization/create",
				method: "POST",
				body: { name: "Acme", slug: "acme" },
			},
		]);

		for (const input of [
			{ name: " Acme", slug: "acme" },
			{ name: "Acme\n", slug: "acme" },
			{ name: "\u0000Acme", slug: "acme" },
			{ name: "A".repeat(257), slug: "acme" },
			{ name: "Acme", slug: "Acme" },
			{ name: "Acme", slug: "acme--team" },
			{ name: "Acme", slug: "-acme" },
			{ name: "Acme", slug: "acme-" },
			{ name: "Acme", slug: "a".repeat(49) },
		]) {
			await expect(client.auth.createOrganization(input)).rejects.toThrow(
				/organization (name|slug) is invalid/,
			);
		}
		expect(requests).toHaveLength(1);
	});

	it("requires safe endpoint origins", () => {
		expect(() =>
			configureVaultEndpoints({
				authBaseURL: "http://example.com/api/auth",
			}),
		).toThrow("must use HTTPS");
		expect(() =>
			configureVaultEndpoints({
				authBaseURL: "https://user:secret@example.com/api/auth",
			}),
		).toThrow("must not contain URL credentials");
		expect(() =>
			configureVaultEndpoints({
				authBaseURL: "https://example.com/api/auth?token=secret",
			}),
		).toThrow("must not contain a query or fragment");
		expect(() =>
			configureVaultEndpoints({
				authBaseURL: "https://api.example.com/api/auth",
			}),
		).toThrow("must be same-origin");
		expect(
			configureVaultEndpoints({
				authBaseURL: "http://localhost:3000/api/auth",
				development: true,
			}),
		).toEqual({
			authBaseURL: "http://localhost:3000/api/auth",
			tenantBaseURL: "http://localhost:3000/api/auth/tenant",
		});
	});

	it("uses only organization-scoped tenant enterprise routes with exact mutation bodies", async () => {
		const requests: Array<{ path: string; method: string; body?: unknown }> = [];
		vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = new URL(String(input));
			requests.push({
				path: `${url.pathname}${url.search}`,
				method: init?.method ?? "GET",
				...(init?.body ? { body: JSON.parse(String(init.body)) } : {}),
			});
			if (url.pathname.endsWith("/audit")) {
				return json({ events: [], nextCursor: null });
			}
			if (url.pathname.endsWith("/enterprise/sso") && init?.method === "GET") {
				return json({ connections: [ssoConnection()] });
			}
			if (url.pathname.endsWith("/enterprise/sso/sso_1")) {
				return json({ connection: ssoConnection() });
			}
			if (url.pathname.endsWith("/enterprise/sso") && init?.method === "POST") {
				if (JSON.parse(String(init.body)).protocol === "saml") {
					return json({
						preview: true,
						proposed: {
							organizationId: "org_1", protocol: "saml", provider: "okta",
							issuer: "https://issuer.example.test", domain: "example.test", audience: null,
							samlEntryPoint: "https://issuer.example.test/saml", hasSamlCertificate: true,
						},
						wouldChange: true,
					});
				}
				return json({ connection: ssoConnection({ ignoredSecret: "never-exposed" }) });
			}
			if (url.pathname.endsWith("/enterprise/sso/sso_1/test")) {
				return json({ connection: ssoConnection(), pass: true, mode: "simulation", liveCertified: false });
			}
			if (url.pathname.endsWith("/enterprise/sso/sso_1/disable")) {
				return json({ connection: ssoConnection({ status: "disabled" }), idempotent: false, runtimeRemoved: true });
			}
			if (url.pathname.endsWith("/enterprise/sso/sso_1/replace-secret")) {
				return json(ssoConnection());
			}
			if (url.pathname.endsWith("/enterprise/scim") && init?.method === "GET") {
				return json({ connections: [scimConnection()] });
			}
			if (url.pathname.endsWith("/enterprise/scim/scim_1")) {
				return json({ connection: scimConnection() });
			}
			if (url.pathname.endsWith("/enterprise/scim") && init?.method === "POST") {
				return json({ connection: scimConnection(), bearerTokenOnce: "scim_once" });
			}
			if (url.pathname.endsWith("/enterprise/scim/scim_1/test")) {
				return json({ connection: scimConnection(), pass: true, mode: "simulation", liveCertified: false });
			}
			if (url.pathname.endsWith("/enterprise/scim/scim_1/disable")) {
				return json({ connection: scimConnection({ status: "disabled" }), idempotent: false, runtimeRemoved: true });
			}
			if (url.pathname.endsWith("/enterprise/scim/scim_1/rotate")) {
				return json({ connection: scimConnection(), replayed: false, bearerTokenOnce: "rotated_once" });
			}
			throw new Error(`Unexpected request: ${url}`);
		});
		const client = createVaultClient({ authBaseURL: "http://localhost:3000/api/auth", development: true });

		await client.tenant.listAudit("org/1", { cursor: "next/1", limit: 10, action: "sso.test" });
		await client.tenant.listSso("org_1");
		await client.tenant.inspectSso("org_1", "sso_1");
		const createdSso = await client.tenant.createSso("org_1", {
			protocol: "oidc", provider: "okta", issuer: "https://issuer.example.test", domain: "example.test",
			clientId: "client_1", clientSecret: "secret", dryRun: false, confirm: true,
		});
		const samlPreview = await client.tenant.createSso("org_1", {
			protocol: "saml", provider: "okta", issuer: "https://issuer.example.test", domain: "example.test",
			samlEntryPoint: "https://issuer.example.test/saml",
			dryRun: true, confirm: false,
		});
		const testedSso = await client.tenant.testSso("org_1", "sso_1", { dryRun: false, confirm: true });
		await client.tenant.disableSso("org_1", "sso_1", { dryRun: false, confirm: true });
		await client.tenant.replaceSsoSecret("org_1", "sso_1", { newClientSecret: "replacement", operationId: OPERATION_ID, dryRun: false, confirm: true });
		await client.tenant.listScim("org_1");
		await client.tenant.inspectScim("org_1", "scim_1");
		await client.tenant.createScim("org_1", { provider: "okta", operationId: OPERATION_ID, dryRun: false, confirm: true });
		const testedScim = await client.tenant.testScim("org_1", "scim_1", { dryRun: false, confirm: true });
		await client.tenant.disableScim("org_1", "scim_1", { dryRun: false, confirm: true });
		await client.tenant.rotateScim("org_1", "scim_1", { operationId: OPERATION_ID, dryRun: false, confirm: true });

		expect(requests).toContainEqual({
			path: "/api/auth/tenant/v1/organizations/org%2F1/audit?cursor=next%2F1&limit=10&action=sso.test",
			method: "GET",
		});
		expect(requests).toContainEqual({
			path: "/api/auth/tenant/v1/organizations/org_1/enterprise/sso",
			method: "POST",
			body: {
				protocol: "saml", provider: "okta", issuer: "https://issuer.example.test", domain: "example.test",
				samlEntryPoint: "https://issuer.example.test/saml", dryRun: true, confirm: false,
			},
		});
		expect(requests).toContainEqual({
			path: "/api/auth/tenant/v1/organizations/org_1/enterprise/sso",
			method: "POST",
			body: {
				protocol: "oidc", provider: "okta", issuer: "https://issuer.example.test", domain: "example.test",
				clientId: "client_1", clientSecret: "secret", dryRun: false, confirm: true,
			},
		});
		expect(requests).toContainEqual({
			path: "/api/auth/tenant/v1/organizations/org_1/enterprise/sso/sso_1/replace-secret",
			method: "POST",
			body: { newClientSecret: "replacement", operationId: OPERATION_ID, dryRun: false, confirm: true },
		});
		expect(requests).toContainEqual({
			path: "/api/auth/tenant/v1/organizations/org_1/enterprise/scim",
			method: "POST",
			body: { provider: "okta", operationId: OPERATION_ID, dryRun: false, confirm: true },
		});
		expect(requests).toContainEqual({
			path: "/api/auth/tenant/v1/organizations/org_1/enterprise/scim/scim_1/rotate",
			method: "POST",
			body: { dryRun: false, confirm: true, operationId: OPERATION_ID },
		});
		expect(requests.map((request) => request.path)).not.toContain("/api/auth/sso/providers");
		expect(createdSso).not.toHaveProperty("ignoredSecret");
		expect(samlPreview).toMatchObject({ preview: true, proposed: { protocol: "saml", hasSamlCertificate: true } });
		expect(testedSso).toMatchObject({ mode: "simulation", liveCertified: false });
		expect(testedScim).toMatchObject({ mode: "simulation", liveCertified: false });
	});

	it("uses canonical operation IDs for live secret mutations and accepts secretless rotation replays", async () => {
		const bodies: unknown[] = [];
		let requests = 0;
		vi.stubGlobal("fetch", async (_input: RequestInfo | URL, init?: RequestInit) => {
			bodies.push(JSON.parse(String(init?.body)));
			requests += 1;
			return json(requests === 1
				? { connection: scimConnection(), replayed: false, bearerTokenOnce: "once" }
				: { connection: scimConnection(), replayed: true });
		});
		const client = createVaultClient({ authBaseURL: "http://localhost:3000/api/auth", development: true });
		await expect(client.tenant.rotateScim("org_1", "scim_1", { operationId: OPERATION_ID, dryRun: false, confirm: true }))
			.resolves.toEqual({ connection: scimConnection(), replayed: false, bearerTokenOnce: "once" });
		await expect(client.tenant.rotateScim("org_1", "scim_1", { operationId: OPERATION_ID, dryRun: false, confirm: true }))
			.resolves.toEqual({ connection: scimConnection(), replayed: true });
		expect(bodies).toEqual([
			{ dryRun: false, confirm: true, operationId: OPERATION_ID },
			{ dryRun: false, confirm: true, operationId: OPERATION_ID },
		]);
		await expect(client.tenant.rotateScim("org_1", "scim_1", { operationId: "not-a-uuid", dryRun: false, confirm: true }))
			.rejects.toThrow("operationId must be a canonical UUID");
		await expect(client.tenant.replaceSsoSecret("org_1", "sso_1", { newClientSecret: "replacement", operationId: "not-a-uuid", dryRun: false, confirm: true }))
			.rejects.toThrow("operationId must be a canonical UUID");
	});

	it("requires canonical operation IDs for live credential creation and rotation", async () => {
		const bodies: unknown[] = [];
		vi.stubGlobal("fetch", async (_input: RequestInfo | URL, init?: RequestInit) => {
			bodies.push(JSON.parse(String(init?.body)));
			return json({
				credential: {
					organizationId: "org_1", serviceAccountId: "svc_1", credentialId: "cred_1",
					credentialPrefix: "clr", credentialFingerprint: "fingerprint", expiresAt: null, version: 1,
				},
				secret: "once", previousRevision: "1", revision: "2",
			});
		});
		const client = createVaultClient({ authBaseURL: "http://localhost:3000/api/auth", development: true });
		await client.tenant.createCredential("org_1", "svc_1", { dryRun: false, operationId: OPERATION_ID });
		await client.tenant.rotateCredential("org_1", "svc_1", "cred_1", { dryRun: false, confirm: true, operationId: OPERATION_ID });
		expect(bodies).toEqual([
			{ dryRun: false, operationId: OPERATION_ID },
			{ dryRun: false, confirm: true, operationId: OPERATION_ID },
		]);
		await expect(client.tenant.createCredential("org_1", "svc_1", { dryRun: false, operationId: "not-a-uuid" }))
			.rejects.toThrow("operationId must be a canonical UUID");
		await expect(client.tenant.rotateCredential("org_1", "svc_1", "cred_1", { dryRun: false, confirm: true, operationId: "not-a-uuid" }))
			.rejects.toThrow("operationId must be a canonical UUID");
	});

	it("rejects legacy and unknown enterprise test result fields while preserving group lifecycle evidence", async () => {
		let request = 0;
		vi.stubGlobal("fetch", async () => {
			request += 1;
			if (request === 1) return json({ connection: ssoConnection(), pass: true, mode: "simulation", certifiedExternalTenant: false });
			return json({
				connection: scimConnection(), pass: true, mode: "live", liveCertified: true,
				scenario: "group-lifecycle",
				groupLifecycle: {
					group: { id: "group_1", status: "deleted" },
					counts: { usersCreated: 2, membersCreated: 2, membersAfterPatch: 1 },
				},
			});
		});
		const client = createVaultClient({ authBaseURL: "http://localhost:3000/api/auth", development: true });
		await expect(client.tenant.testSso("org_1", "sso_1", { dryRun: false, confirm: true }))
			.rejects.toThrow("invalid SSO test response");
		await expect(client.tenant.testScim("org_1", "scim_1", { dryRun: false, confirm: true }))
			.resolves.toMatchObject({ liveCertified: true, scenario: "group-lifecycle", groupLifecycle: { group: { status: "deleted" } } });
	});

	it("redacts closed enterprise results, labels simulations, and returns SCIM tokens only from live mutations", async () => {
		const localStorageWrite = vi.spyOn(Storage.prototype, "setItem");
		let request = 0;
		vi.stubGlobal("fetch", async () => {
			request += 1;
			if (request === 1) {
				return json({
					events: [{
						id: "audit_1", correlationId: "req_1", action: "scim.rotate", outcome: "success", source: "scim",
						message: "SCIM credential rotated", createdAt: "2026-07-24T00:00:00.000Z",
						metadata: { bearerTokenOnce: "hidden" }, actor: "hidden",
					}],
					nextCursor: null,
				});
			}
			if (request === 2) {
				return json({ preview: true, proposed: { organizationId: "org_1", provider: "okta", endpoint: null, bearerTokenGenerated: false, bearerTokenOnce: "forbidden" }, wouldChange: true, bearerTokenOnce: "forbidden" });
			}
			return json({ connection: scimConnection({ bearerToken: "hidden" }), bearerTokenOnce: "visible_once", serverSecret: "hidden" });
		});
		const client = createVaultClient({ authBaseURL: "http://localhost:3000/api/auth", development: true });
		const audit = await client.tenant.listAudit("org_1");
		await expect(client.tenant.createScim("org_1", { provider: "okta", dryRun: true, confirm: false })).rejects.toThrow("SCIM secret in a preview");
		const live = await client.tenant.createScim("org_1", { provider: "okta", operationId: OPERATION_ID, dryRun: false, confirm: true });
		expect(audit).toEqual({ events: [{ id: "audit_1", correlationId: "req_1", action: "scim.rotate", outcome: "success", source: "scim", message: "SCIM credential rotated", createdAt: "2026-07-24T00:00:00.000Z" }], nextCursor: null });
		expect(live).toEqual({ connection: scimConnection(), bearerTokenOnce: "visible_once" });
		expect(JSON.stringify(live)).not.toContain("hidden");
		expect(localStorageWrite).not.toHaveBeenCalled();
		localStorageWrite.mockRestore();
	});

	it("projects readiness into ready, stale, not-run, and blocked states", async () => {
		const reports = [
			{ state: "current", overall: "ready" },
			{ state: "stale", overall: "ready" },
			{ state: "not_run", overall: "blocked" },
			{ state: "current", overall: "attention" },
		];
		vi.stubGlobal("fetch", async () => {
			const report = reports.shift()!;
			return json({ report: {
				...report, generatedAt: "2026-07-24T00:00:00.000Z",
				conformance: { mode: "simulation", liveCertified: false, note: "simulation only" },
				checks: [{ id: "sso.test", name: "SSO", status: "warn", detail: "simulated", simulation: true, secret: "hidden" }],
				remainingCustomerActions: ["Run live tests"], signature: "ignored",
			} });
		});
		const client = createVaultClient({ authBaseURL: "http://localhost:3000/api/auth", development: true });
		await expect(client.tenant.getReadiness("org_1")).resolves.toMatchObject({ state: "ready", conformance: { mode: "simulation" }, checks: [{ simulation: true }] });
		await expect(client.tenant.getReadiness("org_1")).resolves.toMatchObject({ state: "stale" });
		await expect(client.tenant.getReadiness("org_1")).resolves.toMatchObject({ state: "not_run" });
		await expect(client.tenant.getReadiness("org_1")).resolves.toMatchObject({ state: "blocked" });
	});
});
