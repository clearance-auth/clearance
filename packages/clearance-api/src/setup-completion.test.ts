/**
 * Behavioral tests for safe SSO/SCIM setup capability completion:
 * reserve → provision (deterministic attempt ids) → commit | release+compensate.
 * Includes crash-after-runtime-insert recovery and replay denial.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dirs: string[] = [];
const OPERATOR = "test-operator-token-32chars!!";

/** Simulated runtime PK rows for durable recovery assertions */
const runtimeSso = new Map<string, { id: string; providerId: string }>();
const runtimeScim = new Map<string, { id: string; providerId: string; token: string }>();

function configureTestEnvironment(dataPath: string) {
	delete process.env.DATABASE_URL;
	process.env.CLEARANCE_DATA_PATH = dataPath;
	process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
	process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
	process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
	process.env.CLEARANCE_BASE_URL = "https://auth.test.example";
	process.env.NODE_ENV = "development";
}

function clearTestEnvironment() {
	delete process.env.CLEARANCE_DATA_PATH;
	delete process.env.CLEARANCE_SECRET;
	delete process.env.CLEARANCE_OPERATOR_TOKEN;
	delete process.env.DATABASE_URL;
	delete process.env.CLEARANCE_CORS_ORIGINS;
	delete process.env.CLEARANCE_BASE_URL;
	delete process.env.NODE_ENV;
}

const mocks = vi.hoisted(() => ({
	createSsoConnectionReal: vi.fn(),
	createScimConnectionReal: vi.fn(),
	deleteSsoProviderById: vi.fn(async () => undefined),
	deleteScimProviderById: vi.fn(async () => undefined),
}));

vi.mock("@clearance/management", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@clearance/management")>();
	return {
		...actual,
		createSsoConnectionReal: mocks.createSsoConnectionReal,
		createScimConnectionReal: mocks.createScimConnectionReal,
		deleteSsoProviderById: mocks.deleteSsoProviderById,
		deleteScimProviderById: mocks.deleteScimProviderById,
	};
});

// Transform the large server graph during test-file loading, outside an
// individual test's 5-second budget. CI runs several package suites in
// parallel, so the first per-test dynamic import can otherwise time out while
// Vite is still transforming dependencies. A timed-out import keeps running
// and the following test can join the same module initialization, reusing its
// store despite selecting a new data path.
const warmDirectory = mkdtempSync(join(tmpdir(), "clr-setup-warm-"));
configureTestEnvironment(join(warmDirectory, "data.json"));
try {
	await import("./server.js");
} finally {
	vi.resetModules();
	clearTestEnvironment();
	rmSync(warmDirectory, { recursive: true, force: true });
}

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	clearTestEnvironment();
	runtimeSso.clear();
	runtimeScim.clear();
	vi.resetModules();
	mocks.createSsoConnectionReal.mockReset();
	mocks.createScimConnectionReal.mockReset();
	mocks.deleteSsoProviderById.mockReset();
	mocks.deleteScimProviderById.mockReset();
	mocks.deleteSsoProviderById.mockImplementation(async (id: string) => {
		runtimeSso.delete(id);
	});
	mocks.deleteScimProviderById.mockImplementation(async (id: string) => {
		runtimeScim.delete(id);
	});
});

async function boot() {
	const dir = mkdtempSync(join(tmpdir(), "clr-setup-"));
	dirs.push(dir);
	configureTestEnvironment(join(dir, "data.json"));

	const { app, getStore } = await import("./server.js");
	const {
		createSetupLink,
		createOrganization,
		initProject,
		listEvents,
	} = await import("@clearance/management");

	const store = await getStore();
	initProject(store, { name: "Setup Completion", source: "api" });
	const org = createOrganization(store, { name: "Customer Co", source: "api" });
	await store.ready();

	return { app, store, org, createSetupLink, listEvents };
}

function ssoBody(token: string, organizationId: string, extra: Record<string, string> = {}) {
	return {
		token,
		organizationId,
		provider: "okta",
		protocol: "oidc",
		issuer: "https://dev-example.okta.com/oauth2/default",
		domain: "customer.example",
		clientId: "client-id",
		clientSecret: "client-secret-value",
		...extra,
	};
}

function deterministicIds(
	kind: "sso" | "scim",
	setupAttemptId: string,
): { connectionId: string; providerId: string } {
	const material = createHash("sha256")
		.update(`clearance:setup:v1:${kind}:${setupAttemptId}`, "utf8")
		.digest("hex");
	if (kind === "sso") {
		return {
			connectionId: `sso${material.slice(0, 24)}`,
			providerId: `clr-setup-sso-${material.slice(0, 28)}`,
		};
	}
	return {
		connectionId: `scim${material.slice(0, 24)}`,
		providerId: `clr-setup-scim-${material.slice(0, 28)}`,
	};
}

describe("setup capability completion safety", () => {
	beforeEach(() => {
		mocks.createSsoConnectionReal.mockImplementation(async (store, input) => {
			const ids = input.setupAttemptId
				? deterministicIds("sso", input.setupAttemptId)
				: {
						connectionId: `sso_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`,
						providerId: `gen-${Date.now()}`,
					};
			const existingMgmt = store.snapshot.identityConnections.find(
				(c: { id: string }) => c.id === ids.connectionId,
			);
			if (existingMgmt) {
				return { ...existingMgmt, hasClientSecret: true };
			}
			const existingRuntime = runtimeSso.get(ids.connectionId);
			if (!existingRuntime) {
				runtimeSso.set(ids.connectionId, {
					id: ids.connectionId,
					providerId: ids.providerId,
				});
			}
			const conn = {
				id: ids.connectionId,
				organizationId: input.organizationId,
				provider: input.provider ?? "okta",
				protocol: "oidc",
				status: "draft",
				domains: [input.domain ?? "customer.example"],
				issuer: input.issuer,
				hasClientSecret: true,
				clientSecretFingerprint: "fp_sso",
			};
			store.mutate((data: { identityConnections: unknown[] }) => {
				if (!data.identityConnections.some((c: { id: string }) => c.id === conn.id)) {
					data.identityConnections.push(conn);
				}
			});
			await store.ready();
			return conn;
		});
		mocks.createScimConnectionReal.mockImplementation(async (store, input) => {
			const ids = input.setupAttemptId
				? deterministicIds("scim", input.setupAttemptId)
				: {
						connectionId: `scim_${Date.now()}_${Math.random().toString(16).slice(2, 8)}`,
						providerId: `gen-scim-${Date.now()}`,
					};
			const existingMgmt = store.snapshot.directoryConnections.find(
				(c: { id: string }) => c.id === ids.connectionId,
			);
			if (existingMgmt) {
				const tokenOnce =
					runtimeScim.get(ids.connectionId)?.token ??
					`scimtok_once_${ids.connectionId}`;
				return {
					...existingMgmt,
					hasBearerToken: true,
					bearerTokenOnce: tokenOnce,
				};
			}
			const tokenOnce =
				runtimeScim.get(ids.connectionId)?.token ??
				`scimtok_once_${Math.random().toString(16).slice(2)}`;
			if (!runtimeScim.has(ids.connectionId)) {
				runtimeScim.set(ids.connectionId, {
					id: ids.connectionId,
					providerId: ids.providerId,
					token: tokenOnce,
				});
			}
			const persisted = {
				id: ids.connectionId,
				organizationId: input.organizationId,
				provider: input.provider ?? "okta",
				status: "draft",
				endpoint: "/api/auth/scim/v2",
				bearerTokenFingerprint: "fp_test",
				// Encrypted envelope stand-in — never the plaintext once-token
				bearerTokenEncrypted: `clr$v1$dev$iv$tag$ct_${ids.connectionId}`,
				deprovisioningPolicy: "disable" as const,
				createdAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
			};
			store.mutate((data: { directoryConnections: unknown[] }) => {
				if (
					!data.directoryConnections.some((c: { id: string }) => c.id === persisted.id)
				) {
					data.directoryConnections.push({ ...persisted });
				}
			});
			await store.ready();
			return {
				...persisted,
				hasBearerToken: true,
				bearerTokenOnce: tokenOnce,
			};
		});
	});

	it("rejects incomplete SAML configuration before reserving the capability", async () => {
		const { app, store, org, createSetupLink } = await boot();
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
			ttlMinutes: 30,
		});
		await store.ready();
		const response = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				token: link.token,
				organizationId: org.id,
				provider: "okta",
				protocol: "saml",
				issuer: "https://customer.okta.test",
			}),
		});
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({
			error: { code: "SETUP_INPUT" },
		});
		expect(mocks.createSsoConnectionReal).not.toHaveBeenCalled();
		const capability = store.snapshot.setupLinks.find(
			(item) => item.id === link.capabilityId,
		)!;
		expect(capability.useCount).toBe(0);
		expect(capability.reservationId).toBeUndefined();
	});

	it("invalid SSO provisioning does not consume token and creates no partial connection", async () => {
		const { app, store, org, createSetupLink } = await boot();
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
			ttlMinutes: 30,
		});
		await store.ready();

		mocks.createSsoConnectionReal.mockImplementation(async () => {
			throw Object.assign(new Error("discovery rejected"), {
				code: "SSO_DISCOVERY_URL_INVALID",
				status: 400,
			});
		});

		const res = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(ssoBody(link.token, org.id)),
		});
		expect(res.status).toBeGreaterThanOrEqual(400);
		const errBody = await res.json();
		expect(JSON.stringify(errBody)).not.toContain(link.token);

		const cap = store.snapshot.setupLinks.find((c) => c.id === link.capabilityId)!;
		expect(cap.useCount).toBe(0);
		expect(cap.redeemedAt).toBeFalsy();
		expect(cap.reservationId).toBeFalsy();
		expect(store.snapshot.identityConnections).toHaveLength(0);

		// Retry with same token can succeed
		mocks.createSsoConnectionReal.mockImplementation(async (s, input) => {
			const conn = {
				id: "sso_retry_ok",
				organizationId: input.organizationId,
				provider: "okta",
				protocol: "oidc",
				status: "draft",
				hasClientSecret: true,
			};
			s.mutate((data: { identityConnections: unknown[] }) => {
				data.identityConnections.push(conn);
			});
			return conn;
		});
		const retry = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(ssoBody(link.token, org.id)),
		});
		expect(retry.status).toBe(201);
		const retryBody = await retry.json();
		expect(retryBody.ok).toBe(true);
		expect(JSON.stringify(retryBody)).not.toContain(link.token);
		expect(store.snapshot.identityConnections).toHaveLength(1);
		const after = store.snapshot.setupLinks.find((c) => c.id === link.capabilityId)!;
		expect(after.useCount).toBe(1);
		expect(after.redeemedAt).toBeTruthy();
	});

	it("invalid SCIM provisioning does not consume token; retry succeeds; no partial connection", async () => {
		const { app, store, org, createSetupLink } = await boot();
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "scim",
		});
		await store.ready();

		mocks.createScimConnectionReal.mockImplementation(async () => {
			throw new Error("runtime insert failed");
		});

		const fail = await app.request("/setup/scim", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				token: link.token,
				organizationId: org.id,
				provider: "okta",
			}),
		});
		expect(fail.status).toBeGreaterThanOrEqual(400);
		expect(store.snapshot.directoryConnections).toHaveLength(0);
		const cap = store.snapshot.setupLinks.find((c) => c.id === link.capabilityId)!;
		expect(cap.useCount).toBe(0);
		expect(cap.redeemedAt).toBeFalsy();
		expect(mocks.deleteScimProviderById).not.toHaveBeenCalled();

		// Restore happy path mock for retry
		mocks.createScimConnectionReal.mockImplementation(async (s, input) => {
			const tokenOnce = "scimtok_retry_once_value";
			const persisted = {
				id: "scim_retry_ok",
				organizationId: input.organizationId,
				provider: input.provider,
				status: "draft",
				endpoint: "/api/auth/scim/v2",
				bearerTokenFingerprint: "fp_retry",
				deprovisioningPolicy: "disable" as const,
				createdAt: new Date().toISOString(),
				updatedAt: new Date().toISOString(),
			};
			s.mutate((data: { directoryConnections: unknown[] }) => {
				data.directoryConnections.push({ ...persisted });
			});
			return { ...persisted, hasBearerToken: true, bearerTokenOnce: tokenOnce };
		});

		const ok = await app.request("/setup/scim", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				token: link.token,
				organizationId: org.id,
				provider: "okta",
			}),
		});
		expect(ok.status).toBe(201);
		const body = await ok.json();
		expect(body.scimHandoff?.bearerToken).toBe("scimtok_retry_once_value");
		expect(body.scimHandoff?.endpoint).toBe("https://auth.test.example/api/auth/scim/v2");
		expect(body.scimHandoff?.retrieveAgain).toBe(false);
		expect(body.scimHandoff?.warning).toMatch(/cannot show the token again/i);
		expect(JSON.stringify(body)).not.toContain(link.token);
		expect(store.snapshot.directoryConnections).toHaveLength(1);
		// Plaintext handoff token is response-only — not in store snapshot
		expect(JSON.stringify(store.snapshot)).not.toContain("scimtok_retry_once_value");
	});

	it("compensates only this request's returned connection and preserves an unrelated connection", async () => {
		const { app, store, org, createSetupLink } = await boot();
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
		});
		await store.ready();

		mocks.createSsoConnectionReal.mockImplementation(async (s, input) => {
			const target = {
				id: "sso_this_request",
				organizationId: input.organizationId,
				provider: "okta",
				protocol: "oidc",
				status: "draft",
				hasClientSecret: true,
			};
			const unrelated = {
				...target,
				id: "sso_unrelated_concurrent",
				provider: "entra",
			};
			s.mutate((data: {
				identityConnections: unknown[];
				setupLinks: Array<{ reservationExpiresAt?: string }>;
			}) => {
				data.identityConnections.push(target, unrelated);
				// Force the later commit step to fail after provisioning returned an id.
				data.setupLinks[0]!.reservationExpiresAt = new Date(0).toISOString();
			});
			return target;
		});

		const response = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(ssoBody(link.token, org.id)),
		});
		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(store.snapshot.identityConnections.map((connection) => connection.id)).toEqual([
			"sso_unrelated_concurrent",
		]);
		expect(mocks.deleteSsoProviderById).toHaveBeenCalledTimes(1);
		expect(mocks.deleteSsoProviderById).toHaveBeenCalledWith("sso_this_request");
		expect(mocks.deleteSsoProviderById).not.toHaveBeenCalledWith(
			"sso_unrelated_concurrent",
		);
		const cap = store.snapshot.setupLinks.find((candidate) => candidate.id === link.capabilityId)!;
		expect(cap.useCount).toBe(0);
		expect(cap.redeemedAt).toBeFalsy();
		expect(cap.reservationId).toBeFalsy();
	});

	it("two concurrent completions produce one success, one in-progress/replay, one connection", async () => {
		const { app, store, org, createSetupLink } = await boot();
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
		});
		await store.ready();

		let releaseCreate: (() => void) | undefined;
		const gate = new Promise<void>((resolve) => {
			releaseCreate = resolve;
		});
		let createCalls = 0;
		mocks.createSsoConnectionReal.mockImplementation(async (s, input) => {
			createCalls += 1;
			const conn = {
				id: `sso_race_${createCalls}`,
				organizationId: input.organizationId,
				provider: "okta",
				protocol: "oidc",
				status: "draft",
				hasClientSecret: true,
			};
			s.mutate((data: { identityConnections: unknown[] }) => {
				data.identityConnections.push(conn);
			});
			// Keep the first request in provisioning after its connection is visible.
			// A losing reserve must never compensate the winner's connection.
			await gate;
			return conn;
		});

		const req = () =>
			app.request("/setup/sso", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(ssoBody(link.token, org.id)),
			});

		const p1 = req();
		// Allow first request to reserve and enter provisioning
		await vi.waitFor(() => expect(createCalls).toBe(1));
		const p2 = req();
		// Second should fail at reserve while first is in progress
		const r2 = await p2;
		expect(r2.status).toBeGreaterThanOrEqual(400);
		const r2Body = await r2.json();
		expect(r2Body.error?.code).toMatch(/IN_PROGRESS|REPLAY|RESERVATION/i);
		expect(JSON.stringify(r2Body)).not.toContain(link.token);

		releaseCreate?.();
		const r1 = await p1;
		expect(r1.status).toBe(201);
		const r1Body = await r1.json();
		expect(JSON.stringify(r1Body)).not.toContain(link.token);

		expect(store.snapshot.identityConnections).toHaveLength(1);
		const cap = store.snapshot.setupLinks.find((c) => c.id === link.capabilityId)!;
		expect(cap.useCount).toBe(1);
		expect(cap.redeemedAt).toBeTruthy();
		expect(createCalls).toBe(1);
	});

	it("successful completion consumes token and replay fails; no raw token in audits/snapshot", async () => {
		const { app, store, org, createSetupLink, listEvents } = await boot();
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
		});
		await store.ready();

		const ok = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(ssoBody(link.token, org.id)),
		});
		expect(ok.status).toBe(201);
		const okBody = await ok.json();
		expect(okBody.ok).toBe(true);
		expect(okBody.kind).toBe("sso");

		const replay = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(ssoBody(link.token, org.id)),
		});
		expect(replay.status).toBeGreaterThanOrEqual(400);
		const replayBody = await replay.json();
		expect(replayBody.error?.code).toMatch(/REPLAY|IN_PROGRESS|NOT_FOUND/i);

		expect(store.snapshot.identityConnections).toHaveLength(1);
		const snap = JSON.stringify(store.snapshot);
		expect(snap).not.toContain(link.token);
		const events = JSON.stringify(listEvents(store, { limit: 200 }));
		expect(events).not.toContain(link.token);
		expect(JSON.stringify(okBody)).not.toContain(link.token);
		expect(JSON.stringify(replayBody)).not.toContain(link.token);
	});

	it("SCIM success returns one-time handoff with absolute endpoint only in response body", async () => {
		const { app, store, org, createSetupLink, listEvents } = await boot();
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "scim",
		});
		await store.ready();

		const res = await app.request("/setup/scim", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				token: link.token,
				organizationId: org.id,
				provider: "entra",
			}),
		});
		expect(res.status).toBe(201);
		const body = await res.json();
		expect(body.scimHandoff.bearerToken).toBeTruthy();
		expect(body.scimHandoff.endpoint).toMatch(/^https:\/\/auth\.test\.example\/api\/auth\/scim\/v2$/);
		expect(body.connection.endpoint).toBe(body.scimHandoff.endpoint);
		// handoff secret not in durable state or audits
		expect(JSON.stringify(store.snapshot)).not.toContain(body.scimHandoff.bearerToken);
		expect(JSON.stringify(listEvents(store, { limit: 200 }))).not.toContain(
			body.scimHandoff.bearerToken,
		);
		expect(JSON.stringify(store.snapshot)).not.toContain(link.token);
	});

	it("crash after runtime insert: after lease expiry same capability recovers one row, commits, replay fails", async () => {
		const { app, store, org, createSetupLink, listEvents } = await boot();
		const { deriveSetupReservationId, deriveSetupConnectionIds, reserveSetupLink } =
			await import("@clearance/management");
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
		});
		await store.ready();

		const digest = createHash("sha256").update(link.token, "utf8").digest("hex");
		const attemptId = deriveSetupReservationId(digest);
		const ids = deriveSetupConnectionIds("sso", attemptId);

		// Simulate death after runtime insert + management row, before capability commit.
		// Leave an active reservation that we then expire.
		await reserveSetupLink(store, {
			token: link.token,
			kind: "sso",
			organizationId: org.id,
			reservationTtlMs: 1,
		});
		runtimeSso.set(ids.connectionId, {
			id: ids.connectionId,
			providerId: ids.providerId,
		});
		store.mutate((data: {
			identityConnections: unknown[];
			setupLinks: Array<{
				id: string;
				reservationExpiresAt?: string;
				reservationId?: string;
			}>;
		}) => {
			data.identityConnections.push({
				id: ids.connectionId,
				organizationId: org.id,
				provider: "okta",
				protocol: "oidc",
				status: "draft",
				domains: ["customer.example"],
				issuer: "https://dev-example.okta.com/oauth2/default",
				hasClientSecret: true,
				clientSecretFingerprint: "fp_orphan",
			});
			const cap = data.setupLinks.find((c) => c.id === link.capabilityId)!;
			cap.reservationExpiresAt = new Date(0).toISOString();
		});
		await store.ready();

		const retry = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(ssoBody(link.token, org.id)),
		});
		expect(retry.status).toBe(201);
		const body = await retry.json();
		expect(body.connection.id).toBe(ids.connectionId);
		expect(store.snapshot.identityConnections).toHaveLength(1);
		expect(runtimeSso.size).toBe(1);
		expect(store.snapshot.identityConnections[0]!.id).toBe(ids.connectionId);

		const cap = store.snapshot.setupLinks.find((c) => c.id === link.capabilityId)!;
		expect(cap.useCount).toBe(1);
		expect(cap.redeemedAt).toBeTruthy();
		expect(cap.reservationId).toBeFalsy();

		const replay = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(ssoBody(link.token, org.id)),
		});
		expect(replay.status).toBeGreaterThanOrEqual(400);
		const replayBody = await replay.json();
		expect(replayBody.error?.code).toMatch(/REPLAY|IN_PROGRESS|NOT_FOUND/i);
		expect(store.snapshot.identityConnections).toHaveLength(1);
		expect(runtimeSso.size).toBe(1);
		expect(JSON.stringify(store.snapshot)).not.toContain(link.token);
		expect(JSON.stringify(listEvents(store, { limit: 200 }))).not.toContain(link.token);
		expect(JSON.stringify(body)).not.toContain(link.token);
	});

	it("passes stable setupAttemptId so provision reuses deterministic connection id", async () => {
		const { app, store, org, createSetupLink } = await boot();
		const { deriveSetupReservationId, deriveSetupConnectionIds } =
			await import("@clearance/management");
		const link = createSetupLink(store, {
			organizationId: org.id,
			kind: "sso",
		});
		await store.ready();
		const digest = createHash("sha256").update(link.token, "utf8").digest("hex");
		const expectedAttempt = deriveSetupReservationId(digest);
		const expected = deriveSetupConnectionIds("sso", expectedAttempt);

		const res = await app.request("/setup/sso", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(ssoBody(link.token, org.id)),
		});
		expect(res.status).toBe(201);
		const body = await res.json();
		expect(body.connection.id).toBe(expected.connectionId);
		expect(mocks.createSsoConnectionReal).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({
				setupAttemptId: expectedAttempt,
				organizationId: org.id,
			}),
		);
	});
});
