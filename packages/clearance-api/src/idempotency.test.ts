/**
 * Idempotency-Key API behavior (FOLLOW.md P2.3.2), JSON-store backend.
 *
 * - Replay (same key + same payload) returns the ORIGINAL status and a
 *   byte-identical body, marked with the Idempotency-Replayed: true header,
 *   and does NOT re-execute the mutation.
 * - Same key + different payload is a structured 409 conflict.
 * - Keys are scoped per route+method.
 * - TTL expiry re-executes (short TTL injected via env).
 * The Postgres companion-table storage is covered in the management package
 * (idempotency-pg.test.ts).
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
	delete process.env.CLEARANCE_IDEMPOTENCY_TTL_MS;
	vi.resetModules();
});

function setupEnv(): Record<string, string> {
	const dir = mkdtempSync(join(tmpdir(), "clr-api-idem-"));
	dirs.push(dir);
	delete process.env.DATABASE_URL;
	process.env.CLEARANCE_DATA_PATH = join(dir, "data.json");
	process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
	process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
	process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
	process.env.NODE_ENV = "development";
	return {
		authorization: `Bearer ${OPERATOR}`,
		"content-type": "application/json",
	};
}

describe("API Idempotency-Key", () => {
	let authHeaders: Record<string, string>;

	beforeEach(async () => {
		authHeaders = setupEnv();
		const { app } = await import("./server.js");
		const init = await app.request("/v1/init", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Idempotency API" }),
		});
		expect(init.status).toBe(200);
	});

	async function loadApp() {
		return (await import("./server.js")).app;
	}

	it("replays the original response body + status without re-executing the mutation", async () => {
		const app = await loadApp();
		const body = JSON.stringify({
			email: "idem@t.dev",
			name: "Idem",
			password: "Explicit!Password42",
		});
		const first = await app.request("/v1/users", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-create-1" },
			body,
		});
		expect(first.status).toBe(201);
		expect(first.headers.get("idempotency-replayed")).toBeNull();
		const firstBody = await first.text();

		const replay = await app.request("/v1/users", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-create-1" },
			body,
		});
		expect(replay.status).toBe(201);
		expect(replay.headers.get("idempotency-replayed")).toBe("true");
		// Byte-identical replay when the response contains no one-time secret.
		expect(await replay.text()).toBe(firstBody);

		// The mutation genuinely did not re-execute: exactly one user exists.
		const list = await app.request("/v1/users", { headers: authHeaders });
		const users = (await list.json()).users as { email: string }[];
		expect(users.filter((u) => u.email === "idem@t.dev").length).toBe(1);
		expect(users.length).toBe(1);
	});

	it("never persists a generated temporary password in the replay record", async () => {
		const app = await loadApp();
		const body = JSON.stringify({ email: "one-time@t.dev", name: "One Time" });
		const first = await app.request("/v1/users", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-one-time-secret" },
			body,
		});
		expect(first.status).toBe(201);
		const original = await first.json();
		expect(original.temporaryPassword).toMatch(/^Tmp!/);

		const replay = await app.request("/v1/users", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-one-time-secret" },
			body,
		});
		expect(replay.status).toBe(201);
		expect(replay.headers.get("idempotency-replayed")).toBe("true");
		const replayed = await replay.json();
		expect(replayed.user).toEqual(original.user);
		expect(replayed.temporaryPassword).toBeUndefined();
		expect(replayed.oneTimeSecretsOmitted).toEqual(["temporaryPassword"]);
		expect(JSON.stringify(replayed)).not.toContain(original.temporaryPassword);

		const list = await app.request("/v1/users", { headers: authHeaders });
		const users = (await list.json()).users as { email: string }[];
		expect(users.filter((user) => user.email === "one-time@t.dev")).toHaveLength(1);
	});

	it("omits every API-key, setup-link, and SCIM one-time secret from replay", async () => {
		const app = await loadApp();
		const orgResponse = await app.request("/v1/organizations", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "Secret Replay Org" }),
		});
		const organizationId = (await orgResponse.json()).organization.id as string;

		async function firstAndReplay(path: string, key: string, requestBody: unknown) {
			const request = () => app.request(path, {
				method: "POST",
				headers: { ...authHeaders, "idempotency-key": key },
				body: JSON.stringify(requestBody),
			});
			const first = await request();
			expect(first.status).toBeLessThan(300);
			const original = await first.json();
			const replay = await request();
			expect(replay.status).toBe(first.status);
			expect(replay.headers.get("idempotency-replayed")).toBe("true");
			return { original, replayed: await replay.json() };
		}

		const createdKey = await firstAndReplay("/v1/keys", "secret-api-key-create", { name: "replay-key", scopes: ["users:read"] });
		expect(createdKey.original.secret).toBeTruthy();
		expect(createdKey.replayed.secret).toBeUndefined();
		expect(createdKey.replayed.oneTimeSecretsOmitted).toEqual(["secret"]);

		const rotatedKey = await firstAndReplay(`/v1/keys/${createdKey.original.apiKey.id}/rotate`, "secret-api-key-rotate", {});
		expect(rotatedKey.original.secret).toBeTruthy();
		expect(rotatedKey.replayed.secret).toBeUndefined();
		expect(rotatedKey.replayed.oneTimeSecretsOmitted).toEqual(["secret"]);

		for (const kind of ["sso", "scim"] as const) {
			const setup = await firstAndReplay(`/v1/${kind}/setup-links`, `secret-${kind}-setup-link`, { organizationId });
			expect(setup.original.token).toBeTruthy();
			expect(setup.original.url).toContain(setup.original.token);
			expect(setup.replayed.token).toBeUndefined();
			expect(setup.replayed.url).toBeUndefined();
			expect(setup.replayed.oneTimeSecretsOmitted).toEqual(["token", "url"]);
			expect(JSON.stringify(setup.replayed)).not.toContain(setup.original.token);
		}

		const scim = await firstAndReplay("/v1/scim", "secret-scim-create", { organizationId, provider: "okta" });
		expect(scim.original.connection.bearerTokenOnce).toBeTruthy();
		expect(scim.replayed.connection.bearerTokenOnce).toBeUndefined();
		expect(scim.replayed.oneTimeSecretsOmitted).toEqual(["connection.bearerTokenOnce"]);
		expect(JSON.stringify(scim.replayed)).not.toContain(scim.original.connection.bearerTokenOnce);
	});

	it("same key with a different payload is a structured 409 conflict", async () => {
		const app = await loadApp();
		const first = await app.request("/v1/users", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-conflict" },
			body: JSON.stringify({ email: "a@t.dev", name: "A" }),
		});
		expect(first.status).toBe(201);

		const conflict = await app.request("/v1/users", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-conflict" },
			body: JSON.stringify({ email: "b@t.dev", name: "B" }),
		});
		expect(conflict.status).toBe(409);
		const err = await conflict.json();
		expect(err.error.code).toBe("IDEMPOTENCY_KEY_CONFLICT");
		expect(err.error.remediation).toMatch(/fresh Idempotency-Key/);

		// The conflicting request did not execute
		const list = await app.request("/v1/users", { headers: authHeaders });
		const users = (await list.json()).users as { email: string }[];
		expect(users.some((u) => u.email === "b@t.dev")).toBe(false);
	});

	it("keys are scoped per route+method — reuse on another route is not a conflict", async () => {
		const app = await loadApp();
		const sharedKey = "key-shared-across-routes";
		const user = await app.request("/v1/users", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": sharedKey },
			body: JSON.stringify({ email: "scoped@t.dev", name: "Scoped" }),
		});
		expect(user.status).toBe(201);

		const org = await app.request("/v1/organizations", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": sharedKey },
			body: JSON.stringify({ name: "Scoped Org" }),
		});
		expect(org.status).toBe(201);
		expect(org.headers.get("idempotency-replayed")).toBeNull();
	});

	it("rejects malformed keys fail-closed without executing the mutation", async () => {
		const app = await loadApp();
		const res = await app.request("/v1/users", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "x".repeat(201) },
			body: JSON.stringify({ email: "badkey@t.dev", name: "Bad" }),
		});
		expect(res.status).toBe(400);
		expect((await res.json()).error.code).toBe("IDEMPOTENCY_KEY_INVALID");
		const list = await app.request("/v1/users", { headers: authHeaders });
		expect(
			((await list.json()).users as { email: string }[]).some(
				(u) => u.email === "badkey@t.dev",
			),
		).toBe(false);
	});

	it("GET requests and requests without the header are untouched", async () => {
		const app = await loadApp();
		const get = await app.request("/v1/users", {
			headers: { ...authHeaders, "idempotency-key": "key-get-ignored" },
		});
		expect(get.status).toBe(200);
		expect(get.headers.get("idempotency-replayed")).toBeNull();

		// Two keyless identical posts both execute (legacy behavior unchanged)
		const mk = () =>
			app.request("/v1/organizations", {
				method: "POST",
				headers: authHeaders,
				body: JSON.stringify({ name: "Keyless Org", slug: undefined }),
			});
		const first = await mk();
		expect(first.status).toBe(201);
		const second = await mk();
		expect(second.status).toBe(409); // duplicate slug — proves it re-executed
		expect((await second.json()).error.code).toBe("ORG_SLUG_EXISTS");
	});
});

describe("API Idempotency-Key TTL expiry", () => {
	it("honors a short TTL — after expiry the request re-executes", async () => {
		const authHeaders = setupEnv();
		process.env.CLEARANCE_IDEMPOTENCY_TTL_MS = "120";
		const { app } = await import("./server.js");
		const init = await app.request("/v1/init", {
			method: "POST",
			headers: authHeaders,
			body: JSON.stringify({ name: "TTL API" }),
		});
		expect(init.status).toBe(200);

		// users export: repeatable success whose envelope differs per execution
		// (correlationId), so replay vs re-execution is directly observable.
		const body = JSON.stringify({ limit: 5 });
		const first = await app.request("/v1/users/export", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-ttl" },
			body,
		});
		expect(first.status).toBe(200);
		const firstEnvelope = await first.json();

		const replayed = await app.request("/v1/users/export", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-ttl" },
			body,
		});
		expect(replayed.headers.get("idempotency-replayed")).toBe("true");
		expect((await replayed.json()).correlationId).toBe(
			firstEnvelope.correlationId,
		);

		await new Promise((resolve) => setTimeout(resolve, 150));

		const after = await app.request("/v1/users/export", {
			method: "POST",
			headers: { ...authHeaders, "idempotency-key": "key-ttl" },
			body,
		});
		expect(after.status).toBe(200);
		expect(after.headers.get("idempotency-replayed")).toBeNull();
		expect((await after.json()).correlationId).not.toBe(
			firstEnvelope.correlationId,
		);
	});
});
