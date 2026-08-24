/**
 * Idempotency backend unit tests (FOLLOW.md P2.3.2) — no database required.
 * The Postgres companion-table backend is covered by idempotency-pg.test.ts.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonStore } from "../store/json-store.js";
import {
	IDEMPOTENCY_DEFAULT_TTL_MS,
	assertIdempotencyKeyValid,
	createIdempotencyBackend,
	fingerprintIdempotentRequest,
	idempotencyConflictError,
	resolveIdempotencyTtlMs,
} from "../services/idempotency.js";

const dirs: string[] = [];

function newStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-idem-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

afterEach(() => {
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("idempotency key + fingerprint primitives", () => {
	it("accepts sane keys and fails closed on invalid ones", () => {
		expect(() => assertIdempotencyKeyValid("a")).not.toThrow();
		expect(() =>
			assertIdempotencyKeyValid("550e8400-e29b-41d4-a716-446655440000"),
		).not.toThrow();
		for (const bad of ["", " leading", "has space", "x".repeat(201), "tab\there"]) {
			expect(() => assertIdempotencyKeyValid(bad), JSON.stringify(bad)).toThrowError(
				expect.objectContaining({ code: "IDEMPOTENCY_KEY_INVALID", status: 400 }),
			);
		}
	});

	it("fingerprints are stable per scope+body and differ across either", () => {
		const a = fingerprintIdempotentRequest("POST /v1/users", '{"email":"a"}');
		expect(fingerprintIdempotentRequest("POST /v1/users", '{"email":"a"}')).toBe(a);
		expect(fingerprintIdempotentRequest("POST /v1/users", '{"email":"b"}')).not.toBe(a);
		expect(fingerprintIdempotentRequest("POST /v1/orgs", '{"email":"a"}')).not.toBe(a);
	});

	it("conflict error is a structured 409", () => {
		const err = idempotencyConflictError("POST /v1/users");
		expect(err.code).toBe("IDEMPOTENCY_KEY_CONFLICT");
		expect(err.status).toBe(409);
		expect(err.remediation).toMatch(/fresh Operation-Key/);
	});

	it("TTL env override is validated fail-closed", () => {
		expect(resolveIdempotencyTtlMs({})).toBe(IDEMPOTENCY_DEFAULT_TTL_MS);
		expect(resolveIdempotencyTtlMs({ CLEARANCE_IDEMPOTENCY_TTL_MS: "500" })).toBe(500);
		for (const bad of ["nope", "0", "-1", "2.5", String(365 * 24 * 3600 * 1000)]) {
			expect(
				() => resolveIdempotencyTtlMs({ CLEARANCE_IDEMPOTENCY_TTL_MS: bad }),
				bad,
			).toThrowError(
				expect.objectContaining({ code: "IDEMPOTENCY_TTL_INVALID" }),
			);
		}
	});
});

describe("in-memory backend (JSON store)", () => {
	it("claims before side effects, waits concurrent callers, and fences stale completions", async () => {
		let now = 1_000_000;
		const backend = createIdempotencyBackend(newStore(), { ttlMs: 60_000, now: () => now });
		const input = { scopeKey: "POST /v1/keys", key: "race", fingerprint: "fp", leaseMs: 1_000 };
		const first = await backend.claim(input);
		expect(first).toEqual({ state: "claimed", generation: 1 });
		expect(await backend.claim(input)).toEqual({ state: "pending", generation: 1 });
		now += 1_001;
		const recovered = await backend.claim(input);
		expect(recovered).toEqual({ state: "claimed", generation: 2 });
		if (first.state !== "claimed" || recovered.state !== "claimed") throw new Error("expected claims");
		expect(await backend.complete({ ...input, generation: first.generation, status: 201, contentType: "application/json", body: "stale" })).toBe(false);
		expect(await backend.complete({ ...input, generation: recovered.generation, status: 201, contentType: "application/json", body: "current" })).toBe(true);
		expect(await backend.get(input.scopeKey, input.key)).toMatchObject({ body: "current" });
	});

	it("keeps an active pending claim when its requested TTL is shorter than its lease", async () => {
		let now = 1_000_000;
		const backend = createIdempotencyBackend(newStore(), { ttlMs: 10, now: () => now });
		const input = { scopeKey: "POST /v1/keys", key: "short-ttl", fingerprint: "fp", leaseMs: 1_000 };
		expect(await backend.claim(input)).toEqual({ state: "claimed", generation: 1 });
		now += 11;
		expect(await backend.claim(input)).toEqual({ state: "pending", generation: 1 });
	});

	it("renewal keeps a long-running generation pending beyond its original lease", async () => {
		let now = 1_000_000;
		const backend = createIdempotencyBackend(newStore(), { ttlMs: 10, now: () => now });
		const input = { scopeKey: "POST /v1/keys", key: "renew", fingerprint: "fp", leaseMs: 1_000 };
		const claim = await backend.claim(input);
		if (claim.state !== "claimed") throw new Error("expected claim");
		now += 900;
		expect(await backend.renew({ ...input, generation: claim.generation })).toBe(true);
		now += 200;
		expect(await backend.claim(input)).toEqual({ state: "pending", generation: claim.generation });
	});

	it("stores and replays a record scoped per route+method", async () => {
		const backend = createIdempotencyBackend(newStore(), { ttlMs: 60_000 });
		expect(backend.kind).toBe("memory");
		const record = {
			scopeKey: "POST /v1/users",
			key: "key-1",
			fingerprint: "fp-1",
			status: 201,
			contentType: "application/json",
			body: '{"user":{"id":"user_1"}}',
		};
		await backend.put(record);
		expect(await backend.get("POST /v1/users", "key-1")).toEqual(record);
		// Same key under a different scope is a different slot
		expect(await backend.get("POST /v1/organizations", "key-1")).toBeNull();
		expect(await backend.get("PATCH /v1/users", "key-1")).toBeNull();
	});

	it("first responder wins under same-key double put", async () => {
		const backend = createIdempotencyBackend(newStore(), { ttlMs: 60_000 });
		const base = {
			scopeKey: "POST /v1/users",
			key: "key-race",
			fingerprint: "fp",
			contentType: "application/json",
		};
		await backend.put({ ...base, status: 201, body: "first" });
		await backend.put({ ...base, status: 201, body: "second" });
		expect((await backend.get(base.scopeKey, base.key))?.body).toBe("first");
	});

	it("honors TTL expiry with an injected clock", async () => {
		let now = 1_000_000;
		const backend = createIdempotencyBackend(newStore(), {
			ttlMs: 500,
			now: () => now,
		});
		await backend.put({
			scopeKey: "POST /v1/users",
			key: "key-ttl",
			fingerprint: "fp",
			status: 201,
			contentType: "application/json",
			body: "{}",
		});
		now += 499;
		expect(await backend.get("POST /v1/users", "key-ttl")).not.toBeNull();
		now += 2; // past expiry
		expect(await backend.get("POST /v1/users", "key-ttl")).toBeNull();
		// A later put also opportunistically sweeps expired entries
		await backend.put({
			scopeKey: "POST /v1/users",
			key: "key-new",
			fingerprint: "fp2",
			status: 200,
			contentType: "application/json",
			body: "{}",
		});
		expect(await backend.get("POST /v1/users", "key-ttl")).toBeNull();
	});
});
