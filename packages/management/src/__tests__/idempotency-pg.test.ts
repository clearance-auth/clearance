/**
 * Postgres idempotency companion table (FOLLOW.md P2.3.2).
 *
 * Replay records live in <snapshot_table>_idempotency — NOT the JSONB
 * snapshot — with expires_at TTL and opportunistic cleanup. Gated through
 * pg-gate so the suite skips without a database and hard-fails under
 * CLEARANCE_REQUIRE_PG_TESTS=1 (scripts/test-with-postgres.sh).
 */
import { afterAll, describe, expect, it } from "vitest";
import pg from "pg";
import { gatePostgresSuite } from "./pg-gate.js";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { createIdempotencyBackend } from "../services/idempotency.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TEST_TABLE = `clearance_management_snapshot_idem_${process.pid}`;

const available = await gatePostgresSuite(DATABASE_URL, "idempotency-pg");

describe.skipIf(!available)("PgStore idempotency companion table", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const s of stores) {
			await s.destroy().catch(() => undefined);
		}
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		for (const suffix of [
			"",
			"_principal_email",
			"_organization_slug",
			"_idempotency",
		]) {
			await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}${suffix}`);
		}
		await pool.end();
	});

	async function openStore(): Promise<PgStore> {
		const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(store);
		return store;
	}

	it("selects the postgres backend for a PgStore", async () => {
		const store = await openStore();
		const backend = createIdempotencyBackend(store, { ttlMs: 60_000 });
		expect(backend.kind).toBe("postgres");
	});

	it("stores, replays, and scopes records per route+method — durably across store instances", async () => {
		const storeA = await openStore();
		const backendA = createIdempotencyBackend(storeA, { ttlMs: 60_000 });
		const record = {
			scopeKey: "POST /v1/users",
			key: `key-${process.pid}-durable`,
			fingerprint: "fp-durable",
			status: 201,
			contentType: "application/json",
			body: '{"user":{"id":"user_pg"}}',
		};
		await backendA.put(record);
		expect(await backendA.get(record.scopeKey, record.key)).toEqual(record);
		expect(await backendA.get("POST /v1/organizations", record.key)).toBeNull();

		// A second store (separate pool — models another process) sees the record:
		// replay protection survives process restarts, unlike the JSON dev map.
		const storeB = await openStore();
		const backendB = createIdempotencyBackend(storeB, { ttlMs: 60_000 });
		expect(await backendB.get(record.scopeKey, record.key)).toEqual(record);
	});

	it("first responder wins under same-key double put (ON CONFLICT DO NOTHING)", async () => {
		const store = await openStore();
		const backend = createIdempotencyBackend(store, { ttlMs: 60_000 });
		const base = {
			scopeKey: "POST /v1/users",
			key: `key-${process.pid}-race`,
			fingerprint: "fp",
			contentType: "application/json",
		};
		await backend.put({ ...base, status: 201, body: "first" });
		await backend.put({ ...base, status: 201, body: "second" });
		expect((await backend.get(base.scopeKey, base.key))?.body).toBe("first");
	});

	it("does not sweep an active pending claim when TTL is shorter than its lease", async () => {
		const store = await openStore();
		const backend = createIdempotencyBackend(store, { ttlMs: 10 });
		const input = {
			scopeKey: "POST /v1/keys",
			key: `key-${process.pid}-active-pending`,
			fingerprint: "fp-pending",
			leaseMs: 1_000,
		};
		expect(await backend.claim(input)).toEqual({ state: "claimed", generation: 1 });
		await new Promise((resolve) => setTimeout(resolve, 25));
		expect(await backend.claim(input)).toEqual({ state: "pending", generation: 1 });
	});

	it("renews a pending generation so another process cannot reclaim it", async () => {
		const store = await openStore();
		const backend = createIdempotencyBackend(store, { ttlMs: 10 });
		const input = {
			scopeKey: "POST /v1/keys",
			key: `key-${process.pid}-renew`,
			fingerprint: "fp-renew",
			leaseMs: 100,
		};
		const claim = await backend.claim(input);
		if (claim.state !== "claimed") throw new Error("expected claim");
		await new Promise((resolve) => setTimeout(resolve, 50));
		expect(await backend.renew({ ...input, generation: claim.generation })).toBe(true);
		await new Promise((resolve) => setTimeout(resolve, 60));
		expect(await backend.claim(input)).toEqual({ state: "pending", generation: claim.generation });
	});

	it("honors expires_at on read and cleans expired rows opportunistically on write", async () => {
		const store = await openStore();
		const backend = createIdempotencyBackend(store, { ttlMs: 60_000 });
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			const expiredKey = `key-${process.pid}-expired`;
			// Insert an already-expired row directly (no clock injection needed).
			await pool.query(
				`INSERT INTO ${TEST_TABLE}_idempotency
           (scope_key, key, fingerprint, status, content_type, body, expires_at)
         VALUES ('POST /v1/users', $1, 'fp', 201, 'application/json', '{}', now() - interval '1 second')`,
				[expiredKey],
			);
			// TTL enforced on read: expired ⇒ absent
			expect(await backend.get("POST /v1/users", expiredKey)).toBeNull();
			// Opportunistic cleanup: any write sweeps expired rows
			await backend.put({
				scopeKey: "POST /v1/users",
				key: `key-${process.pid}-fresh`,
				fingerprint: "fp2",
				status: 200,
				contentType: "application/json",
				body: "{}",
			});
			const remaining = await pool.query(
				`SELECT 1 FROM ${TEST_TABLE}_idempotency WHERE key = $1`,
				[expiredKey],
			);
			expect(remaining.rowCount).toBe(0);
		} finally {
			await pool.end();
		}
	});

	it("keeps idempotency records out of the JSONB snapshot", async () => {
		const store = await openStore();
		const backend = createIdempotencyBackend(store, { ttlMs: 60_000 });
		const checksumBefore = store.checksum();
		await backend.put({
			scopeKey: "POST /v1/users",
			key: `key-${process.pid}-snapshot`,
			fingerprint: "fp",
			status: 201,
			contentType: "application/json",
			body: "{}",
		});
		await store.refresh();
		// Snapshot untouched: no key material, no revision churn from idempotency
		expect(store.checksum()).toBe(checksumBefore);
		expect(JSON.stringify(store.snapshot)).not.toContain("key-");
	});
});
