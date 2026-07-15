import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import {
	createDeliveryTransactionAdapter,
	enqueueDelivery,
	type EnqueueDeliveryInput,
} from "./enqueue.js";
import { createDeliveryKeyring } from "./keyring.js";
import {
	deliveryTableNames,
	migrateDeliverySchema,
	qualifiedDeliveryTables,
	quoteIdentifier,
	type DeliverySchemaOptions,
} from "./schema.js";
import { DeliveryStore } from "./store.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const suffix = `${process.pid}_${randomUUID().slice(0, 8).replace(/-/g, "")}_`;
const mainOptions = { prefix: `delivery_${suffix}` } satisfies DeliverySchemaOptions;
const collisionOptions = { prefix: `delivery_collision_${suffix}` } satisfies DeliverySchemaOptions;
const futureOptions = { prefix: `delivery_future_${suffix}` } satisfies DeliverySchemaOptions;
const driftOptions = { prefix: `delivery_drift_${suffix}` } satisfies DeliverySchemaOptions;

const gate = new pg.Pool({ connectionString: DATABASE_URL, connectionTimeoutMillis: 500 });
let available = false;
try {
	await gate.query("SELECT 1");
	available = true;
} catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
		throw new Error(`Delivery Postgres tests require a reachable database at ${DATABASE_URL}`);
	}
	process.stderr.write(`[delivery-store-pg] skipped: Postgres unavailable at ${DATABASE_URL}\n`);
} finally {
	await gate.end();
}

async function dropSchemaAssets(pool: pg.Pool, options: DeliverySchemaOptions) {
	const schema = options.schema ?? "public";
	const names = deliveryTableNames(options);
	for (const name of [names.attempt, names.job, names.payload, names.event, names.worker, names.meta]) {
		await pool.query(`DROP TABLE IF EXISTS ${quoteIdentifier(schema)}.${quoteIdentifier(name)} CASCADE`);
	}
	await pool.query(
		`DROP FUNCTION IF EXISTS ${quoteIdentifier(schema)}.${quoteIdentifier(names.rejectMutationFunction)}()`,
	);
}

describe.skipIf(!available)("delivery Postgres storage", () => {
	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	const store = new DeliveryStore(pool, mainOptions);
	const keyring = createDeliveryKeyring({
		currentKeyId: "current",
		keys: { current: randomBytes(32), previous: randomBytes(32) },
		fingerprintKey: randomBytes(32),
	});
	const start = new Date(Date.now() + 5_000);
	const expiry = new Date(start.getTime() + 60 * 60_000);

	afterAll(async () => {
		for (const options of [mainOptions, collisionOptions, futureOptions, driftOptions]) {
			await dropSchemaAssets(pool, options).catch(() => undefined);
		}
		await pool.end();
	});

	it("refuses unowned collisions and future schema versions", async () => {
		const collision = qualifiedDeliveryTables(collisionOptions);
		await pool.query(`CREATE TABLE ${collision.event} (marker text NOT NULL)`);
		await pool.query(`INSERT INTO ${collision.event} (marker) VALUES ('external')`);
		await expect(migrateDeliverySchema(pool, collisionOptions)).rejects.toMatchObject({
			code: "DELIVERY_SCHEMA_COLLISION",
		});
		expect((await pool.query(`SELECT marker FROM ${collision.event}`)).rows).toEqual([
			{ marker: "external" },
		]);
		await pool.query(`DROP TABLE ${collision.event}`);

		await migrateDeliverySchema(pool, futureOptions);
		const future = qualifiedDeliveryTables(futureOptions);
		await pool.query(
			`UPDATE ${future.meta} SET value='2'::jsonb WHERE key='schema_version'`,
		);
		await expect(migrateDeliverySchema(pool, futureOptions)).rejects.toMatchObject({
			code: "DELIVERY_SCHEMA_VERSION_FUTURE",
		});

		await migrateDeliverySchema(pool, driftOptions);
		const drift = qualifiedDeliveryTables(driftOptions);
		await pool.query(`DROP INDEX ${quoteIdentifier(drift.schema)}.${quoteIdentifier(`${drift.names.job}_claim_idx`)}`);
		await expect(migrateDeliverySchema(pool, driftOptions)).rejects.toMatchObject({
			code: "DELIVERY_SCHEMA_DRIFT",
		});
	});

	it("rolls enqueue back atomically and stores no plaintext", async () => {
		await store.migrate();
		expect((await store.migrate()).version).toBe(1);
		const client = await pool.connect();
		try {
			await expect(enqueueDelivery(
				createDeliveryTransactionAdapter(client),
				baseInput("no-transaction-event", "no-transaction-job", "no-transaction-source"),
				keyring,
				mainOptions,
			)).rejects.toMatchObject({ code: "DELIVERY_TRANSACTION_REQUIRED" });
			expect((await client.query("SELECT 1 value")).rows[0]).toEqual({ value: 1 });

			await client.query("BEGIN");
			await enqueueDelivery(
				createDeliveryTransactionAdapter(client),
				{
					eventId: "rolled-event",
					jobId: "rolled-job",
					kind: "password.reset",
					sourceKey: "reset-token-plaintext",
					projectId: "project-1",
					environmentId: "environment-1",
					channel: "email",
					destination: "person@example.test",
					payload: { to: "person@example.test", token: "reset-token-plaintext" },
					semanticExpiresAt: expiry,
					now: start,
				},
				keyring,
				mainOptions,
			);
			await client.query("ROLLBACK");
		} finally {
			client.release();
		}
		const tables = qualifiedDeliveryTables(mainOptions);
		expect((await pool.query(`SELECT count(*)::int count FROM ${tables.event}`)).rows[0].count).toBe(0);

		await enqueue("event-existing", "job-existing", "source-existing", expiry);
		const partial = await pool.connect();
		try {
			await partial.query("BEGIN");
			await expect(enqueueDelivery(
				createDeliveryTransactionAdapter(partial),
				baseInput("partial-event", "job-existing", "partial-source"),
				keyring,
				mainOptions,
			)).rejects.toMatchObject({ code: "DELIVERY_DUPLICATE" });
			expect((await partial.query("SELECT 1 value")).rows[0]).toEqual({ value: 1 });
			await partial.query("COMMIT");
		} finally {
			partial.release();
		}
		expect((await pool.query(`SELECT count(*)::int count FROM ${tables.event} WHERE id='partial-event'`)).rows[0].count).toBe(0);

		await enqueue("event-1", "job-1", "shared-source", expiry);
		await enqueue("event-tenant-2", "job-tenant-2", "shared-source", expiry, {
			projectId: "project-2",
			environmentId: "environment-2",
		});
		const atRest = JSON.stringify(
			(await pool.query(`SELECT e.*, p.* FROM ${tables.event} e JOIN ${tables.payload} p ON p.event_id=e.id`)).rows,
		);
		expect(atRest).not.toContain("person@example.test");
		expect(atRest).not.toContain("reset-token-plaintext");
		await expect(pool.query(`UPDATE ${tables.event} SET kind='changed' WHERE id='event-1'`))
			.rejects.toThrow(/immutable/);
		expect((await store.cancel("job-1", start))?.state).toBe("cancelled");
		expect((await store.cancel("job-existing", start))?.state).toBe("cancelled");
		expect((await store.cancel("job-tenant-2", start))?.state).toBe("cancelled");
	});

	it("claims concurrently, fences stale workers, and records retry/dead/cancel/reclaim", async () => {
		await enqueue("event-2", "job-2", "source-2", expiry);
		await enqueue("event-3", "job-3", "source-3", expiry);
		const [first, second] = await Promise.all([
			store.claimNext({ workerId: "worker-a", now: start }),
			store.claimNext({ workerId: "worker-b", now: start }),
		]);
		expect(first).not.toBeNull();
		expect(second).not.toBeNull();
		expect(first!.id).not.toBe(second!.id);
		await expect(store.complete({
			jobId: first!.id, leaseToken: "wrong", workerId: "worker-a", now: start,
		})).rejects.toMatchObject({ code: "DELIVERY_STALE_LEASE" });
		await expect(store.complete({
			jobId: first!.id, leaseToken: first!.leaseToken, workerId: "worker-other", now: start,
		})).rejects.toMatchObject({ code: "DELIVERY_STALE_LEASE" });
		const payload = await store.readLeasedPayload<{ token: string }>({
			jobId: first!.id, leaseToken: first!.leaseToken, keyring, now: start,
		});
		expect(payload.token).toBe("reset-token-plaintext");
		expect((await store.complete({
			jobId: first!.id, leaseToken: first!.leaseToken, workerId: first!.leaseOwner, now: start,
		})).state).toBe("delivered");
		expect((await store.fail({
			jobId: second!.id, leaseToken: second!.leaseToken, workerId: second!.leaseOwner,
			retryable: true, errorClass: "smtp.timeout", now: start, random: () => 0,
		})).state).toBe("retry");
		const retried = await store.claimNext({ workerId: "worker-c", now: start });
		expect(retried?.id).toBe(second!.id);
		expect((await store.fail({
			jobId: retried!.id, leaseToken: retried!.leaseToken, workerId: retried!.leaseOwner,
			retryable: false, errorClass: "smtp.rejected", now: start,
		})).state).toBe("dead");

		await enqueue("event-4", "job-4", "source-4", expiry);
		expect((await store.cancel("job-4", start))?.state).toBe("cancelled");
		await enqueue("event-5", "job-5", "source-5", expiry);
		const expiringLease = await store.claimNext({ workerId: "worker-d", leaseMs: 1_000, now: start });
		expect(expiringLease?.id).toBe("job-5");
		const reclaimedAt = new Date(start.getTime() + 1_001);
		expect(await store.reclaimExpired(reclaimedAt)).toBe(1);
		expect((await store.inspectJob("job-5"))?.state).toBe("retry");
		const renewed = await store.claimNext({ workerId: "worker-e", leaseMs: 1_000, now: reclaimedAt });
		expect(renewed?.id).toBe("job-5");
		await expect(store.complete({
			jobId: "job-5", leaseToken: expiringLease!.leaseToken,
			workerId: expiringLease!.leaseOwner, now: reclaimedAt,
		})).rejects.toMatchObject({ code: "DELIVERY_STALE_LEASE" });
		expect((await store.cancel("job-5", reclaimedAt))?.state).toBe("leased");
		expect(await store.reclaimExpired(new Date(reclaimedAt.getTime() + 1_001))).toBe(1);
		expect((await store.inspectJob("job-5"))?.state).toBe("cancelled");
	});

	it("dead-letters semantic expiry and never erases claimable or leased payloads", async () => {
		const tables = qualifiedDeliveryTables(mainOptions);
		await enqueue("event-6", "job-6", "source-6", new Date(start.getTime() + 10));
		const afterExpiry = new Date(start.getTime() + 11);
		await store.eraseTerminalPayloads({ terminalBefore: afterExpiry, now: afterExpiry });
		expect((await pool.query(`SELECT count(*)::int count FROM ${tables.payload} WHERE event_id='event-6'`)).rows[0].count).toBe(1);
		expect(await store.expireAndEraseUndeliverable(afterExpiry)).toEqual({
			deadJobs: 1,
			erasedPayloads: 1,
		});
		expect((await store.inspectJob("job-6"))?.state).toBe("dead");
		await expect(store.readLeasedPayload({
			jobId: "job-6", leaseToken: "none", keyring, now: afterExpiry,
		})).rejects.toMatchObject({ code: "DELIVERY_STALE_LEASE" });

		const leasedExpiry = new Date(start.getTime() + 2_000);
		await enqueue("event-7", "job-7", "source-7", leasedExpiry);
		const leased = await store.claimNext({ workerId: "worker-expiry", leaseMs: 5_000, now: start });
		expect(leased?.id).toBe("job-7");
		const completedAfterExpiry = new Date(leasedExpiry.getTime() + 1);
		expect(await store.eraseTerminalPayloads({
			terminalBefore: completedAfterExpiry,
			now: completedAfterExpiry,
		})).toBe(0);
		expect((await pool.query(`SELECT count(*)::int count FROM ${tables.payload} WHERE event_id='event-7'`)).rows[0].count).toBe(1);
		const expiredCompletion = await store.complete({
			jobId: leased!.id,
			leaseToken: leased!.leaseToken,
			workerId: leased!.leaseOwner,
			now: completedAfterExpiry,
		});
		expect(expiredCompletion.state).toBe("dead");
		expect(expiredCompletion.lastErrorClass).toBe("semantic_expired");
		expect(await store.expireAndEraseUndeliverable(completedAfterExpiry)).toEqual({
			deadJobs: 0,
			erasedPayloads: 1,
		});
	});

	it("validates worker, lease, date, retry, and maintenance bounds", async () => {
		await expect(store.claimNext({ workerId: "worker/path", now: start }))
			.rejects.toMatchObject({ code: "DELIVERY_WORKER_ID_INVALID" });
		await expect(store.claimNext({ workerId: "worker-valid", leaseMs: 999, now: start }))
			.rejects.toMatchObject({ code: "DELIVERY_BOUND_INVALID" });
		await expect(store.reclaimExpired(start, 0))
			.rejects.toMatchObject({ code: "DELIVERY_BOUND_INVALID" });
		await expect(store.cancel("none", new Date(Number.NaN)))
			.rejects.toMatchObject({ code: "DELIVERY_DATE_INVALID" });
		await expect(store.heartbeat({ workerId: "worker-valid", version: "secret/path", state: "ready", now: start }))
			.rejects.toMatchObject({ code: "DELIVERY_WORKER_VERSION_INVALID" });
	});

	it("deletes only aged terminal structure and preserves replay roots and recent audit", async () => {
		const day = 24 * 60 * 60_000;
		const retentionNow = new Date();
		const oldCreated = new Date(retentionNow.getTime() - 45 * day);
		const oldExpiry = new Date(oldCreated.getTime() + day);
		const oldCompletion = new Date(oldCreated.getTime() + 1_000);
		const tables = qualifiedDeliveryTables(mainOptions);

		await enqueue("event-old-delete", "job-old-delete", "source-old-delete", oldExpiry, {
			now: oldCreated,
		});
		const deletable = await store.claimNext({ workerId: "worker-old-delete", now: oldCreated });
		expect(deletable?.id).toBe("job-old-delete");
		await store.complete({
			jobId: deletable!.id,
			leaseToken: deletable!.leaseToken,
			workerId: deletable!.leaseOwner,
			now: oldCompletion,
		});

		await enqueue("event-old-root", "job-old-root", "source-old-root", oldExpiry, {
			now: oldCreated,
		});
		const root = await store.claimNext({ workerId: "worker-old-root", now: oldCreated });
		expect(root?.id).toBe("job-old-root");
		await store.complete({
			jobId: root!.id,
			leaseToken: root!.leaseToken,
			workerId: root!.leaseOwner,
			now: oldCompletion,
		});
		await enqueue("event-replay-current", "job-replay-current", "source-replay-current", expiry, {
			replayOf: "event-old-root",
		});
		await store.heartbeat({
			workerId: "worker-stale",
			version: "1.0.0",
			state: "stopped",
			now: new Date(retentionNow.getTime() - 2 * day),
		});
		await store.heartbeat({
			workerId: "worker-current",
			version: "1.0.0",
			state: "ready",
			now: retentionNow,
		});

		const cutoff = new Date(retentionNow.getTime() - 30 * day);
		const cleaned = await store.cleanupRetention({
			payloadBefore: retentionNow,
			terminalBefore: cutoff,
			eventBefore: cutoff,
			workerBefore: new Date(retentionNow.getTime() - day),
			now: retentionNow,
		});
		expect(cleaned).toEqual({
			erasedPayloads: 2,
			deletedAttempts: 4,
			deletedJobs: 2,
			deletedEvents: 1,
			deletedWorkers: 1,
		});
		expect((await pool.query(`SELECT count(*)::int count FROM ${tables.event} WHERE id='event-old-delete'`)).rows[0].count).toBe(0);
		expect((await pool.query(`SELECT count(*)::int count FROM ${tables.event} WHERE id='event-old-root'`)).rows[0].count).toBe(1);
		expect((await pool.query(`SELECT count(*)::int count FROM ${tables.event} WHERE id='event-replay-current'`)).rows[0].count).toBe(1);
		expect((await pool.query(`SELECT id FROM ${tables.worker} ORDER BY id`)).rows).toEqual([
			{ id: "worker-current" },
		]);
		await expect(store.eraseTerminalPayloads({
			terminalBefore: new Date(retentionNow.getTime() + 1),
			now: retentionNow,
		})).rejects.toMatchObject({ code: "DELIVERY_RETENTION_INVALID" });
	});

	function baseInput(
		eventId: string,
		jobId: string,
		sourceKey: string,
		overrides: Partial<EnqueueDeliveryInput> = {},
	): EnqueueDeliveryInput {
		return {
			eventId,
			jobId,
			kind: "password.reset",
			sourceKey,
			projectId: "project-1",
			environmentId: "environment-1",
			channel: "email",
			destination: "person@example.test",
			payload: { to: "person@example.test", token: "reset-token-plaintext" },
			semanticExpiresAt: expiry,
			now: start,
			...overrides,
		};
	}

	async function enqueue(
		eventId: string,
		jobId: string,
		sourceKey: string,
		semanticExpiresAt: Date,
		overrides: Partial<EnqueueDeliveryInput> = {},
	) {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			const result = await enqueueDelivery(
				createDeliveryTransactionAdapter(client),
				baseInput(eventId, jobId, sourceKey, { semanticExpiresAt, ...overrides }),
				keyring,
				mainOptions,
			);
			await client.query("COMMIT");
			return result;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}
});
