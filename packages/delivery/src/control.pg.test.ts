import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	cancelDeliveryInExistingTransaction,
	replayDeliveryInExistingTransaction,
	retryDeliveryInExistingTransaction,
} from "./control.js";
import {
	enqueueDeliveryInExistingTransaction,
	type DeliveryRawTransaction,
} from "./enqueue.js";
import { createDeliveryKeyring, type DeliveryKeyring } from "./keyring.js";
import { qualifiedDeliveryTables, type DeliverySchemaOptions } from "./schema.js";
import { DeliveryStore } from "./store.js";

const DATABASE_URL = process.env.CLEARANCE_TEST_DATABASE_URL ?? process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const suffix = `${process.pid}_${randomUUID().slice(0, 8).replace(/-/g, "")}_`;
const options = { prefix: `delivery_control_${suffix}` } satisfies DeliverySchemaOptions;
const driftOptions = { prefix: `delivery_control_drift_${suffix}` } satisfies DeliverySchemaOptions;
const gate = new pg.Pool({ connectionString: DATABASE_URL, connectionTimeoutMillis: 500 });
let available = false;
try {
	await gate.query("SELECT 1");
	available = true;
} catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") throw new Error("Delivery control tests require Postgres");
} finally {
	await gate.end();
}

function ring(input: { current?: string; fingerprint?: string; previous?: DeliveryKeyring } = {}) {
	const current = input.current ?? "enc-current";
	const fingerprint = input.fingerprint ?? "fp-current";
	return createDeliveryKeyring({
		currentKeyId: current,
		keys: {
			...(input.previous ? Object.fromEntries(input.previous.keys) : {}),
			[current]: randomBytes(32),
		},
		currentFingerprintKeyId: fingerprint,
		fingerprintKeys: {
			...(input.previous ? Object.fromEntries(input.previous.fingerprintKeys) : {}),
			[fingerprint]: randomBytes(32),
		},
		sourceDedupeKey: input.previous?.sourceDedupeKey ?? randomBytes(32),
	});
}

describe.skipIf(!available)("delivery control Postgres primitives", () => {
	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	const store = new DeliveryStore(pool, options);
	const keyring = ring();
	let replayKeyring: DeliveryKeyring | null = null;
	const start = new Date(Date.now() + 5_000);
	const expiry = new Date(start.getTime() + 3_600_000);

	async function transaction<T>(fn: (tx: DeliveryRawTransaction) => Promise<T>): Promise<T> {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			const tx: DeliveryRawTransaction = {
				rawTransactionQuery: async <Row extends Record<string, unknown>>(
					text: string,
					values: readonly unknown[] = [],
				) => {
					const result = await client.query(text, [...values]);
					return { rows: result.rows as Row[], rowCount: result.rowCount };
				},
			};
			const result = await fn(tx);
			await client.query("COMMIT");
			return result;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	async function enqueue(input: {
		eventId: string;
		jobId: string;
		sourceKey?: string;
		projectId?: string;
		environmentId?: string;
		maxAttempts?: number;
		quota?: { maxActive: number; maxBacklog: number; maxEnqueuesPerWindow: number; windowMs: number };
		now?: Date;
		semanticExpiresAt?: Date;
	}, activeRing = keyring) {
		return transaction((tx) => enqueueDeliveryInExistingTransaction(tx, {
			eventId: input.eventId,
			jobId: input.jobId,
			kind: "password.reset",
			sourceKey: input.sourceKey ?? input.eventId,
			projectId: input.projectId ?? "project-1",
			environmentId: input.environmentId ?? "env-1",
			channel: "email",
			destination: "person@example.test",
			payload: { to: "person@example.test", template: "password-reset", url: "https://example.test/reset" },
			semanticExpiresAt: input.semanticExpiresAt ?? expiry,
			maxAttempts: input.maxAttempts,
			quota: input.quota,
			now: input.now ?? start,
		}, activeRing, options));
	}

	beforeAll(async () => {
		await store.migrate();
	});

	afterAll(async () => {
		for (const target of [options, driftOptions]) {
			const tables = qualifiedDeliveryTables(target);
			await pool.query(`DROP TABLE IF EXISTS ${tables.attempt}, ${tables.job}, ${tables.payload}, ${tables.event}, ${tables.worker}, ${tables.meta} CASCADE`);
			await pool.query(`DROP FUNCTION IF EXISTS ${tables.schema}."${tables.names.rejectMutationFunction}"() CASCADE`);
		}
		await pool.end();
	});

	it("lists with a surface-bound keyset cursor and hides other scopes", async () => {
		await enqueue({ eventId: "list-event-1", jobId: "list-job-1", now: new Date(start.getTime() + 1) });
		await enqueue({ eventId: "list-event-2", jobId: "list-job-2", now: new Date(start.getTime() + 2) });
		await enqueue({
			eventId: "list-event-other", jobId: "list-job-other", projectId: "project-other",
			now: new Date(start.getTime() + 3),
		});
		const first = await store.listJobs({ projectId: "project-1", environmentId: "env-1", limit: 1,
			channel: "email", kind: "password.reset" });
		expect(first.items).toHaveLength(1);
		expect(first.items[0]).toMatchObject({ id: "list-job-2", destination: "[redacted]" });
		expect(JSON.stringify(first)).not.toContain("fingerprint");
		const second = await store.listJobs({
			projectId: "project-1", environmentId: "env-1", limit: 1, cursor: first.nextCursor!,
		});
		expect(second.items[0]?.id).toBe("list-job-1");
		expect(await store.inspectJobScoped({
			projectId: "project-1", environmentId: "env-1", jobId: "list-job-other",
		})).toBeNull();
		const crossSurface = Buffer.from(JSON.stringify({
			v: 1, s: "audit_events", k: [start.toISOString(), "list-job-1"],
		})).toString("base64url");
		await expect(store.listJobs({
			projectId: "project-1", environmentId: "env-1", cursor: crossSurface,
		})).rejects.toMatchObject({ code: "DELIVERY_CURSOR_INVALID" });
		await store.cancel("list-job-1", start);
		await store.cancel("list-job-2", start);
		await store.cancel("list-job-other", start);
	});

	it("scopes cancel and retry while preserving attempts and terminal authority", async () => {
		await enqueue({ eventId: "retry-event", jobId: "retry-job", maxAttempts: 8 });
		const accelerated = await transaction((tx) => retryDeliveryInExistingTransaction(tx, {
			projectId: "project-1", environmentId: "env-1", jobId: "retry-job", now: start,
		}, options));
		expect(accelerated).toMatchObject({ state: "retry", attemptCount: 0, maxAttempts: 8 });
		const leased = await store.claimNext({ workerId: "control-worker", now: start });
		expect(leased?.id).toBe("retry-job");
		await store.dead({
			jobId: leased!.id, leaseToken: leased!.leaseToken, workerId: "control-worker",
			errorClass: "manual-test", now: new Date(start.getTime() + 1),
		});
		const preview = await store.previewControl({
			projectId: "project-1", environmentId: "env-1", jobId: "retry-job", action: "retry",
			now: new Date(start.getTime() + 2),
		});
		expect(preview).toMatchObject({ allowed: true, effect: { state: "retry", maxAttempts: 2 } });
		const retried = await transaction((tx) => retryDeliveryInExistingTransaction(tx, {
			projectId: "project-1", environmentId: "env-1", jobId: "retry-job",
			now: new Date(start.getTime() + 2),
		}, options));
		expect(retried).toMatchObject({ state: "retry", attemptCount: 1, maxAttempts: 2, deadAt: null });
		const tables = qualifiedDeliveryTables(options);
		expect((await pool.query(`SELECT count(*) count FROM ${tables.attempt} WHERE job_id='retry-job'`)).rows[0].count).toBe("2");

		const leaseForCancel = await store.claimNext({ workerId: "cancel-worker", now: new Date(start.getTime() + 3) });
		expect(leaseForCancel?.id).toBe("retry-job");
		const cancelledLease = await transaction((tx) => cancelDeliveryInExistingTransaction(tx, {
			projectId: "project-1", environmentId: "env-1", jobId: "retry-job",
			now: new Date(start.getTime() + 4),
		}, options));
		expect(cancelledLease).toMatchObject({ state: "leased", cancelRequested: true });
		expect((await pool.query(`SELECT cancel_requested FROM ${tables.job} WHERE id='retry-job'`)).rows[0]).toEqual({ cancel_requested: true });
		expect(await transaction((tx) => cancelDeliveryInExistingTransaction(tx, {
			projectId: "wrong", environmentId: "env-1", jobId: "retry-job", now: start,
		}, options))).toBeNull();
	});

	it("replays terminal payloads with fresh ids, authority, and current keys", async () => {
		const previousRing = ring({ current: "enc-old", fingerprint: "fp-old" });
		const rotatedRing = ring({ current: "enc-new", fingerprint: "fp-new", previous: previousRing });
		replayKeyring = rotatedRing;
		await enqueue({ eventId: "replay-event", jobId: "replay-job", projectId: "replay-project" }, previousRing);
		const leased = await store.claimNext({ workerId: "replay-worker", now: start });
		expect(leased?.id).toBe("replay-job");
		await store.complete({
			jobId: leased!.id, leaseToken: leased!.leaseToken, workerId: "replay-worker",
			now: new Date(start.getTime() + 1),
		});
		expect(await store.previewControl({
			projectId: "replay-project",
			environmentId: "env-1",
			jobId: "replay-job",
			action: "replay",
			maxAttempts: 12,
			now: new Date(start.getTime() + 2),
		})).toMatchObject({
			allowed: true,
			effect: { maxAttempts: 12, createsEvent: true, createsJob: true },
		});
		await expect(transaction((tx) => retryDeliveryInExistingTransaction(tx, {
			projectId: "replay-project", environmentId: "env-1", jobId: "replay-job", now: start,
		}, options))).rejects.toMatchObject({ code: "DELIVERY_CONTROL_CONFLICT", httpStatus: 409 });
		await expect(transaction((tx) => cancelDeliveryInExistingTransaction(tx, {
			projectId: "replay-project", environmentId: "env-1", jobId: "replay-job", now: start,
		}, options))).rejects.toMatchObject({ code: "DELIVERY_CONTROL_CONFLICT", httpStatus: 409 });
		const replay = await transaction((tx) => replayDeliveryInExistingTransaction(tx, {
			projectId: "replay-project", environmentId: "env-1", jobId: "replay-job",
			now: new Date(start.getTime() + 2),
		}, rotatedRing, options));
		expect(replay?.eventId).not.toBe("replay-event");
		expect(replay?.jobId).not.toBe("replay-job");
		const tables = qualifiedDeliveryTables(options);
		const authority = await pool.query(
			`SELECT e.replay_of, e.source_dedupe_version, e.source_fingerprint_key_id, p.key_id
			 FROM ${tables.event} e JOIN ${tables.payload} p ON p.event_id=e.id WHERE e.id=$1`,
			[replay!.eventId],
		);
		expect(authority.rows[0]).toEqual({
			replay_of: "replay-event", source_dedupe_version: 2,
			source_fingerprint_key_id: "fp-new", key_id: "enc-new",
		});
		await store.eraseTerminalPayloads({
			terminalBefore: new Date(start.getTime() + 2),
			now: new Date(start.getTime() + 2),
		});
		await expect(transaction((tx) => replayDeliveryInExistingTransaction(tx, {
			projectId: "replay-project", environmentId: "env-1", jobId: "replay-job",
			now: new Date(start.getTime() + 3),
		}, rotatedRing, options))).rejects.toThrow("Erased delivery payloads cannot be replayed");

		await enqueue({
			eventId: "expired-replay-event", jobId: "expired-replay-job", projectId: "expired-project",
			semanticExpiresAt: new Date(start.getTime() + 10),
		}, rotatedRing);
		await transaction((tx) => cancelDeliveryInExistingTransaction(tx, {
			projectId: "expired-project", environmentId: "env-1", jobId: "expired-replay-job",
			now: new Date(start.getTime() + 1),
		}, options));
		await expect(transaction((tx) => replayDeliveryInExistingTransaction(tx, {
			projectId: "expired-project", environmentId: "env-1", jobId: "expired-replay-job",
			now: new Date(start.getTime() + 11),
		}, rotatedRing, options))).rejects.toThrow("Expired delivery payloads cannot be replayed");
	});

	it("enforces quota under concurrent ambient transactions and reports usage", async () => {
		const quota = { maxActive: 1, maxBacklog: 1, maxEnqueuesPerWindow: 10, windowMs: 60_000 };
		const attempts = await Promise.allSettled([
			enqueue({ eventId: "quota-event-a", jobId: "quota-job-a", projectId: "quota-project", quota }),
			enqueue({ eventId: "quota-event-b", jobId: "quota-job-b", projectId: "quota-project", quota }),
		]);
		expect(attempts.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		const rejected = attempts.find((result) => result.status === "rejected") as PromiseRejectedResult;
		expect(rejected.reason).toMatchObject({
			code: "DELIVERY_QUOTA_EXCEEDED", httpStatus: 429, quota: "active", limit: 1,
		});
		const status = await store.quotaStatus({
			projectId: "quota-project", environmentId: "env-1", policy: quota, now: start,
		});
		expect(status).toMatchObject({ active: { used: 1, limit: 1 }, backlog: { used: 1, limit: 1 } });
		const accepted = attempts.find((result) => result.status === "fulfilled") as PromiseFulfilledResult<{
			eventId: string;
		}>;
		await expect(enqueue({
			eventId: "quota-duplicate-event",
			jobId: "quota-duplicate-job",
			projectId: "quota-project",
			sourceKey: accepted.value.eventId,
			quota,
		})).rejects.toMatchObject({ code: "DELIVERY_DUPLICATE" });

		const retryScope = { projectId: "quota-retry-project", environmentId: "env-1" };
		const looseQuota = { ...quota, maxActive: 10, maxBacklog: 10 };
		await enqueue({
			eventId: "quota-dead-event",
			jobId: "quota-dead-job",
			projectId: retryScope.projectId,
			quota: looseQuota,
		});
		const tables = qualifiedDeliveryTables(options);
		await pool.query(
			`UPDATE ${tables.job} SET state='dead', dead_at=$2, updated_at=$2 WHERE id=$1`,
			["quota-dead-job", new Date(start.getTime() + 1)],
		);
		await enqueue({
			eventId: "quota-active-event",
			jobId: "quota-active-job",
			projectId: retryScope.projectId,
			quota: looseQuota,
			now: new Date(start.getTime() + 2),
		});
		await expect(transaction((tx) => retryDeliveryInExistingTransaction(tx, {
			...retryScope,
			jobId: "quota-dead-job",
			quota,
			now: new Date(start.getTime() + 3),
		}, options))).rejects.toMatchObject({
			code: "DELIVERY_QUOTA_EXCEEDED",
			httpStatus: 429,
			quota: "active",
		});
	});

	it("returns structured unready summaries for stale workers and schema drift", async () => {
		await store.heartbeat({ workerId: "ready-worker", version: "0.2.1", state: "ready", now: start });
		const historicalRing = ring({ current: "enc-historical", fingerprint: "fp-historical" });
		await enqueue({
			eventId: "readiness-terminal-event",
			jobId: "readiness-terminal-job",
			projectId: "readiness-project",
		}, historicalRing);
		await transaction((tx) => cancelDeliveryInExistingTransaction(tx, {
			projectId: "readiness-project",
			environmentId: "env-1",
			jobId: "readiness-terminal-job",
			now: new Date(start.getTime() + 1),
		}, options));
		const readinessKeyring = createDeliveryKeyring({
			currentKeyId: keyring.currentKeyId,
			keys: Object.fromEntries([
				...keyring.keys,
				...(replayKeyring?.keys ?? []),
				...historicalRing.keys,
			]),
			currentFingerprintKeyId: keyring.currentFingerprintKeyId,
			fingerprintKeys: Object.fromEntries([
				...keyring.fingerprintKeys,
				...(replayKeyring?.fingerprintKeys ?? []),
				...historicalRing.fingerprintKeys,
			]),
			sourceDedupeKey: keyring.sourceDedupeKey,
		});
		const withoutHistoricalFingerprint = createDeliveryKeyring({
			currentKeyId: readinessKeyring.currentKeyId,
			keys: Object.fromEntries(readinessKeyring.keys),
			currentFingerprintKeyId: readinessKeyring.currentFingerprintKeyId,
			fingerprintKeys: Object.fromEntries(
				[...readinessKeyring.fingerprintKeys].filter(([keyId]) => keyId !== "fp-historical"),
			),
			sourceDedupeKey: readinessKeyring.sourceDedupeKey,
		});
		expect(await store.readiness({
			now: new Date(start.getTime() + 1), staleAfterMs: 60_000,
		}, withoutHistoricalFingerprint)).toMatchObject({
			ready: false,
			keys: { checked: true, available: false },
			reasons: expect.arrayContaining(["key_unavailable"]),
		});
		expect(await store.readiness({
			now: new Date(start.getTime() + 1), staleAfterMs: 60_000,
		}, readinessKeyring)).toMatchObject({
			ready: true, schema: { isUpToDate: true }, keys: { checked: true, available: true },
			workers: { freshReady: 1 },
		});
		const driftStore = new DeliveryStore(pool, driftOptions);
		await driftStore.migrate();
		const tables = qualifiedDeliveryTables(driftOptions);
		await pool.query(`DROP TABLE ${tables.job} CASCADE`);
		await expect(driftStore.readiness({}, keyring)).resolves.toMatchObject({
			ready: false, schema: { isUpToDate: false }, reasons: ["schema_unavailable"],
		});
	});
});
