/**
 * Opt-in store-v2 authoritative-event performance gate.
 *
 * The timed section uses PgStore.mutateDurable + appendAuditEvent, including
 * the snapshot row lock, atomic resource/event write, retention, revision,
 * compact snapshot persistence, commit, and public event-cache update.
 * Test setup bulk-loads relational events so reaching 50k does not dominate
 * the measurement with 50k individual production transactions.
 *
 * Run with:
 *   CLEARANCE_STORE_V2_SCALE=1 CLEARANCE_TEST_DATABASE_URL=postgres://... \
 *     pnpm --filter @clearance/management exec vitest run \
 *       src/__tests__/store-v2-events-scale.test.ts
 */
import pg from "pg";
import { describe, expect, it } from "vitest";
import { appendAuditEvent } from "../services/audit.js";
import { createPgStore } from "../store/pg-store.js";
import { storeV2TableNames } from "../store/store-v2-schema.js";
import { gatePostgresSuite } from "./pg-gate.js";

const OPT_IN = process.env.CLEARANCE_STORE_V2_SCALE === "1";
const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const COUNTS = [5_000, 50_000] as const;
const WARMUPS = 5;
const SAMPLES = 50;

type ScaleResult = {
	retainedEvents: number;
	warmups: number;
	samples: number;
	p50Ms: number;
	p95Ms: number;
	minMs: number;
	maxMs: number;
	eventProjectionBytesBefore: number;
	eventProjectionBytesAfter: number;
	maxSnapshotGrowthBytes: number;
};

function quantile(sorted: number[], q: number): number {
	const index = Math.max(0, Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1));
	return sorted[index]!;
}

async function snapshotMetrics(pool: pg.Pool, table: string): Promise<{
	snapshotBytes: number;
	eventProjectionBytes: number;
	eventCount: number;
}> {
	const result = await pool.query<{
		snapshot_bytes: number;
		event_projection_bytes: number;
		event_count: number;
	}>(
		`SELECT pg_column_size(data)::int snapshot_bytes,
		        octet_length((data->'events')::text)::int event_projection_bytes,
		        jsonb_array_length(data->'events')::int event_count
		 FROM ${table} WHERE id = 1`,
	);
	const row = result.rows[0];
	if (!row) throw new Error("store-v2 scale snapshot row is missing");
	return {
		snapshotBytes: Number(row.snapshot_bytes),
		eventProjectionBytes: Number(row.event_projection_bytes),
		eventCount: Number(row.event_count),
	};
}

async function measure(retainedEvents: number): Promise<ScaleResult> {
	const table = `ces_${process.pid}_${retainedEvents}`;
	const prefix = `${table}_v_`;
	const tables = storeV2TableNames(prefix);
	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	const store = await createPgStore(DATABASE_URL, {
		tableName: table,
		normalizedPrefix: prefix,
	});
	const previousMax = process.env.CLEARANCE_AUDIT_MAX_EVENTS;
	process.env.CLEARANCE_AUDIT_MAX_EVENTS = String(retainedEvents);
	try {
		const createdAt = new Date(Date.now() - retainedEvents - 60_000).toISOString();
		await store.mutateDurable((data) => {
			data.projects.push({
				id: "scale_project",
				name: "Event Scale",
				slug: "event-scale",
				createdAt,
				updatedAt: createdAt,
			});
			data.environments.push({
				id: "scale_environment",
				projectId: "scale_project",
				name: "Scale",
				slug: "scale",
				kind: "development",
				createdAt,
				updatedAt: createdAt,
			});
		});
		await store.storeV2!.apply();
		await store.storeV2!.cutoverEvents();

		await pool.query(
			`INSERT INTO ${tables.events}
			 (id, correlation_id, project_id, environment_id, actor, action,
			  subject_type, outcome, source, message, created_at,
			  committed_revision, retention_marker, visible)
			 SELECT 'scale_seed_' || series::text,
			        'scale_corr_' || series::text,
			        'scale_project', 'scale_environment', 'scale', 'scale.seed',
			        'benchmark', 'success', 'system', 'scale seed',
			        clock_timestamp() - (($1::int - series) * interval '1 millisecond'),
			        $2, false, true
			 FROM generate_series(1, $1::int) series`,
			[retainedEvents, store.currentRevision],
		);
		await pool.query(
			`UPDATE ${tables.meta} SET value=$2::jsonb, updated_at=now() WHERE key=$1`,
			[
				"store_v2_events_state",
				JSON.stringify({
					retainedCount: retainedEvents,
					markerId: null,
					droppedCount: 0,
					oldestDroppedCreatedAt: null,
				}),
			],
		);
		await store.refresh();
		expect(store.snapshot.events).toHaveLength(retainedEvents);

		let appendIndex = 0;
		const append = async () => {
			const index = appendIndex++;
			await store.mutateDurable((data) => {
				data.projects[0]!.updatedAt = new Date().toISOString();
				appendAuditEvent(data, {
					actor: "scale",
					action: `scale.append.${retainedEvents}.${index}`,
					subjectType: "benchmark",
					subjectId: String(index),
					outcome: "success",
					source: "system",
					projectId: "scale_project",
					environmentId: "scale_environment",
					message: "authoritative event append benchmark",
				});
			});
		};

		for (let index = 0; index < WARMUPS; index++) await append();
		let metrics = await snapshotMetrics(pool, table);
		const projectionBefore = metrics.eventProjectionBytes;
		let maxSnapshotGrowthBytes = 0;
		const samples: number[] = [];
		for (let index = 0; index < SAMPLES; index++) {
			const beforeBytes = metrics.snapshotBytes;
			const started = performance.now();
			await append();
			samples.push(performance.now() - started);
			metrics = await snapshotMetrics(pool, table);
			maxSnapshotGrowthBytes = Math.max(
				maxSnapshotGrowthBytes,
				metrics.snapshotBytes - beforeBytes,
			);
			expect(metrics.eventCount).toBe(0);
		}
		const sorted = [...samples].sort((left, right) => left - right);
		const result: ScaleResult = {
			retainedEvents,
			warmups: WARMUPS,
			samples: SAMPLES,
			p50Ms: Number(quantile(sorted, 0.5).toFixed(2)),
			p95Ms: Number(quantile(sorted, 0.95).toFixed(2)),
			minMs: Number(sorted[0]!.toFixed(2)),
			maxMs: Number(sorted.at(-1)!.toFixed(2)),
			eventProjectionBytesBefore: projectionBefore,
			eventProjectionBytesAfter: metrics.eventProjectionBytes,
			maxSnapshotGrowthBytes,
		};
		console.log(`STORE_V2_EVENTS_SCALE ${JSON.stringify(result)}`);

		expect(result.p50Ms).toBeLessThan(25);
		expect(result.p95Ms).toBeLessThan(50);
		expect(result.eventProjectionBytesAfter).toBe(result.eventProjectionBytesBefore);
		expect(result.maxSnapshotGrowthBytes).toBeLessThan(1024);
		expect(store.snapshot.events).toHaveLength(retainedEvents);
		expect(
			store.snapshot.events.some((event) => event.action.startsWith("scale.append")),
		).toBe(true);
		return result;
	} finally {
		if (previousMax === undefined) delete process.env.CLEARANCE_AUDIT_MAX_EVENTS;
		else process.env.CLEARANCE_AUDIT_MAX_EVENTS = previousMax;
		await store.destroy().catch(() => undefined);
		for (const target of [
			tables.events,
			tables.principals,
			tables.organizations,
			tables.environments,
			tables.projects,
			tables.meta,
			`${table}_principal_email`,
			`${table}_organization_slug`,
			`${table}_idempotency`,
			table,
		]) {
			await pool.query(`DROP TABLE IF EXISTS ${target}`).catch(() => undefined);
		}
		await pool.end().catch(() => undefined);
	}
}

describe("store-v2 authoritative event scale gate (opt-in)", () => {
	if (!OPT_IN) {
		it("is opt-in: set CLEARANCE_STORE_V2_SCALE=1 with real Postgres", () => {
			expect(OPT_IN).toBe(false);
		});
		return;
	}

	it("keeps production-path append latency flat at 5k and 50k retained events", { timeout: 600_000 }, async () => {
		if (!(await gatePostgresSuite(DATABASE_URL, "store-v2-events-scale"))) {
			throw new Error(
				"CLEARANCE_STORE_V2_SCALE=1 requires reachable Postgres via CLEARANCE_TEST_DATABASE_URL",
			);
		}
		const fiveThousand = await measure(COUNTS[0]);
		const fiftyThousand = await measure(COUNTS[1]);
		expect(fiftyThousand.p95Ms).toBeLessThanOrEqual(
			2 * fiveThousand.p95Ms + 5,
		);
	});
});
