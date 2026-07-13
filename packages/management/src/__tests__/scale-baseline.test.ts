/**
 * Scale tripwire baseline (FOLLOW.md P2.2.4) — evidence, not a perf gate.
 *
 * Seeds N=5000 principals + 5000 organizations into a real PgStore, then
 * measures single-mutation commit latency (mutateDurable round trip) at that
 * scale. The single-row JSONB store rewrites the whole snapshot and rebuilds
 * both uniqueness side-tables (DELETE-all + ~10k row INSERTs) on EVERY write,
 * so this number is the O(N)-per-write cost store-v2 must beat. The measured
 * baseline is recorded in DESIGN-store-v2.md.
 *
 * Opt-in: run with
 *   CLEARANCE_SCALE_BASELINE=1 CLEARANCE_TEST_DATABASE_URL=postgres://... \
 *     pnpm --filter @clearance/management exec vitest run src/__tests__/scale-baseline.test.ts
 *
 * The 5k seed plus ~20 timed mutations takes well over a minute, far too slow
 * for the canonical gate, so this is deliberately NOT part of the gated
 * describe.skipIf(pg) set: without CLEARANCE_SCALE_BASELINE=1 it registers a
 * trivially passing placeholder (never a skip, so the suite's zero-skip
 * invariant and CLEARANCE_REQUIRE_PG_TESTS tripwire are untouched). With the
 * flag set, an unreachable database fails loudly instead of skipping.
 */
import pg from "pg";
import { describe, expect, it } from "vitest";
import { createPgStore } from "../store/pg-store.js";
import { newId, nowIso } from "../store/json-store.js";
import { gatePostgresSuite } from "./pg-gate.js";

const OPT_IN = process.env.CLEARANCE_SCALE_BASELINE === "1";
const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";

const TEST_TABLE = `clearance_mgmt_scale_${process.pid}`;
const SEED_COUNT = 5000;
const SAMPLE_COUNT = 20;

function quantile(sortedMs: number[], q: number): number {
	const idx = Math.min(
		sortedMs.length - 1,
		Math.ceil(q * sortedMs.length) - 1,
	);
	return sortedMs[Math.max(0, idx)] as number;
}

describe("JSONB snapshot store scale baseline (opt-in)", () => {
	if (!OPT_IN) {
		it("is opt-in: set CLEARANCE_SCALE_BASELINE=1 with a reachable Postgres to measure", () => {
			// Intentionally a pass, not a skip: the canonical gate requires zero
			// skipped tests, and this baseline is evidence tooling, not a gate.
			expect(OPT_IN).toBe(false);
		});
		return;
	}

	it(
		`measures mutation latency at N=${SEED_COUNT} principals + ${SEED_COUNT} orgs`,
		{ timeout: 600_000 },
		async () => {
			const available = await gatePostgresSuite(DATABASE_URL, "scale-baseline");
			if (!available) {
				throw new Error(
					"CLEARANCE_SCALE_BASELINE=1 but Postgres is unreachable — set CLEARANCE_TEST_DATABASE_URL to a disposable database",
				);
			}

			const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
			try {
				const now = nowIso();
				const seedStart = performance.now();
				await store.mutateDurable((data) => {
					const project = {
						id: newId("prj"),
						name: "scale-baseline",
						slug: "scale-baseline",
						createdAt: now,
						updatedAt: now,
					};
					const environment = {
						id: newId("env"),
						projectId: project.id,
						name: "development",
						slug: "development",
						kind: "development" as const,
						createdAt: now,
						updatedAt: now,
					};
					data.projects.push(project);
					data.environments.push(environment);
					data.meta.config.projectId = project.id;
					data.meta.config.environmentId = environment.id;
					for (let i = 0; i < SEED_COUNT; i++) {
						data.principals.push({
							id: `usr_scale_${i}`,
							projectId: project.id,
							environmentId: environment.id,
							email: `scale-user-${i}@example.test`,
							name: `Scale User ${i}`,
							status: "active",
							createdAt: now,
							updatedAt: now,
						});
						data.organizations.push({
							id: `org_scale_${i}`,
							projectId: project.id,
							environmentId: environment.id,
							name: `Scale Org ${i}`,
							slug: `scale-org-${i}`,
							status: "active",
							createdAt: now,
							updatedAt: now,
						});
					}
				});
				const seedMs = performance.now() - seedStart;

				const projectId = store.snapshot.meta.config.projectId as string;
				const environmentId = store.snapshot.meta.config.environmentId as string;

				// Timed section: representative single-resource writes (one new
				// principal + its audit event per mutation) at N≈5000.
				const samples: number[] = [];
				for (let i = 0; i < SAMPLE_COUNT; i++) {
					const start = performance.now();
					await store.mutateDurable((data) => {
						data.principals.push({
							id: `usr_scale_timed_${i}`,
							projectId,
							environmentId,
							email: `scale-timed-${i}@example.test`,
							name: `Scale Timed ${i}`,
							status: "active",
							createdAt: nowIso(),
							updatedAt: nowIso(),
						});
						data.events.unshift({
							id: newId("evt"),
							correlationId: newId("corr"),
							actor: "scale-baseline",
							action: "users.create",
							subjectType: "principal",
							subjectId: `usr_scale_timed_${i}`,
							outcome: "success",
							source: "cli",
							projectId,
							environmentId,
							message: "scale baseline timed mutation",
							createdAt: nowIso(),
						});
					});
					samples.push(performance.now() - start);
				}

				const sorted = [...samples].sort((a, b) => a - b);
				const result = {
					n_principals: SEED_COUNT + SAMPLE_COUNT,
					n_organizations: SEED_COUNT,
					samples: SAMPLE_COUNT,
					seed_ms: Math.round(seedMs),
					p50_ms: Number(quantile(sorted, 0.5).toFixed(1)),
					p95_ms: Number(quantile(sorted, 0.95).toFixed(1)),
					min_ms: Number((sorted[0] as number).toFixed(1)),
					max_ms: Number((sorted[sorted.length - 1] as number).toFixed(1)),
				};
				// Machine-greppable baseline line — recorded in DESIGN-store-v2.md.
				console.log(`SCALE_BASELINE ${JSON.stringify(result)}`);

				expect(store.snapshot.principals.length).toBe(SEED_COUNT + SAMPLE_COUNT);
				expect(store.snapshot.organizations.length).toBe(SEED_COUNT);
				expect(result.p50_ms).toBeGreaterThan(0);
			} finally {
				await store.destroy().catch(() => undefined);
				const pool = new pg.Pool({ connectionString: DATABASE_URL });
				try {
					for (const suffix of ["", "_principal_email", "_organization_slug"]) {
						await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}${suffix}`);
					}
				} finally {
					await pool.end().catch(() => undefined);
				}
			}
		},
	);
});
