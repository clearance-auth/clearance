import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import {
	exportEventsOperational,
	inspectEventOperational,
	listEventsPageOperational,
} from "../services/events.js";
import { initProject } from "../services/core.js";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import { gatePostgresSuite } from "./pg-gate.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TABLE = `runtime_audit_reader_${process.pid}`;
const SCHEMA = `runtime_audit_reader_schema_${process.pid}`;
const available = await gatePostgresSuite(DATABASE_URL, "runtime-audit-events-pg");

describe.skipIf(!available)("runtime audit event reader", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const store of stores) await store.destroy().catch(() => undefined);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await pool.query(`DROP TABLE IF EXISTS ${TABLE}_principal_email`);
			await pool.query(`DROP TABLE IF EXISTS ${TABLE}_organization_slug`);
			await pool.query(`DROP TABLE IF EXISTS ${TABLE}_idempotency`);
			await pool.query(`DROP TABLE IF EXISTS ${TABLE}`);
			await pool.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
		} finally {
			await pool.end();
		}
	});

	it("keeps an absent outbox empty then reads the bounded, redacted scoped union", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: TABLE,
			runtimeAudit: { schema: SCHEMA },
		});
		stores.push(store);
		const { project, environment } = initProject(store, { name: "Runtime Audit Reader" });
		await store.ready();
		const scope = { projectId: project.id, environmentId: environment.id };

		expect(await store.runtimeAuditEvents.listPage({ scope, limit: 2 })).toEqual({
			events: [], hasMore: false,
		});

		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await pool.query(`CREATE SCHEMA ${SCHEMA}`);
			await pool.query(`CREATE TABLE ${SCHEMA}.clearance_runtime_audit_events (
				id text PRIMARY KEY, correlation_id text NOT NULL, project_id text NOT NULL,
				environment_id text NOT NULL, organization_id text, actor text NOT NULL,
				action text NOT NULL, subject_type text, subject_id text, outcome text NOT NULL,
				source text NOT NULL, message text NOT NULL, metadata jsonb, created_at timestamptz NOT NULL
			)`);
			await store.mutateDurable((data) => {
				data.events = [{
					id: "evt_management", correlationId: "corr_management", ...scope,
					actor: "operator", action: "users.create", subjectType: "user",
					outcome: "success", source: "cli", message: "management",
					createdAt: "2026-01-01T00:00:02.000Z",
				}];
			});
			await pool.query(
				`INSERT INTO ${SCHEMA}.clearance_runtime_audit_events
				 (id, correlation_id, project_id, environment_id, organization_id, actor, action,
				  subject_type, subject_id, outcome, source, message, metadata, created_at)
				 VALUES
				 ('runtime_newer', 'corr_runtime_newer', $1, $2, 'org_keep', 'runtime', 'auth.login.succeeded',
				  'user', 'user_runtime', 'success', 'sso', 'runtime success', '{"token":"Bearer eyJ.runtime.secret"}', '2026-01-01T00:00:03.000Z'),
				 ('runtime_older', 'corr_runtime_older', $1, $2, 'org_keep', 'runtime', 'auth.login.failed',
				  NULL, NULL, 'failure', 'system', 'runtime failure', NULL, '2026-01-01T00:00:01.000Z'),
				 ('runtime_foreign', 'corr_runtime_foreign', 'proj_foreign', $2, 'org_keep', 'runtime', 'auth.login.succeeded',
				  'user', 'user_foreign', 'success', 'sso', 'foreign', NULL, '2026-01-01T00:00:04.000Z')`,
				[scope.projectId, scope.environmentId],
			);

			const first = await listEventsPageOperational(store, { scope, limit: 2 });
			expect(first.events.map((event) => event.id)).toEqual([
				"runtime_newer", "evt_management",
			]);
			const second = await listEventsPageOperational(store, {
				scope,
				limit: 2,
				cursor: first.nextCursor!,
			});
			expect(second.events.map((event) => event.id)).toEqual(["runtime_older"]);

			const actionOrg = await listEventsPageOperational(store, {
				scope, limit: 5, action: "auth.login.succeeded", organizationId: "org_keep",
			});
			expect(actionOrg.events.map((event) => event.id)).toEqual(["runtime_newer"]);
			expect(await inspectEventOperational(store, "runtime_newer", { scope })).toMatchObject({
				event: { correlationId: "corr_runtime_newer", actor: "runtime", subjectId: "user_runtime", source: "sso" },
				replayable: false,
			});

			const exported = await exportEventsOperational(store, {
				scope, limit: 5, before: "2026-01-01T00:00:02.000Z", skipAudit: true,
			});
			expect(exported.events.map((event) => event.id)).toEqual(["runtime_older"]);
			const full = await exportEventsOperational(store, { scope, limit: 5, skipAudit: true });
			expect(JSON.stringify(full)).not.toContain("eyJ.runtime.secret");
			expect(JSON.stringify(full)).toContain("[redacted]");
		} finally {
			await pool.end();
		}
	});
});
