import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createClearanceAuth } from "./create-auth.js";
import { createRuntimeAuditOutbox } from "./runtime-audit.js";

const databaseUrl =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const pool = new pg.Pool({ connectionString: databaseUrl, connectionTimeoutMillis: 500 });
const schema = `runtime_audit_${randomUUID().replaceAll("-", "")}`;
let available = false;

beforeAll(async () => {
	try {
		await pool.query("SELECT 1");
		available = true;
		await pool.query(`CREATE SCHEMA "${schema}"`);
	} catch {
		if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") throw new Error("runtime audit PostgreSQL test requires a database");
	}
});

afterAll(async () => {
	if (available) await pool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
	await pool.end();
});

describe("runtime audit outbox", () => {
	it("commits only with its owner transaction and rejects alteration", async () => {
		if (!available) return;
		const outbox = createRuntimeAuditOutbox(pool, {
			projectId: "project_test",
			environmentId: "environment_test",
			schema,
		});
		const plan = await outbox.planMigration();
		expect(plan.pendingSecurityMigrations).toContain("runtime-audit-outbox-v1");
		await plan.apply();
		expect((await outbox.planMigration()).pendingSecurityMigrations).toEqual([]);
		const client = await pool.connect();
		const transaction = { rawTransactionQuery: client.query.bind(client) };
		const draft = {
			actor: "user_test",
			action: "auth.session.created",
			subjectType: "session",
			subjectId: "session_test",
			outcome: "success" as const,
			source: "system" as const,
			organizationId: null,
			message: "Session issued",
			metadata: { safe: "kept", password: "must-not-store", nested: { token: "must-not-store" } },
			request: {
				correlationId: "request_test",
				operationId: "sign-in-email",
				route: "/sign-in/email",
				method: "POST",
				clientIp: "127.0.0.1",
				userAgent: "runtime-audit-test",
			},
		};
		try {
			await client.query("BEGIN");
			await client.query('CREATE TEMP TABLE runtime_audit_owner_probe (id text PRIMARY KEY)');
			await client.query("INSERT INTO runtime_audit_owner_probe VALUES ('committed')");
			await outbox.binding.append(transaction as never, draft);
			await client.query("COMMIT");

			const committed = await pool.query<{ metadata: Record<string, unknown> }>(
				`SELECT metadata FROM "${schema}".clearance_runtime_audit_events WHERE correlation_id='request_test'`,
			);
			expect(committed.rows).toHaveLength(1);
			expect(committed.rows[0]?.metadata).toMatchObject({ safe: "kept" });
			expect(JSON.stringify(committed.rows[0]?.metadata)).not.toContain("must-not-store");

			await client.query("BEGIN");
			await outbox.binding.append(transaction as never, { ...draft, request: { ...draft.request, correlationId: "request_rollback" } });
			await client.query("ROLLBACK");
			const rolledBack = await pool.query(`SELECT count(*)::int AS count FROM "${schema}".clearance_runtime_audit_events WHERE correlation_id='request_rollback'`);
			expect(rolledBack.rows[0]?.count).toBe(0);

			const scopedDatabaseUrl = new URL(databaseUrl);
			scopedDatabaseUrl.searchParams.set("options", `-csearch_path=${schema}`);
			const product = createClearanceAuth({
				baseURL: "http://localhost:3000",
				secret: "runtime-audit-product-test-secret-value",
				databaseUrl: scopedDatabaseUrl.toString(),
				runtimeAudit: {
					projectId: "project_test",
					environmentId: "environment_test",
					schema,
				},
				authenticationPolicy: {
					projectId: "project_test",
					environmentId: "environment_test",
				},
			});
			try {
				await product.migrate();
				const email = `runtime-audit-${randomUUID()}@example.test`;
				const password = "correct-horse-battery-staple";
				await product.auth.api.signUpEmail({ body: { email, password, name: "Runtime Audit" } });
				const signIn = await product.auth.api.signInEmail({ body: { email, password } });
				const failedPassword = "incorrect-password-must-not-persist";
				const failedResponse = await product.auth.handler(new Request(
					"http://localhost:3000/api/auth/sign-in/email",
					{
						method: "POST",
						headers: {
							"content-type": "application/json",
							origin: "http://localhost:3000",
							"x-request-id": "runtime-audit-failed-login-request",
						},
						body: JSON.stringify({ email, password: failedPassword }),
					},
				));
				expect(failedResponse.ok).toBe(false);
				const runtimeEvents = await pool.query<{ action: string; metadata: Record<string, unknown> }>(
					`SELECT action, metadata FROM "${schema}".clearance_runtime_audit_events
					 WHERE action IN ('auth.session.created', 'auth.login.succeeded') ORDER BY sequence`,
				);
				expect(runtimeEvents.rows.map((event) => event.action)).toEqual(expect.arrayContaining([
					"auth.session.created",
					"auth.login.succeeded",
				]));
				expect(JSON.stringify(runtimeEvents.rows)).not.toContain(signIn.token);
				expect(JSON.stringify(runtimeEvents.rows)).not.toContain(password);
				const failedEvents = await pool.query<{
					correlation_id: string;
					actor: string;
					message: string;
					subject_id: string | null;
					metadata: Record<string, unknown>;
				}>(`SELECT correlation_id, actor, message, subject_id, metadata FROM "${schema}".clearance_runtime_audit_events
					WHERE action='auth.login.failed' AND correlation_id='runtime-audit-failed-login-request'`);
				expect(failedEvents.rows).toHaveLength(1);
				const failedEvent = failedEvents.rows[0]!;
				expect(failedEvent).toMatchObject({
					correlation_id: "runtime-audit-failed-login-request",
					actor: "anonymous",
					subject_id: null,
					message: "Interactive authentication failed",
					metadata: { status: 401, method: "password" },
				});
				const requestMetadata = failedEvent.metadata.request as Record<string, unknown>;
				expect(requestMetadata).toMatchObject({ route: "/sign-in/email", method: "POST" });
				expect(Object.hasOwn(requestMetadata, "clientIp")).toBe(true);
				expect(Object.hasOwn(requestMetadata, "userAgent")).toBe(true);
				expect(JSON.stringify(failedEvent)).not.toContain(email);
				expect(JSON.stringify(failedEvent)).not.toContain(failedPassword);
			} finally {
				await product.destroy();
			}

			for (const sql of [
				`UPDATE "${schema}".clearance_runtime_audit_events SET message='tampered'`,
				`DELETE FROM "${schema}".clearance_runtime_audit_events`,
				`TRUNCATE "${schema}".clearance_runtime_audit_events`,
			]) {
				await expect(pool.query(sql)).rejects.toMatchObject({ code: "CLR01" });
			}
			await pool.query(`ALTER TABLE "${schema}".clearance_runtime_audit_events ADD COLUMN tampered text`);
			const tampered = await outbox.planMigration();
			expect(tampered.pendingSecurityMigrations).toContain("runtime-audit-outbox-v1");
			await expect(tampered.apply()).rejects.toMatchObject({
				code: "RUNTIME_AUDIT_SCHEMA_INVALID",
			});
			await expect(tampered.compileSql()).rejects.toMatchObject({
				code: "RUNTIME_AUDIT_SCHEMA_INVALID",
			});
		} finally {
			await client.query("ROLLBACK").catch(() => undefined);
			client.release();
		}
	});
});
