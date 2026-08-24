import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	createDeliveryKeyring,
	createDeliveryTransactionAdapter,
	DeliveryStore,
	enqueueDelivery,
	migrateDeliverySchema,
} from "@clearance/delivery";
import { createClearanceAuth } from "./create-auth.js";
import { createRuntimeAuditOutbox } from "./runtime-audit.js";

const baseDatabaseUrl =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const admin = new pg.Pool({ connectionString: baseDatabaseUrl, connectionTimeoutMillis: 500 });
const pool = new pg.Pool({ connectionString: baseDatabaseUrl, connectionTimeoutMillis: 500 });
const schema = `runtime_audit_${randomUUID().replaceAll("-", "")}`;
let available = false;

beforeAll(async () => {
	try {
		await admin.query("SELECT 1");
		await pool.query(`CREATE SCHEMA "${schema}"`);
		available = true;
	} catch {
		if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") throw new Error("runtime audit PostgreSQL test requires a database");
	}
});

afterAll(async () => {
	if (available) await pool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
	await pool.end();
	await admin.end();
});

describe("runtime audit outbox", () => {
	it("accepts only the exact enabled rollback fence alongside its append-only triggers", async () => {
		if (!available) return;
		const databaseName = `runtime_audit_guard_${randomUUID().replaceAll("-", "")}`;
		const isolatedDatabaseUrl = new URL(baseDatabaseUrl);
		isolatedDatabaseUrl.pathname = `/${databaseName}`;
		const guardPool = new pg.Pool({
			connectionString: isolatedDatabaseUrl.toString(),
			connectionTimeoutMillis: 500,
		});
		const guardSchema = `runtime_audit_${randomUUID().replaceAll("-", "")}`;
		await admin.query(`CREATE DATABASE "${databaseName}"`);
		try {
			await guardPool.query(`CREATE SCHEMA "${guardSchema}"`);
			const prefix = `rf_${randomUUID().slice(0, 8)}`;
			const outbox = createRuntimeAuditOutbox(guardPool, {
				projectId: "project_rollback_fence",
				environmentId: "environment_rollback_fence",
				schema: guardSchema,
				prefix,
			});
			const table = `"${guardSchema}".${prefix}_runtime_audit_events`;
			await outbox.applyMigration();
			const installRollbackFenceFunction = async () => {
				await guardPool.query(`CREATE OR REPLACE FUNCTION "public"."clearance_import_rollback_guard_v1"()
					RETURNS trigger
					LANGUAGE plpgsql
					AS $rollback_fence$
					DECLARE
						argument_index integer := 0;
						fence_kind text;
						reference_column text;
						condition_column text;
						condition_value text;
						reference_id text;
						row_data jsonb := to_jsonb(NEW);
					BEGIN
						WHILE argument_index < TG_NARGS LOOP
							fence_kind := TG_ARGV[argument_index];
							reference_column := TG_ARGV[argument_index + 1];
							condition_column := TG_ARGV[argument_index + 2];
							condition_value := TG_ARGV[argument_index + 3];
							reference_id := row_data ->> reference_column;
							IF reference_id IS NOT NULL AND (
								condition_column = '' OR row_data ->> condition_column = condition_value
							) THEN
								PERFORM pg_advisory_xact_lock(hashtextextended(
									'clearance-import-rollback:v1:' || fence_kind || ':' || reference_id,
									0
								));
								IF EXISTS (
									SELECT 1 FROM "public"."clearance_import_rollback_tombstones"
									WHERE kind = fence_kind AND resource_id = reference_id
								) THEN
									RAISE EXCEPTION 'Clearance rollback-fenced resource cannot be referenced'
										USING ERRCODE = '23503';
								END IF;
							END IF;
							argument_index := argument_index + 4;
						END LOOP;
						RETURN NEW;
					END
					$rollback_fence$`);
			};
			await installRollbackFenceFunction();
			await guardPool.query(`CREATE TRIGGER clearance_import_rollback_guard_v1
				BEFORE INSERT OR UPDATE ON ${table}
				FOR EACH ROW EXECUTE FUNCTION "public"."clearance_import_rollback_guard_v1"(
					'organization', 'organization_id', '', ''
				)`);
			expect((await outbox.planMigration()).pendingSecurityMigrations).toEqual([]);

			await guardPool.query(`ALTER TABLE ${table} DISABLE TRIGGER clearance_import_rollback_guard_v1`);
			expect((await outbox.planMigration()).pendingSecurityMigrations).toContain("runtime-audit-outbox-v2");
			await guardPool.query(`ALTER TABLE ${table} ENABLE TRIGGER clearance_import_rollback_guard_v1`);

			await guardPool.query(`CREATE TRIGGER clearance_import_rollback_guard_duplicate
				BEFORE INSERT OR UPDATE ON ${table}
				FOR EACH ROW EXECUTE FUNCTION "public"."clearance_import_rollback_guard_v1"(
					'organization', 'organization_id', '', ''
				)`);
			expect((await outbox.planMigration()).pendingSecurityMigrations).toContain("runtime-audit-outbox-v2");
			await guardPool.query(`DROP TRIGGER clearance_import_rollback_guard_duplicate ON ${table}`);

			await guardPool.query(`CREATE OR REPLACE FUNCTION "public"."clearance_import_rollback_guard_v1"()
				RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`);
			expect((await outbox.planMigration()).pendingSecurityMigrations).toContain("runtime-audit-outbox-v2");
			await installRollbackFenceFunction();
			expect((await outbox.planMigration()).pendingSecurityMigrations).toEqual([]);
		} finally {
			await guardPool.end();
			await admin.query(`DROP DATABASE "${databaseName}" WITH (FORCE)`);
		}
	});

	it("commits only with its owner transaction and rejects alteration", async () => {
		if (!available) return;
		const outbox = createRuntimeAuditOutbox(pool, {
			projectId: "project_test",
			environmentId: "environment_test",
			schema,
		});
		const plan = await outbox.planMigration();
		expect(plan.pendingSecurityMigrations).toContain("runtime-audit-outbox-v2");
		await plan.apply();
		await pool.query(`DROP INDEX "${schema}".clearance_runtime_audit_scope_created_id_v2`);
		const repair = await outbox.planMigration();
		expect(repair.pendingSecurityMigrations).toContain("runtime-audit-outbox-v2");
		expect(await repair.compileSql()).toContain("scope_created_id_v2");
		await repair.apply();
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
			metadata: {
				safe: "kept",
				password: "must-not-store",
				email: "person@example.com",
				callback: "https://example.com/callback",
				nested: { token: "must-not-store" },
			},
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
			const serializedMetadata = JSON.stringify(committed.rows[0]?.metadata);
			expect(serializedMetadata).not.toContain("must-not-store");
			expect(serializedMetadata).not.toContain("person@example.com");
			expect(serializedMetadata).not.toContain("https://example.com/callback");

			await client.query("BEGIN");
			await outbox.binding.append(transaction as never, { ...draft, request: { ...draft.request, correlationId: "request_rollback" } });
			await client.query("ROLLBACK");
			const rolledBack = await pool.query(`SELECT count(*)::int AS count FROM "${schema}".clearance_runtime_audit_events WHERE correlation_id='request_rollback'`);
			expect(rolledBack.rows[0]?.count).toBe(0);

			const scopedDatabaseUrl = new URL(baseDatabaseUrl);
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
			expect(tampered.pendingSecurityMigrations).toContain("runtime-audit-outbox-v2");
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

	it("binds webhook enqueue and terminal transitions to the product audit transaction", async () => {
		if (!available) return;
		const outbox = createRuntimeAuditOutbox(pool, {
			projectId: "project_delivery_audit",
			environmentId: "environment_delivery_audit",
			schema,
			prefix: `audit_${randomUUID().slice(0, 8)}`,
		});
		await outbox.applyMigration();
		const prefix = `delivery_audit_${randomUUID().slice(0, 8)}_`;
		const options = { schema, prefix, runtimeAudit: outbox.auditTable };
		await migrateDeliverySchema(pool, options);
		const keyring = createDeliveryKeyring({
			currentKeyId: "current",
			keys: { current: randomBytes(32) },
			currentFingerprintKeyId: "fingerprint-current",
			fingerprintKeys: { "fingerprint-current": randomBytes(32) },
			sourceDedupeKey: randomBytes(32),
		});
		const eventId = `event-${randomUUID()}`;
		const jobId = `job-${randomUUID()}`;
		const now = new Date();
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await enqueueDelivery(createDeliveryTransactionAdapter(client), {
				eventId,
				jobId,
				kind: "webhook.endpoint.test",
				sourceKey: `source-${eventId}`,
				projectId: "project_delivery_audit",
				environmentId: "environment_delivery_audit",
				organizationId: null,
				actorId: "actor_delivery_audit",
				correlationId: "correlation_delivery_audit",
				channel: "webhook",
				destination: "https://example.test/hooks/secret-destination",
				payload: {
					version: 1,
					endpoint: {
						id: "endpoint_delivery_audit",
						url: "https://example.test/hooks/secret-destination",
						signingSecret: "delivery-audit-signing-secret-0123456789",
					},
					event: {
						id: eventId,
						type: "webhook.endpoint.test",
						occurredAt: now.toISOString(),
						context: {
							projectId: "project_delivery_audit",
							environmentId: "environment_delivery_audit",
							organizationId: null,
							actor: "actor_delivery_audit",
							correlationId: "correlation_delivery_audit",
						},
						data: { endpointId: "endpoint_delivery_audit" },
					},
				},
				semanticExpiresAt: new Date(now.getTime() + 60_000),
				now,
			}, keyring, options);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		const store = new DeliveryStore(pool, options);
		const leased = await store.claimNext({ workerId: "delivery-audit-worker", now });
		expect(leased?.id).toBe(jobId);
		await store.complete({
			jobId,
			leaseToken: leased!.leaseToken,
			workerId: leased!.leaseOwner,
			providerStatus: "204",
			providerRequestId: "provider_request_1",
			now: new Date(now.getTime() + 1),
		});
		const events = await pool.query<{
			action: string;
			correlation_id: string;
			subject_id: string;
			metadata: Record<string, unknown>;
		}>(`SELECT action, correlation_id, subject_id, metadata FROM ${outbox.auditTable.qualifiedTable}
			WHERE correlation_id='correlation_delivery_audit' ORDER BY sequence`);
		expect(events.rows.map((event) => event.action)).toEqual([
			"delivery.webhook.queued",
			"delivery.webhook.delivered",
		]);
		expect(events.rows.every((event) => event.subject_id === jobId)).toBe(true);
		expect(JSON.stringify(events.rows)).not.toContain("secret-destination");
		expect(JSON.stringify(events.rows)).not.toContain("signing-secret");
	});
});
