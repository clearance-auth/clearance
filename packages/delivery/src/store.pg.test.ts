import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import {
	createDeliveryTransactionAdapter,
	enqueueDelivery,
	type DeliveryRawTransaction,
	type EnqueueDeliveryInput,
} from "./enqueue.js";
import { createDeliveryKeyring } from "./keyring.js";
import {
	assertDeliverySchemaCurrent,
	deliveryTableNames,
	migrateDeliverySchema,
	qualifiedDeliveryTables,
	quoteIdentifier,
	type DeliverySchemaOptions,
} from "./schema.js";
import { DeliveryStore } from "./store.js";
import { replayDeliveryInExistingTransaction } from "./control.js";
import {
	createWebhookEndpoint,
	createWebhookEndpointInExistingTransaction,
	enqueueWebhookEndpointDeliveryInExistingTransaction,
	enqueueWebhookEndpointTestInExistingTransaction,
	fanoutOrganizationUpdatedWebhookInExistingTransaction,
	inspectWebhookEndpointScoped,
	listWebhookEndpoints,
	previewWebhookEndpointDeletion,
	previewWebhookEndpointSecretRotation,
	previewWebhookEndpointTest,
	rotateWebhookEndpointSecret,
	softDeleteWebhookEndpoint,
	softDeleteWebhookEndpointInExistingTransaction,
	updateWebhookEndpoint,
	updateWebhookEndpointInExistingTransaction,
} from "./webhook-endpoints.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const suffix = `${process.pid}_${randomUUID().slice(0, 8).replace(/-/g, "")}_`;
const mainOptions = { prefix: `delivery_${suffix}` } satisfies DeliverySchemaOptions;
const collisionOptions = { prefix: `delivery_collision_${suffix}` } satisfies DeliverySchemaOptions;
const futureOptions = { prefix: `delivery_future_${suffix}` } satisfies DeliverySchemaOptions;
const driftOptions = { prefix: `delivery_drift_${suffix}` } satisfies DeliverySchemaOptions;
const traceParentDriftOptions = { prefix: `delivery_trace_${suffix}` } satisfies DeliverySchemaOptions;
const endpointConstraintDriftOptions = { prefix: `delivery_epc_${suffix}` } satisfies DeliverySchemaOptions;
const endpointFkDriftOptions = { prefix: `delivery_epfk_${suffix}` } satisfies DeliverySchemaOptions;
const endpointIndexDriftOptions = { prefix: `delivery_epi_${suffix}` } satisfies DeliverySchemaOptions;
const endpointKeyOptions = { prefix: `delivery_endpoint_keys_${suffix}` } satisfies DeliverySchemaOptions;
const rollbackIndexOptions = { prefix: `delivery_rbi_${suffix}` } satisfies DeliverySchemaOptions;
const historyTriggerDriftOptions = { prefix: `delivery_htr_${suffix}` } satisfies DeliverySchemaOptions;
const migrationOptions = {
	prefix: `delivery_migration_${suffix}`,
	legacyFingerprintKeyId: "fingerprint-v2",
} satisfies DeliverySchemaOptions;
const rotationOptions = { prefix: `delivery_rotation_${suffix}` } satisfies DeliverySchemaOptions;

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
	for (const name of [names.attempt, names.job, names.payload, names.event, names.webhookEndpoint, names.worker, names.meta]) {
		await pool.query(`DROP TABLE IF EXISTS ${quoteIdentifier(schema)}.${quoteIdentifier(name)} CASCADE`);
	}
	await pool.query(
		`DROP FUNCTION IF EXISTS ${quoteIdentifier(schema)}.${quoteIdentifier(names.rejectMutationFunction)}()`,
	);
}

function rawTransaction(client: pg.PoolClient): DeliveryRawTransaction {
	return {
		rawTransactionQuery: async <Row extends Record<string, unknown> = Record<string, unknown>>(
			text: string,
			values: readonly unknown[] = [],
		) => {
			const result = await client.query<Row>(text, [...values]);
			return { rows: result.rows, rowCount: result.rowCount };
		},
	};
}

describe.skipIf(!available)("delivery Postgres storage", () => {
	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	const store = new DeliveryStore(pool, mainOptions);
	const keyring = createDeliveryKeyring({
		currentKeyId: "current",
		keys: { current: randomBytes(32), previous: randomBytes(32) },
		currentFingerprintKeyId: "fingerprint-current",
		fingerprintKeys: {
			"fingerprint-current": randomBytes(32),
			"fingerprint-previous": randomBytes(32),
		},
		sourceDedupeKey: randomBytes(32),
	});
	const start = new Date(Date.now() + 5_000);
	const expiry = new Date(start.getTime() + 60 * 60_000);

	afterAll(async () => {
		for (const options of [
			mainOptions, collisionOptions, futureOptions, driftOptions, endpointConstraintDriftOptions,
			traceParentDriftOptions,
			endpointFkDriftOptions,
			endpointIndexDriftOptions, endpointKeyOptions, rollbackIndexOptions, migrationOptions,
			historyTriggerDriftOptions,
			rotationOptions,
		]) {
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
			`UPDATE ${future.meta} SET value='6'::jsonb WHERE key='schema_version'`,
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

		await migrateDeliverySchema(pool, traceParentDriftOptions);
		const traceParentTables = qualifiedDeliveryTables(traceParentDriftOptions);
		await expect(pool.query(
			`INSERT INTO ${traceParentTables.event}
			 (id, kind, source_fingerprint, source_fingerprint_key_id, source_dedupe_fingerprint,
			  source_dedupe_version, project_id, environment_id, destination_fingerprint,
			  destination_fingerprint_key_id, created_at, semantic_expires_at, trace_parent)
			 VALUES ('invalid-trace-parent','password.reset',$1,'fingerprint-current',$2,2,
			 'project-1','env-1',$3,'fingerprint-current',$4,$5,$6)`,
			[
				"a".repeat(64), "b".repeat(64), "c".repeat(64), start, expiry,
				"00-00000000000000000000000000000000-1234567890abcdef-01",
			],
		)).rejects.toThrow();
		await pool.query(
			`ALTER TABLE ${traceParentTables.event}
			 DROP CONSTRAINT ${quoteIdentifier(`${traceParentTables.names.event}_trace_parent_check`)},
			 ADD CONSTRAINT ${quoteIdentifier(`${traceParentTables.names.event}_trace_parent_check`)}
			 CHECK (trace_parent IS NULL OR trace_parent ~ '^00-')`,
		);
		await expect(assertDeliverySchemaCurrent(pool, traceParentDriftOptions))
			.rejects.toMatchObject({ code: "DELIVERY_SCHEMA_DRIFT" });
	});

	it("fails closed when endpoint privacy constraints or URL uniqueness drift", async () => {
		await migrateDeliverySchema(pool, endpointConstraintDriftOptions);
		const constraintTables = qualifiedDeliveryTables(endpointConstraintDriftOptions);
		const constraint = (await pool.query<{ conname: string }>(
			`SELECT conname FROM pg_constraint
			 WHERE conrelid=$1::regclass
			   AND pg_get_constraintdef(oid,true) ILIKE '%last_test_job_id%'`,
			[constraintTables.webhookEndpoint],
		)).rows[0]?.conname;
		expect(constraint).toBeTruthy();
		await pool.query(
			`ALTER TABLE ${constraintTables.webhookEndpoint} DROP CONSTRAINT ${quoteIdentifier(constraint!)}`,
		);
		await expect(assertDeliverySchemaCurrent(pool, endpointConstraintDriftOptions))
			.rejects.toMatchObject({ code: "DELIVERY_SCHEMA_DRIFT" });

		await migrateDeliverySchema(pool, endpointIndexDriftOptions);
		const indexTables = qualifiedDeliveryTables(endpointIndexDriftOptions);
		const index = (await pool.query<{ indexname: string }>(
			`SELECT indexname FROM pg_indexes WHERE schemaname=$1 AND tablename=$2
			   AND indexdef ILIKE '%url_fingerprint_key_id%'`,
			[indexTables.schema, indexTables.names.webhookEndpoint],
		)).rows[0]?.indexname;
		expect(index).toBeTruthy();
		await pool.query(
			`DROP INDEX ${quoteIdentifier(indexTables.schema)}.${quoteIdentifier(index!)}`,
		);
		await pool.query(
			`CREATE INDEX ${quoteIdentifier(index!)} ON ${indexTables.webhookEndpoint} (project_id)
			 WHERE status <> 'deleted'`,
		);
		await expect(assertDeliverySchemaCurrent(pool, endpointIndexDriftOptions))
			.rejects.toMatchObject({ code: "DELIVERY_SCHEMA_DRIFT" });
	});

	it("rejects a hostile substituted endpoint provenance foreign key", async () => {
		await migrateDeliverySchema(pool, endpointFkDriftOptions);
		const tables = qualifiedDeliveryTables(endpointFkDriftOptions);
		const constraint = (await pool.query<{ conname: string }>(
			`SELECT conname FROM pg_constraint
			 WHERE conrelid=$1::regclass AND contype='f'
			   AND pg_get_constraintdef(oid,true) ILIKE '%webhook_endpoint_id%'`,
			[tables.event],
		)).rows[0]?.conname;
		expect(constraint).toBeTruthy();
		await pool.query(
			`ALTER TABLE ${tables.event} DROP CONSTRAINT ${quoteIdentifier(constraint!)},
			 ADD FOREIGN KEY (webhook_endpoint_id) REFERENCES ${tables.webhookEndpoint}(id) ON DELETE CASCADE`,
		);
		await expect(assertDeliverySchemaCurrent(pool, endpointFkDriftOptions))
			.rejects.toMatchObject({ code: "DELIVERY_SCHEMA_DRIFT" });
	});

	it("requires the exact immutable-history trigger and permits separately named rollback fences", async () => {
		await migrateDeliverySchema(pool, historyTriggerDriftOptions);
		const tables = qualifiedDeliveryTables(historyTriggerDriftOptions);
		await pool.query(
			`DROP TRIGGER ${quoteIdentifier(`${tables.names.event}_immutable`)} ON ${tables.event}`,
		);
		await pool.query(
			`CREATE TRIGGER ${quoteIdentifier("clearance_import_rollback_guard_v1")}
			 BEFORE UPDATE OR DELETE ON ${tables.event}
			 FOR EACH ROW EXECUTE FUNCTION ${quoteIdentifier(tables.schema)}.${quoteIdentifier(tables.names.rejectMutationFunction)}()`,
		);

		await expect(assertDeliverySchemaCurrent(pool, historyTriggerDriftOptions))
			.rejects.toMatchObject({ code: "DELIVERY_SCHEMA_DRIFT" });
		await pool.query(
			`CREATE TRIGGER ${quoteIdentifier(`${tables.names.event}_immutable`)}
			 BEFORE UPDATE OR DELETE ON ${tables.event}
			 FOR EACH ROW EXECUTE FUNCTION ${quoteIdentifier(tables.schema)}.${quoteIdentifier(tables.names.rejectMutationFunction)}()`,
		);
		await expect(assertDeliverySchemaCurrent(pool, historyTriggerDriftOptions))
			.resolves.toMatchObject({ version: 5 });
		await pool.query(
			`ALTER TABLE ${tables.event} ENABLE REPLICA TRIGGER ${quoteIdentifier(`${tables.names.event}_immutable`)}`,
		);
		await expect(assertDeliverySchemaCurrent(pool, historyTriggerDriftOptions))
			.rejects.toMatchObject({ code: "DELIVERY_SCHEMA_DRIFT" });
		await pool.query(
			`ALTER TABLE ${tables.event} ENABLE TRIGGER ${quoteIdentifier(`${tables.names.event}_immutable`)}`,
		);
		const shadowFunction = `${tables.names.rejectMutationFunction}_shadow`;
		await pool.query(
			`CREATE FUNCTION ${quoteIdentifier(tables.schema)}.${quoteIdentifier(shadowFunction)}() RETURNS trigger
			 LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`,
		);
		await pool.query(
			`DROP TRIGGER ${quoteIdentifier(`${tables.names.event}_immutable`)} ON ${tables.event}`,
		);
		await pool.query(
			`CREATE TRIGGER ${quoteIdentifier(`${tables.names.event}_immutable`)}
			 BEFORE UPDATE OR DELETE ON ${tables.event}
			 FOR EACH ROW EXECUTE FUNCTION ${quoteIdentifier(tables.schema)}.${quoteIdentifier(shadowFunction)}()`,
		);
		await expect(assertDeliverySchemaCurrent(pool, historyTriggerDriftOptions))
			.rejects.toMatchObject({ code: "DELIVERY_SCHEMA_DRIFT" });
		await pool.query(
			`DROP TRIGGER ${quoteIdentifier(`${tables.names.event}_immutable`)} ON ${tables.event}`,
		);
		await pool.query(
			`CREATE TRIGGER ${quoteIdentifier(`${tables.names.event}_immutable`)}
			 BEFORE UPDATE OR DELETE ON ${tables.event}
			 FOR EACH ROW EXECUTE FUNCTION ${quoteIdentifier(tables.schema)}.${quoteIdentifier(tables.names.rejectMutationFunction)}()`,
		);
		await pool.query(
			`DROP FUNCTION ${quoteIdentifier(tables.schema)}.${quoteIdentifier(shadowFunction)}()`,
		);
		await expect(assertDeliverySchemaCurrent(pool, historyTriggerDriftOptions))
			.resolves.toMatchObject({ version: 5 });
	});

	it("transactionally upgrades owned v4 storage with the nullable private trace carrier", async () => {
		await migrateDeliverySchema(pool, migrationOptions);
		const tables = qualifiedDeliveryTables(migrationOptions);
		await pool.query(`ALTER TABLE ${tables.event} DROP COLUMN trace_parent`);
		for (const name of [
			tables.names.meta, tables.names.webhookEndpoint, tables.names.event, tables.names.payload,
			tables.names.job, tables.names.attempt, tables.names.worker,
		]) {
			await pool.query(`COMMENT ON TABLE ${quoteIdentifier(tables.schema)}.${quoteIdentifier(name)} IS 'clearance.delivery:v4'`);
		}
		await pool.query(`COMMENT ON FUNCTION ${quoteIdentifier(tables.schema)}.${quoteIdentifier(tables.names.rejectMutationFunction)}() IS 'clearance.delivery:v4'`);
		await pool.query(`UPDATE ${tables.meta} SET value='4'::jsonb WHERE key='schema_version'`);
		const v5 = await migrateDeliverySchema(pool, migrationOptions);
		expect(v5.version).toBe(5);
		expect((await pool.query(`SELECT trace_parent FROM ${tables.event}`)).rows).toEqual([]);

		// Continue from a deliberately reconstructed owned v1 schema to ensure all
		// historical forward paths still finish at the same v5 authority.
		await pool.query(
			`ALTER TABLE ${tables.job}
			 DROP CONSTRAINT ${quoteIdentifier(`${tables.names.job}_provider_check`)},
			 DROP COLUMN provider_accepted_at,
			 DROP COLUMN provider_status,
			 DROP COLUMN provider_request_id,
			 DROP COLUMN destination_fingerprint_key_id CASCADE,
			 ADD UNIQUE (event_id, channel, destination_fingerprint)`,
		);
		await pool.query(
			`ALTER TABLE ${tables.event}
			 DROP COLUMN webhook_endpoint_id,
			 DROP COLUMN trace_parent,
			 DROP COLUMN source_fingerprint_key_id,
			 DROP COLUMN source_dedupe_fingerprint CASCADE,
			 DROP COLUMN source_dedupe_version,
			 DROP COLUMN destination_fingerprint_key_id,
			 ADD UNIQUE (source_fingerprint)`,
		);
		await pool.query(`DROP TABLE ${tables.webhookEndpoint}`);
		for (const name of [tables.names.meta, tables.names.event, tables.names.payload, tables.names.job, tables.names.attempt, tables.names.worker]) {
			await pool.query(`COMMENT ON TABLE ${quoteIdentifier(tables.schema)}.${quoteIdentifier(name)} IS 'clearance.delivery:v1'`);
		}
		await pool.query(`COMMENT ON FUNCTION ${quoteIdentifier(tables.schema)}.${quoteIdentifier(tables.names.rejectMutationFunction)}() IS 'clearance.delivery:v1'`);
		await pool.query(`UPDATE ${tables.meta} SET value='1'::jsonb WHERE key='schema_version'`);
		await pool.query(
			`INSERT INTO ${tables.event}
			 (id,kind,source_fingerprint,project_id,environment_id,destination_fingerprint,created_at,semantic_expires_at)
			 VALUES ('v1-event','password.reset',$1,'project-1','env-1',$2,$3,$4)`,
			["a".repeat(64), "b".repeat(64), start, expiry],
		);
		await pool.query(
			`INSERT INTO ${tables.job}
			 (id,event_id,channel,destination_fingerprint,state,available_at,semantic_expires_at,max_attempts,created_at,updated_at)
			 VALUES ('v1-job','v1-event','email',$1,'queued',$2,$3,3,$2,$2)`,
			["b".repeat(64), start, expiry],
		);

		await expect(migrateDeliverySchema(pool, {
			prefix: migrationOptions.prefix,
		})).rejects.toMatchObject({
			code: "DELIVERY_FINGERPRINT_MIGRATION_KEY_ID_REQUIRED",
		});
		const migrated = await migrateDeliverySchema(pool, migrationOptions);
		expect(migrated.version).toBe(5);
		expect((await pool.query(
			`SELECT j.id, j.state, j.provider_accepted_at, j.destination_fingerprint_key_id,
			 e.source_fingerprint_key_id, e.source_dedupe_version, e.trace_parent
			 FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id WHERE j.id='v1-job'`,
		)).rows).toEqual([
			{
				id: "v1-job",
				state: "queued",
				provider_accepted_at: null,
				destination_fingerprint_key_id: "fingerprint-v2",
				source_fingerprint_key_id: "fingerprint-v2",
				source_dedupe_version: 1,
				trace_parent: null,
			},
		]);
		expect((await pool.query(`SELECT value FROM ${tables.meta} WHERE key='schema_version'`)).rows[0].value).toBe(5);

		const carrierNow = new Date(start.getTime() - 1_000);
		const carrierStore = new DeliveryStore(pool, migrationOptions);
		await pool.query(
			`INSERT INTO ${tables.event}
			 (id, kind, source_fingerprint, source_fingerprint_key_id, source_dedupe_fingerprint,
			  source_dedupe_version, project_id, environment_id, destination_fingerprint,
			  destination_fingerprint_key_id, created_at, semantic_expires_at, trace_parent)
			 VALUES ('trace-event','password.reset',$1,'fingerprint-v2',$2,2,'project-1','env-1',$3,
			 'fingerprint-v2',$4,$5,$6)`,
			["c".repeat(64), "d".repeat(64), "e".repeat(64), carrierNow, expiry,
				"00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"],
		);
		await pool.query(
			`INSERT INTO ${tables.job}
			 (id, event_id, channel, destination_fingerprint, destination_fingerprint_key_id, state,
			  available_at, semantic_expires_at, max_attempts, created_at, updated_at)
			 VALUES ('trace-job','trace-event','email',$1,'fingerprint-v2','queued',$2,$3,3,$2,$2)`,
			["e".repeat(64), carrierNow, expiry],
		);
		const lease = await carrierStore.claimNext({ workerId: "trace-worker", now: carrierNow });
		expect(lease?.traceCarrier?.traceparent)
			.toBe("00-1234567890abcdef1234567890abcdef-1234567890abcdef-01");
		expect(JSON.stringify(await carrierStore.inspectJob("trace-job")))
			.not.toContain("1234567890abcdef1234567890abcdef");
	});

	it("recreates rollback lookup indexes with their exact catalog definitions", async () => {
		await migrateDeliverySchema(pool, rollbackIndexOptions);
		const tables = qualifiedDeliveryTables(rollbackIndexOptions);
		const indexDefinitions = await pool.query<{ indexname: string; indexdef: string }>(
			`SELECT indexname, indexdef FROM pg_indexes
			 WHERE schemaname=$1 AND tablename=$2
			   AND (
				indexdef LIKE '%(project_id, environment_id, organization_id)%'
				OR indexdef LIKE '%(project_id, environment_id, actor_id)%'
			   )`,
			[tables.schema, tables.names.event],
		);
		expect(indexDefinitions.rows).toHaveLength(2);
		for (const { indexname } of indexDefinitions.rows) {
			await pool.query(`DROP INDEX ${quoteIdentifier(tables.schema)}.${quoteIdentifier(indexname)}`);
		}

		await migrateDeliverySchema(pool, rollbackIndexOptions);
		const repaired = await pool.query<{ indexdef: string }>(
			`SELECT indexdef FROM pg_indexes WHERE schemaname=$1 AND tablename=$2`,
			[tables.schema, tables.names.event],
		);
		expect(repaired.rows.map((row) => row.indexdef)).toEqual(expect.arrayContaining([
			expect.stringContaining("(project_id, environment_id, organization_id)"),
			expect.stringContaining("(project_id, environment_id, actor_id)"),
		]));
	});

	it("rolls enqueue back atomically and stores no plaintext", async () => {
		await store.migrate();
		const mainTables = qualifiedDeliveryTables(mainOptions);
		await pool.query(
			`DROP INDEX ${quoteIdentifier(mainTables.schema)}.${quoteIdentifier(`${mainTables.names.event}_scope_created_idx`)}`,
		);
		expect((await store.migrate()).version).toBe(5);
		expect((await pool.query<{ indexdef: string }>(
			`SELECT indexdef FROM pg_indexes WHERE schemaname=$1 AND indexname=$2`,
			[mainTables.schema, `${mainTables.names.event}_scope_created_idx`],
		)).rows[0]?.indexdef).toContain("(project_id, environment_id, created_at)");
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

	it("stores scoped webhook endpoints with one-time secrets and crypto-erasing lifecycle", async () => {
		await store.migrate();
		const scope = { projectId: "project-webhooks", environmentId: "environment-webhooks" };
		const rollbackClient = await pool.connect();
		try {
			await rollbackClient.query("BEGIN");
			await createWebhookEndpointInExistingTransaction(rawTransaction(rollbackClient), {
				...scope,
				id: "endpoint-rolled-back",
				name: "Rolled back",
				url: "https://rolled-back.example.test/events",
				now: start,
			}, keyring, mainOptions);
			await rollbackClient.query("ROLLBACK");
		} finally {
			rollbackClient.release();
		}
		expect(await inspectWebhookEndpointScoped(pool, {
			...scope, endpointId: "endpoint-rolled-back",
		}, keyring, mainOptions)).toBeNull();
		const created = await createWebhookEndpoint(pool, {
			...scope,
			id: "endpoint-1",
			name: "Primary",
			url: "https://hooks.example.test/events",
			now: start,
		}, keyring, mainOptions);
		expect(created.endpoint).toMatchObject({
			status: "disabled",
			url: "https://hooks.example.test/events",
			resourceVersion: 1,
			secretVersion: 1,
		});
		expect(created.signingSecret).toMatch(/^whsec_/);
		const publicJson = JSON.stringify(created.endpoint);
		expect(publicJson).not.toContain(created.signingSecret);
		expect(publicJson).not.toContain("envelope");
		expect(publicJson).not.toContain("configKeyId");
		await expect(createWebhookEndpoint(pool, {
			...scope,
			id: "endpoint-port-rejected",
			name: "Port rejected",
			url: "https://hooks.example.test:8443/events",
			now: start,
		}, keyring, mainOptions)).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_URL_INVALID" });
		await expect(updateWebhookEndpoint(pool, {
			...scope,
			endpointId: "endpoint-1",
			expectedVersion: 1,
			url: "https://hooks.example.test:8443/events",
			now: start,
		}, keyring, mainOptions)).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_URL_INVALID" });
		await expect(createWebhookEndpoint(pool, {
			...scope,
			id: "endpoint-duplicate",
			name: "Duplicate",
			url: "https://hooks.example.test/events",
			now: start,
		}, keyring, mainOptions)).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_DUPLICATE" });

		const activated = await updateWebhookEndpoint(pool, {
			...scope, endpointId: "endpoint-1", expectedVersion: 1, status: "active", now: start,
		}, keyring, mainOptions);
		expect(activated).toMatchObject({ status: "active", resourceVersion: 2 });
		await expect(updateWebhookEndpoint(pool, {
			...scope, endpointId: "endpoint-1", expectedVersion: 1, name: "Stale", now: start,
		}, keyring, mainOptions)).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_VERSION_CONFLICT" });
		expect(await previewWebhookEndpointSecretRotation(pool, {
			...scope, endpointId: "endpoint-1", expectedVersion: 2,
		}, keyring, mainOptions)).toMatchObject({
			action: "rotate",
			expectedVersion: 2,
			nextResourceVersion: 3,
			nextSecretVersion: 2,
			secretGenerated: false,
			endpoint: { resourceVersion: 2, secretVersion: 1 },
		});
		const rotated = await rotateWebhookEndpointSecret(pool, {
			...scope, endpointId: "endpoint-1", expectedVersion: 2, now: start,
		}, keyring, mainOptions);
		expect(rotated?.endpoint).toMatchObject({ resourceVersion: 3, secretVersion: 2 });
		expect(rotated?.signingSecret).not.toBe(created.signingSecret);
		const urlChanged = await updateWebhookEndpoint(pool, {
			...scope,
			endpointId: "endpoint-1",
			expectedVersion: 3,
			url: "https://hooks.example.test/v2",
			now: start,
		}, keyring, mainOptions);
		expect(urlChanged).toMatchObject({ status: "disabled", resourceVersion: 4 });
		const reactivated = await updateWebhookEndpoint(pool, {
			...scope,
			endpointId: "endpoint-1",
			expectedVersion: 4,
			status: "active",
			now: start,
		}, keyring, mainOptions);
		expect(reactivated).toMatchObject({ status: "active", resourceVersion: 5 });
		expect(await previewWebhookEndpointTest(pool, {
			...scope, endpointId: "endpoint-1", expectedVersion: 5,
		}, keyring, mainOptions)).toMatchObject({
			action: "test",
			expectedVersion: 5,
			nextResourceVersion: 6,
			createsDelivery: true,
			endpoint: { resourceVersion: 5 },
		});
		const testClient = await pool.connect();
		let tested: Awaited<ReturnType<typeof enqueueWebhookEndpointTestInExistingTransaction>>;
		try {
			await testClient.query("BEGIN");
			tested = await enqueueWebhookEndpointTestInExistingTransaction(
				rawTransaction(testClient),
				{ ...scope, endpointId: "endpoint-1", expectedVersion: 5, now: start },
				keyring,
				mainOptions,
			);
			await enqueueWebhookEndpointDeliveryInExistingTransaction(rawTransaction(testClient), {
				eventId: "event-delete-queued",
				jobId: "job-delete-queued",
				endpointId: "endpoint-1",
				expectedVersion: 6,
				eventKind: "organization.updated",
				sourceKey: "endpoint-delete-queued",
				...scope,
				organizationId: "organization-delete",
				event: {
					occurredAt: start.toISOString(),
					data: {
						organization: {
							id: "organization-delete",
							name: "Delete Org",
							slug: "delete-org",
							status: "active",
						},
						previous: { name: "Old Delete Org", slug: "old-delete-org" },
					},
				},
				semanticExpiresAt: expiry,
				now: start,
			}, keyring, mainOptions);
			await testClient.query("COMMIT");
		} catch (error) {
			await testClient.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			testClient.release();
		}
		expect(tested).toMatchObject({
			endpoint: { resourceVersion: 6 },
			delivery: { kind: "webhook.endpoint.test", state: "queued" },
		});
		const tables = qualifiedDeliveryTables(mainOptions);
		const testLink = (await pool.query(
			`SELECT e.id event_id,e.kind,e.webhook_endpoint_id,j.id job_id
			 FROM ${tables.event} e JOIN ${tables.job} j ON j.event_id=e.id
			 WHERE j.id=$1`,
			[tested!.delivery.jobId],
		)).rows[0];
		expect(testLink).toEqual({
			event_id: tested!.delivery.eventId,
			kind: "webhook.endpoint.test",
			webhook_endpoint_id: "endpoint-1",
			job_id: tested!.delivery.jobId,
		});
		await pool.query(
			`UPDATE ${tables.job} SET state='leased',lease_token='lease-test',lease_owner='worker-test',
			 lease_expires_at=$2,updated_at=$1 WHERE id=$3`,
			[start, new Date(start.getTime() + 60_000), tested!.delivery.jobId],
		);
		expect(await previewWebhookEndpointDeletion(pool, {
			...scope, endpointId: "endpoint-1", expectedVersion: 6,
		}, keyring, mainOptions)).toMatchObject({
			action: "delete",
			expectedVersion: 6,
			nextResourceVersion: 7,
			erasedPayloads: 2,
			jobs: {
				queuedOrRetryCancelled: 1,
				leasedCancellationRequested: 1,
				leasedDeliveryOutcomeAmbiguous: true,
			},
			endpoint: { resourceVersion: 6, status: "active" },
		});
		const deleteClient = await pool.connect();
		let deleted: Awaited<ReturnType<typeof softDeleteWebhookEndpoint>>;
		try {
			await deleteClient.query("BEGIN");
			deleted = await softDeleteWebhookEndpointInExistingTransaction(
				rawTransaction(deleteClient),
				{ ...scope, endpointId: "endpoint-1", expectedVersion: 6, now: start },
				mainOptions,
			);
			await deleteClient.query("COMMIT");
		} catch (error) {
			await deleteClient.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			deleteClient.release();
		}
		expect(deleted).toMatchObject({
			endpoint: { status: "deleted", resourceVersion: 7, urlFingerprint: null },
			erasedPayloads: 2,
			jobs: {
				queuedOrRetryCancelled: 1,
				leasedCancellationRequested: 1,
				leasedDeliveryOutcomeAmbiguous: true,
			},
		});
		expect((await pool.query(
			`SELECT j.id,j.state,j.cancel_requested,e.webhook_endpoint_id
			 FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id
			 WHERE j.id = ANY($1::text[]) ORDER BY j.id`,
			[[tested!.delivery.jobId, "job-delete-queued"]],
		)).rows).toEqual(expect.arrayContaining([
			{ id: "job-delete-queued", state: "cancelled", cancel_requested: false, webhook_endpoint_id: "endpoint-1" },
			{ id: tested!.delivery.jobId, state: "leased", cancel_requested: true, webhook_endpoint_id: "endpoint-1" },
		]));
		expect((await pool.query(
			`SELECT count(*)::int count FROM ${tables.payload} p
			 JOIN ${tables.event} e ON e.id=p.event_id WHERE e.webhook_endpoint_id='endpoint-1'`,
		)).rows[0]?.count).toBe(0);
		expect(await inspectWebhookEndpointScoped(pool, {
			...scope, endpointId: "endpoint-1",
		}, keyring, mainOptions)).toBeNull();
		expect(await inspectWebhookEndpointScoped(pool, {
			...scope, endpointId: "endpoint-1", includeDeleted: true,
		}, keyring, mainOptions)).toMatchObject({ status: "deleted", url: null, secretFingerprint: null });
		expect((await pool.query(
			`SELECT config_key_id,config_envelope,url_fingerprint_key_id,url_fingerprint
			 FROM ${tables.webhookEndpoint} WHERE id='endpoint-1'`,
		)).rows[0]).toEqual({
			config_key_id: null, config_envelope: null,
			url_fingerprint_key_id: null, url_fingerprint: null,
		});
	});

	it("keeps managed endpoint selection and enqueue atomic across lifecycle races", async () => {
		await store.migrate();
		const scope = { projectId: "project-webhook-routing", environmentId: "environment-webhook-routing" };
		const created = await createWebhookEndpoint(pool, {
			...scope, id: "endpoint-routing", name: "Routing endpoint",
			url: "https://routing.example.test/events", now: start,
		}, keyring, mainOptions);
		await updateWebhookEndpoint(pool, {
			...scope, endpointId: created.endpoint.id, expectedVersion: 1,
			status: "active", now: start,
		}, keyring, mainOptions);
		const forgedClient = await pool.connect();
		try {
			await forgedClient.query("BEGIN");
			await expect(enqueueDelivery(
				createDeliveryTransactionAdapter(forgedClient),
				{
					eventId: "event-forged-managed",
					kind: "organization.updated",
					sourceKey: "forged-managed",
					...scope,
					channel: "webhook",
					destination: "https://routing.example.test/events",
					payload: {},
					semanticExpiresAt: expiry,
					webhookEndpointId: created.endpoint.id,
				} as EnqueueDeliveryInput,
				keyring,
				mainOptions,
			)).rejects.toMatchObject({ code: "DELIVERY_WEBHOOK_ENDPOINT_AUTHORITY_REQUIRED" });
			await forgedClient.query("ROLLBACK");
		} finally {
			forgedClient.release();
		}

		const deliveryInput = {
			...scope,
			endpointId: created.endpoint.id,
			expectedVersion: 2,
			eventKind: "organization.updated" as const,
			sourceKey: "atomic-routing",
			event: {
				occurredAt: start.toISOString(),
				data: {
					organization: {
						id: "org-routing", name: "Routing Org", slug: "routing-org", status: "active",
					},
					previous: { name: "Old Routing Org", slug: "old-routing-org" },
				},
			},
			organizationId: "org-routing",
			semanticExpiresAt: expiry,
			now: start,
		};
		const wrongScopeClient = await pool.connect();
		try {
			await wrongScopeClient.query("BEGIN");
			expect(await enqueueWebhookEndpointDeliveryInExistingTransaction(
				rawTransaction(wrongScopeClient),
				{ ...deliveryInput, projectId: "wrong-project", sourceKey: "wrong-scope" },
				keyring,
				mainOptions,
			)).toBeNull();
			await wrongScopeClient.query("COMMIT");
		} finally {
			wrongScopeClient.release();
		}

		const staleClient = await pool.connect();
		try {
			await staleClient.query("BEGIN");
			await expect(enqueueWebhookEndpointDeliveryInExistingTransaction(
				rawTransaction(staleClient),
				{ ...deliveryInput, expectedVersion: 1, sourceKey: "stale-version" },
				keyring,
				mainOptions,
			)).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_VERSION_CONFLICT" });
			await staleClient.query("ROLLBACK");
		} finally {
			staleClient.release();
		}

		const enqueueClient = await pool.connect();
		let enqueued: Awaited<ReturnType<typeof enqueueWebhookEndpointDeliveryInExistingTransaction>>;
		try {
			await enqueueClient.query("BEGIN");
			enqueued = await enqueueWebhookEndpointDeliveryInExistingTransaction(
				rawTransaction(enqueueClient), deliveryInput, keyring, mainOptions,
			);
			expect(enqueued).toMatchObject({
				endpoint: { id: "endpoint-routing", resourceVersion: 2 },
				delivery: { kind: "organization.updated", state: "queued" },
			});

			for (const action of ["update", "delete"] as const) {
				const contender = await pool.connect();
				try {
					await contender.query("BEGIN");
					await contender.query("SET LOCAL lock_timeout='100ms'");
					const operation = action === "update"
						? updateWebhookEndpointInExistingTransaction(
							rawTransaction(contender),
							{ ...scope, endpointId: created.endpoint.id, expectedVersion: 2, name: "Raced", now: start },
							keyring,
							mainOptions,
						)
						: softDeleteWebhookEndpointInExistingTransaction(
							rawTransaction(contender),
							{ ...scope, endpointId: created.endpoint.id, expectedVersion: 2, now: start },
							mainOptions,
						);
					await expect(operation).rejects.toMatchObject({ code: "55P03" });
					await contender.query("ROLLBACK");
				} finally {
					contender.release();
				}
			}
			await enqueueClient.query("COMMIT");
		} catch (error) {
			await enqueueClient.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			enqueueClient.release();
		}

		const tables = qualifiedDeliveryTables(mainOptions);
		const persisted = JSON.stringify((await pool.query(
			`SELECT e.*,j.*,p.envelope FROM ${tables.event} e
			 JOIN ${tables.job} j ON j.event_id=e.id
			 JOIN ${tables.payload} p ON p.event_id=e.id WHERE j.id=$1`,
			[enqueued!.delivery.jobId],
		)).rows);
		expect(persisted).not.toContain("routing.example.test");
		expect(persisted).not.toContain(created.signingSecret);
		expect((await updateWebhookEndpoint(pool, {
			...scope, endpointId: created.endpoint.id, expectedVersion: 2,
			name: "Routing endpoint updated", now: start,
		}, keyring, mainOptions))?.resourceVersion).toBe(3);
		expect((await store.cancel(enqueued!.delivery.jobId, start))?.state).toBe("cancelled");
		expect((await updateWebhookEndpoint(pool, {
			...scope, endpointId: created.endpoint.id, expectedVersion: 3,
			status: "disabled", now: start,
		}, keyring, mainOptions))?.resourceVersion).toBe(4);
		const replayClient = await pool.connect();
		try {
			await replayClient.query("BEGIN");
			await expect(replayDeliveryInExistingTransaction(
				rawTransaction(replayClient),
				{ ...scope, jobId: enqueued!.delivery.jobId, now: start },
				keyring,
				mainOptions,
			)).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_NOT_ACTIVE" });
		} finally {
			await replayClient.query("ROLLBACK").catch(() => undefined);
			replayClient.release();
		}
	});

	it("fans out the complete active subscription set deterministically and atomically", async () => {
		await store.migrate();
		const scope = { projectId: "project-webhook-fanout", environmentId: "environment-webhook-fanout" };
		for (const id of ["endpoint-fanout-b", "endpoint-fanout-a", "endpoint-fanout-disabled"]) {
			await createWebhookEndpoint(pool, {
				...scope, id, name: id, url: `https://${id}.example.test/events`, now: start,
			}, keyring, mainOptions);
			if (id !== "endpoint-fanout-disabled") {
				await updateWebhookEndpoint(pool, {
					...scope, endpointId: id, expectedVersion: 1, status: "active", now: start,
				}, keyring, mainOptions);
			}
		}
		const event = {
			occurredAt: start.toISOString(),
			data: {
				organization: { id: "org-fanout", name: "Fanout Org", slug: "fanout-org", status: "active" },
				previous: { name: "Old Fanout Org", slug: "old-fanout-org" },
			},
		};
		const transactFanout = async (sourceKey: string, candidateEvent: typeof event) => {
			const client = await pool.connect();
			try {
				await client.query("BEGIN");
				const result = await fanoutOrganizationUpdatedWebhookInExistingTransaction(
					rawTransaction(client),
					{
						...scope, sourceKey, event: candidateEvent,
						organizationId: "org-fanout", semanticExpiresAt: expiry, now: start,
					},
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
		};

		const deliveries = await transactFanout("organization-update-1", event);
		expect(deliveries.map((entry) => entry.endpoint.id)).toEqual([
			"endpoint-fanout-a", "endpoint-fanout-b",
		]);
		const tables = qualifiedDeliveryTables(mainOptions);
		const count = async () => Number((await pool.query(
			`SELECT count(*) count FROM ${tables.event}
			 WHERE project_id=$1 AND environment_id=$2 AND organization_id='org-fanout'`,
			[scope.projectId, scope.environmentId],
		)).rows[0]?.count);
		expect(await count()).toBe(2);
		await expect(transactFanout("organization-update-1", event))
			.rejects.toMatchObject({ code: "DELIVERY_DUPLICATE" });
		expect(await count()).toBe(2);
		const poison = {
			...event,
			data: { ...event.data, previous: { ...event.data.previous, extra: "poison" } },
		} as unknown as typeof event;
		await expect(transactFanout("organization-update-poison", poison))
			.rejects.toMatchObject({ code: "WEBHOOK_PAYLOAD_INVALID" });
		expect(await count()).toBe(2);

		const emptyClient = await pool.connect();
		try {
			await emptyClient.query("BEGIN");
			expect(await fanoutOrganizationUpdatedWebhookInExistingTransaction(
				rawTransaction(emptyClient),
				{
					projectId: "project-with-no-endpoints", environmentId: "environment-with-no-endpoints",
					sourceKey: "empty", event, organizationId: "org-fanout",
					semanticExpiresAt: expiry, now: start,
				},
				keyring,
				mainOptions,
			)).toEqual([]);
			await emptyClient.query("COMMIT");
		} finally {
			emptyClient.release();
		}
		await Promise.all(deliveries.map((entry) => store.cancel(entry.delivery.jobId, start)));
	});

	it("applies caller quota policy to managed endpoint delivery, fanout, and tests", async () => {
		await store.migrate();
		const scope = { projectId: "project-webhook-quota", environmentId: "environment-webhook-quota" };
		const created = await createWebhookEndpoint(pool, {
			...scope,
			id: "endpoint-quota",
			name: "Quota endpoint",
			url: "https://quota.example.test/events",
			now: start,
		}, keyring, mainOptions);
		await updateWebhookEndpoint(pool, {
			...scope,
			endpointId: created.endpoint.id,
			expectedVersion: 1,
			status: "active",
			now: start,
		}, keyring, mainOptions);
		await enqueue("event-webhook-quota-seed", "job-webhook-quota-seed", "webhook-quota-seed", expiry, {
			...scope,
			now: start,
		});
		const quota = {
			maxActive: 1,
			maxBacklog: 10,
			maxEnqueuesPerWindow: 10,
			windowMs: 60_000,
		};
		const event = {
			occurredAt: start.toISOString(),
			data: {
				organization: { id: "org-quota", name: "Quota Org", slug: "quota-org", status: "active" },
				previous: { name: "Old Quota Org", slug: "old-quota-org" },
			},
		};
		const operations = [
			(transaction: DeliveryRawTransaction) => enqueueWebhookEndpointDeliveryInExistingTransaction(
				transaction,
				{
					...scope,
					endpointId: created.endpoint.id,
					expectedVersion: 2,
					eventKind: "organization.updated",
					sourceKey: "webhook-quota-direct",
					event,
					organizationId: "org-quota",
					semanticExpiresAt: expiry,
					quota,
					now: start,
				},
				keyring,
				mainOptions,
			),
			(transaction: DeliveryRawTransaction) => fanoutOrganizationUpdatedWebhookInExistingTransaction(
				transaction,
				{
					...scope,
					sourceKey: "webhook-quota-fanout",
					event,
					organizationId: "org-quota",
					semanticExpiresAt: expiry,
					quota,
					now: start,
				},
				keyring,
				mainOptions,
			),
			(transaction: DeliveryRawTransaction) => enqueueWebhookEndpointTestInExistingTransaction(
				transaction,
				{
					...scope,
					endpointId: created.endpoint.id,
					expectedVersion: 2,
					quota,
					now: start,
				},
				keyring,
				mainOptions,
			),
		];
		for (const operation of operations) {
			const client = await pool.connect();
			try {
				await client.query("BEGIN");
				await expect(operation(rawTransaction(client))).rejects.toMatchObject({
					code: "DELIVERY_QUOTA_EXCEEDED",
					quota: "active",
					limit: 1,
				});
				await client.query("ROLLBACK");
			} finally {
				client.release();
			}
		}
		expect((await store.cancel("job-webhook-quota-seed", start))?.state).toBe("cancelled");
	});

	it("lists endpoint resources with scoped stable keysets and status filters", async () => {
		await store.migrate();
		const scope = { projectId: "project-webhook-list", environmentId: "environment-webhook-list" };
		for (const [id, offset] of [["endpoint-list-a", 1], ["endpoint-list-b", 2], ["endpoint-list-c", 3]] as const) {
			await createWebhookEndpoint(pool, {
				...scope, id, name: id, url: `https://${id}.example.test/events`,
				now: new Date(start.getTime() + offset),
			}, keyring, mainOptions);
		}
		await updateWebhookEndpoint(pool, {
			...scope, endpointId: "endpoint-list-b", expectedVersion: 1,
			status: "active", now: new Date(start.getTime() + 4),
		}, keyring, mainOptions);
		expect((await listWebhookEndpoints(pool, {
			...scope, statuses: ["active"],
		}, keyring, mainOptions)).items).toEqual([
			expect.objectContaining({
				id: "endpoint-list-b",
				url: "https://endpoint-list-b.example.test/events",
			}),
		]);
		const disabledClient = await pool.connect();
		try {
			await disabledClient.query("BEGIN");
			await expect(enqueueWebhookEndpointDeliveryInExistingTransaction(
				rawTransaction(disabledClient),
				{
					...scope,
					endpointId: "endpoint-list-a",
					expectedVersion: 1,
					eventKind: "organization.updated",
					sourceKey: "disabled-endpoint",
					event: { occurredAt: start.toISOString(), context: {}, data: {} },
					semanticExpiresAt: expiry,
					now: start,
				},
				keyring,
				mainOptions,
			)).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_NOT_ACTIVE" });
			await disabledClient.query("ROLLBACK");
		} finally {
			disabledClient.release();
		}

		const first = await listWebhookEndpoints(pool, { ...scope, limit: 1 }, keyring, mainOptions);
		const second = await listWebhookEndpoints(pool, {
			...scope, limit: 1, cursor: first.nextCursor!,
		}, keyring, mainOptions);
		expect(first.items).toHaveLength(1);
		expect(second.items).toHaveLength(1);
		expect(second.items[0]?.id).not.toBe(first.items[0]?.id);
		await expect(listWebhookEndpoints(pool, {
			projectId: "wrong-project", environmentId: scope.environmentId,
			limit: 1, cursor: first.nextCursor!,
		}, keyring, mainOptions)).rejects.toMatchObject({ code: "WEBHOOK_ENDPOINT_CURSOR_INVALID" });
		expect(await inspectWebhookEndpointScoped(pool, {
			projectId: "wrong-project", environmentId: scope.environmentId,
			endpointId: "endpoint-list-a",
		}, keyring, mainOptions)).toBeNull();
		expect(await updateWebhookEndpoint(pool, {
			projectId: "wrong-project", environmentId: scope.environmentId,
			endpointId: "endpoint-list-a", expectedVersion: 1,
			name: "Wrong scope", now: start,
		}, keyring, mainOptions)).toBeNull();
	});

	it("requires every live endpoint encryption and fingerprint key", async () => {
		const keyStore = new DeliveryStore(pool, endpointKeyOptions);
		await keyStore.migrate();
		const oldEncryption = randomBytes(32);
		const newEncryption = randomBytes(32);
		const oldFingerprint = randomBytes(32);
		const newFingerprint = randomBytes(32);
		const sourceDedupeKey = randomBytes(32);
		const oldRing = createDeliveryKeyring({
			currentKeyId: "endpoint-encryption-old", keys: { "endpoint-encryption-old": oldEncryption },
			currentFingerprintKeyId: "endpoint-fingerprint-old",
			fingerprintKeys: { "endpoint-fingerprint-old": oldFingerprint }, sourceDedupeKey,
		});
		const retainedRing = createDeliveryKeyring({
			currentKeyId: "endpoint-encryption-new",
			keys: { "endpoint-encryption-old": oldEncryption, "endpoint-encryption-new": newEncryption },
			currentFingerprintKeyId: "endpoint-fingerprint-new",
			fingerprintKeys: {
				"endpoint-fingerprint-old": oldFingerprint, "endpoint-fingerprint-new": newFingerprint,
			}, sourceDedupeKey,
		});
		const missingEncryption = createDeliveryKeyring({
			currentKeyId: "endpoint-encryption-new", keys: { "endpoint-encryption-new": newEncryption },
			currentFingerprintKeyId: "endpoint-fingerprint-new",
			fingerprintKeys: {
				"endpoint-fingerprint-old": oldFingerprint, "endpoint-fingerprint-new": newFingerprint,
			}, sourceDedupeKey,
		});
		const missingFingerprint = createDeliveryKeyring({
			currentKeyId: "endpoint-encryption-new",
			keys: { "endpoint-encryption-old": oldEncryption, "endpoint-encryption-new": newEncryption },
			currentFingerprintKeyId: "endpoint-fingerprint-new",
			fingerprintKeys: { "endpoint-fingerprint-new": newFingerprint }, sourceDedupeKey,
		});
		await createWebhookEndpoint(pool, {
			projectId: "project-endpoint-keys", environmentId: "environment-endpoint-keys",
			id: "endpoint-key-history", name: "Historical keys",
			url: "https://historical-keys.example.test/events", now: start,
		}, oldRing, endpointKeyOptions);
		await keyStore.assertDeliveryKeysAvailable(retainedRing, start);
		await expect(keyStore.assertDeliveryKeysAvailable(missingEncryption, start))
			.rejects.toMatchObject({ code: "DELIVERY_KEY_UNAVAILABLE" });
		await expect(keyStore.assertDeliveryKeysAvailable(missingFingerprint, start))
			.rejects.toMatchObject({ code: "DELIVERY_FINGERPRINT_KEY_UNAVAILABLE" });
	});

	it("processes queued work and preserves source-generation dedupe across fingerprint rotation", async () => {
		const rotationStore = new DeliveryStore(pool, rotationOptions);
		await rotationStore.migrate();
		const encryptionKey = randomBytes(32);
		const nextEncryptionKey = randomBytes(32);
		const oldFingerprintKey = randomBytes(32);
		const newFingerprintKey = randomBytes(32);
		const sourceDedupeKey = randomBytes(32);
		const oldKeyring = createDeliveryKeyring({
			currentKeyId: "payload-old",
			keys: { "payload-old": encryptionKey },
			currentFingerprintKeyId: "fingerprint-old",
			fingerprintKeys: { "fingerprint-old": oldFingerprintKey },
			sourceDedupeKey,
		});
		const rotatedKeyring = createDeliveryKeyring({
			currentKeyId: "payload-new",
			keys: { "payload-old": encryptionKey, "payload-new": nextEncryptionKey },
			currentFingerprintKeyId: "fingerprint-new",
			fingerprintKeys: {
				"fingerprint-old": oldFingerprintKey,
				"fingerprint-new": newFingerprintKey,
			},
			sourceDedupeKey,
		});
		const retiredTooEarlyKeyring = createDeliveryKeyring({
			currentKeyId: "payload-new",
			keys: { "payload-old": encryptionKey, "payload-new": nextEncryptionKey },
			currentFingerprintKeyId: "fingerprint-new",
			fingerprintKeys: { "fingerprint-new": newFingerprintKey },
			 sourceDedupeKey,
		});
		const retiredPayloadTooEarlyKeyring = createDeliveryKeyring({
			currentKeyId: "payload-new",
			keys: { "payload-new": nextEncryptionKey },
			currentFingerprintKeyId: "fingerprint-new",
			fingerprintKeys: {
				"fingerprint-old": oldFingerprintKey,
				"fingerprint-new": newFingerprintKey,
			},
			sourceDedupeKey,
		});

		const enqueueWith = async (
			eventId: string,
			jobId: string,
			ring: typeof oldKeyring,
		) => {
			const client = await pool.connect();
			try {
				await client.query("BEGIN");
				const result = await enqueueDelivery(
					createDeliveryTransactionAdapter(client),
					{
						...baseInput(eventId, jobId, "rotation-source"),
						payload: { to: "rotation@example.test", token: "rotation-secret" },
						destination: "rotation@example.test",
					},
					ring,
					rotationOptions,
				);
				await client.query("COMMIT");
				return result;
			} catch (error) {
				await client.query("ROLLBACK").catch(() => undefined);
				throw error;
			} finally {
				client.release();
			}
		};

		await enqueueWith("rotation-event-old", "rotation-job-old", oldKeyring);
		await expect(enqueueWith(
			"rotation-event-duplicate",
			"rotation-job-duplicate",
			rotatedKeyring,
		)).rejects.toMatchObject({ code: "DELIVERY_DUPLICATE" });

		await rotationStore.assertFingerprintKeysAvailable(rotatedKeyring);
		await expect(rotationStore.assertFingerprintKeysAvailable(retiredPayloadTooEarlyKeyring, start))
			.rejects.toMatchObject({ code: "DELIVERY_KEY_UNAVAILABLE" });
		await expect(rotationStore.assertFingerprintKeysAvailable(retiredTooEarlyKeyring))
			.rejects.toMatchObject({ code: "DELIVERY_FINGERPRINT_KEY_UNAVAILABLE" });
		const leased = await rotationStore.claimNext({ workerId: "worker-rotation", now: start });
		expect(leased?.id).toBe("rotation-job-old");
		const payload = await rotationStore.readLeasedPayload<{ to: string; token: string }>({
			jobId: leased!.id,
			leaseToken: leased!.leaseToken,
			keyring: rotatedKeyring,
			now: start,
		});
		expect(payload).toEqual({
			to: "rotation@example.test",
			token: "rotation-secret",
		});
		let retiredError: unknown;
		try {
			await rotationStore.assertLeasedDestination({
				jobId: leased!.id,
				leaseToken: leased!.leaseToken,
				destination: payload.to,
				keyring: retiredTooEarlyKeyring,
				now: start,
			});
		} catch (error) {
			retiredError = error;
		}
		expect(retiredError).toMatchObject({ code: "DELIVERY_FINGERPRINT_KEY_UNAVAILABLE" });
		expect(String(retiredError)).not.toContain(payload.to);
		await rotationStore.assertLeasedDestination({
			jobId: leased!.id,
			leaseToken: leased!.leaseToken,
			destination: payload.to,
			keyring: rotatedKeyring,
			now: start,
		});
		expect((await rotationStore.complete({
			jobId: leased!.id,
			leaseToken: leased!.leaseToken,
			workerId: leased!.leaseOwner,
			now: start,
		})).state).toBe("delivered");
		await expect(rotationStore.assertDeliveryKeysAvailable(retiredTooEarlyKeyring, start))
			.rejects.toMatchObject({ code: "DELIVERY_FINGERPRINT_KEY_UNAVAILABLE" });
		const tables = qualifiedDeliveryTables(rotationOptions);
		const persisted = JSON.stringify((await pool.query(
			`SELECT e.*, j.*, p.envelope FROM ${tables.event} e
			 JOIN ${tables.job} j ON j.event_id=e.id
			 JOIN ${tables.payload} p ON p.event_id=e.id`,
		)).rows);
		expect(persisted).not.toContain("rotation@example.test");
		expect(persisted).not.toContain("rotation-secret");
		expect(persisted).toContain("fingerprint-old");
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

	it("renews only a live lease held by the matching token and owner", async () => {
		await enqueue("event-renew", "job-renew", "source-renew", expiry);
		const leased = await store.claimNext({ workerId: "worker-renew", leaseMs: 1_000, now: start });
		expect(leased?.id).toBe("job-renew");
		const renewAt = new Date(start.getTime() + 500);
		const renewedExpiry = await store.renewLease({
			jobId: leased!.id,
			leaseToken: leased!.leaseToken,
			workerId: leased!.leaseOwner,
			leaseMs: 5_000,
			now: renewAt,
		});
		expect(renewedExpiry).toBe(new Date(renewAt.getTime() + 5_000).toISOString());
		await expect(store.renewLease({
			jobId: leased!.id, leaseToken: "stale", workerId: leased!.leaseOwner,
			leaseMs: 5_000, now: renewAt,
		})).rejects.toMatchObject({ code: "DELIVERY_STALE_LEASE" });
		await expect(store.renewLease({
			jobId: leased!.id, leaseToken: leased!.leaseToken, workerId: "wrong-owner",
			leaseMs: 5_000, now: renewAt,
		})).rejects.toMatchObject({ code: "DELIVERY_STALE_LEASE" });
		await expect(store.renewLease({
			jobId: leased!.id, leaseToken: leased!.leaseToken, workerId: leased!.leaseOwner,
			leaseMs: 5_000, now: new Date(renewAt.getTime() + 5_001),
		})).rejects.toMatchObject({ code: "DELIVERY_STALE_LEASE" });
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
