import { createHash } from "node:crypto";
import type pg from "pg";
import { DeliveryError } from "./errors.js";

export const DELIVERY_SCHEMA_VERSION = 4 as const;
export const DELIVERY_SCHEMA_OWNER = "clearance.delivery" as const;
const deliverySchemaAssetMarker = (version: 1 | 2 | 3 | 4) => `clearance.delivery:v${version}`;

const IDENTIFIER = /^[a-z_][a-z0-9_]*$/i;
const IDENTIFIER_MAX = 63;

export type DeliverySchemaOptions = {
	schema?: string;
	prefix?: string;
	/**
	 * Fingerprint key id active when an owned v1/v2 schema last accepted rows.
	 * Required only while upgrading legacy rows; migrate before rotating that key.
	 */
	legacyFingerprintKeyId?: string;
};

export type DeliveryTableNames = {
	meta: string;
	webhookEndpoint: string;
	event: string;
	payload: string;
	job: string;
	attempt: string;
	worker: string;
	rejectMutationFunction: string;
};

function identifier(value: string): string {
	if (!IDENTIFIER.test(value) || value.length > IDENTIFIER_MAX) {
		throw new DeliveryError("DELIVERY_SCHEMA_IDENTIFIER_INVALID", `Invalid Postgres identifier ${value}`);
	}
	return value;
}

export function quoteIdentifier(value: string): string {
	return `"${identifier(value)}"`;
}

export function deliverySchemaName(options: DeliverySchemaOptions = {}): string {
	return identifier(options.schema ?? "public");
}

export function deliveryTableNames(options: DeliverySchemaOptions = {}): DeliveryTableNames {
	const prefix = identifier(options.prefix ?? "delivery_");
	const names = {
		meta: identifier(`${prefix}meta`),
		webhookEndpoint: identifier(`${prefix}webhook_endpoint`),
		event: identifier(`${prefix}event`),
		payload: identifier(`${prefix}payload`),
		job: identifier(`${prefix}job`),
		attempt: identifier(`${prefix}attempt`),
		worker: identifier(`${prefix}worker`),
		rejectMutationFunction: identifier(`${prefix}reject_mutation`),
	};
	// PostgreSQL silently truncates overlong derived identifiers. Validate every
	// constraint, index, and trigger name before any connection or DDL work.
	for (const derived of [
		`${names.event}_scope_created_idx`,
		`${names.job}_provider_check`,
		`${names.job}_claim_idx`,
		`${names.job}_lease_idx`,
		`${names.attempt}_job_idx`,
		`${names.event}_immutable`,
		`${names.attempt}_immutable`,
	]) {
		identifier(derived);
	}
	return names;
}

function fq(schema: string, name: string): string {
	return `${quoteIdentifier(schema)}.${quoteIdentifier(name)}`;
}

function deliveryIndexName(base: string, suffix: string): string {
	const candidate = `${base}_${suffix}`;
	if (candidate.length <= IDENTIFIER_MAX) return identifier(candidate);
	const digest = createHash("sha256").update(candidate, "utf8").digest("hex").slice(0, 8);
	return identifier(`${base.slice(0, IDENTIFIER_MAX - digest.length - 1)}_${digest}`);
}

function schemaStatements(schema: string, names: DeliveryTableNames): string[] {
	const meta = fq(schema, names.meta);
	const webhookEndpoint = fq(schema, names.webhookEndpoint);
	const event = fq(schema, names.event);
	const payload = fq(schema, names.payload);
	const job = fq(schema, names.job);
	const attempt = fq(schema, names.attempt);
	const worker = fq(schema, names.worker);
	const rejectMutation = fq(schema, names.rejectMutationFunction);
	return [
		`CREATE TABLE IF NOT EXISTS ${meta} (
			key text PRIMARY KEY,
			value jsonb NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT now()
		)`,
		`CREATE OR REPLACE FUNCTION ${rejectMutation}() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			IF TG_OP = 'DELETE' THEN
				IF TG_TABLE_NAME = '${names.attempt}' THEN
					IF OLD.created_at <= now() - interval '30 days'
					   AND EXISTS (
						SELECT 1 FROM ${job} j WHERE j.id = OLD.job_id
						  AND j.state IN ('delivered','dead','cancelled')
						  AND COALESCE(j.delivered_at, j.dead_at, j.cancelled_at)
						      <= now() - interval '30 days'
					   ) THEN
						RETURN OLD;
					END IF;
				ELSIF TG_TABLE_NAME = '${names.event}' THEN
					IF OLD.created_at <= now() - interval '30 days'
					   AND NOT EXISTS (SELECT 1 FROM ${job} j WHERE j.event_id = OLD.id)
					   AND NOT EXISTS (SELECT 1 FROM ${payload} p WHERE p.event_id = OLD.id) THEN
						RETURN OLD;
					END IF;
				END IF;
			END IF;
			RAISE EXCEPTION 'delivery history rows are immutable' USING ERRCODE = '55000';
		END
		$$`,
		`CREATE TABLE IF NOT EXISTS ${webhookEndpoint} (
			id text PRIMARY KEY,
			project_id text NOT NULL,
			environment_id text NOT NULL,
			UNIQUE (id, project_id, environment_id),
			name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
			status text NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
			event_kinds text[] NOT NULL,
			config_envelope_version smallint,
			config_key_id text,
			config_envelope text,
			url_fingerprint_key_id text,
			url_fingerprint text,
			secret_fingerprint text CHECK (secret_fingerprint IS NULL OR secret_fingerprint ~ '^[0-9a-f]{64}$'),
			secret_version integer NOT NULL CHECK (secret_version >= 1),
			resource_version bigint NOT NULL CHECK (resource_version >= 1),
			last_test_job_id text,
			last_test_requested_at timestamptz,
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL,
			deleted_at timestamptz,
			CHECK (event_kinds = ARRAY['organization.updated']::text[]),
			CHECK ((last_test_job_id IS NULL) = (last_test_requested_at IS NULL)),
			CHECK (
				(status = 'deleted' AND deleted_at IS NOT NULL
				 AND config_envelope_version IS NULL AND config_key_id IS NULL AND config_envelope IS NULL
				 AND url_fingerprint_key_id IS NULL AND url_fingerprint IS NULL)
				OR
				(status <> 'deleted' AND deleted_at IS NULL AND config_envelope_version = 1
				 AND config_key_id ~ '^[A-Za-z0-9._-]{1,64}$' AND config_envelope IS NOT NULL
				 AND url_fingerprint_key_id ~ '^[A-Za-z0-9._-]{1,64}$'
				 AND url_fingerprint ~ '^[0-9a-f]{64}$' AND secret_fingerprint IS NOT NULL)
			)
		)`,
		`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(deliveryIndexName(names.webhookEndpoint, "scope_idx"))}
		ON ${webhookEndpoint} (project_id, environment_id, created_at DESC, id DESC)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${quoteIdentifier(deliveryIndexName(names.webhookEndpoint, "url_idx"))}
		ON ${webhookEndpoint} (project_id, environment_id, url_fingerprint_key_id, url_fingerprint)
		WHERE status <> 'deleted'`,
		`CREATE TABLE IF NOT EXISTS ${event} (
			id text PRIMARY KEY,
			kind text NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
			source_fingerprint text NOT NULL CHECK (source_fingerprint ~ '^[0-9a-f]{64}$'),
			source_fingerprint_key_id text NOT NULL CHECK (source_fingerprint_key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
			source_dedupe_fingerprint text NOT NULL UNIQUE CHECK (source_dedupe_fingerprint ~ '^[0-9a-f]{64}$'),
			source_dedupe_version smallint NOT NULL CHECK (source_dedupe_version IN (1, 2)),
			project_id text NOT NULL,
			environment_id text NOT NULL,
			organization_id text,
			actor_id text,
			correlation_id text,
			destination_fingerprint text NOT NULL CHECK (destination_fingerprint ~ '^[0-9a-f]{64}$'),
			destination_fingerprint_key_id text NOT NULL CHECK (destination_fingerprint_key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
			webhook_endpoint_id text,
			replay_of text REFERENCES ${event}(id) ON DELETE RESTRICT,
			created_at timestamptz NOT NULL,
			semantic_expires_at timestamptz NOT NULL,
			CHECK (semantic_expires_at > created_at),
			FOREIGN KEY (webhook_endpoint_id, project_id, environment_id)
				REFERENCES ${webhookEndpoint}(id, project_id, environment_id) ON DELETE RESTRICT
		)`,
		`CREATE TABLE IF NOT EXISTS ${payload} (
			event_id text PRIMARY KEY REFERENCES ${event}(id) ON DELETE CASCADE,
			envelope_version smallint NOT NULL CHECK (envelope_version = 1),
			key_id text NOT NULL CHECK (length(key_id) BETWEEN 1 AND 64),
			envelope text NOT NULL,
			created_at timestamptz NOT NULL,
			expires_at timestamptz NOT NULL,
			CHECK (expires_at > created_at)
		)`,
		`CREATE TABLE IF NOT EXISTS ${job} (
			id text PRIMARY KEY,
			event_id text NOT NULL REFERENCES ${event}(id) ON DELETE RESTRICT,
			channel text NOT NULL CHECK (channel IN ('email', 'webhook')),
			destination_fingerprint text NOT NULL CHECK (destination_fingerprint ~ '^[0-9a-f]{64}$'),
			destination_fingerprint_key_id text NOT NULL CHECK (destination_fingerprint_key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
			state text NOT NULL CHECK (state IN ('queued', 'leased', 'retry', 'delivered', 'dead', 'cancelled')),
			available_at timestamptz NOT NULL,
			semantic_expires_at timestamptz NOT NULL,
			attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
			max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
			lease_token text,
			lease_owner text,
			lease_expires_at timestamptz,
			cancel_requested boolean NOT NULL DEFAULT false,
			last_error_class text,
			provider_accepted_at timestamptz,
			provider_status text,
			provider_request_id text,
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL,
			delivered_at timestamptz,
			dead_at timestamptz,
			cancelled_at timestamptz,
			UNIQUE (event_id, channel, destination_fingerprint_key_id, destination_fingerprint),
			CHECK (attempt_count <= max_attempts),
			CHECK ((state = 'leased') = (lease_token IS NOT NULL AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
			CHECK (state = 'leased' OR cancel_requested = false),
			CONSTRAINT ${quoteIdentifier(`${names.job}_provider_check`)}
				CHECK ((provider_accepted_at IS NULL) = (provider_status IS NULL)),
			CHECK (state <> 'delivered' OR delivered_at IS NOT NULL),
			CHECK (state <> 'dead' OR dead_at IS NOT NULL),
			CHECK (state <> 'cancelled' OR cancelled_at IS NOT NULL)
		)`,
		`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(`${names.job}_claim_idx`)}
		ON ${job} (available_at, id) WHERE state IN ('queued', 'retry')`,
		`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(`${names.job}_lease_idx`)}
		ON ${job} (lease_expires_at, id) WHERE state = 'leased'`,
		`CREATE TABLE IF NOT EXISTS ${attempt} (
			id text PRIMARY KEY,
			job_id text NOT NULL REFERENCES ${job}(id) ON DELETE RESTRICT,
			attempt_number integer NOT NULL CHECK (attempt_number >= 1),
			lease_token text NOT NULL,
			phase text NOT NULL CHECK (phase IN ('claimed', 'delivered', 'retry', 'dead', 'cancelled', 'lease_expired')),
			worker_id text NOT NULL,
			provider_status text,
			provider_request_id text,
			error_class text,
			created_at timestamptz NOT NULL,
			UNIQUE (job_id, attempt_number, phase)
		)`,
		`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(`${names.attempt}_job_idx`)}
		ON ${attempt} (job_id, attempt_number, created_at)`,
		`CREATE TABLE IF NOT EXISTS ${worker} (
			id text PRIMARY KEY,
			version text NOT NULL,
			state text NOT NULL CHECK (state IN ('starting', 'ready', 'draining', 'stopped', 'failed')),
			started_at timestamptz NOT NULL,
			last_seen_at timestamptz NOT NULL
		)`,
		...([names.meta, names.webhookEndpoint, names.event, names.payload, names.job, names.attempt, names.worker] as const)
			.map((name) => `COMMENT ON TABLE ${fq(schema, name)} IS '${deliverySchemaAssetMarker(4)}'`),
		`COMMENT ON FUNCTION ${rejectMutation}() IS '${deliverySchemaAssetMarker(4)}'`,
		`DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '${names.event}_immutable' AND tgrelid = '${event}'::regclass) THEN
				CREATE TRIGGER ${quoteIdentifier(`${names.event}_immutable`)}
				BEFORE UPDATE OR DELETE ON ${event}
				FOR EACH ROW EXECUTE FUNCTION ${rejectMutation}();
			END IF;
		END $$`,
		`DO $$ BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = '${names.attempt}_immutable' AND tgrelid = '${attempt}'::regclass) THEN
				CREATE TRIGGER ${quoteIdentifier(`${names.attempt}_immutable`)}
				BEFORE UPDATE OR DELETE ON ${attempt}
				FOR EACH ROW EXECUTE FUNCTION ${rejectMutation}();
			END IF;
		END $$`,
	];
}

function schemaDrift(message: string): never {
	throw new DeliveryError("DELIVERY_SCHEMA_DRIFT", message);
}

async function verifyDeliverySchema(
	client: pg.PoolClient,
	schema: string,
	names: DeliveryTableNames,
	version: 1 | 2 | 3 | 4,
	allowMissingAdditiveIndexes = false,
): Promise<void> {
	const expectedColumns = new Map<string, string[]>([
		[names.meta, ["key:text:true", "updated_at:timestamp with time zone:true", "value:jsonb:true"]],
		...(version >= 4 ? [[names.webhookEndpoint, [
			"config_envelope:text:false", "config_envelope_version:smallint:false", "config_key_id:text:false",
			"created_at:timestamp with time zone:true", "deleted_at:timestamp with time zone:false",
			"environment_id:text:true", "event_kinds:text[]:true", "id:text:true",
			"last_test_job_id:text:false", "last_test_requested_at:timestamp with time zone:false",
			"name:text:true", "project_id:text:true", "resource_version:bigint:true",
			"secret_fingerprint:text:false", "secret_version:integer:true", "status:text:true",
			"updated_at:timestamp with time zone:true", "url_fingerprint:text:false",
			"url_fingerprint_key_id:text:false",
		]] as [string, string[]]] : []),
		[names.event, [
			"actor_id:text:false", "correlation_id:text:false", "created_at:timestamp with time zone:true",
			"destination_fingerprint:text:true", "environment_id:text:true", "id:text:true", "kind:text:true",
			"organization_id:text:false", "project_id:text:true", "replay_of:text:false",
			"semantic_expires_at:timestamp with time zone:true", "source_fingerprint:text:true",
			...(version >= 3 ? [
				"destination_fingerprint_key_id:text:true", "source_dedupe_fingerprint:text:true",
				"source_dedupe_version:smallint:true", "source_fingerprint_key_id:text:true",
			] : []),
			...(version >= 4 ? ["webhook_endpoint_id:text:false"] : []),
		]],
		[names.payload, [
			"created_at:timestamp with time zone:true", "envelope:text:true", "envelope_version:smallint:true",
			"event_id:text:true", "expires_at:timestamp with time zone:true", "key_id:text:true",
		]],
		[names.job, [
			"attempt_count:integer:true", "available_at:timestamp with time zone:true", "cancel_requested:boolean:true",
			"cancelled_at:timestamp with time zone:false", "channel:text:true", "created_at:timestamp with time zone:true",
			"dead_at:timestamp with time zone:false", "delivered_at:timestamp with time zone:false",
			"destination_fingerprint:text:true", "event_id:text:true", "id:text:true", "last_error_class:text:false",
			...(version >= 3 ? ["destination_fingerprint_key_id:text:true"] : []),
			"lease_expires_at:timestamp with time zone:false", "lease_owner:text:false", "lease_token:text:false",
			"max_attempts:integer:true", "semantic_expires_at:timestamp with time zone:true", "state:text:true",
			...(version >= 2 ? [
				"provider_accepted_at:timestamp with time zone:false", "provider_request_id:text:false",
				"provider_status:text:false",
			] : []),
			"updated_at:timestamp with time zone:true",
		]],
		[names.attempt, [
			"attempt_number:integer:true", "created_at:timestamp with time zone:true", "error_class:text:false",
			"id:text:true", "job_id:text:true", "lease_token:text:true", "phase:text:true",
			"provider_request_id:text:false", "provider_status:text:false", "worker_id:text:true",
		]],
		[names.worker, [
			"id:text:true", "last_seen_at:timestamp with time zone:true", "started_at:timestamp with time zone:true",
			"state:text:true", "version:text:true",
		]],
	]);
	const columns = await client.query<{
		table_name: string;
		column_name: string;
		data_type: string;
		not_null: boolean;
	}>(
		`SELECT c.relname table_name, a.attname column_name,
		 format_type(a.atttypid, a.atttypmod) data_type, a.attnotnull not_null
		 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid
		 JOIN pg_namespace n ON n.oid=c.relnamespace
		 WHERE n.nspname=$1 AND c.relname=ANY($2::text[])
		   AND a.attnum > 0 AND NOT a.attisdropped`,
		[schema, [...expectedColumns.keys()]],
	);
	for (const [table, expected] of expectedColumns) {
		const actual = columns.rows
			.filter((row) => row.table_name === table)
			.map((row) => `${row.column_name}:${row.data_type}:${row.not_null}`)
			.sort();
		if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
			schemaDrift(`Delivery table ${table} columns differ from schema v${version}`);
		}
	}

	const constraints = await client.query<{
		table_name: string;
		definition: string;
	}>(
		`SELECT c.relname table_name, pg_get_constraintdef(k.oid, true) definition
		 FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid
		 JOIN pg_namespace n ON n.oid=c.relnamespace
		 WHERE n.nspname=$1 AND c.relname=ANY($2::text[])`,
		[schema, [...expectedColumns.keys()]],
	);
	const definitions = (table: string) => constraints.rows
		.filter((row) => row.table_name === table)
		.map((row) => row.definition.toUpperCase())
		.join("\n");
	if (version >= 4) {
		const endpointDefinitions = constraints.rows
			.filter((row) => row.table_name === names.webhookEndpoint)
			.map((row) => row.definition.replace(/\s+/g, " ").trim().toUpperCase())
			.sort();
		const expectedEndpointDefinitions = [
			"CHECK ((LAST_TEST_JOB_ID IS NULL) = (LAST_TEST_REQUESTED_AT IS NULL))",
			"CHECK (EVENT_KINDS = ARRAY['ORGANIZATION.UPDATED'::TEXT])",
			"CHECK (LENGTH(NAME) >= 1 AND LENGTH(NAME) <= 128)",
			"CHECK (RESOURCE_VERSION >= 1)",
			"CHECK (SECRET_FINGERPRINT IS NULL OR SECRET_FINGERPRINT ~ '^[0-9A-F]{64}$'::TEXT)",
			"CHECK (SECRET_VERSION >= 1)",
			"CHECK (STATUS = 'DELETED'::TEXT AND DELETED_AT IS NOT NULL AND CONFIG_ENVELOPE_VERSION IS NULL AND CONFIG_KEY_ID IS NULL AND CONFIG_ENVELOPE IS NULL AND URL_FINGERPRINT_KEY_ID IS NULL AND URL_FINGERPRINT IS NULL OR STATUS <> 'DELETED'::TEXT AND DELETED_AT IS NULL AND CONFIG_ENVELOPE_VERSION = 1 AND CONFIG_KEY_ID ~ '^[A-ZA-Z0-9._-]{1,64}$'::TEXT AND CONFIG_ENVELOPE IS NOT NULL AND URL_FINGERPRINT_KEY_ID ~ '^[A-ZA-Z0-9._-]{1,64}$'::TEXT AND URL_FINGERPRINT ~ '^[0-9A-F]{64}$'::TEXT AND SECRET_FINGERPRINT IS NOT NULL)",
			"CHECK (STATUS = ANY (ARRAY['ACTIVE'::TEXT, 'DISABLED'::TEXT, 'DELETED'::TEXT]))",
			"PRIMARY KEY (ID)",
			"UNIQUE (ID, PROJECT_ID, ENVIRONMENT_ID)",
		].sort();
		if (JSON.stringify(endpointDefinitions) !== JSON.stringify(expectedEndpointDefinitions)) {
			schemaDrift(`Delivery table ${names.webhookEndpoint} constraints differ from schema v${version}`);
		}
	}
	const requiredConstraintFragments = new Map<string, string[]>([
		[names.meta, ["PRIMARY KEY (KEY)"]],
		[names.event, [
			"PRIMARY KEY (ID)",
			version >= 3 ? "UNIQUE (SOURCE_DEDUPE_FINGERPRINT)" : "UNIQUE (SOURCE_FINGERPRINT)",
			"FOREIGN KEY (REPLAY_OF)", "SEMANTIC_EXPIRES_AT > CREATED_AT",
		]],
		[names.payload, ["PRIMARY KEY (EVENT_ID)", "FOREIGN KEY (EVENT_ID)", "EXPIRES_AT > CREATED_AT"]],
		[names.job, [
			"PRIMARY KEY (ID)", "FOREIGN KEY (EVENT_ID)",
			version >= 3
				? "UNIQUE (EVENT_ID, CHANNEL, DESTINATION_FINGERPRINT_KEY_ID, DESTINATION_FINGERPRINT)"
				: "UNIQUE (EVENT_ID, CHANNEL, DESTINATION_FINGERPRINT)",
			"STATE = ANY", "LEASE_TOKEN IS NOT NULL",
			"ATTEMPT_COUNT <= MAX_ATTEMPTS",
		]],
		[names.attempt, ["PRIMARY KEY (ID)", "FOREIGN KEY (JOB_ID)", "UNIQUE (JOB_ID, ATTEMPT_NUMBER, PHASE)", "PHASE = ANY"]],
		[names.worker, ["PRIMARY KEY (ID)", "STATE = ANY"]],
	]);
	if (version >= 2) {
		requiredConstraintFragments.get(names.job)!.push("PROVIDER_ACCEPTED_AT IS NULL");
	}
	if (version >= 3) {
		requiredConstraintFragments.get(names.event)!.push(
			"SOURCE_FINGERPRINT_KEY_ID ~",
			"SOURCE_DEDUPE_FINGERPRINT ~",
			"SOURCE_DEDUPE_VERSION = ANY",
			"DESTINATION_FINGERPRINT_KEY_ID ~",
		);
		requiredConstraintFragments.get(names.job)!.push("DESTINATION_FINGERPRINT_KEY_ID ~");
	}
	if (version >= 4) {
		requiredConstraintFragments.get(names.event)!.push(
			"FOREIGN KEY (WEBHOOK_ENDPOINT_ID, PROJECT_ID, ENVIRONMENT_ID)",
		);
	}
	for (const [table, fragments] of requiredConstraintFragments) {
		const actual = definitions(table);
		for (const fragment of fragments) {
			if (!actual.includes(fragment)) schemaDrift(`Delivery table ${table} lost required constraint ${fragment}`);
		}
	}
	if (version >= 4) {
		const provenance = await client.query<{
			referenced_schema: string;
			referenced_table: string;
			delete_action: string;
			source_columns: string[];
			target_columns: string[];
		}>(
			`SELECT rn.nspname referenced_schema, rc.relname referenced_table,
			 k.confdeltype delete_action,
			 ARRAY(SELECT a.attname::text FROM unnest(k.conkey) WITH ORDINALITY ck(attnum,ordinality)
			       JOIN pg_attribute a ON a.attrelid=k.conrelid AND a.attnum=ck.attnum
			       ORDER BY ck.ordinality) source_columns,
			 ARRAY(SELECT a.attname::text FROM unnest(k.confkey) WITH ORDINALITY fk(attnum,ordinality)
			       JOIN pg_attribute a ON a.attrelid=k.confrelid AND a.attnum=fk.attnum
			       ORDER BY fk.ordinality) target_columns
			 FROM pg_constraint k
			 JOIN pg_class rc ON rc.oid=k.confrelid
			 JOIN pg_namespace rn ON rn.oid=rc.relnamespace
			 WHERE k.conrelid=$1::regclass AND k.contype='f'`,
			[fq(schema, names.event)],
		);
		const candidates = provenance.rows.filter((row) => row.source_columns.includes("webhook_endpoint_id"));
		const expectedSource = ["webhook_endpoint_id", "project_id", "environment_id"];
		const expectedTarget = ["id", "project_id", "environment_id"];
		const row = candidates[0];
		if (candidates.length !== 1 || row?.referenced_schema !== schema ||
			row.referenced_table !== names.webhookEndpoint || row.delete_action !== "r" ||
			JSON.stringify(row.source_columns) !== JSON.stringify(expectedSource) ||
			JSON.stringify(row.target_columns) !== JSON.stringify(expectedTarget)) {
			schemaDrift("Delivery event webhook endpoint provenance foreign key differs from schema v4");
		}
	}

	const indexes = await client.query<{ indexname: string; indexdef: string }>(
		`SELECT indexname, indexdef FROM pg_indexes
		 WHERE schemaname=$1 AND indexname=ANY($2::text[])`,
		[
			schema,
			[
				`${names.event}_scope_created_idx`,
				...(version >= 4 ? [
					deliveryIndexName(names.webhookEndpoint, "scope_idx"),
					deliveryIndexName(names.webhookEndpoint, "url_idx"),
				] : []),
				`${names.job}_claim_idx`,
				`${names.job}_lease_idx`,
				`${names.attempt}_job_idx`,
			],
		],
	);
	const indexDefinitions = new Map(indexes.rows.map((row) => [row.indexname, row.indexdef.toUpperCase()]));
	for (const [indexName, fragments] of [
		[`${names.event}_scope_created_idx`, ["(PROJECT_ID, ENVIRONMENT_ID, CREATED_AT)"]],
		...(version >= 4 ? [
			[deliveryIndexName(names.webhookEndpoint, "scope_idx"), [
				"(PROJECT_ID, ENVIRONMENT_ID, CREATED_AT DESC, ID DESC)",
			]],
			[deliveryIndexName(names.webhookEndpoint, "url_idx"), [
				"CREATE UNIQUE INDEX",
				"(PROJECT_ID, ENVIRONMENT_ID, URL_FINGERPRINT_KEY_ID, URL_FINGERPRINT)",
				"WHERE (STATUS <> 'DELETED'::TEXT)",
			]],
		] as const : []),
		[`${names.job}_claim_idx`, ["WHERE (STATE = ANY"]],
		[`${names.job}_lease_idx`, ["WHERE (STATE = 'LEASED'"]],
		[`${names.attempt}_job_idx`, ["(JOB_ID, ATTEMPT_NUMBER, CREATED_AT)"]],
	] as const) {
		const definition = indexDefinitions.get(indexName);
		if (
			(!definition || fragments.some((fragment) => !definition.includes(fragment))) &&
			!(allowMissingAdditiveIndexes &&
				indexName === `${names.event}_scope_created_idx` &&
				definition === undefined)
		) {
			schemaDrift(`Delivery schema is missing or changed index ${indexName}`);
		}
	}

	const triggers = await client.query<{ table_name: string; definition: string; enabled: string }>(
		`SELECT c.relname table_name, pg_get_triggerdef(t.oid, true) definition, t.tgenabled enabled
		 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
		 JOIN pg_namespace n ON n.oid=c.relnamespace
		 WHERE n.nspname=$1 AND NOT t.tgisinternal
		   AND c.relname=ANY($2::text[])`,
		[schema, [names.event, names.attempt]],
	);
	for (const table of [names.event, names.attempt]) {
		const trigger = triggers.rows.find((row) => row.table_name === table);
		if (
			!trigger || trigger.enabled === "D" ||
			!trigger.definition.toUpperCase().includes("BEFORE DELETE OR UPDATE") ||
			!trigger.definition.includes(names.rejectMutationFunction)
		) {
			schemaDrift(`Delivery history guard for ${table} is missing, disabled, or changed`);
		}
	}
	const fn = await client.query<{ definition: string }>(
		`SELECT pg_get_functiondef(p.oid) definition
		 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
		 WHERE n.nspname=$1 AND p.proname=$2`,
		[schema, names.rejectMutationFunction],
	);
	const functionDefinition = fn.rows[0]?.definition ?? "";
	if (
		!functionDefinition.includes("delivery history rows are immutable") ||
		!functionDefinition.includes("interval '30 days'") ||
		!functionDefinition.includes(names.job)
	) {
		schemaDrift(`Delivery history guard function differs from schema v${version}`);
	}
}

async function migrateDeliverySchemaV1ToV2(
	client: pg.PoolClient,
	schema: string,
	names: DeliveryTableNames,
): Promise<void> {
	const job = fq(schema, names.job);
	await client.query(`ALTER TABLE ${job}
		ADD COLUMN provider_accepted_at timestamptz,
		ADD COLUMN provider_status text,
		ADD COLUMN provider_request_id text`);
	await client.query(`ALTER TABLE ${job}
		ADD CONSTRAINT ${quoteIdentifier(`${names.job}_provider_check`)}
		CHECK ((provider_accepted_at IS NULL) = (provider_status IS NULL))`);
	for (const name of [names.meta, names.event, names.payload, names.job, names.attempt, names.worker]) {
		await client.query(`COMMENT ON TABLE ${fq(schema, name)} IS '${deliverySchemaAssetMarker(2)}'`);
	}
	await client.query(
		`COMMENT ON FUNCTION ${fq(schema, names.rejectMutationFunction)}() IS '${deliverySchemaAssetMarker(2)}'`,
	);
}

function migrationFingerprintKeyId(value: string | undefined): string | null {
	if (value === undefined) return null;
	if (!/^[A-Za-z0-9._-]{1,64}$/.test(value)) {
		throw new DeliveryError(
			"DELIVERY_FINGERPRINT_KEY_ID_INVALID",
			"Legacy delivery fingerprint key id is invalid",
		);
	}
	return value;
}

async function migrateDeliverySchemaV2ToV3(
	client: pg.PoolClient,
	schema: string,
	names: DeliveryTableNames,
	legacyFingerprintKeyId: string | undefined,
): Promise<void> {
	const event = fq(schema, names.event);
	const job = fq(schema, names.job);
	const legacyRowCount = Number((await client.query<{ count: string }>(
		`SELECT count(*) count FROM ${event}`,
	)).rows[0]?.count ?? "0");
	const keyId = migrationFingerprintKeyId(legacyFingerprintKeyId);
	if (legacyRowCount > 0 && keyId === null) {
		throw new DeliveryError(
			"DELIVERY_FINGERPRINT_MIGRATION_KEY_ID_REQUIRED",
			"Set legacyFingerprintKeyId to the still-retained fingerprint key that created v1/v2 delivery rows, migrate, then rotate",
		);
	}

	await client.query(`ALTER TABLE ${event}
		ADD COLUMN source_fingerprint_key_id text,
		ADD COLUMN source_dedupe_fingerprint text,
		ADD COLUMN source_dedupe_version smallint,
		ADD COLUMN destination_fingerprint_key_id text`);
	await client.query(`ALTER TABLE ${job}
		ADD COLUMN destination_fingerprint_key_id text`);
	if (legacyRowCount > 0) {
		await client.query(
			`ALTER TABLE ${event} DISABLE TRIGGER ${quoteIdentifier(`${names.event}_immutable`)}`,
		);
		await client.query(
			`UPDATE ${event} SET source_fingerprint_key_id=$1,
			 source_dedupe_fingerprint=source_fingerprint,
			 source_dedupe_version=1,
			 destination_fingerprint_key_id=$1`,
			[keyId],
		);
		await client.query(
			`ALTER TABLE ${event} ENABLE TRIGGER ${quoteIdentifier(`${names.event}_immutable`)}`,
		);
		await client.query(
			`UPDATE ${job} SET destination_fingerprint_key_id=$1`,
			[keyId],
		);
	}

	const sourceUnique = await client.query<{ conname: string }>(
		`SELECT k.conname FROM pg_constraint k
		 WHERE k.conrelid=$1::regclass AND k.contype='u'
		   AND upper(pg_get_constraintdef(k.oid, true))='UNIQUE (SOURCE_FINGERPRINT)'`,
		[event],
	);
	const sourceUniqueName = sourceUnique.rows[0]?.conname;
	if (!sourceUniqueName) {
		schemaDrift("Delivery v2 source fingerprint uniqueness constraint is missing");
	}
	await client.query(`ALTER TABLE ${event}
		DROP CONSTRAINT ${quoteIdentifier(sourceUniqueName)},
		ALTER COLUMN source_fingerprint_key_id SET NOT NULL,
		ALTER COLUMN source_dedupe_fingerprint SET NOT NULL,
		ALTER COLUMN source_dedupe_version SET NOT NULL,
		ALTER COLUMN destination_fingerprint_key_id SET NOT NULL,
		ADD UNIQUE (source_dedupe_fingerprint),
		ADD CHECK (source_fingerprint_key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
		ADD CHECK (source_dedupe_fingerprint ~ '^[0-9a-f]{64}$'),
		ADD CHECK (source_dedupe_version IN (1, 2)),
		ADD CHECK (destination_fingerprint_key_id ~ '^[A-Za-z0-9._-]{1,64}$')`);

	const jobDestinationUnique = await client.query<{ conname: string }>(
		`SELECT k.conname FROM pg_constraint k
		 WHERE k.conrelid=$1::regclass AND k.contype='u'
		   AND upper(pg_get_constraintdef(k.oid, true))=
		       'UNIQUE (EVENT_ID, CHANNEL, DESTINATION_FINGERPRINT)'`,
		[job],
	);
	const jobDestinationUniqueName = jobDestinationUnique.rows[0]?.conname;
	if (!jobDestinationUniqueName) {
		schemaDrift("Delivery v2 job destination uniqueness constraint is missing");
	}
	await client.query(`ALTER TABLE ${job}
		DROP CONSTRAINT ${quoteIdentifier(jobDestinationUniqueName)},
		ALTER COLUMN destination_fingerprint_key_id SET NOT NULL,
		ADD UNIQUE (event_id, channel, destination_fingerprint_key_id, destination_fingerprint),
		ADD CHECK (destination_fingerprint_key_id ~ '^[A-Za-z0-9._-]{1,64}$')`);

	for (const name of [names.meta, names.event, names.payload, names.job, names.attempt, names.worker]) {
		await client.query(`COMMENT ON TABLE ${fq(schema, name)} IS '${deliverySchemaAssetMarker(3)}'`);
	}
	await client.query(
		`COMMENT ON FUNCTION ${fq(schema, names.rejectMutationFunction)}() IS '${deliverySchemaAssetMarker(3)}'`,
	);
}

async function migrateDeliverySchemaV3ToV4(
	client: pg.PoolClient,
	schema: string,
	names: DeliveryTableNames,
): Promise<void> {
	const endpoint = fq(schema, names.webhookEndpoint);
	const event = fq(schema, names.event);
	await client.query(`CREATE TABLE ${endpoint} (
		id text PRIMARY KEY,
		project_id text NOT NULL,
		environment_id text NOT NULL,
		UNIQUE (id, project_id, environment_id),
		name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
		status text NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
		event_kinds text[] NOT NULL CHECK (event_kinds = ARRAY['organization.updated']::text[]),
		config_envelope_version smallint,
		config_key_id text,
		config_envelope text,
		url_fingerprint_key_id text,
		url_fingerprint text,
		secret_fingerprint text CHECK (secret_fingerprint IS NULL OR secret_fingerprint ~ '^[0-9a-f]{64}$'),
		secret_version integer NOT NULL CHECK (secret_version >= 1),
		resource_version bigint NOT NULL CHECK (resource_version >= 1),
		last_test_job_id text,
		last_test_requested_at timestamptz,
		created_at timestamptz NOT NULL,
		updated_at timestamptz NOT NULL,
		deleted_at timestamptz,
		CHECK ((last_test_job_id IS NULL) = (last_test_requested_at IS NULL)),
		CHECK (
			(status = 'deleted' AND deleted_at IS NOT NULL
			 AND config_envelope_version IS NULL AND config_key_id IS NULL AND config_envelope IS NULL
			 AND url_fingerprint_key_id IS NULL AND url_fingerprint IS NULL)
			OR
			(status <> 'deleted' AND deleted_at IS NULL AND config_envelope_version = 1
			 AND config_key_id ~ '^[A-Za-z0-9._-]{1,64}$' AND config_envelope IS NOT NULL
			 AND url_fingerprint_key_id ~ '^[A-Za-z0-9._-]{1,64}$'
			 AND url_fingerprint ~ '^[0-9a-f]{64}$' AND secret_fingerprint IS NOT NULL)
		)
	)`);
	await client.query(`ALTER TABLE ${event}
		ADD COLUMN webhook_endpoint_id text,
		ADD FOREIGN KEY (webhook_endpoint_id, project_id, environment_id)
			REFERENCES ${endpoint}(id, project_id, environment_id) ON DELETE RESTRICT`);
	await client.query(
		`CREATE INDEX ${quoteIdentifier(deliveryIndexName(names.webhookEndpoint, "scope_idx"))}
		 ON ${endpoint} (project_id, environment_id, created_at DESC, id DESC)`,
	);
	await client.query(
		`CREATE UNIQUE INDEX ${quoteIdentifier(deliveryIndexName(names.webhookEndpoint, "url_idx"))}
		 ON ${endpoint} (project_id, environment_id, url_fingerprint_key_id, url_fingerprint)
		 WHERE status <> 'deleted'`,
	);
	for (const name of [
		names.meta, names.webhookEndpoint, names.event, names.payload,
		names.job, names.attempt, names.worker,
	]) {
		await client.query(`COMMENT ON TABLE ${fq(schema, name)} IS '${deliverySchemaAssetMarker(4)}'`);
	}
	await client.query(
		`COMMENT ON FUNCTION ${fq(schema, names.rejectMutationFunction)}() IS '${deliverySchemaAssetMarker(4)}'`,
	);
}

export async function migrateDeliverySchema(
	pool: pg.Pool,
	options: DeliverySchemaOptions = {},
): Promise<{ schema: string; version: number; tables: DeliveryTableNames }> {
	const schema = deliverySchemaName(options);
	const names = deliveryTableNames(options);
	const legacyTargets = [names.meta, names.event, names.payload, names.job, names.attempt, names.worker];
	const targets = [names.meta, names.webhookEndpoint, names.event, names.payload, names.job, names.attempt, names.worker];
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtext('clearance.delivery'), hashtext($1))",
			[`${schema}.${options.prefix ?? "delivery_"}`],
		);
		const schemaResult = await client.query(
			"SELECT 1 FROM information_schema.schemata WHERE schema_name = $1",
			[schema],
		);
		if (!schemaResult.rowCount) {
			throw new DeliveryError("DELIVERY_SCHEMA_MISSING", `Postgres schema ${schema} does not exist`);
		}
		const existing = await client.query<{ relname: string }>(
			`SELECT c.relname FROM pg_class c
			 JOIN pg_namespace n ON n.oid = c.relnamespace
			 WHERE n.nspname = $1 AND c.relname = ANY($2::text[]) AND c.relkind IN ('r', 'p')`,
			[schema, targets],
		);
		const functionExisting = await client.query(
			`SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
			 WHERE n.nspname = $1 AND p.proname = $2`,
			[schema, names.rejectMutationFunction],
		);
		const metaExists = existing.rows.some((row) => row.relname === names.meta);
		if (!metaExists && (existing.rows.length > 0 || Boolean(functionExisting.rowCount))) {
			throw new DeliveryError(
				"DELIVERY_SCHEMA_COLLISION",
				"Refusing to adopt unowned delivery tables or functions",
			);
		}
		let existingVersion: 1 | 2 | 3 | 4 | null = null;
		if (metaExists) {
			const metadata = await client.query<{ key: string; value: unknown }>(
				`SELECT key, value FROM ${fq(schema, names.meta)} WHERE key IN ('owner', 'schema_version')`,
			);
			const values = new Map(metadata.rows.map((row) => [row.key, row.value]));
			if (values.get("owner") !== DELIVERY_SCHEMA_OWNER) {
				throw new DeliveryError("DELIVERY_SCHEMA_COLLISION", "Delivery metadata owner is missing or invalid");
			}
			const version = Number(values.get("schema_version"));
			if (!Number.isSafeInteger(version) || version < 1) {
				throw new DeliveryError("DELIVERY_SCHEMA_VERSION_INVALID", "Delivery schema version is invalid");
			}
			if (version > DELIVERY_SCHEMA_VERSION) {
				throw new DeliveryError(
					"DELIVERY_SCHEMA_VERSION_FUTURE",
					`Delivery schema version ${version} is newer than supported version ${DELIVERY_SCHEMA_VERSION}`,
				);
			}
			existingVersion = version as 1 | 2 | 3 | 4;
			const versionTargets = existingVersion >= 4 ? targets : legacyTargets;
			if (existing.rows.length !== versionTargets.length || !functionExisting.rowCount) {
				throw new DeliveryError(
					"DELIVERY_SCHEMA_COLLISION",
					"Owned delivery schema is missing required tables or functions",
				);
			}
			const tableOwnership = await client.query<{ relname: string; marker: string | null }>(
				`SELECT c.relname, obj_description(c.oid, 'pg_class') marker
				 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
				 WHERE n.nspname=$1 AND c.relname=ANY($2::text[])`,
				[schema, versionTargets],
			);
			const functionOwnership = await client.query<{ marker: string | null }>(
				`SELECT obj_description(p.oid, 'pg_proc') marker
				 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
				 WHERE n.nspname=$1 AND p.proname=$2`,
				[schema, names.rejectMutationFunction],
			);
			const expectedMarker = deliverySchemaAssetMarker(existingVersion);
			if (
				tableOwnership.rows.some((row) => row.marker !== expectedMarker) ||
				functionOwnership.rows[0]?.marker !== expectedMarker
			) {
				throw new DeliveryError(
					"DELIVERY_SCHEMA_COLLISION",
					"Delivery schema contains assets without Clearance ownership markers",
				);
			}
			// Performance-only indexes are additive within a schema version. Permit
			// them to be absent during preflight so schemaStatements can create them;
			// changed definitions still fail closed, and final verification is strict.
			await verifyDeliverySchema(client, schema, names, existingVersion, true);
		}
		if (existingVersion === null) {
			for (const statement of schemaStatements(schema, names)) await client.query(statement);
		} else {
			if (existingVersion === 1) {
			await migrateDeliverySchemaV1ToV2(client, schema, names);
			}
			if (existingVersion <= 2) {
			await migrateDeliverySchemaV2ToV3(
				client,
				schema,
				names,
				options.legacyFingerprintKeyId,
			);
			}
			if (existingVersion <= 3) {
				await migrateDeliverySchemaV3ToV4(client, schema, names);
			}
		}
		// This performance-only index is additive within the current schema. Create it for
		// fresh installs and every supported upgrade path before strict verification.
		await client.query(
			`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(`${names.event}_scope_created_idx`)}
			 ON ${fq(schema, names.event)} (project_id, environment_id, created_at)`,
		);
		await verifyDeliverySchema(client, schema, names, DELIVERY_SCHEMA_VERSION);
		const meta = fq(schema, names.meta);
		await client.query(
			`INSERT INTO ${meta} (key, value) VALUES ('owner', $1::jsonb), ('schema_version', $2::jsonb)
			 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			[JSON.stringify(DELIVERY_SCHEMA_OWNER), JSON.stringify(DELIVERY_SCHEMA_VERSION)],
		);
		await client.query("COMMIT");
		return { schema, version: DELIVERY_SCHEMA_VERSION, tables: names };
	} catch (error) {
		await client.query("ROLLBACK").catch(() => undefined);
		throw error;
	} finally {
		client.release();
	}
}

/** Read-only production readiness assertion, including owned asset and drift checks. */
export async function assertDeliverySchemaCurrent(
	pool: pg.Pool,
	options: DeliverySchemaOptions = {},
): Promise<{ schema: string; version: typeof DELIVERY_SCHEMA_VERSION; tables: DeliveryTableNames }> {
	const schema = deliverySchemaName(options);
	const names = deliveryTableNames(options);
	const targets = [names.meta, names.webhookEndpoint, names.event, names.payload, names.job, names.attempt, names.worker];
	const client = await pool.connect();
	try {
		await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
		const schemaResult = await client.query(
			"SELECT 1 FROM information_schema.schemata WHERE schema_name=$1",
			[schema],
		);
		if (!schemaResult.rowCount) {
			throw new DeliveryError("DELIVERY_SCHEMA_MISSING", `Postgres schema ${schema} does not exist`);
		}
		const existing = await client.query<{ relname: string; marker: string | null }>(
			`SELECT c.relname, obj_description(c.oid, 'pg_class') marker
			 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
			 WHERE n.nspname=$1 AND c.relname=ANY($2::text[]) AND c.relkind IN ('r','p')`,
			[schema, targets],
		);
		const fn = await client.query<{ marker: string | null }>(
			`SELECT obj_description(p.oid, 'pg_proc') marker
			 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
			 WHERE n.nspname=$1 AND p.proname=$2`,
			[schema, names.rejectMutationFunction],
		);
		if (existing.rows.length !== targets.length || fn.rows.length !== 1) {
			throw new DeliveryError(
				"DELIVERY_SCHEMA_DRIFT",
				"Owned delivery schema is missing required tables or functions",
			);
		}
		const metadata = await client.query<{ key: string; value: unknown }>(
			`SELECT key, value FROM ${fq(schema, names.meta)} WHERE key IN ('owner','schema_version')`,
		);
		const values = new Map(metadata.rows.map((row) => [row.key, row.value]));
		if (values.get("owner") !== DELIVERY_SCHEMA_OWNER) {
			throw new DeliveryError("DELIVERY_SCHEMA_COLLISION", "Delivery metadata owner is missing or invalid");
		}
		const version = Number(values.get("schema_version"));
		if (version !== DELIVERY_SCHEMA_VERSION) {
			throw new DeliveryError(
				version > DELIVERY_SCHEMA_VERSION
					? "DELIVERY_SCHEMA_VERSION_FUTURE"
					: "DELIVERY_SCHEMA_VERSION_OUTDATED",
				`Delivery schema version ${version} is not current version ${DELIVERY_SCHEMA_VERSION}`,
			);
		}
		const marker = deliverySchemaAssetMarker(DELIVERY_SCHEMA_VERSION);
		if (
			existing.rows.some((row) => row.marker !== marker) ||
			fn.rows[0]?.marker !== marker
		) {
			throw new DeliveryError(
				"DELIVERY_SCHEMA_COLLISION",
				"Delivery schema contains assets without current Clearance ownership markers",
			);
		}
		await verifyDeliverySchema(client, schema, names, DELIVERY_SCHEMA_VERSION);
		await client.query("COMMIT");
		return { schema, version: DELIVERY_SCHEMA_VERSION, tables: names };
	} catch (error) {
		await client.query("ROLLBACK").catch(() => undefined);
		throw error;
	} finally {
		client.release();
	}
}

export function qualifiedDeliveryTables(options: DeliverySchemaOptions = {}) {
	const schema = deliverySchemaName(options);
	const names = deliveryTableNames(options);
	return {
		schema,
		names,
		meta: fq(schema, names.meta),
		webhookEndpoint: fq(schema, names.webhookEndpoint),
		event: fq(schema, names.event),
		payload: fq(schema, names.payload),
		job: fq(schema, names.job),
		attempt: fq(schema, names.attempt),
		worker: fq(schema, names.worker),
	};
}
