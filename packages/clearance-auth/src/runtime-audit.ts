import type pg from "pg";
import {
	appendRuntimeAuditInTransaction,
	createRuntimeAuditTable,
	type RuntimeAuditTable,
} from "@clearance/delivery";
import type {
	InternalRuntimeAuditBinding,
	InternalRuntimeAuditDraft,
} from "../../runtime/src/internal/runtime-audit.js";
import {
	attachInternalRuntimeAudit,
	readInternalRuntimeAudit,
} from "../../runtime/src/internal/runtime-audit.js";
import type { ClearanceTransactionQuery } from "./public-types/index.js";

const MIGRATION_ID = "runtime-audit-outbox-v2";
const DEFAULT_TABLE = "clearance_runtime_audit_events";
const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const MAX_IDENTIFIER_LENGTH = 63;
const SENSITIVE_METADATA_KEY =
	/(?:authorization|cookie|credential|password|secret|token|bearer|jwt|api[-_]?key|private[-_]?key)/i;
const SENSITIVE_METADATA_VALUE = /(?:bearer\s+|clr(?:_|-)[a-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{8,}\.|(?:https?|wss?):\/\/|\b[^\s@]+@[^\s@]+\.[^\s@]+\b)/i;

type RuntimeAuditScope = Readonly<{
	projectId: string;
	environmentId: string;
}>;

type RuntimeAuditOptions = RuntimeAuditScope &
	Readonly<{
		schema?: string;
		prefix?: string;
	}>;

type Queryable = Pick<pg.Pool, "query"> | Pick<ClearanceTransactionQuery, "rawTransactionQuery">;

export type RuntimeAuditOutboxMigrationPlan = Readonly<{
	pendingTables: number;
	pendingFields: number;
	pendingSecurityMigrations: readonly string[];
	compileSql(): Promise<string>;
	apply(): Promise<void>;
}>;

export class RuntimeAuditSchemaError extends Error {
	readonly code = "RUNTIME_AUDIT_SCHEMA_INVALID" as const;

	constructor() {
		super("Runtime audit schema is incompatible with the append-only authority");
		this.name = "RuntimeAuditSchemaError";
	}
}

export type RuntimeAuditOutbox = Readonly<{
	readonly binding: InternalRuntimeAuditBinding;
	readonly auditTable: RuntimeAuditTable;
	planMigration(): Promise<RuntimeAuditOutboxMigrationPlan>;
	applyMigration(transaction?: Queryable): Promise<void>;
}>;

function assertScopePart(value: string, label: string): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 1_024 ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		throw new Error(`runtimeAudit ${label} is invalid`);
	}
	return value;
}

function assertIdentifier(
	value: string | undefined,
	label: string,
	maxLength = MAX_IDENTIFIER_LENGTH,
): string | undefined {
	if (value === undefined) return undefined;
	if (
		typeof value !== "string" ||
		!IDENTIFIER.test(value) ||
		value.length > maxLength
	) {
		throw new Error(`runtimeAudit ${label} must be a safe PostgreSQL identifier`);
	}
	return value;
}

function quoteIdentifier(value: string): string {
	return `"${value.replaceAll('"', '""')}"`;
}

function boundedIdentifier(value: string, label: string): string {
	if (value.length > MAX_IDENTIFIER_LENGTH) {
		throw new Error(`runtimeAudit ${label} exceeds PostgreSQL identifier length`);
	}
	return value;
}

function tableNames(input: RuntimeAuditOptions): Readonly<{
	schema?: string;
	table: string;
	qualifiedTable: string;
	updateFunction: string;
	deleteFunction: string;
	truncateFunction: string;
	updateTrigger: string;
	deleteTrigger: string;
	truncateTrigger: string;
	scopeTimeIndex: string;
	scopeActionIndex: string;
	scopeCreatedIdIndex: string;
	scopeActionCreatedIdIndex: string;
}> {
	const schema = assertIdentifier(input.schema, "schema");
	const prefix = assertIdentifier(input.prefix, "prefix", 30);
	const table = boundedIdentifier(
		prefix ? `${prefix}_runtime_audit_events` : DEFAULT_TABLE,
		"table name",
	);
	const name = (suffix: string) => boundedIdentifier(
		`${prefix ?? "clearance"}_runtime_audit_${suffix}`,
		`${suffix} name`,
	);
	return Object.freeze({
		schema,
		table,
		qualifiedTable: schema
			? `${quoteIdentifier(schema)}.${quoteIdentifier(table)}`
			: quoteIdentifier(table),
		updateFunction: name("reject_update_v1"),
		deleteFunction: name("reject_delete_v1"),
		truncateFunction: name("reject_truncate_v1"),
		updateTrigger: name("append_only_update_v1"),
		deleteTrigger: name("append_only_delete_v1"),
		truncateTrigger: name("append_only_truncate_v1"),
		scopeTimeIndex: name("scope_time_v1"),
		scopeActionIndex: name("scope_action_v1"),
		scopeCreatedIdIndex: name("scope_created_id_v2"),
		scopeActionCreatedIdIndex: name("scope_action_created_id_v2"),
	});
}

function redactedMetadata(value: unknown, depth = 0): unknown {
	if (depth > 8) return "[REDACTED]";
	if (typeof value === "string") {
		return SENSITIVE_METADATA_VALUE.test(value) ? "[REDACTED]" : value;
	}
	if (value === null || typeof value !== "object") return value;
	if (Array.isArray(value)) return value.map((entry) => redactedMetadata(entry, depth + 1));
	return Object.fromEntries(
		Object.entries(value).flatMap(([key, entry]) =>
			SENSITIVE_METADATA_KEY.test(key)
				? []
				: [[key, redactedMetadata(entry, depth + 1)]],
		),
	);
}

function migrationSql(names: ReturnType<typeof tableNames>): string {
	const qualifiedFunction = (name: string) =>
		names.schema
			? `${quoteIdentifier(names.schema)}.${quoteIdentifier(name)}`
			: quoteIdentifier(name);
	return [
		`CREATE TABLE IF NOT EXISTS ${names.qualifiedTable} (
			sequence bigint GENERATED ALWAYS AS IDENTITY CONSTRAINT ${quoteIdentifier(nameFor(names, "sequence_pkey"))} PRIMARY KEY,
			id text NOT NULL CONSTRAINT ${quoteIdentifier(nameFor(names, "id_key"))} UNIQUE,
			correlation_id text NOT NULL,
			project_id text NOT NULL,
			environment_id text NOT NULL,
			organization_id text,
			actor text NOT NULL,
			action text NOT NULL,
			subject_type text,
			subject_id text,
			outcome text NOT NULL CONSTRAINT ${quoteIdentifier(nameFor(names, "outcome_ck"))} CHECK (outcome IN ('success', 'failure', 'pending')),
			source text NOT NULL CONSTRAINT ${quoteIdentifier(nameFor(names, "source_ck"))} CHECK (source IN ('system', 'sso', 'scim')),
			message text NOT NULL,
			metadata jsonb,
			created_at timestamptz NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(names.scopeTimeIndex)} ON ${names.qualifiedTable} (project_id, environment_id, created_at DESC, sequence DESC)`,
		`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(names.scopeActionIndex)} ON ${names.qualifiedTable} (project_id, environment_id, action, created_at DESC, sequence DESC)`,
		`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(names.scopeCreatedIdIndex)} ON ${names.qualifiedTable} (project_id, environment_id, created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS ${quoteIdentifier(names.scopeActionCreatedIdIndex)} ON ${names.qualifiedTable} (project_id, environment_id, action, created_at DESC, id DESC)`,
		`CREATE OR REPLACE FUNCTION ${qualifiedFunction(names.updateFunction)}()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'runtime audit events are append-only' USING ERRCODE = 'CLR01'; END $$`,
		`ALTER FUNCTION ${qualifiedFunction(names.updateFunction)}() SECURITY INVOKER`,
		`CREATE OR REPLACE FUNCTION ${qualifiedFunction(names.deleteFunction)}()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'runtime audit events are append-only' USING ERRCODE = 'CLR01'; END $$`,
		`ALTER FUNCTION ${qualifiedFunction(names.deleteFunction)}() SECURITY INVOKER`,
		`CREATE OR REPLACE FUNCTION ${qualifiedFunction(names.truncateFunction)}()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'runtime audit events are append-only' USING ERRCODE = 'CLR01'; END $$`,
		`ALTER FUNCTION ${qualifiedFunction(names.truncateFunction)}() SECURITY INVOKER`,
		`DROP TRIGGER IF EXISTS ${quoteIdentifier(names.updateTrigger)} ON ${names.qualifiedTable}`,
		`CREATE TRIGGER ${quoteIdentifier(names.updateTrigger)} BEFORE UPDATE ON ${names.qualifiedTable} FOR EACH ROW EXECUTE FUNCTION ${qualifiedFunction(names.updateFunction)}()`,
		`DROP TRIGGER IF EXISTS ${quoteIdentifier(names.deleteTrigger)} ON ${names.qualifiedTable}`,
		`CREATE TRIGGER ${quoteIdentifier(names.deleteTrigger)} BEFORE DELETE ON ${names.qualifiedTable} FOR EACH ROW EXECUTE FUNCTION ${qualifiedFunction(names.deleteFunction)}()`,
		`DROP TRIGGER IF EXISTS ${quoteIdentifier(names.truncateTrigger)} ON ${names.qualifiedTable}`,
		`CREATE TRIGGER ${quoteIdentifier(names.truncateTrigger)} BEFORE TRUNCATE ON ${names.qualifiedTable} FOR EACH STATEMENT EXECUTE FUNCTION ${qualifiedFunction(names.truncateFunction)}()`,
	].map((statement) => `${statement};`).join("\n");
}

async function query(
	target: Queryable,
	text: string,
	values?: readonly unknown[],
): Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }> {
	if ("rawTransactionQuery" in target) {
		return target.rawTransactionQuery(text, values);
	}
	const pool = target as Pick<pg.Pool, "query">;
	return values === undefined
		? pool.query<Record<string, unknown>>(text)
		: pool.query<Record<string, unknown>>(text, [...values]);
}

function nameFor(names: ReturnType<typeof tableNames>, suffix: string): string {
	return boundedIdentifier(`${names.table}_${suffix}`, `${suffix} name`);
}

async function setupReady(target: Queryable, names: ReturnType<typeof tableNames>): Promise<boolean> {
	const schema =
		names.schema ??
		String(
			(await query(target, "SELECT current_schema() AS schema")).rows[0]
				?.schema ?? "",
		);
	if (!schema) return false;
	const expectedColumns = JSON.stringify([
		["sequence", "bigint", false], ["id", "text", false], ["correlation_id", "text", false],
		["project_id", "text", false], ["environment_id", "text", false], ["organization_id", "text", true],
		["actor", "text", false], ["action", "text", false], ["subject_type", "text", true],
		["subject_id", "text", true], ["outcome", "text", false], ["source", "text", false],
		["message", "text", false], ["metadata", "jsonb", true], ["created_at", "timestamp with time zone", false],
	]);
	const result = await query(
		target,
		`WITH target AS (
			SELECT c.oid, c.relrowsecurity, c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind='r' AND c.relpersistence='p'
		), columns_ready AS (
			SELECT jsonb_agg(jsonb_build_array(a.attname, format_type(a.atttypid,a.atttypmod), NOT a.attnotnull) ORDER BY a.attnum) = $3::jsonb AS ready
			FROM pg_attribute a JOIN target ON target.oid=a.attrelid WHERE a.attnum>0 AND NOT a.attisdropped
		)
		SELECT EXISTS(SELECT 1 FROM target WHERE NOT relrowsecurity AND NOT relforcerowsecurity)
			AND COALESCE((SELECT ready FROM columns_ready),false)
			AND EXISTS (
				SELECT 1 FROM pg_attribute a JOIN target ON target.oid=a.attrelid
				WHERE a.attname='sequence' AND a.attidentity='a' AND a.attnum=1
			)
			AND (SELECT count(*) FROM pg_constraint con JOIN target ON target.oid=con.conrelid) = 4
			AND EXISTS (
				SELECT 1 FROM pg_constraint con JOIN target ON target.oid=con.conrelid
				WHERE con.conname=$4 AND con.contype='p' AND con.conkey=ARRAY[1]::smallint[]
					AND NOT con.condeferrable AND con.convalidated
			)
			AND EXISTS (
				SELECT 1 FROM pg_constraint con JOIN target ON target.oid=con.conrelid
				WHERE con.conname=$5 AND con.contype='u' AND con.conkey=ARRAY[2]::smallint[]
					AND NOT con.condeferrable AND con.convalidated
			)
			AND EXISTS (
				SELECT 1 FROM pg_constraint con JOIN target ON target.oid=con.conrelid
				WHERE con.conname=$6 AND con.contype='c' AND con.convalidated
					AND regexp_replace(lower(pg_get_constraintdef(con.oid, true)), '\\s+', '', 'g') = 'check(outcome=any(array[''success''::text,''failure''::text,''pending''::text]))'
			)
			AND EXISTS (
				SELECT 1 FROM pg_constraint con JOIN target ON target.oid=con.conrelid
				WHERE con.conname=$7 AND con.contype='c' AND con.convalidated
					AND regexp_replace(lower(pg_get_constraintdef(con.oid, true)), '\\s+', '', 'g') = 'check(source=any(array[''system''::text,''sso''::text,''scim''::text]))'
			)
			AND EXISTS (
				SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN target ON target.oid=i.indrelid
				WHERE c.relname=$8 AND i.indisvalid AND i.indisready AND NOT i.indisunique AND i.indnkeyatts=4 AND i.indnatts=4
					AND i.indkey::text='4 5 15 1' AND i.indoption::text='0 0 3 3' AND i.indpred IS NULL
			)
			AND EXISTS (
				SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN target ON target.oid=i.indrelid
				WHERE c.relname=$9 AND i.indisvalid AND i.indisready AND NOT i.indisunique AND i.indnkeyatts=5 AND i.indnatts=5
					AND i.indkey::text='4 5 8 15 1' AND i.indoption::text='0 0 0 3 3' AND i.indpred IS NULL
			)
			AND EXISTS (
				SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN target ON target.oid=i.indrelid
				WHERE c.relname=$10 AND i.indisvalid AND i.indisready AND NOT i.indisunique AND i.indnkeyatts=4 AND i.indnatts=4
					AND i.indkey::text='4 5 15 2' AND i.indoption::text='0 0 3 3' AND i.indpred IS NULL
			)
			AND EXISTS (
				SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN target ON target.oid=i.indrelid
				WHERE c.relname=$11 AND i.indisvalid AND i.indisready AND NOT i.indisunique AND i.indnkeyatts=5 AND i.indnatts=5
					AND i.indkey::text='4 5 8 15 2' AND i.indoption::text='0 0 0 3 3' AND i.indpred IS NULL
			)
			AND NOT EXISTS (
				SELECT 1 FROM pg_trigger t JOIN target ON target.oid=t.tgrelid
				WHERE NOT t.tgisinternal AND t.tgname IN ($12,$13,$14)
					AND NOT ((t.tgname=$12 AND t.tgtype=19 AND t.tgenabled='O')
						OR (t.tgname=$13 AND t.tgtype=11 AND t.tgenabled='O')
						OR (t.tgname=$14 AND t.tgtype=34 AND t.tgenabled='O'))
			)
			AND (SELECT count(*) FROM pg_trigger t JOIN target ON target.oid=t.tgrelid
				WHERE NOT t.tgisinternal) = 3
			AND (SELECT count(*) FROM pg_trigger t JOIN target ON target.oid=t.tgrelid
				WHERE NOT t.tgisinternal AND t.tgname IN ($12,$13,$14) AND octet_length(t.tgargs)=0) = 3
			AND NOT EXISTS (
				SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace JOIN target ON target.oid=t.tgrelid
				WHERE NOT t.tgisinternal AND t.tgname IN ($12,$13,$14)
					AND NOT (n.nspname=$1 AND ((t.tgname=$12 AND p.proname=$15) OR (t.tgname=$13 AND p.proname=$16) OR (t.tgname=$14 AND p.proname=$17)))
			)
			AND (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
				WHERE n.nspname=$1 AND p.proname IN ($15,$16,$17) AND p.pronargs=0
					AND p.prorettype='trigger'::regtype
					AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
					AND NOT p.prosecdef
					AND regexp_replace(lower(p.prosrc), '\\s+', '', 'g') = 'beginraiseexception''runtimeauditeventsareappend-only''usingerrcode=''clr01'';end') = 3
			AS ready`,
		[
			schema, names.table, expectedColumns,
			nameFor(names, "sequence_pkey"), nameFor(names, "id_key"), nameFor(names, "outcome_ck"), nameFor(names, "source_ck"),
			names.scopeTimeIndex, names.scopeActionIndex,
			names.scopeCreatedIdIndex, names.scopeActionCreatedIdIndex,
			names.updateTrigger, names.deleteTrigger, names.truncateTrigger,
			names.updateFunction, names.deleteFunction, names.truncateFunction,
		],
	);
	return result.rows[0]?.ready === true;
}

async function schemaState(
	target: Queryable,
	names: ReturnType<typeof tableNames>,
): Promise<"absent" | "ready" | "invalid"> {
	const schema = names.schema ?? String((await query(target, "SELECT current_schema() AS schema")).rows[0]?.schema ?? "");
	const exists = await query(
		target,
		`SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname=$1 AND c.relname=$2) AS exists`,
		[schema, names.table],
	);
	if (exists.rows[0]?.exists !== true) return "absent";
	return (await setupReady(target, names)) ? "ready" : "invalid";
}

async function baseStructureReady(
	target: Queryable,
	names: ReturnType<typeof tableNames>,
): Promise<boolean> {
	const schema = names.schema ?? String((await query(target, "SELECT current_schema() AS schema")).rows[0]?.schema ?? "");
	const columns = JSON.stringify([
		["sequence", "bigint", false], ["id", "text", false], ["correlation_id", "text", false], ["project_id", "text", false], ["environment_id", "text", false], ["organization_id", "text", true], ["actor", "text", false], ["action", "text", false], ["subject_type", "text", true], ["subject_id", "text", true], ["outcome", "text", false], ["source", "text", false], ["message", "text", false], ["metadata", "jsonb", true], ["created_at", "timestamp with time zone", false],
	]);
	const result = await query(target, `WITH target AS (
		SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
	), columns_ready AS (
		SELECT jsonb_agg(jsonb_build_array(a.attname, format_type(a.atttypid,a.atttypmod), NOT a.attnotnull) ORDER BY a.attnum)=$3::jsonb AS ready
		FROM pg_attribute a JOIN target ON target.oid=a.attrelid WHERE a.attnum>0 AND NOT a.attisdropped
	)
	SELECT EXISTS(SELECT 1 FROM target) AND COALESCE((SELECT ready FROM columns_ready),false)
		AND EXISTS (SELECT 1 FROM pg_attribute a JOIN target ON target.oid=a.attrelid WHERE a.attname='sequence' AND a.attnum=1 AND a.attidentity='a')
		AND (SELECT count(*) FROM pg_constraint con JOIN target ON target.oid=con.conrelid)=4
		AND EXISTS (SELECT 1 FROM pg_constraint con JOIN target ON target.oid=con.conrelid WHERE con.conname=$4 AND con.contype='p' AND con.conkey=ARRAY[1]::smallint[] AND NOT con.condeferrable AND con.convalidated)
		AND EXISTS (SELECT 1 FROM pg_constraint con JOIN target ON target.oid=con.conrelid WHERE con.conname=$5 AND con.contype='u' AND con.conkey=ARRAY[2]::smallint[] AND NOT con.condeferrable AND con.convalidated)
		AND EXISTS (SELECT 1 FROM pg_constraint con JOIN target ON target.oid=con.conrelid WHERE con.conname=$6 AND con.contype='c' AND con.convalidated AND regexp_replace(lower(pg_get_constraintdef(con.oid,true)), '\\s+', '', 'g')='check(outcome=any(array[''success''::text,''failure''::text,''pending''::text]))')
		AND EXISTS (SELECT 1 FROM pg_constraint con JOIN target ON target.oid=con.conrelid WHERE con.conname=$7 AND con.contype='c' AND con.convalidated AND regexp_replace(lower(pg_get_constraintdef(con.oid,true)), '\\s+', '', 'g')='check(source=any(array[''system''::text,''sso''::text,''scim''::text]))')
		AND NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN target ON target.oid=t.tgrelid
			WHERE NOT t.tgisinternal AND t.tgname NOT IN ($8,$9,$10)) AS ready`, [
		schema, names.table, columns,
		nameFor(names, "sequence_pkey"), nameFor(names, "id_key"), nameFor(names, "outcome_ck"), nameFor(names, "source_ck"),
		names.updateTrigger, names.deleteTrigger, names.truncateTrigger,
	]);
	return result.rows[0]?.ready === true;
}

function repairSql(names: ReturnType<typeof tableNames>): string {
	const qualifiedIndex = (name: string) => names.schema
		? `${quoteIdentifier(names.schema)}.${quoteIdentifier(name)}`
		: quoteIdentifier(name);
	return [
		`DROP INDEX IF EXISTS ${qualifiedIndex(names.scopeTimeIndex)}`,
		`DROP INDEX IF EXISTS ${qualifiedIndex(names.scopeActionIndex)}`,
		`DROP INDEX IF EXISTS ${qualifiedIndex(names.scopeCreatedIdIndex)}`,
		`DROP INDEX IF EXISTS ${qualifiedIndex(names.scopeActionCreatedIdIndex)}`,
		migrationSql(names),
	].map((statement) => `${statement};`).join("\n");
}

export function createRuntimeAuditOutbox(
	pool: pg.Pool,
	input: RuntimeAuditOptions,
): RuntimeAuditOutbox {
	const identity = Object.freeze({
		projectId: assertScopePart(input.projectId, "projectId"),
		environmentId: assertScopePart(input.environmentId, "environmentId"),
	});
	const names = tableNames(input);
	const auditTable = createRuntimeAuditTable({
		...(names.schema === undefined ? {} : { schema: names.schema }),
		table: names.table,
	});
	const sql = migrationSql(names);
	const repair = repairSql(names);
	const rawBinding: InternalRuntimeAuditBinding = Object.freeze({
		identity,
		async append(transaction, draft: InternalRuntimeAuditDraft): Promise<void> {
			if (typeof transaction.rawTransactionQuery !== "function") {
				throw new Error("runtime audit requires the owning PostgreSQL transaction");
			}
			const metadata = redactedMetadata({
				...draft.metadata,
				request: {
					operationId: draft.request.operationId,
					route: draft.request.route,
					method: draft.request.method,
					clientIp: draft.request.clientIp,
					userAgent: draft.request.userAgent,
				},
			}) as Record<string, unknown>;
			await appendRuntimeAuditInTransaction({
				rawTransactionQuery: transaction.rawTransactionQuery!,
			}, auditTable, {
				correlationId: draft.request.correlationId,
				projectId: identity.projectId,
				environmentId: identity.environmentId,
				organizationId: draft.organizationId,
				actor: draft.actor,
				action: draft.action,
				subjectType: draft.subjectType,
				subjectId: draft.subjectId,
				outcome: draft.outcome,
				source: draft.source,
				message: draft.message,
				metadata,
			});
		},
	});
	const bindingTarget = {};
	attachInternalRuntimeAudit(bindingTarget, rawBinding);
	const binding = readInternalRuntimeAudit(bindingTarget);
	if (!binding) throw new Error("runtime audit binding capture failed");

	let applyMigration: (transaction?: Queryable) => Promise<void>;
	applyMigration = async (transaction?: Queryable): Promise<void> => {
		if (transaction) {
			await query(
				transaction,
				"SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':clearance:runtime-audit-outbox:v1', 0))",
			);
			const state = await schemaState(transaction, names);
			if (state === "ready") return;
			if (state === "invalid" && !(await baseStructureReady(transaction, names))) {
				throw new RuntimeAuditSchemaError();
			}
			await query(transaction, state === "absent" ? sql : repair);
			if (!(await setupReady(transaction, names))) throw new RuntimeAuditSchemaError();
			return;
		}
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(
				"SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':clearance:runtime-audit-outbox:v1', 0))",
			);
			const state = await schemaState(client as Queryable, names);
			if (state === "ready") {
				await client.query("COMMIT");
				return;
			}
			if (state === "invalid" && !(await baseStructureReady(client as Queryable, names))) {
				throw new RuntimeAuditSchemaError();
			}
			await client.query(state === "absent" ? sql : repair);
			if (!(await setupReady(client as Queryable, names))) {
				throw new RuntimeAuditSchemaError();
			}
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	};
	return Object.freeze({
		binding,
		auditTable,
		applyMigration,
		async planMigration() {
			const state = await schemaState(pool, names);
			const baseReady = state === "invalid" && await baseStructureReady(pool, names);
			const incompatible = state === "invalid" && !baseReady;
			const pending = state === "absent";
			return {
				pendingTables: Number(pending),
				pendingFields: pending ? 15 : 0,
				pendingSecurityMigrations: state === "ready" ? [] : [MIGRATION_ID],
				compileSql: async () => {
					if (incompatible) throw new RuntimeAuditSchemaError();
					return pending ? sql : state === "ready" ? "" : repair;
				},
				apply: async () => {
					if (incompatible) throw new RuntimeAuditSchemaError();
					await applyMigration();
				},
			};
		},
	});
}
