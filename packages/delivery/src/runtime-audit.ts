import { randomUUID } from "node:crypto";
import { DeliveryError } from "./errors.js";

const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const MAX_IDENTIFIER_LENGTH = 63;
const RUNTIME_AUDIT_TABLE_SUFFIX = "_runtime_audit_events";
const SENSITIVE_METADATA_KEY =
	/(?:authorization|cookie|credential|password|secret|token|bearer|jwt|api[-_]?key|private[-_]?key)/i;
const SENSITIVE_METADATA_VALUE = /(?:bearer\s+|clr(?:_|-)[a-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{8,}\.|(?:https?|wss?):\/\/|\b[^\s@]+@[^\s@]+\.[^\s@]+\b)/i;

const runtimeAuditTableBrand: unique symbol = Symbol("runtime-audit-table");

export type RuntimeAuditTransaction = Readonly<{
	rawTransactionQuery: <Row extends Record<string, unknown> = Record<string, unknown>>(
		text: string,
		values?: readonly unknown[],
	) => Promise<{ rows: Row[]; rowCount: number | null }>;
}>;

/**
 * An immutable reference to an audit authority provisioned by the product.
 * Delivery deliberately owns no DDL for this table.
 */
export type RuntimeAuditTable = Readonly<{
	readonly [runtimeAuditTableBrand]: true;
	readonly schema?: string;
	readonly table: string;
	readonly qualifiedTable: string;
	readonly updateFunction: string;
	readonly deleteFunction: string;
	readonly truncateFunction: string;
	readonly updateTrigger: string;
	readonly deleteTrigger: string;
	readonly truncateTrigger: string;
}>;

export type RuntimeAuditInsert = Readonly<{
	correlationId: string;
	projectId: string;
	environmentId: string;
	organizationId: string | null;
	actor: string;
	action: string;
	subjectType: string | null;
	subjectId: string | null;
	outcome: "success" | "failure" | "pending";
	source: "system" | "sso" | "scim";
	message: string;
	metadata: Record<string, unknown>;
	createdAt?: Date;
}>;

function identifier(value: string, label: string): string {
	if (!IDENTIFIER.test(value) || value.length > MAX_IDENTIFIER_LENGTH) {
		throw new DeliveryError("DELIVERY_RUNTIME_AUDIT_IDENTIFIER_INVALID", `${label} must be a safe PostgreSQL identifier`);
	}
	return value;
}

function quoteIdentifier(value: string): string {
	return `"${value}"`;
}

export function createRuntimeAuditTable(input: Readonly<{
	schema?: string;
	table: string;
}>): RuntimeAuditTable {
	const schema = input.schema === undefined ? undefined : identifier(input.schema, "runtime audit schema");
	const table = identifier(input.table, "runtime audit table");
	const prefix = table.endsWith(RUNTIME_AUDIT_TABLE_SUFFIX)
		? table.slice(0, -RUNTIME_AUDIT_TABLE_SUFFIX.length)
		: "";
	if (!prefix || !IDENTIFIER.test(prefix)) {
		throw new DeliveryError("DELIVERY_RUNTIME_AUDIT_CAPABILITY_INVALID", "runtime audit table must use the owned runtime audit naming convention");
	}
	const capability: RuntimeAuditTable = {
		[runtimeAuditTableBrand]: true,
		...(schema === undefined ? {} : { schema }),
		table,
		qualifiedTable: schema === undefined
			? quoteIdentifier(table)
			: `${quoteIdentifier(schema)}.${quoteIdentifier(table)}`,
		updateFunction: identifier(`${prefix}_runtime_audit_reject_update_v1`, "runtime audit update function"),
		deleteFunction: identifier(`${prefix}_runtime_audit_reject_delete_v1`, "runtime audit delete function"),
		truncateFunction: identifier(`${prefix}_runtime_audit_reject_truncate_v1`, "runtime audit truncate function"),
		updateTrigger: identifier(`${prefix}_runtime_audit_append_only_update_v1`, "runtime audit update trigger"),
		deleteTrigger: identifier(`${prefix}_runtime_audit_append_only_delete_v1`, "runtime audit delete trigger"),
		truncateTrigger: identifier(`${prefix}_runtime_audit_append_only_truncate_v1`, "runtime audit truncate trigger"),
	};
	return Object.freeze(capability);
}

function assertTable(table: RuntimeAuditTable): void {
	if (table[runtimeAuditTableBrand] !== true) {
		throw new DeliveryError("DELIVERY_RUNTIME_AUDIT_CAPABILITY_INVALID", "runtime audit table capability is invalid");
	}
}

function redactMetadata(value: unknown, depth = 0): unknown {
	if (depth > 8) return "[REDACTED]";
	if (typeof value === "string") return SENSITIVE_METADATA_VALUE.test(value) ? "[REDACTED]" : value;
	if (value === null || typeof value !== "object") return value;
	if (Array.isArray(value)) return value.map((entry) => redactMetadata(entry, depth + 1));
	return Object.fromEntries(
		Object.entries(value).flatMap(([key, entry]) =>
			SENSITIVE_METADATA_KEY.test(key) ? [] : [[key, redactMetadata(entry, depth + 1)]],
		),
	);
}

/** Fail closed for missing or structurally incompatible product-owned audit tables. */
export async function assertRuntimeAuditTableReady(
	transaction: RuntimeAuditTransaction,
	table: RuntimeAuditTable,
): Promise<void> {
	assertTable(table);
	const schema = table.schema ?? String(
		(await transaction.rawTransactionQuery<{ schema: string }>("SELECT current_schema() AS schema")).rows[0]?.schema ?? "",
	);
	const expectedColumns = JSON.stringify([
		["sequence", "bigint", false], ["id", "text", false], ["correlation_id", "text", false],
		["project_id", "text", false], ["environment_id", "text", false], ["organization_id", "text", true],
		["actor", "text", false], ["action", "text", false], ["subject_type", "text", true],
		["subject_id", "text", true], ["outcome", "text", false], ["source", "text", false],
		["message", "text", false], ["metadata", "jsonb", true], ["created_at", "timestamp with time zone", false],
	]);
	const result = await transaction.rawTransactionQuery<{ ready: boolean }>(
		`WITH target AS (
			SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
			WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind='r' AND c.relpersistence='p'
				AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
		), columns_ready AS (
			SELECT jsonb_agg(jsonb_build_array(a.attname, format_type(a.atttypid,a.atttypmod), NOT a.attnotnull) ORDER BY a.attnum)=$3::jsonb AS ready
			FROM pg_attribute a JOIN target ON target.oid=a.attrelid WHERE a.attnum>0 AND NOT a.attisdropped
		)
		SELECT EXISTS(SELECT 1 FROM target) AND COALESCE((SELECT ready FROM columns_ready),false)
			AND (SELECT count(*) FROM pg_trigger t JOIN target ON target.oid=t.tgrelid WHERE NOT t.tgisinternal)=3
			AND NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN target ON target.oid=t.tgrelid
				WHERE NOT t.tgisinternal AND t.tgname IN ($4,$5,$6)
					AND NOT ((t.tgname=$4 AND t.tgtype=19 AND t.tgenabled='O')
						OR (t.tgname=$5 AND t.tgtype=11 AND t.tgenabled='O')
						OR (t.tgname=$6 AND t.tgtype=34 AND t.tgenabled='O')))
			AND (SELECT count(*) FROM pg_trigger t JOIN target ON target.oid=t.tgrelid
				WHERE NOT t.tgisinternal AND t.tgname IN ($4,$5,$6) AND octet_length(t.tgargs)=0)=3
			AND NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace JOIN target ON target.oid=t.tgrelid
				WHERE NOT t.tgisinternal AND t.tgname IN ($4,$5,$6)
					AND NOT (n.nspname=$1 AND ((t.tgname=$4 AND p.proname=$7) OR (t.tgname=$5 AND p.proname=$8) OR (t.tgname=$6 AND p.proname=$9))))
			AND (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
				WHERE n.nspname=$1 AND p.proname IN ($7,$8,$9) AND p.pronargs=0
					AND p.prorettype='trigger'::regtype AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
					AND NOT p.prosecdef
					AND regexp_replace(lower(p.prosrc), '\\s+', '', 'g')='beginraiseexception''runtimeauditeventsareappend-only''usingerrcode=''clr01'';end')=3
			AS ready`,
		[
			schema, table.table, expectedColumns,
			table.updateTrigger, table.deleteTrigger, table.truncateTrigger,
			table.updateFunction, table.deleteFunction, table.truncateFunction,
		],
	);
	if (result.rows[0]?.ready !== true) {
		throw new DeliveryError("DELIVERY_RUNTIME_AUDIT_SCHEMA_INVALID", "runtime audit table is absent or incompatible");
	}
}

/** Insert through the caller's already-active transaction. This function never starts or commits one. */
export async function appendRuntimeAuditInTransaction(
	transaction: RuntimeAuditTransaction,
	table: RuntimeAuditTable,
	entry: RuntimeAuditInsert,
): Promise<void> {
	if (typeof transaction.rawTransactionQuery !== "function") {
		throw new DeliveryError("DELIVERY_TRANSACTION_REQUIRED", "runtime audit requires the owning PostgreSQL transaction");
	}
	assertTable(table);
	let metadata: string;
	try {
		metadata = JSON.stringify(redactMetadata(entry.metadata));
	} catch {
		throw new DeliveryError("DELIVERY_RUNTIME_AUDIT_METADATA_INVALID", "runtime audit metadata must be serializable");
	}
	await transaction.rawTransactionQuery(
		`INSERT INTO ${table.qualifiedTable} (
			id, correlation_id, project_id, environment_id, organization_id,
			actor, action, subject_type, subject_id, outcome, source, message,
			metadata, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14)`,
		[
			randomUUID(), entry.correlationId, entry.projectId, entry.environmentId,
			entry.organizationId, entry.actor, entry.action, entry.subjectType, entry.subjectId,
			entry.outcome, entry.source, entry.message, metadata,
			entry.createdAt ?? new Date(),
		],
	);
}
