import type pg from "pg";
import { redactRecord } from "../services/redact.js";
import type { PageCursorKey } from "../services/pagination.js";
import type { ResourceScope } from "../services/scope.js";
import type { AuditEvent } from "../types/resources.js";

const RUNTIME_AUDIT_EVENTS_TABLE = "clearance_runtime_audit_events";
const IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const MAX_IDENTIFIER_LENGTH = 63;

type Queryable = pg.Pool | pg.PoolClient;

interface RuntimeAuditEventRow {
	id: string;
	correlation_id: string;
	project_id: string;
	environment_id: string;
	organization_id: string | null;
	actor: string;
	action: string;
	subject_type: string | null;
	subject_id: string | null;
	outcome: AuditEvent["outcome"];
	source: Extract<AuditEvent["source"], "system" | "sso" | "scim">;
	message: string;
	metadata: Record<string, unknown> | null;
	created_at: Date | string;
}

export type RuntimeAuditEventPageInput = {
	scope: ResourceScope;
	limit: number;
	cursor?: PageCursorKey;
	action?: string;
	organizationId?: string;
	/** Strict archival upper bound. */
	before?: string;
};

/** Matches clearance-auth runtimeAudit schema/prefix configuration. */
export type RuntimeAuditStoreOptions = {
	schema?: string;
	prefix?: string;
};

/**
 * Read-only access to the runtime-owned audit outbox. This is deliberately a
 * separate source from store-v2: runtime rows are committed by the product
 * transaction and must never be imported into the management snapshot on a
 * read path.
 */
export interface RuntimeAuditEventReader {
	listPage(input: RuntimeAuditEventPageInput): Promise<{
		events: AuditEvent[];
		hasMore: boolean;
	}>;
	getById(input: {
		scope: ResourceScope;
		id: string;
	}): Promise<AuditEvent | null>;
}

function iso(value: Date | string): string {
	return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function optional<K extends string>(key: K, value: string | null) {
	return value === null ? {} : { [key]: value };
}

function mapRuntimeAuditEvent(row: RuntimeAuditEventRow): AuditEvent {
	return {
		id: row.id,
		correlationId: row.correlation_id,
		projectId: row.project_id,
		environmentId: row.environment_id,
		...optional("organizationId", row.organization_id),
		actor: row.actor,
		action: row.action,
		...optional("subjectType", row.subject_type),
		...optional("subjectId", row.subject_id),
		outcome: row.outcome,
		source: row.source,
		message: row.message,
		...(row.metadata === null ? {} : { metadata: redactRecord(row.metadata) }),
		createdAt: iso(row.created_at),
	};
}

function identifier(value: string | undefined, label: string, max = MAX_IDENTIFIER_LENGTH): string | undefined {
	if (value === undefined) return undefined;
	if (!IDENTIFIER.test(value) || value.length > max) {
		throw new Error(`runtimeAudit ${label} must be a safe PostgreSQL identifier`);
	}
	return value;
}

function names(input: RuntimeAuditStoreOptions): {
	relation: string;
	qualifiedTable: string;
} {
	const schema = identifier(input.schema, "schema");
	const prefix = identifier(input.prefix, "prefix", 30);
	const table = prefix ? `${prefix}_runtime_audit_events` : RUNTIME_AUDIT_EVENTS_TABLE;
	if (table.length > MAX_IDENTIFIER_LENGTH) {
		throw new Error("runtimeAudit table name exceeds PostgreSQL identifier length");
	}
	const quote = (value: string) => `"${value}"`;
	return {
		relation: schema ? `${schema}.${table}` : table,
		qualifiedTable: schema ? `${quote(schema)}.${quote(table)}` : quote(table),
	};
}

async function tableExists(queryable: Queryable, relation: string): Promise<boolean> {
	const result = await queryable.query<{ relation: string | null }>(
		"SELECT to_regclass($1) AS relation",
		[relation],
	);
	return result.rows[0]?.relation !== null && result.rows[0]?.relation !== undefined;
}

export class PgRuntimeAuditEventReader implements RuntimeAuditEventReader {
	private readonly table: ReturnType<typeof names>;

	constructor(
		private readonly pool: pg.Pool,
		options: RuntimeAuditStoreOptions = {},
	) {
		this.table = names(options);
	}

	async listPage(input: RuntimeAuditEventPageInput): Promise<{
		events: AuditEvent[];
		hasMore: boolean;
	}> {
		if (!(await tableExists(this.pool, this.table.relation))) return { events: [], hasMore: false };
		const params: unknown[] = [input.scope.projectId, input.scope.environmentId];
		const where = ["project_id = $1", "environment_id = $2"];
		if (input.action) {
			params.push(input.action);
			where.push(`action = $${params.length}`);
		}
		if (input.organizationId) {
			params.push(input.organizationId);
			where.push(`organization_id = $${params.length}`);
		}
		if (input.before) {
			params.push(input.before);
			where.push(`created_at < $${params.length}::timestamptz`);
		}
		if (input.cursor) {
			params.push(input.cursor.createdAt, input.cursor.id);
			where.push(
				`(created_at, id) < ($${params.length - 1}::timestamptz, $${params.length})`,
			);
		}
		params.push(input.limit + 1);
		const result = await this.pool.query<RuntimeAuditEventRow>(
			`SELECT id, correlation_id, project_id, environment_id, organization_id,
			        actor, action, subject_type, subject_id, outcome, source, message,
			        metadata, created_at
			 FROM ${this.table.qualifiedTable}
			 WHERE ${where.join(" AND ")}
			 ORDER BY created_at DESC, id DESC
			 LIMIT $${params.length}`,
			params,
		);
		return {
			events: result.rows.slice(0, input.limit).map(mapRuntimeAuditEvent),
			hasMore: result.rows.length > input.limit,
		};
	}

	async getById(input: {
		scope: ResourceScope;
		id: string;
	}): Promise<AuditEvent | null> {
		if (!(await tableExists(this.pool, this.table.relation))) return null;
		const result = await this.pool.query<RuntimeAuditEventRow>(
			`SELECT id, correlation_id, project_id, environment_id, organization_id,
			        actor, action, subject_type, subject_id, outcome, source, message,
			        metadata, created_at
			 FROM ${this.table.qualifiedTable}
			 WHERE id = $1 AND project_id = $2 AND environment_id = $3
			 LIMIT 1`,
			[input.id, input.scope.projectId, input.scope.environmentId],
		);
		const row = result.rows[0];
		return row ? mapRuntimeAuditEvent(row) : null;
	}
}
