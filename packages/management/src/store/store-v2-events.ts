import type pg from "pg";
import {
	AUDIT_PRUNED_ACTION,
	auditMaxEvents,
	buildAuditEvent,
} from "../services/audit.js";
import type { PageCursorKey } from "../services/pagination.js";
import type { ResourceScope } from "../services/scope.js";
import type { AuditEvent } from "../types/resources.js";
import type { StoreV2TableNames } from "./store-v2-schema.js";

const EVENTS_STATE_KEY = "store_v2_events_state";

type Queryable = pg.Pool | pg.PoolClient;

interface EventRow {
	id: string;
	correlation_id: string;
	project_id: string | null;
	environment_id: string | null;
	organization_id: string | null;
	actor: string;
	action: string;
	subject_type: string;
	subject_id: string | null;
	outcome: AuditEvent["outcome"];
	source: AuditEvent["source"];
	message: string;
	metadata: Record<string, unknown> | null;
	created_at: Date | string;
	retention_marker: boolean;
	visible: boolean;
}

interface EventsState {
	retainedCount: number;
	markerId: string | null;
	droppedCount: number;
	oldestDroppedCreatedAt: string | null;
}

export interface StoreV2EventDelta {
	inserted: AuditEvent[];
	removedIds: string[];
}

function iso(value: Date | string): string {
	return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function optional<K extends string>(key: K, value: string | null) {
	return value === null ? {} : { [key]: value };
}

function mapEvent(row: EventRow): AuditEvent {
	return {
		id: row.id,
		correlationId: row.correlation_id,
		...optional("projectId", row.project_id),
		...optional("environmentId", row.environment_id),
		...optional("organizationId", row.organization_id),
		actor: row.actor,
		action: row.action,
		subjectType: row.subject_type,
		...optional("subjectId", row.subject_id),
		outcome: row.outcome,
		source: row.source,
		message: row.message,
		...(row.metadata === null ? {} : { metadata: row.metadata }),
		createdAt: iso(row.created_at),
	};
}

function isRetentionMarker(event: AuditEvent): boolean {
	return event.actor === "system" && event.action === AUDIT_PRUNED_ACTION;
}

async function writeState(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	state: EventsState,
): Promise<void> {
	await client.query(
		`INSERT INTO ${tables.meta} (key, value, updated_at)
		 VALUES ($1, $2::jsonb, now())
		 ON CONFLICT (key) DO UPDATE
		 SET value = EXCLUDED.value, updated_at = now()`,
		[EVENTS_STATE_KEY, JSON.stringify(state)],
	);
}

async function readState(
	queryable: Queryable,
	tables: StoreV2TableNames,
	forUpdate = false,
): Promise<EventsState> {
	const result = await queryable.query<{ value: unknown }>(
		`SELECT value FROM ${tables.meta} WHERE key = $1${forUpdate ? " FOR UPDATE" : ""}`,
		[EVENTS_STATE_KEY],
	);
	const value = result.rows[0]?.value;
	if (value && typeof value === "object" && !Array.isArray(value)) {
		const state = value as Partial<EventsState>;
		if (
			Number.isSafeInteger(state.retainedCount) &&
			(state.markerId === null || typeof state.markerId === "string") &&
			Number.isSafeInteger(state.droppedCount) &&
			(state.oldestDroppedCreatedAt === null ||
				typeof state.oldestDroppedCreatedAt === "string")
		) {
			return state as EventsState;
		}
	}
	throw new Error("STORE_V2_EVENTS_STATE_INVALID");
}

async function insertEvent(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	event: AuditEvent,
	revision: number,
	retentionMarker = false,
): Promise<void> {
	await client.query(
		`INSERT INTO ${tables.events}
		 (id, correlation_id, project_id, environment_id, organization_id,
		  actor, action, subject_type, subject_id, outcome, source, message,
		  metadata, created_at, committed_revision, retention_marker, visible)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
		         $13::jsonb, $14, $15, $16, true)`,
		[
			event.id,
			event.correlationId,
			event.projectId ?? null,
			event.environmentId ?? null,
			event.organizationId ?? null,
			event.actor,
			event.action,
			event.subjectType,
			event.subjectId ?? null,
			event.outcome,
			event.source,
			event.message,
			event.metadata === undefined ? null : JSON.stringify(event.metadata),
			event.createdAt,
			revision,
			retentionMarker,
		],
	);
}

function markerState(event: AuditEvent | undefined): Omit<EventsState, "retainedCount"> {
	const metadata = event?.metadata as
		| { droppedCount?: unknown; oldestDroppedCreatedAt?: unknown }
		| undefined;
	return {
		markerId: event?.id ?? null,
		droppedCount: Number(metadata?.droppedCount ?? 0) || 0,
		oldestDroppedCreatedAt:
			typeof metadata?.oldestDroppedCreatedAt === "string"
				? metadata.oldestDroppedCreatedAt
				: null,
	};
}

export async function replaceStoreV2Events(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	events: readonly AuditEvent[],
	revision: number,
): Promise<void> {
	await client.query(`DELETE FROM ${tables.events} WHERE visible = true`);
	const marker = events.find(isRetentionMarker);
	for (const event of events) {
		await insertEvent(client, tables, event, revision, event.id === marker?.id);
	}
	await writeState(client, tables, {
		retainedCount: events.length,
		...markerState(marker),
	});
}

export async function appendStoreV2Events(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	events: readonly AuditEvent[],
	revision: number,
): Promise<StoreV2EventDelta> {
	const state = await readState(client, tables, true);
	for (const event of events) {
		await insertEvent(client, tables, event, revision);
	}

	const max = auditMaxEvents();
	const total = state.retainedCount + events.length;
	if (total <= max) {
		await writeState(client, tables, { ...state, retainedCount: total });
		return { inserted: [...events], removedIds: [] };
	}

	const removedIds: string[] = [];
	if (state.markerId) {
		await client.query(
			`UPDATE ${tables.events} SET visible = false WHERE id = $1 AND visible = true`,
			[state.markerId],
		);
		removedIds.push(state.markerId);
	}
	const dropCount = total - max + (state.markerId ? 0 : 1);
	const dropped = await client.query<{ id: string; created_at: Date | string }>(
		`UPDATE ${tables.events}
		 SET visible = false
		 WHERE id IN (
			SELECT id FROM ${tables.events}
			WHERE retention_marker = false AND visible = true
			ORDER BY created_at ASC, id ASC
			LIMIT $1
		 )
		 RETURNING id, created_at`,
		[dropCount],
	);
	removedIds.push(...dropped.rows.map((row) => row.id));
	const droppedOldest = dropped.rows
		.map((row) => iso(row.created_at))
		.sort()[0] ?? null;
	const oldestDroppedCreatedAt = [
		state.oldestDroppedCreatedAt,
		droppedOldest,
	]
		.filter((value): value is string => Boolean(value))
		.sort()[0] ?? null;
	const cumulativeDropped = state.droppedCount + dropped.rows.length;
	const marker = buildAuditEvent({
		actor: "system",
		action: AUDIT_PRUNED_ACTION,
		subjectType: "audit_log",
		outcome: "success",
		source: "system",
		message: `Pruned ${cumulativeDropped} audit event(s) beyond retention cap ${max} (cumulative)`,
		metadata: {
			droppedCount: cumulativeDropped,
			oldestDroppedCreatedAt,
			cap: max,
		},
	});
	await insertEvent(client, tables, marker, revision, true);
	await writeState(client, tables, {
		retainedCount: max,
		markerId: marker.id,
		droppedCount: cumulativeDropped,
		oldestDroppedCreatedAt,
	});
	const removed = new Set(removedIds);
	return {
		inserted: [...events.filter((event) => !removed.has(event.id)), marker],
		removedIds,
	};
}

export async function readStoreV2Events(
	queryable: Queryable,
	tables: StoreV2TableNames,
): Promise<AuditEvent[]> {
	const result = await queryable.query<EventRow>(
		`SELECT * FROM ${tables.events} WHERE visible = true ORDER BY created_at DESC, id DESC`,
	);
	return result.rows.map(mapEvent);
}

export async function listStoreV2EventsPage(
	queryable: Queryable,
	tables: StoreV2TableNames,
	input: {
		scope: ResourceScope;
		limit: number;
		cursor?: PageCursorKey;
		action?: string;
		organizationId?: string;
	},
): Promise<{ events: AuditEvent[]; hasMore: boolean }> {
	const params: unknown[] = [input.scope.projectId, input.scope.environmentId];
	const where = [
		`visible = true`,
		`(project_id IS NULL OR project_id = $1)`,
		`(environment_id IS NULL OR environment_id = $2)`,
	];
	if (input.action) {
		params.push(input.action);
		where.push(`action = $${params.length}`);
	}
	if (input.organizationId) {
		params.push(input.organizationId);
		where.push(`organization_id = $${params.length}`);
	}
	if (input.cursor) {
		params.push(input.cursor.createdAt, input.cursor.id);
		where.push(`(created_at, id) < ($${params.length - 1}::timestamptz, $${params.length})`);
	}
	params.push(input.limit + 1);
	const result = await queryable.query<EventRow>(
		`SELECT * FROM ${tables.events}
		 WHERE ${where.join(" AND ")}
		 ORDER BY created_at DESC, id DESC
		 LIMIT $${params.length}`,
		params,
	);
	return {
		events: result.rows.slice(0, input.limit).map(mapEvent),
		hasMore: result.rows.length > input.limit,
	};
}

export function applyStoreV2EventDelta(
	current: readonly AuditEvent[],
	delta: StoreV2EventDelta,
): AuditEvent[] {
	const removed = new Set(delta.removedIds);
	const retained = current.filter((event) => !removed.has(event.id));
	const inserted = [...delta.inserted].sort((left, right) =>
		left.createdAt === right.createdAt
			? right.id.localeCompare(left.id)
			: right.createdAt.localeCompare(left.createdAt),
	);
	const merged: AuditEvent[] = [];
	let retainedIndex = 0;
	let insertedIndex = 0;
	while (retainedIndex < retained.length || insertedIndex < inserted.length) {
		const existing = retained[retainedIndex];
		const incoming = inserted[insertedIndex];
		if (!incoming) {
			merged.push(existing!);
			retainedIndex++;
			continue;
		}
		if (!existing) {
			merged.push(incoming);
			insertedIndex++;
			continue;
		}
		const incomingFirst =
			incoming.createdAt > existing.createdAt ||
			(incoming.createdAt === existing.createdAt && incoming.id > existing.id);
		if (incomingFirst) {
			merged.push(incoming);
			insertedIndex++;
		} else {
			merged.push(existing);
			retainedIndex++;
		}
	}
	return merged;
}
