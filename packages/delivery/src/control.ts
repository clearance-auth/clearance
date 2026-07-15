import { randomUUID } from "node:crypto";
import type pg from "pg";
import {
	enqueueDeliveryInExistingTransaction,
	type DeliveryRawTransaction,
	type EnqueuedDelivery,
} from "./enqueue.js";
import { enqueueWebhookEndpointDeliveryInExistingTransaction } from "./webhook-endpoints.js";
import { parseOrganizationUpdatedWebhookPayload } from "./webhook-payload.js";
import {
	DeliveryControlConflictError,
	DeliveryError,
} from "./errors.js";
import {
	decryptDeliveryPayload,
	fingerprintDestination,
	type DeliveryKeyring,
	type DeliveryPayloadAad,
} from "./keyring.js";
import {
	redactedDeliveryJob,
	type DeliveryJobRecord,
	type DeliveryJobState,
	type PublicDeliveryJob,
} from "./redaction.js";
import {
	DEFAULT_DELIVERY_QUOTA_POLICY,
	enforceDeliveryQuotaInExistingTransaction,
	type DeliveryQuotaPolicy,
	type DeliveryScope,
} from "./quota.js";
import {
	assertDeliverySchemaCurrent,
	DELIVERY_SCHEMA_OWNER,
	DELIVERY_SCHEMA_VERSION,
	qualifiedDeliveryTables,
	type DeliverySchemaOptions,
} from "./schema.js";

export type DeliveryControlAction = "cancel" | "retry" | "replay";

export type DeliveryControlPreview = {
	action: DeliveryControlAction;
	allowed: boolean;
	reason: "active_delivery" | "already_terminal" | "lease_active" | "payload_erased" |
		"semantic_expired" | "attempt_limit" | null;
	job: PublicDeliveryJob;
	effect: {
		state: DeliveryJobState | null;
		cancelRequested: boolean | null;
		maxAttempts: number | null;
		createsEvent: boolean;
		createsJob: boolean;
	};
};

export type DeliveryJobPage = {
	items: PublicDeliveryJob[];
	nextCursor: string | null;
};

export type DeliveryReadinessSummary = {
	ready: boolean;
	schema: {
		owner: string | null;
		version: number | null;
		currentVersion: number;
		current: boolean;
	};
	jobs: Record<DeliveryJobState, number>;
	workers: {
		total: number;
		ready: number;
		freshReady: number;
		stale: number;
		staleAfterMs: number;
		lastSeenAt: string | null;
	};
	keys: {
		checked: boolean;
		available: boolean;
		missingReferences: number;
	};
	webhookEndpoints: {
		total: number;
		active: number;
		disabled: number;
		untestedActive: number;
		testPendingActive: number;
		testFailedActive: number;
		testSucceededActive: number;
		lastTestRequestedAt: string | null;
	};
	reasons: Array<
		"schema_unavailable" | "schema_outdated" | "worker_unavailable" | "key_unavailable" |
		"webhook_endpoint_untested" | "webhook_endpoint_test_pending" |
		"webhook_endpoint_test_failed"
	>;
};

type ControlJobRow = {
	id: string;
	event_id: string;
	kind: string;
	project_id: string;
	environment_id: string;
	organization_id: string | null;
	webhook_endpoint_id: string | null;
	channel: "email" | "webhook";
	state: DeliveryJobState;
	cancel_requested: boolean;
	attempt_count: number;
	max_attempts: number;
	available_at: Date | string;
	semantic_expires_at: Date | string;
	last_error_class: string | null;
	created_at: Date | string;
	updated_at: Date | string;
	delivered_at: Date | string | null;
	dead_at: Date | string | null;
	cancelled_at: Date | string | null;
};

type LockedControlJobRow = ControlJobRow & {
	payload_exists: boolean;
	payload_expires_at: Date | string | null;
};

const DELIVERY_STATES: readonly DeliveryJobState[] = [
	"queued", "leased", "retry", "delivered", "dead", "cancelled",
];

function iso(value: Date | string | null): string | null {
	return value === null ? null : new Date(value).toISOString();
}

function date(value: Date | undefined, label: string): Date {
	const result = value ?? new Date();
	if (!(result instanceof Date) || !Number.isFinite(result.getTime())) {
		throw new DeliveryError("DELIVERY_DATE_INVALID", `${label} must be a valid date`);
	}
	return result;
}

function bounded(value: number, label: string, minimum: number, maximum: number): number {
	if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
		throw new DeliveryError(
			"DELIVERY_BOUND_INVALID",
			`${label} must be an integer between ${minimum} and ${maximum}`,
		);
	}
	return value;
}

function scopeValue(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized || normalized.length > 512 || /[\u0000-\u001f]/.test(normalized)) {
		throw new DeliveryError("DELIVERY_SCOPE_INVALID", `${label} is invalid`);
	}
	return normalized;
}

function scope(input: DeliveryScope): DeliveryScope {
	return {
		projectId: scopeValue(input.projectId, "projectId"),
		environmentId: scopeValue(input.environmentId, "environmentId"),
	};
}

function jobId(value: string): string {
	const normalized = value.trim();
	if (!normalized || normalized.length > 4_096 || normalized.includes("\u0000")) {
		throw new DeliveryError("DELIVERY_JOB_ID_INVALID", "jobId is invalid");
	}
	return normalized;
}

function record(row: ControlJobRow): PublicDeliveryJob {
	const result: DeliveryJobRecord = {
		id: row.id,
		eventId: row.event_id,
		kind: row.kind,
		projectId: row.project_id,
		environmentId: row.environment_id,
		organizationId: row.organization_id,
		webhookEndpointId: row.webhook_endpoint_id,
		channel: row.channel,
		state: row.state,
		cancelRequested: row.cancel_requested,
		attemptCount: Number(row.attempt_count),
		maxAttempts: Number(row.max_attempts),
		availableAt: iso(row.available_at)!,
		semanticExpiresAt: iso(row.semantic_expires_at)!,
		lastErrorClass: row.last_error_class,
		createdAt: iso(row.created_at)!,
		updatedAt: iso(row.updated_at)!,
		deliveredAt: iso(row.delivered_at),
		deadAt: iso(row.dead_at),
		cancelledAt: iso(row.cancelled_at),
	};
	return redactedDeliveryJob(result);
}

function requireRawTransaction(transaction: DeliveryRawTransaction) {
	if (!transaction.rawTransactionQuery) {
		throw new DeliveryError(
			"DELIVERY_TRANSACTION_REQUIRED",
			"Delivery control mutation requires an active PostgreSQL transaction adapter",
		);
	}
	return transaction.rawTransactionQuery;
}

function parseStates(states: readonly DeliveryJobState[] | undefined): DeliveryJobState[] {
	if (!states) return [...DELIVERY_STATES];
	if (states.length === 0 || states.length > DELIVERY_STATES.length) {
		throw new DeliveryError("DELIVERY_STATE_FILTER_INVALID", "Delivery state filter is invalid");
	}
	const result = [...new Set(states)];
	if (result.some((state) => !DELIVERY_STATES.includes(state))) {
		throw new DeliveryError("DELIVERY_STATE_FILTER_INVALID", "Delivery state filter is invalid");
	}
	return result;
}

function encodeCursor(row: PublicDeliveryJob): string {
	return Buffer.from(JSON.stringify({
		v: 1,
		s: "delivery_jobs",
		k: [row.createdAt, row.id],
	}), "utf8").toString("base64url");
}

function decodeCursor(value: string | undefined): [Date, string] | null {
	if (value === undefined) return null;
	if (!/^[A-Za-z0-9_-]{1,8192}$/.test(value)) {
		throw new DeliveryError("DELIVERY_CURSOR_INVALID", "Delivery cursor is invalid");
	}
	try {
		const bytes = Buffer.from(value, "base64url");
		if (bytes.toString("base64url") !== value) throw new Error("invalid");
		const raw = bytes.toString("utf8");
		const parsed: unknown = JSON.parse(raw);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid");
		const cursor = parsed as Record<string, unknown>;
		if (cursor.v !== 1 || cursor.s !== "delivery_jobs" ||
			!Array.isArray(cursor.k) || cursor.k.length !== 2 ||
			typeof cursor.k[0] !== "string" || typeof cursor.k[1] !== "string" ||
			cursor.k[1].length < 1 || cursor.k[1].length > 4_096 ||
			JSON.stringify({ v: 1, s: "delivery_jobs", k: cursor.k }) !== raw) {
			throw new Error("invalid");
		}
		const createdAt = new Date(cursor.k[0]);
		if (!Number.isFinite(createdAt.getTime()) || createdAt.toISOString() !== cursor.k[0]) {
			throw new Error("invalid");
		}
		return [createdAt, cursor.k[1]];
	} catch {
		throw new DeliveryError("DELIVERY_CURSOR_INVALID", "Delivery cursor is invalid");
	}
}

export async function listDeliveryJobs(
	pool: pg.Pool,
	input: DeliveryScope & {
		limit?: number;
		cursor?: string;
		states?: readonly DeliveryJobState[];
		channel?: "email" | "webhook";
		kind?: string;
	},
	options: DeliverySchemaOptions = {},
): Promise<DeliveryJobPage> {
	const target = scope(input);
	const limit = bounded(input.limit ?? 50, "limit", 1, 200);
	const states = parseStates(input.states);
	const cursor = decodeCursor(input.cursor);
	const channel = input.channel ?? null;
	if (channel !== null && channel !== "email" && channel !== "webhook") {
		throw new DeliveryError("DELIVERY_CHANNEL_INVALID", "Delivery channel filter is invalid");
	}
	const kind = input.kind === undefined ? null : input.kind.trim();
	if (kind !== null && (!kind || kind.length > 128)) {
		throw new DeliveryError("DELIVERY_KIND_INVALID", "Delivery kind filter is invalid");
	}
	const tables = qualifiedDeliveryTables(options);
	const result = await pool.query<ControlJobRow>(
		`SELECT j.*, e.kind, e.project_id, e.environment_id, e.organization_id, e.webhook_endpoint_id
		 FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id
		 WHERE e.project_id=$1 AND e.environment_id=$2 AND j.state=ANY($3::text[])
		   AND ($4::text IS NULL OR j.channel=$4)
		   AND ($5::text IS NULL OR e.kind=$5)
		   AND ($6::timestamptz IS NULL OR (j.created_at,j.id) < ($6,$7))
		 ORDER BY j.created_at DESC, j.id DESC LIMIT $8`,
		[
			target.projectId, target.environmentId, states, channel, kind,
			cursor?.[0] ?? null, cursor?.[1] ?? null, limit + 1,
		],
	);
	const hasMore = result.rows.length > limit;
	const items = result.rows.slice(0, limit).map(record);
	return {
		items,
		nextCursor: hasMore ? encodeCursor(items.at(-1)!) : null,
	};
}

export async function inspectDeliveryJobScoped(
	pool: pg.Pool,
	input: DeliveryScope & { jobId: string },
	options: DeliverySchemaOptions = {},
): Promise<PublicDeliveryJob | null> {
	const target = scope(input);
	const tables = qualifiedDeliveryTables(options);
	const result = await pool.query<ControlJobRow>(
		`SELECT j.*, e.kind, e.project_id, e.environment_id, e.organization_id, e.webhook_endpoint_id
		 FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id
		 WHERE j.id=$1 AND e.project_id=$2 AND e.environment_id=$3`,
		[jobId(input.jobId), target.projectId, target.environmentId],
	);
	return result.rows[0] ? record(result.rows[0]) : null;
}

function effectFor(
	action: DeliveryControlAction,
	row: ControlJobRow & { payload_exists: boolean; payload_expires_at: Date | string | null },
	now: Date,
	requestedMaxAttempts?: number,
): Omit<DeliveryControlPreview, "job"> {
	const expired = new Date(row.semantic_expires_at) <= now ||
		(row.payload_expires_at !== null && new Date(row.payload_expires_at) <= now);
	if (action === "cancel") {
		const allowed = ["queued", "retry", "leased"].includes(row.state);
			return {
				action, allowed,
				reason: allowed ? null : "already_terminal",
				effect: {
					state: allowed ? (row.state === "leased" ? "leased" : "cancelled") : null,
					cancelRequested: allowed ? row.state === "leased" : null,
					maxAttempts: null,
				createsEvent: false,
				createsJob: false,
			},
		};
	}
	if (action === "retry") {
		const active = row.state === "queued" || row.state === "retry";
		const dead = row.state === "dead";
		const reason = row.state === "leased" ? "lease_active"
			: !active && !dead ? "already_terminal"
				: !row.payload_exists ? "payload_erased"
				: expired ? "semantic_expired"
					: Number(row.attempt_count) >= 100 ? "attempt_limit" : null;
		return {
			action, allowed: reason === null, reason,
			effect: {
				state: reason === null ? "retry" : null,
				cancelRequested: reason === null ? false : null,
				maxAttempts: reason === null
					? dead ? Number(row.attempt_count) + 1 : Number(row.max_attempts)
					: null,
				createsEvent: false,
				createsJob: false,
			},
		};
	}
	const replayMaxAttempts = requestedMaxAttempts === undefined
		? Number(row.max_attempts)
		: bounded(requestedMaxAttempts, "maxAttempts", 1, 100);
	const terminal = ["delivered", "dead", "cancelled"].includes(row.state);
	const reason = !terminal ? "active_delivery"
		: !row.payload_exists ? "payload_erased"
			: expired ? "semantic_expired" : null;
	return {
		action, allowed: reason === null, reason,
		effect: {
			state: reason === null ? "queued" : null,
			cancelRequested: reason === null ? false : null,
			maxAttempts: reason === null ? replayMaxAttempts : null,
			createsEvent: reason === null,
			createsJob: reason === null,
		},
	};
}

export async function previewDeliveryControl(
	pool: pg.Pool,
	input: DeliveryScope & {
		jobId: string;
		action: DeliveryControlAction;
		now?: Date;
		maxAttempts?: number;
	},
	options: DeliverySchemaOptions = {},
): Promise<DeliveryControlPreview | null> {
	const target = scope(input);
	const now = date(input.now, "now");
	const tables = qualifiedDeliveryTables(options);
	const result = await pool.query<ControlJobRow & {
		payload_exists: boolean;
		payload_expires_at: Date | string | null;
	}>(
		`SELECT j.*, e.kind, e.project_id, e.environment_id, e.organization_id, e.webhook_endpoint_id,
		 (p.event_id IS NOT NULL) payload_exists, p.expires_at payload_expires_at
		 FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id
		 LEFT JOIN ${tables.payload} p ON p.event_id=e.id
		 WHERE j.id=$1 AND e.project_id=$2 AND e.environment_id=$3`,
		[jobId(input.jobId), target.projectId, target.environmentId],
	);
	const row = result.rows[0];
	return row
		? { ...effectFor(input.action, row, now, input.maxAttempts), job: record(row) }
		: null;
}

async function lockedScopedJob(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & { jobId: string },
	options: DeliverySchemaOptions,
): Promise<LockedControlJobRow | null> {
	const rawQuery = requireRawTransaction(transaction);
	const target = scope(input);
	const tables = qualifiedDeliveryTables(options);
	const result = await rawQuery<LockedControlJobRow>(
		`SELECT j.*, e.kind, e.project_id, e.environment_id, e.organization_id, e.webhook_endpoint_id,
		 (p.event_id IS NOT NULL) payload_exists, p.expires_at payload_expires_at
		 FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id
		 LEFT JOIN ${tables.payload} p ON p.event_id=e.id
		 WHERE j.id=$1 AND e.project_id=$2 AND e.environment_id=$3 FOR UPDATE OF j`,
		[jobId(input.jobId), target.projectId, target.environmentId],
	);
	return result.rows[0] ?? null;
}

/** Preview against the same locked row that a confirmed control will mutate. */
export async function previewDeliveryControlInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & {
		jobId: string;
		action: DeliveryControlAction;
		now?: Date;
		maxAttempts?: number;
	},
	options: DeliverySchemaOptions = {},
): Promise<DeliveryControlPreview | null> {
	const now = date(input.now, "now");
	const row = await lockedScopedJob(transaction, input, options);
	return row
		? { ...effectFor(input.action, row, now, input.maxAttempts), job: record(row) }
		: null;
}

export async function cancelDeliveryInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & { jobId: string; now?: Date },
	options: DeliverySchemaOptions = {},
): Promise<PublicDeliveryJob | null> {
	const rawQuery = requireRawTransaction(transaction);
	const now = date(input.now, "now");
	const row = await lockedScopedJob(transaction, input, options);
	if (!row) return null;
	if (!["queued", "retry", "leased"].includes(row.state)) {
		throw new DeliveryControlConflictError("Terminal delivery jobs cannot be cancelled", row.state);
	}
	const tables = qualifiedDeliveryTables(options);
	const updated = await rawQuery<ControlJobRow>(
		`UPDATE ${tables.job} SET
		 state=CASE WHEN state IN ('queued','retry') THEN 'cancelled' ELSE state END,
		 cancel_requested=CASE WHEN state='leased' THEN true ELSE false END,
		 cancelled_at=CASE WHEN state IN ('queued','retry') THEN $2 ELSE cancelled_at END,
		 updated_at=$2 WHERE id=$1 RETURNING *`,
		[row.id, now],
	);
	return record({ ...updated.rows[0]!, kind: row.kind, project_id: row.project_id,
		environment_id: row.environment_id, organization_id: row.organization_id,
		webhook_endpoint_id: row.webhook_endpoint_id });
}

export async function retryDeliveryInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & {
		jobId: string;
		now?: Date;
		quota?: DeliveryQuotaPolicy;
	},
	options: DeliverySchemaOptions = {},
): Promise<PublicDeliveryJob | null> {
	const rawQuery = requireRawTransaction(transaction);
	const now = date(input.now, "now");
	const row = await lockedScopedJob(transaction, input, options);
	if (!row) return null;
	if (row.state === "leased") {
		throw new DeliveryControlConflictError("Leased delivery jobs cannot be manually retried", row.state);
	}
	if (row.state === "delivered" || row.state === "cancelled") {
		throw new DeliveryControlConflictError("This terminal delivery job must be replayed", row.state);
	}
	if (row.state !== "queued" && row.state !== "retry" && row.state !== "dead") {
		throw new DeliveryControlConflictError("Delivery job cannot be manually retried", row.state);
	}
	if (!row.payload_exists || row.payload_expires_at === null) {
		throw new DeliveryControlConflictError("Erased delivery payloads cannot be retried", row.state);
	}
	if (new Date(row.semantic_expires_at) <= now || new Date(row.payload_expires_at) <= now) {
		throw new DeliveryControlConflictError("Expired delivery jobs cannot be retried", row.state);
	}
	if (Number(row.attempt_count) >= 100) {
		throw new DeliveryControlConflictError("Delivery job reached the hard attempt limit", row.state);
	}
	if (row.state === "dead") {
		await enforceDeliveryQuotaInExistingTransaction(
			transaction,
			{
				projectId: row.project_id,
				environmentId: row.environment_id,
				policy: input.quota ?? DEFAULT_DELIVERY_QUOTA_POLICY,
				now,
			},
			options,
		);
	}
	const tables = qualifiedDeliveryTables(options);
	const nextMaxAttempts = row.state === "dead"
		? Number(row.attempt_count) + 1
		: Number(row.max_attempts);
	const updated = await rawQuery<ControlJobRow>(
		`UPDATE ${tables.job} SET state='retry', available_at=$2,
		 max_attempts=$3, dead_at=CASE WHEN state='dead' THEN NULL ELSE dead_at END,
		 last_error_class=CASE WHEN state='dead' THEN NULL ELSE last_error_class END,
		 updated_at=$2 WHERE id=$1 RETURNING *`,
		[row.id, now, nextMaxAttempts],
	);
	return record({ ...updated.rows[0]!, kind: row.kind, project_id: row.project_id,
		environment_id: row.environment_id, organization_id: row.organization_id,
		webhook_endpoint_id: row.webhook_endpoint_id });
}

function replayDestination(channel: "email" | "webhook", payload: unknown): string {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		throw new DeliveryError("DELIVERY_REPLAY_PAYLOAD_INVALID", "Delivery payload cannot be replayed");
	}
	const root = payload as Record<string, unknown>;
	const destination = channel === "email"
		? root.to
		: root.endpoint && typeof root.endpoint === "object" && !Array.isArray(root.endpoint)
			? (root.endpoint as Record<string, unknown>).url
			: undefined;
	if (typeof destination !== "string" || !destination.trim()) {
		throw new DeliveryError("DELIVERY_REPLAY_PAYLOAD_INVALID", "Delivery destination is unavailable");
	}
	return destination;
}

function replayPayload(channel: "email" | "webhook", payload: unknown, eventId: string): unknown {
	if (channel !== "webhook" || !payload || typeof payload !== "object" || Array.isArray(payload)) {
		return payload;
	}
	const root = payload as Record<string, unknown>;
	if (!root.event || typeof root.event !== "object" || Array.isArray(root.event)) return payload;
	return { ...root, event: { ...(root.event as Record<string, unknown>), id: eventId } };
}

export async function replayDeliveryInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & {
		jobId: string;
		now?: Date;
		maxAttempts?: number;
		quota?: DeliveryQuotaPolicy;
	},
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<EnqueuedDelivery | null> {
	const rawQuery = requireRawTransaction(transaction);
	const target = scope(input);
	const now = date(input.now, "now");
	const tables = qualifiedDeliveryTables(options);
	const result = await rawQuery<ControlJobRow & {
		envelope: string | null;
		payload_expires_at: Date | string | null;
		destination_fingerprint: string;
		destination_fingerprint_key_id: string;
		actor_id: string | null;
		correlation_id: string | null;
		webhook_endpoint_id: string | null;
	}>(
		`SELECT j.*, e.kind, e.project_id, e.environment_id, e.organization_id,
		 e.actor_id, e.correlation_id, e.webhook_endpoint_id, e.destination_fingerprint,
		 e.destination_fingerprint_key_id, p.envelope, p.expires_at payload_expires_at
		 FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id
		 LEFT JOIN ${tables.payload} p ON p.event_id=e.id
		 WHERE j.id=$1 AND e.project_id=$2 AND e.environment_id=$3 FOR UPDATE OF j`,
		[jobId(input.jobId), target.projectId, target.environmentId],
	);
	const row = result.rows[0];
	if (!row) return null;
	if (!["delivered", "dead", "cancelled"].includes(row.state)) {
		throw new DeliveryControlConflictError("Active delivery jobs cannot be replayed", row.state);
	}
	if (!row.envelope || row.payload_expires_at === null) {
		throw new DeliveryControlConflictError("Erased delivery payloads cannot be replayed", row.state);
	}
	const expiresAt = new Date(row.payload_expires_at);
	if (expiresAt <= now || new Date(row.semantic_expires_at) <= now) {
		throw new DeliveryControlConflictError("Expired delivery payloads cannot be replayed", row.state);
	}
	const aad: DeliveryPayloadAad = {
		version: 1,
		eventId: row.event_id,
		kind: row.kind,
		channel: row.channel,
		projectId: row.project_id,
		environmentId: row.environment_id,
		destinationFingerprint: row.destination_fingerprint,
		expiresAt: expiresAt.toISOString(),
	};
	const payload = decryptDeliveryPayload<unknown>(row.envelope, aad, keyring);
	if (row.webhook_endpoint_id !== null) {
		if (row.channel !== "webhook" || row.kind !== "organization.updated") {
			throw new DeliveryControlConflictError("Managed webhook delivery cannot be replayed", row.state);
		}
		const original = parseOrganizationUpdatedWebhookPayload(payload);
		const eventId = randomUUID();
		const managed = await enqueueWebhookEndpointDeliveryInExistingTransaction(
			transaction,
			{
				eventId,
				endpointId: row.webhook_endpoint_id,
				projectId: target.projectId,
				environmentId: target.environmentId,
				eventKind: "organization.updated",
				sourceKey: `managed-control-replay:${JSON.stringify([row.event_id, eventId])}`,
				event: {
					occurredAt: original.event.occurredAt,
					data: original.event.data,
				},
				organizationId: original.event.context.organizationId,
				...(original.event.context.actor === null ? {} : { actorId: original.event.context.actor }),
				...(original.event.context.correlationId === null
					? {}
					: { correlationId: original.event.context.correlationId }),
				replayOf: row.event_id,
				semanticExpiresAt: expiresAt,
				maxAttempts: input.maxAttempts ?? Number(row.max_attempts),
				quota: input.quota ?? DEFAULT_DELIVERY_QUOTA_POLICY,
				now,
			},
			keyring,
			options,
		);
		if (!managed) {
			throw new DeliveryControlConflictError("Managed webhook endpoint is unavailable", row.state);
		}
		return managed.delivery;
	}
	const destination = replayDestination(row.channel, payload);
	if (
		fingerprintDestination(destination, keyring, row.destination_fingerprint_key_id) !==
		row.destination_fingerprint
	) {
		throw new DeliveryError(
			"DELIVERY_DESTINATION_MISMATCH",
			"Decrypted delivery recipient does not match the audited destination",
		);
	}
	const eventId = randomUUID();
	const nextPayload = replayPayload(row.channel, payload, eventId);
	return enqueueDeliveryInExistingTransaction(
		transaction,
		{
			eventId,
			jobId: randomUUID(),
			kind: row.kind,
			sourceKey: `control-replay:${row.event_id}:${eventId}`,
			projectId: target.projectId,
			environmentId: target.environmentId,
			...(row.organization_id ? { organizationId: row.organization_id } : {}),
			...(row.actor_id ? { actorId: row.actor_id } : {}),
			...(row.correlation_id ? { correlationId: row.correlation_id } : {}),
			replayOf: row.event_id,
			channel: row.channel,
			destination,
			payload: nextPayload,
			semanticExpiresAt: expiresAt,
			maxAttempts: input.maxAttempts ?? Number(row.max_attempts),
			now,
			quota: input.quota ?? DEFAULT_DELIVERY_QUOTA_POLICY,
		},
		keyring,
		options,
	);
}

export async function deliveryReadiness(
	pool: pg.Pool,
	input: { now?: Date; staleAfterMs?: number } = {},
	options: DeliverySchemaOptions = {},
	keyring?: DeliveryKeyring,
): Promise<DeliveryReadinessSummary> {
	const now = date(input.now, "now");
	const staleAfterMs = bounded(input.staleAfterMs ?? 60_000, "staleAfterMs", 1_000, 86_400_000);
	const staleBefore = new Date(now.getTime() - staleAfterMs);
	const tables = qualifiedDeliveryTables(options);
	let owner: string | null = null;
	let version: number | null = null;
	let schemaCurrent = false;
	const jobs = Object.fromEntries(DELIVERY_STATES.map((state) => [state, 0])) as Record<DeliveryJobState, number>;
	let workerSummary = { total: 0, ready: 0, freshReady: 0, stale: 0, lastSeenAt: null as string | null };
	let keySummary = { checked: false, available: true, missingReferences: 0 };
	let webhookEndpointSummary = {
		total: 0,
		active: 0,
		disabled: 0,
		untestedActive: 0,
		testPendingActive: 0,
		testFailedActive: 0,
		testSucceededActive: 0,
		lastTestRequestedAt: null as string | null,
	};
	const reasons: DeliveryReadinessSummary["reasons"] = [];
	try {
		await assertDeliverySchemaCurrent(pool, options);
		owner = DELIVERY_SCHEMA_OWNER;
		version = DELIVERY_SCHEMA_VERSION;
		schemaCurrent = true;
		const counts = await pool.query<{ state: DeliveryJobState; count: string }>(
			`SELECT state, count(*) count FROM ${tables.job} GROUP BY state`,
		);
		for (const row of counts.rows) jobs[row.state] = Number(row.count);
		const workers = await pool.query<{
			total: string; ready: string; fresh_ready: string; stale: string;
			last_seen_at: Date | string | null;
		}>(
			`SELECT count(*) total,
			 count(*) FILTER (WHERE state='ready') ready,
			 count(*) FILTER (WHERE state='ready' AND last_seen_at > $1) fresh_ready,
			 count(*) FILTER (WHERE last_seen_at <= $1) stale,
			 max(last_seen_at) last_seen_at FROM ${tables.worker}`,
			[staleBefore],
		);
			const row = workers.rows[0]!;
			workerSummary = {
				total: Number(row.total), ready: Number(row.ready), freshReady: Number(row.fresh_ready),
				stale: Number(row.stale), lastSeenAt: iso(row.last_seen_at),
			};
			const endpointCounts = await pool.query<{
				total: string;
				active: string;
				disabled: string;
				untested_active: string;
				test_pending_active: string;
				test_failed_active: string;
				test_succeeded_active: string;
				last_test_requested_at: Date | string | null;
			}>(
				`SELECT
				 count(*) FILTER (WHERE w.status <> 'deleted') total,
				 count(*) FILTER (WHERE w.status = 'active') active,
				 count(*) FILTER (WHERE w.status = 'disabled') disabled,
				 count(*) FILTER (WHERE w.status = 'active' AND w.last_test_job_id IS NULL) untested_active,
				 count(*) FILTER (WHERE w.status = 'active' AND j.state IN ('queued','leased','retry')) test_pending_active,
				 count(*) FILTER (WHERE w.status = 'active' AND w.last_test_job_id IS NOT NULL
				   AND (j.id IS NULL OR j.state IN ('dead','cancelled'))) test_failed_active,
				 count(*) FILTER (WHERE w.status = 'active' AND j.state = 'delivered') test_succeeded_active,
				 max(w.last_test_requested_at) last_test_requested_at
				 FROM ${tables.webhookEndpoint} w
				 LEFT JOIN ${tables.job} j ON j.id = w.last_test_job_id`,
			);
			const endpointRow = endpointCounts.rows[0]!;
			webhookEndpointSummary = {
				total: Number(endpointRow.total),
				active: Number(endpointRow.active),
				disabled: Number(endpointRow.disabled),
				untestedActive: Number(endpointRow.untested_active),
				testPendingActive: Number(endpointRow.test_pending_active),
				testFailedActive: Number(endpointRow.test_failed_active),
				testSucceededActive: Number(endpointRow.test_succeeded_active),
				lastTestRequestedAt: iso(endpointRow.last_test_requested_at),
			};
			if (webhookEndpointSummary.untestedActive > 0) {
				reasons.push("webhook_endpoint_untested");
			}
			if (webhookEndpointSummary.testPendingActive > 0) {
				reasons.push("webhook_endpoint_test_pending");
			}
			if (webhookEndpointSummary.testFailedActive > 0) {
				reasons.push("webhook_endpoint_test_failed");
			}
		if (keyring) {
			const referenced = await pool.query<{ key_kind: "encryption" | "fingerprint"; key_id: string }>(
				`SELECT DISTINCT 'encryption' key_kind, p.key_id
				 FROM ${tables.payload} p WHERE p.expires_at > $1
				 UNION
			 SELECT DISTINCT 'fingerprint' key_kind, e.destination_fingerprint_key_id key_id
			 FROM ${tables.event} e
			 JOIN ${tables.job} j ON j.event_id=e.id
			 LEFT JOIN ${tables.payload} p ON p.event_id=e.id
			 WHERE j.state IN ('queued','leased','retry')
			    OR (j.state IN ('delivered','dead','cancelled')
			        AND p.expires_at > $1 AND e.semantic_expires_at > $1)
				 UNION
				 SELECT DISTINCT 'fingerprint' key_kind, e.source_fingerprint_key_id key_id
				 FROM ${tables.event} e WHERE e.source_dedupe_version=1
				 UNION
				 SELECT DISTINCT 'encryption' key_kind, w.config_key_id key_id
				 FROM ${tables.webhookEndpoint} w WHERE w.status <> 'deleted'
				 UNION
				 SELECT DISTINCT 'fingerprint' key_kind, w.url_fingerprint_key_id key_id
				 FROM ${tables.webhookEndpoint} w WHERE w.status <> 'deleted'`,
				[now],
			);
			const missingReferences = referenced.rows.filter((reference) =>
				reference.key_kind === "encryption"
					? !keyring.keys.has(reference.key_id)
					: !keyring.fingerprintKeys.has(reference.key_id),
			).length;
			keySummary = { checked: true, available: missingReferences === 0, missingReferences };
			if (missingReferences > 0) reasons.push("key_unavailable");
		}
	} catch (error) {
		schemaCurrent = false;
		const code = (error as { code?: unknown }).code;
		if (code === "DELIVERY_SCHEMA_VERSION_OUTDATED" || code === "DELIVERY_SCHEMA_VERSION_FUTURE") {
			reasons.push("schema_outdated");
		} else {
			reasons.push("schema_unavailable");
		}
	}
	if (schemaCurrent && workerSummary.freshReady === 0) reasons.push("worker_unavailable");
	return {
		ready: reasons.length === 0,
		schema: { owner, version, currentVersion: DELIVERY_SCHEMA_VERSION, current: schemaCurrent },
		jobs,
		workers: { ...workerSummary, staleAfterMs },
		keys: keySummary,
		webhookEndpoints: webhookEndpointSummary,
		reasons,
	};
}
