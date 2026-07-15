import type pg from "pg";
import type { DeliveryRawTransaction } from "./enqueue.js";
import {
	DeliveryError,
	DeliveryQuotaExceededError,
	type DeliveryQuotaKind,
} from "./errors.js";
import { qualifiedDeliveryTables, type DeliverySchemaOptions } from "./schema.js";

export type DeliveryScope = {
	projectId: string;
	environmentId: string;
};

export type DeliveryQuotaPolicy = {
	maxActive: number;
	maxBacklog: number;
	maxEnqueuesPerWindow: number;
	windowMs: number;
};

/** Conservative per-environment guardrails that callers may tighten. */
export const DEFAULT_DELIVERY_QUOTA_POLICY: Readonly<DeliveryQuotaPolicy> = Object.freeze({
	maxActive: 10_000,
	maxBacklog: 5_000,
	maxEnqueuesPerWindow: 1_000,
	windowMs: 60_000,
});

export type DeliveryQuotaStatus = {
	scope: DeliveryScope;
	active: { used: number; limit: number };
	backlog: { used: number; limit: number };
	enqueueRate: {
		used: number;
		limit: number;
		windowMs: number;
		windowStartedAt: string;
		resetsAt: string | null;
	};
};

type Query = <Row extends pg.QueryResultRow>(
	text: string,
	values?: readonly unknown[],
) => Promise<{ rows: Row[]; rowCount: number | null }>;

function bounded(value: number, label: string, minimum: number, maximum: number): number {
	if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
		throw new DeliveryError(
			"DELIVERY_BOUND_INVALID",
			`${label} must be an integer between ${minimum} and ${maximum}`,
		);
	}
	return value;
}

function date(value: Date | undefined, label: string): Date {
	const result = value ?? new Date();
	if (!(result instanceof Date) || !Number.isFinite(result.getTime())) {
		throw new DeliveryError("DELIVERY_DATE_INVALID", `${label} must be a valid date`);
	}
	return result;
}

function scopeValue(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized || normalized.length > 512 || /[\u0000-\u001f]/.test(normalized)) {
		throw new DeliveryError("DELIVERY_SCOPE_INVALID", `${label} is invalid`);
	}
	return normalized;
}

function normalizeScope(input: DeliveryScope): DeliveryScope {
	return {
		projectId: scopeValue(input.projectId, "projectId"),
		environmentId: scopeValue(input.environmentId, "environmentId"),
	};
}

/** Validate and clone a quota policy before any storage work begins. */
export function normalizeDeliveryQuotaPolicy(
	value: DeliveryQuotaPolicy,
): DeliveryQuotaPolicy {
	return {
		maxActive: bounded(value.maxActive, "maxActive", 1, 10_000_000),
		maxBacklog: bounded(value.maxBacklog, "maxBacklog", 1, 10_000_000),
		maxEnqueuesPerWindow: bounded(
			value.maxEnqueuesPerWindow,
			"maxEnqueuesPerWindow",
			1,
			10_000_000,
		),
		windowMs: bounded(value.windowMs, "windowMs", 1_000, 86_400_000),
	};
}

function iso(value: Date | string | null): string | null {
	return value === null ? null : new Date(value).toISOString();
}

async function statusWithQuery(
	query: Query,
	input: DeliveryScope & { policy: DeliveryQuotaPolicy; now?: Date },
	options: DeliverySchemaOptions,
): Promise<DeliveryQuotaStatus> {
	const target = normalizeScope(input);
	const policy = normalizeDeliveryQuotaPolicy(input.policy);
	const now = date(input.now, "now");
	const windowStartedAt = new Date(now.getTime() - policy.windowMs);
	const tables = qualifiedDeliveryTables(options);
	const result = await query<{
		active: string;
		backlog: string;
		enqueue_rate: string;
		oldest_enqueue: Date | string | null;
	}>(
		`SELECT
		 (SELECT count(*) FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id
		  WHERE e.project_id=$1 AND e.environment_id=$2
		    AND j.state IN ('queued','leased','retry')) active,
		 (SELECT count(*) FROM ${tables.job} j JOIN ${tables.event} e ON e.id=j.event_id
		  WHERE e.project_id=$1 AND e.environment_id=$2
		    AND j.state IN ('queued','retry')) backlog,
		 (SELECT count(*) FROM ${tables.event} e WHERE e.project_id=$1 AND e.environment_id=$2
		    AND e.created_at >= $3 AND e.created_at <= $4) enqueue_rate,
		 (SELECT min(e.created_at) FROM ${tables.event} e WHERE e.project_id=$1 AND e.environment_id=$2
		    AND e.created_at >= $3 AND e.created_at <= $4) oldest_enqueue`,
		[target.projectId, target.environmentId, windowStartedAt, now],
	);
	const row = result.rows[0]!;
	const oldest = iso(row.oldest_enqueue);
	return {
		scope: target,
		active: { used: Number(row.active), limit: policy.maxActive },
		backlog: { used: Number(row.backlog), limit: policy.maxBacklog },
		enqueueRate: {
			used: Number(row.enqueue_rate),
			limit: policy.maxEnqueuesPerWindow,
			windowMs: policy.windowMs,
			windowStartedAt: windowStartedAt.toISOString(),
			resetsAt: oldest === null
				? null
				: new Date(new Date(oldest).getTime() + policy.windowMs).toISOString(),
		},
	};
}

export function deliveryQuotaStatus(
	pool: pg.Pool,
	input: DeliveryScope & { policy?: DeliveryQuotaPolicy; now?: Date },
	options: DeliverySchemaOptions = {},
): Promise<DeliveryQuotaStatus> {
	const query: Query = async (text, values) => {
		const result = await pool.query(text, values as unknown[] | undefined);
		return { rows: result.rows, rowCount: result.rowCount };
	};
	return statusWithQuery(
		query,
		{ ...input, policy: input.policy ?? DEFAULT_DELIVERY_QUOTA_POLICY },
		options,
	);
}

/**
 * Serialize enqueue admission for one project/environment inside the caller's
 * transaction. Callers that also enforce quota may use this before duplicate
 * detection so an idempotent retry keeps duplicate authority when capacity is
 * already exhausted.
 */
export async function lockDeliveryQuotaScopeInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope,
): Promise<DeliveryScope> {
	if (!transaction.rawTransactionQuery) {
		throw new DeliveryError(
			"DELIVERY_TRANSACTION_REQUIRED",
			"Delivery quota admission requires an active PostgreSQL transaction adapter",
		);
	}
	const target = normalizeScope(input);
	await transaction.rawTransactionQuery(
		"SELECT pg_advisory_xact_lock(hashtext('clearance.delivery.quota'), hashtext($1))",
		[JSON.stringify([target.projectId, target.environmentId])],
	);
	return target;
}

export async function enforceDeliveryQuotaInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & { policy?: DeliveryQuotaPolicy; now?: Date },
	options: DeliverySchemaOptions = {},
): Promise<DeliveryQuotaStatus> {
	if (!transaction.rawTransactionQuery) {
		throw new DeliveryError(
			"DELIVERY_TRANSACTION_REQUIRED",
			"Delivery quota enforcement requires an active PostgreSQL transaction adapter",
		);
	}
	const rawQuery = transaction.rawTransactionQuery;
	const target = await lockDeliveryQuotaScopeInExistingTransaction(transaction, input);
	const now = date(input.now, "now");
	const policy = input.policy ?? DEFAULT_DELIVERY_QUOTA_POLICY;
	const status = await statusWithQuery(
		rawQuery,
		{ ...target, policy, now },
		options,
	);
	let quota: DeliveryQuotaKind | null = null;
	let limit = 0;
	let retryAfterSeconds: number | null = null;
	if (status.active.used >= status.active.limit) {
		quota = "active";
		limit = status.active.limit;
	} else if (status.backlog.used >= status.backlog.limit) {
		quota = "backlog";
		limit = status.backlog.limit;
	} else if (status.enqueueRate.used >= status.enqueueRate.limit) {
		quota = "enqueue_rate";
		limit = status.enqueueRate.limit;
		if (status.enqueueRate.resetsAt) {
			retryAfterSeconds = Math.max(
				1,
				Math.ceil((new Date(status.enqueueRate.resetsAt).getTime() - now.getTime()) / 1_000),
			);
		}
	}
	if (quota) throw new DeliveryQuotaExceededError({ quota, limit, retryAfterSeconds });
	return status;
}
