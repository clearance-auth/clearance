import { randomUUID } from "node:crypto";
import {
	extractDeliveryTraceCarrier,
	type DeliveryTraceCarrier,
	withDeliveryProcessingSpan,
} from "@clearance/observability-node";
import { context, ROOT_CONTEXT } from "@opentelemetry/api";
import pg from "pg";
import { DeliveryError, StaleDeliveryLeaseError } from "./errors.js";
import {
	deliveryReadiness,
	inspectDeliveryJobScoped,
	listDeliveryJobs,
	previewDeliveryControl,
	type DeliveryControlAction,
	type DeliveryControlPreview,
	type DeliveryJobPage,
	type DeliveryReadinessSummary,
} from "./control.js";
import {
	decryptDeliveryPayload,
	fingerprintDestination,
	type DeliveryKeyring,
	type DeliveryPayloadAad,
} from "./keyring.js";
import {
	type DeliveryJobRecord,
	type DeliveryJobState,
	redactedDeliveryJob,
	safeErrorClass,
	safeProviderValue,
} from "./redaction.js";
import {
	migrateDeliverySchema,
	qualifiedDeliveryTables,
	type DeliverySchemaOptions,
} from "./schema.js";
import {
	deliveryQuotaStatus,
	type DeliveryQuotaPolicy,
	type DeliveryQuotaStatus,
	type DeliveryScope,
} from "./quota.js";
import {
	appendRuntimeAuditInTransaction,
	assertRuntimeAuditTableReady,
} from "./runtime-audit.js";

type JobRow = {
	id: string;
	event_id: string;
	kind: string;
	project_id: string;
	environment_id: string;
	organization_id: string | null;
	actor_id: string | null;
	correlation_id: string | null;
	webhook_endpoint_id: string | null;
	channel: "email" | "webhook";
	state: DeliveryJobState;
	cancel_requested: boolean;
	attempt_count: number;
	max_attempts: number;
	available_at: Date | string;
	semantic_expires_at: Date | string;
	last_error_class: string | null;
	provider_accepted_at: Date | string | null;
	provider_status: string | null;
	provider_request_id: string | null;
	created_at: Date | string;
	updated_at: Date | string;
	delivered_at: Date | string | null;
	dead_at: Date | string | null;
	cancelled_at: Date | string | null;
	trace_parent: string | null;
};

function withDetachedTraceContext<T>(operation: () => T): T {
	return context.with(ROOT_CONTEXT, operation);
}

export type LeasedDeliveryJob = DeliveryJobRecord & {
	leaseToken: string;
	leaseOwner: string;
	leaseExpiresAt: string;
	/** Internal worker-only propagation state; omitted from all job inspection records. */
	traceCarrier?: DeliveryTraceCarrier;
};

function iso(value: Date | string | null): string | null {
	return value === null ? null : new Date(value).toISOString();
}

function validDate(value: Date, label: string): Date {
	if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
		throw new DeliveryError("DELIVERY_DATE_INVALID", `${label} must be a valid date`);
	}
	return value;
}

function boundedInteger(
	value: number,
	label: string,
	minimum: number,
	maximum: number,
): number {
	if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
		throw new DeliveryError(
			"DELIVERY_BOUND_INVALID",
			`${label} must be an integer between ${minimum} and ${maximum}`,
		);
	}
	return value;
}

function validWorkerId(value: string): string {
	const normalized = value.trim();
	if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(normalized)) {
		throw new DeliveryError(
			"DELIVERY_WORKER_ID_INVALID",
			"workerId must be a bounded opaque identifier",
		);
	}
	return normalized;
}

function jobRecord(row: JobRow): DeliveryJobRecord {
	return {
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
}

export function fullJitterDelayMs(
	attemptNumber: number,
	options: { baseMs?: number; capMs?: number; random?: () => number } = {},
): number {
	const attempt = boundedInteger(attemptNumber, "attemptNumber", 1, 100);
	const baseMs = boundedInteger(options.baseMs ?? 5_000, "baseMs", 1, 60_000);
	const capMs = boundedInteger(options.capMs ?? 3_600_000, "capMs", baseMs, 86_400_000);
	const random = options.random ?? Math.random;
	const sample = random();
	if (!Number.isFinite(sample) || sample < 0 || sample > 1) {
		throw new DeliveryError("DELIVERY_RANDOM_INVALID", "Retry jitter source must return a value from 0 through 1");
	}
	const ceiling = Math.min(capMs, baseMs * 2 ** Math.max(0, attempt - 1));
	return Math.floor(Math.min(0.999999999, sample) * ceiling);
}

export class DeliveryStore {
	readonly pool: pg.Pool;
	readonly options: DeliverySchemaOptions;
	private readonly tables: ReturnType<typeof qualifiedDeliveryTables>;

	constructor(pool: pg.Pool, options: DeliverySchemaOptions = {}) {
		this.pool = pool;
		this.options = options;
		this.tables = qualifiedDeliveryTables(options);
	}

	migrate() {
		return migrateDeliverySchema(this.pool, this.options);
	}

	/** Verify a configured product-owned audit authority without ever migrating it. */
	async assertRuntimeAuditTableReady(): Promise<void> {
		if (!this.options.runtimeAudit) return;
		await assertRuntimeAuditTableReady({
			rawTransactionQuery: async <Row extends Record<string, unknown> = Record<string, unknown>>(
				text: string,
				values: readonly unknown[] = [],
			) => {
				const result = await this.pool.query<Row>(text, [...values]);
				return { rows: result.rows, rowCount: result.rowCount };
			},
		}, this.options.runtimeAudit);
	}

	private async appendWebhookAudit(
		client: pg.PoolClient,
		row: Readonly<{
			id: string;
			event_id: string;
			project_id: string;
			environment_id: string;
			organization_id: string | null;
			actor_id: string | null;
			correlation_id: string | null;
			webhook_endpoint_id: string | null;
			attempt_count: number;
		}>,
		action: "delivery.webhook.delivered" | "delivery.webhook.retried" | "delivery.webhook.dead",
		terminalState: "delivered" | "retry" | "dead",
		input: Readonly<{
			providerStatus?: string | null;
			providerRequestId?: string | null;
			errorClass?: string | null;
			now: Date;
		}>,
	): Promise<void> {
		if (!this.options.runtimeAudit) return;
		const providerStatus = safeProviderValue(input.providerStatus, "status");
		const providerRequestId = safeProviderValue(input.providerRequestId, "requestId");
		const errorClass = safeErrorClass(input.errorClass);
		await appendRuntimeAuditInTransaction({
			rawTransactionQuery: async <Row extends Record<string, unknown> = Record<string, unknown>>(
				text: string,
				values: readonly unknown[] = [],
			) => {
				const result = await client.query<Row>(text, [...values]);
				return { rows: result.rows, rowCount: result.rowCount };
			},
		}, this.options.runtimeAudit, {
			correlationId: row.correlation_id ?? row.event_id,
			projectId: row.project_id,
			environmentId: row.environment_id,
			organizationId: row.organization_id,
			actor: row.actor_id ?? "system",
			action,
			subjectType: "delivery_job",
			subjectId: row.id,
			outcome: terminalState === "retry" ? "pending" : terminalState === "delivered" ? "success" : "failure",
			source: "system",
			message: terminalState === "retry" ? "Webhook delivery retry scheduled" : terminalState === "delivered" ? "Webhook delivery delivered" : "Webhook delivery dead-lettered",
			metadata: {
				eventId: row.event_id,
				...(row.webhook_endpoint_id === null ? {} : { endpointId: row.webhook_endpoint_id }),
				attempt: Number(row.attempt_count),
				terminalState,
				...(providerStatus === null ? {} : { providerStatus }),
				...(providerRequestId === null ? {} : { providerRequestId }),
				...(errorClass === null ? {} : { errorClass }),
				request: {
					operationId: "delivery-webhook-transition",
					route: "/internal/delivery/webhook",
					method: "POST",
					clientIp: null,
					userAgent: null,
				},
			},
			createdAt: input.now,
		});
	}

	/**
	 * Worker/readiness gate for every retained delivery key reference: unexpired
	 * payload encryption, live endpoint config and URL fingerprints, active-job
	 * destination fingerprints, and legacy source-dedupe aliases.
	 */
	async assertDeliveryKeysAvailable(keyring: DeliveryKeyring, now = new Date()): Promise<void> {
		validDate(now, "now");
		const referenced = await this.pool.query<{ key_kind: "encryption" | "fingerprint"; key_id: string }>(
			`SELECT DISTINCT p.key_id, 'encryption' key_kind
			 FROM ${this.tables.payload} p WHERE p.expires_at > $1
			 UNION
			 SELECT DISTINCT e.destination_fingerprint_key_id key_id, 'fingerprint' key_kind
			 FROM ${this.tables.event} e JOIN ${this.tables.job} j ON j.event_id=e.id
			 LEFT JOIN ${this.tables.payload} p ON p.event_id=e.id
			 WHERE j.state IN ('queued','leased','retry')
			    OR (j.state IN ('delivered','dead','cancelled')
			        AND p.expires_at > $1 AND e.semantic_expires_at > $1)
			 UNION
			 SELECT DISTINCT e.source_fingerprint_key_id key_id, 'fingerprint' key_kind
			 FROM ${this.tables.event} e WHERE e.source_dedupe_version=1
			 UNION
			 SELECT DISTINCT w.config_key_id key_id, 'encryption' key_kind
			 FROM ${this.tables.webhookEndpoint} w WHERE w.status <> 'deleted'
			 UNION
			 SELECT DISTINCT w.url_fingerprint_key_id key_id, 'fingerprint' key_kind
			 FROM ${this.tables.webhookEndpoint} w WHERE w.status <> 'deleted'`,
			[now],
		);
		const missing = referenced.rows.find((row) => row.key_kind === "encryption"
			? !keyring.keys.has(row.key_id)
			: !keyring.fingerprintKeys.has(row.key_id));
		if (missing) {
			throw new DeliveryError(
				missing.key_kind === "encryption"
					? "DELIVERY_KEY_UNAVAILABLE"
					: "DELIVERY_FINGERPRINT_KEY_UNAVAILABLE",
				"A retained delivery key reference is unavailable",
			);
		}
	}

	/** Backward-compatible worker entry point; now checks encryption and fingerprint keys. */
	assertFingerprintKeysAvailable(keyring: DeliveryKeyring, now = new Date()): Promise<void> {
		return this.assertDeliveryKeysAvailable(keyring, now);
	}

	private async transaction<T>(fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const value = await fn(client);
			await client.query("COMMIT");
			return value;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	async claimNext(input: {
		workerId: string;
		leaseMs?: number;
		now?: Date;
	}): Promise<LeasedDeliveryJob | null> {
		return (await this.#claimNextDetached(input)) ?? null;
	}

	/**
	 * Lease the next job without inheriting an ambient trace. Only after the
	 * claim commits and releases its database client does the worker operation
	 * begin under that job's durable parent.
	 */
	async claimNextWithTrace<T>(input: {
		workerId: string;
		leaseMs?: number;
		now?: Date;
	}, process: (leased: LeasedDeliveryJob) => Promise<T>): Promise<T | undefined> {
		const leased = await this.#claimNextDetached(input);
		if (!leased) return undefined;
		return withDeliveryProcessingSpan({
			...(leased.traceCarrier === undefined ? {} : { carrier: leased.traceCarrier }),
			channel: leased.channel,
			transport: "postgres",
		}, () => process(leased));
	}

	/**
	 * The complete candidate read and atomic claim run detached from ambient
	 * context. Lease-only callers therefore create no processing span.
	 */
	async #claimNextDetached(input: {
		workerId: string;
		leaseMs?: number;
		now?: Date;
	}): Promise<LeasedDeliveryJob | undefined> {
		const now = validDate(input.now ?? new Date(), "now");
		const workerId = validWorkerId(input.workerId);
		const leaseMs = boundedInteger(input.leaseMs ?? 60_000, "leaseMs", 1_000, 600_000);
		const leaseExpiresAt = new Date(now.getTime() + leaseMs);
		const leaseToken = randomUUID();
		const client = await this.pool.connect();
		let transactionOpen = false;
		let clientReleased = false;
		try {
			await withDetachedTraceContext(() => client.query("BEGIN"));
			transactionOpen = true;
			const candidate = await withDetachedTraceContext(() => client.query<JobRow>(
				`SELECT j.*, e.kind, e.project_id, e.environment_id, e.organization_id, e.webhook_endpoint_id,
				 e.trace_parent
				 FROM ${this.tables.job} j JOIN ${this.tables.event} e ON e.id=j.event_id
				 WHERE j.state IN ('queued','retry') AND j.available_at <= $1
				   AND j.semantic_expires_at > $1 AND j.attempt_count < j.max_attempts
				 ORDER BY j.available_at, j.id FOR UPDATE SKIP LOCKED LIMIT 1`,
				[now],
			));
			const selected = candidate.rows[0];
			if (!selected) {
				await withDetachedTraceContext(() => client.query("COMMIT"));
				transactionOpen = false;
				return undefined;
			}
			const traceCarrier = extractDeliveryTraceCarrier(selected.trace_parent);
			const updated = await withDetachedTraceContext(() => client.query<JobRow>(
				`UPDATE ${this.tables.job} SET
				 state='leased', lease_token=$2, lease_owner=$3, lease_expires_at=$4,
				 attempt_count=attempt_count+1, updated_at=$1, cancel_requested=false,
				 provider_accepted_at=NULL, provider_status=NULL, provider_request_id=NULL
				 WHERE id=$5 AND state IN ('queued','retry')
				 RETURNING *`,
				[now, leaseToken, workerId, leaseExpiresAt, selected.id],
			));
			const row = updated.rows[0];
			if (!row) throw new StaleDeliveryLeaseError();
			await withDetachedTraceContext(() => client.query(
				`INSERT INTO ${this.tables.attempt}
				 (id, job_id, attempt_number, lease_token, phase, worker_id, created_at)
				 VALUES ($1,$2,$3,$4,'claimed',$5,$6)`,
				[randomUUID(), row.id, row.attempt_count, leaseToken, workerId, now],
			));
			await withDetachedTraceContext(() => client.query("COMMIT"));
			transactionOpen = false;
			const leased: LeasedDeliveryJob = {
				...jobRecord({ ...selected, ...row }),
				leaseToken,
				leaseOwner: workerId,
				leaseExpiresAt: leaseExpiresAt.toISOString(),
				...(traceCarrier === undefined ? {} : { traceCarrier }),
			};
			client.release();
			clientReleased = true;
			return leased;
		} catch (error) {
			if (transactionOpen) {
				try {
					await withDetachedTraceContext(() => client.query("ROLLBACK"));
				} catch (rollbackError) {
					throw new AggregateError([error, rollbackError], "Delivery claim and rollback both failed");
				}
			}
			throw error;
		} finally {
			if (!clientReleased) client.release();
		}
	}

	async readLeasedPayload<T>(input: {
		jobId: string;
		leaseToken: string;
		keyring: DeliveryKeyring;
		now?: Date;
	}): Promise<T> {
		const now = validDate(input.now ?? new Date(), "now");
		const result = await this.pool.query<{
			envelope: string;
			event_id: string;
			kind: string;
			channel: "email" | "webhook";
			project_id: string;
			environment_id: string;
			destination_fingerprint: string;
			expires_at: Date | string;
		}>(
			`SELECT p.envelope, e.id event_id, e.kind, j.channel, e.project_id, e.environment_id,
			 e.destination_fingerprint, p.expires_at
			 FROM ${this.tables.job} j
			 JOIN ${this.tables.event} e ON e.id=j.event_id
			 JOIN ${this.tables.payload} p ON p.event_id=e.id
			 WHERE j.id=$1 AND j.state='leased' AND j.lease_token=$2
			   AND j.lease_expires_at > $3 AND p.expires_at > $3`,
			[input.jobId, input.leaseToken, now],
		);
		const row = result.rows[0];
		if (!row) throw new StaleDeliveryLeaseError();
		const aad: DeliveryPayloadAad = {
			version: 1,
			eventId: row.event_id,
			kind: row.kind,
			channel: row.channel,
			projectId: row.project_id,
			environmentId: row.environment_id,
			destinationFingerprint: row.destination_fingerprint,
			expiresAt: iso(row.expires_at)!,
		};
		return decryptDeliveryPayload<T>(row.envelope, aad, input.keyring);
	}

	/** Extend an active lease while preserving token and owner fencing. */
	async renewLease(input: {
		jobId: string;
		leaseToken: string;
		workerId: string;
		leaseMs?: number;
		now?: Date;
	}): Promise<string> {
		const now = validDate(input.now ?? new Date(), "now");
		const workerId = validWorkerId(input.workerId);
		const leaseMs = boundedInteger(input.leaseMs ?? 60_000, "leaseMs", 1_000, 600_000);
		const leaseExpiresAt = new Date(now.getTime() + leaseMs);
		const result = await this.pool.query<{ lease_expires_at: Date | string }>(
			`UPDATE ${this.tables.job} SET lease_expires_at=GREATEST(lease_expires_at,$5), updated_at=$4
			 WHERE id=$1 AND state='leased' AND lease_token=$2 AND lease_owner=$3
			   AND lease_expires_at > $4
			 RETURNING lease_expires_at`,
			[input.jobId, input.leaseToken, workerId, now, leaseExpiresAt],
		);
		const row = result.rows[0];
		if (!row) throw new StaleDeliveryLeaseError();
		return iso(row.lease_expires_at)!;
	}

	/** Fail closed if the decrypted recipient differs from the audited destination. */
	async assertLeasedDestination(input: {
		jobId: string;
		leaseToken: string;
		destination: string;
		keyring: DeliveryKeyring;
		now?: Date;
	}): Promise<void> {
		const now = validDate(input.now ?? new Date(), "now");
		const result = await this.pool.query<{
			destination_fingerprint: string;
			destination_fingerprint_key_id: string;
		}>(
			`SELECT e.destination_fingerprint, e.destination_fingerprint_key_id
			 FROM ${this.tables.job} j
			 JOIN ${this.tables.event} e ON e.id=j.event_id
			 WHERE j.id=$1 AND j.state='leased' AND j.lease_token=$2
			   AND j.lease_expires_at > $3`,
			[input.jobId, input.leaseToken, now],
		);
		const row = result.rows[0];
		if (!row) throw new StaleDeliveryLeaseError();
		if (
			fingerprintDestination(
				input.destination,
				input.keyring,
				row.destination_fingerprint_key_id,
			) !== row.destination_fingerprint
		) {
			throw new DeliveryError(
				"DELIVERY_DESTINATION_MISMATCH",
				"Decrypted delivery recipient does not match the audited destination",
			);
		}
	}

	/** Persist provider acceptance before final completion to prevent blind resend. */
	async markProviderAccepted(input: {
		jobId: string;
		leaseToken: string;
		workerId: string;
		providerStatus: string;
		providerRequestId?: string;
		now?: Date;
	}): Promise<void> {
		const now = validDate(input.now ?? new Date(), "now");
		const workerId = validWorkerId(input.workerId);
		const providerStatus = safeProviderValue(input.providerStatus, "status");
		if (!providerStatus) {
			throw new DeliveryError("DELIVERY_PROVIDER_STATUS_REQUIRED", "Provider acceptance status is required");
		}
		const providerRequestId = safeProviderValue(input.providerRequestId, "requestId");
		const result = await this.pool.query(
			`UPDATE ${this.tables.job} SET provider_accepted_at=$4, provider_status=$5,
			 provider_request_id=$6, last_error_class='provider_accepted_unconfirmed', updated_at=$4
			 WHERE id=$1 AND state='leased' AND lease_token=$2 AND lease_owner=$3
			   AND lease_expires_at > $4`,
			[input.jobId, input.leaseToken, workerId, now, providerStatus, providerRequestId],
		);
		if (!result.rowCount) throw new StaleDeliveryLeaseError();
	}

	async complete(input: {
		jobId: string;
		leaseToken: string;
		workerId: string;
		providerStatus?: string;
		providerRequestId?: string;
		now?: Date;
	}): Promise<DeliveryJobRecord> {
		return this.finishLease({ ...input, retryable: false, delivered: true });
	}

	async fail(input: {
		jobId: string;
		leaseToken: string;
		workerId: string;
		retryable: boolean;
		errorClass?: string;
		providerStatus?: string;
		providerRequestId?: string;
		now?: Date;
		random?: () => number;
	}): Promise<DeliveryJobRecord> {
		return this.finishLease({ ...input, delivered: false });
	}

	async retry(input: Omit<Parameters<DeliveryStore["fail"]>[0], "retryable">) {
		return this.fail({ ...input, retryable: true });
	}

	async dead(input: Omit<Parameters<DeliveryStore["fail"]>[0], "retryable">) {
		return this.fail({ ...input, retryable: false });
	}

	private async finishLease(input: {
		jobId: string;
		leaseToken: string;
		workerId: string;
		retryable: boolean;
		delivered: boolean;
		errorClass?: string;
		providerStatus?: string;
		providerRequestId?: string;
		now?: Date;
		random?: () => number;
	}): Promise<DeliveryJobRecord> {
		const now = validDate(input.now ?? new Date(), "now");
		const workerId = validWorkerId(input.workerId);
		return this.transaction(async (client) => {
			const locked = await client.query<JobRow & { cancel_requested: boolean }>(
				`SELECT j.*, e.kind, e.project_id, e.environment_id, e.organization_id, e.actor_id, e.correlation_id, e.webhook_endpoint_id
				 FROM ${this.tables.job} j JOIN ${this.tables.event} e ON e.id=j.event_id
				 WHERE j.id=$1 AND j.state='leased' AND j.lease_token=$2
				   AND j.lease_owner=$3 AND j.lease_expires_at > $4 FOR UPDATE OF j`,
				[input.jobId, input.leaseToken, workerId, now],
			);
			const row = locked.rows[0];
			if (!row) throw new StaleDeliveryLeaseError();
			let state: DeliveryJobState;
			let phase: "delivered" | "retry" | "dead" | "cancelled";
			let availableAt = new Date(row.available_at);
			const semanticExpired = new Date(row.semantic_expires_at) <= now;
			if (semanticExpired) {
				state = phase = "dead";
			} else if (input.delivered) {
				state = phase = "delivered";
			} else if (row.cancel_requested) {
				state = phase = "cancelled";
			} else if (
				!input.retryable ||
				Number(row.attempt_count) >= Number(row.max_attempts) ||
				new Date(row.semantic_expires_at) <= now
			) {
				state = phase = "dead";
			} else {
				state = phase = "retry";
				availableAt = new Date(
					now.getTime() + fullJitterDelayMs(Number(row.attempt_count), { random: input.random }),
				);
				if (availableAt >= new Date(row.semantic_expires_at)) {
					state = phase = "dead";
				}
			}
			const errorClass = semanticExpired
				? "semantic_expired"
				: safeErrorClass(input.errorClass);
			const updated = await client.query<JobRow>(
				`UPDATE ${this.tables.job} SET state=$3, available_at=$4,
				 lease_token=NULL, lease_owner=NULL, lease_expires_at=NULL, cancel_requested=false,
				 last_error_class=$5, updated_at=$6,
				 delivered_at=CASE WHEN $3='delivered' THEN $6 ELSE delivered_at END,
				 dead_at=CASE WHEN $3='dead' THEN $6 ELSE dead_at END,
				 cancelled_at=CASE WHEN $3='cancelled' THEN $6 ELSE cancelled_at END
				 WHERE id=$1 AND lease_token=$2 RETURNING *`,
				[input.jobId, input.leaseToken, state, availableAt, errorClass, now],
			);
			await client.query(
				`INSERT INTO ${this.tables.attempt}
				 (id, job_id, attempt_number, lease_token, phase, worker_id,
				  provider_status, provider_request_id, error_class, created_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
				[
					randomUUID(), row.id, row.attempt_count, input.leaseToken, phase,
					workerId, safeProviderValue(input.providerStatus, "status"),
					safeProviderValue(input.providerRequestId, "requestId"), errorClass, now,
				],
			);
			if (row.channel === "webhook") {
				const audit = state === "delivered"
					? { action: "delivery.webhook.delivered" as const, terminalState: "delivered" as const }
					: state === "retry"
						? { action: "delivery.webhook.retried" as const, terminalState: "retry" as const }
						: state === "dead"
							? { action: "delivery.webhook.dead" as const, terminalState: "dead" as const }
							: null;
				if (audit) {
					await this.appendWebhookAudit(client, row, audit.action, audit.terminalState, {
						providerStatus: input.providerStatus,
						providerRequestId: input.providerRequestId,
						errorClass,
						now,
					});
				}
			}
			return jobRecord({ ...updated.rows[0]!, kind: row.kind, project_id: row.project_id,
				environment_id: row.environment_id, organization_id: row.organization_id,
				webhook_endpoint_id: row.webhook_endpoint_id });
		});
	}

	async cancel(jobId: string, now = new Date()): Promise<DeliveryJobRecord | null> {
		validDate(now, "now");
		const result = await this.pool.query<JobRow>(
			`UPDATE ${this.tables.job} SET
			 state=CASE WHEN state IN ('queued','retry') THEN 'cancelled' ELSE state END,
			 cancel_requested=CASE WHEN state='leased' THEN true ELSE false END,
			 cancelled_at=CASE WHEN state IN ('queued','retry') THEN $2 ELSE cancelled_at END,
			 updated_at=$2
			 WHERE id=$1 AND state IN ('queued','retry','leased') RETURNING *`,
			[jobId, now],
		);
		const row = result.rows[0];
		if (!row) return null;
		const event = await this.pool.query<Pick<JobRow, "kind" | "project_id" | "environment_id" | "organization_id" | "webhook_endpoint_id">>(
			`SELECT kind, project_id, environment_id, organization_id, webhook_endpoint_id
			 FROM ${this.tables.event} WHERE id=$1`,
			[row.event_id],
		);
		return jobRecord({ ...row, ...event.rows[0]! });
	}

	async reclaimExpired(now = new Date(), limit = 100): Promise<number> {
		validDate(now, "now");
		boundedInteger(limit, "reclaim limit", 1, 1_000);
		return this.transaction(async (client) => {
			const rows = await client.query<{
				id: string; event_id: string; channel: "email" | "webhook"; project_id: string;
				environment_id: string; organization_id: string | null; actor_id: string | null;
				correlation_id: string | null; webhook_endpoint_id: string | null;
				attempt_count: number; max_attempts: number; semantic_expires_at: Date | string;
				lease_token: string; lease_owner: string; cancel_requested: boolean;
				provider_accepted_at: Date | string | null; provider_status: string | null;
				provider_request_id: string | null;
			}>(
				`SELECT j.id, j.event_id, j.channel, j.attempt_count, j.max_attempts, j.semantic_expires_at,
				 j.lease_token, j.lease_owner, j.cancel_requested, j.provider_accepted_at, j.provider_status,
				 j.provider_request_id, e.project_id, e.environment_id, e.organization_id, e.actor_id,
				 e.correlation_id, e.webhook_endpoint_id
				 FROM ${this.tables.job} j JOIN ${this.tables.event} e ON e.id=j.event_id
				 WHERE j.state='leased' AND j.lease_expires_at <= $1
				 ORDER BY j.lease_expires_at, j.id FOR UPDATE OF j SKIP LOCKED LIMIT $2`,
				[now, limit],
			);
			for (const row of rows.rows) {
				const acceptedUnconfirmed = row.provider_accepted_at !== null;
				const dead = acceptedUnconfirmed || Number(row.attempt_count) >= Number(row.max_attempts) || new Date(row.semantic_expires_at) <= now;
				const state = row.cancel_requested ? "cancelled" : dead ? "dead" : "retry";
				const phase = row.cancel_requested ? "cancelled" : acceptedUnconfirmed ? "dead" : "lease_expired";
				const errorClass = acceptedUnconfirmed ? "provider_accepted_unconfirmed" : "lease_expired";
				await client.query(
					`UPDATE ${this.tables.job} SET state=$2, available_at=$1,
					 lease_token=NULL, lease_owner=NULL, lease_expires_at=NULL, cancel_requested=false,
					 updated_at=$1, dead_at=CASE WHEN $2='dead' THEN $1 ELSE dead_at END,
					 cancelled_at=CASE WHEN $2='cancelled' THEN $1 ELSE cancelled_at END,
						 last_error_class=$5 WHERE id=$3 AND lease_token=$4`,
					[now, state, row.id, row.lease_token, errorClass],
				);
				await client.query(
					`INSERT INTO ${this.tables.attempt}
						 (id, job_id, attempt_number, lease_token, phase, worker_id,
						  provider_status, provider_request_id, error_class, created_at)
						 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
					[randomUUID(), row.id, row.attempt_count, row.lease_token, phase, row.lease_owner,
						row.provider_status, row.provider_request_id, errorClass, now],
				);
				if (row.channel === "webhook" && state !== "cancelled") {
					await this.appendWebhookAudit(
						client,
						row,
						state === "retry" ? "delivery.webhook.retried" : "delivery.webhook.dead",
						state === "retry" ? "retry" : "dead",
						{
							providerStatus: row.provider_status,
							providerRequestId: row.provider_request_id,
							errorClass,
							now,
						},
					);
				}
			}
			return rows.rows.length;
		});
	}

	/** Dead-letter semantic expiry and crypto-erase only after every event job is terminal. */
	async expireAndEraseUndeliverable(
		now = new Date(),
		limit = 1_000,
	): Promise<{ deadJobs: number; erasedPayloads: number }> {
		validDate(now, "now");
		boundedInteger(limit, "expiry limit", 1, 1_000);
		return this.transaction(async (client) => {
			const expired = await client.query<{
				id: string; event_id: string; channel: "email" | "webhook"; project_id: string;
				environment_id: string; organization_id: string | null; actor_id: string | null;
				correlation_id: string | null; webhook_endpoint_id: string | null;
				state: DeliveryJobState; attempt_count: number; lease_token: string | null; lease_owner: string | null;
			}>(
				`SELECT j.id, j.event_id, j.channel, j.state, j.attempt_count, j.lease_token, j.lease_owner,
				 e.project_id, e.environment_id, e.organization_id, e.actor_id, e.correlation_id,
				 e.webhook_endpoint_id
				 FROM ${this.tables.job} j JOIN ${this.tables.event} e ON e.id=j.event_id
				 WHERE j.state IN ('queued','retry','leased') AND j.semantic_expires_at <= $1
				 ORDER BY j.semantic_expires_at, j.id FOR UPDATE OF j SKIP LOCKED LIMIT $2`,
				[now, limit],
			);
			for (const row of expired.rows) {
				await client.query(
					`UPDATE ${this.tables.job} SET state='dead', dead_at=$1, updated_at=$1,
					 lease_token=NULL, lease_owner=NULL, lease_expires_at=NULL,
					 cancel_requested=false, last_error_class='semantic_expired'
					 WHERE id=$2`,
					[now, row.id],
				);
				if (row.state === "leased" && row.lease_token && row.lease_owner) {
					await client.query(
						`INSERT INTO ${this.tables.attempt}
						 (id, job_id, attempt_number, lease_token, phase, worker_id, error_class, created_at)
						 VALUES ($1,$2,$3,$4,'dead',$5,'semantic_expired',$6)`,
						[randomUUID(), row.id, row.attempt_count, row.lease_token, row.lease_owner, now],
					);
				}
				if (row.channel === "webhook") {
					await this.appendWebhookAudit(client, row, "delivery.webhook.dead", "dead", {
						errorClass: "semantic_expired",
						now,
					});
				}
			}
			const erased = await client.query(
				`DELETE FROM ${this.tables.payload} p
				 WHERE p.expires_at <= $1
				   AND NOT EXISTS (
					SELECT 1 FROM ${this.tables.job} j
					WHERE j.event_id=p.event_id AND j.state IN ('queued','retry','leased')
				   )`,
				[now],
			);
			return {
				deadJobs: expired.rows.length,
				erasedPayloads: erased.rowCount ?? 0,
			};
		});
	}

	/** Explicit replay-window erasure; claimable and leased deliveries are never touched. */
	async eraseTerminalPayloads(input: {
		terminalBefore: Date;
		now?: Date;
	}): Promise<number> {
		const now = validDate(input.now ?? new Date(), "now");
		const terminalBefore = validDate(input.terminalBefore, "terminalBefore");
		if (terminalBefore > now) {
			throw new DeliveryError(
				"DELIVERY_RETENTION_INVALID",
				"terminalBefore cannot be in the future",
			);
		}
		const erased = await this.pool.query(
			`DELETE FROM ${this.tables.payload} p
			 WHERE NOT EXISTS (
				SELECT 1 FROM ${this.tables.job} active
				WHERE active.event_id=p.event_id AND active.state IN ('queued','retry','leased')
			 )
			 AND EXISTS (
				SELECT 1 FROM ${this.tables.job} terminal
				WHERE terminal.event_id=p.event_id
				  AND COALESCE(terminal.delivered_at, terminal.dead_at, terminal.cancelled_at) <= $1
			 )`,
			[terminalBefore],
		);
		return erased.rowCount ?? 0;
	}

	/**
	 * Explicit structural retention. Event/attempt deletion is additionally
	 * guarded in Postgres by age and terminal-state checks.
	 */
	async cleanupRetention(input: {
		payloadBefore: Date;
		terminalBefore: Date;
		eventBefore: Date;
		workerBefore: Date;
		now?: Date;
	}): Promise<{
		erasedPayloads: number;
		deletedAttempts: number;
		deletedJobs: number;
		deletedEvents: number;
		deletedWorkers: number;
	}> {
		const now = validDate(input.now ?? new Date(), "now");
		const payloadBefore = validDate(input.payloadBefore, "payloadBefore");
		const terminalBefore = validDate(input.terminalBefore, "terminalBefore");
		const eventBefore = validDate(input.eventBefore, "eventBefore");
		const workerBefore = validDate(input.workerBefore, "workerBefore");
		const minimumStructuralAge = 30 * 24 * 60 * 60_000;
		const minimumWorkerAge = 24 * 60 * 60_000;
		if (
			terminalBefore.getTime() > now.getTime() - minimumStructuralAge ||
			eventBefore.getTime() > now.getTime() - minimumStructuralAge ||
			workerBefore.getTime() > now.getTime() - minimumWorkerAge ||
			payloadBefore > now ||
			payloadBefore < terminalBefore ||
			eventBefore > terminalBefore
		) {
			throw new DeliveryError(
				"DELIVERY_RETENTION_INVALID",
				"Retention requires payload cutoff by now, terminal/event age of at least 30 days, worker age of at least 24 hours, and dependency-safe cutoff ordering",
			);
		}
		return this.transaction(async (client) => {
			const payloads = await client.query(
				`DELETE FROM ${this.tables.payload} p
				 WHERE NOT EXISTS (
					SELECT 1 FROM ${this.tables.job} active
					WHERE active.event_id=p.event_id AND active.state IN ('queued','retry','leased')
				 )
				 AND EXISTS (
					SELECT 1 FROM ${this.tables.job} terminal
					WHERE terminal.event_id=p.event_id
					  AND COALESCE(terminal.delivered_at, terminal.dead_at, terminal.cancelled_at) <= $1
				 )`,
				[payloadBefore],
			);
			const attempts = await client.query(
				`DELETE FROM ${this.tables.attempt} a USING ${this.tables.job} j
				 WHERE a.job_id=j.id AND a.created_at <= $1
				   AND j.state IN ('delivered','dead','cancelled')
				   AND COALESCE(j.delivered_at, j.dead_at, j.cancelled_at) <= $1`,
				[terminalBefore],
			);
			const jobs = await client.query(
				`DELETE FROM ${this.tables.job}
				 WHERE state IN ('delivered','dead','cancelled')
				   AND COALESCE(delivered_at, dead_at, cancelled_at) <= $1`,
				[terminalBefore],
			);
			const events = await client.query(
				`DELETE FROM ${this.tables.event} e
				 WHERE e.created_at <= $1
				   AND NOT EXISTS (SELECT 1 FROM ${this.tables.job} j WHERE j.event_id=e.id)
				   AND NOT EXISTS (SELECT 1 FROM ${this.tables.payload} p WHERE p.event_id=e.id)
				   AND NOT EXISTS (SELECT 1 FROM ${this.tables.event} replay WHERE replay.replay_of=e.id)`,
				[eventBefore],
			);
			const workers = await client.query(
				`DELETE FROM ${this.tables.worker} WHERE last_seen_at <= $1`,
				[workerBefore],
			);
			return {
				erasedPayloads: payloads.rowCount ?? 0,
				deletedAttempts: attempts.rowCount ?? 0,
				deletedJobs: jobs.rowCount ?? 0,
				deletedEvents: events.rowCount ?? 0,
				deletedWorkers: workers.rowCount ?? 0,
			};
		});
	}

	async heartbeat(input: {
		workerId: string;
		version: string;
		state: "starting" | "ready" | "draining" | "stopped" | "failed";
		now?: Date;
	}): Promise<void> {
		const now = validDate(input.now ?? new Date(), "now");
		const workerId = validWorkerId(input.workerId);
		const version = input.version.trim();
		if (!/^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$/.test(version)) {
			throw new DeliveryError(
				"DELIVERY_WORKER_VERSION_INVALID",
				"Worker version must be a bounded opaque version identifier",
			);
		}
		await this.pool.query(
			`INSERT INTO ${this.tables.worker} (id, version, state, started_at, last_seen_at)
			 VALUES ($1,$2,$3,$4,$4)
			 ON CONFLICT (id) DO UPDATE SET version=EXCLUDED.version,
			 state=EXCLUDED.state, last_seen_at=EXCLUDED.last_seen_at`,
			[workerId, version, input.state, now],
		);
	}

	async inspectJob(jobId: string) {
		const result = await this.pool.query<JobRow>(
			`SELECT j.*, e.kind, e.project_id, e.environment_id, e.organization_id, e.webhook_endpoint_id
			 FROM ${this.tables.job} j JOIN ${this.tables.event} e ON e.id=j.event_id
			 WHERE j.id=$1`,
			[jobId],
		);
		return result.rows[0] ? redactedDeliveryJob(jobRecord(result.rows[0])) : null;
	}

	listJobs(input: DeliveryScope & {
		limit?: number;
		cursor?: string;
		states?: readonly DeliveryJobState[];
		channel?: "email" | "webhook";
		kind?: string;
	}): Promise<DeliveryJobPage> {
		return listDeliveryJobs(this.pool, input, this.options);
	}

	inspectJobScoped(
		input: DeliveryScope & { jobId: string },
	): Promise<ReturnType<typeof redactedDeliveryJob> | null> {
		return inspectDeliveryJobScoped(this.pool, input, this.options);
	}

	previewControl(
		input: DeliveryScope & {
			jobId: string;
			action: DeliveryControlAction;
			now?: Date;
			maxAttempts?: number;
		},
	): Promise<DeliveryControlPreview | null> {
		return previewDeliveryControl(this.pool, input, this.options);
	}

	quotaStatus(
		input: DeliveryScope & { policy?: DeliveryQuotaPolicy; now?: Date },
	): Promise<DeliveryQuotaStatus> {
		return deliveryQuotaStatus(this.pool, input, this.options);
	}

	readiness(
		input: { now?: Date; staleAfterMs?: number } = {},
		keyring?: DeliveryKeyring,
	): Promise<DeliveryReadinessSummary> {
		return deliveryReadiness(this.pool, input, this.options, keyring);
	}
}
