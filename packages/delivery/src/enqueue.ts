import { randomUUID } from "node:crypto";
import type pg from "pg";
import { DeliveryError } from "./errors.js";
import {
	encryptDeliveryPayload,
	fingerprintDestination,
	fingerprintSource,
	fingerprintSourceDedupe,
	type DeliveryKeyring,
	type DeliveryPayloadAad,
} from "./keyring.js";
import {
	qualifiedDeliveryTables,
	type DeliverySchemaOptions,
} from "./schema.js";
import {
	enforceDeliveryQuotaInExistingTransaction,
	lockDeliveryQuotaScopeInExistingTransaction,
	type DeliveryQuotaPolicy,
} from "./quota.js";
import { parseWebhookDeliveryPayload } from "./webhook-payload.js";

const transactionAdapterBrand: unique symbol = Symbol("delivery-transaction-adapter");

export interface DeliveryTransactionAdapter {
	readonly [transactionAdapterBrand]: true;
	query<Row extends pg.QueryResultRow = pg.QueryResultRow>(
		text: string,
		params?: unknown[],
	): Promise<pg.QueryResult<Row>>;
}

export type DeliveryRawTransaction = {
	rawTransactionQuery?: <Row extends Record<string, unknown> = Record<string, unknown>>(
		text: string,
		values?: readonly unknown[],
	) => Promise<{ rows: Row[]; rowCount: number | null }>;
};

/**
 * Adapt an already checked-out Postgres client. The caller owns BEGIN/COMMIT/
 * ROLLBACK; enqueueDelivery never opens or commits a transaction itself.
 */
export function createDeliveryTransactionAdapter(
	client: pg.PoolClient,
): DeliveryTransactionAdapter {
	return {
		[transactionAdapterBrand]: true,
		query: (text, params = []) => client.query(text, params),
	};
}

function createDeliveryRawTransactionAdapter(
	rawTransactionQuery: NonNullable<DeliveryRawTransaction["rawTransactionQuery"]>,
): DeliveryTransactionAdapter {
	return {
		[transactionAdapterBrand]: true,
		query: async <Row extends pg.QueryResultRow = pg.QueryResultRow>(
			text: string,
			params: unknown[] = [],
		) => {
			const result = await rawTransactionQuery<Row>(text, params);
			return {
				command: "",
				rowCount: result.rowCount,
				oid: 0,
				fields: [],
				rows: result.rows,
			};
		},
	};
}

export type EnqueueDeliveryInput = {
	eventId?: string;
	jobId?: string;
	kind: string;
	/** Secret-safe dedupe input; only its keyed HMAC is persisted. */
	sourceKey: string;
	projectId: string;
	environmentId: string;
	organizationId?: string;
	actorId?: string;
	correlationId?: string;
	replayOf?: string;
	channel: "email" | "webhook";
	/** Canonical destination; plaintext is encrypted only inside payload. */
	destination: string;
	payload: unknown;
	semanticExpiresAt: Date;
	availableAt?: Date;
	maxAttempts?: number;
	/** Per-scope server policy; defaults to Clearance's bounded production policy. */
	quota?: DeliveryQuotaPolicy;
	now?: Date;
};

export type EnqueuedDelivery = {
	eventId: string;
	jobId: string;
	kind: string;
	channel: "email" | "webhook";
	state: "queued";
	createdAt: string;
	semanticExpiresAt: string;
};

type InternalEnqueueDeliveryInput = EnqueueDeliveryInput & { webhookEndpointId?: string };

export async function enqueueDeliveryInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: EnqueueDeliveryInput,
	ring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<EnqueuedDelivery> {
	if (!transaction.rawTransactionQuery) {
		throw new DeliveryError(
			"DELIVERY_TRANSACTION_REQUIRED",
			"Durable delivery requires an active PostgreSQL transaction adapter",
		);
	}
	return enqueueDelivery(
		createDeliveryRawTransactionAdapter(transaction.rawTransactionQuery),
		input,
		ring,
		options,
	);
}

function required(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized) throw new DeliveryError("DELIVERY_INPUT_REQUIRED", `${label} is required`);
	return normalized;
}

async function enqueueDeliveryInternal(
	tx: DeliveryTransactionAdapter,
	input: InternalEnqueueDeliveryInput,
	ring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<EnqueuedDelivery> {
	if (tx[transactionAdapterBrand] !== true) {
		throw new DeliveryError(
			"DELIVERY_TRANSACTION_REQUIRED",
			"enqueueDelivery requires a transaction-bound adapter",
		);
	}
	const tables = qualifiedDeliveryTables(options);
	const now = input.now ?? new Date();
	if (!Number.isFinite(now.getTime())) {
		throw new DeliveryError("DELIVERY_NOW_INVALID", "Delivery current time is invalid");
	}
	const expiresAt = input.semanticExpiresAt;
	if (!Number.isFinite(expiresAt.getTime()) || expiresAt <= now) {
		throw new DeliveryError("DELIVERY_ALREADY_EXPIRED", "Delivery semantic expiry must be in the future");
	}
	const availableAt = input.availableAt ?? now;
	if (!Number.isFinite(availableAt.getTime())) {
		throw new DeliveryError("DELIVERY_AVAILABLE_AT_INVALID", "Delivery availability time is invalid");
	}
	const maxAttempts = input.maxAttempts ?? 8;
	if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 100) {
		throw new DeliveryError("DELIVERY_MAX_ATTEMPTS_INVALID", "maxAttempts must be between 1 and 100");
	}
	const eventId = input.eventId ?? randomUUID();
	const jobId = input.jobId ?? randomUUID();
	const kind = required(input.kind, "kind");
	const projectId = required(input.projectId, "projectId");
	const environmentId = required(input.environmentId, "environmentId");
	const webhookEndpointId = input.webhookEndpointId === undefined
		? null
		: required(input.webhookEndpointId, "webhookEndpointId");
	if (webhookEndpointId !== null &&
		(webhookEndpointId.length > 4_096 || /[\u0000-\u001f]/.test(webhookEndpointId))) {
		throw new DeliveryError("DELIVERY_WEBHOOK_ENDPOINT_INVALID", "Webhook endpoint provenance is invalid");
	}
	if (webhookEndpointId !== null && input.channel !== "webhook") {
		throw new DeliveryError(
			"DELIVERY_WEBHOOK_ENDPOINT_INVALID",
			"Webhook endpoint provenance is valid only for webhook delivery",
		);
	}
	if (input.channel === "webhook") {
		const payload = parseWebhookDeliveryPayload(input.payload);
		if (payload.event.id !== eventId || payload.event.type !== kind ||
			payload.endpoint.url !== input.destination.trim() ||
			(webhookEndpointId !== null && payload.endpoint.id !== webhookEndpointId)) {
			throw new DeliveryError("WEBHOOK_PAYLOAD_INVALID", "Webhook payload authority is invalid");
		}
	}
	const fingerprintKeyId = ring.currentFingerprintKeyId;
	const destinationFingerprint = fingerprintDestination(input.destination, ring, fingerprintKeyId);
	const sourceFingerprint = fingerprintSource(
		projectId,
		environmentId,
		kind,
		input.sourceKey,
		ring,
		fingerprintKeyId,
	);
	const sourceDedupeFingerprint = fingerprintSourceDedupe(
		projectId,
		environmentId,
		kind,
		input.sourceKey,
		ring,
	);
	const legacySourceAliases = [...ring.fingerprintKeys.keys()].map((keyId) => ({
		keyId,
		fingerprint: fingerprintSource(
			projectId,
			environmentId,
			kind,
			input.sourceKey,
			ring,
			keyId,
		),
	}));
	const createdAt = now.toISOString();
	const semanticExpiresAt = expiresAt.toISOString();
	const aad: DeliveryPayloadAad = {
		version: 1,
		eventId,
		kind,
		channel: input.channel,
		projectId,
		environmentId,
		destinationFingerprint,
		expiresAt: semanticExpiresAt,
	};
	const encrypted = encryptDeliveryPayload(input.payload, aad, ring);
	const quotaTransaction: DeliveryRawTransaction = {
		rawTransactionQuery: async <Row extends Record<string, unknown> = Record<string, unknown>>(
			text: string,
			values: readonly unknown[] = [],
		) => {
			const result = await tx.query<Row>(text, [...values]);
			return { rows: result.rows, rowCount: result.rowCount };
		},
	};
	await lockDeliveryQuotaScopeInExistingTransaction(
		quotaTransaction,
		{ projectId, environmentId },
	);
	const legacyKeyIds = await tx.query<{ source_fingerprint_key_id: string }>(
		`SELECT DISTINCT source_fingerprint_key_id FROM ${tables.event}
		 WHERE source_dedupe_version=1`,
	);
	const unavailableLegacyKeyId = legacyKeyIds.rows.find(
		(row) => !ring.fingerprintKeys.has(row.source_fingerprint_key_id),
	)?.source_fingerprint_key_id;
	if (unavailableLegacyKeyId) {
		throw new DeliveryError(
			"DELIVERY_FINGERPRINT_KEY_UNAVAILABLE",
			`Delivery fingerprint key ${unavailableLegacyKeyId} is unavailable`,
		);
	}
	const duplicate = await tx.query(
		`SELECT 1 FROM ${tables.event}
		 WHERE source_dedupe_fingerprint=$1
		    OR (source_fingerprint_key_id, source_fingerprint) IN (
			SELECT * FROM unnest($2::text[], $3::text[])
		 ) LIMIT 1`,
		[
			sourceDedupeFingerprint,
			legacySourceAliases.map((alias) => alias.keyId),
			legacySourceAliases.map((alias) => alias.fingerprint),
		],
	);
	if (duplicate.rowCount) {
		throw new DeliveryError("DELIVERY_DUPLICATE", "A delivery for this source generation already exists");
	}
	await enforceDeliveryQuotaInExistingTransaction(
		quotaTransaction,
		{
			projectId,
			environmentId,
			...(input.quota ? { policy: input.quota } : {}),
			now,
		},
		options,
	);
	const savepoint = `clearance_delivery_${randomUUID().replace(/-/g, "")}`;
	let savepointCreated = false;
	try {
		await tx.query(`SAVEPOINT ${savepoint}`);
		savepointCreated = true;
		await tx.query(
			`INSERT INTO ${tables.event}
			 (id, kind, source_fingerprint, source_fingerprint_key_id, source_dedupe_fingerprint,
			  source_dedupe_version,
				  project_id, environment_id, organization_id, actor_id, correlation_id, webhook_endpoint_id,
				  destination_fingerprint, destination_fingerprint_key_id, replay_of, created_at,
				  semantic_expires_at)
				 VALUES ($1,$2,$3,$4,$5,2,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			[
				eventId,
				kind,
				sourceFingerprint,
				fingerprintKeyId,
				sourceDedupeFingerprint,
				projectId,
				environmentId,
				input.organizationId ?? null,
				input.actorId ?? null,
				input.correlationId ?? null,
				webhookEndpointId,
				destinationFingerprint,
				fingerprintKeyId,
				input.replayOf ?? null,
				now,
				expiresAt,
			],
		);
		await tx.query(
			`INSERT INTO ${tables.payload}
			 (event_id, envelope_version, key_id, envelope, created_at, expires_at)
			 VALUES ($1,1,$2,$3,$4,$5)`,
			[eventId, encrypted.keyId, encrypted.envelope, now, expiresAt],
		);
		await tx.query(
			`INSERT INTO ${tables.job}
			 (id, event_id, channel, destination_fingerprint, destination_fingerprint_key_id,
			  state, available_at, semantic_expires_at, max_attempts, created_at, updated_at)
			 VALUES ($1,$2,$3,$4,$5,'queued',$6,$7,$8,$9,$9)`,
			[
				jobId,
				eventId,
				input.channel,
				destinationFingerprint,
				fingerprintKeyId,
				availableAt,
				expiresAt,
				maxAttempts,
				now,
			],
		);
		await tx.query(`RELEASE SAVEPOINT ${savepoint}`);
	} catch (error) {
		if (!savepointCreated && (error as { code?: string }).code === "25P01") {
			throw new DeliveryError(
				"DELIVERY_TRANSACTION_REQUIRED",
				"enqueueDelivery requires an active caller-owned transaction",
			);
		}
		if (savepointCreated) {
			try {
				await tx.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
				await tx.query(`RELEASE SAVEPOINT ${savepoint}`);
			} catch {
				throw new DeliveryError(
					"DELIVERY_TRANSACTION_RECOVERY_FAILED",
					"Delivery enqueue failed and its savepoint could not be recovered",
				);
			}
		}
		if ((error as { code?: string }).code === "23505") {
			throw new DeliveryError("DELIVERY_DUPLICATE", "A delivery for this source generation already exists");
		}
		throw error;
	}
	return {
		eventId,
		jobId,
		kind,
		channel: input.channel,
		state: "queued",
		createdAt,
		semanticExpiresAt,
	};
}

export async function enqueueDelivery(
	tx: DeliveryTransactionAdapter,
	input: EnqueueDeliveryInput,
	ring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<EnqueuedDelivery> {
	if (Object.prototype.hasOwnProperty.call(input, "webhookEndpointId")) {
		throw new DeliveryError(
			"DELIVERY_WEBHOOK_ENDPOINT_AUTHORITY_REQUIRED",
			"Managed webhook delivery requires endpoint authority",
		);
	}
	return enqueueDeliveryInternal(tx, input, ring, options);
}

/** Package-internal authority used only after endpoint locking and config derivation. */
export async function enqueueManagedDeliveryInExistingTransactionInternal(
	transaction: DeliveryRawTransaction,
	input: EnqueueDeliveryInput & { webhookEndpointId: string },
	ring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<EnqueuedDelivery> {
	if (!transaction.rawTransactionQuery) {
		throw new DeliveryError(
			"DELIVERY_TRANSACTION_REQUIRED",
			"Durable delivery requires an active PostgreSQL transaction adapter",
		);
	}
	return enqueueDeliveryInternal(
		createDeliveryRawTransactionAdapter(transaction.rawTransactionQuery),
		input,
		ring,
		options,
	);
}
