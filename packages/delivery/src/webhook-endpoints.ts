import { createHash, randomBytes, randomUUID } from "node:crypto";
import type pg from "pg";
import { DeliveryError } from "./errors.js";
import {
	enqueueManagedDeliveryInExistingTransactionInternal,
	type DeliveryRawTransaction,
	type EnqueuedDelivery,
} from "./enqueue.js";
import {
	decryptWebhookEndpointConfig,
	encryptWebhookEndpointConfig,
	fingerprintDestination,
	webhookEndpointSecretFingerprint,
	type DeliveryKeyring,
	type WebhookEndpointConfig,
} from "./keyring.js";
import type { DeliveryQuotaPolicy, DeliveryScope } from "./quota.js";
import { qualifiedDeliveryTables, type DeliverySchemaOptions } from "./schema.js";
import {
	parseWebhookDeliveryPayload,
	type OrganizationUpdatedWebhookPayload,
	type WebhookDeliveryPayload,
} from "./webhook-payload.js";

export const WEBHOOK_EVENT_KINDS = ["organization.updated"] as const;
export type WebhookEventKind = typeof WEBHOOK_EVENT_KINDS[number];
export type WebhookEndpointStatus = "active" | "disabled" | "deleted";

export type PublicWebhookEndpoint = {
	id: string;
	projectId: string;
	environmentId: string;
	name: string;
	url: string | null;
	status: WebhookEndpointStatus;
	eventKinds: WebhookEventKind[];
	urlFingerprint: string | null;
	secretFingerprint: string | null;
	secretVersion: number;
	resourceVersion: number;
	lastTestJobId: string | null;
	lastTestRequestedAt: string | null;
	createdAt: string;
	updatedAt: string;
	deletedAt: string | null;
};

export type WebhookEndpointPage = {
	items: PublicWebhookEndpoint[];
	nextCursor: string | null;
};

type EndpointRow = {
	id: string;
	project_id: string;
	environment_id: string;
	name: string;
	status: WebhookEndpointStatus;
	event_kinds: string[];
	config_envelope_version: number | null;
	config_key_id: string | null;
	config_envelope: string | null;
	url_fingerprint_key_id: string | null;
	url_fingerprint: string | null;
	secret_fingerprint: string | null;
	secret_version: number;
	resource_version: string | number;
	last_test_job_id: string | null;
	last_test_requested_at: Date | string | null;
	created_at: Date | string;
	updated_at: Date | string;
	deleted_at: Date | string | null;
};

function iso(value: Date | string | null): string | null {
	return value === null ? null : new Date(value).toISOString();
}

function publicEndpoint(row: EndpointRow, keyring?: DeliveryKeyring): PublicWebhookEndpoint {
	let url: string | null = null;
	if (row.status !== "deleted") {
		if (!keyring) {
			throw new DeliveryError("WEBHOOK_ENDPOINT_KEYRING_REQUIRED", "Webhook endpoint keyring is required");
		}
		url = decryptRowConfig(row, keyring).url;
	}
	return {
		id: row.id,
		projectId: row.project_id,
		environmentId: row.environment_id,
		name: row.name,
		url,
		status: row.status,
		eventKinds: parseStoredEventKinds(row.event_kinds),
		urlFingerprint: row.url_fingerprint,
		secretFingerprint: row.secret_fingerprint,
		secretVersion: Number(row.secret_version),
		resourceVersion: Number(row.resource_version),
		lastTestJobId: row.last_test_job_id,
		lastTestRequestedAt: iso(row.last_test_requested_at),
		createdAt: iso(row.created_at)!,
		updatedAt: iso(row.updated_at)!,
		deletedAt: iso(row.deleted_at),
	};
}

function boundedText(value: string, label: string, maximum: number): string {
	const normalized = value.trim();
	if (!normalized || normalized.length > maximum || /[\u0000-\u001f]/.test(normalized)) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_INPUT_INVALID", `${label} is invalid`);
	}
	return normalized;
}

function endpointScope(input: DeliveryScope): DeliveryScope {
	return {
		projectId: boundedText(input.projectId, "projectId", 512),
		environmentId: boundedText(input.environmentId, "environmentId", 512),
	};
}

function endpointId(value: string): string {
	return boundedText(value, "endpointId", 4_096);
}

function expectedVersion(value: number): number {
	if (!Number.isSafeInteger(value) || value < 1) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_VERSION_INVALID", "Expected resource version is invalid");
	}
	return value;
}

function validDate(value: Date | undefined, label: string): Date {
	const result = value ?? new Date();
	if (!(result instanceof Date) || !Number.isFinite(result.getTime())) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_DATE_INVALID", `${label} is invalid`);
	}
	return result;
}

function eventKinds(input: readonly string[] | undefined): WebhookEventKind[] {
	const values = input ?? WEBHOOK_EVENT_KINDS;
	if (values.length !== WEBHOOK_EVENT_KINDS.length ||
		values.some((value, index) => value !== WEBHOOK_EVENT_KINDS[index])) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_EVENT_KINDS_INVALID", "Webhook endpoint event kinds are invalid");
	}
	return [...WEBHOOK_EVENT_KINDS];
}

function eventKind(input: string): WebhookEventKind {
	if (!WEBHOOK_EVENT_KINDS.includes(input as WebhookEventKind)) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_EVENT_KIND_INVALID", "Webhook event kind is invalid");
	}
	return input as WebhookEventKind;
}

function parseStoredEventKinds(values: string[]): WebhookEventKind[] {
	return eventKinds(values);
}

function loopback(hostname: string): boolean {
	return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export function webhookEndpointUsesSupportedPort(url: URL): boolean {
	return url.protocol !== "https:" || url.port === "";
}

export function normalizeWebhookEndpointUrl(
	input: string,
	options: { allowInsecureLoopback?: boolean } = {},
): string {
	if (typeof input !== "string" || input.length < 1 || input.length > 8_192 ||
		/[\u0000-\u001f\u007f]/.test(input)) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_URL_INVALID", "Webhook endpoint URL is invalid");
	}
	let url: URL;
	try {
		url = new URL(input);
	} catch {
		throw new DeliveryError("WEBHOOK_ENDPOINT_URL_INVALID", "Webhook endpoint URL is invalid");
	}
	if (url.username || url.password || url.hash || !url.hostname ||
		!webhookEndpointUsesSupportedPort(url) ||
		(url.protocol !== "https:" &&
			!(options.allowInsecureLoopback === true && url.protocol === "http:" && loopback(url.hostname)))) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_URL_INVALID", "Webhook endpoint URL is invalid");
	}
	return url.toString();
}

function secret(): string {
	return `whsec_${randomBytes(32).toString("base64url")}`;
}

function scopeDigest(target: DeliveryScope): string {
	return createHash("sha256")
		.update(target.projectId, "utf8").update("\0", "utf8")
		.update(target.environmentId, "utf8").digest("hex");
}

function encodeCursor(row: PublicWebhookEndpoint, target: DeliveryScope): string {
	return Buffer.from(JSON.stringify({
		v: 1,
		s: "webhook_endpoints",
		scope: scopeDigest(target),
		k: [row.createdAt, row.id],
	}), "utf8").toString("base64url");
}

function decodeCursor(value: string | undefined, target: DeliveryScope): [Date, string] | null {
	if (value === undefined) return null;
	if (!/^[A-Za-z0-9_-]{1,8192}$/.test(value)) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_CURSOR_INVALID", "Webhook endpoint cursor is invalid");
	}
	try {
		const bytes = Buffer.from(value, "base64url");
		if (bytes.toString("base64url") !== value) throw new Error("invalid");
		const raw = bytes.toString("utf8");
		const parsed: unknown = JSON.parse(raw);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid");
		const cursor = parsed as Record<string, unknown>;
		if (cursor.v !== 1 || cursor.s !== "webhook_endpoints" || cursor.scope !== scopeDigest(target) ||
			!Array.isArray(cursor.k) || cursor.k.length !== 2 ||
			typeof cursor.k[0] !== "string" || typeof cursor.k[1] !== "string" ||
			JSON.stringify({ v: 1, s: "webhook_endpoints", scope: cursor.scope, k: cursor.k }) !== raw) {
			throw new Error("invalid");
		}
		const createdAt = new Date(cursor.k[0]);
		if (!Number.isFinite(createdAt.getTime()) || createdAt.toISOString() !== cursor.k[0]) {
			throw new Error("invalid");
		}
		return [createdAt, endpointId(cursor.k[1])];
	} catch {
		throw new DeliveryError("WEBHOOK_ENDPOINT_CURSOR_INVALID", "Webhook endpoint cursor is invalid");
	}
}

async function transaction<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		const result = await fn(client);
		await client.query("COMMIT");
		return result;
	} catch (error) {
		await client.query("ROLLBACK").catch(() => undefined);
		throw error;
	} finally {
		client.release();
	}
}

type EndpointQuery = NonNullable<DeliveryRawTransaction["rawTransactionQuery"]>;

function requireEndpointTransaction(transaction: DeliveryRawTransaction): EndpointQuery {
	if (!transaction.rawTransactionQuery) {
		throw new DeliveryError(
			"DELIVERY_TRANSACTION_REQUIRED",
			"Webhook endpoint mutation requires an active PostgreSQL transaction adapter",
		);
	}
	return transaction.rawTransactionQuery;
}

function clientTransaction(client: pg.PoolClient): DeliveryRawTransaction {
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

async function lockScope(query: EndpointQuery, target: DeliveryScope): Promise<void> {
	await query(
		"SELECT pg_advisory_xact_lock(hashtext('clearance.webhook-endpoint'), hashtext($1))",
		[JSON.stringify([target.projectId, target.environmentId])],
	);
}

function urlAliases(url: string, keyring: DeliveryKeyring): Array<{ keyId: string; fingerprint: string }> {
	return [...keyring.fingerprintKeys.keys()].map((keyId) => ({
		keyId,
		fingerprint: fingerprintDestination(url, keyring, keyId),
	}));
}

async function assertUrlAvailable(
	query: EndpointQuery,
	table: string,
	target: DeliveryScope,
	url: string,
	keyring: DeliveryKeyring,
	excludeId?: string,
): Promise<void> {
	const aliases = urlAliases(url, keyring);
	const duplicate = await query(
		`SELECT 1 FROM ${table}
		 WHERE project_id=$1 AND environment_id=$2 AND status <> 'deleted'
		   AND ($3::text IS NULL OR id <> $3)
		   AND (url_fingerprint_key_id, url_fingerprint) IN (
			SELECT * FROM unnest($4::text[], $5::text[])
		   ) LIMIT 1`,
		[
			target.projectId, target.environmentId, excludeId ?? null,
			aliases.map((alias) => alias.keyId), aliases.map((alias) => alias.fingerprint),
		],
	);
	if (duplicate.rowCount) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_DUPLICATE", "A webhook endpoint already uses this destination", 409);
	}
}

function configAad(row: Pick<EndpointRow, "id" | "project_id" | "environment_id" | "secret_version">) {
	return {
		version: 1 as const,
		endpointId: row.id,
		projectId: row.project_id,
		environmentId: row.environment_id,
		secretVersion: Number(row.secret_version),
	};
}

function decryptRowConfig(row: EndpointRow, keyring: DeliveryKeyring): WebhookEndpointConfig {
	if (row.status === "deleted" || row.config_envelope_version !== 1 ||
		!row.config_key_id || !row.config_envelope) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_CONFIG_UNAVAILABLE", "Webhook endpoint configuration is unavailable");
	}
	return decryptWebhookEndpointConfig(row.config_envelope, configAad(row), keyring, row.config_key_id);
}

function conflict(): never {
	throw new DeliveryError("WEBHOOK_ENDPOINT_VERSION_CONFLICT", "Webhook endpoint resource version changed", 409);
}

export async function createWebhookEndpointInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & {
		id?: string;
		name: string;
		url: string;
		eventKinds?: readonly WebhookEventKind[];
		now?: Date;
		allowInsecureLoopback?: boolean;
	},
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<{ endpoint: PublicWebhookEndpoint; signingSecret: string }> {
	const target = endpointScope(input);
	const id = endpointId(input.id ?? randomUUID());
	const name = boundedText(input.name, "name", 128);
	const kinds = eventKinds(input.eventKinds);
	const url = normalizeWebhookEndpointUrl(input.url, {
		allowInsecureLoopback: input.allowInsecureLoopback,
	});
	const signingSecret = secret();
	const now = validDate(input.now, "now");
	const encrypted = encryptWebhookEndpointConfig(
		{ url, signingSecret },
		{ version: 1, endpointId: id, projectId: target.projectId, environmentId: target.environmentId, secretVersion: 1 },
		keyring,
	);
	const fingerprintKeyId = keyring.currentFingerprintKeyId;
	const urlFingerprint = fingerprintDestination(url, keyring, fingerprintKeyId);
	const tables = qualifiedDeliveryTables(options);
	const query = requireEndpointTransaction(transaction);
	await lockScope(query, target);
	await assertUrlAvailable(query, tables.webhookEndpoint, target, url, keyring);
	try {
		const result = await query<EndpointRow>(
				`INSERT INTO ${tables.webhookEndpoint}
				 (id,project_id,environment_id,name,status,event_kinds,
				  config_envelope_version,config_key_id,config_envelope,
				  url_fingerprint_key_id,url_fingerprint,secret_fingerprint,
				  secret_version,resource_version,created_at,updated_at)
				 VALUES ($1,$2,$3,$4,'disabled',$5,1,$6,$7,$8,$9,$10,1,1,$11,$11)
				 RETURNING *`,
				[
					id, target.projectId, target.environmentId, name, kinds,
					encrypted.keyId, encrypted.envelope, fingerprintKeyId, urlFingerprint,
					webhookEndpointSecretFingerprint(signingSecret), now,
				],
			);
		const endpoint = publicEndpoint(result.rows[0]!, keyring);
		return { endpoint, signingSecret };
	} catch (error) {
		if ((error as { code?: unknown }).code === "23505") {
			throw new DeliveryError("WEBHOOK_ENDPOINT_DUPLICATE", "A webhook endpoint already exists", 409);
		}
		throw error;
	}
}

export async function createWebhookEndpoint(
	pool: pg.Pool,
	input: DeliveryScope & {
		id?: string;
		name: string;
		url: string;
		eventKinds?: readonly WebhookEventKind[];
		now?: Date;
		allowInsecureLoopback?: boolean;
	},
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<{ endpoint: PublicWebhookEndpoint; signingSecret: string }> {
	return transaction(pool, (client) => createWebhookEndpointInExistingTransaction(
		clientTransaction(client), input, keyring, options,
	));
}

export async function listWebhookEndpoints(
	pool: pg.Pool,
	input: DeliveryScope & {
		limit?: number;
		cursor?: string;
		statuses?: readonly WebhookEndpointStatus[];
		eventKind?: WebhookEventKind;
	},
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<WebhookEndpointPage> {
	const target = endpointScope(input);
	const limit = input.limit ?? 50;
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_LIMIT_INVALID", "Webhook endpoint limit is invalid");
	}
	const allowed: readonly WebhookEndpointStatus[] = ["active", "disabled", "deleted"];
	const statuses: WebhookEndpointStatus[] = input.statuses
		? [...new Set(input.statuses)]
		: ["active", "disabled"];
	if (statuses.length < 1 || statuses.some((status) => !allowed.includes(status))) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_STATUS_INVALID", "Webhook endpoint status filter is invalid");
	}
	const kind = input.eventKind === undefined ? null : eventKind(input.eventKind);
	const cursor = decodeCursor(input.cursor, target);
	const table = qualifiedDeliveryTables(options).webhookEndpoint;
	const result = await pool.query<EndpointRow>(
		`SELECT * FROM ${table}
		 WHERE project_id=$1 AND environment_id=$2 AND status=ANY($3::text[])
		   AND ($4::text IS NULL OR event_kinds @> ARRAY[$4]::text[])
		   AND ($5::timestamptz IS NULL OR (created_at,id) < ($5,$6))
		 ORDER BY created_at DESC,id DESC LIMIT $7`,
		[target.projectId, target.environmentId, statuses, kind, cursor?.[0] ?? null, cursor?.[1] ?? null, limit + 1],
	);
	const hasMore = result.rows.length > limit;
	const items = result.rows.slice(0, limit).map((row) => publicEndpoint(row, keyring));
	return { items, nextCursor: hasMore ? encodeCursor(items.at(-1)!, target) : null };
}

export async function inspectWebhookEndpointScoped(
	pool: pg.Pool,
	input: DeliveryScope & { endpointId: string; includeDeleted?: boolean },
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<PublicWebhookEndpoint | null> {
	const target = endpointScope(input);
	const table = qualifiedDeliveryTables(options).webhookEndpoint;
	const result = await pool.query<EndpointRow>(
		`SELECT * FROM ${table} WHERE id=$1 AND project_id=$2 AND environment_id=$3
		   AND ($4::boolean OR status <> 'deleted')`,
		[endpointId(input.endpointId), target.projectId, target.environmentId, input.includeDeleted === true],
	);
	return result.rows[0] ? publicEndpoint(result.rows[0], keyring) : null;
}

export type EnqueueWebhookEndpointDeliveryInput = DeliveryScope & {
	endpointId: string;
	expectedVersion?: number;
	eventKind: WebhookEventKind;
	sourceKey: string;
	event: Pick<OrganizationUpdatedWebhookPayload["event"], "occurredAt" | "data">;
	eventId?: string;
	jobId?: string;
	replayOf?: string;
	organizationId?: string;
	actorId?: string;
	correlationId?: string;
	semanticExpiresAt: Date;
	availableAt?: Date;
	maxAttempts?: number;
	quota?: DeliveryQuotaPolicy;
	now?: Date;
};

/**
 * Lock, decrypt, and enqueue a managed endpoint delivery in the caller's
 * product transaction. The endpoint signing secret never escapes this helper.
 */
export async function enqueueWebhookEndpointDeliveryInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: EnqueueWebhookEndpointDeliveryInput,
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<{ endpoint: PublicWebhookEndpoint; delivery: EnqueuedDelivery } | null> {
	const target = endpointScope(input);
	const id = endpointId(input.endpointId);
	const version = input.expectedVersion === undefined ? null : expectedVersion(input.expectedVersion);
	const kind = eventKind(input.eventKind);
	const table = qualifiedDeliveryTables(options).webhookEndpoint;
	const query = requireEndpointTransaction(transaction);
	const result = await query<EndpointRow>(
		`SELECT * FROM ${table} WHERE id=$1 AND project_id=$2 AND environment_id=$3
		   AND status <> 'deleted' FOR SHARE`,
		[id, target.projectId, target.environmentId],
	);
	const row = result.rows[0];
	if (!row) return null;
	if (version !== null && Number(row.resource_version) !== version) conflict();
	if (row.status !== "active" || !parseStoredEventKinds(row.event_kinds).includes(kind)) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_NOT_ACTIVE", "Webhook endpoint is not active for this event", 409);
	}
	const config = decryptRowConfig(row, keyring);
	const eventId = input.eventId ?? randomUUID();
	if (!input.organizationId) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_EVENT_INVALID", "Organization webhook context is invalid");
	}
	const payload = parseWebhookDeliveryPayload({
		version: 1,
		endpoint: { id: row.id, url: config.url, signingSecret: config.signingSecret },
		event: {
			id: eventId,
			type: kind,
			occurredAt: input.event.occurredAt,
			context: {
				projectId: target.projectId,
				environmentId: target.environmentId,
				organizationId: input.organizationId,
				actor: input.actorId ?? null,
				correlationId: input.correlationId ?? null,
			},
			data: input.event.data,
		},
	});
	const delivery = await enqueueManagedDeliveryInExistingTransactionInternal(transaction, {
		eventId,
		...(input.jobId === undefined ? {} : { jobId: input.jobId }),
		kind,
		sourceKey: input.sourceKey,
		projectId: target.projectId,
		environmentId: target.environmentId,
		...(input.organizationId === undefined ? {} : { organizationId: input.organizationId }),
		...(input.actorId === undefined ? {} : { actorId: input.actorId }),
		...(input.correlationId === undefined ? {} : { correlationId: input.correlationId }),
		...(input.replayOf === undefined ? {} : { replayOf: input.replayOf }),
		webhookEndpointId: row.id,
		channel: "webhook",
		destination: config.url,
		payload,
		semanticExpiresAt: input.semanticExpiresAt,
		...(input.availableAt === undefined ? {} : { availableAt: input.availableAt }),
		...(input.maxAttempts === undefined ? {} : { maxAttempts: input.maxAttempts }),
		...(input.quota === undefined ? {} : { quota: input.quota }),
		...(input.now === undefined ? {} : { now: input.now }),
	}, keyring, options);
	return { endpoint: publicEndpoint(row, keyring), delivery };
}

export type FanoutOrganizationUpdatedWebhookInput = DeliveryScope & {
	sourceKey: string;
	event: Pick<OrganizationUpdatedWebhookPayload["event"], "occurredAt" | "data">;
	organizationId: string;
	actorId?: string;
	correlationId?: string;
	semanticExpiresAt: Date;
	availableAt?: Date;
	maxAttempts?: number;
	quota?: DeliveryQuotaPolicy;
	now?: Date;
};

/** Select and enqueue the complete active subscription set under one transaction lock snapshot. */
export async function fanoutOrganizationUpdatedWebhookInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: FanoutOrganizationUpdatedWebhookInput,
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<Array<{ endpoint: PublicWebhookEndpoint; delivery: EnqueuedDelivery }>> {
	const target = endpointScope(input);
	const tables = qualifiedDeliveryTables(options);
	const query = requireEndpointTransaction(transaction);
	await lockScope(query, target);
	const selected = await query<EndpointRow>(
		`SELECT * FROM ${tables.webhookEndpoint}
		 WHERE project_id=$1 AND environment_id=$2 AND status='active'
		   AND event_kinds @> ARRAY['organization.updated']::text[]
		 ORDER BY id FOR SHARE`,
		[target.projectId, target.environmentId],
	);
	const results: Array<{ endpoint: PublicWebhookEndpoint; delivery: EnqueuedDelivery }> = [];
	for (const row of selected.rows) {
		const config = decryptRowConfig(row, keyring);
		const eventId = randomUUID();
		const payload: WebhookDeliveryPayload = parseWebhookDeliveryPayload({
			version: 1,
			endpoint: { id: row.id, url: config.url, signingSecret: config.signingSecret },
			event: {
				id: eventId,
				type: "organization.updated",
				occurredAt: input.event.occurredAt,
				context: {
					projectId: target.projectId,
					environmentId: target.environmentId,
					organizationId: input.organizationId,
					actor: input.actorId ?? null,
					correlationId: input.correlationId ?? null,
				},
				data: input.event.data,
			},
		});
		const delivery = await enqueueManagedDeliveryInExistingTransactionInternal(transaction, {
			eventId,
			kind: "organization.updated",
			sourceKey: `managed-webhook:${JSON.stringify([row.id, input.sourceKey])}`,
			projectId: target.projectId,
			environmentId: target.environmentId,
			organizationId: input.organizationId,
			...(input.actorId === undefined ? {} : { actorId: input.actorId }),
			...(input.correlationId === undefined ? {} : { correlationId: input.correlationId }),
			webhookEndpointId: row.id,
			channel: "webhook",
			destination: config.url,
			payload,
			semanticExpiresAt: input.semanticExpiresAt,
			...(input.availableAt === undefined ? {} : { availableAt: input.availableAt }),
			...(input.maxAttempts === undefined ? {} : { maxAttempts: input.maxAttempts }),
			...(input.quota === undefined ? {} : { quota: input.quota }),
			...(input.now === undefined ? {} : { now: input.now }),
		}, keyring, options);
		results.push({ endpoint: publicEndpoint(row, keyring), delivery });
	}
	return results;
}

export async function updateWebhookEndpointInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & {
		endpointId: string;
		expectedVersion: number;
		name?: string;
		url?: string;
		eventKinds?: readonly WebhookEventKind[];
		status?: "active" | "disabled";
		now?: Date;
		allowInsecureLoopback?: boolean;
	},
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<PublicWebhookEndpoint | null> {
	const target = endpointScope(input);
	const id = endpointId(input.endpointId);
	const version = expectedVersion(input.expectedVersion);
	if (input.name === undefined && input.url === undefined && input.eventKinds === undefined && input.status === undefined) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_UPDATE_EMPTY", "Webhook endpoint update is empty");
	}
	const now = validDate(input.now, "now");
	const table = qualifiedDeliveryTables(options).webhookEndpoint;
	const query = requireEndpointTransaction(transaction);
	await lockScope(query, target);
	const found = await query<EndpointRow>(
			`SELECT * FROM ${table} WHERE id=$1 AND project_id=$2 AND environment_id=$3
			 AND status <> 'deleted' FOR UPDATE`,
			[id, target.projectId, target.environmentId],
		);
	const row = found.rows[0];
	if (!row) return null;
	if (Number(row.resource_version) !== version) conflict();
	const previous = decryptRowConfig(row, keyring);
	const nextUrl = input.url === undefined ? previous.url : normalizeWebhookEndpointUrl(input.url, {
		allowInsecureLoopback: input.allowInsecureLoopback,
	});
	const urlChanged = nextUrl !== previous.url;
	if (urlChanged) await assertUrlAvailable(query, table, target, nextUrl, keyring, id);
	const encrypted = encryptWebhookEndpointConfig(
		{ url: nextUrl, signingSecret: previous.signingSecret }, configAad(row), keyring,
	);
	const fingerprintKeyId = keyring.currentFingerprintKeyId;
	const result = await query<EndpointRow>(
			`UPDATE ${table} SET name=$5,event_kinds=$6,status=$7,
			 config_envelope_version=1,config_key_id=$8,config_envelope=$9,
			 url_fingerprint_key_id=$10,url_fingerprint=$11,
			 last_test_job_id=CASE WHEN $12 THEN NULL ELSE last_test_job_id END,
			 last_test_requested_at=CASE WHEN $12 THEN NULL ELSE last_test_requested_at END,
			 resource_version=resource_version+1,updated_at=$13
			 WHERE id=$1 AND project_id=$2 AND environment_id=$3 AND resource_version=$4
			   AND status <> 'deleted' RETURNING *`,
			[
				id, target.projectId, target.environmentId, version,
				input.name === undefined ? row.name : boundedText(input.name, "name", 128),
				input.eventKinds === undefined ? row.event_kinds : eventKinds(input.eventKinds),
				urlChanged ? "disabled" : (input.status ?? row.status),
				encrypted.keyId, encrypted.envelope, fingerprintKeyId,
				fingerprintDestination(nextUrl, keyring, fingerprintKeyId), urlChanged, now,
			],
		);
	if (!result.rows[0]) conflict();
	return publicEndpoint(result.rows[0], keyring);
}

export async function updateWebhookEndpoint(
	pool: pg.Pool,
	input: DeliveryScope & {
		endpointId: string;
		expectedVersion: number;
		name?: string;
		url?: string;
		eventKinds?: readonly WebhookEventKind[];
		status?: "active" | "disabled";
		now?: Date;
		allowInsecureLoopback?: boolean;
	},
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<PublicWebhookEndpoint | null> {
	return transaction(pool, (client) => updateWebhookEndpointInExistingTransaction(
		clientTransaction(client), input, keyring, options,
	));
}

export async function rotateWebhookEndpointSecretInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & { endpointId: string; expectedVersion: number; now?: Date },
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<{ endpoint: PublicWebhookEndpoint; signingSecret: string } | null> {
	const target = endpointScope(input);
	const id = endpointId(input.endpointId);
	const version = expectedVersion(input.expectedVersion);
	const now = validDate(input.now, "now");
	const table = qualifiedDeliveryTables(options).webhookEndpoint;
	const query = requireEndpointTransaction(transaction);
	const found = await query<EndpointRow>(
			`SELECT * FROM ${table} WHERE id=$1 AND project_id=$2 AND environment_id=$3
			 AND status <> 'deleted' FOR UPDATE`,
			[id, target.projectId, target.environmentId],
		);
	const row = found.rows[0];
	if (!row) return null;
	if (Number(row.resource_version) !== version) conflict();
	const previous = decryptRowConfig(row, keyring);
	const signingSecret = secret();
	const secretVersion = Number(row.secret_version) + 1;
	const encrypted = encryptWebhookEndpointConfig(
		{ url: previous.url, signingSecret },
		{ ...configAad(row), secretVersion },
		keyring,
	);
	const result = await query<EndpointRow>(
			`UPDATE ${table} SET config_envelope_version=1,config_key_id=$5,config_envelope=$6,
			 secret_fingerprint=$7,secret_version=$8,resource_version=resource_version+1,updated_at=$9
			 WHERE id=$1 AND project_id=$2 AND environment_id=$3 AND resource_version=$4
			   AND status <> 'deleted' RETURNING *`,
			[
				id, target.projectId, target.environmentId, version, encrypted.keyId, encrypted.envelope,
				webhookEndpointSecretFingerprint(signingSecret), secretVersion, now,
			],
		);
	if (!result.rows[0]) conflict();
	return { endpoint: publicEndpoint(result.rows[0], keyring), signingSecret };
}

export async function rotateWebhookEndpointSecret(
	pool: pg.Pool,
	input: DeliveryScope & { endpointId: string; expectedVersion: number; now?: Date },
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<{ endpoint: PublicWebhookEndpoint; signingSecret: string } | null> {
	return transaction(pool, (client) => rotateWebhookEndpointSecretInExistingTransaction(
		clientTransaction(client), input, keyring, options,
	));
}

export type WebhookEndpointDeletionResult = {
	endpoint: PublicWebhookEndpoint;
	erasedPayloads: number;
	jobs: {
		queuedOrRetryCancelled: number;
		leasedCancellationRequested: number;
		leasedDeliveryOutcomeAmbiguous: boolean;
	};
};

export async function softDeleteWebhookEndpointInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & { endpointId: string; expectedVersion: number; now?: Date },
	options: DeliverySchemaOptions = {},
): Promise<WebhookEndpointDeletionResult | null> {
	const target = endpointScope(input);
	const id = endpointId(input.endpointId);
	const version = expectedVersion(input.expectedVersion);
	const now = validDate(input.now, "now");
	const tables = qualifiedDeliveryTables(options);
	const query = requireEndpointTransaction(transaction);
	const found = await query<EndpointRow>(
		`SELECT * FROM ${tables.webhookEndpoint}
		 WHERE id=$1 AND project_id=$2 AND environment_id=$3 AND status <> 'deleted' FOR UPDATE`,
		[id, target.projectId, target.environmentId],
	);
	const row = found.rows[0];
	if (!row) return null;
	if (Number(row.resource_version) !== version) conflict();
	const affected = await query<{
		queued_or_retry_cancelled: number | string;
		leased_cancellation_requested: number | string;
	}>(
		`WITH target_jobs AS (
			SELECT j.id,j.state FROM ${tables.job} j
			JOIN ${tables.event} e ON e.id=j.event_id
			WHERE e.webhook_endpoint_id=$1 AND e.project_id=$2 AND e.environment_id=$3
			  AND j.state IN ('queued','retry','leased')
			FOR UPDATE OF j
		), changed AS (
			UPDATE ${tables.job} j SET
			 state=CASE WHEN target_jobs.state IN ('queued','retry') THEN 'cancelled' ELSE j.state END,
			 cancel_requested=CASE WHEN target_jobs.state='leased' THEN true ELSE false END,
			 cancelled_at=CASE WHEN target_jobs.state IN ('queued','retry') THEN $4 ELSE j.cancelled_at END,
			 updated_at=$4
			FROM target_jobs WHERE j.id=target_jobs.id
			RETURNING target_jobs.state previous_state
		)
		SELECT count(*) FILTER (WHERE previous_state IN ('queued','retry'))::int queued_or_retry_cancelled,
		 count(*) FILTER (WHERE previous_state='leased')::int leased_cancellation_requested
		FROM changed`,
		[id, target.projectId, target.environmentId, now],
	);
	const erased = await query(
		`DELETE FROM ${tables.payload} p USING ${tables.event} e
		 WHERE p.event_id=e.id AND e.webhook_endpoint_id=$1
		   AND e.project_id=$2 AND e.environment_id=$3`,
		[id, target.projectId, target.environmentId],
	);
	const result = await query<EndpointRow>(
			`UPDATE ${tables.webhookEndpoint} SET status='deleted',config_envelope_version=NULL,config_key_id=NULL,
			 config_envelope=NULL,url_fingerprint_key_id=NULL,url_fingerprint=NULL,secret_fingerprint=NULL,
			 resource_version=resource_version+1,updated_at=$5,deleted_at=$5
			 WHERE id=$1 AND project_id=$2 AND environment_id=$3 AND resource_version=$4
			   AND status <> 'deleted' RETURNING *`,
			[id, target.projectId, target.environmentId, version, now],
		);
	if (!result.rows[0]) conflict();
	const cancelled = Number(affected.rows[0]?.queued_or_retry_cancelled ?? 0);
	const leased = Number(affected.rows[0]?.leased_cancellation_requested ?? 0);
	return {
		endpoint: publicEndpoint(result.rows[0]),
		erasedPayloads: erased.rowCount ?? 0,
		jobs: {
			queuedOrRetryCancelled: cancelled,
			leasedCancellationRequested: leased,
			leasedDeliveryOutcomeAmbiguous: leased > 0,
		},
	};
}

export async function softDeleteWebhookEndpoint(
	pool: pg.Pool,
	input: DeliveryScope & { endpointId: string; expectedVersion: number; now?: Date },
	options: DeliverySchemaOptions = {},
): Promise<WebhookEndpointDeletionResult | null> {
	return transaction(pool, (client) => softDeleteWebhookEndpointInExistingTransaction(
		clientTransaction(client), input, options,
	));
}

export async function enqueueWebhookEndpointTestInExistingTransaction(
	transaction: DeliveryRawTransaction,
	input: DeliveryScope & {
		endpointId: string;
		expectedVersion: number;
		actorId?: string;
		correlationId?: string;
		quota?: DeliveryQuotaPolicy;
		now?: Date;
	},
	keyring: DeliveryKeyring,
	options: DeliverySchemaOptions = {},
): Promise<{ endpoint: PublicWebhookEndpoint; delivery: EnqueuedDelivery } | null> {
	const target = endpointScope(input);
	const id = endpointId(input.endpointId);
	const version = expectedVersion(input.expectedVersion);
	const now = validDate(input.now, "now");
	const table = qualifiedDeliveryTables(options).webhookEndpoint;
	const query = requireEndpointTransaction(transaction);
	const found = await query<EndpointRow>(
		`SELECT * FROM ${table} WHERE id=$1 AND project_id=$2 AND environment_id=$3
		   AND status <> 'deleted' FOR UPDATE`,
		[id, target.projectId, target.environmentId],
	);
	const row = found.rows[0];
	if (!row) return null;
	if (Number(row.resource_version) !== version) conflict();
	const config = decryptRowConfig(row, keyring);
	const eventId = randomUUID();
	const payload = parseWebhookDeliveryPayload({
		version: 1,
		endpoint: { id: row.id, url: config.url, signingSecret: config.signingSecret },
		event: {
			id: eventId,
			type: "webhook.endpoint.test",
			occurredAt: now.toISOString(),
			context: {
				projectId: target.projectId,
				environmentId: target.environmentId,
				organizationId: null,
				actor: input.actorId ?? null,
				correlationId: input.correlationId ?? null,
			},
			data: { endpointId: row.id },
		},
	});
	const delivery = await enqueueManagedDeliveryInExistingTransactionInternal(transaction, {
		eventId,
		kind: "webhook.endpoint.test",
		sourceKey: `webhook.endpoint.test:${row.id}:${eventId}`,
		projectId: target.projectId,
		environmentId: target.environmentId,
		...(input.actorId === undefined ? {} : { actorId: input.actorId }),
		...(input.correlationId === undefined ? {} : { correlationId: input.correlationId }),
		webhookEndpointId: row.id,
		channel: "webhook",
		destination: config.url,
		payload,
		semanticExpiresAt: new Date(now.getTime() + 15 * 60_000),
		maxAttempts: 3,
		...(input.quota === undefined ? {} : { quota: input.quota }),
		now,
	}, keyring, options);
	const updated = await query<EndpointRow>(
		`UPDATE ${table} SET last_test_job_id=$5,last_test_requested_at=$6,
		 resource_version=resource_version+1,updated_at=$6
		 WHERE id=$1 AND project_id=$2 AND environment_id=$3 AND resource_version=$4
		   AND status <> 'deleted' RETURNING *`,
		[id, target.projectId, target.environmentId, version, delivery.jobId, now],
	);
	if (!updated.rows[0]) conflict();
	return { endpoint: publicEndpoint(updated.rows[0], keyring), delivery };
}
