/**
 * Postgres-backed management store.
 *
 * Single-row JSONB snapshot with revision + row-lock semantics.
 * Mutations are queued and transactionally replayed against the latest locked
 * row so concurrent CLI/API processes do not lose each other's writes.
 *
 * Database-enforced uniqueness (same transaction as snapshot + audit):
 * - principal email unique per (project_id, environment_id)
 * - organization slug unique per (project_id, environment_id)
 *
 * Call refresh() on long-lived readers before serving requests.
 */
import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import pg from "pg";
import { reconcileAuthorizationTerminalizationAtManagementStartup } from "../auth-bridge.js";
import {
	cancelDeliveryInExistingTransaction,
	createRuntimeAuditTable,
	createWebhookEndpointInExistingTransaction,
	createDeliveryKeyring,
	DEFAULT_DELIVERY_QUOTA_POLICY,
	deliveryQuotaStatus,
	deliveryReadiness,
	deliverySchemaName,
	deliveryTableNames,
	fanoutOrganizationUpdatedWebhookInExistingTransaction,
	enqueueDeliveryInExistingTransaction,
	inspectDeliveryJobScoped,
	inspectWebhookEndpointScoped,
	listDeliveryJobs,
	listWebhookEndpoints,
	migrateDeliverySchema,
	normalizeDeliveryQuotaPolicy,
	previewDeliveryControl,
	previewDeliveryControlInExistingTransaction,
	previewWebhookEndpointDeletion,
	previewWebhookEndpointDeletionInExistingTransaction,
	previewWebhookEndpointSecretRotation,
	previewWebhookEndpointSecretRotationInExistingTransaction,
	previewWebhookEndpointTest,
	previewWebhookEndpointTestInExistingTransaction,
	replayDeliveryInExistingTransaction,
	rotateWebhookEndpointSecretInExistingTransaction,
	retryDeliveryInExistingTransaction,
	softDeleteWebhookEndpointInExistingTransaction,
	updateWebhookEndpointInExistingTransaction,
	enqueueWebhookEndpointTestInExistingTransaction,
	type DeliveryKeyring,
	type DeliveryKeyringInput,
	type DeliveryQuotaPolicy,
	type DeliverySchemaOptions,
	type DeliveryRawTransaction,
	type EnqueuedDelivery,
	type EnqueueDeliveryInput,
} from "@clearance/delivery";
import type { ManagementWebhookEndpointCapability } from "../services/webhook-endpoints.js";
import {
	MANAGEMENT_WEBHOOK_TTL_MS,
	type ManagementWebhookEndpointFanout,
} from "../application/delivery.js";
import {
	CLEARANCE_RELEASE_VERSION,
	cloneSnapshot,
	emptySnapshot,
	normalizeSnapshot,
	snapshotResourceCounts,
	stableSnapshotJson,
	STORE_SCHEMA_VERSION,
} from "./snapshot.js";
import type { AuditEvent, DataStoreSnapshot } from "../types/resources.js";
import {
	PgStoreV2Shadow,
	StoreV2MigrationError,
	type StoreV2LoadResult,
	type StoreV2SyncResult,
} from "./store-v2-shadow.js";
import {
	appendStoreV2Events,
	applyStoreV2EventDelta,
} from "./store-v2-events.js";
import {
	PgRuntimeAuditEventReader,
	type RuntimeAuditStoreOptions,
} from "./runtime-audit-events.js";
import { PgStoreV2PrincipalRepository } from "./store-v2-principals.js";
import {
	PgStoreV2TopologyRepository,
	readStoreV2TopologyState,
	type StoreV2TopologyState,
} from "./store-v2-topology.js";
import { registerInternalCoordinatedExecutor } from "./coordinated-internal.js";
import {
	appendAuditEvent,
	buildAuditEvent,
	consumeDeferredAuditEvents,
	deferAuditRetentionForDraft,
	type AuditEventInput,
} from "../services/audit.js";
import type {
	DeliveryControlMutationInput,
	DeliveryControlAuditContext,
	DeliveryControlScope,
	ManagementDeliveryControlMutation,
	ManagementDeliveryControlReader,
	InternalManagementCoordinatedMutationContext,
	ManagementCoordinatedMutationContext,
	ManagementStore,
	StoreV2EventReader,
	StoreV2MigrationControl,
	StoreV2Phase,
	StoreV2PrincipalReader,
	StoreV2PrincipalRepository,
	StoreV2TopologyReader,
	StoreV2TopologyRepository,
	StoreV2Collection,
} from "./types.js";

const SNAPSHOT_TABLE = "clearance_management_snapshot";

type StoreV2SnapshotPublication = Omit<StoreV2LoadResult, "storedSnapshot">;

class TransactionCapabilityRevokedError extends Error {
	readonly code = "TRANSACTION_CAPABILITY_REVOKED";

	constructor() {
		super("The transaction query capability is no longer active.");
		this.name = "TransactionCapabilityRevokedError";
	}
}

export type PgStoreDeliveryOptions = DeliverySchemaOptions & {
	keyring: DeliveryKeyringInput | DeliveryKeyring;
	quota?: DeliveryQuotaPolicy;
};

function normalizeDeliveryKeyring(
	value: DeliveryKeyringInput | DeliveryKeyring,
): DeliveryKeyring {
	if (
		value.keys instanceof Map &&
		value.fingerprintKeys instanceof Map &&
		Buffer.isBuffer(value.sourceDedupeKey)
	) {
		return createDeliveryKeyring({
			currentKeyId: value.currentKeyId,
			keys: Object.fromEntries(
				[...value.keys].map(([keyId, key]) => [keyId, Buffer.from(key)]),
			),
			currentFingerprintKeyId: value.currentFingerprintKeyId,
			fingerprintKeys: Object.fromEntries(
				[...value.fingerprintKeys].map(([keyId, key]) => [keyId, Buffer.from(key)]),
			),
			sourceDedupeKey: Buffer.from(value.sourceDedupeKey),
		});
	}
	return createDeliveryKeyring(value as DeliveryKeyringInput);
}

function safeTableName(value: string): string {
	if (!/^[a-z_][a-z0-9_]*$/i.test(value)) {
		throw new Error(`Invalid Postgres snapshot table name: ${value}`);
	}
	return value;
}

export class PgStore implements ManagementStore {
	readonly backend = "postgres" as const;
	readonly path: string;
	readonly storeV2?: StoreV2MigrationControl;
	readonly storeV2Events?: StoreV2EventReader;
	readonly runtimeAuditEvents: PgRuntimeAuditEventReader;
	readonly storeV2Principals?: StoreV2PrincipalReader;
	readonly storeV2Topology?: StoreV2TopologyReader;
	readonly storeV2OrganizationAuthority?: Readonly<{ schema: string; table: string }>;
	readonly deliveryControl?: ManagementDeliveryControlReader;
	readonly webhookEndpoints?: ManagementWebhookEndpointCapability;
	private data: DataStoreSnapshot;
	private revision = 0;
	private pool: pg.Pool;
	private table: string;
	private emailUniqueTable: string;
	private slugUniqueTable: string;
	private idempotencyTable: string;
	private deliveryKeyring?: DeliveryKeyring;
	private deliverySchemaOptions?: DeliverySchemaOptions;
	private deliveryQuotaPolicy: DeliveryQuotaPolicy = DEFAULT_DELIVERY_QUOTA_POLICY;
	private storeV2Shadow?: PgStoreV2Shadow;
	private storeV2Phase: StoreV2Phase = "absent";
	private storeV2AuthoritativeCollections: StoreV2Collection[] = [];
	private storeV2PrincipalRevision: number | null = null;
	private storeV2PrincipalCount = 0;
	private storeV2TopologyState: StoreV2TopologyState | null = null;
	private storeV2TopologySnapshotRevision = -1;
	private storeV2Publication: Promise<void> = Promise.resolve();
	private pending: Promise<void> = Promise.resolve();
	/** Set when a queued write fails; rethrown from ready() so the chain never rejects. */
	private writeError: unknown = null;
	private readonly activePrincipalTransactions = new Set<Promise<unknown>>();
	private readonly activeTopologyTransactions = new Set<Promise<unknown>>();
	private authorizationTerminalizationStartup: Promise<void> | undefined;
	private initialized = false;

	constructor(
		databaseUrl: string,
		opts?: {
			backupDir?: string;
			tableName?: string;
			normalizedPrefix?: string;
			delivery?: PgStoreDeliveryOptions;
			runtimeAudit?: RuntimeAuditStoreOptions;
		},
	) {
		const normalizedDelivery = opts?.delivery
			? {
					keyring: normalizeDeliveryKeyring(opts.delivery.keyring),
					quota: normalizeDeliveryQuotaPolicy(
						opts.delivery.quota ?? DEFAULT_DELIVERY_QUOTA_POLICY,
					),
					options: {
						...(opts.delivery.schema ? { schema: opts.delivery.schema } : {}),
						...(opts.delivery.prefix ? { prefix: opts.delivery.prefix } : {}),
						...(opts.runtimeAudit === undefined
							? {}
							: {
									runtimeAudit: createRuntimeAuditTable({
										...(opts.runtimeAudit.schema
											? { schema: opts.runtimeAudit.schema }
											: {}),
										table: opts.runtimeAudit.prefix
											? `${opts.runtimeAudit.prefix}_runtime_audit_events`
											: "clearance_runtime_audit_events",
									}),
								}),
						...(opts.delivery.legacyFingerprintKeyId
							? { legacyFingerprintKeyId: opts.delivery.legacyFingerprintKeyId }
							: {}),
					} satisfies DeliverySchemaOptions,
				}
			: undefined;
		if (normalizedDelivery) {
			deliverySchemaName(normalizedDelivery.options);
			deliveryTableNames(normalizedDelivery.options);
		}
		this.path = resolve(opts?.backupDir ?? process.cwd(), ".clearance", "pg");
		this.pool = new pg.Pool({ connectionString: databaseUrl });
		this.runtimeAuditEvents = new PgRuntimeAuditEventReader(
			this.pool,
			opts?.runtimeAudit,
		);
		this.table = safeTableName(opts?.tableName ?? SNAPSHOT_TABLE);
		// Companion uniqueness tables share the snapshot table prefix for test isolation
		this.emailUniqueTable = safeTableName(`${this.table}_principal_email`);
		this.slugUniqueTable = safeTableName(`${this.table}_organization_slug`);
		this.idempotencyTable = safeTableName(`${this.table}_idempotency`);
		if (normalizedDelivery) {
			this.deliveryKeyring = normalizedDelivery.keyring;
			this.deliveryQuotaPolicy = normalizedDelivery.quota;
			this.deliverySchemaOptions = normalizedDelivery.options;
			this.deliveryControl = {
				list: (input) => listDeliveryJobs(this.pool, input, this.deliverySchemaOptions),
				inspect: (input) => inspectDeliveryJobScoped(
					this.pool,
					input,
					this.deliverySchemaOptions,
				),
				preview: (input) => previewDeliveryControl(
					this.pool,
					input,
					this.deliverySchemaOptions,
				),
				readiness: (input) => deliveryReadiness(
					this.pool,
					input,
					this.deliverySchemaOptions,
					this.deliveryKeyring,
				),
				quota: (input) => deliveryQuotaStatus(
					this.pool,
					{ ...input, policy: this.deliveryQuotaPolicy },
					this.deliverySchemaOptions,
				),
			};
			const keyring = normalizedDelivery.keyring;
			const options = normalizedDelivery.options;
			this.webhookEndpoints = {
				list: (input) => listWebhookEndpoints(this.pool, input, keyring, options),
				inspect: (input) => inspectWebhookEndpointScoped(
					this.pool,
					input,
					keyring,
					options,
				),
				preview: (input) => {
					if (input.action === "rotate") {
						return previewWebhookEndpointSecretRotation(
							this.pool,
							input,
							keyring,
							options,
						);
					}
					if (input.action === "delete") {
						return previewWebhookEndpointDeletion(
							this.pool,
							input,
							keyring,
							options,
						);
					}
					return previewWebhookEndpointTest(this.pool, input, keyring, options);
				},
				create: (input) => this.mutateWebhookEndpoint(
					input,
					"create",
					(transaction) => createWebhookEndpointInExistingTransaction(
						transaction,
						input,
						keyring,
						options,
					),
					(result) => ({
						endpointId: result.endpoint.id,
						resourceVersion: result.endpoint.resourceVersion,
						secretVersion: result.endpoint.secretVersion,
						status: result.endpoint.status,
						eventKinds: result.endpoint.eventKinds,
						urlFingerprint: result.endpoint.urlFingerprint,
					}),
				),
				update: (input) => this.mutateWebhookEndpoint(
					input,
					"update",
					(transaction) => updateWebhookEndpointInExistingTransaction(
						transaction,
						input,
						keyring,
						options,
					),
					(endpoint) => ({
						endpointId: endpoint.id,
						resourceVersion: endpoint.resourceVersion,
						secretVersion: endpoint.secretVersion,
						status: endpoint.status,
						eventKinds: endpoint.eventKinds,
						urlFingerprint: endpoint.urlFingerprint,
					}),
				),
				rotate: (input) => this.mutateWebhookEndpoint(
					input,
					"rotate",
					async (transaction) => {
						const preview = await previewWebhookEndpointSecretRotationInExistingTransaction(
							transaction,
							input,
							keyring,
							options,
						);
						if (!preview) return null;
						const result = await rotateWebhookEndpointSecretInExistingTransaction(
							transaction,
							input,
							keyring,
							options,
						);
						return result ? { preview, ...result } : null;
					},
					(result) => ({
						endpointId: result.endpoint.id,
						resourceVersion: result.endpoint.resourceVersion,
						secretVersion: result.endpoint.secretVersion,
						status: result.endpoint.status,
						urlFingerprint: result.endpoint.urlFingerprint,
					}),
				),
				delete: (input) => this.mutateWebhookEndpoint(
					input,
					"delete",
					async (transaction) => {
						const preview = await previewWebhookEndpointDeletionInExistingTransaction(
							transaction,
							input,
							keyring,
							options,
						);
						if (!preview) return null;
						const result = await softDeleteWebhookEndpointInExistingTransaction(
							transaction,
							input,
							options,
						);
						return result ? { preview, result } : null;
					},
					(result) => ({
						endpointId: result.result.endpoint.id,
						resourceVersion: result.result.endpoint.resourceVersion,
						status: result.result.endpoint.status,
						urlFingerprint: result.preview.endpoint.urlFingerprint,
						erasedPayloads: result.result.erasedPayloads,
						...result.result.jobs,
					}),
				),
				test: (input) => this.mutateWebhookEndpoint(
					input,
					"test",
					async (transaction) => {
						const preview = await previewWebhookEndpointTestInExistingTransaction(
							transaction,
							input,
							keyring,
							options,
						);
						if (!preview) return null;
						const result = await enqueueWebhookEndpointTestInExistingTransaction(
							transaction,
							{
								...input,
								actorId: input.actor,
								quota: this.deliveryQuotaPolicy,
							},
							keyring,
							options,
						);
						return result ? { preview, ...result } : null;
					},
					(result) => ({
						endpointId: result.endpoint.id,
						resourceVersion: result.endpoint.resourceVersion,
						status: result.endpoint.status,
						urlFingerprint: result.endpoint.urlFingerprint,
						testJobId: result.delivery.jobId,
					}),
				),
			};
		}
		const normalizedPrefix =
			opts?.normalizedPrefix ??
			(this.table === SNAPSHOT_TABLE ? "mgmt_" : undefined);
		if (normalizedPrefix) {
			this.storeV2Shadow = new PgStoreV2Shadow(
				this.pool,
				this.table,
				normalizedPrefix,
			);
			this.storeV2OrganizationAuthority = Object.freeze({
				schema: "public",
				table: this.storeV2Shadow.tables.organizations,
			});
			this.storeV2 = {
				plan: async () => {
					await this.ready();
					return this.storeV2Shadow!.plan();
				},
				status: async () => {
					await this.ready();
					return this.storeV2Shadow!.status();
				},
				apply: async () => {
					await this.ready();
					const applied = await this.storeV2Shadow!.apply();
					const loaded = await this.storeV2Shadow!.loadSnapshot();
					await this.#reconcileAuthorizationTerminalizationAtStartup(loaded);
					return applied;
				},
				verify: async () => {
					await this.ready();
					return this.storeV2Shadow!.verify();
				},
				disable: async () => {
					await this.ready();
					return this.storeV2Shadow!.disable();
				},
				cutoverEvents: async () => {
					await this.ready();
					const status = await this.storeV2Shadow!.cutoverEvents();
					await this.refresh();
					return status;
				},
				rollbackEvents: async () => {
					await this.ready();
					const status = await this.storeV2Shadow!.rollbackEvents();
					await this.refresh();
					return status;
				},
				cutoverPrincipals: async () => {
					await this.ready();
					const status = await this.storeV2Shadow!.cutoverPrincipals();
					await this.refresh();
					return status;
				},
				rollbackPrincipals: async () => {
					await this.ready();
					const status = await this.storeV2Shadow!.rollbackPrincipals();
					await this.refresh();
					return status;
				},
				cutoverTopology: async () => {
					await this.ready();
					const status = await this.storeV2Shadow!.cutoverTopology();
					await this.refresh();
					await this.#reconcileAuthorizationTerminalizationAtStartup(
						await this.storeV2Shadow!.loadSnapshot(),
					);
					return status;
				},
				rollbackTopology: async () => {
					await this.ready();
					const status = await this.storeV2Shadow!.rollbackTopology();
					await this.refresh();
					return status;
				},
			};
			const owner = this;
			this.storeV2Events = {
				get authoritative() {
					return owner.storeV2AuthoritativeCollections.includes("events");
				},
				listPage: (input) => this.storeV2Shadow!.listEventsPage(input),
			};
			this.storeV2Principals = {
				get authoritative() {
					return owner.storeV2AuthoritativeCollections.includes("principals");
				},
				getById: (input) => this.storeV2Shadow!.getPrincipalById(input),
				findActiveByEmail: (input) =>
					this.storeV2Shadow!.findActivePrincipalByEmail(input),
				findActiveByExternalId: (input) =>
					this.storeV2Shadow!.findActivePrincipalByExternalId(input),
				listPage: (input) => this.storeV2Shadow!.listPrincipalsPage(input),
				listActiveSessionsPage: (input) =>
					this.storeV2Shadow!.listActivePrincipalSessionsPage(input),
				listForExport: (input) =>
					this.storeV2Shadow!.listPrincipalsForExport(input),
				countByScope: (input) =>
					this.storeV2Shadow!.countPrincipalsByScope(input),
				countActiveSessions: (input) =>
					this.storeV2Shadow!.countActivePrincipalSessions(input),
			};
			const topologyRepository = new PgStoreV2TopologyRepository(
				this.pool as unknown as pg.PoolClient,
				this.storeV2Shadow.tables,
				false,
			);
			this.storeV2Topology = Object.freeze({
				get authoritative() {
					return ["projects", "environments", "organizations"].every(
						(collection) => owner.storeV2AuthoritativeCollections.includes(
							collection as StoreV2Collection,
						),
					);
				},
				getProjectById: (id: string) =>
					topologyRepository.capability.getProjectById(id),
				findProjectConflict: (
					input: Parameters<StoreV2TopologyReader["findProjectConflict"]>[0],
				) => topologyRepository.capability.findProjectConflict(input),
				getEnvironment: (
					input: Parameters<StoreV2TopologyReader["getEnvironment"]>[0],
				) => topologyRepository.capability.getEnvironment(input),
				findEnvironmentByKey: (
					input: Parameters<StoreV2TopologyReader["findEnvironmentByKey"]>[0],
				) => topologyRepository.capability.findEnvironmentByKey(input),
				getOrganization: (
					input: Parameters<StoreV2TopologyReader["getOrganization"]>[0],
				) => topologyRepository.capability.getOrganization(input),
				organizationIdExists: (id: string) =>
					topologyRepository.capability.organizationIdExists(id),
				getOrganizationBySlug: (
					input: Parameters<StoreV2TopologyReader["getOrganizationBySlug"]>[0],
				) => topologyRepository.capability.getOrganizationBySlug(input),
				getOrganizationByExternalId: (
					input: Parameters<StoreV2TopologyReader["getOrganizationByExternalId"]>[0],
				) => topologyRepository.capability.getOrganizationByExternalId(input),
				countOrganizations: (
					input: Parameters<StoreV2TopologyReader["countOrganizations"]>[0],
				) => topologyRepository.capability.countOrganizations(input),
				listProjectsPage: (
					input: Parameters<StoreV2TopologyReader["listProjectsPage"]>[0],
				) => topologyRepository.capability.listProjectsPage(input),
				listEnvironmentsPage: (
					input: Parameters<StoreV2TopologyReader["listEnvironmentsPage"]>[0],
				) => topologyRepository.capability.listEnvironmentsPage(input),
				listOrganizationsPage: (
					input: Parameters<StoreV2TopologyReader["listOrganizationsPage"]>[0],
				) => topologyRepository.capability.listOrganizationsPage(input),
			});
		}
		this.data = emptySnapshot();
		registerInternalCoordinatedExecutor(this, (fn) =>
			this.queueCoordinated(fn),
		);
	}

	/** Ensure schema + load snapshot. Call before first use. */
	async init(): Promise<this> {
		if (this.initialized) return this;
		await this.pool.query(`
			CREATE TABLE IF NOT EXISTS ${this.table} (
				id integer PRIMARY KEY CHECK (id = 1),
				data jsonb NOT NULL,
				revision bigint NOT NULL DEFAULT 0,
				updated_at timestamptz NOT NULL DEFAULT now()
			)
		`);
		if (this.deliveryKeyring) {
			await migrateDeliverySchema(this.pool, this.deliverySchemaOptions);
			// Resolve and validate the effective quota during initialization so a
			// malformed production policy cannot survive until the first mutation.
			await deliveryQuotaStatus(
				this.pool,
				{
					projectId: "__clearance_config_validation__",
					environmentId: "__clearance_config_validation__",
					policy: this.deliveryQuotaPolicy,
				},
				this.deliverySchemaOptions,
			);
		}
		// Existing installs created before revision column
		await this.pool.query(`
			ALTER TABLE ${this.table}
			ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 0
		`);

		// Database-enforced uniqueness within project/environment scope
		await this.pool.query(`
			CREATE TABLE IF NOT EXISTS ${this.emailUniqueTable} (
				project_id text NOT NULL,
				environment_id text NOT NULL,
				email_lower text NOT NULL,
				principal_id text NOT NULL,
				PRIMARY KEY (project_id, environment_id, email_lower)
			)
		`);
		await this.pool.query(`
			CREATE TABLE IF NOT EXISTS ${this.slugUniqueTable} (
				project_id text NOT NULL,
				environment_id text NOT NULL,
				slug text NOT NULL,
				organization_id text NOT NULL,
				PRIMARY KEY (project_id, environment_id, slug)
			)
		`);

		// Idempotency-Key replay records (FOLLOW.md P2.3.2). Deliberately a
		// companion table, NOT part of the JSONB snapshot: storing keys in the
		// snapshot would inflate every subsequent write of any kind and make TTL
		// expiry itself a snapshot mutation.
		await this.pool.query(`
			CREATE TABLE IF NOT EXISTS ${this.idempotencyTable} (
				scope_key text NOT NULL,
				key text NOT NULL,
				fingerprint text NOT NULL,
				status integer NOT NULL,
				content_type text NOT NULL,
				body text NOT NULL,
				created_at timestamptz NOT NULL DEFAULT now(),
				expires_at timestamptz NOT NULL,
				PRIMARY KEY (scope_key, key)
			)
		`);

		const result = await this.pool.query<{
			data: DataStoreSnapshot;
			revision: string | number;
		}>(`SELECT data, revision FROM ${this.table} WHERE id = 1`);
		if (result.rows[0]?.data) {
			this.data = normalizeSnapshot(result.rows[0].data);
			this.revision = Number(result.rows[0].revision ?? 0);
		} else {
			this.data = emptySnapshot({
				storeBackend: "postgres",
			});
			await this.persistLocked(this.data, 0);
			this.revision = 1;
		}
		if (this.storeV2Shadow) {
			const loaded = await this.storeV2Shadow.loadSnapshot();
			await this.publishStoreV2Publication(() => {
				this.publishStoreV2Snapshot(loaded);
			});
			// The reconciliation may append its durable migration audit through the
			// coordinated executor, which requires an initialized store.
			this.initialized = true;
			await this.#reconcileAuthorizationTerminalizationAtStartup(loaded);
		}
		this.initialized = true;
		return this;
	}

	async #reconcileAuthorizationTerminalizationAtStartup(loaded: {
		authoritativeCollections: readonly StoreV2Collection[];
	}): Promise<void> {
		const topologyAuthoritative = ["projects", "environments", "organizations"].every(
			(collection) => loaded.authoritativeCollections.includes(collection as StoreV2Collection),
		);
		// Management-only and legacy startup must never force runtime auth setup.
		if (!topologyAuthoritative || !process.env.DATABASE_URL || !process.env.CLEARANCE_SECRET) return;
		if (this.authorizationTerminalizationStartup) {
			return this.authorizationTerminalizationStartup;
		}
		const run = reconcileAuthorizationTerminalizationAtManagementStartup(this);
		this.authorizationTerminalizationStartup = run;
		try {
			await run;
		} finally {
			if (this.authorizationTerminalizationStartup === run) {
				this.authorizationTerminalizationStartup = undefined;
			}
		}
	}

	load(): DataStoreSnapshot {
		return this.data;
	}

	get snapshot(): DataStoreSnapshot {
		return this.data;
	}

	/** Monotonic revision of the last known durable snapshot (test/debug). */
	get currentRevision(): number {
		return this.revision;
	}

	save(): void {
		this.queueWrite((data) => data);
	}

	async ready(): Promise<void> {
		await this.pending;
		while (this.activePrincipalTransactions.size > 0) {
			await Promise.allSettled([...this.activePrincipalTransactions]);
		}
		while (this.activeTopologyTransactions.size > 0) await Promise.allSettled([...this.activeTopologyTransactions]);
		if (this.writeError) {
			const err = this.writeError;
			this.writeError = null;
			throw err;
		}
	}

	/**
	 * Pull latest durable snapshot if another process advanced the revision.
	 * Safe to call on every API request; no-op when revision is current.
	 */
	async refresh(): Promise<void> {
		await this.ready();
		if (this.storeV2Shadow) {
			const loaded = await this.storeV2Shadow.loadSnapshot({
				principalRevision: this.storeV2PrincipalRevision,
				principalCount: this.storeV2PrincipalCount,
			});
			await this.publishStoreV2Publication(() => {
				this.publishStoreV2Snapshot(loaded);
			});
			if (process.env.CLEARANCE_STORE_V2_VERIFY === "1") {
				const status = await this.storeV2Shadow.verify();
				if ((status.phase === "shadow" || status.phase === "hybrid") && !status.consistent) {
					throw new StoreV2MigrationError(
						"STORE_V2_DIVERGENCE",
						"Store-v2 data diverged from the authoritative representation.",
					);
				}
			}
			return;
		}
		const result = await this.pool.query<{
			data: DataStoreSnapshot;
			revision: string | number;
		}>(`SELECT data, revision FROM ${this.table} WHERE id = 1`);
		if (!result.rows[0]) return;
		const rev = Number(result.rows[0].revision ?? 0);
		if (rev !== this.revision) {
			this.data = normalizeSnapshot(result.rows[0].data);
			this.revision = rev;
		}
	}

	replace(snapshot: DataStoreSnapshot): void {
		const next = cloneSnapshot(snapshot);
		this.queueWrite(() => next, true);
	}

	mutate(fn: (data: DataStoreSnapshot) => void): DataStoreSnapshot {
		this.queueWrite(fn);
		// Snapshot may lag until ready(); callers that built objects outside the
		// mutator still return those objects. Await ready() before reading snapshot.
		return this.data;
	}

	mutateDurable<T>(fn: (data: DataStoreSnapshot) => T): Promise<T> {
		return new Promise<T>((resolvePromise, rejectPromise) => {
			this.pending = this.pending.then(async () => {
				try {
					resolvePromise(await this.transactMutation(fn));
				} catch (error) {
					rejectPromise(error);
				}
			});
		});
	}

	mutateStoreV2Principals<T>(
		fn: (principals: StoreV2PrincipalRepository) => Promise<T> | T,
	): Promise<T> {
		return this.trackPrincipalTransaction(this.transactStoreV2Principals(fn));
	}

	mutateStoreV2Identity<T>(
		fn: (context: {
			principals: StoreV2PrincipalRepository;
			appendAudit(input: AuditEventInput): AuditEvent;
		}) => Promise<T> | T,
	): Promise<T> {
		return this.trackPrincipalTransaction(this.transactStoreV2Identity(fn));
	}

	mutateStoreV2Topology<T>(
		fn: (context: {
			topology: StoreV2TopologyRepository;
			appendAudit(input: AuditEventInput): AuditEvent;
		}) => Promise<T> | T,
	): Promise<T> {
		const transaction = this.transactStoreV2Topology(fn);
		this.activeTopologyTransactions.add(transaction);
		transaction.finally(() => this.activeTopologyTransactions.delete(transaction)).catch(() => undefined);
		return transaction;
	}

	private trackPrincipalTransaction<T>(transaction: Promise<T>): Promise<T> {
		this.activePrincipalTransactions.add(transaction);
		transaction.then(
			() => {
				this.activePrincipalTransactions.delete(transaction);
			},
			() => {
				this.activePrincipalTransactions.delete(transaction);
			},
		);
		return transaction;
	}

	/**
	 * Single Postgres transaction: lock management snapshot, run caller SQL
	 * (runtime user/session/account tables) + snapshot mutator, enforce
	 * uniqueness indexes, commit. Full ROLLBACK on any throw — never returns
	 * success when runtime and management diverge.
	 */
	mutateCoordinated<T>(
		fn: (ctx: ManagementCoordinatedMutationContext) => Promise<T> | T,
	): Promise<T> {
		return this.queueCoordinated(async (context) => {
			const { query: _query, ...publicContext } = context;
			return fn(publicContext);
		});
	}

	private queueCoordinated<T>(
		fn: (
			context: InternalManagementCoordinatedMutationContext,
		) => Promise<T> | T,
	): Promise<T> {
		return new Promise<T>((resolvePromise, rejectPromise) => {
			this.pending = this.pending.then(async () => {
				try {
					resolvePromise(await this.transactCoordinated(fn));
				} catch (error) {
					rejectPromise(error);
				}
			});
		});
	}

	checksum(): string {
		return createHash("sha256").update(stableSnapshotJson(this.data)).digest("hex");
	}

	resourceCounts(): Record<string, number> {
		const counts = snapshotResourceCounts(this.data);
		if (this.storeV2AuthoritativeCollections.includes("principals")) {
			counts.principals = this.storeV2PrincipalCount;
		}
		if (
			["projects", "environments", "organizations"].every((collection) =>
				this.storeV2AuthoritativeCollections.includes(
					collection as StoreV2Collection,
				),
			)
		) {
			if (!this.storeV2TopologyState) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_STATE_INVALID",
					"Store-v2 topology state metadata is missing or invalid.",
				);
			}
			counts.projects = this.storeV2TopologyState.projectCount;
			counts.environments = this.storeV2TopologyState.environmentCount;
			counts.organizations = this.storeV2TopologyState.organizationCount;
		}
		return counts;
	}

	/**
	 * A refresh reads snapshot, authority, principals, and topology from one
	 * database view. Publish that view all at once only when it cannot regress
	 * the snapshot or topology views already observed by this process.
	 */
	private publishStoreV2Snapshot(loaded: StoreV2SnapshotPublication): boolean {
		if (
			!this.canPublishStoreV2SnapshotTopology(loaded) ||
			!this.canPublishStoreV2PrincipalCache(loaded)
		) {
			this.publishStoreV2TopologyState({
				phase: loaded.phase,
				authoritativeCollections: loaded.authoritativeCollections,
				topologyState: loaded.topologyState,
				snapshotRevision: loaded.revision,
			});
			return false;
		}
		this.data = loaded.snapshot;
		this.revision = loaded.revision;
		this.storeV2PrincipalCount = loaded.principalCount;
		this.storeV2PrincipalRevision = loaded.principalRevision;
		this.publishStoreV2TopologyState({
			phase: loaded.phase,
			authoritativeCollections: loaded.authoritativeCollections,
			topologyState: loaded.topologyState,
			snapshotRevision: loaded.revision,
		});
		return true;
	}

	/**
	 * A committed snapshot candidate may lose a local publication race to a
	 * direct relational transaction. Reload directly after commit until one
	 * coherent view publishes, retaining the newer safe view if writers remain
	 * continuously active.
	 */
	private async publishCommittedStoreV2Snapshot(
		candidate: StoreV2SnapshotPublication,
	): Promise<void> {
		await this.publishStoreV2Publication(async () => {
			if (this.publishStoreV2Snapshot(candidate) || !this.storeV2Shadow) return;
			try {
				const loaded = await this.storeV2Shadow.loadSnapshot({
					principalRevision: this.storeV2PrincipalRevision,
					principalCount: this.storeV2PrincipalCount,
				});
				this.publishStoreV2Snapshot(loaded);
			} catch {
				// The database commit is durable. Retain the newer coherent local view;
				// the next ordinary refresh can retry convergence.
			}
		});
	}

	private publishStoreV2Publication<T>(
		fn: () => Promise<T> | T,
	): Promise<T> {
		const publication = this.storeV2Publication.then(fn, fn);
		this.storeV2Publication = publication.then(
			() => undefined,
			() => undefined,
		);
		return publication;
	}

	private canPublishStoreV2SnapshotTopology(
		loaded: StoreV2SnapshotPublication,
	): boolean {
		if (loaded.revision < this.revision) return false;
		const currentTopologyRevision = this.storeV2TopologyState?.revision;
		const incomingTopologyRevision = loaded.topologyState?.revision;
		if (
			currentTopologyRevision !== undefined &&
			(incomingTopologyRevision === undefined ||
				incomingTopologyRevision < currentTopologyRevision)
		) return false;
		if (
			currentTopologyRevision !== undefined &&
			incomingTopologyRevision === currentTopologyRevision &&
			loaded.revision < this.storeV2TopologySnapshotRevision
		) return false;
		return true;
	}

	private canPublishStoreV2PrincipalCache(
		loaded: StoreV2SnapshotPublication,
	): boolean {
		const incomingPrincipalsAuthoritative =
			loaded.authoritativeCollections.includes("principals");
		if (incomingPrincipalsAuthoritative && loaded.principalRevision === null) {
			return false;
		}
		if (
			this.storeV2PrincipalRevision !== null &&
			(loaded.principalRevision === null ||
				loaded.principalRevision < this.storeV2PrincipalRevision)
		) return false;
		return true;
	}

	private publishStoreV2PrincipalState(revision: number, count: number): void {
		if (
			this.storeV2PrincipalRevision !== null &&
			revision < this.storeV2PrincipalRevision
		) return;
		this.storeV2PrincipalRevision = revision;
		this.storeV2PrincipalCount = count;
	}

	/**
	 * Publish the topology authority view as one monotonic cache update. Direct
	 * topology writers do not advance the snapshot revision, so an older refresh
	 * may return after their commit; its older topology state must not win.
	 */
	private publishStoreV2TopologyState(input: {
		phase: StoreV2Phase;
		authoritativeCollections: readonly StoreV2Collection[];
		topologyState: StoreV2TopologyState | null;
		snapshotRevision: number;
	}): void {
		const authoritativeCollections = [...input.authoritativeCollections];
		const nextTopologyAuthoritative = [
			"projects",
			"environments",
			"organizations",
		].every((collection) =>
			authoritativeCollections.includes(collection as StoreV2Collection),
		);
		const currentTopologyAuthoritative = [
			"projects",
			"environments",
			"organizations",
		].every((collection) =>
			this.storeV2AuthoritativeCollections.includes(
				collection as StoreV2Collection,
			),
		);
		if (input.topologyState) {
			const currentTopologyRevision = this.storeV2TopologyState?.revision;
			if (
				currentTopologyRevision !== undefined &&
				input.topologyState.revision < currentTopologyRevision
			) return;
			if (
				input.topologyState.revision === currentTopologyRevision &&
				input.snapshotRevision < this.storeV2TopologySnapshotRevision
			) return;
			if (
				currentTopologyRevision === undefined &&
				input.snapshotRevision < this.storeV2TopologySnapshotRevision
			) return;
			this.storeV2TopologyState = input.topologyState;
			if (input.snapshotRevision < this.storeV2TopologySnapshotRevision) return;
			this.storeV2Phase = input.phase;
			this.storeV2AuthoritativeCollections = authoritativeCollections;
			this.storeV2TopologySnapshotRevision = input.snapshotRevision;
			return;
		}
		if (input.phase !== "absent" && nextTopologyAuthoritative) return;
		if (
			input.snapshotRevision < this.storeV2TopologySnapshotRevision ||
			(this.storeV2TopologyState &&
				currentTopologyAuthoritative &&
				input.snapshotRevision === this.storeV2TopologySnapshotRevision)
		) {
			return;
		}
		this.storeV2Phase = input.phase;
		this.storeV2AuthoritativeCollections = authoritativeCollections;
		this.storeV2TopologyState = null;
		this.storeV2TopologySnapshotRevision = input.snapshotRevision;
	}

	async destroy(): Promise<void> {
		await this.ready().catch(() => undefined);
		await this.pool.end();
	}

	/**
	 * Read a stored Idempotency-Key replay record. Expired rows are treated as
	 * absent (TTL is enforced on read as well as by opportunistic cleanup).
	 */
	async getIdempotencyRecord(
		scopeKey: string,
		key: string,
	): Promise<{
		fingerprint: string;
		status: number;
		contentType: string;
		body: string;
	} | null> {
		const r = await this.pool.query<{
			fingerprint: string;
			status: number;
			content_type: string;
			body: string;
		}>(
			`SELECT fingerprint, status, content_type, body
       FROM ${this.idempotencyTable}
       WHERE scope_key = $1 AND key = $2 AND expires_at > now()`,
			[scopeKey, key],
		);
		const row = r.rows[0];
		if (!row) return null;
		return {
			fingerprint: row.fingerprint,
			status: Number(row.status),
			contentType: row.content_type,
			body: row.body,
		};
	}

	/**
	 * Store an Idempotency-Key replay record with a TTL. Opportunistically
	 * deletes expired rows first (the table stays small; expiry never touches
	 * the snapshot). ON CONFLICT DO NOTHING: the first committed responder wins
	 * under a same-key race.
	 */
	async putIdempotencyRecord(record: {
		scopeKey: string;
		key: string;
		fingerprint: string;
		status: number;
		contentType: string;
		body: string;
		ttlMs: number;
	}): Promise<void> {
		await this.pool.query(
			`DELETE FROM ${this.idempotencyTable} WHERE expires_at <= now()`,
		);
		await this.pool.query(
			`INSERT INTO ${this.idempotencyTable}
         (scope_key, key, fingerprint, status, content_type, body, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7::double precision / 1000))
       ON CONFLICT (scope_key, key) DO NOTHING`,
			[
				record.scopeKey,
				record.key,
				record.fingerprint,
				record.status,
				record.contentType,
				record.body,
				record.ttlMs,
			],
		);
	}

	/**
	 * Enqueue a mutation that will be transactionally replayed against the
	 * row-locked latest snapshot (not applied only to a stale process-local copy).
	 * The chain never rejects (errors are stashed and rethrown from ready()) so
	 * concurrent writers cannot strand later ops or emit unhandledRejection.
	 */
	private queueWrite(
		fn: (data: DataStoreSnapshot) => DataStoreSnapshot | void,
		replacing = false,
	): void {
		this.pending = this.pending.then(async () => {
			try {
				await this.transactReplay(fn, replacing);
			} catch (e) {
				// Preserve the first unobserved failure until ready() reports it. A later
				// successful queued write must never erase evidence of a failed mutation.
				this.writeError ??= e;
			}
		});
	}

	private async transactReplay(
		fn: (data: DataStoreSnapshot) => DataStoreSnapshot | void,
		replacing = false,
	): Promise<void> {
		const client = await this.pool.connect();
		let committed = false;
		let released = false;
		const release = () => {
			if (!released) {
				released = true;
				client.release();
			}
		};
		try {
			await client.query("BEGIN");
			if (this.storeV2Shadow) {
				await this.storeV2Shadow.lockPrincipalAuthorityShared(client);
			}
			const result = await client.query<{
				data: DataStoreSnapshot;
				revision: string | number;
			}>(
				`SELECT data, revision FROM ${this.table} WHERE id = 1 FOR UPDATE`,
			);

			let base: DataStoreSnapshot;
			let rev: number;
			if (result.rows[0]?.data) {
				base = normalizeSnapshot(cloneSnapshot(result.rows[0].data));
				rev = Number(result.rows[0].revision ?? 0);
			} else {
				base = emptySnapshot({ storeBackend: "postgres" });
				rev = 0;
			}
			const phase = this.storeV2Shadow
				? await this.storeV2Shadow.transactionPhase(client)
				: "absent";
			if (phase === "hybrid") {
				if (replacing) {
					throw new StoreV2MigrationError(
						"STORE_V2_REPLACE_REQUIRES_EVENTS_ROLLBACK",
						"Roll back authoritative events before replacing the management snapshot.",
					);
				}
			}

			const before = cloneSnapshot(base);
			if (phase === "hybrid") deferAuditRetentionForDraft(base);
			// Apply on draft — if fn throws (e.g. USER_EXISTS), full ROLLBACK
			const applied = fn(base);
			const next = applied === undefined ? base : applied;
			if (phase === "hybrid" && next !== base) {
				throw new StoreV2MigrationError(
					"STORE_V2_REPLACE_REQUIRES_EVENTS_ROLLBACK",
					"Roll back authoritative events before replacing the management snapshot.",
				);
			}
			const appendedEvents = phase === "hybrid"
				? consumeDeferredAuditEvents(next)
				: undefined;
			const newRevision = rev + 1;

			const sync = await this.storeV2Shadow?.syncTransaction(
				client,
				before,
				next,
				newRevision,
				appendedEvents,
			);
			// Enforce uniqueness indexes from the committed snapshot draft
			await this.syncUniqueness(
				client,
				next,
				sync?.authoritativeCollections ?? [],
			);

			const persisted = sync?.persistedSnapshot ?? next;
			const materialized = await this.materializeStoreV2Candidate(
				client,
				next,
				rev,
				sync,
			);
			const principalCount = await this.resolvePrincipalCount(
				client,
				sync?.authoritativeCollections ?? [],
			);
			await client.query(
				`INSERT INTO ${this.table} (id, data, revision, updated_at)
         VALUES (1, $1::jsonb, $2, now())
         ON CONFLICT (id) DO UPDATE
         SET data = EXCLUDED.data,
             revision = EXCLUDED.revision,
             updated_at = now()`,
				[JSON.stringify(persisted), newRevision],
			);
			await client.query("COMMIT");
			committed = true;
			release();
			await this.publishCommittedStoreV2Snapshot({
				snapshot: materialized,
				principalCount,
				revision: newRevision,
				phase: sync?.phase ?? phase,
				authoritativeCollections: sync?.authoritativeCollections ?? [],
				principalRevision: sync?.principalRevision ?? null,
				topologyState: sync?.topologyState ?? null,
			}).catch(() => undefined);
		} catch (e) {
			if (committed) return;
			await client.query("ROLLBACK").catch(() => undefined);
			throw e;
		} finally {
			release();
		}
	}

	private async transactMutation<T>(
		fn: (data: DataStoreSnapshot) => T,
	): Promise<T> {
		const client = await this.pool.connect();
		let committed = false;
		let released = false;
		const release = () => {
			if (!released) {
				released = true;
				client.release();
			}
		};
		let committedValue!: T;
		try {
			await client.query("BEGIN");
			if (this.storeV2Shadow) {
				await this.storeV2Shadow.lockPrincipalAuthorityShared(client);
			}
			const result = await client.query<{
				data: DataStoreSnapshot;
				revision: string | number;
			}>(`SELECT data, revision FROM ${this.table} WHERE id = 1 FOR UPDATE`);
			const base = result.rows[0]?.data
				? normalizeSnapshot(cloneSnapshot(result.rows[0].data))
				: emptySnapshot({ storeBackend: "postgres" });
			const previousRevision = Number(result.rows[0]?.revision ?? 0);
			const phase = this.storeV2Shadow
				? await this.storeV2Shadow.transactionPhase(client)
				: "absent";
			const before = cloneSnapshot(base);
			if (phase === "hybrid") deferAuditRetentionForDraft(base);
			const revision = previousRevision + 1;
			const value = committedValue = fn(base);
			const appendedEvents = phase === "hybrid"
				? consumeDeferredAuditEvents(base)
				: undefined;
			const sync = await this.storeV2Shadow?.syncTransaction(
				client,
				before,
				base,
				revision,
				appendedEvents,
			);
			await this.syncUniqueness(
				client,
				base,
				sync?.authoritativeCollections ?? [],
			);
			const persisted = sync?.persistedSnapshot ?? base;
			const materialized = await this.materializeStoreV2Candidate(
				client,
				base,
				previousRevision,
				sync,
			);
			const principalCount = await this.resolvePrincipalCount(
				client,
				sync?.authoritativeCollections ?? [],
			);
			await client.query(
				`INSERT INTO ${this.table} (id, data, revision, updated_at)
         VALUES (1, $1::jsonb, $2, now())
         ON CONFLICT (id) DO UPDATE
         SET data = EXCLUDED.data,
             revision = EXCLUDED.revision,
             updated_at = now()`,
				[JSON.stringify(persisted), revision],
			);
			await client.query("COMMIT");
			committed = true;
			release();
			await this.publishCommittedStoreV2Snapshot({
				snapshot: materialized,
				principalCount,
				revision,
				phase: sync?.phase ?? phase,
				authoritativeCollections: sync?.authoritativeCollections ?? [],
				principalRevision: sync?.principalRevision ?? null,
				topologyState: sync?.topologyState ?? null,
			}).catch(() => undefined);
			return value;
		} catch (error) {
			if (committed) return committedValue;
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			release();
		}
	}

	private transactStoreV2Principals<T>(
		fn: (principals: StoreV2PrincipalRepository) => Promise<T> | T,
	): Promise<T> {
		return this.transactStoreV2Identity(({ principals }) => fn(principals));
	}

	private async transactStoreV2Identity<T>(
		fn: (context: {
			principals: StoreV2PrincipalRepository;
			appendAudit(input: AuditEventInput): AuditEvent;
		}) => Promise<T> | T,
	): Promise<T> {
		if (!this.storeV2Shadow) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_UNAVAILABLE",
				"Normalized principal storage is not configured for this store.",
			);
		}
		const snapshotRevision = this.revision;
		const client = await this.pool.connect();
		let committed = false;
		let released = false;
		const release = () => {
			if (!released) {
				released = true;
				client.release();
			}
		};
		let committedValue!: T;
		try {
			await client.query("BEGIN");
			await this.storeV2Shadow.lockPrincipalAuthorityShared(client);
			const authoritativeCollections =
				await this.storeV2Shadow.transactionAuthoritativeCollections(client);
			const phase = await this.storeV2Shadow.transactionPhase(client);
			if (!authoritativeCollections.includes("principals")) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
					"Direct principal mutation requires relational principal authority.",
				);
			}
			if (!authoritativeCollections.includes("events")) {
				throw new StoreV2MigrationError(
					"STORE_V2_EVENTS_NOT_AUTHORITATIVE",
					"Relational identity transactions require append-only event authority.",
				);
			}
			const repository = new PgStoreV2PrincipalRepository(
				client,
				this.storeV2Shadow.tables,
			);
			const audits: AuditEvent[] = [];
			let auditActive = true;
			const appendAudit = (input: AuditEventInput): AuditEvent => {
				if (!auditActive) {
					throw new TransactionCapabilityRevokedError();
				}
				const event = buildAuditEvent(structuredClone(input));
				audits.push(event);
				return structuredClone(event);
			};
			let value!: T;
			let callbackError: unknown;
			let callbackFailed = false;
			try {
				value = await fn({ principals: repository.capability, appendAudit });
			} catch (error) {
				callbackFailed = true;
				callbackError = error;
			}
			repository.revoke();
			auditActive = false;
			let issuedError: unknown;
			try {
				await repository.settleIssued();
			} catch (error) {
				issuedError = error;
			}
			if (callbackFailed) throw callbackError;
			if (issuedError !== undefined) throw issuedError;
			committedValue = value;
			const principalState = await repository.finalizeState();
			const topologyState = await readStoreV2TopologyState(
				client,
				this.storeV2Shadow.tables,
			);
			const eventDelta = audits.length > 0
				? await appendStoreV2Events(
						client,
						this.storeV2Shadow.tables,
						audits,
						principalState.revision,
					)
				: undefined;
			await client.query("COMMIT");
			committed = true;
			release();
			await this.publishStoreV2Publication(() => {
				this.publishStoreV2TopologyState({
					phase,
					authoritativeCollections,
					topologyState,
					snapshotRevision,
				});
				if (eventDelta) {
					this.data = {
						...this.data,
						events: applyStoreV2EventDelta(this.data.events, eventDelta),
					};
				}
				this.publishStoreV2PrincipalState(
					principalState.revision,
					principalState.count,
				);
			}).catch(() => undefined);
			return value;
		} catch (error) {
			if (committed) return committedValue;
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			release();
		}
	}

	private async transactStoreV2Topology<T>(
		fn: (context: {
			topology: StoreV2TopologyRepository;
			appendAudit(input: AuditEventInput): AuditEvent;
		}) => Promise<T> | T,
	): Promise<T> {
		if (!this.storeV2Shadow) {
			throw new StoreV2MigrationError(
				"STORE_V2_TOPOLOGY_UNAVAILABLE",
				"Normalized topology storage is not configured for this store.",
			);
		}
		const snapshotRevision = this.revision;
		const client = await this.pool.connect();
		let committed = false;
		let released = false;
		const release = () => {
			if (!released) {
				released = true;
				client.release();
			}
		};
		let committedValue!: T;
		try {
			await client.query("BEGIN");
			await this.storeV2Shadow.lockPrincipalAuthorityShared(client);
			const authority =
				await this.storeV2Shadow.transactionAuthoritativeCollections(client);
			const phase = await this.storeV2Shadow.transactionPhase(client);
			if (
				!["projects", "environments", "organizations"].every((collection) =>
					authority.includes(collection as StoreV2Collection),
				)
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_NOT_AUTHORITATIVE",
					"Direct topology mutation requires relational topology authority.",
				);
			}
			if (!authority.includes("events")) {
				throw new StoreV2MigrationError(
					"STORE_V2_EVENTS_NOT_AUTHORITATIVE",
					"Relational topology transactions require append-only event authority.",
				);
			}
			const repository = new PgStoreV2TopologyRepository(
				client,
				this.storeV2Shadow.tables,
			);
			const audits: AuditEvent[] = [];
			let auditActive = true;
			const appendAudit = (input: AuditEventInput): AuditEvent => {
				if (!auditActive) throw new TransactionCapabilityRevokedError();
				const event = buildAuditEvent(structuredClone(input));
				audits.push(event);
				return structuredClone(event);
			};
			let value!: T;
			let callbackError: unknown;
			let callbackFailed = false;
			try {
				value = await fn(
					Object.freeze({ topology: repository.capability, appendAudit }),
				);
			} catch (error) {
				callbackFailed = true;
				callbackError = error;
			}
			repository.revoke();
			auditActive = false;
			let issuedError: unknown;
			try {
				await repository.settleIssued();
			} catch (error) {
				issuedError = error;
			}
			if (callbackFailed) throw callbackError;
			if (issuedError !== undefined) throw issuedError;
			committedValue = value;
			if (repository.hasMutations() && audits.length === 0) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_AUDIT_REQUIRED",
					"Changed relational topology transactions must append an audit event.",
				);
			}
			const topologyState = await repository.finalizeState();
			if (!topologyState) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_STATE_INVALID",
					"Store-v2 topology state metadata is missing or invalid.",
				);
			}
			const eventDelta = audits.length > 0
				? await appendStoreV2Events(
						client,
						this.storeV2Shadow.tables,
						audits,
						topologyState.revision,
					)
				: undefined;
			await client.query("COMMIT");
			committed = true;
			release();
			await this.publishStoreV2Publication(() => {
				this.publishStoreV2TopologyState({
					phase,
					authoritativeCollections: authority,
					topologyState,
					snapshotRevision,
				});
				if (eventDelta) {
					this.data = {
						...this.data,
						events: applyStoreV2EventDelta(this.data.events, eventDelta),
					};
				}
			}).catch(() => undefined);
			return value;
		} catch (error) {
			if (committed) return committedValue;
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			release();
		}
	}

	private async transactCoordinated<T>(
		fn: (
			context: InternalManagementCoordinatedMutationContext,
		) => Promise<T> | T,
	): Promise<T> {
		const client = await this.pool.connect();
		let committed = false;
		let released = false;
		const release = () => {
			if (!released) {
				released = true;
				client.release();
			}
		};
		let committedValue!: T;
		try {
			await client.query("BEGIN");
			if (this.storeV2Shadow) {
				await this.storeV2Shadow.lockPrincipalAuthorityShared(client);
			}
			const result = await client.query<{
				data: DataStoreSnapshot;
				revision: string | number;
			}>(`SELECT data, revision FROM ${this.table} WHERE id = 1 FOR UPDATE`);
			const base = result.rows[0]?.data
				? normalizeSnapshot(cloneSnapshot(result.rows[0].data))
				: emptySnapshot({ storeBackend: "postgres" });
			const previousRevision = Number(result.rows[0]?.revision ?? 0);
			const phase = this.storeV2Shadow
				? await this.storeV2Shadow.transactionPhase(client)
				: "absent";
			const authoritativeCollections = this.storeV2Shadow
				? await this.storeV2Shadow.transactionAuthoritativeCollections(client)
				: [];
			const principalTransaction = authoritativeCollections.includes("principals")
				? new PgStoreV2PrincipalRepository(client, this.storeV2Shadow!.tables)
				: undefined;
			const principals = principalTransaction?.capability;
			const topologyTransaction = [
				"projects",
				"environments",
				"organizations",
			].every((collection) =>
				authoritativeCollections.includes(collection as StoreV2Collection),
			)
				? new PgStoreV2TopologyRepository(client, this.storeV2Shadow!.tables)
				: undefined;
			const topology = topologyTransaction?.capability;
			const before = cloneSnapshot(base);
			if (phase === "hybrid") deferAuditRetentionForDraft(base);
			const revision = previousRevision + 1;
			let auditActive = true;
			const appendAudit = (input: AuditEventInput): AuditEvent => {
				if (!auditActive) throw new TransactionCapabilityRevokedError();
				return structuredClone(appendAuditEvent(base, structuredClone(input)));
			};

			let queryActive = true;
			const pendingQueries = new Set<Promise<{
				rows: Record<string, unknown>[];
				rowCount: number | null;
			}>>();
			const issueQuery = (sql: string, params?: readonly unknown[]) => {
				const capturedParams = params === undefined
					? undefined
					: structuredClone([...params]).map((value, index) =>
						Buffer.isBuffer(params[index])
							? Buffer.from(params[index] as Buffer)
							: value,
					);
				const pending = Promise.resolve().then(async () => {
					const r = await client.query(sql, capturedParams);
					return {
						rows: r.rows as Record<string, unknown>[],
						rowCount: r.rowCount,
					};
				});
				// Observe every rejection at issuance time even when the caller drops
				// the returned promise. transactCoordinated still drains and rethrows it.
				pending.then(
					() => undefined,
					() => undefined,
				);
				pendingQueries.add(pending);
				return pending;
			};
			const query = (sql: string, params?: unknown[]) => {
				if (!queryActive) {
					const rejected = Promise.reject(new TransactionCapabilityRevokedError());
					rejected.catch(() => undefined);
					return rejected;
				}
				return issueQuery(sql, params);
			};
			const settleIssuedQueries = async (): Promise<PromiseSettledResult<unknown>[]> => {
				const settled: PromiseSettledResult<unknown>[] = [];
				while (pendingQueries.size > 0) {
					const issued = [...pendingQueries];
					pendingQueries.clear();
					settled.push(...await Promise.allSettled(issued));
				}
				return settled;
			};

			const rawTransaction = {
				rawTransactionQuery: async <
					Row extends Record<string, unknown> = Record<string, unknown>,
				>(text: string, values?: readonly unknown[]) => {
					const result = await issueQuery(text, values);
					return {
						rows: result.rows as Row[],
						rowCount: result.rowCount,
					};
				},
			};
			const pendingDeliveryEnqueues: Promise<EnqueuedDelivery>[] = [];
			const enqueueDelivery = this.deliveryKeyring
				? (input: EnqueueDeliveryInput) => {
						const pending = enqueueDeliveryInExistingTransaction(
							rawTransaction,
							{
								...input,
								quota: input.quota ?? this.deliveryQuotaPolicy,
							},
							this.deliveryKeyring!,
							this.deliverySchemaOptions,
						);
						pendingDeliveryEnqueues.push(pending);
						return pending;
					}
				: undefined;

			const pendingDeliveryControls: Promise<unknown>[] = [];
			const trackedControl = <T>(
				action: "cancel" | "retry" | "replay",
				input: DeliveryControlMutationInput & { maxAttempts?: number },
				operation: () => Promise<T | null>,
			) => {
				const pending = (async () => {
					const preview = await previewDeliveryControlInExistingTransaction(
						rawTransaction,
						{
							...input,
							action,
							...(input.maxAttempts === undefined
								? {}
								: { maxAttempts: input.maxAttempts }),
						},
						this.deliverySchemaOptions,
					);
					if (!preview) return null;
					const controlled = await operation();
					if (controlled !== null) {
						const result = controlled as Record<string, unknown>;
						const cancellationPending = action === "cancel" &&
							result.cancelRequested === true;
						appendAuditEvent(base, {
							actor: input.actor,
							action: `delivery.job.${action}`,
							subjectType: "delivery_job",
							subjectId: input.jobId,
							outcome: cancellationPending ? "pending" : "success",
							source: input.source,
							projectId: input.projectId,
							environmentId: input.environmentId,
							...(input.correlationId ? { correlationId: input.correlationId } : {}),
							message: cancellationPending
								? "Delivery job cancellation requested"
								: `Delivery job ${action} completed`,
							metadata: {
								action,
								...(typeof result.cancelRequested === "boolean"
									? { cancelRequested: result.cancelRequested }
									: {}),
								resultJobId: result.jobId ?? result.id,
								resultEventId: result.eventId,
								state: result.state,
							},
						});
					}
					return controlled === null ? null : { preview, result: controlled };
				})();
				pendingDeliveryControls.push(pending);
				return pending;
			};
			const controlDelivery: ManagementDeliveryControlMutation | undefined =
				this.deliveryKeyring
					? {
							cancel: (input) => trackedControl("cancel", input, () =>
								cancelDeliveryInExistingTransaction(
									rawTransaction,
									input,
									this.deliverySchemaOptions,
								)),
							retry: (input) => trackedControl("retry", input, () =>
								retryDeliveryInExistingTransaction(
									rawTransaction,
									{ ...input, quota: this.deliveryQuotaPolicy },
									this.deliverySchemaOptions,
								)),
							replay: (input) => trackedControl("replay", input, () =>
								replayDeliveryInExistingTransaction(
									rawTransaction,
									{
										...input,
										quota: this.deliveryQuotaPolicy,
									},
									this.deliveryKeyring!,
									this.deliverySchemaOptions,
								)),
						}
					: undefined;
			const pendingWebhookFanouts: Promise<unknown>[] = [];
			const fanoutWebhookEndpoints: ManagementWebhookEndpointFanout | undefined =
				this.deliveryKeyring
					? (input) => {
							const occurredAt = input.occurredAt.toISOString();
							const sourceGeneration = input.context.correlationId ?? occurredAt;
							const pending = fanoutOrganizationUpdatedWebhookInExistingTransaction(
								rawTransaction,
								{
									projectId: input.context.scope.projectId,
									environmentId: input.context.scope.environmentId,
									sourceKey: `organization.updated:${input.organization.id}:${sourceGeneration}`,
									event: {
										occurredAt,
										data: {
											organization: {
												id: input.organization.id,
												name: input.organization.name,
												slug: input.organization.slug,
												status: input.organization.status,
											},
											previous: input.before,
										},
									},
									organizationId: input.organization.id,
									actorId: input.context.actor,
									...(input.context.correlationId
										? { correlationId: input.context.correlationId }
										: {}),
									semanticExpiresAt: new Date(
										input.occurredAt.getTime() + MANAGEMENT_WEBHOOK_TTL_MS,
									),
									quota: this.deliveryQuotaPolicy,
									now: input.occurredAt,
								},
								this.deliveryKeyring!,
								this.deliverySchemaOptions,
							).then((results) =>
								results.map(({ endpoint, delivery }) => {
									if (!endpoint.url) {
										throw new Error(
											`Active webhook endpoint ${endpoint.id} has no destination URL`,
										);
									}
									return {
										endpointId: endpoint.id,
										destinationUrl: endpoint.url,
										delivery,
									};
								}),
							);
							pendingWebhookFanouts.push(pending);
							return pending;
						}
					: undefined;

			let value!: T;
			let callbackError: unknown;
			let callbackFailed = false;
			try {
				value = await fn({
					data: base,
					...(principals ? { principals } : {}),
					...(topology ? { topology } : {}),
					appendAudit,
					query,
					...(enqueueDelivery ? { enqueueDelivery } : {}),
					...(controlDelivery ? { controlDelivery } : {}),
					...(fanoutWebhookEndpoints ? { fanoutWebhookEndpoints } : {}),
				});
			} catch (error) {
				callbackFailed = true;
				callbackError = error;
			}
			queryActive = false;
			principalTransaction?.revoke();
			topologyTransaction?.revoke();
			auditActive = false;
			// A caller cannot accidentally commit product state before an issued
			// outbox/control write settles by forgetting to await the returned
			// promise. Settle issued work even when the callback throws so no query or
			// rejection can escape after this transaction starts rolling back.
			const issued = await Promise.allSettled([
				...pendingDeliveryEnqueues,
				...pendingDeliveryControls,
				...pendingWebhookFanouts,
				...(principalTransaction ? [principalTransaction.settleIssued()] : []),
				...(topologyTransaction ? [topologyTransaction.settleIssued()] : []),
			]);
			issued.push(...await settleIssuedQueries());
			if (callbackFailed) throw callbackError;
			const failed = issued.find(
				(result): result is PromiseRejectedResult => result.status === "rejected",
			);
			if (failed) throw failed.reason;
			committedValue = value;
			await principalTransaction?.finalizeState();
			const appendedEvents = phase === "hybrid"
				? consumeDeferredAuditEvents(base)
				: undefined;
			if (
				topologyTransaction?.hasMutations() &&
				(appendedEvents?.length ?? base.events.length - before.events.length) === 0
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_AUDIT_REQUIRED",
					"Changed relational topology transactions must append an audit event.",
				);
			}
			await topologyTransaction?.finalizeState();

			const sync = await this.storeV2Shadow?.syncTransaction(
				client,
				before,
				base,
				revision,
				appendedEvents,
			);
			await this.syncUniqueness(
				client,
				base,
				sync?.authoritativeCollections ?? [],
			);
			const persisted = sync?.persistedSnapshot ?? base;
			const materialized = await this.materializeStoreV2Candidate(
				client,
				base,
				previousRevision,
				sync,
			);
			const principalCount = await this.resolvePrincipalCount(
				client,
				sync?.authoritativeCollections ?? [],
			);
			await client.query(
				`INSERT INTO ${this.table} (id, data, revision, updated_at)
         VALUES (1, $1::jsonb, $2, now())
         ON CONFLICT (id) DO UPDATE
         SET data = EXCLUDED.data,
             revision = EXCLUDED.revision,
             updated_at = now()`,
				[JSON.stringify(persisted), revision],
			);
			await client.query("COMMIT");
			committed = true;
			release();
			await this.publishCommittedStoreV2Snapshot({
				snapshot: materialized,
				principalCount,
				revision,
				phase: sync?.phase ?? phase,
				authoritativeCollections: sync?.authoritativeCollections ?? [],
				principalRevision: sync?.principalRevision ?? null,
				topologyState: sync?.topologyState ?? null,
			}).catch(() => undefined);
			return value;
		} catch (error) {
			if (committed) return committedValue;
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			release();
		}
	}

	private mutateWebhookEndpoint<T>(
		input: DeliveryControlScope & DeliveryControlAuditContext,
		action: "create" | "update" | "rotate" | "delete" | "test",
		operation: (transaction: DeliveryRawTransaction) => Promise<T>,
		metadata: (result: NonNullable<T>) => Record<string, unknown> & { endpointId: string },
	): Promise<T> {
		return this.queueCoordinated(async ({ data, query }) => {
			const transaction: DeliveryRawTransaction = {
				rawTransactionQuery: async <
					Row extends Record<string, unknown> = Record<string, unknown>,
				>(text: string, values?: readonly unknown[]) => {
					const result = await query(
						text,
						values === undefined ? undefined : [...values],
					);
					return {
						rows: result.rows as Row[],
						rowCount: result.rowCount,
					};
				},
			};
			const result = await operation(transaction);
			if (result === null) return null;
			const { endpointId, ...safeMetadata } = metadata(result as NonNullable<T>);
			appendAuditEvent(data, {
				actor: input.actor,
				action: `delivery.webhook_endpoints.${action}`,
				subjectType: "webhook_endpoint",
				subjectId: endpointId,
				outcome: "success",
				source: input.source,
				projectId: input.projectId,
				environmentId: input.environmentId,
				correlationId: input.correlationId,
				message: `Webhook endpoint ${action} completed`,
				metadata: safeMetadata,
			});
			return result;
		}) as Promise<T>;
	}

	/**
	 * Rebuild uniqueness tables from snapshot inside the open transaction.
	 * Primary keys enforce same-email / same-slug within project+environment.
	 * Concurrent writers serialize on snapshot FOR UPDATE; app checks catch
	 * duplicates first, and these constraints fail closed as a second layer.
	 */
	private async syncUniqueness(
		client: pg.PoolClient,
		snapshot: DataStoreSnapshot,
		authoritativeCollections: readonly StoreV2Collection[] = [],
	): Promise<void> {
		const principalsAuthoritative = authoritativeCollections.includes("principals");
		const topologyAuthoritative = [
			"projects",
			"environments",
			"organizations",
		].every((collection) =>
			authoritativeCollections.includes(collection as StoreV2Collection),
		);
		if (!principalsAuthoritative) {
			await client.query(`DELETE FROM ${this.emailUniqueTable}`);
		}
		if (!topologyAuthoritative) {
			await client.query(`DELETE FROM ${this.slugUniqueTable}`);
		}

		if (!principalsAuthoritative) {
			for (const p of snapshot.principals) {
				if (p.status === "deleted") continue;
				await client.query(
				`INSERT INTO ${this.emailUniqueTable}
         (project_id, environment_id, email_lower, principal_id)
         VALUES ($1, $2, $3, $4)`,
				[
					p.projectId,
					p.environmentId,
					p.email.toLowerCase(),
					p.id,
				],
				);
			}
		}

		if (!topologyAuthoritative) {
			for (const o of snapshot.organizations) {
				if (o.status === "archived") continue;
				await client.query(
					`INSERT INTO ${this.slugUniqueTable}
         (project_id, environment_id, slug, organization_id)
         VALUES ($1, $2, $3, $4)`,
					[o.projectId, o.environmentId, o.slug, o.id],
				);
			}
		}
	}

	private async materializeStoreV2Candidate(
		client: pg.PoolClient,
		candidate: DataStoreSnapshot,
		previousRevision: number,
		sync: StoreV2SyncResult | undefined,
	): Promise<DataStoreSnapshot> {
		if (!sync) return candidate;
		let materialized = candidate;
		if (sync.authoritativeCollections.includes("events")) {
			const events = sync.eventDelta && previousRevision === this.revision
				? applyStoreV2EventDelta(this.data.events, sync.eventDelta)
				: await this.storeV2Shadow!.materializeEvents(client);
			materialized = { ...materialized, events };
		}
		if (sync.authoritativeCollections.includes("principals")) {
			materialized = { ...materialized, principals: [] };
		}
		if (
			["projects", "environments", "organizations"].every((collection) =>
				sync.authoritativeCollections.includes(collection as StoreV2Collection),
			)
		) {
			materialized = {
				...materialized,
				projects: [],
				environments: [],
				organizations: [],
			};
		}
		return materialized;
	}

	private async resolvePrincipalCount(
		client: pg.PoolClient,
		authoritativeCollections: readonly StoreV2Collection[],
	): Promise<number> {
		if (!authoritativeCollections.includes("principals")) {
			return 0;
		}
		const state = await this.storeV2Shadow!.principalState(client);
		if (!state) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPAL_STATE_INVALID",
				"Principal authority state metadata is missing or invalid.",
			);
		}
		return state.count;
	}

	/** Initial insert path used only from init when the row is missing. */
	private async persistLocked(
		data: DataStoreSnapshot,
		fromRevision: number,
	): Promise<void> {
		const newRevision = fromRevision + 1;
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(
				`INSERT INTO ${this.table} (id, data, revision, updated_at)
         VALUES (1, $1::jsonb, $2, now())
         ON CONFLICT (id) DO UPDATE
         SET data = EXCLUDED.data,
             revision = EXCLUDED.revision,
             updated_at = now()`,
				[JSON.stringify(data), newRevision],
			);
			await this.syncUniqueness(client, data);
			await client.query("COMMIT");
			this.data = data;
			this.revision = newRevision;
		} catch (e) {
			try {
				await client.query("ROLLBACK");
			} catch {
				/* ignore */
			}
			throw e;
		} finally {
			client.release();
		}
	}
}

export async function createPgStore(
	databaseUrl: string,
	opts?: {
		backupDir?: string;
		tableName?: string;
		normalizedPrefix?: string;
		delivery?: PgStoreDeliveryOptions;
		runtimeAudit?: RuntimeAuditStoreOptions;
	},
): Promise<PgStore> {
	const store = new PgStore(databaseUrl, opts);
	await store.init();
	return store;
}

export function pgStoreId(): string {
	return `pg_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
}

export { CLEARANCE_RELEASE_VERSION, STORE_SCHEMA_VERSION };
