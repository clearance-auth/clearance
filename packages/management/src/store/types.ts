import type {
	AuditEvent,
	DataStoreSnapshot,
	Principal,
} from "../types/resources.js";
import type { PageCursorKey } from "../services/pagination.js";
import type { ResourceScope } from "../services/scope.js";
import type { RuntimeAuditEventReader } from "./runtime-audit-events.js";
import type {
	DeliveryControlPreview,
	DeliveryJobPage,
	DeliveryJobState,
	DeliveryQuotaStatus,
	DeliveryReadinessSummary,
	EnqueuedDelivery,
	EnqueueDeliveryInput,
	PublicDeliveryJob,
} from "@clearance/delivery";
import type { ManagementWebhookEndpointFanout } from "../application/delivery.js";
import type { AuditEventInput } from "../services/audit.js";

export const STORE_V2_COLLECTIONS = [
	"projects",
	"environments",
	"principals",
	"organizations",
	"events",
] as const;

export type StoreV2Collection = (typeof STORE_V2_COLLECTIONS)[number];
export type StoreV2Phase = "absent" | "shadow" | "hybrid" | "disabled";

export interface StoreV2CollectionStatus {
	snapshotCount: number;
	relationalCount: number | null;
	snapshotChecksum: string;
	relationalChecksum: string | null;
	consistent: boolean;
	differingIds: string[];
}

export interface StoreV2Status {
	schemaVersion: 2 | null;
	phase: StoreV2Phase;
	snapshotRevision: number;
	relationalRevision: number | null;
	/** Changes only when relational principal rows change or authority moves. */
	principalRevision: number | null;
	consistent: boolean;
	authoritativeCollections: StoreV2Collection[];
	collections: Record<StoreV2Collection, StoreV2CollectionStatus>;
}

export interface StoreV2PlanBlocker {
	code: string;
	collection: StoreV2Collection;
	resourceIds: string[];
}

export interface StoreV2Plan {
	schemaVersion: 2;
	phase: StoreV2Phase;
	snapshotRevision: number;
	collections: readonly StoreV2Collection[];
	rowCounts: Record<StoreV2Collection, number>;
	blockerCount: number;
	blockers: StoreV2PlanBlocker[];
	canApply: boolean;
}

export interface StoreV2MigrationControl {
	plan(): Promise<StoreV2Plan>;
	status(): Promise<StoreV2Status>;
	apply(): Promise<StoreV2Status>;
	verify(): Promise<StoreV2Status>;
	disable(): Promise<StoreV2Status>;
	cutoverEvents(): Promise<StoreV2Status>;
	rollbackEvents(): Promise<StoreV2Status>;
	cutoverPrincipals(): Promise<StoreV2Status>;
	rollbackPrincipals(): Promise<StoreV2Status>;
}

/** Postgres event reads once store-v2 events are relational-authoritative. */
export interface StoreV2EventReader {
	readonly authoritative: boolean;
	listPage(input: {
		scope: ResourceScope;
		limit: number;
		cursor?: PageCursorKey;
		action?: string;
		organizationId?: string;
		/** Strict archival upper bound for bounded exports. */
		before?: string;
	}): Promise<{ events: AuditEvent[]; hasMore: boolean }>;
}

/** PostgreSQL principal reads backed by normalized store-v2 rows. */
export interface StoreV2PrincipalReader {
	readonly authoritative: boolean;
	getById(input: {
		scope: ResourceScope;
		id: string;
		includeDeleted?: boolean;
	}): Promise<Principal | null>;
	findActiveByEmail(input: {
		scope: ResourceScope;
		email: string;
	}): Promise<Principal | null>;
	findActiveByExternalId(input: {
		scope: ResourceScope;
		externalId: string;
	}): Promise<Principal | null>;
	listPage(input: {
		scope: ResourceScope;
		limit: number;
		cursor?: PageCursorKey;
		includeDeleted?: boolean;
		status?: Principal["status"];
	}): Promise<{ principals: Principal[]; hasMore: boolean }>;
	/** Bounded relational join used by runtime session operator reads. */
	listActiveSessionsPage?(input: {
		scope: ResourceScope;
		limit: number;
		cursor?: PageCursorKey;
	}): Promise<{
		sessions: Array<{
			id: string;
			principal: Principal;
			createdAt: string;
			cursorCreatedAt: string;
			expiresAt?: string;
			ipAddress?: string;
			userAgent?: string;
		}>;
		hasMore: boolean;
	}>;
	listForExport?(input: {
		scope: ResourceScope;
		limit: number;
		status?: "active" | "disabled";
	}): Promise<{ principals: Principal[]; hasMore: boolean }>;
	countByScope?(input: { scope: ResourceScope }): Promise<{
		total: number;
		active: number;
	}>;
	countActiveSessions?(input: { scope: ResourceScope }): Promise<number>;
}

/** Transaction-bound normalized principal mutations. PostgreSQL only. */
export interface StoreV2PrincipalRepository extends StoreV2PrincipalReader {
	insert(principal: Principal): Promise<Principal>;
	update(
		principal: Principal,
		input: { expectedUpdatedAt: string },
	): Promise<Principal | null>;
	disable(input: {
		scope: ResourceScope;
		id: string;
		updatedAt: string;
		expectedUpdatedAt: string;
	}): Promise<Principal | null>;
	delete(input: {
		scope: ResourceScope;
		id: string;
		updatedAt: string;
		expectedUpdatedAt: string;
	}): Promise<Principal | null>;
}

/** Read-only view used by domain queries and validation. */
export interface ManagementSnapshotReader {
	readonly snapshot: DataStoreSnapshot;
	readonly storeV2Principals?: StoreV2PrincipalReader;
}

export type DeliveryControlScope = {
	projectId: string;
	environmentId: string;
};

/** PostgreSQL-only, redacted delivery reads bound to the configured schema. */
export interface ManagementDeliveryControlReader {
	list(input: DeliveryControlScope & {
		limit?: number;
		cursor?: string;
		states?: readonly DeliveryJobState[];
		channel?: "email" | "webhook";
		kind?: string;
	}): Promise<DeliveryJobPage>;
	inspect(input: DeliveryControlScope & { jobId: string }): Promise<PublicDeliveryJob | null>;
	preview(input: DeliveryControlScope & {
		jobId: string;
		action: "cancel" | "retry" | "replay";
		now?: Date;
		maxAttempts?: number;
	}): Promise<DeliveryControlPreview | null>;
	readiness(input?: { now?: Date; staleAfterMs?: number }): Promise<DeliveryReadinessSummary>;
	quota(input: DeliveryControlScope & { now?: Date }): Promise<DeliveryQuotaStatus>;
}

export type DeliveryControlAuditContext = {
	actor: string;
	source: AuditEvent["source"];
	correlationId?: string;
};

export type DeliveryControlMutationInput = DeliveryControlScope &
	DeliveryControlAuditContext & {
		jobId: string;
		now?: Date;
	};

export type DeliveryControlMutationOutcome<T> = {
	preview: DeliveryControlPreview;
	result: T;
};

/**
 * Same-transaction delivery mutations. Implementations own the management
 * audit append; callers cannot obtain the underlying unaudited SQL primitive.
 */
export interface ManagementDeliveryControlMutation {
	cancel(
		input: DeliveryControlMutationInput,
	): Promise<DeliveryControlMutationOutcome<PublicDeliveryJob> | null>;
	retry(
		input: DeliveryControlMutationInput,
	): Promise<DeliveryControlMutationOutcome<PublicDeliveryJob> | null>;
	replay(
		input: DeliveryControlMutationInput & { maxAttempts?: number },
	): Promise<DeliveryControlMutationOutcome<EnqueuedDelivery> | null>;
}

export type ManagementCoordinatedQuery = (
	sql: string,
	params?: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;

export interface ManagementCoordinatedMutationContext {
	data: DataStoreSnapshot;
	/** Present only when normalized principals are authoritative. */
	principals?: StoreV2PrincipalRepository;
	/** Opaque same-transaction outbox capability when delivery is configured. */
	enqueueDelivery?: (
		input: EnqueueDeliveryInput,
	) => Promise<EnqueuedDelivery>;
	/** Audited same-transaction delivery controls when configured. */
	controlDelivery?: ManagementDeliveryControlMutation;
	/** Managed endpoint fanout in the same product transaction when configured. */
	fanoutWebhookEndpoints?: ManagementWebhookEndpointFanout;
}

/** Package-internal runtime SQL seam; never exposed to public store callbacks. */
export interface InternalManagementCoordinatedMutationContext
	extends ManagementCoordinatedMutationContext {
	query: ManagementCoordinatedQuery;
}

/**
 * One atomic management-snapshot transaction. Domain services may inspect the
 * current draft and apply synchronous mutations; persistence is owned by the
 * adapter that created the unit of work.
 */
export interface ManagementUnitOfWork extends ManagementSnapshotReader {
	mutate(fn: (data: DataStoreSnapshot) => void): DataStoreSnapshot;
}

/**
 * Management control-plane store.
 * Json backend is for local dev without DATABASE_URL.
 * Postgres backend is the single transactional source of truth when DATABASE_URL is set.
 *
 * Cross-process safety (Postgres): mutations are transactionally replayed against a
 * row-locked snapshot with a monotonically increasing revision. Long-lived processes
 * must call refresh() before reads so CLI writes are visible to a running API.
 */
export interface ManagementStore extends ManagementUnitOfWork {
	/** Local path used for file-backed stores and backup directory resolution */
	readonly path: string;
	readonly backend: "json" | "postgres";
	/** Postgres-only, explicitly activated normalized shadow-store migration. */
	readonly storeV2?: StoreV2MigrationControl;
	readonly storeV2Events?: StoreV2EventReader;
	/** PostgreSQL runtime audit authority; absent on the local JSON backend. */
	readonly runtimeAuditEvents?: RuntimeAuditEventReader;
	readonly storeV2Principals?: StoreV2PrincipalReader;
	/** Direct normalized transaction, available only after principal authority. */
	mutateStoreV2Principals?<T>(
		fn: (principals: StoreV2PrincipalRepository) => Promise<T> | T,
	): Promise<T>;
	/** Relational-only identity transaction with append-only audit authority. */
	mutateStoreV2Identity?<T>(
		fn: (context: {
			principals: StoreV2PrincipalRepository;
			appendAudit(input: AuditEventInput): AuditEvent;
		}) => Promise<T> | T,
	): Promise<T>;
	/** Present only when PostgreSQL delivery storage and keys are configured. */
	readonly deliveryControl?: ManagementDeliveryControlReader;
	/** Audited customer-managed webhook endpoint lifecycle when delivery is configured. */
	readonly webhookEndpoints?: import("../services/webhook-endpoints.js").ManagementWebhookEndpointCapability;
	load(): DataStoreSnapshot;
	save(): void;
	/** Flush pending durable writes (no-op for json; await for postgres) */
	ready(): Promise<void>;
	/**
	 * Reload from durable backend when another process may have written.
	 * Json re-reads the file; Postgres compares revision and replaces local cache.
	 */
	refresh(): Promise<void>;
	replace(snapshot: DataStoreSnapshot): void;
	/**
	 * Queue a mutation. For Postgres the function is replayed inside
	 * BEGIN…SELECT FOR UPDATE…COMMIT so concurrent writers merge by replaying
	 * ops rather than last-write-wins full snapshot overwrite.
	 * Await ready() before relying on snapshot for subsequent reads.
	 */
	/** Execute against the latest durable draft and resolve only after commit. */
	mutateDurable<T>(fn: (data: DataStoreSnapshot) => T): Promise<T>;
	/**
	 * Postgres only: one transaction covering management snapshot, normalized
	 * principal mutations, uniqueness, audit, and opaque delivery capabilities.
	 * JsonStore does not implement this — callers must use management-only paths.
	 */
	mutateCoordinated?<T>(
		fn: (ctx: ManagementCoordinatedMutationContext) => Promise<T> | T,
	): Promise<T>;
	checksum(): string;
	resourceCounts(): Record<string, number>;
}

export function isManagementStore(value: unknown): value is ManagementStore {
	return (
		typeof value === "object" &&
		value !== null &&
		"snapshot" in value &&
		"mutate" in value &&
		"backend" in value
	);
}
