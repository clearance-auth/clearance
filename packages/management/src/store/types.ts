import type {
	AuditEvent,
	DataStoreSnapshot,
} from "../types/resources.js";
import type { PageCursorKey } from "../services/pagination.js";
import type { ResourceScope } from "../services/scope.js";
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
	schemaVersion: 1 | null;
	phase: StoreV2Phase;
	snapshotRevision: number;
	relationalRevision: number | null;
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
	schemaVersion: 1;
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
	}): Promise<{ events: AuditEvent[]; hasMore: boolean }>;
}

/** Read-only view used by domain queries and validation. */
export interface ManagementSnapshotReader {
	readonly snapshot: DataStoreSnapshot;
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

/**
 * Same-transaction delivery mutations. Implementations own the management
 * audit append; callers cannot obtain the underlying unaudited SQL primitive.
 */
export interface ManagementDeliveryControlMutation {
	cancel(input: DeliveryControlMutationInput): Promise<PublicDeliveryJob | null>;
	retry(input: DeliveryControlMutationInput): Promise<PublicDeliveryJob | null>;
	replay(input: DeliveryControlMutationInput & { maxAttempts?: number }): Promise<EnqueuedDelivery | null>;
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
	/** Present only when PostgreSQL delivery storage and keys are configured. */
	readonly deliveryControl?: ManagementDeliveryControlReader;
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
	 * Postgres only: one transaction covering management snapshot (+ uniqueness +
	 * audit via the mutator) and arbitrary runtime SQL on the same connection.
	 * JsonStore does not implement this — callers must use management-only paths.
	 */
	mutateCoordinated?<T>(
		fn: (ctx: {
			data: DataStoreSnapshot;
			query: (
				sql: string,
				params?: unknown[],
			) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
			/** Opaque same-transaction outbox capability when delivery is configured. */
			enqueueDelivery?: (
				input: EnqueueDeliveryInput,
			) => Promise<EnqueuedDelivery>;
			/** Audited same-transaction delivery controls when configured. */
			controlDelivery?: ManagementDeliveryControlMutation;
		}) => Promise<T> | T,
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
