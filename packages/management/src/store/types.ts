import type { DataStoreSnapshot } from "../types/resources.js";

/**
 * Management control-plane store.
 * Json backend is for local dev without DATABASE_URL.
 * Postgres backend is the single transactional source of truth when DATABASE_URL is set.
 *
 * Cross-process safety (Postgres): mutations are transactionally replayed against a
 * row-locked snapshot with a monotonically increasing revision. Long-lived processes
 * must call refresh() before reads so CLI writes are visible to a running API.
 */
export interface ManagementStore {
	/** Local path used for file-backed stores and backup directory resolution */
	readonly path: string;
	readonly backend: "json" | "postgres";
	get snapshot(): DataStoreSnapshot;
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
	mutate(fn: (data: DataStoreSnapshot) => void): DataStoreSnapshot;
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
