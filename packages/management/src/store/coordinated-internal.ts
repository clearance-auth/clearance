import type {
	InternalManagementCoordinatedMutationContext,
	ManagementStore,
} from "./types.js";

export type InternalCoordinatedExecutor = <T>(
	fn: (
		context: InternalManagementCoordinatedMutationContext,
	) => Promise<T> | T,
) => Promise<T>;

/**
 * A transaction capability borrowed from the runtime. It deliberately exposes
 * only SQL execution: the management store must never begin, commit, roll
 * back, or acquire a second connection around it.
 */
export type InternalExistingTransaction = Readonly<{
	rawTransactionQuery<Row extends Record<string, unknown> = Record<string, unknown>>(
		sql: string,
		params?: readonly unknown[],
	): Promise<{ rows: Row[]; rowCount: number | null }>;
}>;

export type InternalExternalCoordinatedExecutor = <T>(
	transaction: InternalExistingTransaction,
	fn: (
		context: InternalManagementCoordinatedMutationContext,
	) => Promise<T> | T,
) => Promise<T>;

const INTERNAL_COORDINATED_EXECUTORS = new WeakMap<
	ManagementStore,
	InternalCoordinatedExecutor
>();
const INTERNAL_EXTERNAL_COORDINATED_EXECUTORS = new WeakMap<
	ManagementStore,
	InternalExternalCoordinatedExecutor
>();

export function registerInternalCoordinatedExecutor(
	store: ManagementStore,
	executor: InternalCoordinatedExecutor,
): void {
	INTERNAL_COORDINATED_EXECUTORS.set(store, executor);
}

/** Register the Postgres-only shared-runtime-transaction path. */
export function registerInternalExternalCoordinatedExecutor(
	store: ManagementStore,
	executor: InternalExternalCoordinatedExecutor,
): void {
	INTERNAL_EXTERNAL_COORDINATED_EXECUTORS.set(store, executor);
}

export function wrapInternalCoordinatedExecutor(
	store: ManagementStore,
	wrap: (
		original: InternalCoordinatedExecutor,
	) => InternalCoordinatedExecutor,
): () => void {
	const original = INTERNAL_COORDINATED_EXECUTORS.get(store);
	if (!original) throw new Error("Internal coordinated executor unavailable");
	const wrapped = wrap(original);
	INTERNAL_COORDINATED_EXECUTORS.set(store, wrapped);
	return () => {
		if (INTERNAL_COORDINATED_EXECUTORS.get(store) === wrapped) {
			INTERNAL_COORDINATED_EXECUTORS.set(store, original);
		}
	};
}

/**
 * Package-internal runtime-table SQL path. This module is intentionally absent
 * from the package barrel and public package exports.
 */
export function mutateCoordinatedWithRuntimeSql<T>(
	store: ManagementStore,
	fn: (
		context: InternalManagementCoordinatedMutationContext,
	) => Promise<T> | T,
): Promise<T> {
	const executor = INTERNAL_COORDINATED_EXECUTORS.get(store);
	if (executor) return executor(fn);
	if (typeof store.mutateCoordinated !== "function") {
		return Promise.reject(new Error("Coordinated Postgres mutation unavailable"));
	}
	// Test doubles may provide the richer internal context. Production PgStore
	// instances always resolve through the private WeakMap executor above.
	return store.mutateCoordinated<T>(fn as Parameters<
		NonNullable<ManagementStore["mutateCoordinated"]>
	>[0] as (
		context: Parameters<
			Parameters<NonNullable<ManagementStore["mutateCoordinated"]>>[0]
		>[0],
	) => Promise<T> | T);
}

/**
 * Run the full private coordinated-management draft against an already active
 * runtime transaction. This is intentionally unavailable to public store
 * callers so a pool-shaped object cannot be mistaken for a live transaction.
 */
export function mutateCoordinatedInExistingTransaction<T>(
	store: ManagementStore,
	transaction: InternalExistingTransaction,
	fn: (
		context: InternalManagementCoordinatedMutationContext,
	) => Promise<T> | T,
): Promise<T> {
	const executor = INTERNAL_EXTERNAL_COORDINATED_EXECUTORS.get(store);
	if (!executor) {
		return Promise.reject(
			new Error("External coordinated Postgres transaction unavailable"),
		);
	}
	return executor(transaction, fn);
}
