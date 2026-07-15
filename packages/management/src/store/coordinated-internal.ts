import type {
	InternalManagementCoordinatedMutationContext,
	ManagementStore,
} from "./types.js";

export type InternalCoordinatedExecutor = <T>(
	fn: (
		context: InternalManagementCoordinatedMutationContext,
	) => Promise<T> | T,
) => Promise<T>;

const INTERNAL_COORDINATED_EXECUTORS = new WeakMap<
	ManagementStore,
	InternalCoordinatedExecutor
>();

export function registerInternalCoordinatedExecutor(
	store: ManagementStore,
	executor: InternalCoordinatedExecutor,
): void {
	INTERNAL_COORDINATED_EXECUTORS.set(store, executor);
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
