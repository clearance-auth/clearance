import type { AsyncLocalStorage } from "node:async_hooks";
import { getAsyncLocalStorage } from "@clearance/core/async_hooks";
import type { DBAdapter, DBTransactionAdapter } from "../db/adapter";
import type { ClearanceOptions } from "../types";
import { __getClearanceGlobal } from "./global";

type StoredAdapter = DBTransactionAdapter<ClearanceOptions>;

type HookContext = {
	rootAdapter: object;
	adapter: StoredAdapter;
	activeTransactions: ReadonlyMap<object, HookContext>;
	pendingBeforeCommitHooks: Array<() => Promise<void>>;
	pendingHooks: Array<() => Promise<void>>;
	isTransactionActive: boolean;
	parent?: HookContext | undefined;
};

function ownsAdapter(store: HookContext, adapter: object): boolean {
	return store.rootAdapter === adapter || store.adapter === adapter;
}

function findAdapterContext(
	store: HookContext | undefined,
	adapter: object,
): HookContext | undefined {
	const active = store?.activeTransactions.get(adapter);
	if (active?.isTransactionActive) return active;
	for (let current = store; current; current = current.parent) {
		if (ownsAdapter(current, adapter)) return current;
	}
	return undefined;
}

function ownerView(owner: HookContext, current: HookContext): HookContext {
	return {
		rootAdapter: owner.rootAdapter,
		adapter: owner.adapter,
		activeTransactions: current.activeTransactions,
		pendingBeforeCommitHooks: owner.pendingBeforeCommitHooks,
		pendingHooks: owner.pendingHooks,
		isTransactionActive: owner.isTransactionActive,
		parent: current,
	};
}

function runInOwnerContext<R>(
	als: AsyncLocalStorage<HookContext>,
	owner: HookContext,
	current: HookContext | undefined,
	fn: () => R,
): R | Promise<Awaited<R>> {
	if (owner === current || !current) return fn();
	return als.run(ownerView(owner, current), fn);
}

function findActiveTransactionContext(
	store: HookContext | undefined,
	adapter: object,
): HookContext | undefined {
	const registered = store?.activeTransactions.get(adapter);
	if (registered?.isTransactionActive) return registered;
	for (let current = store; current; current = current.parent) {
		if (current.isTransactionActive && ownsAdapter(current, adapter)) {
			return current;
		}
	}
	return undefined;
}

/**
 * The database transaction committed, but one or more best-effort publication
 * hooks failed afterward. Callers that retain the committed result may recover
 * without confusing this boundary with a rollback or commit failure.
 */
export class AfterTransactionHookError extends Error {
	readonly errors: readonly unknown[];

	constructor(errors: readonly unknown[]) {
		super("One or more after-transaction hooks failed", {
			cause: errors[0],
		});
		this.name = "AfterTransactionHookError";
		this.errors = errors;
	}
}

/** A non-transactional operation completed, then one or more hooks failed. */
export class AfterOperationHookError extends Error {
	readonly errors: readonly unknown[];

	constructor(errors: readonly unknown[]) {
		super("One or more after-operation hooks failed", {
			cause: errors[0],
		});
		this.name = "AfterOperationHookError";
		this.errors = errors;
	}
}

const ensureAsyncStorage = async () => {
	const clearanceGlobal = __getClearanceGlobal();
	if (!clearanceGlobal.context.adapterAsyncStorage) {
		const AsyncLocalStorage = await getAsyncLocalStorage();
		clearanceGlobal.context.adapterAsyncStorage = new AsyncLocalStorage();
	}
	return clearanceGlobal.context
		.adapterAsyncStorage as AsyncLocalStorage<HookContext>;
};

/**
 * This is for internal use only. Most users should use `getCurrentAdapter` instead.
 *
 * It is exposed for advanced use cases where you need direct access to the AsyncLocalStorage instance.
 */
export const getCurrentDBAdapterAsyncLocalStorage = async () => {
	return ensureAsyncStorage();
};

export const isTransactionActive = async (
	adapter?: object,
): Promise<boolean> => {
	try {
		const store = (await ensureAsyncStorage()).getStore();
		return adapter
			? findActiveTransactionContext(store, adapter) !== undefined
			: store?.isTransactionActive === true;
	} catch {
		return false;
	}
};

export const getCurrentAdapter = async <
	Options extends ClearanceOptions = ClearanceOptions,
>(
	fallback: DBTransactionAdapter<Options>,
): Promise<DBTransactionAdapter<Options>> => {
	return ensureAsyncStorage()
		.then((als) => {
			const store = findAdapterContext(als.getStore(), fallback);
			return (
				(store?.adapter as DBTransactionAdapter<Options> | undefined) ||
				fallback
			);
		})
		.catch(() => {
			return fallback;
		});
};

export const runWithAdapter = async <
	R,
	Options extends ClearanceOptions = ClearanceOptions,
>(
	adapter: DBAdapter<Options>,
	fn: () => R,
): Promise<R> => {
	let called = false;
	return ensureAsyncStorage()
		.then(async (als) => {
			called = true;
			const activeStore = als.getStore();
			const matchingTransaction = findActiveTransactionContext(
				activeStore,
				adapter,
			);
			if (matchingTransaction) {
				return runInOwnerContext(
					als,
					matchingTransaction,
					activeStore,
					fn,
				);
			}
			const pendingHooks: Array<() => Promise<void>> = [];
			const activeTransactions =
				activeStore?.activeTransactions ?? new Map<object, HookContext>();
			let result: Awaited<R>;
			let error: unknown;
			let hasError = false;
			try {
				result = await als.run(
					{
						rootAdapter: adapter,
						adapter: adapter as unknown as StoredAdapter,
						activeTransactions,
						pendingBeforeCommitHooks: [],
						pendingHooks,
						isTransactionActive: false,
						parent: activeStore,
					},
					fn,
				);
			} catch (err) {
				error = err;
				hasError = true;
			}
			// Hooks describe successful work and run only after the operation returns.
			if (hasError) {
				throw error;
			}
			const hookErrors: unknown[] = [];
			for (const hook of pendingHooks) {
				try {
					await hook();
				} catch (error) {
					hookErrors.push(error);
				}
			}
			if (hookErrors.length > 0) {
				throw new AfterOperationHookError(hookErrors);
			}
			return result!;
		})
		.catch((err) => {
			if (!called) {
				return fn();
			}
			throw err;
		});
};

export const runWithTransaction = async <
	R,
	Options extends ClearanceOptions = ClearanceOptions,
>(
	adapter: DBAdapter<Options>,
	fn: () => R,
): Promise<R> => {
	return ensureAsyncStorage()
		.then(async (als) => {
			const store = als.getStore();
			const matchingTransaction = findActiveTransactionContext(store, adapter);
			if (matchingTransaction) {
				return runInOwnerContext(als, matchingTransaction, store, fn);
			}
			// An adapter may re-invoke its transaction callback as part of a
			// whole-transaction retry. Keep each callback attempt's hooks local so
			// hooks from an abandoned attempt cannot escape after the eventual
			// commit. A successful callback replaces this reference; retrying
			// adapters invoke callbacks serially and return the last committed result.
			let committedPendingHooks: Array<() => Promise<void>> = [];
			let result: Awaited<R>;
			let error: unknown;
			let hasError = false;
			try {
				result = await adapter.transaction(async (trx) => {
					const pendingBeforeCommitHooks: Array<() => Promise<void>> = [];
					const pendingHooks: Array<() => Promise<void>> = [];
					const activeTransactions = new Map(
						store?.activeTransactions ?? [],
					);
					const transactionContext: HookContext = {
						rootAdapter: adapter,
						adapter: trx as unknown as StoredAdapter,
						activeTransactions,
						pendingBeforeCommitHooks,
						pendingHooks,
						isTransactionActive: true,
						parent: store,
					};
					activeTransactions.set(adapter, transactionContext);
					activeTransactions.set(trx, transactionContext);
					const transactionResult = await als.run(transactionContext, async () => {
						const transactionResult = await fn();
						for (const hook of pendingBeforeCommitHooks) {
							await hook();
						}
						return transactionResult;
					});
					committedPendingHooks = pendingHooks;
					return transactionResult;
				});
			} catch (e) {
				hasError = true;
				error = e;
			}
			if (hasError) {
				throw error;
			}
			const hookErrors: unknown[] = [];
			for (const hook of committedPendingHooks) {
				try {
					await hook();
				} catch (error) {
					hookErrors.push(error);
				}
			}
			if (hookErrors.length > 0) {
				throw new AfterTransactionHookError(hookErrors);
			}
			return result!;
		});
};

/**
 * Queue rollback-critical work after the transaction body succeeds and before
 * the adapter commits. A hook failure rejects the transaction callback so the
 * database rolls back. Outside a transaction the hook executes immediately.
 */
export const queueBeforeTransactionCommitHook = async (
	hook: () => Promise<void>,
	adapter?: object,
): Promise<void> => {
	let als: AsyncLocalStorage<HookContext>;
	try {
		als = await ensureAsyncStorage();
	} catch {
		return hook();
	}

	const store = als.getStore();
	const owner = adapter
		? findActiveTransactionContext(store, adapter)
		: store?.isTransactionActive
			? store
			: undefined;
	if (owner) {
		owner.pendingBeforeCommitHooks.push(hook);
		return;
	}
	await hook();
};

/**
 * Queue a hook to be executed after the current transaction commits.
 * If not in a transaction, the hook will execute immediately.
 */
export const queueAfterTransactionHook = async (
	hook: () => Promise<void>,
	adapter?: object,
): Promise<void> => {
	let als: AsyncLocalStorage<HookContext>;
	try {
		als = await ensureAsyncStorage();
	} catch {
		// No async storage available, execute immediately.
		return hook();
	}

	const store = als.getStore();
	const owner = adapter ? findAdapterContext(store, adapter) : store;
	if (owner) {
		// We're in a transaction context, queue the hook.
		owner.pendingHooks.push(hook);
		return;
	}

	// Not in a transaction, execute immediately. Hook failures propagate once.
	await hook();
};
