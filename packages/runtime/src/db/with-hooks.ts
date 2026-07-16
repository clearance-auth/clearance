import type { ClearanceOptions } from "@clearance/core";
import {
	getCurrentAdapter,
	getCurrentAuthContext,
	isTransactionActive,
	queueAfterTransactionHook,
	queueBeforeTransactionCommitHook,
	runWithTransaction,
} from "@clearance/core/context";
import type { BaseModelNames } from "@clearance/core/db";
import type {
	DBAdapter,
	DBTransactionAdapter,
	Where,
} from "@clearance/core/db/adapter";
import type { InternalLogger } from "@clearance/core/env";
import {
	ATTR_CONTEXT,
	ATTR_DB_COLLECTION_NAME,
	ATTR_HOOK_TYPE,
	withSpan,
} from "@clearance/core/instrumentation";

export type DatabaseHooksEntry = {
	source: string;
	hooks: Exclude<ClearanceOptions["databaseHooks"], undefined>;
	failureMode?: "observe" | "rollback" | undefined;
};

type CustomMutation<Input> = {
	fn: (input: Input, adapter: DBTransactionAdapter) => void | Promise<any>;
	executeMainFn?: boolean | undefined;
	/** The callback performs database work only through the supplied adapter. */
	usesTransactionAdapter?: true | undefined;
};

export function getWithHooks(
	adapter: DBAdapter<ClearanceOptions>,
	ctx: {
		options: ClearanceOptions;
		hooks: DatabaseHooksEntry[];
		logger?: Pick<InternalLogger, "error"> | undefined;
	},
) {
	const hooksEntries = ctx.hooks;

	function hasRollbackAfterHook(
		model: BaseModelNames,
		operation: "create" | "update" | "delete",
	): boolean {
		return hooksEntries.some(
			({ hooks, failureMode }) =>
				failureMode === "rollback" && Boolean(hooks[model]?.[operation]?.after),
		);
	}

	function assertRollbackSafeCustomMutation(
		model: BaseModelNames,
		operation: "create" | "update" | "delete",
		customMutation: CustomMutation<any> | undefined,
	): void {
		if (
			customMutation &&
			hasRollbackAfterHook(model, operation) &&
			customMutation.usesTransactionAdapter !== true
		) {
			throw new Error(
				`Rollback-critical ${model}.${operation} hooks require custom mutations to use the supplied transaction adapter`,
			);
		}
	}

	async function queuePublicAfterHook(
		model: BaseModelNames,
		operation: "create" | "update" | "updateMany" | "delete" | "deleteMany",
		source: string,
		failureMode: "observe" | "rollback" | undefined,
		run: () => Promise<unknown>,
	): Promise<void> {
		const execute = () =>
			withSpan(
				`db ${operation}.after ${model}`,
				{
					[ATTR_HOOK_TYPE]: `${operation}.after`,
					[ATTR_DB_COLLECTION_NAME]: model,
					[ATTR_CONTEXT]: source,
				},
				run,
			);
		if (failureMode === "rollback") {
			await queueBeforeTransactionCommitHook(async () => {
				await execute();
			}, adapter);
			return;
		}
		await queueAfterTransactionHook(async () => {
			try {
				await execute();
			} catch (error) {
				ctx.logger?.error("Database after hook failed after commit", {
					model,
					operation,
					source,
					errorName: error instanceof Error ? error.name : "UnknownError",
				});
			}
		}, adapter);
	}

	async function createWithHooks<T extends Record<string, any>>(
		data: T,
		model: BaseModelNames,
		customCreateFn?: CustomMutation<Record<string, any>> | undefined,
		enforceData?: ((data: T) => T) | undefined,
	): Promise<any> {
		assertRollbackSafeCustomMutation(model, "create", customCreateFn);
		if (
			hasRollbackAfterHook(model, "create") &&
			!(await isTransactionActive(adapter))
		) {
			return runWithTransaction(adapter, () =>
				createWithHooks(data, model, customCreateFn, enforceData),
			);
		}
		const context = await getCurrentAuthContext().catch(() => null);
		let actualData = data;
		for (const { source, hooks } of hooksEntries) {
			const toRun = hooks[model]?.create?.before;
			if (toRun) {
				const result = await withSpan(
					`db create.before ${model}`,
					{
						[ATTR_HOOK_TYPE]: "create.before",
						[ATTR_DB_COLLECTION_NAME]: model,
						[ATTR_CONTEXT]: source,
					},
					() =>
						// @ts-expect-error context type mismatch
						toRun(actualData as any, context),
				);
				if (result === false) {
					return null;
				}
				const isObject = typeof result === "object" && "data" in result;
				if (isObject) {
					actualData = {
						...actualData,
						...result.data,
					};
				}
			}
		}
		actualData = enforceData ? enforceData(actualData) : actualData;

		let created: any = null;
		if (!customCreateFn || customCreateFn.executeMainFn) {
			created = await (await getCurrentAdapter(adapter)).create<T>({
				model,
				data: actualData as any,
				forceAllowId: true,
			});
		}
		if (customCreateFn?.fn) {
			created = await customCreateFn.fn(
				created ?? actualData,
				await getCurrentAdapter(adapter),
			);
		}

		for (const { source, hooks, failureMode } of hooksEntries) {
			const toRun = hooks[model]?.create?.after;
			if (toRun) {
				await queuePublicAfterHook(model, "create", source, failureMode, () =>
					// @ts-expect-error context type mismatch
					toRun(created as any, context),
				);
			}
		}

		return created;
	}

	async function updateWithHooks<T extends Record<string, any>>(
		data: any,
		where: Where[],
		model: BaseModelNames,
		customUpdateFn?: CustomMutation<Record<string, any>> | undefined,
		enforceData?: ((data: T) => T) | undefined,
	): Promise<any> {
		assertRollbackSafeCustomMutation(model, "update", customUpdateFn);
		if (
			hasRollbackAfterHook(model, "update") &&
			!(await isTransactionActive(adapter))
		) {
			return runWithTransaction(adapter, () =>
				updateWithHooks(data, where, model, customUpdateFn, enforceData),
			);
		}
		const context = await getCurrentAuthContext().catch(() => null);
		let actualData = data;

		for (const { source, hooks } of hooksEntries) {
			const toRun = hooks[model]?.update?.before;
			if (toRun) {
				const result = await withSpan(
					`db update.before ${model}`,
					{
						[ATTR_HOOK_TYPE]: "update.before",
						[ATTR_DB_COLLECTION_NAME]: model,
						[ATTR_CONTEXT]: source,
					},
					() =>
						// @ts-expect-error context type mismatch
						toRun(data as any, context),
				);
				if (result === false) {
					return null;
				}
				const isObject = typeof result === "object" && "data" in result;
				if (isObject) {
					actualData = {
						...actualData,
						...result.data,
					};
				}
			}
		}
		actualData = enforceData ? enforceData(actualData) : actualData;

		const customUpdated = customUpdateFn
			? await customUpdateFn.fn(actualData, await getCurrentAdapter(adapter))
			: null;

		const updated =
			!customUpdateFn || customUpdateFn.executeMainFn
				? await (await getCurrentAdapter(adapter)).update<T>({
						model,
						update: actualData,
						where,
					})
				: customUpdated;

		for (const { source, hooks, failureMode } of hooksEntries) {
			const toRun = hooks[model]?.update?.after;
			if (toRun) {
				await queuePublicAfterHook(model, "update", source, failureMode, () =>
					// @ts-expect-error context type mismatch
					toRun(updated as any, context),
				);
			}
		}
		return updated;
	}

	async function updateManyWithHooks<_T extends Record<string, any>>(
		data: any,
		where: Where[],
		model: BaseModelNames,
		customUpdateFn?: CustomMutation<Record<string, any>> | undefined,
	): Promise<any> {
		assertRollbackSafeCustomMutation(model, "update", customUpdateFn);
		if (
			hasRollbackAfterHook(model, "update") &&
			!(await isTransactionActive(adapter))
		) {
			return runWithTransaction(adapter, () =>
				updateManyWithHooks(data, where, model, customUpdateFn),
			);
		}
		const context = await getCurrentAuthContext().catch(() => null);
		let actualData = data;

		for (const { source, hooks } of hooksEntries) {
			const toRun = hooks[model]?.update?.before;
			if (toRun) {
				const result = await withSpan(
					`db updateMany.before ${model}`,
					{
						[ATTR_HOOK_TYPE]: "updateMany.before",
						[ATTR_DB_COLLECTION_NAME]: model,
						[ATTR_CONTEXT]: source,
					},
					() =>
						// @ts-expect-error context type mismatch
						toRun(data as any, context),
				);
				if (result === false) {
					return null;
				}
				const isObject = typeof result === "object" && "data" in result;
				if (isObject) {
					actualData = {
						...actualData,
						...result.data,
					};
				}
			}
		}

		const customUpdated = customUpdateFn
			? await customUpdateFn.fn(actualData, await getCurrentAdapter(adapter))
			: null;

		const updated =
			!customUpdateFn || customUpdateFn.executeMainFn
				? await (await getCurrentAdapter(adapter)).updateMany({
						model,
						update: actualData,
						where,
					})
				: customUpdated;

		for (const { source, hooks, failureMode } of hooksEntries) {
			const toRun = hooks[model]?.update?.after;
			if (toRun) {
				await queuePublicAfterHook(model, "updateMany", source, failureMode, () =>
					// @ts-expect-error context type mismatch
					toRun(updated as any, context),
				);
			}
		}

		return updated;
	}

	async function deleteWithHooks<T extends Record<string, any>>(
		where: Where[],
		model: BaseModelNames,
		customDeleteFn?: CustomMutation<Where[]> | undefined,
	): Promise<any> {
		assertRollbackSafeCustomMutation(model, "delete", customDeleteFn);
		if (
			hasRollbackAfterHook(model, "delete") &&
			!(await isTransactionActive(adapter))
		) {
			return runWithTransaction(adapter, () =>
				deleteWithHooks(where, model, customDeleteFn),
			);
		}
		const context = await getCurrentAuthContext().catch(() => null);
		let entityToDelete: T | null = null;

		try {
			const entities = await (await getCurrentAdapter(adapter)).findMany<T>({
				model,
				where,
				limit: 1,
			});
			entityToDelete = entities[0] || null;
		} catch {
			// If we can't find the entity, we'll still proceed with deletion
		}

		if (entityToDelete) {
			for (const { source, hooks } of hooksEntries) {
				const toRun = hooks[model]?.delete?.before;
				if (toRun) {
					const result = await withSpan(
						`db delete.before ${model}`,
						{
							[ATTR_HOOK_TYPE]: "delete.before",
							[ATTR_DB_COLLECTION_NAME]: model,
							[ATTR_CONTEXT]: source,
						},
						() =>
							// @ts-expect-error context type mismatch
							toRun(entityToDelete as any, context),
					);
					if (result === false) {
						return null;
					}
				}
			}
		}

		const customDeleted = customDeleteFn
			? await customDeleteFn.fn(where, await getCurrentAdapter(adapter))
			: null;

		const shouldRunAdapterDelete =
			!customDeleteFn || customDeleteFn.executeMainFn;
		const deleted =
			shouldRunAdapterDelete && entityToDelete
				? await (await getCurrentAdapter(adapter)).delete({
						model,
						where,
					})
				: customDeleted;

		if (entityToDelete) {
			for (const { source, hooks, failureMode } of hooksEntries) {
				const toRun = hooks[model]?.delete?.after;
				if (toRun) {
					await queuePublicAfterHook(model, "delete", source, failureMode, () =>
						// @ts-expect-error context type mismatch
						toRun(entityToDelete as any, context),
					);
				}
			}
		}

		return deleted;
	}

	async function deleteManyWithHooks<T extends Record<string, any>>(
		where: Where[],
		model: BaseModelNames,
		customDeleteFn?: CustomMutation<Where[]> | undefined,
	): Promise<any> {
		assertRollbackSafeCustomMutation(model, "delete", customDeleteFn);
		if (
			hasRollbackAfterHook(model, "delete") &&
			!(await isTransactionActive(adapter))
		) {
			return runWithTransaction(adapter, () =>
				deleteManyWithHooks(where, model, customDeleteFn),
			);
		}
		const context = await getCurrentAuthContext().catch(() => null);
		let entitiesToDelete: T[] = [];

		try {
			entitiesToDelete = await (await getCurrentAdapter(adapter)).findMany<T>({
				model,
				where,
			});
		} catch {
			// If we can't find the entities, we'll still proceed with deletion
		}

		for (const entity of entitiesToDelete) {
			for (const { source, hooks } of hooksEntries) {
				const toRun = hooks[model]?.delete?.before;
				if (toRun) {
					const result = await withSpan(
						`db delete.before ${model}`,
						{
							[ATTR_HOOK_TYPE]: "delete.before",
							[ATTR_DB_COLLECTION_NAME]: model,
							[ATTR_CONTEXT]: source,
						},
						() =>
							// @ts-expect-error context type mismatch
							toRun(entity as any, context),
					);
					if (result === false) {
						return null;
					}
				}
			}
		}

		const customDeleted = customDeleteFn
			? await customDeleteFn.fn(where, await getCurrentAdapter(adapter))
			: null;

		const deleted =
			!customDeleteFn || customDeleteFn.executeMainFn
				? await (await getCurrentAdapter(adapter)).deleteMany({
						model,
						where,
					})
				: customDeleted;

		for (const entity of entitiesToDelete) {
			for (const { source, hooks, failureMode } of hooksEntries) {
				const toRun = hooks[model]?.delete?.after;
				if (toRun) {
					await queuePublicAfterHook(model, "delete", source, failureMode, () =>
						// @ts-expect-error context type mismatch
						toRun(entity as any, context),
					);
				}
			}
		}

		return deleted;
	}

	/**
	 * Wraps an atomic consume operation in the plugin `delete.before` and
	 * `delete.after` hook lifecycle. The caller supplies a `consumeFn` that
	 * performs the actual single-row delete-and-return (typically the
	 * adapter's `consumeOne`). The first concurrent caller wins, subsequent
	 * racers resolve to `null` without firing `delete.after` hooks.
	 *
	 * `preSnapshot` lets the caller hand in a row it already fetched so
	 * `delete.before` hooks don't trigger a second read. Without it, the
	 * helper falls back to a best-effort `findMany` against `hookWhere`.
	 * The snapshot only feeds `delete.before`; the `consumeFn` return value
	 * is the race gate.
	 *
	 * Returning `false` from a `delete.before` hook aborts the consume and
	 * the helper resolves to `null` (no `consumeFn` call, no after hooks).
	 */
	async function consumeOneWithHooks<T extends Record<string, any>>(
		model: BaseModelNames,
		hookWhere: Where[],
		consumeFn: (adapter: DBTransactionAdapter) => Promise<T | null>,
		preSnapshot?: T | null,
	): Promise<T | null> {
		if (
			hasRollbackAfterHook(model, "delete") &&
			!(await isTransactionActive(adapter))
		) {
			return runWithTransaction(adapter, () =>
				consumeOneWithHooks(model, hookWhere, consumeFn, preSnapshot),
			);
		}
		const context = await getCurrentAuthContext().catch(() => null);
		const beforeHooks = hooksEntries.flatMap(({ source, hooks }) => {
			const fn = hooks[model]?.delete?.before;
			return fn ? [{ source, fn }] : [];
		});

		let snapshot: T | null = preSnapshot ?? null;
		if (beforeHooks.length) {
			if (!snapshot) {
				try {
					const rows = await (await getCurrentAdapter(adapter)).findMany<T>({
						model,
						where: hookWhere,
						limit: 1,
					});
					snapshot = rows[0] || null;
				} catch {}
			}

			if (snapshot) {
				for (const { source, fn } of beforeHooks) {
					const result = await withSpan(
						`db delete.before ${model}`,
						{
							[ATTR_HOOK_TYPE]: "delete.before",
							[ATTR_DB_COLLECTION_NAME]: model,
							[ATTR_CONTEXT]: source,
						},
						() =>
							// @ts-expect-error context type mismatch
							fn(snapshot as any, context),
					);
					if (result === false) {
						return null;
					}
				}
			}
		}

		const consumed = await consumeFn(await getCurrentAdapter(adapter));
		if (!consumed) return null;

		for (const { source, hooks, failureMode } of hooksEntries) {
			const toRun = hooks[model]?.delete?.after;
			if (toRun) {
				await queuePublicAfterHook(model, "delete", source, failureMode, () =>
					// @ts-expect-error context type mismatch
					toRun(consumed as any, context),
				);
			}
		}

		return consumed;
	}

	return {
		createWithHooks,
		updateWithHooks,
		updateManyWithHooks,
		deleteWithHooks,
		deleteManyWithHooks,
		consumeOneWithHooks,
	};
}
