import { describe, expect, it, vi } from "vitest";
import type { DBAdapter, DBTransactionAdapter } from "../db/adapter";
import { __getClearanceGlobal } from "./global";
import {
	AfterOperationHookError,
	AfterTransactionHookError,
	getCurrentAdapter,
	queueAfterTransactionHook,
	queueBeforeTransactionCommitHook,
	runWithAdapter,
	runWithTransaction,
} from "./transaction";

const asyncStorageControl = vi.hoisted(() => ({ fail: false }));

vi.mock("@clearance/core/async_hooks", async (importOriginal) => {
	const actual = await importOriginal<
		typeof import("@clearance/core/async_hooks")
	>();
	return {
		...actual,
		getAsyncLocalStorage: async () => {
			if (asyncStorageControl.fail) {
				throw new Error("injected async storage initialization failure");
			}
			return actual.getAsyncLocalStorage();
		},
	};
});

function createTransactionHarness() {
	let transactionCalls = 0;
	const transactionAdapter = {} as DBTransactionAdapter;
	const adapter = {
		transaction: async <R>(
			callback: (trx: DBTransactionAdapter) => Promise<R>,
		) => {
			transactionCalls += 1;
			return callback(transactionAdapter);
		},
	} as DBAdapter;

	return {
		adapter,
		transactionAdapter,
		getTransactionCalls: () => transactionCalls,
	};
}

describe("runWithTransaction", () => {
	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	it("reuses the active transaction for nested calls", async () => {
		const { adapter, transactionAdapter, getTransactionCalls } =
			createTransactionHarness();
		const adapters: DBTransactionAdapter[] = [];

		await runWithTransaction(adapter, async () => {
			adapters.push(await getCurrentAdapter(adapter));

			await runWithTransaction(adapter, async () => {
				adapters.push(await getCurrentAdapter(adapter));
			});
		});

		expect(getTransactionCalls()).toBe(1);
		expect(adapters).toEqual([transactionAdapter, transactionAdapter]);
	});

	it("still opens a transaction from a plain adapter context", async () => {
		const { adapter, transactionAdapter, getTransactionCalls } =
			createTransactionHarness();
		let activeAdapter: DBTransactionAdapter | null = null;

		await runWithAdapter(adapter, () =>
			runWithTransaction(adapter, async () => {
				activeAdapter = await getCurrentAdapter(adapter);
			}),
		);

		expect(getTransactionCalls()).toBe(1);
		expect(activeAdapter).toBe(transactionAdapter);
	});

	it("preserves an active transaction through a nested adapter context", async () => {
		const { adapter, transactionAdapter, getTransactionCalls } =
			createTransactionHarness();
		const adapters: DBTransactionAdapter[] = [];
		let hookRuns = 0;

		await runWithTransaction(adapter, async () => {
			await runWithAdapter(adapter, async () => {
				adapters.push(await getCurrentAdapter(adapter));
				await runWithTransaction(adapter, async () => {
					adapters.push(await getCurrentAdapter(adapter));
					await queueAfterTransactionHook(async () => {
						hookRuns += 1;
					});
				});
				expect(hookRuns).toBe(0);
			});
		});

		expect(getTransactionCalls()).toBe(1);
		expect(adapters).toEqual([transactionAdapter, transactionAdapter]);
		expect(hookRuns).toBe(1);
	});

	it("does not retry a failing adapter callback inside an active transaction", async () => {
		const { adapter, getTransactionCalls } = createTransactionHarness();
		let callbackCalls = 0;

		await expect(
			runWithTransaction(adapter, () =>
				runWithAdapter(adapter, () => {
					callbackCalls += 1;
					throw new Error("nested adapter work failed");
				}),
			),
		).rejects.toThrow("nested adapter work failed");

		expect(getTransactionCalls()).toBe(1);
		expect(callbackCalls).toBe(1);
	});

	it("runs hooks queued by nested calls after the outer transaction finishes", async () => {
		const { adapter, getTransactionCalls } = createTransactionHarness();
		let hookRuns = 0;
		let hookRunsInsideTransaction = 0;

		await runWithTransaction(adapter, async () => {
			await runWithTransaction(adapter, async () => {
				await queueAfterTransactionHook(async () => {
					hookRuns += 1;
				});
			});

			hookRunsInsideTransaction = hookRuns;
		});

		expect(getTransactionCalls()).toBe(1);
		expect(hookRunsInsideTransaction).toBe(0);
		expect(hookRuns).toBe(1);
	});

	it("discards after-transaction hooks when the transaction rolls back", async () => {
		const { adapter } = createTransactionHarness();
		let hookRuns = 0;

		await expect(runWithTransaction(adapter, async () => {
			await queueAfterTransactionHook(async () => {
				hookRuns += 1;
			});
			throw new Error("force rollback");
		})).rejects.toThrow("force rollback");

		expect(hookRuns).toBe(0);
	});

	it("runs rollback-critical hooks after the body and before commit", async () => {
		const events: string[] = [];
		const transactionAdapter = {} as DBTransactionAdapter;
		const adapter = {
			transaction: async <R>(
				callback: (trx: DBTransactionAdapter) => Promise<R>,
			) => {
				events.push("begin");
				const result = await callback(transactionAdapter);
				events.push("commit");
				return result;
			},
		} as DBAdapter;

		await runWithTransaction(adapter, async () => {
			await queueBeforeTransactionCommitHook(async () => {
				events.push("before-commit");
			});
			await queueAfterTransactionHook(async () => {
				events.push("after-commit");
			});
			events.push("body");
		});

		expect(events).toEqual([
			"begin",
			"body",
			"before-commit",
			"commit",
			"after-commit",
		]);
	});

	it("discards rollback-critical hooks when later transaction work fails", async () => {
		const { adapter } = createTransactionHarness();
		let hookRuns = 0;

		await expect(
			runWithTransaction(adapter, async () => {
				await queueBeforeTransactionCommitHook(async () => {
					hookRuns += 1;
				});
				throw new Error("later mutation failed");
			}),
		).rejects.toThrow("later mutation failed");
		expect(hookRuns).toBe(0);
	});

	it("fails closed before work when transaction context cannot initialize", async () => {
		const { adapter, getTransactionCalls } = createTransactionHarness();
		const clearanceGlobal = __getClearanceGlobal();
		const previousStorage = clearanceGlobal.context.adapterAsyncStorage;
		let workCalls = 0;

		delete clearanceGlobal.context.adapterAsyncStorage;
		asyncStorageControl.fail = true;
		try {
			await expect(
				runWithTransaction(adapter, async () => {
					workCalls += 1;
				}),
			).rejects.toThrow("injected async storage initialization failure");
		} finally {
			asyncStorageControl.fail = false;
			if (previousStorage) {
				clearanceGlobal.context.adapterAsyncStorage = previousStorage;
			} else {
				delete clearanceGlobal.context.adapterAsyncStorage;
			}
		}

		expect(getTransactionCalls()).toBe(0);
		expect(workCalls).toBe(0);
	});

	it("distinguishes post-commit hook failures and attempts every queued hook", async () => {
		const { adapter } = createTransactionHarness();
		const events: string[] = [];

		const failure = runWithTransaction(adapter, async () => {
			await queueAfterTransactionHook(async () => {
				events.push("first");
				throw new Error("first publication failed");
			});
			await queueAfterTransactionHook(async () => {
				events.push("second");
				throw new Error("second publication failed");
			});
			await queueAfterTransactionHook(async () => {
				events.push("third");
			});
			return "committed";
		});

		await expect(failure).rejects.toMatchObject({
			name: "AfterTransactionHookError",
			errors: [expect.any(Error), expect.any(Error)],
		});
		await expect(failure).rejects.toBeInstanceOf(AfterTransactionHookError);
		expect(events).toEqual(["first", "second", "third"]);
	});

	it("attempts every non-transactional after hook before reporting failures", async () => {
		const { adapter } = createTransactionHarness();
		const events: string[] = [];

		const failure = runWithAdapter(adapter, async () => {
			await queueAfterTransactionHook(async () => {
				events.push("first");
				throw new Error("first publication failed");
			});
			await queueAfterTransactionHook(async () => {
				events.push("second");
				throw new Error("second publication failed");
			});
			await queueAfterTransactionHook(async () => {
				events.push("third");
			});
		});

		await expect(failure).rejects.toBeInstanceOf(AfterOperationHookError);
		await expect(failure).rejects.toMatchObject({
			errors: [expect.any(Error), expect.any(Error)],
		});
		expect(events).toEqual(["first", "second", "third"]);
	});

	it("propagates an immediate hook failure without executing the hook twice", async () => {
		let hookRuns = 0;

		await expect(
			queueAfterTransactionHook(async () => {
				hookRuns += 1;
				throw new Error("immediate hook failed");
			}),
		).rejects.toThrow("immediate hook failed");

		expect(hookRuns).toBe(1);
	});
});
