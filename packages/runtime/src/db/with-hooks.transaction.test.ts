import { runWithAdapter, runWithTransaction } from "@clearance/core/context";
import type { DBAdapter, DBTransactionAdapter } from "@clearance/core/db/adapter";
import { describe, expect, it } from "vitest";
import { getWithHooks } from "./with-hooks";

function harness(
	events: string[],
	throwAfter = false,
	failureMode?: "observe" | "rollback",
) {
	const transactionAdapter = {
		create: async ({ data }: { data: Record<string, unknown> }) => ({
			id: "created-id",
			...data,
		}),
	} as unknown as DBTransactionAdapter;
	const adapter = {
		transaction: async <R>(
			callback: (trx: DBTransactionAdapter) => Promise<R>,
		) => {
			events.push("begin");
			try {
				const result = await callback(transactionAdapter);
				events.push("commit");
				return result;
			} catch (error) {
				events.push("rollback");
				throw error;
			}
		},
	} as DBAdapter;
	const withHooks = getWithHooks(adapter, {
		options: {},
		logger: {
			error: () => {
				events.push("logged");
			},
		},
		hooks: [
			{
				source: "test",
				failureMode,
				hooks: {
					session: {
						create: {
							after: async () => {
								events.push("after");
								if (throwAfter) throw new Error("observer delivery failed");
							},
						},
						delete: {
							after: async () => {
								events.push("after");
								if (throwAfter) throw new Error("observer delivery failed");
							},
						},
					},
				},
			},
			{
				source: "second-test",
				hooks: {
					session: {
						create: {
							after: async () => {
								events.push("second-after");
							},
						},
					},
				},
			},
		],
	});
	return { adapter, transactionAdapter, withHooks };
}

describe("database after-hook transaction order", () => {
	it("runs public after hooks only after commit", async () => {
		const events: string[] = [];
		const { adapter, withHooks } = harness(events);
		await runWithTransaction(adapter, async () => {
			await withHooks.createWithHooks({ userId: "user-id" }, "session");
			events.push("inside");
		});
		expect(events).toEqual([
			"begin",
			"inside",
			"commit",
			"after",
			"second-after",
		]);
	});

	it("logs public after-hook failures without changing committed results", async () => {
		const events: string[] = [];
		const { adapter, withHooks } = harness(events, true);
		await expect(
			runWithTransaction(adapter, async () => {
				await withHooks.createWithHooks({ userId: "user-id" }, "session");
				events.push("inside");
				return "committed-result";
			}),
		).resolves.toBe("committed-result");
		expect(events).toEqual([
			"begin",
			"inside",
			"commit",
			"after",
			"logged",
			"second-after",
		]);
	});

	it("discards public after hooks when later work rolls back", async () => {
		const events: string[] = [];
		const { adapter, withHooks } = harness(events);
		await expect(
			runWithTransaction(adapter, async () => {
				await withHooks.createWithHooks({ userId: "user-id" }, "session");
				throw new Error("later credential insert failed");
			}),
		).rejects.toThrow("later credential insert failed");
		expect(events).toEqual(["begin", "rollback"]);
	});

	it("rolls back when a rollback-critical after hook fails", async () => {
		const events: string[] = [];
		const { adapter, withHooks } = harness(events, true, "rollback");

		await expect(
			runWithTransaction(adapter, async () => {
				await withHooks.createWithHooks({ userId: "user-id" }, "session");
			}),
		).rejects.toThrow("observer delivery failed");

		expect(events).toEqual(["begin", "after", "rollback"]);
	});

	it("defers rollback-critical hooks until later transaction work succeeds", async () => {
		const events: string[] = [];
		const { adapter, withHooks } = harness(events, false, "rollback");

		await expect(
			runWithTransaction(adapter, async () => {
				await withHooks.createWithHooks({ userId: "user-id" }, "session");
				throw new Error("later credential insert failed");
			}),
		).rejects.toThrow("later credential insert failed");

		expect(events).toEqual(["begin", "rollback"]);
	});

	it("runs rollback-critical hooks immediately before commit", async () => {
		const events: string[] = [];
		const { adapter, withHooks } = harness(events, false, "rollback");

		await runWithTransaction(adapter, async () => {
			await withHooks.createWithHooks({ userId: "user-id" }, "session");
			events.push("inside");
		});

		expect(events).toEqual([
			"begin",
			"inside",
			"after",
			"commit",
			"second-after",
		]);
	});

	it("opens a transaction for rollback-critical hooks without a context", async () => {
		const events: string[] = [];
		const { adapter, withHooks } = harness(events, true, "rollback");

		await expect(
			withHooks.createWithHooks({ userId: "user-id" }, "session"),
		).rejects.toThrow("observer delivery failed");
		expect(events).toEqual(["begin", "after", "rollback"]);
	});

	it("opens a nested transaction from a plain adapter context", async () => {
		const events: string[] = [];
		const { adapter, withHooks } = harness(events, true, "rollback");

		await expect(
			runWithAdapter(adapter, () =>
				withHooks.createWithHooks({ userId: "user-id" }, "session"),
			),
		).rejects.toThrow("observer delivery failed");
		expect(events).toEqual(["begin", "after", "rollback"]);
	});

	it("keeps direct with-hooks work on a suspended transaction owner", async () => {
		const firstEvents: string[] = [];
		const secondEvents: string[] = [];
		const first = harness(firstEvents);
		const second = harness(secondEvents, false, "rollback");

		await runWithTransaction(first.adapter, async () => {
			await runWithTransaction(second.adapter, async () => {
				await runWithTransaction(first.adapter, async () => {
					await second.withHooks.createWithHooks(
						{ userId: "second-owner-user" },
						"session",
					);
				});
				expect(secondEvents).toEqual(["begin"]);
			});
			expect(secondEvents).toEqual([
				"begin",
				"after",
				"commit",
				"second-after",
			]);
		});

		expect(firstEvents).toEqual(["begin", "commit"]);
	});

	it("rejects non-transactional custom mutations before any work", async () => {
		const events: string[] = [];
		const { withHooks } = harness(events, true, "rollback");
		let customRuns = 0;

		await expect(
			withHooks.createWithHooks({ userId: "user-id" }, "session", {
				fn: async (data) => {
					customRuns += 1;
					return data;
				},
				executeMainFn: false,
			}),
		).rejects.toThrow(
			"Rollback-critical session.create hooks require custom mutations to use the supplied transaction adapter",
		);
		expect(customRuns).toBe(0);
		expect(events).toEqual([]);
	});

	it("injects the ambient transaction into declared custom mutations", async () => {
		const events: string[] = [];
		const { transactionAdapter, withHooks } = harness(
			events,
			true,
			"rollback",
		);
		let receivedAdapter: DBTransactionAdapter | null = null;

		await expect(
			withHooks.createWithHooks({ userId: "user-id" }, "session", {
				fn: async (data, adapter) => {
					receivedAdapter = adapter;
					return { id: "custom-id", ...data };
				},
				executeMainFn: false,
				usesTransactionAdapter: true,
			}),
		).rejects.toThrow("observer delivery failed");

		expect(receivedAdapter).toBe(transactionAdapter);
		expect(events).toEqual(["begin", "after", "rollback"]);
	});

	it("injects the ambient transaction into atomic consume callbacks", async () => {
		const events: string[] = [];
		const { transactionAdapter, withHooks } = harness(
			events,
			true,
			"rollback",
		);
		let receivedAdapter: DBTransactionAdapter | null = null;

		await expect(
			withHooks.consumeOneWithHooks(
				"session",
				[{ field: "id", value: "session-id" }],
				async (adapter) => {
					receivedAdapter = adapter;
					return { id: "session-id", userId: "user-id" };
				},
			),
		).rejects.toThrow("observer delivery failed");

		expect(receivedAdapter).toBe(transactionAdapter);
		expect(events).toEqual(["begin", "after", "rollback"]);
	});
});
