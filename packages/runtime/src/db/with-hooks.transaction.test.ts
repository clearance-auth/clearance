import { runWithTransaction } from "@clearance/core/context";
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
	return { adapter, withHooks };
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
});
