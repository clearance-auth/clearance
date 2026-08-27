import { describe, expect, it, vi } from "vitest";
import { TuiController } from "./model.js";
import type { WorkflowExecutor } from "./types.js";

describe("TuiController", () => {
	it("previews mutations and requires an explicit y before dispatch", async () => {
		const execute = vi.fn<WorkflowExecutor>().mockResolvedValue({ id: "usr_1" });
		const controller = new TuiController(execute);
		controller.handleKey("\u001b[C");
		controller.handleKey("j");
		controller.handleKey("j");
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		expect(controller.state.mode).toBe("preview");
		expect(execute).not.toHaveBeenCalled();
		controller.handleKey("y");
		await controller.waitForIdle();
		expect(execute).toHaveBeenCalledTimes(1);
		expect(execute.mock.calls[0]?.[0].command).toBe("clearance users create --email ada@example.com --name Ada");
		expect(controller.state.mutation).toMatchObject({ phase: "settled", outcome: "succeeded", reconciliationRequired: false });
		expect(controller.state.receipts.at(-1)).toMatchObject({ phase: "settled", outcome: "succeeded" });
	});

	it("requires typed confirmation for destructive actions", async () => {
		const execute = vi.fn<WorkflowExecutor>().mockResolvedValue({ deleted: true });
		const controller = new TuiController(execute);
		controller.state.areaIndex = 1;
		controller.state.selection = 5;
		controller.handleKey("\r");
		for (const character of "usr_1") controller.handleKey(character);
		controller.handleKey("\r");
		controller.handleKey("y");
		expect(execute).not.toHaveBeenCalled();
		controller.handleKey("\u007f");
		for (const character of "users-delete") controller.handleKey(character);
		controller.handleKey("\r");
		await controller.waitForIdle();
		expect(execute.mock.calls[0]?.[0].global.yes).toBe(true);
	});

	it("offers canonical dry-run execution without live confirmation", async () => {
		const execute = vi.fn<WorkflowExecutor>().mockResolvedValue({ dryRun: true });
		const controller = new TuiController(execute);
		controller.state.areaIndex = 1;
		controller.state.selection = 4;
		controller.handleKey("\r");
		for (const character of "usr_1") controller.handleKey(character);
		controller.handleKey("\r");
		controller.handleKey("d");
		await controller.waitForIdle();
		expect(execute.mock.calls[0]?.[0].global).toMatchObject({ dryRun: true, yes: false });
		expect(execute.mock.calls[0]?.[0].command).toContain("--dry-run");
	});

	it("keeps unsupported mutations inert for a global dry-run session", () => {
		const execute = vi.fn<WorkflowExecutor>().mockResolvedValue({ deleted: true });
		const controller = new TuiController(execute, undefined, undefined, { dryRun: true });
		controller.state.areaIndex = 1;
		controller.state.selection = 5;
		controller.handleKey("\r");
		for (const character of "usr_1") controller.handleKey(character);
		controller.handleKey("\r");
		expect(controller.state.mode).toBe("preview");
		controller.handleKey("y");
		expect(execute).not.toHaveBeenCalled();
		expect(controller.state.mode).toBe("preview");
		expect(controller.state.notice).toContain("will not dispatch it live");
	});

	it("preserves the last good result when a refresh fails", async () => {
		const execute = vi.fn<WorkflowExecutor>()
			.mockResolvedValueOnce({ users: 12 })
			.mockRejectedValueOnce(Object.assign(new Error("offline"), { code: "CLI_API_UNREACHABLE", remediation: "Retry." }));
		const controller = new TuiController(execute);
		controller.handleKey("\r");
		await controller.waitForIdle();
		controller.handleKey("r");
		await controller.waitForIdle();
		expect(controller.state.snapshots.overview?.data).toEqual({ users: 12 });
		expect(controller.state.snapshots.overview?.error).toContain("CLI_API_UNREACHABLE");
		expect(controller.state.notice).toContain("last good result");
	});

	it("ignores stale responses when a lane is restarted", async () => {
		const resolutions: Array<(value: unknown) => void> = [];
		const execute: WorkflowExecutor = () => new Promise((resolve) => resolutions.push(resolve));
		const controller = new TuiController(execute);
		controller.handleKey("\r");
		controller.handleKey("r");
		resolutions[1]({ revision: 2 });
		await Promise.resolve();
		resolutions[0]({ revision: 1 });
		await controller.waitForIdle();
		expect(controller.state.snapshots.overview?.data).toEqual({ revision: 2 });
	});

	it("propagates cancellation into an active read executor and keeps its existing snapshot", async () => {
		let requestSignal: AbortSignal | undefined;
		const execute: WorkflowExecutor = (_invocation, context) => {
			requestSignal = context.signal;
			return new Promise((_resolve, reject) => context.signal.addEventListener("abort", () => reject(context.signal.reason), { once: true }));
		};
		const controller = new TuiController(execute);
		controller.state.snapshots.overview = { data: { users: 3 } };
		controller.handleKey("\r");
		controller.handleKey("c");
		await controller.waitForIdle();
		expect(requestSignal?.aborted).toBe(true);
		expect(controller.state.loading).toBeUndefined();
		expect(controller.state.snapshots.overview?.data).toEqual({ users: 3 });
	});

	it("does not offer cancellation or ordinary quit after a mutation is dispatched", async () => {
		let requestSignal: AbortSignal | undefined;
		const execute: WorkflowExecutor = (_invocation, context) => {
			requestSignal = context.signal;
			return new Promise(() => {});
		};
		const controller = new TuiController(execute);
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		controller.handleKey("y");
		await vi.waitFor(() => expect(requestSignal).toBeDefined());
		controller.handleKey("c");
		expect(requestSignal?.aborted).toBe(false);
		expect(controller.state.notice).toContain("cannot be cancelled safely");
		controller.handleKey("q");
		expect(controller.state.quit).toBe(false);
		expect(requestSignal?.aborted).toBe(false);
		expect(controller.state.notice).toContain("Quit is blocked");
	});

	it("detaches an in-flight mutation only with an indeterminate receipt and reconciliation state", async () => {
		const recorded: unknown[] = [];
		let metadataPublished = false;
		const execute: WorkflowExecutor = (_invocation, context) => {
			context.updateReceiptMetadata?.({
				dispatchedAt: "2026-08-27T10:00:01.000Z",
				requestId: "req_detached",
				idempotencyKey: "operation-key-detached",
			});
			metadataPublished = true;
			return new Promise(() => {});
		};
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			receiptJournal: { async record(receipt) { recorded.push(receipt); } },
			createReceiptId: () => "op_test",
			now: () => 42,
		});
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		controller.handleKey("y");
		await vi.waitFor(() => expect(metadataPublished).toBe(true));
		await controller.detachAndQuit("SIGTERM");
		expect(controller.state.quit).toBe(true);
		expect(controller.state.mutation).toEqual({
			actionId: "users-create",
			phase: "settled",
			receiptId: "op_test",
			outcome: "indeterminate",
			reconciliationRequired: true,
			reconciliationCommands: ["clearance users list"],
		});
		expect(controller.state.receipts[0]).toMatchObject({
			id: "op_test",
			operationId: "users.create",
			path: "users create",
			requestId: "req_detached",
			idempotencyKey: "operation-key-detached",
			outcome: "indeterminate",
			detached: true,
			reconciliationRequired: true,
		});
		expect(recorded.at(-1)).toMatchObject({
			id: "op_test",
			operationId: "users.create",
			path: "users create",
			requestId: "req_detached",
			idempotencyKey: "operation-key-detached",
			outcome: "indeterminate",
			detached: true,
		});
	});

	it("classifies explicit server rejection separately from an indeterminate dispatch failure", async () => {
		const rejection = Object.assign(new Error("conflict"), { status: 409 });
		const execute = vi.fn<WorkflowExecutor>().mockRejectedValueOnce(rejection).mockRejectedValueOnce(new Error("connection reset"));
		const controller = new TuiController(execute);
		for (const expected of ["rejected", "indeterminate"] as const) {
			controller.state.areaIndex = 1;
			controller.state.selection = 2;
			controller.handleKey("\r");
			for (const value of ["ada@example.com", "Ada"]) {
				for (const character of value) controller.handleKey(character);
				controller.handleKey("\r");
			}
			controller.handleKey("y");
			await controller.waitForIdle();
			expect(controller.state.mutation?.outcome).toBe(expected);
		}
		expect(controller.state.receipts.map((receipt) => receipt.outcome)).toEqual(["rejected", "indeterminate"]);
		expect(controller.state.mutation?.reconciliationRequired).toBe(true);
	});

	it("fails before dispatch when durable receipt persistence is unavailable", async () => {
		const execute = vi.fn<WorkflowExecutor>().mockResolvedValue({ id: "usr_1" });
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			receiptJournal: { async record() { throw new Error("disk full"); } },
		});
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		controller.handleKey("y");
		await controller.waitForIdle();
		expect(execute).not.toHaveBeenCalled();
		expect(controller.state.mutation?.outcome).toBe("failed_before_dispatch");
		expect(controller.state.notice).toContain("Receipt persistence failed");
	});

	it("keeps shared receipt error details and remediation visible after a mutation failure", async () => {
		const execute = vi.fn<WorkflowExecutor>().mockResolvedValue({
			operationRunner: true,
			data: undefined,
			receipt: {
				receiptVersion: 1,
				outcome: "rejected",
				requestId: "req_rejected",
				reconciliationCommands: ["clearance users list"],
				error: {
					code: "USER_EMAIL_CONFLICT",
					message: "That email already exists.",
					remediation: "Inspect the existing user before retrying.",
				},
			},
		});
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			receiptJournal: { async record() {} },
		});
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		controller.handleKey("y");
		await controller.waitForIdle();
		expect(controller.state.snapshots["users-create"]?.error).toBe(
			"[USER_EMAIL_CONFLICT] That email already exists.\nNext: Inspect the existing user before retrying.",
		);
		expect(controller.state.receipts.at(-1)).toMatchObject({
			outcome: "rejected",
			requestId: "req_rejected",
			error: { code: "USER_EMAIL_CONFLICT", remediation: "Inspect the existing user before retrying." },
		});
		expect(controller.state.notice).toContain("USER_EMAIL_CONFLICT");
	});

	it("reveals returned secrets once without retaining them in snapshots or state", async () => {
		const execute = vi.fn<WorkflowExecutor>().mockResolvedValue({ id: "usr_1", setupToken: "one-time-secret" });
		const revealed: Array<{ path: string; value: string }> = [];
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			revealSecret(secret) { revealed.push(secret); },
		});
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		controller.handleKey("y");
		await controller.waitForIdle();
		expect(revealed).toEqual([{ path: "setupToken", value: "one-time-secret" }]);
		expect(controller.state.snapshots["users-create"]?.data).toEqual({ id: "usr_1", setupToken: "<redacted: revealed once>" });
		expect(JSON.stringify(controller.state)).not.toContain("one-time-secret");
	});

	it("gives an in-flight mutation exclusive ownership of loading and lifecycle state", async () => {
		let readSignal: AbortSignal | undefined;
		let settleMutation: ((value: unknown) => void) | undefined;
		const execute = vi.fn<WorkflowExecutor>((_invocation, context) => {
			if (!context.mutation) {
				readSignal = context.signal;
				return new Promise((_resolve, reject) => context.signal.addEventListener("abort", () => reject(context.signal.reason), { once: true }));
			}
			return new Promise((resolve) => { settleMutation = resolve; });
		});
		const controller = new TuiController(execute);

		controller.handleKey("\r");
		await vi.waitFor(() => expect(readSignal).toBeDefined());
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		controller.handleKey("y");
		await vi.waitFor(() => expect(settleMutation).toBeDefined());

		expect(readSignal?.aborted).toBe(true);
		expect(controller.state.loading).toMatchObject({ actionId: "users-create", mutation: true });
		expect(controller.state.mutation).toMatchObject({ actionId: "users-create", phase: "dispatching" });

		controller.state.workspaceFocus = "resources";
		controller.handleKey("r");
		expect(execute).toHaveBeenCalledTimes(2);
		expect(controller.state.loading).toMatchObject({ actionId: "users-create", mutation: true });
		expect(controller.state.mutation).toMatchObject({ actionId: "users-create", phase: "dispatching" });

		controller.state.workspaceFocus = "actions";
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		expect(controller.state.mode).toBe("browse");
		expect(controller.state.notice).toContain("active mutation receipt");
		expect(execute).toHaveBeenCalledTimes(2);
		controller.handleKey("q");
		expect(controller.state.quit).toBe(false);
		expect(controller.state.loading).toMatchObject({ actionId: "users-create", mutation: true });

		settleMutation?.({ id: "usr_1" });
		await controller.waitForIdle();
		expect(controller.state.loading).toBeUndefined();
		expect(controller.state.mutation).toMatchObject({ phase: "settled", outcome: "succeeded" });
		expect(controller.state.receipts.at(-1)).toMatchObject({ phase: "settled", outcome: "succeeded" });
	});

	it("orders durable receipt writes and detaches before a confirmed mutation can dispatch", async () => {
		let releaseConfirmed: (() => void) | undefined;
		const confirmedPersisted = new Promise<void>((resolve) => { releaseConfirmed = resolve; });
		const recorded: Array<{ phase: string; outcome?: string }> = [];
		const execute = vi.fn<WorkflowExecutor>().mockResolvedValue({ id: "usr_1" });
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			receiptJournal: {
				async record(receipt) {
					recorded.push({ phase: receipt.phase, outcome: receipt.outcome });
					if (recorded.length === 1) await confirmedPersisted;
				},
			},
			createReceiptId: () => "op_ordered",
		});
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		controller.handleKey("y");
		await vi.waitFor(() => expect(recorded).toEqual([{ phase: "confirmed", outcome: undefined }]));

		const detached = controller.detachAndQuit("SIGTERM");
		expect(controller.state.mutation).toMatchObject({ phase: "settled", outcome: "indeterminate" });
		expect(controller.state.quit).toBe(true);
		expect(controller.state.loading).toBeUndefined();
		releaseConfirmed?.();
		await detached;
		await controller.waitForIdle();

		expect(execute).not.toHaveBeenCalled();
		expect(recorded).toEqual([
			{ phase: "confirmed", outcome: undefined },
			{ phase: "settled", outcome: "indeterminate" },
		]);
		expect(controller.state.quit).toBe(true);
		expect(controller.state.loading).toBeUndefined();
		expect(controller.state.receipts[0]).toMatchObject({ phase: "settled", outcome: "indeterminate", detached: true });
	});

	it("keeps an indeterminate detached receipt when its final journal update fails", async () => {
		let journalWrites = 0;
		const execute: WorkflowExecutor = () => new Promise(() => {});
		const controller = new TuiController(execute, undefined, undefined, undefined, {
			receiptJournal: {
				async record(receipt) {
					journalWrites += 1;
					if (receipt.detached) throw new Error("journal unavailable");
				},
			},
			createReceiptId: () => "op_failed_detach",
		});
		controller.state.areaIndex = 1;
		controller.state.selection = 2;
		controller.handleKey("\r");
		for (const value of ["ada@example.com", "Ada"]) {
			for (const character of value) controller.handleKey(character);
			controller.handleKey("\r");
		}
		controller.handleKey("y");
		await vi.waitFor(() => expect(controller.state.mutation?.phase).toBe("dispatching"));
		await controller.detachAndQuit("SIGTERM");

		expect(journalWrites).toBe(3);
		expect(controller.state.quit).toBe(true);
		expect(controller.state.loading).toBeUndefined();
		expect(controller.state.mutation).toMatchObject({ phase: "settled", outcome: "indeterminate", reconciliationRequired: true });
		expect(controller.state.receipts[0]).toMatchObject({ phase: "settled", outcome: "indeterminate", detached: true });
		expect(controller.state.notice).toContain("receipt update could not be persisted");
	});
});
