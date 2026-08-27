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

	it("aborts an active lane and keeps its existing snapshot", async () => {
		let requestSignal: AbortSignal | undefined;
		const execute: WorkflowExecutor = (_invocation, context) => {
			requestSignal = context.signal;
			return new Promise(() => {});
		};
		const controller = new TuiController(execute);
		controller.state.snapshots.overview = { data: { users: 3 } };
		controller.handleKey("\r");
		controller.handleKey("c");
		expect(requestSignal?.aborted).toBe(true);
		expect(controller.state.loading).toBeUndefined();
		expect(controller.state.snapshots.overview?.data).toEqual({ users: 3 });
	});

	it("does not offer cancellation after a mutation is dispatched", () => {
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
		controller.handleKey("c");
		expect(requestSignal?.aborted).toBe(false);
		expect(controller.state.notice).toContain("cannot be cancelled safely");
	});
});
