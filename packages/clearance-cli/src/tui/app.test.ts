import { describe, expect, it, vi } from "vitest";
import { EventEmitter } from "node:events";
import { createRemoteWorkflowExecutor, decodeInput, runTerminalUi } from "./app.js";
import type { TuiInput, TuiOutput, TuiProcessSignals, VerifiedStartupIdentity, WorkflowExecutor } from "./types.js";

function memoryReceiptCoordinator(saved: unknown[] = []) {
	return {
		async prepare() {},
		async save(receipt: unknown) { saved.push(receipt); },
		async record() {},
	};
}

const IDENTITY: VerifiedStartupIdentity = {
	verified: true,
	verifiedAt: 1,
	apiUrl: "https://api.example.com",
	credentialSource: "saved",
	profile: "default",
	projectId: "proj_1",
	environmentId: "env_1",
	operatorId: "operator",
	operatorType: "operator",
};

describe("decodeInput", () => {
	it("preserves terminal arrows as single keys", () => {
		expect(decodeInput(Buffer.from("j\u001b[Aq"))).toEqual(["j", "\u001b[A", "q"]);
	});

	it("swallows unknown terminal control sequences instead of leaking their bytes", () => {
		expect(decodeInput("a\u001b[?2004hb\u001bOPc\u001b]0;hostile\u0007d")).toEqual(["a", "b", "c", "d"]);
	});
});

describe("runTerminalUi", () => {
	it("rejects an unsupported mutation dry run before transport dispatch", async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal("fetch", fetchSpy);
		try {
			const executor = createRemoteWorkflowExecutor({
				apiUrl: "https://api.example.com",
				token: "operator-token",
				profile: "default",
				credentialSource: "saved",
			}, { dryRun: true }, { receiptCoordinator: memoryReceiptCoordinator() });
			const result = await executor({
				path: "product domains create",
				args: [],
				opts: { origin: "https://login.example.com" },
				global: { dryRun: true },
				command: "clearance --dry-run product domains create --origin https://login.example.com",
			}, { signal: new AbortController().signal, lane: "test", generation: 1, mutation: true });
			expect(result).toMatchObject({
				operationRunner: true,
				receipt: {
					outcome: "failed_before_dispatch",
					commitState: "not-applicable",
					error: { code: "CLI_REMOTE_DRY_RUN_UNSUPPORTED" },
				},
			});
			expect(fetchSpy).not.toHaveBeenCalled();
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("preserves request and idempotency metadata in the canonical persisted TUI receipt", async () => {
		const saved: unknown[] = [];
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({
			dryRun: true,
			project: { name: "Preview", slug: "preview" },
		}, { headers: { "x-request-id": "req_tui_mutation" } })));
		try {
			const executor = createRemoteWorkflowExecutor({
				apiUrl: "https://api.example.com",
				token: "operator-token",
				profile: "default",
				credentialSource: "saved",
			}, { dryRun: true }, { receiptCoordinator: memoryReceiptCoordinator(saved) });
			const result = await executor({
				path: "project create",
				args: [],
				opts: { name: "Preview" },
				global: { dryRun: true },
				command: "clearance --dry-run project create --name Preview",
			}, { signal: new AbortController().signal, lane: "test", generation: 1, mutation: true });

			expect(result).toMatchObject({
				operationRunner: true,
				receiptPersistence: "saved",
				receipt: {
					receiptVersion: 1,
					requestId: "req_tui_mutation",
					commitState: "not-applicable",
					outcome: "succeeded",
				},
			});
			expect((result as { receipt: { idempotencyKey: unknown } }).receipt.idempotencyKey).toEqual(expect.any(String));
			expect(saved).toEqual([(result as { receipt: unknown }).receipt]);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("uses the preallocated lifecycle receipt ID and publishes transport metadata before completion", async () => {
		const saved: unknown[] = [];
		const metadata: unknown[] = [];
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({
			dryRun: true,
			project: { name: "Preview", slug: "preview" },
		}, { headers: { "x-request-id": "req_lifecycle" } })));
		try {
			const executor = createRemoteWorkflowExecutor({
				apiUrl: "https://api.example.com",
				token: "operator-token",
				profile: "default",
				credentialSource: "saved",
			}, { dryRun: true }, { receiptCoordinator: memoryReceiptCoordinator(saved) });
			const result = await executor({
				path: "project create",
				args: [],
				opts: { name: "Preview" },
				global: { dryRun: true },
				command: "clearance --dry-run project create --name Preview",
			}, {
				signal: new AbortController().signal,
				lane: "project-create",
				generation: 1,
				mutation: true,
				lifecycle: {
					receiptId: "receipt_preallocated",
					operationId: "projects.create",
					path: "project create",
					startedAt: "2026-08-27T10:00:00.000Z",
					target: { principal: "default", apiOrigin: "https://api.example.com", environment: "env_1" },
				},
				updateReceiptMetadata(value) { metadata.push(value); },
			});

			expect(result).toMatchObject({
				receipt: {
					receiptId: "receipt_preallocated",
					operationId: "projects.create",
					path: "project create",
					startedAt: "2026-08-27T10:00:00.000Z",
					requestId: "req_lifecycle",
					idempotencyKey: expect.any(String),
				},
			});
			expect(metadata).toEqual([
				{ dispatchedAt: expect.any(String) },
				{ requestId: "req_lifecycle", idempotencyKey: expect.any(String) },
			]);
			expect(saved).toEqual([(result as { receipt: unknown }).receipt]);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	it("rejects streaming and artifact-writing invocations before dispatch", async () => {
		const executor = createRemoteWorkflowExecutor({
			apiUrl: "https://api.example.com",
			token: "operator-token",
			profile: "default",
			credentialSource: "saved",
		});
		const context = { signal: new AbortController().signal, lane: "test", generation: 1, mutation: false };
		await expect(executor({ path: "events tail", args: [], opts: {}, global: {}, command: "clearance events tail" }, context))
			.rejects.toThrow("streaming command");
		await expect(executor({ path: "users export", args: [], opts: { output: "users.json" }, global: {}, command: "clearance users export --output users.json" }, { ...context, mutation: true }))
			.rejects.toThrow("artifact-writing command");
	});

	it("uses the alternate screen, redraws on resize, and restores terminal state", async () => {
		let onData: ((data: Buffer | string) => void) | undefined;
		let onResize: (() => void) | undefined;
		const setRawMode = vi.fn();
		const writes: string[] = [];
		const input: TuiInput = {
			isTTY: true,
			setRawMode,
			resume: vi.fn(),
			pause: vi.fn(),
			on(_event, listener) { onData = listener; return this; },
			off(_event, listener) { if (onData === listener) onData = undefined; return this; },
		};
		const output: TuiOutput = {
			isTTY: true,
			columns: 48,
			rows: 16,
			write(value) { writes.push(value); return true; },
			on(_event, listener) { onResize = listener; return this; },
			off(_event, listener) { if (onResize === listener) onResize = undefined; return this; },
		};
		const executor: WorkflowExecutor = async () => ({});
		const running = runTerminalUi({
			executor,
			io: { input, output },
			verifyIdentity: async () => IDENTITY,
			receiptJournal: { async record() {} },
		});
		await vi.waitFor(() => expect(writes[0]).toContain("\u001b[?1049h"));
		expect(writes[0]).toContain("\u001b[?1049h");
		const frameCount = writes.length;
		onResize?.();
		expect(writes.length).toBeGreaterThan(frameCount);
		onData?.("q");
		await running;
		expect(setRawMode.mock.calls).toEqual([[true], [false]]);
		expect(writes.at(-1)).toContain("\u001b[?1049l");
	});

	it("fails closed before acquiring terminal control when identity cannot be verified", async () => {
		const writes: string[] = [];
		const input: TuiInput = {
			isTTY: true,
			setRawMode: vi.fn(),
			resume: vi.fn(),
			pause: vi.fn(),
			on() { return this; },
			off() { return this; },
		};
		const output: TuiOutput = { isTTY: true, write(value) { writes.push(value); return true; } };
		const executor: WorkflowExecutor = async () => ({});
		await expect(runTerminalUi({
			executor,
			io: { input, output },
			verifyIdentity: async () => { throw new Error("unauthorized"); },
		})).rejects.toThrow("unauthorized");
		expect(writes).toEqual([]);
		expect(input.setRawMode).not.toHaveBeenCalled();
	});

	it("normalizes equivalent API origins before verifying the selected target", async () => {
		let onData: ((data: Buffer | string) => void) | undefined;
		const input: TuiInput = {
			isTTY: true,
			setRawMode: vi.fn(),
			resume: vi.fn(),
			pause: vi.fn(),
			on(_event, listener) { onData = listener; return this; },
			off(_event, listener) { if (onData === listener) onData = undefined; return this; },
		};
		const output: TuiOutput = { isTTY: true, columns: 100, rows: 30, write() { return true; } };
		const executor: WorkflowExecutor = async () => ({});
		Object.defineProperty(executor, "global", { value: { apiUrl: "https://api.example.com/", profile: "default" } });
		const running = runTerminalUi({ executor, io: { input, output }, verifyIdentity: async () => IDENTITY });
		await vi.waitFor(() => expect(onData).toBeDefined());
		onData?.("q");
		await expect(running).resolves.toBeUndefined();
	});

	it("restores terminal ownership when drawing throws", async () => {
		const setRawMode = vi.fn();
		const writes: string[] = [];
		const input: TuiInput = {
			isTTY: true,
			setRawMode,
			resume: vi.fn(),
			pause: vi.fn(),
			on() { return this; },
			off() { return this; },
		};
		const output: TuiOutput = {
			isTTY: true,
			write(value) {
				writes.push(value);
				if (value.startsWith("\u001b[H")) throw new Error("draw failed");
				return true;
			},
		};
		const executor: WorkflowExecutor = async () => ({});
		await expect(runTerminalUi({ executor, io: { input, output }, verifyIdentity: async () => IDENTITY })).rejects.toThrow("draw failed");
		expect(setRawMode.mock.calls).toEqual([[true], [false]]);
		expect(writes.at(-1)).toContain("\u001b[?1049l");
	});

	it("reveals a returned secret in a one-acknowledgment overlay, then overwrites it", async () => {
		let onData: ((data: Buffer | string) => void) | undefined;
		const writes: string[] = [];
		const input: TuiInput = {
			isTTY: true,
			setRawMode: vi.fn(),
			resume: vi.fn(),
			pause: vi.fn(),
			on(_event, listener) { onData = listener; return this; },
			off(_event, listener) { if (onData === listener) onData = undefined; return this; },
		};
		const output: TuiOutput = { isTTY: true, columns: 100, rows: 30, write(value) { writes.push(value); return true; } };
		const executor: WorkflowExecutor = async () => ({ setupToken: "secret-once" });
		const running = runTerminalUi({
			executor,
			io: { input, output },
			verifyIdentity: async () => IDENTITY,
			receiptJournal: { async record() {} },
		});
		await vi.waitFor(() => expect(onData).toBeDefined());
		onData?.("\u001b[Cjj\r");
		onData?.("ada@example.com\rAda\r");
		onData?.("y");
		await vi.waitFor(() => expect(writes.some((write) => write.includes("setupToken: secret-once"))).toBe(true));
		expect(writes.filter((write) => write.includes("secret-once"))).toHaveLength(1);
		onData?.("x");
		await vi.waitFor(() => expect(writes.at(-1)).not.toContain("secret-once"));
		onData?.("q");
		await running;
		expect(writes.at(-1)).toContain("\u001b[?1049l");
	});

	it("restores terminal ownership and reports process signals", async () => {
		let onData: ((data: Buffer | string) => void) | undefined;
		const setRawMode = vi.fn();
		const writes: string[] = [];
		const input: TuiInput = {
			isTTY: true,
			setRawMode,
			resume: vi.fn(),
			pause: vi.fn(),
			on(_event, listener) { onData = listener; return this; },
			off(_event, listener) { if (onData === listener) onData = undefined; return this; },
		};
		const output: TuiOutput = { isTTY: true, write(value) { writes.push(value); return true; } };
		const signals = new EventEmitter() as TuiProcessSignals & EventEmitter;
		const executor: WorkflowExecutor = async () => ({});
		const running = runTerminalUi({ executor, io: { input, output }, signals, verifyIdentity: async () => IDENTITY });
		await vi.waitFor(() => expect(onData).toBeDefined());
		signals.emit("SIGTERM");
		await expect(running).rejects.toThrow("terminated by SIGTERM");
		expect(setRawMode.mock.calls).toEqual([[true], [false]]);
		expect(writes.at(-1)).toContain("\u001b[?1049l");
	});
});
