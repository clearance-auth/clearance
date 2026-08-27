import { describe, expect, it, vi } from "vitest";
import { decodeInput, runTerminalUi } from "./app.js";
import type { TuiInput, TuiOutput, WorkflowExecutor } from "./types.js";

describe("decodeInput", () => {
	it("preserves terminal arrows as single keys", () => {
		expect(decodeInput(Buffer.from("j\u001b[Aq"))).toEqual(["j", "\u001b[A", "q"]);
	});
});

describe("runTerminalUi", () => {
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
		const running = runTerminalUi({ executor, io: { input, output } });
		expect(writes[0]).toContain("\u001b[?1049h");
		const frameCount = writes.length;
		onResize?.();
		expect(writes.length).toBeGreaterThan(frameCount);
		onData?.("q");
		await running;
		expect(setRawMode.mock.calls).toEqual([[true], [false]]);
		expect(writes.at(-1)).toContain("\u001b[?1049l");
	});
});
