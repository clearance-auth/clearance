import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";
import { attachTerminalSignals, TerminalSession } from "./terminal-session.js";
import type { TuiIO, TuiProcessSignals } from "./types.js";

function fakeIo(setRawMode = vi.fn()): { io: TuiIO; writes: string[]; setRawMode: ReturnType<typeof vi.fn> } {
	const writes: string[] = [];
	return {
		setRawMode,
		writes,
		io: {
			input: {
				isTTY: true,
				setRawMode,
				resume: vi.fn(),
				pause: vi.fn(),
				on() { return this; },
				off() { return this; },
			},
			output: { isTTY: true, write(value) { writes.push(value); return true; } },
		},
	};
}

describe("TerminalSession", () => {
	it("restores raw mode and the alternate screen exactly once", () => {
		const { io, writes, setRawMode } = fakeIo();
		const session = new TerminalSession(io);
		session.enter();
		session.enter();
		session.restore();
		session.restore();
		expect(setRawMode.mock.calls).toEqual([[true], [false]]);
		expect(writes).toHaveLength(2);
		expect(writes[0]).toContain("\u001b[?1049h");
		expect(writes[1]).toContain("\u001b[?1049l");
	});

	it("attempts restoration when raw-mode acquisition throws after changing terminal state", () => {
		const setRawMode = vi.fn((enabled: boolean) => { if (enabled) throw new Error("raw failed"); });
		const { io, writes } = fakeIo(setRawMode);
		const session = new TerminalSession(io);
		expect(() => session.enter()).toThrow("raw failed");
		expect(setRawMode.mock.calls).toEqual([[true], [false]]);
		expect(writes.at(-1)).toContain("\u001b[?1049l");
	});

	it("attaches and idempotently removes SIGINT and SIGTERM handlers", () => {
		const signals = new EventEmitter() as TuiProcessSignals & EventEmitter;
		const seen: string[] = [];
		const detach = attachTerminalSignals(signals, (signal) => seen.push(signal));
		signals.emit("SIGINT");
		signals.emit("SIGTERM");
		detach();
		detach();
		signals.emit("SIGTERM");
		expect(seen).toEqual(["SIGINT", "SIGTERM"]);
	});
});
