import { describe, expect, it } from "vitest";
import { TerminalInputDecoder } from "./input.js";

describe("TerminalInputDecoder", () => {
	it("decodes split CSI and SS3 arrows without leaking sequence bytes", () => {
		const decoder = new TerminalInputDecoder();
		expect(decoder.push("\u001b[")).toEqual([]);
		expect(decoder.push("1;5A\u001bO")).toEqual(["\u001b[A"]);
		expect(decoder.push("D")).toEqual(["\u001b[D"]);
		expect(decoder.flush()).toEqual([]);
	});

	it("swallows unknown CSI, OSC, DCS, and SS3 sequences across chunks", () => {
		const decoder = new TerminalInputDecoder();
		expect(decoder.push("a\u001b[?20")).toEqual(["a"]);
		expect(decoder.push("04hb\u001b]title")).toEqual(["b"]);
		expect(decoder.push("\u001b\\c\u001bPpayload")).toEqual(["c"]);
		expect(decoder.push("\u001b\\d\u001bOPe")).toEqual(["d", "e"]);
	});

	it("preserves a split UTF-8 code point and flushes a standalone Escape", () => {
		const decoder = new TerminalInputDecoder();
		const bytes = Buffer.from("🔐");
		expect(decoder.push(bytes.subarray(0, 2))).toEqual([]);
		expect(decoder.push(bytes.subarray(2))).toEqual(["🔐"]);
		expect(decoder.push("\u001b")).toEqual([]);
		expect(decoder.flush()).toEqual(["\u001b"]);
	});
});
