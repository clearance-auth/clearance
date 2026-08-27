import { describe, expect, it } from "vitest";
import { sanitizeTerminalText } from "./terminal-sanitize.js";

describe("sanitizeTerminalText", () => {
	it("removes CSI, OSC, DCS, C1, and other terminal controls", () => {
		expect(sanitizeTerminalText("safe\u001b[31m red\u001b[0m\u001b]8;;https://bad\u0007link\u001b]8;;\u0007\u009b2J\u0090payload\u009c"))
			.toBe("safe redlink");
	});

	it("removes C0, bidi, and invisible controls while preserving safe layout by default", () => {
		expect(sanitizeTerminalText("a\u0000\tb\n\u202ec\u200bd\u{e0061}\u007f")).toBe("a\tb\ncd");
		expect(sanitizeTerminalText("a\tb\nc", { preserveNewlines: false, preserveTabs: false })).toBe("abc");
	});
});
