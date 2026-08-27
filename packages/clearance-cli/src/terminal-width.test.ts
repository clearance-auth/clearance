import { describe, expect, it } from "vitest";
import { terminalWidth, truncateTerminalText, wrapTerminalText } from "./terminal-width.js";

describe("terminal dimensions", () => {
	it("measures ASCII, combining text, CJK, and emoji by terminal cells", () => {
		expect(terminalWidth("abc")).toBe(3);
		expect(terminalWidth("e\u0301")).toBe(1);
		expect(terminalWidth("你好")).toBe(4);
		expect(terminalWidth("👩‍💻")).toBe(2);
	});

	it("truncates and wraps whole graphemes", () => {
		expect(truncateTerminalText("你好abc", 5)).toBe("你好…");
		expect(truncateTerminalText("👩‍💻 work", 3)).toBe("👩‍💻…");
		expect(wrapTerminalText("A你好B", 3)).toEqual(["A你", "好B"]);
		expect(wrapTerminalText("keep words together", 10)).toEqual(["keep words", "together"]);
	});
});
