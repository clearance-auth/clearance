import { describe, expect, it } from "vitest";
import { renderHumanData, renderHumanError, renderHumanSuccess } from "./output-human.js";

describe("human output safety", () => {
	it("sanitizes keys, scalar values, summaries, notices, and next actions", () => {
		const data = renderHumanData({ "na\u001b[31mme": "Alice\u202e\nAdmin", values: ["x\u0000y"] });
		expect(data).toBe("Name: Alice Admin\nValues:\n  - xy");
		const success = renderHumanSuccess({
			data: null,
			summary: "Created\u001b]8;;https://bad.example\u0007 user",
			notice: "remote\nnotice",
			next: ["clearance\u009b2J users list"],
		});
		expect(success).toContain("Created user");
		expect(success).toContain("Notice: remote notice");
		expect(success).toContain("clearance users list");
		expect(success).not.toContain("\u001b");
	});

	it("prevents error fields from injecting terminal lines", () => {
		const rendered = renderHumanError({
			code: "BAD\u001b[31m",
			stage: "api\nforged",
			message: "Nope\u202e\nSuccess",
			remediation: "Retry\u0000 now",
		});
		expect(rendered).toBe("Error [BAD] stage=api forged: Nope Success\nRemediation: Retry now");
	});
});
