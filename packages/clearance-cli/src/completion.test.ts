import { describe, expect, it } from "vitest";
import { renderCompletion } from "./completion.js";
import type { CommandSpecDocument } from "./command-spec.js";

const document: CommandSpecDocument = {
	specVersion: 1,
	commands: [{
		specVersion: 1,
		path: "users create",
		executionClass: "management-api",
		mutation: true,
		confirmation: "none",
		supportsDryRun: true,
		agentNotes: [],
		arguments: [],
		options: [{ flags: "--email <email>", required: false, optional: false, variadic: false }],
	}, {
		specVersion: 1,
		path: "users list",
		executionClass: "management-api",
		mutation: false,
		confirmation: "none",
		supportsDryRun: false,
		agentNotes: [],
		arguments: [],
		options: [{ flags: "--limit <n>", required: false, optional: false, variadic: false }],
	}],
};

describe("shell completion", () => {
	const globalOptions = [{ flags: "--json" }, { flags: "--profile <name>" }];

	it.each(["bash", "zsh", "fish"] as const)("uses command paths and flags for %s", (shell) => {
		const completion = renderCompletion(shell, document, globalOptions);
		expect(completion).toContain("users");
		expect(completion).toContain("create");
		expect(completion).toContain("--json");
		expect(completion).toContain("--email");
		expect(completion).toContain("--limit");
	});

	it("only offers a leaf flag at its command path", () => {
		const completion = renderCompletion("bash", document, globalOptions);
		expect(completion).toContain("'users create') candidates=('--email' '--json' '--profile')");
		expect(completion).not.toContain("'users create') candidates=('--email' '--limit'");
	});
});
