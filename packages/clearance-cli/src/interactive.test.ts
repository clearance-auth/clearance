import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { runGuidedInteraction } from "./interactive.js";

function terminal(): PassThrough & { isTTY: boolean } {
	const stream = new PassThrough() as PassThrough & { isTTY: boolean };
	stream.isTTY = true;
	return stream;
}

describe("guided interaction", () => {
	it("writes prompts and the selected command only to stderr", async () => {
		const input = terminal();
		const output = terminal();
		const error = terminal();
		let stderr = "";
		let stdout = "";
		error.on("data", (chunk) => { stderr += String(chunk); });
		output.on("data", (chunk) => { stdout += String(chunk); });
		const resultPromise = runGuidedInteraction({ io: { input, output, error }, env: {} });
		// Feed each response after the preceding readline interface has closed.
		await new Promise((resolve) => setImmediate(resolve));
		input.write("3\n");
		await new Promise((resolve) => setImmediate(resolve));
		input.write("my'app\n");
		await new Promise((resolve) => setImmediate(resolve));
		input.end("staging\n");

		const result = await resultPromise;
		expect(result).toEqual({
			status: "completed",
			command: "clearance init --name 'my'\"'\"'app' --environment 'staging'",
		});
		expect(stderr).toContain("clearance init --name 'my'\"'\"'app' --environment 'staging'");
		expect(stdout).toBe("");
	});

	it("permits cancelling the flow", async () => {
		const input = terminal();
		input.end("q\n");
		expect(await runGuidedInteraction({ io: { input, output: terminal(), error: terminal() }, env: {} }))
			.toEqual({ status: "cancelled" });
	});
});
