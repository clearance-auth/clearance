import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CLI_EXIT_CODE } from "./output.js";

const entry = join(dirname(fileURLToPath(import.meta.url)), "index.ts");

function run(args: string[], input = ""): { status: number; stdout: string } {
	try {
		return {
			status: 0,
			stdout: execFileSync(process.execPath, ["--import", "tsx", entry, ...args, "--json", "--no-input"], {
				encoding: "utf8",
				input,
				timeout: 15_000,
				env: { ...process.env, CLEARANCE_OPERATOR_TOKEN: "", CLEARANCE_API_TOKEN: "" },
		}),
		};
	} catch (cause: unknown) {
		const error = cause as { status?: number; stdout?: string };
		return { status: error.status ?? 1, stdout: error.stdout ?? "" };
	}
}

describe("CLI initial password input", () => {
	it("rejects conflicting password sources without echoing stdin", () => {
		const input = "secret\n";
		const result = run([
			"users", "create", "--email", "person@example.test", "--name", "Person",
			"--password-stdin", "--password-prompt",
		], input);
		expect(result.status).toBe(CLI_EXIT_CODE.invalidInput);
		expect(JSON.parse(result.stdout)).toMatchObject({
			error: { code: "USER_CREATE_PASSWORD_SOURCE_CONFLICT" },
		});
		expect(result.stdout).not.toContain(input.trim());
	}, 30_000);

	it("fails a noninteractive password prompt promptly without echoing input", () => {
		const result = run([
			"users", "create", "--email", "person@example.test", "--name", "Person",
			"--password-prompt",
		]);
		expect(result.status).toBe(CLI_EXIT_CODE.invalidInput);
		expect(JSON.parse(result.stdout)).toMatchObject({
			error: { code: "USER_CREATE_PASSWORD_PROMPT_NONINTERACTIVE" },
		});
	}, 20_000);
});
