import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const entry = join(dirname(fileURLToPath(import.meta.url)), "index.ts");

function run(args: string[], input = ""): { status: number; stdout: string } {
	try {
		return {
			status: 0,
			stdout: execFileSync(process.execPath, ["--import", "tsx", entry, ...args, "--json", "--no-input"], {
			encoding: "utf8",
			input,
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
		expect(result.status).toBe(1);
		expect(JSON.parse(result.stdout)).toMatchObject({
			error: { code: "USER_CREATE_PASSWORD_SOURCE_CONFLICT" },
		});
		expect(result.stdout).not.toContain(input.trim());
	}, 15_000);
});
