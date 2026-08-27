import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const entry = join(dirname(fileURLToPath(import.meta.url)), "index.ts");

function run(args: readonly string[]): string {
	return execFileSync(process.execPath, ["--import", "tsx", entry, ...args], {
		encoding: "utf8",
		env: { ...process.env, CLEARANCE_OPERATOR_TOKEN: "", CLEARANCE_API_TOKEN: "", CLEARANCE_NONINTERACTIVE: "1" },
		});
}

describe("CLI experience", () => {
	it("publishes an exact command contract with full parity", () => {
		const envelope = JSON.parse(run(["commands", "--output-format", "json", "--no-input"])) as {
			ok: boolean;
			data: { commands: unknown[]; parity: { matches: boolean; missingCanonicalPaths: string[]; unexpectedRegisteredPaths: string[] } };
		};
		expect(envelope.ok).toBe(true);
		expect(envelope.data.commands.length).toBeGreaterThan(140);
		expect(envelope.data.parity).toMatchObject({ matches: true, missingCanonicalPaths: [], unexpectedRegisteredPaths: [] });
	}, 15_000);

	it("supports built-in machine selection", () => {
		expect(JSON.parse(run(["commands", "--jq", ".data.specVersion", "--no-input"]))).toBe(1);
	}, 15_000);

	it("generates shell completion without an API session", () => {
		expect(run(["completion", "zsh"])).toContain("#compdef clearance");
	}, 15_000);
});
