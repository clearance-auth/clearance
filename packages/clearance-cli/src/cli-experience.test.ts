import { execFileSync } from "node:child_process";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const entry = join(dirname(fileURLToPath(import.meta.url)), "index.ts");

const temporaryDirectories: string[] = [];

afterEach(() => {
	for (const path of temporaryDirectories.splice(0)) rmSync(path, { recursive: true, force: true });
});

function temporaryDirectory(): string {
	const path = mkdtempSync(join(realpathSync(tmpdir()), "clearance-cli-experience-"));
	temporaryDirectories.push(path);
	return path;
}

function run(args: readonly string[], env: NodeJS.ProcessEnv = {}): string {
	const configDirectory = env.CLEARANCE_CLI_CONFIG_DIR ?? join(temporaryDirectory(), "config");
	return execFileSync(process.execPath, ["--import", "tsx", entry, ...args], {
		encoding: "utf8",
		env: {
			...process.env,
			CLEARANCE_OPERATOR_TOKEN: "",
			CLEARANCE_API_TOKEN: "",
			CLEARANCE_NONINTERACTIVE: "1",
			CLEARANCE_CLI_CONFIG_DIR: configDirectory,
			...env,
		},
		});
}

function runResult(args: readonly string[], env: NodeJS.ProcessEnv = {}): { status: number; stdout: string; stderr: string } {
	try {
		return { status: 0, stdout: run(args, env), stderr: "" };
	} catch (cause) {
		const error = cause as { status?: number; stdout?: string; stderr?: string };
		return { status: error.status ?? 1, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
	}
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
		expect(JSON.parse(run(["commands", "--jq", ".data.specVersion", "--no-input"]))).toBe(2);
	}, 15_000);

	it("generates shell completion without an API session", () => {
		expect(run(["completion", "zsh"])).toContain("#compdef clearance");
	}, 15_000);

	it("renders curated help without an API session", () => {
		const help = run(["help", "profiles", "--output-format", "human"]);
		expect(help).toContain("Profiles");
		expect(help).toContain("clearance --profile staging whoami");
	}, 15_000);

	it("emits one protocol error for Commander usage failures", () => {
		const result = runResult(["definitely-not-a-command", "--output-format", "json", "--no-input"]);
		expect(result.status).toBe(64);
		expect(result.stderr).toBe("");
		const document = JSON.parse(result.stdout);
		expect(result.stdout.match(/"protocol":/gu)).toHaveLength(1);
		expect(document).toMatchObject({
			ok: false,
			error: { code: "CLI_USAGE", stage: "cli.usage" },
		});
	}, 15_000);

	it("routes nested Commander usage failures through one exit-64 document", () => {
		const result = runResult(["backup", "verify", "--output-format", "json", "--no-input"]);
		expect(result.status).toBe(64);
		expect(result.stderr).toBe("");
		expect(result.stdout.match(/"protocol":/gu)).toHaveLength(1);
		expect(JSON.parse(result.stdout)).toMatchObject({
			ok: false,
			error: { code: "CLI_USAGE", stage: "cli.usage" },
			meta: {},
		});
	}, 15_000);

	it("renders useful human help for bare groups and a precise machine usage error", () => {
		const human = runResult(["users", "--output-format", "human", "--no-input"]);
		expect(human.status).toBe(0);
		expect(human.stderr).toBe("");
		expect(human.stdout).toContain("Usage: clearance users");
		expect(human.stdout).toContain("Commands:");
		expect(human.stdout).toContain("list");

		const machine = runResult(["orgs", "members", "--output-format", "json", "--no-input"]);
		expect(machine.status).toBe(64);
		expect(machine.stderr).toBe("");
		expect(machine.stdout).not.toContain("(outputHelp)");
		expect(JSON.parse(machine.stdout)).toMatchObject({
			ok: false,
			error: {
				code: "CLI_USAGE",
				stage: "cli.usage",
				message: "A subcommand is required for orgs members.",
			},
		});
	}, 30_000);

	it("classifies malformed output, numeric, and export format options as CLI usage", () => {
		const cases = [
			["commands", "--output-format", "yaml", "--no-input"],
			["users", "list", "--limit", "nope", "--output-format", "json", "--no-input"],
			["events", "export", "--output", "/tmp/clearance-invalid-format.json", "--format", "xml", "--output-format", "json", "--no-input"],
		] as const;
		for (const args of cases) {
			const result = runResult(args, {
				CLEARANCE_OPERATOR_TOKEN: "subprocess-token",
				CLEARANCE_API_URL: "http://127.0.0.1:1",
			});
			expect(result.status).toBe(64);
			expect(result.stderr).toBe("");
			expect(JSON.parse(result.stdout)).toMatchObject({
				ok: false,
				error: { code: "CLI_USAGE", stage: "cli.usage" },
			});
		}
	}, 60_000);

	it("rejects malformed jq before a remote mutation can dispatch", () => {
		const result = runResult([
			"backup", "create", "--jq", ".data[", "--no-input",
		], {
			CLEARANCE_OPERATOR_TOKEN: "subprocess-token",
			CLEARANCE_API_URL: "http://127.0.0.1:1",
		});
		expect(result.status).toBe(64);
		expect(result.stderr).toBe("");
		expect(JSON.parse(result.stdout)).toMatchObject({
			ok: false,
			error: { code: "CLI_JQ_INVALID", stage: "cli.output" },
			meta: {},
		});
	}, 15_000);

	it("rejects unsupported remote dry runs centrally with a pre-dispatch receipt", () => {
		const result = runResult([
			"backup", "create", "--dry-run", "--output-format", "json", "--no-input",
		], {
			CLEARANCE_OPERATOR_TOKEN: "subprocess-token",
			CLEARANCE_API_URL: "http://127.0.0.1:1",
		});
		expect(result.status).toBe(64);
		expect(result.stderr).toBe("");
		expect(JSON.parse(result.stdout)).toMatchObject({
			ok: false,
			error: { code: "CLI_REMOTE_DRY_RUN_UNSUPPORTED", stage: "cli.dispatch" },
			meta: {
				receipt: {
					operationId: "backups.create",
					outcome: "failed_before_dispatch",
					commitState: "not-applicable",
					dispatchedAt: null,
				},
			},
		});
	}, 15_000);

	it("enforces every local mutation dry-run contract without changing local state", () => {
		const root = temporaryDirectory();
		const configDirectory = join(root, "config");
		const credentialPath = join(configDirectory, "operator-credentials.json");
		const receiptPath = join(configDirectory, "operation-receipts.jsonl");
		const completionPath = join(root, "_clearance");
		const skillDirectory = join(root, "skills");
		const skillPath = join(skillDirectory, "clearance", "SKILL.md");
		const originalCredential = `${JSON.stringify({
			version: 1,
			apiUrl: "https://saved.example.test",
			token: "saved-credential-token-value",
		})}\n`;
		mkdirSync(configDirectory, { recursive: true, mode: 0o700 });
		chmodSync(configDirectory, 0o700);
		writeFileSync(credentialPath, originalCredential, { mode: 0o600 });
		const env = {
			CLEARANCE_CLI_CONFIG_DIR: configDirectory,
			CLEARANCE_RECEIPT_PATH: receiptPath,
			CLEARANCE_OPERATOR_TOKEN: "replacement-token-value",
			CLEARANCE_API_URL: "http://127.0.0.1:1",
			DATABASE_URL: "",
		};

		for (const [command, operationId] of [
			[["login", "--url", "http://127.0.0.1:1", "--dry-run", "--output-format", "json", "--no-input"], "authentication.login"],
			[["logout", "--dry-run", "--output-format", "json", "--no-input"], "authentication.logout"],
		] as const) {
			const result = runResult(command, env);
			expect(result.status).toBe(64);
			expect(result.stderr).toBe("");
			expect(JSON.parse(result.stdout)).toMatchObject({
				ok: false,
				error: { code: "CLI_LOCAL_DRY_RUN_UNSUPPORTED", stage: "cli.dispatch" },
				meta: {
					receipt: {
						operationId,
						dryRun: true,
						outcome: "failed_before_dispatch",
						commitState: "not-applicable",
						dispatchedAt: null,
					},
				},
			});
			expect(readFileSync(credentialPath, "utf8")).toBe(originalCredential);
		}

		const completion = runResult([
			"completion", "install", "zsh", "--path", completionPath, "--dry-run", "--output-format", "json", "--no-input",
		], env);
		expect(completion.status).toBe(0);
		expect(JSON.parse(completion.stdout)).toMatchObject({
			ok: true,
			data: { dryRun: true, projected: { path: completionPath } },
			meta: { receipt: { operationId: "local.completion.install", dryRun: true, outcome: "succeeded" } },
		});
		expect(existsSync(completionPath)).toBe(false);

		const skill = runResult([
			"skill", "install", "--directory", skillDirectory, "--dry-run", "--output-format", "json", "--no-input",
		], env);
		expect(skill.status).toBe(0);
		expect(JSON.parse(skill.stdout)).toMatchObject({
			ok: true,
			data: { dryRun: true, projected: { path: skillPath } },
			meta: { receipt: { operationId: "local.skill.install", dryRun: true, outcome: "succeeded" } },
		});
		expect(existsSync(skillPath)).toBe(false);

		const schema = runResult([
			"schema", "migrate", "--local", "--dry-run", "--output-format", "json", "--no-input",
		], env);
		expect(schema.status).toBe(64);
		expect(JSON.parse(schema.stdout)).toMatchObject({
			ok: false,
			error: { code: "RUNTIME_DATABASE_URL_REQUIRED", stage: "schema.migrate" },
			meta: {
				receipt: {
					operationId: "schema.migrate.local",
					dryRun: true,
					outcome: "rejected",
				},
			},
		});
		expect(readFileSync(credentialPath, "utf8")).toBe(originalCredential);
		expect(existsSync(completionPath)).toBe(false);
		expect(existsSync(skillPath)).toBe(false);
	}, 60_000);

	it("reports an indeterminate receipt when a mutation transport fails", () => {
		const result = runResult([
			"backup", "create", "--output-format", "json", "--no-input",
		], {
			CLEARANCE_OPERATOR_TOKEN: "subprocess-token",
			CLEARANCE_API_URL: "http://127.0.0.1:1",
		});
		expect(result.status).toBe(75);
		expect(result.stderr).toBe("");
		expect(JSON.parse(result.stdout)).toMatchObject({
			ok: false,
			error: { code: "CLI_API_UNREACHABLE", stage: "cli.api", retryable: true },
			meta: {
				receipt: {
					operationId: "backups.create",
					outcome: "indeterminate",
					commitState: "unknown",
				},
			},
		});
	}, 15_000);

	it("installs and inspects owned completion content", () => {
		const root = temporaryDirectory();
		const path = join(root, "_clearance");
		const installed = JSON.parse(run([
			"completion", "install", "zsh", "--path", path, "--output-format", "json",
		])) as { ok: boolean; data: { action: string; projected: { path: string; owned: boolean } } };
		expect(installed).toMatchObject({ ok: true, data: { action: "installed", projected: { path, owned: true } } });
		const status = JSON.parse(run([
			"completion", "status", "zsh", "--path", path, "--output-format", "json",
		])) as { ok: boolean; data: { exists: boolean; owned: boolean } };
		expect(status).toMatchObject({ ok: true, data: { exists: true, owned: true } });
	}, 30_000);

	it("records every declared local and authentication mutation with the canonical receipt schema", () => {
		const root = temporaryDirectory();
		const receiptPath = join(root, "config", "operation-receipts.jsonl");
		const env = {
			CLEARANCE_CLI_CONFIG_DIR: join(root, "config"),
			CLEARANCE_RECEIPT_PATH: receiptPath,
		};

		expect(runResult(["login", "--url", "http://127.0.0.1:1", "--output-format", "json"], env).status).not.toBe(0);
		expect(runResult(["logout", "--output-format", "json"], env).status).toBe(0);
		expect(runResult([
			"completion", "install", "zsh", "--path", join(root, "_clearance"), "--dry-run", "--output-format", "json",
		], env).status).toBe(0);
		expect(runResult([
			"skill", "install", "--directory", join(root, "skills"), "--dry-run", "--output-format", "json",
		], env).status).toBe(0);
		expect(runResult(["schema", "migrate", "--local", "--output-format", "json"], env).status).not.toBe(0);

		const receipts = readFileSync(receiptPath, "utf8").trim().split("\n").map((line) => JSON.parse(line)) as Array<Record<string, unknown>>;
		expect(receipts.map((receipt) => receipt.path)).toEqual([
			"login",
			"logout",
			"completion install",
			"skill install",
			"schema migrate",
		]);
		for (const receipt of receipts) {
			expect(receipt).toMatchObject({
				receiptVersion: 1,
				mutation: true,
				requestId: null,
				idempotencyKey: null,
			});
			expect(receipt).toHaveProperty("commitState");
			expect(receipt).not.toHaveProperty("phase");
		}
	}, 45_000);

	it("runs local doctor without requiring a credential", () => {
		const root = temporaryDirectory();
		const result = runResult(["doctor", "--output-format", "json"], {
			CLEARANCE_CLI_CONFIG_DIR: join(root, "config"),
		});
		expect([0, 2]).toContain(result.status);
		const envelope = JSON.parse(result.stdout) as {
			ok: boolean;
			data: { checks: Array<{ id: string; status: string }> };
		};
		expect(envelope.ok).toBe(true);
		expect(envelope.data.checks.map((check) => check.id)).toEqual([
			"cli", "config", "profile", "api", "skill", "completion",
		]);
		expect(result.stderr).toBe("");
	}, 15_000);

	it("uses CLEARANCE_API_URL for the unauthenticated local doctor probe", () => {
		const root = temporaryDirectory();
		const result = runResult(["doctor", "--output-format", "json", "--no-input"], {
			CLEARANCE_API_URL: "http://127.0.0.1:1",
			CLEARANCE_CLI_CONFIG_DIR: join(root, "config"),
		});
		expect(result.status).toBe(2);
		expect(result.stderr).toBe("");
		expect(JSON.parse(result.stdout)).toMatchObject({
			ok: true,
			data: { apiOrigin: "http://127.0.0.1:1" },
		});
	}, 15_000);
});
