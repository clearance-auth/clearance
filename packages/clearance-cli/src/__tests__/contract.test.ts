/**
 * --json single-document contract tests.
 *
 * The 2026-07-13 audit reproduced two JSON documents on stdout for the
 * destructive-command refusal paths (fail() called inside try, re-caught,
 * fail() again) and raw stack traces from read commands without try/catch.
 * These tests pin the contract: under --json, every command invocation emits
 * EXACTLY ONE parseable JSON document on stdout, for success and for every
 * induced failure, discovered by walking the real command registry via
 * recursive --help so new commands are covered automatically.
 */
import { execFile, execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, describe, expect, it } from "vitest";
import { authenticatedApiEnv, stopAuthenticatedApiServers } from "./api-test-server.js";

const execFileAsync = promisify(execFile);
const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const entry = join(root, "dist", "index.js");
const dirs: string[] = [];

const ENV = {
	...process.env,
	DATABASE_URL: "",
	CLEARANCE_SECRET: "unit-test-secret-value-not-default!!",
	CLEARANCE_BASE_URL: "http://localhost:3000",
	CLEARANCE_CREDENTIAL_KEY: "unit-test-credential-key-material-32b!!",
	CLEARANCE_CREDENTIAL_KEY_ID: "k1",
	NODE_ENV: "development",
};

const UNREACHABLE_API_ENV = {
	CLEARANCE_OPERATOR_TOKEN: "test-operator-token-for-cli-api-32chars!!",
	CLEARANCE_API_URL: "http://127.0.0.1:1",
};

function tempDir(prefix: string): string {
	const d = mkdtempSync(join(tmpdir(), prefix));
	dirs.push(d);
	return d;
}

afterAll(() => {
	stopAuthenticatedApiServers();
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function runSync(
	args: string[],
	dataPath: string,
	cwd?: string,
	apiEnv?: NodeJS.ProcessEnv,
): { stdout: string; stderr: string; status: number } {
	try {
		const stdout = execFileSync(
			process.execPath,
			[entry, ...args, "--json", "--no-input"],
			{ encoding: "utf8", env: { ...ENV, ...(apiEnv ?? authenticatedApiEnv(dataPath)) }, cwd, stdio: ["ignore", "pipe", "pipe"] },
		);
		return { stdout, stderr: "", status: 0 };
	} catch (err: unknown) {
		const e = err as { stdout?: string; stderr?: string; status?: number };
		return {
			stdout: e.stdout ?? "",
			stderr: e.stderr ?? "",
			status: e.status ?? 1,
		};
	}
}

/** Assert stdout is exactly one JSON document (the whole stream parses). */
function parseSingleDocument(stdout: string, label: string): unknown {
	try {
		return JSON.parse(stdout);
	} catch {
		throw new Error(
			`${label}: stdout is not exactly one JSON document:\n${stdout}`,
		);
	}
}

describe("destructive refusal paths emit one structured document (the audited double-JSON bug)", () => {
	const cases: Array<{ args: string[]; code: string }> = [
		{ args: ["users", "delete", "u_x"], code: "USER_DELETE_CONFIRM_REQUIRED" },
		{
			args: ["orgs", "members", "remove", "--org", "o_x", "--member", "m_x"],
			code: "MEMBER_REMOVE_CONFIRM_REQUIRED",
		},
		{
			args: ["migration", "rollback", "--id", "p_x", "--fixture", "f.json"],
			code: "MIGRATION_ROLLBACK_CONFIRM_REQUIRED",
		},
	];
	for (const c of cases) {
		it(`${c.args.join(" ")} without --yes`, () => {
			const dir = tempDir("clr-contract-refusal-");
			const data = join(dir, "d.json");
			runSync(["init", "--name", "Contract"], data);
			const res = runSync(c.args, data);
			expect(res.status).toBe(1);
			// THE assertion the audit found missing: the ENTIRE stdout must parse.
			const doc = parseSingleDocument(res.stdout, c.args.join(" ")) as {
				error: { code: string; remediation?: string };
			};
			expect(doc.error.code).toBe(c.code);
			expect(doc.error.remediation).toMatch(/--yes/);
		});
	}
});

describe("read commands emit a structured envelope on API failure (no stack traces)", () => {
	const reads: string[][] = [
		["users", "list"],
		["orgs", "list"],
		["sso", "list"],
		["scim", "list"],
		["overview"],
		["events", "list"],
		["sessions", "list"],
	];
	for (const args of reads) {
		it(args.join(" "), () => {
			const dir = tempDir("clr-contract-api-failure-");
			const data = join(dir, "data.json");
			const res = runSync(args, data, undefined, UNREACHABLE_API_ENV);
			expect(res.status).not.toBe(0);
			const doc = parseSingleDocument(res.stdout, args.join(" ")) as {
				error: { code: string; message: string };
			};
			expect(doc.error.code).toBeTruthy();
			expect(res.stdout).not.toMatch(/\n\s+at /); // no stack frames on stdout
		});
	}
});

describe("numeric option validation fails closed with stage-scoped codes", () => {
	it("events list --limit garbage", () => {
		const dir = tempDir("clr-contract-limit-");
		const data = join(dir, "d.json");
		runSync(["init", "--name", "Contract"], data);
		const res = runSync(["events", "list", "--limit", "garbage"], data);
		expect(res.status).toBe(1);
		const doc = parseSingleDocument(res.stdout, "events list") as {
			error: { code: string };
		};
		expect(doc.error.code).toBe("EVENTS_LIST_OPTION_INVALID");
	});
	it("sessions list --limit garbage", () => {
		const dir = tempDir("clr-contract-limit-");
		const data = join(dir, "d.json");
		runSync(["init", "--name", "Contract"], data);
		const res = runSync(["sessions", "list", "--limit", "garbage"], data);
		expect(res.status).toBe(1);
		const doc = parseSingleDocument(res.stdout, "sessions list") as {
			error: { code: string };
		};
		expect(doc.error.code).toBe("SESSION_LIMIT_INVALID"); // shipped code, service-level validator predates the CLI check
	});
	it("events tail keeps its shipped code", () => {
		const dir = tempDir("clr-contract-limit-");
		const data = join(dir, "d.json");
		runSync(["init", "--name", "Contract"], data);
		const res = runSync(["events", "tail", "--once", "--limit", "garbage"], data);
		expect(res.status).toBe(1);
		const doc = parseSingleDocument(res.stdout, "events tail") as {
			error: { code: string };
		};
		expect(doc.error.code).toBe("EVENTS_TAIL_OPTION_INVALID");
	});
});

// ---------------------------------------------------------------------------
// Registry sweep: every leaf command, success-shaped and failure-injected.
// ---------------------------------------------------------------------------

/**
 * Authentication commands that do not call the management API. These may
 * succeed against an unreachable API; every remote command must fail with a
 * structured envelope.
 */
const NO_REMOTE_COMMANDS = new Set<string>([
	"login", // validates and saves the explicit origin locally
	"logout", // removes the operator credential file; never opens the data store
	"whoami", // reports credential/env state; never opens the data store
]);

/**
 * Streaming commands emit newline-delimited JSON (one document per line),
 * not a single document. The contract for these is: EVERY line parses.
 */
const STREAM_COMMANDS = new Set<string>(["events tail"]);

/**
 * Extra args required to make a command terminate or parse in a sweep.
 * Keep minimal and justified.
 */
const SWEEP_EXTRA_ARGS: Record<string, string[]> = {
	"events tail": ["--once"], // without --once the command polls forever by design
	login: ["--url", "http://127.0.0.1:1"], // avoid inheriting a real credential env
};

/**
 * Global spawn gate: every child process in this file goes through one
 * semaphore. Unbounded concurrent spawns exhaust file descriptors on macOS
 * (default ulimit -n 256) and child_process.spawn then throws EBADF
 * SYNCHRONOUSLY, bypassing promise .catch handlers.
 */
const SPAWN_LIMIT = 4;
let spawnActive = 0;
const spawnWaiters: Array<() => void> = [];
async function withSpawnSlot<T>(fn: () => Promise<T>): Promise<T> {
	if (spawnActive >= SPAWN_LIMIT) {
		await new Promise<void>((resolve) => spawnWaiters.push(resolve));
	}
	spawnActive++;
	try {
		return await fn();
	} finally {
		spawnActive--;
		spawnWaiters.shift()?.();
	}
}

async function helpText(path: string[]): Promise<string> {
	return withSpawnSlot(async () => {
		try {
			const { stdout } = await execFileAsync(
				process.execPath,
				[entry, ...path, "--help"],
				{ encoding: "utf8", env: ENV, timeout: 30_000, killSignal: "SIGKILL" },
			);
			return stdout;
		} catch (e) {
			const stdout = (e as { stdout?: string }).stdout;
			if (typeof stdout === "string" && stdout.length > 0) return stdout;
			throw e;
		}
	});
}

/**
 * Parse subcommand names out of commander's "Commands:" help block.
 * Command entries are indented EXACTLY two spaces; wrapped description
 * continuations are indented much deeper — matching them as commands sent
 * discovery into infinite recursion (e.g. "(no secrets)" wrapping produced a
 * phantom `secrets` command, and commander echoes the parent help for unknown
 * subcommands, so the walk never terminated).
 */
function parseSubcommands(help: string): string[] {
	const lines = help.split("\n");
	const start = lines.findIndex((l) => /^Commands:/.test(l.trim()));
	if (start === -1) return [];
	const out: string[] = [];
	for (const line of lines.slice(start + 1)) {
		const m = /^ {2}([a-z][a-z0-9-]*)/.exec(line);
		if (!m) continue;
		if (m[1] === "help") continue;
		out.push(m[1]);
	}
	return out;
}

/** The "Usage: clearance <path> …" line must echo the path we asked about. */
function usageMatchesPath(help: string, path: string[]): boolean {
	const usage =
		help.split("\n").find((l) => l.trim().startsWith("Usage:")) ?? "";
	const expected = `Usage: clearance${path.length ? ` ${path.join(" ")}` : ""}`;
	return usage.trim().startsWith(expected);
}

/** Derive dummy positional args from the "Usage:" line (<x> → "x"). */
function dummyPositionals(help: string): string[] {
	const usage = help.split("\n").find((l) => l.trim().startsWith("Usage:")) ?? "";
	const args: string[] = [];
	for (const m of usage.matchAll(/<([^>]+)>/g)) {
		args.push(`dummy-${m[1].replace(/[^a-z0-9-]/gi, "")}`);
	}
	return args;
}

/** Bounded-concurrency runner: parallel spawns exhaust file descriptors. */
async function withPool<T, R>(
	items: T[],
	limit: number,
	fn: (item: T) => Promise<R>,
): Promise<R[]> {
	const results: R[] = new Array(items.length);
	let next = 0;
	async function worker(): Promise<void> {
		for (;;) {
			const i = next++;
			if (i >= items.length) return;
			results[i] = await fn(items[i]);
		}
	}
	await Promise.all(
		Array.from({ length: Math.min(limit, items.length) }, worker),
	);
	return results;
}

interface Leaf {
	path: string[];
	help: string;
}

async function discoverLeaves(path: string[] = []): Promise<Leaf[]> {
	const help = await helpText(path);
	if (!usageMatchesPath(help, path)) {
		// Commander echoes the PARENT help for unknown subcommands; recursing on
		// an echo loops forever. A mismatch here means the parser produced a
		// phantom command — fail loudly instead of walking a fictional registry.
		throw new Error(
			`help for "${path.join(" ")}" does not echo its own usage — phantom command in discovery`,
		);
	}
	const subs = parseSubcommands(help);
	if (subs.length === 0) return [{ path, help }];
	const nested = await withPool(subs, 4, (s) => discoverLeaves([...path, s]));
	return nested.flat();
}

async function sweepRun(
	args: string[],
	dataPath: string,
	cwd: string,
	apiEnv?: NodeJS.ProcessEnv,
): Promise<{ stdout: string; stderr: string; status: number }> {
	// Auto-satisfy commander's required options: run, read the "required
	// option" parse error, add a dummy value, retry. This walks the real
	// registry without hand-maintaining per-command arg lists.
	const extra: string[] = [];
	for (let attempt = 0; attempt < 8; attempt++) {
		const res = await withSpawnSlot(() =>
			execFileAsync(
				process.execPath,
				[entry, ...args, ...extra, "--json", "--no-input"],
				{
					encoding: "utf8",
					env: { ...ENV, ...(apiEnv ?? authenticatedApiEnv(dataPath)) },
					cwd,
					timeout: 20_000,
					killSignal: "SIGKILL",
				},
			).then(
				(r) => ({ stdout: r.stdout, stderr: r.stderr, status: 0 }),
				(e: { stdout?: string; stderr?: string; code?: number | string }) => ({
					stdout: e.stdout ?? "",
					stderr: e.stderr ?? "",
					status: typeof e.code === "number" ? e.code : 1,
				}),
			),
		);
		const missing = /required option '(--[a-z-]+)/.exec(res.stderr);
		if (missing && res.stdout.trim() === "") {
			extra.push(missing[1], `dummy-${missing[1].slice(2)}`);
			continue;
		}
		return res;
	}
	throw new Error(`could not satisfy required options for: ${args.join(" ")}`);
}

describe("registry sweep: one JSON document per invocation", () => {
	it("every leaf command honors the single-document contract (healthy and unreachable API)", async () => {
		const leaves = await discoverLeaves();
		expect(leaves.length).toBeGreaterThan(40); // registry really was walked

		const okDir = tempDir("clr-sweep-ok-");
		const okData = join(okDir, "d.json");
		runSync(["init", "--name", "Sweep"], okData, okDir);
		const failures: string[] = [];
		const queue = leaves.flatMap((leaf) => {
			const name = leaf.path.join(" ");
			return [
				{ mode: "valid" as const, leaf, name },
				{ mode: "unreachable" as const, leaf, name },
			];
		});

		async function runCase(c: (typeof queue)[number]): Promise<void> {
			const positionals = dummyPositionals(c.leaf.help);
			const extra = SWEEP_EXTRA_ARGS[c.name] ?? [];
			const args = [...c.leaf.path, ...positionals, ...extra];
			const dataPath = okData;
			const cwd = tempDir(`clr-sweep-cwd-`);
			const res = await sweepRun(
				args,
				dataPath,
				cwd,
				c.mode === "unreachable" ? UNREACHABLE_API_ENV : undefined,
			);
			const label = `${c.name} [${c.mode}]`;
			if (res.stdout.trim() === "") {
				// Empty stdout is only acceptable for a commander parse error that
				// we could not auto-satisfy; there should be none.
				failures.push(`${label}: empty stdout (stderr: ${res.stderr.slice(0, 200)})`);
				return;
			}
			if (STREAM_COMMANDS.has(c.name) && res.status === 0) {
				// NDJSON stream: every line must parse.
				for (const line of res.stdout.split("\n")) {
					if (!line.trim()) continue;
					try {
						JSON.parse(line);
					} catch {
						failures.push(`${label}: stream line is not JSON: ${line.slice(0, 200)}`);
					}
				}
			} else {
				try {
					const doc = JSON.parse(res.stdout) as { error?: { code?: string } };
					if (res.status !== 0 && !doc.error?.code) {
						failures.push(`${label}: nonzero exit without error envelope`);
					}
					if (
						c.mode === "unreachable" &&
						res.status === 0 &&
						!NO_REMOTE_COMMANDS.has(c.name)
					) {
						failures.push(`${label}: succeeded against an unreachable API`);
					}
				} catch {
					failures.push(
						`${label}: stdout is not one JSON document:\n${res.stdout.slice(0, 400)}`,
					);
				}
			}
			if (/\n\s+at .*\d+:\d+/.test(res.stdout)) {
				failures.push(`${label}: stack trace on stdout`);
			}
		}

		await withPool(queue, 8, runCase);
		expect(failures, failures.join("\n")).toEqual([]);
	}, 600_000);
});
