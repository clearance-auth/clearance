import { createHash, randomBytes } from "node:crypto";
import { open, lstat, mkdir, readFile, realpath, rename, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { CompletionShell } from "./completion.js";

export const CLEARANCE_COMPLETION_VERSION = 1;
export const CLEARANCE_COMPLETION_MARKER = `# clearance-completion: version=${CLEARANCE_COMPLETION_VERSION}`;
const MAX_COMPLETION_BYTES = 1024 * 1024;

export type CompletionInstallAction = "installed" | "refreshed" | "unchanged" | "conflict" | "newer";

export type CompletionInstallation = {
	path: string;
	exists: boolean;
	owned: boolean;
	version?: number;
	digest?: string;
};

export type CompletionInstallResult = {
	action: CompletionInstallAction;
	dryRun: boolean;
	current: CompletionInstallation;
	projected: CompletionInstallation;
	activation: string;
};

export type CompletionInstallOptions = {
	shell: CompletionShell;
	content: string;
	/** Override the exact completion file path. Takes precedence over environment paths. */
	path?: string;
	/** Environment values used to resolve standard user locations. Defaults to process.env. */
	env?: NodeJS.ProcessEnv;
	/** Home directory used when environment variables do not provide a location. */
	home?: string;
	dryRun?: boolean;
};

function pathFromEnvironment(shell: CompletionShell, env: NodeJS.ProcessEnv, home: string): string {
	const override = env.CLEARANCE_COMPLETION_PATH;
	if (override) return resolve(override);
	const directory = env.CLEARANCE_COMPLETION_DIR;
	if (directory) return resolve(directory, shell === "zsh" ? "_clearance" : shell === "fish" ? "clearance.fish" : "clearance");
	if (shell === "bash") {
		return resolve(env.BASH_COMPLETION_USER_DIR ?? env.XDG_DATA_HOME ?? join(home, ".local", "share"), env.BASH_COMPLETION_USER_DIR ? "clearance" : "bash-completion/completions/clearance");
	}
	if (shell === "zsh") return resolve(env.ZDOTDIR ?? home, ".zfunc", "_clearance");
	return resolve(env.XDG_CONFIG_HOME ?? join(home, ".config"), "fish", "completions", "clearance.fish");
}

/** Resolve the canonical per-user completion file, with explicit environment overrides. */
export function completionInstallationPath(shell: CompletionShell, options: Pick<CompletionInstallOptions, "path" | "env" | "home"> = {}): string {
	if (options.path) return resolve(options.path);
	return pathFromEnvironment(shell, options.env ?? process.env, options.home ?? homedir());
}

function markerVersion(content: string): number | undefined {
	const found = /^# clearance-completion: version=(\d+)$/mu.exec(content);
	if (!found) return undefined;
	const version = Number(found[1]);
	return Number.isSafeInteger(version) ? version : undefined;
}

function digest(content: string): string {
	return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

export function managedCompletionContent(content: string): string {
	const normalized = content.endsWith("\n") ? content : `${content}\n`;
	return normalized.startsWith(`${CLEARANCE_COMPLETION_MARKER}\n`) ? normalized : `${CLEARANCE_COMPLETION_MARKER}\n${normalized}`;
}

function activationGuidance(shell: CompletionShell, path: string): string {
	if (shell === "fish") return `Fish loads ${path} automatically in new shells.`;
	const quotedPath = `'${path.replaceAll("'", "'\"'\"'")}'`;
	if (shell === "bash") return `Start a new shell, or run: source ${quotedPath}`;
	const quotedDirectory = `'${dirname(path).replaceAll("'", "'\"'\"'")}'`;
	return `Activate now: fpath=(${quotedDirectory} $fpath); autoload -Uz compinit && compinit`;
}

async function statOrMissing(path: string) {
	try {
		return await lstat(path);
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw cause;
	}
}

async function pathIsSafeDirectory(path: string): Promise<boolean> {
	const stat = await statOrMissing(path);
	return stat?.isDirectory() === true && !stat.isSymbolicLink();
}

async function pathHasSymlinkAncestor(path: string): Promise<boolean> {
	let cursor = resolve(path);
	while (!await statOrMissing(cursor)) {
		const parent = dirname(cursor);
		if (parent === cursor) return true;
		cursor = parent;
	}
	if (!await pathIsSafeDirectory(cursor)) return true;
	return await realpath(cursor) !== cursor;
}

/** Inspect a target without creating parent directories or writing a completion file. */
export async function inspectCompletionInstallation(path: string): Promise<CompletionInstallation> {
	const target = resolve(path);
	const parent = dirname(target);
	if (await pathHasSymlinkAncestor(parent)) return { path: target, exists: true, owned: false };
	if (!await pathIsSafeDirectory(parent)) {
		const parentState = await statOrMissing(parent);
		if (parentState) return { path: target, exists: true, owned: false };
	}
	const stat = await statOrMissing(target);
	if (!stat) return { path: target, exists: false, owned: false };
	if (!stat.isFile() || stat.isSymbolicLink()) return { path: target, exists: true, owned: false };
	const content = await readFile(target, "utf8");
	const version = markerVersion(content);
	return { path: target, exists: true, owned: version !== undefined, ...(version === undefined ? {} : { version, digest: digest(content) }) };
}

async function ensureSafeParent(path: string): Promise<void> {
	const parent = dirname(path);
	if (await pathHasSymlinkAncestor(parent)) {
		throw new Error("Completion destination path contains a symbolic link.");
	}
	const segments: string[] = [];
	let cursor = parent;
	while (!await statOrMissing(cursor)) {
		segments.push(cursor);
		const next = dirname(cursor);
		if (next === cursor) throw new Error("Completion destination has no existing directory ancestor.");
		cursor = next;
	}
	if (!await pathIsSafeDirectory(cursor)) throw new Error("Completion destination contains an unowned file or symbolic link.");
	for (const directory of segments.reverse()) {
		await mkdir(directory, { mode: 0o700 });
		if (!await pathIsSafeDirectory(directory)) throw new Error("Completion destination contains an unowned file or symbolic link.");
	}
}

function sameInstallation(left: CompletionInstallation, right: CompletionInstallation): boolean {
	return left.exists === right.exists && left.owned === right.owned
		&& left.version === right.version && left.digest === right.digest;
}

async function writeAtomically(path: string, content: string, expected: CompletionInstallation): Promise<void> {
	await ensureSafeParent(path);
	const temporary = join(dirname(path), `.${randomBytes(12).toString("hex")}.clearance.tmp`);
	let handle: Awaited<ReturnType<typeof open>> | undefined;
	try {
		handle = await open(temporary, "wx", 0o600);
		await handle.writeFile(content, "utf8");
		await handle.close();
		handle = undefined;
		const observed = await inspectCompletionInstallation(path);
		if (!sameInstallation(observed, expected)) {
			throw new Error("Completion destination changed during installation; no file was replaced.");
		}
		await rename(temporary, path);
	} catch (cause) {
		await handle?.close().catch(() => undefined);
		await unlink(temporary).catch(() => undefined);
		throw cause;
	}
}

/**
 * Install shell completion only into a missing target or a file carrying the
 * Clearance ownership marker. The inspection result makes every decision safe
 * to display in human or JSON CLI output.
 */
export async function installCompletion(options: CompletionInstallOptions): Promise<CompletionInstallResult> {
	const path = completionInstallationPath(options.shell, options);
	const content = managedCompletionContent(options.content);
	if (Buffer.byteLength(content, "utf8") > MAX_COMPLETION_BYTES) {
		throw new Error("Completion content exceeds the 1 MiB installation limit.");
	}
	const current = await inspectCompletionInstallation(path);
	const projected: CompletionInstallation = { path, exists: true, owned: true, version: CLEARANCE_COMPLETION_VERSION, digest: digest(content) };
	const result = (action: CompletionInstallAction, next: CompletionInstallation): CompletionInstallResult => ({ action, dryRun: options.dryRun === true, current, projected: next, activation: activationGuidance(options.shell, path) });
	if (current.exists && !current.owned) return result("conflict", current);
	if ((current.version ?? -1) > CLEARANCE_COMPLETION_VERSION) return result("newer", current);
	if (current.owned && current.digest === projected.digest) return result("unchanged", current);
	const action: CompletionInstallAction = current.exists ? "refreshed" : "installed";
	const response = result(action, projected);
	if (options.dryRun) return response;
	await writeAtomically(path, content, current);
	return response;
}
