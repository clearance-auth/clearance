import { createHash, randomBytes } from "node:crypto";
import { open, lstat, mkdir, readFile, rename } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const CLEARANCE_AGENT_SKILL_NAME = "clearance";
export const CLEARANCE_AGENT_SKILL_FILE = "SKILL.md";
export const CLEARANCE_AGENT_SKILL_VERSION = 1;

const OWNERSHIP_MARKER = `<!-- clearance-agent-skill: version=${CLEARANCE_AGENT_SKILL_VERSION} -->`;

export type AgentSkillInstallAction = "installed" | "refreshed" | "unchanged" | "conflict" | "newer";

export type AgentSkillInspection = {
	path: string;
	exists: boolean;
	owned: boolean;
	version?: number;
	digest?: string;
};

export type AgentSkillInstallResult = {
	action: AgentSkillInstallAction;
	dryRun: boolean;
	/** State observed before this invocation. */
	current: AgentSkillInspection;
	/** State that will exist after this invocation, if it is not a dry run. */
	projected: AgentSkillInspection;
};

export type InstallClearanceAgentSkillOptions = {
	/** Root skill directory, for example ~/.codex/skills. */
	directory: string;
	dryRun?: boolean;
};

function installedSkillPath(directory: string): string {
	return resolve(directory, CLEARANCE_AGENT_SKILL_NAME, CLEARANCE_AGENT_SKILL_FILE);
}

function sourceSkillPath(): string {
	const moduleDirectory = dirname(fileURLToPath(import.meta.url));
	const skillsDirectory = basename(moduleDirectory) === "src"
		? resolve(moduleDirectory, "../skills")
		: resolve(moduleDirectory, "skills");
	return resolve(skillsDirectory, CLEARANCE_AGENT_SKILL_NAME, CLEARANCE_AGENT_SKILL_FILE);
}

function ownershipVersion(content: string): number | undefined {
	const marker = /<!-- clearance-agent-skill: version=(\d+) -->/.exec(content);
	if (!marker) return undefined;
	const version = Number(marker[1]);
	return Number.isSafeInteger(version) ? version : undefined;
}

function contentDigest(content: string): string {
	return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

type BundledSkill = { content: string; digest: string };

async function readBundledSkill(): Promise<BundledSkill> {
	const content = await readFile(sourceSkillPath(), "utf8");
	if (!content.includes(OWNERSHIP_MARKER)) {
		throw new Error("Bundled Clearance agent skill is missing its ownership marker.");
	}
	return { content, digest: contentDigest(content) };
}

export function clearanceAgentSkillSourcePath(): string {
	return sourceSkillPath();
}

async function isSymbolicLink(path: string): Promise<boolean> {
	try {
		return (await lstat(path)).isSymbolicLink();
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw cause;
	}
}

/** Read ownership state without changing the target directory or file. */
export async function inspectClearanceAgentSkill(directory: string): Promise<AgentSkillInspection> {
	const path = installedSkillPath(directory);
	if (await isSymbolicLink(resolve(directory))) return { path, exists: true, owned: false };
	try {
		const stat = await lstat(path);
		if (stat.isSymbolicLink() || !stat.isFile()) return { path, exists: true, owned: false };
		const content = await readFile(path, "utf8");
		const version = ownershipVersion(content);
		return {
			path,
			exists: true,
			owned: version !== undefined,
			...(version === undefined ? {} : { version, digest: contentDigest(content) }),
		};
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") {
			try {
				const parent = await lstat(dirname(path));
				if (parent.isSymbolicLink() || !parent.isDirectory()) {
					return { path, exists: true, owned: false };
				}
			} catch (parentCause) {
				if ((parentCause as NodeJS.ErrnoException).code !== "ENOENT") throw parentCause;
			}
			return { path, exists: false, owned: false };
		}
		throw cause;
	}
}

async function writeAtomically(path: string, content: string): Promise<void> {
	const directory = dirname(path);
	if (await isSymbolicLink(directory)) {
		throw new Error("Clearance agent skill destination path contains a symbolic link.");
	}
	await mkdir(directory, { recursive: true, mode: 0o700 });
	if (await isSymbolicLink(directory)) {
		throw new Error("Clearance agent skill destination path contains a symbolic link.");
	}
	const directoryStat = await lstat(directory);
	if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) {
		throw new Error("Clearance agent skill destination directory is not a regular directory.");
	}
	const temporaryPath = join(directory, `.${CLEARANCE_AGENT_SKILL_FILE}.${randomBytes(12).toString("hex")}.tmp`);
	const handle = await open(temporaryPath, "wx", 0o600);
	try {
		await handle.writeFile(content, "utf8");
	} finally {
		await handle.close();
	}
	await rename(temporaryPath, path);
}

/**
 * Install the bundled skill only when the destination is absent or clearly
 * owned by Clearance. Unowned files, directories, and symlinks are never
 * overwritten. Results are deliberately inspectable for JSON CLI output.
 */
export async function installClearanceAgentSkill(
	options: InstallClearanceAgentSkillOptions,
): Promise<AgentSkillInstallResult> {
	const [current, bundled] = await Promise.all([
		inspectClearanceAgentSkill(options.directory),
		readBundledSkill(),
	]);
	const dryRun = options.dryRun === true;
	const result = (action: AgentSkillInstallAction, projected: AgentSkillInspection): AgentSkillInstallResult => ({
		action,
		dryRun,
		current,
		projected,
	});
	if (current.exists && !current.owned) return result("conflict", current);
	if (current.owned && (current.version ?? -1) > CLEARANCE_AGENT_SKILL_VERSION) {
		return result("newer", current);
	}
	if (
		current.owned &&
		current.version === CLEARANCE_AGENT_SKILL_VERSION &&
		current.digest === bundled.digest
	) {
		return result("unchanged", current);
	}

	const action: AgentSkillInstallAction = current.exists ? "refreshed" : "installed";
	const projected: AgentSkillInspection = {
		path: current.path,
		exists: true,
		owned: true,
		version: CLEARANCE_AGENT_SKILL_VERSION,
		digest: bundled.digest,
	};
	const next = result(action, projected);
	if (dryRun) return next;

	await writeAtomically(current.path, bundled.content);
	return next;
}
