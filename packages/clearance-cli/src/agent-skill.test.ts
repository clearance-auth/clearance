import { existsSync, mkdtempSync, rmSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	CLEARANCE_AGENT_SKILL_VERSION,
	inspectClearanceAgentSkill,
	installClearanceAgentSkill,
} from "./agent-skill.js";

const directories: string[] = [];

function directory(): string {
	const path = mkdtempSync(join(tmpdir(), "clearance-cli-agent-skill-"));
	directories.push(path);
	return path;
}

function target(root: string): string {
	return join(root, "clearance", "SKILL.md");
}

afterEach(() => {
	for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("Clearance agent skill installation", () => {
	it("reports a dry-run install without changing the destination", async () => {
		const root = directory();
		await expect(installClearanceAgentSkill({ directory: root, dryRun: true })).resolves.toMatchObject({
			action: "installed", dryRun: true,
			current: { exists: false, owned: false },
			projected: { exists: true, owned: true, version: CLEARANCE_AGENT_SKILL_VERSION },
		});
		expect(existsSync(target(root))).toBe(false);
	});

	it("installs once and leaves the current owned version unchanged", async () => {
		const root = directory();
		await expect(installClearanceAgentSkill({ directory: root })).resolves.toMatchObject({ action: "installed" });
		await expect(inspectClearanceAgentSkill(root)).resolves.toMatchObject({ exists: true, owned: true, version: CLEARANCE_AGENT_SKILL_VERSION });
		await expect(installClearanceAgentSkill({ directory: root })).resolves.toMatchObject({ action: "unchanged" });
	});

	it("refreshes a same-version owned skill whose content digest does not match", async () => {
		const root = directory();
		await installClearanceAgentSkill({ directory: root });
		writeFileSync(target(root), `<!-- clearance-agent-skill: version=${CLEARANCE_AGENT_SKILL_VERSION} -->\ncorrupted\n`);
		const preview = await installClearanceAgentSkill({ directory: root, dryRun: true });
		expect(preview).toMatchObject({
			action: "refreshed",
			current: { version: CLEARANCE_AGENT_SKILL_VERSION },
			projected: { version: CLEARANCE_AGENT_SKILL_VERSION },
		});
		expect(preview.current.digest).not.toBe(preview.projected.digest);
		await expect(installClearanceAgentSkill({ directory: root })).resolves.toMatchObject({ action: "refreshed" });
	});

	it("refreshes an older owned skill, including in dry-run mode", async () => {
		const root = directory();
		const path = target(root);
		// Create the target directory through a first install, then make it old.
		await installClearanceAgentSkill({ directory: root });
		writeFileSync(path, "<!-- clearance-agent-skill: version=0 -->\nold\n");
		await expect(installClearanceAgentSkill({ directory: root, dryRun: true })).resolves.toMatchObject({ action: "refreshed", dryRun: true });
		await expect(installClearanceAgentSkill({ directory: root })).resolves.toMatchObject({
			action: "refreshed", projected: { version: CLEARANCE_AGENT_SKILL_VERSION },
		});
	});

	it("does not downgrade a newer owned skill", async () => {
		const root = directory();
		await installClearanceAgentSkill({ directory: root });
		writeFileSync(target(root), "<!-- clearance-agent-skill: version=2 -->\nnewer\n");
		await expect(installClearanceAgentSkill({ directory: root })).resolves.toMatchObject({
			action: "newer", current: { version: 2 },
		});
	});

	it("refuses to overwrite unowned files and symlinks", async () => {
		const root = directory();
		await installClearanceAgentSkill({ directory: root });
		writeFileSync(target(root), "custom skill\n");
		await expect(installClearanceAgentSkill({ directory: root })).resolves.toMatchObject({
			action: "conflict", current: { owned: false },
		});

		const symlinkRoot = directory();
		await installClearanceAgentSkill({ directory: symlinkRoot });
		const skillPath = target(symlinkRoot);
		const outside = join(symlinkRoot, "outside.md");
		writeFileSync(outside, "custom skill\n");
		unlinkSync(skillPath);
		symlinkSync(outside, skillPath);
		await expect(installClearanceAgentSkill({ directory: symlinkRoot })).resolves.toMatchObject({ action: "conflict" });

		const redirectedRoot = directory();
		const actualRoot = directory();
		rmdirSync(redirectedRoot);
		symlinkSync(actualRoot, redirectedRoot);
		await expect(installClearanceAgentSkill({ directory: redirectedRoot })).resolves.toMatchObject({
			action: "conflict", current: { owned: false },
		});
		expect(existsSync(target(actualRoot))).toBe(false);
	});
});
