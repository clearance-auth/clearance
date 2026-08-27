import { existsSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	CLEARANCE_COMPLETION_MARKER,
	CLEARANCE_COMPLETION_VERSION,
	completionInstallationPath,
	inspectCompletionInstallation,
	installCompletion,
} from "./completion-installer.js";

const directories: string[] = [];

function directory(): string {
	const path = mkdtempSync(join(realpathSync(tmpdir()), "clearance-cli-completion-"));
	directories.push(path);
	return path;
}

function options(root: string, shell: "bash" | "zsh" | "fish" = "bash") {
	return { shell, content: "complete -F _clearance_complete clearance", path: join(root, "completions", "clearance") } as const;
}

afterEach(() => {
	for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

describe("completion installation", () => {
	it("uses canonical user paths and explicit environment overrides", () => {
		const home = "/tmp/home";
		expect(completionInstallationPath("bash", { home, env: {} })).toBe("/tmp/home/.local/share/bash-completion/completions/clearance");
		expect(completionInstallationPath("zsh", { home, env: {} })).toBe("/tmp/home/.zfunc/_clearance");
		expect(completionInstallationPath("fish", { home, env: {} })).toBe("/tmp/home/.config/fish/completions/clearance.fish");
		expect(completionInstallationPath("fish", { home, env: { CLEARANCE_COMPLETION_PATH: "/chosen/completion" } })).toBe("/chosen/completion");
		expect(completionInstallationPath("zsh", { home, env: { CLEARANCE_COMPLETION_DIR: "/chosen" } })).toBe("/chosen/_clearance");
	});

	it("inspects without creating paths and supports dry-run", async () => {
		const root = directory();
		const target = options(root).path;
		await expect(inspectCompletionInstallation(target)).resolves.toMatchObject({ exists: false, owned: false });
		await expect(installCompletion({ ...options(root), dryRun: true })).resolves.toMatchObject({
			action: "installed", dryRun: true, current: { exists: false }, projected: { owned: true, version: CLEARANCE_COMPLETION_VERSION },
		});
		expect(existsSync(target)).toBe(false);
	});

	it("installs, stays unchanged, and refreshes owned content", async () => {
		const root = directory();
		const install = options(root);
		await expect(installCompletion(install)).resolves.toMatchObject({ action: "installed" });
		expect(await inspectCompletionInstallation(install.path)).toMatchObject({ owned: true, version: CLEARANCE_COMPLETION_VERSION });
		await expect(installCompletion(install)).resolves.toMatchObject({ action: "unchanged" });
		writeFileSync(install.path, `${CLEARANCE_COMPLETION_MARKER}\nmodified\n`);
		await expect(installCompletion(install)).resolves.toMatchObject({ action: "refreshed" });
	});

	it("does not replace newer owned completion", async () => {
		const root = directory();
		const install = options(root);
		await installCompletion(install);
		writeFileSync(install.path, "# clearance-completion: version=2\nnewer\n");
		await expect(installCompletion(install)).resolves.toMatchObject({ action: "newer", current: { version: 2 } });
	});

	it("refuses unowned files, directories, and symlinks", async () => {
		const root = directory();
		const install = options(root);
		await installCompletion(install);
		writeFileSync(install.path, "custom completion\n");
		await expect(installCompletion(install)).resolves.toMatchObject({ action: "conflict", current: { owned: false } });

		const directoryTarget = join(directory(), "completion");
		await import("node:fs/promises").then(({ mkdir }) => mkdir(directoryTarget));
		await expect(installCompletion({ ...options(root), path: directoryTarget })).resolves.toMatchObject({ action: "conflict" });

		const symlinkRoot = directory();
		const symlinkInstall = options(symlinkRoot);
		await installCompletion(symlinkInstall);
		const outside = join(symlinkRoot, "outside");
		writeFileSync(outside, "custom completion\n");
		unlinkSync(symlinkInstall.path);
		symlinkSync(outside, symlinkInstall.path);
		await expect(installCompletion(symlinkInstall)).resolves.toMatchObject({ action: "conflict" });

		const redirectedRoot = directory();
		const actualRoot = directory();
		rmSync(redirectedRoot, { recursive: true });
		symlinkSync(actualRoot, redirectedRoot);
		await expect(installCompletion({ ...options(root), path: join(redirectedRoot, "completion") })).resolves.toMatchObject({ action: "conflict" });
		expect(existsSync(join(actualRoot, "completion"))).toBe(false);
	});
});
