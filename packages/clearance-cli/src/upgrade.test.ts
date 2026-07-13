import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { applyUpgrade, planUpgrade, rollbackUpgrade, verifyUpgrade } from "./upgrade.js";

const dirs: string[] = [];
const directory = () => {
	const dir = mkdtempSync(join(tmpdir(), "clearance-upgrade-"));
	dirs.push(dir);
	return dir;
};

afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("upgrade script lane", () => {
	it("ships the supported 0.1.1 to 0.2.0 transition hook", () => {
		const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
		const hook = join(root, "deploy/upgrades/steps/0.2.0/apply.sh");
		expect(existsSync(hook)).toBe(true);
		expect(readFileSync(hook, "utf8")).toContain('[[ "$FROM" == "0.1.1" && "$TO" == "0.2.0" ]]');
	});

	it("creates an offline plan in an isolated artifact directory", async () => {
		const dir = directory();
		const result = await planUpgrade({ target: "0.2.0", current: "0.1.1", dir });
		expect(result).toMatchObject({ schemaVersion: "v1", operation: "upgrade.plan", dryRun: false, plan: { currentVersion: "0.1.1", targetVersion: "0.2.0", status: "planned" } });
		expect(existsSync(result.plan.path)).toBe(true);
		expect(existsSync(join(dir, `${result.plan.id}.state.json`))).toBe(true);
	});

	it("keeps dry-run non-mutating", async () => {
		const parent = directory();
		const dir = join(parent, "not-created");
		const result = await planUpgrade({ target: "0.2.0", dir, dryRun: true });
		expect(result).toMatchObject({ dryRun: true, plan: { createsArtifacts: false } });
		expect(existsSync(dir)).toBe(false);
	});

	it("supports apply dry-run without confirmation and requires confirmation for mutation", async () => {
		const dir = directory();
		const planned = await planUpgrade({ target: "0.2.0", current: "0.1.1", dir });
		await expect(applyUpgrade({ plan: planned.plan.id, dir, dryRun: true })).resolves.toMatchObject({ operation: "upgrade.apply", dryRun: true, plan: { status: "planned" } });
		await expect(applyUpgrade({ plan: planned.plan.id, dir })).rejects.toMatchObject({ code: "UPGRADE_APPLY_CONFIRMATION_REQUIRED", stage: "upgrade.apply" });
	});

	it("keeps verification dry-run non-mutating", async () => {
		const dir = directory();
		const planned = await planUpgrade({ target: "0.2.0", current: "0.1.1", dir });
		const result = await verifyUpgrade({ plan: planned.plan.id, dir, dryRun: true });
		expect(result).toMatchObject({ dryRun: true, plan: { status: "planned" }, wouldRun: ["backup_reference_check", "apply_marker_check"] });
	});

	it("keeps rollback dry-run non-mutating and explicit about active database safety", async () => {
		const dir = directory();
		const planned = await planUpgrade({ target: "0.2.0", current: "0.1.1", dir });
		const before = readFileSync(join(dir, `${planned.plan.id}.state.json`), "utf8");
		const result = await rollbackUpgrade({ plan: planned.plan.id, dir, dryRun: true });
		expect(result).toMatchObject({ operation: "upgrade.rollback", dryRun: true, mode: "isolated_verify_only", activeDatabaseUntouched: true });
		expect(readFileSync(join(dir, `${planned.plan.id}.state.json`), "utf8")).toBe(before);
		await expect(rollbackUpgrade({ plan: planned.plan.id, dir })).rejects.toMatchObject({ code: "UPGRADE_ROLLBACK_CONFIRMATION_REQUIRED" });
		await expect(rollbackUpgrade({ plan: planned.plan.id, dir, restoreActive: true, dryRun: true })).resolves.toMatchObject({
			mode: "active_database_restore",
			activeDatabaseUntouched: true,
			wouldModifyActiveDatabase: true,
			wouldRun: ["advisory_lock", "safety_backup", "staging_restore", "database_swap", "live_verification", "rollback_receipt"],
		});
		await expect(rollbackUpgrade({ plan: planned.plan.id, dir, restoreActive: true, yes: true, confirm: "wrong" })).rejects.toMatchObject({
			code: "UPGRADE_ACTIVE_ROLLBACK_CONFIRMATION_REQUIRED",
		});
	});

	it("fails closed on missing, tampered, and invalid plan inputs", async () => {
		const dir = directory();
		await expect(verifyUpgrade({ plan: "upg_missing", dir })).rejects.toMatchObject({ code: "UPGRADE_PLAN_INVALID", stage: "upgrade.verify" });
		const planned = await planUpgrade({ target: "0.2.0", current: "0.1.1", dir });
		chmodSync(planned.plan.path, 0o644);
		const tampered = JSON.parse(readFileSync(planned.plan.path, "utf8"));
		tampered.targetVersion = "0.2.1";
		writeFileSync(planned.plan.path, `${JSON.stringify(tampered, null, 2)}\n`);
		await expect(applyUpgrade({ plan: planned.plan.id, dir, yes: true })).rejects.toMatchObject({ code: "UPGRADE_PLAN_TAMPERED", stage: "upgrade.apply" });
		await expect(planUpgrade({ target: "bad/version", dir })).rejects.toMatchObject({ code: "UPGRADE_VERSION_INVALID" });
		await expect(verifyUpgrade({ plan: planned.plan.id, dir, healthUrl: "https://user:secret@example.test/health" })).rejects.toMatchObject({ code: "UPGRADE_HEALTH_URL_INVALID" });
		await expect(verifyUpgrade({ plan: planned.plan.id, dir, healthUrl: "https://example.test/health?token=secret" })).rejects.toMatchObject({ code: "UPGRADE_HEALTH_URL_INVALID" });
	});

	it("rejects symlinked artifacts", async () => {
		const dir = directory();
		const planned = await planUpgrade({ target: "0.2.0", current: "0.1.1", dir });
		const original = `${planned.plan.path}.original`;
		writeFileSync(original, readFileSync(planned.plan.path));
		rmSync(planned.plan.path);
		symlinkSync(original, planned.plan.path);
		await expect(verifyUpgrade({ plan: planned.plan.id, dir, dryRun: true })).rejects.toMatchObject({ code: "UPGRADE_PLAN_INVALID" });
	});

	it("rejects a symlinked artifact directory", async () => {
		const parent = directory();
		const target = join(parent, "real");
		const link = join(parent, "linked");
		mkdirSync(target);
		symlinkSync(target, link);
		await expect(planUpgrade({ target: "0.2.0", current: "0.1.1", dir: link })).rejects.toMatchObject({ code: "UPGRADE_DIR_UNSAFE" });
	});

	it("maps child failures to a redacted structured error", async () => {
		const dir = directory();
		const planned = await planUpgrade({ target: "0.2.0", current: "0.1.1", dir });
		await expect(applyUpgrade({ plan: planned.plan.id, dir, yes: true })).rejects.toMatchObject({
			code: "UPGRADE_SCRIPT_FAILED",
			stage: "upgrade.apply",
		});
	});
});
