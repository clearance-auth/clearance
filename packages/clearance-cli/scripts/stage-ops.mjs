import { chmodSync, copyFileSync, cpSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(packageRoot, "../..");
const outputRoot = resolve(packageRoot, "dist/ops");
const scripts = [
	"backup-create.sh",
	"backup-restore-verify.sh",
	"backup-verify.sh",
	"scim-legacy-preflight.sh",
	"upgrade-apply.sh",
	"upgrade-plan.sh",
	"upgrade-preflight.sh",
	"upgrade-rollback.sh",
	"upgrade-verify.sh",
	"validate-production-env.sh",
];

rmSync(outputRoot, { recursive: true, force: true });
mkdirSync(resolve(outputRoot, "scripts/lib"), { recursive: true });

for (const script of scripts) {
	const target = resolve(outputRoot, "scripts", script);
	copyFileSync(resolve(repoRoot, "scripts", script), target);
	chmodSync(target, 0o755);
}
copyFileSync(
	resolve(repoRoot, "scripts/lib/ops-common.sh"),
	resolve(outputRoot, "scripts/lib/ops-common.sh"),
);
cpSync(
	resolve(repoRoot, "deploy/upgrades"),
	resolve(outputRoot, "deploy/upgrades"),
	{ recursive: true },
);
mkdirSync(resolve(outputRoot, "deploy/compose"), { recursive: true });
copyFileSync(
	resolve(repoRoot, "deploy/compose/docker-compose.production.yml"),
	resolve(outputRoot, "deploy/compose/docker-compose.production.yml"),
);
chmodSync(resolve(outputRoot, "deploy/upgrades/steps/0.2.0/apply.sh"), 0o755);
chmodSync(resolve(outputRoot, "deploy/upgrades/steps/0.2.1/apply.sh"), 0o755);
