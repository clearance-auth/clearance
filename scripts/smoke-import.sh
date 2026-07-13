#!/usr/bin/env bash
# Fail-closed package acceptance: pack shipping Clearance tarballs, install them
# into a genuinely empty consumer outside the workspace, and import public entry points
# only from the installed tarballs (never workspace node_modules or source).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Prefer OS temp outside the monorepo so installers cannot walk into the workspace.
BASE="${TMPDIR:-/tmp}"
case "$BASE" in
  "$ROOT"|"$ROOT"/*) BASE="/tmp" ;;
esac
SCRATCH="$(mktemp -d "${BASE}/clearance-smoke-import.XXXXXX")"
PACK="$SCRATCH/tarballs"
CONSUMER="$SCRATCH/consumer"
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

mkdir -p "$PACK" "$CONSUMER"

fail() {
  echo "SMOKE_IMPORT_FAILED: $*" >&2
  exit 1
}

# Shipping Clearance product packages under acceptance.
SHIPPING=(
  "@clearance/auth"
  "@clearance/management"
  "@clearance/cli"
  "@clearance/api"
)

required_dist_for() {
  case "$1" in
    "@clearance/auth") echo "dist/index.mjs dist/client.mjs dist/node.mjs types/index.d.ts types/client.d.ts types/node.d.ts" ;;
    "@clearance/management") echo "dist/index.mjs" ;;
    "@clearance/cli") echo "dist/index.js dist/ops/scripts/upgrade-plan.sh dist/ops/scripts/upgrade-preflight.sh dist/ops/scripts/upgrade-apply.sh dist/ops/scripts/upgrade-verify.sh dist/ops/scripts/upgrade-rollback.sh dist/ops/scripts/scim-legacy-preflight.sh dist/ops/scripts/validate-production-env.sh dist/ops/scripts/backup-create.sh dist/ops/scripts/backup-verify.sh dist/ops/scripts/backup-restore-verify.sh dist/ops/scripts/lib/ops-common.sh dist/ops/deploy/upgrades/steps/0.2.0/apply.sh dist/ops/deploy/compose/docker-compose.production.yml" ;;
    "@clearance/api") echo "dist/server.js" ;;
    *) return 1 ;;
  esac
}

echo "scratch=$SCRATCH"

pack_all() {
  local pkg
  for pkg in "${SHIPPING[@]}"; do
    pnpm --filter "$pkg" pack --pack-destination "$PACK" >/dev/null \
      || fail "pack failed for $pkg"
  done
}

tarball_for() {
  local pkg="$1"
  node -e "
    const fs=require('fs'); const {execSync}=require('child_process');
    const dir=process.argv[1]; const want=process.argv[2];
    for (const f of fs.readdirSync(dir).filter(x=>x.endsWith('.tgz'))) {
      const pj=JSON.parse(execSync('tar -xzf '+JSON.stringify(dir+'/'+f)+' -O package/package.json',{encoding:'utf8'}));
      if (pj.name===want) { process.stdout.write(dir+'/'+f); process.exit(0); }
    }
    process.exit(1);
  " "$PACK" "$pkg"
}

verify_shipping_tarball() {
  local pkg="$1"
  local tgz extract rel safe required pj
  tgz="$(tarball_for "$pkg")" || fail "no tarball for $pkg"
  safe="$(echo "$pkg" | tr '/@' '__')"
  extract="$SCRATCH/verify-$safe"
  mkdir -p "$extract"
  tar -xzf "$tgz" -C "$extract"
  pj="$extract/package/package.json"
  [[ -f "$pj" ]] || fail "$pkg: missing package.json"
  if grep -E '"workspace:' "$pj" >/dev/null 2>&1; then
    fail "$pkg: workspace: remains in tarball"
  fi
  if grep -E '"catalog:' "$pj" >/dev/null 2>&1; then
    fail "$pkg: catalog: remains in tarball"
  fi
  required="$(required_dist_for "$pkg")" || fail "$pkg: no required dist map entry"
  for rel in $required; do
    [[ -f "$extract/package/$rel" ]] || fail "$pkg: missing $rel"
  done
}

write_consumer_manifest() {
  node -e "
    const fs=require('fs');
    const path=require('path');
    const {execSync}=require('child_process');
    const pack=process.argv[1];
    const consumer=process.argv[2];
    const deps={};
    for (const f of fs.readdirSync(pack).filter(x=>x.endsWith('.tgz'))) {
      const abs=path.join(pack,f);
      const pj=JSON.parse(execSync('tar -xzf '+JSON.stringify(abs)+' -O package/package.json',{encoding:'utf8'}));
      deps[pj.name]='file:'+abs;
    }
    const pkg={
      name:'clearance-tarball-consumer',
      private:true,
      type:'module',
      dependencies:deps,
      devDependencies:{
        typescript:'^5.9.3',
        '@types/node':'^22.13.10',
      },
    };
    fs.writeFileSync(path.join(consumer,'package.json'), JSON.stringify(pkg,null,2)+'\\n');
    console.log('consumer_deps='+Object.keys(deps).length);
  " "$PACK" "$CONSUMER"
}

install_consumer() {
  cd "$CONSUMER"
  # Isolated install: no workspace, no monorepo node_modules.
  # Generate a lockfile then reinstall frozen for determinism.
  npm install --no-fund --no-audit --package-lock-only >/dev/null \
    || fail "npm package-lock generation failed"
  [[ -f package-lock.json ]] || fail "package-lock.json not generated"
  npm ci --no-fund --no-audit \
    || fail "npm ci frozen install failed"
  cd "$ROOT"
}

assert_declaration_compile() {
  cd "$CONSUMER"
  node --input-type=module <<'EOF' || exit 1
import fs from "node:fs";

fs.writeFileSync("consumer.ts", `
import { createClearanceAuth, type CreateClearanceAuthOptions } from "@clearance/auth";
import { JsonStore, type ManagementStore } from "@clearance/management";
import type {} from "@clearance/auth/client";
import type {} from "@clearance/auth/node";

declare const options: CreateClearanceAuthOptions;
declare const store: ManagementStore;
void createClearanceAuth;
void JsonStore;
void options;
void store;
`);
fs.writeFileSync("tsconfig.json", `${JSON.stringify({
  compilerOptions: {
    target: "ES2022",
    module: "NodeNext",
    moduleResolution: "NodeNext",
    strict: true,
    skipLibCheck: false,
    noEmit: true,
    types: ["node"],
    lib: ["ES2022", "DOM"],
  },
  include: ["consumer.ts"],
}, null, 2)}\n`);
EOF
  ./node_modules/.bin/tsc -p tsconfig.json \
    || fail "published declaration compile failed with skipLibCheck=false"
  cd "$ROOT"
  echo "declaration_compile=ok"
}

assert_isolated_resolution() {
  cd "$CONSUMER"
  # Embed monorepo root so the consumer can detect accidental workspace leaks.
  ROOT_FOR_CHECK="$ROOT" node --input-type=module <<'EOF' || exit 1
import { createRequire } from "node:module";
import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { spawnSync } from "node:child_process";

const consumerRoot = process.cwd();
const monorepoRoot = process.env.ROOT_FOR_CHECK || "";
const require = createRequire(path.join(consumerRoot, "package.json"));
const rootReal = fs.realpathSync(consumerRoot);
const monoReal = monorepoRoot ? fs.realpathSync(monorepoRoot) : "";

function assertUnderConsumer(label, resolved) {
  const real = fs.realpathSync(resolved);
  if (!real.startsWith(rootReal + path.sep) && real !== rootReal) {
    console.error("SMOKE_IMPORT_FAILED: resolution escaped consumer:", label, real);
    process.exit(1);
  }
  if (monoReal) {
    const pkgLeak = path.join(monoReal, "packages") + path.sep;
    const nmLeak = path.join(monoReal, "node_modules") + path.sep;
    if (real.startsWith(pkgLeak)) {
      console.error("SMOKE_IMPORT_FAILED: workspace source leak:", label, real);
      process.exit(1);
    }
    if (real.startsWith(nmLeak)) {
      console.error("SMOKE_IMPORT_FAILED: workspace node_modules leak:", label, real);
      process.exit(1);
    }
  }
  return real;
}

/** Locate installed package.json without relying on exports['./package.json']. */
function packageJsonPath(name) {
  let start;
  try {
    start = path.dirname(require.resolve(name));
  } catch {
    // Packages whose main is not exported as bare name (unlikely) — try node_modules path.
    start = path.join(consumerRoot, "node_modules", ...name.split("/"));
  }
  let dir = start;
  for (let i = 0; i < 8; i++) {
    const candidate = path.join(dir, "package.json");
    if (fs.existsSync(candidate)) {
      try {
        const pj = JSON.parse(fs.readFileSync(candidate, "utf8"));
        if (pj.name === name) return candidate;
      } catch {
        /* continue */
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // Fallback: standard node_modules layout inside consumer.
  const direct = path.join(consumerRoot, "node_modules", ...name.split("/"), "package.json");
  if (fs.existsSync(direct)) return direct;
  throw new Error("package.json not found for " + name);
}

const mustResolve = ["@clearance/auth", "@clearance/management", "@clearance/cli", "@clearance/api"];
for (const id of mustResolve) {
  const resolved = require.resolve(id);
  assertUnderConsumer(id, resolved);
  const pj = packageJsonPath(id);
  assertUnderConsumer(id + "/package.json", pj);
  console.log("resolved", id, "->", path.relative(consumerRoot, resolved));
}

for (const forbidden of ["clearance", "@clearance/sso", "@clearance/scim", "@clearance/core"]) {
  const candidate = path.join(consumerRoot, "node_modules", ...forbidden.split("/"), "package.json");
  if (fs.existsSync(candidate)) {
    console.error("SMOKE_IMPORT_FAILED: substitutable fork dependency was installed:", forbidden);
    process.exit(1);
  }
}

// Public entry points from installed tarballs only.
const auth = await import("@clearance/auth");
const {
  createClearanceAuth,
  clearance,
  organization,
  sso,
  scim,
  withClearanceDefaults,
  CLEARANCE_AUTH_VERSION,
} = auth;

const management = await import("@clearance/management");
const { JsonStore } = management;

const client = await import("@clearance/auth/client");
const node = await import("@clearance/auth/node");

// API public entry (side-effect free unless executed as main).
const api = await import("@clearance/api");

const checks = [
  ["createClearanceAuth", typeof createClearanceAuth === "function"],
  ["clearance", typeof clearance === "function"],
  ["organization", typeof organization === "function"],
  ["sso", typeof sso === "function"],
  ["scim", typeof scim === "function"],
  ["withClearanceDefaults", typeof withClearanceDefaults === "function"],
  ["CLEARANCE_AUTH_VERSION", typeof CLEARANCE_AUTH_VERSION === "string"],
  ["JsonStore", typeof JsonStore === "function"],
  ["auth/client", client != null && typeof client === "object"],
  ["auth/node", node != null && typeof node === "object"],
  ["api.start", typeof api.start === "function"],
  ["api.app", api.app != null],
];

const failed = checks.filter(([, ok]) => !ok).map(([name]) => name);
if (failed.length) {
  console.error("SMOKE_IMPORT_FAILED:", failed.join(", "));
  process.exit(1);
}

const defaults = withClearanceDefaults({ baseURL: "http://localhost:3300" });
if (defaults.telemetry?.enabled !== false) {
  console.error("SMOKE_IMPORT_FAILED: telemetry not disabled by defaults");
  process.exit(1);
}

// Execute CLI entry from installed tarball.
const clearancePkgDir = path.dirname(packageJsonPath("@clearance/cli"));
const clearanceBin = path.join(clearancePkgDir, "dist", "index.js");
assertUnderConsumer("clearance.bin", clearanceBin);
if (!fs.existsSync(clearanceBin)) {
  console.error("SMOKE_IMPORT_FAILED: clearance bin missing", clearanceBin);
  process.exit(1);
}
const help = spawnSync(process.execPath, [clearanceBin, "--help"], {
  encoding: "utf8",
  env: { ...process.env, NODE_PATH: "", DATABASE_URL: "" },
  cwd: consumerRoot,
});
if (help.status !== 0) {
  console.error("SMOKE_IMPORT_FAILED: clearance --help failed", help.stderr || help.stdout);
  process.exit(1);
}
if (!/Clearance CLI/i.test(help.stdout)) {
  console.error("SMOKE_IMPORT_FAILED: clearance --help unexpected output");
  process.exit(1);
}

// Execute an operational command from the installed tarball. This must use
// packaged scripts; the consumer has no monorepo scripts directory.
const upgradeDir = fs.mkdtempSync(path.join(os.tmpdir(), "clearance-packed-upgrade-"));
const upgradePlan = spawnSync(process.execPath, [
  clearanceBin,
  "--local-direct",
  "--json",
  "upgrade",
  "plan",
  "--target",
  "0.2.0",
  "--current",
  "0.1.1",
  "--dir",
  upgradeDir,
], {
	encoding: "utf8",
	env: { ...process.env, NODE_PATH: "", DATABASE_URL: "" },
  cwd: consumerRoot,
});
if (upgradePlan.status !== 0) {
  console.error("SMOKE_IMPORT_FAILED: packed clearance upgrade plan failed", upgradePlan.stderr || upgradePlan.stdout);
  process.exit(1);
}
const upgradeResult = JSON.parse(upgradePlan.stdout);
if (upgradeResult.operation !== "upgrade.plan" || upgradeResult.plan?.status !== "planned") {
  console.error("SMOKE_IMPORT_FAILED: packed clearance upgrade plan returned an invalid result");
  process.exit(1);
}
if (!fs.existsSync(upgradeResult.plan.path) || !upgradeResult.plan.path.startsWith(upgradeDir + path.sep)) {
  console.error("SMOKE_IMPORT_FAILED: packed clearance upgrade artifacts are missing or escaped their directory");
  process.exit(1);
}
const packagedPreflight = path.join(clearancePkgDir, "dist", "ops", "scripts", "upgrade-preflight.sh");
const preflight = spawnSync("bash", [
  packagedPreflight,
  "--plan",
  upgradeResult.plan.path,
  "--dir",
  upgradeDir,
], {
  encoding: "utf8",
  cwd: consumerRoot,
  env: {
    ...process.env,
    CLEARANCE_STRICT_SECRETS: "1",
    CLEARANCE_ALLOW_LOCALHOST_PRODUCTION: "1",
    CLEARANCE_OPERATOR_TOKEN: "packed-operator-token-value-32-chars",
    CLEARANCE_SECRET: "packed-clearance-secret-value-32-chars",
    CLEARANCE_CREDENTIAL_KEY: "packed-credential-key-value-32-chars",
    CLEARANCE_CREDENTIAL_KEY_ID: "packed-k1",
    CLEARANCE_CONSOLE_ADMIN_USER: "packed-admin",
    CLEARANCE_CONSOLE_ADMIN_PASSWORD: "packed-console-password-value-32",
    CLEARANCE_CONSOLE_SESSION_SECRET: "packed-console-session-value-32",
    CLEARANCE_DB_USER: "clearance_user",
    CLEARANCE_DB_PASSWORD: "packed-database-password-value-32",
    CLEARANCE_DB_NAME: "clearance_prod",
    DATABASE_URL: "postgres://clearance_user:packed-database-password-value-32@localhost:5432/clearance_prod",
    CLEARANCE_BASE_URL: "http://localhost:3000",
    CLEARANCE_CONSOLE_URL: "http://localhost:3100",
    CLEARANCE_CORS_ORIGINS: "http://localhost:3100",
    CLEARANCE_API_PORT: "3200",
    CLEARANCE_CONSOLE_PORT: "3100",
    CLEARANCE_SAMPLE_PORT: "3000",
    CLEARANCE_PG_VOLUME: "packed-pg",
    CLEARANCE_BACKUP_VOLUME: "packed-backups",
    CLEARANCE_IMAGE_REPOSITORY: "ghcr.io/example/clearance",
    CLEARANCE_IMAGE_DIGEST: `sha256:${"a".repeat(64)}`,
    CLEARANCE_BACKUP_IMAGE_REPOSITORY: "ghcr.io/example/clearance-backup",
    CLEARANCE_BACKUP_IMAGE_DIGEST: `sha256:${"b".repeat(64)}`,
  },
});
if (preflight.status !== 0 || !preflight.stdout.includes("PREFLIGHT_OK=1")) {
  console.error("SMOKE_IMPORT_FAILED: packed strict upgrade preflight failed", preflight.stderr || preflight.stdout);
  process.exit(1);
}
fs.rmSync(upgradeDir, { recursive: true, force: true });

// Prove installed package.json has no workspace leftovers.
for (const name of ["@clearance/auth", "@clearance/management", "@clearance/cli", "@clearance/api"]) {
  const pjPath = packageJsonPath(name);
  assertUnderConsumer(name + "/package.json", pjPath);
  const text = fs.readFileSync(pjPath, "utf8");
  if (text.includes("workspace:") || text.includes("catalog:")) {
    console.error("SMOKE_IMPORT_FAILED: installed", name, "still has workspace/catalog protocol");
    process.exit(1);
  }
}

console.log("SMOKE_IMPORT_OK", CLEARANCE_AUTH_VERSION);
EOF
  local rc=$?
  cd "$ROOT"
  [[ $rc -eq 0 ]] || fail "isolated import checks failed"
}

pack_all

shipping_count=0
for pkg in "${SHIPPING[@]}"; do
  verify_shipping_tarball "$pkg"
  shipping_count=$((shipping_count + 1))
done
echo "shipping_tarballs=$shipping_count"
[[ "$shipping_count" -eq "${#SHIPPING[@]}" ]] || fail "shipping tarball count mismatch"

tarball_total="$(find "$PACK" -maxdepth 1 -type f -name '*.tgz' | wc -l | tr -d ' ')"
echo "packed_tarballs=$tarball_total"
expected_total=${#SHIPPING[@]}
[[ "$tarball_total" -eq "$expected_total" ]] || fail "expected $expected_total tarballs, got $tarball_total"

write_consumer_manifest
install_consumer
assert_declaration_compile
assert_isolated_resolution
