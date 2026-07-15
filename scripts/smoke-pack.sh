#!/usr/bin/env bash
# Fail-closed pack smoke: pack shipping Clearance tarballs and verify contents.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/clearance-smoke-pack.XXXXXX")"
cleanup() { find "$TMP" -depth -delete 2>/dev/null || true; }
trap cleanup EXIT

# Shipping Clearance product packages (not inherited clearance runtime).
PACKAGES=(
  "@clearance/auth"
  "@clearance/management"
  "@clearance/cli"
  "@clearance/api"
)

fail() {
  echo "SMOKE_PACK_FAILED: $*" >&2
  exit 1
}

required_dist_for() {
  case "$1" in
    "@clearance/auth") echo "dist/index.mjs dist/client.mjs dist/node.mjs dist/secret-policy.mjs types/index.d.ts types/client.d.ts types/node.d.ts types/secret-policy.d.ts" ;;
    "@clearance/management") echo "dist/index.mjs" ;;
    "@clearance/cli") echo "dist/index.js dist/ops/scripts/upgrade-plan.sh dist/ops/scripts/upgrade-preflight.sh dist/ops/scripts/upgrade-apply.sh dist/ops/scripts/upgrade-verify.sh dist/ops/scripts/upgrade-rollback.sh dist/ops/scripts/scim-legacy-preflight.sh dist/ops/scripts/validate-production-env.sh dist/ops/scripts/backup-create.sh dist/ops/scripts/backup-verify.sh dist/ops/scripts/backup-restore-verify.sh dist/ops/scripts/lib/ops-common.sh dist/ops/deploy/upgrades/steps/0.2.1/apply.sh dist/ops/deploy/compose/docker-compose.production.yml" ;;
    "@clearance/api") echo "dist/server.js" ;;
    *) return 1 ;;
  esac
}

pack_one() {
  local pkg="$1"
  pnpm --filter "$pkg" pack --pack-destination "$TMP" >/dev/null
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
  " "$TMP" "$pkg"
}

verify_tarball() {
  local pkg="$1"
  local tgz extract pj required rel safe
  tgz="$(tarball_for "$pkg")" || fail "no tarball for $pkg"

  safe="$(echo "$pkg" | tr '/@' '__')"
  extract="$TMP/extract-$safe"
  mkdir -p "$extract"
  tar -xzf "$tgz" -C "$extract"

  pj="$extract/package/package.json"
  [[ -f "$pj" ]] || fail "$pkg: missing package.json in tarball"

  # Fail closed: workspace/catalog protocols must not ship (pnpm pack rewrites them).
  if grep -E '"workspace:' "$pj" >/dev/null 2>&1; then
    fail "$pkg: workspace: protocol remains in packed package.json"
  fi
  if grep -E '"catalog:' "$pj" >/dev/null 2>&1; then
    fail "$pkg: catalog: protocol remains in packed package.json"
  fi

  required="$(required_dist_for "$pkg")" || fail "$pkg: no required dist map entry"
  for rel in $required; do
    [[ -f "$extract/package/$rel" ]] || fail "$pkg: missing $rel in tarball"
  done

  # exports / main / bin must point at dist, not src-only.
  node -e "
    const fs=require('fs');
    const pj=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));
    const bad=[];
    const check=(label,p)=>{
      if (typeof p!=='string') return;
      if (p.includes('/src/') || p.startsWith('./src/') || p==='src') bad.push(label+':'+p);
      const declaration=label==='types'||label.endsWith('.types');
      if (!p.includes('dist') && !(declaration && p.includes('types'))) bad.push(label+': not packaged runtime/types: '+p);
    };
    if (pj.main) check('main', pj.main);
    if (pj.types) check('types', pj.types);
    if (pj.bin) {
      for (const [k,v] of Object.entries(typeof pj.bin==='string'?{bin:pj.bin}:pj.bin)) check('bin.'+k, v);
    }
    const walk=(obj,prefix)=>{
      if (!obj||typeof obj!=='object') return;
      for (const [k,v] of Object.entries(obj)) {
        const path=prefix+k;
        if (typeof v==='string') check('exports.'+path, v);
        else if (v && typeof v==='object') {
          if (v.default) check('exports.'+path+'.default', v.default);
          if (v.types) check('exports.'+path+'.types', v.types);
          if (v.import) check('exports.'+path+'.import', v.import);
          if (v.require) check('exports.'+path+'.require', v.require);
        }
      }
    };
    if (pj.exports) walk(pj.exports, '');
    if (bad.length) { console.error(bad.join('\\n')); process.exit(1); }
  " "$pj" || fail "$pkg: export/main points outside dist or is missing dist"

  echo "ok $pkg -> $(basename "$tgz")"
}

for pkg in "${PACKAGES[@]}"; do
  pack_one "$pkg"
done

count="$(find "$TMP" -maxdepth 1 -type f -name '*.tgz' | wc -l | tr -d ' ')"
echo "packed_tarballs=$count"
if [[ "$count" -lt "${#PACKAGES[@]}" ]]; then
  fail "expected ${#PACKAGES[@]} tarballs, got $count"
fi

for pkg in "${PACKAGES[@]}"; do
  verify_tarball "$pkg"
done

node scripts/verify-release-runtime-closure.mjs "$(tarball_for '@clearance/auth')"
node scripts/verify-release-runtime-closure.mjs "$(tarball_for '@clearance/management')"

echo "SMOKE_PACK_OK"
