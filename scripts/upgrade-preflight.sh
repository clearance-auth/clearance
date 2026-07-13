#!/usr/bin/env bash
# Preflight checks for an upgrade plan. Fail closed.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

usage() {
  cat <<'EOF'
Usage: upgrade-preflight.sh --plan PLAN_ID_OR_PATH [--dir DIR]
EOF
}

PLAN_DIR="${CLEARANCE_UPGRADE_DIR:-$ROOT/.clearance/upgrades}"
PLAN_REF=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) PLAN_REF="$2"; shift 2 ;;
    --dir) PLAN_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$PLAN_REF" ]] || die "--plan is required"

if [[ -f "$PLAN_REF" ]]; then
  PLAN_PATH="$PLAN_REF"
else
  PLAN_PATH="$PLAN_DIR/${PLAN_REF}.plan.json"
  [[ -f "$PLAN_PATH" ]] || PLAN_PATH="$PLAN_DIR/${PLAN_REF}"
fi
[[ -f "$PLAN_PATH" ]] || die "plan not found: $PLAN_REF"
require_cmd node

PLAN_ID="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.planId)' "$PLAN_PATH")"
[[ "$PLAN_ID" =~ ^upg_[0-9TZ]+_[a-f0-9]+$ ]] || die "plan id is unsafe"
CURRENT="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.currentVersion)' "$PLAN_PATH")"
TARGET="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.targetVersion)' "$PLAN_PATH")"
assert_safe_version "$CURRENT" "current version"
assert_safe_version "$TARGET" "target version"
STATE_PATH="$PLAN_DIR/${PLAN_ID}.state.json"
[[ -f "$STATE_PATH" ]] || die "state sidecar missing for plan $PLAN_ID"
STATE_PLAN_ID="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.planId||"")' "$STATE_PATH")"
[[ "$STATE_PLAN_ID" == "$PLAN_ID" ]] || die "state sidecar plan id mismatch"

EXPECTED_PLAN_SHA="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.planSha256||"")' "$STATE_PATH")"
[[ -n "$EXPECTED_PLAN_SHA" ]] || die "state sidecar missing immutable plan checksum"
ACTUAL_PLAN_SHA="$(sha256_file "$PLAN_PATH")"
[[ "$ACTUAL_PLAN_SHA" == "$EXPECTED_PLAN_SHA" ]] || die "immutable plan checksum mismatch (re-plan required)"

errors=0
fail() { printf 'preflight fail: %s\n' "$*" >&2; errors=$((errors + 1)); }
ok() { printf 'preflight ok: %s\n' "$*"; }

# Plan immutability: refuse if plan body changed vs fingerprint of required fields
node -e '
  const j=require(process.argv[1]);
  if(!j.immutable) process.exit(2);
  if(!j.planId || !j.currentVersion || !j.targetVersion) process.exit(3);
  if(j.currentVersion === j.targetVersion) {
    console.error("target equals current — nothing to upgrade (fail closed for empty apply)");
    process.exit(4);
  }
' "$PLAN_PATH" || fail "plan invalid or target equals current"

# Database reachable when plan recorded a source database
SOURCE_DB="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.sourceDatabase||"")' "$PLAN_PATH")"
if [[ -n "$SOURCE_DB" ]]; then
  require_pg_client
  URL="$(resolve_database_url)"
  require_database_url "$URL"
  ACTIVE="$(db_name_from_url "$URL")"
  if [[ "$ACTIVE" != "$SOURCE_DB" ]]; then
    fail "active database '$ACTIVE' does not match plan sourceDatabase '$SOURCE_DB'"
  else
    ok "active database matches plan ($ACTIVE)"
  fi
  if ! psql_q "$URL" -c 'SELECT 1' >/dev/null 2>&1; then
    fail "cannot connect to DATABASE_URL"
  else
    ok "database connectivity"
  fi
  if require_application_release "$URL" "$CURRENT"; then
    ok "application release contract matches plan ($CURRENT)"
  else
    fail "application release contract does not match plan currentVersion"
  fi
  if bash "$ROOT/scripts/scim-legacy-preflight.sh" >/dev/null; then
    ok "legacy personal/global SCIM credential inventory is empty"
  else
    fail "legacy personal/global SCIM credentials remain; inventory and revoke before upgrade"
  fi
  # Schema fingerprint drift warning as hard fail for preflight
  EV="$(mktemp "${TMPDIR:-/tmp}/clearance-pre-ev.XXXXXX")"
  collect_db_evidence "$URL" "$EV"
  NOW_FP="$(schema_fingerprint_from_evidence "$EV")"
  rm -f "$EV"
  PLAN_FP="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.schemaFingerprintSha256||"")' "$PLAN_PATH")"
  if [[ -n "$PLAN_FP" && "$PLAN_FP" != "no-database-url" && "$PLAN_FP" != "$NOW_FP" ]]; then
    fail "schema fingerprint changed since plan was created (re-plan required)"
  else
    ok "schema fingerprint matches plan"
  fi
else
  ok "plan has no source database (offline plan)"
fi

# Production env optional: if CLEARANCE_STRICT_SECRETS=1, require strong secrets
if [[ "${CLEARANCE_STRICT_SECRETS:-}" == "1" ]]; then
  if ! bash "$ROOT/scripts/validate-production-env.sh" >/dev/null 2>&1; then
    fail "CLEARANCE_STRICT_SECRETS=1 but validate-production-env failed"
  else
    ok "production env validation"
  fi
fi

if [[ "$errors" -ne 0 ]]; then
  die "upgrade-preflight failed ($errors checks)"
fi

node -e '
  const fs=require("fs");
  const p=process.argv[1];
  const j=JSON.parse(fs.readFileSync(p,"utf8"));
  j.status="preflight_ok";
  j.updatedAt=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
  j.applyJournal=j.applyJournal||[];
  j.applyJournal.push({at:j.updatedAt, event:"preflight_ok"});
  fs.writeFileSync(p, JSON.stringify(j,null,2)+"\n");
' "$STATE_PATH"

printf 'upgrade-preflight: OK plan=%s\n' "$PLAN_ID"
printf 'PREFLIGHT_OK=1\n'
