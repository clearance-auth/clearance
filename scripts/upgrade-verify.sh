#!/usr/bin/env bash
# Post-apply upgrade verification: plan state, backup reference, schema health, optional HTTP.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

usage() {
  cat <<'EOF'
Usage: upgrade-verify.sh --plan PLAN_ID_OR_PATH [--dir DIR] [--health-url URL]
EOF
}

PLAN_DIR="${CLEARANCE_UPGRADE_DIR:-$ROOT/.clearance/upgrades}"
PLAN_REF=""
HEALTH_URL="${CLEARANCE_HEALTH_URL:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) PLAN_REF="$2"; shift 2 ;;
    --dir) PLAN_DIR="$2"; shift 2 ;;
    --health-url) HEALTH_URL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$PLAN_REF" ]] || die "--plan is required"
if [[ -f "$PLAN_REF" ]]; then
  PLAN_PATH="$PLAN_REF"
else
  PLAN_PATH="$PLAN_DIR/${PLAN_REF}.plan.json"
fi
[[ -f "$PLAN_PATH" ]] || die "plan not found"
require_cmd node

PLAN_ID="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.planId)' "$PLAN_PATH")"
STATE_PATH="$PLAN_DIR/${PLAN_ID}.state.json"
[[ -f "$STATE_PATH" ]] || die "state missing"

STATUS="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.status||"")' "$STATE_PATH")"
[[ "$STATUS" == "applied" || "$STATUS" == "verified" ]] || die "plan state is '$STATUS' (expected applied|verified)"

BACKUP_ID="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.backupId||"")' "$STATE_PATH")"
[[ -n "$BACKUP_ID" ]] || die "missing backupId rollback reference in state"
BACKUP_META="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.backupMeta||"")' "$STATE_PATH")"
[[ -f "$BACKUP_META" ]] || die "backup meta missing: $BACKUP_META"
bash "$ROOT/scripts/backup-verify.sh" --dump "$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.backupDump)' "$STATE_PATH")" --meta "$BACKUP_META" >/dev/null

# Schema still queryable
if [[ -n "${DATABASE_URL:-}" ]]; then
  require_pg_client
  URL="$(resolve_database_url)"
  psql_q "$URL" -c 'SELECT 1' >/dev/null || die "post-apply database health query failed"
  TARGET="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.targetVersion)' "$PLAN_PATH")"
  require_application_release "$URL" "$TARGET"
  assert_safe_version "$TARGET" "target version"
  LEDGER_PLAN="$(psql_q "$URL" -At -c "SELECT plan_id FROM clearance_schema_migrations WHERE version = '${TARGET}'")"
  [[ "$LEDGER_PLAN" == "$PLAN_ID" ]] || die "migration ledger missing plan/version transition"
  # Fingerprint may change after real migrations; ensure DB still has public schema access
  EV="$(mktemp "${TMPDIR:-/tmp}/clearance-post-ev.XXXXXX")"
  collect_db_evidence "$URL" "$EV"
  [[ -s "$EV" ]] || die "failed to collect post-apply schema evidence"
  rm -f "$EV"
  printf 'upgrade-verify: database evidence collected\n' >&2
fi

# Optional HTTP health
if [[ -n "$HEALTH_URL" ]]; then
  require_cmd curl
  code="$(curl -sS -o /dev/null -w '%{http_code}' "$HEALTH_URL" || true)"
  [[ "$code" == "200" ]] || die "health URL $HEALTH_URL returned HTTP $code"
  printf 'upgrade-verify: health URL OK\n' >&2
fi

# Applied marker exists
MARKER="$PLAN_DIR/markers/${PLAN_ID}.applied"
[[ -f "$MARKER" ]] || die "apply marker missing"

TARGET="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.targetVersion)' "$PLAN_PATH")"
MARKER_TO="$(node -e 'const fs=require("fs"); const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(j.toVersion||"")' "$MARKER")"
[[ "$MARKER_TO" == "$TARGET" ]] || die "marker version mismatch"

node -e '
  const fs=require("fs");
  const p=process.argv[1];
  const j=JSON.parse(fs.readFileSync(p,"utf8"));
  const at=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
  j.status="verified";
  j.updatedAt=at;
  j.applyJournal=j.applyJournal||[];
  j.applyJournal.push({at, event:"verified"});
  fs.writeFileSync(p, JSON.stringify(j,null,2)+"\n");
' "$STATE_PATH"

printf 'upgrade-verify: OK plan=%s target=%s\n' "$PLAN_ID" "$TARGET"
printf 'VERIFY_OK=1\n'
