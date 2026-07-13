#!/usr/bin/env bash
# Apply an upgrade plan: preflight + verified backup, then controlled apply steps.
# Fail closed. Records rollback reference. Does not silently mutate without backup.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

usage() {
  cat <<'EOF'
Usage: upgrade-apply.sh --plan PLAN_ID_OR_PATH [--dir DIR] [--backup-dir DIR]

Sequence (fail closed):
  1. preflight
  2. backup-create + backup-verify (mandatory)
  3. required deploy/upgrades/steps/<target>/apply.sh
  4. write version marker file + state journal
  5. record rollbackReference = verified backup

Does not drop or overwrite the active database.
EOF
}

PLAN_DIR="${CLEARANCE_UPGRADE_DIR:-$ROOT/.clearance/upgrades}"
BACKUP_DIR="${CLEARANCE_BACKUP_DIR:-$ROOT/.clearance/backups}"
PLAN_REF=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) PLAN_REF="$2"; shift 2 ;;
    --dir) PLAN_DIR="$2"; shift 2 ;;
    --backup-dir) BACKUP_DIR="$2"; shift 2 ;;
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
[[ "$PLAN_ID" =~ ^upg_[0-9TZ]+_[a-f0-9]+$ ]] || die "plan id is unsafe"
STATE_PATH="$PLAN_DIR/${PLAN_ID}.state.json"
TARGET="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.targetVersion)' "$PLAN_PATH")"
CURRENT="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.currentVersion)' "$PLAN_PATH")"
assert_safe_version "$CURRENT" "current version"
assert_safe_version "$TARGET" "target version"

# 1. Preflight
bash "$ROOT/scripts/upgrade-preflight.sh" --plan "$PLAN_PATH" --dir "$PLAN_DIR"

# 2. Mandatory verified backup when DATABASE_URL is set (or plan has source DB)
SOURCE_DB="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.sourceDatabase||"")' "$PLAN_PATH")"
BACKUP_ID=""
BACKUP_DUMP=""
BACKUP_META=""
BACKUP_EVIDENCE=""

if [[ -n "$SOURCE_DB" || -n "${DATABASE_URL:-}" ]]; then
  require_pg_client
  URL="$(resolve_database_url)"
  export DATABASE_URL="$URL"
  CREATE_OUT="$(bash "$ROOT/scripts/backup-create.sh" --dir "$BACKUP_DIR")"
  BACKUP_ID="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_ID=//p' | tail -1)"
  BACKUP_DUMP="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_DUMP=//p' | tail -1)"
  BACKUP_META="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_META=//p' | tail -1)"
  BACKUP_EVIDENCE="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_EVIDENCE=//p' | tail -1)"
  [[ -n "$BACKUP_ID" && -f "$BACKUP_DUMP" && -f "$BACKUP_META" && -f "$BACKUP_EVIDENCE" ]] || die "backup-create failed to produce artifacts"
  bash "$ROOT/scripts/backup-verify.sh" --id "$BACKUP_ID" --dir "$BACKUP_DIR" >/dev/null
  # Isolated restore verification before apply
  bash "$ROOT/scripts/backup-restore-verify.sh" --id "$BACKUP_ID" --dir "$BACKUP_DIR" >/dev/null
else
  die "upgrade-apply requires DATABASE_URL / plan sourceDatabase so a verified backup can be taken"
fi

# Persist the verified rollback reference before any version-specific hook runs.
# A missing or failing hook therefore leaves recoverable evidence in plan state.
node -e '
  const fs=require("fs");
  const p=process.argv[1];
  const backupId=process.argv[2];
  const dump=process.argv[3];
  const meta=process.argv[4];
  const evidence=process.argv[5];
  const j=JSON.parse(fs.readFileSync(p,"utf8"));
  const at=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
  j.status="backup_verified";
  j.updatedAt=at;
  j.backupId=backupId;
  j.backupDump=dump;
  j.backupMeta=meta;
  j.backupEvidence=evidence;
  j.rollbackReference={
    type:"verified_pg_dump",
    backupId,
    dump,
    meta,
    evidence,
    note:"Verified by checksum, archive inspection, and isolated restore before apply"
  };
  j.applyJournal=j.applyJournal||[];
  j.applyJournal.push({at,event:"backup_verified",backupId});
  fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");
' "$STATE_PATH" "$BACKUP_ID" "$BACKUP_DUMP" "$BACKUP_META" "$BACKUP_EVIDENCE"

# 3. Required version-specific apply hook (operator-supplied, fail closed if absent/non-zero)
STEP="$ROOT/deploy/upgrades/steps/${TARGET}/apply.sh"
if [[ -f "$STEP" ]]; then
  printf 'upgrade-apply: running step hook %s\n' "$STEP" >&2
  bash "$STEP" --plan "$PLAN_PATH" --from "$CURRENT" --to "$TARGET" \
    || die "apply step hook failed (fail closed); rollbackReference=$BACKUP_ID"
else
  die "upgrade step hook missing: $STEP (refusing to record a no-op version transition); verified rollbackReference=$BACKUP_ID"
fi

# 4. Version marker (operational reference; not a fake health claim)
MARKER_DIR="$PLAN_DIR/markers"
mkdir -p "$MARKER_DIR"
MARKER="$MARKER_DIR/${PLAN_ID}.applied"
cat >"$MARKER" <<EOF
{
  "planId": $(json_escape "$PLAN_ID"),
  "fromVersion": $(json_escape "$CURRENT"),
  "toVersion": $(json_escape "$TARGET"),
  "appliedAt": $(json_escape "$(iso_now)"),
  "backupId": $(json_escape "$BACKUP_ID"),
  "backupDump": $(json_escape "$BACKUP_DUMP"),
  "backupMeta": $(json_escape "$BACKUP_META")
  ,"backupEvidence": $(json_escape "$BACKUP_EVIDENCE")
}
EOF

# 5. State update with rollback reference
node -e '
  const fs=require("fs");
  const p=process.argv[1];
  const backupId=process.argv[2];
  const dump=process.argv[3];
  const meta=process.argv[4];
  const marker=process.argv[5];
  const evidence=process.argv[6];
  const j=JSON.parse(fs.readFileSync(p,"utf8"));
  const at=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
  j.status="applied";
  j.updatedAt=at;
  j.backupId=backupId;
  j.backupDump=dump;
  j.backupMeta=meta;
  j.backupEvidence=evidence;
  j.rollbackReference.note="Apply completed; active restore remains an explicit operator runbook action";
  j.applyJournal=j.applyJournal||[];
  j.applyJournal.push({at, event:"applied", marker, backupId});
  fs.writeFileSync(p, JSON.stringify(j,null,2)+"\n");
' "$STATE_PATH" "$BACKUP_ID" "$BACKUP_DUMP" "$BACKUP_META" "$MARKER" "$BACKUP_EVIDENCE"

printf 'upgrade-apply: OK plan=%s target=%s backup=%s\n' "$PLAN_ID" "$TARGET" "$BACKUP_ID" >&2
printf 'PLAN_ID=%s\n' "$PLAN_ID"
printf 'BACKUP_ID=%s\n' "$BACKUP_ID"
printf 'ROLLBACK_REF=%s\n' "$BACKUP_ID"
printf 'APPLY_OK=1\n'
