#!/usr/bin/env bash
# Verify or execute a deterministic rollback from an upgrade plan.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"
umask 077

usage() {
  cat <<'EOF'
Usage: upgrade-rollback.sh --plan PLAN_ID_OR_PATH [--dir DIR]
       upgrade-rollback.sh --plan PLAN_ID_OR_PATH --restore-active \
         --confirm RESTORE_ACTIVE:<plan-id>:<database> [--backup-dir DIR]

Default behavior verifies the immutable rollback backup in an isolated database
and writes a drill receipt. --restore-active performs the real active-database
rollback only with the exact confirmation token. The active path:
  1. serializes operators with a held Postgres advisory lock
  2. creates and restore-verifies a pre-restore safety backup
  3. restores and verifies the rollback backup in a staging database
  4. drains connections and swaps database names
  5. verifies counts and application version while retaining the drained old database
  6. writes an owner-only rollback receipt and plan-state journal entry
EOF
}

PLAN_DIR="${CLEARANCE_UPGRADE_DIR:-$ROOT/.clearance/upgrades}"
BACKUP_DIR="${CLEARANCE_BACKUP_DIR:-$ROOT/.clearance/backups}"
PLAN_REF=""
RESTORE_ACTIVE=0
CONFIRM=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) PLAN_REF="$2"; shift 2 ;;
    --dir) PLAN_DIR="$2"; shift 2 ;;
    --backup-dir) BACKUP_DIR="$2"; shift 2 ;;
    --restore-active) RESTORE_ACTIVE=1; shift ;;
    --confirm) CONFIRM="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$PLAN_REF" ]] || die "--plan is required"
if [[ -f "$PLAN_REF" ]]; then PLAN_PATH="$PLAN_REF"; else PLAN_PATH="$PLAN_DIR/${PLAN_REF}.plan.json"; fi
[[ -f "$PLAN_PATH" ]] || die "plan not found"
require_cmd node
require_cmd openssl
require_pg_client

PLAN_ID="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.planId)' "$PLAN_PATH")"
[[ "$PLAN_ID" =~ ^upg_[0-9TZ]+_[a-f0-9]+$ ]] || die "plan id is unsafe"
STATE_PATH="$PLAN_DIR/${PLAN_ID}.state.json"
[[ -f "$STATE_PATH" ]] || die "state missing"
EXPECTED_PLAN_SHA="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.planSha256||"")' "$STATE_PATH")"
[[ -n "$EXPECTED_PLAN_SHA" && "$(sha256_file "$PLAN_PATH")" == "$EXPECTED_PLAN_SHA" ]] \
  || die "immutable plan checksum mismatch"

BACKUP_ID="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.backupId||(j.rollbackReference&&j.rollbackReference.backupId)||"")' "$STATE_PATH")"
BACKUP_DUMP="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.backupDump||(j.rollbackReference&&j.rollbackReference.dump)||"")' "$STATE_PATH")"
BACKUP_META="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.backupMeta||(j.rollbackReference&&j.rollbackReference.meta)||"")' "$STATE_PATH")"
BACKUP_EVIDENCE="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.backupEvidence||(j.rollbackReference&&j.rollbackReference.evidence)||"")' "$STATE_PATH")"
[[ -n "$BACKUP_ID" && -f "$BACKUP_DUMP" && -f "$BACKUP_META" && -f "$BACKUP_EVIDENCE" ]] \
  || die "rollback reference is incomplete or its immutable artifacts are missing"

URL="$(resolve_database_url)"
require_database_url "$URL"
export DATABASE_URL="$URL"
ACTIVE_DB="$(db_name_from_url "$URL")"
assert_safe_ident "$ACTIVE_DB" "active database"
ADMIN_URL="$(admin_url_from_url "$URL")"
SOURCE_DB="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.sourceDatabase||"")' "$BACKUP_META")"
[[ "$SOURCE_DB" == "$ACTIVE_DB" ]] || die "rollback backup source database does not match active database"

bash "$ROOT/scripts/backup-verify.sh" --dump "$BACKUP_DUMP" --meta "$BACKUP_META" --evidence "$BACKUP_EVIDENCE" >/dev/null
bash "$ROOT/scripts/backup-restore-verify.sh" --dump "$BACKUP_DUMP" --meta "$BACKUP_META" >/dev/null

RECEIPT_DIR="$PLAN_DIR/rollbacks"
mkdir -p "$RECEIPT_DIR"
chmod 700 "$RECEIPT_DIR"

if [[ "$RESTORE_ACTIVE" -eq 0 ]]; then
  RECEIPT="$RECEIPT_DIR/${PLAN_ID}.rollback-drill.json"
  RECEIPT_TMP="$(mktemp "$RECEIPT_DIR/.${PLAN_ID}.rollback-drill.XXXXXX")"
  cat >"$RECEIPT_TMP" <<EOF
{
  "planId": $(json_escape "$PLAN_ID"),
  "verifiedAt": $(json_escape "$(iso_now)"),
  "mode": "isolated_verify_only",
  "backupId": $(json_escape "$BACKUP_ID"),
  "backupDumpSha256": $(json_escape "$(sha256_file "$BACKUP_DUMP")"),
  "backupMetaSha256": $(json_escape "$(sha256_file "$BACKUP_META")"),
  "backupEvidenceSha256": $(json_escape "$(sha256_file "$BACKUP_EVIDENCE")"),
  "activeDatabaseUntouched": true
}
EOF
  chmod 400 "$RECEIPT_TMP"
  mv -f "$RECEIPT_TMP" "$RECEIPT"
  printf 'upgrade-rollback: DRILL OK; active environment unchanged plan=%s backup=%s\n' "$PLAN_ID" "$BACKUP_ID" >&2
  printf 'ROLLBACK_RECEIPT=%s\n' "$RECEIPT"
  printf 'ROLLBACK_DRILL_OK=1\n'
  exit 0
fi

STATUS="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.status||"")' "$STATE_PATH")"
[[ "$STATUS" == "applied" || "$STATUS" == "verified" ]] \
  || die "active rollback requires plan state applied or verified (found $STATUS)"
EXPECTED_CONFIRM="RESTORE_ACTIVE:${PLAN_ID}:${ACTIVE_DB}"
[[ "$CONFIRM" == "$EXPECTED_CONFIRM" ]] \
  || die "active rollback confirmation mismatch; required --confirm $EXPECTED_CONFIRM"
TARGET_VERSION="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.targetVersion)' "$PLAN_PATH")"
require_application_release "$URL" "$TARGET_VERSION"

# Keep one session open while the operation runs. pg_try_advisory_lock is
# session-scoped, so a second rollback operator fails before taking a backup.
# Named pipes keep this compatible with macOS Bash 3.2 (no coproc dependency).
LOCK_KEY=7176324950072026
LOCK_PIPE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/clearance-rollback-lock.XXXXXX")"
LOCK_IN="$LOCK_PIPE_DIR/in"
LOCK_OUT="$LOCK_PIPE_DIR/out"
mkfifo "$LOCK_IN" "$LOCK_OUT"
psql --no-psqlrc -qAt -v ON_ERROR_STOP=1 "$ADMIN_URL" <"$LOCK_IN" >"$LOCK_OUT" &
LOCK_PID=$!
exec 8>"$LOCK_IN"
exec 9<"$LOCK_OUT"
printf 'SELECT pg_try_advisory_lock(%s);\n' "$LOCK_KEY" >&8
if ! IFS= read -r LOCKED <&9; then
  exec 8>&-
  exec 9<&-
  wait "$LOCK_PID" 2>/dev/null || true
  find "$LOCK_PIPE_DIR" -type p -delete 2>/dev/null || true
  rmdir "$LOCK_PIPE_DIR" 2>/dev/null || true
  die "could not acquire rollback advisory lock"
fi
[[ "$LOCKED" == "t" ]] || {
  printf '\\q\n' >&8 2>/dev/null || true
  exec 8>&-
  exec 9<&-
  wait "$LOCK_PID" 2>/dev/null || true
  find "$LOCK_PIPE_DIR" -type p -delete 2>/dev/null || true
  rmdir "$LOCK_PIPE_DIR" 2>/dev/null || true
  die "another active-database recovery operation holds the advisory lock"
}

STAGE_DB="clr_rb_$(openssl rand -hex 4)"
OLD_DB="clr_old_$(openssl rand -hex 4)"
assert_safe_ident "$STAGE_DB" "rollback staging database"
assert_safe_ident "$OLD_DB" "pre-rollback database"
STAGE_CREATED=0
SWAPPED=0
LOCK_RELEASED=0
FAILED_DB=""

database_exists() {
  local name="$1"
  [[ "$(psql_q "$ADMIN_URL" -At -c "SELECT count(*) FROM pg_database WHERE datname='${name}';" 2>/dev/null || printf '0')" == "1" ]]
}

database_oid() {
  local name="$1"
  psql_q "$ADMIN_URL" -At -c "SELECT oid::text FROM pg_database WHERE datname='${name}';" 2>/dev/null | head -n1
}

journal_rollback_failure() {
  local event="$1"
  local recovered="$2"
  local detail="$3"
  ROLLBACK_EVENT="$event" ROLLBACK_RECOVERED="$recovered" ROLLBACK_DETAIL="$detail" \
  ROLLBACK_ACTIVE_DB="$ACTIVE_DB" ROLLBACK_STAGE_DB="$STAGE_DB" \
  ROLLBACK_OLD_DB="$OLD_DB" ROLLBACK_FAILED_DB="$FAILED_DB" node -e '
    const fs=require("fs");
    const p=process.argv[1];
    const j=JSON.parse(fs.readFileSync(p,"utf8"));
    const at=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
    const exists=(v)=>v ? v : null;
    j.status="rollback_failed";
    j.updatedAt=at;
    j.rollbackFailure={
      at,
      event:process.env.ROLLBACK_EVENT,
      recovered:process.env.ROLLBACK_RECOVERED==="true",
      detail:process.env.ROLLBACK_DETAIL,
      databases:{
        active:exists(process.env.ROLLBACK_ACTIVE_DB),
        staging:exists(process.env.ROLLBACK_STAGE_DB),
        preRollback:exists(process.env.ROLLBACK_OLD_DB),
        failedRestore:exists(process.env.ROLLBACK_FAILED_DB)
      }
    };
    j.applyJournal=j.applyJournal||[];
    j.applyJournal.push({at,event:"active_database_rollback_failed",...j.rollbackFailure});
    fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");
  ' "$STATE_PATH"
}

cleanup() {
  local ec=$?
  # Only clean an unmistakably isolated staging DB. If the active name is
  # absent or the old name exists, preserve every database for recovery.
  if [[ "$STAGE_CREATED" -eq 1 && "$SWAPPED" -eq 0 ]] \
    && database_exists "$ACTIVE_DB" && ! database_exists "$OLD_DB"; then
    psql_q "$ADMIN_URL" -c "DROP DATABASE IF EXISTS \"${STAGE_DB}\" WITH (FORCE);" >/dev/null 2>&1 || true
  fi
  if [[ "$LOCK_RELEASED" -eq 0 ]]; then
    printf 'SELECT pg_advisory_unlock(%s);\n\\q\n' "$LOCK_KEY" >&8 2>/dev/null || true
    exec 8>&-
    exec 9<&-
    wait "$LOCK_PID" 2>/dev/null || true
  fi
  find "$LOCK_PIPE_DIR" -type p -delete 2>/dev/null || true
  rmdir "$LOCK_PIPE_DIR" 2>/dev/null || true
  exit "$ec"
}
trap cleanup EXIT INT TERM

# Preserve the current target-version database before any connection drain.
SAFETY_OUT="$(bash "$ROOT/scripts/backup-create.sh" --dir "$BACKUP_DIR")"
SAFETY_ID="$(printf '%s\n' "$SAFETY_OUT" | sed -n 's/^BACKUP_ID=//p' | tail -1)"
SAFETY_DUMP="$(printf '%s\n' "$SAFETY_OUT" | sed -n 's/^BACKUP_DUMP=//p' | tail -1)"
SAFETY_META="$(printf '%s\n' "$SAFETY_OUT" | sed -n 's/^BACKUP_META=//p' | tail -1)"
SAFETY_EVIDENCE="$(printf '%s\n' "$SAFETY_OUT" | sed -n 's/^BACKUP_EVIDENCE=//p' | tail -1)"
[[ -n "$SAFETY_ID" && -f "$SAFETY_DUMP" && -f "$SAFETY_META" && -f "$SAFETY_EVIDENCE" ]] \
  || die "pre-restore safety backup is incomplete"
bash "$ROOT/scripts/backup-verify.sh" --id "$SAFETY_ID" --dir "$BACKUP_DIR" >/dev/null
bash "$ROOT/scripts/backup-restore-verify.sh" --id "$SAFETY_ID" --dir "$BACKUP_DIR" >/dev/null
if [[ "${CLEARANCE_OPS_TESTING:-0}" == "1" ]]; then
  if [[ -n "${CLEARANCE_ROLLBACK_TEST_AFTER_SAFETY_READY_FILE:-}" ]]; then
    : >"$CLEARANCE_ROLLBACK_TEST_AFTER_SAFETY_READY_FILE"
  fi
  delay="${CLEARANCE_ROLLBACK_TEST_DELAY_AFTER_SAFETY_SECONDS:-0}"
  [[ "$delay" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "invalid rollback testing delay"
  if [[ "$delay" != "0" ]]; then sleep "$delay"; fi
fi

# Preserve database owner, encoding, and locale in the staging database.
CREATE_STAGE_SQL="$(psql_q "$ADMIN_URL" -At -c "
  SELECT format('CREATE DATABASE %I WITH OWNER %I TEMPLATE template0 ENCODING %L LC_COLLATE %L LC_CTYPE %L',
    '${STAGE_DB}', pg_get_userbyid(datdba), pg_encoding_to_char(encoding), datcollate, datctype)
  FROM pg_database WHERE datname = '${ACTIVE_DB}';
")"
[[ -n "$CREATE_STAGE_SQL" ]] || die "could not capture active database creation contract"
psql_q "$ADMIN_URL" -c "$CREATE_STAGE_SQL" >/dev/null
STAGE_CREATED=1
STAGE_URL="$(url_with_db "$URL" "$STAGE_DB")"
psql_restore_file "$STAGE_URL" "$BACKUP_DUMP"
STAGE_EVIDENCE="$(mktemp "${TMPDIR:-/tmp}/clearance-active-restore.XXXXXX")"
collect_db_evidence "$STAGE_URL" "$STAGE_EVIDENCE"
compare_backup_evidence "$BACKUP_META" "$STAGE_EVIDENCE" >/dev/null
EXPECTED_BACKUP_VERSION="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.applicationVersion||"")' "$BACKUP_META")"
[[ -n "$EXPECTED_BACKUP_VERSION" ]] || die "rollback backup lacks an application version contract"
require_application_release "$STAGE_URL" "$EXPECTED_BACKUP_VERSION"
find "$STAGE_EVIDENCE" -type f -delete 2>/dev/null || true

# The restored staging DB is complete before traffic is drained. Rename swap
# keeps the destructive window short and preserves the old DB until live proof.
OLD_OID="$(database_oid "$ACTIVE_DB")"
[[ -n "$OLD_OID" ]] || die "could not capture original active database identity"
DRAIN_RENAME_OK=1
psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${ACTIVE_DB}\" WITH ALLOW_CONNECTIONS false;" >/dev/null \
  || DRAIN_RENAME_OK=0
if [[ "$DRAIN_RENAME_OK" -eq 1 ]]; then
  psql_q "$ADMIN_URL" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${ACTIVE_DB}' AND pid<>pg_backend_pid();" >/dev/null \
    || DRAIN_RENAME_OK=0
fi
if [[ "${CLEARANCE_OPS_TESTING:-0}" == "1" && "${CLEARANCE_ROLLBACK_TEST_FAIL_INITIAL_RENAME:-0}" == "1" ]]; then
  DRAIN_RENAME_OK=0
elif [[ "$DRAIN_RENAME_OK" -eq 1 ]]; then
  psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${ACTIVE_DB}\" RENAME TO \"${OLD_DB}\";" >/dev/null \
    || DRAIN_RENAME_OK=0
fi
if [[ "$DRAIN_RENAME_OK" -ne 1 ]]; then
  RECOVERED=false
  if database_exists "$OLD_DB" && ! database_exists "$ACTIVE_DB"; then
    psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${OLD_DB}\" RENAME TO \"${ACTIVE_DB}\";" >/dev/null 2>&1 || true
  fi
  if database_exists "$ACTIVE_DB" \
    && [[ "$(database_oid "$ACTIVE_DB")" == "$OLD_OID" ]] \
    && psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${ACTIVE_DB}\" WITH ALLOW_CONNECTIONS true;" >/dev/null 2>&1 \
    && database_exists "$ACTIVE_DB" && ! database_exists "$OLD_DB"; then
    RECOVERED=true
  fi
  journal_rollback_failure "active_database_drain_or_rename_failed" "$RECOVERED" \
    "active database drain or initial rename failed; catalog state was preserved"
  if [[ "$RECOVERED" == "true" ]]; then
    die "active database drain or rename failed; original database was verified as connection-enabled; failure journal written"
  fi
  die "active database drain or rename failed and recovery could not be verified; all databases preserved; failure journal written"
fi
if ! psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${STAGE_DB}\" RENAME TO \"${ACTIVE_DB}\";" >/dev/null; then
  RECOVERED=false
  if psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${OLD_DB}\" RENAME TO \"${ACTIVE_DB}\";" >/dev/null 2>&1 \
    && psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${ACTIVE_DB}\" WITH ALLOW_CONNECTIONS true;" >/dev/null 2>&1 \
    && database_exists "$ACTIVE_DB" && ! database_exists "$OLD_DB" \
    && [[ "$(database_oid "$ACTIVE_DB")" == "$OLD_OID" ]]; then
    RECOVERED=true
  fi
  journal_rollback_failure "staging_database_rename_failed" "$RECOVERED" \
    "staging database could not be promoted; catalog state was preserved"
  if [[ "$RECOVERED" == "true" ]]; then
    die "database swap failed; original database was verified as reinstated; failure journal written"
  fi
  die "database swap failed and original database could not be verified as reinstated; all databases preserved; failure journal written"
fi
SWAPPED=1
STAGE_CREATED=0

LIVE_EVIDENCE="$(mktemp "${TMPDIR:-/tmp}/clearance-active-live.XXXXXX")"
LIVE_VERIFY_OK=1
collect_db_evidence "$URL" "$LIVE_EVIDENCE" || LIVE_VERIFY_OK=0
compare_backup_evidence "$BACKUP_META" "$LIVE_EVIDENCE" >/dev/null || LIVE_VERIFY_OK=0
LIVE_APP_VERSION="$(application_release_version "$URL")"
[[ "$LIVE_APP_VERSION" == "$EXPECTED_BACKUP_VERSION" ]] || LIVE_VERIFY_OK=0
if [[ "${CLEARANCE_OPS_TESTING:-0}" == "1" && "${CLEARANCE_ROLLBACK_TEST_FAIL_AFTER_SWAP:-0}" == "1" ]]; then
  LIVE_VERIFY_OK=0
fi
if [[ "$LIVE_VERIFY_OK" -ne 1 ]]; then
  # Reverse the swap while the untouched old database is still available.
  FAILED_DB="clr_failed_$(openssl rand -hex 4)"
  assert_safe_ident "$FAILED_DB" "failed restore database"
  RECOVERED=false
  REVERSAL_OK=1
  psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${ACTIVE_DB}\" WITH ALLOW_CONNECTIONS false;" >/dev/null 2>&1 || REVERSAL_OK=0
  psql_q "$ADMIN_URL" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${ACTIVE_DB}' AND pid<>pg_backend_pid();" >/dev/null 2>&1 || REVERSAL_OK=0
  psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${ACTIVE_DB}\" RENAME TO \"${FAILED_DB}\";" >/dev/null 2>&1 || REVERSAL_OK=0
  if [[ "${CLEARANCE_OPS_TESTING:-0}" == "1" && "${CLEARANCE_ROLLBACK_TEST_FAIL_REVERSAL:-0}" == "1" ]]; then
    REVERSAL_OK=0
  elif [[ "$REVERSAL_OK" -eq 1 ]]; then
    psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${OLD_DB}\" RENAME TO \"${ACTIVE_DB}\";" >/dev/null 2>&1 || REVERSAL_OK=0
    psql_q "$ADMIN_URL" -c "ALTER DATABASE \"${ACTIVE_DB}\" WITH ALLOW_CONNECTIONS true;" >/dev/null 2>&1 || REVERSAL_OK=0
  fi
  if [[ "$REVERSAL_OK" -eq 1 ]] && database_exists "$ACTIVE_DB" && ! database_exists "$OLD_DB" \
    && [[ "$(database_oid "$ACTIVE_DB")" == "$OLD_OID" ]]; then
    RECOVERED=true
  fi
  journal_rollback_failure "post_restore_verification_failed" "$RECOVERED" \
    "post-restore verification failed; databases were preserved for recovery"
  if [[ "$RECOVERED" == "true" ]]; then
    die "post-restore verification failed; original database was verified as reinstated; failure journal written"
  fi
  die "post-restore verification failed and reversal could not be verified; all databases preserved; failure journal written"
fi
find "$LIVE_EVIDENCE" -type f -delete 2>/dev/null || true

RECEIPT="$RECEIPT_DIR/${PLAN_ID}.rollback.json"
cat >"$RECEIPT" <<EOF
{
  "planId": $(json_escape "$PLAN_ID"),
  "rolledBackAt": $(json_escape "$(iso_now)"),
  "mode": "active_database_restore",
  "database": $(json_escape "$ACTIVE_DB"),
  "fromVersion": $(json_escape "$TARGET_VERSION"),
  "toVersion": $(json_escape "$EXPECTED_BACKUP_VERSION"),
  "backupId": $(json_escape "$BACKUP_ID"),
  "backupDumpSha256": $(json_escape "$(sha256_file "$BACKUP_DUMP")"),
  "backupMetaSha256": $(json_escape "$(sha256_file "$BACKUP_META")"),
  "backupEvidenceSha256": $(json_escape "$(sha256_file "$BACKUP_EVIDENCE")"),
  "preRestoreSafetyBackupId": $(json_escape "$SAFETY_ID"),
  "preRestoreSafetyDumpSha256": $(json_escape "$(sha256_file "$SAFETY_DUMP")"),
  "preRestoreSafetyMetaSha256": $(json_escape "$(sha256_file "$SAFETY_META")"),
  "preRestoreSafetyEvidenceSha256": $(json_escape "$(sha256_file "$SAFETY_EVIDENCE")"),
  "preservedPreRollbackDatabase": $(json_escape "$OLD_DB"),
  "preservedPreRollbackDatabaseOid": $(json_escape "$OLD_OID"),
  "postSafetyWritesPreserved": true,
  "advisoryLockKey": "$LOCK_KEY",
  "postRestoreVerified": true
}
EOF
chmod 400 "$RECEIPT"

node -e '
  const fs=require("fs");
  const p=process.argv[1], receipt=process.argv[2], safety=process.argv[3], to=process.argv[4], preserved=process.argv[5];
  const j=JSON.parse(fs.readFileSync(p,"utf8"));
  const at=new Date().toISOString().replace(/\.\d{3}Z$/,"Z");
  j.status="rolled_back";
  j.updatedAt=at;
  j.rollbackReceipt=receipt;
  j.preRestoreSafetyBackupId=safety;
  j.preservedPreRollbackDatabase=preserved;
  j.applyJournal=j.applyJournal||[];
  j.applyJournal.push({at,event:"active_database_rollback_completed",receipt,safetyBackupId:safety,toVersion:to,preservedPreRollbackDatabase:preserved});
  fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");
' "$STATE_PATH" "$RECEIPT" "$SAFETY_ID" "$EXPECTED_BACKUP_VERSION" "$OLD_DB"

printf 'SELECT pg_advisory_unlock(%s);\n\\q\n' "$LOCK_KEY" >&8
exec 8>&-
exec 9<&-
wait "$LOCK_PID" 2>/dev/null || true
LOCK_RELEASED=1
printf 'upgrade-rollback: ACTIVE RESTORE OK plan=%s database=%s backup=%s safety=%s\n' "$PLAN_ID" "$ACTIVE_DB" "$BACKUP_ID" "$SAFETY_ID" >&2
printf 'ROLLBACK_RECEIPT=%s\n' "$RECEIPT"
printf 'SAFETY_BACKUP_ID=%s\n' "$SAFETY_ID"
printf 'ACTIVE_ROLLBACK_OK=1\n'
