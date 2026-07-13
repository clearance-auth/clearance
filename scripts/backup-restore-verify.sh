#!/usr/bin/env bash
# Restore a verified backup into an ISOLATED temporary database, compare evidence,
# and clean up. Never drops or overwrites the active database.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

usage() {
  cat <<'EOF'
Usage: backup-restore-verify.sh --id ID [--dir DIR]
       backup-restore-verify.sh --dump PATH --meta PATH

Restores into a temporary database name (clr_rv_*), queries management/runtime
tables when present, compares row counts to backup metadata evidence, drops the
temp database, and exits non-zero on mismatch.

Refuses to target the active database name under all circumstances.
EOF
}

BACKUP_DIR="${CLEARANCE_BACKUP_DIR:-$ROOT/.clearance/backups}"
ID=""
DUMP=""
META=""
KEEP_TEMP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --id) ID="$2"; shift 2 ;;
    --dir) BACKUP_DIR="$2"; shift 2 ;;
    --dump) DUMP="$2"; shift 2 ;;
    --meta) META="$2"; shift 2 ;;
    --keep-temp) KEEP_TEMP=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -n "$ID" ]]; then
  DUMP="${DUMP:-$BACKUP_DIR/${ID}.sql}"
  META="${META:-$BACKUP_DIR/${ID}.meta.json}"
fi
[[ -n "$DUMP" && -f "$DUMP" ]] || die "dump required"
[[ -n "$META" && -f "$META" ]] || die "meta required"

require_pg_client
require_cmd node
require_cmd openssl
URL="$(resolve_database_url)"
require_database_url "$URL"
ACTIVE_DB="$(db_name_from_url "$URL")"
ADMIN_URL="$(admin_url_from_url "$URL")"

# Integrity first
bash "$ROOT/scripts/backup-verify.sh" --dump "$DUMP" --meta "$META" >/dev/null

# Isolated temp DB name
SUFFIX="$(openssl rand -hex 4)"
TEMP_DB="clr_rv_${SUFFIX}"
assert_safe_ident "$TEMP_DB" "temp database"
assert_not_active_db "$TEMP_DB"
[[ "$TEMP_DB" != "$ACTIVE_DB" ]] || die "temp db collided with active db"

TEMP_URL="$(url_with_db "$URL" "$TEMP_DB")"
CREATED=0
RESTORED_EV=""

drop_temp_database() {
  assert_not_active_db "$TEMP_DB"
  psql_q "$ADMIN_URL" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${TEMP_DB}' AND pid <> pg_backend_pid();" >/dev/null 2>&1 || true
  psql_q "$ADMIN_URL" -c "DROP DATABASE IF EXISTS \"${TEMP_DB}\";" >/dev/null 2>&1 || return 1
  local remains
  remains="$(psql_q "$ADMIN_URL" -At -c "SELECT count(*) FROM pg_database WHERE datname = '${TEMP_DB}'")" || return 1
  [[ "$remains" == "0" ]]
}

cleanup() {
  local ec=$?
  [[ -z "$RESTORED_EV" ]] || rm -f "$RESTORED_EV"
  if [[ "$KEEP_TEMP" -eq 1 ]]; then
    printf 'backup-restore-verify: keeping temp database %s (active remains %s)\n' "$TEMP_DB" "$ACTIVE_DB" >&2
    exit "$ec"
  fi
  if [[ "$CREATED" -eq 1 ]]; then
    if ! drop_temp_database; then
      printf 'backup-restore-verify: failed to clean up isolated database %s\n' "$TEMP_DB" >&2
      ec=1
    fi
  fi
  exit "$ec"
}
trap cleanup EXIT INT TERM

printf 'backup-restore-verify: creating isolated database %s (active=%s remains untouched)\n' \
  "$TEMP_DB" "$ACTIVE_DB" >&2

psql_q "$ADMIN_URL" -c "CREATE DATABASE \"${TEMP_DB}\";"
CREATED=1

printf 'backup-restore-verify: restoring dump into isolated database\n' >&2
psql_restore_file "$TEMP_URL" "$DUMP"

# Evidence from restored DB
RESTORED_EV="$(mktemp "${TMPDIR:-/tmp}/clearance-restore-ev.XXXXXX")"
collect_db_evidence "$TEMP_URL" "$RESTORED_EV"

# Compare table evidence and the application release captured with the backup.
compare_backup_evidence "$META" "$RESTORED_EV"
EXPECTED_APP_VERSION="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.applicationVersion||"")' "$META")"
if [[ -n "$EXPECTED_APP_VERSION" ]]; then
  require_application_release "$TEMP_URL" "$EXPECTED_APP_VERSION"
fi
rm -f "$RESTORED_EV"
RESTORED_EV=""

# Confirm active DB still exists and was not the restore target
STILL="$(psql_q "$ADMIN_URL" -At -c "SELECT 1 FROM pg_database WHERE datname = '${ACTIVE_DB}'")"
[[ "$STILL" == "1" ]] || die "active database disappeared — aborting (investigation required)"
assert_not_active_db "$TEMP_DB"

if [[ "$KEEP_TEMP" -eq 0 ]]; then
  drop_temp_database || die "isolated restore succeeded but temporary database cleanup failed"
  CREATED=0
fi

printf 'backup-restore-verify: OK (isolated restore compared; active db %s untouched; cleanup verified)\n' "$ACTIVE_DB"
printf 'RESTORE_VERIFIED=1\n'
