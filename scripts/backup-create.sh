#!/usr/bin/env bash
# Create a real Postgres backup (pg_dump) with checksum + metadata.
# Never prints credentials. Never overwrites without a new backup id.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

# Dumps contain production data. Make every created directory/artifact owner-only.
umask 077

usage() {
  cat <<'EOF'
Usage: backup-create.sh [--dir DIR]

Environment:
  DATABASE_URL   Required. Postgres connection string for the active database.

Writes:
  DIR/<id>.sql           plain-format pg_dump
  DIR/<id>.meta.json     checksum, counts, timestamps, source db name
  DIR/<id>.verified.json read-only evidence binding the dump and metadata
  Prints backup id on stdout (last line: BACKUP_ID=<id>)
EOF
}

BACKUP_DIR="${CLEARANCE_BACKUP_DIR:-$ROOT/.clearance/backups}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) BACKUP_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_pg_client
require_cmd node
require_cmd openssl
URL="$(resolve_database_url)"
require_database_url "$URL"

ACTIVE_DB="$(db_name_from_url "$URL")"
assert_safe_ident "$ACTIVE_DB" "active database name"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
# Unique id: bak_<utc>_<random>
ID="bak_$(date -u +%Y%m%dT%H%M%SZ)_$(openssl rand -hex 4)"
DUMP="$BACKUP_DIR/${ID}.sql"
META="$BACKUP_DIR/${ID}.meta.json"
VERIFIED="$BACKUP_DIR/${ID}.verified.json"
EVIDENCE_TMP="$(mktemp "${TMPDIR:-/tmp}/clearance-bak-evidence.XXXXXX")"
SNAPSHOT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/clearance-bak-snapshot.XXXXXX")"
SNAPSHOT_IN="$SNAPSHOT_DIR/in"
SNAPSHOT_OUT="$SNAPSHOT_DIR/out"
SNAPSHOT_OPEN=0
SNAPSHOT_PID=""
cleanup_tmp() {
  local ec=$?
  if [[ "$SNAPSHOT_OPEN" -eq 1 ]]; then
    printf 'ROLLBACK;\n\\q\n' >&8 2>/dev/null || true
    exec 8>&-
    exec 9<&-
    wait "$SNAPSHOT_PID" 2>/dev/null || true
  fi
  find "$SNAPSHOT_DIR" -type p -delete 2>/dev/null || true
  rmdir "$SNAPSHOT_DIR" 2>/dev/null || true
  find "$EVIDENCE_TMP" -type f -delete 2>/dev/null || true
  if [[ "$ec" -ne 0 ]]; then
    find "$DUMP" "$META" "$VERIFIED" -type f -delete 2>/dev/null || true
  fi
}
trap cleanup_tmp EXIT

printf 'backup-create: dumping database=%s (url redacted=%s)\n' "$ACTIVE_DB" "$(redact_url "$URL")" >&2

# Hold one exported repeatable-read snapshot across both pg_dump and the
# resource/version evidence queries. Without this, ordinary writes between the
# dump and count collection can make a valid backup permanently unverifiable.
mkfifo "$SNAPSHOT_IN" "$SNAPSHOT_OUT"
psql --no-psqlrc -qAt -v ON_ERROR_STOP=1 "$URL" <"$SNAPSHOT_IN" >"$SNAPSHOT_OUT" &
SNAPSHOT_PID=$!
exec 8>"$SNAPSHOT_IN"
exec 9<"$SNAPSHOT_OUT"
SNAPSHOT_OPEN=1
printf 'BEGIN ISOLATION LEVEL REPEATABLE READ;\nSELECT pg_export_snapshot();\n' >&8
IFS= read -r SNAPSHOT_ID <&9 || die "could not export backup snapshot"
[[ "$SNAPSHOT_ID" =~ ^[0-9A-Fa-f-]+$ ]] || die "postgres returned an invalid backup snapshot id"
if [[ "${CLEARANCE_OPS_TESTING:-0}" == "1" ]]; then
  if [[ -n "${CLEARANCE_BACKUP_TEST_SNAPSHOT_READY_FILE:-}" ]]; then
    : >"$CLEARANCE_BACKUP_TEST_SNAPSHOT_READY_FILE"
  fi
  delay="${CLEARANCE_BACKUP_TEST_DELAY_AFTER_SNAPSHOT_SECONDS:-0}"
  [[ "$delay" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "invalid backup snapshot testing delay"
  if [[ "$delay" != "0" ]]; then sleep "$delay"; fi
fi

# Real pg_dump — plain SQL for inspectability. Fail closed on any dump error.
# Uses matching major client via Docker when local pg_dump is older/newer than server.
pg_dump_to_file "$URL" "$DUMP" "$SNAPSHOT_ID"

printf '%s\n' \
  'CREATE TEMP TABLE clearance_backup_counts(table_name text PRIMARY KEY, row_count bigint NOT NULL);' \
  "SELECT format('INSERT INTO clearance_backup_counts SELECT %L, count(*) FROM %I.%I;', table_name, table_schema, table_name) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY table_name;" \
  '\gexec' \
  "SELECT json_build_object('capturedAt', to_char(CURRENT_TIMESTAMP AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), 'tables', COALESCE((SELECT json_object_agg(table_name,row_count ORDER BY table_name) FROM clearance_backup_counts),'{}'::json))::text;" \
  "SELECT CASE WHEN to_regclass('public.clearance_management_snapshot') IS NULL THEN 'SELECT '''' || ''__CLEARANCE_APP_VERSION__'';' ELSE 'SELECT COALESCE((SELECT data->>''releaseVersion'' FROM clearance_management_snapshot WHERE id=1),'''') || ''__CLEARANCE_APP_VERSION__'';' END;" \
  '\gexec' \
  "SELECT '__CLEARANCE_SNAPSHOT_END__';" >&8

SNAPSHOT_EVIDENCE=""
APP_VERSION=""
while IFS= read -r line <&9; do
  if [[ "$line" == "__CLEARANCE_SNAPSHOT_END__" ]]; then
    break
  elif [[ "$line" == *"__CLEARANCE_APP_VERSION__" ]]; then
    APP_VERSION="${line%__CLEARANCE_APP_VERSION__}"
  elif [[ "$line" == \{* ]]; then
    SNAPSHOT_EVIDENCE="$line"
  fi
done
[[ -n "$SNAPSHOT_EVIDENCE" ]] || die "could not collect evidence from the backup snapshot"
printf '%s\n' "$SNAPSHOT_EVIDENCE" >"$EVIDENCE_TMP"
printf 'COMMIT;\n\\q\n' >&8
exec 8>&-
exec 9<&-
wait "$SNAPSHOT_PID"
SNAPSHOT_OPEN=0

[[ -s "$DUMP" ]] || die "pg_dump produced empty file"
if ! grep -q 'PostgreSQL database dump' "$DUMP"; then
  die "pg_dump output missing expected PostgreSQL dump header"
fi
grep -q 'PostgreSQL database dump complete' "$DUMP" \
  || die "pg_dump output missing completion marker"

CHECKSUM="$(sha256_file "$DUMP")"
BYTES="$(wc -c <"$DUMP" | tr -d ' ')"
PG_VER="$(grep -m1 'Dumped from database version' "$DUMP" || pg_dump --version | head -n1 || true)"

# Resource counts as flat map from evidence tables
COUNTS_JSON="$(node -e '
    const fs=require("fs");
    const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
    if (!j.tables || typeof j.tables !== "object" || Array.isArray(j.tables)) process.exit(2);
    process.stdout.write(JSON.stringify(j.tables));
  ' "$EVIDENCE_TMP")" || die "failed to serialize required backup evidence"

CREATED="$(iso_now)"
cat >"$META" <<EOF
{
  "id": $(json_escape "$ID"),
  "format": "pg_dump_plain",
  "createdAt": $(json_escape "$CREATED"),
  "dumpFile": $(json_escape "$(basename "$DUMP")"),
  "metaFile": $(json_escape "$(basename "$META")"),
  "checksumSha256": $(json_escape "$CHECKSUM"),
  "bytes": $BYTES,
  "sourceDatabase": $(json_escape "$ACTIVE_DB"),
  "applicationVersion": $(if [[ -n "$APP_VERSION" ]]; then json_escape "$APP_VERSION"; else printf 'null'; fi),
  "pgDumpVersion": $(json_escape "$PG_VER"),
  "resourceCounts": $COUNTS_JSON,
  "tool": "scripts/backup-create.sh"
}
EOF

# Refuse writing secrets into meta
if grep -qiE 'password|postgresql://[^"]+:[^"]+@' "$META"; then
  find "$DUMP" "$META" -type f -delete 2>/dev/null || true
  die "metadata unexpectedly contained credential material; aborted"
fi

# Bind both artifacts into immutable local verification evidence. The evidence
# is owner-readable and non-writable; backup-verify checks every digest.
META_CHECKSUM="$(sha256_file "$META")"
RESOURCE_FINGERPRINT="$(schema_fingerprint_from_evidence "$EVIDENCE_TMP")"
cat >"$VERIFIED" <<EOF
{
  "id": $(json_escape "$ID"),
  "verifiedAt": $(json_escape "$(iso_now)"),
  "dumpFile": $(json_escape "$(basename "$DUMP")"),
  "metaFile": $(json_escape "$(basename "$META")"),
  "dumpSha256": $(json_escape "$CHECKSUM"),
  "metaSha256": $(json_escape "$META_CHECKSUM"),
  "resourceEvidenceSha256": $(json_escape "$RESOURCE_FINGERPRINT"),
  "checks": ["nonempty", "pg_dump_complete", "metadata_bound", "resource_counts_captured"]
}
EOF
chmod 600 "$DUMP" "$META"
chmod 400 "$VERIFIED"

printf 'backup-create: wrote %s (%s bytes, sha256=%s)\n' "$DUMP" "$BYTES" "$CHECKSUM" >&2
printf 'BACKUP_ID=%s\n' "$ID"
printf 'BACKUP_DUMP=%s\n' "$DUMP"
printf 'BACKUP_META=%s\n' "$META"
printf 'BACKUP_EVIDENCE=%s\n' "$VERIFIED"
