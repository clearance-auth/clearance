#!/usr/bin/env bash
# Verify a Clearance Postgres backup archive: checksum + dump structure + metadata.
# Does not connect to the live database and never restores.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

usage() {
  cat <<'EOF'
Usage: backup-verify.sh --id ID [--dir DIR]
       backup-verify.sh --dump PATH [--meta PATH] [--evidence PATH]

Inspects archive integrity only (checksum, pg_dump markers, metadata consistency).
Does not restore and does not touch the active database.
EOF
}

BACKUP_DIR="${CLEARANCE_BACKUP_DIR:-$ROOT/.clearance/backups}"
ID=""
DUMP=""
META=""
EVIDENCE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --id) ID="$2"; shift 2 ;;
    --dir) BACKUP_DIR="$2"; shift 2 ;;
    --dump) DUMP="$2"; shift 2 ;;
    --meta) META="$2"; shift 2 ;;
    --evidence) EVIDENCE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -n "$ID" ]]; then
  DUMP="${DUMP:-$BACKUP_DIR/${ID}.sql}"
  META="${META:-$BACKUP_DIR/${ID}.meta.json}"
  EVIDENCE="${EVIDENCE:-$BACKUP_DIR/${ID}.verified.json}"
fi

[[ -n "$DUMP" ]] || die "provide --id or --dump"
require_cmd node
[[ -f "$DUMP" ]] || die "dump file missing: $DUMP"
[[ -s "$DUMP" ]] || die "dump file empty: $DUMP"

if [[ -z "$META" && -n "$ID" ]]; then
  META="$BACKUP_DIR/${ID}.meta.json"
fi
[[ -n "$META" && -f "$META" ]] || die "metadata file missing (expected alongside dump)"
if [[ -z "$EVIDENCE" ]]; then
  EVIDENCE="${DUMP%.sql}.verified.json"
fi
[[ -f "$EVIDENCE" ]] || die "immutable verification evidence missing: $EVIDENCE"

# Checksum
ACTUAL="$(sha256_file "$DUMP")"
EXPECTED="$(node -e '
  const fs=require("fs");
  const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
  if(!j.checksumSha256) process.exit(2);
  process.stdout.write(j.checksumSha256);
' "$META")" || die "metadata missing checksumSha256"

[[ "$ACTUAL" == "$EXPECTED" ]] || die "checksum mismatch (archive may be corrupted)"

# Archive structure inspection (plain pg_dump)
grep -q 'PostgreSQL database dump' "$DUMP" || die "archive missing PostgreSQL dump header"
grep -q 'PostgreSQL database dump complete' "$DUMP" || die "archive missing PostgreSQL dump completion marker"
# At least one CREATE or COPY / table structure signal
if ! grep -qE '^(CREATE TABLE|COPY |CREATE SCHEMA)' "$DUMP"; then
  printf 'backup-verify: archive contains no table definitions (valid empty database)\n' >&2
fi

# Metadata consistency
node -e '
  const fs=require("fs");
  const meta=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
  const dumpBase=require("path").basename(process.argv[2]);
  if(!meta.id) { console.error("meta missing id"); process.exit(1); }
  if(meta.format !== "pg_dump_plain") { console.error("unsupported format"); process.exit(1); }
  if(meta.dumpFile && meta.dumpFile !== dumpBase) {
    console.error("meta.dumpFile does not match dump basename");
    process.exit(1);
  }
  if(typeof meta.bytes === "number") {
    const st=fs.statSync(process.argv[2]);
    if(st.size !== meta.bytes) {
      console.error("meta.bytes does not match dump size");
      process.exit(1);
    }
  }
  // Fail closed: meta must not embed credentials
  const raw=fs.readFileSync(process.argv[1],"utf8");
  if(/password\s*[:=]/i.test(raw) || /postgres(ql)?:\/\/[^/\s"]+:[^@\s"]+@/i.test(raw)) {
    console.error("metadata appears to contain credentials");
    process.exit(1);
  }
' "$META" "$DUMP"

# Verification evidence is content-addressed. This catches metadata rewriting
# as well as dump corruption, even when only one checksum was updated.
node -e '
  const fs=require("fs");
  const path=require("path");
  const crypto=require("crypto");
  const ev=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
  const dump=process.argv[2];
  const meta=process.argv[3];
  const sha=(p)=>crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
  if(!ev.id || !ev.verifiedAt || !Array.isArray(ev.checks)) process.exit(2);
  if(ev.dumpFile!==path.basename(dump) || ev.metaFile!==path.basename(meta)) process.exit(3);
  if(ev.dumpSha256!==sha(dump) || ev.metaSha256!==sha(meta)) process.exit(4);
  if((fs.statSync(process.argv[1]).mode & 0o222)!==0) process.exit(5);
' "$EVIDENCE" "$DUMP" "$META" || die "immutable backup verification evidence mismatch"

printf 'backup-verify: OK id=%s sha256=%s\n' "$(basename "$DUMP" .sql)" "$ACTUAL"
printf 'BACKUP_VERIFIED=1\n'
printf 'BACKUP_EVIDENCE=%s\n' "$EVIDENCE"
