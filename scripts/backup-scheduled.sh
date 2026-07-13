#!/usr/bin/env bash
# Scheduled backup entrypoint: create, verify, rehearse, copy off-host, retain.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"
umask 077

usage() {
  cat <<'EOF'
Usage: backup-scheduled.sh [--dir DIR] [--retention-days DAYS]

Environment:
  DATABASE_URL                    required active Postgres database
  CLEARANCE_BACKUP_COPY_COMMAND   optional executable hook; receives
    CLEARANCE_BACKUP_ID, CLEARANCE_BACKUP_DUMP, CLEARANCE_BACKUP_META,
    CLEARANCE_BACKUP_EVIDENCE. It must return zero before local retention runs.
  CLEARANCE_BACKUP_RESTORE_VERIFY 1 (default) performs an isolated restore drill
  CLEARANCE_BACKUP_ALLOW_LOCAL_ONLY=1 permits no copy hook for dev/test only
EOF
}

BACKUP_DIR="${CLEARANCE_BACKUP_DIR:-$ROOT/.clearance/backups}"
RETENTION_DAYS="${CLEARANCE_BACKUP_RETENTION_DAYS:-30}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) BACKUP_DIR="$2"; shift 2 ;;
    --retention-days) RETENTION_DAYS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || die "retention days must be a non-negative integer"

CREATE_OUT="$(bash "$ROOT/scripts/backup-create.sh" --dir "$BACKUP_DIR")"
ID="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_ID=//p' | tail -1)"
DUMP="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_DUMP=//p' | tail -1)"
META="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_META=//p' | tail -1)"
EVIDENCE="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_EVIDENCE=//p' | tail -1)"
[[ -n "$ID" && -f "$DUMP" && -f "$META" && -f "$EVIDENCE" ]] \
  || die "backup-create did not return a complete artifact set"
bash "$ROOT/scripts/backup-verify.sh" --id "$ID" --dir "$BACKUP_DIR" >/dev/null
if [[ "${CLEARANCE_BACKUP_RESTORE_VERIFY:-1}" == "1" ]]; then
  bash "$ROOT/scripts/backup-restore-verify.sh" --id "$ID" --dir "$BACKUP_DIR" >/dev/null
fi

OFFSITE_RECEIPT="$BACKUP_DIR/${ID}.offsite.json"
if [[ -z "${CLEARANCE_BACKUP_COPY_COMMAND:-}" && "${CLEARANCE_BACKUP_ALLOW_LOCAL_ONLY:-0}" != "1" ]]; then
  die "CLEARANCE_BACKUP_COPY_COMMAND is required; set CLEARANCE_BACKUP_ALLOW_LOCAL_ONLY=1 only for dev/test"
fi
if [[ -n "${CLEARANCE_BACKUP_COPY_COMMAND:-}" ]]; then
  export CLEARANCE_BACKUP_ID="$ID" CLEARANCE_BACKUP_DUMP="$DUMP"
  export CLEARANCE_BACKUP_META="$META" CLEARANCE_BACKUP_EVIDENCE="$EVIDENCE"
  bash -c "$CLEARANCE_BACKUP_COPY_COMMAND" \
    || die "off-host backup copy hook failed; local retention was not run"
  cat >"$OFFSITE_RECEIPT" <<EOF
{
  "id": $(json_escape "$ID"),
  "copiedAt": $(json_escape "$(iso_now)"),
  "dumpSha256": $(json_escape "$(sha256_file "$DUMP")"),
  "metaSha256": $(json_escape "$(sha256_file "$META")"),
  "evidenceSha256": $(json_escape "$(sha256_file "$EVIDENCE")"),
  "copyHookSucceeded": true
}
EOF
  chmod 400 "$OFFSITE_RECEIPT"
fi

# Prune only complete artifact sets with successful off-host receipts. Keep the
# just-created backup even when retention is zero.
if [[ "$RETENTION_DAYS" -gt 0 && -n "${CLEARANCE_BACKUP_COPY_COMMAND:-}" ]]; then
  node -e '
    const fs=require("fs"), path=require("path");
    const dir=process.argv[1], keep=process.argv[2], days=Number(process.argv[3]);
    const cutoff=Date.now()-days*86400_000;
    for(const name of fs.readdirSync(dir)) {
      const match=/^(bak_[0-9TZ]+_[a-f0-9]+)\.offsite\.json$/.exec(name);
      if(!match || match[1]===keep) continue;
      const id=match[1], receipt=JSON.parse(fs.readFileSync(path.join(dir,name),"utf8"));
      if(receipt.id!==id || receipt.copyHookSucceeded!==true || Date.parse(receipt.copiedAt)>=cutoff) continue;
      for(const suffix of [".sql",".meta.json",".verified.json",".offsite.json"]) {
        const target=path.join(dir,id+suffix);
        if(fs.existsSync(target)) fs.unlinkSync(target);
      }
    }
  ' "$BACKUP_DIR" "$ID" "$RETENTION_DAYS"
fi

printf 'backup-scheduled: OK id=%s offsite=%s retentionDays=%s\n' \
  "$ID" "$([[ -f "$OFFSITE_RECEIPT" ]] && printf yes || printf no)" "$RETENTION_DAYS"
printf 'BACKUP_ID=%s\n' "$ID"
printf 'SCHEDULED_BACKUP_OK=1\n'
