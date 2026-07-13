#!/usr/bin/env bash
# Create an immutable upgrade plan with reference evidence and required backup slot.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

usage() {
  cat <<'EOF'
Usage: upgrade-plan.sh --target VERSION [--dir DIR]

Writes an immutable plan JSON under DIR. Refuses to overwrite an existing plan id.
Captures current release reference, schema evidence fingerprint, and preflight gates.
EOF
}

PLAN_DIR="${CLEARANCE_UPGRADE_DIR:-$ROOT/.clearance/upgrades}"
TARGET=""
CURRENT="${CLEARANCE_RELEASE_VERSION:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2 ;;
    --current) CURRENT="$2"; shift 2 ;;
    --dir) PLAN_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$TARGET" ]] || die "--target VERSION is required"
assert_safe_version "$TARGET" "target version"
require_cmd node
require_cmd openssl

mkdir -p "$PLAN_DIR"
PLAN_ID="upg_$(date -u +%Y%m%dT%H%M%SZ)_$(openssl rand -hex 3)"
PLAN_PATH="$PLAN_DIR/${PLAN_ID}.plan.json"
[[ ! -f "$PLAN_PATH" ]] || die "plan path already exists (immutable): $PLAN_PATH"

URL=""
EVIDENCE="{}"
SOURCE_DB=""
if [[ -n "${DATABASE_URL:-}" ]]; then
  require_pg_client
  URL="$(resolve_database_url)"
  require_database_url "$URL"
  SOURCE_DB="$(db_name_from_url "$URL")"
  APP_RELEASE="$(application_release_version "$URL")"
  [[ -n "$APP_RELEASE" ]] || die "database is missing the Clearance application release contract"
  if [[ -z "$CURRENT" ]]; then
    CURRENT="$APP_RELEASE"
  elif [[ "$CURRENT" != "$APP_RELEASE" ]]; then
    die "--current $CURRENT does not match application release $APP_RELEASE"
  fi
  EV_FILE="$(mktemp "${TMPDIR:-/tmp}/clearance-upg-ev.XXXXXX")"
  collect_db_evidence "$URL" "$EV_FILE"
  EVIDENCE="$(cat "$EV_FILE")"
  FINGERPRINT="$(schema_fingerprint_from_evidence "$EV_FILE")"
  rm -f "$EV_FILE"
else
  FINGERPRINT="no-database-url"
fi

if [[ -z "$CURRENT" ]]; then
  CURRENT="$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$ROOT/packages/clearance-api/package.json")"
fi
assert_safe_version "$CURRENT" "current version"

CREATED="$(iso_now)"
cat >"$PLAN_PATH" <<EOF
{
  "planId": $(json_escape "$PLAN_ID"),
  "immutable": true,
  "createdAt": $(json_escape "$CREATED"),
  "currentVersion": $(json_escape "$CURRENT"),
  "targetVersion": $(json_escape "$TARGET"),
  "sourceDatabase": $(json_escape "${SOURCE_DB}"),
  "schemaFingerprintSha256": $(json_escape "$FINGERPRINT"),
  "schemaEvidence": $EVIDENCE,
  "applicationContract": {
    "snapshotTable": "clearance_management_snapshot",
    "releaseVersion": $(json_escape "$CURRENT"),
    "migrationLedger": "clearance_schema_migrations"
  },
  "status": "planned",
  "requiredGates": [
    "preflight",
    "verified_backup",
    "apply",
    "post_verify"
  ],
  "backupId": null,
  "backupDump": null,
  "backupMeta": null,
  "backupEvidence": null,
  "rollbackReference": null,
  "applyJournal": [],
  "tool": "scripts/upgrade-plan.sh"
}
EOF

# File permissions: plan is reference material
chmod a-w "$PLAN_PATH" 2>/dev/null || true
PLAN_SHA256="$(sha256_file "$PLAN_PATH")"

# Writable side-car for status transitions (plan body stays immutable)
STATE_PATH="$PLAN_DIR/${PLAN_ID}.state.json"
cat >"$STATE_PATH" <<EOF
{
  "planId": $(json_escape "$PLAN_ID"),
  "planPath": $(json_escape "$PLAN_PATH"),
  "planSha256": $(json_escape "$PLAN_SHA256"),
  "status": "planned",
  "updatedAt": $(json_escape "$CREATED"),
  "backupId": null,
  "backupDump": null,
  "backupMeta": null,
  "backupEvidence": null,
  "rollbackReference": null,
  "applyJournal": []
}
EOF

printf 'upgrade-plan: wrote immutable plan %s\n' "$PLAN_PATH" >&2
printf 'PLAN_ID=%s\n' "$PLAN_ID"
printf 'PLAN_PATH=%s\n' "$PLAN_PATH"
printf 'STATE_PATH=%s\n' "$STATE_PATH"
