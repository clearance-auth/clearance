#!/usr/bin/env bash
# Inventory and optionally revoke legacy personal/global SCIM credentials.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"
umask 077

usage() {
  cat <<'EOF'
Usage: scim-legacy-preflight.sh [--revoke --confirm TOKEN] [--receipt-dir DIR]

Rows in the runtime scimProvider table with no organizationId were minted by
the legacy personal/global path. Inventory is the default and fails closed when
any remain. To revoke them, rerun with the exact token printed by inventory:
  REVOKE_LEGACY_SCIM:<database>:<count>

No bearer token or encrypted credential is read or printed.
EOF
}

REVOKE=0
CONFIRM=""
RECEIPT_DIR="${CLEARANCE_SECURITY_RECEIPT_DIR:-$ROOT/.clearance/security-receipts}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --revoke) REVOKE=1; shift ;;
    --confirm) CONFIRM="$2"; shift 2 ;;
    --receipt-dir) RECEIPT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

require_pg_client
URL="$(resolve_database_url)"
require_database_url "$URL"
DB="$(db_name_from_url "$URL")"
assert_safe_ident "$DB" "active database"
HAS_TABLE="$(psql_q "$URL" -At -c "SELECT CASE WHEN to_regclass('public.\"scimProvider\"') IS NULL THEN 0 ELSE 1 END")"
if [[ "$HAS_TABLE" == "0" ]]; then
  printf 'scim-legacy-preflight: OK; runtime SCIM table is absent (zero issued credentials)\n'
  printf 'LEGACY_SCIM_COUNT=0\nSCIM_LEGACY_PREFLIGHT_OK=1\n'
  exit 0
fi

COUNT="$(psql_q "$URL" -At -c "SELECT count(*) FROM \"scimProvider\" WHERE \"organizationId\" IS NULL OR btrim(\"organizationId\") = ''")"
[[ "$COUNT" =~ ^[0-9]+$ ]] || die "could not inventory legacy SCIM credentials"
if [[ "$COUNT" == "0" ]]; then
  printf 'scim-legacy-preflight: OK; no personal/global SCIM credentials remain\n'
  printf 'LEGACY_SCIM_COUNT=0\nSCIM_LEGACY_PREFLIGHT_OK=1\n'
  exit 0
fi

TOKEN="REVOKE_LEGACY_SCIM:${DB}:${COUNT}"
if [[ "$REVOKE" -eq 0 ]]; then
  printf 'scim-legacy-preflight: BLOCKED; %s legacy personal/global credential(s) remain\n' "$COUNT" >&2
  printf 'rerun with: --revoke --confirm %s\n' "$TOKEN" >&2
  exit 1
fi
[[ "$CONFIRM" == "$TOKEN" ]] || die "revoke confirmation mismatch; required --confirm $TOKEN"

if [[ "${CLEARANCE_OPS_TESTING:-0}" == "1" && -n "${CLEARANCE_SCIM_PREFLIGHT_TEST_DELAY_SECONDS:-}" ]]; then
  sleep "$CLEARANCE_SCIM_PREFLIGHT_TEST_DELAY_SECONDS"
fi

DELETED="$(psql_q "$URL" -At -v expected="$COUNT" <<'SQL'
BEGIN;
SELECT pg_advisory_xact_lock(7176324950072027);
LOCK TABLE "scimProvider" IN ACCESS EXCLUSIVE MODE;
WITH deleted AS (
  DELETE FROM "scimProvider"
  WHERE ("organizationId" IS NULL OR btrim("organizationId") = '')
    AND (SELECT count(*) FROM "scimProvider"
         WHERE "organizationId" IS NULL OR btrim("organizationId") = '') = :'expected'::bigint
  RETURNING id
)
SELECT count(*) FROM deleted;
COMMIT;
SQL
)"
DELETED="$(printf '%s\n' "$DELETED" | awk '/^[0-9]+$/ {v=$0} END {print v}')"
[[ "$DELETED" == "$COUNT" ]] || die "legacy SCIM revoke count mismatch"
REMAINING="$(psql_q "$URL" -At -c "SELECT count(*) FROM \"scimProvider\" WHERE \"organizationId\" IS NULL OR btrim(\"organizationId\") = ''")"
[[ "$REMAINING" == "0" ]] || die "legacy SCIM credentials remain after revoke"

mkdir -p "$RECEIPT_DIR"
chmod 700 "$RECEIPT_DIR"
RECEIPT="$RECEIPT_DIR/scim-legacy-revoke-$(date -u +%Y%m%dT%H%M%SZ).json"
cat >"$RECEIPT" <<EOF
{
  "database": $(json_escape "$DB"),
  "revokedAt": $(json_escape "$(iso_now)"),
  "legacyCredentialsRevoked": $DELETED,
  "remainingLegacyCredentials": 0,
  "tokenMaterialInspected": false
}
EOF
chmod 400 "$RECEIPT"
printf 'scim-legacy-preflight: OK; revoked %s personal/global credentials\n' "$DELETED"
printf 'SCIM_REVOKE_RECEIPT=%s\n' "$RECEIPT"
printf 'SCIM_LEGACY_PREFLIGHT_OK=1\n'
