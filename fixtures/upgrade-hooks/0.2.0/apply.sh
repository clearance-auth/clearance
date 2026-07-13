#!/usr/bin/env bash
# Isolated acceptance fixture: performs a real, reversible release-marker mutation.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
# shellcheck source=scripts/lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

PLAN=""
FROM=""
TO=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan) PLAN="$2"; shift 2 ;;
    --from) FROM="$2"; shift 2 ;;
    --to) TO="$2"; shift 2 ;;
    *) die "unknown fixture hook argument: $1" ;;
  esac
done

[[ -f "$PLAN" ]] || die "fixture upgrade plan is missing"
[[ "$FROM" == "0.1.2" && "$TO" == "0.2.0" ]] \
  || die "fixture hook only supports 0.1.2 to 0.2.0"

require_pg_client
URL="$(resolve_database_url)"
before="$(psql_q "$URL" -At -c "SELECT value FROM clearance_ops_meta WHERE key = 'release'")"
[[ "$before" == "$FROM" ]] || die "fixture release marker expected $FROM, found $before"
# FROM/TO are restricted to the exact fixture versions above, so this literal
# statement cannot contain operator-controlled SQL.
psql_q "$URL" -c "UPDATE clearance_ops_meta SET value = '0.2.0' WHERE key = 'release'" >/dev/null
after="$(psql_q "$URL" -At -c "SELECT value FROM clearance_ops_meta WHERE key = 'release'")"
[[ "$after" == "$TO" ]] || die "fixture release marker did not advance to $TO"
