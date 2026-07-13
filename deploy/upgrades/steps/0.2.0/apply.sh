#!/usr/bin/env bash
# Shipped 0.1.3 -> 0.2.0 database transition.
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
    *) die "unknown upgrade hook argument: $1" ;;
  esac
done

[[ -f "$PLAN" ]] || die "upgrade plan is missing"
[[ "$FROM" == "0.1.3" && "$TO" == "0.2.0" ]] \
  || die "this hook only supports 0.1.3 to 0.2.0"

require_pg_client
require_cmd node
URL="$(resolve_database_url)"
PLAN_ID="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.planId)' "$PLAN")"
PLAN_SHA="$(sha256_file "$PLAN")"
[[ "$PLAN_ID" =~ ^upg_[0-9TZ]+_[a-f0-9]+$ ]] || die "unsafe plan id"
require_application_release "$URL" "$FROM"

# This is the application-owned migration contract: the durable management
# snapshot used by the running API advances atomically with an append-only
# migration ledger. It cannot pass against the old test-only ops marker.
psql_q "$URL" \
  -v from_version="$FROM" -v to_version="$TO" \
  -v plan_id="$PLAN_ID" -v plan_sha="$PLAN_SHA" <<'SQL' >/dev/null
BEGIN;
CREATE TABLE IF NOT EXISTS clearance_schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now(),
  plan_id text NOT NULL,
  plan_sha256 text NOT NULL,
  from_version text
);
INSERT INTO clearance_schema_migrations(version, plan_id, plan_sha256, from_version)
VALUES (:'from_version', 'application-baseline', :'plan_sha', NULL)
ON CONFLICT (version) DO NOTHING;
UPDATE clearance_management_snapshot
SET data = jsonb_set(data, '{releaseVersion}', to_jsonb(:'to_version'::text), false),
    revision = revision + 1,
    updated_at = now()
WHERE id = 1 AND data->>'releaseVersion' = :'from_version';
INSERT INTO clearance_schema_migrations(version, plan_id, plan_sha256, from_version)
VALUES (:'to_version', :'plan_id', :'plan_sha', :'from_version');
COMMIT;
SQL

require_application_release "$URL" "$TO"
ledger_plan="$(psql_q "$URL" -At -c "SELECT plan_id FROM clearance_schema_migrations WHERE version = '${TO}'")"
[[ "$ledger_plan" == "$PLAN_ID" ]] || die "migration ledger did not record plan $PLAN_ID"
