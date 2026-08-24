#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -z "${CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON:-}" ]]; then
	: "${CLEARANCE_CREDENTIAL_KEY:?set CLEARANCE_CREDENTIAL_KEY}"
	: "${CLEARANCE_CREDENTIAL_KEY_ID:?set CLEARANCE_CREDENTIAL_KEY_ID}"
	export CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON="$(node "$ROOT/scripts/local-key-management-config.mjs")"
fi

if [[ "${1:-}" != "bootstrap" ]]; then
	exec docker compose "$@"
fi

# A new database starts credential authority at legacy-open. Build the image,
# migrate that fence through the CLI, then start digest-only serving services.
# The migration identity and drain ID are stable across a retried bootstrap.
deployment_id="${CLEARANCE_DEPLOYMENT_ID:-development}"
drain_id="${CLEARANCE_CREDENTIAL_DRAIN_ID:-bootstrap-${deployment_id}}"
docker compose build
docker compose up -d --wait postgres
docker compose run --rm --no-deps \
	-e CLEARANCE_INSTANCE_ID=local-credential-migrator \
	-e CLEARANCE_CREDENTIAL_DRAIN_ID="$drain_id" \
	api node packages/clearance-cli/dist/index.js --json --no-input --yes \
	schema migrate --local --drain-id "$drain_id"

# The API's init route is deliberately scope-free. Use the short-lived
# bootstrap API only to create Store V2 products/topology, then restart the
# serving cohort with the exact authoritative identifiers it returned.
docker compose up -d api
api_url="http://127.0.0.1:${CLEARANCE_API_PORT:-13200}"
init_response=""
for _ in $(seq 1 60); do
	if init_response="$(curl -fsS -X POST "$api_url/v1/init" \
		-H "authorization: Bearer ${CLEARANCE_OPERATOR_TOKEN}" \
		-H 'content-type: application/json' \
		-d '{"name":"clearance-local","environment":"development"}')"; then
		break
	fi
	sleep 1
done
[[ -n "$init_response" ]] || { echo "Local API did not initialize Store V2 topology" >&2; exit 1; }
scope="$(node -e '
const value=JSON.parse(process.argv[1]);
const project=value?.project?.id, environment=value?.environment?.id;
if(typeof project!=="string"||!project||typeof environment!=="string"||!environment)process.exit(1);
process.stdout.write(`${project}\n${environment}`);
' "$init_response")"
mapfile -t scope_parts <<<"$scope"
(( ${#scope_parts[@]} == 2 )) || { echo "Local init returned an incomplete operator scope" >&2; exit 1; }
CLEARANCE_PROJECT_ID="${scope_parts[0]}"
CLEARANCE_ENV_ID="${scope_parts[1]}"
export CLEARANCE_PROJECT_ID CLEARANCE_ENV_ID
exec docker compose up -d --force-recreate api sample-b2b console
