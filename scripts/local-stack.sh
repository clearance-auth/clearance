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
exec docker compose up -d
