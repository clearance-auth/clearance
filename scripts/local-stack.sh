#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -z "${CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON:-}" ]]; then
	: "${CLEARANCE_CREDENTIAL_KEY:?set CLEARANCE_CREDENTIAL_KEY}"
	: "${CLEARANCE_CREDENTIAL_KEY_ID:?set CLEARANCE_CREDENTIAL_KEY_ID}"
	export CLEARANCE_KEY_MANAGEMENT_CONFIG_JSON="$(node "$ROOT/scripts/local-key-management-config.mjs")"
fi

exec docker compose "$@"
