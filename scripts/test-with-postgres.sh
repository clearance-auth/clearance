#!/usr/bin/env bash
# Boots disposable Postgres containers and runs the Postgres-gated test
# suites with CLEARANCE_REQUIRE_PG_TESTS=1, so an unreachable database FAILS
# the suites instead of silently skipping them (packages/management/src/
# __tests__/pg-gate.ts). The 2026-07-13 audit found the canonical gate had
# never executed these suites because they skipped without a database.
#
# Two instances:
#   shared        -> CLEARANCE_TEST_DATABASE_URL      (six coexisting suites)
#   org-lifecycle -> CLEARANCE_ORG_TEST_DATABASE_URL  (hard-deletes runtime
#                    rows; refuses the shared database by design)
#
# Ephemeral host ports (-p 127.0.0.1::5432) eliminate port collisions rather
# than detecting them; deterministic container names + docker rm -f before
# start make a SIGKILLed previous run self-healing.
#
# Usage:
#   scripts/test-with-postgres.sh                 # management suite + 0-skip assert
#   scripts/test-with-postgres.sh -- <command...> # run any command in this env
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is required (fail closed: the Pg suites must run, not skip)"
docker info >/dev/null 2>&1 || die "docker daemon is unavailable (fail closed: the Pg suites must run, not skip)"

SHARED_NAME="clearance-pgtest-shared"
ORG_NAME="clearance-pgtest-org"

cleanup() {
  docker rm -f "$SHARED_NAME" "$ORG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Self-heal any stale containers from a killed prior run.
cleanup

docker run -d --rm --name "$SHARED_NAME" \
  -e POSTGRES_USER=clearance -e POSTGRES_PASSWORD=clearance -e POSTGRES_DB=clearance \
  -p 127.0.0.1::5432 postgres:16-alpine >/dev/null
docker run -d --rm --name "$ORG_NAME" \
  -e POSTGRES_USER=user -e POSTGRES_PASSWORD=password -e POSTGRES_DB=clearance \
  -p 127.0.0.1::5432 postgres:16-alpine >/dev/null

port_of() {
  docker port "$1" 5432/tcp | head -n1 | awk -F: '{print $NF}'
}
SHARED_PORT="$(port_of "$SHARED_NAME")"
ORG_PORT="$(port_of "$ORG_NAME")"
[[ -n "$SHARED_PORT" && -n "$ORG_PORT" ]] || die "could not resolve ephemeral container ports"

wait_ready() {
  local name="$1" user="$2" tries=60
  for _ in $(seq 1 "$tries"); do
    if docker exec "$name" pg_isready -U "$user" -q 2>/dev/null; then return 0; fi
    sleep 1
  done
  docker logs "$name" | tail -20 >&2 || true
  die "$name did not become ready"
}
wait_ready "$SHARED_NAME" clearance
wait_ready "$ORG_NAME" user

export CLEARANCE_TEST_DATABASE_URL="postgres://clearance:clearance@127.0.0.1:${SHARED_PORT}/clearance"
export CLEARANCE_ORG_TEST_DATABASE_URL="postgres://user:password@127.0.0.1:${ORG_PORT}/clearance"
export CLEARANCE_REQUIRE_PG_TESTS=1

echo "test-with-postgres: shared=127.0.0.1:${SHARED_PORT} org=127.0.0.1:${ORG_PORT} (CLEARANCE_REQUIRE_PG_TESTS=1)"

if [[ "${1:-}" == "--" ]]; then
  shift
  [[ $# -gt 0 ]] || die "usage: test-with-postgres.sh -- <command...>"
  "$@"
  exit $?
fi

# Default: run the management suite with a machine-checked zero-skip result.
# The pg-gate tripwire already fails unreachable-DB suites; the reporter
# assertion additionally catches any FUTURE suite that skips by some other
# mechanism (belt and braces, per FOLLOW.md P1.1.4).
REPORT="$(mktemp -t clearance-mgmt-report.XXXXXX).json"
rm_report() { rm -f "$REPORT"; }
trap 'rm_report; cleanup' EXIT INT TERM

(cd packages/management && npx vitest run --reporter=default --reporter=json --outputFile="$REPORT")

node - "$REPORT" <<'EOF'
const fs = require("node:fs");
const r = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const skipped = (r.numPendingTests ?? 0) + (r.numTodoTests ?? 0);
if (!r.success) {
  console.error(`management suite failed (${r.numFailedTests} failed)`);
  process.exit(1);
}
if (skipped !== 0) {
  console.error(`management suite skipped ${skipped} tests under the canonical gate — silent skip is a gate defect`);
  process.exit(1);
}
console.log(`management suite: ${r.numPassedTests} passed, 0 skipped (asserted)`);
EOF

echo "TEST_WITH_POSTGRES_OK"
