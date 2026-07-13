#!/usr/bin/env bash
# Canonical local release verification. Every stage fails closed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "### verification step 0: versioned source of truth ###"
# The tree under verification must be committed history, not a loose working
# directory. (Tag checks live in the release path; default CI clones are
# shallow and tagless, so only commit existence is asserted here.)
git rev-parse HEAD >/dev/null 2>&1 || {
  echo "FAIL: repository has no commits; verification requires committed history" >&2
  exit 1
}

echo "### verification step 1: clean source build ###"
find packages apps -type d -name dist -prune -exec rm -rf {} +
pnpm build

echo "### verification step 2: full typecheck ###"
pnpm typecheck:runtime:full
pnpm typecheck:clearance

echo "### verification step 3: runtime and Clearance tests ###"
pnpm test:runtime
# Management suite runs against live disposable Postgres with the silent-skip
# tripwire armed (CLEARANCE_REQUIRE_PG_TESTS=1) and a machine-checked 0-skip
# result. Fails closed when Docker is unavailable.
bash "$ROOT/scripts/test-with-postgres.sh"
pnpm --filter @clearance/auth --filter @clearance/cli --filter @clearance/api --filter @clearance/sample-b2b --filter @clearance/console test

echo "### verification step 4: isolated full-stack acceptance ###"
bash "$ROOT/scripts/compose-smoke.sh"

echo "### verification step 5: production operations acceptance ###"
bash "$ROOT/scripts/verify-production-ops.sh"

echo "### verification step 6: publish artifacts ###"
bash "$ROOT/scripts/smoke-pack.sh"
bash "$ROOT/scripts/smoke-import.sh"

echo VERIFY_REAL_OK
