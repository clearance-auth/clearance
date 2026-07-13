#!/usr/bin/env bash
# Self-contained Clearance package tests with disposable external databases.
#
# Honesty note about what the containers actually exercise:
# - This script runs the runtime package suite (packages/runtime). Only the
#   test files that opt in via `testWith: "postgres"` / `testWith: "mongodb"` consume
#   the Postgres/Mongo containers provisioned below; every other test file defaults to
#   in-memory SQLite. The exact opt-in file list is derived at runtime (grep below) and
#   printed in the banner before the containers boot. If that list is ever empty, the
#   script fails: the containers would be pure waste and this script's premise false.
# - packages/runtime/vitest.config.ts excludes src/adapters/**/*.test.ts, so no
#   adapter tests run here. Adapter coverage lives in the separate @clearance/*-adapter
#   package suites (kysely/memory/mongo/drizzle/prisma) run by the root `test:runtime`
#   script in package.json, which invokes this script last.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../packages/runtime" && pwd)"

# Derive (never hardcode) the test files that consume the provisioned databases.
# Anchored to postgres|mongodb only: `testWith: "sqlite"` also exists and is in-memory.
DB_TEST_FILES="$(cd "$PKG_DIR" && grep -rl --include='*.test.ts' -E 'testWith:\s*"(postgres|mongodb)"' src/ || true)"

if [[ -z "$DB_TEST_FILES" ]]; then
  echo "ERROR: no test files under packages/runtime/src opt into the external databases" >&2
  echo "       (expected at least one match for: testWith: \"postgres\" | \"mongodb\")." >&2
  echo "       Booting Postgres/Mongo containers would be pure waste; this script's premise is false." >&2
  echo "       Either restore DB-backed tests or retire this script's container provisioning." >&2
  exit 1
fi

echo "=== test-runtime.sh ==="
echo "Runs the clearance package suite. Only the following test files consume the"
echo "provisioned Postgres/Mongo containers (via testWith: \"postgres\" | \"mongodb\");"
echo "all other test files in the suite run against in-memory SQLite:"
printf '  - packages/runtime/%s\n' $DB_TEST_FILES
echo "Adapter tests (src/adapters/**) are excluded by packages/runtime/vitest.config.ts;"
echo "adapter coverage runs in the @clearance/*-adapter package suites via root 'test:runtime'."
echo "==========================="

RUN_ID="${$}-$(openssl rand -hex 4)"
POSTGRES_CONTAINER="clearance-runtime-test-postgres-$RUN_ID"
MONGO_CONTAINER="clearance-runtime-test-mongo-$RUN_ID"

cleanup() {
  docker rm -f "$POSTGRES_CONTAINER" "$MONGO_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run -d --rm --name "$POSTGRES_CONTAINER" -p 127.0.0.1::5432 \
  -e POSTGRES_USER=user -e POSTGRES_PASSWORD=password -e POSTGRES_DB=clearance \
  postgres:16-alpine >/dev/null
docker run -d --rm --name "$MONGO_CONTAINER" -p 127.0.0.1::27017 mongo:7 >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$POSTGRES_CONTAINER" pg_isready -U user -d clearance >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$POSTGRES_CONTAINER" pg_isready -U user -d clearance >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$MONGO_CONTAINER" mongosh --quiet --eval 'db.runCommand({ ping: 1 }).ok' 2>/dev/null | grep -q '^1$'; then break; fi
  sleep 1
done
docker exec "$MONGO_CONTAINER" mongosh --quiet --eval 'db.runCommand({ ping: 1 }).ok' 2>/dev/null | grep -q '^1$'

POSTGRES_PORT="$(docker port "$POSTGRES_CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')"
MONGO_PORT="$(docker port "$MONGO_CONTAINER" 27017/tcp | head -n 1 | awk -F: '{print $NF}')"

export CLEARANCE_TEST_POSTGRES_URL="postgres://user:password@127.0.0.1:$POSTGRES_PORT/clearance"
export CLEARANCE_TEST_MONGODB_URL="mongodb://127.0.0.1:$MONGO_PORT"

pnpm --filter @clearance/mongo-adapter build
pnpm --filter @clearance/runtime test -- --run
