#!/usr/bin/env bash
# Self-contained Clearance package tests with disposable external databases.
#
# Honesty note about what the containers actually exercise:
# - This script runs the runtime package suite (packages/runtime). Only the
#   test files that opt in via `testWith` or direct `CLEARANCE_TEST_*` URLs consume
#   the Postgres/Mongo/MySQL/MariaDB containers provisioned below; every other test file defaults to
#   in-memory SQLite. The exact consumer file list is derived at runtime (grep below) and
#   printed in the banner before the containers boot. If that list is ever empty, the
#   script fails: the containers would be pure waste and this script's premise false.
# - packages/runtime/vitest.config.ts excludes src/adapters/**/*.test.ts, so no
#   adapter tests run here. Adapter coverage lives in the separate @clearance/*-adapter
#   package suites (kysely/memory/mongo/drizzle/prisma) run by the root `test:runtime`
#   script in package.json, which invokes this script last.
set -euo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../packages/runtime" && pwd)"

# Derive (never hardcode) the test files that consume the provisioned databases.
# Include explicit testWith opt-ins and direct environment-backed integration
# tests. `testWith: "sqlite"` remains in-memory and is intentionally excluded.
DB_TEST_FILES="$(cd "$PKG_DIR" && grep -rl --include='*.test.ts' -E 'testWith:\s*"(postgres|mongodb|mysql)"|CLEARANCE_TEST_(POSTGRES|MONGODB|MYSQL|MARIADB)_URL|CLEARANCE_TEST_DATABASE_URL' src/ || true)"

if [[ -z "$DB_TEST_FILES" ]]; then
  echo "ERROR: no test files under packages/runtime/src opt into the external databases" >&2
  echo "       (expected a testWith opt-in or a CLEARANCE_TEST_* database URL)." >&2
  echo "       Booting database containers would be pure waste; this script's premise is false." >&2
  echo "       Either restore DB-backed tests or retire this script's container provisioning." >&2
  exit 1
fi

echo "=== test-runtime.sh ==="
echo "Runs the clearance package suite. Only the following test files consume the"
echo "provisioned database containers (via testWith or CLEARANCE_TEST_* URLs);"
echo "all other test files in the suite run against in-memory SQLite:"
printf '  - packages/runtime/%s\n' $DB_TEST_FILES
echo "Adapter tests (src/adapters/**) are excluded by packages/runtime/vitest.config.ts;"
echo "adapter coverage runs in the @clearance/*-adapter package suites via root 'test:runtime'."
echo "==========================="

RUN_ID="${$}-$(openssl rand -hex 4)"
POSTGRES_CONTAINER="clearance-runtime-test-postgres-$RUN_ID"
MONGO_CONTAINER="clearance-runtime-test-mongo-$RUN_ID"
MYSQL_CONTAINER="clearance-runtime-test-mysql-$RUN_ID"
MARIADB_CONTAINER="clearance-runtime-test-mariadb-$RUN_ID"
MONGO_PORT="$(node -e 'const net = require("node:net"); const server = net.createServer(); server.listen(0, "127.0.0.1", () => { console.log(server.address().port); server.close(); });')"
MYSQL_PORT="$(node -e 'const net = require("node:net"); const server = net.createServer(); server.listen(0, "127.0.0.1", () => { console.log(server.address().port); server.close(); });')"
MARIADB_PORT="$(node -e 'const net = require("node:net"); const server = net.createServer(); server.listen(0, "127.0.0.1", () => { console.log(server.address().port); server.close(); });')"

cleanup() {
  docker rm -f "$POSTGRES_CONTAINER" "$MONGO_CONTAINER" "$MYSQL_CONTAINER" "$MARIADB_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run -d --name "$POSTGRES_CONTAINER" -p 127.0.0.1::5432 \
	--tmpfs /var/lib/postgresql/data:rw,size=256m \
  -e POSTGRES_USER=user -e POSTGRES_PASSWORD=password -e POSTGRES_DB=clearance \
  postgres:16-alpine >/dev/null
docker run -d --name "$MONGO_CONTAINER" \
	-p "127.0.0.1:$MONGO_PORT:$MONGO_PORT" \
	--tmpfs /data/db:rw,size=512m mongo:7 \
	--replSet clearance-rs --bind_ip_all --port "$MONGO_PORT" >/dev/null
docker run -d --name "$MYSQL_CONTAINER" \
	-p "127.0.0.1:$MYSQL_PORT:3306" \
	--tmpfs /var/lib/mysql:rw,size=512m \
	-e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=clearance \
	mysql:8.4 >/dev/null
docker run -d --name "$MARIADB_CONTAINER" \
	-p "127.0.0.1:$MARIADB_PORT:3306" \
	--tmpfs /var/lib/mysql:rw,size=512m \
	-e MARIADB_ROOT_PASSWORD=password -e MARIADB_DATABASE=clearance \
	mariadb:11.4 >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$POSTGRES_CONTAINER" pg_isready -U user -d clearance >/dev/null 2>&1; then break; fi
	if [[ "$(docker inspect -f '{{.State.Running}}' "$POSTGRES_CONTAINER" 2>/dev/null || true)" != "true" ]]; then
		echo "ERROR: disposable PostgreSQL exited during startup" >&2
		docker logs "$POSTGRES_CONTAINER" >&2 || true
		exit 1
	fi
  sleep 1
done
docker exec "$POSTGRES_CONTAINER" pg_isready -U user -d clearance >/dev/null

for _ in $(seq 1 60); do
	if docker exec "$MONGO_CONTAINER" mongosh --quiet --port "$MONGO_PORT" --eval 'db.runCommand({ ping: 1 }).ok' 2>/dev/null | grep -q '^1$'; then break; fi
	if [[ "$(docker inspect -f '{{.State.Running}}' "$MONGO_CONTAINER" 2>/dev/null || true)" != "true" ]]; then
		echo "ERROR: disposable MongoDB exited during startup" >&2
		docker logs "$MONGO_CONTAINER" >&2 || true
		exit 1
	fi
  sleep 1
done
docker exec "$MONGO_CONTAINER" mongosh --quiet --port "$MONGO_PORT" --eval \
	"rs.initiate({_id: 'clearance-rs', members: [{_id: 0, host: 'localhost:$MONGO_PORT'}]}).ok" \
	2>/dev/null | grep -q '^1$'

for _ in $(seq 1 60); do
	if docker exec "$MONGO_CONTAINER" mongosh --quiet --port "$MONGO_PORT" --eval \
		'db.hello().isWritablePrimary' 2>/dev/null | grep -q '^true$'; then
		break
	fi
	sleep 1
done
docker exec "$MONGO_CONTAINER" mongosh --quiet --port "$MONGO_PORT" --eval \
	'db.hello().isWritablePrimary' 2>/dev/null | grep -q '^true$'

for container in "$MYSQL_CONTAINER" "$MARIADB_CONTAINER"; do
	admin_command="mysqladmin"
	if [[ "$container" == "$MARIADB_CONTAINER" ]]; then
		admin_command="mariadb-admin"
	fi
	for _ in $(seq 1 90); do
		if docker exec "$container" "$admin_command" ping -uroot -ppassword --silent >/dev/null 2>&1; then break; fi
		if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
			echo "ERROR: disposable MySQL-compatible database exited during startup" >&2
			docker logs "$container" >&2 || true
			exit 1
		fi
		sleep 1
	done
	docker exec "$container" "$admin_command" ping -uroot -ppassword --silent >/dev/null
done

POSTGRES_PORT="$(docker port "$POSTGRES_CONTAINER" 5432/tcp | head -n 1 | awk -F: '{print $NF}')"

export CLEARANCE_TEST_POSTGRES_URL="postgres://user:password@127.0.0.1:$POSTGRES_PORT/clearance"
export CLEARANCE_TEST_MONGODB_URL="mongodb://127.0.0.1:$MONGO_PORT/?replicaSet=clearance-rs"
export CLEARANCE_TEST_MYSQL_URL="mysql://root:password@127.0.0.1:$MYSQL_PORT/clearance"
export CLEARANCE_TEST_MARIADB_URL="mysql://root:password@127.0.0.1:$MARIADB_PORT/clearance"

pnpm --filter @clearance/mongo-adapter build
pnpm --filter @clearance/runtime exec vitest run "$@"
