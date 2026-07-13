#!/usr/bin/env bash
# Isolated, destructive end-to-end acceptance test for the complete local stack.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${SCRATCH_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/clearance-compose-smoke.XXXXXX")}"
PROJECT="clearance-smoke-${$}"
CLI_NODE="$ROOT/packages/clearance-cli/dist/index.js"
LOG="$SCRATCH/compose-smoke.log"

rand() { openssl rand -hex 32; }
BASE_PORT="${CLEARANCE_SMOKE_BASE_PORT:-$((22000 + ($$ % 10000)))}"
export CLEARANCE_POSTGRES_PORT="${CLEARANCE_POSTGRES_PORT:-$BASE_PORT}"
export CLEARANCE_CONSOLE_PORT="${CLEARANCE_CONSOLE_PORT:-$((BASE_PORT + 1))}"
export CLEARANCE_API_PORT="${CLEARANCE_API_PORT:-$((BASE_PORT + 2))}"
export CLEARANCE_SAMPLE_PORT="${CLEARANCE_SAMPLE_PORT:-$((BASE_PORT + 3))}"
export CLEARANCE_DB_USER="${CLEARANCE_DB_USER:-clearance}"
export CLEARANCE_DB_NAME="${CLEARANCE_DB_NAME:-clearance}"
export CLEARANCE_DB_PASSWORD="${CLEARANCE_DB_PASSWORD:-$(rand)}"
# docker-compose.yml supports an operator-selected volume name. Keep the
# destructive smoke volume scoped to this run so concurrent/local stacks can
# never attach to or remove each other's Postgres data.
export CLEARANCE_PG_VOLUME="${CLEARANCE_PG_VOLUME:-${PROJECT}-pg}"
export CLEARANCE_IMAGE="${CLEARANCE_IMAGE:-${PROJECT}:local}"
export CLEARANCE_SECRET="${CLEARANCE_SECRET:-$(rand)}"
export CLEARANCE_OPERATOR_TOKEN="${CLEARANCE_OPERATOR_TOKEN:-$(rand)}"
export CLEARANCE_CREDENTIAL_KEY="${CLEARANCE_CREDENTIAL_KEY:-$(rand)}"
export CLEARANCE_CREDENTIAL_KEY_ID="${CLEARANCE_CREDENTIAL_KEY_ID:-smoke-v1}"
export CLEARANCE_CONSOLE_ADMIN_USER="${CLEARANCE_CONSOLE_ADMIN_USER:-smoke-admin}"
export CLEARANCE_CONSOLE_ADMIN_PASSWORD="${CLEARANCE_CONSOLE_ADMIN_PASSWORD:-$(rand)}"
export CLEARANCE_CONSOLE_SESSION_SECRET="${CLEARANCE_CONSOLE_SESSION_SECRET:-$(rand)}"
# The management CLI runs on the host, so its Docker fallback needs the
# per-run Compose container identity rather than the ordinary stack default.
export CLEARANCE_PG_CONTAINER="${CLEARANCE_PG_CONTAINER:-${PROJECT}-postgres-1}"
export CLEARANCE_LOCAL_DIRECT=1

SAMPLE_URL="http://localhost:$CLEARANCE_SAMPLE_PORT"
API_URL="http://localhost:$CLEARANCE_API_PORT"
CONSOLE_URL="http://localhost:$CLEARANCE_CONSOLE_PORT"
DATABASE_URL="postgres://$CLEARANCE_DB_USER:$CLEARANCE_DB_PASSWORD@127.0.0.1:$CLEARANCE_POSTGRES_PORT/$CLEARANCE_DB_NAME"
COMPOSE=(docker compose -p "$PROJECT")

cleanup() {
  # Images are tagged with the per-run Compose project. Remove them with the
  # disposable containers/volume so repeated acceptance runs cannot exhaust
  # Docker's VM storage. Shared/base images remain untouched.
  "${COMPOSE[@]}" down -v --remove-orphans --rmi local >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

on_error() {
  local status="$?" line="$1"
  # Never print BASH_COMMAND here: several smoke commands carry temporary
  # bearer tokens and passwords in their arguments.
  printf 'COMPOSE_SMOKE_FAILED status=%s line=%s\n' "$status" "$line" >&2
  "${COMPOSE[@]}" ps --all >&2 || true
  "${COMPOSE[@]}" logs --no-color >&2 || true
  return "$status"
}
trap 'on_error "$LINENO"' ERR

json_field() {
  node -e "const fs=require('fs'); const j=JSON.parse(fs.readFileSync(0,'utf8')); const v=$1; if(v===undefined) process.exit(2); process.stdout.write(String(v))"
}

auth_curl() {
  curl -fsS -H "authorization: Bearer $CLEARANCE_OPERATOR_TOKEN" "$@"
}

wait_for() {
  local url="$1"
  for _ in $(seq 1 90); do
    if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  "${COMPOSE[@]}" ps --all >&2 || true
  "${COMPOSE[@]}" logs --no-color >&2 || true
  return 1
}

{
  cd "$ROOT"
  echo "compose_project=$PROJECT scratch=$SCRATCH"
  echo "ports postgres=$CLEARANCE_POSTGRES_PORT console=$CLEARANCE_CONSOLE_PORT api=$CLEARANCE_API_PORT sample=$CLEARANCE_SAMPLE_PORT"

  [[ -f "$CLI_NODE" ]] || pnpm build
  "${COMPOSE[@]}" config --quiet
  "${COMPOSE[@]}" build
  if ! "${COMPOSE[@]}" up -d; then
    "${COMPOSE[@]}" ps --all >&2 || true
    "${COMPOSE[@]}" logs --no-color >&2 || true
    exit 1
  fi
  wait_for "$API_URL/health"
  wait_for "$SAMPLE_URL/health"
  wait_for "$CONSOLE_URL/api/health"

  [[ "$(curl -sS -o /dev/null -w '%{http_code}' "$API_URL/v1/users")" == "401" ]]
  auth_curl -X POST "$API_URL/v1/init" -H 'content-type: application/json' -d '{"name":"compose-stack"}' >"$SCRATCH/init.json"

  USER_PASSWORD="Smoke!$(openssl rand -hex 12)aA1"
  auth_curl -X POST "$API_URL/v1/users" -H 'content-type: application/json' \
    -d "{\"email\":\"ops@compose.test\",\"name\":\"Compose Ops\",\"password\":\"$USER_PASSWORD\"}" >"$SCRATCH/user.json"
  USER_ID="$(json_field 'j.user.id' <"$SCRATCH/user.json")"
  auth_curl -X POST "$API_URL/v1/organizations" -H 'content-type: application/json' \
    -d "{\"name\":\"Compose Org\",\"ownerUserId\":\"$USER_ID\"}" >"$SCRATCH/org.json"
  ORG_ID="$(json_field 'j.organization.id' <"$SCRATCH/org.json")"

  COOKIE="$SCRATCH/sample.cookies"
  curl -fsS -c "$COOKIE" -b "$COOKIE" -X POST "$SAMPLE_URL/api/auth/sign-in/email" \
    -H 'content-type: application/json' -H "origin: $SAMPLE_URL" \
    -d "{\"email\":\"ops@compose.test\",\"password\":\"$USER_PASSWORD\"}" >"$SCRATCH/sign-in.json"
  curl -fsS -b "$COOKIE" "$SAMPLE_URL/api/me" | grep -q '"protected":true'
  curl -fsS -b "$COOKIE" "$SAMPLE_URL/dashboard" | grep -q 'Access granted'

  # Served console markup must contain the login form (data-testid pinned by
  # the DOM tests in packages/clearance-console/src/ui.test.js). The 2026-07-13
  # audit found the login backend working while the shipped UI had no form —
  # this tripwire plus the DOM suite makes that regression impossible to miss.
  curl -fsS "$CONSOLE_URL/" | grep -q 'data-testid="console-login"'

  CONSOLE_COOKIE="$SCRATCH/console.cookies"
  curl -fsS -c "$CONSOLE_COOKIE" -b "$CONSOLE_COOKIE" -X POST "$CONSOLE_URL/api/console/login" \
    -H 'content-type: application/json' -H "origin: $CONSOLE_URL" \
    -d "{\"username\":\"$CLEARANCE_CONSOLE_ADMIN_USER\",\"password\":\"$CLEARANCE_CONSOLE_ADMIN_PASSWORD\"}" >"$SCRATCH/console-login.json"
  CSRF="$(json_field 'j.csrf' <"$SCRATCH/console-login.json")"
  curl -fsS -b "$CONSOLE_COOKIE" "$CONSOLE_URL/api/v1/overview" >"$SCRATCH/console-overview.json"
  curl -fsS -b "$CONSOLE_COOKIE" -X POST "$CONSOLE_URL/api/console/logout" \
    -H "origin: $CONSOLE_URL" -H "x-csrf-token: $CSRF" >/dev/null
  [[ "$(curl -sS -b "$CONSOLE_COOKIE" -o /dev/null -w '%{http_code}' "$CONSOLE_URL/api/v1/overview")" == "401" ]]

  # Rendered-browser acceptance (FOLLOW.md P2.5): a real chromium completes
  # console login/overview/users/sign-out and sample sign-up→dashboard→
  # sign-out against this same stack. Fail closed if the browser binary is
  # missing — never auto-download mid-gate.
  node -e '
    const { chromium } = require("'"$ROOT"'/packages/clearance-e2e/node_modules/@playwright/test");
    const p = chromium.executablePath();
    if (!require("fs").existsSync(p)) {
      console.error("chromium is not installed for Playwright (fail closed).");
      console.error("Remediation: pnpm --filter @clearance/e2e exec playwright install chromium");
      process.exit(1);
    }
  '
  (cd "$ROOT/packages/clearance-e2e" && \
    CLEARANCE_CONSOLE_URL="$CONSOLE_URL" \
    CLEARANCE_SAMPLE_URL="$SAMPLE_URL" \
    CLEARANCE_CONSOLE_ADMIN_USER="$CLEARANCE_CONSOLE_ADMIN_USER" \
    CLEARANCE_CONSOLE_ADMIN_PASSWORD="$CLEARANCE_CONSOLE_ADMIN_PASSWORD" \
    npx playwright test)

  # Cursor pagination acceptance (FOLLOW.md P2.3.1): create more users than
  # one page, walk cursors to exhaustion, assert no duplicates or omissions
  # and that a garbage cursor fails structured.
  for i in 1 2 3 4 5; do
    auth_curl -X POST "$API_URL/v1/users" -H 'content-type: application/json' \
      -d "{\"email\":\"page-$i@compose.test\",\"name\":\"Page $i\",\"password\":\"$USER_PASSWORD\"}" >/dev/null
  done
  node -e '
    const api = process.argv[1], token = process.argv[2];
    (async () => {
      const seen = new Set();
      let cursor, pages = 0;
      for (;;) {
        const url = new URL(api + "/v1/users");
        url.searchParams.set("limit", "2");
        if (cursor) url.searchParams.set("cursor", cursor);
        const res = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
        if (!res.ok) { console.error("page fetch failed", res.status); process.exit(1); }
        const body = await res.json();
        for (const u of body.users) {
          if (seen.has(u.id)) { console.error("duplicate across pages:", u.id); process.exit(1); }
          seen.add(u.id);
        }
        pages++;
        if (!body.nextCursor) break;
        cursor = body.nextCursor;
        if (pages > 50) { console.error("cursor walk did not terminate"); process.exit(1); }
      }
      if (seen.size < 6 || pages < 3) { console.error(`walk incomplete: ${seen.size} users over ${pages} pages`); process.exit(1); }
      const bad = await fetch(api + "/v1/users?cursor=garbage-cursor", { headers: { authorization: `Bearer ${token}` } });
      const badBody = await bad.json();
      if (bad.status !== 400 || badBody?.error?.code !== "CURSOR_INVALID") { console.error("garbage cursor not failed closed:", bad.status, JSON.stringify(badBody).slice(0,200)); process.exit(1); }
      console.log(`pagination walk asserted: ${seen.size} users over ${pages} pages, garbage cursor CURSOR_INVALID`);
    })().catch((e) => { console.error(e); process.exit(1); });
  ' "$API_URL" "$CLEARANCE_OPERATOR_TOKEN"

  # Idempotency-Key acceptance (FOLLOW.md P2.3.2): replay returns the original
  # response byte-identically with the replay marker; conflicting payload 409s.
  IDEM_KEY="smoke-idem-$(openssl rand -hex 8)"
  auth_curl -X POST "$API_URL/v1/organizations" -H 'content-type: application/json' \
    -H "idempotency-key: $IDEM_KEY" \
    -d "{\"name\":\"Idem Org\",\"ownerUserId\":\"$USER_ID\"}" >"$SCRATCH/idem-1.json"
  curl -sS -D "$SCRATCH/idem-2.headers" -H "authorization: Bearer $CLEARANCE_OPERATOR_TOKEN" \
    -X POST "$API_URL/v1/organizations" -H 'content-type: application/json' \
    -H "idempotency-key: $IDEM_KEY" \
    -d "{\"name\":\"Idem Org\",\"ownerUserId\":\"$USER_ID\"}" >"$SCRATCH/idem-2.json"
  cmp -s "$SCRATCH/idem-1.json" "$SCRATCH/idem-2.json"
  grep -qi '^idempotency-replayed: true' "$SCRATCH/idem-2.headers"
  [[ "$(curl -sS -o /dev/null -w '%{http_code}' -H "authorization: Bearer $CLEARANCE_OPERATOR_TOKEN" \
    -X POST "$API_URL/v1/organizations" -H 'content-type: application/json' \
    -H "idempotency-key: $IDEM_KEY" \
    -d "{\"name\":\"Different Payload\",\"ownerUserId\":\"$USER_ID\"}")" == "409" ]]
  echo "idempotency replay + conflict asserted"

  MARKER="OIDC-SMOKE-PLAINTEXT-$(openssl rand -hex 8)"
  SSO_STATUS="$(curl -sS -o "$SCRATCH/sso.json" -w '%{http_code}' \
    -H "authorization: Bearer $CLEARANCE_OPERATOR_TOKEN" \
    -X POST "$API_URL/v1/sso" -H 'content-type: application/json' \
    -d "{\"organizationId\":\"$ORG_ID\",\"provider\":\"oidc\",\"issuer\":\"https://idp.example.test\",\"clientId\":\"smoke-client\",\"clientSecret\":\"$MARKER\"}")"
  if [[ "$SSO_STATUS" != "201" ]]; then
    node -e 'const j=require(process.argv[1]); console.error("SSO create failed", process.argv[2], j.error?.code ?? "UNKNOWN", j.error?.message ?? "unknown error")' "$SCRATCH/sso.json" "$SSO_STATUS"
    exit 1
  fi
  SSO_ID="$(json_field 'j.connection.id' <"$SCRATCH/sso.json")"
  STORED="$(${COMPOSE[@]} exec -T postgres psql -U "$CLEARANCE_DB_USER" -d "$CLEARANCE_DB_NAME" -Atc "select \"oidcConfig\" from \"ssoProvider\" where id = '$SSO_ID'")"
  [[ "$STORED" == *'clr-sso:v1:'* ]] || { echo "runtime SSO credential is missing the encrypted-storage marker" >&2; exit 1; }
  [[ "$STORED" != *"$MARKER"* ]] || { echo "runtime SSO credential retained plaintext" >&2; exit 1; }

  export DATABASE_URL CLEARANCE_BASE_URL="$SAMPLE_URL" CLEARANCE_API_URL="$API_URL" CLEARANCE_CONSOLE_URL="$CONSOLE_URL" CLEARANCE_STRICT_SECRETS=1 NODE_ENV=production
  node "$CLI_NODE" doctor --json --no-input >"$SCRATCH/doctor.json"
  # Fail closed on the real doctor contract ({ ok, checks[], releaseVersion }).
  # The previous check read j.summary?.failures — doctor output has no
  # `summary` field at all, so that assertion could never fire.
  node -e "
    const j=require(process.argv[1]);
    if (j.ok !== true || !Array.isArray(j.checks) || j.checks.some(c => c.status === 'fail')) {
      console.error('doctor gate failed: ok=' + j.ok + ' failing=' + JSON.stringify((j.checks||[]).filter(c=>c.status==='fail').map(c=>c.id)));
      process.exit(1);
    }
  " "$SCRATCH/doctor.json"

  IMPORT_FIXTURE="$ROOT/fixtures/migration-export/sample.json"
  IMPORT_BASELINE="$(${COMPOSE[@]} exec -T postgres psql -U "$CLEARANCE_DB_USER" -d "$CLEARANCE_DB_NAME" -Atc "select (select count(*) from \"user\")||'/'||(select count(*) from organization)||'/'||(select count(*) from member)")"
  node "$CLI_NODE" --json --no-input --yes import legacy --file "$IMPORT_FIXTURE" >"$SCRATCH/import-first.json"
  node -e 'const j=require(process.argv[1]); const a=j.verification?.actual; if(!j.verification?.reconciled || a?.users!==3 || a?.organizations!==1 || a?.members!==3 || j.storeBackend!=="postgres") process.exit(1)' "$SCRATCH/import-first.json"
  IMPORT_FIRST_ID="$(json_field 'j.migration.id' <"$SCRATCH/import-first.json")"
  IMPORT_FIRST_USER_ID="$(json_field 'j.migration.createdRuntimeResourceIds.users[0]' <"$SCRATCH/import-first.json")"
  IMPORT_FIRST_MEMBER_ID="$(json_field 'j.migration.createdRuntimeResourceIds.memberships[0]' <"$SCRATCH/import-first.json")"

  "${COMPOSE[@]}" exec -T postgres psql -U "$CLEARANCE_DB_USER" -d "$CLEARANCE_DB_NAME" -v ON_ERROR_STOP=1 \
    -c "update member set role = 'member' where id = '$IMPORT_FIRST_MEMBER_ID'" >/dev/null
  if node "$CLI_NODE" --json --no-input migration verify --id "$IMPORT_FIRST_ID" --fixture "$IMPORT_FIXTURE" >"$SCRATCH/import-role-drift.json"; then
    echo "migration verify accepted a drifted runtime membership role" >&2
    exit 1
  fi
  "${COMPOSE[@]}" exec -T postgres psql -U "$CLEARANCE_DB_USER" -d "$CLEARANCE_DB_NAME" -v ON_ERROR_STOP=1 \
    -c "update member set role = 'admin' where id = '$IMPORT_FIRST_MEMBER_ID'" >/dev/null
  node "$CLI_NODE" --json --no-input migration verify --id "$IMPORT_FIRST_ID" --fixture "$IMPORT_FIXTURE" >/dev/null

  node "$CLI_NODE" --json --no-input --yes import legacy --file "$IMPORT_FIXTURE" >"$SCRATCH/import-second.json"
  node -e 'const j=require(process.argv[1]); const c=j.migration?.createdResourceIds; const r=j.migration?.createdRuntimeResourceIds; if(c?.users?.length || c?.organizations?.length || c?.memberships?.length || r?.users?.length || r?.organizations?.length || r?.memberships?.length) process.exit(1)' "$SCRATCH/import-second.json"
  IMPORT_SECOND_ID="$(json_field 'j.migration.id' <"$SCRATCH/import-second.json")"

  IMPORTED_RUNTIME="$(${COMPOSE[@]} exec -T postgres psql -U "$CLEARANCE_DB_USER" -d "$CLEARANCE_DB_NAME" -Atc "select (select count(*) from \"user\")||'/'||(select count(*) from organization)||'/'||(select count(*) from member)")"
  node -e '
    const before=process.argv[1].split("/").map(Number), after=process.argv[2].split("/").map(Number);
    if(after[0]!==before[0]+3 || after[1]!==before[1]+1 || after[2]!==before[2]+3) process.exit(1);
  ' "$IMPORT_BASELINE" "$IMPORTED_RUNTIME"

  "${COMPOSE[@]}" exec -T postgres psql -U "$CLEARANCE_DB_USER" -d "$CLEARANCE_DB_NAME" -v ON_ERROR_STOP=1 \
    -c "update \"user\" set email = 'changed-after-import@example.test' where id = '$IMPORT_FIRST_USER_ID'" >/dev/null
  if node "$CLI_NODE" --json --no-input --yes migration rollback --id "$IMPORT_FIRST_ID" --fixture "$IMPORT_FIXTURE" >"$SCRATCH/import-unsafe-rollback.json"; then
    echo "migration rollback deleted a runtime user whose checkpointed identity changed" >&2
    exit 1
  fi
  "${COMPOSE[@]}" exec -T postgres psql -U "$CLEARANCE_DB_USER" -d "$CLEARANCE_DB_NAME" -v ON_ERROR_STOP=1 \
    -c "update \"user\" set email = 'alice@example.com' where id = '$IMPORT_FIRST_USER_ID'" >/dev/null
  echo "CLEARANCE_IMPORT_DRIFT_GUARDS_OK role_verify=refused user_rollback=refused"

  node "$CLI_NODE" --json --no-input --yes migration rollback --id "$IMPORT_SECOND_ID" --fixture "$IMPORT_FIXTURE" >/dev/null
  node "$CLI_NODE" --json --no-input --yes migration rollback --id "$IMPORT_FIRST_ID" --fixture "$IMPORT_FIXTURE" >/dev/null
  IMPORTED_AFTER_ROLLBACK="$(${COMPOSE[@]} exec -T postgres psql -U "$CLEARANCE_DB_USER" -d "$CLEARANCE_DB_NAME" -Atc "select (select count(*) from \"user\")||'/'||(select count(*) from organization)||'/'||(select count(*) from member)")"
  [[ "$IMPORTED_AFTER_ROLLBACK" == "$IMPORT_BASELINE" ]]
  echo "CLEARANCE_IMPORT_POSTGRES_OK apply=3/1/3 rerun=0/0/0 rollback=0/0/0"

  PREEXISTING_FIXTURE="$ROOT/fixtures/migration-export/preexisting-compose.json"
  node "$CLI_NODE" --json --no-input --yes import legacy --file "$PREEXISTING_FIXTURE" >"$SCRATCH/import-preexisting.json"
  node -e 'const j=require(process.argv[1]); const c=j.migration?.createdResourceIds; const r=j.migration?.createdRuntimeResourceIds; if(!j.verification?.reconciled || c?.users?.length || c?.organizations?.length || c?.memberships?.length || r?.users?.length || r?.organizations?.length || r?.memberships?.length) process.exit(1)' "$SCRATCH/import-preexisting.json"
  PREEXISTING_IMPORT_ID="$(json_field 'j.migration.id' <"$SCRATCH/import-preexisting.json")"
  node "$CLI_NODE" --json --no-input --yes migration rollback --id "$PREEXISTING_IMPORT_ID" --fixture "$PREEXISTING_FIXTURE" >/dev/null
  auth_curl "$API_URL/v1/users" | grep -q "$USER_ID"
  auth_curl "$API_URL/v1/organizations" | grep -q "$ORG_ID"
  echo "CLEARANCE_IMPORT_PREEXISTING_OK preserved_user=$USER_ID preserved_org=$ORG_ID"

  node "$CLI_NODE" backup create --dir "$SCRATCH/backups" --json --no-input >"$SCRATCH/backup.json"
  BACKUP_ID="$(json_field 'j.backup.id' <"$SCRATCH/backup.json")"
  BACKUP_PATH="$(json_field 'j.backup.path' <"$SCRATCH/backup.json")"
  BACKUP_META="${BACKUP_PATH%.sql}.meta.json"
  node -e '
    const fs=require("fs");
    const paths=[[process.argv[1],0o700],[process.argv[2],0o600],[process.argv[3],0o600]];
    for (const [path, expected] of paths) {
      if ((fs.statSync(path).mode & 0o777) !== expected) process.exit(1);
    }
  ' "$SCRATCH/backups" "$BACKUP_PATH" "$BACKUP_META"
  node "$CLI_NODE" backup verify --id "$BACKUP_ID" --json --no-input >/dev/null
  node "$CLI_NODE" backup restore --id "$BACKUP_ID" --json --no-input >"$SCRATCH/restore.json"
  node -e '
    const j=require(process.argv[1]);
    if(j.verified!==true || j.retained!==false || !j.database) process.exit(1);
  ' "$SCRATCH/restore.json"
  RESTORE_DATABASE="$(json_field 'j.database' <"$SCRATCH/restore.json")"
  [[ "$("${COMPOSE[@]}" exec -T postgres psql -U "$CLEARANCE_DB_USER" -d postgres -Atc "select count(*) from pg_database where datname = '$RESTORE_DATABASE'")" == "0" ]]

  "${COMPOSE[@]}" restart api console sample-b2b
  wait_for "$API_URL/health"
  wait_for "$SAMPLE_URL/health"
  wait_for "$CONSOLE_URL/api/health"
  auth_curl "$API_URL/v1/users" | grep -q "$USER_ID"
  auth_curl "$API_URL/v1/organizations" | grep -q "$ORG_ID"
  curl -fsS -c "$SCRATCH/restart.cookies" -X POST "$SAMPLE_URL/api/auth/sign-in/email" \
    -H 'content-type: application/json' -H "origin: $SAMPLE_URL" \
    -d "{\"email\":\"ops@compose.test\",\"password\":\"$USER_PASSWORD\"}" >/dev/null

  "${COMPOSE[@]}" ps
  echo COMPOSE_STACK_HEALTHY
} 2>&1 | tee "$LOG"

echo "Wrote $LOG"
