#!/usr/bin/env bash
# Focused static + behavioral verification for production ops hardening.
# Does NOT claim full production readiness. Optional live Postgres proof is isolated.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"

PASS=0
FAIL=0
SKIP=0
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/clearance-prod-ops.XXXXXX")"
PG_CID=""
COMPOSE_PROJECT=""

cleanup() {
  if [[ -n "$PG_CID" ]]; then
    docker rm -f "$PG_CID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$COMPOSE_PROJECT" ]]; then
    docker compose -p "$COMPOSE_PROJECT" -f docker-compose.yml -f deploy/compose/docker-compose.production.yml down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -rf "$SCRATCH"
}
trap cleanup EXIT INT TERM

ok() { printf 'PASS  %s\n' "$*"; PASS=$((PASS + 1)); }
bad() { printf 'FAIL  %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }
skip() { printf 'SKIP  %s\n' "$*"; SKIP=$((SKIP + 1)); }

section() { printf '\n### %s ###\n' "$*"; }

# ---------- static: shell safety ----------
section "static: operational scripts use strict shell"
SCRIPTS=(
  scripts/validate-production-env.sh
  scripts/backup-create.sh
  scripts/backup-verify.sh
  scripts/backup-restore-verify.sh
  scripts/backup-scheduled.sh
  scripts/scim-legacy-preflight.sh
  scripts/upgrade-plan.sh
  scripts/upgrade-preflight.sh
  scripts/upgrade-apply.sh
  scripts/upgrade-verify.sh
  scripts/upgrade-rollback.sh
  scripts/sign-release.sh
  scripts/verify-production-ops.sh
)
for s in "${SCRIPTS[@]}"; do
  if [[ ! -f "$s" ]]; then bad "missing $s"; continue; fi
  if head -n 20 "$s" | grep -qE 'set -Eeuo pipefail|set -euo pipefail'; then
    ok "$s has strict mode"
  else
    bad "$s missing set -Eeuo pipefail (or set -euo pipefail)"
  fi
done
# Note: the former sign-release source-grep checks (genrsa / signing-key text)
# were removed — the behavioral sign-release section below proves the same
# contracts by execution (refuses missing key, real verifiable signature).

if grep -qE 'trap .*BASH_COMMAND|COMPOSE_SMOKE_FAILED.*command=' scripts/compose-smoke.sh; then
  bad "compose smoke failure diagnostics can expose expanded secret-bearing commands"
else
  ok "compose smoke failure diagnostics omit expanded commands"
fi

# ---------- static: production compose ----------
section "static: production compose fail-closed"
PROD=deploy/compose/docker-compose.production.yml
if [[ ! -f "$PROD" ]]; then
  bad "missing $PROD"
else
  # Only flag real ${VAR:-default} forms (not comments, not fail-closed ${VAR:?msg}).
  if grep -E '^[^#]*\$\{[A-Z0-9_]+:-[^}]+\}' "$PROD" >/dev/null; then
    bad "production overlay still has \${VAR:-default} interpolation"
  else
    ok "production overlay has no \${VAR:-default} traps"
  fi
  if grep -q 'DATABASE_URL: \${DATABASE_URL:?' "$PROD"; then
    ok "DATABASE_URL required fail-closed"
  else
    bad "DATABASE_URL not fail-closed in production overlay"
  fi
  if grep -q 'NODE_ENV: production' "$PROD"; then
    ok "NODE_ENV forced production"
  else
    bad "NODE_ENV not forced production"
  fi
  if grep -qE 'ports: !reset' "$PROD"; then
    ok "postgres host ports reset (not published by default)"
  else
    bad "postgres ports not reset in production overlay"
  fi
  PROD_PORT_OVERRIDES="$(grep -cE '^[[:space:]]+ports: !override$' "$PROD" || true)"
  if [[ "$PROD_PORT_OVERRIDES" == "3" ]]; then
    ok "API, console, and sample production ports replace base bindings"
  else
    bad "expected three production !override port lists, found $PROD_PORT_OVERRIDES"
  fi
  if grep -qE 'CLEARANCE_SECRET:-\$\{|:-dev-secret|:-change-me|:-clearance"' "$PROD"; then
    bad "weak secret defaults in production overlay"
  else
    ok "no weak secret defaults detected in production overlay"
  fi
  if grep -q 'CLEARANCE_GITHUB_CLIENT_ID:' "$PROD" \
    && grep -q 'CLEARANCE_GITHUB_CLIENT_SECRET:' "$PROD" \
    && grep -q 'CLEARANCE_GOOGLE_CLIENT_ID:' "$PROD" \
    && grep -q 'CLEARANCE_GOOGLE_CLIENT_SECRET:' "$PROD"; then
    ok "production sample app accepts optional GitHub/Google credential pairs"
  else
    bad "production sample app is missing optional social credential passthrough"
  fi
fi

# base compose must not be claimed as production-only
if grep -qi 'not a production profile\|Do not deploy this file alone' docker-compose.yml; then
  ok "base docker-compose.yml documents non-production profile"
else
  bad "base compose missing non-production warning"
fi

# ---------- behavioral: validate-production-env ----------
section "behavioral: validate-production-env refuse weak/missing"
# env -i gives a genuinely empty environment (the caller's shell exports
# CLEARANCE_* vars in CI/dev, which would silently defeat this test).
# PATH must be preserved or the script fails for the wrong reason.
set +e
env -i PATH="$PATH" bash scripts/validate-production-env.sh >/dev/null 2>&1
ec=$?
set -e
if [[ $ec -ne 0 ]]; then
  ok "validate-production-env fails with empty env"
else
  bad "validate-production-env should fail with empty env"
fi

export CLEARANCE_OPERATOR_TOKEN="short"
export CLEARANCE_SECRET="dev-secret-change-me"
export CLEARANCE_CREDENTIAL_KEY="x"
export CLEARANCE_CREDENTIAL_KEY_ID="k1"
export CLEARANCE_CONSOLE_ADMIN_USER="admin"
export CLEARANCE_CONSOLE_ADMIN_PASSWORD="password"
export CLEARANCE_CONSOLE_SESSION_SECRET="change-me"
export CLEARANCE_DB_USER="clearance"
export CLEARANCE_DB_PASSWORD="clearance"
export CLEARANCE_DB_NAME="clearance"
export DATABASE_URL="postgres://clearance:clearance@postgres:5432/clearance"
export CLEARANCE_BASE_URL="https://app.example.test"
export CLEARANCE_CONSOLE_URL="https://console.example.test"
export CLEARANCE_CORS_ORIGINS="https://app.example.test"
export CLEARANCE_API_PORT="3200"
export CLEARANCE_CONSOLE_PORT="3100"
export CLEARANCE_SAMPLE_PORT="3000"
export CLEARANCE_PG_VOLUME="clearance_pg_prod"
export CLEARANCE_BACKUP_VOLUME="clearance_backups_prod"
export CLEARANCE_IMAGE_REPOSITORY="ghcr.io/example/clearance"
export CLEARANCE_IMAGE_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
export CLEARANCE_BACKUP_IMAGE_REPOSITORY="ghcr.io/example/clearance-backup"
export CLEARANCE_BACKUP_IMAGE_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
export NODE_ENV=production
set +e
bash scripts/validate-production-env.sh >/dev/null 2>&1
ec=$?
set -e
if [[ $ec -ne 0 ]]; then
  ok "validate-production-env refuses weak defaults"
else
  bad "validate-production-env accepted weak defaults"
fi

export CLEARANCE_GITHUB_CLIENT_ID="github-client"
unset CLEARANCE_GITHUB_CLIENT_SECRET || true
set +e
bash scripts/validate-production-env.sh >/dev/null 2>&1
ec=$?
set -e
if [[ $ec -ne 0 ]]; then
  ok "validate-production-env refuses incomplete social credential pairs"
else
  bad "validate-production-env accepted an incomplete social credential pair"
fi
unset CLEARANCE_GITHUB_CLIENT_ID

# Strong secrets should pass (localhost base URL requires allow flag)
export CLEARANCE_OPERATOR_TOKEN="$(openssl rand -hex 24)"
export CLEARANCE_SECRET="$(openssl rand -hex 24)"
export CLEARANCE_CREDENTIAL_KEY="$(openssl rand -hex 24)"
export CLEARANCE_CONSOLE_ADMIN_PASSWORD="$(openssl rand -hex 24)"
export CLEARANCE_CONSOLE_SESSION_SECRET="$(openssl rand -hex 24)"
export CLEARANCE_DB_PASSWORD="$(openssl rand -hex 24)"
export DATABASE_URL="postgres://clearance_prod_user:${CLEARANCE_DB_PASSWORD}@postgres:5432/clearance_prod"
export CLEARANCE_DB_USER="clearance_prod_user"
export CLEARANCE_DB_NAME="clearance_prod"
export CLEARANCE_ALLOW_LOCALHOST_PRODUCTION=0
set +e
bash scripts/validate-production-env.sh >"$SCRATCH/val-ok.txt" 2>&1
ec=$?
set -e
if [[ $ec -eq 0 ]]; then
  ok "validate-production-env accepts strong production-like env"
else
  bad "validate-production-env rejected strong env: $(head -5 "$SCRATCH/val-ok.txt" | tr '\n' ' ')"
fi

# ---------- behavioral: sign-release ----------
section "behavioral: sign-release fail-closed without key"
unset CLEARANCE_RELEASE_SIGNING_KEY CLEARANCE_RELEASE_SIGNING_KEY_FILE || true
set +e
bash scripts/sign-release.sh "$SCRATCH/unsigned-should-fail" >/dev/null 2>&1
ec=$?
set -e
if [[ $ec -ne 0 ]]; then
  ok "sign-release refuses missing key"
else
  bad "sign-release should fail without key"
fi

section "behavioral: sign-release real signature + self-verify"
KEY="$SCRATCH/test-release.key"
openssl genrsa -out "$KEY" 2048 >/dev/null 2>&1
export CLEARANCE_RELEASE_SIGNING_KEY_FILE="$KEY"
export CLEARANCE_VERSION="0.1.0-test"
bash scripts/sign-release.sh "$SCRATCH/signed" >/dev/null
if [[ -s "$SCRATCH/signed/release-bundle.sig" && -s "$SCRATCH/signed/release-public.pem" ]]; then
  openssl dgst -sha256 -verify "$SCRATCH/signed/release-public.pem" \
    -signature "$SCRATCH/signed/release-bundle.sig" \
    "$SCRATCH/signed/release-bundle.txt" >/dev/null \
    && ok "sign-release produces verifiable signature" \
    || bad "signature did not verify"
else
  bad "sign-release missing sig/public key outputs"
fi
if grep -qi 'unsigned' "$SCRATCH/signed/provenance.json"; then
  bad "provenance claims unsigned"
else
  ok "provenance does not claim unsigned"
fi
unset CLEARANCE_RELEASE_SIGNING_KEY_FILE

# ---------- compose config with production overlay (no up) ----------
section "behavioral: production compose config requires secrets"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  # (A former unasserted `docker compose config` run was removed here: the
  # caller env still carries strong secrets from the section above, so a bare
  # run proved nothing. The fail case unsets the critical vars explicitly and
  # the pass case exports a full strong env below.)
  (
    unset CLEARANCE_OPERATOR_TOKEN CLEARANCE_SECRET DATABASE_URL
    set +e
    docker compose -f docker-compose.yml -f deploy/compose/docker-compose.production.yml --profile backup config >/dev/null 2>"$SCRATCH/compose-fail.txt"
    ec=$?
    set -e
    if [[ $ec -ne 0 ]]; then
      ok "production compose config fails without required secrets"
    else
      bad "production compose config should fail without secrets"
    fi
  )
  # With full env, config should succeed and must not publish postgres
  export CLEARANCE_OPERATOR_TOKEN="$(openssl rand -hex 24)"
  export CLEARANCE_SECRET="$(openssl rand -hex 24)"
  export CLEARANCE_CREDENTIAL_KEY="$(openssl rand -hex 24)"
  export CLEARANCE_CREDENTIAL_KEY_ID="prod-v1"
  export CLEARANCE_CONSOLE_ADMIN_USER="ops"
  export CLEARANCE_CONSOLE_ADMIN_PASSWORD="$(openssl rand -hex 24)"
  export CLEARANCE_CONSOLE_SESSION_SECRET="$(openssl rand -hex 24)"
  export CLEARANCE_DB_USER="clearance_prod_user"
  export CLEARANCE_DB_PASSWORD="$(openssl rand -hex 24)"
  export CLEARANCE_DB_NAME="clearance_prod"
  export DATABASE_URL="postgres://clearance_prod_user:${CLEARANCE_DB_PASSWORD}@postgres:5432/clearance_prod"
  export CLEARANCE_BASE_URL="https://app.example.test"
  export CLEARANCE_CONSOLE_URL="https://console.example.test"
  export CLEARANCE_CORS_ORIGINS="https://app.example.test"
  export CLEARANCE_API_PORT="3200"
  export CLEARANCE_CONSOLE_PORT="3100"
  export CLEARANCE_SAMPLE_PORT="3000"
  export CLEARANCE_PG_VOLUME="clearance_pg_prod_verify"
  export CLEARANCE_BACKUP_VOLUME="clearance_backups_prod_verify"
  export CLEARANCE_IMAGE_REPOSITORY="ghcr.io/example/clearance"
  export CLEARANCE_IMAGE_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  export CLEARANCE_BACKUP_IMAGE_REPOSITORY="ghcr.io/example/clearance-backup"
  export CLEARANCE_BACKUP_IMAGE_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  if docker compose -f docker-compose.yml -f deploy/compose/docker-compose.production.yml --profile backup config >"$SCRATCH/compose-ok.yml" 2>/dev/null; then
    ok "production compose config succeeds with strong env"
    # postgres ports should be empty / absent host publish
    if node -e '
      const fs=require("fs");
      const y=fs.readFileSync(process.argv[1],"utf8");
      // Match the top-level postgres service only (indent: two spaces + name + colon).
      const m=y.match(/^  postgres:\n([\s\S]*?)(?=^  [a-zA-Z0-9_-]+:|\nvolumes:)/m);
      if(!m) { console.error("postgres service not found"); process.exit(2); }
      const block=m[1];
      // Any host publish of 5432 is a failure for the production default profile.
      if (/published:/.test(block) || /target:\s*5432/.test(block) || /:\d+:5432/.test(block) || /-\s*"?\d+:5432"/.test(block)) {
        process.exit(1);
      }
      process.exit(0);
    ' "$SCRATCH/compose-ok.yml"; then
      ok "resolved production config does not publish postgres to host"
    else
      bad "resolved production config still publishes postgres"
    fi
    if node -e '
      const fs=require("fs"), y=fs.readFileSync(process.argv[1],"utf8");
      const expected={
        api:"ghcr.io/example/clearance@sha256:"+"a".repeat(64),
        console:"ghcr.io/example/clearance@sha256:"+"a".repeat(64),
        "sample-b2b":"ghcr.io/example/clearance@sha256:"+"a".repeat(64),
        backup:"ghcr.io/example/clearance-backup@sha256:"+"b".repeat(64),
      };
      for (const [name,image] of Object.entries(expected)) {
        const m=y.match(new RegExp(`^  ${name}:\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9_-]+:|\\nvolumes:)`,"m"));
        if(!m || !m[1].includes(`image: ${image}`) || /^    build:/m.test(m[1])) process.exit(1);
      }
    ' "$SCRATCH/compose-ok.yml"; then
      ok "production Compose deploys signed digest references with local builds disabled"
    else
      bad "production Compose did not resolve exclusively to signed digest references"
    fi
    if node -e '
      const fs=require("fs");
      const y=fs.readFileSync(process.argv[1],"utf8");
      const expected={api:3200,console:3100,"sample-b2b":3000};
      for (const [name,target] of Object.entries(expected)) {
        const escaped=name.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
        const m=y.match(new RegExp(`^  ${escaped}:\\n([\\s\\S]*?)(?=^  [a-zA-Z0-9_-]+:|\\nvolumes:|\\nnetworks:)`,"m"));
        if(!m) { console.error(`${name}: service not found`); process.exit(2); }
        const published=[...m[1].matchAll(/^\s+published:\s+"?([^"\n]+)"?$/gm)];
        const targets=[...m[1].matchAll(/^\s+target:\s+(\d+)$/gm)].map(x=>Number(x[1]));
        if(published.length!==1 || targets.length!==1 || targets[0]!==target) {
          console.error(`${name}: expected one target ${target}, got published=${published.length} targets=${targets}`);
          process.exit(1);
        }
      }
    ' "$SCRATCH/compose-ok.yml"; then
      ok "resolved production config has exactly one API/console/sample binding each"
    else
      bad "resolved production config has duplicate, missing, or unexpected service bindings"
    fi
  else
    bad "production compose config failed with strong env"
  fi
else
  # Fail closed: verify-real.sh hard-requires Docker, so there is no
  # legitimate no-docker path through this gate.
  bad "docker is unavailable; production compose config checks cannot run"
fi

# ---------- Helm network and trusted-proxy contracts ----------
section "behavioral: Helm network and trusted-proxy contracts"
if command -v helm >/dev/null 2>&1; then
  HELM_ARGS=(
    --set image.repository=ghcr.io/example/clearance
    --set-string image.digest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    --set secrets.existingSecret=clearance-secrets
    --set console.secrets.existingSecret=clearance-secrets
    --set env.CLEARANCE_BASE_URL=https://auth.example.test
    --set env.CLEARANCE_CORS_ORIGINS=https://console.example.test
  )
  if helm lint deploy/helm/clearance "${HELM_ARGS[@]}" >/dev/null \
    && helm template beta deploy/helm/clearance --namespace beta "${HELM_ARGS[@]}" >"$SCRATCH/helm-default.yml"; then
    ok "Helm lint and default render"
  else
    bad "Helm lint/default render failed"
  fi
  if grep -q 'name: beta-api-ingress' "$SCRATCH/helm-default.yml" \
    && grep -q 'name: beta-console-ingress' "$SCRATCH/helm-default.yml" \
    && grep -q 'name: beta-console-api-egress' "$SCRATCH/helm-default.yml" \
    && grep -q 'name: beta-egress' "$SCRATCH/helm-default.yml" \
    && grep -A8 'name: CLEARANCE_TRUSTED_PROXY' "$SCRATCH/helm-default.yml" | grep -q 'value: "0"' \
    && grep -q 'image: "ghcr.io/example/clearance@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$SCRATCH/helm-default.yml"; then
    ok "Helm defaults to untrusted forwarded headers and renders split policies"
  else
    bad "Helm default proxy/network policy contract is missing"
  fi
  if helm template beta deploy/helm/clearance --namespace beta "${HELM_ARGS[@]}" \
    --set-string env.CLEARANCE_TRUSTED_PROXY=1 >"$SCRATCH/helm-trusted.yml" \
    && grep -A22 'name: beta-api-ingress' "$SCRATCH/helm-trusted.yml" \
      | grep -q 'app.kubernetes.io/component: console' \
    && grep -A30 'name: beta-console-api-egress' "$SCRATCH/helm-trusted.yml" \
      | grep -q 'app.kubernetes.io/component: api'; then
    ok "trusted-proxy render scopes console-to-API traffic to this release"
  else
    bad "trusted-proxy render lacks release-scoped console-to-API policy"
  fi
  if helm template beta deploy/helm/clearance --namespace beta "${HELM_ARGS[@]}" \
    --set-string env.CLEARANCE_TRUSTED_PROXY=1 \
    --set metrics.serviceMonitor.enabled=true \
    --set-string 'metrics.networkPolicy.namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=monitoring' \
    --set-string 'metrics.networkPolicy.podSelector.matchLabels.app\.kubernetes\.io/name=prometheus' \
    >"$SCRATCH/helm-trusted-metrics.yml" \
    && grep -A42 'name: beta-api-ingress' "$SCRATCH/helm-trusted-metrics.yml" \
      | grep -q 'kubernetes.io/metadata.name: monitoring' \
    && grep -A42 'name: beta-api-ingress' "$SCRATCH/helm-trusted-metrics.yml" \
      | grep -q 'app.kubernetes.io/name: prometheus'; then
    ok "trusted-proxy ServiceMonitor ingress is namespace-and-pod scoped"
  else
    bad "trusted-proxy ServiceMonitor ingress is missing its exact scraper selectors"
  fi
  set +e
  helm template beta deploy/helm/clearance --namespace beta "${HELM_ARGS[@]}" \
    --set-string env.CLEARANCE_TRUSTED_PROXY=1 \
    --set metrics.serviceMonitor.enabled=true \
    >"$SCRATCH/helm-trusted-metrics-unsafe.out" 2>"$SCRATCH/helm-trusted-metrics-unsafe.err"
  metrics_ec=$?
  set -e
  if [[ $metrics_ec -ne 0 ]] \
    && grep -q 'requires metrics.networkPolicy.namespaceSelector' "$SCRATCH/helm-trusted-metrics-unsafe.err"; then
    ok "trusted-proxy ServiceMonitor fails closed without scraper selectors"
  else
    bad "trusted-proxy ServiceMonitor accepted empty scraper selectors"
  fi
  set +e
  helm template beta deploy/helm/clearance "${HELM_ARGS[@]}" \
    --set-string env.CLEARANCE_TRUSTED_PROXY=1 \
    --set ingress.api.enabled=true \
    --set ingress.api.host=auth.example.test \
    --set ingress.api.tls.secretName=auth-tls \
    >"$SCRATCH/helm-unsafe.out" 2>"$SCRATCH/helm-unsafe.err"
  ec=$?
  set -e
  if [[ $ec -ne 0 ]] && grep -q 'requires ingress.api.enabled=false' "$SCRATCH/helm-unsafe.err"; then
    ok "trusted-proxy mode fails closed with direct API Ingress"
  else
    bad "trusted-proxy mode accepted direct API Ingress"
  fi
else
  bad "helm is unavailable; chart security contracts cannot be verified"
fi

# ---------- isolated Postgres backup/upgrade proof ----------
section "live isolated: backup + upgrade lifecycle"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  PG_PORT="$((54000 + RANDOM % 1000))"
  PG_PASS="$(openssl rand -hex 16)"
  PG_USER="clr_ops"
  PG_DB="clearance_active"
  PG_CID="$(docker run -d --rm \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_PASSWORD="$PG_PASS" \
    -e POSTGRES_DB="$PG_DB" \
    -p "127.0.0.1:${PG_PORT}:5432" \
    postgres:16-alpine)"
  export PG_CID
  if command -v psql >/dev/null 2>&1 && command -v pg_dump >/dev/null 2>&1; then
    export DATABASE_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}/${PG_DB}"
    PG_ADMIN_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}/postgres"
    ok "live proof uses host Postgres clients"
  else
    # The disposable database image includes matching clients. Shell functions
    # make the operational scripts use them when host clients are absent.
    psql() { docker exec -i "$PG_CID" psql "$@"; }
    pg_dump() {
      local out=""
      local -a args=()
      for arg in "$@"; do
        case "$arg" in
          --file=*) out="${arg#--file=}" ;;
          *) args+=("$arg") ;;
        esac
      done
      if [[ -n "$out" ]]; then
        docker exec -i "$PG_CID" pg_dump "${args[@]}" >"$out"
      else
        docker exec -i "$PG_CID" pg_dump "${args[@]}"
      fi
    }
    export -f psql pg_dump
    export DATABASE_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:5432/${PG_DB}"
    PG_ADMIN_URL="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:5432/postgres"
    ok "live proof uses disposable-container Postgres clients"
  fi
  # wait for ready
  for _ in $(seq 1 40); do
    if psql --no-psqlrc "$DATABASE_URL" -c 'SELECT 1' >/dev/null 2>&1; then break; fi
    sleep 0.5
  done
  psql --no-psqlrc "$DATABASE_URL" -c 'SELECT 1' >/dev/null || { bad "isolated postgres not ready"; }

  # Seed the real management release contract and representative runtime tables.
  psql --no-psqlrc "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE "user" (id text primary key, email text not null);
CREATE TABLE organization (id text primary key, name text not null);
CREATE TABLE session (id text primary key, user_id text);
CREATE TABLE clearance_management_snapshot (
  id integer PRIMARY KEY CHECK (id = 1),
  data jsonb NOT NULL,
  revision bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE "scimProvider" (
  id text primary key,
  "providerId" text not null unique,
  "scimToken" text not null unique,
  "organizationId" text,
  "userId" text
);
INSERT INTO "user" VALUES ('u1','ops@example.test'),('u2','it@example.test');
INSERT INTO organization VALUES ('o1','Acme');
INSERT INTO session VALUES ('s1','u1');
INSERT INTO clearance_management_snapshot(id, data) VALUES
  (1, '{"version":1,"releaseVersion":"0.1.2","meta":{"schemaVersion":1}}'::jsonb);
SQL
  ok "seeded isolated active database"

  BAK_DIR="$SCRATCH/backups"
  UPG_DIR="$SCRATCH/upgrades"
  mkdir -p "$BAK_DIR" "$UPG_DIR"
  chmod 700 "$BAK_DIR"
  export CLEARANCE_BACKUP_DIR="$BAK_DIR"
  export CLEARANCE_UPGRADE_DIR="$UPG_DIR"

  # Legacy SCIM cutover gate: count changes between confirmation and lock must
  # delete nothing, then exact confirmation revokes legacy rows only.
  psql --no-psqlrc "$DATABASE_URL" -c \
    "INSERT INTO \"scimProvider\" VALUES ('legacy-1','legacy-one','encrypted-a',NULL,'u1'),('scoped-1','scoped-one','encrypted-b','o1','u1')" >/dev/null
  set +e
  bash scripts/scim-legacy-preflight.sh >/dev/null 2>"$SCRATCH/scim-inventory.err"
  ec=$?
  set -e
  [[ $ec -ne 0 ]] && ok "legacy SCIM inventory fails closed" || bad "legacy SCIM inventory passed with a personal credential"

  export CLEARANCE_OPS_TESTING=1
  export CLEARANCE_SCIM_PREFLIGHT_TEST_DELAY_SECONDS=1
  set +e
  bash scripts/scim-legacy-preflight.sh --revoke \
    --confirm "REVOKE_LEGACY_SCIM:${PG_DB}:1" >"$SCRATCH/scim-race.out" 2>"$SCRATCH/scim-race.err" &
  SCIM_RACE_PID=$!
  sleep 0.25
  psql --no-psqlrc "$DATABASE_URL" -c \
    "INSERT INTO \"scimProvider\" VALUES ('legacy-2','legacy-two','encrypted-c','',NULL)" >/dev/null
  wait "$SCIM_RACE_PID"
  ec=$?
  set -e
  unset CLEARANCE_SCIM_PREFLIGHT_TEST_DELAY_SECONDS
  SCIM_AFTER_RACE="$(psql --no-psqlrc "$DATABASE_URL" -At -c "SELECT count(*) FROM \"scimProvider\" WHERE \"organizationId\" IS NULL OR btrim(\"organizationId\") = ''")"
  [[ $ec -ne 0 && "$SCIM_AFTER_RACE" == "2" ]] \
    && ok "legacy SCIM revoke count race deletes nothing" \
    || bad "legacy SCIM race guard failed (exit=$ec remaining=$SCIM_AFTER_RACE)"

  bash scripts/scim-legacy-preflight.sh --revoke \
    --confirm "REVOKE_LEGACY_SCIM:${PG_DB}:2" --receipt-dir "$SCRATCH/security-receipts" >/dev/null \
    && ok "legacy SCIM exact-confirmation revoke" || bad "legacy SCIM revoke failed"
  SCIM_SCOPED_LEFT="$(psql --no-psqlrc "$DATABASE_URL" -At -c "SELECT count(*) FROM \"scimProvider\" WHERE \"organizationId\" = 'o1'")"
  SCIM_LEGACY_LEFT="$(psql --no-psqlrc "$DATABASE_URL" -At -c "SELECT count(*) FROM \"scimProvider\" WHERE \"organizationId\" IS NULL OR btrim(\"organizationId\") = ''")"
  [[ "$SCIM_SCOPED_LEFT" == "1" && "$SCIM_LEGACY_LEFT" == "0" ]] \
    && ok "SCIM revoke preserves organization-scoped provider and proves zero legacy" \
    || bad "SCIM cutover result inconsistent"

  SNAPSHOT_READY="$SCRATCH/backup-snapshot.ready"
  export CLEARANCE_BACKUP_TEST_SNAPSHOT_READY_FILE="$SNAPSHOT_READY"
  export CLEARANCE_BACKUP_TEST_DELAY_AFTER_SNAPSHOT_SECONDS=2
  bash scripts/backup-create.sh --dir "$BAK_DIR" >"$SCRATCH/backup-create.out" &
  BACKUP_CREATE_PID=$!
  for _ in $(seq 1 40); do
    [[ -f "$SNAPSHOT_READY" ]] && break
    sleep 0.1
  done
  if [[ -f "$SNAPSHOT_READY" ]]; then
    psql --no-psqlrc "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
      "INSERT INTO \"user\" VALUES ('u_after_snapshot','snapshot@example.test');" >/dev/null
  fi
  wait "$BACKUP_CREATE_PID"
  CREATE_OUT="$(cat "$SCRATCH/backup-create.out")"
  unset CLEARANCE_BACKUP_TEST_SNAPSHOT_READY_FILE CLEARANCE_BACKUP_TEST_DELAY_AFTER_SNAPSHOT_SECONDS
  BID="$(printf '%s\n' "$CREATE_OUT" | sed -n 's/^BACKUP_ID=//p' | tail -1)"
  [[ -n "$BID" && -f "$BAK_DIR/${BID}.sql" && -f "$BAK_DIR/${BID}.meta.json" && -f "$BAK_DIR/${BID}.verified.json" ]] \
    && ok "backup-create produced dump+meta+immutable evidence ($BID)" \
    || bad "backup-create failed"
  SNAPSHOT_META_USERS="$(node -e 'const j=require(process.argv[1]); process.stdout.write(String(j.resourceCounts.user))' "$BAK_DIR/${BID}.meta.json")"
  SNAPSHOT_LIVE_USERS="$(psql --no-psqlrc "$DATABASE_URL" -At -c 'SELECT count(*) FROM "user"')"
  [[ -f "$SNAPSHOT_READY" && "$SNAPSHOT_META_USERS" == "2" && "$SNAPSHOT_LIVE_USERS" == "3" ]] \
    && ok "backup dump and evidence share one exported snapshot during concurrent writes" \
    || bad "backup snapshot evidence drifted (meta=$SNAPSHOT_META_USERS live=$SNAPSHOT_LIVE_USERS)"
  psql --no-psqlrc "$DATABASE_URL" -c "DELETE FROM \"user\" WHERE id='u_after_snapshot';" >/dev/null
  if node -e '
    const fs=require("fs");
    const paths=[[process.argv[1],0o700],[process.argv[2],0o600],[process.argv[3],0o600],[process.argv[4],0o400]];
    for (const [path, expected] of paths) {
      if ((fs.statSync(path).mode & 0o777) !== expected) process.exit(1);
    }
  ' "$BAK_DIR" "$BAK_DIR/${BID}.sql" "$BAK_DIR/${BID}.meta.json" "$BAK_DIR/${BID}.verified.json"; then
    ok "backup directory, artifacts, and read-only evidence are owner-only"
  else
    bad "backup permissions are not directory=0700 artifacts=0600"
  fi

  META_BEFORE="$(sha256_file "$BAK_DIR/${BID}.meta.json")"
  bash scripts/backup-verify.sh --id "$BID" --dir "$BAK_DIR" >/dev/null \
    && ok "backup-verify archive inspection" \
    || bad "backup-verify failed"
  META_AFTER="$(sha256_file "$BAK_DIR/${BID}.meta.json")"
  [[ "$META_BEFORE" == "$META_AFTER" ]] && ok "backup verification preserves immutable metadata evidence" \
    || bad "backup verification mutated metadata evidence"

  unset CLEARANCE_BACKUP_COPY_COMMAND CLEARANCE_BACKUP_ALLOW_LOCAL_ONLY || true
  export CLEARANCE_BACKUP_RESTORE_VERIFY=0
  set +e
  bash scripts/backup-scheduled.sh --dir "$BAK_DIR" >"$SCRATCH/scheduled-no-copy.out" 2>"$SCRATCH/scheduled-no-copy.err"
  ec=$?
  set -e
  [[ $ec -ne 0 ]] && ok "scheduled backup fails closed without off-host copy hook" \
    || bad "scheduled backup looked green without off-host copy"
  export CLEARANCE_BACKUP_ALLOW_LOCAL_ONLY=1
  bash scripts/backup-scheduled.sh --dir "$BAK_DIR" --retention-days 30 >/dev/null \
    && ok "scheduled backup local-only override is explicit" || bad "scheduled backup dev override failed"
  unset CLEARANCE_BACKUP_ALLOW_LOCAL_ONLY CLEARANCE_BACKUP_RESTORE_VERIFY

  # Active DB name must survive restore-verify
  bash scripts/backup-restore-verify.sh --id "$BID" --dir "$BAK_DIR" >"$SCRATCH/restore.txt" \
    && ok "backup-restore-verify isolated restore" \
    || bad "backup-restore-verify failed"

  TAMPER_META="$SCRATCH/tampered.meta.json"
  node -e '
    const fs=require("fs");
    const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
    j.resourceCounts.missing_expected_table=1;
    fs.writeFileSync(process.argv[2],JSON.stringify(j,null,2)+"\n");
  ' "$BAK_DIR/${BID}.meta.json" "$TAMPER_META"
  set +e
  bash scripts/backup-restore-verify.sh --dump "$BAK_DIR/${BID}.sql" --meta "$TAMPER_META" \
    >/dev/null 2>"$SCRATCH/tampered-restore.err"
  ec=$?
  set -e
  [[ $ec -ne 0 ]] && ok "restore verification rejects missing expected tables" \
    || bad "restore verification ignored a missing expected table"

  ACTIVE_STILL="$(psql --no-psqlrc "$DATABASE_URL" -At -c 'SELECT count(*) FROM "user"')"
  [[ "$ACTIVE_STILL" == "2" ]] && ok "active DB untouched after restore-verify (users=2)" \
    || bad "active DB corrupted (users=$ACTIVE_STILL)"

  # Temp DBs should be cleaned up
  TEMP_LEFT="$(psql --no-psqlrc "$PG_ADMIN_URL" -At \
    -c "SELECT count(*) FROM pg_database WHERE datname LIKE 'clr_rv_%'")"
  [[ "$TEMP_LEFT" == "0" ]] && ok "isolated restore cleaned up temp databases" \
    || bad "temp databases remain: $TEMP_LEFT"

  # Upgrade flow
  PLAN_OUT="$(bash scripts/upgrade-plan.sh --target 0.2.0 --current 0.1.2 --dir "$UPG_DIR")"
  PLAN_ID="$(printf '%s\n' "$PLAN_OUT" | sed -n 's/^PLAN_ID=//p' | tail -1)"
  [[ -n "$PLAN_ID" ]] && ok "upgrade-plan created $PLAN_ID" || bad "upgrade-plan failed"

  PLAN_PATH="$UPG_DIR/${PLAN_ID}.plan.json"
  cp "$PLAN_PATH" "$SCRATCH/original.plan.json"
  chmod u+w "$PLAN_PATH"
  node -e '
    const fs=require("fs"); const p=process.argv[1];
    const j=JSON.parse(fs.readFileSync(p,"utf8")); j.targetVersion="9.9.9";
    fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");
  ' "$PLAN_PATH"
  set +e
  bash scripts/upgrade-preflight.sh --plan "$PLAN_ID" --dir "$UPG_DIR" >/dev/null 2>&1
  ec=$?
  set -e
  [[ $ec -ne 0 ]] && ok "upgrade-preflight rejects a modified immutable plan" \
    || bad "upgrade-preflight accepted a modified immutable plan"
  cp "$SCRATCH/original.plan.json" "$PLAN_PATH"
  chmod a-w "$PLAN_PATH" 2>/dev/null || true

  # A matching attacker-written state checksum must not make a traversal
  # target executable at the shell boundary.
  MALICIOUS_ID="upg_20260713T000000Z_bad123"
  MALICIOUS_PLAN="$UPG_DIR/${MALICIOUS_ID}.plan.json"
  MALICIOUS_STATE="$UPG_DIR/${MALICIOUS_ID}.state.json"
  node -e '
    const fs=require("fs");
    const plan={
      planId:process.argv[1], immutable:true, currentVersion:"0.1.2",
      targetVersion:"../../../../tmp/evil", sourceDatabase:""
    };
    fs.writeFileSync(process.argv[2],JSON.stringify(plan,null,2)+"\n");
  ' "$MALICIOUS_ID" "$MALICIOUS_PLAN"
  MALICIOUS_SHA="$(sha256_file "$MALICIOUS_PLAN")"
  node -e '
    const fs=require("fs");
    fs.writeFileSync(process.argv[2],JSON.stringify({
      planId:process.argv[1], planSha256:process.argv[3], status:"planned"
    },null,2)+"\n");
  ' "$MALICIOUS_ID" "$MALICIOUS_STATE" "$MALICIOUS_SHA"
  set +e
  bash scripts/upgrade-preflight.sh --plan "$MALICIOUS_ID" --dir "$UPG_DIR" \
    >"$SCRATCH/malicious-preflight.out" 2>"$SCRATCH/malicious-preflight.err"
  malicious_preflight_ec=$?
  bash scripts/upgrade-apply.sh --plan "$MALICIOUS_ID" --dir "$UPG_DIR" --backup-dir "$BAK_DIR" \
    >"$SCRATCH/malicious-apply.out" 2>"$SCRATCH/malicious-apply.err"
  malicious_apply_ec=$?
  set -e
  if [[ "$malicious_preflight_ec" -ne 0 && "$malicious_apply_ec" -ne 0 ]] \
    && grep -q "target version is not a safe release version" "$SCRATCH/malicious-preflight.err" \
    && grep -q "target version is not a safe release version" "$SCRATCH/malicious-apply.err"; then
    ok "upgrade shell boundaries reject traversal versions despite a matching state checksum"
  else
    bad "upgrade shell boundary accepted or mishandled a traversal version"
  fi

  bash scripts/upgrade-preflight.sh --plan "$PLAN_ID" --dir "$UPG_DIR" >/dev/null \
    && ok "upgrade-preflight" || bad "upgrade-preflight failed"

  # A target without a shipped hook still fails closed after preserving a
  # verified rollback reference.
  NO_HOOK_PLAN_OUT="$(bash scripts/upgrade-plan.sh --target 0.2.1 --current 0.1.2 --dir "$UPG_DIR")"
  NO_HOOK_PLAN_ID="$(printf '%s\n' "$NO_HOOK_PLAN_OUT" | sed -n 's/^PLAN_ID=//p' | tail -1)"
  [[ -n "$NO_HOOK_PLAN_ID" ]] && ok "upgrade-plan created an unshipped-target plan" \
    || bad "upgrade-plan failed for unshipped target"
  bash scripts/upgrade-preflight.sh --plan "$NO_HOOK_PLAN_ID" --dir "$UPG_DIR" >/dev/null \
    && ok "upgrade-preflight for unshipped target" || bad "upgrade-preflight failed for unshipped target"

  set +e
  bash scripts/upgrade-apply.sh --plan "$NO_HOOK_PLAN_ID" --dir "$UPG_DIR" --backup-dir "$BAK_DIR" \
    >"$SCRATCH/apply-no-hook.out" 2>"$SCRATCH/apply-no-hook.err"
  ec=$?
  set -e
  [[ $ec -ne 0 ]] && ok "upgrade-apply refuses missing version hook" \
    || bad "upgrade-apply recorded a no-op version transition"

  STATE="$UPG_DIR/${NO_HOOK_PLAN_ID}.state.json"
  if node -e '
    const j=require(process.argv[1]);
    if(j.status!=="backup_verified") process.exit(1);
    if(!j.rollbackReference?.backupId || !j.backupDump || !j.backupMeta) process.exit(2);
  ' "$STATE"; then
    ok "failed apply retains verified immutable rollback reference"
  else
    bad "failed apply did not retain its verified rollback reference"
  fi

  ACTIVE_STILL2="$(psql --no-psqlrc "$DATABASE_URL" -At -c 'SELECT count(*) FROM "user"')"
  [[ "$ACTIVE_STILL2" == "2" ]] && ok "active DB untouched after refused upgrade" \
    || bad "active DB changed during refused upgrade"

  # Exercise the real shipped 0.1.2 -> 0.2.0 hook from deploy/upgrades.
  bash scripts/upgrade-apply.sh --plan "$PLAN_ID" --dir "$UPG_DIR" --backup-dir "$BAK_DIR" \
    >/dev/null 2>"$SCRATCH/apply-success.err" \
    && ok "upgrade-apply executes the shipped 0.1.2 to 0.2.0 hook" \
    || bad "upgrade-apply failed with the shipped 0.1.2 to 0.2.0 hook"

  RELEASE_AFTER="$(application_release_version "$DATABASE_URL")"
  LEDGER_AFTER="$(psql --no-psqlrc "$DATABASE_URL" -At -c "SELECT plan_id FROM clearance_schema_migrations WHERE version='0.2.0'")"
  [[ "$RELEASE_AFTER" == "0.2.0" && "$LEDGER_AFTER" == "$PLAN_ID" ]] \
    && ok "version hook advanced the real application contract and migration ledger" \
    || bad "application release contract/ledger transition failed"

  bash scripts/upgrade-verify.sh --plan "$PLAN_ID" --dir "$UPG_DIR" >/dev/null \
    && ok "upgrade-verify accepts the applied release" \
    || bad "upgrade-verify rejected the applied release"

  if [[ -f packages/clearance-cli/dist/index.js ]]; then
    if node packages/clearance-cli/dist/index.js --local-direct --json --yes upgrade rollback \
      --plan "$PLAN_ID" --dir "$UPG_DIR" >"$SCRATCH/rollback-cli.json"; then
      if node -e '
        const j=require(process.argv[1]);
        if(j.operation!=="upgrade.rollback" || j.mode!=="isolated_verify_only" || j.activeDatabaseUntouched!==true || !j.rollbackReceipt) process.exit(1);
      ' "$SCRATCH/rollback-cli.json"; then
        ok "CLI upgrade rollback verifies the reference in isolation"
      else
        bad "CLI upgrade rollback returned inconsistent evidence"
      fi
    else
      bad "CLI upgrade rollback reference verification failed"
    fi
  else
    bash scripts/upgrade-rollback.sh --plan "$PLAN_ID" --dir "$UPG_DIR" >/dev/null \
      && ok "upgrade rollback reference restores and verifies in isolation" \
      || bad "upgrade rollback reference verification failed"
  fi

  ROLLBACK_RECEIPT="$UPG_DIR/rollbacks/${PLAN_ID}.rollback-drill.json"
  if [[ -f "$ROLLBACK_RECEIPT" ]] && node -e '
    const j=require(process.argv[1]);
    if(j.mode!=="isolated_verify_only" || j.activeDatabaseUntouched!==true || !j.backupId) process.exit(1);
  ' "$ROLLBACK_RECEIPT"; then
    ok "rollback receipt records deterministic isolated recovery evidence"
  else
    bad "rollback receipt is missing or inconsistent"
  fi

  RELEASE_AFTER_DRILL="$(application_release_version "$DATABASE_URL")"
  [[ "$RELEASE_AFTER_DRILL" == "0.2.0" ]] && ok "rollback drill leaves the active database untouched" \
    || bad "rollback drill unexpectedly changed the active database"

  ACTIVE_OID_BEFORE="$(psql --no-psqlrc "$PG_ADMIN_URL" -At -c "SELECT oid FROM pg_database WHERE datname='${PG_DB}'")"
  CONFIRM="RESTORE_ACTIVE:${PLAN_ID}:${PG_DB}"
  export CLEARANCE_ROLLBACK_TEST_FAIL_INITIAL_RENAME=1
  set +e
  bash scripts/upgrade-rollback.sh --plan "$PLAN_ID" --dir "$UPG_DIR" --backup-dir "$BAK_DIR" \
    --restore-active --confirm "$CONFIRM" >"$SCRATCH/initial-rename-failure.out" 2>"$SCRATCH/initial-rename-failure.err"
  INITIAL_RENAME_EC=$?
  set -e
  unset CLEARANCE_ROLLBACK_TEST_FAIL_INITIAL_RENAME
  INITIAL_RENAME_OID="$(psql --no-psqlrc "$PG_ADMIN_URL" -At -c "SELECT oid FROM pg_database WHERE datname='${PG_DB}'")"
  INITIAL_RENAME_ALLOW="$(psql --no-psqlrc "$PG_ADMIN_URL" -At -c "SELECT datallowconn::text FROM pg_database WHERE datname='${PG_DB}'")"
  STATE="$UPG_DIR/${PLAN_ID}.state.json"
  if [[ "$INITIAL_RENAME_EC" -ne 0 && "$INITIAL_RENAME_OID" == "$ACTIVE_OID_BEFORE" && "$INITIAL_RENAME_ALLOW" == "true" ]] \
    && node -e 'const j=require(process.argv[1]); if(j.status!=="rollback_failed"||j.rollbackFailure?.event!=="active_database_drain_or_rename_failed"||j.rollbackFailure?.recovered!==true) process.exit(1)' "$STATE"; then
    ok "initial drain/rename failure restores connections and writes a recovered failure journal"
  else
    bad "initial drain/rename failure did not recover and journal fail-closed state"
  fi
  node -e '
    const fs=require("fs"), p=process.argv[1];
    const j=JSON.parse(fs.readFileSync(p,"utf8"));
    j.status="verified";
    delete j.rollbackFailure;
    fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");
  ' "$STATE"
  SAFETY_READY="$SCRATCH/rollback-safety.ready"
  export CLEARANCE_ROLLBACK_TEST_AFTER_SAFETY_READY_FILE="$SAFETY_READY"
  export CLEARANCE_ROLLBACK_TEST_DELAY_AFTER_SAFETY_SECONDS=2
  bash scripts/upgrade-rollback.sh --plan "$PLAN_ID" --dir "$UPG_DIR" --backup-dir "$BAK_DIR" \
    --restore-active --confirm "$CONFIRM" >"$SCRATCH/active-rollback.out" &
  ACTIVE_ROLLBACK_PID=$!
  for _ in $(seq 1 300); do
    [[ -f "$SAFETY_READY" ]] && break
    sleep 0.1
  done
  if [[ -f "$SAFETY_READY" ]]; then
    psql --no-psqlrc "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
      "INSERT INTO \"user\" VALUES ('u_after_safety','safety@example.test');" >/dev/null
  fi
  set +e
  wait "$ACTIVE_ROLLBACK_PID"
  ACTIVE_ROLLBACK_EC=$?
  set -e
  unset CLEARANCE_ROLLBACK_TEST_AFTER_SAFETY_READY_FILE CLEARANCE_ROLLBACK_TEST_DELAY_AFTER_SAFETY_SECONDS
  [[ "$ACTIVE_ROLLBACK_EC" -eq 0 ]] \
    && ok "active rollback executes guarded database swap" || bad "active rollback failed"
  ACTIVE_OID_AFTER="$(psql --no-psqlrc "$PG_ADMIN_URL" -At -c "SELECT oid FROM pg_database WHERE datname='${PG_DB}'")"
  RELEASE_ROLLED_BACK="$(application_release_version "$DATABASE_URL")"
  ACTIVE_RECEIPT="$UPG_DIR/rollbacks/${PLAN_ID}.rollback.json"
  PRESERVED_DB="$(node -e 'const j=require(process.argv[1]); process.stdout.write(j.preservedPreRollbackDatabase||"")' "$ACTIVE_RECEIPT")"
  psql --no-psqlrc "$PG_ADMIN_URL" -v ON_ERROR_STOP=1 -c \
    "ALTER DATABASE \"${PRESERVED_DB}\" WITH ALLOW_CONNECTIONS true;" >/dev/null
  PRESERVED_URL="$(url_with_db "$DATABASE_URL" "$PRESERVED_DB")"
  PRESERVED_POST_SAFETY="$(psql --no-psqlrc "$PRESERVED_URL" -At -c "SELECT count(*) FROM \"user\" WHERE id='u_after_safety'")"
  psql --no-psqlrc "$PG_ADMIN_URL" -v ON_ERROR_STOP=1 -c \
    "ALTER DATABASE \"${PRESERVED_DB}\" WITH ALLOW_CONNECTIONS false;" >/dev/null
  if [[ "$ACTIVE_OID_BEFORE" != "$ACTIVE_OID_AFTER" && "$RELEASE_ROLLED_BACK" == "0.1.2" && "$PRESERVED_POST_SAFETY" == "1" ]] \
    && node -e 'const j=require(process.argv[1]); if(j.mode!=="active_database_restore"||!j.postRestoreVerified||!j.preRestoreSafetyBackupId||!j.postSafetyWritesPreserved||!j.preservedPreRollbackDatabase) process.exit(1)' "$ACTIVE_RECEIPT"; then
    ok "active rollback proves new database identity, restored version, safety backup, and receipt"
    ok "active rollback preserves writes committed after the safety backup in the drained old database"
  else
    bad "active rollback evidence is incomplete"
  fi

  # Upgrade again, inject a post-swap verification failure, and prove the old
  # database is reinstated with the target version and original oid.
  FAIL_PLAN_OUT="$(bash scripts/upgrade-plan.sh --target 0.2.0 --current 0.1.2 --dir "$UPG_DIR")"
  FAIL_PLAN_ID="$(printf '%s\n' "$FAIL_PLAN_OUT" | sed -n 's/^PLAN_ID=//p' | tail -1)"
  bash scripts/upgrade-apply.sh --plan "$FAIL_PLAN_ID" --dir "$UPG_DIR" --backup-dir "$BAK_DIR" >/dev/null
  OID_BEFORE_FAILED_SWAP="$(psql --no-psqlrc "$PG_ADMIN_URL" -At -c "SELECT oid FROM pg_database WHERE datname='${PG_DB}'")"
  export CLEARANCE_ROLLBACK_TEST_FAIL_AFTER_SWAP=1
  set +e
  bash scripts/upgrade-rollback.sh --plan "$FAIL_PLAN_ID" --dir "$UPG_DIR" --backup-dir "$BAK_DIR" \
    --restore-active --confirm "RESTORE_ACTIVE:${FAIL_PLAN_ID}:${PG_DB}" \
    >"$SCRATCH/failed-swap.out" 2>"$SCRATCH/failed-swap.err"
  ec=$?
  set -e
  unset CLEARANCE_ROLLBACK_TEST_FAIL_AFTER_SWAP CLEARANCE_OPS_TESTING
  OID_AFTER_FAILED_SWAP="$(psql --no-psqlrc "$PG_ADMIN_URL" -At -c "SELECT oid FROM pg_database WHERE datname='${PG_DB}'")"
  VERSION_AFTER_FAILED_SWAP="$(application_release_version "$DATABASE_URL")"
  [[ $ec -ne 0 && "$OID_AFTER_FAILED_SWAP" == "$OID_BEFORE_FAILED_SWAP" && "$VERSION_AFTER_FAILED_SWAP" == "0.2.0" ]] \
    && ok "failed post-swap verification reverses to the original active database" \
    || bad "failed-swap reversal did not preserve the original target database"
  FAIL_STATE="$UPG_DIR/${FAIL_PLAN_ID}.state.json"
  if node -e 'const j=require(process.argv[1]); if(j.status!=="rollback_failed"||j.rollbackFailure?.recovered!==true) process.exit(1)' "$FAIL_STATE"; then
    ok "verified rollback reversal writes a recovered failure journal"
  else
    bad "verified rollback reversal omitted its failure journal"
  fi

  # Re-arm the same immutable applied plan in this disposable test environment,
  # inject reversal failure, and prove the script preserves every catalog
  # artifact instead of deleting staging or claiming recovery.
  node -e '
    const fs=require("fs"), p=process.argv[1];
    const j=JSON.parse(fs.readFileSync(p,"utf8"));
    j.status="applied";
    delete j.rollbackFailure;
    fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");
  ' "$FAIL_STATE"
  export CLEARANCE_OPS_TESTING=1
  export CLEARANCE_ROLLBACK_TEST_FAIL_AFTER_SWAP=1
  export CLEARANCE_ROLLBACK_TEST_FAIL_REVERSAL=1
  set +e
  bash scripts/upgrade-rollback.sh --plan "$FAIL_PLAN_ID" --dir "$UPG_DIR" --backup-dir "$BAK_DIR" \
    --restore-active --confirm "RESTORE_ACTIVE:${FAIL_PLAN_ID}:${PG_DB}" \
    >"$SCRATCH/failed-reversal.out" 2>"$SCRATCH/failed-reversal.err"
  reversal_ec=$?
  set -e
  unset CLEARANCE_ROLLBACK_TEST_FAIL_AFTER_SWAP CLEARANCE_ROLLBACK_TEST_FAIL_REVERSAL CLEARANCE_OPS_TESTING
  FAILURE_NAMES="$(node -e '
    const j=require(process.argv[1]), d=j.rollbackFailure?.databases||{};
    process.stdout.write([d.active||"",d.preRollback||"",d.failedRestore||""].join("|"));
  ' "$FAIL_STATE")"
  IFS='|' read -r FAILURE_ACTIVE FAILURE_OLD FAILURE_RESTORE <<<"$FAILURE_NAMES"
  FAILURE_CATALOG="$(psql --no-psqlrc "$PG_ADMIN_URL" -At -c "SELECT datname FROM pg_database WHERE datname IN ('${FAILURE_ACTIVE}','${FAILURE_OLD}','${FAILURE_RESTORE}') ORDER BY datname;")"
  FAILURE_CATALOG_COUNT="$(printf '%s\n' "$FAILURE_CATALOG" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$reversal_ec" -ne 0 && "$FAILURE_CATALOG_COUNT" == "2" ]] \
    && ! printf '%s\n' "$FAILURE_CATALOG" | grep -qx "$FAILURE_ACTIVE" \
    && printf '%s\n' "$FAILURE_CATALOG" | grep -qx "$FAILURE_OLD" \
    && printf '%s\n' "$FAILURE_CATALOG" | grep -qx "$FAILURE_RESTORE" \
    && node -e 'const j=require(process.argv[1]); if(j.status!=="rollback_failed"||j.rollbackFailure?.recovered!==false) process.exit(1)' "$FAIL_STATE"; then
    ok "unverified reversal journals rollback_failed and preserves both recovery databases"
  else
    bad "ambiguous reversal did not fail closed with preserved catalog evidence"
  fi
else
  bad "docker is unavailable; live backup and upgrade proof cannot run"
fi

# ---------- summary ----------
section "summary"
printf 'results: PASS=%s FAIL=%s SKIP=%s\n' "$PASS" "$FAIL" "$SKIP"
printf 'note: static/behavioral checks prove ops script contracts only; they do not prove production readiness.\n'
if [[ "$FAIL" -ne 0 ]]; then
  printf 'VERIFY_PRODUCTION_OPS_FAILED\n' >&2
  exit 1
fi
printf 'VERIFY_PRODUCTION_OPS_OK\n'
exit 0
