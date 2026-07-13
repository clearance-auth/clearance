#!/usr/bin/env bash
# Fail-closed production environment validation for Compose/Helm/TF operators.
# Does not print secret values. Exits non-zero on any missing/weak/default secret.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=lib/ops-common.sh
source "$ROOT/scripts/lib/ops-common.sh"
require_cmd node

usage() {
  cat <<'EOF'
Usage: validate-production-env.sh

Validates operator-supplied environment for production Compose overlay:
  deploy/compose/docker-compose.production.yml

Required (strong secrets, no defaults):
  CLEARANCE_OPERATOR_TOKEN
  CLEARANCE_SECRET
  CLEARANCE_CREDENTIAL_KEY
  CLEARANCE_CREDENTIAL_KEY_ID
  CLEARANCE_CONSOLE_ADMIN_USER
  CLEARANCE_CONSOLE_ADMIN_PASSWORD
  CLEARANCE_CONSOLE_SESSION_SECRET
  CLEARANCE_DB_USER
  CLEARANCE_DB_PASSWORD
  CLEARANCE_DB_NAME
  DATABASE_URL          # full postgres URL; no compose password interpolation
  CLEARANCE_BASE_URL
  CLEARANCE_CONSOLE_URL
  CLEARANCE_CORS_ORIGINS
  CLEARANCE_API_PORT
  CLEARANCE_CONSOLE_PORT
  CLEARANCE_SAMPLE_PORT
  CLEARANCE_PG_VOLUME
  CLEARANCE_BACKUP_VOLUME
  CLEARANCE_IMAGE_REPOSITORY
  CLEARANCE_IMAGE_DIGEST          # sha256:... from the signed release
  CLEARANCE_BACKUP_IMAGE_REPOSITORY
  CLEARANCE_BACKUP_IMAGE_DIGEST   # sha256:... from the signed release

Optional:
  CLEARANCE_POSTGRES_PORT  # only if intentionally publishing Postgres to the host
  CLEARANCE_GITHUB_CLIENT_ID + CLEARANCE_GITHUB_CLIENT_SECRET
  CLEARANCE_GOOGLE_CLIENT_ID + CLEARANCE_GOOGLE_CLIENT_SECRET

Fails closed on missing, empty, short, or known-weak values.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

errors=0
note() { printf 'ok: %s\n' "$*"; }
fail() { printf 'fail: %s\n' "$*" >&2; errors=$((errors + 1)); }

check_secret() {
  local label="$1"
  local value="${2-}"
  if is_forbidden_secret "$value"; then
    fail "$label is missing, empty, short (<16), or a known weak default"
  else
    note "$label present and not a known weak default (len=${#value})"
  fi
}

check_present() {
  local label="$1"
  local value="${2-}"
  if [[ -z "$value" ]]; then
    fail "$label is required and must be non-empty"
  else
    note "$label is set"
  fi
}

check_port() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( 10#$value < 1 || 10#$value > 65535 )); then
    fail "$label must be an integer from 1 through 65535"
  else
    note "$label is a valid TCP port"
  fi
}

check_https_url() {
  local label="$1"
  local value="$2"
  if [[ "$value" =~ ^https://[^[:space:]]+$ ]]; then
    note "$label uses HTTPS"
  elif [[ "${CLEARANCE_ALLOW_LOCALHOST_PRODUCTION:-}" == "1" \
    && "$value" =~ ^http://(localhost|127\.0\.0\.1)(:[0-9]+)?(/.*)?$ ]]; then
    note "$label uses explicitly allowed local HTTP"
  else
    fail "$label must be an absolute HTTPS URL (local HTTP requires CLEARANCE_ALLOW_LOCALHOST_PRODUCTION=1)"
  fi
}

# Secrets / credentials
check_secret CLEARANCE_OPERATOR_TOKEN "${CLEARANCE_OPERATOR_TOKEN-}"
check_secret CLEARANCE_SECRET "${CLEARANCE_SECRET-}"
check_secret CLEARANCE_CREDENTIAL_KEY "${CLEARANCE_CREDENTIAL_KEY-}"
check_present CLEARANCE_CREDENTIAL_KEY_ID "${CLEARANCE_CREDENTIAL_KEY_ID-}"
check_present CLEARANCE_CONSOLE_ADMIN_USER "${CLEARANCE_CONSOLE_ADMIN_USER-}"
check_secret CLEARANCE_CONSOLE_ADMIN_PASSWORD "${CLEARANCE_CONSOLE_ADMIN_PASSWORD-}"
check_secret CLEARANCE_CONSOLE_SESSION_SECRET "${CLEARANCE_CONSOLE_SESSION_SECRET-}"
check_secret CLEARANCE_DB_PASSWORD "${CLEARANCE_DB_PASSWORD-}"

# Non-secret required production knobs (no compose defaults in overlay)
check_present CLEARANCE_DB_USER "${CLEARANCE_DB_USER-}"
check_present CLEARANCE_DB_NAME "${CLEARANCE_DB_NAME-}"
check_present CLEARANCE_BASE_URL "${CLEARANCE_BASE_URL-}"
check_present CLEARANCE_CONSOLE_URL "${CLEARANCE_CONSOLE_URL-}"
check_present CLEARANCE_CORS_ORIGINS "${CLEARANCE_CORS_ORIGINS-}"
check_port CLEARANCE_API_PORT "${CLEARANCE_API_PORT-}"
check_port CLEARANCE_CONSOLE_PORT "${CLEARANCE_CONSOLE_PORT-}"
check_port CLEARANCE_SAMPLE_PORT "${CLEARANCE_SAMPLE_PORT-}"
check_present CLEARANCE_PG_VOLUME "${CLEARANCE_PG_VOLUME-}"
check_present CLEARANCE_BACKUP_VOLUME "${CLEARANCE_BACKUP_VOLUME-}"
check_present CLEARANCE_IMAGE_REPOSITORY "${CLEARANCE_IMAGE_REPOSITORY-}"
check_present CLEARANCE_BACKUP_IMAGE_REPOSITORY "${CLEARANCE_BACKUP_IMAGE_REPOSITORY-}"
if [[ "${CLEARANCE_IMAGE_DIGEST-}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  note "CLEARANCE_IMAGE_DIGEST is an immutable sha256 digest"
else
  fail "CLEARANCE_IMAGE_DIGEST must be sha256 followed by 64 lowercase hex characters"
fi
if [[ "${CLEARANCE_BACKUP_IMAGE_DIGEST-}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  note "CLEARANCE_BACKUP_IMAGE_DIGEST is an immutable sha256 digest"
else
  fail "CLEARANCE_BACKUP_IMAGE_DIGEST must be sha256 followed by 64 lowercase hex characters"
fi

check_optional_pair() {
  local provider="$1"
  local client_id="$2"
  local client_secret="$3"
  if [[ -n "$client_id" && -n "$client_secret" ]]; then
    check_secret "${provider} client secret" "$client_secret"
    note "${provider} social credentials are configured as a complete pair"
  elif [[ -n "$client_id" || -n "$client_secret" ]]; then
    fail "${provider} social credentials must set both client id and client secret"
  else
    note "${provider} social provider is disabled"
  fi
}

check_optional_pair GitHub "${CLEARANCE_GITHUB_CLIENT_ID-}" "${CLEARANCE_GITHUB_CLIENT_SECRET-}"
check_optional_pair Google "${CLEARANCE_GOOGLE_CLIENT_ID-}" "${CLEARANCE_GOOGLE_CLIENT_SECRET-}"

# DATABASE_URL: full string required — refuse weak defaults and incomplete forms.
if is_weak_database_url "${DATABASE_URL-}"; then
  fail "DATABASE_URL missing, not a postgres URL, or uses weak/default credentials (redacted=$(redact_url "${DATABASE_URL-}"))"
else
  note "DATABASE_URL looks like a non-default postgres URL (redacted=$(redact_url "$DATABASE_URL"))"
fi

# The database container credentials and application URL must describe the same
# user, password, and database. Compare via process environment; print no values.
if [[ -n "${DATABASE_URL-}" ]]; then
  if DATABASE_URL_CHECK="$DATABASE_URL" \
    EXPECT_DB_USER="${CLEARANCE_DB_USER-}" \
    EXPECT_DB_PASSWORD="${CLEARANCE_DB_PASSWORD-}" \
    EXPECT_DB_NAME="${CLEARANCE_DB_NAME-}" \
    node -e '
      const u=new URL(process.env.DATABASE_URL_CHECK);
      if(!/^postgres(ql)?:$/.test(u.protocol)) process.exit(1);
      if(decodeURIComponent(u.username)!==process.env.EXPECT_DB_USER) process.exit(2);
      if(decodeURIComponent(u.password)!==process.env.EXPECT_DB_PASSWORD) process.exit(3);
      if(decodeURIComponent(u.pathname.replace(/^\//,""))!==process.env.EXPECT_DB_NAME) process.exit(4);
    ' 2>/dev/null; then
    note "DATABASE_URL credentials and database match Compose Postgres settings"
  else
    fail "DATABASE_URL user/password/database must match CLEARANCE_DB_USER/CLEARANCE_DB_PASSWORD/CLEARANCE_DB_NAME"
  fi
fi

check_https_url CLEARANCE_BASE_URL "${CLEARANCE_BASE_URL-}"
check_https_url CLEARANCE_CONSOLE_URL "${CLEARANCE_CONSOLE_URL-}"
IFS=',' read -r -a cors_origins <<<"${CLEARANCE_CORS_ORIGINS-}"
for origin in "${cors_origins[@]}"; do
  check_https_url "CLEARANCE_CORS_ORIGINS entry" "${origin//[[:space:]]/}"
done

# Refuse localhost-only defaults that are fine for dev but not production profiles
if [[ "${CLEARANCE_BASE_URL-}" == *"localhost"* || "${CLEARANCE_BASE_URL-}" == *"127.0.0.1"* ]]; then
  if [[ "${CLEARANCE_ALLOW_LOCALHOST_PRODUCTION:-}" != "1" ]]; then
    fail "CLEARANCE_BASE_URL points at localhost; set CLEARANCE_ALLOW_LOCALHOST_PRODUCTION=1 only for intentional local prod-profile tests"
  else
    note "CLEARANCE_BASE_URL is localhost (explicitly allowed for local prod-profile tests)"
  fi
fi

# NODE_ENV must not be development when operators claim production
if [[ "${NODE_ENV-}" == "development" || "${CLEARANCE_NODE_ENV-}" == "development" ]]; then
  fail "NODE_ENV/CLEARANCE_NODE_ENV must not be 'development' for production validation"
else
  note "NODE_ENV is not development"
fi

# Compose production overlay must exist
overlay="$ROOT/deploy/compose/docker-compose.production.yml"
if [[ ! -f "$overlay" ]]; then
  fail "missing production overlay: deploy/compose/docker-compose.production.yml"
else
  # Static fail-closed markers in overlay
  if grep -qE 'CLEARANCE_SECRET:-\$\{|:-dev|:-secret|:-change-me|:-clearance\}' "$overlay"; then
    fail "production overlay appears to embed weak defaults"
  fi
  if grep -qE 'DATABASE_URL:-\$\{' "$overlay"; then
    fail "production overlay must not construct DATABASE_URL from password parts"
  fi
  if ! grep -q 'DATABASE_URL: \${DATABASE_URL:?' "$overlay"; then
    fail "production overlay must require DATABASE_URL with fail-closed \${DATABASE_URL:?...}"
  fi
  if ! grep -q 'NODE_ENV: production' "$overlay"; then
    fail "production overlay must force NODE_ENV: production"
  fi
  note "production overlay present with fail-closed DATABASE_URL and NODE_ENV"
fi

if [[ "$errors" -ne 0 ]]; then
  printf '\nvalidate-production-env: FAILED (%s checks)\n' "$errors" >&2
  exit 1
fi

printf '\nvalidate-production-env: OK\n'
exit 0
