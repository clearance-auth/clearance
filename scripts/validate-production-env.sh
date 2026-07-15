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
  CLEARANCE_DELIVERY_KEY_ID
  CLEARANCE_DELIVERY_KEYS_JSON
  CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID
  CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON
  CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY
  CLEARANCE_EMAIL_TRANSPORT       # smtp or ses
  CLEARANCE_EMAIL_FROM
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
  CLEARANCE_DELIVERY_HEALTH_PUBLISHED_PORT
  CLEARANCE_PG_VOLUME
  CLEARANCE_BACKUP_VOLUME
  CLEARANCE_IMAGE_REPOSITORY
  CLEARANCE_IMAGE_DIGEST          # immutable sha256:...; signature is a release gate
  CLEARANCE_BACKUP_IMAGE_REPOSITORY
  CLEARANCE_BACKUP_IMAGE_DIGEST   # immutable sha256:...; signature is a release gate

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

check_integer_range() {
  local label="$1" value="$2" minimum="$3" maximum="$4"
  if [[ ! "$value" =~ ^[0-9]+$ ]] || (( 10#$value < minimum || 10#$value > maximum )); then
    fail "$label must be an integer from $minimum through $maximum"
  else
    note "$label is within its supported range"
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
check_present CLEARANCE_DELIVERY_KEY_ID "${CLEARANCE_DELIVERY_KEY_ID-}"
check_present CLEARANCE_DELIVERY_KEYS_JSON "${CLEARANCE_DELIVERY_KEYS_JSON-}"
check_present CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID "${CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID-}"
check_present CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON "${CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON-}"
check_present CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY "${CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY-}"
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
check_port CLEARANCE_DELIVERY_HEALTH_PUBLISHED_PORT "${CLEARANCE_DELIVERY_HEALTH_PUBLISHED_PORT-}"
check_present CLEARANCE_PG_VOLUME "${CLEARANCE_PG_VOLUME-}"
check_present CLEARANCE_BACKUP_VOLUME "${CLEARANCE_BACKUP_VOLUME-}"
check_present CLEARANCE_IMAGE_REPOSITORY "${CLEARANCE_IMAGE_REPOSITORY-}"
check_present CLEARANCE_BACKUP_IMAGE_REPOSITORY "${CLEARANCE_BACKUP_IMAGE_REPOSITORY-}"

# Delivery keys are three purpose-separated 32-byte authorities. Validate the
# complete ring without printing ids, JSON, or decoded material.
if node -e '
  const decode=(raw)=>{
    if(typeof raw!=="string") throw new Error();
    const v=raw.trim();
    let b;
    if(/^[0-9a-fA-F]{64}$/.test(v)) b=Buffer.from(v,"hex");
    else if(/^[A-Za-z0-9+/_-]+={0,2}$/.test(v)) b=Buffer.from(v.replace(/-/g,"+").replace(/_/g,"/"),"base64");
    else throw new Error();
    if(b.length!==32) throw new Error();
    return b.toString("hex");
  };
  const id=/^[A-Za-z0-9._-]{1,64}$/;
  const current=process.env.CLEARANCE_DELIVERY_KEY_ID||"";
  const fingerprint=process.env.CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID||"";
  const legacyFingerprint=(process.env.CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID||"").trim();
  if(!id.test(current)||!id.test(fingerprint)) throw new Error();
  if(legacyFingerprint&&!id.test(legacyFingerprint)) throw new Error();
  const keys=JSON.parse(process.env.CLEARANCE_DELIVERY_KEYS_JSON||"");
  const fingerprints=JSON.parse(process.env.CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON||"");
  if(!keys||Array.isArray(keys)||typeof keys!=="object"||!fingerprints||Array.isArray(fingerprints)||typeof fingerprints!=="object") throw new Error();
  const decoded=[...Object.entries(keys),...Object.entries(fingerprints)].map(([keyId,value])=>{
    if(!id.test(keyId)) throw new Error();
    return decode(value);
  });
  if(!Object.hasOwn(keys,current)||!Object.hasOwn(fingerprints,fingerprint)) throw new Error();
  if(legacyFingerprint&&!Object.hasOwn(fingerprints,legacyFingerprint)) throw new Error();
  decoded.push(decode(process.env.CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY||""));
  if(new Set(decoded).size!==decoded.length) throw new Error();
' 2>/dev/null; then
  note "delivery keyring and optional legacy fingerprint key id are valid"
else
  fail "delivery keyring must contain distinct 32-byte purpose keys and every configured fingerprint key id"
fi

if [[ "${CLEARANCE_DELIVERY_SCHEMA-}" =~ ^[A-Za-z_][A-Za-z0-9_]{0,62}$ ]]; then
  note "CLEARANCE_DELIVERY_SCHEMA is a valid Postgres identifier"
else
  fail "CLEARANCE_DELIVERY_SCHEMA must be a valid Postgres identifier"
fi
if [[ "${CLEARANCE_DELIVERY_PREFIX-}" =~ ^[A-Za-z_][A-Za-z0-9_]{0,39}$ ]]; then
  note "CLEARANCE_DELIVERY_PREFIX is a bounded Postgres identifier prefix"
else
  fail "CLEARANCE_DELIVERY_PREFIX must be a valid identifier no longer than 40 characters"
fi
check_integer_range CLEARANCE_DELIVERY_QUOTA_MAX_ACTIVE "${CLEARANCE_DELIVERY_QUOTA_MAX_ACTIVE-}" 1 10000000
check_integer_range CLEARANCE_DELIVERY_QUOTA_MAX_BACKLOG "${CLEARANCE_DELIVERY_QUOTA_MAX_BACKLOG-}" 1 10000000
check_integer_range CLEARANCE_DELIVERY_QUOTA_MAX_ENQUEUES_PER_WINDOW "${CLEARANCE_DELIVERY_QUOTA_MAX_ENQUEUES_PER_WINDOW-}" 1 10000000
check_integer_range CLEARANCE_DELIVERY_QUOTA_WINDOW_MS "${CLEARANCE_DELIVERY_QUOTA_WINDOW_MS-}" 1000 86400000
check_integer_range CLEARANCE_DELIVERY_CONCURRENCY "${CLEARANCE_DELIVERY_CONCURRENCY-}" 1 64
check_integer_range CLEARANCE_DELIVERY_POLL_MS "${CLEARANCE_DELIVERY_POLL_MS-}" 25 60000
check_integer_range CLEARANCE_DELIVERY_LEASE_MS "${CLEARANCE_DELIVERY_LEASE_MS-}" 5000 600000
check_integer_range CLEARANCE_DELIVERY_HEARTBEAT_MS "${CLEARANCE_DELIVERY_HEARTBEAT_MS-}" 1000 60000
check_integer_range CLEARANCE_DELIVERY_MAINTENANCE_MS "${CLEARANCE_DELIVERY_MAINTENANCE_MS-}" 1000 300000
check_integer_range CLEARANCE_DELIVERY_DRAIN_TIMEOUT_MS "${CLEARANCE_DELIVERY_DRAIN_TIMEOUT_MS-}" 1000 300000
check_integer_range CLEARANCE_DELIVERY_MAX_BODY_BYTES "${CLEARANCE_DELIVERY_MAX_BODY_BYTES-}" 1024 10485760
check_present CLEARANCE_DELIVERY_APP_NAME "${CLEARANCE_DELIVERY_APP_NAME-}"
check_integer_range CLEARANCE_WEBHOOK_DNS_TIMEOUT_MS "${CLEARANCE_WEBHOOK_DNS_TIMEOUT_MS-}" 250 60000
check_integer_range CLEARANCE_WEBHOOK_CONNECT_TIMEOUT_MS "${CLEARANCE_WEBHOOK_CONNECT_TIMEOUT_MS-}" 250 60000
check_integer_range CLEARANCE_WEBHOOK_RESPONSE_TIMEOUT_MS "${CLEARANCE_WEBHOOK_RESPONSE_TIMEOUT_MS-}" 250 120000
check_integer_range CLEARANCE_WEBHOOK_MAX_RESPONSE_BYTES "${CLEARANCE_WEBHOOK_MAX_RESPONSE_BYTES-}" 0 1048576

if [[ "${CLEARANCE_EMAIL_FROM-}" =~ ^[^[:space:]@\<\>]+@[^[:space:]@\<\>]+$ ]]; then
  note "CLEARANCE_EMAIL_FROM is a single mailbox"
else
  fail "CLEARANCE_EMAIL_FROM must be a single mailbox"
fi
case "${CLEARANCE_EMAIL_TRANSPORT-}" in
  smtp)
    check_present CLEARANCE_SMTP_HOST "${CLEARANCE_SMTP_HOST-}"
    check_port CLEARANCE_SMTP_PORT "${CLEARANCE_SMTP_PORT-}"
    if [[ "${CLEARANCE_SMTP_SECURE-}" != "true" && "${CLEARANCE_SMTP_SECURE-}" != "false" ]]; then fail "CLEARANCE_SMTP_SECURE must be true or false"; fi
    if [[ "${CLEARANCE_SMTP_REQUIRE_TLS-}" != "true" && "${CLEARANCE_SMTP_REQUIRE_TLS-}" != "false" ]]; then fail "CLEARANCE_SMTP_REQUIRE_TLS must be true or false"; fi
    if [[ "${CLEARANCE_SMTP_SECURE-}" != "true" && "${CLEARANCE_SMTP_REQUIRE_TLS-}" != "true" ]]; then fail "production SMTP must use implicit TLS or require STARTTLS"; fi
    if [[ -n "${CLEARANCE_SMTP_USER-}" || -n "${CLEARANCE_SMTP_PASSWORD-}" ]]; then
      check_present CLEARANCE_SMTP_USER "${CLEARANCE_SMTP_USER-}"
      check_secret CLEARANCE_SMTP_PASSWORD "${CLEARANCE_SMTP_PASSWORD-}"
    else
      note "SMTP authentication is intentionally disabled"
    fi
    check_integer_range CLEARANCE_SMTP_CONNECTION_TIMEOUT_MS "${CLEARANCE_SMTP_CONNECTION_TIMEOUT_MS-}" 1000 120000
    check_integer_range CLEARANCE_SMTP_SOCKET_TIMEOUT_MS "${CLEARANCE_SMTP_SOCKET_TIMEOUT_MS-}" 1000 300000
    check_integer_range CLEARANCE_SMTP_GREETING_TIMEOUT_MS "${CLEARANCE_SMTP_GREETING_TIMEOUT_MS-}" 1000 120000
    ;;
  ses)
    ses_secret="${CLEARANCE_SES_SECRET_ACCESS_KEY-}"
    ses_session="${CLEARANCE_SES_SESSION_TOKEN-}"
    if [[ "${CLEARANCE_SES_REGION-}" =~ ^[a-z]{2}(-gov)?-[a-z0-9-]{2,24}-[1-9]$ ]]; then note "CLEARANCE_SES_REGION is valid"; else fail "CLEARANCE_SES_REGION is invalid"; fi
    if [[ "${CLEARANCE_SES_ACCESS_KEY_ID-}" =~ ^[A-Za-z0-9]{16,128}$ ]]; then note "CLEARANCE_SES_ACCESS_KEY_ID is valid"; else fail "CLEARANCE_SES_ACCESS_KEY_ID is invalid"; fi
    if (( ${#ses_secret} >= 20 && ${#ses_secret} <= 256 )); then note "CLEARANCE_SES_SECRET_ACCESS_KEY has a supported length"; else fail "CLEARANCE_SES_SECRET_ACCESS_KEY must contain 20 through 256 characters"; fi
    if [[ -n "$ses_session" ]]; then
      if (( ${#ses_session} >= 16 && ${#ses_session} <= 8192 )); then note "CLEARANCE_SES_SESSION_TOKEN has a supported length"; else fail "CLEARANCE_SES_SESSION_TOKEN must contain 16 through 8192 characters"; fi
    fi
    check_integer_range CLEARANCE_SES_REQUEST_TIMEOUT_MS "${CLEARANCE_SES_REQUEST_TIMEOUT_MS-}" 1000 120000
    ;;
  *) fail "CLEARANCE_EMAIL_TRANSPORT must be smtp or ses" ;;
esac
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
