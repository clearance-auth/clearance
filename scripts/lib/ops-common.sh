# Shared helpers for Clearance operational scripts.
# shellcheck shell=bash
# Sourced by backup/upgrade/validate scripts — not executed directly.
#
# Callers must run under: set -Eeuo pipefail

if [[ -n "${OPS_COMMON_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
OPS_COMMON_LOADED=1

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# Never print secret values. Label-only diagnostics.
redact_url() {
  local url="${1:-}"
  if [[ -z "$url" ]]; then
    printf '%s' "(empty)"
    return
  fi
  # Strip userinfo credentials if present.
  printf '%s' "$url" | sed -E \
    -e 's#(postgres(ql)?://)[^/@]+@#\1***@#' \
    -e 's#([?&](password|sslpassword|token|secret)=)[^&]*#\1***#g'
}

# Known-insecure defaults (mirrors packages/management secret policy).
is_forbidden_secret() {
  local secret="${1:-}"
  local lower
  if [[ -z "$secret" ]]; then
    return 0
  fi
  if (( ${#secret} < 16 )); then
    return 0
  fi
  lower="$(printf '%s' "$secret" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    "dev-secret-change-me"|"dev-secret-change-me-please-32chars!!"|"secret"|"local-compose-secret-change-me-32"|"test-secret-value-32-characters"|"test-secret-value-that-is-long-enough"|"test-secret-value-that-is-long-enough-32"|"change-me"|"password"|"clearance"|"clearance-secret"|"postgres"|"admin"|"changeme")
      return 0
      ;;
  esac
  if [[ "$lower" == *"change-me"* || "$lower" == *"dev-secret"* || "$lower" == *"replace-me"* ]]; then
    return 0
  fi
  return 1
}

require_strong_secret() {
  local label="$1"
  local value="${2:-}"
  if is_forbidden_secret "$value"; then
    die "$label is missing, empty, shorter than 16 chars, or a known weak default"
  fi
}

# Reject obvious non-production placeholders used as DATABASE_URL.
is_weak_database_url() {
  local url="${1:-}"
  local lower
  if [[ -z "$url" ]]; then
    return 0
  fi
  lower="$(printf '%s' "$url" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    *"://clearance:clearance@"*|*"://postgres:postgres@"*|*"://user:pass@"*|*"://user:password@"*|*changeme*|*change-me*|*example.com*)
      return 0
      ;;
  esac
  # Missing scheme or host
  if [[ ! "$url" =~ ^postgres(ql)?://[^[:space:]]+$ ]]; then
    return 0
  fi
  return 1
}

require_database_url() {
  local url="${1:-}"
  if is_weak_database_url "$url"; then
    die "DATABASE_URL is missing, not a postgres URL, or uses a weak/default credential (redacted=$(redact_url "$url"))"
  fi
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

iso_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

# Resolve DATABASE_URL for host-side pg tools. Prefer explicit DATABASE_URL.
resolve_database_url() {
  if [[ -n "${DATABASE_URL:-}" ]]; then
    printf '%s' "$DATABASE_URL"
    return
  fi
  die "DATABASE_URL is required (postgres connection string for the active environment)"
}

# Parse active database name from DATABASE_URL without printing secrets.
db_name_from_url() {
  local url="$1"
  local path
  path="$(printf '%s' "$url" | sed -E 's#^[a-zA-Z0-9+.-]+://[^/]+/##' | sed 's#[?#].*##')"
  # URL-decode minimal %xx if present
  if [[ -z "$path" || "$path" == *"/"* ]]; then
    die "could not parse database name from DATABASE_URL"
  fi
  printf '%s' "$path"
}

# Admin URL that connects to maintenance db (postgres) for CREATE/DROP DATABASE.
admin_url_from_url() {
  local url="$1"
  # Replace path with /postgres while preserving query string.
  if [[ "$url" == *"?"* ]]; then
    printf '%s' "$url" | sed -E 's#(postgres(ql)?://[^/]+)/[^?]+#\1/postgres#'
  else
    printf '%s' "$url" | sed -E 's#(postgres(ql)?://[^/]+)/.*#\1/postgres#'
  fi
}

# Build a URL pointing at a different database name (same host/user).
url_with_db() {
  local url="$1"
  local db="$2"
  if [[ "$url" == *"?"* ]]; then
    printf '%s' "$url" | sed -E "s#(postgres(ql)?://[^/]+)/[^?]+#\1/${db}#"
  else
    printf '%s' "$url" | sed -E "s#(postgres(ql)?://[^/]+)/.*#\1/${db}#"
  fi
}

json_escape() {
  # Minimal JSON string escape for plan/meta files.
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()), end="")'
  else
    JSON_ESCAPE_VALUE="$1" node -e 'process.stdout.write(JSON.stringify(process.env.JSON_ESCAPE_VALUE))'
  fi
}

# Active DB protection: refuse operations that target the live database name for drop/overwrite.
assert_not_active_db() {
  local candidate="$1"
  local active
  active="$(db_name_from_url "$(resolve_database_url)")"
  if [[ "$candidate" == "$active" ]]; then
    die "refusing operation on active database '$candidate' (isolated names only)"
  fi
  case "$candidate" in
    postgres|template0|template1)
      die "refusing operation on system database '$candidate'"
      ;;
  esac
}

# Safe identifier: lowercase alphanumeric + underscore only.
assert_safe_ident() {
  local name="$1"
  local label="${2:-identifier}"
  if [[ ! "$name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
    die "$label must be a simple SQL identifier (got unsafe value)"
  fi
  if (( ${#name} > 63 )); then
    die "$label exceeds 63 characters"
  fi
}

# Release values are passed to SQL hooks and filesystem paths. Keep the
# accepted grammar deliberately narrower than arbitrary operator input.
assert_safe_version() {
  local version="$1"
  local label="${2:-version}"
  if [[ ! "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$ ]]; then
    die "$label is not a safe release version"
  fi
}

psql_q() {
  # Quiet psql: never echo connection string beyond env; use argv.
  local url="$1"
  shift
  PGPASSWORD="${PGPASSWORD:-}" psql --no-psqlrc -v ON_ERROR_STOP=1 "$url" "$@"
}

# Collect lightweight resource evidence from a database (counts, table list).
# Schema fingerprint consumers should hash only the stable "tables" object
# (see schema_fingerprint_from_evidence); capturedAt is observational only.
collect_db_evidence() {
  local url="$1"
  local out_file="$2"

  {
    printf '{\n'
    printf '  "capturedAt": %s,\n' "$(json_escape "$(iso_now)")"
    printf '  "tables": {'
    local first=1
    # Prefer known management/runtime tables when present; otherwise all public base tables.
    local tables
    tables="$(psql_q "$url" -At -c "
      SELECT table_name FROM information_schema.tables
      WHERE table_schema='public' AND table_type='BASE TABLE'
      ORDER BY table_name;
    " 2>/dev/null || true)"
    if [[ -n "$tables" ]]; then
      while IFS= read -r t; do
        [[ -z "$t" ]] && continue
        assert_safe_ident "$t" "table"
        local c
        c="$(psql_q "$url" -At -c "SELECT count(*)::text FROM \"${t}\";" 2>/dev/null || echo "null")"
        if [[ $first -eq 1 ]]; then
          first=0
        else
          printf ','
        fi
        printf '\n    %s: %s' "$(json_escape "$t")" "$c"
      done <<<"$tables"
    fi
    printf '\n  }\n'
    printf '}\n'
  } >"$out_file"
}

# Stable sha256 over table->count map only (ignores capturedAt).
schema_fingerprint_from_evidence() {
  local evidence_file="$1"
  node -e '
    const fs=require("fs");
    const crypto=require("crypto");
    const j=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
    const tables=j.tables||{};
    const keys=Object.keys(tables).sort();
    const stable={};
    for (const k of keys) stable[k]=tables[k];
    process.stdout.write(crypto.createHash("sha256").update(JSON.stringify(stable)).digest("hex"));
  ' "$evidence_file"
}

# The application release contract lives in the durable management snapshot,
# which is created and consumed by the running Clearance API.
application_release_version() {
  local url="$1"
  { psql_q "$url" -At -c "
    SELECT data->>'releaseVersion'
    FROM clearance_management_snapshot
    WHERE id = 1;
  " 2>/dev/null || true; } | head -n1
}

require_application_release() {
  local url="$1"
  local expected="$2"
  assert_safe_version "$expected" "expected application release"
  local actual
  actual="$(application_release_version "$url")"
  [[ -n "$actual" ]] || die "active database has no Clearance application release contract"
  [[ "$actual" == "$expected" ]] \
    || die "application release mismatch: expected $expected, found $actual"
}

# Compare the complete public-table count map captured in backup metadata with
# evidence collected after a restore. New, missing, or changed tables all fail.
compare_backup_evidence() {
  local meta_file="$1"
  local restored_evidence_file="$2"
  node -e '
    const fs=require("fs");
    const meta=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
    const restored=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));
    const expected=meta.resourceCounts || {};
    const actual=restored.tables || {};
    const keys=Object.keys(expected).sort();
    const actualKeys=Object.keys(actual).sort();
    let mismatches=0;
    for (const k of keys) {
      const e=expected[k];
      const a=actual[k];
      if (typeof e !== "number" || a === undefined || a === null || Number(a) !== Number(e)) {
        console.error(`count mismatch for ${k}: expected ${e}, restored ${a}`);
        mismatches++;
      }
    }
    if (JSON.stringify(keys) !== JSON.stringify(actualKeys)) {
      console.error(`table set mismatch: expected ${keys.join(",")}; restored ${actualKeys.join(",")}`);
      mismatches++;
    }
    if (mismatches > 0) process.exit(1);
    process.stdout.write(JSON.stringify({ok:true, comparedTables:keys.length, restoredTables:actualKeys.length, sourceDatabase:meta.sourceDatabase}));
  ' "$meta_file" "$restored_evidence_file"
}

require_pg_client() {
  require_cmd psql
  require_cmd pg_dump
}

# Map DATABASE_URL host for tools running inside Docker (Desktop/Mac/Windows).
dockerized_database_url() {
  local url="$1"
  printf '%s' "$url" \
    | sed -E 's#(@|://)127\.0\.0\.1#\1host.docker.internal#g' \
    | sed -E 's#(@|://)localhost#\1host.docker.internal#g'
}

# Detect server major version (e.g. 16) without printing secrets.
pg_server_major() {
  local url="$1"
  local full
  full="$(psql_q "$url" -At -c 'SHOW server_version;' 2>/dev/null | head -n1 | awk '{print $1}')"
  if [[ -z "$full" ]]; then
    die "could not determine postgres server version"
  fi
  printf '%s' "${full%%.*}"
}

# Real pg_dump to file. Prefer local client; on version mismatch use matching postgres image.
# Never prints the connection string.
pg_dump_to_file() {
  local url="$1"
  local out="$2"
  local snapshot="${3:-}"
  local -a snapshot_arg=()
  if [[ -n "$snapshot" ]]; then
    snapshot_arg=("--snapshot=$snapshot")
  fi
  local err
  err="$(mktemp "${TMPDIR:-/tmp}/clearance-pgdump-err.XXXXXX")"
  if pg_dump --no-owner --no-acl --format=plain "${snapshot_arg[@]}" --dbname="$url" --file="$out" 2>"$err"; then
    find "$err" -type f -delete 2>/dev/null || true
    return 0
  fi
  if ! grep -qi 'version mismatch' "$err"; then
    # surface non-secret error text only
    printf 'pg_dump failed: %s\n' "$(redact_url "$(tr '\n' ' ' <"$err")")" >&2
    find "$err" -type f -delete 2>/dev/null || true
    die "pg_dump failed"
  fi
  find "$err" -type f -delete 2>/dev/null || true
  require_cmd docker
  local major docker_url img
  major="$(pg_server_major "$url")"
  docker_url="$(dockerized_database_url "$url")"
  img="postgres:${major}-alpine"
  printf 'backup: local pg_dump version mismatch; using %s\n' "$img" >&2
  # host.docker.internal works on Docker Desktop; host-gateway helps Linux.
  if ! docker run --rm \
      --add-host=host.docker.internal:host-gateway \
      "$img" \
      pg_dump --no-owner --no-acl --format=plain "${snapshot_arg[@]}" --dbname="$docker_url" >"$out"
  then
    die "dockerized pg_dump failed (image=$img)"
  fi
  [[ -s "$out" ]] || die "dockerized pg_dump produced empty file"
}

# Restore plain SQL dump into target URL (local psql is generally forward-compatible).
psql_restore_file() {
  local url="$1"
  local dump="$2"
  psql_q "$url" -f "$dump" >/dev/null
}
