#!/usr/bin/env bash
# Host-local, no-Docker smoke for the authenticated CLI-to-API path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${SCRATCH_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/clearance-local-smoke.XXXXXX")}"
mkdir -p "$SCRATCH"
cd "$ROOT"

export CLEARANCE_SECRET="${CLEARANCE_SECRET:-local-dev-secret-change-in-prod-32}"
export CLEARANCE_BASE_URL="${CLEARANCE_BASE_URL:-http://localhost:3000}"
export CLEARANCE_DATA_PATH="${CLEARANCE_DATA_PATH:-$SCRATCH/local-smoke-data.json}"
export CLEARANCE_OPERATOR_TOKEN="${CLEARANCE_OPERATOR_TOKEN:-$(openssl rand -hex 24)}"
export CLEARANCE_CREDENTIAL_KEY="${CLEARANCE_CREDENTIAL_KEY:-$(openssl rand -hex 32)}"
export CLEARANCE_CREDENTIAL_KEY_ID="${CLEARANCE_CREDENTIAL_KEY_ID:-local-smoke-v1}"
export CLEARANCE_API_PORT="${CLEARANCE_API_PORT:-$(node -e "const n=require('node:net');const s=n.createServer();s.listen(0,'127.0.0.1',()=>{console.log(s.address().port);s.close()})")}"
export CLEARANCE_API_URL="http://127.0.0.1:$CLEARANCE_API_PORT"
CLI=(node "$ROOT/packages/clearance-cli/dist/index.js")

echo "local-smoke SCRATCH=$SCRATCH"

if [[ ! -f "$ROOT/packages/clearance-cli/dist/index.js" || ! -f "$ROOT/packages/clearance-api/dist/server.js" ]]; then
  echo "building workspace (dist missing)..."
  pnpm build
fi

node "$ROOT/packages/clearance-api/dist/server.js" >"$SCRATCH/api.log" 2>&1 &
API_PID=$!
cleanup() {
  kill "$API_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
for _ in $(seq 1 100); do
  if curl -fsS "$CLEARANCE_API_URL/health" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$API_PID" >/dev/null 2>&1; then
    cat "$SCRATCH/api.log" >&2
    exit 1
  fi
  sleep 0.05
done
curl -fsS "$CLEARANCE_API_URL/health" >/dev/null

"${CLI[@]}" init --name local-smoke --json --no-input
"${CLI[@]}" users create --email smoke@test.com --name Smoke --json --no-input
"${CLI[@]}" orgs create --name SmokeOrg --json --no-input
ORG=$("${CLI[@]}" orgs list --json --no-input | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).organizations[0].id))")
USER=$("${CLI[@]}" users list --json --no-input | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).users[0].id))")
"${CLI[@]}" orgs members add --org "$ORG" --user "$USER" --role admin --json --no-input
SSO=$("${CLI[@]}" sso create --org "$ORG" --provider okta --protocol oidc --issuer https://idp.example/oauth2 --audience clearance-sp --json --no-input | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).connection.id))")
"${CLI[@]}" sso test "$SSO" --fixture ok --json --no-input >/dev/null
SCIM=$("${CLI[@]}" scim create --org "$ORG" --provider okta --json --no-input | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).connection.id))")
"${CLI[@]}" scim test "$SCIM" --apply --json --no-input >/dev/null
# Assert content, not just emit it: readiness check --json prints
# { report: { overall, checks[], conformance } }. In this offline fixture flow
# both conformance tests are simulation (warn), so overall must be "ready" or
# "attention" and no check may be status:"fail".
"${CLI[@]}" readiness check --org "$ORG" --json --no-input >"$SCRATCH/readiness.json"
node -e '
  const j = require(process.argv[1]);
  const r = j.report;
  if (!r || !Array.isArray(r.checks) || r.checks.length === 0) {
    console.error("readiness gate failed: missing report/checks"); process.exit(1);
  }
  if (r.overall !== "ready" && r.overall !== "attention") {
    console.error(`readiness gate failed: overall=${r.overall}`); process.exit(1);
  }
  if (r.checks.some((c) => c.status === "fail")) {
    console.error("readiness gate failed: " + JSON.stringify(r.checks.filter((c) => c.status === "fail").map((c) => c.id))); process.exit(1);
  }
  console.log(`readiness asserted: overall=${r.overall} checks=${r.checks.length} liveCertified=${r.conformance?.liveCertified}`);
' "$SCRATCH/readiness.json"
# doctor --json prints { ok, checks[], releaseVersion }; assert ok explicitly.
"${CLI[@]}" doctor --json --no-input >"$SCRATCH/doctor.json"
node -e '
  const j = require(process.argv[1]);
  if (j.ok !== true || !Array.isArray(j.checks) || j.checks.some((c) => c.status === "fail")) {
    console.error(`doctor gate failed: ok=${j.ok} failing=` + JSON.stringify((j.checks || []).filter((c) => c.status === "fail").map((c) => c.id))); process.exit(1);
  }
  console.log(`doctor asserted: ok=${j.ok} checks=${j.checks.length}`);
' "$SCRATCH/doctor.json"
echo "LOCAL_CLI_API_SMOKE_OK org=$ORG"
