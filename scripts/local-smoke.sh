#!/usr/bin/env bash
# Host-local, no-Docker smoke for the CLI's offline JSON profile.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${SCRATCH_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/clearance-local-smoke.XXXXXX")}"
mkdir -p "$SCRATCH"
cd "$ROOT"

export CLEARANCE_SECRET="${CLEARANCE_SECRET:-local-dev-secret-change-in-prod-32}"
export CLEARANCE_BASE_URL="${CLEARANCE_BASE_URL:-http://localhost:3000}"
export CLEARANCE_DATA_PATH="${CLEARANCE_DATA_PATH:-$SCRATCH/local-smoke-data.json}"
export CLEARANCE_LOCAL_DIRECT=1
rm -f "$CLEARANCE_DATA_PATH"
CLI=(node "$ROOT/packages/clearance-cli/dist/index.js")

echo "local-smoke SCRATCH=$SCRATCH"

if [[ ! -f "$ROOT/packages/clearance-cli/dist/index.js" ]]; then
  echo "building workspace (dist missing)..."
  pnpm build
fi

"${CLI[@]}" init --name local-smoke --json --no-input --data-path "$CLEARANCE_DATA_PATH"
"${CLI[@]}" users create --email smoke@test.com --name Smoke --json --no-input --data-path "$CLEARANCE_DATA_PATH"
"${CLI[@]}" orgs create --name SmokeOrg --json --no-input --data-path "$CLEARANCE_DATA_PATH"
ORG=$("${CLI[@]}" orgs list --json --no-input --data-path "$CLEARANCE_DATA_PATH" | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).organizations[0].id))")
USER=$("${CLI[@]}" users list --json --no-input --data-path "$CLEARANCE_DATA_PATH" | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).users[0].id))")
"${CLI[@]}" orgs members add --org "$ORG" --user "$USER" --role admin --json --no-input --data-path "$CLEARANCE_DATA_PATH"
SSO=$("${CLI[@]}" sso create --org "$ORG" --provider okta --protocol oidc --issuer https://idp.example/oauth2 --audience clearance-sp --json --no-input --data-path "$CLEARANCE_DATA_PATH" | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).connection.id))")
"${CLI[@]}" sso test "$SSO" --fixture ok --json --no-input --data-path "$CLEARANCE_DATA_PATH" >/dev/null
SCIM=$("${CLI[@]}" scim create --org "$ORG" --provider okta --json --no-input --data-path "$CLEARANCE_DATA_PATH" | node -e "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>console.log(JSON.parse(s).connection.id))")
"${CLI[@]}" scim test "$SCIM" --apply --json --no-input --data-path "$CLEARANCE_DATA_PATH" >/dev/null
# Assert content, not just emit it: readiness check --json prints
# { report: { overall, checks[], conformance } }. In this offline fixture flow
# both conformance tests are simulation (warn), so overall must be "ready" or
# "attention" and no check may be status:"fail".
"${CLI[@]}" readiness check --org "$ORG" --json --no-input --data-path "$CLEARANCE_DATA_PATH" >"$SCRATCH/readiness.json"
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
"${CLI[@]}" doctor --json --no-input --data-path "$CLEARANCE_DATA_PATH" >"$SCRATCH/doctor.json"
node -e '
  const j = require(process.argv[1]);
  if (j.ok !== true || !Array.isArray(j.checks) || j.checks.some((c) => c.status === "fail")) {
    console.error(`doctor gate failed: ok=${j.ok} failing=` + JSON.stringify((j.checks || []).filter((c) => c.status === "fail").map((c) => c.id))); process.exit(1);
  }
  console.log(`doctor asserted: ok=${j.ok} checks=${j.checks.length}`);
' "$SCRATCH/doctor.json"
echo "LOCAL_CLI_OFFLINE_SMOKE_OK org=$ORG"
