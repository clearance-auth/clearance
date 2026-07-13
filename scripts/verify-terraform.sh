#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="$ROOT/deploy/terraform"
EXPECTED_TERRAFORM_VERSION="1.5.7"
DEFAULT_CLEARANCE_IMAGE="ghcr.io/clearance-auth/clearance/clearance@sha256:f9dc74b3bd3ee3a4107e168556889acadb10d2701c3438858f036c24033629b7"
CLEARANCE_IMAGE="${CLEARANCE_TERRAFORM_IMAGE:-$DEFAULT_CLEARANCE_IMAGE}"

if ! command -v terraform >/dev/null 2>&1; then
  echo "terraform $EXPECTED_TERRAFORM_VERSION is required" >&2
  exit 1
fi

ACTUAL_TERRAFORM_VERSION="$(terraform version -json | sed -n 's/.*"terraform_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [[ "$ACTUAL_TERRAFORM_VERSION" != "$EXPECTED_TERRAFORM_VERSION" ]]; then
  echo "terraform $EXPECTED_TERRAFORM_VERSION is required; found ${ACTUAL_TERRAFORM_VERSION:-unknown}" >&2
  exit 1
fi

if [[ ! "$CLEARANCE_IMAGE" =~ ^[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "CLEARANCE_TERRAFORM_IMAGE must be an immutable repository@sha256 digest" >&2
  exit 1
fi

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/clearance-terraform.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT
export TF_DATA_DIR="$SCRATCH/terraform-data"
export TF_IN_AUTOMATION=1
export TF_INPUT=0

# Representative values exercise every required variable without writing
# credentials to the repository or a reusable Terraform state file.
export TF_VAR_clearance_image="$CLEARANCE_IMAGE"
export TF_VAR_postgres_password="terraform-plan-postgres-secret"
export TF_VAR_clearance_secret="terraform-plan-clearance-secret"
export TF_VAR_operator_token="terraform-plan-operator-token"
export TF_VAR_credential_key="terraform-plan-credential-key-32-characters"
export TF_VAR_credential_key_id="terraform-plan-v1"
export TF_VAR_console_admin_password="terraform-plan-console-password"
export TF_VAR_console_session_secret="terraform-plan-console-session-secret"

terraform -chdir="$MODULE" fmt -check -diff
terraform -chdir="$MODULE" init \
  -backend=false \
  -input=false \
  -lockfile=readonly \
  -no-color
terraform -chdir="$MODULE" validate -no-color

set +e
terraform -chdir="$MODULE" plan \
  -input=false \
  -lock=false \
  -refresh=false \
  -no-color \
  -detailed-exitcode \
  -out="$SCRATCH/terraform.plan"
PLAN_STATUS=$?
set -e

if [[ "$PLAN_STATUS" -ne 0 && "$PLAN_STATUS" -ne 2 ]]; then
  echo "terraform plan failed with exit code $PLAN_STATUS" >&2
  exit "$PLAN_STATUS"
fi

terraform -chdir="$MODULE" show -json "$SCRATCH/terraform.plan" >"$SCRATCH/terraform-plan.json"
if ! grep -Fq "\"name\":\"$CLEARANCE_IMAGE\"" "$SCRATCH/terraform-plan.json"; then
  echo "terraform plan did not retain the immutable Clearance image digest" >&2
  exit 1
fi

echo "Terraform verification passed with $CLEARANCE_IMAGE"
