# Clearance Terraform local Docker profile

This module pulls an immutable signed Clearance image and runs an isolated,
single-host evaluation stack: Postgres, management API, operator console, and
sample B2B app. Its default network, volume, and container names use the
`clearance-tf` prefix so they do not share Compose state. It is intentionally a
local Docker profile, not a production infrastructure module: endpoints are
loopback-only HTTP, secrets live in Terraform state, Postgres is a single local
volume, and there is no load balancer, TLS, remote state, monitoring, or
automated backup resource.

Create `terraform.tfvars` with strong values for every required secret:

```hcl
postgres_password      = "..."
clearance_secret       = "..."
operator_token         = "..."
credential_key         = "..." # at least 32 characters
credential_key_id      = "v1"
console_admin_password = "..."
console_session_secret = "..."
clearance_image         = "ghcr.io/owner/repo/clearance@sha256:<signed-release-digest>"
```

Then run:

```bash
bash ../../scripts/verify-terraform.sh
terraform init -backend=false -lockfile=readonly
terraform plan
terraform apply
terraform output
```

The repository verification command pins Terraform `1.5.7` and Docker provider
`3.9.0`, checks formatting, initializes without a backend from the committed
read-only lockfile, validates the module, and creates a refresh-free
representative plan. By default it plans with a known immutable,
keyless-signed beta release image. Set `CLEARANCE_TERRAFORM_IMAGE` to another
digest-addressed image only after verifying that release's signature. The
verification command never applies the plan.

The default endpoints are `http://localhost:13200` (API), `http://localhost:13100` (console), and `http://localhost:13300` (sample app). Optional GitHub and Google client ID/secret variables must be supplied as complete pairs.

Terraform state contains sensitive container environment values. Use the Helm profile or your platform-specific infrastructure for beta production, with external Postgres, TLS ingress, monitoring, and scheduled off-host backups. `terraform destroy` removes the isolated Postgres volume and its data.
