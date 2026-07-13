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
terraform init
terraform validate
terraform plan
terraform apply
terraform output
```

The default endpoints are `http://localhost:13200` (API), `http://localhost:13100` (console), and `http://localhost:13300` (sample app). Optional GitHub and Google client ID/secret variables must be supplied as complete pairs.

Terraform state contains sensitive container environment values. Use the Helm profile or your platform-specific infrastructure for beta production, with external Postgres, TLS ingress, monitoring, and scheduled off-host backups. `terraform destroy` removes the isolated Postgres volume and its data.
