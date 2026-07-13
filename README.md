# Clearance

Open-source authentication infrastructure for B2B software companies. Clearance provides enterprise SSO, SCIM, organizations, roles, audit events, and operational tooling through one CLI-first platform.

**CLI:** `clearance` · **Packages:** `@clearance/*` · **Repository:** [clearance-auth/clearance](https://github.com/clearance-auth/clearance)

## What you can run today

| Surface | Port | How |
|---|---|---|
| Sample B2B app (email/password plus configured GitHub/Google login) | **13300** (Compose) / 3000 (host dev) | Compose or `pnpm dev:sample` |
| Operator console | **13100** (Compose) / 3100 (host dev) | Compose or `pnpm dev:console` |
| Management API | **13200** (Compose) / 3200 (host dev) | Compose or `pnpm dev:api` |
| Postgres (production-like dependency) | **15434** | Compose |
| CLI | — | `node packages/clearance-cli/dist/index.js` |

## Install and authenticate the CLI

The published package is `@clearance/cli`; it installs the `clearance` command.

```bash
npm install --global @clearance/cli
export CLEARANCE_OPERATOR_TOKEN='<operator-token>'
clearance login --profile production --url https://clearance.example.com
clearance --profile production users list
```

After login, ordinary resource and configuration commands use the authenticated `/v1/*` management API and the server-derived project/environment scope. Use `--local-direct` only for a deliberately host-bound workflow such as local development, file export/import, schema tooling, backup/restore, or upgrade/rollback:

```bash
clearance --local-direct --data-path .clearance/dev.json init --name my-app
clearance --local-direct backup create --dir /secure/clearance-backups
```

## Full stack (recommended)

```bash
corepack enable
pnpm install
pnpm build

# One command: build an isolated stack, test it end to end, then tear it down
pnpm stack:smoke
```

For a persistent local stack:

```bash
export CLEARANCE_DB_PASSWORD="$(openssl rand -hex 32)"
export CLEARANCE_OPERATOR_TOKEN="$(openssl rand -hex 32)"
export CLEARANCE_SECRET="$(openssl rand -hex 32)"
export CLEARANCE_CREDENTIAL_KEY="$(openssl rand -hex 32)"
export CLEARANCE_CREDENTIAL_KEY_ID=local-v1
export CLEARANCE_CONSOLE_ADMIN_USER=admin
export CLEARANCE_CONSOLE_ADMIN_PASSWORD="$(openssl rand -hex 32)"
export CLEARANCE_CONSOLE_SESSION_SECRET="$(openssl rand -hex 32)"
pnpm stack:up
docker compose ps

curl http://localhost:13200/health
curl http://localhost:13300/health     # must return {"ok":true,"app":"sample-b2b"}
open http://localhost:13300/sign-up    # first login
open http://localhost:13100/overview   # console
```

Optional social login is enabled only when a complete provider credential pair is present. An incomplete pair fails application startup so a broken sign-in option cannot be advertised.

```bash
# GitHub callback: http://localhost:13300/api/auth/callback/github
export CLEARANCE_GITHUB_CLIENT_ID=...
export CLEARANCE_GITHUB_CLIENT_SECRET=...

# Google callback: http://localhost:13300/api/auth/callback/google
export CLEARANCE_GOOGLE_CLIENT_ID=...
export CLEARANCE_GOOGLE_CLIENT_SECRET=...
```

Stop the persistent stack while retaining the named Postgres volume and its data:

```bash
pnpm stack:down
```

Destroy the persistent stack and permanently remove its named Postgres volume and local database:

```bash
pnpm stack:destroy
```

## Host-run apps (existing Postgres required)

```bash
pnpm install && pnpm build
export CLEARANCE_SECRET="$(openssl rand -hex 32)"
export CLEARANCE_BASE_URL=http://localhost:3000
export DATABASE_URL='postgres://clearance:replace-me@127.0.0.1:5432/clearance'

pnpm smoke   # CLI init → users/orgs → SSO/SCIM readiness → doctor

# terminals:
pnpm dev:api
pnpm dev:console
pnpm dev:sample
```

CLI examples:

```bash
node packages/clearance-cli/dist/index.js --local-direct init --name my-app --json --no-input
node packages/clearance-cli/dist/index.js --local-direct doctor --json --no-input
node packages/clearance-cli/dist/index.js --local-direct users create --email a@b.com --name A --json --no-input
node packages/clearance-cli/dist/index.js --local-direct orgs create --name Acme --json --no-input
node packages/clearance-cli/dist/index.js --local-direct sso create --org <id> --provider okta --protocol oidc \
  --issuer https://example.okta.com --audience clearance-sp --json --no-input
node packages/clearance-cli/dist/index.js --local-direct readiness check --org <id> --json --no-input
node packages/clearance-cli/dist/index.js --local-direct backup create --json --no-input
node packages/clearance-cli/dist/index.js --local-direct upgrade check --json --no-input
```

## Packages

| Package | Role |
|---|---|
| `@clearance/auth` | Auth runtime identity and safe defaults |
| `@clearance/management` | Shared application services (CLI + API + console) |
| `@clearance/cli` | CLI package (installs the `clearance` binary) |
| `@clearance/api` | Versioned management HTTP API (`/v1/*`) |
| `@clearance/console` | Dark operator console |
| `@clearance/sample-b2b` | Sample B2B app for login e2e |

## Scope honesty (current cut)

This repository currently ships a **locally testable Clearance control plane + sample app** covering selected local workflows from INIT milestones M1–M4:

- Fresh public history containing only Clearance-owned package names and product identity
- CLI management of projects, users, orgs, events with a tested single-JSON-document output contract (registry-swept)
- Console surfaces (Overview / Users / Orgs / Events / Settings) with in-browser operator login/logout, proven by DOM tests and a chromium E2E stage inside the canonical gate
- SSO/SCIM setup/test with diagnostic stages + readiness report. Fixture/simulation labs remain the default; `sso test --live` / `scim test --live` run **read-only discovery/JWKS and SCIM endpoint conformance against a real external tenant** (HTTPS, non-loopback, `--yes`-armed). Full interactive sign-in certification against Okta/Entra tenants is still open; live SAML refuses rather than pretending
- Clearance import plus migration plan/run/verify/rollback on validated exports, including coordinated Postgres runtime and management writes
- Config and runtime-schema lifecycle, operator login/logout/whoami, API-key lifecycle, and event tailing
- Persistent Compose stack lifecycle, doctor, backup/verify/restore, and the shipped `0.1.0` → `0.2.0` upgrade check/plan/apply/verify/rollback drill, including an exact-token active-database restore path
- Canonical gate (`scripts/verify-real.sh`) runs the Postgres-backed management suites against disposable databases with a machine-checked zero-skip assertion, plus the browser E2E — silent skip is a gate failure

The full milestone gates remain open. Deploy/cloud commands and hosted-source imports are absent; environment promotion remains limited; the console still uses process-local sessions; and the management Postgres store is a single-row JSONB snapshot suitable for local/small-tenant use only (measured baseline and exit design in DESIGN-store-v2.md). Live Okta/Entra tenant *certification* (interactive sign-in) and signed-release publication against the final public registry have not been performed. The beta readiness evidence, external adversarial review result, residual risks, and rollout prerequisites are recorded in `docs/beta-readiness.md`.

## Docs

- [COMPATIBILITY.md](./COMPATIBILITY.md) — package map  
- [LICENSE](./LICENSE) — MIT with required attribution  
