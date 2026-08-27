# Clearance

Open-source authentication for B2B software, self-hosted on Postgres.

Clearance gives your product sign-in, organizations, roles, enterprise SSO and
SCIM, transactional delivery, and the operating tools to run them. The CLI,
management API, and operator console use the same management plane, so your
team can automate routine work and investigate the same state in a browser.

**Current release:** [0.4.0](https://github.com/clearance-auth/clearance/releases/tag/v0.4.0)

Start with:

- [`@clearance/auth`](https://www.npmjs.com/package/@clearance/auth) for the authentication runtime
- [`@clearance/runtime`](https://www.npmjs.com/package/@clearance/runtime) for browser and server integrations
- [`@clearance/cli`](https://www.npmjs.com/package/@clearance/cli) for operational workflows
- [`@clearance/api`](https://www.npmjs.com/package/@clearance/api) for the management API

**Project:** [clearance-auth/clearance](https://github.com/clearance-auth/clearance)

## Build the product your customers expect

Clearance is for teams building multi-tenant software that need a strong
authentication foundation now and enterprise identity capabilities as their
customers grow. Keep identity data and operations in your own Postgres
deployment while giving product, support, and platform teams a common way to
work.

| Capability | What it gives your product team |
| --- | --- |
| Sign-in and account security | Email and password, social sign-in, magic links, email OTP, passkeys, TOTP, recovery codes, session management, and password policy controls. |
| Organizations and access | Organizations, memberships, invitations, custom roles and actions, API keys, and service accounts for B2B applications. |
| Enterprise identity | SAML and OIDC connections, SCIM directories, diagnostics, readiness checks, and read-only live conformance probes. |
| Reliable customer communication | Transactional email through SMTP or Amazon SES, signed webhooks, durable delivery, retries, and a separately deployable worker. |
| Operator experience | A typed management API, task-oriented CLI and TUI, dark operator console, scoped audit events, imports, backups, restore drills, and upgrades. |
| Production control | Postgres-backed deployment with Docker Compose or Helm, health and readiness endpoints, Prometheus metrics, key-management providers, and signed release assets. |

## Start locally

Clearance supports Node 22 and 24. The default local path requires Docker with
Compose and starts the API, console, sample B2B app, and Postgres together.

```bash
corepack enable
pnpm install

export CLEARANCE_DB_PASSWORD="$(openssl rand -hex 32)"
export CLEARANCE_OPERATOR_TOKEN="$(openssl rand -hex 32)"
export CLEARANCE_SECRET="$(openssl rand -hex 32)"
export CLEARANCE_CREDENTIAL_KEY="$(openssl rand -hex 32)"
export CLEARANCE_CREDENTIAL_KEY_ID=local-v1
export CLEARANCE_CONSOLE_ADMIN_USER=admin
export CLEARANCE_CONSOLE_ADMIN_PASSWORD="$(openssl rand -hex 32)"
export CLEARANCE_CONSOLE_SESSION_SECRET="$(openssl rand -hex 32)"

pnpm stack:up
pnpm stack:status
```

Then open:

- Sample B2B app: <http://localhost:13300/sign-up>
- Operator console: <http://localhost:13100/overview>
- Management API health: <http://localhost:13200/health>

`pnpm stack:up` derives a purpose-separated local key-management
configuration and migrates a fresh credential-authority fence before the
serving services start. To validate the full local journey in an isolated
stack, run `pnpm stack:smoke`.

Stop the stack while retaining local data:

```bash
pnpm stack:down
```

Remove the local Postgres volume as well:

```bash
pnpm stack:destroy
```

For social sign-in, provide a complete provider credential pair before
starting the sample application:

```bash
# GitHub callback: http://localhost:13300/api/auth/callback/github
export CLEARANCE_GITHUB_CLIENT_ID=...
export CLEARANCE_GITHUB_CLIENT_SECRET=...

# Google callback: http://localhost:13300/api/auth/callback/google
export CLEARANCE_GOOGLE_CLIENT_ID=...
export CLEARANCE_GOOGLE_CLIENT_SECRET=...
```

## Add Clearance to an application

Use the sample B2B application's [server configuration](./apps/sample-b2b/src/server.ts)
as the complete server reference. It configures the auth runtime, management
services, SSO, SCIM, and key management in one working application.

For a React client, the browser integration starts with the real runtime
client:

```tsx
import { createAuthClient } from "@clearance/runtime/react";
import { type FormEvent, useState } from "react";

const authClient = createAuthClient({
  baseURL: import.meta.env.VITE_CLEARANCE_URL ?? "http://localhost:13300",
});

export function SignInForm() {
  const session = authClient.useSession();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const result = await authClient.signIn.email({ email, password });
    if (!result.error) await session.refetch();
  }

  return (
    <form onSubmit={signIn}>
      <input onChange={(event) => setEmail(event.target.value)} type="email" />
      <input onChange={(event) => setPassword(event.target.value)} type="password" />
      <button type="submit">Sign in</button>
    </form>
  );
}
```

Compile-checked reference integrations are available for React, Next.js App
Router, and Express. They show browser session handling and server-side ES256
token verification: [framework quickstarts](./apps/framework-quickstarts/README.md).

## Operate it through the CLI

The published [`@clearance/cli`](https://www.npmjs.com/package/@clearance/cli)
package installs the `clearance` command. Run `clearance` in a terminal to
start the guided setup. It verifies a connection before saving a named profile,
accepts the token through hidden input, offers shell completion and the bundled
agent skill, then previews a first read operation before offering to run it. A
valid saved profile resumes with useful next commands. An absent profile or a
credential that no longer verifies returns to connection setup.

```bash
npm install --global @clearance/cli
clearance

# Or connect a remote profile explicitly.
export CLEARANCE_OPERATOR_TOKEN='<operator-token>'
clearance login --profile production --url https://auth.example.com
unset CLEARANCE_OPERATOR_TOKEN

clearance --profile production init --name my-app --output-format json --no-input
clearance --profile production orgs create --name Acme --output-format json --no-input
clearance --profile production users create \
  --email owner@example.com --name 'Acme Owner' --output-format json --no-input
clearance --profile production readiness check \
  --org <organization-id> --output-format json --no-input
```

For normal API-backed commands, authentication is resolved in this order:

1. `CLEARANCE_OPERATOR_TOKEN`, then the compatibility
   `CLEARANCE_API_TOKEN`, with `--api-url` or `CLEARANCE_API_URL` required.
2. The saved profile selected by `--profile`, then `CLEARANCE_PROFILE`, then
   `default`.

An explicit `--profile` cannot be combined with an environment token. A saved
profile remains bound to its saved origin, so an inconsistent `--api-url` is
rejected. Interactive setup, `login`, and the unauthenticated local doctor use
the Compose management API at `http://localhost:13200` when no origin is
provided. Remote HTTP is rejected; loopback HTTP remains available for local
development.

Human output is task-oriented: lists render as bounded tables, detail views
group fields, empty results explain what was searched, and mutations finish
with an outcome and receipt. Untrusted terminal text is sanitized and declared
secrets are redacted from errors and receipts. When stdout is piped, the CLI
selects JSON. Use `--output-format human|json|jsonl|quiet` to choose explicitly,
`--jq '.data.id'` for built-in field selection, and `--no-input` or
`CLEARANCE_NONINTERACTIVE=1` to guarantee that no prompt is opened.

```bash
clearance doctor                               # local files, profile, tools, and unauthenticated API health
clearance --profile production doctor --remote # authenticated server checks
clearance help profiles                        # curated task help
clearance commands --output-format json        # command contract and experience manifest

clearance completion generate zsh              # print completion source
clearance completion status zsh                # inspect ownership without writing
clearance completion install zsh               # install without replacing unowned content
clearance skill status                         # inspect the bundled agent skill
clearance skill install --dry-run               # preview its owned installation
```

Explicit `--output-format json` and inferred piped JSON use an `ok`, `data`,
`summary`, `notice`, `next`, `actions`, and `meta` envelope with a protocol
name and version. The legacy `--json` flag continues to emit the raw result
on success for compatibility; its errors still use the versioned envelope.
Errors include a stable code, stage, retryability, and remediation, with
distinct process statuses for invalid input, authentication, temporary
failure, service failure, and failed health checks. `clearance commands`
publishes the complete parser-derived command and safety contract together
with the same versioned experience manifest consumed by agents and the TUI.

Canonical management operations and CLI-owned mutations run through the same
receipt-producing runner. Commands whose manifest entry requires confirmation
reject live execution until `--yes` is present. `--dry-run` skips live
confirmation only for commands that declare dry-run support; unsupported
previews fail before dispatch. Each receipt records the target, safe command,
dispatch state, request and idempotency identifiers when available, outcome,
commit state, and recovery commands. Live mutations verify that the private
append-only journal is writable before dispatch. Its default is
`operation-receipts.jsonl` in the Clearance CLI configuration directory; set
`CLEARANCE_RECEIPT_PATH` to an absolute path to override it.

### Terminal workspace

```bash
clearance --profile production tui
clearance --profile production tui --user <user-id>
clearance --profile production tui --organization <organization-id>
clearance --profile production tui --open event <event-id>
```

The TUI opens to a quiet, resource-oriented workspace with four destinations:
Overview, People, Security, and Operations. The default view keeps verified
identity details on demand and hides routine polling, while connectivity,
stale-data, and mutation-outcome problems remain visible. Search, resource
detail, the exact equivalent CLI command, target review, dry-run availability,
confirmation, durable outcomes, and recovery guidance appear as the task
requires them.

Deep links support `--user`, `--organization`, `--event`, `--delivery`,
`--sso`, and `--scim`. The equivalent generic form is
`--open <resource> <id>`, where resource is `user`, `organization`, `event`,
`delivery`, `sso`, or `scim`.

`clearance events tail` is intentionally a CLI stream rather than a TUI
action. It polls for new scoped events, suppresses duplicate event IDs, and
stops on Ctrl-C, `--once`, or `--max-events <n>`. Human output is one safe line
per event. Machine output is one JSON Lines record per event, including when
`--output-format json` is selected; legacy `--json` keeps each event in its raw
shape.

Use the same API-backed workflows for enterprise setup, audit history,
backups, restores, and upgrades. The [CLI source](./packages/clearance-cli)
and [production operations guide](./docs/production-operations.md) describe
the available commands and operating sequence.

## Deploy with control

Use Docker Compose for a single-host deployment and the Helm chart for
Kubernetes. Both paths require explicit production secrets and key-management
configuration. The production overlay fails closed when required operator
inputs are missing.

- [Production operations](./docs/production-operations.md) covers TLS,
  health checks, metrics, delivery, backups, restores, upgrades, and recovery.
- [Helm chart](./deploy/helm/clearance/README.md) covers Kubernetes values and
  deployment requirements.
- [Compose deployment](./deploy/compose/docker-compose.production.yml) is the
  single-host reference configuration.
- [Compatibility](./docs/compatibility.md) maps maintained package and migration
  import compatibility.

## Packages

| Package | Use it for |
| --- | --- |
| [`@clearance/auth`](./packages/clearance-auth) | Product auth runtime and safe defaults. |
| [`@clearance/runtime`](./packages/runtime) | Browser and server runtime integrations. |
| [`@clearance/sso`](./packages/sso) | SAML and OIDC enterprise sign-in. |
| [`@clearance/scim`](./packages/scim) | SCIM provisioning endpoints. |
| [`@clearance/verification`](./packages/verification) | Server-side ES256 access-token verification. |
| [`@clearance/management`](./packages/management) | Shared management services behind the CLI, API, and console. |
| [`@clearance/management-client`](./packages/management-client) | Typed management API transport. |
| [`@clearance/cli`](./packages/clearance-cli) | Task-oriented human, agent, and TUI operations. |
| [`@clearance/api`](./packages/clearance-api) | Versioned management HTTP API. |
| [`@clearance/console`](./packages/clearance-console) | Operator console. |
| [`@clearance/delivery`](./packages/delivery) | Durable transactional delivery storage. |
| [`@clearance/delivery-worker`](./packages/delivery-worker) | SMTP and Amazon SES delivery worker. |
| [`@clearance/key-management`](./packages/key-management) | Purpose-bound local and cloud key providers. |
| [`@clearance/vault`](./packages/vault) | Hosted authentication and tenant self-service. |
| [`@clearance/observability-node`](./packages/observability-node) | Opt-in OpenTelemetry bootstrap for Node services. |

## What is next

- Certified interactive SSO flows with Okta and Microsoft Entra ID.
- Hosted-source imports and expanded environment-promotion workflows.
- CLI-driven cloud deployment and production operations.
- Distributed console sessions and horizontally scalable management storage.
- Hardened live-conformance egress with DNS resolution and private-network
  rejection.

## Learn more

- [Security policy](./SECURITY.md)
- [Production operations](./docs/production-operations.md)
- [Framework quickstarts](./apps/framework-quickstarts/README.md)
- [Release notes](https://github.com/clearance-auth/clearance/releases)
- [License and attribution](./LICENSE)
