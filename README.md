# Clearance

Open-source authentication for B2B software, self-hosted on Postgres.

Clearance gives your product sign-in, organizations, roles, enterprise SSO and
SCIM, transactional delivery, and the operating tools to run them. The CLI,
management API, and operator console use the same management plane, so your
team can automate routine work and investigate the same state in a browser.

**Current release:** [0.3.1](https://github.com/clearance-auth/clearance/releases/tag/v0.3.1)

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
| Operator experience | A typed management API, JSON-first CLI, dark operator console, scoped audit events, imports, backups, restore drills, and upgrades. |
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
package installs the `clearance` command. Run `clearance` in a terminal for
guided, copyable workflows or `clearance tui` for the operations workspace.
Every interactive action has an equivalent command for scripts and agents.

```bash
npm install --global @clearance/cli
export CLEARANCE_OPERATOR_TOKEN='<operator-token>'
clearance login --profile production --url https://auth.example.com

clearance --profile production init --name my-app --json --no-input
clearance --profile production orgs create --name Acme --json --no-input
clearance --profile production users create \
  --email owner@example.com --name 'Acme Owner' --json --no-input
clearance --profile production readiness check --org <organization-id> --json --no-input
```

The CLI selects readable terminal output for people and JSON when stdout is
piped. Use `--output-format human|json|jsonl|quiet` to choose explicitly,
`--jq '.data.id'` for built-in field selection, and `--no-input` or
`CLEARANCE_NONINTERACTIVE=1` to guarantee that no prompt is opened.

```bash
clearance commands --json                 # versioned command and safety catalog
clearance completion zsh                  # bash, zsh, and fish are supported
clearance skill install --dry-run --json  # inspect the agent-skill installation
clearance --profile production tui        # interactive operations workspace
```

Explicit `--output-format json` and inferred piped JSON use an `ok`, `data`,
`summary`, `notice`, `next`, and `meta` envelope. The legacy `--json` flag
continues to emit the raw result for compatibility. Errors include a stable
code, stage, retryability, and remediation, with distinct process statuses for
invalid input, authentication, temporary failure, service failure, and failed
health checks.

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
| [`@clearance/cli`](./packages/clearance-cli) | JSON-first operational CLI. |
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
