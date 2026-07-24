# Clearance framework quickstarts

This private workspace contains three compile-checked integration paths. React
uses the real Clearance browser client for sign-in and cookie-backed session
state. Express and Next keep ES256 token verification on the server through
`@clearance/verification`.

| Quickstart | Run command |
| --- | --- |
| React browser app | `pnpm --filter @clearance/framework-quickstarts dev:react` |
| Next.js App Router | `pnpm --filter @clearance/framework-quickstarts dev:next` |
| Express API | `pnpm --filter @clearance/framework-quickstarts dev:express` |

Compile all three:

```sh
pnpm --filter @clearance/framework-quickstarts typecheck
```

These commands resolve workspace packages through the `dev-source` export
condition, so a clean checkout does not need ignored `dist` output.

Before starting any example, set these variables in its shell:

```sh
export CLEARANCE_ISSUER="https://auth.example.com"
export CLEARANCE_AUDIENCE="https://api.example.com"
export CLEARANCE_JWKS_URL="https://auth.example.com/api/auth/jwks"
export VITE_CLEARANCE_URL="https://auth.example.com"
```

`@clearance/verification` accepts HTTPS issuer and JWKS URLs. For an explicit
loopback-only development server, set `CLEARANCE_ALLOW_INSECURE_LOOPBACK=true`
as well as loopback issuer/JWKS URLs. Do not use HTTP for a deployed issuer or
JWKS endpoint.

The browser never receives a JWKS URL. Express and Next accept a bearer token
at their own server boundary and verify it before returning claims.
