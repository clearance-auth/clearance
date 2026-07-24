# Next.js App Router quickstart

`app/api/me/route.ts` verifies route-handler requests.
`app/server-claims/page.tsx` demonstrates the same verifier in a server
component. Both consume the shared `@clearance/verification` package.

```sh
export CLEARANCE_ISSUER="https://auth.example.com"
export CLEARANCE_AUDIENCE="https://api.example.com"
export CLEARANCE_JWKS_URL="https://auth.example.com/api/auth/jwks"
pnpm --filter @clearance/framework-quickstarts dev:next
```

Open `http://localhost:3000`. The verifier requires HTTPS for issuer and JWKS
URLs. A loopback development endpoint additionally requires
`CLEARANCE_ALLOW_INSECURE_LOOPBACK=true`.
