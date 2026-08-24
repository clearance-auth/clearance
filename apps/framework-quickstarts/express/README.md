# Express quickstart

The `requireClearanceToken` middleware verifies a bearer token before the
protected `/me` route receives it.

```sh
export CLEARANCE_ISSUER="https://auth.example.com"
export CLEARANCE_AUDIENCE="https://api.example.com"
export CLEARANCE_JWKS_URL="https://auth.example.com/api/auth/jwks"
pnpm --filter @clearance/framework-quickstarts dev:express

curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:3000/me
```

The remote issuer and JWKS URLs must use HTTPS. For an explicit loopback
development server such as `http://localhost:8787/api/auth/jwks`, also set
`CLEARANCE_ALLOW_INSECURE_LOOPBACK=true`.
