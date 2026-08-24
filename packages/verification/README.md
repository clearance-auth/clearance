# `@clearance/verification`

Strict, dependency-free server verification for Clearance ES256 access tokens.

The canonical human and service-account claim grammar lives in the
[shared conformance contract](https://github.com/clearance-auth/clearance/blob/main/sdks/conformance/README.md),
alongside the fixed fixture consumed by every server SDK.

```ts
import { createRemoteVerifier } from "@clearance/verification";

const verifier = createRemoteVerifier({
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
});

const claims = await verifier.verify(bearerToken);
if (claims.kind === "service_account") {
  console.log(claims.organizationId, claims.actions);
}
```

The default key endpoint is `<issuer>/api/auth/jwks`. Configure `jwksUrl` when
keys are hosted elsewhere. HTTPS is mandatory. Local HTTP requires the explicit
`allowInsecureLoopback: true` development option and is still limited to
loopback hosts. Unknown key IDs share one forced JWKS refresh, followed by a
30-second cache-wide refresh cooldown.
