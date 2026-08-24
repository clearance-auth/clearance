# Clearance verification for Rust

Strict server-side verification for Clearance ES256 access tokens.

```rust,no_run
use clearance_verification::{RemoteOptions, RemoteVerifier};

let verifier = RemoteVerifier::new(RemoteOptions::new(
    "https://auth.example.com",
    "https://api.example.com",
))?;
let bearer_token = "an access token from the Authorization header";
let claims = verifier.verify(bearer_token)?;
println!("{} {:?}", claims.subject, claims.kind);
# Ok::<(), clearance_verification::VerificationError>(())
```

`RemoteVerifier` uses `<issuer>/api/auth/jwks` by default. It requires HTTPS. To use a
loopback HTTP issuer during local development, set
`RemoteOptions::allow_loopback_http` to `true` explicitly. Remote responses,
timeouts, and cache lifetimes are bounded. Unknown key IDs share at most one
refresh per verifier-wide 30-second window, with bounded expiring negative misses.
