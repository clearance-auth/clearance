# Clearance verification for Go

Standard-library server verification for Clearance ES256 access tokens.

The canonical claim grammar and shared fixed fixture are documented in the
[shared conformance contract](https://github.com/clearance-auth/clearance/blob/main/sdks/conformance/README.md).

```go
verifier, err := verification.NewRemoteVerifier(verification.RemoteOptions{
    Issuer:   "https://auth.example.com",
    Audience: "https://api.example.com",
})
claims, err := verifier.Verify(ctx, bearerToken)
```

The verifier uses `<issuer>/api/auth/jwks` by default and requires HTTPS. Development
HTTP needs `AllowInsecureLoopback: true` and remains limited to loopback hosts.
It bounds network reads and caches key sets. Unknown key IDs share one refresh
followed by a 30-second cache-wide refresh cooldown.
