# `clearance-verification` for Python

Server verification for Clearance ES256 access tokens, cryptography-backed by
`cryptography`'s audited P-256 implementation. It has one runtime dependency:
`cryptography`.

The canonical claim grammar and shared fixed fixture are documented in the
[shared conformance contract](https://github.com/clearance-auth/clearance/blob/main/sdks/conformance/README.md).

```python
from clearance_verification import RemoteVerifier

verifier = RemoteVerifier(
    issuer="https://auth.example.com",
    audience="https://api.example.com",
)
claims = verifier.verify(bearer_token)
print(claims.subject, claims.kind)
```

The default key URL is `<issuer>/api/auth/jwks`. HTTPS is required. Local HTTP needs
`allow_insecure_loopback=True` and remains restricted to loopback hosts.
`RemoteVerifier` caches bounded JWKS responses. Unknown key IDs coalesce with
an in-flight load and share a verifier-wide, bounded 30-second cooldown.
