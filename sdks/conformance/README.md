# Clearance verification contract

`fixture.json` is the language-neutral verification contract. Every official
server SDK consumes the exact signed token and malformed-JWKS cases
without regenerating them.
The private signing key exists only while `generate.mjs` runs and is never
checked in.

All SDKs accept only ES256 JWTs whose selected JWKS member is an EC P-256
verification key (`kty=EC`, `crv=P-256`, `use=sig`, `alg=ES256`) with a unique
`kid` and no unrecognized JWK members. They reject non-standard JSON constants
such as `NaN`, require exact issuer and audience matches, integral `iat`/`exp`
claims, a maximum five-minute `exp - iat` window, and the stable error codes in
the fixture.

`remote_cases` defines the remote-JWKS cache contract: concurrent unknown-key
verification shares the initial load and one forced refresh. A verifier-wide
30-second cooldown bounds attacker-controlled key IDs, while bounded negative
misses expire and normal TTL refreshes remain available.

Reserved Clearance authority claims are:

| Claim | Meaning |
| --- | --- |
| `urn:clearance:claims:subject-kind` | Must be `service_account` when present. |
| `urn:clearance:claims:organization-id` | Service-account organization; present exactly with subject kind. |
| `actions` | Sorted, unique authorization actions. |
| `authz_revision` | Positive PostgreSQL-bigint authorization revision; present exactly with actions. |
| `urn:clearance:claims:session-derivative-authority` | Opaque live-session authority binding. |
| `urn:clearance:claims:session-source-subject` | Bound human source subject. |
| `urn:clearance:claims:session-source-organization` | Bound source organization or `null`. |

A service-account token carries subject kind, organization, actions, and
revision, and never carries session-derivative claims. A session-derived human
token carries all three session-derivative claims; authorization claims, when
present, are paired and require a non-null source organization. A generic human
token carries neither machine nor session-derivative claims. SDKs validate this
grammar; live session/revision authority is enforced by Clearance when a token
is issued or introspected.
