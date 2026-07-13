# Compatibility

Clearance uses the `@clearance/*` npm scope and installs the `clearance` CLI binary.

## Package map

| Package | Role |
|---|---|
| `@clearance/runtime` | Authentication runtime and framework integrations |
| `@clearance/core` | Shared runtime contracts and primitives |
| `@clearance/utils` | Encoding and cryptographic utilities |
| `@clearance/auth` | Product entry point and secure defaults |
| `@clearance/sso` | SAML and OIDC enterprise SSO |
| `@clearance/scim` | SCIM directory provisioning |
| `@clearance/management` | Management-plane services |
| `@clearance/cli` | CLI package |
| `@clearance/api` | Management HTTP API |
| `@clearance/console` | Operator console |

## Migration imports

The migration commands accept validated JSON fixtures whose `source` field is `"legacy"`. Clearance rejects other source identifiers, validates the full fixture before mutation, and supports plan, apply, verify, and rollback workflows.

## Schema and releases

The management schema and runtime packages are versioned under Clearance release policy. Release artifacts are built from committed, tagged source and checked for consistent package, image, chart, and API versions before publication.
