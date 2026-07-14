# Production beta readiness

Evidence captured on 2026-07-14 against release `v0.2.1` at commit
`47c48a65b7c12833dbfca1b97c01351610f2e984`.

## Verdict

Clearance `v0.2.1` has passed the production-beta engineering, security, publication, and recovery gates. The four public npm packages include trusted provenance, the GitHub release provides a signed asset bundle, and both public GHCR packages expose immutable, keyless-signed application and backup container digests.

## Acceptance evidence

- `pnpm verify:real`: `VERIFY_REAL_OK` from the final release candidate. This includes runtime typechecks and 2,303 runtime tests, 215 Postgres-backed management tests, 82 API tests, 76 CLI tests, 62 console tests, 21 sample-application tests, five rendered-browser/Compose checks, packaging, strict declaration compilation, and isolated clean imports.
- `scripts/verify-production-ops.sh`: `PASS=80 FAIL=0 SKIP=0`. The live rehearsal covers snapshot-consistent backup, isolated restore verification, immutable upgrade plans, traversal-resistant hook selection, verified rollback references, active database swap, post-safety-write preservation, recovered reversal, fail-closed ambiguous reversal, and source-scoped Prometheus access in trusted-proxy deployments.
- Hosted verification: CI passed on Node 22 and 24 with typecheck and Terraform validation; E2E and GitHub Actions security analysis passed on the exact tagged commit. The tag-triggered [release workflow](https://github.com/clearance-auth/clearance/actions/runs/29291719510) completed every signing, publication, registry-integrity, and asset-attachment step.
- Anonymous release verification: the public GitHub API and release downloads worked with GitHub tokens unset. The detached signature, asset manifest, and published tarball checksums all verified.
- Anonymous npm verification: all four exact `0.2.1` packages installed in a clean consumer with npm tokens unset. Library imports and `clearance --version` passed; `npm audit signatures --include-attestations` reported zero invalid or missing signatures, and every provenance bundle binds its registry tarball to tag `v0.2.1` and the exact release commit.
- Anonymous container verification: with GitHub tokens unset and an empty Docker credential store, GHCR issued pull tokens for both public packages. Exact-digest and `0.2.1` tag pulls succeeded for `linux/amd64`; both tags resolved to the signed release digests, and Cosign verified the tag-bound workflow identity and GitHub Actions OIDC issuer for each digest.
- Published-artifact recovery: the npm-installed CLI upgraded a fresh Postgres 16 database from `0.1.4` to `0.2.1`, verified the migration ledger, restored the rollback backup in isolation, created a safety backup, swapped the active database back to `0.1.4`, retained the pre-rollback database, and wrote both recovery receipts. The registry inputs and active-restore receipt are retained in [`docs/evidence`](./evidence/v0.2.1-published-rehearsal.md).
- Release artifacts: four Clearance tarballs install without substitutable Clearance runtime packages or local dependency protocols. Helm, Compose, and Terraform accept immutable `repository@sha256` image references. The signed application digest is `sha256:b061dc44d6f07d7795957174e3b3a4a0e7d918fc94faeb7c8e488725be7f56ff`; the backup digest is `sha256:cb21066bfa94f50904f240502242bc442b79b0f33d0487406d48a697ec049c78`.
- Release workflow: staging images are built with provenance/SBOM, signed and verified at their immutable digests with pinned cosign installer code, and receive final release tags only after verification.
- Dependency audit: zero critical/high/low production advisories; two moderate advisories remain inherited in the resolved dependency graph.
- Final read-only adversarial review: zero critical and zero high findings. The final focused pass independently verified the operator-token origin binding, rollback recovery, digest/signing order, upgrade-version traversal guard, malicious matching-checksum regression, and single-image production wiring.

## Residual beta risks

- Live SSO/SCIM conformance probes reject plaintext and loopback endpoints, but do not yet resolve and pin DNS or reject every private/link-local address family. Until that policy is hardened, production operators should leave live probes unused or constrain API egress to approved identity-provider and SCIM endpoints. Fixture-based conformance remains available.
- The console uses process-local operator sessions, and the management store remains the documented single-row JSONB design. The beta should use a small operator group and the documented tenant/load envelope.
- Interactive live Okta/Entra sign-in certification remains separate from the implemented read-only discovery/JWKS probes.
- Published container images currently target `linux/amd64`; arm64 hosts must use emulation until a multi-architecture image is released.

## Production deployment checklist

1. Provision production Postgres, strong application and operator secrets, DNS/TLS, monitoring, and an operator-owned off-host backup destination.
2. Verify the npm provenance and signed container digest, then deploy that immutable digest through the production Compose or Helm path. For `v0.2.1`, select `linux/amd64` explicitly on arm64 hosts.
3. Run health, readiness, metrics, CLI, console, and browser smoke checks against the deployed environment.
4. Complete a backup and isolated-restore drill before onboarding beta users, and retain the prior database through the beta observation window.
