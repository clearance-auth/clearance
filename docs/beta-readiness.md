# Production beta readiness

Evidence captured on 2026-07-13 against the current working tree.

## Verdict

The Clearance software and release machinery are ready for a controlled production beta. Public publication and the first production rollout remain pending external account and infrastructure inputs: the final npm organization/trusted publisher, product GitHub/GHCR namespace, deployment environment, secrets, DNS/TLS, and an operator-owned off-host backup destination.

## Acceptance evidence

- `pnpm verify:real`: `VERIFY_REAL_OK` from the final working tree. This includes runtime typechecks and suites, 2,303 Clearance tests, 213 Postgres-backed management tests, 76 API tests, 76 CLI tests, 62 console tests, 21 sample-application tests, a rendered-browser install-to-use acceptance flow, packaging, strict declaration compilation, and isolated clean imports.
- `scripts/verify-production-ops.sh`: `PASS=77 FAIL=0 SKIP=0`. The live rehearsal covers snapshot-consistent backup, isolated restore verification, immutable upgrade plans, traversal-resistant hook selection, verified rollback references, active database swap, post-safety-write preservation, recovered reversal, fail-closed ambiguous reversal, and source-scoped Prometheus access in trusted-proxy deployments.
- Release artifacts: four Clearance tarballs install in a clean consumer without substitutable Clearance runtime packages or local dependency protocols. Helm, Compose, and Terraform accept immutable `repository@sha256` image references.
- Release workflow: staging images are built with provenance/SBOM, signed and verified at their immutable digests with pinned cosign installer code, and receive final release tags only after verification.
- Dependency audit: zero critical/high production advisories; two moderate advisories remain inherited in the resolved dependency graph.
- Final read-only adversarial review: zero critical and zero high findings. The final focused pass independently verified the operator-token origin binding, rollback recovery, digest/signing order, upgrade-version traversal guard, malicious matching-checksum regression, and single-image production wiring.

## Residual beta risks

- Live SSO/SCIM conformance probes reject plaintext and loopback endpoints, but do not yet resolve and pin DNS or reject every private/link-local address family. Until that policy is hardened, production operators should leave live probes unused or constrain API egress to approved identity-provider and SCIM endpoints. Fixture-based conformance remains available.
- The console uses process-local operator sessions, and the management store remains the documented single-row JSONB design. The beta should use a small operator group and the documented tenant/load envelope.
- Interactive live Okta/Entra sign-in certification remains separate from the implemented read-only discovery/JWKS probes.

## Rollout prerequisites

1. Establish the public npm organization and trusted publisher for `@clearance/*`, including `@clearance/cli` with the `clearance` binary.
2. Set the product GitHub remote and GHCR namespace, then configure protected release environments and keyless signing permissions.
3. Provision production Postgres, secrets, DNS/TLS, monitoring, and the off-host backup copy command.
4. Publish the signed release, verify its npm provenance and container digest, deploy that digest, run health/readiness and browser smoke checks, execute a backup/restore drill, and retain the prior database until the beta observation window closes.
