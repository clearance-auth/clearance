# Clearance v0.2.1 security review

## Executive summary

A focused independent adversarial review of the v0.2.1 release candidate found no unresolved critical or high vulnerabilities. The review covered authentication, authorization, replay protection, credential lifecycle, request boundaries, the operator console, database recovery, immutable deployment, and the tag-bound npm and container release path.

The final release-delta pass was completed on 2026-07-13 by Anthropic Claude Fable 5 in a read-only CLI session restricted to `Read`, `Grep`, and `Glob`. The exact reviewer identity, session/result identifiers, findings, and dispositions are retained in [`docs/evidence/v0.2.1-external-security-review.json`](./evidence/v0.2.1-external-security-review.json).

## Critical findings

None.

## High findings

None.

## Reviewed controls

- Deprecated SAML signature, digest, and encryption algorithms reject by default, while unrecognized algorithms fail closed (`packages/sso/src/saml/algorithms.ts:180`, `packages/sso/src/saml/algorithms.ts:201`, `packages/sso/src/saml/algorithms.ts:214`).
- SAML assertions require a replay-stable ID and reserve it atomically before user or session creation (`packages/sso/src/routes/saml-pipeline.ts:178`, `packages/sso/src/routes/saml-pipeline.ts:455`, `packages/sso/src/routes/saml-pipeline.ts:465`).
- Administrative user creation removes the sign-up session; passwordless provisioning returns a random, one-hour, single-use setup token backed by the runtime reset flow (`packages/management/src/auth-bridge.ts:177`, `packages/management/src/auth-bridge.ts:211`, `packages/management/src/auth-bridge.ts:231`, `packages/management/src/auth-bridge.ts:237`).
- Idempotency persistence removes password-setup tokens and other one-time credentials from replay bodies (`packages/clearance-api/src/server.ts:507`, `packages/clearance-api/src/server.ts:519`, `packages/clearance-api/src/server.ts:532`).
- The API enforces its request-size limit against both declared and streamed body sizes before Hono authentication or parsing (`packages/clearance-api/src/server.ts:2909`, `packages/clearance-api/src/server.ts:2913`, `packages/clearance-api/src/server.ts:2921`, `packages/clearance-api/src/server.ts:2946`).
- The operator console applies a same-origin CSP, denies framing, keeps the upstream operator token server-side, and requires an authenticated session plus CSRF validation for logout (`packages/clearance-console/src/server.js:454`, `packages/clearance-console/src/server.js:459`, `packages/clearance-console/src/server.js:670`, `packages/clearance-console/src/server.js:681`).
- Terraform accepts only immutable `repository@sha256` application images (`deploy/terraform/variables.tf:16`).
- First publication is tag-triggered, every dispatch is recovery-only, and npm provenance verification binds registry bytes to the exact release tag and commit (`.github/workflows/release-sign.yml:123`, `scripts/verify-npm-provenance.mjs:118`).
- Upgrade hooks update the durable release marker and append the migration ledger entry through one conditional SQL statement, preserving safe retry if the guarded update loses a race (`deploy/upgrades/steps/0.2.1/apply.sh:39`).

## Verification evidence

- Focused SAML algorithm and replay-ID regressions: 46 passed.
- Real Postgres password-setup and user-lifecycle suite: 7 passed.
- API idempotency and one-time-secret replay suite: 9 passed.
- Production dependency audit: 0 critical, 0 high, 0 low, and 2 moderate advisories.
- Independent read-only adversarial review of the product and final release-path delta: 0 critical and 0 high findings.
- The review's one medium finding, a retry-blocking TOCTOU in the `0.2.1` upgrade hook, was fixed before release by making the ledger insert conditional on the guarded snapshot update in one CTE.

## Design constraints below the release threshold

- SAML integrations should send an explicit signature algorithm; cryptographic verification remains authoritative when the binding omits the optional algorithm hint.
- Idempotency prevents replay after a response is stored; simultaneous first requests with the same key are not serialized by the in-process development backend.
- Backup and upgrade artifact paths are operator-controlled server paths and therefore require the operator token to remain restricted to trusted production administrators.
