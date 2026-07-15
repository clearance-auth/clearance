# Tesseral parity and lead plan

## Live execution ledger

- **Status:** In progress
- **Branch:** `tesseral-parity-and-lead`
- **Canonical ledger:** `/Users/stephenwalker/Code/projects/clearance-auth/plans/2026-07-15-tesseral-comparison-gap-closure-plan.md`
- **Active goal:** `019f636b-e317-7b42-a47d-0f9f8db7de44`
- **Release target:** `0.3.0`
- **Goal:** Make Clearance demonstrably better than Tesseral on every dimension identified in this comparison while preserving Clearance's existing leads.
- **Completion rule:** Every row below must be `Proven ahead`, with direct source, CLI, live-product, operational, or release evidence recorded in this file. A feature without an API and CLI workflow is incomplete. Completion includes a review-ready pull request followed by the signed `0.3.0` release and public-registry verification.
- **Ledger rule:** Update status, evidence, decisions, dependencies, and next actions after each completed implementation unit. Current code and observed behavior remain the source of truth.

### Status legend

- `In progress`: active implementation work.
- `Queued`: accepted work with unmet dependencies.
- `Lead to protect`: Clearance currently leads; regression proof remains required.
- `Proven ahead`: implemented and verified against the stated acceptance bar.

### Dimension ledger

| Dimension | Acceptance bar for Clearance to lead | Status | Evidence |
|---|---|---|---|
| Normalized persistence and query scale | Normalized relational management data, row-level concurrency, online verified migration, stable cursor queries, and measured 5k/50k performance ahead of the snapshot baseline | In progress | Slice 1 storage core landed: default-off core-identity schema, transactional backfill, verified dual writes, fail-closed refresh verification, explicit disable/reconcile, schema-collision and future-version guards; API/CLI/doctor integration and authoritative cutover remain |
| Credential authentication and authorization | Managed keys authenticate by digest; status, expiry, project, environment, and route scopes are enforced; key identity appears in audit; operator token is bootstrap/break-glass only | Proven ahead | Digest-only authentication, expiry/revocation, key-derived scope, route read/write scopes, operator-only topology/recovery/configuration/tests, audit attribution, CLI expiry, and API-key-aware CLI `whoami`; live CLI proof created an expiring key, authenticated `whoami`, listed users, and rejected `users:write` with exit 1 |
| Durable jobs, email, and webhooks | Transactional outbox, separately deployable worker, retries, dead letters, signed delivery, replay, SES/SMTP, quotas, readiness, and complete CLI control | Queued | Runtime verification/reset/invitation delivery can land against the existing relational transaction; management-originated webhooks depend on the store-v2 delivery-intent seam |
| Authentication security | Supported passkeys, TOTP, recovery, factor policy, breached-password defense, account lockout, digest-stored refresh/session secrets, rotating asymmetric access tokens, purpose-separated keys, and KMS providers | Queued | Existing latent JWT, TOTP, HIBP, and management keyring capabilities will be productized |
| Runtime auditability | Append-only login, recovery, factor, session, SSO, SCIM, API-key, invitation, webhook, and impersonation events with actor, target, outcome, network context, and correlation | Queued | Extend the existing redacted atomic management audit design |
| RBAC and tenant credentials | Canonical many-to-many role/action assignments for people and organization service accounts, consistent runtime action claims, immediate revocation/version behavior, API/CLI/UI parity | Queued | Preserve simple built-in roles while supporting composed assignments |
| Hosted login and customer portal | A production-quality `@clearance/vault` covers login, signup, recovery, organization switching, account security, invitations, enterprise connections, API keys, policy, and audit logs | Queued | Starts after foundational identity workflows stabilize |
| Operator console | Typed nested resource UI with accessible components, generated client, complete operational and product workflows, and exact CLI equivalents | Queued | Preserve current security-focused BFF posture |
| Branding, domains, and enterprise setup | Theme/branding, custom-domain verification, email-domain readiness, templates, provider-guided SAML/OIDC/SCIM setup, testing, and actionable failure ownership | Queued | Builds on Vault, worker, and readiness infrastructure |
| Typed API and SDK onboarding | Runtime-validated canonical contract, generated browser/server clients, precise public types, runnable React/Next/Express paths, then Python/Go/Rust verification SDKs with shared conformance fixtures | Queued | Existing in-tree framework/runtime breadth is the implementation base |
| Observability and image portability | OpenTelemetry across HTTP/Postgres/external protocols/jobs, existing Prometheus retained, multi-architecture application/worker/backup images, anonymous digest-pull proof | Queued | Instrument the worker and normalized store as they land |
| CLI and automation | Every workflow is scriptable with stable JSON, noninteractive operation, dry-run/plan where meaningful, structured remediation, and complete API parity | Lead to protect | Existing CLI breadth exceeds Tesseral; add regression/parity proof per new workflow |
| Environment and identity model | Development/preview/production lifecycle and multi-organization principals remain first-class across every new feature | Lead to protect | Existing Clearance model is ahead; every schema and workflow must preserve it |
| SAML and SCIM rigor | Preserve request correlation, replay defense, binding validation, scoped deprovisioning, discovery, session revocation, and fail-closed behavior; close SCIM Groups | Lead to protect | Existing implementation is stronger; SCIM Groups remains queued work |
| Self-hosting, recovery, and release safety | Production Compose/Helm/Terraform, backup/restore/rollback, signed provenance, registry read-back, complete Node matrix, and worker/Vault deployment remain one verified release system | Lead to protect | Existing operations and release gates are ahead; extend them for every new component |

### Active work

- [x] Define and land the storage core for the first reversible store-v2 schema/backfill/verification slice.
- [x] Expose store-v2 plan/status/apply/verify/rollback through the operation registry, API, CLI, and doctor.
- [x] Make managed API keys real `/v1` authenticators with route-scope enforcement and attribution.
- [ ] Define the outbox transaction seam against store-v2 so job delivery never races product state.
- [x] Record targeted verification and update dimension statuses for the first mergeable foundation unit.

### Execution log

| Date | Change | Evidence / next action |
|---|---|---|
| 2026-07-15 | Created branch `tesseral-parity-and-lead` and activated the plan-linked goal | Goal `019f636b-e317-7b42-a47d-0f9f8db7de44`; begin credential enforcement and store-v2 foundation |
| 2026-07-15 | Started managed API-key implementation lane | Inspect live authentication middleware and add narrowly scoped tests; manager verification required |
| 2026-07-15 | Started read-only store-v2 implementation-slice review | Select a reversible first slice that preserves the existing JSON backend and avoids speculative rewrites |
| 2026-07-15 | Set terminal release target to `0.3.0` | Open a review-ready PR after implementation and complete proof; release only after approval and the full release gate |
| 2026-07-15 | Accepted store-v2 Slice 1 boundary | Normalize projects, environments, principals, and organizations behind explicit apply; snapshot stays authoritative during verified shadow mode; storage implementation started |
| 2026-07-15 | Accepted delivery-plane dependency boundary | Runtime email outbox may precede store-v2; management webhook emission waits for transactional delivery intents; encrypted payloads and signed HTTPS delivery are mandatory |
| 2026-07-15 | Implemented managed API-key authentication | Full API suite 88/88, focused auth/security 5/5, management key lifecycle 6/6, CLI auth and transport 18/18; API, management, and CLI typechecks green |
| 2026-07-15 | Proved managed-key operation through the live API and CLI | CLI created an expiring scoped key, `whoami` identified the key and exact scopes, `users list` succeeded, and `users create` failed with `API_KEY_SCOPE_FORBIDDEN` and exit 1; live proof artifacts moved to Trash |
| 2026-07-15 | Landed store-v2 Slice 1 storage core | Pure helpers 4/4; canonical real-Postgres regression 34/34 across shadow, revision drift, atomic swaps, environment reparenting, concurrency, user lifecycle, and organization lifecycle; management typecheck and diff check green |
| 2026-07-15 | Hardened store-v2 adoption boundaries during manager review | Apply refuses unowned target-table collisions, invalid phase metadata, and future schema versions without touching external data |
| 2026-07-15 | Completed store-v2 control-plane integration | Stable registry/API/CLI envelopes for status, plan, apply, verify, and rollback; two-sided confirmation, doctor visibility, structured failure, operation contracts 9/9, API operations 5/5, CLI transport 11/11 |
| 2026-07-15 | Closed two strict security reviews on the foundation | Fixed missed-writer revision masking, valid unique swaps and environment reparenting, forged enterprise audit actors, raw settings exposure, expired rotation and dry-run, case-variant staging, and SCIM SSRF using all-answer validation, global-unicast policy, pinned DNS, redirect refusal, and operator-only enterprise probes; final review reported no blocker |
| 2026-07-15 | Committed the first mergeable foundation unit | Commit `ca361e7` contains managed API authorization, store-v2 shadow/control plane, strict-review hardening, live-ledger evidence, and no live secret material |
| 2026-07-15 | Selected first relational-authority cutover | Audit events move first into a hybrid authoritative store: immutable append cost becomes O(1), the JSON backend remains unchanged, rollback reverse-materializes the visible projection, and 5k/50k production-path append benchmarks gate acceptance; storage implementation started |
| 2026-07-15 | Froze the delivery-plane transaction and security boundary | Runtime email only in Slice 1; product state plus immutable event, encrypted payload, and initial job must use the ambient runtime adapter transaction; no pool, second Kysely instance, background helper, or post-commit hook; management webhooks remain deferred |
| 2026-07-15 | Started delivery storage/worker-core implementation | New `@clearance/delivery` package is limited to guarded schema migration, purpose-specific AEAD/HMAC keyring, transaction-adapter enqueue, fenced leasing/retry/dead/cancel/reclaim, retention crypto-erasure, redacted views, and Postgres proof; SMTP/runtime/API/CLI/deploy wiring follows after core review |

### Current implementation decisions

- Store-v2 Slice 1 is default-off and Postgres-only. It adds a core-identity relational shadow for projects, environments, principals, and organizations; explicit plan/apply/status/verify/rollback operations control adoption.
- The snapshot remains authoritative through Slice 1. Every Postgres mutation path writes the shadow representation in the same transaction and advances a relational revision marker. Divergence fails verification without exposing PII.
- Slice 1 deliberately retains the existing snapshot cost. The persistence dimension stays `In progress` until relational reads/writes cut over and the 5k/50k benchmarks prove flat changed-row performance.
- Delivery uses Postgres-native immutable events, leased jobs, attempts, and worker heartbeats. Payloads and endpoint secrets are encrypted under a purpose-specific rotating keyring.
- Runtime verification, reset, and invitation email jobs use their existing relational transaction context. Management-originated webhooks wait for a store-v2 unit-of-work delivery-intent seam.
- Delivery semantics are at-least-once with stable event IDs, bounded full-jitter retries, dead-letter state, CLI retry/cancel/replay, exact-byte HMAC signatures, and production SSRF controls.
- Runtime delivery uses a distinct durable enqueue capability. Signup uses its existing adapter transaction; reset and invitation state changes must be wrapped with `runWithTransaction` and enqueue through `getCurrentAdapter`. Legacy background email callbacks and `queueAfterTransactionHook` are prohibited because they leave post-commit loss windows.
- Delivery persistence separates immutable event metadata, encrypted expiring payloads, jobs, append-only attempts, and worker heartbeats. Recipient, subject, body, URLs, reset/verification tokens, and invitation details remain inside a purpose-specific AES-256-GCM envelope; keyed fingerprints support quotas and deduplication without plaintext PII.

### Terminal PR and `0.3.0` release gate

- [ ] Freeze all source, schema, package-version, deployment, and release-workflow changes.
- [ ] Confirm every dimension in this ledger is `Proven ahead` with direct evidence.
- [ ] Run targeted verification for each completed unit, then the exact local release rehearsal.
- [ ] Run the complete CI matrix under every supported Node version.
- [ ] Review the full branch diff for correctness, security, generated artifacts, prohibited references, and release consistency.
- [ ] Push the branch once and open a review-ready pull request describing the ledger, implementation, migrations, operational impact, and verification evidence.
- [ ] Resolve every actionable review thread and rerun only the proof invalidated by review changes.
- [ ] Create the immutable `v0.3.0` tag only after the candidate and guarded tag workflow are proven.
- [ ] Publish `0.3.0` through the tag-triggered release path with signed provenance, SBOMs, signatures, and exact tag-commit binding.
- [ ] Verify SHA-512 integrity and signed provenance from the public npm registry, retrying first-publish read-back for up to ten minutes.
- [ ] Verify anonymous installation and anonymous multi-architecture image/chart pulls by immutable digest.
- [ ] Attach final evidence to the release and mark the goal complete only after public visibility is confirmed.

## Comparison baseline

Downloaded Tesseral to [tesseral-reference](/Users/stephenwalker/Code/projects/tesseral-reference) and pinned the comparison to public `main` commit `de5d3348380b820b2670c96728d36e456f696538` from September 10, 2025. Clearance was inspected at `969d6d2901a4a45421cdf27e06caf4ad3b2ed553`, including the current uncommitted worktree.

## Executive verdict

Tesseral is currently the more complete auth product. Its lead comes from customer-facing workflows, a normalized service architecture, durable delivery infrastructure, and productized authentication security.

Clearance is already stronger as an open-source, operator-controlled platform. Its CLI, environment lifecycle, multi-organization identity model, deployment artifacts, recovery tooling, protocol rigor, and release supply chain are materially better.

| Area | Leader | Assessment |
|---|---|---|
| Hosted login and customer portal | Tesseral | Decisive |
| Console and administrative UX | Tesseral | Decisive |
| Database and async architecture | Tesseral | Decisive |
| MFA, passkeys, invitations, branding | Tesseral | Decisive |
| CLI and automation | Clearance | Decisive |
| Self-hosting, recovery, release safety | Clearance | Decisive |
| SAML and SCIM protocol rigor | Clearance | Meaningful |
| Environment and multi-org identity model | Clearance | Meaningful |
| SDK onboarding | Tesseral | Current advantage |
| Runtime/framework implementation breadth | Clearance | Latent advantage |

## Where Tesseral is better

1. **It ships the complete end-user product layer.**

   Tesseral’s Vault covers login, signup, recovery, account security, organization administration, invitations, API keys, audit logs, SAML, OIDC, and SCIM, including guided Google, Entra, and Okta setup flows ([Vault routes](/Users/stephenwalker/Code/projects/tesseral-reference/vault-ui/src/App.tsx:118)). Clearance currently exposes a basic sample application and generic SSO/SCIM setup capability links.

2. **Its operator console models the actual product.**

   Tesseral has nested pages for organizations, users, sessions, passkeys, roles, API keys, authentication policy, enterprise connections, branding, and domains ([console routes](/Users/stephenwalker/Code/projects/tesseral-reference/console/src/App.tsx:91)). Clearance’s console remains a small flat application centered on operational resource lists ([current routes](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-console/public/app.js:13)).

3. **Its core database is designed for scale and querying.**

   Tesseral uses normalized PostgreSQL tables, `sqlc`, and 95 numbered schema migrations. Clearance’s management service still stores global state in one JSONB row, serializes writes with `FOR UPDATE`, rewrites the snapshot, and rebuilds uniqueness tables on mutation ([snapshot store](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/store/pg-store.ts:1)). The repository already documents the appropriate normalized replacement in [DESIGN-store-v2.md](/Users/stephenwalker/Code/projects/clearance-auth/DESIGN-store-v2.md:159).

4. **It has a durable delivery plane.**

   Tesseral transactionally enqueues verification, reset, invitation, and webhook jobs, then processes them through a separately deployed River worker. Clearance enables email/password without a configured verification or reset delivery implementation ([product factory](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-auth/src/create-auth.ts:175)). There is currently no application worker, transactional outbox, webhook delivery, retry, dead-letter, or replay system.

5. **MFA, passkeys, RBAC, and invitations are finished workflows.**

   Tesseral persists WebAuthn credentials, TOTP authenticators, recovery codes, lockout state, invitations, many-to-many role assignments, and organization API-key roles. Clearance contains a latent two-factor plugin, while the product bundle only wires organization, SSO, and SCIM ([plugin construction](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-auth/src/create-auth.ts:112)). Passkey implementation and invitation operations are absent from the shipped product surface.

6. **Its token and key architecture is more mature.**

   Tesseral stores refresh-token digests, issues five-minute asymmetric access tokens containing resolved actions, and protects rotating per-project signing keys with AWS/GCP KMS abstractions ([access-token issuance](/Users/stephenwalker/Code/projects/tesseral-reference/internal/common/store/accesstoken.go:25)). Clearance has capable JWT machinery in its runtime, though the product does not expose it as the canonical session/access-token architecture.

7. **Its application integration story is clearer.**

   Tesseral documents React, Next.js, Express, Python, Go, and Rust integrations. Clearance has broad framework and datastore code in-tree, while its public product types still include `any` and `unknown` surfaces ([public runtime types](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-auth/src/public-types/index.ts:51)) and framework onboarding remains thin.

## Clearance’s most serious gaps

- **Managed API keys currently do not authenticate management API calls.** `/v1` still uses the single `CLEARANCE_OPERATOR_TOKEN`. Created key digests and scopes are lifecycle metadata rather than an enforced authorization boundary.

- **Runtime identity activity is missing from the audit ledger.** Management mutations are recorded and redacted well; login, factor, session, SSO, SCIM, and recovery activity needs the same append-only audit sink.

- **Session compromise has a larger blast radius than necessary.** Opaque session values are stored directly. The optional bearer plugin accepts unsigned input by default. Move to token digests, short-lived asymmetric access tokens, refresh rotation, and reuse detection.

- **Custom RBAC is disconnected from application authorization.** Management stores permissions, while runtime membership receives a role slug and sessions lack resolved action claims.

- **Credential purpose separation is incomplete.** Runtime OIDC and SCIM credentials reuse the general auth secret. The existing management keyring is a good foundation for separated key domains and external KMS providers.

## Where Clearance should preserve its lead

- The CLI already covers projects, environments, users, organizations, sessions, roles, SSO, SCIM, diagnostics, migrations, backups, restores, and upgrades ([CLI commands](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-cli/src/index.ts:93)). Tesseral’s CLI is primarily bootstrap and database migration tooling.

- Clearance explicitly models development, preview, and production environments. Tesseral lacks that dimension.

- Clearance separates principals from organization memberships, allowing one identity to belong to several organizations. Tesseral directly associates each user record with one organization.

- Clearance has production Compose, Helm, Terraform, NetworkPolicy, PDB, ServiceMonitor, backup scheduling, restore verification, and rollback guidance. Tesseral’s checked-in deployment stack is development-oriented.

- Clearance’s SAML correlation, replay prevention, destination validation, and default rejection of IdP-initiated login are stronger. Its SCIM implementation also has broader discovery, deprovisioning, and session-revocation behavior.

- Clearance’s signed release, provenance, registry-readback, backup, and recovery discipline is substantially stronger.

## Recommended closure sequence

1. **Normalize management persistence.** Execute store-v2 using expand/backfill, dual writes or equivalent compatibility, checksum verification, cutover, and CLI-visible migration status.

2. **Make credentials real authorization boundaries.** Authenticate managed API keys by digest, enforce project/environment/status/expiry/scopes, attribute audits to key IDs, and retain the operator token only for bootstrap or break-glass use.

3. **Add the durable worker plane.** Implement a transactional outbox, bounded retries, dead-letter state, signed webhooks, SES/SMTP email, and CLI commands for inspection, retry, cancellation, replay, and readiness.

4. **Finish the identity security product.** Productize the existing JWT, TOTP, and breached-password capabilities; add WebAuthn/passkeys, invitation lifecycle, factor policy, recovery, lockout, asymmetric access tokens, KMS providers, and runtime audit events.

5. **Ship `@clearance/vault`.** Cover hosted login/signup/recovery, organization switching, account security, invitations, customer-managed enterprise connections, API keys, and audit logs.

6. **Rebuild the console around typed nested resources.** Use the canonical operation registry to generate runtime schemas and browser/server clients. Preserve exact CLI equivalents for every mutation.

7. **Complete the ecosystem.** Add React/Next/Express guides first, then thin Python/Go/Rust verification libraries, OpenTelemetry tracing, branding/domains, and multi-architecture images.

The strongest direction is to retain Clearance’s CLI and operations model while adopting Tesseral’s product completeness, normalized persistence, worker architecture, and security workflow coverage.
