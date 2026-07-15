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
