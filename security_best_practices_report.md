# Clearance security review

Date: 2026-08-13

Scope: the working tree reviewed before remediation, followed by verification of the remediated current working tree. Coverage includes the runtime authentication core, management API and CLI operations, SSO/SAML/OIDC, SCIM, delivery worker, operator console, vault and client packages, deployment assets, and production dependency graph. No deployed environment was tested.

Remediation status: **complete in the current working tree**. All six confirmed findings and both conditional risks described below have code, contract, test, or dependency remediations. The detailed finding sections preserve the original vulnerable-state evidence; the remediation record below is authoritative for the current tree.

## Executive summary

The review found one high-severity vulnerability, three medium-severity vulnerabilities, two low-severity vulnerabilities, and two conditional risks. I found no critical-severity vulnerability and no confirmed authentication or tenant-isolation bypass in the core runtime.

The completed fixes add a bounded console request boundary, move remote upgrade filesystem and network targets into server configuration, enforce algorithms from verified SAML XML, reject SAML DTDs and disable entity processing, normalize malformed SCIM credentials to 401, add replay-aware webhook verification, and refresh the directly actionable dependency set.

## Remediation record

- **SEC-001 resolved:** malformed cookie encoding returns `400 MALFORMED_COOKIE`; unexpected request failures return a generic 500 or close an already-started response without producing an unhandled rejection. Console tests also prove post-error liveness.
- **SEC-002 and SEC-005 resolved:** remote upgrade routes reject caller-supplied `dir`, `backupDir`, and `healthUrl`. The API injects `CLEARANCE_UPGRADE_DIR` and optional `CLEARANCE_UPGRADE_HEALTH_URL`, fails closed when upgrade storage is absent, and the remote contracts, generated client metadata, and CLI no longer expose those inputs. Direct local management functions retain explicit local targets.
- **SEC-003 resolved:** after samlify verifies the signature, Clearance validates every direct Response/Assertion signature candidate it may accept. Missing, duplicate, off-path, mixed, unknown, disallowed, and deprecated signature or digest methods fail closed; matching dual signatures and supported RSA-PSS remain valid. Encrypted assertion algorithm checks follow the direct encrypted data/key chain.
- **SEC-004 resolved:** `fast-xml-parser` resolves to 5.10.1. Application XML parsing is centralized with `processEntities: false`, and inbound login/logout SAML rejects `DOCTYPE` before samlify parsing.
- **SEC-006 resolved:** strict Base64 and fatal UTF-8 decoding failures, malformed token shapes, and invalid credentials produce the same bounded SCIM 401 response without credential disclosure.
- **Webhook conditional risk resolved:** `verifyWebhookRequest` authenticates exact raw bytes, enforces a five-minute default age and bounded future skew, and requires an atomic caller-provided event-ID consumer. The legacy helper remains explicitly authenticity-only for source compatibility.
- **Dependency conditional risk resolved:** Next.js resolves to 16.3.0, clearing the reported Next, Sharp, and PostCSS advisories. Directly actionable XML parser, Hono, Nodemailer, and Google Cloud KMS dependency findings were also refreshed without blanket overrides.

## Verification record

- Frozen install, root build, and root typecheck passed on Node 22.23.2 and Node 24.18.0.
- On Node 24.18.0, remediation-focused suites passed: console 62, upgrade API 16, upgrade CLI 11, webhook 15, SCIM 30, and focused SAML 79 tests (213 total). The complete SAML package suite separately passed 449 tests with 2 existing todo cases.
- The Node 22 root suite reached 3,210 passing tests, 9 skipped, and 1 todo before two failures in pre-existing, user-owned runtime work: a trusted-device assertion in `two-factor.security.test.ts` and a PostgreSQL team-concurrency timeout. Those files were preserved and are outside this report's remediation diff.
- `git diff --check` passed.
- `pnpm audit --prod` improved from 35 advisories (15 high, 18 moderate, 2 low) to 6 (2 high, 4 moderate, 0 low, 0 critical). The remaining paths are Prisma development/local tooling (`fast-uri`, `@hono/node-server`, `valibot`) and Drizzle development tooling (`esbuild`); no reviewed application runtime or quickstart imports those affected development servers or utilities.

## Confirmed findings (resolved; vulnerable-state evidence retained)

### SEC-001 — High — Malformed cookie terminates the operator console — Resolved

**CWE:** CWE-248 (Uncaught Exception), CWE-400 (Uncontrolled Resource Consumption)

**Evidence:** `packages/clearance-console/src/server.js:268-290`, `packages/clearance-console/src/server.js:690-727`, `packages/clearance-console/src/server.js:928-979`, `packages/clearance-console/src/server.js:985-995`.

`parseCookies` applies `decodeURIComponent` to every cookie value without handling malformed percent escapes. Any non-public `/api/*` path calls `getSessionFromRequest` before authentication succeeds. The async HTTP listener has a `try/finally` and no `catch`, and `createServer` does not consume the returned promise.

**Exploit:** send a request such as `GET /api/v1/users` with `Cookie: probe=%`. No session or operator credential is required.

**Impact:** one request terminates the console process under Node 22, taking the administrative UI and management proxy offline until a supervisor restarts it.

**Validation:** a live ephemeral console server on Node v22.23.2 exited with status 1 and an uncaught `URIError: URI malformed` originating at `server.js:289`.

**Remediation:** parse each cookie defensively. Catch URI decoding failures and either retain the raw value or reject the request with 400. Add a top-level request error boundary that always converts handler failures to a bounded 4xx/5xx response and never lets an async listener rejection escape.

### SEC-002 — Medium — Operator-only SSRF through upgrade health verification — Resolved

**CWE:** CWE-918 (Server-Side Request Forgery)

**Evidence:** `packages/clearance-api/src/routes/operations.ts:192-200`, `packages/clearance-api/src/request-auth.ts:81-92`, `packages/management/src/services/upgrade.ts:83-91`, `packages/management/src/services/upgrade.ts:233-248`, `scripts/upgrade-verify.sh:69-74`.

The remote `/v1/upgrades/verify` endpoint accepts `healthUrl`. Validation checks only that it is credential-free HTTP(S) without a query or fragment. The server then invokes `curl` against the supplied URL. Loopback, link-local, private, IPv6-local, and internal DNS destinations are accepted.

**Exploit prerequisite:** the bootstrap operator bearer token and a valid upgrade plan state.

**Impact:** an operator-token holder can make the API host issue GET requests to internal services and cloud metadata addresses. The response is blind beyond success/failure, though it still permits internal service discovery and GET side effects.

**Remediation:** remove the arbitrary URL from the remote API and derive the health endpoint from server configuration. If arbitrary endpoints remain necessary, enforce an origin allowlist, reject non-public IP ranges after every DNS resolution, pin the resolved address, and keep redirects disabled.

### SEC-003 — Medium — SAML POST signatures bypass the configured algorithm policy — Resolved

**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

**Evidence:** `packages/sso/src/routes/saml-pipeline.ts:345-378`, `packages/sso/src/saml/algorithms.ts:172-207`, `packages/sso/src/saml/algorithms.ts:256-265`, `packages/sso/src/saml/algorithms.test.ts:138-156`.

`validateSAMLAlgorithms` validates only `response.sigAlg`. In the installed `samlify` POST-binding flow, the parse result contains `samlContent` and `extract`; `sigAlg` is populated for detached SimpleSign/redirect parameters, not for an embedded XML Digital Signature. Ordinary SAML POST responses therefore reach the policy check with `sigAlg` undefined, and the validator deliberately returns early. `allowedDigestAlgorithms` is not applied to the response XML at all.

Cryptographic signature verification still occurs. The defect is a policy bypass: a response signed by the configured IdP certificate can use an XML `SignatureMethod` or `DigestMethod` that Clearance's default or custom policy intends to reject, including SHA-1.

**Impact:** deployments cannot reliably enforce their declared SAML cryptographic baseline. Continued acceptance of SHA-1 increases exposure to weaknesses in deprecated algorithms and creates a compliance gap.

**Remediation:** after cryptographic verification, extract `SignatureMethod/@Algorithm` and every signed `Reference/DigestMethod/@Algorithm` from the verified signed subtree. Apply `allowedSignatureAlgorithms`, `allowedDigestAlgorithms`, and the deprecated-algorithm behavior to those exact values. Reject missing, mixed, or unknown methods.

### SEC-004 — Medium — Vulnerable XML entity expansion remains enabled in one signed-SAML parser — Resolved

**CWE:** CWE-776 (Improper Restriction of Recursive Entity References in DTDs)

**Evidence:** `packages/sso/package.json:67-72`, `pnpm-lock.yaml:3681-3683`, `packages/sso/src/saml/parser.ts:3-8`, `packages/sso/src/routes/saml-pipeline.ts:208-215`, `packages/sso/src/routes/saml-pipeline.ts:274-280`, `packages/sso/src/routes/saml-pipeline.ts:517-523`.

The lockfile resolves `fast-xml-parser` 5.9.3, which is affected by [GHSA-8r6m-32jq-jx6q](https://github.com/advisories/GHSA-8r6m-32jq-jx6q); 5.10.1 is the patched release. The shared parser correctly disables entity processing, while `extractAssertionId` constructs a separate parser with the vulnerable default enabled.

The vulnerable parser runs after `samlify` verifies the response signature, so exploitation requires control of a configured IdP signing key or another way to obtain a valid signature over the crafted XML. The 256 KiB response limit reduces raw input size and does not stop recursive entity expansion.

**Impact:** a malicious or compromised configured IdP can submit a compact signed SAML response that consumes excessive CPU or memory and may terminate the application process.

**Validation:** a bounded local probe against the locked 5.9.3 package showed that repeated `DOCTYPE` declarations are accepted and entities are processed with the `extractAssertionId` options; the same probe left both entities literal with `processEntities: false`.

**Remediation:** upgrade to `fast-xml-parser` 5.10.1 or later and set `processEntities: false` on every SAML parser. Reject any `DOCTYPE` in inbound SAML as defense in depth.

### SEC-005 — Low — Remote upgrade planning accepts an arbitrary server directory — Resolved

**CWE:** CWE-73 (External Control of File Name or Path)

**Evidence:** `packages/clearance-api/src/routes/operations.ts:164-176`, `packages/clearance-api/src/request-auth.ts:81-92`, `packages/management/src/services/upgrade.ts:69-74`, `packages/management/src/services/upgrade.ts:203-220`, `scripts/upgrade-plan.sh:18-40`, `scripts/upgrade-plan.sh:104-123`.

The operator-only `/v1/upgrades/plan` endpoint accepts any absolute `dir`. The server passes it to a script that creates the directory recursively and writes randomly named plan and state artifacts there. Symlinks and non-directories are rejected at the final path, and existing plan files are not overwritten.

**Impact:** an operator-token holder can create directories and place operational JSON artifacts anywhere writable by the API process. This can consume disk space or pollute locations consumed by other workflows. The current filenames and contents do not provide a direct arbitrary-file overwrite primitive.

**Remediation:** ignore client-supplied directories on remote requests. Use a server-configured upgrade root and enforce realpath containment beneath it. Retain `--dir` only for the local CLI if that flexibility is required.

### SEC-006 — Low — Malformed SCIM bearer tokens escape as internal errors — Resolved

**CWE:** CWE-248 (Uncaught Exception)

**Evidence:** `packages/scim/src/middlewares.ts:13-35`, `packages/utils/src/base64.ts:41-65`.

The SCIM authentication middleware decodes the bearer token before entering an error boundary that maps bad credentials to `SCIMAPIError`. A character outside the accepted Base64 alphabet throws a generic error from the decoder.

**Impact:** unauthenticated clients can turn malformed Authorization headers into 500 responses and exception logs. This is a request-level availability and observability issue; I did not find a process-level crash or authentication bypass from this path.

**Remediation:** catch decoder and UTF-8/shape failures and return the same bounded 401 response used for invalid SCIM credentials. Rate-limit repeated failures without logging the token.

## Conditional risks and dependency observations (resolved)

### Webhook verification helper permits indefinite replay — Resolved

`packages/delivery-worker/src/webhook.ts:247-250` binds the timestamp into the HMAC and returns `true` for a valid signature of any age. There is no in-repository webhook receiver using this helper, so this is not a demonstrated first-party replay vulnerability. As a public integration primitive, it is easy for consumers to treat the boolean result as complete verification. Add a higher-level verifier that parses the timestamp, enforces a short skew window, and atomically consumes the event ID; document the existing helper as authenticity-only.

### The private Next.js quickstart is locked to an advisory-affected release — Resolved

`apps/framework-quickstarts/package.json:1-18` depends on Next.js and `pnpm-lock.yaml:4229-4232` resolves 16.2.10. [GHSA-6gpp-xcg3-4w24](https://github.com/advisories/GHSA-6gpp-xcg3-4w24) affects versions before 16.2.11 under specific middleware/proxy, Turbopack, and locale conditions. The current private quickstart has no middleware/proxy or locale configuration, so I did not confirm that authorization bypass. Upgrade to 16.2.11 or later before users copy the example into a real application.

## Dependency-audit triage (post-remediation)

The original `pnpm audit --prod` result was 0 critical, 15 high, 18 moderate, and 2 low advisories. Dependency refreshes reduced the current result to 0 critical, 2 high, 4 moderate, and 0 low:

- `fast-xml-parser` 5.10.1, Next.js 16.3.0, Hono 4.12.34, Nodemailer 9.0.5, and Google Cloud KMS 5.7.0 clear the directly actionable findings identified in this review;
- the two remaining high findings are `fast-uri` paths nested beneath Prisma's local streams tooling;
- three remaining moderate findings are `@hono/node-server` and `valibot` paths beneath Prisma development/local tooling;
- the final moderate finding is `esbuild` beneath Drizzle Kit's development-server tooling.

These residual advisories are tracked dependency risk. They do not provide an application-runtime exploit path in the reviewed source, and no safe direct package refresh or blanket override was introduced solely to manipulate the audit total.

## Areas reviewed without a confirmed vulnerability

- Core session creation, rotation, revocation, cookie defaults, OAuth token authority, password reset and email-change flows, two-factor recovery, passkeys, and organization membership checks.
- Management API bearer-token comparison, API-key expiry/revocation, scope enforcement, operator-only route gates, request body limits, idempotency handling, backup/restore validation, and CLI credential permissions.
- OIDC discovery and callback validation, SAML signature wrapping defenses, response correlation, timestamp/audience/recipient checks, and atomic assertion replay reservation.
- Delivery payload validation, SMTP header handling, webhook destination DNS/IP pinning, redirect refusal, log redaction, key-management providers, vault origin checks, and client request construction.

## Completed remediation order

1. Fixed SEC-001 and verified malformed cookies produce a bounded response under both supported Node versions.
2. Removed remote control over `healthUrl` and upgrade directories.
3. Enforced SAML signature and digest algorithms from verified XML, rejected DTDs, disabled entity processing, and upgraded `fast-xml-parser`.
4. Normalized malformed SCIM credentials to 401 responses.
5. Added replay-aware webhook verification and refreshed the direct dependency set.
