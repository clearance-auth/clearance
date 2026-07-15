The codebase has solid domain primitives, especially structured errors, scoped pagination, coordinated Postgres transactions, and the console’s server-owned credential boundary. The main design weakness is unclear execution ownership across CLI, API, management, runtime, and storage. Clearance-specific control-plane code should receive the first refactoring attention; the inherited runtime can remain stable outside targeted local duplication.

## Highest-impact improvements

1. **P0 — Resolve the CLI’s two implementations**

   The pre-action hook remotely dispatches every command except authentication, prints the response, and exits ([index.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-cli/src/index.ts:298)). The same file retains thousands of lines of local implementations, such as user creation ([index.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-cli/src/index.ts:601)), alongside the separate remote switch ([remote-dispatch.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-cli/src/remote-dispatch.ts:186)).

   Choose API-only execution, or expose local execution as an explicit adapter such as `--local`. Command definitions should own options, confirmation, and presentation once.

2. **P0 — Introduce a management application layer**

   Both CLI and API repeatedly choose between snapshot operations and runtime-coordinated operations using `process.env.DATABASE_URL` ([CLI](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-cli/src/index.ts:614), [API](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-api/src/server.ts:1191)).

   Add a `ManagementApplication` with use cases such as:

   ```ts
   application.users.create(context, input)
   application.organizations.archive(context, input)
   application.members.add(context, input)
   ```

   Select the JSON or coordinated-Postgres implementation once during startup. Transports then handle parsing, authorization, and serialization only.

3. **P0 — Make the operation registry authoritative**

   Today, one workflow appears independently in:

   - Commander registration
   - `REMOTE_COMMANDS`
   - the remote dispatch switch
   - Hono routes
   - `MANAGEMENT_SURFACES`
   - console route metadata and raw fetch calls

   The existing registry contains descriptive strings rather than enforceable contracts ([surfaces.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/contracts/surfaces.ts:1)). Replace it with typed operation definitions containing stable ID, method/path, input/output schema, mutation and confirmation metadata, and CLI presentation metadata. Keep framework-specific rendering and option declarations explicit.

4. **P1 — Replace store temporal coupling with a unit of work**

   `ManagementStore.mutate()` is synchronous, while Postgres queues the mutation and requires callers to remember `ready()` and sometimes `refresh()` ([types.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/store/types.ts:12), [pg-store.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/store/pg-store.ts:190)).

   Expose uniformly asynchronous, durable application operations. Hide snapshot replacement, queued writes, and raw coordinated SQL behind a unit-of-work boundary. Longer-term, keep the serialized snapshot private to adapters rather than treating `DataStoreSnapshot` as the domain API.

5. **P1 — Split composition from domain code**

   Several files currently act as entire subsystems:

   - API server: 3,117 lines
   - CLI entry: 2,744 lines
   - auth bridge: 2,527 lines
   - management `core.ts`: 1,978 lines
   - console app: 2,054 lines

   Create feature routers and command modules—`users`, `organizations`, `members`, `enterprise`, `operations`—around the application layer. Split [auth-bridge.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/auth-bridge.ts:78) into an auth runtime gateway, SQL mappings, reconciliation, and resource lifecycle adapters. Preserve coordinated transactions as an explicit gateway capability.

6. **P1 — Extract the shared SSO/SCIM lifecycle shell**

   SSO and SCIM repeat scoped resolution, public projection, credential rotation, disablement, audit context, and runtime deletion ([sso.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/services/sso.ts:280), [scim.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/services/scim.ts:164)).

   A small internal enterprise-connection lifecycle kernel is appropriate. Protocol-specific create, configure, testing, and conformance behavior should remain separate.

7. **P1 — Generate the public auth declarations**

   Auth declaration generation is disabled, while hand-written declarations approximate rich implementation types using `any`, `unknown`, and broad records ([tsdown.config.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-auth/tsdown.config.ts:8), [index.d.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-auth/types/index.d.ts:42)). Generate declarations from source, then bundle or rewrite them during packaging.

8. **P2 — Take the surgical DRY wins**

   - Share snapshot cloning, normalization, and resource counting between JSON and Postgres stores; their counts have already diverged ([json-store.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/store/json-store.ts:141), [pg-store.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/store/pg-store.ts:239)).
   - Extract one adapter-local `compileCondition()` from the three repeated predicate compilers in [drizzle-adapter.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/drizzle-adapter/src/drizzle-adapter.ts:325).
   - Centralize secret-strength policy, currently repeated across auth, management, and console ([create-auth.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-auth/src/create-auth.ts:16), [secrets.ts](/Users/stephenwalker/Code/projects/clearance-auth/packages/management/src/services/secrets.ts:5), [server.js](/Users/stephenwalker/Code/projects/clearance-auth/packages/clearance-console/src/server.js:121)).
   - Introduce one `OperationContext { scope, actor, source }` instead of redeclaring similar context shapes across services.

## Recommended sequence

1. Decide the CLI execution model.
2. Add `ManagementApplication` and `OperationContext`.
3. Introduce typed operation contracts.
4. Split API and CLI by resource.
5. Invert the auth-runtime dependency.
6. Encapsulate store semantics.
7. Apply adapter and policy-level DRY cleanups.

Avoid universal CRUD repositories, transport-generating mega-schemas, an event bus, or a DI container. The code needs three deliberate seams—application use cases, operation contracts, and durable units of work—rather than a generalized framework.

The initial review was read-only. The execution ledger below records the subsequent implementation and verification work.

## Active plan tracker

**Goal:** Execute `plans/2026-07-15-design-clarity-dry-abstraction-plan.md` as Clearance’s living refactor plan, recording decisions, progress, notes, and current TODO state in this file until completion.

**Status:** Complete
**Current focus:** Completed — all seven phases implemented and verified
**Last updated:** 2026-07-15

### Progress

- [x] Complete the repository-wide design, DRY, clarity, and abstraction review.
- [x] Save the prioritized review as this dated plan.
- [x] Establish this file as the active execution ledger.
- [x] Phase 1: Resolve the CLI execution model and remove shadow workflow ownership.
- [x] Phase 2: Add `ManagementApplication` and shared `OperationContext` boundaries.
- [x] Phase 3: Introduce authoritative typed operation contracts.
- [x] Phase 4: Split API and CLI composition by resource.
- [x] Phase 5: Invert the auth-runtime dependency behind a gateway.
- [x] Phase 6: Encapsulate store durability and unit-of-work semantics.
- [x] Phase 7: Apply adapter, policy, declaration, and snapshot DRY cleanups.

### Current TODO

- None. The plan is complete.

### Decisions

- 2026-07-15 — The supported CLI execution model is API-only. `README.md` states that every operational command uses the authenticated `/v1/*` management API, and the transport-parity test requires every leaf command except `login`, `logout`, and `whoami` to classify as API-backed. No implicit local adapter will remain.
- 2026-07-15 — Operational commands use a shared Commander action directly. This keeps each public command declaration explicit while eliminating the interception hook, sentinel fallback actions, and duplicate local workflow ownership.
- 2026-07-15 — The CLI-local store adapter and `--data-path` option were removed. Test data paths now configure only the private API test server, which reflects the supported API-only execution model.
- 2026-07-15 — `packages/clearance-cli/src/upgrade.ts` remains temporarily because it has direct unit coverage and is no longer command execution code; its final ownership belongs to the later composition/DRY phase.
- 2026-07-15 — `ManagementApplication` begins as a small explicit factory over `ManagementStore`, with backend selection performed once. The first use case is `users.create`; no repository interface, dependency container, generic CRUD service, or event bus was added.
- 2026-07-15 — `OperationContext` requires scope, actor, and audit source. Runtime identity synchronization now receives this context rather than hardcoding `system` for API-created principals.
- 2026-07-15 — Typed operation contracts are compile-time transport contracts plus small immutable runtime metadata records. They do not generate Commander trees, Hono handlers, validation frameworks, or application services.
- 2026-07-15 — Exact route-template literals are preserved through the operation-definition helper so Hono continues to infer required path parameters without casts.
- 2026-07-15 — Confirmation metadata records enforcement ownership: `client-required` describes a CLI-only gate, while `server-required` describes an API-enforced preview/confirmation contract. This exposes gaps instead of implying all confirmations have equal authority.
- 2026-07-15 — An inspect operation with an optional public ID remains one stable operation. Its contract carries the parameterized route as the primary path and an explicit `/current` path as an alternate, keeping route selection visible without manufacturing a second CLI operation.
- 2026-07-15 — Distinct public workflows retain distinct stable operation IDs when they intentionally share an HTTP route. `events.tail` is a client polling workflow over the events-list endpoint, so it shares `GET /v1/events` while remaining independently identifiable.
- 2026-07-15 — Operation output types describe the canonical API result. CLI-only artifact metadata may extend that result, but adapters do not add redundant envelopes; role validation now returns the API validation object directly.
- 2026-07-15 — Confirmation metadata may be conditional when the operation has materially different modes. `client-required-when-live` records that SSO/SCIM simulations need no confirmation while live external probes are CLI-gated.
- 2026-07-15 — Public SSO/SCIM operation outputs use named credential-safe connection views. Persisted connection types include encrypted-at-rest fields and are therefore too broad for public transport contracts.
- 2026-07-15 — HTTP method does not determine mutation metadata. Candidate validation and diff operations remain read-only POSTs, while readiness check is a write because it persists a report and audit evidence.
- 2026-07-15 — Remote classification derives from the complete `MANAGEMENT_OPERATIONS` registry. Family registries remain useful typed namespaces for dispatch and route registration, while the aggregate is the sole source of operational CLI membership.
- 2026-07-15 — Feature modules own framework-specific route registration or remote dispatch for one coherent resource family. The API composition root continues to own middleware, store/scope resolution, and error policy; `index.ts` continues to own explicit Commander declarations; the root remote dispatcher retains explicit family delegation and a fail-closed default.
- 2026-07-15 — Small resource-local transport helpers may remain private during the first extractions. A shared helper is justified only after a second module proves identical semantics, preventing a premature generic router or transport utility layer.
- 2026-07-15 — `AuthRuntimeGateway` is a resource-capability boundary over the existing coordinated bridge. It owns runtime provisioning and coordinated lifecycle calls, while `ManagementApplication` owns backend selection; authenticated resource routers never inspect runtime availability.
- 2026-07-15 — Public runtime setup and enterprise connector paths remain direct bridge consumers because they are composition/deployment workflows outside the resource application boundary. This phase does not manufacture a universal runtime repository.
- 2026-07-15 — Lifecycle audit sources derive from the shared operation source union. Import remains an explicit extra source for offline migration paths, eliminating narrower duplicated unions and gateway casts.
- 2026-07-15 — Domain queries depend on `ManagementSnapshotReader`; atomic snapshot mutations depend on `ManagementUnitOfWork`. `ManagementStore` is the adapter capability superset and application use cases enter it only through `withManagementUnitOfWork`.
- 2026-07-15 — Unit-of-work transitions are synchronous by contract. The adapter commits one complete draft through `mutateDurable`, rejects promise-returning transitions before commit, and leaves runtime-plus-management SQL coordination on `mutateCoordinated`.
- 2026-07-15 — Snapshot initialization, legacy normalization, JSON-semantic cloning, and public resource counts belong to `store/snapshot.ts`. Both adapters consume that module; Postgres locked mutation paths normalize legacy rows before use, and its public counts now include `setupLinks` consistently.
- 2026-07-15 — Drizzle keeps its shipped flat `Where[]` contract. A private recursive condition AST and one `compileCondition` remove the repeated predicate implementations while preserving the existing `(AND predicates) AND (OR predicates)` grouping and making missing-field failures consistent.
- 2026-07-15 — Default-secret classification is a pure browser-safe `@clearance/auth/secret-policy` subpath consumed by auth, management, and console. Environment strictness remains at each owning surface because it is deployment policy rather than secret classification.
- 2026-07-15 — Public auth declarations are generated from self-contained TypeScript product contracts during every build. A compile-time conformance module requires the real root, client, Node, and secret-policy exports to satisfy those contracts; this avoids publishing inherited runtime internals while eliminating manually maintained `.d.ts` files and `any` from the public declaration graph.
- 2026-07-15 — The attempted inherited declaration bundle was rejected by the strict isolated consumer because upstream internal declarations exposed platform-specific and optional types. The public product contract is the stable package boundary; the bundled runtime remains an implementation detail.
- 2026-07-15 — SSO and SCIM share only fail-closed scoped connection resolution. Rotation, disablement, runtime persistence, credential fields, and audit behavior remain protocol-specific because a deeper lifecycle shell would replace visible invariants with callback configuration.

### Phase 1 acceptance criteria

- `login`, `logout`, and `whoami` remain the only locally executed command actions.
- Every operational command retains its public command name, arguments, options, and help while delegating exactly once through remote dispatch.
- `packages/clearance-cli/src/index.ts` no longer imports management operations, opens a management store, branches on `DATABASE_URL`, or owns workflow behavior.
- The obsolete CLI `--data-path` option and its store lifecycle helper are removed.
- CLI typecheck, build, transport parity, contract tests, and the full CLI package suite pass.

### Progress notes

- 2026-07-15: Goal activated. This file is now the source of truth for execution status, current TODOs, decisions, and progress notes.
- 2026-07-15: Phase 1 contract verified from current source: the pre-action hook intercepts all operational commands, while README and tests define the CLI as API-backed. The local action bodies are unreachable shadow implementations.
- 2026-07-15: Phase 1 complete. Replaced 80 shadow operational bodies with one explicit API action, retained exactly three local authentication actions, reduced `index.ts` from 2,744 to 681 lines, removed the orphan CLI store adapter and obsolete data-path surface, and corrected README ownership language.
- 2026-07-15: Phase 1 verification passed: CLI typecheck, CLI build, `remote-dispatch` plus contract tests (22/22), full CLI tests (76/76), static ownership checks, and `git diff --check`.
- 2026-07-15: Phase 2 complete. Added the public application/context seam and moved user-create validation, dry-run behavior, backend selection, runtime provisioning, audit context, and durable completion out of `POST /v1/users`.
- 2026-07-15: Updated architecture guards that still required local CLI mutations. They now assert API-only CLI ownership and application-layer durability.
- 2026-07-15: Phase 2 verification passed: management and API typecheck/build, focused application test (1/1), affected API contracts (31/31), full API tests (82/82), full management tests (162 passed, 54 Postgres-dependent skipped), and `git diff --check`.
- 2026-07-15: Phase 3 users slice complete. Seven user operations now define stable typed IDs, CLI paths, HTTP methods/templates, mutation flags, dry-run support, and confirmation policy once. CLI remote classification/dispatch, API route registration, and the existing surface registry consume those definitions.
- 2026-07-15: Phase 3 users verification passed: operation/parity/durability tests (9/9), CLI transport and contract tests (22/22), affected API tests (31/31), management/CLI/API typechecks, management/CLI/API builds, and `git diff --check`.
- 2026-07-15: Phase 3 organizations/members slice complete. Ten additional operations now share typed IDs, HTTP contracts, policy metadata, API route literals, CLI classification, and CLI dispatch. Nested IDs use `organizations.members.*` to keep tenant scope explicit.
- 2026-07-15: Phase 3 registry coverage is now 17/80 operational leaves. Organization/member verification passed: management contract/parity/surface tests (9/9), CLI remote-dispatch tests (8/8), affected API tests (34/34), management/CLI/API typechecks, and management/CLI/API builds.
- 2026-07-15: Phase 3 system/project/environment slice complete. Eleven additional operations now own their stable IDs, HTTP contracts, policy metadata, API route registration, CLI classification, and CLI dispatch. Project and environment inspection model their optional ID with explicit parameterized and `/current` paths; `doctor` truthfully records a mutating GET because it writes audit state.
- 2026-07-15: Phase 3 registry coverage is now 28/80 operational leaves. System/project/environment verification passed: management operation/parity/surface tests (10/10), CLI remote-dispatch and leaf-command contract tests (22/22), affected API tests (22/22), management/CLI/API typechecks, management/CLI/API builds, static duplicate-route checks, and `git diff --check`.
- 2026-07-15: Phase 3 events/keys/sessions/roles slice complete. Fifteen additional operations now own their stable IDs, typed inputs/outputs, shared HTTP contracts, mutation and safety metadata, API route registration, CLI classification, CLI dispatch, and applicable console-surface paths.
- 2026-07-15: Removed two transport artifacts while migrating the slice: session listing no longer sends undeclared `userId`/`status` query fields that the API ignored, and role validation no longer double-nests the canonical API result under a CLI-only `validation` key.
- 2026-07-15: Phase 3 registry coverage is now 43/80 operational leaves. Events/keys/sessions/roles verification passed: management operation/parity/surface tests (11/11), CLI remote-dispatch and leaf-command contract tests (22/22), affected API tests (22/22), management/CLI/API typechecks and builds, static duplicate-route checks, and `git diff --check`.
- 2026-07-15: Phase 3 SSO/SCIM slice complete. Fourteen additional operations now own their stable IDs, credential-safe typed outputs, shared HTTP contracts, mutation/dry-run/confirmation metadata, API route registration, CLI classification, and CLI dispatch.
- 2026-07-15: Resolved four backend/transport inconsistencies while migrating the slice: SSO create now has a real OIDC CLI default, singular `domain` is normalized for both JSON and Postgres backends, non-live SSO test rejects unsupported global dry-run, and global dry-run overrides SCIM `--apply`.
- 2026-07-15: Phase 3 registry coverage is now 57/80 operational leaves. SSO/SCIM verification passed: management operation/parity/surface tests (12/12), affected API tests (23/23), CLI transport tests (9/9), CLI live-flag tests (5/5), management/CLI/API typechecks and builds, static duplicate-route checks, and `git diff --check`.
- 2026-07-15: Phase 3 readiness/config slice complete. Six additional operations now own typed transport and policy contracts. The readiness surface catalog now pairs the read-only CLI report with the read-only API report, and runtime config validation rejects non-object or non-string-valued JSON at the shared service boundary.
- 2026-07-15: Phase 3 registry coverage is now 63/80 operational leaves. Readiness/config verification passed: management config/operation/parity/surface tests (14/14), affected API tests (18/18), management/CLI/API typechecks and builds, static duplicate-route checks, and `git diff --check`.
- 2026-07-15: Phase 3 import/migration/backup/upgrade/schema slice complete. The final seventeen leaves now own typed transport contracts and policy metadata. Unsupported dry-run now fails before migration plan/verify/rollback, backup create/verify/restore, and upgrade check can mutate; the dead public backup `--dir` option was removed and restore target ownership is explicit in CLI help.
- 2026-07-15: Phase 3 complete at 80/80 operational leaves. `REMOTE_COMMANDS` derives solely from `MANAGEMENT_OPERATIONS`; API route registration and CLI dispatch consume the same family contracts. Final verification passed: operation registry and remote classifier both report 80, full API tests (82/82), full CLI tests (77/77), full management tests (171 passed, 54 Postgres-dependent skipped), management/CLI/API typechecks and builds, durability/parity/static duplicate-route guards, and `git diff --check`.
- 2026-07-15: Phase 4 first composition cut complete. Organization/member remote dispatch moved into `clearance-cli/src/dispatch/organizations.ts`, while all Commander declarations remain explicit in `index.ts` and the root switch visibly delegates the ten supported paths. The four config handlers moved into `clearance-api/src/routes/config.ts`; the server still composes them in their original position and supplies store, scope, and error-policy dependencies.
- 2026-07-15: The durability guard now scans feature route modules in addition to `server.ts`, so route extraction cannot evade the queued-write completion invariant. The parity guard verifies both root composition and resource-module ownership.
- 2026-07-15: Phase 4 first-cut verification passed: CLI and API typechecks, management parity/durability guards (6/6), CLI remote-dispatch behavior (9/9), API config/core contracts (9/9), and `git diff --check`.
- 2026-07-15: Phase 4 API platform/events cut complete. Process probes, public setup completion, middleware, store/application lifecycle, scope policy, and error policy remain in `server.ts`; authenticated platform and event registrations now live in narrow feature routers mounted in their original order. Current-project/current-environment routes remain ahead of parameterized routes, and event replay/export durability semantics are unchanged.
- 2026-07-15: Platform/events verification passed: API typecheck, affected API event/core/scope/pagination contracts (27/27), management parity/durability guards (6/6), and `git diff --check`.
- 2026-07-15: Phase 4 CLI composition split complete. `remote-dispatch.ts` is now a 166-line explicit facade over eight coherent family dispatchers covering all 80 operations. Shared transport helpers exist only for behavior proven identical across multiple families; event streaming, artifact writing, live-test gates, file-read error contracts, confirmation order, and the fail-closed default remain feature-visible.
- 2026-07-15: CLI partition verification passed: CLI typecheck, remote-dispatch behavior (9/9), management parity/durability guards (6/6), and `git diff --check`.
- 2026-07-15: Phase 4 API users/access cut complete. User, API-key, session, role, and settings routes now live in feature routers at their original registration positions. Runtime availability remains a root-owned policy exposed as `runtimeDatabaseConfigured()`, and user creation still enters `ManagementApplication` rather than regaining transport-owned workflow behavior.
- 2026-07-15: Users/access verification passed: API and CLI typechecks, affected API core/role/session/scope/pagination contracts (36/36), management parity/durability guards (6/6), and `git diff --check`.
- 2026-07-15: Phase 4 API enterprise/operations cut complete. SSO, SCIM, and readiness remain one enterprise router; backup, upgrade, schema, legacy import, and migration remain one operational router. Runtime and backup deployment policy stay root-owned through named dependency functions, while migration fixture parsing is private to its owning feature.
- 2026-07-15: Enterprise/operations verification passed: API typecheck, affected enterprise/operations/idempotency/core contracts (27/27), management parity/durability guards (6/6), and `git diff --check`.
- 2026-07-15: Phase 4 complete. All authenticated management routes now live in eight explicit feature routers composed by `server.ts`; public setup, process probes, middleware, store/application lifecycle, deployment policy, Node bridging, and shutdown remain root-owned. `server.ts` fell from roughly 3,100 to 1,097 lines. The CLI root dispatcher is a 166-line explicit facade over eight family modules, while Commander declarations remain explicit in `index.ts`.
- 2026-07-15: Phase 4 boundary verification passed: full API tests (82/82), full CLI tests (77/77), full management tests (171 passed, 54 Postgres-dependent skipped), management/CLI/API typechecks and builds, parity/durability guards (6/6), and `git diff --check`.
- 2026-07-15: Phase 5 seam selected. The complete user mutation family is the smallest meaningful gateway slice because creation already enters `ManagementApplication`, while update/disable/delete still select auth-runtime implementations in the user router. The gateway will expose user-specific capabilities and wrap existing bridge functions without changing their transaction internals.
- 2026-07-15: Phase 5 user gateway slice complete. Added a resource-specific `AuthRuntimeGateway` and one auth-bridge adapter bound to the same Postgres store as `ManagementApplication`. User create/update/disable/delete now select JSON or runtime behavior in the application layer; the user router contains parsing/context/serialization only for mutations and has no bridge or runtime-selection imports.
- 2026-07-15: User gateway verification passed: focused management application/parity/durability tests (9/9), affected API core/scope tests (18/18), full management tests (173 passed, 54 Postgres-dependent skipped), full API tests (82/82), management/API typechecks and builds, and `git diff --check`.
- 2026-07-15: Phase 5 organization/member/session slice complete. Added explicit gateway capabilities and matching application use cases for organization provision/update/archive, membership add/update/remove, and session list/inspect/revoke. The organization and access routers now construct `OperationContext`, invoke `ManagementApplication`, and serialize results without importing the auth bridge or selecting a backend.
- 2026-07-15: The JSON application contract now exercises organization, membership, and session lifecycles end to end. The parity guard asserts that authenticated resource routers contain no `*InAuth`, migration, or runtime-database policy branches and that the auth-bridge adapter is their single runtime implementation boundary.
- 2026-07-15: Phase 5 complete. Final verification passed: full management tests (174 passed, 54 Postgres-dependent skipped), full API tests (82/82), management/API typechecks and builds, CLI typecheck, static router-boundary checks, and `git diff --check`.
- 2026-07-15: Phase 6 complete. Added explicit snapshot-reader and unit-of-work capabilities, narrowed resource query/mutation services to those capabilities, and migrated all user, organization, membership, and session application mutations to one durable draft boundary. Application modules contain no `store.ready()` temporal coupling; coordinated gateway operations remain unchanged.
- 2026-07-15: Unit-of-work tests prove one durable commit without a flush, full-draft rollback on failure, and rejection of asynchronous transitions. The durability guard now classifies the unit-of-work boundary as durable and prevents application mutation modules from regaining direct flush ownership.
- 2026-07-15: Phase 6 verification passed: full management tests (177 passed, 54 Postgres-dependent skipped), full API tests (82/82), full CLI tests (77/77), management/API/CLI typechecks and builds, and `git diff --check`.
- 2026-07-15: Phase 7 snapshot and adapter cleanup complete. JSON and Postgres now share snapshot construction, normalization, JSON-semantic cloning, and resource counting; one recursive Drizzle compiler handles every comparison and logical group; focused management tests pass (180 passed, 54 Postgres-dependent skipped) and Drizzle tests pass (22/22).
- 2026-07-15: Phase 7 policy and enterprise cleanup complete. Auth, management, and console consume one browser-safe default-secret policy, with exact forbidden-default coverage at the product surfaces. SSO/SCIM share the scoped resolver while retaining protocol-specific lifecycle code. Auth tests pass (15/15) and console tests pass (62/62).
- 2026-07-15: Phase 7 declaration cleanup complete. Auth builds generated root, client, Node, and secret-policy declarations from TypeScript contracts; compile-time source conformance passes; the packaged declarations contain no `any` or workspace-runtime imports. The isolated tarball consumer compiles with `skipLibCheck: false`, resolves all four shipping packages inside the consumer, and reports `SMOKE_IMPORT_OK 0.2.1`.
- 2026-07-15: Moving release-version ownership into the shared snapshot module exposed one stale CLI guard. The full CLI run had 76 unaffected tests pass and that single guard fail; after updating the guard and fixture path, the invalidated release-version test passed (1/1). CLI typecheck/build and the previously completed full 77-test suite remain green.
- 2026-07-15: Phase 7 and the plan are complete. Final affected-package gates passed: auth, management, Drizzle, CLI, and API typechecks/builds; API tests (82/82); management tests (180 passed, 54 Postgres-dependent skipped); Drizzle tests (22/22); auth tests (15/15); console build/tests (62/62); strict isolated package import; structural invariants; and `git diff --check`.

### Phase 7 acceptance criteria

- JSON and Postgres adapters consume one snapshot module for construction, legacy normalization, JSON-semantic cloning, and public resource counts.
- Drizzle has one private recursive condition compiler, preserves the public flat query contract and existing grouping semantics, and rejects missing fields consistently.
- Auth, management, and console consume one browser-safe default-secret policy while keeping environment enforcement at the owning surfaces.
- Auth declarations are generated from TypeScript product contracts, are checked against the real exports, preserve all public subpaths, and compile from an isolated tarball consumer with `skipLibCheck: false`.
- SSO and SCIM share only the protocol-neutral scoped-resolution invariant; protocol-specific lifecycle behavior remains explicit.
- Focused and affected-package tests, relevant typechecks/builds, package smoke checks, structural invariants, and `git diff --check` pass.

### Phase 6 acceptance criteria

- Domain reads can depend on `ManagementSnapshotReader`; atomic snapshot mutations can depend on `ManagementUnitOfWork` without receiving persistence, refresh, backend, or coordinated-SQL capabilities.
- `withManagementUnitOfWork` executes one synchronous transition against the latest durable draft and resolves only after commit on both JSON and Postgres adapters.
- Application resource mutation modules do not call `store.mutate`, `store.ready`, `store.refresh`, or `store.replace`; durable completion is an adapter responsibility.
- Promise-returning transitions and thrown transitions fail without committing a partial snapshot.
- Runtime-plus-management operations continue to use the existing coordinated Postgres transaction boundary.
- Behavioral unit-of-work tests, structural durability guards, full management/API/CLI suites, relevant typechecks/builds, and `git diff --check` pass.

### Phase 5 acceptance criteria

- `ManagementApplication` owns JSON/Postgres selection for user, organization, membership, and session resource lifecycles.
- `AuthRuntimeGateway` exposes explicit resource capabilities and is implemented by one adapter over the existing auth bridge; coordinated transaction internals remain unchanged.
- Authenticated user, organization, member, and session routes contain no bridge imports, `*InAuth` calls, `ensureAuthMigrated`, `DATABASE_URL`, or runtime-database policy branches.
- Public setup and enterprise connector provisioning remain stable and outside this resource boundary.
- Operation scope, actor, and source reach JSON audit records and coordinated runtime operations through one required `OperationContext`.
- JSON lifecycle coverage, structural parity/durability guards, full management and API suites, relevant builds/typechecks, and `git diff --check` pass.

### Phase 4 acceptance criteria

- `server.ts` owns middleware, public setup, process probes, store/application construction, deployment policy, Node bridging, shutdown, and explicit feature-router composition; authenticated management handler bodies live in resource modules.
- Feature routers preserve the original registration order and receive only the narrow root-owned dependencies they consume.
- `remote-dispatch.ts` classifies from `MANAGEMENT_OPERATIONS`, explicitly delegates every operation family, and retains a fail-closed default; detailed request construction lives in resource dispatchers.
- Commander declarations remain explicit in `index.ts`; no router generator, handler registry, dependency container, or generic CRUD abstraction is introduced.
- Structural parity and durability guards discover extracted source files, and full management, CLI, and API suites pass.

### Phase 3 contract discrepancies

- User deletion, member removal, key rotation/revocation, and session revocation are confirmation-gated only by the CLI; direct API callers can currently mutate without a confirm field. Their contracts record `client-required` until server enforcement is implemented deliberately.
- Organization creation does not support dry-run; a direct API `dryRun` field is ignored. Its response also omits `scope` while adjacent organization responses include it.
- Member import is server-safe by default, but the CLI refuses a no-flag preview rather than forwarding the API's default preview behavior.
- Events tail polls only the newest bounded page without cursor catch-up, so a burst larger than the requested limit can be missed between polls.
- Role create/update dry-run validation is shallower than apply: it does not fully prove target existence, built-in-role restrictions, slug conflicts, or every description-only update.
- Live SSO/SCIM tests require confirmation only in the CLI; the API accepts `live: true` directly.
- Live SSO/SCIM probes are externally read-only but still persist local trace/audit evidence; successful live SSO also moves the connection to `testing`, while live SCIM leaves connection state unchanged.
- Events export silently ignores global `--dry-run` even though it writes a local artifact and an API audit record.
- `doctor` and JSON-backed upgrade check mutate audit state despite using GET; Postgres upgrade check differs, so mutation metadata is backend-dependent.
- Events tail is a distinct client polling operation over the events-list HTTP route and therefore needs a separate stable operation ID despite sharing method/path.
- Schema-generate dry-run is client-local: the API generates SQL while the CLI suppresses writing the returned artifact.
- Readiness and config mutation services still hardcode audit source `cli` when invoked through the API; their application-boundary migration belongs with the remaining `OperationContext` adoption.
- Migration fixture loading uses a generic CLI file read instead of the existing regular-file/no-symlink loader used by management import code.
- Upgrade artifact directories, plan paths, rollback backup paths, and health checks are interpreted on the API host even though the developer supplies them through the client CLI; artifact IDs and server-owned storage need a clearer remote contract.
- Import preview defaults differ by transport: the API safely previews without confirmation, while the CLI refuses a no-flag preview instead of forwarding that default.

### Phase 2 acceptance criteria

- `POST /v1/users` contains body parsing, complete `OperationContext` construction, application invocation, and response serialization only.
- `application.users.create` owns required-field and duplicate validation, dry-run behavior, backend-selected provisioning, context propagation, and durable completion.
- Backend choice uses `store.backend` at application composition time; the use case and route do not inspect `DATABASE_URL`.
- Every application call requires `scope`, `actor`, and `source`; runtime-to-management sync receives the same context instead of hardcoding `system`.
- JSON and Postgres paths preserve existing user identity, status, setup-token, error, scope, and HTTP response behavior.
- Focused management application coverage and affected API/management checks pass.

### Phase 3 acceptance criteria

- Every operational CLI leaf has one unique stable operation ID and typed input/output contract.
- Remote-command classification is derived entirely from the operation registry; no second command-name set remains.
- API route registration and CLI dispatch consume the same HTTP method and path template for each operation.
- Mutation, dry-run, and confirmation semantics are explicit and testable metadata.
- Commander option declarations, Hono handler bodies, and transport-specific serialization remain explicit at their natural boundaries.
- Contract uniqueness/parity coverage and full management, CLI, and API suites pass.
