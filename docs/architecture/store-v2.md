# DESIGN: Management store v2 — normalized relational storage

Status: proposed (FOLLOW.md P2.2.3). This document designs the exit from the
single-row JSONB snapshot store. P2.2 shipped containment (targeted
`mutateDurable` migration, the durability structural guard, and the measured
baseline below); the migration itself is scheduled as its own plan and must
not start before this design is reviewed and merged. P2.3.2 (idempotency
keys) sequences behind the storage decision here.

## 1. Problem and evidence

The current "Postgres store" (`packages/management/src/store/pg-store.ts`) is
one JSONB row (`CHECK (id = 1)`) holding the entire management state. Every
mutation:

1. takes a global `SELECT ... FOR UPDATE` on that row (all writers serialize),
2. clones and rewrites the full snapshot,
3. rebuilds both uniqueness side-tables with DELETE-all + one INSERT per
   principal and per organization (`syncUniqueness`).

Correct under concurrency (proven by `pg-concurrency.test.ts`), but O(N) per
write in both bytes and row churn.

### Measured baseline (the number store-v2 must beat)

Measured 2026-07-13 by `packages/management/src/__tests__/scale-baseline.test.ts`
(opt-in: `CLEARANCE_SCALE_BASELINE=1`) against a disposable local
`postgres:16-alpine` container (Docker, Apple Silicon; ephemeral port; no
other load), after seeding **5,000 principals + 5,000 organizations**:

| Metric (single mutation: 1 principal insert + 1 audit event, `mutateDurable` round trip) | Value |
| --- | --- |
| p50 | **3,267.8 ms** |
| p95 | **3,448.1 ms** |
| min / max (20 samples) | 2,868.2 ms / 3,468.8 ms |
| Seed transaction (10,000 resources, one commit) | 3,333 ms |

Raw line: `SCALE_BASELINE {"n_principals":5020,"n_organizations":5000,"samples":20,"seed_ms":3333,"p50_ms":3267.8,"p95_ms":3448.1,"min_ms":2868.2,"max_ms":3468.8}`

**A single user-create costs ~3.3 seconds at 5k-tenant scale** — the same
cost as bulk-seeding all 10,000 resources at once, because every write pays
the full snapshot rewrite + side-table rebuild regardless of its own size.
Store-v2 acceptance: the same operation shape at the same N must commit in
**< 25 ms p50 / < 50 ms p95** on the same hardware (comfortably achievable
for a two-row INSERT under row-level constraints), and must be O(changed
rows), flat as N grows — verified by re-running the same baseline harness at
N=5k and N=50k.

## 2. Target schema: normalized tables per resource

One table per resource collection currently embedded in `DataStoreSnapshot`,
under a `mgmt_` prefix (companion tables already prove the multi-table
pattern):

```
mgmt_projects        (id PK, name, slug, created_at, updated_at)
mgmt_environments    (id PK, project_id FK, name, slug, kind, created_at, updated_at)
mgmt_principals      (id PK, project_id, environment_id, email, name, status,
                      external_id, created_at, updated_at)
mgmt_organizations   (id PK, project_id, environment_id, name, slug, status,
                      external_id, created_at, updated_at)
mgmt_memberships     (id PK, organization_id FK, principal_id FK, role, status,
                      source, created_at, updated_at)
mgmt_identity_connections   (id PK, organization_id, ...config jsonb, status, ...)
mgmt_directory_connections  (id PK, organization_id, ...config jsonb, status, ...)
mgmt_roles           (id PK, project_id, environment_id, key, ...)
mgmt_api_keys        (id PK, project_id, environment_id, digest, prefix, status, ...)
mgmt_sessions        (id PK, principal_id, environment_id, status, created_at, ...)
mgmt_setup_links     (id PK, organization_id, kind, digest, reservation fields, ...)
mgmt_events          (id PK, created_at, correlation_id, actor, action,
                      subject_type, subject_id, outcome, source, project_id,
                      environment_id, organization_id, message, metadata jsonb)
mgmt_traces          (id PK, subsystem, created_at, payload jsonb)
mgmt_readiness_reports (id PK, organization_id, generated_at, report jsonb)
mgmt_migrations      (id PK, status, plan jsonb, created_at, updated_at)
mgmt_backups         (id PK, path, checksum, verified, resource_counts jsonb, created_at)
mgmt_meta            (key PK, value)   -- schema version, operator config
mgmt_idempotency_keys (key PK, request_digest, response jsonb, expires_at)  -- P2.3.2 lands here
```

Principles:

- **Hot, queried, constrained columns are real columns**; provider-specific
  config blobs stay `jsonb` (they are opaque to queries and constraints).
- Events and traces become **append-only** tables — the audit log stops being
  rewritten on every unrelated mutation, and the 5,000-event in-snapshot cap
  (P2.3.4) becomes a retention policy instead of a data-loss mechanism.
- `mgmt_idempotency_keys` is the dedicated table P2.3.2 requires (storage
  explicitly must not live in a snapshot; TTL expiry via `expires_at` +
  opportunistic delete).

## 3. Concurrency: row-level locking, no global lock

- Single-resource mutations rely on ordinary MVCC: `INSERT`/`UPDATE ... WHERE
  id = $1` locks only the touched rows. The global writer serialization
  disappears.
- Multi-resource invariants (e.g. `assertOwnerInvariant`: an organization must
  retain an active owner) run inside one transaction that takes `SELECT ...
  FOR UPDATE` on the parent row (`mgmt_organizations.id`) first, then reads
  memberships. Lock ordering rule: **parent resource before children,
  organizations before principals** — documented per service, enforced by a
  helper (`withOrgLock(orgId, fn)`) so services cannot improvise orderings.
- Coordinated runtime+management operations keep the existing
  `mutateCoordinated` shape: one transaction on one connection covering
  runtime tables (Clearance `user`/`member`/...) and `mgmt_*` tables. This
  already exists and survives unchanged in concept; only the management side
  stops being a snapshot rewrite.
- Isolation level stays `READ COMMITTED` + explicit row locks (matches
  current behavior; no serializable-retry machinery needed).

## 4. Real unique constraints replace the syncUniqueness side-tables

The rebuilt-per-write side-tables become declarative partial unique indexes:

```sql
CREATE UNIQUE INDEX mgmt_principals_email_unique
  ON mgmt_principals (project_id, environment_id, lower(email))
  WHERE status <> 'deleted';

CREATE UNIQUE INDEX mgmt_organizations_slug_unique
  ON mgmt_organizations (project_id, environment_id, slug)
  WHERE status <> 'archived';
```

Also promoted to constraints (currently app-checked only):

```sql
CREATE UNIQUE INDEX mgmt_memberships_active_unique
  ON mgmt_memberships (organization_id, principal_id)
  WHERE status = 'active';
CREATE UNIQUE INDEX mgmt_api_keys_digest_unique ON mgmt_api_keys (digest);
CREATE UNIQUE INDEX mgmt_setup_links_digest_unique ON mgmt_setup_links (digest);
```

App-level checks remain for good error codes (`USER_EXISTS`, 409 before 23505);
the constraints fail closed as the second layer — same layering as today, but
enforced per-row instead of rebuilt O(N) per write.

## 5. Cursor-friendly indexes (P2.3.1 alignment)

Every list endpoint gets a stable ordering backed by a composite index whose
suffix is the tiebreak `id`, so an opaque cursor is `(sort_key, id)`:

```sql
CREATE INDEX mgmt_principals_cursor    ON mgmt_principals    (project_id, environment_id, created_at DESC, id DESC);
CREATE INDEX mgmt_organizations_cursor ON mgmt_organizations (project_id, environment_id, created_at DESC, id DESC);
CREATE INDEX mgmt_events_cursor        ON mgmt_events        (created_at DESC, id DESC);
CREATE INDEX mgmt_events_scope_cursor  ON mgmt_events        (project_id, environment_id, created_at DESC, id DESC);
CREATE INDEX mgmt_sessions_cursor      ON mgmt_sessions      (environment_id, status, created_at DESC, id DESC);
CREATE INDEX mgmt_memberships_org      ON mgmt_memberships   (organization_id, status, created_at DESC, id DESC);
```

Keyset pagination (`WHERE (created_at, id) < ($1, $2) ORDER BY created_at
DESC, id DESC LIMIT $3`) — no OFFSET scans, cursors stay valid under
concurrent writes. If P2.3.1 ships before store-v2, its cursor contract is
defined on exactly these orderings so the storage swap does not change the
API surface.

## 6. Migration: snapshot → relational, with dual-read verification

Phased, reversible, no downtime requirement (single-operator deployments):

1. **Expand.** `clearance upgrade store-v2 --plan/--run` creates `mgmt_*`
   tables alongside the snapshot row. Inside one transaction: read the
   snapshot `FOR UPDATE`, decompose into rows, insert, record
   `mgmt_meta('store_v2_backfill', revision)`. The snapshot row stays
   authoritative.
2. **Dual-write.** `PgStoreV2` applies every mutation to the normalized
   tables AND rewrites the snapshot row in the same transaction (cost: no
   worse than today). Revision column keeps advancing so old readers stay
   correct.
3. **Dual-read verification.** Every `refresh()` — and a dedicated
   `clearance doctor --store-v2` check — loads both representations, compares
   canonicalized checksums per collection, and records divergence as a
   `system.store.divergence` audit event + doctor failure. The canonical gate
   runs the full Pg suite against dual-read mode with
   `CLEARANCE_STORE_V2_VERIFY=1` (fail closed on any divergence). Minimum
   soak: the entire existing pg-gated suite + compose smoke green under
   dual-read, plus the scale-baseline harness re-run showing the target
   numbers.
4. **Contract.** Reads flip to normalized tables; the snapshot row is
   rewritten one final time and marked `mgmt_meta('store_v1_frozen', ...)`.
   Rollback before this point = drop `mgmt_*` tables (snapshot never stopped
   being written). Rollback after = re-run backfill in reverse (one
   transaction, snapshot reconstructed from rows — the shape conversion is
   loss-free by construction and proven by phase-3 checksums).
5. **Contract removal** (separate release): snapshot row and `syncUniqueness`
   side-tables dropped; `backup.ts` pg path switches to pg_dump-only (it
   already is for runtime data).

JSON file backend is unaffected: it keeps the snapshot shape (its `mutate` is
synchronous and durable); store-v2 is Postgres-only.

## 7. `ManagementStore` compatibility contract

Services do not change in the store-v2 release. The interface keeps its exact
shape (`store/types.ts`), including the semantics services rely on today:

- `snapshot` / `load()`: still return a full `DataStoreSnapshot`. `PgStoreV2`
  materializes it from the normalized tables into an in-process cache,
  invalidated by revision (a `mgmt_meta` revision row bumped per transaction,
  reusing today's `refresh()` comparison). Reads stay synchronous.
- `mutate(fn)`: still accepted; the draft the mutator receives is the
  materialized snapshot, and the store **diffs draft vs. base per collection
  by id + content hash** to emit row operations. Collections a mutator did
  not touch produce zero SQL. This is the compatibility bridge, not the end
  state: services migrate incrementally to typed repository methods
  (`store.principals.insert(...)`) that skip the diff; the diff bridge is
  deleted when the last `mutate` caller is gone.
- `mutateDurable(fn)`: same contract (resolves after commit) — already the
  required form for any path that reports success to a caller.
- `mutateCoordinated(fn)`: same contract, now without the O(N) snapshot
  rewrite at the end.
- `ready()` / `refresh()` / `replace()` / `checksum()` / `resourceCounts()`:
  preserved. `checksum()` is computed over the canonicalized materialized
  snapshot so backup/doctor comparisons remain meaningful across v1/v2.

### Decision: full `mutate()` async unification happens in store-v2

Deferred from P2.2 (59 call-sites across 17 service files), decided here:
**store-v2 removes fire-and-forget `mutate()` from the interface.** The
end-state interface exposes only awaitable mutations (`mutateDurable`,
`mutateCoordinated`, and the typed repository methods). Sequencing within the
store-v2 plan:

1. Land `PgStoreV2` behind the unchanged interface (diff bridge above).
2. Mechanically convert services file-by-file from `mutate` to
   `mutateDurable` (each conversion is now local: same transaction cost,
   the caller becomes async; CLI/API callers already await at the surface).
   The P2.2 durability guard keeps surfaces honest during the transition —
   as services convert, its derived "queued" list shrinks toward empty.
3. Delete `mutate()` from `ManagementStore`; the guard's queued-mutator
   check becomes a tripwire that the method never reappears.

Until step 3 completes, the P2.2 containment invariants (CLI `flushStore`,
API `await store.ready()`, structural guard) remain the enforced convention.

## 8. Out of scope for store-v2

- Multi-region / read replicas (single-writer Postgres assumed).
- Changing the JSON dev backend.
- Runtime (Clearance) schema — already relational.
- Audit archival beyond retention events (P2.3.4 documents `events export
  --before <ts>`; true archival tiering is future work on `mgmt_events`).
