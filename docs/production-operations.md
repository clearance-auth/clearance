# Production operations

This runbook is the minimum operations contract for a Clearance beta. It assumes
managed Postgres with point-in-time recovery, encrypted off-host object storage,
TLS termination before Clearance, and an alerting system that scrapes `/metrics`
and watches Kubernetes Jobs or the host scheduler.

## Service health and telemetry

- `/livez` is process-only. Alert on restarts; do not couple liveness to Postgres.
- `/readyz` verifies the durable management store. Alert when no API replica is
  ready for five minutes.
- `/metrics` exposes request count/status, cumulative duration, in-flight work,
  and process uptime in Prometheus text format. Alert on sustained 5xx responses,
  readiness loss, backup job failures, and restart loops.
- API and console production request logs are one-line JSON with request ID,
  method, path, status, and duration. Authorization, cookies, query strings,
  bodies, and token material are excluded. Safe caller-supplied request IDs are
  reused; malformed IDs are replaced with a generated UUID before logging or
  forwarding upstream.
- SIGTERM marks API readiness as draining, stops admission, waits for active
  HTTP work and pending store writes, closes the Postgres pool, and has a
  25-second hard deadline under the chart's 30-second grace period.

## Credential-authority cutover

For a fresh Compose database, bootstrap with the unexposed CLI migrator before
starting either credential-capable service. Use a stable bootstrap drain ID so
the same command resumes safely after interruption:

```bash
COMPOSE="docker compose -f docker-compose.yml -f deploy/compose/docker-compose.production.yml"
export CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION=digest-v1
export CLEARANCE_CREDENTIAL_DRAIN_ID="bootstrap-$CLEARANCE_DEPLOYMENT_ID"

$COMPOSE --profile migration run --rm credential-migrator
$COMPOSE up -d api sample-b2b
clearance --json schema credential-authority status
```

The API and sample ports remain closed until migration publishes `digest-live`.
The same command refuses an existing unarmed database, so an upgrade cannot be
silently treated as a fresh install.

The 0.3 credential upgrade uses one immutable application image and one
deployment identity through four phases: `bridge`, `drain`, `migrate`, and
`serve`. Bridge runtimes hold shared PostgreSQL session advisory leases. The
durable fence records the armed deployment, exact runtime count, drain ID,
phase, and generation. Credential mutation requires the exclusive lease after
every bridge process has released its shared lease. A paused process therefore
blocks the migration, and a restarted legacy process cannot serve after drain.

For production Compose, export the immutable image reference plus
`CLEARANCE_DEPLOYMENT_ID`, start the candidate with
`CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION=legacy-v1`, and verify the image ID
of both credential-capable services before arming:

```bash
COMPOSE="docker compose -f docker-compose.yml -f deploy/compose/docker-compose.production.yml"

$COMPOSE up -d --force-recreate api sample-b2b
clearance schema credential-authority arm \
  --deployment-id "$CLEARANCE_DEPLOYMENT_ID" --expected-runtimes 2 --yes
clearance schema credential-authority drain \
  --deployment-id "$CLEARANCE_DEPLOYMENT_ID" \
  --drain-id "$CLEARANCE_CREDENTIAL_DRAIN_ID" --yes

$COMPOSE up -d --no-deps --scale api=0 --scale sample-b2b=0 api sample-b2b
$COMPOSE --profile migration run --no-deps --rm credential-migrator

export CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION=digest-v1
$COMPOSE up -d --force-recreate api sample-b2b
clearance --json schema credential-authority status
```

The migrator has no published port, uses the exact API image digest, and accepts
only the armed drain ID. Do not start it until every Clearance runtime sharing
the database has joined the armed cohort and then stopped. A failed migration
leaves the durable phase at `migrating`; resume with the same image, deployment,
and drain ID. Writer constraints reject later plaintext session and OAuth
authority even if an old binary reconnects. The Helm chart documents and
renders the equivalent phase sequence as a zero-replica Deployment plus a
one-shot Job.

## Delivery worker operations

Production Compose and Helm run `packages/delivery-worker/dist/cli.mjs` from
the same immutable application image as the API. The API and every worker must
receive the same delivery encryption ring, fingerprint ring, source-dedupe key,
schema, and prefix. Purpose keys must use distinct 32-byte material. The source
dedupe key stays stable across encryption and fingerprint rotations.

Check one running worker directly with its built-in CLI:

```bash
docker compose -f docker-compose.yml \
  -f deploy/compose/docker-compose.production.yml \
  exec -T delivery-worker \
  node packages/delivery-worker/dist/cli.mjs --ready

kubectl --namespace clearance exec deployment/clearance-delivery-worker -- \
  node packages/delivery-worker/dist/cli.mjs --ready
```

The command exits non-zero unless Postgres, the owned schema, retained keys,
worker heartbeat, and the selected SMTP or SES transport are ready. Use the
management CLI for fleet and queue state:

```bash
clearance --json --no-input delivery readiness
clearance --json --no-input delivery quotas
clearance --json --no-input delivery list --state retry --state dead
```

`/live` is process-only, `/ready` checks the complete delivery dependency set,
and `/metrics` exports low-cardinality job outcomes and worker health. The
Compose port is loopback-only. The Helm Service is ClusterIP-only, has no
Ingress, and grants scrape access only to the configured Prometheus selectors.

Alert when no worker is ready for five minutes, schema or email transport health
is zero, or `accepted_unconfirmed` and `finish_failed` outcomes increase. Track
sustained retry/dead growth and quota saturation. Counters are process-local
and reset with a pod, so aggregate by workload in Prometheus. A live SES account
readiness check remains part of release-environment proof.

The worker migrates the delivery schema before serving health endpoints. A
custom schema must exist before rollout, and its database role needs DDL rights
over the owned delivery tables and guard function. Keep the worker termination
grace longer than `CLEARANCE_DELIVERY_DRAIN_TIMEOUT_MS`. The production Compose
profile allows 310 seconds for the supported maximum drain; the default Helm
profile allows 45 seconds for the default 30-second drain and rejects an unsafe
grace/deadline combination.

For key rotation, deploy the expanded retained rings to API and workers first.
After all replicas are ready, switch the current encryption and fingerprint IDs
in a second rollout. Keep old keys until `clearance delivery readiness` proves
they are no longer required. External Kubernetes Secret contents are invisible
to Helm checksums, so change the API and worker restart tokens for each phase.

## Backup, RPO, and retention

The beta target is **RPO <= 1 hour** and **RTO <= 60 minutes**. These targets are
valid only after a timed rehearsal on production-equivalent data and capacity.

Run `scripts/backup-scheduled.sh` hourly. It creates a plain Postgres dump,
captures complete table counts and application version, binds the dump and
metadata into read-only SHA-256 evidence, restores into an isolated database,
runs the operator-supplied off-host copy hook, and writes a copy receipt. It
fails closed when the hook is absent; `CLEARANCE_BACKUP_ALLOW_LOCAL_ONLY=1` is
limited to development and test. Local retention removes only artifact sets
that have a successful off-host receipt. Configure independent object-lock and
lifecycle retention at the remote destination (recommended: 30 daily copies
plus managed Postgres PITR).

The checked-in deployment support matrix is Postgres 16 with the separately
published `backup-runtime` image target (official `postgres:16-bookworm` client).
A fixed UID/GID 10001 runs the job without root privileges; Compose and Helm
mount only `/backups` and `/tmp` writable while keeping the root filesystem
read-only.
A different managed Postgres major requires a backup image built from the same
server major and an updated chart image value before admission.

For Compose, invoke the one-shot `backup` profile from cron or systemd:

Before any production Compose command, set `CLEARANCE_IMAGE_REPOSITORY` and
`CLEARANCE_IMAGE_DIGEST` plus their `CLEARANCE_BACKUP_IMAGE_*` equivalents from
the immutable release evidence. The overlay validates digest-reference syntax;
the release gate separately verifies signatures and provenance. Local image
builds are disabled and only `repository@sha256:...` references are accepted.

```bash
docker compose -f docker-compose.yml \
  -f deploy/compose/docker-compose.production.yml \
  --profile backup run --rm backup
```

## Upgrade and active rollback

1. Put the API and console behind a maintenance response and stop background
   writers. Create an immutable plan with `scripts/upgrade-plan.sh`.
2. Run `scripts/upgrade-preflight.sh`; it validates the real
   `clearance_management_snapshot` release contract, schema fingerprint,
   environment, and legacy SCIM inventory.
3. Run `scripts/upgrade-apply.sh`, then `scripts/upgrade-verify.sh`. Apply cannot
   begin before a checksum and isolated-restore-verified rollback backup exists.
4. Rehearse without changing production:
   `scripts/upgrade-rollback.sh --plan <plan-id>`.
5. For an incident, read the exact confirmation token from the command error,
   then run:

```bash
scripts/upgrade-rollback.sh --plan <plan-id> --restore-active \
  --confirm 'RESTORE_ACTIVE:<plan-id>:<database>'
```

Active rollback holds a session-level advisory lock, takes and restore-verifies
a safety backup of the current database, restores the rollback dump into a
staging database, validates all table counts and the application release, then
drains connections and swaps database names. The old database remains intact
until live verification succeeds. A failed live check reverses the swap. The
receipt records both backups, digests, versions, database, and lock key.

After recovery, verify `/readyz`, critical sign-in/SSO/SCIM flows, the receipt,
backup copy status, and error-rate metrics. Record actual RPO/RTO and retain all
incident artifacts under access control.

## Legacy SCIM cutover gate

The hardened runtime refuses personal/global SCIM token creation, but previously
issued credentials remain valid until deleted. Before beta admission or upgrade:

```bash
scripts/scim-legacy-preflight.sh
# If blocked, rerun with the exact count-bound token it prints:
scripts/scim-legacy-preflight.sh --revoke \
  --confirm 'REVOKE_LEGACY_SCIM:<database>:<count>'
```

The command inventories only runtime rows without an organization, never reads
or prints bearer material, serializes deletion, refuses a changed count, proves
zero remain, and writes a read-only receipt. Organization-scoped providers are
left intact.

## External infrastructure responsibilities

- Terminate modern TLS and redirect HTTP before the API and console.
- Use managed Postgres HA/PITR and credentials with the database-create/rename/
  drop privileges required by the active rollback operator; runtime credentials
  may be narrower when a separate recovery URL is introduced.
- Encrypt and access-control Terraform/Kubernetes state and all Secrets.
- Monitor the scheduler, object destination, Postgres storage, certificate
  expiry, `/metrics`, and `/readyz` from outside the cluster.
- The console's operator sessions are process-local. A rollout requires operator
  re-login; keep one console replica until a durable session backend ships.
