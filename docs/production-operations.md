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
the signed release evidence. The overlay disables local image builds and
accepts only `repository@sha256:...` references.

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
