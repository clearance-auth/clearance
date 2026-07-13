# Clearance Helm chart

This chart deploys the Clearance API and operator console against an external
Postgres database. Production defaults provide two API replicas, separate
process/dependency probes, graceful termination, a PodDisruptionBudget,
NetworkPolicy, Prometheus metrics, and external-Secret-backed credentials.

Create a Secret before install. Required API keys are `database-url`,
`clearance-secret`, `operator-token`, `credential-key`, and `credential-key-id`.
When the console is enabled, also supply `console-admin-user`,
`console-admin-password`, and `console-session-secret`.

```bash
helm lint deploy/helm/clearance \
  --set image.repository=ghcr.io/owner/clearance/clearance \
  --set-string image.digest=sha256:<signed-release-digest> \
  --set secrets.existingSecret=clearance-secrets \
  --set console.secrets.existingSecret=clearance-secrets \
  --set env.CLEARANCE_BASE_URL=https://auth.example.com \
  --set env.CLEARANCE_CORS_ORIGINS=https://console.example.com

helm upgrade --install clearance deploy/helm/clearance \
  --namespace clearance --create-namespace -f production-values.yaml \
  --set image.repository=ghcr.io/owner/clearance/clearance \
  --set-string image.digest=sha256:<signed-release-digest>
```

`image.repository` and `image.digest` are required and have no placeholder
defaults. Copy the `sha256:` digest from the signed release bundle and verify
its keyless cosign identity before deployment. Workloads render
`repository@sha256:...`; the console inherits the same immutable reference
unless explicitly given another signed digest.

Ingress is disabled until hosts and existing TLS Secret names are supplied.
Enable `ingress.api` and `ingress.console` independently. TLS defaults on for
either ingress and fails templating without `tls.secretName`.

`CLEARANCE_TRUSTED_PROXY` defaults to `0`. Setting it to `1` is supported only
for the chart's narrow console-proxy topology: NetworkPolicy enabled, API
Service type `ClusterIP`, API Ingress disabled, console enabled, and the default
release-local console-to-API URL. Templating fails for any broader topology so
direct clients cannot spoof `X-Forwarded-For` to bypass rate limits.

`metrics.enabled` exposes `/metrics`; enabling `metrics.serviceMonitor` creates
the Prometheus Operator CR. `/livez` checks the process only and `/readyz`
checks Postgres-backed store readiness, so dependency failure removes a pod
from service without creating a restart loop.

When `CLEARANCE_TRUSTED_PROXY=1` and the ServiceMonitor is enabled, set both
`metrics.networkPolicy.namespaceSelector` and
`metrics.networkPolicy.podSelector` to the labels of the Prometheus scraper.
The chart fails templating when either selector is empty and grants API-port
ingress only to pods matching both selectors; it does not open cluster-wide
application ingress.

Secret objects are external and Helm cannot hash their contents. Change
`restartToken` (and `console.restartToken`) after secret rotation to force a
controlled rollout. The checksum annotation also rolls pods when relevant
non-secret chart configuration changes.

## Scheduled off-host backup

Enable `backup.enabled`, provide a writable `ReadWriteMany` PVC (or let the chart create one),
set the published backup-runtime repository and signed digest in
`backup.image.repository` and `backup.image.digest`, and put
`database-url` plus `backup-copy-command` in `backup.existingSecret`.
The copy command receives the four exact artifact paths through environment
variables. The CronJob fails unless the copy hook succeeds, restore-verifies
the backup in an isolated database by default, and prunes only copies with a
successful off-host receipt. Build and publish the `backup-runtime` Docker
target as the configured `backup.image`; its official Postgres 16 base supplies
a matching `pg_dump`. The image and CronJob use fixed UID/GID 10001, a read-only
root filesystem, and writable mounts limited to `/backups` and `/tmp`. The
shared claim lets authenticated API backup/verify/restore commands and the
scheduled off-host copy job address the same artifacts across pods. The
default hourly schedule supports a one-hour RPO only
when the CronJob and destination are monitored.

The shipped deployment profile supports Postgres 16. For another server major,
publish a backup image from the matching official Postgres base and point
`backup.image` at it; never use an older `pg_dump` against a newer server.

The console currently keeps operator sessions in process memory. Keep its
default single replica and expect operator re-login during a rollout; client
affinity only reduces churn and does not make those sessions durable.

See [production operations](../../../docs/production-operations.md) for RPO,
RTO, recovery, SCIM cutover, alerts, and rollback rehearsal.
