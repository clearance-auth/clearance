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
  --set-string image.digest=sha256:<immutable-release-digest> \
  --set secrets.existingSecret=clearance-secrets \
  --set console.secrets.existingSecret=clearance-secrets \
  --set env.CLEARANCE_BASE_URL=https://auth.example.com \
  --set env.CLEARANCE_CORS_ORIGINS=https://console.example.com

helm upgrade --install clearance deploy/helm/clearance \
  --namespace clearance --create-namespace -f production-values.yaml \
  --set image.repository=ghcr.io/owner/clearance/clearance \
  --set-string image.digest=sha256:<immutable-release-digest>
```

`image.repository` and `image.digest` are required and have no placeholder
defaults. The chart validates immutable `sha256:` reference syntax. The release
gate separately verifies the bundle signature and keyless cosign identity
before deployment. Workloads render `repository@sha256:...`; the console
inherits the same immutable reference unless explicitly given another digest.

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

## Transactional delivery worker

Set `delivery.enabled=true` to deploy the separately scalable delivery worker.
The API and worker then share the delivery schema, prefix, quotas, and keyring.
The worker always reads `database-url` from `secrets.existingSecret`, the same
database authority used by the API. Add the following keys to
`delivery.existingSecret`, or to `secrets.existingSecret` when the
delivery-specific name is empty:

- `delivery-key-id` and `delivery-keys-json`
- `delivery-fingerprint-key-id` and `delivery-fingerprint-keys-json`
- `delivery-source-dedupe-key`

The delivery-specific Secret may also contain provider credentials such as
SMTP or SES keys. It does not become a second authority for `database-url`.

Each encryption, fingerprint, and source-dedupe value must decode to 32 bytes,
and every purpose must use different material. The JSON values map retained key
IDs to hex or base64 material. Generate each key independently. Keep retired
encryption and fingerprint keys in their rings until `clearance delivery
readiness` reports that queued and leased jobs no longer reference them.

SMTP requires `delivery.worker.email.from`, `smtp.host`, and an explicit
destination-scoped rule in `delivery.worker.networkPolicy.smtpEgress`. Each
rule must include at least one non-empty destination selector or CIDR and TCP
ports exactly matching `smtp.port`; empty rules and IPv4 or IPv6 `/0` CIDRs are
rejected.
The SMTP port must not overlap the worker's DNS, database, or HTTPS egress
ports, because such an overlap would bypass destination scoping. Put
optional authenticated SMTP credentials in `smtp-user` and `smtp-password`;
supplying only one makes worker startup fail. TLS or STARTTLS remains mandatory.

```yaml
delivery:
  enabled: true
  worker:
    email:
      transport: smtp
      from: auth@example.com
      smtp:
        host: smtp.example.com
        port: 587
        secure: false
        requireTls: true
    networkPolicy:
      dnsPeers:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
          podSelector:
            matchLabels: { k8s-app: kube-dns }
      databasePeers:
        - podSelector:
            matchLabels: { app.kubernetes.io/name: postgresql }
      smtpEgress:
        - to:
            - ipBlock: { cidr: 203.0.113.0/24 }
          ports:
            - { protocol: TCP, port: 587 }
```

SES requires `ses-access-key-id` and `ses-secret-access-key` in the Secret;
`ses-session-token` is optional. The worker currently reads explicit static or
session credentials, so workload-identity-only pods are unsupported. SES uses
the chart's HTTPS egress rule.

```yaml
delivery:
  enabled: true
  worker:
    email:
      transport: ses
      from: auth@example.com
      ses:
        region: us-east-1
    networkPolicy:
      dnsPeers:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
          podSelector:
            matchLabels: { k8s-app: kube-dns }
      databasePeers:
        - podSelector:
            matchLabels: { app.kubernetes.io/name: postgresql }
```

The worker Service is ClusterIP-only and has no Ingress. It serves `/live`,
`/ready`, and `/metrics` on the internal health port. Enabling its
ServiceMonitor requires `networkPolicy.enabled=true` and exact Prometheus
namespace and pod selectors under `delivery.worker.networkPolicy.metrics`.
When the worker and NetworkPolicy are enabled, non-empty `dnsPeers` and
`databasePeers` render as the `to` selectors for those egress rules. Set all
four worker CPU/memory requests and limits to concrete Kubernetes quantities.
Kubernetes probes remain node-local.
The PodDisruptionBudget assumes the default two replicas, and the 45-second
termination grace exceeds the default 30-second drain deadline.

The worker owns delivery schema migration during startup. A custom
`delivery.schema` must already exist, and the database role needs ownership or
the DDL grants required to create and verify owned delivery assets. After an
external Secret change, update both `restartToken` and
`delivery.worker.restartToken` so API producers and workers roll onto the same
ring. Rotate in two deployments: first add retained keys everywhere, then
switch the current IDs everywhere.

## Scheduled off-host backup

Enable `backup.enabled`, provide a writable `ReadWriteMany` PVC (or let the chart create one),
set the published backup-runtime repository and immutable digest in
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
