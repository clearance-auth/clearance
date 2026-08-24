# Clearance Node Observability

`@clearance/observability-node` is the opt-in Node preload for correlated
Clearance OpenTelemetry traces. It registers HTTP and PostgreSQL
instrumentation only when explicitly enabled.

```sh
OTEL_SDK_DISABLED=false \
CLEARANCE_OTEL_SERVICE_NAME=clearance-api \
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://collector.example/v1/traces \
OTEL_EXPORTER_OTLP_HEADERS='authorization=Bearer example' \
OTEL_TRACES_SAMPLER=parentbased_traceidratio \
OTEL_TRACES_SAMPLER_ARG=0.1 \
node --import @clearance/observability-node/register ./dist/server.mjs
```

Only `clearance-api` and `clearance-delivery-worker` are valid service names.
The exporter must use HTTPS; plain HTTP is limited to a loopback collector for
local development. The bootstrap removes every attribute except safe HTTP
method/status and PostgreSQL system/operation attributes immediately before
OTLP serialization. URLs, query strings, headers, SQL text/parameters, and
exception messages/stacks cannot reach the exporter. `startObservability()`
returns an idempotent, timeout-bounded `shutdown()` operation for hosts that
manage their own process lifecycle. Shutdown resolves with the redacted status
after a complete flush and rejects with `ObservabilityShutdownError` carrying a
`failed` or `timed-out` reason otherwise. The preload performs the same bounded
flush before restoring normal `SIGINT` or `SIGTERM` termination.
