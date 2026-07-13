# Security

Report vulnerabilities to the Clearance maintainers (private disclosure). Do not file public issues for active exploits.

## Supported releases

- Current `0.x` development line: best-effort fixes on `main`.

## Policy highlights

- Privileged mutations emit audit events.
- No remote telemetry by default.
- Secrets are write-only after creation (fingerprints only on read).
- Forbidden third-party telemetry hosts are blocked by `clearance doctor`.
