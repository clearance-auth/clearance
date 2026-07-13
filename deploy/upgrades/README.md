# Upgrade step hooks

`scripts/upgrade-apply.sh` requires a hook:

```text
deploy/upgrades/steps/<targetVersion>/apply.sh
```

The currently supported transition is `0.1.3` to `0.2.0`. Its shipped hook is
`deploy/upgrades/steps/0.2.0/apply.sh`; it verifies the release marker is at
`0.1.3`, advances it to `0.2.0`, and verifies the result. The Clearance CLI
packages this hook under `dist/ops/deploy/upgrades/steps/0.2.0/apply.sh`.

## Contract

- Invoked only after preflight and a **verified** Postgres backup (with isolated restore verification).
- Args: `--plan PATH --from CURRENT --to TARGET`
- Exit non-zero to fail closed (no silent partial apply).
- Must not drop or overwrite the active database; destructive changes require explicit operator runbooks.
- Rollback reference is always the verified backup id recorded in the plan state sidecar.

Without a hook, apply fails after creating and verifying its rollback backup. It never records a no-op version transition as applied.

`scripts/upgrade-rollback.sh` is a rollback **drill**: it verifies the deterministic backup reference through an isolated restore and leaves the active environment unchanged. An actual rollback remains an operator-runbook action until active restore automation is designed and tested separately.
