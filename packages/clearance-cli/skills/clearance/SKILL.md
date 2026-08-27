---
name: clearance
description: Operate Clearance auth projects, environments, users, organizations, access controls, and migrations through the Clearance CLI. Use for authenticated Clearance administration and safe operational changes.
---

<!-- clearance-agent-skill: version=1 -->

# Clearance CLI

Start with `clearance commands --json`. It is the machine-readable command contract: use its paths, arguments, options, mutation status, confirmation requirements, and dry-run support to choose a command. Then use `clearance <command> --help` only when you need human detail. Prefer read-only discovery first: `whoami`, `project list`, `env inspect`, and resource `list` or `inspect` commands.

## Session selection

`--profile` selects a saved profile; otherwise `CLEARANCE_PROFILE`, then `default`, selects it. `CLEARANCE_OPERATOR_TOKEN` takes precedence over `CLEARANCE_API_TOKEN`; either environment token takes precedence over saved credentials. An environment token requires `--api-url` or `CLEARANCE_API_URL`. Do not combine an explicit `--profile` with either environment token. Remote API URLs must be HTTPS, except loopback HTTP.

## Output and errors

Use `--json` for automation. It emits one JSON document to stdout for either a result or error. Human results use stdout; human errors use stderr. Exit code `0` means success and every nonzero exit means failure. `--jq <expression>` selects from machine output and its result is the stdout contract. Do not parse human prose, assume a stable field beyond the documented JSON response, or expose bearer tokens, passwords, credentials, or secret-returning output in logs.

## Identifiers and concurrency

Pass IDs exactly as returned. A positional `<id>` is a resource identifier unless its command explicitly permits a slug or a path. Cursors are opaque and only valid for the matching list query. Preserve operation IDs for retryable credential operations. For replace/apply operations, retrieve the current resource or plan and pass the returned expected revision/version/plan identifier instead of guessing it.

## Mutations and unattended operation

Start with `--dry-run` when a command supports it. `--yes` is explicit confirmation for guarded mutations; it does not override validation, confirmation tokens, revisions, or server policy. A plan is evidence to review, not authority to apply. `--no-input` guarantees no interactive prompts: provide every required value explicitly, use `--password-stdin` only with piped input, and never use `--password-prompt`.

## Common workflows

```sh
clearance whoami --json
clearance commands --json
clearance users list --limit 100 --json
clearance users create --email user@example.com --name "Example User" --no-input --json
clearance orgs authorization reconcile --org <org-id> --dry-run --json
clearance orgs authorization reconcile --org <org-id> --yes --no-input --json
clearance auth-policy plan --file policy.json --json
```

## High-risk safeguards

Use the exact production profile or HTTPS origin and verify it with `whoami` before mutation. Keep `--dry-run` output with the change record. Never perform destructive actions, archive/revoke/delete/disable, credential rotation, or live migration without explicit user authorization, target verification, and the command's required `--yes` or confirmation token. Do not retry a mutation with a newly invented idempotency key, expected version, plan ID, drain ID, or confirmation token. Stop on an ambiguous result and inspect the resource or audit events first.
