#!/usr/bin/env bash
# Compatibility entrypoint for the canonical local release verification.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec bash "$ROOT/scripts/verify-real.sh"
