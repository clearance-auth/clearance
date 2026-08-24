#!/usr/bin/env bash
# Require a tag-triggered first publication to name a commit already reachable
# from the canonical repository's master branch.
set -Eeuo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

SOURCE_COMMIT="$(git rev-parse HEAD)"
CANONICAL_REF="origin/master"

[[ "$(git rev-parse --is-shallow-repository)" == "false" ]] \
  || die "release tag authority requires full Git history"
git rev-parse --verify --quiet "${CANONICAL_REF}^{commit}" >/dev/null \
  || die "canonical release branch ${CANONICAL_REF} is unavailable"
git merge-base --is-ancestor "$SOURCE_COMMIT" "$CANONICAL_REF" \
  || die "release tag commit ${SOURCE_COMMIT} is not reachable from ${CANONICAL_REF}"
