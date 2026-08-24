#!/usr/bin/env bash
# Verify the detached release bundle using an identity anchored outside the
# downloaded asset set. In particular, never accept a public key or identity
# declared by the release bundle itself.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PUBLISHER_REPOSITORY="${CLEARANCE_RELEASE_PUBLISHER_REPOSITORY:-clearance-auth/clearance}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

if [[ "${1:-}" == "--self-test" ]]; then
  forged="$(mktemp -d "${TMPDIR:-/tmp}/clearance-forged-release.XXXXXX")"
  trap 'rm -rf "$forged"' EXIT
  printf '0.1.0-test\n' >"$forged/VERSION"
  printf 'forged bundle\n' >"$forged/release-bundle.txt"
  printf '{}\n' >"$forged/release-bundle.sigstore.json"
  # A substituted sibling key is deliberately ignored by the verifier.
  printf 'forged sibling public key\n' >"$forged/release-public.pem"
  : >"$forged/assets.sha256"
  if CLEARANCE_RELEASE_CERTIFICATE_IDENTITY='https://github.com/attacker/release-sign.yml@refs/tags/v0.1.0-test' \
    "$0" "$forged" >/dev/null 2>&1; then
    die "forged replacement identity/key was accepted"
  fi
  if CLEARANCE_RELEASE_ALLOW_RECOVERY_IDENTITY=1 \
    CLEARANCE_RELEASE_CERTIFICATE_IDENTITY='https://github.com/clearance-auth/clearance/.github/workflows/release-sign.yml@refs/tags/v0.1.0-test' \
    "$0" "$forged" >/dev/null 2>&1; then
    die "tag identity was accepted in the explicit recovery trust mode"
  fi
  printf 'RELEASE_BUNDLE_SELF_TEST_OK\n'
  exit 0
fi

OUT="${1:-$ROOT/dist-release}"
[[ -d "$OUT" ]] || die "release bundle directory does not exist: $OUT"
[[ "$PUBLISHER_REPOSITORY" == "clearance-auth/clearance" ]] \
  || die "publisher repository is fixed to clearance-auth/clearance for public release verification"

VERSION="$(tr -d '[:space:]' <"$OUT/VERSION" 2>/dev/null || true)"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?(\+([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$ ]] \
  || die "release bundle has no valid exact SemVer VERSION"

# This is a verifier trust anchor, not an artifact property. It binds the
# certificate to the canonical release workflow and the immutable release tag.
EXPECTED_IDENTITY="https://github.com/${PUBLISHER_REPOSITORY}/.github/workflows/release-sign.yml@refs/tags/v${VERSION}"
if [[ "${CLEARANCE_RELEASE_ALLOW_RECOVERY_IDENTITY:-0}" == "1" ]]; then
  # Recovery is explicitly enabled by the canonical master-only workflow gate;
  # callers must opt into this separate, still independently anchored ref.
  EXPECTED_IDENTITY="https://github.com/${PUBLISHER_REPOSITORY}/.github/workflows/release-sign.yml@refs/heads/master"
fi
[[ -z "${CLEARANCE_RELEASE_CERTIFICATE_IDENTITY:-}" || "$CLEARANCE_RELEASE_CERTIFICATE_IDENTITY" == "$EXPECTED_IDENTITY" ]] \
  || die "configured certificate identity does not match the canonical tag-bound release workflow"
[[ -z "${CLEARANCE_RELEASE_CERTIFICATE_OIDC_ISSUER:-}" || "$CLEARANCE_RELEASE_CERTIFICATE_OIDC_ISSUER" == "$OIDC_ISSUER" ]] \
  || die "configured certificate OIDC issuer does not match GitHub Actions"

require_cmd cosign

for artifact in release-bundle.txt release-bundle.sigstore.json assets.sha256; do
  [[ -s "$OUT/$artifact" ]] || die "required release artifact is missing or empty: $artifact"
done

cosign verify-blob --bundle "$OUT/release-bundle.sigstore.json" \
  --certificate-identity "$EXPECTED_IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$OUT/release-bundle.txt" >/dev/null

if [[ -s "$OUT/assets.sha256" ]]; then
  [[ -d "$OUT/assets" ]] || die "release asset directory is missing for a nonempty asset manifest"
  (cd "$OUT/assets" && sha256sum --check ../assets.sha256)
fi
printf 'Verified keyless release bundle for %s from %s\n' "$VERSION" "$EXPECTED_IDENTITY"
