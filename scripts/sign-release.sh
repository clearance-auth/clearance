#!/usr/bin/env bash
# Fail-closed release artifact packaging + cryptographic signing.
# Never fabricates signatures. Never claims unsigned artifacts are signed.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist-release}"
VERSION="${CLEARANCE_VERSION:-}"
ASSET_DIR="${CLEARANCE_RELEASE_ASSET_DIR:-$OUT/assets}"
REQUIRE_ASSETS="${CLEARANCE_REQUIRE_RELEASE_ASSETS:-0}"
REQUIRE_TAG_BINDING="${CLEARANCE_REQUIRE_TAG_BINDING:-0}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_cmd openssl
require_cmd node

[[ -n "$VERSION" ]] || die "CLEARANCE_VERSION is required"
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?(\+([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$ ]] \
  || die "CLEARANCE_VERSION must be exact SemVer: $VERSION"

# --- Provenance (mandatory) --------------------------------------------------
# Releases sign committed, tagged history only. This check lives here (not in
# verify-real.sh) because default CI clones are shallow/tagless; release jobs
# must fetch full history (fetch-depth: 0).
git -C "$ROOT" rev-parse HEAD >/dev/null 2>&1 \
  || die "release requires committed history (no commits found)"
SOURCE_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
SOURCE_TAG=""
if [[ "$REQUIRE_TAG_BINDING" == "1" ]]; then
  [[ "$(git -C "$ROOT" rev-parse --is-shallow-repository)" == "false" ]] \
    || die "tag-bound release requires full Git history"
  [[ "$(git -C "$ROOT" rev-parse "refs/tags/v${VERSION}^{commit}" 2>/dev/null)" == "$SOURCE_COMMIT" ]] \
    || die "tag v${VERSION} must exist and resolve to HEAD ($SOURCE_COMMIT)"
  SOURCE_TAG="v$VERSION"
  node "$ROOT/scripts/verify-release-version.mjs" "$VERSION"
fi

# --- Signing key (mandatory) -------------------------------------------------
# Provide either:
#   CLEARANCE_RELEASE_SIGNING_KEY_FILE  path to PEM private key
#   CLEARANCE_RELEASE_SIGNING_KEY       PEM contents (CI secret)
KEY_FILE="${CLEARANCE_RELEASE_SIGNING_KEY_FILE:-}"
TMP_KEY=""
cleanup() {
  if [[ -n "$TMP_KEY" && -f "$TMP_KEY" ]]; then
    rm -f "$TMP_KEY"
  fi
}
trap cleanup EXIT

if [[ -z "$KEY_FILE" && -n "${CLEARANCE_RELEASE_SIGNING_KEY:-}" ]]; then
  TMP_KEY="$(mktemp "${TMPDIR:-/tmp}/clearance-sign-key.XXXXXX")"
  # Restrictive perms before writing key material
  umask 077
  printf '%s\n' "$CLEARANCE_RELEASE_SIGNING_KEY" >"$TMP_KEY"
  KEY_FILE="$TMP_KEY"
fi

[[ -n "$KEY_FILE" && -f "$KEY_FILE" && -s "$KEY_FILE" ]] \
  || die "signing key required: set CLEARANCE_RELEASE_SIGNING_KEY_FILE or CLEARANCE_RELEASE_SIGNING_KEY (fail closed; no ephemeral or fake signatures)"

# Validate key is a private key openssl can use
openssl pkey -in "$KEY_FILE" -noout -check >/dev/null 2>&1 \
  || openssl rsa -in "$KEY_FILE" -check -noout >/dev/null 2>&1 \
  || die "CLEARANCE_RELEASE_SIGNING_KEY is not a usable private key"

mkdir -p "$OUT"
printf '%s\n' "$VERSION" >"$OUT/VERSION"

# Bind the signature to every shipping package and the immutable container
# reference/digest produced by release CI. Local contract tests may omit assets;
# release CI sets CLEARANCE_REQUIRE_RELEASE_ASSETS=1 and fails closed.
: >"$OUT/assets.sha256"
if [[ -d "$ASSET_DIR" ]]; then
  while IFS= read -r asset; do
    rel="${asset#"$ASSET_DIR"/}"
    if command -v sha256sum >/dev/null 2>&1; then
      digest="$(sha256sum "$asset" | awk '{print $1}')"
    else
      digest="$(shasum -a 256 "$asset" | awk '{print $1}')"
    fi
    printf '%s  %s\n' "$digest" "$rel" >>"$OUT/assets.sha256"
  done < <(find "$ASSET_DIR" -type f -print | LC_ALL=C sort)
fi
if [[ "$REQUIRE_ASSETS" == "1" && ! -s "$OUT/assets.sha256" ]]; then
  die "release assets are required but none were found under $ASSET_DIR"
fi

# SBOM package versions come from the same manifests that produced the tarballs.
node - "$ROOT" "$OUT/sbom.cdx.json" "$VERSION" <<'EOF'
const fs = require("fs");
const path = require("path");
const [root, output, version] = process.argv.slice(2);
const manifests = [
  "packages/clearance-auth/package.json",
  "packages/management/package.json",
  "packages/clearance-cli/package.json",
  "packages/clearance-api/package.json",
].map((relative) => JSON.parse(fs.readFileSync(path.join(root, relative), "utf8")));
const document = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    component: { type: "application", name: "clearance", version },
  },
  components: manifests.map(({ name, version: packageVersion }) => ({
    type: "library",
    name,
    version: packageVersion,
  })),
};
fs.writeFileSync(output, `${JSON.stringify(document, null, 2)}\n`);
EOF

# Bundle bytes that are signed
cat "$OUT/VERSION" "$OUT/sbom.cdx.json" "$OUT/assets.sha256" >"$OUT/release-bundle.txt"

# Detached signature over the bundle (real private key only)
if ! openssl dgst -sha256 -sign "$KEY_FILE" -out "$OUT/release-bundle.sig" "$OUT/release-bundle.txt"; then
  die "openssl signing failed (fail closed)"
fi
[[ -s "$OUT/release-bundle.sig" ]] || die "signature file empty after openssl dgst -sign"

# Content digest (not a signature)
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$OUT/release-bundle.txt" | awk '{print $1}' >"$OUT/release-bundle.sha256"
else
  shasum -a 256 "$OUT/release-bundle.txt" | awk '{print $1}' >"$OUT/release-bundle.sha256"
fi
DIGEST="$(tr -d ' \n' <"$OUT/release-bundle.sha256")"

# Public key material for verification (safe to distribute)
openssl pkey -in "$KEY_FILE" -pubout -out "$OUT/release-public.pem" 2>/dev/null \
  || openssl rsa -in "$KEY_FILE" -pubout -out "$OUT/release-public.pem" 2>/dev/null \
  || die "failed to export public key for verification"

# Self-verify immediately (fail closed if signature does not verify)
openssl dgst -sha256 -verify "$OUT/release-public.pem" -signature "$OUT/release-bundle.sig" "$OUT/release-bundle.txt" >/dev/null \
  || die "signature self-verification failed"

# Provenance attestation — only written after a verified signature exists
cat >"$OUT/provenance.json" <<EOF
{
  "predicateType": "https://clearance.dev/attestation/v1",
  "subject": [
    {
      "name": "clearance",
      "version": "$VERSION",
      "digest": { "sha256": "$DIGEST" }
    }
  ],
  "predicate": {
    "builder": "scripts/sign-release.sh",
    "sourceCommit": "$SOURCE_COMMIT",
    "sourceTag": "$SOURCE_TAG",
    "releaseVersion": "$VERSION",
    "signed": true,
    "signatureFile": "release-bundle.sig",
    "publicKeyFile": "release-public.pem",
    "signedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "assetManifest": "assets.sha256"
  }
}
EOF

# Refuse "unsigned" placeholders in provenance
if grep -qiE 'unsigned|placeholder|fake|ephemeral' "$OUT/provenance.json"; then
  die "provenance contained forbidden unsigned/fake markers"
fi

printf 'Signed release artifacts written to %s (version=%s sha256=%s)\n' "$OUT" "$VERSION" "$DIGEST"
ls -la "$OUT"
