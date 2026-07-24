#!/usr/bin/env bash

# Assemble the release artifacts without signing, publishing, tagging, or making
# any external mutation. Run after the candidate has been built:
#   pnpm release:rehearse -- 0.3.0
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <exact-semver-version>" >&2
  exit 2
fi

VERSION="$1"
ASSET_DIRECTORY="dist-release/assets"

for TOOL in node pnpm helm tar; do
  command -v "$TOOL" >/dev/null || {
    echo "Required release assembly tool is unavailable: $TOOL" >&2
    exit 1
  }
done

node scripts/verify-release-version.mjs "$VERSION"

# Rehearsal evidence must be generated from an empty deterministic destination.
# Do not delete a prior run: preserve it for inspection and require the caller to
# move it aside (or to Trash) before a fresh rehearsal.
if [[ -e "$ASSET_DIRECTORY" ]]; then
  [[ -d "$ASSET_DIRECTORY" ]] || {
    echo "Release asset destination is not a directory: $ASSET_DIRECTORY" >&2
    exit 1
  }
  [[ -z "$(ls -A "$ASSET_DIRECTORY")" ]] || {
    echo "Release asset destination must be empty: $ASSET_DIRECTORY" >&2
    exit 1
  }
else
  mkdir -p "$ASSET_DIRECTORY"
fi

PACKAGES=()
while IFS= read -r PACKAGE; do
  PACKAGES+=("$PACKAGE")
done < <(node scripts/release-packages.mjs names)
node -e '
  const names = process.argv.slice(1);
  if (names.length !== 12 || new Set(names).size !== 12) {
    throw new Error("Release must contain exactly 12 unique public npm package names.");
  }
' "${PACKAGES[@]}"

for PACKAGE in "${PACKAGES[@]}"; do
  pnpm --filter "$PACKAGE" pack --pack-destination "$ASSET_DIRECTORY"
done

helm package deploy/helm/clearance --version "$VERSION" --app-version "$VERSION" --destination "$ASSET_DIRECTORY"

VAULT_PROOF_REPOSITORY="registry.example/clearance-vault"
VAULT_PROOF_DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
helm template clearance deploy/helm/clearance \
  --set credentialAuthority.phase=serve \
  --set credentialAuthority.deploymentId=release-vault-proof \
  --set secrets.existingSecret=release-proof \
  --set image.repository=registry.example/clearance \
  --set image.digest="$VAULT_PROOF_DIGEST" \
  --set vault.enabled=true \
  --set vault.image.repository="$VAULT_PROOF_REPOSITORY" \
  --set vault.image.digest="$VAULT_PROOF_DIGEST" \
  --set vault.secrets.existingSecret=release-proof \
  --set vault.publicUrl=https://vault.example.test \
  --set vault.projectId=release-proof \
  --set vault.environmentId=production \
  > "$ASSET_DIRECTORY/vault-rendered.yaml"
node -e '
  const fs = require("fs");
  const [file, repository, digest] = process.argv.slice(1);
  const source = fs.readFileSync(file, "utf8");
  const expected = `${repository}@${digest}`;
  if (!/^sha256:[0-9a-f]{64}$/.test(digest) || !source.includes(`image: "${expected}"`)) {
    throw new Error(`Vault render must contain exact immutable image ${expected}.`);
  }
' "$ASSET_DIRECTORY/vault-rendered.yaml" "$VAULT_PROOF_REPOSITORY" "$VAULT_PROOF_DIGEST"

pnpm list -r --prod --json --depth Infinity > "$ASSET_DIRECTORY/dependency-graph.json"
node -e '
  const fs = require("fs"), cp = require("child_process"), path = require("path");
  const [directory, version, ...expected] = process.argv.slice(1);
  const tarballs = fs.readdirSync(directory).filter((file) => file.endsWith(".tgz"));
  const packages = tarballs.map((file) => {
    try {
      return { file, name: JSON.parse(cp.execFileSync("tar", ["-xzf", path.join(directory, file), "-O", "package/package.json"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })).name };
    } catch {
      return { file, name: null };
    }
  });
  const names = packages.map(({ name }) => name).filter(Boolean);
  const chart = `clearance-${version}.tgz`;
  if (tarballs.length !== 13 || names.length !== 12 || new Set(names).size !== 12
      || expected.some((name) => !names.includes(name)) || !tarballs.includes(chart)
      || packages.filter(({ name }) => name === null).length !== 1) {
    throw new Error("Release must contain exactly 12 unique npm package tarballs and one Helm chart tarball.");
  }
' "$ASSET_DIRECTORY" "$VERSION" "${PACKAGES[@]}"

tarball_for() {
  node -e '
    const fs = require("fs"), cp = require("child_process"), path = require("path");
    const [directory, wanted] = process.argv.slice(1);
    const found = fs.readdirSync(directory).filter((file) => file.endsWith(".tgz")).find((file) => {
      try {
        const manifest = JSON.parse(cp.execFileSync("tar", ["-xzf", path.join(directory, file), "-O", "package/package.json"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
        return manifest.name === wanted;
      } catch {
        return false;
      }
    });
    if (!found) process.exit(1);
    process.stdout.write(path.join(directory, found));
  ' "$ASSET_DIRECTORY" "$1"
}

RUNTIME_CLOSURE_PACKAGES=()
while IFS= read -r PACKAGE; do
  RUNTIME_CLOSURE_PACKAGES+=("$PACKAGE")
done < <(node scripts/release-packages.mjs runtime-closure-names)
for PACKAGE in "${RUNTIME_CLOSURE_PACKAGES[@]}"; do
  node scripts/verify-release-runtime-closure.mjs "$(tarball_for "$PACKAGE")" \
    "$ASSET_DIRECTORY/$(echo "$PACKAGE" | tr '/@' '__')-runtime-closure.json"
done

echo "RELEASE_ASSEMBLY_REHEARSAL_OK $VERSION"
