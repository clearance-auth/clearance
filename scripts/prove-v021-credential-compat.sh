#!/usr/bin/env bash
# Exact public @clearance/auth@0.2.1 credential-authority compatibility proof.
# Cryptographically binds the proof to the installed public artifact tree digest.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
FIXTURE_DIR="$ROOT/packages/clearance-auth/test-fixtures/v021-public"
LOCKFILE="$FIXTURE_DIR/package-lock.json"
EXPECTED_TARBALL='https://registry.npmjs.org/@clearance/auth/-/auth-0.2.1.tgz'
EXPECTED_INTEGRITY='sha512-qkrsSXwq2Kf7iWOTbeAzMfrFKMbrXAoNv1NgzCOl3Y6Ktt/soNo7VAipGRlM2Qb/sl9X3G0rb38UfoCHFP9Tcw=='
# Known installed public-tree manifest (sha512 hex of sorted "posixRel\tsha256hex\n" rows).
KNOWN_PUBLIC_TREE_DIGEST='01bd531bc9a19c1b6f54532ae953d398c2762873a683a1c0b055f3abaa80624f5ab6a553389d08851830b3d336c108413352dc0b6e922ea61b922d509c5b4980'
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
PROOF_TMP=""
cleanup() {
	# Temporary material only. Never delete repository paths or fixture node_modules.
	if [[ -n "${PROOF_TMP}" && -d "${PROOF_TMP}" ]]; then rm -rf "${PROOF_TMP}" 2>/dev/null || true; fi
}
trap cleanup EXIT

[[ -f "$LOCKFILE" ]] || die "missing fixture lockfile"
[[ -f "$FIXTURE_DIR/prove.mjs" && -f "$FIXTURE_DIR/package.json" ]] || die "missing fixture files"
command -v npm >/dev/null && command -v pnpm >/dev/null && command -v node >/dev/null \
	|| die "npm, pnpm, and node are required"

# Lock tarball+integrity check before install.
node --input-type=module - "$LOCKFILE" "$EXPECTED_TARBALL" "$EXPECTED_INTEGRITY" <<'EOF'
import fs from "node:fs";
const [p, t, i] = process.argv.slice(2);
const lock = JSON.parse(fs.readFileSync(p, "utf8"));
const e = lock.packages?.["node_modules/@clearance/auth"] ?? lock.dependencies?.["@clearance/auth"];
if (!e || typeof e !== "object") { console.error("error: lockfile missing @clearance/auth entry"); process.exit(1); }
if (String(e.resolved ?? "") !== t) { console.error("error: lockfile does not pin the exact public auth tarball URL"); process.exit(1); }
if (String(e.integrity ?? "") !== i) { console.error("error: lockfile does not pin the exact public auth integrity"); process.exit(1); }
EOF

(cd "$FIXTURE_DIR" && npm ci --ignore-scripts --no-audit --no-fund)

PROOF_TMP="$(mktemp -d "${TMPDIR:-/tmp}/clearance-v021-public.XXXXXX")"
# Fetch pinned tarball, SRI, archive preflight, extract, reject symlinks, match tree, bind known digest.
export CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST
CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST="$(
	node --input-type=module - "$FIXTURE_DIR" "$EXPECTED_TARBALL" "$EXPECTED_INTEGRITY" "$PROOF_TMP" "$KNOWN_PUBLIC_TREE_DIGEST" <<'EOF'
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
const [fixtureDir, tarballUrl, expectedIntegrity, tmp, known] = process.argv.slice(2);
const die = (m) => { console.error(`error: ${m}`); process.exit(1); };
const assertSafeMember = (name) => {
	if (typeof name !== "string" || !name || name.includes("\\") || name.includes("\0") || name.startsWith("/"))
		throw new Error(`unsafe member: ${name}`);
	const n = name.endsWith("/") ? name.slice(0, -1) : name;
	if (!n || (n !== "package" && !n.startsWith("package/"))) throw new Error(`outside package/: ${name}`);
	for (const s of n.split("/")) if (!s || s === "." || s === "..") throw new Error(`bad segment: ${name}`);
};
const assertAllowedType = (typeChar, line) => {
	if (typeChar !== "d" && typeChar !== "-") throw new Error(`disallowed type ${typeChar}`);
	if (/\s->\s/.test(line) || /\slink to\s/.test(line)) throw new Error("link member rejected");
};
// Deterministic negative checks (helpers only; no install mutation).
const mustThrow = (fn, label) => { try { fn(); die(`negative check did not reject: ${label}`); } catch (e) { if (String(e).includes("negative check did not reject")) throw e; } };
for (const [fn, label] of [
	[() => assertSafeMember("/package/x"), "absolute"], [() => assertSafeMember("package\\x"), "backslash"],
	[() => assertSafeMember("package//x"), "empty seg"], [() => assertSafeMember("package/./x"), ". seg"],
	[() => assertSafeMember("package/../x"), ".. seg"], [() => assertSafeMember("other/x"), "outside"],
	[() => assertAllowedType("l", "lrwxr-xr-x 0 0 0 0 Jan 1 00:00 package/l -> t"), "symlink"],
	[() => assertAllowedType("h", "hrw-r--r-- 0 0 0 0 Jan 1 00:00 package/h link to package/f"), "hardlink"],
	[() => assertAllowedType("c", "crw-r--r-- 0 0 0 0 Jan 1 00:00 package/dev"), "device"],
	[() => assertAllowedType("p", "prw-r--r-- 0 0 0 0 Jan 1 00:00 package/fifo"), "fifo"],
	[() => assertAllowedType("s", "srw-r--r-- 0 0 0 0 Jan 1 00:00 package/sock"), "socket"],
	[() => assertAllowedType("?", "?rw-r--r-- 0 0 0 0 Jan 1 00:00 package/u"), "unknown"],
]) mustThrow(fn, label);
if (!/^[0-9a-f]{128}$/.test(known)) die("KNOWN_PUBLIC_TREE_DIGEST is not 128 lowercase hex");
const wrongKnown = "0".repeat(128);
if (wrongKnown === known) die("wrong-known negative constant collided with KNOWN");
const tgz = path.join(tmp, "auth-0.2.1.tgz");
const res = await fetch(tarballUrl);
if (!res.ok) die(`failed to fetch pinned tarball (HTTP ${res.status})`);
const bytes = Buffer.from(await res.arrayBuffer());
fs.writeFileSync(tgz, bytes);
const sri = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
if (sri !== expectedIntegrity) die("pinned tarball SHA-512 SRI does not match EXPECTED_INTEGRITY");
// Archive preflight before extraction: names + verbose types (dirs/files only).
const names = execFileSync("tar", ["-tzf", tgz], { encoding: "utf8" }).split("\n").filter(Boolean);
const verbose = execFileSync("tar", ["-tvzf", tgz], { encoding: "utf8" }).split("\n").filter(Boolean);
if (!names.length || names.length !== verbose.length) die("archive member list empty or verbose mismatch");
for (let i = 0; i < names.length; i++) { assertSafeMember(names[i]); assertAllowedType(verbose[i][0], verbose[i]); }
execFileSync("tar", ["-xzf", tgz, "-C", tmp], { stdio: ["ignore", "ignore", "pipe"] });
const extracted = path.join(tmp, "package"), installed = path.join(fixtureDir, "node_modules/@clearance/auth");
if (!fs.existsSync(extracted) || !fs.existsSync(installed)) die("extracted or installed package tree missing");
// Manifest: sorted POSIX rel path + sha256 of regular-file bytes. No ignores (fail-closed).
const walk = (root) => {
	const rows = [];
	const rootSt = fs.lstatSync(root);
	if (rootSt.isSymbolicLink()) die(`symlink rejected at package root: ${root}`);
	if (!rootSt.isDirectory()) die(`package root is not a directory: ${root}`);
	const rec = (abs, rel) => {
		const st = fs.lstatSync(abs);
		if (st.isSymbolicLink()) die(`symlink rejected: ${rel || "."}`);
		if (st.isDirectory()) {
			for (const name of fs.readdirSync(abs).sort()) rec(path.join(abs, name), rel ? `${rel}/${name}` : name);
			return;
		}
		if (!st.isFile()) die(`non-regular file rejected: ${rel || "."}`);
		rows.push(`${rel}\t${createHash("sha256").update(fs.readFileSync(abs)).digest("hex")}`);
	};
	rec(root, "");
	return rows.sort();
};
const a = walk(extracted), b = walk(installed);
if (a.length !== b.length || a.some((line, i) => line !== b[i]))
	die("extracted package/ tree does not match installed node_modules/@clearance/auth");
const digest = createHash("sha512").update(b.length ? `${b.join("\n")}\n` : "", "utf8").digest("hex");
if (digest !== known) die("derived public tree digest does not equal KNOWN_PUBLIC_TREE_DIGEST");
if (wrongKnown === digest) die("wrong known tree digest must not match derived digest");
process.stdout.write(digest);
EOF
)"
[[ -n "${CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST}" ]] || die "missing CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST"
[[ "${CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST}" == "${KNOWN_PUBLIC_TREE_DIGEST}" ]] \
	|| die "exported tree digest must equal KNOWN_PUBLIC_TREE_DIGEST"
[[ "${#CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST}" -eq 128 ]] || die "public tree digest must be 128 hex chars"

# Installed path/version/no-mcp-no-oidc check after install.
node --input-type=module - "$FIXTURE_DIR" <<'EOF'
import fs from "node:fs"; import path from "node:path";
import { createRequire } from "node:module"; import { pathToFileURL } from "node:url";
const d = process.argv[2], req = createRequire(path.join(d, "package.json"));
let r; try { r = req.resolve("@clearance/auth"); } catch {
	console.error("error: could not resolve installed @clearance/auth"); process.exit(1);
}
const mods = path.join(path.resolve(d), "node_modules") + path.sep;
if (!path.resolve(r).startsWith(mods)) {
	console.error("error: public package resolved outside fixture node_modules"); process.exit(1);
}
const m = JSON.parse(fs.readFileSync(path.join(d, "node_modules/@clearance/auth/package.json"), "utf8"));
if (m.version !== "0.2.1") { console.error("error: installed public package is not version 0.2.1"); process.exit(1); }
const names = Object.keys(await import(pathToFileURL(r).href));
if (names.includes("mcp") || names.includes("oidcProvider")) {
	console.error("error: public 0.2.1 surface unexpectedly exports mcp or oidcProvider"); process.exit(1);
}
EOF

pnpm --filter @clearance/auth build
# Do not exec: keep EXIT trap so PROOF_TMP cleanup runs after the proof.
"$ROOT/scripts/test-with-postgres.sh" -- node "$FIXTURE_DIR/prove.mjs"
