#!/usr/bin/env node

import { mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { publicReleasePackages } from "./release-packages.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const version = process.argv[2]?.trim();
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

if (!version || !semver.test(version)) {
	throw new Error(`Expected an exact stable SemVer version, received ${JSON.stringify(version ?? "")}`);
}

function read(relative) {
	return readFileSync(resolve(root, relative), "utf8");
}

function write(relative, value) {
	writeFileSync(resolve(root, relative), value, "utf8");
}

function versionManifest(relative) {
	const manifest = JSON.parse(read(relative));
	manifest.version = version;
	write(relative, `${JSON.stringify(manifest, null, 2)}\n`);
}

function replaceOne(relative, pattern, replacement, label) {
	const source = read(relative);
	const matches = source.match(pattern);
	if (!matches || matches.length !== 1) {
		throw new Error(`${relative} must contain exactly one ${label}`);
	}
	write(relative, source.replace(pattern, replacement));
}

for (const { manifest } of publicReleasePackages) versionManifest(manifest);
versionManifest("apps/sample-b2b/package.json");

replaceOne("deploy/helm/clearance/Chart.yaml", /^version: .*$/gm, `version: ${version}`, "chart version");
replaceOne("deploy/helm/clearance/Chart.yaml", /^appVersion: .*$/gm, `appVersion: "${version}"`, "chart appVersion");

const values = read("deploy/helm/clearance/values.yaml");
const releaseTags = values.match(/^\s+tag: "[^"]+"$/gm) ?? [];
if (releaseTags.length !== 2) throw new Error("Helm values must contain exactly two release image tags");
write("deploy/helm/clearance/values.yaml", values.replace(/^([ \t]+)tag: "[^"]+"$/gm, `$1tag: "${version}"`));

replaceOne("packages/clearance-auth/src/create-auth.ts", /export const CLEARANCE_AUTH_VERSION = "[^"]+";/g, `export const CLEARANCE_AUTH_VERSION = "${version}";`, "auth release constant");
replaceOne("packages/management/src/store/snapshot.ts", /export const CLEARANCE_RELEASE_VERSION = "[^"]+";/g, `export const CLEARANCE_RELEASE_VERSION = "${version}";`, "management release constant");
replaceOne("packages/clearance-api/src/server.ts", /(?<=\n\t\tversion: ")[^"]+(?=",)/g, version, "health release version");
replaceOne("packages/delivery-worker/src/worker.ts", /const VERSION = "[^"]+";/g, `const VERSION = "${version}";`, "delivery worker release constant");
replaceOne("README.md", /\*\*Current release:\*\* \[[^\]]+\]\(https:\/\/github\.com\/clearance-auth\/clearance\/releases\/tag\/v[^)]+\)/g, `**Current release:** [${version}](https://github.com/clearance-auth/clearance/releases/tag/v${version})`, "README current release link");

const changesetDirectory = resolve(root, ".changeset");
const archiveDirectory = resolve(changesetDirectory, "archive", `v${version}`);
const pending = readdirSync(changesetDirectory, { withFileTypes: true })
	.filter((entry) => entry.isFile() && entry.name.endsWith(".md") && entry.name !== "README.md")
	.map((entry) => entry.name)
	.sort();
if (pending.length > 0) {
	mkdirSync(archiveDirectory, { recursive: true });
	for (const name of pending) renameSync(resolve(changesetDirectory, name), resolve(archiveDirectory, basename(name)));
}

process.stdout.write(`RELEASE_VERSIONED ${version}\n`);
