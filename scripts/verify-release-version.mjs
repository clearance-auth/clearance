#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(process.env.CLEARANCE_RELEASE_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), ".."));
const version = process.argv[2]?.trim();
const semver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;

function fail(message) {
	process.stderr.write(`release version check failed: ${message}\n`);
	process.exit(1);
}

function yamlSection(source, name, indent = 0) {
	const prefix = " ".repeat(indent);
	const marker = `${prefix}${name}:`;
	const lines = source.split("\n");
	const start = lines.findIndex((line) => line === marker);
	if (start < 0) return "";
	let end = lines.length;
	for (let index = start + 1; index < lines.length; index += 1) {
		const line = lines[index];
		if (!line.trim() || line.trimStart().startsWith("#")) continue;
		const lineIndent = line.length - line.trimStart().length;
		if (lineIndent <= indent) { end = index; break; }
	}
	return lines.slice(start + 1, end).join("\n");
}

function yamlString(source, key, indent) {
	const match = source.match(new RegExp(`^${" ".repeat(indent)}${key}:\\s*["']?([^"'\\s]*)["']?\\s*$`, "m"));
	return match?.[1];
}

if (!version || !semver.test(version)) {
	fail(`expected an exact SemVer version, received ${JSON.stringify(version ?? "")}`);
}

const shippingPackages = [
	"packages/clearance-auth/package.json",
	"packages/management/package.json",
	"packages/clearance-cli/package.json",
	"packages/clearance-api/package.json",
	"packages/clearance-console/package.json",
	"apps/sample-b2b/package.json",
];

for (const relative of shippingPackages) {
	const manifest = JSON.parse(readFileSync(resolve(root, relative), "utf8"));
	if (manifest.version !== version) {
		fail(`${relative} is ${manifest.version}; expected ${version}`);
	}
}

const cli = JSON.parse(readFileSync(resolve(root, "packages/clearance-cli/package.json"), "utf8"));
if (cli.name !== "@clearance/cli" || cli.bin?.clearance !== "./dist/index.js") {
	fail("@clearance/cli must install the clearance binary from ./dist/index.js");
}


const bundledRuntimePackages = new Set([
	"@clearance/runtime",
	"@clearance/core",
	"@clearance/sso",
	"@clearance/scim",
	"@clearance/utils",
	"@clearance/call",
	"@clearance/telemetry",
	"@clearance/memory-adapter",
	"@clearance/kysely-adapter",
	"@clearance/mongo-adapter",
	"@clearance/drizzle-adapter",
	"@clearance/prisma-adapter",
]);

for (const relative of ["packages/clearance-auth/package.json", "packages/management/package.json"]) {
	const manifest = JSON.parse(readFileSync(resolve(root, relative), "utf8"));
	const substitutable = Object.keys(manifest.dependencies ?? {}).find((name) =>
		bundledRuntimePackages.has(name),
	);
	if (substitutable) fail(`${relative} production dependencies include substitutable fork package ${substitutable}`);
}

const chart = readFileSync(resolve(root, "deploy/helm/clearance/Chart.yaml"), "utf8");
const chartVersion = chart.match(/^version:\s*([^\s]+)\s*$/m)?.[1];
const appVersion = chart.match(/^appVersion:\s*["']?([^"'\s]+)["']?\s*$/m)?.[1];
if (chartVersion !== version || appVersion !== version) {
	fail(`Helm Chart version/appVersion must both be ${version}`);
}

const values = readFileSync(resolve(root, "deploy/helm/clearance/values.yaml"), "utf8");
const imageTag = yamlString(yamlSection(values, "image"), "tag", 2);
if (imageTag !== version) {
	fail(`Helm default image tag is ${imageTag ?? "missing"}; expected ${version}`);
}
const backupTag = yamlString(yamlSection(yamlSection(values, "backup"), "image", 2), "tag", 4);
if (backupTag !== version) {
	fail(`Helm backup image tag is ${backupTag ?? "missing"}; expected ${version}`);
}
const consoleTag = yamlString(yamlSection(yamlSection(values, "console"), "image", 2), "tag", 4);
if (consoleTag !== "" && consoleTag !== version) {
	fail(`Helm console image tag must inherit the release tag or equal ${version}`);
}

const authSource = readFileSync(resolve(root, "packages/clearance-auth/src/create-auth.ts"), "utf8");
const authVersion = authSource.match(/export const CLEARANCE_AUTH_VERSION = ["']([^"']+)["']/)?.[1];
if (authVersion !== version) {
	fail(`CLEARANCE_AUTH_VERSION is ${authVersion ?? "missing"}; expected ${version}`);
}

const managementSource = readFileSync(resolve(root, "packages/management/src/store/json-store.ts"), "utf8");
const managementVersion = managementSource.match(/export const CLEARANCE_RELEASE_VERSION = ["']([^"']+)["']/)?.[1];
if (managementVersion !== version) {
	fail(`CLEARANCE_RELEASE_VERSION is ${managementVersion ?? "missing"}; expected ${version}`);
}

const apiSource = readFileSync(resolve(root, "packages/clearance-api/src/server.ts"), "utf8");
const apiVersion = apiSource.match(/app\.get\(["']\/health["'][\s\S]*?version:\s*["']([^"']+)["']/)?.[1];
if (apiVersion !== version) {
	fail(`Clearance API health version is ${apiVersion ?? "missing"}; expected ${version}`);
}

const terraform = readFileSync(resolve(root, "deploy/terraform/variables.tf"), "utf8");
if (!terraform.includes("@sha256:[0-9a-f]{64}")) {
	fail("Terraform clearance_image must enforce an immutable repository@sha256 digest");
}

const releaseWorkflow = readFileSync(resolve(root, ".github/workflows/release-sign.yml"), "utf8");
const terraformSetup = releaseWorkflow.indexOf("hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd");
const terraformPin = releaseWorkflow.indexOf("terraform_version: 1.5.7", terraformSetup);
const releaseVerification = releaseWorkflow.indexOf("pnpm verify:real");
if (terraformSetup < 0 || terraformPin < terraformSetup || releaseVerification < terraformPin) {
	fail("release workflow must install pinned Terraform 1.5.7 before verify:real");
}
const dispatchRecoveryOnly = releaseWorkflow.indexOf('"$GITHUB_EVENT_NAME" == "workflow_dispatch" && "$RECOVER_PUBLISHED_NPM" != "1"');
const recoveryGuard = releaseWorkflow.indexOf('if [[ "$RECOVER_PUBLISHED_NPM" == "1" ]]', dispatchRecoveryOnly);
const guardedMasterRef = releaseWorkflow.indexOf('"$GITHUB_REF" == "refs/heads/master"', recoveryGuard);
const guardedWorkflowRef = releaseWorkflow.indexOf('"$GITHUB_WORKFLOW_REF" == "$GITHUB_REPOSITORY/.github/workflows/release-sign.yml@refs/heads/master"', recoveryGuard);
const guardedWorkflowSha = releaseWorkflow.indexOf('"$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA"', recoveryGuard);
if (dispatchRecoveryOnly < 0 || recoveryGuard < dispatchRecoveryOnly || guardedMasterRef < recoveryGuard
	|| guardedWorkflowRef < guardedMasterRef
	|| guardedWorkflowSha < guardedWorkflowRef) {
	fail("release workflow must reserve canonical master dispatches for explicit npm recovery");
}
const tagIdentity = 'release-sign.yml@refs/tags/v${VERSION}';
const tagIdentityIndex = releaseWorkflow.indexOf(tagIdentity, guardedWorkflowSha);
const exportedIdentity = releaseWorkflow.indexOf('echo "COSIGN_IDENTITY=$COSIGN_IDENTITY" >> "$GITHUB_ENV"', tagIdentityIndex);
if (tagIdentityIndex < 0 || exportedIdentity < tagIdentityIndex
	|| releaseWorkflow.includes('COSIGN_IDENTITY="https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release-sign.yml@refs/heads/master"')) {
	fail("release workflow must export the tag signing identity for publication and recovery verification");
}
const releaseNpmPins = [...releaseWorkflow.matchAll(/npm install --global npm@([0-9.]+)/g)].map((match) => match[1]);
if (releaseNpmPins.length !== 2 || releaseNpmPins.some((pin) => pin !== "11.16.0")
	|| !releaseWorkflow.includes("npm audit signatures --prefix \"$AUDIT_DIR\" --json --include-attestations")) {
	fail("release workflow must use npm 11.16.0 with attestation evidence enabled");
}
const stagingBuild = releaseWorkflow.indexOf("--tag \"$STAGING_IMAGE\"");
const cosignVerifications = [...releaseWorkflow.matchAll(/cosign verify --certificate-identity "\$COSIGN_IDENTITY"/g)];
const cosignVerify = releaseWorkflow.indexOf('cosign verify --certificate-identity "$COSIGN_IDENTITY"');
const finalTag = releaseWorkflow.indexOf("docker buildx imagetools create --tag \"$IMAGE\"");
const npmPublish = releaseWorkflow.indexOf('npm publish "$(tarball_for "$PACKAGE")"');
if (cosignVerifications.length !== 4 || stagingBuild < 0 || cosignVerify < stagingBuild
	|| finalTag < cosignVerify || npmPublish < finalTag) {
	fail("release workflow must build staging references, verify keyless signatures, create final tags, then publish npm");
}

for (const relative of [
	"deploy/helm/clearance/templates/deployment.yaml",
	"deploy/helm/clearance/templates/console-deployment.yaml",
	"deploy/helm/clearance/templates/backup.yaml",
	"deploy/compose/docker-compose.production.yml",
]) {
	const source = readFileSync(resolve(root, relative), "utf8");
	if (!source.includes("@")) fail(`${relative} must deploy an immutable digest reference`);
}

process.stdout.write(`RELEASE_VERSION_OK ${version}\n`);
