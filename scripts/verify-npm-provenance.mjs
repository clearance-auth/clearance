#!/usr/bin/env node

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

const [version, sourceCommit, auditPath, assetDirectory, outputPath, ...packages] = process.argv.slice(2);

if (!version || !sourceCommit || !auditPath || !assetDirectory || !outputPath || packages.length === 0) {
	console.error("Usage: node scripts/verify-npm-provenance.mjs <version> <source-commit> <audit-json> <asset-directory> <output-json> <package> [...package]");
	process.exit(2);
}

if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
	throw new Error(`Expected an exact SemVer version, received ${version}.`);
}

if (!/^[0-9a-f]{40}$/.test(sourceCommit)) {
	throw new Error(`Expected a full lowercase Git commit, received ${sourceCommit}.`);
}

const repository = "https://github.com/clearance-auth/clearance";
const certificateIssuer = "https://token.actions.githubusercontent.com";
const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const certificateIdentity = `^https://github\\.com/clearance-auth/clearance/\\.github/workflows/release-sign\\.yml@refs/tags/v${escapedVersion}$`;
const workflow = {
	path: ".github/workflows/release-sign.yml",
	ref: `refs/tags/v${version}`,
	repository,
};
const require = createRequire(import.meta.url);
const npmRoot = execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim();
const { verify: verifySigstore } = require(join(npmRoot, "npm/node_modules/sigstore"));

const audit = JSON.parse(readFileSync(auditPath, "utf8"));
if (!Array.isArray(audit.invalid) || audit.invalid.length !== 0
	|| !Array.isArray(audit.missing) || audit.missing.length !== 0
	|| !Array.isArray(audit.verified)) {
	throw new Error("npm audit signatures did not return a fully verified result.");
}

function decodePayload(attestation) {
	const payload = attestation?.bundle?.dsseEnvelope?.payload;
	if (typeof payload !== "string" || payload.length === 0) throw new Error("Attestation has no DSSE payload.");
	return JSON.parse(Buffer.from(payload, "base64").toString("utf8"));
}

function subjectFor(statement, packageName) {
	const expected = `pkg:npm/${encodeURIComponent(packageName).replace(/%2F/gi, "/")}@${version}`;
	return statement.subject?.find((subject) => subject.name === expected);
}

function tarballFor(packageName) {
	const matches = readdirSync(assetDirectory).filter((file) => file.endsWith(".tgz") && (() => {
		try {
			const manifest = JSON.parse(execFileSync("tar", ["-xzf", join(assetDirectory, file), "-O", "package/package.json"], {
				encoding: "utf8",
				stdio: ["ignore", "pipe", "ignore"],
			}));
			return manifest.name === packageName && manifest.version === version;
		} catch {
			return false;
		}
	})());
	if (matches.length !== 1) {
		throw new Error(`Expected one registry tarball for ${packageName}@${version}; found ${matches.length}.`);
	}
	return matches[0];
}

const evidence = {
	schemaVersion: 1,
	registry: "https://registry.npmjs.org/",
	sourceCommit,
	sourceTag: `v${version}`,
	workflow,
	certificateIdentity,
	certificateIssuer,
	packages: [],
};

for (const packageName of packages) {
	const verified = audit.verified.filter((item) => item.name === packageName && item.version === version);
	if (verified.length !== 1 || verified[0].registry !== "https://registry.npmjs.org/") {
		throw new Error(`${packageName}@${version} is not uniquely verified against the public npm registry.`);
	}
	const bundles = verified[0].attestationBundles;
	const publishes = bundles?.filter((item) =>
		item.predicateType === "https://github.com/npm/attestation/tree/main/specs/publish/v0.1") ?? [];
	const provenances = bundles?.filter((item) => item.predicateType === "https://slsa.dev/provenance/v1") ?? [];
	if (publishes.length !== 1 || provenances.length !== 1) {
		throw new Error(`${packageName}@${version} does not have exactly one verified npm publish and SLSA provenance bundle.`);
	}
	const [publish] = publishes;
	const [provenance] = provenances;
	await verifySigstore(provenance.bundle, { certificateIdentityURI: certificateIdentity, certificateIssuer });

	const publishStatement = decodePayload(publish);
	const provenanceStatement = decodePayload(provenance);
	const publishSubject = subjectFor(publishStatement, packageName);
	const provenanceSubject = subjectFor(provenanceStatement, packageName);
	if (!publishSubject || !provenanceSubject) {
		throw new Error(`${packageName}@${version} attestations do not name the expected package subject.`);
	}
	const tarball = tarballFor(packageName);
	const expectedDigest = createHash("sha512").update(readFileSync(join(assetDirectory, tarball))).digest("hex");
	if (publishSubject.digest?.sha512 !== expectedDigest || provenanceSubject.digest?.sha512 !== expectedDigest) {
		throw new Error(`${packageName}@${version} attestation digest does not match registry integrity.`);
	}
	const publishPredicate = publishStatement.predicate;
	if (publishPredicate?.name !== packageName || publishPredicate?.version !== version
		|| publishPredicate?.registry !== "https://registry.npmjs.org") {
		throw new Error(`${packageName}@${version} npm publish attestation has unexpected package metadata.`);
	}
	const definition = provenanceStatement.predicate?.buildDefinition;
	const recordedWorkflow = definition?.externalParameters?.workflow;
	if (recordedWorkflow?.path !== workflow.path || recordedWorkflow?.ref !== workflow.ref
		|| recordedWorkflow?.repository !== workflow.repository) {
		throw new Error(`${packageName}@${version} provenance is not bound to the expected release workflow and tag.`);
	}
	const source = definition?.resolvedDependencies?.find((dependency) => dependency.digest?.gitCommit === sourceCommit);
	if (!source || source.uri !== `git+${repository}@refs/tags/v${version}`) {
		throw new Error(`${packageName}@${version} provenance is not bound to source commit ${sourceCommit}.`);
	}

	console.log(`Verified npm provenance for ${packageName}@${version} at ${sourceCommit}.`);
	evidence.packages.push({ name: packageName, version, tarball, sha512: expectedDigest });
}

writeFileSync(outputPath, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
