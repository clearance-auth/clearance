#!/usr/bin/env node

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { join, relative, resolve } from "node:path";

const tarball = process.argv[2] ? resolve(process.argv[2]) : undefined;
const output = process.argv[3] ? resolve(process.argv[3]) : undefined;
if (!tarball) {
	console.error("Usage: node scripts/verify-release-runtime-closure.mjs <auth-tarball> [evidence-json]");
	process.exit(2);
}

function tar(...args) {
	return execFileSync("tar", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

function sha256(value) {
	return createHash("sha256").update(value).digest("hex");
}

function filesUnder(directory) {
	const files = [];
	for (const entry of readdirSync(directory, { withFileTypes: true })) {
		const path = join(directory, entry.name);
		if (entry.isDirectory()) files.push(...filesUnder(path));
		else if (entry.isFile()) files.push(path);
	}
	return files;
}

function hashDirectories(directories) {
	const hash = createHash("sha256");
	for (const directory of directories) {
		for (const file of filesUnder(directory).sort()) {
			hash.update(relative(process.cwd(), file));
			hash.update("\0");
			hash.update(readFileSync(file));
			hash.update("\0");
		}
	}
	return hash.digest("hex");
}

function stripComments(source) {
	let result = "";
	let state = "code";
	for (let index = 0; index < source.length; index += 1) {
		const char = source[index];
		const next = source[index + 1];
		if (state === "line") {
			if (char === "\n") { state = "code"; result += char; }
			else result += " ";
			continue;
		}
		if (state === "block") {
			if (char === "*" && next === "/") { state = "code"; result += "  "; index += 1; }
			else result += char === "\n" ? "\n" : " ";
			continue;
		}
		if (state === "single" || state === "double" || state === "template") {
			result += char;
			if (char === "\\") {
				if (next !== undefined) { result += next; index += 1; }
				continue;
			}
			if ((state === "single" && char === "'") || (state === "double" && char === '"') || (state === "template" && char === "`")) state = "code";
			continue;
		}
		if (char === "/" && next === "/") { state = "line"; result += "  "; index += 1; continue; }
		if (char === "/" && next === "*") { state = "block"; result += "  "; index += 1; continue; }
		if (char === "'") state = "single";
		else if (char === '"') state = "double";
		else if (char === "`") state = "template";
		result += char;
	}
	return result;
}

const entries = tar("-tzf", tarball).trim().split("\n").filter(Boolean);
if (entries.some((entry) => entry.includes("../") || entry.startsWith("/") || entry.includes("/node_modules/"))) {
	throw new Error("Auth tarball contains an unsafe path or an embedded node_modules tree.");
}

const packageJson = JSON.parse(tar("-xOzf", tarball, "package/package.json"));
if (packageJson.name !== "@clearance/auth" && packageJson.name !== "@clearance/management") {
	throw new Error("Expected an @clearance/auth or @clearance/management tarball.");
}
const dependencySections = ["dependencies", "peerDependencies", "optionalDependencies"];
const declaredDependencies = Object.fromEntries(
	dependencySections.flatMap((section) =>
		Object.entries(packageJson[section] ?? {}).map(([name, version]) => [name, { section, version }]),
	),
);
const dependencies = Object.keys(packageJson.dependencies ?? {}).sort();
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
const forbiddenDependency = Object.keys(declaredDependencies)
	.find((name) => bundledRuntimePackages.has(name));
if (forbiddenDependency) throw new Error(`Published auth runtime still depends on substitutable package ${forbiddenDependency}.`);
const localDependency = Object.entries(declaredDependencies).find(([, metadata]) =>
	/^(?:workspace:|catalog:|link:|file:)/.test(String(metadata.version)),
);
if (localDependency) {
	const [name, metadata] = localDependency;
	throw new Error(`Published package has unresolved local ${metadata.section} entry ${name}@${metadata.version}.`);
}

const allowedBare = new Set([...dependencies, ...builtinModules, ...builtinModules.map((name) => `node:${name}`)]);
const runtimeFiles = entries.filter((entry) => /^package\/dist\/.*\.(?:mjs|cjs|js)$/.test(entry));
if (runtimeFiles.length === 0) throw new Error("Auth tarball contains no runtime files.");
function collectBareImports(files) {
	const imports = new Set();
	for (const file of files) {
		const source = stripComments(tar("-xOzf", tarball, file));
		const patterns = [
			/(?:^|[;\n])\s*(?:import|export)\s+(?:[^"']*?\s+from\s+)?["']([^"']+)["']/g,
			/\b(?:import|require)\s*\(\s*["']([^"']+)["']\s*\)/g,
		];
		for (const pattern of patterns) {
			for (const match of source.matchAll(pattern)) {
				const specifier = match[1];
				if (specifier.startsWith(".") || specifier.startsWith("/") || specifier.startsWith("#")) continue;
				imports.add(specifier);
			}
		}
	}
	return imports;
}

const bareImports = collectBareImports(runtimeFiles);

const unresolved = [...bareImports].filter((specifier) => {
	if (specifier.startsWith("bun:")) return false;
	const packageName = specifier.startsWith("@") ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0];
	return !allowedBare.has(specifier) && !allowedBare.has(packageName);
}).sort();
if (unresolved.length > 0) throw new Error(`Auth tarball has undeclared bare runtime imports: ${unresolved.join(", ")}`);

const declarationFiles = entries.filter((entry) => /^package\/(?:dist|types)\/.*\.d\.(?:mts|cts|ts)$/.test(entry));
if (declarationFiles.length === 0) throw new Error("Package tarball contains no declarations.");
const declarationImports = collectBareImports(declarationFiles);
const unresolvedDeclarations = [...declarationImports].filter((specifier) => {
	if (specifier.startsWith("node:") || specifier.startsWith("bun:")) return false;
	const packageName = specifier.startsWith("@") ? specifier.split("/").slice(0, 2).join("/") : specifier.split("/")[0];
	return !allowedBare.has(specifier) && !allowedBare.has(packageName);
}).sort();
if (unresolvedDeclarations.length > 0) {
	throw new Error(`Package declarations have undeclared bare imports: ${unresolvedDeclarations.join(", ")}`);
}

const forkInputs = ["packages/runtime/dist", "packages/core/dist", "packages/sso/dist", "packages/scim/dist"]
	.map((path) => resolve(path))
	.filter((path) => statSync(path).isDirectory());
const evidence = {
	schemaVersion: 1,
	package: `${packageJson.name}@${packageJson.version}`,
	tarballSha256: sha256(readFileSync(tarball)),
	forkInputSha256: hashDirectories(forkInputs),
	runtimeFileCount: runtimeFiles.length,
	declarationFileCount: declarationFiles.length,
	productionDependencies: dependencies,
	bareRuntimeImports: [...bareImports].sort(),
	bareDeclarationImports: [...declarationImports].sort(),
	forbiddenRuntimePackages: [],
};
if (output) writeFileSync(output, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
console.log(`Runtime closure verified for ${evidence.package}: ${runtimeFiles.length} bundled runtime files, ${dependencies.length} external dependencies.`);
