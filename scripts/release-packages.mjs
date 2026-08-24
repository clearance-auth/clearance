#!/usr/bin/env node

/**
 * The complete ordered npm surface for a Clearance release. Keep the chart out
 * of this list: it is a separately versioned Helm artifact, not an npm product.
 */
export const publicReleasePackages = Object.freeze([
	{ name: "@clearance/management-client", manifest: "packages/management-client/package.json" },
	{ name: "@clearance/observability-node", manifest: "packages/observability-node/package.json" },
	{ name: "@clearance/delivery", manifest: "packages/delivery/package.json" },
	{ name: "@clearance/delivery-worker", manifest: "packages/delivery-worker/package.json" },
	{ name: "@clearance/key-management", manifest: "packages/key-management/package.json" },
	{ name: "@clearance/verification", manifest: "packages/verification/package.json" },
	{ name: "@clearance/vault", manifest: "packages/vault/package.json" },
	{ name: "@clearance/auth", manifest: "packages/clearance-auth/package.json" },
	{ name: "@clearance/management", manifest: "packages/management/package.json" },
	{ name: "@clearance/cli", manifest: "packages/clearance-cli/package.json" },
	{ name: "@clearance/api", manifest: "packages/clearance-api/package.json" },
	{ name: "@clearance/console", manifest: "packages/clearance-console/package.json" },
]);

export const publicReleasePackageNames = Object.freeze(publicReleasePackages.map(({ name }) => name));
export const runtimeClosurePackageNames = publicReleasePackageNames;
export const publicReleasePackageCount = publicReleasePackages.length;

export const bundledRuntimePackages = Object.freeze([
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

export function assertCanonicalReleasePackageSequence(packages, { allowSubset = false } = {}) {
	if (!Array.isArray(packages) || packages.length === 0) {
		throw new Error("Release package sequence must not be empty.");
	}
	const expected = allowSubset
		? publicReleasePackageNames.filter((name) => packages.includes(name))
		: publicReleasePackageNames;
	if (packages.length !== expected.length || packages.some((name, index) => name !== expected[index])) {
		throw new Error(`Release package sequence must be the canonical ordered ${allowSubset ? "subset" : "list"}: ${expected.join(", ")}.`);
	}
}

if (import.meta.url === `file://${process.argv[1]}`) {
	const mode = process.argv[2] ?? "names";
	if (mode === "names") process.stdout.write(`${publicReleasePackageNames.join("\n")}\n`);
	else if (mode === "runtime-closure-names") process.stdout.write(`${runtimeClosurePackageNames.join("\n")}\n`);
	else if (mode === "json") process.stdout.write(`${JSON.stringify(publicReleasePackages)}\n`);
	else {
		process.stderr.write("Usage: node scripts/release-packages.mjs [names|runtime-closure-names|json]\n");
		process.exitCode = 2;
	}
}
