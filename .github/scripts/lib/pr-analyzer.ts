/**
 * PR Analyzer — shared classification module
 *
 * Pure functions for mapping conventional commit scopes and file paths
 * to domain labels. No side effects, no network calls.
 *
 * Used by: auto-changeset.ts, release-notes.ts
 */

const SCOPE_TO_DOMAIN: Record<string, string> = {
	// core
	core: "core",
	api: "core",
	client: "core",
	cookies: "core",
	crypto: "core",
	account: "core",
	session: "core",
	instrumentation: "core",
	"last-login-method": "core",
	"redis-storage": "core",

	// database
	db: "database",
	adapters: "database",
	"drizzle-adapter": "database",
	"prisma-adapter": "database",
	"kysely-adapter": "database",
	"mongo-adapter": "database",
	"memory-adapter": "database",

	// oauth
	"oauth-proxy": "oauth",
	"one-tap": "oauth",
	"generic-oauth": "oauth",
	"social-provider": "oauth",

	// credentials
	"magic-link": "credentials",
	"email-otp": "credentials",
	"phone-number": "credentials",
	phone: "credentials",
	username: "credentials",
	anonymous: "credentials",
	siwe: "credentials",
	passkey: "credentials",

	// identity
	"oauth-provider": "identity",
	"oidc-provider": "identity",
	mcp: "identity",
	"device-authorization": "identity",

	// organization
	organization: "organization",
	admin: "organization",
	access: "organization",

	// security
	"two-factor": "security",
	"2fa": "security",
	captcha: "security",
	haveibeenpwned: "security",
	"rate-limiter": "security",

	// enterprise
	sso: "enterprise",
	scim: "enterprise",

	// payments
	stripe: "payments",
	"api-key": "payments",

	// platform
	expo: "platform",
	electron: "platform",

	// devtools
	cli: "devtools",
	telemetry: "devtools",
	i18n: "devtools",
	"test-utils": "devtools",
	"open-api": "devtools",

	// devops (filtered from release notes)
	build: "devops",
	ci: "devops",
	deps: "devops",
	"deps-dev": "devops",
	knip: "devops",

	// docs (filtered from release notes)
	docs: "docs",
	blog: "docs",
	landing: "docs",
};

const PATH_TO_DOMAIN: [string, string][] = [
	["packages/oauth-provider/", "identity"],
	["packages/runtime/src/plugins/oidc-provider/", "identity"],
	["packages/runtime/src/plugins/mcp/", "identity"],
	["packages/runtime/src/plugins/device-authorization/", "identity"],
	["packages/runtime/src/plugins/magic-link/", "credentials"],
	["packages/runtime/src/plugins/email-otp/", "credentials"],
	["packages/runtime/src/plugins/phone-number/", "credentials"],
	["packages/runtime/src/plugins/username/", "credentials"],
	["packages/runtime/src/plugins/anonymous/", "credentials"],
	["packages/runtime/src/plugins/siwe/", "credentials"],
	["packages/passkey/", "credentials"],
	["packages/runtime/src/plugins/two-factor/", "security"],
	["packages/runtime/src/api/rate-limiter/", "security"],
	["packages/runtime/src/plugins/captcha/", "security"],
	["packages/runtime/src/plugins/haveibeenpwned/", "security"],
	["packages/runtime/src/plugins/organization/", "organization"],
	["packages/runtime/src/plugins/admin/", "organization"],
	["packages/runtime/src/plugins/access/", "organization"],
	["packages/runtime/src/plugins/generic-oauth/", "oauth"],
	["packages/runtime/src/plugins/oauth-proxy/", "oauth"],
	["packages/runtime/src/plugins/one-tap/", "oauth"],
	["packages/runtime/src/oauth2/", "oauth"],
	["packages/core/src/social-providers/", "oauth"],
	["packages/core/src/oauth2/", "oauth"],
	["packages/sso/", "enterprise"],
	["packages/scim/", "enterprise"],
	["packages/stripe/", "payments"],
	["packages/api-key/", "payments"],
	["packages/runtime/src/db/", "database"],
	["packages/runtime/src/adapters/", "database"],
	["packages/drizzle-adapter/", "database"],
	["packages/prisma-adapter/", "database"],
	["packages/mongo-adapter/", "database"],
	["packages/kysely-adapter/", "database"],
	["packages/memory-adapter/", "database"],
	["packages/expo/", "platform"],
	["packages/electron/", "platform"],
	["packages/runtime/src/integrations/", "platform"],
	["packages/cli/", "devtools"],
	["packages/runtime/src/plugins/open-api/", "devtools"],
	["packages/telemetry/", "devtools"],
	["packages/i18n/", "devtools"],
	["packages/test-utils/", "devtools"],
	// Session-related plugins → core
	["packages/runtime/src/plugins/jwt/", "core"],
	["packages/runtime/src/plugins/bearer/", "core"],
	["packages/runtime/src/plugins/multi-session/", "core"],
	["packages/runtime/src/plugins/custom-session/", "core"],
	["packages/redis-storage/", "core"],
	// Catch-all for clearance and core packages
	["packages/runtime/", "core"],
	["packages/core/", "core"],
	// Non-user-facing
	["docs/", "docs"],
	["demo/", "docs"],
	[".github/", "devops"],
	["e2e/", "devops"],
];

export interface ConventionalCommit {
	type: string;
	scope: string;
	subject: string;
	breaking: boolean;
}

export function parseConventionalCommit(title: string): ConventionalCommit {
	const typeMatch = title.match(/^([a-z]+)/);
	const type = typeMatch?.[1] ?? "";
	const scopeMatch = title.match(/^[a-z]+\(([^)]+)\)/);
	const scope = scopeMatch?.[1] ?? "";
	const breaking = /^[a-z]+(\([^)]+\))?!:/.test(title);
	const subject = title.replace(/^[a-z]+(\([^)]+\))?!?:\s*/, "");
	return { type, scope, subject, breaking };
}

function classifyDomain(filePath: string): string | undefined {
	for (const [prefix, domain] of PATH_TO_DOMAIN) {
		if (filePath.startsWith(prefix)) return domain;
	}
	return undefined;
}

export function resolveDomain(
	scope: string | undefined,
	changedFiles: string[],
): string {
	if (scope) {
		const domain = SCOPE_TO_DOMAIN[scope];
		if (domain) return domain;
	}

	const counts: Record<string, number> = {};
	for (const file of changedFiles) {
		const domain = classifyDomain(file);
		if (domain) {
			counts[domain] = (counts[domain] ?? 0) + 1;
		}
	}

	const domains = Object.keys(counts);
	if (domains.length === 0) return "devops";
	if (domains.length >= 3) return "core";

	return domains.sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0))[0]!;
}

export function mapTypeToBump(
	type: string,
	breaking: boolean,
): "patch" | "minor" | "major" | "skip" {
	if (breaking) return "major";
	switch (type) {
		case "fix":
		case "perf":
		case "refactor":
			return "patch";
		case "feat":
			return "minor";
		case "chore":
		case "docs":
		case "ci":
		case "test":
		case "style":
		case "build":
			return "skip";
		default:
			return "patch";
	}
}

/** Domains in display order for release notes */
export const DOMAIN_ORDER = [
	"core",
	"database",
	"oauth",
	"credentials",
	"identity",
	"organization",
	"security",
	"enterprise",
	"payments",
	"platform",
	"devtools",
] as const;

/** Domains excluded from release notes */
export const FILTERED_DOMAINS = new Set(["docs", "devops"]);

// ── Package resolution (for release notes output) ─────────────────────

/**
 * Maps commit scopes to npm package names.
 * Used by release-notes.ts to group entries by the package users install.
 */
const SCOPE_TO_PACKAGE: Record<string, string> = {
	sso: "@clearance/sso",
	scim: "@clearance/scim",
	passkey: "@clearance/passkey",
	"oauth-provider": "@clearance/oauth-provider",
	stripe: "@clearance/stripe",
	"api-key": "@clearance/api-key",
	expo: "@clearance/expo",
	electron: "@clearance/electron",
	i18n: "@clearance/i18n",
	"test-utils": "@clearance/test-utils",
	"drizzle-adapter": "@clearance/drizzle-adapter",
	"prisma-adapter": "@clearance/prisma-adapter",
	"kysely-adapter": "@clearance/kysely-adapter",
	"mongo-adapter": "@clearance/mongo-adapter",
	"memory-adapter": "@clearance/memory-adapter",
	"redis-storage": "@clearance/redis-storage",
	cli: "auth",
};

/**
 * Maps file path prefixes to npm package names.
 * Order matters: more specific paths must come before catch-alls.
 */
const PATH_TO_PACKAGE: [string, string][] = [
	["packages/sso/", "@clearance/sso"],
	["packages/scim/", "@clearance/scim"],
	["packages/passkey/", "@clearance/passkey"],
	["packages/oauth-provider/", "@clearance/oauth-provider"],
	["packages/stripe/", "@clearance/stripe"],
	["packages/api-key/", "@clearance/api-key"],
	["packages/expo/", "@clearance/expo"],
	["packages/electron/", "@clearance/electron"],
	["packages/i18n/", "@clearance/i18n"],
	["packages/redis-storage/", "@clearance/redis-storage"],
	["packages/test-utils/", "@clearance/test-utils"],
	["packages/telemetry/", "@clearance/telemetry"],
	["packages/drizzle-adapter/", "@clearance/drizzle-adapter"],
	["packages/prisma-adapter/", "@clearance/prisma-adapter"],
	["packages/kysely-adapter/", "@clearance/kysely-adapter"],
	["packages/mongo-adapter/", "@clearance/mongo-adapter"],
	["packages/memory-adapter/", "@clearance/memory-adapter"],
	// Catch-all: everything in clearance or core maps to the main package
	["packages/runtime/", "clearance"],
	["packages/core/", "clearance"],
	["packages/cli/", "auth"],
];

/**
 * Resolves the npm package name for release notes grouping.
 * Priority: scope match > file path match > "clearance" fallback.
 */
export function resolvePackage(
	scope: string | undefined,
	changedFiles: string[],
): string {
	if (scope) {
		const pkg = SCOPE_TO_PACKAGE[scope];
		if (pkg) return pkg;
	}

	const counts: Record<string, number> = {};
	for (const file of changedFiles) {
		for (const [prefix, pkg] of PATH_TO_PACKAGE) {
			if (file.startsWith(prefix)) {
				counts[pkg] = (counts[pkg] ?? 0) + 1;
				break;
			}
		}
	}

	const packages = Object.keys(counts);
	if (packages.length === 0) return "clearance";

	// If files span multiple external packages, return the one with the most hits.
	// If all files are in clearance, return clearance.
	return packages.sort((a, b) => {
		// Prefer non-clearance packages (they're more specific)
		const aIsCore = a === "clearance" ? 1 : 0;
		const bIsCore = b === "clearance" ? 1 : 0;
		if (aIsCore !== bIsCore) return aIsCore - bIsCore;
		return (counts[b] ?? 0) - (counts[a] ?? 0);
	})[0]!;
}

/** Classifies a conventional commit type into a release notes category. */
export function classifyChangeType(
	type: string,
	breaking: boolean,
): "breaking" | "feat" | "fix" {
	if (breaking) return "breaking";
	if (type === "feat") return "feat";
	return "fix";
}
