import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export function fixturesRoot(): string {
	return (
		process.env.CLEARANCE_FIXTURES_DIR ??
		resolve(process.cwd(), "fixtures")
	);
}

export function loadJsonFixture<T = unknown>(relativePath: string): T {
	const full = resolve(fixturesRoot(), relativePath);
	return JSON.parse(readFileSync(full, "utf8")) as T;
}

export type SsoOidcFixture = {
	matrix: string;
	provider: string;
	protocol: "oidc" | "saml";
	issuer: string;
	audience?: string;
	domain?: string;
	clientId?: string;
	clientSecret?: string;
	discovery: {
		issuer: string;
		authorization_endpoint: string;
		token_endpoint: string;
		jwks_uri: string;
		[k: string]: unknown;
	};
};

export type ScimUsersFixture = {
	provider: string;
	users: Array<{
		schemas: string[];
		userName: string;
		name?: { formatted?: string };
		emails?: Array<{ value: string; primary?: boolean }>;
		active?: boolean;
	}>;
};

export type AdversarialFixtureFile = {
	cases: Array<{
		id: string;
		stage: string;
		discovery?: Record<string, unknown>;
		configuredIssuer?: string;
		saml?: { notBefore?: string; notOnOrAfter?: string };
		audience?: string;
		configuredAudience?: string;
	}>;
};
