export type VaultEndpointConfig = Readonly<{
	authBaseURL?: string | URL;
	development?: boolean;
}>;

export type VaultEndpointOrigins = Readonly<{
	authBaseURL: string;
	tenantBaseURL: string;
}>;

function isLoopback(hostname: string): boolean {
	const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
	return (
		normalized === "localhost" ||
		normalized === "127.0.0.1" ||
		normalized === "::1" ||
		normalized.endsWith(".localhost")
	);
}

function currentOrigin(): string {
	if (typeof window === "undefined" || !window.location?.origin) {
		throw new TypeError(
			"Vault endpoint origins are required outside a browser document",
		);
	}
	return window.location.origin;
}

function endpointURL(
	value: string | URL | undefined,
	fallback: string,
	development: boolean,
	label: string,
	requireSameOrigin: boolean,
): URL {
	const base = currentOrigin();
	const candidate = new URL(value?.toString() ?? fallback, base);
	if (candidate.username || candidate.password) {
		throw new TypeError(`${label} must not contain URL credentials`);
	}
	if (candidate.search || candidate.hash) {
		throw new TypeError(`${label} must not contain a query or fragment`);
	}
	if (
		candidate.protocol !== "https:" &&
		!(
			development &&
			candidate.protocol === "http:" &&
			isLoopback(candidate.hostname)
		)
	) {
		throw new TypeError(
			`${label} must use HTTPS (loopback HTTP requires development: true)`,
		);
	}
	if (requireSameOrigin && candidate.origin !== new URL(base).origin) {
		throw new TypeError(`${label} must be same-origin with the Vault host`);
	}
	candidate.pathname = candidate.pathname.replace(/\/+$/, "") || "/";
	return candidate;
}

export function configureVaultEndpoints(
	config: VaultEndpointConfig = {},
): VaultEndpointOrigins {
	const development = config.development === true;
	const auth = endpointURL(
		config.authBaseURL,
		"/api/auth",
		development,
		"authBaseURL",
		true,
	);
	return Object.freeze({
		authBaseURL: auth.href.replace(/\/+$/, ""),
		tenantBaseURL: `${auth.href.replace(/\/+$/, "")}/tenant`,
	});
}

export function safePublicLink(
	value: string | URL | undefined,
	label: string,
	development: boolean,
): string | undefined {
	if (value === undefined) return undefined;
	const url = endpointURL(value, value.toString(), development, label, false);
	if (url.pathname.split("/").some((part) => /^(org|env|project)_[\w-]+$/i.test(part))) {
		throw new TypeError(`${label} must not contain a scope identifier`);
	}
	return url.href;
}
