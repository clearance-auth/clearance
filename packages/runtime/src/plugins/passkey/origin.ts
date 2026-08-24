import type { GenericEndpointContext } from "@clearance/core";
import { APIError } from "@clearance/core/error";
import { isLoopbackHost } from "@clearance/core/utils/host";
import { getDomain } from "tldts";
import { PASSKEY_ERROR_CODES } from "./error-codes";
import type { PasskeyOptions } from "./types";

const RP_ID_MAX_LENGTH = 253;
const HOSTNAME_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
const IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Validates that `candidate` is a syntactically valid, canonical WebAuthn RP
 * ID: a bare hostname with no scheme, no port, no path, no whitespace, no
 * credentials, and no IP-address literal (WebAuthn RP IDs must be
 * registrable domain strings, not IP addresses). Rejects anything else,
 * including malformed hostnames, so a misconfigured `rpID` fails closed
 * rather than silently degrading downstream origin matching.
 */
function normalizeRpID(candidate: string): string | null {
	const normalized = candidate.toLowerCase();
	if (
		!normalized ||
		normalized.length > RP_ID_MAX_LENGTH ||
		/\s/.test(normalized)
	) {
		return null;
	}
	if (
		normalized.includes("://") ||
		normalized.includes("/") ||
		normalized.includes("?") ||
		normalized.includes("#") ||
		normalized.includes("@") ||
		normalized.includes(":") ||
		normalized.includes("[") ||
		normalized.includes("]") ||
		normalized.includes("*")
	) {
		return null;
	}
	if (normalized.startsWith(".") || normalized.endsWith(".") || normalized.includes("..")) {
		return null;
	}
	if (IPV4_LITERAL.test(normalized)) {
		return null;
	}
	const labels = normalized.split(".");
	if (!labels.every((label) => HOSTNAME_LABEL.test(label))) {
		return null;
	}
	// A WebAuthn RP ID may be a registrable domain or one of its subdomains,
	// never a bare public suffix. `localhost` is the sole single-label
	// development exception accepted by browsers.
	if (
		normalized !== "localhost" &&
		getDomain(normalized, { allowPrivateDomains: true }) === null
	) {
		return null;
	}
	return normalized;
}

/**
 * A registrable-domain check for WebAuthn RP ID compatibility: the origin's
 * host must equal the RP ID exactly, or be a strict subdomain of it.
 */
function hostMatchesRpID(host: string, rpID: string): boolean {
	const normalizedHost = host.toLowerCase();
	const normalizedRpID = rpID.toLowerCase();
	return (
		normalizedHost === normalizedRpID ||
		normalizedHost.endsWith(`.${normalizedRpID}`)
	);
}

/**
 * Parses a candidate origin string into a normalized, syntactically valid
 * exact origin (`scheme://host[:port]`, no path/query/fragment/credentials,
 * no wildcard characters). Returns `null` for anything that isn't a single,
 * literal, absolute HTTP(S) origin.
 */
function parseExactOrigin(candidate: string): URL | null {
	if (
		!candidate ||
		candidate.includes("*") ||
		candidate.includes("?") ||
		candidate.includes("@")
	) {
		return null;
	}
	let parsed: URL;
	try {
		parsed = new URL(candidate);
	} catch {
		return null;
	}
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		return null;
	}
	if (parsed.pathname !== "/" && parsed.pathname !== "") {
		return null;
	}
	if (parsed.search || parsed.hash || parsed.username || parsed.password) {
		return null;
	}
	return parsed;
}

/**
 * An allowed origin must be HTTPS, or HTTP with a loopback/localhost host
 * (explicit development exception). It must also be compatible with the
 * resolved RP ID (equal to it, or a subdomain of it).
 */
function isAllowableOrigin(parsed: URL, rpID: string): boolean {
	if (!hostMatchesRpID(parsed.hostname, rpID)) {
		return false;
	}
	if (parsed.protocol === "https:") {
		return true;
	}
	return isLoopbackHost(parsed.hostname);
}

/**
 * Resolves the WebAuthn RP ID from explicit plugin configuration, or from a
 * statically configured string `baseURL`. A dynamic (function/object)
 * `baseURL` configuration, or the absence of any of the above, is treated as
 * ambiguous and fails closed rather than falling back to request headers.
 */
export function resolveRpID(
	ctx: GenericEndpointContext,
	options: PasskeyOptions | undefined,
): string {
	if (options?.rpID) {
		const normalized = normalizeRpID(options.rpID);
		if (!normalized) {
			throw APIError.from(
				"INTERNAL_SERVER_ERROR",
				PASSKEY_ERROR_CODES.CONFIGURATION_ERROR,
			);
		}
		return normalized;
	}
	const baseURL = ctx.context.options.baseURL;
	if (typeof baseURL === "string" && baseURL) {
		try {
			const normalized = normalizeRpID(new URL(baseURL).hostname);
			if (normalized) {
				return normalized;
			}
		} catch {
			// fall through to the configuration error below
		}
	}
	throw APIError.from("INTERNAL_SERVER_ERROR", PASSKEY_ERROR_CODES.CONFIGURATION_ERROR);
}

/**
 * Resolves the set of exact origins allowed to complete a WebAuthn ceremony
 * for the given RP ID.
 *
 * Sources (all static — resolved once from configuration, never per-request):
 * 1. `options.origin` — explicit plugin configuration. Every entry MUST be an
 *    exact, RP-ID-compatible origin; an incompatible or malformed entry is a
 *    deployment misconfiguration and fails closed immediately.
 * 2. Literal (non-wildcard) entries in the statically configured
 *    `ClearanceOptions.trustedOrigins` array. This reads only
 *    `ctx.context.options.trustedOrigins` (the static configuration value)
 *    and only when it is an array; a dynamic (function) `trustedOrigins`
 *    configuration is never invoked or trusted here, since it may resolve
 *    per-request from untrusted headers. Wildcard patterns and anything
 *    incompatible with the RP ID are silently excluded: they may be
 *    configured for unrelated purposes (OAuth redirects, CORS) and are never
 *    treated as WebAuthn origin authority.
 * 3. The static canonical `baseURL` origin, when `baseURL` is configured as a
 *    plain string.
 *
 * Request headers (Origin, Host, X-Forwarded-Host) and any per-request
 * resolved trusted-origins list (`ctx.context.trustedOrigins`) are never read
 * here and never contribute to this set.
 */
export function resolveAllowedOrigins(
	ctx: GenericEndpointContext,
	options: PasskeyOptions | undefined,
	rpID: string,
): string[] {
	const allowed = new Set<string>();

	for (const candidate of options?.origin ?? []) {
		const parsed = parseExactOrigin(candidate);
		if (!parsed || !isAllowableOrigin(parsed, rpID)) {
			throw APIError.from(
				"INTERNAL_SERVER_ERROR",
				PASSKEY_ERROR_CODES.CONFIGURATION_ERROR,
			);
		}
		allowed.add(parsed.origin);
	}

	const staticTrustedOrigins = ctx.context.options.trustedOrigins;
	if (Array.isArray(staticTrustedOrigins)) {
		for (const candidate of staticTrustedOrigins) {
			const parsed = parseExactOrigin(candidate);
			if (!parsed || !isAllowableOrigin(parsed, rpID)) {
				continue;
			}
			allowed.add(parsed.origin);
		}
	}

	const baseURL = ctx.context.options.baseURL;
	if (typeof baseURL === "string" && baseURL) {
		const parsed = parseExactOrigin(baseURL);
		if (parsed && isAllowableOrigin(parsed, rpID)) {
			allowed.add(parsed.origin);
		}
	}

	return [...allowed];
}

/**
 * Validates the request's `Origin` header against the resolved allow-list and
 * returns the exact matched origin. Fails closed (generic, redacted error) on
 * a missing header, an unparseable header, or no match — this is the only
 * place a request header is read, and it is used purely as a candidate to
 * check membership in the allow-list, never as configuration itself.
 */
export function assertTrustedOrigin(
	ctx: GenericEndpointContext,
	options: PasskeyOptions | undefined,
	rpID: string,
): string {
	const rawOrigin = ctx.headers?.get("origin");
	if (!rawOrigin) {
		throw APIError.from("FORBIDDEN", PASSKEY_ERROR_CODES.INVALID_ORIGIN);
	}
	const parsed = parseExactOrigin(rawOrigin);
	if (!parsed) {
		throw APIError.from("FORBIDDEN", PASSKEY_ERROR_CODES.INVALID_ORIGIN);
	}
	const allowedOrigins = resolveAllowedOrigins(ctx, options, rpID);
	if (!allowedOrigins.includes(parsed.origin)) {
		throw APIError.from("FORBIDDEN", PASSKEY_ERROR_CODES.INVALID_ORIGIN);
	}
	return parsed.origin;
}
