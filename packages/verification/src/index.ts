export const CLEARANCE_CLAIMS = Object.freeze({
	sessionDerivativeAuthority:
		"urn:clearance:claims:session-derivative-authority",
	sessionSourceSubject: "urn:clearance:claims:session-source-subject",
	sessionSourceOrganization:
		"urn:clearance:claims:session-source-organization",
	actions: "actions",
	authorizationRevision: "authz_revision",
	subjectKind: "urn:clearance:claims:subject-kind",
	organizationId: "urn:clearance:claims:organization-id",
} as const);

export type VerificationErrorCode =
	| "token_malformed"
	| "algorithm_rejected"
	| "key_not_found"
	| "jwks_invalid"
	| "jwks_unavailable"
	| "signature_invalid"
	| "issuer_mismatch"
	| "audience_mismatch"
	| "token_expired"
	| "token_not_active"
	| "claims_invalid"
	| "configuration_invalid";

const ERROR_MESSAGES: Readonly<Record<VerificationErrorCode, string>> =
	Object.freeze({
		token_malformed: "Access token is malformed",
		algorithm_rejected: "Access token algorithm is not allowed",
		key_not_found: "Access token verification key was not found",
		jwks_invalid: "Verification key set is invalid",
		jwks_unavailable: "Verification key set is unavailable",
		signature_invalid: "Access token signature is invalid",
		issuer_mismatch: "Access token issuer does not match",
		audience_mismatch: "Access token audience does not match",
		token_expired: "Access token has expired",
		token_not_active: "Access token is not active",
		claims_invalid: "Access token claims are invalid",
		configuration_invalid: "Verifier configuration is invalid",
	});

export class ClearanceVerificationError extends Error {
	readonly code: VerificationErrorCode;

	constructor(code: VerificationErrorCode) {
		super(ERROR_MESSAGES[code]);
		this.name = "ClearanceVerificationError";
		this.code = code;
	}
}

export interface ClearanceJwk {
	readonly kty: "EC";
	readonly crv: "P-256";
	readonly x: string;
	readonly y: string;
	readonly kid: string;
	readonly use: "sig";
	readonly alg: "ES256";
	readonly key_ops?: readonly ["verify"];
}

export interface ClearanceJwks {
	readonly keys: readonly ClearanceJwk[];
}

export interface ClearanceBaseClaims {
	readonly iss: string;
	readonly aud: string | readonly string[];
	readonly sub: string;
	readonly exp: number;
	readonly iat: number;
	readonly nbf?: number;
	/** Frozen signed custom claims, excluding every recognized or typed alias. */
	readonly raw: Readonly<Record<string, unknown>>;
}

export interface ClearanceHumanClaims extends ClearanceBaseClaims {
	readonly kind: "human";
	readonly sessionDerivativeAuthority?: string;
	readonly sourceSubjectId?: string;
	readonly sourceOrganizationId?: string | null;
	readonly actions?: readonly string[];
	readonly authorizationRevision?: string;
}

export interface ClearanceServiceAccountClaims extends ClearanceBaseClaims {
	readonly kind: "service_account";
	readonly organizationId: string;
	readonly actions: readonly string[];
	readonly authorizationRevision: string;
}

export type ClearanceVerifiedClaims =
	| ClearanceHumanClaims
	| ClearanceServiceAccountClaims;

export interface VerifyOptions {
	readonly issuer: string;
	readonly audience: string;
	readonly clockSkewSeconds?: number;
	readonly now?: number;
}

export interface RemoteVerifierOptions extends VerifyOptions {
	readonly jwksUrl?: string;
	/** Permit HTTP only for localhost/loopback development endpoints. */
	readonly allowInsecureLoopback?: boolean;
	readonly fetch?: typeof globalThis.fetch;
	readonly fetchTimeoutMs?: number;
	readonly maxResponseBytes?: number;
	readonly cacheTtlSeconds?: number;
}

type JsonObject = Record<string, unknown>;

const ACTION_TOKEN = /^[a-z][a-z0-9._:-]{0,127}$/;
const KID_TOKEN = /^[A-Za-z0-9._:-]{1,128}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const MAX_TOKEN_BYTES = 16_384;
const MAX_JSON_BYTES = 12_288;
const MAX_ACTIONS = 256;
const MAX_JWKS_KEYS = 32;
const MAX_TOKEN_LIFETIME_SECONDS = 300;
const UNKNOWN_KID_REFRESH_COOLDOWN_MS = 30_000;
const MAX_UNKNOWN_KID_MISSES = 64;
const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;

const NORMALIZED_CLAIM_NAMES = new Set([
	"iss",
	"aud",
	"sub",
	"exp",
	"iat",
	"nbf",
	CLEARANCE_CLAIMS.sessionDerivativeAuthority,
	CLEARANCE_CLAIMS.sessionSourceSubject,
	CLEARANCE_CLAIMS.sessionSourceOrganization,
	CLEARANCE_CLAIMS.actions,
	CLEARANCE_CLAIMS.authorizationRevision,
	CLEARANCE_CLAIMS.subjectKind,
	CLEARANCE_CLAIMS.organizationId,
]);

const NORMALIZED_ALIAS_NAMES = new Set([
	"kind",
	"raw",
	"sessionDerivativeAuthority",
	"sourceSubjectId",
	"sourceOrganizationId",
	"organizationId",
	"authorizationRevision",
]);

function fail(code: VerificationErrorCode): never {
	throw new ClearanceVerificationError(code);
}

function isObject(value: unknown): value is JsonObject {
	return (
		typeof value === "object" &&
		value !== null &&
		!Array.isArray(value) &&
		Object.getPrototypeOf(value) === Object.prototype
	);
}

function decodeBase64Url(value: string): Uint8Array {
	if (
		value.length === 0 ||
		value.includes("=") ||
		!BASE64URL.test(value) ||
		value.length % 4 === 1
	) {
		fail("token_malformed");
	}
	try {
		const bytes = Uint8Array.from(Buffer.from(value, "base64url"));
		if (Buffer.from(bytes).toString("base64url") !== value) {
			fail("token_malformed");
		}
		return bytes;
	} catch {
		return fail("token_malformed");
	}
}

function rejectDuplicateJsonMembers(
	source: string,
	code: "token_malformed" | "jwks_invalid",
): void {
	let offset = 0;
	const whitespace = (): void => {
		while (
			offset < source.length &&
			(source[offset] === " " ||
				source[offset] === "\t" ||
				source[offset] === "\n" ||
				source[offset] === "\r")
		) {
			offset += 1;
		}
	};
	const string = (): string => {
		const start = offset;
		if (source[offset] !== '"') fail(code);
		offset += 1;
		while (offset < source.length) {
			const character = source[offset];
			if (character === '"') {
				offset += 1;
				try {
					return JSON.parse(source.slice(start, offset)) as string;
				} catch {
					return fail(code);
				}
			}
			if (character === "\\") {
				offset += 2;
			} else {
				offset += 1;
			}
		}
		return fail(code);
	};
	const value = (): void => {
		whitespace();
		const character = source[offset];
		if (character === "{") {
			offset += 1;
			whitespace();
			const members = new Set<string>();
			if (source[offset] === "}") {
				offset += 1;
				return;
			}
			while (offset < source.length) {
				whitespace();
				const key = string();
				if (members.has(key)) fail(code);
				members.add(key);
				whitespace();
				if (source[offset] !== ":") fail(code);
				offset += 1;
				value();
				whitespace();
				if (source[offset] === "}") {
					offset += 1;
					return;
				}
				if (source[offset] !== ",") fail(code);
				offset += 1;
			}
			return fail(code);
		}
		if (character === "[") {
			offset += 1;
			whitespace();
			if (source[offset] === "]") {
				offset += 1;
				return;
			}
			while (offset < source.length) {
				value();
				whitespace();
				if (source[offset] === "]") {
					offset += 1;
					return;
				}
				if (source[offset] !== ",") fail(code);
				offset += 1;
			}
			return fail(code);
		}
		if (character === '"') {
			string();
			return;
		}
		const start = offset;
		while (
			offset < source.length &&
			![" ", "\t", "\n", "\r", ",", "]", "}"].includes(source[offset]!)
		) {
			offset += 1;
		}
		if (offset === start) fail(code);
	};
	value();
	whitespace();
	if (offset !== source.length) fail(code);
}

function parseJsonSegment(value: string): JsonObject {
	const bytes = decodeBase64Url(value);
	if (bytes.byteLength > MAX_JSON_BYTES) fail("token_malformed");
	try {
		const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
		rejectDuplicateJsonMembers(decoded, "token_malformed");
		const parsed: unknown = JSON.parse(decoded);
		if (!isObject(parsed)) fail("token_malformed");
		return parsed;
	} catch (error) {
		if (error instanceof ClearanceVerificationError) throw error;
		return fail("token_malformed");
	}
}

function parseToken(token: string): {
	readonly header: JsonObject;
	readonly payload: JsonObject;
	readonly signingInput: Uint8Array;
	readonly signature: Uint8Array;
} {
	if (
		typeof token !== "string" ||
		new TextEncoder().encode(token).byteLength > MAX_TOKEN_BYTES
	) {
		fail("token_malformed");
	}
	const parts = token.split(".");
	if (parts.length !== 3) fail("token_malformed");
	const [encodedHeader, encodedPayload, encodedSignature] = parts;
	if (!encodedHeader || !encodedPayload || !encodedSignature) {
		fail("token_malformed");
	}
	const header = parseJsonSegment(encodedHeader);
	const allowedHeaderMembers = new Set(["alg", "kid", "typ"]);
	if (
		Object.keys(header).some((member) => !allowedHeaderMembers.has(member)) ||
		header.alg !== "ES256" ||
		typeof header.kid !== "string" ||
		!KID_TOKEN.test(header.kid) ||
		(header.typ !== undefined && header.typ !== "JWT")
	) {
		if (header.alg !== "ES256") fail("algorithm_rejected");
		fail("token_malformed");
	}
	const signature = decodeBase64Url(encodedSignature);
	if (signature.byteLength !== 64) fail("signature_invalid");
	return {
		header,
		payload: parseJsonSegment(encodedPayload),
		signingInput: new TextEncoder().encode(
			`${encodedHeader}.${encodedPayload}`,
		),
		signature,
	};
}

function exactInteger(value: unknown): value is number {
	return Number.isSafeInteger(value);
}

function nonEmptyString(value: unknown): value is string {
	return typeof value === "string" && value.length > 0;
}

function has(object: JsonObject, key: string): boolean {
	return Object.hasOwn(object, key);
}

function parseActions(value: unknown): readonly string[] {
	if (
		!Array.isArray(value) ||
		value.length > MAX_ACTIONS ||
		!value.every(
			(action, index) =>
				typeof action === "string" &&
				ACTION_TOKEN.test(action) &&
				(index === 0 || action > value[index - 1]!),
		)
	) {
		fail("claims_invalid");
	}
	return Object.freeze([...value]) as readonly string[];
}

function parseRevision(value: unknown): string {
	if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
		fail("claims_invalid");
	}
	try {
		if (BigInt(value) > POSTGRES_BIGINT_MAX) fail("claims_invalid");
	} catch {
		fail("claims_invalid");
	}
	return value;
}

function validateOptions(options: VerifyOptions): {
	readonly skew: number;
	readonly now: number;
} {
	if (
		!nonEmptyString(options.issuer) ||
		!nonEmptyString(options.audience) ||
		(options.clockSkewSeconds !== undefined &&
			(!Number.isInteger(options.clockSkewSeconds) ||
				options.clockSkewSeconds < 0 ||
				options.clockSkewSeconds > 300))
	) {
		fail("configuration_invalid");
	}
	const now = options.now ?? Math.floor(Date.now() / 1_000);
	if (!Number.isSafeInteger(now) || now < 0) fail("configuration_invalid");
	return { skew: options.clockSkewSeconds ?? 30, now };
}

function validateClaims(
	payload: JsonObject,
	options: VerifyOptions,
): ClearanceVerifiedClaims {
	const { skew, now } = validateOptions(options);
	if (payload.iss !== options.issuer) fail("issuer_mismatch");
	const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
	if (
		audiences.length === 0 ||
		!audiences.every(nonEmptyString) ||
		!audiences.includes(options.audience)
	) {
		fail("audience_mismatch");
	}
	if (
		!nonEmptyString(payload.sub) ||
		!exactInteger(payload.exp) ||
		!exactInteger(payload.iat) ||
		(payload.nbf !== undefined && !exactInteger(payload.nbf)) ||
		payload.exp <= payload.iat ||
		payload.exp - payload.iat > MAX_TOKEN_LIFETIME_SECONDS
	) {
		fail("claims_invalid");
	}
	if (payload.exp <= now - skew) fail("token_expired");
	if (
		(payload.nbf !== undefined && payload.nbf > now + skew) ||
		payload.iat > now + skew
	) {
		fail("token_not_active");
	}

	const claims = CLEARANCE_CLAIMS;
	const hasActions = has(payload, claims.actions);
	const hasRevision = has(payload, claims.authorizationRevision);
	if (hasActions !== hasRevision) fail("claims_invalid");
	const actions = hasActions ? parseActions(payload[claims.actions]) : undefined;
	const revision = hasRevision
		? parseRevision(payload[claims.authorizationRevision])
		: undefined;

	const hasKind = has(payload, claims.subjectKind);
	const hasOrganization = has(payload, claims.organizationId);
	if (hasKind !== hasOrganization) fail("claims_invalid");

	const hasBinding = has(payload, claims.sessionDerivativeAuthority);
	const hasSourceSubject = has(payload, claims.sessionSourceSubject);
	const hasSourceOrganization = has(payload, claims.sessionSourceOrganization);
	if (
		hasBinding !== hasSourceSubject ||
		hasBinding !== hasSourceOrganization
	) {
		fail("claims_invalid");
	}

	const aud = Array.isArray(payload.aud)
		? (Object.freeze([...audiences]) as readonly string[])
		: (payload.aud as string);
	const base = Object.freeze({
		iss: options.issuer,
		aud,
		sub: payload.sub as string,
		exp: payload.exp as number,
		iat: payload.iat as number,
		...(payload.nbf === undefined ? {} : { nbf: payload.nbf as number }),
		raw: normalizedRawClaims(payload),
	});

	if (hasKind) {
		if (
			payload[claims.subjectKind] !== "service_account" ||
			!nonEmptyString(payload[claims.organizationId]) ||
			!actions ||
			!revision ||
			hasBinding
		) {
			fail("claims_invalid");
		}
		return Object.freeze({
			...base,
			kind: "service_account",
			organizationId: payload[claims.organizationId],
			actions,
			authorizationRevision: revision,
		}) as ClearanceServiceAccountClaims;
	}

	if (actions && !hasBinding) fail("claims_invalid");
	if (
		hasBinding &&
		(!nonEmptyString(payload[claims.sessionDerivativeAuthority]) ||
			!nonEmptyString(payload[claims.sessionSourceSubject]) ||
			(payload[claims.sessionSourceOrganization] !== null &&
				!nonEmptyString(payload[claims.sessionSourceOrganization])))
	) {
		fail("claims_invalid");
	}
	if (
		actions &&
		!nonEmptyString(payload[claims.sessionSourceOrganization])
	) {
		fail("claims_invalid");
	}
	return Object.freeze({
		...base,
		kind: "human",
		...(hasBinding
			? {
					sessionDerivativeAuthority:
						payload[claims.sessionDerivativeAuthority] as string,
					sourceSubjectId: payload[claims.sessionSourceSubject] as string,
					sourceOrganizationId: payload[
						claims.sessionSourceOrganization
					] as string | null,
				}
			: {}),
		...(actions ? { actions, authorizationRevision: revision } : {}),
	}) as ClearanceHumanClaims;
}

function normalizedRawClaims(
	payload: JsonObject,
): Readonly<Record<string, unknown>> {
	const raw: Record<string, unknown> = {};
	for (const [name, value] of Object.entries(payload)) {
		if (
			!NORMALIZED_CLAIM_NAMES.has(name) &&
			!NORMALIZED_ALIAS_NAMES.has(name)
		) {
			raw[name] = value;
		}
	}
	return Object.freeze(raw);
}

function validJwk(value: unknown, kid: string): value is ClearanceJwk {
	if (!isObject(value)) return false;
	const allowedMembers = new Set([
		"kty",
		"crv",
		"x",
		"y",
		"kid",
		"use",
		"alg",
		"key_ops",
	]);
	if (
		Object.keys(value).some((member) => !allowedMembers.has(member)) ||
		value.kid !== kid ||
		value.kty !== "EC" ||
		value.crv !== "P-256" ||
		value.use !== "sig" ||
		value.alg !== "ES256" ||
		typeof value.x !== "string" ||
		typeof value.y !== "string" ||
		has(value, "d")
	) {
		return false;
	}
	if (
		value.key_ops !== undefined &&
		(!Array.isArray(value.key_ops) ||
			value.key_ops.length !== 1 ||
			value.key_ops[0] !== "verify")
	) {
		return false;
	}
	try {
		return (
			decodeBase64Url(value.x).byteLength === 32 &&
			decodeBase64Url(value.y).byteLength === 32
		);
	} catch {
		return false;
	}
}

function parseJwks(value: unknown): ClearanceJwks {
	if (!isObject(value) || !Array.isArray(value.keys)) fail("jwks_invalid");
	if (value.keys.length === 0 || value.keys.length > MAX_JWKS_KEYS) {
		fail("jwks_invalid");
	}
	const seen = new Set<string>();
	const keys: ClearanceJwk[] = [];
	for (const candidate of value.keys) {
		if (
			!isObject(candidate) ||
			typeof candidate.kid !== "string" ||
			!KID_TOKEN.test(candidate.kid) ||
			!validJwk(candidate, candidate.kid) ||
			seen.has(candidate.kid)
		) {
			fail("jwks_invalid");
		}
		seen.add(candidate.kid);
		keys.push(Object.freeze({ ...candidate }) as unknown as ClearanceJwk);
	}
	return Object.freeze({ keys: Object.freeze(keys) });
}

async function verifyParsed(
	parsed: ReturnType<typeof parseToken>,
	jwks: ClearanceJwks,
	options: VerifyOptions,
): Promise<ClearanceVerifiedClaims> {
	const kid = parsed.header.kid as string;
	const key = jwks.keys.find((candidate) => candidate.kid === kid);
	if (!key) fail("key_not_found");
	let cryptoKey: CryptoKey;
	try {
		cryptoKey = await crypto.subtle.importKey(
			"jwk",
			key as JsonWebKey,
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
	} catch {
		return fail("jwks_invalid");
	}
	const valid = await crypto.subtle
		.verify(
			{ name: "ECDSA", hash: "SHA-256" },
			cryptoKey,
			new Uint8Array(parsed.signature),
			new Uint8Array(parsed.signingInput),
		)
		.catch(() => false);
	if (!valid) fail("signature_invalid");
	return validateClaims(parsed.payload, options);
}

export async function verifyWithJwks(
	token: string,
	jwks: unknown,
	options: VerifyOptions,
): Promise<ClearanceVerifiedClaims> {
	return verifyParsed(parseToken(token), parseJwks(jwks), options);
}

function loopbackHostname(hostname: string): boolean {
	const normalized = hostname.toLowerCase();
	if (normalized === "localhost") {
		return true;
	}
	const unwrapped =
		normalized.startsWith("[") && normalized.endsWith("]")
			? normalized.slice(1, -1)
			: normalized;
	if (unwrapped === "::1" || unwrapped === "0:0:0:0:0:0:0:1") return true;
	const octets = unwrapped.split(".");
	return (
		octets.length === 4 &&
		octets.every(
			(octet) =>
				/^(0|[1-9]\d{0,2})$/.test(octet) &&
				Number(octet) >= 0 &&
				Number(octet) <= 255,
		) &&
		Number(octets[0]) === 127
	);
}

function secureUrl(value: string, allowInsecureLoopback: boolean): URL {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return fail("configuration_invalid");
	}
	if (
		url.username ||
		url.password ||
		url.hash ||
		(url.protocol !== "https:" &&
			(url.protocol !== "http:" ||
				!allowInsecureLoopback ||
				!loopbackHostname(url.hostname)))
	) {
		fail("configuration_invalid");
	}
	return url;
}

async function readBoundedResponse(
	response: Response,
	maxBytes: number,
	controller: AbortController,
): Promise<Uint8Array> {
	if (!response.body) fail("jwks_unavailable");
	const reader = response.body.getReader();
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			if (!value) continue;
			length += value.byteLength;
			if (length > maxBytes) {
				controller.abort();
				await reader.cancel().catch(() => undefined);
				fail("jwks_unavailable");
			}
			chunks.push(value);
		}
	} catch (error) {
		if (error instanceof ClearanceVerificationError) throw error;
		return fail("jwks_unavailable");
	} finally {
		reader.releaseLock();
	}
	const body = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) {
		body.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return body;
}

export function createRemoteVerifier(options: RemoteVerifierOptions): {
	readonly verify: (token: string) => Promise<ClearanceVerifiedClaims>;
	readonly clearCache: () => void;
} {
	validateOptions(options);
	if (
		options.allowInsecureLoopback !== undefined &&
		typeof options.allowInsecureLoopback !== "boolean"
	) {
		fail("configuration_invalid");
	}
	const allowInsecureLoopback = options.allowInsecureLoopback === true;
	const issuerUrl = secureUrl(options.issuer, allowInsecureLoopback);
	const jwksUrl = secureUrl(
		options.jwksUrl ?? new URL("/api/auth/jwks", issuerUrl).toString(),
		allowInsecureLoopback,
	);
	const fetcher = options.fetch ?? globalThis.fetch;
	const timeout = options.fetchTimeoutMs ?? 3_000;
	const maxBytes = options.maxResponseBytes ?? 1_048_576;
	const ttl = options.cacheTtlSeconds ?? 300;
	if (
		typeof fetcher !== "function" ||
		!Number.isInteger(timeout) ||
		timeout < 100 ||
		timeout > 30_000 ||
		!Number.isInteger(maxBytes) ||
		maxBytes < 1_024 ||
		maxBytes > 4_194_304 ||
		!Number.isInteger(ttl) ||
		ttl < 1 ||
		ttl > 3_600
	) {
		fail("configuration_invalid");
	}

	let cached: { readonly jwks: ClearanceJwks; readonly expiresAt: number } | null =
		null;
	let inFlight: Promise<ClearanceJwks> | null = null;
	let unknownRefreshInFlight: Promise<ClearanceJwks> | null = null;
	let nextUnknownRefreshAt = 0;
	const unknownKidMisses = new Map<string, number>();

	const load = async (force: boolean): Promise<ClearanceJwks> => {
		const now = Date.now();
		if (!force && cached && cached.expiresAt > now) return cached.jwks;
		if (inFlight) return inFlight;
		const request = (async () => {
			const controller = new AbortController();
			const timer = setTimeout(() => controller.abort(), timeout);
			try {
				const response = await fetcher(jwksUrl, {
					method: "GET",
					headers: { accept: "application/json" },
					redirect: "error",
					credentials: "omit",
					referrerPolicy: "no-referrer",
					signal: controller.signal,
				});
				if (!response.ok) fail("jwks_unavailable");
				const declaredLength = Number(response.headers.get("content-length"));
				if (
					Number.isFinite(declaredLength) &&
					declaredLength > maxBytes
				) {
					fail("jwks_unavailable");
				}
				const bytes = await readBoundedResponse(
					response,
					maxBytes,
					controller,
				);
				let decoded: unknown;
				try {
					const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
					rejectDuplicateJsonMembers(text, "jwks_invalid");
					decoded = JSON.parse(text);
				} catch {
					fail("jwks_invalid");
				}
				const jwks = parseJwks(decoded);
				cached = { jwks, expiresAt: Date.now() + ttl * 1_000 };
				return jwks;
			} catch (error) {
				if (error instanceof ClearanceVerificationError) throw error;
				return fail("jwks_unavailable");
			} finally {
				clearTimeout(timer);
			}
		})();
		inFlight = request;
		try {
			return await request;
		} finally {
			if (inFlight === request) inFlight = null;
		}
	};

	const recordUnknownKid = (kid: string, now: number): void => {
		for (const [missedKid, expiresAt] of unknownKidMisses) {
			if (expiresAt <= now) unknownKidMisses.delete(missedKid);
		}
		if (unknownKidMisses.has(kid)) return;
		if (!unknownKidMisses.has(kid) && unknownKidMisses.size >= MAX_UNKNOWN_KID_MISSES) {
			unknownKidMisses.delete(unknownKidMisses.keys().next().value!);
		}
		unknownKidMisses.set(kid, now + UNKNOWN_KID_REFRESH_COOLDOWN_MS);
	};

	const refreshUnknownKid = async (kid: string): Promise<ClearanceJwks> => {
		if (unknownRefreshInFlight) return unknownRefreshInFlight;
		const now = Date.now();
		const missExpiresAt = unknownKidMisses.get(kid);
		if (missExpiresAt !== undefined && now < missExpiresAt) {
			fail("key_not_found");
		}
		if (now < nextUnknownRefreshAt) {
			recordUnknownKid(kid, now);
			fail("key_not_found");
		}
		nextUnknownRefreshAt = now + UNKNOWN_KID_REFRESH_COOLDOWN_MS;
		const request = load(true);
		unknownRefreshInFlight = request;
		try {
			return await request;
		} finally {
			if (unknownRefreshInFlight === request) {
				unknownRefreshInFlight = null;
			}
		}
	};

	return Object.freeze({
		async verify(token: string): Promise<ClearanceVerifiedClaims> {
			const parsed = parseToken(token);
			let jwks = await load(false);
			if (!jwks.keys.some((key) => key.kid === parsed.header.kid)) {
				jwks = await refreshUnknownKid(parsed.header.kid as string);
				if (!jwks.keys.some((key) => key.kid === parsed.header.kid)) {
					recordUnknownKid(parsed.header.kid as string, Date.now());
				}
			}
			return verifyParsed(parsed, jwks, options);
		},
		clearCache(): void {
			cached = null;
			nextUnknownRefreshAt = 0;
			unknownKidMisses.clear();
		},
	});
}
