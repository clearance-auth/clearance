import type {
	ClearanceOptions,
	ClearancePlugin,
	GenericEndpointContext,
	InternalAdapter,
	SecretConfig,
} from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import {
	getCurrentAdapter,
	getCurrentAuthContext,
	runWithTransaction,
} from "@clearance/core/context";
import type {
	DBAdapter,
	DBTransactionAdapter,
} from "@clearance/core/db/adapter";
import { ClearanceError } from "@clearance/core/error";
import { deprecate } from "@clearance/core/utils/deprecate";
import { isSafeUrlScheme } from "@clearance/core/utils/url";
import { base64 } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";
import { createHMAC } from "@clearance/utils/hmac";
import type { OpenAPIParameter } from "@clearance/call";
import { decodeJwt, jwtVerify, SignJWT } from "jose";
import * as z from "zod";
import {
	APIError,
	getAuthoritativeSessionFromCtx,
	getSessionFromCtx,
	sensitiveSessionMiddleware,
	sessionMiddleware,
} from "../../api";
import { expireCookie, parseSetCookieHeader } from "../../cookies";
import {
	constantTimeEqual,
	generateRandomString,
	symmetricDecrypt,
	symmetricEncrypt,
} from "../../crypto";
import { mergeSchema } from "../../db";
import {
	assertSecurityMigrationComplete,
	OAUTH_TOKEN_MIGRATION_ID,
	runSecurityMigrationPage,
} from "../../db/session-credential-migration";
import { HIDE_METADATA } from "../../utils";
import {
	CREDENTIAL_OPERATION_KEY_REQUIREMENT,
	parseCredentialOperationKey,
} from "../../utils/operation-key";
import { PACKAGE_VERSION } from "../../version";
import { signJWT, verifyJWT } from "../jwt";
import { authorize } from "./authorize";
import type { OAuthApplication } from "./schema";
import { schema } from "./schema";
import {
	oauthExpiresIn,
	restoreOAuthResponseHeaders,
	setNoStoreTokenResponseHeaders,
	snapshotOAuthResponseHeaders,
} from "./token-response";
import { lockAndReadActiveUser } from "../../db/user-authority";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../internal/verification-challenge-context";
import {
	runManagedAuthenticationTransaction,
	usesManagedAuthenticationPolicy,
} from "../../internal/managed-authentication-transaction";
import {
	type InternalSessionDerivativeAuthority,
	ManagedSessionDerivativeAuthorityError,
	validateInternalSessionDerivativeAuthority,
} from "../../internal/session-derivative-authority";
import {
	attachInternalCredentialAuthority,
	readInternalCredentialAuthority,
} from "../../internal/credential-authority";
import type {
	Client,
	CodeVerificationValue,
	OAuthAccessToken,
	OIDCMetadata,
	OIDCOptions,
} from "./types";
import { defaultClientSecretHasher } from "./utils";
import { parsePrompt } from "./utils/prompt";

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		"oidc-provider": {
			creator: typeof oidcProvider;
		};
	}
}

const RESERVED_OIDC_PROTOCOL_CLAIMS = new Set([
	// JWT registered claims (RFC 7519 section 4.1).
	"iss",
	"sub",
	"aud",
	"exp",
	"nbf",
	"iat",
	"jti",
	// OpenID Connect ID Token and logout/session claims.
	"auth_time",
	"nonce",
	"acr",
	"amr",
	"azp",
	"at_hash",
	"c_hash",
	"s_hash",
	"sid",
	// Registered JWT security-context claims.
	"cnf",
	"act",
	"may_act",
	// OpenID Connect standard identity claims. The provider's canonical user
	// projection owns these values; callbacks remain compatible for unregistered
	// extension names such as existing `custom` and `userId` claims.
	"name",
	"given_name",
	"family_name",
	"middle_name",
	"nickname",
	"preferred_username",
	"profile",
	"picture",
	"website",
	"email",
	"email_verified",
	"gender",
	"birthdate",
	"zoneinfo",
	"locale",
	"phone_number",
	"phone_number_verified",
	"address",
	"updated_at",
	"_claim_names",
	"_claim_sources",
	// OAuth/JWT access-token and proof context claims.
	"client_id",
	"scope",
	"authorization_details",
	"token_type",
	"token_use",
	"username",
	"groups",
	"roles",
	"entitlements",
	"events",
	"toe",
	"txn",
	"htm",
	"htu",
	"ath",
	"jkt",
	// Remaining registered names from the IANA JWT Claims registry snapshot
	// dated 2026-06-29. Keep this compatibility deny-list synchronized with IANA;
	// names absent from the registry remain valid legacy extensions.
	"sub_jwk",
	"sip_from_tag",
	"sip_date",
	"sip_callid",
	"sip_cseq_num",
	"sip_via_branch",
	"orig",
	"dest",
	"mky",
	"rph",
	"vot",
	"vtm",
	"attest",
	"origid",
	"jcard",
	"at_use_nbr",
	"div",
	"opt",
	"vc",
	"vp",
	"sph",
	"ace_profile",
	"cnonce",
	"exi",
	"token_introspection",
	"eat_nonce",
	"ueid",
	"sueids",
	"oemid",
	"hwmodel",
	"hwversion",
	"oemboot",
	"dbgstat",
	"location",
	"eat_profile",
	"submods",
	"uptime",
	"bootcount",
	"bootseed",
	"dloas",
	"swname",
	"swversion",
	"manifests",
	"measurements",
	"measres",
	"intuse",
	"cdniv",
	"cdnicrit",
	"cdniip",
	"cdniuc",
	"cdniets",
	"cdnistt",
	"cdnistd",
	"sig_val_claims",
	"verified_claims",
	"place_of_birth",
	"nationalities",
	"birth_family_name",
	"birth_given_name",
	"birth_middle_name",
	"salutation",
	"title",
	"msisdn",
	"also_known_as",
	"atc",
	"sub_id",
	"rcd",
	"rcdi",
	"crn",
	"msgi",
	"rdap_allowed_purposes",
	"rdap_dnt_allowed",
	"geohash",
	"_sd",
	"...",
	"_sd_alg",
	"sd_hash",
	"consumerPlmnId",
	"consumerSnpnId",
	"producerPlmnId",
	"producerSnpnId",
	"producerSnssaiList",
	"producerNsiList",
	"producerNfSetId",
	"producerNfServiceSetId",
	"sourceNfInstanceId",
	"analyticsIdList",
	"resOwnerId",
	"cmw",
	"jwks",
	"metadata",
	"constraints",
	"crit",
	"ref",
	"delegation",
	"logo_uri",
	"authority_hints",
	"trust_anchor_hints",
	"trust_marks",
	"trust_mark_issuers",
	"trust_mark_owners",
	"metadata_policy",
	"metadata_policy_crit",
	"source_endpoint",
	"keys",
	"trust_mark_type",
	"trust_chain",
	"trust_anchor",
	"status",
	"status_list",
	"ttl",
	"stpl",
]);

function assertIssuedOIDCIdToken(
	token: string,
	expected: Readonly<{
		subject: string;
		audience: string;
		issuer: string;
		sessionId: string;
		issuedAt: number;
		authTime: number;
		nonce?: string | undefined;
		maxExpiresAt: Date;
	}>,
): void {
	let claims: ReturnType<typeof decodeJwt>;
	try {
		claims = decodeJwt(token);
	} catch {
		throw new ClearanceError("OIDC signer returned an invalid ID token");
	}
	if (
		claims.sub !== expected.subject ||
		claims.aud !== expected.audience ||
		claims.iss !== expected.issuer ||
		claims.sid !== expected.sessionId ||
		claims.iat !== expected.issuedAt ||
		claims.auth_time !== expected.authTime ||
		claims.nonce !== expected.nonce ||
		claims.acr !== "urn:mace:incommon:iap:silver" ||
		!Number.isFinite(claims.exp) ||
		!Number.isInteger(claims.exp) ||
		claims.exp! > Math.floor(expected.maxExpiresAt.getTime() / 1000)
	) {
		throw new ClearanceError("OIDC signer changed required ID-token authority");
	}
}

export function filterAdditionalUserClaims(
	claims: Record<string, unknown>,
): Record<string, unknown> {
	return Object.fromEntries(
		Object.entries(claims).filter(
			([claim]) => !RESERVED_OIDC_PROTOCOL_CLAIMS.has(claim),
		),
	);
}

/**
 * Get a client by ID, checking trusted clients first, then database
 */
export async function getClient(
	clientId: string,
	trustedClients: (Client & { skipConsent?: boolean | undefined })[] = [],
): Promise<(Client & { skipConsent?: boolean | undefined }) | null> {
	const {
		context: { adapter: rootAdapter },
	} = await getCurrentAuthContext();
	const adapter = await getCurrentAdapter(rootAdapter);
	const trustedClient = trustedClients.find(
		(client) => client.clientId === clientId,
	);
	if (trustedClient) {
		return trustedClient;
	}
	return adapter
		.findOne<OAuthApplication>({
			model: "oauthApplication",
			where: [{ field: "clientId", value: clientId }],
		})
		.then((res) => {
			if (!res) {
				return null;
			}
			// omit sensitive fields
			return {
				clientId: res.clientId,
				clientSecret: res.clientSecret,
				type: res.type,
				name: res.name,
				icon: res.icon,
				disabled: res.disabled,
				redirectUrls: (res.redirectUrls ?? "").split(","),
				metadata: res.metadata ? JSON.parse(res.metadata) : {},
			} satisfies Client;
		});
}

function getOIDCIssuer(
	ctx: GenericEndpointContext,
	options?: OIDCOptions | undefined,
): string {
	const jwtPlugin = ctx.context.getPlugin("jwt");
	return (
		options?.metadata?.issuer ??
		jwtPlugin?.options?.jwt?.issuer ??
		(ctx.context.options.baseURL as string)
	);
}

function resolveIDTokenAudience(payload: {
	aud?: string | string[] | undefined;
	azp?: unknown;
}): string | null {
	if (typeof payload.aud === "string") {
		return payload.aud;
	}
	if (!Array.isArray(payload.aud) || payload.aud.length === 0) {
		return null;
	}
	if (payload.aud.length === 1) {
		return payload.aud[0] ?? null;
	}
	return typeof payload.azp === "string" && payload.aud.includes(payload.azp)
		? payload.azp
		: null;
}

export const getMetadata = (
	ctx: GenericEndpointContext,
	options?: OIDCOptions | undefined,
): OIDCMetadata => {
	const issuer = getOIDCIssuer(ctx, options);
	const baseURL = ctx.context.baseURL;
	const supportedAlgs = options?.useJWTPlugin ? ["RS256", "EdDSA"] : ["HS256"];
	return {
		issuer,
		authorization_endpoint: `${baseURL}/oauth2/authorize`,
		token_endpoint: `${baseURL}/oauth2/token`,
		userinfo_endpoint: `${baseURL}/oauth2/userinfo`,
		jwks_uri: `${baseURL}/jwks`,
		registration_endpoint: `${baseURL}/oauth2/register`,
		end_session_endpoint: `${baseURL}/oauth2/endsession`,
		scopes_supported: ["openid", "profile", "email", "offline_access"],
		response_types_supported: ["code"],
		response_modes_supported: ["query"],
		grant_types_supported: ["authorization_code", "refresh_token"],
		acr_values_supported: [
			"urn:mace:incommon:iap:silver",
			"urn:mace:incommon:iap:bronze",
		],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: supportedAlgs,
		token_endpoint_auth_methods_supported: [
			"client_secret_basic",
			"client_secret_post",
			"none",
		],
		code_challenge_methods_supported: ["S256"],
		claims_supported: [
			"sub",
			"iss",
			"aud",
			"exp",
			"nbf",
			"iat",
			"jti",
			"email",
			"email_verified",
			"name",
		],
		...options?.metadata,
	};
};

const oAuthConsentBodySchema = z.object({
	accept: z.boolean(),
	consent_code: z.string().optional().nullish(),
});

const codeVerificationValueSchema = z
	.object({
		clientId: z.string().min(1),
		redirectURI: z
			.string()
			.min(1)
			.refine(isSafeUrlScheme)
			.refine((value) => {
				try {
					new URL(value);
					return true;
				} catch {
					return false;
				}
			}),
		scope: z.array(z.string().min(1)).min(1),
		userId: z.string().min(1),
		authTime: z.number().finite().positive(),
		requireConsent: z.boolean(),
		state: z.string().nullish(),
		codeChallenge: z.string().min(1).optional(),
		codeChallengeMethod: z.enum(["s256", "sha256", "plain"]).optional(),
		nonce: z.string().optional(),
		sessionDerivativeAuthority: z.string().min(1).optional(),
		organizationId: z.string().min(1).nullish(),
	})
	.passthrough();

export function parseCodeVerificationValue(
	value: string,
): CodeVerificationValue | null {
	let parsed: unknown;
	try {
		parsed = JSON.parse(value);
	} catch {
		return null;
	}
	const result = codeVerificationValueSchema.safeParse(parsed);
	return result.success ? (result.data as CodeVerificationValue) : null;
}

const oAuth2TokenBodySchema = z.record(z.any(), z.any());

const registerOAuthApplicationBodySchema = z.object({
	// This plugin is deprecated and removed in the next major. It gets only the
	// non-breaking guard that rejects code-execution schemes (javascript:, data:,
	// vbscript:). The stricter https-or-loopback policy lives in
	// @clearance/oauth-provider via SafeUrlSchema; migrating there is the path to
	// full parity, so we do not tighten this plugin further.
	redirect_uris: z
		.array(
			z.string().refine(isSafeUrlScheme, {
				message:
					"redirect_uri cannot use a javascript:, data:, or vbscript: scheme",
			}),
		)
		.meta({
			description:
				'A list of redirect URIs. Eg: ["https://client.example.com/callback"]',
		}),
	token_endpoint_auth_method: z
		.enum(["none", "client_secret_basic", "client_secret_post"])
		.meta({
			description:
				'The authentication method for the token endpoint. Eg: "client_secret_basic"',
		})
		.default("client_secret_basic")
		.optional(),
	grant_types: z
		.array(
			z.enum([
				"authorization_code",
				"implicit",
				"password",
				"client_credentials",
				"refresh_token",
				"urn:ietf:params:oauth:grant-type:jwt-bearer",
				"urn:ietf:params:oauth:grant-type:saml2-bearer",
			]),
		)
		.meta({
			description:
				'The grant types supported by the application. Eg: ["authorization_code"]',
		})
		.default(["authorization_code"])
		.optional(),
	response_types: z
		.array(z.enum(["code", "token"]))
		.meta({
			description:
				'The response types supported by the application. Eg: ["code"]',
		})
		.default(["code"])
		.optional(),
	client_name: z
		.string()
		.meta({
			description: 'The name of the application. Eg: "My App"',
		})
		.optional(),
	client_uri: z
		.string()
		.meta({
			description:
				'The URI of the application. Eg: "https://client.example.com"',
		})
		.optional(),
	logo_uri: z
		.string()
		.meta({
			description:
				'The URI of the application logo. Eg: "https://client.example.com/logo.png"',
		})
		.optional(),
	scope: z
		.string()
		.meta({
			description:
				'The scopes supported by the application. Separated by spaces. Eg: "profile email"',
		})
		.optional(),
	contacts: z
		.array(z.string())
		.meta({
			description:
				'The contact information for the application. Eg: ["admin@example.com"]',
		})
		.optional(),
	tos_uri: z
		.string()
		.meta({
			description:
				'The URI of the application terms of service. Eg: "https://client.example.com/tos"',
		})
		.optional(),
	policy_uri: z
		.string()
		.meta({
			description:
				'The URI of the application privacy policy. Eg: "https://client.example.com/policy"',
		})
		.optional(),
	jwks_uri: z
		.string()
		.meta({
			description:
				'The URI of the application JWKS. Eg: "https://client.example.com/jwks"',
		})
		.optional(),
	jwks: z
		.record(z.any(), z.any())
		.meta({
			description:
				'The JWKS of the application. Eg: {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "n": "...", "e": "..."}]}',
		})
		.optional(),
	metadata: z
		.record(z.any(), z.any())
		.meta({
			description: 'The metadata of the application. Eg: {"key": "value"}',
		})
		.optional(),
	software_id: z
		.string()
		.meta({
			description: 'The software ID of the application. Eg: "my-software"',
		})
		.optional(),
	software_version: z
		.string()
		.meta({
			description: 'The software version of the application. Eg: "1.0.0"',
		})
		.optional(),
	software_statement: z
		.string()
		.meta({
			description: "The software statement of the application.",
		})
		.optional(),
});

const DEFAULT_CODE_EXPIRES_IN = 600;
const DEFAULT_ACCESS_TOKEN_EXPIRES_IN = 300;
const DEFAULT_REFRESH_TOKEN_EXPIRES_IN = 604800;
const OAUTH_ACCESS_TOKEN_DIGEST_DOMAIN = "clearance:oauth-access:v1:";
const OAUTH_REFRESH_TOKEN_DIGEST_DOMAIN = "clearance:oauth-refresh:v1:";
const OAUTH_LEGACY_PLACEHOLDER_PREFIX = "clr_oauth_ref_";

function oauthLegacyPlaceholder(
	kind: "access" | "refresh",
	identity: string,
): string {
	return `${OAUTH_LEGACY_PLACEHOLDER_PREFIX}${kind}_${identity}`;
}

function isOAuthLegacyPlaceholder(value: string | null | undefined): boolean {
	return Boolean(value?.startsWith(OAUTH_LEGACY_PLACEHOLDER_PREFIX));
}

export async function digestOAuthToken(
	kind: "access" | "refresh",
	token: string,
): Promise<string> {
	const domain =
		kind === "access"
			? OAUTH_ACCESS_TOKEN_DIGEST_DOMAIN
			: OAUTH_REFRESH_TOKEN_DIGEST_DOMAIN;
	const digest = await createHash("SHA-256", "base64urlnopad").digest(
		`${domain}${token}`,
	);
	return `v1:${digest}`;
}

const hasOfflineAccessScope = (scopes: string | null | undefined): boolean =>
	Boolean(scopes?.split(/\s+/).includes("offline_access"));

/**
 * Removes every legacy replayable OAuth bearer before the provider starts.
 * Rows that were never authorized for offline access have their legacy refresh
 * capability revoked instead of upgraded.
 */
export async function migrateOAuthTokenSecrets(
	adapter: DBAdapter,
	model: string,
	options: ClearanceOptions,
): Promise<{ migrated: number; revoked: number }> {
	if (typeof adapter.options?.adapterConfig.transaction !== "function") {
		throw new ClearanceError(
			"OAuth token migration requires rollback-capable database transactions",
		);
	}
	let migrated = 0;
	let revoked = 0;
	const pageSize = 500;
	for (;;) {
		const ready = await runSecurityMigrationPage(
			adapter,
			options,
			OAUTH_TOKEN_MIGRATION_ID,
			async (tx, progress) => {
				const rows = await tx.findMany<OAuthAccessToken>({
					model,
					limit: pageSize,
					where:
						progress.cursor === undefined
							? undefined
							: [{ field: "id", value: progress.cursor, operator: "gt" }],
					sortBy: { field: "id", direction: "asc" },
				});
				if (progress.phase === "verify") {
					if (
						rows.some(
							(row) =>
								(row.accessToken &&
									!isOAuthLegacyPlaceholder(row.accessToken)) ||
								(row.refreshToken &&
									!isOAuthLegacyPlaceholder(row.refreshToken)),
						)
					) {
						throw new ClearanceError(
							"OAuth bearer migration left replayable plaintext credentials",
						);
					}
					const done = rows.length < pageSize;
					return {
						phase: done ? "ready" : "verify",
						cursor: done ? undefined : rows.at(-1)!.id,
						ready: done,
					};
				}
				const clientAuthority = new Map<string, boolean>();
				const userAuthority = new Map<string, boolean>();

				for (const row of rows) {
					const hasLegacyAccess = Boolean(
						row.accessToken && !isOAuthLegacyPlaceholder(row.accessToken),
					);
					const hasLegacyRefresh = Boolean(
						row.refreshToken && !isOAuthLegacyPlaceholder(row.refreshToken),
					);
					const canRefresh = hasOfflineAccessScope(row.scopes);
					let clientActive = clientAuthority.get(row.clientId);
					if (clientActive === undefined) {
						const client = await tx.findOne<OAuthApplication>({
							model: "oauthApplication",
							where: [{ field: "clientId", value: row.clientId }],
						});
						clientActive = Boolean(client && client.disabled !== true);
						clientAuthority.set(row.clientId, clientActive);
					}
					const userId = row.userId ?? "";
					let userActive = userAuthority.get(userId);
					if (userActive === undefined) {
						const user = userId
							? await tx.findOne<{ banned?: boolean | null }>({
									model: "user",
									where: [{ field: "id", value: userId }],
								})
							: null;
						userActive = Boolean(user && user.banned !== true);
						userAuthority.set(userId, userActive);
					}
					const mustRevoke =
						!clientActive ||
						!userActive ||
						(!canRefresh &&
							(hasLegacyRefresh ||
								Boolean(row.refreshTokenDigest) ||
								row.refreshStatus === "active"));
					if (!hasLegacyAccess && !hasLegacyRefresh && !mustRevoke) continue;

					const now = new Date();
					const updated = await tx.incrementOne<OAuthAccessToken>({
						model,
						where: [
							{ field: "id", value: row.id },
							{ field: "accessToken", value: row.accessToken ?? null },
							{ field: "refreshToken", value: row.refreshToken ?? null },
						],
						increment: {},
						set: {
							accessToken: hasLegacyAccess
								? oauthLegacyPlaceholder("access", String(row.id))
								: row.accessToken,
							refreshToken: hasLegacyRefresh
								? oauthLegacyPlaceholder("refresh", String(row.id))
								: row.refreshToken,
							accessTokenDigest: hasLegacyAccess
								? await digestOAuthToken("access", row.accessToken!)
								: row.accessTokenDigest,
							refreshTokenDigest:
								hasLegacyRefresh && canRefresh
									? await digestOAuthToken("refresh", row.refreshToken!)
									: mustRevoke
										? null
										: row.refreshTokenDigest,
							digestVersion: 1,
							familyId: row.familyId ?? row.id,
							refreshStatus: mustRevoke
								? "revoked"
								: (row.refreshStatus ?? (row.refreshToken ? "active" : "none")),
							rotationCounter: row.rotationCounter ?? 0,
							revokedAt: mustRevoke ? now : row.revokedAt,
							updatedAt: now,
						},
					});
					if (!updated) {
						throw new ClearanceError(
							`OAuth token ${row.id} changed during secret migration; retry the migration`,
						);
					}
					migrated += hasLegacyAccess || hasLegacyRefresh ? 1 : 0;
					revoked += mustRevoke ? 1 : 0;
				}
				const done = rows.length < pageSize;
				return {
					phase: done ? "verify" : "migrate",
					cursor: done ? undefined : rows.at(-1)!.id,
					ready: false,
				};
			},
		);
		if (ready) return { migrated, revoked };
	}
}

export async function findOAuthTokenBySecret(
	adapter: DBAdapter | DBTransactionAdapter,
	model: string,
	kind: "access" | "refresh",
	presentedToken: string,
): Promise<OAuthAccessToken | null> {
	if (readInternalCredentialAuthority(adapter)?.generation === "legacy-v1") {
		const rawField = kind === "access" ? "accessToken" : "refreshToken";
		const token = await adapter.findOne<OAuthAccessToken>({
			model,
			where: [{ field: rawField, value: presentedToken }],
		});
		const storedToken =
			kind === "access" ? token?.accessToken : token?.refreshToken;
		return token &&
			typeof storedToken === "string" &&
			constantTimeEqual(storedToken, presentedToken)
			? token
			: null;
	}
	const digestField =
		kind === "access" ? "accessTokenDigest" : "refreshTokenDigest";
	if (isOAuthLegacyPlaceholder(presentedToken)) return null;
	const digest = await digestOAuthToken(kind, presentedToken);
	const token = await adapter.findOne<OAuthAccessToken>({
		model,
		where: [{ field: digestField, value: digest }],
	});
	return token &&
		constantTimeEqual(
			kind === "access"
				? (token.accessTokenDigest ?? "")
				: (token.refreshTokenDigest ?? ""),
			digest,
		)
		? token
		: null;
}

export type OAuthSessionDerivativePurpose = "oidc" | "mcp";

export async function validateOAuthSessionDerivativeAuthority(
	internalAdapter: InternalAdapter,
	token: Pick<
		OAuthAccessToken,
		"userId" | "organizationId" | "sessionDerivativeAuthority"
	>,
	purpose: OAuthSessionDerivativePurpose,
	managed: boolean,
): Promise<InternalSessionDerivativeAuthority | undefined> {
	if (!managed && !token.sessionDerivativeAuthority) return undefined;
	const authority = await validateInternalSessionDerivativeAuthority(
		internalAdapter,
		token.sessionDerivativeAuthority,
		{
			purpose,
			subjectId: token.userId,
			organizationId: token.organizationId ?? null,
		},
	);
	if (!authority) {
		throw new ManagedSessionDerivativeAuthorityError("authority_missing");
	}
	return authority;
}

export async function revokeOAuthTokenFamily(
	adapter: DBAdapter | DBTransactionAdapter,
	model: string,
	token: Pick<OAuthAccessToken, "id" | "familyId">,
): Promise<void> {
	const revokedAt = new Date();
	await adapter.updateMany({
		model,
		where: [
			token.familyId
				? { field: "familyId", value: token.familyId }
				: { field: "id", value: token.id },
		],
		update: {
			refreshTokenDigest: null,
			refreshStatus: "revoked",
			revokedAt,
			updatedAt: revokedAt,
		},
	});
}

export async function withOAuthAccessTokenAuthority<R>(
	ctx: GenericEndpointContext,
	model: string,
	presentedToken: string,
	purpose: OAuthSessionDerivativePurpose,
	read: (
		adapter: DBAdapter | DBTransactionAdapter,
		token: OAuthAccessToken,
	) => Promise<R>,
): Promise<R | null> {
	return runManagedAuthenticationTransaction(ctx, async () => {
		const adapter = await getCurrentAdapter(ctx.context.adapter);
		const token = await findOAuthTokenBySecret(
			adapter,
			model,
			"access",
			presentedToken,
		);
		if (
			!token ||
			token.refreshStatus === "revoked" ||
			token.accessTokenExpiresAt <= new Date()
		) {
			return null;
		}
		try {
			await validateOAuthSessionDerivativeAuthority(
				ctx.context.internalAdapter,
				token,
				purpose,
				usesManagedAuthenticationPolicy(ctx),
			);
		} catch (error) {
			if (!(error instanceof ManagedSessionDerivativeAuthorityError)) {
				throw error;
			}
			await revokeOAuthTokenFamily(adapter, model, token);
			return null;
		}
		return read(adapter, token);
	});
}

type OAuthTokenIssueInput = {
	clientId: string;
	userId: string;
	scopes: string;
	accessTokenExpiresAt: Date;
	refreshTokenExpiresAt?: Date | null;
	familyId?: string;
	parentTokenId?: string;
	rotationCounter?: number;
	issueRefreshToken: boolean;
	accessToken?: string;
	refreshToken?: string;
	sessionDerivativeAuthority?: string | null;
	organizationId?: string | null;
};

export async function createOAuthTokenPair(
	adapter: DBAdapter | DBTransactionAdapter,
	model: string,
	input: OAuthTokenIssueInput,
): Promise<{
	row: OAuthAccessToken;
	accessToken: string;
	refreshToken?: string;
}> {
	const familyId =
		input.familyId ?? generateRandomString(32, "a-z", "A-Z", "0-9");
	const accessToken =
		input.accessToken ?? generateRandomString(48, "a-z", "A-Z", "0-9");
	const refreshToken = input.issueRefreshToken
		? (input.refreshToken ?? generateRandomString(48, "a-z", "A-Z", "0-9"))
		: undefined;
	const legacyIdentity = generateRandomString(32, "a-z", "A-Z", "0-9");
	const now = new Date();
	if (readInternalCredentialAuthority(adapter)?.generation === "legacy-v1") {
		if (!adapter.rawTransactionQuery) {
			if (
				"transaction" in adapter &&
				typeof adapter.transaction === "function"
			) {
				const authority = readInternalCredentialAuthority(adapter)!;
				return runWithTransaction(adapter, async () => {
					const tx = await getCurrentAdapter(adapter);
					attachInternalCredentialAuthority(tx, authority);
					return createOAuthTokenPair(tx, model, input);
				});
			}
			throw new ClearanceError(
				"Legacy OAuth issuance requires a transaction-bound PostgreSQL adapter",
			);
		}
		const id = generateRandomString(32, "a-z", "A-Z", "0-9");
		const storedRefreshToken =
			refreshToken ?? generateRandomString(48, "a-z", "A-Z", "0-9");
		const quotedModel = `"${model.replaceAll('"', '""')}"`;
		const inserted = await adapter.rawTransactionQuery<Record<string, unknown>>(
			`INSERT INTO ${quotedModel} (
				id, "accessToken", "refreshToken", "accessTokenExpiresAt",
				"refreshTokenExpiresAt", "clientId", "userId", scopes,
				"createdAt", "updatedAt"
			 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
			 RETURNING *`,
			[
				id,
				accessToken,
				storedRefreshToken,
				input.accessTokenExpiresAt,
				input.refreshTokenExpiresAt ?? input.accessTokenExpiresAt,
				input.clientId,
				input.userId,
				input.scopes,
				now,
			],
		);
		const row = inserted.rows[0] as unknown as OAuthAccessToken | undefined;
		if (!row) {
			throw new ClearanceError(
				"Legacy OAuth token issuance did not return a row",
			);
		}
		return { row, accessToken, refreshToken };
	}
	const row = await adapter.create<OAuthAccessToken, OAuthAccessToken>({
		model,
		data: {
			accessToken: oauthLegacyPlaceholder("access", legacyIdentity),
			refreshToken: oauthLegacyPlaceholder("refresh", legacyIdentity),
			accessTokenDigest: await digestOAuthToken("access", accessToken),
			refreshTokenDigest: refreshToken
				? await digestOAuthToken("refresh", refreshToken)
				: null,
			digestVersion: 1,
			familyId,
			refreshStatus: refreshToken ? "active" : "none",
			rotationCounter: input.rotationCounter ?? 0,
			parentTokenId: input.parentTokenId ?? null,
			consumedAt: null,
			revokedAt: null,
			reuseDetectedAt: null,
			rotationNonceDigest: null,
			recoveryExpiresAt: null,
			accessTokenExpiresAt: input.accessTokenExpiresAt,
			// The access expiry is a non-authoritative compatibility value for
			// access-only rows on legacy schemas where this column was NOT NULL.
			refreshTokenExpiresAt:
				input.refreshTokenExpiresAt ?? input.accessTokenExpiresAt,
			sessionDerivativeAuthority:
				input.sessionDerivativeAuthority ?? null,
			organizationId: input.organizationId ?? null,
			clientId: input.clientId,
			userId: input.userId,
			scopes: input.scopes,
			createdAt: now,
			updatedAt: now,
		},
	});
	return { row, accessToken, refreshToken };
}

export async function rotateOAuthRefreshToken(
	adapter: DBAdapter,
	model: string,
	input: {
		presentedRefreshToken: string;
		clientId: string;
		accessTokenExpiresAt: Date;
		secretConfig: string | SecretConfig;
		idempotencyKey?: string | undefined;
		derivativeAuthority?:
			| {
					internalAdapter: InternalAdapter;
					purpose: OAuthSessionDerivativePurpose;
					managed: boolean;
			  }
			| undefined;
	},
) {
	if (typeof adapter.options?.adapterConfig.transaction !== "function") {
		throw new ClearanceError(
			"OAuth refresh token rotation requires an adapter with rollback-capable transactions",
		);
	}
	const operationKey =
		input.idempotencyKey === undefined
			? undefined
			: parseCredentialOperationKey(input.idempotencyKey);
	if (input.idempotencyKey !== undefined && !operationKey) {
		throw new ClearanceError(CREDENTIAL_OPERATION_KEY_REQUIREMENT);
	}
	const credentialAuthority = readInternalCredentialAuthority(adapter);
	if (credentialAuthority?.generation === "legacy-v1") {
		return runWithTransaction(adapter, async () => {
			const tx = await getCurrentAdapter(adapter);
			attachInternalCredentialAuthority(tx, credentialAuthority);
			const token = await findOAuthTokenBySecret(
				tx,
				model,
				"refresh",
				input.presentedRefreshToken,
			);
			if (!token || token.clientId !== input.clientId) {
				return { kind: "invalid" as const };
			}
			if (
				!token.refreshTokenExpiresAt ||
				token.refreshTokenExpiresAt < new Date() ||
				!token.scopes?.split(/\s+/).includes("offline_access")
			) {
				return { kind: "expired" as const };
			}
			let sourceAuthority: InternalSessionDerivativeAuthority | undefined;
			try {
				sourceAuthority = input.derivativeAuthority
					? await validateOAuthSessionDerivativeAuthority(
							input.derivativeAuthority.internalAdapter,
							token,
							input.derivativeAuthority.purpose,
							input.derivativeAuthority.managed,
						)
					: undefined;
			} catch (error) {
				if (!(error instanceof ManagedSessionDerivativeAuthorityError)) {
					throw error;
				}
				await revokeOAuthTokenFamily(tx, model, token);
				return { kind: "invalid" as const };
			}
			if (sourceAuthority && sourceAuthority.sourceExpiresAt <= Date.now()) {
				await revokeOAuthTokenFamily(tx, model, token);
				return { kind: "expired" as const };
			}
			const userAuthority = token.userId
				? await lockAndReadActiveUser(tx, token.userId)
				: null;
			if (!userAuthority) return { kind: "invalid" as const };
			const successor = await createOAuthTokenPair(tx, model, {
				clientId: token.clientId,
				userId: token.userId,
				scopes: token.scopes,
				accessTokenExpiresAt: sourceAuthority
					? new Date(
							Math.min(
								input.accessTokenExpiresAt.getTime(),
								sourceAuthority.sourceExpiresAt,
							),
						)
					: input.accessTokenExpiresAt,
				refreshTokenExpiresAt: sourceAuthority
					? new Date(
							Math.min(
								token.refreshTokenExpiresAt.getTime(),
								sourceAuthority.sourceExpiresAt,
							),
						)
					: token.refreshTokenExpiresAt,
				issueRefreshToken: true,
				sessionDerivativeAuthority: token.sessionDerivativeAuthority,
				organizationId: token.organizationId,
			});
			return { kind: "rotated" as const, successor, token };
		});
	}
	const refreshDigest = await digestOAuthToken(
		"refresh",
		input.presentedRefreshToken,
	);
	return runWithTransaction(adapter, async () => {
		const tx = await getCurrentAdapter(adapter);
		const token = await findOAuthTokenBySecret(
			tx,
			model,
			"refresh",
			input.presentedRefreshToken,
		);
		if (!token || token.clientId !== input.clientId) {
			return { kind: "invalid" as const };
		}
		if (
			!token.refreshTokenExpiresAt ||
			token.refreshTokenExpiresAt < new Date()
		) {
			return { kind: "expired" as const };
		}
		const familyId = token.familyId ?? token.id;
		if (!token.scopes?.split(/\s+/).includes("offline_access")) {
			const revokedAt = new Date();
			await tx.updateMany({
				model,
				where: [{ field: "familyId", value: familyId }],
				update: {
					refreshTokenDigest: null,
					refreshStatus: "revoked",
					revokedAt,
					updatedAt: revokedAt,
				},
			});
			return { kind: "invalid" as const };
		}
		const revokeFamily = async () => {
			const detectedAt = new Date();
			await tx.updateMany({
				model,
				where: [{ field: "familyId", value: familyId }],
				update: {
					refreshStatus: "revoked",
					revokedAt: detectedAt,
					reuseDetectedAt: detectedAt,
					rotationNonceDigest: null,
					recoveryExpiresAt: null,
					updatedAt: detectedAt,
				},
			});
		};
		let sourceAuthority: InternalSessionDerivativeAuthority | undefined;
		try {
			sourceAuthority = input.derivativeAuthority
				? await validateOAuthSessionDerivativeAuthority(
						input.derivativeAuthority.internalAdapter,
						token,
						input.derivativeAuthority.purpose,
						input.derivativeAuthority.managed,
					)
				: undefined;
		} catch (error) {
			if (!(error instanceof ManagedSessionDerivativeAuthorityError)) {
				throw error;
			}
			await revokeFamily();
			return { kind: "invalid" as const };
		}
		if (sourceAuthority && sourceAuthority.sourceExpiresAt <= Date.now()) {
			await revokeFamily();
			return { kind: "expired" as const };
		}
		const userAuthority = token.userId
			? await lockAndReadActiveUser(tx, token.userId)
			: null;
		if (!userAuthority) {
			await revokeFamily();
			return { kind: "invalid" as const };
		}
		const deriveTokens = async (secret: string) => {
			if (!operationKey) return null;
			const authority = [
				"clearance:oauth-refresh-successor:v1",
				token.id,
				refreshDigest,
				input.clientId,
				operationKey,
			].join(":");
			const hmac = createHMAC("SHA-256", "base64urlnopad");
			return {
				accessToken: await hmac.sign(secret, `${authority}:access`),
				refreshToken: await hmac.sign(secret, `${authority}:refresh`),
			};
		};
		const derivationKeys =
			typeof input.secretConfig === "string"
				? [input.secretConfig]
				: [
						input.secretConfig.keys.get(input.secretConfig.currentVersion),
						...input.secretConfig.keys.values(),
					].filter(
						(key, index, all): key is string =>
							Boolean(key) && all.indexOf(key) === index,
					);
		const rotationNonceDigest = operationKey
			? await createHash("SHA-256", "base64urlnopad").digest(
					`clearance:oauth-refresh-operation:v1:${operationKey}`,
				)
			: null;
		const recoverConsumedRotation = async (
			parent: OAuthAccessToken,
		): Promise<{
			kind: "rotated";
			successor: {
				row: OAuthAccessToken;
				accessToken: string;
				refreshToken: string;
			};
			token: OAuthAccessToken;
		} | null> => {
			if (
				!rotationNonceDigest ||
				!parent.rotationNonceDigest ||
				!parent.recoveryExpiresAt ||
				parent.recoveryExpiresAt <= new Date() ||
				!constantTimeEqual(parent.rotationNonceDigest, rotationNonceDigest)
			) {
				return null;
			}
			const successor = await tx.findOne<OAuthAccessToken>({
				model,
				where: [{ field: "parentTokenId", value: parent.id }],
			});
			if (successor?.refreshStatus !== "active") return null;
			for (const key of derivationKeys) {
				const candidate = await deriveTokens(key);
				if (
					candidate &&
					constantTimeEqual(
						successor.accessTokenDigest ?? "",
						await digestOAuthToken("access", candidate.accessToken),
					) &&
					constantTimeEqual(
						successor.refreshTokenDigest ?? "",
						await digestOAuthToken("refresh", candidate.refreshToken),
					)
				) {
					return {
						kind: "rotated",
						successor: { row: successor, ...candidate },
						token: parent,
					};
				}
			}
			return null;
		};
		if (token.refreshStatus !== "active") {
			if (token.refreshStatus === "consumed") {
				const recovered = await recoverConsumedRotation(token);
				if (recovered) return recovered;
				await revokeFamily();
				return { kind: "reused" as const };
			}
			return { kind: "invalid" as const };
		}
		const consumedAt = new Date();
		const recoveryExpiresAt = rotationNonceDigest
			? new Date(consumedAt.getTime() + 30_000)
			: null;
		const consumed = await tx.incrementOne<OAuthAccessToken>({
			model,
			where: [
				{ field: "id", value: token.id },
				{ field: "refreshTokenDigest", value: refreshDigest },
				{ field: "refreshStatus", value: "active" },
			],
			increment: {},
			set: {
				refreshStatus: "consumed",
				consumedAt,
				rotationNonceDigest,
				recoveryExpiresAt,
				updatedAt: consumedAt,
			},
		});
		if (!consumed) {
			const currentParent = await tx.findOne<OAuthAccessToken>({
				model,
				where: [{ field: "id", value: token.id }],
			});
			if (currentParent?.refreshStatus === "consumed") {
				const recovered = await recoverConsumedRotation(currentParent);
				if (recovered) return recovered;
			}
			await revokeFamily();
			return { kind: "reused" as const };
		}
		const derived = await deriveTokens(derivationKeys[0]!);
		const successor = await createOAuthTokenPair(tx, model, {
			clientId: token.clientId,
			userId: token.userId,
			scopes: token.scopes,
			accessTokenExpiresAt: sourceAuthority
				? new Date(
						Math.min(
							input.accessTokenExpiresAt.getTime(),
							sourceAuthority.sourceExpiresAt,
						),
					)
				: input.accessTokenExpiresAt,
			refreshTokenExpiresAt: sourceAuthority
				? new Date(
						Math.min(
							token.refreshTokenExpiresAt.getTime(),
							sourceAuthority.sourceExpiresAt,
						),
					)
				: token.refreshTokenExpiresAt,
			familyId,
			parentTokenId: token.id,
			rotationCounter: (token.rotationCounter ?? 0) + 1,
			issueRefreshToken: true,
			sessionDerivativeAuthority: token.sessionDerivativeAuthority,
			organizationId: token.organizationId,
			...(derived ?? {}),
		});
		if (token.parentTokenId) {
			await tx.update({
				model,
				where: [{ field: "id", value: token.parentTokenId }],
				update: {
					rotationNonceDigest: null,
					recoveryExpiresAt: null,
					updatedAt: consumedAt,
				},
			});
		}
		return { kind: "rotated" as const, successor, token };
	});
}

const warnOidcDeprecation = deprecate(
	() => {},
	'The "oidc-provider" plugin is deprecated and will be removed in the next major version. ' +
		"Migrate to @clearance/oauth-provider. " +
		"See: https://github.com/clearance-auth/clearance",
);

/**
 * OpenID Connect (OIDC) plugin for Clearance. This plugin implements the
 * authorization code flow and the token exchange flow. It also implements the
 * userinfo endpoint.
 *
 * @deprecated Use `@clearance/oauth-provider` instead. This plugin will be removed in the next major version.
 * @see https://github.com/clearance-auth/clearance
 *
 * @param options - The options for the OIDC plugin.
 * @returns A Clearance plugin.
 */
export const oidcProvider = (options: OIDCOptions) => {
	if (!options.__skipDeprecationWarning) {
		warnOidcDeprecation();
	}
	if (
		options.accessTokenExpiresIn !== undefined &&
		(!Number.isFinite(options.accessTokenExpiresIn) ||
			options.accessTokenExpiresIn <= 0 ||
			options.accessTokenExpiresIn > DEFAULT_ACCESS_TOKEN_EXPIRES_IN)
	) {
		throw new ClearanceError(
			"OIDC accessTokenExpiresIn must be between 1 and 300 seconds",
		);
	}
	const modelName = {
		oauthClient: "oauthApplication",
		oauthAccessToken: "oauthAccessToken",
		oauthConsent: "oauthConsent",
	};
	const sessionDerivativePurpose =
		options.__sessionDerivativePurpose ?? "oidc";
	const authorizationChallengePurpose =
		`${sessionDerivativePurpose}-authorization-code`;

	const opts = {
		codeExpiresIn: DEFAULT_CODE_EXPIRES_IN,
		defaultScope: "openid",
		accessTokenExpiresIn: DEFAULT_ACCESS_TOKEN_EXPIRES_IN,
		refreshTokenExpiresIn: DEFAULT_REFRESH_TOKEN_EXPIRES_IN,
		allowPlainCodeChallengeMethod: false,
		storeClientSecret: "plain" as const,
		...options,
		scopes: [
			"openid",
			"profile",
			"email",
			"offline_access",
			...(options?.scopes || []),
		],
	};

	const trustedClients = options.trustedClients || [];
	let tokenSecretMigration: Promise<void> | null = null;

	/**
	 * Store client secret according to the configured storage method
	 */
	async function storeClientSecret(
		ctx: GenericEndpointContext,
		clientSecret: string,
	) {
		if (opts.storeClientSecret === "encrypted") {
			return await symmetricEncrypt({
				key: ctx.context.secretConfig,
				data: clientSecret,
			});
		}
		if (opts.storeClientSecret === "hashed") {
			return await defaultClientSecretHasher(clientSecret);
		}
		if (
			typeof opts.storeClientSecret === "object" &&
			"hash" in opts.storeClientSecret
		) {
			return await opts.storeClientSecret.hash(clientSecret);
		}
		if (
			typeof opts.storeClientSecret === "object" &&
			"encrypt" in opts.storeClientSecret
		) {
			return await opts.storeClientSecret.encrypt(clientSecret);
		}

		return clientSecret;
	}

	/**
	 * Verify stored client secret against provided client secret
	 */
	async function verifyStoredClientSecret(
		ctx: GenericEndpointContext,
		storedClientSecret: string,
		clientSecret: string,
	): Promise<boolean> {
		if (opts.storeClientSecret === "encrypted") {
			const decrypted = await symmetricDecrypt({
				key: ctx.context.secretConfig,
				data: storedClientSecret,
			});
			return constantTimeEqual(decrypted, clientSecret);
		}
		if (opts.storeClientSecret === "hashed") {
			const hashedClientSecret = await defaultClientSecretHasher(clientSecret);
			return constantTimeEqual(hashedClientSecret, storedClientSecret);
		}
		if (
			typeof opts.storeClientSecret === "object" &&
			"hash" in opts.storeClientSecret
		) {
			const hashedClientSecret =
				await opts.storeClientSecret.hash(clientSecret);
			return constantTimeEqual(hashedClientSecret, storedClientSecret);
		}
		if (
			typeof opts.storeClientSecret === "object" &&
			"decrypt" in opts.storeClientSecret
		) {
			const decryptedClientSecret =
				await opts.storeClientSecret.decrypt(storedClientSecret);
			return constantTimeEqual(decryptedClientSecret, clientSecret);
		}

		return constantTimeEqual(clientSecret, storedClientSecret);
	}

	return {
		id: "oidc-provider",
		version: PACKAGE_VERSION,
		init(ctx) {
			if (
				typeof ctx.adapter.options?.adapterConfig.transaction !== "function"
			) {
				throw new ClearanceError(
					"The OIDC provider requires a database adapter with rollback-capable transactions",
				);
			}
			if (
				ctx.options.secondaryStorage &&
				ctx.options.verification?.storeInDatabase !== true
			) {
				throw new ClearanceError(
					"The OIDC provider requires database-backed authorization codes so code consumption and token issuance commit atomically",
				);
			}
		},
		async onRequest(_request, ctx) {
			if (
				readInternalCredentialAuthority(ctx.options)?.generation === "legacy-v1"
			) {
				return;
			}
			if (!tokenSecretMigration) {
				const pending = assertSecurityMigrationComplete(
					ctx.adapter,
					OAUTH_TOKEN_MIGRATION_ID,
				);
				const guarded = pending.catch((error) => {
					if (tokenSecretMigration === guarded) {
						tokenSecretMigration = null;
					}
					throw error;
				});
				tokenSecretMigration = guarded;
			}
			await tokenSecretMigration;
		},
		hooks: {
			after: [
				{
					matcher() {
						return true;
					},
					handler: createAuthMiddleware(async (ctx) => {
						const loginPromptCookie = await ctx.getSignedCookie(
							"oidc_login_prompt",
							ctx.context.secret,
						);
						const cookieName = ctx.context.authCookies.sessionToken.name;
						const parsedSetCookieHeader = parseSetCookieHeader(
							ctx.context.responseHeaders?.get("set-cookie") || "",
						);
						const hasSessionToken = parsedSetCookieHeader.has(cookieName);
						if (!loginPromptCookie || !hasSessionToken) {
							return;
						}
						expireCookie(ctx, {
							name: "oidc_login_prompt",
							attributes: { path: "/" },
						});
						const sessionCookie = parsedSetCookieHeader.get(cookieName)?.value;
						const sessionToken = sessionCookie?.split(".")[0]!;
						if (!sessionToken) {
							return;
						}
						const session =
							(await ctx.context.internalAdapter.findSession(sessionToken)) ||
							ctx.context.newSession;
						if (!session) {
							return;
						}
						ctx.query = JSON.parse(loginPromptCookie);

						// Remove "login" from prompt since user just logged in
						const promptSet = parsePrompt(String(ctx.query?.prompt));
						if (promptSet.has("login")) {
							const newPromptSet = new Set(promptSet);
							newPromptSet.delete("login");
							ctx.query = {
								...ctx.query,
								prompt: Array.from(newPromptSet).join(" "),
							};
						}

						ctx.context.session = session;
						const response = await authorize(ctx, opts);
						return response;
					}),
				},
			],
		},
		endpoints: {
			getOpenIdConfig: createAuthEndpoint(
				"/.well-known/openid-configuration",
				{
					method: "GET",
					operationId: "getOpenIdConfig",
					metadata: HIDE_METADATA,
				},
				async (ctx) => {
					const metadata = getMetadata(ctx, options);
					return ctx.json(metadata);
				},
			),
			oAuth2authorize: createAuthEndpoint(
				"/oauth2/authorize",
				{
					method: "GET",
					operationId: "oauth2Authorize",
					query: z.record(z.string(), z.any()),
					metadata: {
						openapi: {
							description: "Authorize an OAuth2 request",
							responses: {
								"200": {
									description: "Authorization response generated successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												additionalProperties: true,
												description:
													"Authorization response, contents depend on the authorize function implementation",
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					return authorize(ctx, opts);
				},
			),
			oAuthConsent: createAuthEndpoint(
				"/oauth2/consent",
				{
					method: "POST",
					operationId: "oauth2Consent",
					body: oAuthConsentBodySchema,
					use: [sensitiveSessionMiddleware],
					metadata: {
						openapi: {
							description:
								"Handle OAuth2 consent. Supports both URL parameter-based flows (consent_code in body) and cookie-based flows (signed cookie).",
							requestBody: {
								required: true,
								content: {
									"application/json": {
										schema: {
											type: "object",
											properties: {
												accept: {
													type: "boolean",
													description:
														"Whether the user accepts or denies the consent request",
												},
												consent_code: {
													type: "string",
													description:
														"The consent code from the authorization request. Optional if using cookie-based flow.",
												},
											},
											required: ["accept"],
										},
									},
								},
							},
							responses: {
								"200": {
									description: "Consent processed successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													redirectURI: {
														type: "string",
														format: "uri",
														description:
															"The URI to redirect to, either with an authorization code or an error",
													},
												},
												required: ["redirectURI"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					const invalidCode = () =>
						new APIError("UNAUTHORIZED", {
							error_description: "Invalid code",
							error: "invalid_request",
						});
					// Support both consent flow methods:
					// 1. URL parameter-based: consent_code in request body (standard OAuth2 pattern)
					// 2. Cookie-based: using signed cookie for stateful consent flows
					let consentCode: string | null = ctx.body.consent_code || null;

					if (!consentCode) {
						// Check for cookie-based consent flow
						const cookieValue = await ctx.getSignedCookie(
							"oidc_consent_prompt",
							ctx.context.secret,
						);
						if (cookieValue) {
							consentCode = cookieValue;
						}
					}

					if (!consentCode) {
						throw new APIError("UNAUTHORIZED", {
							error_description:
								"consent_code is required (either in body or cookie)",
							error: "invalid_request",
						});
					}

					const responseHeaderSnapshot = snapshotOAuthResponseHeaders(ctx);
					let result: { redirectURI: string };
					try {
						result = await runWithTransaction(
							ctx.context.adapter,
							async () => {
							const currentSession = usesManagedAuthenticationPolicy(ctx)
								? await getAuthoritativeSessionFromCtx(ctx)
								: ctx.context.session;
							const verification =
								await ctx.context.internalAdapter.findVerificationValueAndPruneExpired(
									consentCode,
								);
							if (!verification) throw invalidCode();

							const value = parseCodeVerificationValue(verification.value);
							const sessionSubject = currentSession?.user.id;
							if (
								!value ||
								typeof sessionSubject !== "string" ||
								sessionSubject.length === 0 ||
								sessionSubject !== value.userId
							) {
								throw invalidCode();
							}
							if (verification.expiresAt <= new Date()) {
								throw new APIError("UNAUTHORIZED", {
									error_description: "Code expired",
									error: "invalid_request",
								});
							}
							if (!value.requireConsent) {
								throw new APIError("UNAUTHORIZED", {
									error_description: "Consent not required",
									error: "invalid_request",
								});
							}

							const sourceAuthority =
								await validateOAuthSessionDerivativeAuthority(
									ctx.context.internalAdapter,
									value,
									sessionDerivativePurpose,
									usesManagedAuthenticationPolicy(ctx),
								);
							const consumed = await consumeInternalVerificationChallenge(
								ctx.context.internalAdapter,
								{
									purpose: authorizationChallengePurpose,
									subject: value.clientId,
									identifier: consentCode,
								},
							);
							if (
								!consumed ||
								!constantTimeEqual(consumed.value, verification.value)
							) {
								throw invalidCode();
							}

							if (!ctx.body.accept) {
								return {
									redirectURI: `${value.redirectURI}?error=access_denied&error_description=User denied access`,
								};
							}

							const code = generateRandomString(32, "a-z", "A-Z", "0-9");
							const codeExpiresInMs =
								(opts?.codeExpiresIn ?? DEFAULT_CODE_EXPIRES_IN) * 1000;
							const expiresAt = new Date(
								Math.min(
									Date.now() + codeExpiresInMs,
									sourceAuthority?.sourceExpiresAt ?? Number.POSITIVE_INFINITY,
								),
							);
							if (expiresAt.getTime() <= Date.now()) throw invalidCode();
							await createInternalVerificationChallenge(
								ctx.context.internalAdapter,
								{
									purpose: authorizationChallengePurpose,
									subject: value.clientId,
								},
								{
									value: JSON.stringify({
										...value,
										requireConsent: false,
									}),
									identifier: code,
									expiresAt,
								},
							);
							const adapter = await getCurrentAdapter(ctx.context.adapter);
							const now = new Date();
							await adapter.create({
								model: modelName.oauthConsent,
								data: {
									clientId: value.clientId,
									userId: value.userId,
									scopes: value.scope.join(" "),
									consentGiven: true,
									createdAt: now,
									updatedAt: now,
								},
							});
							const redirectURI = new URL(value.redirectURI);
							redirectURI.searchParams.set("code", code);
							if (value.state) {
								redirectURI.searchParams.set("state", value.state);
							}
							return { redirectURI: redirectURI.toString() };
							},
						);
					} catch (error) {
						restoreOAuthResponseHeaders(ctx, responseHeaderSnapshot);
						if (error instanceof ManagedSessionDerivativeAuthorityError) {
							throw invalidCode();
						}
						throw error;
					}

					// Publish cookie cleanup only after the consent transaction commits.
					expireCookie(ctx, {
						name: "oidc_consent_prompt",
						attributes: { path: "/" },
					});
					return ctx.json(result);
				},
			),
			oAuth2token: createAuthEndpoint(
				"/oauth2/token",
				{
					method: "POST",
					operationId: "oauth2Token",
					body: oAuth2TokenBodySchema,
					metadata: {
						...HIDE_METADATA,
						allowedMediaTypes: [
							"application/x-www-form-urlencoded",
							"application/json",
						],
					},
				},
				async (ctx) => {
					let { body } = ctx;
					if (!body) {
						throw new APIError("BAD_REQUEST", {
							error_description: "request body not found",
							error: "invalid_request",
						});
					}
					if (body instanceof FormData) {
						body = Object.fromEntries(body.entries());
					}
					if (!(body instanceof Object)) {
						throw new APIError("BAD_REQUEST", {
							error_description: "request body is not an object",
							error: "invalid_request",
						});
					}
					let { client_id, client_secret } = body;
					const authorization =
						ctx.request?.headers.get("authorization") || null;
					if (
						authorization &&
						!client_secret &&
						authorization.startsWith("Basic ")
					) {
						let decoded: string;
						try {
							const encoded = authorization.replace("Basic ", "");
							decoded = new TextDecoder().decode(base64.decode(encoded));
						} catch {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid authorization header format",
								error: "invalid_client",
							});
						}
						// RFC 6749 §2.3.1: split on the first `:` (the secret may contain
						// further colons), then percent-decode each half before comparing
						// against stored credentials (the client encodes reserved
						// characters per RFC 3986 before base64).
						const colonIndex = decoded.indexOf(":");
						if (colonIndex === -1) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid authorization header format",
								error: "invalid_client",
							});
						}
						let id: string;
						let secret: string;
						try {
							id = decodeURIComponent(decoded.slice(0, colonIndex));
							secret = decodeURIComponent(decoded.slice(colonIndex + 1));
						} catch {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid authorization header format",
								error: "invalid_client",
							});
						}
						if (!id || !secret) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid authorization header format",
								error: "invalid_client",
							});
						}
						if (client_id && client_id.toString() !== id) {
							throw new APIError("UNAUTHORIZED", {
								error_description:
									"client_id in body does not match Authorization header",
								error: "invalid_client",
							});
						}
						client_id = id;
						client_secret = secret;
					}

					const now = Date.now();
					const iat = Math.floor(now / 1000);
					const exp = iat + opts.accessTokenExpiresIn;

					const accessTokenExpiresAt = new Date(exp * 1000);
					const refreshTokenExpiresAt = new Date(
						(iat + (opts.refreshTokenExpiresIn ?? 604800)) * 1000,
					);

					const {
						grant_type,
						code,
						redirect_uri,
						refresh_token,
						code_verifier,
					} = body;
					if (grant_type === "refresh_token") {
						if (!refresh_token) {
							throw new APIError("BAD_REQUEST", {
								error_description: "refresh_token is required",
								error: "invalid_request",
							});
						}
						if (!client_id) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid client_id",
								error: "invalid_client",
							});
						}
						const refreshClient = await getClient(
							client_id.toString(),
							trustedClients,
						);
						if (!refreshClient) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid client_id",
								error: "invalid_client",
							});
						}
						if (refreshClient.disabled) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "client is disabled",
								error: "invalid_client",
							});
						}
						if (refreshClient.type !== "public") {
							if (!refreshClient.clientSecret || !client_secret) {
								throw new APIError("UNAUTHORIZED", {
									error_description:
										"client_secret is required for confidential clients",
									error: "invalid_client",
								});
							}
							const isValidSecret = await verifyStoredClientSecret(
								ctx,
								refreshClient.clientSecret,
								client_secret.toString(),
							);
							if (!isValidSecret) {
								throw new APIError("UNAUTHORIZED", {
									error_description: "invalid client_secret",
									error: "invalid_client",
								});
							}
						}
						const rawOperationKey =
							ctx.request?.headers.get("idempotency-key") ?? undefined;
						const idempotencyKey =
							rawOperationKey === undefined
								? undefined
								: (parseCredentialOperationKey(rawOperationKey) ?? undefined);
						if (rawOperationKey !== undefined && !idempotencyKey) {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_request",
								error_description: CREDENTIAL_OPERATION_KEY_REQUIREMENT,
							});
						}
						const rotation = await rotateOAuthRefreshToken(
							ctx.context.adapter,
							modelName.oauthAccessToken,
							{
								presentedRefreshToken: refresh_token.toString(),
								clientId: client_id.toString(),
								accessTokenExpiresAt,
								secretConfig: ctx.context.secretConfig,
								idempotencyKey,
								derivativeAuthority: {
									internalAdapter: ctx.context.internalAdapter,
									purpose: "oidc",
									managed: usesManagedAuthenticationPolicy(ctx),
								},
							},
						);
						if (rotation.kind !== "rotated") {
							throw new APIError("UNAUTHORIZED", {
								error_description:
									rotation.kind === "expired"
										? "refresh token expired"
										: "invalid refresh token",
								error: "invalid_grant",
							});
						}
						setNoStoreTokenResponseHeaders(ctx);
						return ctx.json({
							access_token: rotation.successor.accessToken,
							token_type: "Bearer",
							expires_in: oauthExpiresIn(
								rotation.successor.row.accessTokenExpiresAt,
							),
							refresh_token: rotation.successor.refreshToken,
							scope: rotation.token.scopes,
						});
					}

					if (!code) {
						throw new APIError("BAD_REQUEST", {
							error_description: "code is required",
							error: "invalid_request",
						});
					}

					if (options.requirePKCE && !code_verifier) {
						throw new APIError("BAD_REQUEST", {
							error_description: "code verifier is missing",
							error: "invalid_request",
						});
					}

					const verificationValue =
						await ctx.context.internalAdapter.findVerificationValueAndPruneExpired(
							code.toString(),
						);
					if (!verificationValue) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "invalid code",
							error: "invalid_grant",
						});
					}
					if (!client_id) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "client_id is required",
							error: "invalid_client",
						});
					}
					if (!grant_type) {
						throw new APIError("BAD_REQUEST", {
							error_description: "grant_type is required",
							error: "invalid_request",
						});
					}
					if (grant_type !== "authorization_code") {
						throw new APIError("BAD_REQUEST", {
							error_description: "grant_type must be 'authorization_code'",
							error: "unsupported_grant_type",
						});
					}

					if (!redirect_uri) {
						throw new APIError("BAD_REQUEST", {
							error_description: "redirect_uri is required",
							error: "invalid_request",
						});
					}

					const client = await getClient(client_id.toString(), trustedClients);
					if (!client) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "invalid client_id",
							error: "invalid_client",
						});
					}
					if (client.disabled) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "client is disabled",
							error: "invalid_client",
						});
					}

					const value = parseCodeVerificationValue(verificationValue.value);
					if (!value) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "invalid code",
							error: "invalid_grant",
						});
					}
					if (value.clientId !== client_id.toString()) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "invalid client_id",
							error: "invalid_client",
						});
					}
					if (value.redirectURI !== redirect_uri.toString()) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "invalid redirect_uri",
							error: "invalid_client",
						});
					}
					if (value.codeChallenge && !code_verifier) {
						throw new APIError("BAD_REQUEST", {
							error_description: "code verifier is missing",
							error: "invalid_request",
						});
					}
					if (client.type === "public") {
						// For public clients (type: 'public'), validate PKCE instead of client_secret
						if (!code_verifier) {
							throw new APIError("BAD_REQUEST", {
								error_description:
									"code verifier is required for public clients",
								error: "invalid_request",
							});
						}
						// PKCE validation happens later in the flow, so we skip client_secret validation
					} else {
						if (!client.clientSecret || !client_secret) {
							throw new APIError("UNAUTHORIZED", {
								error_description:
									"client_secret is required for confidential clients",
								error: "invalid_client",
							});
						}
						const isValidSecret = await verifyStoredClientSecret(
							ctx,
							client.clientSecret,
							client_secret.toString(),
						);
						if (!isValidSecret) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid client_secret",
								error: "invalid_client",
							});
						}
					}
					if (value.codeChallenge) {
						const challenge =
							value.codeChallengeMethod === "plain"
								? code_verifier
								: await createHash("SHA-256", "base64urlnopad").digest(
										code_verifier,
									);

						if (challenge !== value.codeChallenge) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "code verification failed",
								error: "invalid_request",
							});
						}
					}

					const issued = await runWithTransaction(
						ctx.context.adapter,
						async () => {
							const consumed = await consumeInternalVerificationChallenge(
								ctx.context.internalAdapter,
								{
									purpose: "oidc-authorization-code",
									subject: client_id.toString(),
									identifier: code.toString(),
								},
							);
							if (
								!consumed ||
								!constantTimeEqual(consumed.value, verificationValue.value)
							) {
								return null;
							}
							const adapter = await getCurrentAdapter(ctx.context.adapter);
							const authority = readInternalCredentialAuthority(
								ctx.context.options,
							);
							if (authority) {
								attachInternalCredentialAuthority(adapter, authority);
							}
							let sourceAuthority: InternalSessionDerivativeAuthority | undefined;
							try {
								sourceAuthority = await validateOAuthSessionDerivativeAuthority(
									ctx.context.internalAdapter,
									value,
									"oidc",
									usesManagedAuthenticationPolicy(ctx),
								);
							} catch (error) {
								if (!(error instanceof ManagedSessionDerivativeAuthorityError)) {
									throw error;
								}
								throw new APIError("UNAUTHORIZED", {
									error_description: "invalid code",
									error: "invalid_grant",
								});
							}
							const issuedAt = Math.floor(Date.now() / 1000);
							const sourceExpiresAt = sourceAuthority?.sourceExpiresAt;
							const accessTokenExpiresAt = new Date(
								Math.min(
									(issuedAt + opts.accessTokenExpiresIn) * 1000,
									sourceExpiresAt ?? Number.POSITIVE_INFINITY,
								),
							);
							if (accessTokenExpiresAt.getTime() <= Date.now()) {
								throw new APIError("UNAUTHORIZED", {
									error_description: "source session expired",
									error: "invalid_grant",
								});
							}
							const refreshTokenExpiresAt = new Date(
								Math.min(
									(issuedAt + (opts.refreshTokenExpiresIn ?? 604800)) * 1000,
									sourceExpiresAt ?? Number.POSITIVE_INFINITY,
								),
							);
							const activeUser = await lockAndReadActiveUser(
								adapter,
								value.userId,
							);
							if (!activeUser) {
								throw new APIError("UNAUTHORIZED", {
									error_description: "user is unavailable",
									error: "invalid_grant",
								});
							}
							const requestedScopes = value.scope;
							const oauthFamilyId = generateRandomString(
								32,
								"a-z",
								"A-Z",
								"0-9",
							);
							const accessToken = generateRandomString(
								48,
								"a-z",
								"A-Z",
								"0-9",
							);
							const issueRefreshToken = requestedScopes.includes("offline_access");
							const refreshToken = issueRefreshToken
								? generateRandomString(48, "A-Z", "a-z", "0-9")
								: undefined;
							const profile = {
								given_name: activeUser.name.split(" ")[0]!,
								family_name: activeUser.name.split(" ")[1]!,
								name: activeUser.name,
								profile: activeUser.image,
								updated_at: Math.floor(
									new Date(activeUser.updatedAt).getTime() / 1000,
								),
							};
							const email = {
								email: activeUser.email,
								email_verified: activeUser.emailVerified,
							};
							const userClaims = {
								...(requestedScopes.includes("profile") ? profile : {}),
								...(requestedScopes.includes("email") ? email : {}),
							};
							const extensionClaims = filterAdditionalUserClaims(
								options.getAdditionalUserInfoClaim
									? await options.getAdditionalUserInfoClaim(
											activeUser,
											requestedScopes,
											client,
										)
									: {},
							);
							const payload = {
								...userClaims,
								...extensionClaims,
								sub: activeUser.id,
								aud: client_id.toString(),
								sid: oauthFamilyId,
								iat: issuedAt,
								auth_time: Math.floor(value.authTime / 1000),
								nonce: value.nonce,
								acr: "urn:mace:incommon:iap:silver",
							};
							let idToken: string;
							if (options.useJWTPlugin) {
								const jwtPlugin = ctx.context.getPlugin("jwt");
								if (!jwtPlugin) {
									throw new APIError("INTERNAL_SERVER_ERROR", {
										error_description: "JWT plugin is not enabled",
										error: "internal_server_error",
									});
								}
								idToken = await signJWT(ctx, {
									options: {
										...jwtPlugin.options,
										jwt: {
											...jwtPlugin.options?.jwt,
											audience: client_id.toString(),
											issuer: getOIDCIssuer(ctx, options),
											expirationTime: Math.floor(
												accessTokenExpiresAt.getTime() / 1000,
											),
										},
									},
									maxExpiresAt: accessTokenExpiresAt,
									payload,
								});
							} else {
								idToken = await new SignJWT(payload)
									.setProtectedHeader({ alg: "HS256" })
									.setIssuer(getOIDCIssuer(ctx, options))
									.setIssuedAt(issuedAt)
										.setExpirationTime(accessTokenExpiresAt)
										.sign(new TextEncoder().encode(client.clientSecret));
								}
								assertIssuedOIDCIdToken(idToken, {
									subject: activeUser.id,
									audience: client_id.toString(),
									issuer: getOIDCIssuer(ctx, options),
									sessionId: oauthFamilyId,
									issuedAt,
									authTime: Math.floor(value.authTime / 1000),
									nonce: value.nonce,
									maxExpiresAt: accessTokenExpiresAt,
								});
								await createOAuthTokenPair(adapter, modelName.oauthAccessToken, {
								clientId: client_id.toString(),
								userId: value.userId,
								scopes: requestedScopes.join(" "),
								accessTokenExpiresAt,
								refreshTokenExpiresAt: issueRefreshToken
									? refreshTokenExpiresAt
									: null,
								issueRefreshToken,
								familyId: oauthFamilyId,
								accessToken,
								refreshToken,
								sessionDerivativeAuthority:
									value.sessionDerivativeAuthority ?? null,
								organizationId: value.organizationId ?? null,
							});
							return {
								accessToken,
								refreshToken,
								idToken,
								requestedScopes,
								accessTokenExpiresAt,
							};
						},
					);
					if (!issued) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "invalid code",
							error: "invalid_grant",
						});
					}

					setNoStoreTokenResponseHeaders(ctx);
					return ctx.json({
						access_token: issued.accessToken,
						token_type: "Bearer",
						expires_in: oauthExpiresIn(issued.accessTokenExpiresAt),
						refresh_token: issued.refreshToken,
						scope: issued.requestedScopes.join(" "),
						id_token: issued.requestedScopes.includes("openid")
							? issued.idToken
							: undefined,
					});
				},
			),
			oAuth2userInfo: createAuthEndpoint(
				"/oauth2/userinfo",
				{
					method: "GET",
					operationId: "oauth2Userinfo",
					metadata: {
						...HIDE_METADATA,
						openapi: {
							description: "Get OAuth2 user information",
							responses: {
								"200": {
									description: "User information retrieved successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													sub: {
														type: "string",
														description: "Subject identifier (user ID)",
													},
													email: {
														type: "string",
														format: "email",
														nullable: true,
														description:
															"User's email address, included if 'email' scope is granted",
													},
													name: {
														type: "string",
														nullable: true,
														description:
															"User's full name, included if 'profile' scope is granted",
													},
													picture: {
														type: "string",
														format: "uri",
														nullable: true,
														description:
															"User's profile picture URL, included if 'profile' scope is granted",
													},
													given_name: {
														type: "string",
														nullable: true,
														description:
															"User's given name, included if 'profile' scope is granted",
													},
													family_name: {
														type: "string",
														nullable: true,
														description:
															"User's family name, included if 'profile' scope is granted",
													},
													email_verified: {
														type: "boolean",
														nullable: true,
														description:
															"Whether the email is verified, included if 'email' scope is granted",
													},
												},
												required: ["sub"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					if (!ctx.request) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "request not found",
							error: "invalid_request",
						});
					}
					const authorization = ctx.request.headers.get("authorization");
					if (!authorization) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "authorization header not found",
							error: "invalid_request",
						});
					}
					const token = authorization.replace("Bearer ", "");
					const claims = await withOAuthAccessTokenAuthority(
						ctx,
						modelName.oauthAccessToken,
						token,
						"oidc",
						async (adapter, accessToken) => {
							const client = await getClient(
								accessToken.clientId,
								trustedClients,
							);
							const user = await ctx.context.internalAdapter.findUserById(
								accessToken.userId,
							);
							if (
								!client ||
								client.disabled === true ||
								!user ||
								(user as Record<string, unknown>).banned === true
							) {
								await revokeOAuthTokenFamily(
									adapter,
									modelName.oauthAccessToken,
									accessToken,
								);
								return null;
							}
							const requestedScopes = accessToken.scopes.split(" ");
							const baseUserClaims = {
								sub: user.id,
								email: requestedScopes.includes("email")
									? user.email
									: undefined,
								name: requestedScopes.includes("profile")
									? user.name
									: undefined,
								picture: requestedScopes.includes("profile")
									? user.image
									: undefined,
								given_name: requestedScopes.includes("profile")
									? user.name.split(" ")[0]!
									: undefined,
								family_name: requestedScopes.includes("profile")
									? user.name.split(" ")[1]!
									: undefined,
								email_verified: requestedScopes.includes("email")
									? user.emailVerified
									: undefined,
							};
							const userClaims = options.getAdditionalUserInfoClaim
								? filterAdditionalUserClaims(
										await options.getAdditionalUserInfoClaim(
											user,
											requestedScopes,
											client,
										),
									)
								: {};
							return { ...baseUserClaims, ...userClaims };
						},
					);
					if (!claims) {
						throw new APIError("UNAUTHORIZED", {
							error_description: "invalid access token",
							error: "invalid_token",
						});
					}
					return ctx.json(claims);
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/oauth2/register`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.registerOAuthApplication`
			 *
			 * **client:**
			 * `authClient.oauth2.register`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			registerOAuthApplication: createAuthEndpoint(
				"/oauth2/register",
				{
					method: "POST",
					body: registerOAuthApplicationBodySchema,
					metadata: {
						openapi: {
							description: "Register an OAuth2 application",
							responses: {
								"200": {
									description: "OAuth2 application registered successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													name: {
														type: "string",
														description: "Name of the OAuth2 application",
													},
													icon: {
														type: "string",
														nullable: true,
														description: "Icon URL for the application",
													},
													metadata: {
														type: "object",
														additionalProperties: true,
														nullable: true,
														description:
															"Additional metadata for the application",
													},
													clientId: {
														type: "string",
														description: "Unique identifier for the client",
													},
													clientSecret: {
														type: "string",
														description: "Secret key for the client",
													},
													redirectURLs: {
														type: "array",
														items: { type: "string", format: "uri" },
														description: "List of allowed redirect URLs",
													},
													type: {
														type: "string",
														description: "Type of the client",
														enum: ["web"],
													},
													authenticationScheme: {
														type: "string",
														description:
															"Authentication scheme used by the client",
														enum: ["client_secret"],
													},
													disabled: {
														type: "boolean",
														description: "Whether the client is disabled",
														enum: [false],
													},
													userId: {
														type: "string",
														nullable: true,
														description:
															"ID of the user who registered the client, null if registered anonymously",
													},
													createdAt: {
														type: "string",
														format: "date-time",
														description: "Creation timestamp",
													},
													updatedAt: {
														type: "string",
														format: "date-time",
														description: "Last update timestamp",
													},
												},
												required: [
													"name",
													"clientId",
													"clientSecret",
													"redirectURLs",
													"type",
													"authenticationScheme",
													"disabled",
													"createdAt",
													"updatedAt",
												],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					const body = ctx.body;
					const session = await getSessionFromCtx(ctx);

					// Check authorization
					if (!session && !options.allowDynamicClientRegistration) {
						throw new APIError("UNAUTHORIZED", {
							error: "invalid_token",
							error_description:
								"Authentication required for client registration",
						});
					}

					// Validate redirect URIs for redirect-based flows
					if (
						(!body.grant_types ||
							body.grant_types.includes("authorization_code") ||
							body.grant_types.includes("implicit")) &&
						(!body.redirect_uris || body.redirect_uris.length === 0)
					) {
						throw new APIError("BAD_REQUEST", {
							error: "invalid_redirect_uri",
							error_description:
								"Redirect URIs are required for authorization_code and implicit grant types",
						});
					}

					// Validate correlation between grant_types and response_types
					if (body.grant_types && body.response_types) {
						if (
							body.grant_types.includes("authorization_code") &&
							!body.response_types.includes("code")
						) {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_client_metadata",
								error_description:
									"When 'authorization_code' grant type is used, 'code' response type must be included",
							});
						}
						if (
							body.grant_types.includes("implicit") &&
							!body.response_types.includes("token")
						) {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_client_metadata",
								error_description:
									"When 'implicit' grant type is used, 'token' response type must be included",
							});
						}
					}

					const clientId =
						options.generateClientId?.() ||
						generateRandomString(32, "a-z", "A-Z");
					const clientSecret =
						options.generateClientSecret?.() ||
						generateRandomString(32, "a-z", "A-Z");

					const storedClientSecret = await storeClientSecret(ctx, clientSecret);

					// Create the client with the existing schema
					const client: Client = await ctx.context.adapter.create({
						model: modelName.oauthClient,
						data: {
							name: body.client_name,
							icon: body.logo_uri,
							metadata: body.metadata ? JSON.stringify(body.metadata) : null,
							clientId: clientId,
							clientSecret: storedClientSecret,
							redirectUrls: body.redirect_uris.join(","),
							type: "web",
							authenticationScheme:
								body.token_endpoint_auth_method || "client_secret_basic",
							disabled: false,
							userId: session?.session.userId,
							createdAt: new Date(),
							updatedAt: new Date(),
						},
					});

					// Format the response according to RFC7591
					return ctx.json(
						{
							client_id: clientId,
							...(client.type !== "public"
								? {
										client_secret: clientSecret,
										client_secret_expires_at: 0, // 0 means it doesn't expire
									}
								: {}),
							client_id_issued_at: Math.floor(Date.now() / 1000),
							client_secret_expires_at: 0, // 0 means it doesn't expire
							redirect_uris: body.redirect_uris,
							token_endpoint_auth_method:
								body.token_endpoint_auth_method || "client_secret_basic",
							grant_types: body.grant_types || ["authorization_code"],
							response_types: body.response_types || ["code"],
							client_name: body.client_name,
							client_uri: body.client_uri,
							logo_uri: body.logo_uri,
							scope: body.scope,
							contacts: body.contacts,
							tos_uri: body.tos_uri,
							policy_uri: body.policy_uri,
							jwks_uri: body.jwks_uri,
							jwks: body.jwks,
							software_id: body.software_id,
							software_version: body.software_version,
							software_statement: body.software_statement,
							metadata: body.metadata,
						},
						{
							status: 201,
							headers: {
								"Cache-Control": "no-store",
								Pragma: "no-cache",
							},
						},
					);
				},
			),
			getOAuthClient: createAuthEndpoint(
				"/oauth2/client/:id",
				{
					method: "GET",
					use: [sessionMiddleware],
					metadata: {
						openapi: {
							description: "Get OAuth2 client details",
							responses: {
								"200": {
									description: "OAuth2 client retrieved successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													clientId: {
														type: "string",
														description: "Unique identifier for the client",
													},
													name: {
														type: "string",
														description: "Name of the OAuth2 application",
													},
													icon: {
														type: "string",
														nullable: true,
														description: "Icon URL for the application",
													},
												},
												required: ["clientId", "name"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (
					ctx,
				): Promise<{
					clientId: string;
					name: string;
					icon: string | null;
				}> => {
					const client = await getClient(ctx.params.id, trustedClients);
					if (!client) {
						throw new APIError("NOT_FOUND", {
							error_description: "client not found",
							error: "not_found",
						});
					}
					return ctx.json({
						clientId: client.clientId,
						name: client.name,
						icon: client.icon || null,
					});
				},
			),
			/**
			 * ### Endpoint
			 *
			 * GET/POST `/oauth2/endsession`
			 *
			 * Implements RP-Initiated Logout as per OpenID Connect RP-Initiated Logout 1.0.
			 * Allows relying parties to request that an OpenID Provider log out the end-user.
			 *
			 * @see [OpenID Connect RP-Initiated Logout Spec](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
			 */
			endSession: createAuthEndpoint(
				"/oauth2/endsession",
				{
					method: ["GET", "POST"],
					query: z
						.object({
							id_token_hint: z.string().optional(),
							logout_hint: z.string().optional(),
							client_id: z.string().optional(),
							post_logout_redirect_uri: z.string().optional(),
							state: z.string().optional(),
							ui_locales: z.string().optional(),
						})
						.optional(),
					metadata: {
						...HIDE_METADATA,
						openapi: {
							description:
								"RP-Initiated Logout endpoint. Logs out the end-user and optionally redirects to a post-logout URI.",
							parameters: [
								{
									name: "id_token_hint",
									in: "query",
									description:
										"Previously issued ID Token passed as a hint about the End-User's current authenticated session",
									required: false,
									schema: { type: "string" },
								},
								{
									name: "logout_hint",
									in: "query",
									description:
										"Hint to the Authorization Server about the End-User that is logging out",
									required: false,
									schema: { type: "string" },
								},
								{
									name: "client_id",
									in: "query",
									description:
										"OAuth 2.0 Client Identifier. Required if post_logout_redirect_uri is used without id_token_hint",
									required: false,
									schema: { type: "string" },
								},
								{
									name: "post_logout_redirect_uri",
									in: "query",
									description:
										"URL to which the RP is requesting that the End-User's User Agent be redirected after a logout has been performed",
									required: false,
									schema: { type: "string", format: "uri" },
								},
								{
									name: "state",
									in: "query",
									description:
										"Opaque value used by the RP to maintain state between the logout request and the callback",
									required: false,
									schema: { type: "string" },
								},
								{
									name: "ui_locales",
									in: "query",
									description:
										"End-User's preferred languages and scripts for the user interface",
									required: false,
									schema: { type: "string" },
								},
							] as OpenAPIParameter[],
							responses: {
								"302": {
									description:
										"Redirect to post_logout_redirect_uri or logout confirmation page",
								},
								"200": {
									description: "Logout completed successfully",
								},
							},
						},
					},
				},
				async (ctx) => {
					const { id_token_hint, client_id, post_logout_redirect_uri, state } =
						ctx.query || {};

					let validatedClientId: string | null = null;
					let validatedUserId: string | null = null;
					let validatedFamilyId: string | null = null;

					// Validate id_token_hint if provided
					if (id_token_hint) {
						try {
							const jwtPlugin = ctx.context.getPlugin("jwt");
							if (jwtPlugin && options?.useJWTPlugin) {
								// An unverified audience can identify the candidate RP only. It
								// becomes authoritative after retained-JWKS signature, issuer,
								// and exact RP-audience verification succeeds below.
								const candidateClientId =
									client_id ?? resolveIDTokenAudience(decodeJwt(id_token_hint));
								const candidateClient = candidateClientId
									? await getClient(candidateClientId, trustedClients)
									: null;
								const verified =
									candidateClient && candidateClientId
										? await verifyJWT(id_token_hint, {
												...jwtPlugin.options,
												jwt: {
													...jwtPlugin.options?.jwt,
													issuer: getOIDCIssuer(ctx, options),
													audience: candidateClientId,
												},
											})
										: null;
								if (
									verified &&
									resolveIDTokenAudience(verified) === candidateClientId
								) {
									validatedUserId = verified.sub;
									validatedFamilyId =
										typeof verified.sid === "string" ? verified.sid : null;
									validatedClientId = candidateClientId;
								}
							} else {
								// For HS256 tokens, we need the client_id to verify
								if (client_id) {
									const client = await getClient(client_id, trustedClients);
									if (client && client.clientSecret) {
										try {
											const { payload } = await jwtVerify(
												id_token_hint,
												new TextEncoder().encode(client.clientSecret),
												{
													issuer: getOIDCIssuer(ctx, options),
													audience: client_id,
												},
											);
											validatedUserId = payload.sub as string;
											validatedClientId = payload.aud as string;
											validatedFamilyId =
												typeof payload.sid === "string" ? payload.sid : null;
										} catch {
											// Invalid token, continue with logout but no validation
										}
									}
								}
							}
						} catch {
							// Invalid id_token_hint, but we continue with logout anyway
							ctx.context.logger.debug(
								"Invalid id_token_hint provided to end_session endpoint",
							);
						}
					}

					// Validate client_id if provided
					if (client_id) {
						const client = await getClient(client_id, trustedClients);
						if (!client) {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_client",
								error_description: "Invalid client_id",
							});
						}
						// If we have a validated client from the token, ensure they match
						if (validatedClientId && validatedClientId !== client_id) {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_request",
								error_description:
									"client_id does not match the ID Token's audience",
							});
						}
						validatedClientId = client_id;
					}

					// Validate post_logout_redirect_uri if provided
					if (post_logout_redirect_uri) {
						if (!validatedClientId) {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_request",
								error_description:
									"client_id is required when using post_logout_redirect_uri without a valid id_token_hint",
							});
						}

						const client = await getClient(validatedClientId, trustedClients);
						if (!client) {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_client",
								error_description: "Invalid client",
							});
						}

						const isValidRedirectUri = client.redirectUrls.some(
							(registeredUri) => post_logout_redirect_uri === registeredUri,
						);

						if (!isValidRedirectUri) {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_request",
								error_description:
									"post_logout_redirect_uri is not registered for this client",
							});
						}
					}

					const session = await getSessionFromCtx(ctx);

					// Logout deletes the user's session and OAuth tokens, so on an HTTP
					// request it must be proven intentional: the request is same-site (or
					// from a trusted origin), or it carries an id_token_hint for the
					// session being ended. Otherwise a cross-site GET could log the user
					// out and revoke their tokens, which the global origin check does not
					// prevent because it skips GET. A request whose site cannot be
					// established, or a valid id_token_hint for a different user, does not
					// authorize ending this session.
					if (ctx.request && (validatedUserId || session)) {
						const fetchSite = ctx.request.headers.get("Sec-Fetch-Site");
						const originHeader =
							ctx.request.headers.get("origin") ||
							ctx.request.headers.get("referer");
						const isSameSiteRequest =
							fetchSite === "same-origin" ||
							fetchSite === "same-site" ||
							fetchSite === "none" ||
							(!!originHeader &&
								ctx.context.isTrustedOrigin(originHeader, {
									allowRelativePaths: false,
								}));
						const hintMatchesSession =
							!!validatedUserId && validatedUserId === session?.user.id;
						if (!isSameSiteRequest && !hintMatchesSession) {
							throw new APIError("FORBIDDEN", {
								error: "invalid_request",
								error_description:
									"Logout must be same-site or carry an id_token_hint for the current session",
							});
						}
					}

					const legacyAuthority =
						readInternalCredentialAuthority(ctx.context.options)?.generation ===
						"legacy-v1";
					const logoutUserId = validatedUserId ?? session?.user.id ?? null;
					if (legacyAuthority && logoutUserId) {
						await runWithTransaction(ctx.context.adapter, async () => {
							const adapter = await getCurrentAdapter(ctx.context.adapter);
							await adapter.deleteMany({
								model: modelName.oauthAccessToken,
								where: [
									{ field: "userId", value: logoutUserId },
									...(validatedClientId
										? [{ field: "clientId", value: validatedClientId }]
										: []),
								],
							});
						});
					} else if (validatedUserId && validatedClientId) {
						// Digest authority only revokes from a fully verified id_token_hint.
						// With sid: exactly (userId, clientId, familyId). Without sid: every
						// family for the validated (userId, clientId) pair — pre-sid tokens.
						const revokedAt = new Date();
						await runWithTransaction(ctx.context.adapter, async () => {
							const adapter = await getCurrentAdapter(ctx.context.adapter);
							await adapter.updateMany({
								model: modelName.oauthAccessToken,
								where: [
									{ field: "userId", value: validatedUserId },
									{ field: "clientId", value: validatedClientId },
									...(validatedFamilyId
										? [{ field: "familyId", value: validatedFamilyId }]
										: []),
								],
								update: {
									refreshStatus: "revoked",
									revokedAt,
									rotationNonceDigest: null,
									recoveryExpiresAt: null,
									updatedAt: revokedAt,
								},
							});
						});
					}

					if (session) {
						await ctx.context.internalAdapter.deleteSession(
							session.session.token,
						);
						expireCookie(ctx, ctx.context.authCookies.sessionToken);
					}

					if (post_logout_redirect_uri) {
						try {
							const redirectUrl = new URL(post_logout_redirect_uri);
							if (state) {
								redirectUrl.searchParams.set("state", state);
							}
							return ctx.redirect(redirectUrl.toString());
						} catch {
							throw new APIError("BAD_REQUEST", {
								error: "invalid_request",
								error_description: "Invalid post_logout_redirect_uri format",
							});
						}
					}

					return ctx.json({
						success: true,
						message: "Logout successful",
					});
				},
			),
		},
		schema: mergeSchema(schema, options?.schema),
		get options() {
			return opts;
		},
	} satisfies ClearancePlugin;
};
export type * from "./types";
