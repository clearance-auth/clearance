import type {
	ClearanceOptions,
	ClearancePlugin,
	GenericEndpointContext,
} from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { isProduction, logger } from "@clearance/core/env";
import { safeJSONParse } from "@clearance/core/utils/json";
import { isSafeUrlScheme } from "@clearance/core/utils/url";
import { base64 } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";
import * as z from "zod";
import { APIError, getSessionFromCtx } from "../../api";
import { resolveDynamicTrustedProxyHeaders } from "../../context/helpers";
import { expireCookie, parseSetCookieHeader } from "../../cookies";
import { constantTimeEqual, generateRandomString } from "../../crypto";
import { HIDE_METADATA } from "../../utils";
import { isAPIError } from "../../utils/is-api-error";
import {
	CREDENTIAL_OPERATION_KEY_REQUIREMENT,
	parseCredentialOperationKey,
} from "../../utils/operation-key";
import {
	getBaseURL,
	isDynamicBaseURLConfig,
	resolveBaseURL,
} from "../../utils/url";
import { PACKAGE_VERSION } from "../../version";
import { type Jwk, jwt, signJWT } from "../jwt";
import type {
	Client,
	CodeVerificationValue,
	OAuthAccessToken,
	OIDCMetadata,
	OIDCOptions,
} from "../oidc-provider";
import {
	createOAuthTokenPair,
	filterAdditionalUserClaims,
	findOAuthTokenBySecret,
	getClient,
	oidcProvider,
	parseCodeVerificationValue,
	revokeOAuthTokenFamily,
	rotateOAuthRefreshToken,
	validateOAuthSessionDerivativeAuthority,
	withOAuthAccessTokenAuthority,
} from "../oidc-provider";
import { schema } from "../oidc-provider/schema";
import {
	oauthExpiresIn,
	setNoStoreTokenResponseHeaders,
} from "../oidc-provider/token-response";
import { lockAndReadActiveUser } from "../../db/user-authority";
import { consumeInternalVerificationChallenge } from "../../internal/verification-challenge-context";
import {
	ManagedSessionDerivativeAuthorityError,
	type InternalSessionDerivativeAuthority,
} from "../../internal/session-derivative-authority";
import {
	runManagedAuthenticationTransaction,
	usesManagedAuthenticationPolicy,
} from "../../internal/managed-authentication-transaction";
import {
	attachInternalCredentialAuthority,
	readInternalCredentialAuthority,
} from "../../internal/credential-authority";
import { parsePrompt } from "../oidc-provider/utils/prompt";
import { authorizeMCPOAuth } from "./authorize";

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		mcp: {
			creator: typeof mcp;
		};
	}
}

interface MCPOptions {
	loginPage: string;
	resource?: string | undefined;
	oidcConfig?: OIDCOptions | undefined;
}

export type MCPSession = Pick<
	OAuthAccessToken,
	"id" | "clientId" | "userId" | "scopes" | "accessTokenExpiresAt"
>;

export const getMCPProviderMetadata = (
	ctx: GenericEndpointContext,
	options?: OIDCOptions | undefined,
): OIDCMetadata => {
	const issuer =
		typeof ctx.context.options.baseURL === "string"
			? ctx.context.options.baseURL
			: "";
	const baseURL = ctx.context.baseURL;
	if (!issuer || !baseURL) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			error: "invalid_issuer",
			error_description:
				"issuer or baseURL is not set. If you're the app developer, please make sure to set the `baseURL` in your auth config.",
		});
	}
	return {
		issuer,
		authorization_endpoint: `${baseURL}/mcp/authorize`,
		token_endpoint: `${baseURL}/mcp/token`,
		userinfo_endpoint: `${baseURL}/mcp/userinfo`,
		jwks_uri: `${baseURL}/mcp/jwks`,
		registration_endpoint: `${baseURL}/mcp/register`,
		scopes_supported: ["openid", "profile", "email", "offline_access"],
		response_types_supported: ["code"],
		response_modes_supported: ["query"],
		grant_types_supported: ["authorization_code", "refresh_token"],
		acr_values_supported: [
			"urn:mace:incommon:iap:silver",
			"urn:mace:incommon:iap:bronze",
		],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
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

export const getMCPProtectedResourceMetadata = (
	ctx: GenericEndpointContext,
	options?: MCPOptions | undefined,
) => {
	const baseURL = ctx.context.baseURL;
	const origin = new URL(baseURL).origin;

	return {
		resource: options?.resource ?? origin,
		authorization_servers: [origin],
		jwks_uri: options?.oidcConfig?.metadata?.jwks_uri ?? `${baseURL}/mcp/jwks`,
		scopes_supported: options?.oidcConfig?.metadata?.scopes_supported ?? [
			"openid",
			"profile",
			"email",
			"offline_access",
		],
		bearer_methods_supported: ["header"],
		resource_signing_alg_values_supported: ["RS256"],
	};
};

const registerMcpClientBodySchema = z.object({
	// This plugin is migrating to @clearance/oauth-provider (see the deprecation
	// notice in docs/plugins/mcp). It gets only the non-breaking guard that rejects
	// code-execution schemes here; full https-or-loopback parity comes from
	// @clearance/oauth-provider's SafeUrlSchema, not from tightening this plugin.
	redirect_uris: z.array(
		z.string().refine(isSafeUrlScheme, {
			message:
				"redirect_uri cannot use a javascript:, data:, or vbscript: scheme",
		}),
	),
	token_endpoint_auth_method: z
		.enum(["none", "client_secret_basic", "client_secret_post"])
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
		.default(["authorization_code"])
		.optional(),
	response_types: z
		.array(z.enum(["code", "token"]))
		.default(["code"])
		.optional(),
	client_name: z.string().optional(),
	client_uri: z.string().optional(),
	logo_uri: z.string().optional(),
	scope: z.string().optional(),
	contacts: z.array(z.string()).optional(),
	tos_uri: z.string().optional(),
	policy_uri: z.string().optional(),
	jwks_uri: z.string().optional(),
	jwks: z.record(z.string(), z.any()).optional(),
	metadata: z.record(z.any(), z.any()).optional(),
	software_id: z.string().optional(),
	software_version: z.string().optional(),
	software_statement: z.string().optional(),
});

const mcpOAuthTokenBodySchema = z.record(z.any(), z.any());

export const mcp = (options: MCPOptions) => {
	const opts = {
		codeExpiresIn: 600,
		defaultScope: "openid",
		accessTokenExpiresIn: 300,
		refreshTokenExpiresIn: 604800,
		allowPlainCodeChallengeMethod: false,
		...options.oidcConfig,
		loginPage: options.loginPage,
		scopes: [
			"openid",
			"profile",
			"email",
			"offline_access",
			...(options.oidcConfig?.scopes || []),
		],
	};
	const modelName = {
		oauthClient: "oauthApplication",
		oauthAccessToken: "oauthAccessToken",
		oauthConsent: "oauthConsent",
	};
	const signerOptions = {
		disableSettingJwtHeader: true,
		jwks: {
			jwksPath: "/mcp/jwks",
			keyPairConfig: { alg: "RS256" as const, modulusLength: 2048 },
		},
		adapter: {
			getJwks: async (ctx: GenericEndpointContext) => {
				const keys = await ctx.context.adapter.findMany<Jwk>({ model: "jwks" });
				return keys.filter((key) => key.alg === "RS256");
			},
			createJwk: async (
				data: Omit<Jwk, "id">,
				ctx: GenericEndpointContext,
			) =>
				ctx.context.adapter.create<Omit<Jwk, "id">, Jwk>({
					model: "jwks",
					data,
				}),
		},
	};
	const signer = jwt(signerOptions);
	const provider = oidcProvider({
		...opts,
		__skipDeprecationWarning: true,
		__sessionDerivativePurpose: "mcp",
	});
	return {
		id: "mcp",
		version: PACKAGE_VERSION,
		init(ctx) {
			provider.init?.(ctx);
		},
		async onRequest(request, ctx) {
			return await provider.onRequest?.(request, ctx);
		},
		hooks: {
			after: [
				{
					matcher() {
						return true;
					},
					handler: createAuthMiddleware(async (ctx) => {
						const cookie = await ctx.getSignedCookie(
							"oidc_login_prompt",
							ctx.context.secret,
						);
						const cookieName = ctx.context.authCookies.sessionToken.name;
						const parsedSetCookieHeader = parseSetCookieHeader(
							ctx.context.responseHeaders?.get("set-cookie") || "",
						);
						const hasSessionToken = parsedSetCookieHeader.has(cookieName);
						if (!cookie || !hasSessionToken) {
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
						const parsedCookie = safeJSONParse<Record<string, string>>(cookie);
						if (!parsedCookie) {
							return;
						}
						ctx.query = parsedCookie;

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
						const response = await authorizeMCPOAuth(ctx, opts);
						return response;
					}),
				},
			],
		},
		endpoints: {
			getMcpJwks: signer.endpoints.getJwks,
			mcpUserInfo: createAuthEndpoint(
				"/mcp/userinfo",
				{ method: "GET", metadata: HIDE_METADATA },
				async (ctx) => {
					const authorization = ctx.request?.headers.get("authorization");
					if (!authorization?.startsWith("Bearer ")) {
						throw new APIError("UNAUTHORIZED", {
							error: "invalid_request",
							error_description: "authorization bearer token not found",
						});
					}
					const claims = await withOAuthAccessTokenAuthority(
						ctx,
						modelName.oauthAccessToken,
						authorization.slice("Bearer ".length),
						"mcp",
						async (adapter, accessToken) => {
							const client = await getClient(
								accessToken.clientId,
								opts.trustedClients,
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
							const scopes = accessToken.scopes.split(" ");
							const canonicalClaims = {
								sub: user.id,
								name: scopes.includes("profile") ? user.name : undefined,
								picture: scopes.includes("profile") ? user.image : undefined,
								given_name: scopes.includes("profile")
									? user.name.split(" ")[0]
									: undefined,
								family_name: scopes.includes("profile")
									? user.name.split(" ")[1]
									: undefined,
								email: scopes.includes("email") ? user.email : undefined,
								email_verified: scopes.includes("email")
									? user.emailVerified
									: undefined,
							};
							const extensionClaims = opts.getAdditionalUserInfoClaim
								? filterAdditionalUserClaims(
										await opts.getAdditionalUserInfoClaim(user, scopes, client),
									)
								: {};
							return { ...canonicalClaims, ...extensionClaims };
						},
					);
					if (!claims) {
						throw new APIError("UNAUTHORIZED", {
							error: "invalid_token",
							error_description: "invalid access token",
						});
					}
					setNoStoreTokenResponseHeaders(ctx);
					return ctx.json(claims);
				},
			),
			oAuthConsent: provider.endpoints.oAuthConsent,
			getMcpOAuthConfig: createAuthEndpoint(
				"/.well-known/oauth-authorization-server",
				{
					method: "GET",
					metadata: HIDE_METADATA,
				},
				async (c) => {
					try {
						const metadata = getMCPProviderMetadata(c, options);
						return c.json(metadata);
					} catch (e) {
						console.log(e);
						return c.json(null);
					}
				},
			),
			getMCPProtectedResource: createAuthEndpoint(
				"/.well-known/oauth-protected-resource",
				{
					method: "GET",
					metadata: HIDE_METADATA,
				},
				async (c) => {
					const metadata = getMCPProtectedResourceMetadata(c, options);
					return c.json(metadata);
				},
			),
			mcpOAuthAuthorize: createAuthEndpoint(
				"/mcp/authorize",
				{
					method: "GET",
					query: z.record(z.string(), z.any()),
					metadata: {
						openapi: {
							description: "Authorize an OAuth2 request using MCP",
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
					return authorizeMCPOAuth(ctx, opts);
				},
			),
			mcpOAuthToken: createAuthEndpoint(
				"/mcp/token",
				{
					method: "POST",
					body: mcpOAuthTokenBodySchema,
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
						throw ctx.error("BAD_REQUEST", {
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
						const refreshClient = await ctx.context.adapter
							.findOne<Record<string, any>>({
								model: modelName.oauthClient,
								where: [{ field: "clientId", value: client_id.toString() }],
							})
							.then((res) => {
								if (!res) {
									return null;
								}
								return {
									...res,
									redirectUrls: res.redirectUrls.split(","),
									metadata: res.metadata ? JSON.parse(res.metadata) : {},
								} as Client;
							});
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
							const isValidSecret = constantTimeEqual(
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
						const token = await findOAuthTokenBySecret(
							ctx.context.adapter,
							modelName.oauthAccessToken,
							"refresh",
							refresh_token.toString(),
						);
						if (!token) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid refresh token",
								error: "invalid_grant",
							});
						}
						if (token.clientId !== client_id.toString()) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid client_id",
								error: "invalid_client",
							});
						}
						if (
							!token.refreshTokenExpiresAt ||
							token.refreshTokenExpiresAt < new Date()
						) {
							throw new APIError("UNAUTHORIZED", {
								error_description: "refresh token expired",
								error: "invalid_grant",
							});
						}
						if (!token.scopes?.split(" ").includes("offline_access")) {
							throw new APIError("UNAUTHORIZED", {
								error_description:
									"refresh token was not issued for the offline_access scope",
								error: "invalid_grant",
							});
						}
						const accessTokenExpiresAt = new Date(
							Date.now() + opts.accessTokenExpiresIn * 1000,
						);
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
									purpose: "mcp",
									managed: usesManagedAuthenticationPolicy(ctx),
								},
							},
						);
						if (rotation.kind !== "rotated") {
							throw new APIError("UNAUTHORIZED", {
								error_description: "invalid refresh token",
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

					if (opts.requirePKCE && !code_verifier) {
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

					const client = await ctx.context.adapter
						.findOne<Record<string, any>>({
							model: modelName.oauthClient,
							where: [{ field: "clientId", value: client_id.toString() }],
						})
						.then((res) => {
							if (!res) {
								return null;
							}
							return {
								...res,
								redirectUrls: res.redirectUrls.split(","),
								metadata: res.metadata ? JSON.parse(res.metadata) : {},
							} as Client;
						});
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
					// For public clients (type: 'public'), validate PKCE instead of client_secret
					if (client.type === "public") {
						// Public clients must use PKCE
						if (!code_verifier) {
							throw new APIError("BAD_REQUEST", {
								error_description:
									"code verifier is required for public clients",
								error: "invalid_request",
							});
						}
						// PKCE validation happens later in the flow, so we skip client_secret validation
					} else {
						// For confidential clients, validate client_secret
						if (!client.clientSecret || !client_secret) {
							throw new APIError("UNAUTHORIZED", {
								error_description:
									"client_secret is required for confidential clients",
								error: "invalid_client",
							});
						}
						const isValidSecret = constantTimeEqual(
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
									purpose: "mcp-authorization-code",
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
									"mcp",
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
							const accessTokenExpiresAt = new Date(
								Math.min(
									(issuedAt + opts.accessTokenExpiresIn) * 1000,
									sourceAuthority?.sourceExpiresAt ?? Number.POSITIVE_INFINITY,
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
									(issuedAt + opts.refreshTokenExpiresIn) * 1000,
									sourceAuthority?.sourceExpiresAt ?? Number.POSITIVE_INFINITY,
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
								opts.getAdditionalUserInfoClaim
									? await opts.getAdditionalUserInfoClaim(
											activeUser,
											requestedScopes,
											client,
										)
									: {},
							);
							const issuer = getMCPProviderMetadata(ctx, opts).issuer;
							const idToken = await signJWT(ctx, {
								options: {
									...signerOptions,
									jwt: {
										issuer,
										audience: client_id.toString(),
										expirationTime: Math.floor(
											accessTokenExpiresAt.getTime() / 1000,
										),
									},
								},
								maxExpiresAt: accessTokenExpiresAt,
								payload: {
									...userClaims,
									...extensionClaims,
									sub: activeUser.id,
									aud: client_id.toString(),
									iss: issuer,
									iat: issuedAt,
									auth_time: Math.floor(value.authTime / 1000),
									nonce: value.nonce,
									acr: "urn:mace:incommon:iap:silver",
								},
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
			registerMcpClient: createAuthEndpoint(
				"/mcp/register",
				{
					method: "POST",
					body: registerMcpClientBodySchema,
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
														description:
															"Secret key for the client. Not included for public clients.",
													},
													redirectUrls: {
														type: "array",
														items: { type: "string", format: "uri" },
														description: "List of allowed redirect URLs",
													},
													type: {
														type: "string",
														description: "Type of the client",
														enum: ["web", "public"],
													},
													authenticationScheme: {
														type: "string",
														description:
															"Authentication scheme used by the client",
														enum: ["client_secret", "none"],
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
													"redirectUrls",
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
					ctx.setHeader("Access-Control-Allow-Origin", "*");
					ctx.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
					ctx.setHeader(
						"Access-Control-Allow-Headers",
						"Content-Type, Authorization",
					);
					ctx.setHeader("Access-Control-Max-Age", "86400");
					ctx.headers?.set("Access-Control-Max-Age", "86400");
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
						opts.generateClientId?.() || generateRandomString(32, "a-z", "A-Z");
					const clientSecret =
						opts.generateClientSecret?.() ||
						generateRandomString(32, "a-z", "A-Z");

					// Determine client type based on auth method
					const clientType =
						body.token_endpoint_auth_method === "none" ? "public" : "web";
					const finalClientSecret = clientType === "public" ? "" : clientSecret;

					await ctx.context.adapter.create({
						model: modelName.oauthClient,
						data: {
							name: body.client_name,
							icon: body.logo_uri,
							metadata: body.metadata ? JSON.stringify(body.metadata) : null,
							clientId: clientId,
							clientSecret: finalClientSecret,
							redirectUrls: body.redirect_uris.join(","),
							type: clientType,
							authenticationScheme:
								body.token_endpoint_auth_method || "client_secret_basic",
							disabled: false,
							userId: session?.session.userId,
							createdAt: new Date(),
							updatedAt: new Date(),
						},
					});

					const responseData = {
						client_id: clientId,
						client_id_issued_at: Math.floor(Date.now() / 1000),
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
						...(clientType !== "public"
							? {
									client_secret: finalClientSecret,
									client_secret_expires_at: 0, // 0 means it doesn't expire
								}
							: {}),
					};

					return new Response(JSON.stringify(responseData), {
						status: 201,
						headers: {
							"Content-Type": "application/json",
							"Cache-Control": "no-store",
							Pragma: "no-cache",
						},
					});
				},
			),
			getMcpSession: createAuthEndpoint(
				"/mcp/get-session",
				{
					method: "GET",
					requireHeaders: true,
				},
				async (c) => {
					setNoStoreTokenResponseHeaders(c);
					const invalidToken = () => {
						throw new APIError(
							"UNAUTHORIZED",
							{ message: "invalid_token", code: "invalid_token" },
							{ "WWW-Authenticate": 'Bearer error="invalid_token"' },
						);
					};
					const accessToken = c.headers
						?.get("Authorization")
						?.replace("Bearer ", "");
					if (!accessToken) {
						return invalidToken();
					}
					const session = await withOAuthAccessTokenAuthority(
						c,
						modelName.oauthAccessToken,
						accessToken,
						"mcp",
						async (adapter, accessTokenData) => {
							const tokenClient = await getClient(
								accessTokenData.clientId,
								opts.trustedClients,
							);
							const tokenUser = await c.context.internalAdapter.findUserById(
								accessTokenData.userId,
							);
							if (
								!tokenClient ||
								tokenClient.disabled === true ||
								!tokenUser ||
								(tokenUser as Record<string, unknown>).banned === true
							) {
								await revokeOAuthTokenFamily(
									adapter,
									modelName.oauthAccessToken,
									accessTokenData,
								);
								return null;
							}
							return {
								id: accessTokenData.id,
								clientId: accessTokenData.clientId,
								userId: accessTokenData.userId,
								scopes: accessTokenData.scopes,
								accessTokenExpiresAt: accessTokenData.accessTokenExpiresAt,
							} satisfies MCPSession;
						},
					);
					if (!session) return invalidToken();
					return c.json(session);
				},
			),
		},
		schema: { ...schema, ...signer.schema },
		options,
	} satisfies ClearancePlugin;
};

export const withMcpAuth = <
	Auth extends {
		api: {
			getMcpSession: (...args: any) => Promise<MCPSession | null>;
		};
		options: ClearanceOptions;
	},
>(
	auth: Auth,
	handler: (
		req: Request,
		session: MCPSession,
	) => Response | Promise<Response>,
) => {
	return async (req: Request) => {
		const basePath = auth.options.basePath || "/api/auth";
		const trustedProxyHeaders = resolveDynamicTrustedProxyHeaders(auth.options);
		const baseURL = isDynamicBaseURLConfig(auth.options.baseURL)
			? resolveBaseURL(
					auth.options.baseURL,
					basePath,
					req,
					undefined,
					trustedProxyHeaders,
				)
			: getBaseURL(
					typeof auth.options.baseURL === "string"
						? auth.options.baseURL
						: undefined,
					basePath,
				);
		if (!baseURL && !isProduction) {
			logger.warn("Unable to get the baseURL, please check your config!");
		}
		let session: MCPSession | null;
		try {
			session = await auth.api.getMcpSession({
				request: req,
				headers: req.headers,
				asResponse: false,
			});
		} catch (error) {
			if (!isAPIError(error) || error.statusCode !== 401) throw error;
			session = null;
		}
		// Omit the `resource_metadata` URL when we can't build a valid one,
		// so clients don't follow `Bearer resource_metadata="undefined/..."`.
		const wwwAuthenticateValue = baseURL
			? `Bearer resource_metadata="${baseURL}/.well-known/oauth-protected-resource"`
			: "Bearer";
		if (!session) {
			return Response.json(
				{
					jsonrpc: "2.0",
					error: {
						code: -32000,
						message: "Unauthorized: Authentication required",
						"www-authenticate": wwwAuthenticateValue,
					},
					id: null,
				},
				{
					status: 401,
					headers: {
						"WWW-Authenticate": wwwAuthenticateValue,
						// we also add this headers otherwise browser based clients will not be able to read the `www-authenticate` header
						"Access-Control-Expose-Headers": "WWW-Authenticate",
					},
				},
			);
		}
		return handler(req, session);
	};
};

export const oAuthDiscoveryMetadata = <
	Auth extends {
		api: {
			getMcpOAuthConfig: (...args: any) => any;
		};
	},
>(
	auth: Auth,
) => {
	return async (request: Request) => {
		const res = await auth.api.getMcpOAuthConfig({
			request,
			asResponse: false,
		});
		return new Response(JSON.stringify(res), {
			status: 200,
			headers: {
				"Content-Type": "application/json",
				"Access-Control-Allow-Origin": "*",
				"Access-Control-Allow-Methods": "POST, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type, Authorization",
				"Access-Control-Max-Age": "86400",
			},
		});
	};
};

export const oAuthProtectedResourceMetadata = <
	Auth extends {
		api: {
			getMCPProtectedResource: (...args: any) => any;
		};
	},
>(
	auth: Auth,
) => {
	return async (request: Request) => {
		const res = await auth.api.getMCPProtectedResource({
			request,
			asResponse: false,
		});
		return new Response(JSON.stringify(res), {
			status: 200,
			headers: {
				"Content-Type": "application/json",
				"Access-Control-Allow-Origin": "*",
				"Access-Control-Allow-Methods": "POST, OPTIONS",
				"Access-Control-Allow-Headers": "Content-Type, Authorization",
				"Access-Control-Max-Age": "86400",
			},
		});
	};
};
