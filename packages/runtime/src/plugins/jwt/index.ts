import type { ClearancePlugin } from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import { runWithTransaction } from "@clearance/core/context";
import { ClearanceError } from "@clearance/core/error";
import type { JSONWebKeySet, JWTPayload } from "jose";
import * as z from "zod";
import { APIError, sessionMiddleware } from "../../api";
import { deleteSessionCookie, setSessionCookie } from "../../cookies";
import { mergeSchema } from "../../db/schema";
import { PACKAGE_VERSION } from "../../version";
import {
	CREDENTIAL_OPERATION_KEY_REQUIREMENT,
	parseCredentialOperationKey,
} from "../../utils/operation-key";
import { getJwksAdapter } from "./adapter";
import {
	DEFAULT_JWKS_GRACE_PERIOD_SECONDS,
	JWT_ROTATION_UNAVAILABLE_CODE,
} from "./constant";
import { schema } from "./schema";
import { getJwtToken, issueServiceAccountJWT, signJWT } from "./sign";
import type { JwtOptions } from "./types";
import { createJwk } from "./utils";
import { verifyJWT as verifyJWTHelper } from "./verify";

export { signJWT } from "./sign";
export type * from "./types";
export { createJwk, generateExportedKeyPair, toExpJWT } from "./utils";
export { verifyJWT } from "./verify";

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		jwt: {
			creator: typeof jwt;
		};
	}
}

const signJWTBodySchema = z.object({
	payload: z.record(z.string(), z.any()),
	overrideOptions: z.record(z.string(), z.any()).optional(),
});

const verifyJWTBodySchema = z.object({
	token: z.string(),
	issuer: z.string().optional(),
});

const issueServiceAccountJWTBodySchema = z.object({
	secret: z.string().min(1).max(16_384),
});

const NO_STORE_TOKEN_RESPONSE_HEADERS = {
	"Cache-Control": "no-store",
	Pragma: "no-cache",
} as const;

function setNoStoreTokenResponseHeaders(ctx: {
	setHeader(name: string, value: string): void;
}): void {
	ctx.setHeader(
		"Cache-Control",
		NO_STORE_TOKEN_RESPONSE_HEADERS["Cache-Control"],
	);
	ctx.setHeader("Pragma", NO_STORE_TOKEN_RESPONSE_HEADERS.Pragma);
}

export const jwt = <O extends JwtOptions>(options?: O) => {
	// Custom signers must make their public keys available either remotely or
	// through the local JWKS endpoint.
	if (
		options?.jwt?.sign &&
		!options.jwks?.remoteUrl &&
		!options.adapter?.getJwks
	) {
		throw new ClearanceError(
			"options.jwt.sign requires options.jwks.remoteUrl or options.adapter.getJwks",
		);
	}

	// Alg is required to be specified when using remote url (needed in openid metadata)
	if (options?.jwks?.remoteUrl && !options.jwks?.keyPairConfig?.alg) {
		throw new ClearanceError(
			"options.jwks.keyPairConfig.alg must be specified when using the oidc plugin with options.jwks.remoteUrl",
		);
	}

	const jwksPath = options?.jwks?.jwksPath ?? "/jwks";
	if (
		typeof jwksPath !== "string" ||
		jwksPath.length === 0 ||
		!jwksPath.startsWith("/") ||
		jwksPath.includes("..")
	) {
		throw new ClearanceError(
			"options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'",
		);
	}

	return {
		id: "jwt",
		version: PACKAGE_VERSION,
		options: options as NoInfer<O>,
		endpoints: {
			issueServiceAccountJWT: createAuthEndpoint.serverOnly(
				{
					method: "POST",
					metadata: {
						$Infer: {
							body: {} as { secret: string },
							response: {} as { token: string },
						},
					},
					body: issueServiceAccountJWTBodySchema,
				},
				async (ctx) =>
					ctx.json({
						token: await issueServiceAccountJWT(ctx, options, {
							secret: ctx.body.secret,
						}),
					}),
			),
			getJwks: createAuthEndpoint(
				jwksPath,
				{
					method: "GET",
					metadata: {
						openapi: {
							operationId: "getJSONWebKeySet",
							description: "Get the JSON Web Key Set",
							responses: {
								"200": {
									description: "JSON Web Key Set retrieved successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													keys: {
														type: "array",
														description: "Array of public JSON Web Keys",
														items: {
															type: "object",
															properties: {
																kid: {
																	type: "string",
																	description:
																		"Key ID uniquely identifying the key, corresponds to the 'id' from the stored Jwk",
																},
																kty: {
																	type: "string",
																	description:
																		"Key type (e.g., 'RSA', 'EC', 'OKP')",
																},
																alg: {
																	type: "string",
																	description:
																		"Algorithm intended for use with the key (e.g., 'EdDSA', 'RS256')",
																},
																use: {
																	type: "string",
																	description:
																		"Intended use of the public key (e.g., 'sig' for signature)",
																	enum: ["sig"],
																	nullable: true,
																},
																n: {
																	type: "string",
																	description:
																		"Modulus for RSA keys (base64url-encoded)",
																	nullable: true,
																},
																e: {
																	type: "string",
																	description:
																		"Exponent for RSA keys (base64url-encoded)",
																	nullable: true,
																},
																crv: {
																	type: "string",
																	description:
																		"Curve name for elliptic curve keys (e.g., 'Ed25519', 'P-256')",
																	nullable: true,
																},
																x: {
																	type: "string",
																	description:
																		"X coordinate for elliptic curve keys (base64url-encoded)",
																	nullable: true,
																},
																y: {
																	type: "string",
																	description:
																		"Y coordinate for elliptic curve keys (base64url-encoded)",
																	nullable: true,
																},
															},
															required: ["kid", "kty", "alg"],
														},
													},
												},
												required: ["keys"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					// Disables endpoint if using remote url strategy
					if (options?.jwks?.remoteUrl) {
						throw new APIError("NOT_FOUND");
					}

					const adapter = getJwksAdapter(ctx.context.adapter, options);

					let keySets = await adapter.getAllKeys(ctx);

					if (!keySets || keySets?.length === 0) {
						if (options?.jwt?.sign && options.adapter?.getJwks) {
							throw new ClearanceError(
								"No public JWKS keys found for options.jwt.sign. Make sure options.adapter.getJwks returns at least one key.",
							);
						}
						await createJwk(ctx, options);
						keySets = await adapter.getAllKeys(ctx);
					}

					if (!keySets?.length) {
						throw new ClearanceError(
							"No key sets found. Make sure you have a key in your database.",
						);
					}

					const now = Date.now();
					const gracePeriod =
						(options?.jwks?.gracePeriod ?? DEFAULT_JWKS_GRACE_PERIOD_SECONDS) *
						1000;

					const keys = keySets.filter((key) => {
						if (!key.expiresAt) {
							return true;
						}
						return key.expiresAt.getTime() + gracePeriod > now;
					});

					const keyPairConfig = options?.jwks?.keyPairConfig;
					const defaultCrv = keyPairConfig
						? "crv" in keyPairConfig
							? (keyPairConfig as { crv: string }).crv
							: undefined
						: undefined;
					return ctx.json({
						keys: keys.map((keySet) => {
							return {
								alg: keySet.alg ?? options?.jwks?.keyPairConfig?.alg ?? "EdDSA",
								crv: keySet.crv ?? defaultCrv,
								...JSON.parse(keySet.publicKey),
								kid: keySet.id,
							};
						}),
					} satisfies JSONWebKeySet as JSONWebKeySet);
				},
			),

			getToken: createAuthEndpoint(
				"/token",
				{
					method: "POST",
					requireHeaders: true,
					metadata: {
						openapi: {
							operationId: "getJSONWebToken",
							description: "Get a JWT token",
							parameters: [
								{
									name: "Idempotency-Key",
									in: "header",
									description:
										"Versioned 256-bit opaque operation token using clr_op_v1_ followed by 43 canonical base64url characters; reuse it only for the same refresh operation",
									required: true,
									schema: {
										type: "string",
										minLength: 53,
										maxLength: 53,
										pattern: "^clr_op_v1_[A-Za-z0-9_-]{43}$",
									},
								},
							],
							responses: {
								200: {
									description: "Success",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													token: {
														type: "string",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					const refreshSecret = await ctx.getSignedCookie(
						ctx.context.authCookies.sessionToken.name,
						ctx.context.secret,
					);
					if (!refreshSecret) throw new APIError("UNAUTHORIZED");
					if (
						ctx.context.options.secondaryStorage &&
						ctx.context.options.session?.storeSessionInDatabase !== true
					) {
						setNoStoreTokenResponseHeaders(ctx);
						throw new APIError(
							"SERVICE_UNAVAILABLE",
							{
								code: JWT_ROTATION_UNAVAILABLE_CODE,
								message:
									"Atomic JWT refresh rotation is unavailable for secondary-storage-only sessions; use deprecated GET /token compatibility issuance",
							},
							{ "Clearance-JWT-Token-Mode": "legacy-get" },
						);
					}
					const idempotencyKey = parseCredentialOperationKey(
						ctx.headers?.get("idempotency-key"),
					);
					if (!idempotencyKey) {
						throw new APIError("BAD_REQUEST", {
							message: CREDENTIAL_OPERATION_KEY_REQUIREMENT,
						});
					}
					const issued = await runWithTransaction(
						ctx.context.adapter,
						async () => {
							const rotated =
								await ctx.context.internalAdapter.rotateSessionCredential(
									refreshSecret,
									idempotencyKey,
								);
							if (!rotated) return null;
							ctx.context.session = {
								session: rotated.session,
								user: rotated.user,
							};
							const token = await getJwtToken(ctx, options, {
								sid: rotated.session.id,
								session_family: rotated.familyId,
								session_generation: rotated.rotationCounter,
							});
							return { rotated, token };
						},
					);
					if (!issued) {
						deleteSessionCookie(ctx);
						throw new APIError("UNAUTHORIZED");
					}
					ctx.context.session = {
						session: issued.rotated.session,
						user: issued.rotated.user,
					};
					await setSessionCookie(ctx, {
						session: issued.rotated.session,
						user: issued.rotated.user,
					});
					setNoStoreTokenResponseHeaders(ctx);
					return ctx.json({ token: issued.token });
				},
			),
			legacyGetToken: createAuthEndpoint(
				"/token",
				{
					method: "GET",
					requireHeaders: true,
					use: [sessionMiddleware],
					metadata: {
						openapi: {
							operationId: "getJSONWebTokenLegacy",
							description:
								"Deprecated compatibility endpoint; use POST /token with Idempotency-Key",
							responses: {
								200: { description: "Success" },
							},
						},
					},
				},
				async (ctx) => {
					ctx.setHeader("Deprecation", "true");
					ctx.setHeader("Link", '</token>; rel="successor-version"');
					setNoStoreTokenResponseHeaders(ctx);
					return ctx.json({ token: await getJwtToken(ctx, options) });
				},
			),
			signJWT: createAuthEndpoint.serverOnly(
				{
					method: "POST",
					metadata: {
						$Infer: {
							body: {} as {
								payload: JWTPayload;
								overrideOptions?: JwtOptions | undefined;
							},
						},
					},
					body: signJWTBodySchema,
				},
				async (c) => {
					const jwt = await signJWT(c, {
						options: {
							...options,
							...c.body.overrideOptions,
						},
						payload: c.body.payload,
					});
					return c.json({ token: jwt });
				},
			),
			verifyJWT: createAuthEndpoint.serverOnly(
				{
					method: "POST",
					metadata: {
						$Infer: {
							body: {} as {
								token: string;
								issuer?: string;
							},
							response: {} as {
								payload: {
									sub: string;
									aud: string;
									[key: string]: any;
								} | null;
							},
						},
					},
					body: verifyJWTBodySchema,
				},
				async (ctx) => {
					const overrideOptions = ctx.body.issuer
						? {
								...options,
								jwt: {
									...options?.jwt,
									issuer: ctx.body.issuer,
								},
							}
						: options;

					const payload = await verifyJWTHelper(
						ctx.body.token,
						overrideOptions,
					);

					return ctx.json({ payload });
				},
			),
		},
		hooks: {
			after: [
				{
					matcher(context) {
						return context.path === "/get-session";
					},
					handler: createAuthMiddleware(async (ctx) => {
						if (options?.disableSettingJwtHeader) {
							return;
						}

						const session = ctx.context.session || ctx.context.newSession;
						if (session && session.session) {
							const jwt = await getJwtToken(ctx, options);
							const exposedHeaders =
								ctx.context.responseHeaders?.get(
									"access-control-expose-headers",
								) || "";
							const headersSet = new Set(
								exposedHeaders
									.split(",")
									.map((header) => header.trim())
									.filter(Boolean),
							);
							headersSet.add("set-auth-jwt");
							ctx.setHeader("set-auth-jwt", jwt);
							ctx.setHeader(
								"Access-Control-Expose-Headers",
								Array.from(headersSet).join(", "),
							);
						}
					}),
				},
			],
		},
		schema: mergeSchema(schema, options?.schema),
	} satisfies ClearancePlugin;
};

export { getJwtToken };
