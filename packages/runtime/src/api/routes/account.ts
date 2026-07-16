import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import type { Account } from "@clearance/core/db";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import type { OAuth2Tokens } from "@clearance/core/oauth2";
import { SocialProviderListEnum } from "@clearance/core/social-providers";

import * as z from "zod";
import { getAwaitableValue } from "../../context/helpers";
import { shouldBindAccountCookieToSessionUser } from "../../context/store-capabilities";
import { setSessionCookie } from "../../cookies";
import {
	getAccountCookie,
	setAccountCookie,
} from "../../cookies/session-store";
import { generateRandomString } from "../../crypto/random";
import {
	PASSKEY_SESSION_GENERATION_FIELD,
	rotatePasskeySessionGeneration,
} from "../../db/passkey-session-generation";
import { parseAccountOutput } from "../../db/schema";
import {
	rotateTwoFactorSessionGeneration,
	TWO_FACTOR_SESSION_GENERATION_FIELD,
} from "../../db/two-factor-session-generation";
import { lockAndReadUser } from "../../db/user-authority";
import { missingEmailLogMessage } from "../../oauth2/errors";
import { applyUpdateUserInfoOnLink } from "../../oauth2/link-account";
import { generateState } from "../../oauth2/state";
import { decryptOAuthToken, setTokenUtil } from "../../oauth2/utils";
import type { Session, User } from "../../types";
import {
	getAuthoritativeSessionFromCtx,
	getSessionFromCtx,
	isStateful,
	sessionMiddleware,
} from "./session";

const freshAuthoritativeSessionMiddleware = createAuthMiddleware(async (ctx) => {
	const session = await getAuthoritativeSessionFromCtx(ctx);
	if (!session?.session) {
		throw APIError.from("UNAUTHORIZED", {
			message: "Unauthorized",
			code: "UNAUTHORIZED",
		});
	}
	if (ctx.context.sessionConfig.freshAge !== 0) {
		const createdAt = new Date(session.session.createdAt).getTime();
		const freshAge = ctx.context.sessionConfig.freshAge * 1000;
		if (Date.now() - createdAt >= freshAge) {
			throw APIError.from("FORBIDDEN", BASE_ERROR_CODES.SESSION_NOT_FRESH);
		}
	}
	return { session };
});

function assertCredentialFactorLifecycleConfiguration(
	ctx: GenericEndpointContext,
): void {
	if (
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function" ||
		(ctx.context.options.secondaryStorage !== undefined &&
			ctx.context.options.session?.storeSessionInDatabase !== true)
	) {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			BASE_ERROR_CODES.FACTOR_LIFECYCLE_CONFIGURATION_ERROR,
		);
	}
}

function lastFactorProtected(): never {
	throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.LAST_FACTOR_PROTECTED);
}

function factorLifecycleConflict(): never {
	throw APIError.from("CONFLICT", BASE_ERROR_CODES.FACTOR_LIFECYCLE_CONFLICT);
}

function logFactorLifecycleFailure(
	ctx: GenericEndpointContext,
	label: string,
	error: unknown,
): void {
	ctx.context.logger.debug(
		`[account] ${label}`,
		error instanceof Error ? error.name : "unknown error",
	);
}

export const listUserAccounts = createAuthEndpoint(
	"/list-accounts",
	{
		method: "GET",
		use: [sessionMiddleware],
		metadata: {
			openapi: {
				operationId: "listUserAccounts",
				description: "List all accounts linked to the user",
				responses: {
					"200": {
						description: "Success",
						content: {
							"application/json": {
								schema: {
									type: "array",
									items: {
										type: "object",
										properties: {
											id: {
												type: "string",
											},
											providerId: {
												type: "string",
											},
											createdAt: {
												type: "string",
												format: "date-time",
											},
											updatedAt: {
												type: "string",
												format: "date-time",
											},
											accountId: {
												type: "string",
											},
											userId: {
												type: "string",
											},
											scopes: {
												type: "array",
												items: {
													type: "string",
												},
											},
										},
										required: [
											"id",
											"providerId",
											"createdAt",
											"updatedAt",
											"accountId",
											"userId",
											"scopes",
										],
									},
								},
							},
						},
					},
				},
			},
		},
	},
	async (c) => {
		const session = c.context.session;
		const accounts = await c.context.internalAdapter.findAccounts(
			session.user.id,
		);
		return c.json(
			accounts.map((a) => {
				const { scope, ...parsed } = parseAccountOutput(c.context.options, a);
				return {
					...parsed,
					scopes: scope?.split(",") || [],
				};
			}),
		);
	},
);

export const linkSocialAccount = createAuthEndpoint(
	"/link-social",
	{
		method: "POST",
		requireHeaders: true,
		body: z.object({
			/**
			 * Callback URL to redirect to after the user has signed in.
			 */
			callbackURL: z
				.string()
				.meta({
					description: "The URL to redirect to after the user has signed in",
				})
				.optional(),
			/**
			 * OAuth2 provider to use
			 */
			provider: SocialProviderListEnum,
			/**
			 * ID Token for direct authentication without redirect
			 */
			idToken: z
				.object({
					token: z.string(),
					nonce: z.string().optional(),
					accessToken: z.string().optional(),
					refreshToken: z.string().optional(),
					scopes: z.array(z.string()).optional(),
				})
				.optional(),
			/**
			 * Whether to allow sign up for new users
			 */
			requestSignUp: z.boolean().optional(),
			/**
			 * Additional scopes to request when linking the account.
			 * This is useful for requesting additional permissions when
			 * linking a social account compared to the initial authentication.
			 */
			scopes: z
				.array(z.string())
				.meta({
					description: "Additional scopes to request from the provider",
				})
				.optional(),
			/**
			 * The URL to redirect to if there is an error during the link process.
			 */
			errorCallbackURL: z
				.string()
				.meta({
					description:
						"The URL to redirect to if there is an error during the link process",
				})
				.optional(),
			/**
			 * Disable automatic redirection to the provider
			 *
			 * This is useful if you want to handle the redirection
			 * yourself like in a popup or a different tab.
			 */
			disableRedirect: z
				.boolean()
				.meta({
					description:
						"Disable automatic redirection to the provider. Useful for handling the redirection yourself",
				})
				.optional(),
			/**
			 * Any additional data to pass through the oauth flow.
			 */
			additionalData: z.record(z.string(), z.any()).optional(),
		}),
		use: [sessionMiddleware],
		metadata: {
			openapi: {
				description: "Link a social account to the user",
				operationId: "linkSocialAccount",
				responses: {
					"200": {
						description: "Success",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										url: {
											type: "string",
											description:
												"The authorization URL to redirect the user to",
										},
										redirect: {
											type: "boolean",
											description:
												"Indicates if the user should be redirected to the authorization URL",
										},
										status: {
											type: "boolean",
										},
									},
									required: ["redirect"],
								},
							},
						},
					},
				},
			},
		},
	},
	async (c) => {
		const session = c.context.session;
		const provider = await getAwaitableValue(c.context.socialProviders, {
			value: c.body.provider,
		});

		if (!provider) {
			c.context.logger.error(
				"Provider not found. Make sure to add the provider in your auth config",
				{
					provider: c.body.provider,
				},
			);
			throw APIError.from("NOT_FOUND", BASE_ERROR_CODES.PROVIDER_NOT_FOUND);
		}

		// Handle ID Token flow if provided
		if (c.body.idToken) {
			if (!provider.verifyIdToken) {
				c.context.logger.error(
					"Provider does not support id token verification",
					{
						provider: c.body.provider,
					},
				);
				throw APIError.from(
					"NOT_FOUND",
					BASE_ERROR_CODES.ID_TOKEN_NOT_SUPPORTED,
				);
			}

			const { token, nonce } = c.body.idToken;
			const valid = await provider.verifyIdToken(token, nonce);
			if (!valid) {
				c.context.logger.warn("Invalid id token", {
					provider: c.body.provider,
				});
				throw APIError.from("UNAUTHORIZED", BASE_ERROR_CODES.INVALID_TOKEN);
			}

			const linkingUserInfo = await provider.getUserInfo({
				idToken: token,
				accessToken: c.body.idToken.accessToken,
				refreshToken: c.body.idToken.refreshToken,
			});

			if (!linkingUserInfo || !linkingUserInfo?.user) {
				c.context.logger.error("Failed to get user info", {
					provider: c.body.provider,
				});
				throw APIError.from(
					"UNAUTHORIZED",
					BASE_ERROR_CODES.FAILED_TO_GET_USER_INFO,
				);
			}

			const linkingUserId = String(linkingUserInfo.user.id);

			if (!linkingUserInfo.user.email) {
				c.context.logger.error(
					missingEmailLogMessage(c.body.provider, { source: "id_token" }),
					{ provider: c.body.provider },
				);
				throw APIError.from(
					"UNAUTHORIZED",
					BASE_ERROR_CODES.USER_EMAIL_NOT_FOUND,
				);
			}

			const existingAccounts = await c.context.internalAdapter.findAccounts(
				session.user.id,
			);

			const hasBeenLinked = existingAccounts.find(
				(a) => a.providerId === provider.id && a.accountId === linkingUserId,
			);

			if (hasBeenLinked) {
				return c.json({
					url: "", // this is for type inference
					status: true,
					redirect: false,
				});
			}

			const isTrustedProvider = c.context.trustedProviders.includes(
				provider.id,
			);
			if (
				(!isTrustedProvider && !linkingUserInfo.user.emailVerified) ||
				c.context.options.account?.accountLinking?.enabled === false
			) {
				throw APIError.from("UNAUTHORIZED", {
					message: "Account not linked - linking not allowed",
					code: "LINKING_NOT_ALLOWED",
				});
			}

			if (
				linkingUserInfo.user.email?.toLowerCase() !==
					session.user.email.toLowerCase() &&
				c.context.options.account?.accountLinking?.allowDifferentEmails !== true
			) {
				throw APIError.from("UNAUTHORIZED", {
					message: "Account not linked - different emails not allowed",
					code: "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
				});
			}

			try {
				await c.context.internalAdapter.createAccount({
					userId: session.user.id,
					providerId: provider.id,
					accountId: linkingUserId,
					accessToken: await setTokenUtil(
						c.body.idToken.accessToken,
						c.context,
					),
					idToken: await setTokenUtil(token, c.context),
					refreshToken: await setTokenUtil(
						c.body.idToken.refreshToken,
						c.context,
					),
					scope: c.body.idToken.scopes?.join(","),
				});
			} catch (_e: any) {
				throw APIError.from("EXPECTATION_FAILED", {
					message: "Account not linked - unable to create account",
					code: "LINKING_FAILED",
				});
			}

			await applyUpdateUserInfoOnLink(c, session.user.id, linkingUserInfo.user);

			return c.json({
				url: "", // this is for type inference
				status: true,
				redirect: false,
			});
		}

		// Handle OAuth flow
		const state = await generateState(
			c,
			{
				userId: session.user.id,
				email: session.user.email,
			},
			c.body.additionalData,
		);

		const url = await provider.createAuthorizationURL({
			state: state.state,
			codeVerifier: state.codeVerifier,
			redirectURI: `${c.context.baseURL}/callback/${provider.id}`,
			scopes: c.body.scopes,
		});

		if (!c.body.disableRedirect) {
			c.setHeader("Location", url.toString());
		}

		return c.json({
			url: url.toString(),
			redirect: !c.body.disableRedirect,
		});
	},
);
export const unlinkAccount = createAuthEndpoint(
	"/unlink-account",
	{
		method: "POST",
		body: z.object({
			providerId: z.string(),
			accountId: z.string().optional(),
		}),
		use: [freshAuthoritativeSessionMiddleware],
		metadata: {
			openapi: {
				description: "Unlink an account",
				responses: {
					"200": {
						description: "Success",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										status: {
											type: "boolean",
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
		const { providerId, accountId } = ctx.body;
		const userId = ctx.context.session.user.id;
		const accounts = await ctx.context.internalAdapter.findAccounts(
			userId,
		);
		if (
			accounts.length === 1 &&
			!ctx.context.options.account?.accountLinking?.allowUnlinkingAll
		) {
			throw APIError.from(
				"BAD_REQUEST",
				BASE_ERROR_CODES.FAILED_TO_UNLINK_LAST_ACCOUNT,
			);
		}
		const accountExist = accounts.find((account) =>
			accountId
				? account.accountId === accountId && account.providerId === providerId
				: account.providerId === providerId,
		);
		if (!accountExist) {
			throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.ACCOUNT_NOT_FOUND);
		}
		const isCredentialFactor =
			accountExist.providerId === "credential" &&
			typeof accountExist.password === "string" &&
			accountExist.password.length > 0;
		if (!isCredentialFactor) {
			await ctx.context.internalAdapter.deleteAccount(accountExist.id);
			return ctx.json({ status: true });
		}

		assertCredentialFactorLifecycleConfiguration(ctx);
		const originalExpiresAt = new Date(ctx.context.session.session.expiresAt);
		const originalExpiresAtMs = originalExpiresAt.getTime();
		if (
			!Number.isFinite(originalExpiresAtMs) ||
			originalExpiresAtMs <= Date.now()
		) {
			factorLifecycleConflict();
		}

		const passkeyLifecycle =
			ctx.context.options.plugins?.some((plugin) => plugin.id === "passkey") ===
			true;
		const twoFactorPlugin = ctx.context.getPlugin("two-factor");
		const twoFactorLifecycle = twoFactorPlugin != null;
		const twoFactorTable =
			(
				twoFactorPlugin?.options as
					| { twoFactorTable?: string | undefined }
					| undefined
			)?.twoFactorTable ?? "twoFactor";

		type LifecycleResult = {
			replacementSession: Session;
			replacementUser: User & Record<string, unknown>;
		};
		let lifecycle: LifecycleResult | undefined;
		let committedLifecycle: LifecycleResult | undefined;
		try {
			lifecycle = await runWithTransaction(ctx.context.adapter, async () => {
				const adapter = await getCurrentAdapter(ctx.context.adapter);
				const authoritativeUser = (await lockAndReadUser(
					adapter,
					userId,
				)) as (User & Record<string, unknown>) | null;
				if (!authoritativeUser) factorLifecycleConflict();

				const presentedSession = await ctx.context.internalAdapter.findSession(
					ctx.context.session.session.token,
				);
				if (
					!presentedSession ||
					presentedSession.session.id !== ctx.context.session.session.id ||
					presentedSession.session.userId !== userId ||
					presentedSession.user.id !== userId ||
					new Date(presentedSession.session.expiresAt).getTime() !==
						originalExpiresAtMs
				) {
					factorLifecycleConflict();
				}
				const authoritativeSession = await adapter.findOne<
					Session & Record<string, unknown>
				>({
					model: "session",
					where: [
						{ field: "id", value: ctx.context.session.session.id },
						{ field: "userId", value: userId },
						{ field: "expiresAt", value: originalExpiresAt },
					],
				});
				if (!authoritativeSession) factorLifecycleConflict();

				const currentAccounts = await adapter.findMany<Account>({
					model: "account",
					where: [{ field: "userId", value: userId }],
				});
				if (
					currentAccounts.length === 1 &&
					!ctx.context.options.account?.accountLinking?.allowUnlinkingAll
				) {
					throw APIError.from(
						"BAD_REQUEST",
						BASE_ERROR_CODES.FAILED_TO_UNLINK_LAST_ACCOUNT,
					);
				}
				const currentTarget = currentAccounts.find(
					(account) =>
						account.id === accountExist.id &&
						account.providerId === providerId &&
						(accountId === undefined || account.accountId === accountId),
				);
				if (!currentTarget) {
					throw APIError.from(
						"BAD_REQUEST",
						BASE_ERROR_CODES.ACCOUNT_NOT_FOUND,
					);
				}
				if (
					currentTarget.providerId !== "credential" ||
					typeof currentTarget.password !== "string" ||
					currentTarget.password.length === 0
				) {
					factorLifecycleConflict();
				}

				const hasOtherPassword = currentAccounts.some(
					(account) =>
						account.id !== currentTarget.id &&
						account.providerId === "credential" &&
						typeof account.password === "string" &&
						account.password.length > 0,
				);
				const verifiedTwoFactor = twoFactorLifecycle
					? await adapter.findOne<Record<string, unknown>>({
							model: twoFactorTable,
							where: [
								{ field: "userId", value: userId },
								{ field: "verified", value: true },
							],
						})
					: null;
				const passkeyCount = passkeyLifecycle
					? await adapter.count({
							model: "passkey",
							where: [{ field: "userId", value: userId }],
						})
					: 0;
				const hasVerifiedTwoFactor =
					authoritativeUser.twoFactorEnabled === true &&
					verifiedTwoFactor !== null;
				if (!hasOtherPassword && !hasVerifiedTwoFactor && passkeyCount === 0) {
					lastFactorProtected();
				}

				let replacementUser: User & Record<string, unknown> = authoritativeUser;
				if (passkeyLifecycle) {
					const userGeneration =
						authoritativeUser[PASSKEY_SESSION_GENERATION_FIELD];
					const sessionGeneration =
						authoritativeSession[PASSKEY_SESSION_GENERATION_FIELD];
					if (typeof userGeneration !== "string" || userGeneration.length === 0)
						factorLifecycleConflict();
					if (
						typeof sessionGeneration !== "string" ||
						sessionGeneration.length === 0
					)
						factorLifecycleConflict();
					if (sessionGeneration !== userGeneration)
						factorLifecycleConflict();
					const rotatedUser = await rotatePasskeySessionGeneration(
						adapter,
						userId,
						userGeneration,
						generateRandomString(32),
					);
					if (!rotatedUser) factorLifecycleConflict();
					replacementUser = rotatedUser;
				} else if (twoFactorLifecycle) {
					const userGeneration =
						authoritativeUser[TWO_FACTOR_SESSION_GENERATION_FIELD];
					const sessionGeneration =
						authoritativeSession[TWO_FACTOR_SESSION_GENERATION_FIELD];
					if (
						typeof userGeneration !== "string" ||
						userGeneration.length === 0 ||
						typeof sessionGeneration !== "string" ||
						sessionGeneration.length === 0 ||
						sessionGeneration !== userGeneration
					) {
						factorLifecycleConflict();
					}
					const rotatedUser = await rotateTwoFactorSessionGeneration(
						adapter,
						userId,
						userGeneration,
						generateRandomString(32),
					);
					if (!rotatedUser) factorLifecycleConflict();
					replacementUser = rotatedUser;
				}

				const deletedTarget = await adapter.consumeOne<Account>({
					model: "account",
					where: [
						{ field: "id", value: currentTarget.id },
						{ field: "userId", value: userId },
						{ field: "providerId", value: "credential" },
						{ field: "accountId", value: currentTarget.accountId },
						{ field: "password", value: currentTarget.password },
					],
				});
				if (!deletedTarget) factorLifecycleConflict();

				await ctx.context.internalAdapter.deleteUserSessions(userId);
				const replacementSession =
					await ctx.context.internalAdapter.createSession(userId, false, {
						expiresAt: originalExpiresAt,
						__preserveSessionExpiresAt: true,
					});
				if (
					new Date(replacementSession.expiresAt).getTime() !==
					originalExpiresAtMs
				) {
					factorLifecycleConflict();
				}
				committedLifecycle = { replacementSession, replacementUser };
				return committedLifecycle;
			});
		} catch (error) {
			if (error instanceof AfterTransactionHookError && committedLifecycle) {
				logFactorLifecycleFailure(
					ctx,
					"credential unlink post-commit publication failed",
					error,
				);
				lifecycle = committedLifecycle;
			} else {
				throw error;
			}
		}
		if (!lifecycle) factorLifecycleConflict();

		await setSessionCookie(ctx, {
			session: lifecycle.replacementSession,
			user: lifecycle.replacementUser as User,
		});
		return ctx.json({
			status: true,
		});
	},
);

/**
 * Resolves the user id an account-token operation should act on.
 *
 * A caller reaching the server over HTTP (a request or session headers are
 * present) must have a valid session, and that session's user always wins.
 * A trusted server-side `auth.api` caller with no session may instead name a
 * `userId` directly. Throws `UNAUTHORIZED` when an HTTP caller is
 * unauthenticated, and `USER_ID_OR_SESSION_REQUIRED` when neither a session
 * nor a `userId` is available.
 *
 * When a durable store is authoritative, bypasses the cookie cache: these
 * routes mint or refresh provider access tokens, so a server-side session
 * revocation must take effect immediately rather than waiting for the cached
 * cookie to expire. DB-less deployments keep the session in the cookie itself,
 * so the cache is left in place for them.
 */
async function resolveUserId(
	ctx: GenericEndpointContext,
	userId?: string,
): Promise<string> {
	const session = await getSessionFromCtx(ctx, {
		disableCookieCache: isStateful(ctx),
	});
	if (!session && (ctx.request || ctx.headers)) {
		throw ctx.error("UNAUTHORIZED");
	}
	const resolvedUserId = session?.user?.id || userId;
	if (!resolvedUserId) {
		throw APIError.from("BAD_REQUEST", {
			message: "Either userId or session is required",
			code: "USER_ID_OR_SESSION_REQUIRED",
		});
	}
	return resolvedUserId;
}

function matchesAccountSelection(
	ctx: GenericEndpointContext,
	account: Account,
	{
		resolvedUserId,
		providerId,
		accountId,
	}: {
		resolvedUserId: string;
		providerId?: string;
		accountId?: string;
	},
) {
	const matchesSessionUser =
		!shouldBindAccountCookieToSessionUser(ctx.context.options) ||
		account.userId === resolvedUserId;
	return (
		matchesSessionUser &&
		(!providerId || providerId === account.providerId) &&
		(!accountId || account.accountId === accountId)
	);
}

/**
 * Fetches a currently-valid access token for a user's provider account,
 * refreshing and persisting it when it is within five seconds of expiry.
 * Shared by the `/get-access-token` endpoint and `/account-info` so both
 * resolve and refresh tokens through one path.
 */
async function getValidAccessToken(
	ctx: GenericEndpointContext,
	{
		resolvedUserId,
		providerId,
		accountId,
		account: resolvedAccount,
	}: {
		resolvedUserId: string;
		providerId: string;
		accountId?: string;
		/**
		 * An already-resolved account. When provided, skips the cookie and
		 * database lookup so a caller that has the account in hand does not
		 * re-query for it.
		 */
		account?: Account;
	},
) {
	const provider = await getAwaitableValue(ctx.context.socialProviders, {
		value: providerId,
	});
	if (!provider) {
		throw APIError.from("BAD_REQUEST", {
			message: `Provider ${providerId} is not supported.`,
			code: "PROVIDER_NOT_SUPPORTED",
		});
	}
	let account: Account | undefined = resolvedAccount;
	if (!account) {
		const accountData = await getAccountCookie(ctx);
		if (
			accountData &&
			matchesAccountSelection(ctx, accountData, {
				resolvedUserId,
				providerId,
				accountId,
			})
		) {
			account = accountData;
		} else {
			const accounts =
				await ctx.context.internalAdapter.findAccounts(resolvedUserId);
			account = accounts.find((acc) =>
				accountId
					? acc.accountId === accountId && acc.providerId === providerId
					: acc.providerId === providerId,
			);
		}
	}

	if (!account) {
		throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.ACCOUNT_NOT_FOUND);
	}

	try {
		let newTokens: OAuth2Tokens | null = null;
		const accessTokenExpired =
			account.accessTokenExpiresAt &&
			new Date(account.accessTokenExpiresAt).getTime() - Date.now() < 5_000;
		if (
			account.refreshToken &&
			accessTokenExpired &&
			provider.refreshAccessToken
		) {
			const refreshToken = await decryptOAuthToken(
				account.refreshToken,
				ctx.context,
			);
			newTokens = await provider.refreshAccessToken(refreshToken);
			const updatedData = {
				accessToken: await setTokenUtil(newTokens?.accessToken, ctx.context),
				accessTokenExpiresAt: newTokens?.accessTokenExpiresAt,
				refreshToken: newTokens?.refreshToken
					? await setTokenUtil(newTokens.refreshToken, ctx.context)
					: account.refreshToken,
				refreshTokenExpiresAt:
					newTokens?.refreshTokenExpiresAt ?? account.refreshTokenExpiresAt,
				idToken: newTokens?.idToken
					? await setTokenUtil(newTokens.idToken, ctx.context)
					: account.idToken,
			};
			let updatedAccount: Record<string, any> | null = null;
			if (account.id) {
				updatedAccount = await ctx.context.internalAdapter.updateAccount(
					account.id,
					updatedData,
				);
			}
			if (ctx.context.options.account?.storeAccountCookie) {
				await setAccountCookie(ctx, {
					...account,
					...(updatedAccount ?? updatedData),
				});
			}
		}

		const accessTokenExpiresAt = (() => {
			if (newTokens?.accessTokenExpiresAt) {
				if (typeof newTokens.accessTokenExpiresAt === "string") {
					return new Date(newTokens.accessTokenExpiresAt);
				}
				return newTokens.accessTokenExpiresAt;
			}
			if (account.accessTokenExpiresAt) {
				if (typeof account.accessTokenExpiresAt === "string") {
					return new Date(account.accessTokenExpiresAt);
				}
				return account.accessTokenExpiresAt;
			}
			return undefined;
		})();

		return {
			accessToken:
				newTokens?.accessToken ??
				(await decryptOAuthToken(account.accessToken ?? "", ctx.context)),
			accessTokenExpiresAt,
			scopes: account.scope?.split(",") ?? [],
			idToken:
				newTokens?.idToken ??
				(account.idToken
					? await decryptOAuthToken(account.idToken, ctx.context)
					: undefined),
		};
	} catch (_error) {
		throw APIError.from("BAD_REQUEST", {
			message: "Failed to get a valid access token",
			code: "FAILED_TO_GET_ACCESS_TOKEN",
		});
	}
}

export const getAccessToken = createAuthEndpoint(
	"/get-access-token",
	{
		method: "POST",
		body: z.object({
			providerId: z.string().meta({
				description: "The provider ID for the OAuth provider",
			}),
			accountId: z
				.string()
				.meta({
					description: "The account ID associated with the refresh token",
				})
				.optional(),
			userId: z
				.string()
				.meta({
					description: "The user ID associated with the account",
				})
				.optional(),
		}),
		metadata: {
			openapi: {
				description: "Get a valid access token, doing a refresh if needed",
				responses: {
					200: {
						description: "A Valid access token",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										tokenType: {
											type: "string",
										},
										idToken: {
											type: "string",
										},
										accessToken: {
											type: "string",
										},
										accessTokenExpiresAt: {
											type: "string",
											format: "date-time",
										},
									},
								},
							},
						},
					},
					400: {
						description: "Invalid refresh token or provider configuration",
					},
				},
			},
		},
	},
	async (ctx) => {
		const { providerId, accountId, userId } = ctx.body || {};
		const resolvedUserId = await resolveUserId(ctx, userId);
		const tokens = await getValidAccessToken(ctx, {
			resolvedUserId,
			providerId,
			accountId,
		});
		return ctx.json(tokens);
	},
);

export const refreshToken = createAuthEndpoint(
	"/refresh-token",
	{
		method: "POST",
		body: z.object({
			providerId: z.string().meta({
				description: "The provider ID for the OAuth provider",
			}),
			accountId: z
				.string()
				.meta({
					description: "The account ID associated with the refresh token",
				})
				.optional(),
			userId: z
				.string()
				.meta({
					description: "The user ID associated with the account",
				})
				.optional(),
		}),
		metadata: {
			openapi: {
				description: "Refresh the access token using a refresh token",
				responses: {
					200: {
						description: "Access token refreshed successfully",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										tokenType: {
											type: "string",
										},
										idToken: {
											type: "string",
										},
										accessToken: {
											type: "string",
										},
										refreshToken: {
											type: "string",
										},
										accessTokenExpiresAt: {
											type: "string",
											format: "date-time",
										},
										refreshTokenExpiresAt: {
											type: "string",
											format: "date-time",
										},
									},
								},
							},
						},
					},
					400: {
						description: "Invalid refresh token or provider configuration",
					},
				},
			},
		},
	},
	async (ctx) => {
		const { providerId, accountId, userId } = ctx.body;
		const resolvedUserId = await resolveUserId(ctx, userId);
		const provider = await getAwaitableValue(ctx.context.socialProviders, {
			value: providerId,
		});
		if (!provider) {
			throw APIError.from("BAD_REQUEST", {
				message: `Provider ${providerId} is not supported.`,
				code: "PROVIDER_NOT_SUPPORTED",
			});
		}
		if (!provider.refreshAccessToken) {
			throw APIError.from("BAD_REQUEST", {
				message: `Provider ${providerId} does not support token refreshing.`,
				code: "TOKEN_REFRESH_NOT_SUPPORTED",
			});
		}

		// Try to read refresh token from cookie first
		let account: Account | undefined = undefined;
		const accountData = await getAccountCookie(ctx);
		const usedAccountCookie =
			!!accountData &&
			matchesAccountSelection(ctx, accountData, {
				resolvedUserId,
				providerId,
				accountId,
			});
		if (usedAccountCookie) {
			account = accountData;
		} else {
			const accounts =
				await ctx.context.internalAdapter.findAccounts(resolvedUserId);
			account = accounts.find((acc) =>
				accountId
					? acc.accountId === accountId && acc.providerId === providerId
					: acc.providerId === providerId,
			);
		}

		if (!account) {
			throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.ACCOUNT_NOT_FOUND);
		}
		const refreshToken = account.refreshToken ?? undefined;

		if (!refreshToken) {
			throw APIError.from("BAD_REQUEST", {
				message: "Refresh token not found",
				code: "REFRESH_TOKEN_NOT_FOUND",
			});
		}

		try {
			const decryptedRefreshToken = await decryptOAuthToken(
				refreshToken,
				ctx.context,
			);
			const tokens: OAuth2Tokens = await provider.refreshAccessToken(
				decryptedRefreshToken,
			);

			const resolvedRefreshToken = tokens.refreshToken
				? await setTokenUtil(tokens.refreshToken, ctx.context)
				: refreshToken;
			const resolvedRefreshTokenExpiresAt =
				tokens.refreshTokenExpiresAt ?? account.refreshTokenExpiresAt;

			if (account.id) {
				const updateData = {
					...(account || {}),
					accessToken: await setTokenUtil(tokens.accessToken, ctx.context),
					refreshToken: resolvedRefreshToken,
					accessTokenExpiresAt: tokens.accessTokenExpiresAt,
					refreshTokenExpiresAt: resolvedRefreshTokenExpiresAt,
					scope: tokens.scopes?.join(",") || account.scope,
					idToken: tokens.idToken
						? await setTokenUtil(tokens.idToken, ctx.context)
						: account.idToken,
				};
				await ctx.context.internalAdapter.updateAccount(account.id, updateData);
			}

			if (
				usedAccountCookie &&
				ctx.context.options.account?.storeAccountCookie
			) {
				const updateData = {
					...accountData,
					accessToken: await setTokenUtil(tokens.accessToken, ctx.context),
					refreshToken: resolvedRefreshToken,
					accessTokenExpiresAt: tokens.accessTokenExpiresAt,
					refreshTokenExpiresAt: resolvedRefreshTokenExpiresAt,
					scope: tokens.scopes?.join(",") || accountData.scope,
					idToken: tokens.idToken
						? await setTokenUtil(tokens.idToken, ctx.context)
						: accountData.idToken,
				};
				await setAccountCookie(ctx, updateData);
			}
			return ctx.json({
				accessToken: tokens.accessToken,
				refreshToken: tokens.refreshToken ?? decryptedRefreshToken,
				accessTokenExpiresAt: tokens.accessTokenExpiresAt,
				refreshTokenExpiresAt: resolvedRefreshTokenExpiresAt,
				scope: tokens.scopes?.join(",") || account.scope,
				idToken:
					tokens.idToken ||
					(account.idToken
						? await decryptOAuthToken(account.idToken, ctx.context)
						: undefined),
				providerId: account.providerId,
				accountId: account.accountId,
			});
		} catch (_error) {
			throw APIError.from("BAD_REQUEST", {
				message: "Failed to refresh access token",
				code: "FAILED_TO_REFRESH_ACCESS_TOKEN",
			});
		}
	},
);

const accountInfoQuerySchema = z.optional(
	z.object({
		accountId: z
			.string()
			.meta({
				description:
					"The provider given account id for which to get the account info",
			})
			.optional(),
		providerId: z
			.string()
			.meta({
				description:
					"The provider ID to disambiguate provider-issued account IDs",
			})
			.optional(),
		userId: z
			.string()
			.meta({
				description: "The user ID associated with the account",
			})
			.optional(),
	}),
);

export const accountInfo = createAuthEndpoint(
	"/account-info",
	{
		method: "GET",
		metadata: {
			openapi: {
				description: "Get the account info provided by the provider",
				responses: {
					"200": {
						description: "Success",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										user: {
											type: "object",
											properties: {
												id: {
													type: "string",
												},
												name: {
													type: "string",
												},
												email: {
													type: "string",
												},
												image: {
													type: "string",
												},
												emailVerified: {
													type: "boolean",
												},
											},
											required: ["id", "emailVerified"],
										},
										data: {
											type: "object",
											properties: {},
											additionalProperties: true,
										},
									},
									required: ["user", "data"],
									additionalProperties: false,
								},
							},
						},
					},
				},
			},
		},
		query: accountInfoQuerySchema,
	},
	async (ctx) => {
		const {
			accountId: providedAccountId,
			providerId: providedProviderId,
			userId,
		} = ctx.query || {};
		const resolvedUserId = await resolveUserId(ctx, userId);

		let account: Account | undefined = undefined;
		if (!providedAccountId) {
			if (ctx.context.options.account?.storeAccountCookie) {
				const accountData = await getAccountCookie(ctx);
				if (
					accountData &&
					matchesAccountSelection(ctx, accountData, {
						resolvedUserId,
						providerId: providedProviderId,
					})
				) {
					account = accountData;
				}
			}
		} else {
			const accounts =
				await ctx.context.internalAdapter.findAccounts(resolvedUserId);
			const matchingAccounts = accounts.filter(
				(acc) =>
					acc.accountId === providedAccountId &&
					(!providedProviderId || acc.providerId === providedProviderId),
			);
			if (matchingAccounts.length > 1) {
				throw APIError.from("BAD_REQUEST", {
					message:
						"Multiple accounts share this account ID. Pass a providerId to disambiguate.",
					code: "AMBIGUOUS_ACCOUNT",
				});
			}
			account = matchingAccounts[0];
		}

		if (
			!account ||
			!matchesAccountSelection(ctx, account, {
				resolvedUserId,
			})
		) {
			throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.ACCOUNT_NOT_FOUND);
		}

		const provider = await getAwaitableValue(ctx.context.socialProviders, {
			value: account.providerId,
		});

		if (!provider) {
			throw APIError.from("BAD_REQUEST", {
				message: "Account is not associated with a configured social provider.",
				code: "PROVIDER_NOT_CONFIGURED",
			});
		}
		const tokens = await getValidAccessToken(ctx, {
			resolvedUserId,
			providerId: account.providerId,
			accountId: account.accountId,
			account,
		});
		if (!tokens.accessToken) {
			throw APIError.from("BAD_REQUEST", {
				message: "Access token not found",
				code: "ACCESS_TOKEN_NOT_FOUND",
			});
		}
		const info = await provider.getUserInfo({
			...tokens,
			accessToken: tokens.accessToken,
		});
		return ctx.json(info);
	},
);
