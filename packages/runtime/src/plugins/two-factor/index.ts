import type { ClearancePlugin } from "@clearance/core";
import {
	createAuthEndpoint,
	createAuthMiddleware,
} from "@clearance/core/api";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import { createHMAC } from "@clearance/utils/hmac";
import { createOTP } from "@clearance/utils/otp";
import * as z from "zod";
import { sensitiveSessionMiddleware, sessionMiddleware } from "../../api";
import {
	deleteSessionCookie,
	expireCookie,
	setSessionCookie,
} from "../../cookies";
import { symmetricDecrypt, symmetricEncrypt } from "../../crypto";
import { generateRandomString } from "../../crypto/random";
import { mergeSchema } from "../../db/schema";
import { shouldRequirePassword, validatePassword } from "../../utils/password";
import { PACKAGE_VERSION } from "../../version";
import type { BackupCodeOptions } from "./backup-codes";
import { backupCode2fa, generateBackupCodes } from "./backup-codes";
import {
	TRUST_DEVICE_COOKIE_MAX_AGE,
	TRUST_DEVICE_COOKIE_NAME,
	TWO_FACTOR_COOKIE_NAME,
} from "./constant";
import { TWO_FACTOR_ERROR_CODES } from "./error-code";
import { otp2fa } from "./otp";
import { schema } from "./schema";
import { totp2fa } from "./totp";
import type {
	TwoFactorOptions,
	TwoFactorTable,
	UserWithTwoFactor,
} from "./types";
import {
	assertTwoFactorNotLocked,
	reserveTwoFactorAttempt,
} from "./verify-two-factor";

export * from "./error-code";

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		"two-factor": {
			creator: typeof twoFactor;
		};
	}
}
export const twoFactor = <O extends TwoFactorOptions>(options?: O) => {
	const opts = {
		twoFactorTable: "twoFactor",
	};
	const trustDeviceMaxAge =
		options?.trustDeviceMaxAge ?? TRUST_DEVICE_COOKIE_MAX_AGE;
	const allowPasswordless = options?.allowPasswordless;
	const backupCodeOptions = {
		storeBackupCodes: "encrypted",
		...options?.backupCodeOptions,
	} satisfies BackupCodeOptions;
	const totp = totp2fa({
		...options?.totpOptions,
		allowPasswordless:
			options?.totpOptions?.allowPasswordless ?? allowPasswordless,
	});
	const backupCode = backupCode2fa({
		...backupCodeOptions,
		allowPasswordless:
			options?.backupCodeOptions?.allowPasswordless ?? allowPasswordless,
	});
	const otp = otp2fa(options?.otpOptions);
	const passwordSchema = z.string().meta({
		description: "User password",
	});
	const enableTwoFactorBodySchema = allowPasswordless
		? z.object({
				password: passwordSchema.optional(),
				issuer: z
					.string()
					.meta({
						description: "Custom issuer for the TOTP URI",
					})
					.optional(),
				currentCode: z.string().optional(),
			})
		: z.object({
				password: passwordSchema,
				issuer: z
					.string()
					.meta({
						description: "Custom issuer for the TOTP URI",
					})
					.optional(),
				currentCode: z.string().optional(),
			});
	const disableTwoFactorBodySchema = allowPasswordless
		? z.object({
				password: passwordSchema.optional(),
			})
		: z.object({
				password: passwordSchema,
			});

	return {
		id: "two-factor",
		version: PACKAGE_VERSION,
		endpoints: {
			...totp.endpoints,
			...otp.endpoints,
			...backupCode.endpoints,
			/**
			 * ### Endpoint
			 *
			 * POST `/two-factor/enable`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.enableTwoFactor`
			 *
			 * **client:**
			 * `authClient.twoFactor.enable`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			enableTwoFactor: createAuthEndpoint(
				"/two-factor/enable",
				{
					method: "POST",
					body: enableTwoFactorBodySchema,
					use: [sessionMiddleware],
					metadata: {
						openapi: {
							summary: "Enable two factor authentication",
							description:
								"Use this endpoint to enable two factor authentication. This will generate a TOTP URI and backup codes. Once the user verifies the TOTP URI, the two factor authentication will be enabled.",
							responses: {
								200: {
									description: "Successful response",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													totpURI: {
														type: "string",
														description: "TOTP URI",
													},
													backupCodes: {
														type: "array",
														items: {
															type: "string",
														},
														description: "Backup codes",
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
					const user = ctx.context.session.user as UserWithTwoFactor;
					const { currentCode, password, issuer } = ctx.body;
					const requirePassword = await shouldRequirePassword(
						ctx,
						user.id,
						allowPasswordless,
					);
					if (requirePassword) {
						if (!password) {
							throw APIError.from(
								"BAD_REQUEST",
								BASE_ERROR_CODES.INVALID_PASSWORD,
							);
						}
						const isPasswordValid = await validatePassword(ctx, {
							password,
							userId: user.id,
						});
						if (!isPasswordValid) {
							throw APIError.from(
								"BAD_REQUEST",
								BASE_ERROR_CODES.INVALID_PASSWORD,
							);
						}
					}
					const secret = generateRandomString(32);
					const encryptedSecret = await symmetricEncrypt({
						key: ctx.context.secretConfig,
						data: secret,
					});
					const backupCodes = await generateBackupCodes(
						ctx.context.secretConfig,
						backupCodeOptions,
					);
					const existingTwoFactor =
						await ctx.context.adapter.findOne<TwoFactorTable>({
							model: opts.twoFactorTable,
							where: [{ field: "userId", value: user.id }],
						});
					if (
						existingTwoFactor != null &&
						existingTwoFactor.verified !== false
					) {
						if (!currentCode) {
							throw APIError.from(
								"BAD_REQUEST",
								TWO_FACTOR_ERROR_CODES.TOTP_REPLACEMENT_REQUIRES_CURRENT_CODE,
							);
						}
						await assertTwoFactorNotLocked(
							ctx,
							opts.twoFactorTable,
							existingTwoFactor,
						);
						await reserveTwoFactorAttempt(
							ctx,
							opts.twoFactorTable,
							existingTwoFactor,
						);
						const currentSecret = await symmetricDecrypt({
							key: ctx.context.secretConfig,
							data: existingTwoFactor.secret,
						});
						const currentCounter = await createOTP(currentSecret, {
							digits: options?.totpOptions?.digits || 6,
							period: options?.totpOptions?.period,
						}).verifyWithCounter(currentCode);
						if (currentCounter === null) {
							throw APIError.from(
								"UNAUTHORIZED",
								TWO_FACTOR_ERROR_CODES.INVALID_CODE,
							);
						}
						if (existingTwoFactor.lastUsedTotpCounter == null) {
							await ctx.context.adapter.incrementOne<TwoFactorTable>({
								model: opts.twoFactorTable,
								where: [
									{ field: "id", value: existingTwoFactor.id },
									{ field: "secret", value: existingTwoFactor.secret },
									{ field: "lastUsedTotpCounter", value: null },
								],
								increment: {},
								set: { lastUsedTotpCounter: -1 },
							});
						}
						const staged =
							await ctx.context.adapter.incrementOne<TwoFactorTable>({
							model: opts.twoFactorTable,
							where: [
								{ field: "id", value: existingTwoFactor.id },
								{ field: "secret", value: existingTwoFactor.secret },
								{
									field: "lastUsedTotpCounter",
									operator: "lt",
									value: currentCounter,
								},
							],
							increment: {},
							set: {
								pendingSecret: encryptedSecret,
								pendingBackupCodes: backupCodes.encryptedBackupCodes,
								lastUsedTotpCounter: currentCounter,
								failedVerificationCount: 0,
								lockedUntil: null,
							},
						});
						if (!staged) {
							throw APIError.fromStatus("CONFLICT", {
								message: "Two-factor state changed. Please try again.",
							});
						}
						const totpURI = createOTP(secret, {
							digits: options?.totpOptions?.digits || 6,
							period: options?.totpOptions?.period,
						}).url(
							issuer || options?.issuer || ctx.context.appName,
							user.email,
						);
						return ctx.json({
							totpURI,
							backupCodes: backupCodes.backupCodes,
						});
					}
					let persistedEnrollment: TwoFactorTable;
					try {
						persistedEnrollment = await ctx.context.adapter.transaction(
							async (trx) => {
								const current = await trx.findOne<TwoFactorTable>({
									model: opts.twoFactorTable,
									where: [{ field: "userId", value: user.id }],
								});
								if (current) {
									return current;
								}
								return trx.create<TwoFactorTable>({
									model: opts.twoFactorTable,
									data: {
										secret: encryptedSecret,
										backupCodes: backupCodes.encryptedBackupCodes,
										userId: user.id,
										verified: !!options?.skipVerificationOnEnable,
									},
								});
							},
						);
					} catch (error) {
						if (
							typeof error === "object" &&
							error !== null &&
							"code" in error &&
							error.code === "23505"
						) {
							const concurrent =
								await ctx.context.adapter.findOne<TwoFactorTable>({
									model: opts.twoFactorTable,
									where: [{ field: "userId", value: user.id }],
								});
							if (!concurrent || concurrent.verified !== false) {
								throw APIError.fromStatus("CONFLICT", {
									message: "Two-factor enrollment changed. Please try again.",
								});
							}
							persistedEnrollment = concurrent;
						} else {
							throw error;
						}
					}
					let enrollmentSecret = secret;
					let enrollmentBackupCodes = backupCodes.backupCodes;
					if (persistedEnrollment.secret !== encryptedSecret) {
						if (persistedEnrollment.verified !== false) {
							throw APIError.fromStatus("CONFLICT", {
								message: "Two-factor enrollment changed. Please try again.",
							});
						}
						enrollmentSecret = await symmetricDecrypt({
							key: ctx.context.secretConfig,
							data: persistedEnrollment.secret,
						});
						enrollmentBackupCodes = JSON.parse(
							await symmetricDecrypt({
								key: ctx.context.secretConfig,
								data: persistedEnrollment.backupCodes,
							}),
						) as string[];
					}
					if (options?.skipVerificationOnEnable) {
						const updatedUser = await ctx.context.internalAdapter.updateUser(
							user.id,
							{ twoFactorEnabled: true },
						);
						const newSession = await ctx.context.internalAdapter.createSession(
							updatedUser.id,
							false,
							ctx.context.session.session,
						);
						await setSessionCookie(ctx, {
							session: newSession,
							user: updatedUser,
						});
						await ctx.context.internalAdapter.deleteSession(
							ctx.context.session.session.token,
						);
					}
					const totpURI = createOTP(enrollmentSecret, {
						digits: options?.totpOptions?.digits || 6,
						period: options?.totpOptions?.period,
					}).url(issuer || options?.issuer || ctx.context.appName, user.email);
					return ctx.json({ totpURI, backupCodes: enrollmentBackupCodes });
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/two-factor/disable`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.disableTwoFactor`
			 *
			 * **client:**
			 * `authClient.twoFactor.disable`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			disableTwoFactor: createAuthEndpoint(
				"/two-factor/disable",
				{
					method: "POST",
					body: disableTwoFactorBodySchema,
					// Disabling 2FA is a sensitive operation; require a DB-backed
					// session so a stale or replayed cookie-cache payload cannot
					// authorize it (defense in depth against the duplicate
					// Set-Cookie leak fixed in cookies/expireCookie).
					use: [sensitiveSessionMiddleware],
					metadata: {
						openapi: {
							summary: "Disable two factor authentication",
							description:
								"Use this endpoint to disable two factor authentication.",
							responses: {
								200: {
									description: "Successful response",
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
					const user = ctx.context.session.user as UserWithTwoFactor;
					const { password } = ctx.body;
					const requirePassword = await shouldRequirePassword(
						ctx,
						user.id,
						allowPasswordless,
					);
					if (requirePassword) {
						if (!password) {
							throw APIError.from(
								"BAD_REQUEST",
								BASE_ERROR_CODES.INVALID_PASSWORD,
							);
						}
						const isPasswordValid = await validatePassword(ctx, {
							password,
							userId: user.id,
						});
						if (!isPasswordValid) {
							throw APIError.from(
								"BAD_REQUEST",
								BASE_ERROR_CODES.INVALID_PASSWORD,
							);
						}
					}
					const updatedUser = await ctx.context.internalAdapter.updateUser(
						user.id,
						{
							twoFactorEnabled: false,
						},
					);
					await ctx.context.adapter.delete({
						model: opts.twoFactorTable,
						where: [
							{
								field: "userId",
								value: updatedUser.id,
							},
						],
					});
					const newSession = await ctx.context.internalAdapter.createSession(
						updatedUser.id,
						false,
						ctx.context.session.session,
					);
					/**
					 * Update the session cookie with the new user data
					 */
					await setSessionCookie(ctx, {
						session: newSession,
						user: updatedUser,
					});
					//remove current session
					await ctx.context.internalAdapter.deleteSession(
						ctx.context.session.session.token,
					);
					const disableTrustCookie = ctx.context.createAuthCookie(
						TRUST_DEVICE_COOKIE_NAME,
						{
							maxAge: trustDeviceMaxAge,
						},
					);
					const disableTrustValue = await ctx.getSignedCookie(
						disableTrustCookie.name,
						ctx.context.secret,
					);
					if (disableTrustValue) {
						const [, trustId] = disableTrustValue.split("!");
						if (trustId) {
							await ctx.context.internalAdapter.deleteVerificationByIdentifier(
								trustId,
							);
						}
						expireCookie(ctx, disableTrustCookie);
					}
					return ctx.json({ status: true });
				},
			),
		},
		options: options as NoInfer<O>,
		hooks: {
			after: [
				{
					matcher(context) {
						return (
							context.path === "/sign-in/email" ||
							context.path === "/sign-in/username" ||
							context.path === "/sign-in/phone-number"
						);
					},
					handler: createAuthMiddleware(async (ctx) => {
						const data = ctx.context.newSession;
						if (!data) {
							return;
						}

						if (!data?.user.twoFactorEnabled) {
							return;
						}

						const trustDeviceCookieAttrs = ctx.context.createAuthCookie(
							TRUST_DEVICE_COOKIE_NAME,
							{
								maxAge: trustDeviceMaxAge,
							},
						);
						// Check for trust device cookie
						const trustDeviceCookie = await ctx.getSignedCookie(
							trustDeviceCookieAttrs.name,
							ctx.context.secret,
						);

						if (trustDeviceCookie) {
							const [token, trustIdentifier] = trustDeviceCookie.split("!");
							if (token && trustIdentifier) {
								const expectedToken = await createHMAC(
									"SHA-256",
									"base64urlnopad",
								).sign(
									ctx.context.secret,
									`${data.user.id}!${trustIdentifier}`,
								);

								if (token === expectedToken) {
									// HMAC is valid; verify the server-side record
									const verificationRecord =
										await ctx.context.internalAdapter.findVerificationValue(
											trustIdentifier,
										);
									if (
										verificationRecord &&
										verificationRecord.value === data.user.id &&
										verificationRecord.expiresAt > new Date()
									) {
										await ctx.context.internalAdapter.deleteVerificationByIdentifier(
											trustIdentifier,
										);
										const newTrustIdentifier = `trust-device-${generateRandomString(32)}`;
										const newToken = await createHMAC(
											"SHA-256",
											"base64urlnopad",
										).sign(
											ctx.context.secret,
											`${data.user.id}!${newTrustIdentifier}`,
										);
										await ctx.context.internalAdapter.createVerificationValue({
											value: data.user.id,
											identifier: newTrustIdentifier,
											expiresAt: new Date(
												Date.now() + trustDeviceMaxAge * 1000,
											),
										});
										const newTrustDeviceCookie = ctx.context.createAuthCookie(
											TRUST_DEVICE_COOKIE_NAME,
											{
												maxAge: trustDeviceMaxAge,
											},
										);
										await ctx.setSignedCookie(
											newTrustDeviceCookie.name,
											`${newToken}!${newTrustIdentifier}`,
											ctx.context.secret,
											trustDeviceCookieAttrs.attributes,
										);
										return;
									}
								}
							}
							expireCookie(ctx, trustDeviceCookieAttrs);
						}

						/**
						 * Remove the session cookie set by the credential sign-in.
						 *
						 * The credential handler already created a session and set
						 * `ctx.context.newSession`. Since 2FA is still pending, that
						 * session is deleted here and `newSession` is reset to `null`
						 * so downstream hooks don't observe a session that no longer
						 * exists. Hooks that read `ctx.context.newSession` after a
						 * sign-in must therefore null-check it: it is `null` while a
						 * 2FA challenge is in flight (no authenticated session yet).
						 */
						deleteSessionCookie(ctx, true);
						await ctx.context.internalAdapter.deleteSession(data.session.token);
						ctx.context.setNewSession(null);
						const maxAge = options?.twoFactorCookieMaxAge ?? 10 * 60; // 10 minutes
						const twoFactorCookie = ctx.context.createAuthCookie(
							TWO_FACTOR_COOKIE_NAME,
							{
								maxAge,
							},
						);
						const identifier = `2fa-${generateRandomString(20)}`;
						const expiresAt = new Date(Date.now() + maxAge * 1000);
						await ctx.context.internalAdapter.createVerificationValue({
							value: data.user.id,
							identifier,
							expiresAt,
						});
						// Per-challenge attempt counter, consumed atomically by
						// verify-totp and verify-backup-code as the race gate so a
						// concurrent burst cannot exceed the budget.
						await ctx.context.internalAdapter.createVerificationValue({
							value: "0",
							identifier: `2fa-attempts-${identifier}`,
							expiresAt,
						});
						await ctx.setSignedCookie(
							twoFactorCookie.name,
							identifier,
							ctx.context.secret,
							twoFactorCookie.attributes,
						);
						const twoFactorMethods: string[] = [];

						/**
						 * totp requires per-user setup, so we check
						 * that the user actually has a secret stored.
						 */
						if (!options?.totpOptions?.disable) {
							const userTotpSecret =
								await ctx.context.adapter.findOne<TwoFactorTable>({
									model: opts.twoFactorTable,
									where: [
										{
											field: "userId",
											value: data.user.id,
										},
									],
								});
							if (userTotpSecret && userTotpSecret.verified !== false) {
								twoFactorMethods.push("totp");
							}
						}

						/**
						 * otp is server-level — if sendOTP is configured,
						 * any user with 2fa enabled can receive a code.
						 */
						if (options?.otpOptions?.sendOTP) {
							twoFactorMethods.push("otp");
						}

						return ctx.json({
							twoFactorRedirect: true,
							twoFactorMethods,
						});
					}),
				},
			],
		},
		schema: mergeSchema(schema, {
			...options?.schema,
			twoFactor: {
				...options?.schema?.twoFactor,
				...(options?.twoFactorTable
					? { modelName: options.twoFactorTable }
					: {}),
			},
		}),
		rateLimit: [
			{
				pathMatcher(path) {
					return path.startsWith("/two-factor/");
				},
				window: 10,
				max: 3,
			},
		],
		$ERROR_CODES: TWO_FACTOR_ERROR_CODES,
	} satisfies ClearancePlugin;
};

export * from "./client";
export * from "./types";
