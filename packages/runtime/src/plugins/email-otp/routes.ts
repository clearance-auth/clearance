import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import { BASE_ERROR_CODES } from "@clearance/core/error";
import { deprecate } from "@clearance/core/utils/deprecate";
import * as z from "zod";
import {
	APIError,
	getSessionFromCtx,
	sensitiveSessionMiddleware,
} from "../../api";
import { setCookieCache, setSessionCookie } from "../../cookies";
import { generateRandomString, symmetricDecrypt } from "../../crypto";
import { revokeUnprovenAccountAccess } from "../../db/revoke-unproven-account-access";
import { parseUserInput, parseUserOutput } from "../../db/schema";
import {
	requireManagedAuthenticationTransaction,
	runManagedAuthenticationTransaction,
} from "../../internal/managed-authentication-transaction";
import { createInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../internal/verification-challenge-context";
import { getDate } from "../../utils/date";
import { EMAIL_OTP_ERROR_CODES as ERROR_CODES } from "./error-codes";
import { storeOTP, tryReuseOTP, verifyStoredOTP } from "./otp-token";
import type { EmailOTPOptions, RequiredEmailOTPOptions } from "./types";
import {
	emailOTPChallenge,
	splitAtLastColon,
	toOTPIdentifier,
} from "./utils";

const types = [
	"email-verification",
	"sign-in",
	"forget-password",
	"change-email",
] as const;

/**
 * Resolves the OTP to send: reuses an existing one if possible,
 * otherwise generates and stores a new one.
 *
 * @internal
 */
async function resolveOTP(
	ctx: GenericEndpointContext,
	opts: RequiredEmailOTPOptions,
	email: string,
	type: (typeof types)[number],
): Promise<string> {
	const identifier = toOTPIdentifier(type, email);
	const challenge = emailOTPChallenge(type, email);

	if (opts.resendStrategy === "reuse") {
		const reused = await tryReuseOTP(ctx, opts, challenge);
		if (reused) return reused;
	}

	const otp =
		opts.generateOTP({ email, type }, ctx) || defaultOTPGenerator(opts);
	const storedOTP = await storeOTP(ctx, opts, otp);

	await createInternalVerificationChallenge(
		ctx.context.internalAdapter,
		challenge,
		{
			value: `${storedOTP}:0`,
			identifier,
			expiresAt: getDate(opts.expiresIn, "sec"),
		},
	)
		.catch(async () => {
			await ctx.context.internalAdapter.deleteVerificationByIdentifier(
				identifier,
			);
			await createInternalVerificationChallenge(
				ctx.context.internalAdapter,
				challenge,
				{
					value: `${storedOTP}:0`,
					identifier,
					expiresAt: getDate(opts.expiresIn, "sec"),
				},
			);
		});

	return otp;
}

const sendVerificationOTPBodySchema = z.object({
	email: z.string({}).meta({
		description: "Email address to send the OTP",
	}),
	type: z.enum(types).meta({
		description: "Type of the OTP",
	}),
});

/**
 * ### Endpoint
 *
 * POST `/email-otp/send-verification-otp`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.sendVerificationOTP`
 *
 * **client:**
 * `authClient.emailOtp.sendVerificationOtp`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const sendVerificationOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint(
		"/email-otp/send-verification-otp",
		{
			method: "POST",
			body: sendVerificationOTPBodySchema,
			metadata: {
				openapi: {
					operationId: "sendEmailVerificationOTP",
					description: "Send a verification OTP to an email",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											success: {
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
			if (!opts?.sendVerificationOTP) {
				ctx.context.logger.error("send email verification is not implemented");
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "send email verification is not implemented",
				});
			}
			const email = ctx.body.email.toLowerCase();
			const isValidEmail = z.email().safeParse(email);
			if (!isValidEmail.success) {
				throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
			}

			// Enforce using the correct endpoint for change email OTP
			if (ctx.body.type === "change-email") {
				ctx.context.logger.error(
					"Use the /email-otp/request-email-change endpoint to send OTP for changing email",
				);
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Invalid OTP type",
				});
			}
			const identifier = toOTPIdentifier(ctx.body.type, email);
			const otp = await resolveOTP(ctx, opts, email, ctx.body.type);

			const shouldSendOTP = ctx.body.type === "sign-in" && !opts.disableSignUp;
			const user = await ctx.context.internalAdapter.findUserByEmail(email);
			if (!user && !shouldSendOTP) {
				await ctx.context.internalAdapter.deleteVerificationByIdentifier(
					identifier,
				);
				return ctx.json({ success: true });
			}

			await ctx.context.runInBackgroundOrAwait(
				opts.sendVerificationOTP({ email, otp, type: ctx.body.type }, ctx),
			);
			return ctx.json({ success: true });
		},
	);

const createVerificationOTPBodySchema = z.object({
	email: z.string({}).meta({
		description: "Email address to send the OTP",
	}),
	type: z.enum(types).meta({
		required: true,
		description: "Type of the OTP",
	}),
});

export const createVerificationOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint.serverOnly(
		{
			method: "POST",
			body: createVerificationOTPBodySchema,
			metadata: {
				openapi: {
					operationId: "createEmailVerificationOTP",
					description: "Create a verification OTP for an email",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "string",
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const email = ctx.body.email.toLowerCase();
			const otp =
				opts.generateOTP({ email, type: ctx.body.type }, ctx) ||
				defaultOTPGenerator(opts);
			const storedOTP = await storeOTP(ctx, opts, otp);
			const challenge = emailOTPChallenge(ctx.body.type, email);
			await createInternalVerificationChallenge(
				ctx.context.internalAdapter,
				challenge,
				{
					value: `${storedOTP}:0`,
					identifier: challenge.identifier,
					expiresAt: getDate(opts.expiresIn, "sec"),
				},
			);
			return otp;
		},
	);

const getVerificationOTPBodySchema = z.object({
	email: z.string({}).meta({
		description: "Email address the OTP was sent to",
	}),
	type: z.enum(types).meta({
		required: true,
		description: "Type of the OTP",
	}),
});

/**
 * ### Endpoint
 *
 * GET `/email-otp/get-verification-otp`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.getVerificationOTP`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const getVerificationOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint.serverOnly(
		{
			method: "GET",
			query: getVerificationOTPBodySchema,
			metadata: {
				openapi: {
					operationId: "getEmailVerificationOTP",
					description: "Get a verification OTP for an email",
					responses: {
						"200": {
							description: "OTP retrieved successfully or not found/expired",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											otp: {
												type: "string",
												nullable: true,
												description:
													"The stored OTP, or null if not found or expired",
											},
										},
										required: ["otp"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const email = ctx.query.email.toLowerCase();
			const verificationValue =
				await ctx.context.internalAdapter.findVerificationValueAndPruneExpired(
					toOTPIdentifier(ctx.query.type, email),
				);
			if (!verificationValue || verificationValue.expiresAt < new Date()) {
				return ctx.json({
					otp: null,
				});
			}
			if (
				opts.storeOTP === "keyed" ||
				opts.storeOTP === "hashed" ||
				(typeof opts.storeOTP === "object" && "hash" in opts.storeOTP)
			) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "OTP is hashed, cannot return the plain text OTP",
				});
			}

			const [storedOtp, _attempts] = splitAtLastColon(verificationValue.value);
			let otp = storedOtp;
			if (opts.storeOTP === "encrypted") {
				otp = await symmetricDecrypt({
					key: ctx.context.secretConfig,
					data: storedOtp,
				});
			}

			if (typeof opts.storeOTP === "object" && "decrypt" in opts.storeOTP) {
				otp = await opts.storeOTP.decrypt(storedOtp);
			}

			return ctx.json({
				otp,
			});
		},
	);

const checkVerificationOTPBodySchema = z.object({
	email: z.string().meta({
		description: "Email address the OTP was sent to",
	}),
	type: z.enum(types).meta({
		required: true,
		description: "Type of the OTP",
	}),
	otp: z.string().meta({
		required: true,
		description: "OTP to verify",
	}),
});

/**
 * ### Endpoint
 *
 * GET `/email-otp/check-verification-otp`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.checkVerificationOTP`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const checkVerificationOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint(
		"/email-otp/check-verification-otp",
		{
			method: "POST",
			body: checkVerificationOTPBodySchema,
			metadata: {
				openapi: {
					operationId: "verifyEmailWithOTP",
					description: "Verify an email with an OTP",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											success: {
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
			const email = ctx.body.email.toLowerCase();
			const isValidEmail = z.email().safeParse(email);
			if (!isValidEmail.success) {
				throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
			}
			const user = await ctx.context.internalAdapter.findUserByEmail(email);
			if (!user) {
				throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.USER_NOT_FOUND);
			}
			const identifier = toOTPIdentifier(ctx.body.type, email);
			const verificationValue =
				await ctx.context.internalAdapter.findVerificationValueAndPruneExpired(identifier);
			if (!verificationValue) {
				throw APIError.from("BAD_REQUEST", ERROR_CODES.INVALID_OTP);
			}
			if (verificationValue.expiresAt < new Date()) {
				await ctx.context.internalAdapter.deleteVerificationByIdentifier(
					identifier,
				);
				throw APIError.from("BAD_REQUEST", ERROR_CODES.OTP_EXPIRED);
			}

			const [otpValue, attempts] = splitAtLastColon(verificationValue.value);
			const allowedAttempts = opts?.allowedAttempts || 3;
			if (attempts && parseInt(attempts) >= allowedAttempts) {
				await ctx.context.internalAdapter.deleteVerificationByIdentifier(
					identifier,
				);
				throw APIError.from("FORBIDDEN", ERROR_CODES.TOO_MANY_ATTEMPTS);
			}
			const verified = await verifyStoredOTP(ctx, opts, otpValue, ctx.body.otp);
			if (!verified) {
				await ctx.context.internalAdapter.updateVerificationByIdentifier(
					identifier,
					{
						value: `${otpValue}:${parseInt(attempts || "0") + 1}`,
					},
				);
				throw APIError.from("BAD_REQUEST", ERROR_CODES.INVALID_OTP);
			}
			return ctx.json({
				success: true,
			});
		},
	);

const verifyEmailOTPBodySchema = z.object({
	email: z.string({}).meta({
		description: "Email address to verify",
	}),
	otp: z.string().meta({
		required: true,
		description: "OTP to verify",
	}),
});

/**
 * ### Endpoint
 *
 * POST `/email-otp/verify-email`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.verifyEmailOTP`
 *
 * **client:**
 * `authClient.emailOtp.verifyEmail`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const verifyEmailOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint(
		"/email-otp/verify-email",
		{
			method: "POST",
			body: verifyEmailOTPBodySchema,
			metadata: {
				openapi: {
					description: "Verify email with OTP",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											status: {
												type: "boolean",
												description:
													"Indicates if the verification was successful",
												enum: [true],
											},
											token: {
												type: "string",
												nullable: true,
												description:
													"Session token if autoSignInAfterVerification is enabled, otherwise null",
											},
											user: {
												$ref: "#/components/schemas/User",
											},
										},
										required: ["status", "token", "user"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const email = ctx.body.email.toLowerCase();
			const isValidEmail = z.email().safeParse(email);
			if (!isValidEmail.success) {
				throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
			}

			if (ctx.context.options.emailVerification?.autoSignInAfterVerification) {
				const managed = requireManagedAuthenticationTransaction(ctx);
				if (
					managed &&
					ctx.context.options.emailVerification?.beforeEmailVerification
				) {
					throw new Error(
						"Managed email verification cannot execute beforeEmailVerification outside the atomic authentication transaction",
					);
				}
				const result = await runManagedAuthenticationTransaction(
					ctx,
					async () => {
						try {
							await atomicVerifyOTP(
								ctx,
								opts,
								emailOTPChallenge("email-verification", email),
								ctx.body.otp,
							);
						} catch (verificationError) {
							return { verificationError };
						}
						const user =
							await ctx.context.internalAdapter.findUserByEmail(email);
						if (!user) {
							throw APIError.from(
								"BAD_REQUEST",
								BASE_ERROR_CODES.USER_NOT_FOUND,
							);
						}
						if (!managed) {
							await ctx.context.options.emailVerification?.beforeEmailVerification?.(
								user.user,
								ctx.request,
							);
						}
						const updatedUser = await ctx.context.internalAdapter.updateUser(
							user.user.id,
							{ email, emailVerified: true },
						);
						if (!managed) {
							await ctx.context.options.emailVerification?.afterEmailVerification?.(
								updatedUser,
								ctx.request,
							);
						}
						const session = await ctx.context.internalAdapter.createSession(
							updatedUser.id,
							false,
							undefined,
							false,
							createInternalSessionIssuanceContext({
								purpose: "interactive",
								subjectId: updatedUser.id,
								evidence: [
									{ kind: "primary", primaryMethod: "email_otp" },
								],
							}),
						);
						return { session, updatedUser };
					},
				);
				if ("verificationError" in result) throw result.verificationError;
				const { session, updatedUser } = result;
				if (managed) {
					try {
						await ctx.context.options.emailVerification?.afterEmailVerification?.(
							updatedUser,
							ctx.request,
						);
					} catch {
						ctx.context.logger.error(
							"Managed email verification post-commit callback failed",
						);
					}
				}
				await setSessionCookie(ctx, {
					session,
					user: updatedUser,
				});
				return ctx.json({
					status: true,
					token: session.token,
					user: parseUserOutput(ctx.context.options, updatedUser),
				});
			}

			const managed = requireManagedAuthenticationTransaction(ctx);
			if (
				managed &&
				ctx.context.options.emailVerification?.beforeEmailVerification
			) {
				throw new Error(
					"Managed email verification cannot execute beforeEmailVerification outside the atomic authentication transaction",
				);
			}
			const result = await runManagedAuthenticationTransaction(ctx, async () => {
				try {
					await atomicVerifyOTP(
						ctx,
						opts,
						emailOTPChallenge("email-verification", email),
						ctx.body.otp,
					);
				} catch (verificationError) {
					return { verificationError };
				}
				const user = await ctx.context.internalAdapter.findUserByEmail(email);
				if (!user) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.USER_NOT_FOUND);
				}
				if (!managed) {
					await ctx.context.options.emailVerification?.beforeEmailVerification?.(
						user.user,
						ctx.request,
					);
				}
				const updatedUser = await ctx.context.internalAdapter.updateUser(
					user.user.id,
					{ email, emailVerified: true },
				);
				if (!managed) {
					await ctx.context.options.emailVerification?.afterEmailVerification?.(
						updatedUser,
						ctx.request,
					);
				}
				return { updatedUser };
			});
			if ("verificationError" in result) throw result.verificationError;
			const { updatedUser } = result;
			if (managed) {
				try {
					await ctx.context.options.emailVerification?.afterEmailVerification?.(
						updatedUser,
						ctx.request,
					);
				} catch {
					ctx.context.logger.error(
						"Managed email verification post-commit callback failed",
					);
				}
			}
			const currentSession = await getSessionFromCtx(ctx);
			if (
				currentSession &&
				updatedUser.emailVerified &&
				currentSession.user.id === updatedUser.id
			) {
				const dontRememberMeCookie = await ctx.getSignedCookie(
					ctx.context.authCookies.dontRememberToken.name,
					ctx.context.secret,
				);
				await setCookieCache(
					ctx,
					{
						session: currentSession.session,
						user: {
							...currentSession.user,
							emailVerified: true,
						},
					},
					!!dontRememberMeCookie,
				);
			}
			return ctx.json({
				status: true,
				token: null,
				user: parseUserOutput(ctx.context.options, updatedUser),
			});
		},
	);

const signInEmailOTPBodySchema = z
	.object({
		email: z.string({}).meta({
			description: "Email address to sign in",
		}),
		otp: z.string().meta({
			required: true,
			description: "OTP sent to the email",
		}),
		name: z
			.string()
			.meta({
				description:
					'User display name. Only used if the user is registering for the first time. Eg: "my-name"',
			})
			.optional(),
		image: z
			.string()
			.meta({
				description:
					"User profile image URL. Only used if the user is registering for the first time.",
			})
			.optional(),
	})
	.and(z.record(z.string(), z.any()));

/**
 * ### Endpoint
 *
 * POST `/sign-in/email-otp`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.signInEmailOTP`
 *
 * **client:**
 * `authClient.signIn.emailOtp`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const signInEmailOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint(
		"/sign-in/email-otp",
		{
			method: "POST",
			body: signInEmailOTPBodySchema,
			metadata: {
				openapi: {
					operationId: "signInWithEmailOTP",
					description: "Sign in with email and OTP",
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
												description:
													"Session token for the authenticated session",
											},
											user: {
												$ref: "#/components/schemas/User",
											},
										},
										required: ["token", "user"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const { email: rawEmail, otp, name, image, ...rest } = ctx.body;
			const email = rawEmail.toLowerCase();
			requireManagedAuthenticationTransaction(ctx);
			const result = await runManagedAuthenticationTransaction(
				ctx,
				async () => {
					try {
						await atomicVerifyOTP(
							ctx,
							opts,
							emailOTPChallenge("sign-in", email),
							otp,
						);
					} catch (verificationError) {
						return { verificationError };
					}
					const found =
						await ctx.context.internalAdapter.findUserByEmail(email);
					let user = found?.user;
					if (!user) {
						if (opts.disableSignUp) {
							throw APIError.from("BAD_REQUEST", ERROR_CODES.INVALID_OTP);
						}
						const additionalFields = parseUserInput(
							ctx.context.options,
							rest,
							"create",
						);
						user = await ctx.context.internalAdapter.createUser({
							...additionalFields,
							email,
							emailVerified: true,
							name: name || "",
							image,
						});
					} else if (!user.emailVerified) {
						await revokeUnprovenAccountAccess(ctx, user.id);
						user = await ctx.context.internalAdapter.updateUser(user.id, {
							emailVerified: true,
						});
					}
					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						false,
						undefined,
						false,
						createInternalSessionIssuanceContext({
							purpose: "interactive",
							subjectId: user.id,
							evidence: [
								{ kind: "primary", primaryMethod: "email_otp" },
							],
						}),
					);
					return { session, user };
				},
			);
			if ("verificationError" in result) throw result.verificationError;
			const { session, user } = result;
			await setSessionCookie(ctx, {
				session,
				user,
			});
			return ctx.json({
				token: session.token,
				user: parseUserOutput(ctx.context.options, user),
			});
		},
	);

const requestPasswordResetEmailOTPBodySchema = z.object({
	email: z.string().meta({
		description: "Email address to send the OTP",
	}),
});

/**
 * ### Endpoint
 *
 * POST `/email-otp/request-password-reset`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.requestPasswordResetEmailOTP`
 *
 * **client:**
 * `authClient.emailOtp.requestPasswordReset`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const requestPasswordResetEmailOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint(
		"/email-otp/request-password-reset",
		{
			method: "POST",
			body: requestPasswordResetEmailOTPBodySchema,
			metadata: {
				openapi: {
					operationId: "requestPasswordResetWithEmailOTP",
					description: "Request password reset with email and OTP",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											success: {
												type: "boolean",
												description:
													"Indicates if the OTP was sent successfully",
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
			const email = ctx.body.email.toLowerCase();
			const identifier = toOTPIdentifier("forget-password", email);
			const otp = await resolveOTP(ctx, opts, email, "forget-password");
			const user = await ctx.context.internalAdapter.findUserByEmail(email);
			if (!user) {
				await ctx.context.internalAdapter.deleteVerificationByIdentifier(
					identifier,
				);
				return ctx.json({
					success: true,
				});
			}
			await ctx.context.runInBackgroundOrAwait(
				opts.sendVerificationOTP(
					{
						email,
						otp,
						type: "forget-password",
					},
					ctx,
				),
			);
			return ctx.json({
				success: true,
			});
		},
	);

const forgetPasswordEmailOTPBodySchema = z.object({
	email: z.string().meta({
		description: "Email address to send the OTP",
	}),
});

/**
 * ### Endpoint
 *
 * POST `/forget-password/email-otp`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.forgetPasswordEmailOTP`
 *
 * **client:**
 * `authClient.forgetPassword.emailOtp`
 *
 * @deprecated Use `/email-otp/request-password-reset` instead.
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const forgetPasswordEmailOTP = (opts: RequiredEmailOTPOptions) => {
	const warnDeprecation = deprecate(
		() => {},
		'The "/forget-password/email-otp" endpoint is deprecated. ' +
			'Please use "/email-otp/request-password-reset" instead. ' +
			"This endpoint will be removed in the next major version.",
	);

	return createAuthEndpoint(
		"/forget-password/email-otp",
		{
			method: "POST",
			body: forgetPasswordEmailOTPBodySchema,
			metadata: {
				openapi: {
					operationId: "forgetPasswordWithEmailOTP",
					description:
						"Deprecated: Use /email-otp/request-password-reset instead.",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											success: {
												type: "boolean",
												description:
													"Indicates if the OTP was sent successfully",
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
			warnDeprecation();
			const email = ctx.body.email.toLowerCase();
			const identifier = toOTPIdentifier("forget-password", email);
			const otp = await resolveOTP(ctx, opts, email, "forget-password");
			const user = await ctx.context.internalAdapter.findUserByEmail(email);
			if (!user) {
				await ctx.context.internalAdapter.deleteVerificationByIdentifier(
					identifier,
				);
				return ctx.json({
					success: true,
				});
			}
			await ctx.context.runInBackgroundOrAwait(
				opts.sendVerificationOTP(
					{
						email,
						otp,
						type: "forget-password",
					},
					ctx,
				),
			);
			return ctx.json({
				success: true,
			});
		},
	);
};

const resetPasswordEmailOTPBodySchema = z.object({
	email: z.string().meta({
		description: "Email address to reset the password",
	}),
	otp: z.string().meta({
		description: "OTP sent to the email",
	}),
	password: z.string().meta({
		description: "New password",
	}),
});

/**
 * ### Endpoint
 *
 * POST `/email-otp/reset-password`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.resetPasswordEmailOTP`
 *
 * **client:**
 * `authClient.emailOtp.resetPassword`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const resetPasswordEmailOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint(
		"/email-otp/reset-password",
		{
			method: "POST",
			body: resetPasswordEmailOTPBodySchema,
			metadata: {
				openapi: {
					operationId: "resetPasswordWithEmailOTP",
					description: "Reset password with email and OTP",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											success: {
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
			const email = ctx.body.email.toLowerCase();
			const managed = requireManagedAuthenticationTransaction(ctx);
			const result = await runManagedAuthenticationTransaction(ctx, async () => {
				try {
					await atomicVerifyOTP(
						ctx,
						opts,
						emailOTPChallenge("forget-password", email),
						ctx.body.otp,
					);
				} catch (verificationError) {
					return { verificationError };
				}

				const user = await ctx.context.internalAdapter.findUserByEmail(email, {
					includeAccounts: true,
				});
				if (!user) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.USER_NOT_FOUND);
				}
				const minPasswordLength = ctx.context.password.config.minPasswordLength;
				if (ctx.body.password.length < minPasswordLength) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.PASSWORD_TOO_SHORT);
				}
				const maxPasswordLength = ctx.context.password.config.maxPasswordLength;
				if (ctx.body.password.length > maxPasswordLength) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.PASSWORD_TOO_LONG);
				}
				const passwordHash = await ctx.context.password.hash(ctx.body.password);
				const account = user.accounts?.find(
					(account) => account.providerId === "credential",
				);
				if (!account) {
					await ctx.context.internalAdapter.createAccount({
						userId: user.user.id,
						providerId: "credential",
						accountId: user.user.id,
						password: passwordHash,
					});
				} else {
					await ctx.context.internalAdapter.updatePassword(
						user.user.id,
						passwordHash,
					);
				}

				if (!managed && ctx.context.options.emailAndPassword?.onPasswordReset) {
					await ctx.context.options.emailAndPassword.onPasswordReset(
						{ user: user.user },
						ctx.request,
					);
				}
				if (!user.user.emailVerified) {
					await ctx.context.internalAdapter.updateUser(user.user.id, {
						emailVerified: true,
					});
				}
				if (ctx.context.options.emailAndPassword?.revokeSessionsOnPasswordReset) {
					await ctx.context.internalAdapter.deleteUserSessions(user.user.id);
				}
				return { user: user.user };
			});
			if ("verificationError" in result) throw result.verificationError;
			if (managed && ctx.context.options.emailAndPassword?.onPasswordReset) {
				try {
					await ctx.context.options.emailAndPassword.onPasswordReset(
						{ user: result.user },
						ctx.request,
					);
				} catch {
					ctx.context.logger.error(
						"Managed password reset post-commit callback failed",
					);
				}
			}
			return ctx.json({
				success: true,
			});
		},
	);

const requestEmailChangeEmailOTPBodySchema = z.object({
	newEmail: z.string().meta({
		description: "New email address to send the OTP",
	}),
	otp: z.string().optional().meta({
		description:
			"OTP sent to the current email. This is required if changeEmail.verifyCurrentEmail option is set to true",
	}),
});

/**
 * ### Endpoint
 *
 * POST `/email-otp/request-email-change`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.requestEmailChangeEmailOTP`
 *
 * **client:**
 * `authClient.emailOtp.requestEmailChange`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const requestEmailChangeEmailOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint(
		"/email-otp/request-email-change",
		{
			method: "POST",
			body: requestEmailChangeEmailOTPBodySchema,
			use: [sensitiveSessionMiddleware],
			metadata: {
				openapi: {
					operationId: "requestEmailChangeWithEmailOTP",
					description:
						"Request email change with verification OTP sent to the new email",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											success: {
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
			if (!opts.changeEmail?.enabled) {
				ctx.context.logger.error("Change email with OTP is disabled.");
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Change email with OTP is disabled",
				});
			}

			const email = ctx.context.session.user.email.toLowerCase();
			const newEmail = ctx.body.newEmail.toLowerCase();
			const isValidEmail = z.email().safeParse(newEmail);
			if (!isValidEmail.success) {
				throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
			}
			if (newEmail === email) {
				ctx.context.logger.error("Email is the same");
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Email is the same",
				});
			}

			if (opts.changeEmail?.verifyCurrentEmail && !ctx.body.otp) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "OTP is required to verify current email",
				});
			}
			const managed = opts.changeEmail?.verifyCurrentEmail
				? requireManagedAuthenticationTransaction(ctx)
				: false;
			if (managed) {
				const result = await runManagedAuthenticationTransaction(ctx, async () => {
					try {
						await atomicVerifyOTP(
							ctx,
							opts,
							emailOTPChallenge("email-verification", email),
							ctx.body.otp!,
						);
					} catch (verificationError) {
						return { verificationError };
					}
					const existing =
						await ctx.context.internalAdapter.findUserByEmail(newEmail);
					if (existing) return { otp: null };
					const otp =
						opts.generateOTP({ email: newEmail, type: "change-email" }, ctx) ||
						defaultOTPGenerator(opts);
					const storedOTP = await storeOTP(ctx, opts, otp);
					const challenge = emailOTPChallenge(
						"change-email",
						`${email}-${newEmail}`,
					);
					await createInternalVerificationChallenge(
						ctx.context.internalAdapter,
						challenge,
						{
							value: `${storedOTP}:0`,
							identifier: challenge.identifier,
							expiresAt: getDate(opts.expiresIn, "sec"),
						},
					);
					return { otp };
				});
				if ("verificationError" in result) throw result.verificationError;
				if (result.otp) {
					await ctx.context.runInBackgroundOrAwait(
						opts.sendVerificationOTP(
							{ email: newEmail, otp: result.otp, type: "change-email" },
							ctx,
						),
					);
				}
				return ctx.json({ success: true });
			}

			if (opts.changeEmail?.verifyCurrentEmail) {
				await atomicVerifyOTP(
					ctx,
					opts,
					emailOTPChallenge("email-verification", email),
					ctx.body.otp!,
				);
			} else {
				if (ctx.body.otp) {
					ctx.context.logger.warn(
						"OTP provided but not required for verifying current email. " +
							"If you want to require OTP verification for current email, " +
							"please set the changeEmail.verifyCurrentEmail option to true in the configuration",
					);
				}
			}

			const otp =
				opts.generateOTP({ email: newEmail, type: "change-email" }, ctx) ||
				defaultOTPGenerator(opts);
			const storedOTP = await storeOTP(ctx, opts, otp);
			const challenge = emailOTPChallenge(
				"change-email",
				`${email}-${newEmail}`,
			);
			await createInternalVerificationChallenge(
				ctx.context.internalAdapter,
				challenge,
				{
					value: `${storedOTP}:0`,
					identifier: challenge.identifier,
					expiresAt: getDate(opts.expiresIn, "sec"),
				},
			);

			const user = await ctx.context.internalAdapter.findUserByEmail(newEmail);
			if (user) {
				await ctx.context.internalAdapter.deleteVerificationByIdentifier(
					toOTPIdentifier("change-email", `${email}-${newEmail}`),
				);
				return ctx.json({
					success: true,
				});
			}

			await ctx.context.runInBackgroundOrAwait(
				opts.sendVerificationOTP(
					{
						email: newEmail,
						otp,
						type: "change-email",
					},
					ctx,
				),
			);
			return ctx.json({
				success: true,
			});
		},
	);

const changeEmailEmailOTPBodySchema = z.object({
	newEmail: z.string().meta({
		description: "New email address to verify and change to",
	}),
	otp: z.string().meta({
		description: "OTP sent to the new email",
	}),
});

/**
 * ### Endpoint
 *
 * POST `/email-otp/change-email`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.changeEmailEmailOTP`
 *
 * **client:**
 * `authClient.emailOtp.changeEmail`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const changeEmailEmailOTP = (opts: RequiredEmailOTPOptions) =>
	createAuthEndpoint(
		"/email-otp/change-email",
		{
			method: "POST",
			body: changeEmailEmailOTPBodySchema,
			use: [sensitiveSessionMiddleware],
			metadata: {
				openapi: {
					operationId: "changeEmailWithEmailOTP",
					description:
						"Verify new email with OTP and change the email if verification is successful",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											success: {
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
			if (!opts.changeEmail?.enabled) {
				ctx.context.logger.error("Change email with OTP is disabled.");
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Change email with OTP is disabled",
				});
			}

			const session = ctx.context.session;

			const email = session.user.email.toLowerCase();
			const newEmail = ctx.body.newEmail.toLowerCase();
			const isValidNewEmail = z.email().safeParse(newEmail);
			if (!isValidNewEmail.success) {
				throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
			}
			if (newEmail === email) {
				ctx.context.logger.error("Email is the same");
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Email is the same",
				});
			}

			const managed = requireManagedAuthenticationTransaction(ctx);
			if (
				managed &&
				ctx.context.options.emailVerification?.beforeEmailVerification
			) {
				throw new Error(
					"Managed email verification cannot execute beforeEmailVerification outside the atomic authentication transaction",
				);
			}
			const result = await runManagedAuthenticationTransaction(ctx, async () => {
				try {
					await atomicVerifyOTP(
						ctx,
						opts,
						emailOTPChallenge("change-email", `${email}-${newEmail}`),
						ctx.body.otp,
					);
				} catch (verificationError) {
					return { verificationError };
				}

				const currentUser =
					await ctx.context.internalAdapter.findUserByEmail(email);
				if (!currentUser) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.USER_NOT_FOUND);
				}
				const existingUserWithNewEmail =
					await ctx.context.internalAdapter.findUserByEmail(newEmail);
				if (existingUserWithNewEmail) {
					throw APIError.fromStatus("BAD_REQUEST", {
						message: "Email already in use",
					});
				}
				if (!managed) {
					await ctx.context.options.emailVerification?.beforeEmailVerification?.(
						currentUser.user,
						ctx.request,
					);
				}
				const updatedUser = await ctx.context.internalAdapter.updateUser(
					currentUser.user.id,
					{ email: newEmail, emailVerified: true },
				);
				if (!managed) {
					await ctx.context.options.emailVerification?.afterEmailVerification?.(
						updatedUser,
						ctx.request,
					);
				}
				return { updatedUser };
			});
			if ("verificationError" in result) throw result.verificationError;
			const { updatedUser } = result;
			if (managed) {
				try {
					await ctx.context.options.emailVerification?.afterEmailVerification?.(
						updatedUser,
						ctx.request,
					);
				} catch {
					ctx.context.logger.error(
						"Managed email verification post-commit callback failed",
					);
				}
			}
			await setSessionCookie(ctx, {
				session: session.session,
				user: {
					...session.user,
					email: newEmail,
					emailVerified: true,
				},
			});

			return ctx.json({
				success: true,
			});
		},
	);

const defaultOTPGenerator = (options: EmailOTPOptions) =>
	generateRandomString(options.otpLength ?? 6, "0-9");

/**
 * Verifies a single-use OTP with race-condition protection.
 *
 * The atomic consume is the single gate: only the first concurrent caller
 * receives the record, every later racer receives `null` and is rejected, so
 * a correct OTP can only ever be accepted once. When the submitted code is
 * wrong the record is recreated with the same value and expiry and an
 * incremented attempt count so the next try can still find it; the budget is
 * enforced before verification, and a record whose attempts are exhausted is
 * left consumed (no recreate), locking the identifier out.
 */
async function atomicVerifyOTP(
	ctx: GenericEndpointContext,
	opts: RequiredEmailOTPOptions,
	challenge: ReturnType<typeof emailOTPChallenge>,
	providedOTP: string,
): Promise<void> {
	const { identifier } = challenge;
	// Surface the OTP_EXPIRED error shape before consuming. The consume itself
	// drops expired rows and returns null, which would otherwise be
	// indistinguishable from a missing record; this read only reports expiry
	// and never decides the success path, so it does not weaken the race gate.
	const existing =
		await ctx.context.internalAdapter.findVerificationValueAndPruneExpired(identifier);
	if (existing && existing.expiresAt < new Date()) {
		await ctx.context.internalAdapter.deleteVerificationByIdentifier(
			identifier,
		);
		throw APIError.from("BAD_REQUEST", ERROR_CODES.OTP_EXPIRED);
	}

	const consumed = await consumeInternalVerificationChallenge(
		ctx.context.internalAdapter,
		challenge,
	);

	// A null result means the record was missing, already consumed by a racing
	// request, or expired: there is nothing valid left to verify against.
	if (!consumed) {
		throw APIError.from("BAD_REQUEST", ERROR_CODES.INVALID_OTP);
	}

	const [otpValue, attempts] = splitAtLastColon(consumed.value);
	const allowedAttempts = opts?.allowedAttempts || 3;
	const usedAttempts = parseInt(attempts || "0");

	// Budget exhausted: the record stays consumed, so no further attempt can
	// replay it.
	if (usedAttempts >= allowedAttempts) {
		throw APIError.from("FORBIDDEN", ERROR_CODES.TOO_MANY_ATTEMPTS);
	}

	const verified = await verifyStoredOTP(ctx, opts, otpValue, providedOTP);

	if (!verified) {
		await createInternalVerificationChallenge(
			ctx.context.internalAdapter,
			challenge,
			{
				value: `${otpValue}:${usedAttempts + 1}`,
				identifier,
				expiresAt: consumed.expiresAt,
			},
		);
		throw APIError.from("BAD_REQUEST", ERROR_CODES.INVALID_OTP);
	}
}
