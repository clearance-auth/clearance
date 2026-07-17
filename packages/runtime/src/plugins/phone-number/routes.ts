import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import { getCurrentAdapter } from "@clearance/core/context";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import * as z from "zod";
import { getSessionFromCtx } from "../../api";
import { setSessionCookie } from "../../cookies";
import { generateRandomString } from "../../crypto/random";
import { parseUserInput } from "../../db";
import { parseUserOutput } from "../../db/schema";
import {
	requireManagedAuthenticationTransaction,
	runManagedAuthenticationTransaction,
} from "../../internal/managed-authentication-transaction";
import { createInternalSessionIssuanceContext } from "../../internal/session-issuance-context";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../internal/verification-challenge-context";
import { verifyPasswordForSignIn } from "../../security/password-account-lockout";
import type { Account } from "../../types";
import { getDate } from "../../utils/date";
import { PHONE_NUMBER_ERROR_CODES } from "./error-codes";
import type { PhoneNumberOptions, UserWithPhoneNumber } from "./types";

export type RequiredPhoneNumberOptions = PhoneNumberOptions & {
	expiresIn: number;
	otpLength: number;
	phoneNumber: string;
	phoneNumberVerified: string;
	code: string;
	createdAt: string;
};

function phoneNumberChallenge(
	purpose: "phone-number:verify" | "phone-number:password-reset",
	subject: string,
	identifier = subject,
) {
	return { purpose, subject, identifier } as const;
}

const signInPhoneNumberBodySchema = z.object({
	phoneNumber: z.string().meta({
		description: 'Phone number to sign in. Eg: "+1234567890"',
	}),
	password: z.string().meta({
		description: "Password to use for sign in.",
	}),
	rememberMe: z
		.boolean()
		.meta({
			description: "Remember the session. Eg: true",
		})
		.optional(),
});

/**
 * ### Endpoint
 *
 * POST `/sign-in/phone-number`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.signInPhoneNumber`
 *
 * **client:**
 * `authClient.signIn.phoneNumber`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const signInPhoneNumber = (opts: RequiredPhoneNumberOptions) =>
	createAuthEndpoint(
		"/sign-in/phone-number",
		{
			method: "POST",
			body: signInPhoneNumberBodySchema,
			metadata: {
				openapi: {
					summary: "Sign in with phone number",
					description: "Use this endpoint to sign in with phone number",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											user: {
												$ref: "#/components/schemas/User",
											},
											session: {
												$ref: "#/components/schemas/Session",
											},
										},
									},
								},
							},
						},
						400: {
							description: "Invalid phone number or password",
						},
					},
				},
			},
		},
		async (ctx) => {
			const { password, phoneNumber } = ctx.body;

			if (opts.phoneNumberValidator) {
				const isValidNumber = await opts.phoneNumberValidator(
					ctx.body.phoneNumber,
				);
				if (!isValidNumber) {
					throw APIError.from(
						"BAD_REQUEST",
						PHONE_NUMBER_ERROR_CODES.INVALID_PHONE_NUMBER,
					);
				}
			}

			const user = await ctx.context.adapter.findOne<UserWithPhoneNumber>({
				model: "user",
				where: [
					{
						field: "phoneNumber",
						value: phoneNumber,
					},
				],
			});
			if (!user) {
				throw APIError.from(
					"UNAUTHORIZED",
					PHONE_NUMBER_ERROR_CODES.INVALID_PHONE_NUMBER_OR_PASSWORD,
				);
			}
			if (opts.requireVerification) {
				if (!user.phoneNumberVerified) {
					const otp = generateOTP(opts.otpLength);
					const challenge = phoneNumberChallenge(
						"phone-number:verify",
						phoneNumber,
					);
					await createInternalVerificationChallenge(
						ctx.context.internalAdapter,
						challenge,
						{
							value: otp,
							identifier: challenge.identifier,
							expiresAt: getDate(opts.expiresIn, "sec"),
						},
					);
					if (opts.sendOTP) {
						await ctx.context.runInBackgroundOrAwait(
							opts.sendOTP(
								{
									phoneNumber,
									code: otp,
								},
								ctx,
							),
						);
					}
					throw APIError.from(
						"UNAUTHORIZED",
						PHONE_NUMBER_ERROR_CODES.PHONE_NUMBER_NOT_VERIFIED,
					);
				}
			}
			const accounts = await ctx.context.internalAdapter.findAccountByUserId(
				user.id,
			);
			const credentialAccount = accounts.find(
				(a) => a.providerId === "credential",
			);
			if (!credentialAccount) {
				ctx.context.logger.warn("Credential account not found");
				throw APIError.from(
					"UNAUTHORIZED",
					PHONE_NUMBER_ERROR_CODES.INVALID_PHONE_NUMBER_OR_PASSWORD,
				);
			}
			const currentPassword = credentialAccount?.password;
			if (!currentPassword) {
				ctx.context.logger.warn("Password not found");
				throw APIError.from(
					"UNAUTHORIZED",
					PHONE_NUMBER_ERROR_CODES.UNEXPECTED_ERROR,
				);
			}
			const validPassword = await verifyPasswordForSignIn(
				ctx,
				credentialAccount,
				password,
			);
			if (!validPassword) {
				ctx.context.logger.warn("Invalid password");
				throw APIError.from(
					"UNAUTHORIZED",
					PHONE_NUMBER_ERROR_CODES.INVALID_PHONE_NUMBER_OR_PASSWORD,
				);
			}
			const session = await ctx.context.internalAdapter.createSession(
				user.id,
				ctx.body.rememberMe === false,
				undefined,
				false,
				createInternalSessionIssuanceContext({
					purpose: "interactive",
					subjectId: user.id,
					evidence: [{ kind: "primary", primaryMethod: "password" }],
				}),
			);
			if (!session) {
				ctx.context.logger.error("Failed to create session");
				throw APIError.from(
					"UNAUTHORIZED",
					BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
				);
			}

			await setSessionCookie(
				ctx,
				{
					session,
					user: user,
				},
				ctx.body.rememberMe === false,
			);
			return ctx.json({
				token: session.token,
				user: parseUserOutput(ctx.context.options, user),
			});
		},
	);

const sendPhoneNumberOTPBodySchema = z.object({
	phoneNumber: z.string().meta({
		description: 'Phone number to send OTP. Eg: "+1234567890"',
	}),
});

/**
 * ### Endpoint
 *
 * POST `/phone-number/send-otp`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.sendPhoneNumberOTP`
 *
 * **client:**
 * `authClient.phoneNumber.sendOtp`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const sendPhoneNumberOTP = (opts: RequiredPhoneNumberOptions) =>
	createAuthEndpoint(
		"/phone-number/send-otp",
		{
			method: "POST",
			body: sendPhoneNumberOTPBodySchema,
			metadata: {
				openapi: {
					summary: "Send OTP to phone number",
					description: "Use this endpoint to send OTP to phone number",
					responses: {
						200: {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											message: {
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
			if (!opts?.sendOTP) {
				ctx.context.logger.warn("sendOTP not implemented");
				throw APIError.from(
					"NOT_IMPLEMENTED",
					PHONE_NUMBER_ERROR_CODES.SEND_OTP_NOT_IMPLEMENTED,
				);
			}

			if (opts.phoneNumberValidator) {
				const isValidNumber = await opts.phoneNumberValidator(
					ctx.body.phoneNumber,
				);
				if (!isValidNumber) {
					throw APIError.from(
						"BAD_REQUEST",
						PHONE_NUMBER_ERROR_CODES.INVALID_PHONE_NUMBER,
					);
				}
			}

			const code = generateOTP(opts.otpLength);
			const challenge = phoneNumberChallenge(
				"phone-number:verify",
				ctx.body.phoneNumber,
			);
			await createInternalVerificationChallenge(
				ctx.context.internalAdapter,
				challenge,
				{
					value: `${code}:0`,
					identifier: challenge.identifier,
					expiresAt: getDate(opts.expiresIn, "sec"),
				},
			);
			const sendOTPResult = opts.sendOTP(
				{
					phoneNumber: ctx.body.phoneNumber,
					code,
				},
				ctx,
			);
			if (
				ctx.context.options.advanced?.backgroundTasks?.handler &&
				sendOTPResult instanceof Promise
			) {
				try {
					ctx.context.runInBackground(
						sendOTPResult.catch((e) => {
							ctx.context.logger.error("Failed to run background task:", e);
						}),
					);
				} catch (e) {
					ctx.context.logger.error("Failed to run background task:", e);
				}
			} else {
				await sendOTPResult;
			}
			return ctx.json({ message: "code sent" });
		},
	);

const verifyPhoneNumberBodySchema = z
	.object({
		/**
		 * Phone number
		 */
		phoneNumber: z.string().meta({
			description: 'Phone number to verify. Eg: "+1234567890"',
		}),
		/**
		 * OTP code
		 */
		code: z.string().meta({
			description: 'OTP code. Eg: "123456"',
		}),
		/**
		 * Disable session creation after verification
		 * @default false
		 */
		disableSession: z
			.boolean()
			.meta({
				description: "Disable session creation after verification. Eg: false",
			})
			.optional(),
		/**
		 * This checks if there is a session already
		 * and updates the phone number with the provided
		 * phone number
		 */
		updatePhoneNumber: z
			.boolean()
			.meta({
				description:
					"Check if there is a session and update the phone number. Eg: true",
			})
			.optional(),
	})
	.and(z.record(z.string(), z.any()));

/**
 * ### Endpoint
 *
 * POST `/phone-number/verify`
 *
 * ### API Methods
 *
 * **server:**
 * `auth.api.verifyPhoneNumber`
 *
 * **client:**
 * `authClient.phoneNumber.verify`
 *
 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
 */
export const verifyPhoneNumber = (opts: RequiredPhoneNumberOptions) =>
	createAuthEndpoint(
		"/phone-number/verify",
		{
			method: "POST",
			body: verifyPhoneNumberBodySchema,
			metadata: {
				openapi: {
					summary: "Verify phone number",
					description: "Use this endpoint to verify phone number",
					responses: {
						"200": {
							description: "Phone number verified successfully",
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
													"Session token if session is created, null if disableSession is true or no session is created",
											},
											user: {
												type: "object",
												nullable: true,
												properties: {
													id: {
														type: "string",
														description: "Unique identifier of the user",
													},
													email: {
														type: "string",
														format: "email",
														nullable: true,
														description: "User's email address",
													},
													emailVerified: {
														type: "boolean",
														nullable: true,
														description: "Whether the email is verified",
													},
													name: {
														type: "string",
														nullable: true,
														description: "User's name",
													},
													image: {
														type: "string",
														format: "uri",
														nullable: true,
														description: "User's profile image URL",
													},
													phoneNumber: {
														type: "string",
														description: "User's phone number",
													},
													phoneNumberVerified: {
														type: "boolean",
														description: "Whether the phone number is verified",
													},
													createdAt: {
														type: "string",
														format: "date-time",
														description: "Timestamp when the user was created",
													},
													updatedAt: {
														type: "string",
														format: "date-time",
														description:
															"Timestamp when the user was last updated",
													},
												},
												required: [
													"id",
													"phoneNumber",
													"phoneNumberVerified",
													"createdAt",
													"updatedAt",
												],
												description:
													"User object with phone number details, null if no user is created or found",
											},
										},
										required: ["status"],
									},
								},
							},
						},
						400: {
							description: "Invalid OTP",
						},
					},
				},
			},
			},
			async (ctx) => {
				const managed = requireManagedAuthenticationTransaction(ctx);
				let managedCustomChallengeId: string | undefined;

				if (opts?.verifyOTP) {
					if (managed) {
					const challenge =
						await ctx.context.internalAdapter.findVerificationValue(
							ctx.body.phoneNumber,
						);
					if (!challenge || challenge.expiresAt <= new Date()) {
						throw APIError.from(
							"BAD_REQUEST",
							PHONE_NUMBER_ERROR_CODES.OTP_NOT_FOUND,
						);
					}
					managedCustomChallengeId = challenge.id;
				}
				const isValid = await opts.verifyOTP(
					{
						phoneNumber: ctx.body.phoneNumber,
						code: ctx.body.code,
					},
					ctx,
				);
				if (!isValid) {
					throw APIError.from(
						"BAD_REQUEST",
						PHONE_NUMBER_ERROR_CODES.INVALID_OTP,
					);
				}
					if (!managed) {
					const otp = await ctx.context.internalAdapter.findVerificationValue(
						ctx.body.phoneNumber,
					);
					if (otp) {
						await ctx.context.internalAdapter.deleteVerificationByIdentifier(
							ctx.body.phoneNumber,
						);
					}
				}
				} else if (!managed) {
				await verifyPhoneNumberOTP(
					ctx,
					opts,
					phoneNumberChallenge(
						"phone-number:verify",
						ctx.body.phoneNumber,
					),
					ctx.body.code,
				);
			}

				const result = await runManagedAuthenticationTransaction(ctx, async () => {
					if (managed) {
					if (managedCustomChallengeId) {
						const consumed = await consumeInternalVerificationChallenge(
							ctx.context.internalAdapter,
							phoneNumberChallenge(
								"phone-number:verify",
								ctx.body.phoneNumber,
							),
						);
						if (
							!consumed ||
							consumed.id !== managedCustomChallengeId
						) {
							throw APIError.from(
								"BAD_REQUEST",
								PHONE_NUMBER_ERROR_CODES.INVALID_OTP,
							);
						}
					} else {
						try {
							await verifyPhoneNumberOTP(
								ctx,
								opts,
								phoneNumberChallenge(
									"phone-number:verify",
									ctx.body.phoneNumber,
								),
								ctx.body.code,
							);
						} catch (verificationError) {
							return { verificationError };
						}
					}
					}

					const transactionAdapter = await getCurrentAdapter(ctx.context.adapter);
					if (ctx.body.updatePhoneNumber) {
						const currentSession = await getSessionFromCtx(ctx);
						if (!currentSession) {
							throw APIError.from(
								"UNAUTHORIZED",
								BASE_ERROR_CODES.USER_NOT_FOUND,
							);
						}
						const existingUser =
							await transactionAdapter.findMany<UserWithPhoneNumber>({
								model: "user",
								where: [
									{
										field: opts.phoneNumber,
										value: ctx.body.phoneNumber,
									},
								],
							});
						if (existingUser.length) {
							throw APIError.from(
								"BAD_REQUEST",
								PHONE_NUMBER_ERROR_CODES.PHONE_NUMBER_EXIST,
							);
						}
						const user =
							await ctx.context.internalAdapter.updateUser<UserWithPhoneNumber>(
								currentSession.user.id,
								{
									[opts.phoneNumber]: ctx.body.phoneNumber,
									[opts.phoneNumberVerified]: true,
								},
							);
						if (!user) {
							throw APIError.from(
								"INTERNAL_SERVER_ERROR",
								BASE_ERROR_CODES.FAILED_TO_UPDATE_USER,
							);
						}
						if (!managed) {
							await opts?.callbackOnVerification?.(
								{ phoneNumber: ctx.body.phoneNumber, user },
								ctx,
							);
						}
						return { user, session: null, currentSession };
					}
					let user = await transactionAdapter.findOne<UserWithPhoneNumber>({
					model: "user",
					where: [
						{ value: ctx.body.phoneNumber, field: opts.phoneNumber },
					],
				});
				const creatingUser = !user && Boolean(opts?.signUpOnVerification);
				if (!user && opts?.signUpOnVerification) {
					const {
						phoneNumber,
						code,
						disableSession,
						updatePhoneNumber,
						...rest
					} = ctx.body;
					const additionalFields = parseUserInput(
						ctx.context.options,
						rest,
						"create",
					);
					user =
						await ctx.context.internalAdapter.createUser<UserWithPhoneNumber>({
							...additionalFields,
							email: opts.signUpOnVerification.getTempEmail(
								ctx.body.phoneNumber,
							),
							name: opts.signUpOnVerification.getTempName
								? opts.signUpOnVerification.getTempName(ctx.body.phoneNumber)
								: ctx.body.phoneNumber,
							[opts.phoneNumber]: ctx.body.phoneNumber,
							[opts.phoneNumberVerified]: true,
						});
				} else if (user) {
					user =
						await ctx.context.internalAdapter.updateUser<UserWithPhoneNumber>(
							user.id,
							{ [opts.phoneNumberVerified]: true },
						);
				}
				if (!user) {
					throw APIError.from(
						"INTERNAL_SERVER_ERROR",
						creatingUser
							? BASE_ERROR_CODES.FAILED_TO_CREATE_USER
							: BASE_ERROR_CODES.FAILED_TO_UPDATE_USER,
					);
				}
					if (!managed) {
					await opts?.callbackOnVerification?.(
						{ phoneNumber: ctx.body.phoneNumber, user },
						ctx,
					);
				}
					if (ctx.body.disableSession) {
						return { user, session: null, currentSession: null };
					}
				const session = await ctx.context.internalAdapter.createSession(
					user.id,
					undefined,
					undefined,
					false,
					createInternalSessionIssuanceContext({
						purpose: "interactive",
						subjectId: user.id,
						evidence: [{ kind: "primary", primaryMethod: "phone_otp" }],
					}),
				);
				if (!session) {
					throw APIError.from(
						"INTERNAL_SERVER_ERROR",
						BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
					);
				}
					return { user, session, currentSession: null };
				});
				if ("verificationError" in result) throw result.verificationError;
				const { currentSession, session, user } = result;
				if (managed) {
				try {
					await opts?.callbackOnVerification?.(
						{ phoneNumber: ctx.body.phoneNumber, user },
						ctx,
					);
				} catch {
					ctx.context.logger.error(
						"Managed phone verification post-commit callback failed",
					);
					}
				}
				if (currentSession) {
					return ctx.json({
						status: true,
						token: currentSession.session.token,
						user: parseUserOutput(ctx.context.options, user),
					});
				}

			if (session) {
				await setSessionCookie(ctx, {
					session,
					user,
				});
				return ctx.json({
					status: true,
					token: session.token,
					user: parseUserOutput(ctx.context.options, user),
				});
			}

			return ctx.json({
				status: true,
				token: null,
				user: parseUserOutput(ctx.context.options, user),
			});
		},
	);

const requestPasswordResetPhoneNumberBodySchema = z.object({
	phoneNumber: z.string(),
});

export const requestPasswordResetPhoneNumber = (
	opts: RequiredPhoneNumberOptions,
) =>
	createAuthEndpoint(
		"/phone-number/request-password-reset",
		{
			method: "POST",
			body: requestPasswordResetPhoneNumberBodySchema,
			metadata: {
				openapi: {
					description: "Request OTP for password reset via phone number",
					responses: {
						"200": {
							description: "OTP sent successfully for password reset",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											status: {
												type: "boolean",
												description:
													"Indicates if the OTP was sent successfully",
												enum: [true],
											},
										},
										required: ["status"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const user = await ctx.context.adapter.findOne<UserWithPhoneNumber>({
				model: "user",
				where: [
					{
						value: ctx.body.phoneNumber,
						field: opts.phoneNumber,
					},
				],
			});
			const code = generateOTP(opts.otpLength);
			const challenge = phoneNumberChallenge(
				"phone-number:password-reset",
				ctx.body.phoneNumber,
				`${ctx.body.phoneNumber}-request-password-reset`,
			);
			await createInternalVerificationChallenge(
				ctx.context.internalAdapter,
				challenge,
				{
					value: `${code}:0`,
					identifier: challenge.identifier,
					expiresAt: getDate(opts.expiresIn, "sec"),
				},
			);
			// to avoid leaking the existence of the phone number
			if (!user) {
				return ctx.json({
					status: true,
				});
			}
			if (opts.sendPasswordResetOTP) {
				await ctx.context.runInBackgroundOrAwait(
					opts.sendPasswordResetOTP(
						{
							phoneNumber: ctx.body.phoneNumber,
							code,
						},
						ctx,
					),
				);
			}
			return ctx.json({
				status: true,
			});
		},
	);

const resetPasswordPhoneNumberBodySchema = z.object({
	otp: z.string().meta({
		description: 'The one time password to reset the password. Eg: "123456"',
	}),
	phoneNumber: z.string().meta({
		description:
			'The phone number to the account which intends to reset the password for. Eg: "+1234567890"',
	}),
	newPassword: z.string().meta({
		description: `The new password. Eg: "new-and-secure-password"`,
	}),
});

export const resetPasswordPhoneNumber = (opts: RequiredPhoneNumberOptions) =>
	createAuthEndpoint(
		"/phone-number/reset-password",
		{
			method: "POST",
			body: resetPasswordPhoneNumberBodySchema,
			metadata: {
				openapi: {
					description: "Reset password using phone number OTP",
					responses: {
						"200": {
							description: "Password reset successfully",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											status: {
												type: "boolean",
												description:
													"Indicates if the password was reset successfully",
												enum: [true],
											},
										},
										required: ["status"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const phoneResetIdentifier = `${ctx.body.phoneNumber}-request-password-reset`;
			const managed = requireManagedAuthenticationTransaction(ctx);
			const result = await runManagedAuthenticationTransaction(ctx, async () => {
				try {
					await verifyPhoneNumberOTP(
						ctx,
						opts,
						phoneNumberChallenge(
							"phone-number:password-reset",
							ctx.body.phoneNumber,
							phoneResetIdentifier,
						),
						ctx.body.otp,
					);
				} catch (verificationError) {
					return { verificationError };
				}
				const transactionAdapter = await getCurrentAdapter(ctx.context.adapter);
				const userRes = await transactionAdapter.findOne<
					UserWithPhoneNumber & { account: Account[] | undefined }
				>({
					model: "user",
					where: [
						{ field: opts.phoneNumber, value: ctx.body.phoneNumber },
					],
					join: { account: true },
				});
				if (!userRes) {
					throw APIError.from(
						"BAD_REQUEST",
						PHONE_NUMBER_ERROR_CODES.UNEXPECTED_ERROR,
					);
				}
				const { account: accounts = [], ...user } = userRes;
				const minLength = ctx.context.password.config.minPasswordLength;
				const maxLength = ctx.context.password.config.maxPasswordLength;
				if (ctx.body.newPassword.length < minLength) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.PASSWORD_TOO_SHORT);
				}
				if (ctx.body.newPassword.length > maxLength) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.PASSWORD_TOO_LONG);
				}
				const hashedPassword = await ctx.context.password.hash(
					ctx.body.newPassword,
				);
				const account = accounts.find(
					(account) => account.providerId === "credential",
				);
				if (!account) {
					await ctx.context.internalAdapter.createAccount({
						userId: user.id,
						providerId: "credential",
						accountId: user.id,
						password: hashedPassword,
					});
				} else {
					await ctx.context.internalAdapter.updatePassword(
						user.id,
						hashedPassword,
					);
				}
				if (!managed && ctx.context.options.emailAndPassword?.onPasswordReset) {
					await ctx.context.options.emailAndPassword.onPasswordReset(
						{ user },
						ctx.request,
					);
				}
				if (ctx.context.options.emailAndPassword?.revokeSessionsOnPasswordReset) {
					await ctx.context.internalAdapter.deleteUserSessions(user.id);
				}
				return { user };
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
				status: true,
			});
		},
	);

/**
 * Atomically verifies a phone-number OTP against a stored verification value.
 *
 * Consuming the row is the race gate: the first concurrent caller wins the
 * row, every racer behind it gets `null` and is rejected, so the same code can
 * never satisfy two simultaneous verifications. On a wrong code that is still
 * within the attempt budget, the row is recreated with the same value and
 * expiry and an incremented attempt counter. Once the budget is exhausted the
 * row is not recreated.
 */
async function verifyPhoneNumberOTP(
	ctx: GenericEndpointContext,
	opts: RequiredPhoneNumberOptions,
	challenge: ReturnType<typeof phoneNumberChallenge>,
	providedCode: string,
): Promise<void> {
	const { identifier } = challenge;
	const existing =
		await ctx.context.internalAdapter.findVerificationValue(identifier);
	if (!existing) {
		throw APIError.from("BAD_REQUEST", PHONE_NUMBER_ERROR_CODES.OTP_NOT_FOUND);
	}
	if (existing.expiresAt < new Date()) {
		await ctx.context.internalAdapter.deleteVerificationByIdentifier(
			identifier,
		);
		throw APIError.from("BAD_REQUEST", PHONE_NUMBER_ERROR_CODES.OTP_EXPIRED);
	}

	const allowedAttempts = opts?.allowedAttempts || 3;
	const [, peekedAttempts] = existing.value.split(":");
	if (peekedAttempts && parseInt(peekedAttempts) >= allowedAttempts) {
		await ctx.context.internalAdapter.deleteVerificationByIdentifier(
			identifier,
		);
		throw APIError.from(
			"FORBIDDEN",
			PHONE_NUMBER_ERROR_CODES.TOO_MANY_ATTEMPTS,
		);
	}

	const consumed = await consumeInternalVerificationChallenge(
		ctx.context.internalAdapter,
		challenge,
	);
	if (!consumed) {
		throw APIError.from("BAD_REQUEST", PHONE_NUMBER_ERROR_CODES.INVALID_OTP);
	}

	const [otpValue, attempts] = consumed.value.split(":");
	if (attempts && parseInt(attempts) >= allowedAttempts) {
		throw APIError.from(
			"FORBIDDEN",
			PHONE_NUMBER_ERROR_CODES.TOO_MANY_ATTEMPTS,
		);
	}
	if (otpValue !== providedCode) {
		await createInternalVerificationChallenge(
			ctx.context.internalAdapter,
			challenge,
			{
				value: `${otpValue}:${parseInt(attempts || "0") + 1}`,
				identifier,
				expiresAt: consumed.expiresAt,
			},
		);
		throw APIError.from("BAD_REQUEST", PHONE_NUMBER_ERROR_CODES.INVALID_OTP);
	}
}

function generateOTP(size: number) {
	return generateRandomString(size, "0-9");
}
