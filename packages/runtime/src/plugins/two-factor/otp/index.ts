import type { Awaitable, GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import {
	getCurrentAdapter,
	queueAfterTransactionHook,
} from "@clearance/core/context";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import * as z from "zod";
import { setSessionCookie } from "../../../cookies";
import {
	constantTimeEqual,
	generateRandomString,
	symmetricDecrypt,
	symmetricEncrypt,
} from "../../../crypto";
import { parseUserOutput } from "../../../db/schema";
import {
	runManagedAuthenticationTransaction,
	usesManagedAuthenticationPolicy,
} from "../../../internal/managed-authentication-transaction";
import {
	captureInternalSessionIssuanceContext,
} from "../../../internal/session-issuance-context";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../../internal/verification-challenge-context";
import { PACKAGE_VERSION } from "../../../version";
import { TWO_FACTOR_ERROR_CODES } from "../error-code";
import type {
	TwoFactorProvider,
	TwoFactorTable,
	UserWithTwoFactor,
} from "../types";
import { defaultKeyHasher, TWO_FACTOR_CHALLENGE_PURPOSE } from "../utils";
import {
	assertTwoFactorNotLocked,
	reserveTwoFactorAttempt,
	verifyTwoFactor,
} from "../verify-two-factor";

export interface OTPOptions {
	/**
	 * How long the opt will be valid for in
	 * minutes
	 *
	 * @default "3 mins"
	 */
	period?: number | undefined;
	/**
	 * Number of digits for the OTP code
	 *
	 * @default 6
	 */
	digits?: number | undefined;
	/**
	 * Send the otp to the user
	 *
	 * @param user - The user to send the otp to
	 * @param otp - The otp to send
	 * @param request - The request object
	 * @returns void | Promise<void>
	 */
	sendOTP?:
		| ((
				/**
				 * The user to send the otp to
				 * @type UserWithTwoFactor
				 * @default UserWithTwoFactors
				 */
				data: {
					user: UserWithTwoFactor;
					otp: string;
				},
				/**
				 * The request object
				 */
				ctx?: GenericEndpointContext,
		  ) => Awaitable<void>)
		| undefined;
	/**
	 * The number of allowed attempts for the OTP
	 *
	 * @default 5
	 */
	allowedAttempts?: number | undefined;
	storeOTP?:
		| (
				| "plain"
				| "encrypted"
				| "hashed"
				| { hash: (token: string) => Promise<string> }
				| {
						encrypt: (token: string) => Promise<string>;
						decrypt: (token: string) => Promise<string>;
				  }
		  )
		| undefined;
}

const verifyOTPBodySchema = z.object({
	code: z.string().meta({
		description: 'The otp code to verify. Eg: "012345"',
	}),
	/**
	 * if true, the device will be trusted
	 * for 30 days. It'll be refreshed on
	 * every sign in request within this time.
	 */
	trustDevice: z.boolean().optional().meta({
		description:
			"If true, the device will be trusted for 30 days. It'll be refreshed on every sign in request within this time. Eg: true",
	}),
});

const send2FaOTPBodySchema = z
	.object({
		/**
		 * if true, the device will be trusted
		 * for 30 days. It'll be refreshed on
		 * every sign in request within this time.
		 */
		trustDevice: z.boolean().optional().meta({
			description:
				"If true, the device will be trusted for 30 days. It'll be refreshed on every sign in request within this time. Eg: true",
		}),
	})
	.optional();

/**
 * The otp adapter is created from the totp adapter.
 */
export const otp2fa = (options?: OTPOptions | undefined) => {
	const opts = {
		storeOTP: "plain",
		digits: 6,
		...options,
		period: (options?.period || 3) * 60 * 1000,
	};

	async function storeOTP(ctx: GenericEndpointContext, otp: string) {
		if (opts.storeOTP === "hashed") {
			return await defaultKeyHasher(otp);
		}
		if (typeof opts.storeOTP === "object" && "hash" in opts.storeOTP) {
			return await opts.storeOTP.hash(otp);
		}
		if (typeof opts.storeOTP === "object" && "encrypt" in opts.storeOTP) {
			return await opts.storeOTP.encrypt(otp);
		}
		if (opts.storeOTP === "encrypted") {
			return await symmetricEncrypt({
				key: ctx.context.secretConfig,
				data: otp,
			});
		}
		return otp;
	}

	async function decryptOrHashForComparison(
		ctx: GenericEndpointContext,
		storedOtp: string,
		userInput: string,
	): Promise<[string, string]> {
		if (opts.storeOTP === "hashed") {
			// For hashed storage: hash the user input and compare with stored hash
			return [storedOtp, await defaultKeyHasher(userInput)];
		}
		if (opts.storeOTP === "encrypted") {
			// For encrypted storage: decrypt stored value and compare with plain input
			const decrypted = await symmetricDecrypt({
				key: ctx.context.secretConfig,
				data: storedOtp,
			});
			return [decrypted, userInput];
		}
		if (typeof opts.storeOTP === "object" && "encrypt" in opts.storeOTP) {
			const decrypted = await opts.storeOTP.decrypt(storedOtp);
			return [decrypted, userInput];
		}
		if (typeof opts.storeOTP === "object" && "hash" in opts.storeOTP) {
			// For custom hash: hash the user input and compare with stored hash
			return [storedOtp, await opts.storeOTP.hash(userInput)];
		}
		// Plain storage: compare directly
		return [storedOtp, userInput];
	}

	/**
	 * Generate OTP and send it to the user.
	 */
	const send2FaOTP = createAuthEndpoint(
		"/two-factor/send-otp",
		{
			method: "POST",
			body: send2FaOTPBodySchema,
			metadata: {
				openapi: {
					summary: "Send two factor OTP",
					description: "Send two factor OTP to the user",
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
			if (!options || !options.sendOTP) {
				ctx.context.logger.error(
					"send otp isn't configured. Please configure the send otp function on otp options.",
				);
				throw APIError.from("BAD_REQUEST", {
					message: "otp isn't configured",
					code: "OTP_NOT_CONFIGURED",
				});
			}
			const { session, key } = await verifyTwoFactor(ctx);
			const code = generateRandomString(opts.digits, "0-9");
			const hashedCode = await storeOTP(ctx, code);
			await createInternalVerificationChallenge(
				ctx.context.internalAdapter,
				{
					purpose: TWO_FACTOR_CHALLENGE_PURPOSE.otp,
					subject: session.user.id,
				},
				{
					value: `${hashedCode}:0`,
					identifier: `2fa-otp-${key}`,
					expiresAt: new Date(Date.now() + opts.period),
				},
			);
			const sendOTPResult = options.sendOTP(
				{ user: session.user as UserWithTwoFactor, otp: code },
				ctx,
			);
			if (sendOTPResult instanceof Promise) {
				await ctx.context.runInBackgroundOrAwait(
					sendOTPResult.catch((e: unknown) => {
						ctx.context.logger.error("Failed to send two-factor OTP", e);
					}),
				);
			}
			return ctx.json({ status: true });
		},
	);

	const verifyOTP = createAuthEndpoint(
		"/two-factor/verify-otp",
		{
			method: "POST",
			body: verifyOTPBodySchema,
			metadata: {
				openapi: {
					summary: "Verify two factor OTP",
					description: "Verify two factor OTP",
					responses: {
						"200": {
							description: "Two-factor OTP verified successfully",
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
												type: "object",
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
												required: ["id", "createdAt", "updatedAt"],
												description: "The authenticated user object",
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
			const { session, key, valid, invalid } = await verifyTwoFactor(ctx);
			const managed = usesManagedAuthenticationPolicy(ctx);
			const isSignIn = !session.session;
			const twoFactorTable = "twoFactor";
			const identifier = `2fa-otp-${key}`;
			const outcome = await runManagedAuthenticationTransaction(ctx, async () => {
				const adapter = await getCurrentAdapter(ctx.context.adapter);
				// Account-level lockout shares one counter across all factors. In
				// managed mode the reservation, OTP consume, and authorized mutation
				// all use this same primary transaction.
				let twoFactor: TwoFactorTable | null = null;
				if (isSignIn) {
					twoFactor = await adapter.findOne<TwoFactorTable>({
						model: twoFactorTable,
						where: [{ field: "userId", value: session.user.id }],
					});
					if (!twoFactor) {
						return { kind: "not-enabled" as const };
					}
					await assertTwoFactorNotLocked(
						ctx,
						twoFactorTable,
						twoFactor,
						adapter,
					);
				}

				const consumed = await consumeInternalVerificationChallenge(
					ctx.context.internalAdapter,
					{
						purpose: TWO_FACTOR_CHALLENGE_PURPOSE.otp,
						subject: session.user.id,
						identifier,
					},
				);
				if (!consumed) return { kind: "expired" as const };

				const [otp, counter] = consumed.value?.split(":") ?? [];
				const allowedAttempts = options?.allowedAttempts || 5;
				const attempts = parseInt(counter!, 10) || 0;
				if (attempts >= allowedAttempts) {
					// Returning commits the terminal consume before the API error is
					// raised outside the transaction.
					return { kind: "spent" as const };
				}
				const accountAttempt = twoFactor
					? await reserveTwoFactorAttempt(
							ctx,
							twoFactorTable,
							twoFactor,
							adapter,
						)
					: null;
				let storedValue: string;
				let inputValue: string;
				try {
					[storedValue, inputValue] = await decryptOrHashForComparison(
						ctx,
						otp!,
						ctx.body.code,
					);
				} catch (error) {
					await accountAttempt?.restore();
					await createInternalVerificationChallenge(
						ctx.context.internalAdapter,
						{
							purpose: TWO_FACTOR_CHALLENGE_PURPOSE.otp,
							subject: session.user.id,
						},
						{
							value: consumed.value,
							identifier,
							expiresAt: consumed.expiresAt,
						},
					);
					return { kind: "internal-error" as const, error };
				}
				const isCodeValid = constantTimeEqual(
					new TextEncoder().encode(storedValue),
					new TextEncoder().encode(inputValue),
				);
				if (!isCodeValid) {
					await accountAttempt?.recordFailure();
					await createInternalVerificationChallenge(
						ctx.context.internalAdapter,
						{
							purpose: TWO_FACTOR_CHALLENGE_PURPOSE.otp,
							subject: session.user.id,
						},
						{
							value: `${otp}:${attempts + 1}`,
							identifier,
							expiresAt: consumed.expiresAt,
						},
					);
					return { kind: "invalid" as const };
				}

				await accountAttempt?.recordSuccess();
				// Leave the OTP consumed: a valid code is single-use.
				if (!session.user.twoFactorEnabled) {
					if (!session.session) return { kind: "session-missing" as const };
					const replacementIssuanceContext =
						await captureInternalSessionIssuanceContext(
							ctx.context.internalAdapter,
							{
								purpose: "replacement",
								sourceSessionToken: session.session.token,
							},
						);
					const updatedUser = await ctx.context.internalAdapter.updateUser(
						session.user.id,
						{ twoFactorEnabled: true },
					);
					const newSession = await ctx.context.internalAdapter.createSession(
						session.user.id,
						false,
						session.session,
						false,
						replacementIssuanceContext,
					);
					await ctx.context.internalAdapter.deleteSession(
						session.session.token,
					);
					const publishSessionCookie = () =>
						setSessionCookie(ctx, {
							session: newSession,
							user: updatedUser,
						});
					if (managed) {
						await queueAfterTransactionHook(
							publishSessionCookie,
							ctx.context.adapter,
						);
					} else {
						await publishSessionCookie();
					}
					return { kind: "enabled" as const, newSession, updatedUser };
				}
				return { kind: "verified" as const, response: await valid(ctx) };
			});

			if (outcome.kind === "not-enabled") {
				throw APIError.from(
					"BAD_REQUEST",
					TWO_FACTOR_ERROR_CODES.TWO_FACTOR_NOT_ENABLED,
				);
			}
			if (outcome.kind === "expired") {
				throw APIError.from(
					"BAD_REQUEST",
					TWO_FACTOR_ERROR_CODES.OTP_HAS_EXPIRED,
				);
			}
			if (outcome.kind === "spent") {
				throw APIError.from(
					"BAD_REQUEST",
					TWO_FACTOR_ERROR_CODES.TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE,
				);
			}
			if (outcome.kind === "internal-error") throw outcome.error;
			if (outcome.kind === "invalid") return invalid("INVALID_CODE");
			if (outcome.kind === "session-missing") {
				throw APIError.from(
					"BAD_REQUEST",
					BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION,
				);
			}
			if (outcome.kind === "enabled") {
				return ctx.json({
					token: outcome.newSession.token,
					user: parseUserOutput(ctx.context.options, outcome.updatedUser),
				});
			}
			return outcome.response;
		},
	);

	return {
		id: "otp",
		version: PACKAGE_VERSION,
		endpoints: {
			/**
			 * ### Endpoint
			 *
			 * POST `/two-factor/send-otp`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.sendTwoFactorOTP`
			 *
			 * **client:**
			 * `authClient.twoFactor.sendOtp`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			sendTwoFactorOTP: send2FaOTP,
			/**
			 * ### Endpoint
			 *
			 * POST `/two-factor/verify-otp`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.verifyTwoFactorOTP`
			 *
			 * **client:**
			 * `authClient.twoFactor.verifyOtp`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			verifyTwoFactorOTP: verifyOTP,
		},
	} satisfies TwoFactorProvider;
};
