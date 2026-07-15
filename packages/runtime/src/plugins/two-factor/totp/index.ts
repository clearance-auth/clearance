import { createAuthEndpoint } from "@clearance/core/api";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import { createOTP } from "@clearance/utils/otp";
import * as z from "zod";
import { sessionMiddleware } from "../../../api";
import { expireCookie, setSessionCookie } from "../../../cookies";
import { symmetricDecrypt } from "../../../crypto";
import { generateRandomString } from "../../../crypto/random";
import { parseUserOutput } from "../../../db/schema";
import { shouldRequirePassword } from "../../../utils/password";
import { PACKAGE_VERSION } from "../../../version";
import type { BackupCodeOptions } from "../backup-codes";
import {
	DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS,
	TRUST_DEVICE_COOKIE_MAX_AGE,
	TRUST_DEVICE_COOKIE_NAME,
} from "../constant";
import { TWO_FACTOR_ERROR_CODES } from "../error-code";
import type {
	TwoFactorProvider,
	TwoFactorTable,
	UserWithTwoFactor,
} from "../types";
import { preserveSessionLifetime, revokeTrustGeneration } from "../utils";
import {
	assertTwoFactorNotLocked,
	consumeTotpCounter,
	reserveTwoFactorAttempt,
	resetTwoFactorFailures,
	verifyTwoFactor,
} from "../verify-two-factor";

export type TOTPOptions = {
	/**
	 * Issuer
	 */
	issuer?: string | undefined;
	/**
	 * How many digits the otp to be
	 *
	 * @default 6
	 */
	digits?: (6 | 8) | undefined;
	/**
	 * Period for otp in seconds.
	 * @default 30
	 */
	period?: number | undefined;
	/**
	 * Backup codes configuration
	 */
	backupCodes?: BackupCodeOptions | undefined;
	/**
	 * Allow retrieving the TOTP URI without a password when the user does not
	 * have a credential account.
	 * When enabled, password is still required if a credential account exists.
	 * @default false
	 */
	allowPasswordless?: boolean | undefined;
	/**
	 * Disable totp
	 */
	disable?: boolean | undefined;
};

const generateTOTPBodySchema = z.object({
	secret: z.string().meta({
		description: "The secret to generate the TOTP code",
	}),
});

const verifyTOTPBodySchema = z.object({
	code: z.string().meta({
		description: 'The otp code to verify. Eg: "012345"',
	}),
	/**
	 * if true, the device will be trusted
	 * for 30 days. It'll be refreshed on
	 * every sign in request within this time.
	 */
	trustDevice: z
		.boolean()
		.meta({
			description:
				"If true, the device will be trusted for 30 days. It'll be refreshed on every sign in request within this time. Eg: true",
		})
		.optional(),
});

export const totp2fa = (options?: TOTPOptions | undefined) => {
	const opts = {
		...options,
		digits: options?.digits || 6,
		period: options?.period || 30,
	};
	const passwordSchema = z.string().meta({
		description: "User password",
	});
	const getTOTPURIBodySchema = options?.allowPasswordless
		? z.object({
				password: passwordSchema.optional(),
			})
		: z.object({
				password: passwordSchema,
			});

	const twoFactorTable = "twoFactor";

	const generateTOTP = createAuthEndpoint.serverOnly(
		{
			method: "POST",
			body: generateTOTPBodySchema,
			metadata: {
				openapi: {
					summary: "Generate TOTP code",
					description: "Use this endpoint to generate a TOTP code",
					responses: {
						200: {
							description: "Successful response",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											code: {
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
			if (options?.disable) {
				ctx.context.logger.error(
					"totp isn't configured. please pass totp option on two factor plugin to enable totp",
				);
				throw APIError.from("BAD_REQUEST", {
					message: "totp isn't configured",
					code: "TOTP_NOT_CONFIGURED",
				});
			}
			const code = await createOTP(ctx.body.secret, {
				period: opts.period,
				digits: opts.digits,
			}).totp();
			return { code };
		},
	);

	const getTOTPURI = createAuthEndpoint(
		"/two-factor/get-totp-uri",
		{
			method: "POST",
			use: [sessionMiddleware],
			body: getTOTPURIBodySchema,
			metadata: {
				openapi: {
					summary: "Get TOTP URI",
					description: "Use this endpoint to get the TOTP URI",
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
			if (options?.disable) {
				ctx.context.logger.error(
					"totp isn't configured. please pass totp option on two factor plugin to enable totp",
				);
				throw APIError.from("BAD_REQUEST", {
					message: "totp isn't configured",
					code: "TOTP_NOT_CONFIGURED",
				});
			}
			const user = ctx.context.session.user as UserWithTwoFactor;
			const twoFactor = await ctx.context.adapter.findOne<TwoFactorTable>({
				model: twoFactorTable,
				where: [
					{
						field: "userId",
						value: user.id,
					},
				],
			});
			if (!twoFactor) {
				throw APIError.from(
					"BAD_REQUEST",
					TWO_FACTOR_ERROR_CODES.TOTP_NOT_ENABLED,
				);
			}
			const secret = await symmetricDecrypt({
				key: ctx.context.secretConfig,
				data: twoFactor.secret,
			});
			const requirePassword = await shouldRequirePassword(
				ctx,
				user.id,
				options?.allowPasswordless,
			);
			if (requirePassword) {
				if (!ctx.body.password) {
					throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_PASSWORD);
				}
				await ctx.context.password.checkPassword(user.id, ctx);
			}
			const totpURI = createOTP(secret, {
				digits: opts.digits,
				period: opts.period,
			}).url(options?.issuer || ctx.context.appName, user.email);
			return {
				totpURI,
			};
		},
	);

	const verifyTOTP = createAuthEndpoint(
		"/two-factor/verify-totp",
		{
			method: "POST",
			body: verifyTOTPBodySchema,
			metadata: {
				openapi: {
					summary: "Verify two factor TOTP",
					description: "Verify two factor TOTP",
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
			if (options?.disable) {
				ctx.context.logger.error(
					"totp isn't configured. please pass totp option on two factor plugin to enable totp",
				);
				throw APIError.from("BAD_REQUEST", {
					message: "totp isn't configured",
					code: "TOTP_NOT_CONFIGURED",
				});
			}
			const { session, valid, invalid, beginAttempt } =
				await verifyTwoFactor(ctx);
			const user = session.user as UserWithTwoFactor;
			const isSignIn = !session.session;
			const twoFactor = await ctx.context.adapter.findOne<TwoFactorTable>({
				model: twoFactorTable,
				where: [{ field: "userId", value: user.id }],
			});

			if (!twoFactor) {
				throw APIError.from(
					"BAD_REQUEST",
					TWO_FACTOR_ERROR_CODES.TOTP_NOT_ENABLED,
				);
			}
			// During sign-in, reject explicitly unverified rows (abandoned enrollments).
			// Using === false instead of !twoFactor.verified so that pre-migration rows
			// where the field is absent/null are treated as verified (legacy-safe).
			if (isSignIn && twoFactor.verified === false) {
				throw APIError.from(
					"BAD_REQUEST",
					TWO_FACTOR_ERROR_CODES.TOTP_NOT_ENABLED,
				);
			}
			if (isSignIn) {
				await assertTwoFactorNotLocked(ctx, twoFactorTable, twoFactor);
			}
			// Enforce the per-challenge attempt budget on the sign-in path. The
			// re-verify branch (already authenticated) is not gated.
			const attempt = isSignIn
				? await beginAttempt(DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS)
				: null;
			const accountAttempt = isSignIn
				? await reserveTwoFactorAttempt(ctx, twoFactorTable, twoFactor)
				: null;
			const isPendingReplacement =
				!isSignIn &&
				twoFactor.verified !== false &&
				Boolean(twoFactor.pendingSecret) &&
				Boolean(twoFactor.pendingBackupCodes);
			let matchedCounter: number | null;
			try {
				const decrypted = await symmetricDecrypt({
					key: ctx.context.secretConfig,
					data: isPendingReplacement
						? twoFactor.pendingSecret!
						: twoFactor.secret,
				});
				matchedCounter = await createOTP(decrypted, {
					period: opts.period,
					digits: opts.digits,
				}).verifyWithCounter(ctx.body.code);
			} catch (error) {
				// A server error before the code is checked must not spend the slot.
				await attempt?.restore();
				await accountAttempt?.restore();
				throw error;
			}
			if (matchedCounter === null) {
				await attempt?.recordFailure();
				await accountAttempt?.recordFailure();
				return invalid("INVALID_CODE");
			}
			if (isPendingReplacement) {
				const pendingSecret = twoFactor.pendingSecret!;
				const pendingBackupCodes = twoFactor.pendingBackupCodes!;
				const activeSession = session.session!;
				const replaced = await runWithTransaction(
					ctx.context.adapter,
					async () => {
						const adapter = await getCurrentAdapter(ctx.context.adapter);
						const replaced = await adapter.incrementOne<TwoFactorTable>({
							model: twoFactorTable,
							where: [
								{ field: "id", value: twoFactor.id },
								{ field: "pendingSecret", value: pendingSecret },
								{
									field: "pendingBackupCodes",
									value: pendingBackupCodes,
								},
							],
							increment: {},
							set: {
								secret: pendingSecret,
								backupCodes: pendingBackupCodes,
								pendingSecret: null,
								pendingBackupCodes: null,
								verified: true,
								lastUsedTotpCounter: matchedCounter,
								trustDeviceGeneration: generateRandomString(32),
								failedVerificationCount: 0,
								activeVerificationReservations: "[]",
								lockedUntil: null,
							},
						});
						if (!replaced) {
							throw APIError.fromStatus("CONFLICT", {
								message: "Two-factor state changed. Please try again.",
							});
						}
						if (
							twoFactor.trustDeviceGeneration &&
							(!ctx.context.options.secondaryStorage ||
								ctx.context.options.verification?.storeInDatabase === true)
						) {
							await adapter.deleteMany({
								model: "verification",
								where: [
									{
										field: "value",
										value: `${user.id}!${twoFactor.trustDeviceGeneration}`,
									},
								],
							});
						}
						await revokeTrustGeneration(
							ctx,
							user.id,
							twoFactor.trustDeviceGeneration,
						);
						const updatedUser = await ctx.context.internalAdapter.updateUser(
							user.id,
							{
								twoFactorSessionGeneration: generateRandomString(32),
							},
						);
						await ctx.context.internalAdapter.deleteUserSessions(user.id);
						const replacementSession =
							await ctx.context.internalAdapter.createSession(
								user.id,
								false,
								preserveSessionLifetime(activeSession),
							);
						return { replacementSession, updatedUser };
					},
				);
				await setSessionCookie(ctx, {
					session: replaced.replacementSession,
					user: replaced.updatedUser,
				});
				expireCookie(
					ctx,
					ctx.context.createAuthCookie(TRUST_DEVICE_COOKIE_NAME, {
						maxAge: TRUST_DEVICE_COOKIE_MAX_AGE,
					}),
				);
				return ctx.json({
					token: replaced.replacementSession.token,
					user: parseUserOutput(ctx.context.options, replaced.updatedUser),
				});
			}
			if (
				!(await consumeTotpCounter(
					ctx,
					twoFactorTable,
					twoFactor,
					matchedCounter,
				))
			) {
				await attempt?.restore();
				await accountAttempt?.restore();
				return invalid("INVALID_CODE");
			}
			if (accountAttempt) {
				await accountAttempt.recordSuccess();
			} else {
				await resetTwoFactorFailures(ctx, twoFactorTable, twoFactor);
			}

			// Enrollment mode: TOTP row exists but hasn't been verified yet.
			// This covers fresh TOTP setup (twoFactorEnabled=false),
			// adding TOTP to an OTP-only account (twoFactorEnabled=true),
			// and pre-migration rows where verified is null/undefined.
			const isEnrollmentActivation =
				twoFactor.verified === false ||
				(twoFactor.verified !== true && !user.twoFactorEnabled);
			if (isEnrollmentActivation) {
				const activeSession = session.session!;
				const activated = await runWithTransaction(
					ctx.context.adapter,
					async () => {
						const adapter = await getCurrentAdapter(ctx.context.adapter);
						const factor = await adapter.incrementOne<TwoFactorTable>({
							model: twoFactorTable,
							where: [
								{ field: "id", value: twoFactor.id },
								{ field: "secret", value: twoFactor.secret },
								{
									field: "verified",
									value: twoFactor.verified ?? null,
								},
								{
									field: "lastUsedTotpCounter",
									value: matchedCounter,
								},
							],
							increment: {},
							set: {
								verified: true,
								trustDeviceGeneration: generateRandomString(32),
								failedVerificationCount: 0,
								activeVerificationReservations: "[]",
								lockedUntil: null,
							},
						});
						if (!factor) {
							throw APIError.fromStatus("CONFLICT", {
								message: "Two-factor state changed. Please try again.",
							});
						}
						const updatedUser = await ctx.context.internalAdapter.updateUser(
							user.id,
							{
								twoFactorEnabled: true,
								twoFactorSessionGeneration: generateRandomString(32),
							},
						);
						await ctx.context.internalAdapter.deleteUserSessions(user.id);
						const newSession = await ctx.context.internalAdapter.createSession(
							user.id,
							false,
							preserveSessionLifetime(activeSession),
						);
						return { newSession, updatedUser };
					},
				);
				await setSessionCookie(ctx, {
					session: activated.newSession,
					user: activated.updatedUser,
				});
				expireCookie(
					ctx,
					ctx.context.createAuthCookie(TRUST_DEVICE_COOKIE_NAME, {
						maxAge: TRUST_DEVICE_COOKIE_MAX_AGE,
					}),
				);
				return ctx.json({
					token: activated.newSession.token,
					user: parseUserOutput(ctx.context.options, activated.updatedUser),
				});
			}
			if (twoFactor.verified !== true) {
				await ctx.context.adapter.incrementOne<TwoFactorTable>({
					model: twoFactorTable,
					where: [
						{ field: "id", value: twoFactor.id },
						{ field: "verified", value: null },
					],
					increment: {},
					set: { verified: true },
				});
			}
			return valid(ctx);
		},
	);

	return {
		id: "totp",
		version: PACKAGE_VERSION,
		endpoints: {
			/**
			 * ### Endpoint
			 *
			 * POST `/totp/generate`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.generateTOTP`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			generateTOTP: generateTOTP,
			/**
			 * ### Endpoint
			 *
			 * POST `/two-factor/get-totp-uri`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.getTOTPURI`
			 *
			 * **client:**
			 * `authClient.twoFactor.getTotpUri`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			getTOTPURI: getTOTPURI,
			/**
			 * ### Endpoint
			 *
			 * POST `/two-factor/verify-totp`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.verifyTOTP`
			 *
			 * **client:**
			 * `authClient.twoFactor.verifyTotp`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			verifyTOTP,
		},
	} satisfies TwoFactorProvider;
};
