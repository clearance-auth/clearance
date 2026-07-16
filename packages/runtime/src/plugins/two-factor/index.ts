import type { ClearancePlugin, GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
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
import {
	constantTimeEqual,
	symmetricDecrypt,
	symmetricEncrypt,
} from "../../crypto";
import { generateRandomString } from "../../crypto/random";
import {
	PASSKEY_SESSION_GENERATION_FIELD,
	rotatePasskeySessionGeneration,
} from "../../db/passkey-session-generation";
import {
	rotateTwoFactorSessionGeneration,
	TWO_FACTOR_SESSION_GENERATION_FIELD,
} from "../../db/two-factor-session-generation";
import { mergeSchema } from "../../db/schema";
import { lockAndReadUser } from "../../db/user-authority";
import type { Session, User } from "../../types";
import { shouldRequirePassword, validatePassword } from "../../utils/password";
import { PACKAGE_VERSION } from "../../version";
import type { BackupCodeOptions } from "./backup-codes";
import {
	backupCode2fa,
	generateBackupCodes,
	proveFactorStepUp,
} from "./backup-codes";
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
	preserveSessionLifetime,
	recordTrustGeneration,
	trustGenerationMarkerIdentifier,
} from "./utils";
import {
	assertTwoFactorNotLocked,
	reserveTwoFactorAttempt,
} from "./verify-two-factor";

export * from "./error-code";

function assertTwoFactorLifecycleConfiguration(
	ctx: GenericEndpointContext,
): void {
	if (
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function" ||
		(ctx.context.options.secondaryStorage !== undefined &&
			ctx.context.options.session?.storeSessionInDatabase !== true)
	) {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			TWO_FACTOR_ERROR_CODES.LIFECYCLE_CONFIGURATION_ERROR,
		);
	}
}

function twoFactorLastFactorProtected(): never {
	throw APIError.from("BAD_REQUEST", TWO_FACTOR_ERROR_CODES.LAST_FACTOR_PROTECTED);
}

function twoFactorLifecycleConflict(): never {
	throw APIError.from("CONFLICT", TWO_FACTOR_ERROR_CODES.LIFECYCLE_CONFLICT);
}

function logTwoFactorLifecycleFailure(
	ctx: GenericEndpointContext,
	label: string,
	error: unknown,
): void {
	ctx.context.logger.debug(
		`[two-factor] ${label}`,
		error instanceof Error ? error.name : "unknown error",
	);
}

type ResolveDefault<Value, Default> = Value extends undefined ? Default : Value;
type OptionValue<
	O extends TwoFactorOptions,
	Key extends keyof TwoFactorOptions,
> = Key extends keyof O ? O[Key] : undefined;
type BackupCodeOptionValue<
	Value,
	Key extends keyof BackupCodeOptions,
> = Value extends BackupCodeOptions
	? Key extends keyof Value
		? Value[Key]
		: undefined
	: undefined;

type ResolvedBackupCodeOptions<Value> = ResolveDefault<Value, object> & {
	storeBackupCodes: ResolveDefault<
		BackupCodeOptionValue<Value, "storeBackupCodes">,
		"encrypted"
	>;
};

type ResolvedTwoFactorOptions<O extends TwoFactorOptions> = O & {
	twoFactorTable: ResolveDefault<OptionValue<O, "twoFactorTable">, "twoFactor">;
	backupCodeOptions: ResolvedBackupCodeOptions<
		OptionValue<O, "backupCodeOptions">
	>;
};

function resolveTwoFactorOptions<const O extends TwoFactorOptions = {}>(
	options?: O,
): ResolvedTwoFactorOptions<O>;
function resolveTwoFactorOptions(options?: TwoFactorOptions) {
	return {
		...options,
		twoFactorTable: options?.twoFactorTable ?? "twoFactor",
		backupCodeOptions: {
			storeBackupCodes: "encrypted" as const,
			...options?.backupCodeOptions,
		},
	};
}

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		"two-factor": {
			creator: typeof twoFactor;
		};
	}
}
export const twoFactor = <const O extends TwoFactorOptions = {}>(options?: O) => {
	const resolvedOptions = resolveTwoFactorOptions(options);
	const opts: { twoFactorTable: string } = {
		twoFactorTable: resolvedOptions.twoFactorTable,
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
	const backupCode = backupCode2fa(
		{
			...backupCodeOptions,
			allowPasswordless:
				options?.backupCodeOptions?.allowPasswordless ?? allowPasswordless,
		},
		options?.totpOptions,
	);
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
				currentCode: z.string().optional(),
				recoveryCode: z.string().optional(),
			})
		: z.object({
				password: passwordSchema,
				currentCode: z.string().optional(),
				recoveryCode: z.string().optional(),
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
						const accountAttempt = await reserveTwoFactorAttempt(
							ctx,
							opts.twoFactorTable,
							existingTwoFactor,
						);
						let currentCounter: number | null;
						try {
							const currentSecret = await symmetricDecrypt({
								key: ctx.context.secretConfig,
								data: existingTwoFactor.secret,
							});
							currentCounter = await createOTP(currentSecret, {
								digits: options?.totpOptions?.digits || 6,
								period: options?.totpOptions?.period,
							}).verifyWithCounter(currentCode);
						} catch (error) {
							await accountAttempt.restore();
							throw error;
						}
						if (currentCounter === null) {
							await accountAttempt.recordFailure();
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
									activeVerificationReservations: "[]",
									lockedUntil: null,
								},
							});
						if (!staged) {
							await accountAttempt.restore();
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
					if (
						existingTwoFactor?.verified === false &&
						backupCodeOptions.storeBackupCodes === "hashed"
					) {
						const restarted =
							await ctx.context.adapter.incrementOne<TwoFactorTable>({
								model: opts.twoFactorTable,
								where: [
									{ field: "id", value: existingTwoFactor.id },
									{ field: "verified", value: false },
									{ field: "secret", value: existingTwoFactor.secret },
									{
										field: "backupCodes",
										value: existingTwoFactor.backupCodes,
									},
								],
								increment: {},
								set: {
									secret: encryptedSecret,
									backupCodes: backupCodes.encryptedBackupCodes,
									pendingSecret: null,
									pendingBackupCodes: null,
									lastUsedTotpCounter: null,
									trustDeviceGeneration: generateRandomString(32),
									failedVerificationCount: 0,
									lockedUntil: null,
								},
							});
						if (!restarted) {
							throw APIError.fromStatus("CONFLICT", {
								message: "Two-factor enrollment changed. Please try again.",
							});
						}
						persistedEnrollment = restarted;
					} else {
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
											trustDeviceGeneration: generateRandomString(32),
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
					}
					let enrollmentSecret = secret;
					let enrollmentBackupCodes = backupCodes.backupCodes;
					if (persistedEnrollment.secret !== encryptedSecret) {
						if (persistedEnrollment.verified !== false) {
							throw APIError.fromStatus("CONFLICT", {
								message: "Two-factor enrollment changed. Please try again.",
							});
						}
						if (backupCodeOptions.storeBackupCodes === "hashed") {
							throw APIError.fromStatus("CONFLICT", {
								message:
									"Two-factor enrollment already started. Restart enrollment to issue new recovery codes.",
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
						const activeSession = ctx.context.session.session;
						const activated = await runWithTransaction(
							ctx.context.adapter,
							async () => {
								const adapter = await getCurrentAdapter(ctx.context.adapter);
								const generation = generateRandomString(32);
								const factor = await adapter.incrementOne<TwoFactorTable>({
									model: opts.twoFactorTable,
									where: [
										{ field: "id", value: persistedEnrollment.id },
										{
											field: "trustDeviceGeneration",
											value: persistedEnrollment.trustDeviceGeneration ?? null,
										},
									],
									increment: {},
									set: {
										trustDeviceGeneration: generation,
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
								const updatedUser =
									await ctx.context.internalAdapter.updateUser(user.id, {
										twoFactorEnabled: true,
										twoFactorSessionGeneration: generateRandomString(32),
									});
								await ctx.context.internalAdapter.deleteUserSessions(user.id);
								const newSession =
									await ctx.context.internalAdapter.createSession(
										updatedUser.id,
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
								maxAge: trustDeviceMaxAge,
							}),
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
						const { currentCode, password, recoveryCode } = ctx.body;
						const passkeyLifecycle =
							ctx.context.options.plugins?.some((plugin) => plugin.id === "passkey") ===
							true;
						const twoFactorGenerationLifecycle = !passkeyLifecycle;
						assertTwoFactorLifecycleConfiguration(ctx);
						const originalExpiresAt = new Date(ctx.context.session.session.expiresAt);
						const originalExpiresAtMs = originalExpiresAt.getTime();
						if (
							!Number.isFinite(originalExpiresAtMs) ||
							originalExpiresAtMs <= Date.now()
						) {
							twoFactorLifecycleConflict();
						}

						type DisableResult =
							| {
									kind: "success";
									replacementSession: Session;
									updatedUser: User;
							  }
							| { kind: "proof-error"; error: unknown };
						let rotated: DisableResult | undefined;
						let committedLifecycle:
							| Extract<DisableResult, { kind: "success" }>
							| undefined;
						try {
							rotated = await runWithTransaction(
								ctx.context.adapter,
								async () => {
									const adapter = await getCurrentAdapter(ctx.context.adapter);
									const authoritativeUser = (await lockAndReadUser(
										adapter,
										user.id,
									)) as (User & Record<string, unknown>) | null;
									if (!authoritativeUser) twoFactorLifecycleConflict();

									const presentedSession =
										await ctx.context.internalAdapter.findSession(
											ctx.context.session.session.token,
										);
									if (
										!presentedSession ||
										presentedSession.session.id !==
											ctx.context.session.session.id ||
										presentedSession.session.userId !== user.id ||
										presentedSession.user.id !== user.id ||
										new Date(presentedSession.session.expiresAt).getTime() !==
											originalExpiresAtMs
									) {
										twoFactorLifecycleConflict();
									}
									const authoritativeSession = await adapter.findOne<
										Session & Record<string, unknown>
									>({
										model: "session",
										where: [
											{
												field: "id",
												value: ctx.context.session.session.id,
											},
											{ field: "userId", value: user.id },
											{ field: "expiresAt", value: originalExpiresAt },
										],
									});
									if (!authoritativeSession) twoFactorLifecycleConflict();
									if (authoritativeUser.twoFactorEnabled !== true) {
										throw APIError.from(
											"BAD_REQUEST",
											TWO_FACTOR_ERROR_CODES.TWO_FACTOR_NOT_ENABLED,
										);
									}

									let observedPasskeyGeneration: string | null = null;
									let observedTwoFactorGeneration: string | null = null;
									if (passkeyLifecycle) {
										const userGeneration =
											authoritativeUser[PASSKEY_SESSION_GENERATION_FIELD];
										const sessionGeneration =
											authoritativeSession?.[PASSKEY_SESSION_GENERATION_FIELD];
										if (
											typeof userGeneration !== "string" ||
											userGeneration.length === 0 ||
											typeof sessionGeneration !== "string" ||
											sessionGeneration.length === 0 ||
											sessionGeneration !== userGeneration
										) {
											twoFactorLifecycleConflict();
										}
										observedPasskeyGeneration = userGeneration;
									} else if (twoFactorGenerationLifecycle) {
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
											twoFactorLifecycleConflict();
										}
										observedTwoFactorGeneration = userGeneration;
									}

									const factor = await adapter.findOne<TwoFactorTable>({
										model: opts.twoFactorTable,
										where: [
											{ field: "userId", value: user.id },
											{ field: "verified", value: true },
										],
									});
									if (!factor) {
										throw APIError.from(
											"BAD_REQUEST",
											TWO_FACTOR_ERROR_CODES.TWO_FACTOR_NOT_ENABLED,
										);
									}

									const requirePassword = await shouldRequirePassword(
										ctx,
										user.id,
										allowPasswordless,
									);
									if (requirePassword) {
										if (
											!password ||
											!(await validatePassword(ctx, {
												password,
												userId: user.id,
											}))
										) {
											throw APIError.from(
												"BAD_REQUEST",
												BASE_ERROR_CODES.INVALID_PASSWORD,
											);
										}
									}

									let proof: Awaited<ReturnType<typeof proveFactorStepUp>>;
									try {
										proof = await proveFactorStepUp(
											ctx,
											adapter,
											opts.twoFactorTable,
											factor,
											{ currentCode, recoveryCode },
											{
												backupCodeOptions,
												totpOptions: options?.totpOptions,
											},
										);
									} catch (error) {
										// Returning commits invalid-attempt accounting. Throwing here would
										// roll it back with the lifecycle transaction.
										return { kind: "proof-error" as const, error };
									}

									const accounts =
										await ctx.context.internalAdapter.findAccounts(user.id);
									const passkeyCount = passkeyLifecycle
										? await adapter.count({
												model: "passkey",
												where: [{ field: "userId", value: user.id }],
											})
										: 0;
									const hasPassword = accounts.some(
										(account) =>
											account.providerId === "credential" &&
											typeof account.password === "string" &&
											account.password.length > 0,
									);
									if (!hasPassword && passkeyCount === 0) {
										twoFactorLastFactorProtected();
									}

									const generation = generateRandomString(32);
									const authorized = await adapter.incrementOne<TwoFactorTable>({
										model: opts.twoFactorTable,
										where: [
											{ field: "id", value: factor.id },
											{ field: "userId", value: user.id },
											{ field: "verified", value: true },
											...proof.where,
										],
										increment: {},
										set: {
											...proof.set,
											trustDeviceGeneration: generation,
											failedVerificationCount: 0,
											activeVerificationReservations: "[]",
											lockedUntil: null,
										},
									});
									if (!authorized) twoFactorLifecycleConflict();

									if (passkeyLifecycle) {
										if (!observedPasskeyGeneration) twoFactorLifecycleConflict();
										const rotatedUser = await rotatePasskeySessionGeneration(
											adapter,
											user.id,
											observedPasskeyGeneration,
											generateRandomString(32),
										);
										if (!rotatedUser) twoFactorLifecycleConflict();
									} else if (twoFactorGenerationLifecycle) {
										if (!observedTwoFactorGeneration) twoFactorLifecycleConflict();
										const rotatedUser = await rotateTwoFactorSessionGeneration(
											adapter,
											user.id,
											observedTwoFactorGeneration,
											generateRandomString(32),
										);
										if (!rotatedUser) twoFactorLifecycleConflict();
									}

									if (
										factor.trustDeviceGeneration &&
										(!ctx.context.options.secondaryStorage ||
											ctx.context.options.verification?.storeInDatabase === true)
									) {
										await adapter.deleteMany({
											model: "verification",
											where: [
												{
													field: "value",
													value: `${user.id}!${factor.trustDeviceGeneration}`,
												},
											],
										});
									}
									if (
										factor.trustDeviceGeneration &&
										ctx.context.options.secondaryStorage
									) {
										const marker = trustGenerationMarkerIdentifier(
											user.id,
											factor.trustDeviceGeneration,
										);
										await queueAfterTransactionHook(
											() =>
												ctx.context.internalAdapter.deleteVerificationByIdentifier(
													marker,
												),
											adapter,
										);
									}

									const deletedFactor = await adapter.consumeOne<TwoFactorTable>({
										model: opts.twoFactorTable,
										where: [
											{ field: "id", value: factor.id },
											{ field: "userId", value: user.id },
											{ field: "trustDeviceGeneration", value: generation },
										],
									});
									if (!deletedFactor) twoFactorLifecycleConflict();

									const updatedUser = await ctx.context.internalAdapter.updateUser(
										user.id,
										{
											twoFactorEnabled: false,
											twoFactorSessionGeneration: generateRandomString(32),
										},
									);
									if (!updatedUser) twoFactorLifecycleConflict();
									await ctx.context.internalAdapter.deleteUserSessions(user.id);
									const replacementSession =
										await ctx.context.internalAdapter.createSession(
											user.id,
											false,
											preserveSessionLifetime({
												...ctx.context.session.session,
												expiresAt: originalExpiresAt,
											}),
										);
									if (
										new Date(replacementSession.expiresAt).getTime() !==
										originalExpiresAtMs
									) {
										twoFactorLifecycleConflict();
									}
									committedLifecycle = {
										kind: "success" as const,
										replacementSession,
										updatedUser,
									};
									return committedLifecycle;
								},
							);
						} catch (error) {
							if (error instanceof AfterTransactionHookError && committedLifecycle) {
								logTwoFactorLifecycleFailure(
									ctx,
									"disable post-commit publication failed",
									error,
								);
								rotated = committedLifecycle;
							} else {
								throw error;
							}
						}
						if (!rotated) twoFactorLifecycleConflict();
						if (rotated.kind === "proof-error") throw rotated.error;
						await setSessionCookie(ctx, {
							session: rotated.replacementSession,
							user: rotated.updatedUser,
						});
						const disableTrustCookie = ctx.context.createAuthCookie(
							TRUST_DEVICE_COOKIE_NAME,
							{
								maxAge: trustDeviceMaxAge,
							},
						);
						expireCookie(ctx, disableTrustCookie);
						return ctx.json({ status: true });
					},
				),
		},
		// Runtime consumers such as cross-factor recovery must see the same
		// effective storage contract used by this plugin, including defaults.
		options: resolvedOptions,
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
							const canConsumeTrustAtomically =
								!ctx.context.options.secondaryStorage ||
								ctx.context.options.verification?.storeInDatabase === true ||
								typeof ctx.context.options.secondaryStorage.getAndDelete ===
									"function";
							const [token, trustIdentifier, trustGeneration] =
								trustDeviceCookie.split("!");
							if (
								canConsumeTrustAtomically &&
								token &&
								trustIdentifier &&
								trustGeneration
							) {
								const factor =
									await ctx.context.adapter.findOne<TwoFactorTable>({
										model: opts.twoFactorTable,
										where: [{ field: "userId", value: data.user.id }],
									});
								const expectedToken = await createHMAC(
									"SHA-256",
									"base64urlnopad",
								).sign(
									ctx.context.secret,
									`${data.user.id}!${trustIdentifier}!${trustGeneration}`,
								);

								if (
									constantTimeEqual(token, expectedToken) &&
									factor?.trustDeviceGeneration === trustGeneration
								) {
									const generationMarker =
										await ctx.context.internalAdapter.findVerificationValue(
											trustGenerationMarkerIdentifier(
												data.user.id,
												trustGeneration,
											),
										);
									const verificationRecord =
										await ctx.context.internalAdapter.consumeVerificationValue(
											trustIdentifier,
										);
									if (
										generationMarker?.value ===
											`${data.user.id}!${trustGeneration}` &&
										generationMarker.expiresAt > new Date() &&
										verificationRecord &&
										verificationRecord.value ===
											`${data.user.id}!${trustGeneration}` &&
										verificationRecord.expiresAt > new Date()
									) {
										const newTrustIdentifier = `trust-device-${generateRandomString(32)}`;
										const newToken = await createHMAC(
											"SHA-256",
											"base64urlnopad",
										).sign(
											ctx.context.secret,
											`${data.user.id}!${newTrustIdentifier}!${trustGeneration}`,
										);
										const trustExpiresAt = new Date(
											Date.now() + trustDeviceMaxAge * 1000,
										);
										await ctx.context.internalAdapter.createVerificationValue({
											value: `${data.user.id}!${trustGeneration}`,
											identifier: newTrustIdentifier,
											expiresAt: trustExpiresAt,
										});
										await recordTrustGeneration(
											ctx,
											data.user.id,
											trustGeneration,
											trustExpiresAt,
										);
										const newTrustDeviceCookie = ctx.context.createAuthCookie(
											TRUST_DEVICE_COOKIE_NAME,
											{
												maxAge: trustDeviceMaxAge,
											},
										);
										await ctx.setSignedCookie(
											newTrustDeviceCookie.name,
											`${newToken}!${newTrustIdentifier}!${trustGeneration}`,
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
export { encodeBackupCodes, isOneWayBackupCodeEnvelope } from "./backup-codes";
