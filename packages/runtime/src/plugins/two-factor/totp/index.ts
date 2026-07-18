import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import { createHash } from "@clearance/utils/hash";
import { createOTP } from "@clearance/utils/otp";
import * as z from "zod";
import { sessionMiddleware } from "../../../api";
import { expireCookie, setSessionCookie } from "../../../cookies";
import { symmetricDecrypt, symmetricEncrypt } from "../../../crypto";
import { generateRandomString } from "../../../crypto/random";
import { parseUserOutput } from "../../../db/schema";
import { lockAndReadActiveUser } from "../../../db/user-authority";
import {
	requireManagedAuthenticationTransaction,
} from "../../../internal/managed-authentication-transaction";
import {
	captureInternalSessionIssuanceContext,
	ManagedSessionIssuanceError,
} from "../../../internal/session-issuance-context";
import {
	appendInternalRuntimeAudit,
	attachCapturedInternalRuntimeAudit,
	getRuntimeAuditRequestContext,
	readInternalRuntimeAudit,
	type InternalRuntimeAuditDraft,
} from "@clearance/runtime/internal/runtime-audit";
import {
	consumePreloadedStagedAuthenticationCapability,
	createStagedAuthenticationBinding,
	createStagedSessionIssuanceContext,
	expireStagedAuthenticationCookie,
	getStagedAuthenticationFactorInventory,
	inspectStagedAuthenticationAuthority,
	preloadStagedAuthenticationCapability,
	rotateStagedAuthenticationCapability,
} from "../../../internal/staged-authentication-context";
import { shouldRequirePassword } from "../../../utils/password";
import { PACKAGE_VERSION } from "../../../version";
import { type BackupCodeOptions, generateBackupCodes } from "../backup-codes";
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
import { createRecoveryTOTPRepairEndpoints } from "./recovery-repair";

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

async function appendRuntimeAuditIfBound(
	ctx: GenericEndpointContext,
	transaction: DBTransactionAdapter,
	draft: Omit<InternalRuntimeAuditDraft, "request">,
) {
	const binding =
		readInternalRuntimeAudit(transaction) ??
		readInternalRuntimeAudit(ctx.context.adapter) ??
		readInternalRuntimeAudit(ctx.context.options);
	if (!binding) return;
	attachCapturedInternalRuntimeAudit(transaction, binding);
	const request = await getRuntimeAuditRequestContext();
	if (!request) throw new Error("Runtime audit request context is unavailable");
	await appendInternalRuntimeAudit(transaction, { ...draft, request });
}

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

type ManagedTOTPOptions = Readonly<{
	twoFactorTable: string;
	backupCodeOptions: BackupCodeOptions;
}>;

export const totp2fa = (
	options?: TOTPOptions | undefined,
	managedOptions?: ManagedTOTPOptions | undefined,
) => {
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

	const twoFactorTable = managedOptions?.twoFactorTable ?? "twoFactor";
	const managedBackupCodeOptions = managedOptions?.backupCodeOptions ??
		options?.backupCodes;
	const recoveryTOTPRepair = createRecoveryTOTPRepairEndpoints({
		options,
		twoFactorTable,
		backupCodeOptions: managedBackupCodeOptions,
	});

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

	const stagedAuthenticationInvalid = (): never => {
		throw APIError.from(
			"UNAUTHORIZED",
			TWO_FACTOR_ERROR_CODES.INVALID_STAGED_AUTHENTICATION,
		);
	};
	const stagedTOTPCodeInvalid = (): never => {
		throw APIError.from("UNAUTHORIZED", TWO_FACTOR_ERROR_CODES.INVALID_CODE);
	};
	const assertStagedTOTPAvailable = (
		ctx: Parameters<typeof requireManagedAuthenticationTransaction>[0],
	) => {
		if (options?.disable || !requireManagedAuthenticationTransaction(ctx)) {
			throw APIError.fromStatus("NOT_FOUND");
		}
	};
	class StagedTOTPStateConflict extends Error {}
	const hasPasskeyPlugin = (
		ctx: Parameters<typeof requireManagedAuthenticationTransaction>[0],
	) => Boolean(ctx.context.getPlugin("passkey"));
	const isActiveTOTP = (
		factor: Pick<TwoFactorTable, "verified">,
		user: Pick<UserWithTwoFactor, "twoFactorEnabled">,
	) =>
		factor.verified === true ||
		(factor.verified == null && user.twoFactorEnabled === true);
	const createTOTPBinding = async (
		lineage: NonNullable<
			ReturnType<typeof inspectStagedAuthenticationAuthority>
		>,
		mode: "authentication" | "enrollment",
		factor: Pick<TwoFactorTable, "id" | "secret">,
	) => {
		const secretFingerprint = await createHash(
			"SHA-256",
			"base64urlnopad",
		).digest(`managed-totp-secret:v1:${factor.secret}`);
		return createStagedAuthenticationBinding(
			lineage,
			["totp:v1", mode, factor.id, secretFingerprint],
		);
	};

	/**
	 * Begin the TOTP branch of managed authentication remediation. This endpoint
	 * deliberately has no session middleware: the signed staged cookie is the
	 * sole bearer for this pre-session ceremony.
	 */
	const beginStagedTOTP = createAuthEndpoint(
		"/managed-authentication/totp/options",
		{
			method: "POST",
			body: z.object({}),
		},
		async (ctx) => {
			assertStagedTOTPAvailable(ctx);
			const preloaded = await preloadStagedAuthenticationCapability(ctx, {
				stage: "select_factor",
				binding: "initial",
			});
			if (!preloaded) return stagedAuthenticationInvalid();

			const performSelection = () =>
				runWithTransaction(ctx.context.adapter, async () => {
				const authority = await consumePreloadedStagedAuthenticationCapability(
					ctx,
					preloaded,
				);
				if (!authority) return stagedAuthenticationInvalid();
				const inventory = await getStagedAuthenticationFactorInventory(
					ctx,
					authority,
				);
				if (!inventory) return stagedAuthenticationInvalid();
				const lineage = inspectStagedAuthenticationAuthority(authority);
				if (!lineage || lineage.expiresAt <= new Date()) {
					return stagedAuthenticationInvalid();
				}

				if (inventory.totpRecord) {
					const binding = await createTOTPBinding(
						lineage,
						"authentication",
						inventory.totpRecord,
					);
					await rotateStagedAuthenticationCapability(ctx, authority, {
						stage: "totp_authentication",
						binding,
					});
					return {
						kind: "ready" as const,
						mode: "verification" as const,
						expiresAt: lineage.expiresAt.toISOString(),
					};
				}

				// A verified policy-eligible passkey is authoritative: a user cannot
				// sidestep it by enrolling a new TOTP factor in this remediation flow.
				if (inventory.passkey) {
					return { kind: "existing_factor" as const };
				}

				const adapter = await getCurrentAdapter(ctx.context.adapter);
				const secret = generateRandomString(32);
				const encryptedSecret = await symmetricEncrypt({
					key: ctx.context.secretConfig,
					data: secret,
				});
				const backupCodes = await generateBackupCodes(
					ctx.context.secretConfig,
					managedBackupCodeOptions,
				);
				const current = await adapter.findOne<TwoFactorTable>({
					model: twoFactorTable,
					where: [{ field: "userId", value: lineage.subjectId }],
				});
				const activeUser = (await lockAndReadActiveUser(
					adapter,
					lineage.subjectId,
				)) as UserWithTwoFactor | null;
				if (!activeUser) return stagedAuthenticationInvalid();
				if (current && isActiveTOTP(current, activeUser)) {
					// The inventory was locked; any divergence is a concurrent lifecycle
					// mutation. Never turn it into an enrollment.
					throw APIError.fromStatus("CONFLICT", {
						message: "Two-factor state changed. Please try again.",
					});
				}
				const enrollment = current
					? await adapter.incrementOne<TwoFactorTable>({
						model: twoFactorTable,
						where: [
							{ field: "id", value: current.id },
							{ field: "userId", value: lineage.subjectId },
							{ field: "secret", value: current.secret },
							{
								field: "verified",
								value: current.verified === false ? false : null,
							},
						],
						increment: {},
						set: {
							secret: encryptedSecret,
							backupCodes: backupCodes.encryptedBackupCodes,
							pendingSecret: null,
							pendingBackupCodes: null,
							lastUsedTotpCounter: null,
							verified: false,
							trustDeviceGeneration: generateRandomString(32),
							failedVerificationCount: 0,
							activeVerificationReservations: "[]",
							lockedUntil: null,
						},
					})
					: await adapter.create<TwoFactorTable>({
						model: twoFactorTable,
						data: {
							userId: lineage.subjectId,
							secret: encryptedSecret,
							backupCodes: backupCodes.encryptedBackupCodes,
							verified: false,
							trustDeviceGeneration: generateRandomString(32),
						},
					});
				if (!enrollment) {
					throw APIError.fromStatus("CONFLICT", {
						message: "Two-factor enrollment changed. Please try again.",
					});
				}
				const binding = await createTOTPBinding(
					lineage,
					"enrollment",
					enrollment,
				);
				await rotateStagedAuthenticationCapability(ctx, authority, {
					stage: "totp_enrollment_verification",
					binding,
				});
				const user = await adapter.findOne<UserWithTwoFactor>({
					model: "user",
					where: [{ field: "id", value: lineage.subjectId }],
				});
				if (!user) return stagedAuthenticationInvalid();
				return {
					kind: "ready" as const,
					mode: "enrollment" as const,
					totpURI: createOTP(secret, {
						period: opts.period,
						digits: opts.digits,
					}).url(options?.issuer || ctx.context.appName, user.email),
					backupCodes: backupCodes.backupCodes,
					expiresAt: lineage.expiresAt.toISOString(),
				};
				});
			let result: Awaited<ReturnType<typeof performSelection>>;
			try {
				result = await performSelection();
			} catch (error) {
				if (error instanceof AfterTransactionHookError) {
					ctx.context.logger.debug(
						"[two-factor] staged TOTP selection publication failed",
						error.name,
					);
					await expireStagedAuthenticationCookie(ctx);
					return stagedAuthenticationInvalid();
				}
				throw error;
			}
			if (result.kind === "existing_factor") {
				throw APIError.from(
					"UNAUTHORIZED",
					TWO_FACTOR_ERROR_CODES.STAGED_FACTOR_VERIFICATION_REQUIRED,
				);
			}
			ctx.setHeader("cache-control", "no-store");
			ctx.setHeader("pragma", "no-cache");
			return ctx.json(result);
		},
	);

	const verifyStagedTOTP = createAuthEndpoint(
		"/managed-authentication/totp/verify",
		{
			method: "POST",
			body: z.object({ code: z.string().min(1).max(64) }),
		},
		async (ctx) => {
			assertStagedTOTPAvailable(ctx);
			ctx.setHeader("cache-control", "no-store");
			ctx.setHeader("pragma", "no-cache");
			const preloaded = await preloadStagedAuthenticationCapability(ctx, {
				stages: ["totp_authentication", "totp_enrollment_verification"],
			});
			if (!preloaded) return stagedAuthenticationInvalid();

			// Transaction A burns the stage and durably reserves an account attempt
			// before any attacker-controlled code is decrypted or compared.
			const gate = await runWithTransaction(ctx.context.adapter, async () => {
				const consumed = await consumePreloadedStagedAuthenticationCapability(
					ctx,
					preloaded,
				);
				if (!consumed) return { kind: "invalid" as const };
				const lineage = inspectStagedAuthenticationAuthority(consumed);
				if (!lineage || lineage.expiresAt <= new Date()) {
					return { kind: "invalid" as const };
				}
				const adapter = await getCurrentAdapter(ctx.context.adapter);
				const user = (await lockAndReadActiveUser(
					adapter,
					lineage.subjectId,
				)) as UserWithTwoFactor | null;
				if (!user) return { kind: "invalid" as const };
				const factor = await adapter.findOne<TwoFactorTable>({
					model: twoFactorTable,
					where: [{ field: "userId", value: user.id }],
				});
				if (!factor) return { kind: "invalid" as const };
				const enrollment = lineage.stage === "totp_enrollment_verification";
				const mode = enrollment ? "enrollment" : "authentication";
				if (
					lineage.binding !==
						(await createTOTPBinding(lineage, mode, factor)) ||
					(enrollment ? factor.verified !== false : !isActiveTOTP(factor, user))
				) {
					return { kind: "invalid" as const };
				}
				if (
					enrollment &&
					lineage.allowedFactors.includes("passkey") &&
					hasPasskeyPlugin(ctx) &&
					(await adapter.findOne({
						model: "passkey",
						where: [{ field: "userId", value: user.id }],
					}))
				) {
					return { kind: "invalid" as const };
				}
				try {
					await assertTwoFactorNotLocked(ctx, twoFactorTable, factor, adapter);
				} catch (error) {
					return { kind: "denied" as const, error };
				}
				const attempt = await reserveTwoFactorAttempt(
					ctx,
					twoFactorTable,
					factor,
					adapter,
				);
				return {
					kind: "ready" as const,
					consumed,
					lineage,
					factor,
					enrollment,
					attempt,
				};
			});
			if (gate.kind === "invalid") return stagedAuthenticationInvalid();
			if (gate.kind === "denied") throw gate.error;

			let counter: number | null;
			try {
				const secret = await symmetricDecrypt({
					key: ctx.context.secretConfig,
					data: gate.factor.secret,
				});
				counter = await createOTP(secret, {
					period: opts.period,
					digits: opts.digits,
				}).verifyWithCounter(ctx.body.code);
			} catch (error) {
				await gate.attempt.restore(ctx.context.adapter);
				throw error;
			}
			if (counter === null) {
				await gate.attempt.recordFailure(ctx.context.adapter);
				return stagedTOTPCodeInvalid();
			}
			const factorAt = new Date();

			type Outcome = {
				kind: "success";
				session: Awaited<
					ReturnType<typeof ctx.context.internalAdapter.createSession>
				>;
				user: UserWithTwoFactor;
			};
			let committed: Outcome | null = null;
			let outcome: Outcome;
			try {
				outcome = await runWithTransaction(ctx.context.adapter, async () => {
					const adapter = await getCurrentAdapter(ctx.context.adapter);
					const user = (await lockAndReadActiveUser(
						adapter,
						gate.lineage.subjectId,
					)) as UserWithTwoFactor | null;
					if (!user || gate.lineage.expiresAt <= new Date()) {
						throw new StagedTOTPStateConflict("user");
					}
					const factor = await adapter.findOne<TwoFactorTable>({
						model: twoFactorTable,
						where: [
							{ field: "id", value: gate.factor.id },
							{ field: "userId", value: user.id },
						],
					});
					if (!factor) throw new StagedTOTPStateConflict("factor");
					const mode = gate.enrollment ? "enrollment" : "authentication";
					if (
						factor.secret !== gate.factor.secret ||
						gate.lineage.binding !==
							(await createTOTPBinding(gate.lineage, mode, factor)) ||
						(gate.enrollment
							? factor.verified !== false
							: !isActiveTOTP(factor, user))
					) {
						throw new StagedTOTPStateConflict("binding-or-state");
					}
					if (
						gate.enrollment &&
						gate.lineage.allowedFactors.includes("passkey") &&
						hasPasskeyPlugin(ctx) &&
						(await adapter.findOne({
							model: "passkey",
							where: [{ field: "userId", value: user.id }],
						}))
					) {
						throw new StagedTOTPStateConflict("passkey");
					}

					if (
						!(await consumeTotpCounter(
							ctx,
							twoFactorTable,
							factor,
							counter,
							adapter,
						))
					) {
						throw new StagedTOTPStateConflict("counter");
					}
					if (gate.enrollment) {
						const activated = await adapter.incrementOne<TwoFactorTable>({
							model: twoFactorTable,
							where: [
								{ field: "id", value: factor.id },
								{ field: "userId", value: user.id },
								{ field: "secret", value: factor.secret },
								{ field: "verified", value: false },
								{ field: "lastUsedTotpCounter", value: counter },
							],
							increment: {},
							set: {
								verified: true,
								trustDeviceGeneration: generateRandomString(32),
							},
						});
						if (!activated) throw new StagedTOTPStateConflict("activation");
					} else if (
						factor.verified !== true ||
						user.twoFactorEnabled !== true
					) {
						const normalized = await adapter.incrementOne<TwoFactorTable>({
							model: twoFactorTable,
							where: [
								{ field: "id", value: factor.id },
								{ field: "userId", value: user.id },
								{ field: "secret", value: factor.secret },
								{ field: "lastUsedTotpCounter", value: counter },
							],
							increment: {},
							set: { verified: true },
						});
						if (!normalized) throw new StagedTOTPStateConflict("normalization");
					}
					const issuanceContext = await createStagedSessionIssuanceContext(
						ctx,
						gate.consumed,
						{
							factorMethod: "totp",
							factorAt,
							binding: gate.lineage.binding,
						},
					);
					const updatedUser = gate.enrollment || user.twoFactorEnabled !== true
						? await ctx.context.internalAdapter.updateUser(user.id, {
							twoFactorEnabled: true,
							twoFactorSessionGeneration: generateRandomString(32),
						})
						: user;
					const session = await ctx.context.internalAdapter.createSession(
						user.id,
						gate.lineage.dontRememberMe,
						undefined,
						false,
						issuanceContext,
					);
					await appendRuntimeAuditIfBound(ctx, adapter, {
						actor: user.id,
						action: gate.enrollment
							? "auth.factor.enrolled"
							: "auth.factor.used",
						subjectType: "user",
						subjectId: user.id,
						outcome: "success",
						source: "system",
						organizationId: null,
						message: gate.enrollment ? "TOTP factor enrolled" : "TOTP factor used",
						metadata: { factor: "totp" },
					});
					await resetTwoFactorFailures(ctx, twoFactorTable, factor, adapter);
					await queueAfterTransactionHook(
						() => setSessionCookie(ctx, { session, user: updatedUser }),
						ctx.context.adapter,
					);
					await expireStagedAuthenticationCookie(ctx);
					committed = {
						kind: "success",
						session,
						user: updatedUser as UserWithTwoFactor,
					};
					return committed;
				});
			} catch (error) {
				if (error instanceof AfterTransactionHookError && committed) {
					ctx.context.logger.debug(
						"[two-factor] staged TOTP post-commit publication failed",
						error.name,
					);
					outcome = committed;
				} else if (error instanceof StagedTOTPStateConflict) {
					await gate.attempt.restore(ctx.context.adapter);
					return stagedAuthenticationInvalid();
				} else if (error instanceof ManagedSessionIssuanceError) {
					await gate.attempt.restore(ctx.context.adapter);
					return stagedAuthenticationInvalid();
				} else {
					await gate.attempt.restore(ctx.context.adapter);
					throw error;
				}
			}
			return ctx.json({
				token: outcome.session.token,
				user: parseUserOutput(ctx.context.options, outcome.user),
			});
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
						const replacementIssuanceContext =
							await captureInternalSessionIssuanceContext(
								ctx.context.internalAdapter,
								{
									purpose: "replacement",
									sourceSessionToken: activeSession.token,
								},
							);
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
								false,
								replacementIssuanceContext,
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
						const replacementIssuanceContext =
							await captureInternalSessionIssuanceContext(
								ctx.context.internalAdapter,
								{
									purpose: "replacement",
									sourceSessionToken: activeSession.token,
								},
							);
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
							false,
							replacementIssuanceContext,
						);
						await appendRuntimeAuditIfBound(ctx, adapter, {
							actor: user.id,
							action: "auth.factor.enrolled",
							subjectType: "user",
							subjectId: user.id,
							outcome: "success",
							source: "system",
							organizationId: null,
							message: "TOTP factor enrolled",
							metadata: { factor: "totp" },
						});
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
			recoveryRepairTOTPOptions: recoveryTOTPRepair.options,
			recoveryRepairTOTPVerify: recoveryTOTPRepair.verify,
			beginStagedTOTP,
			verifyStagedTOTP,
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
