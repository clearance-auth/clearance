import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { APIError } from "@clearance/core/error";
import { createOTP } from "@clearance/utils/otp";
import * as z from "zod";
import { symmetricDecrypt, symmetricEncrypt } from "../../../crypto";
import { generateRandomString } from "../../../crypto/random";
import { lockAndReadActiveUser } from "../../../db/user-authority";
import {
	RECOVERY_FACTOR_REPAIR_COOKIE,
	completeRecoveryFactorRepair,
	consumePreloadedRecoveryFactorRepairCapability,
	createRecoveryTOTPEnrollmentBinding,
	inspectRecoveryFactorRepairAuthority,
	preloadRecoveryFactorRepairCapability,
	recoveryFactorRepairSelectionAuthorityIsExact,
	reissueRecoveryTOTPVerificationCapability,
	recoveryTOTPVerificationAuthorityIsExact,
	rotateRecoveryFactorRepairCapability,
} from "../../../internal/recovery-factor-repair-context";
import {
	digestRecoveryRepairCode,
	generateBackupCodes,
	type BackupCodeOptions,
	verifyBackupCode,
} from "../backup-codes";
import { TWO_FACTOR_ERROR_CODES } from "../error-code";
import type {
	TwoFactorOptions,
	TwoFactorTable,
	UserWithTwoFactor,
} from "../types";
import {
	assertTwoFactorNotLocked,
	consumeTotpCounter,
	reserveTwoFactorAttempt,
} from "../verify-two-factor";
import type { TOTPOptions } from ".";

type RecoveryTOTPConfiguration = Readonly<{
	options: TOTPOptions | undefined;
	twoFactorTable: string;
	backupCodeOptions: BackupCodeOptions | undefined;
}>;

const emptyBodySchema = z.object({}).strict();
const verifyBodySchema = z.object({ code: z.string().min(1).max(64) }).strict();

function recoveryInvalid(): never {
	throw APIError.from(
		"UNAUTHORIZED",
		TWO_FACTOR_ERROR_CODES.INVALID_STAGED_AUTHENTICATION,
	);
}

function invalidCode(): never {
	throw APIError.from("UNAUTHORIZED", TWO_FACTOR_ERROR_CODES.INVALID_CODE);
}

function setRecoveryHeaders(ctx: GenericEndpointContext): void {
	ctx.setHeader("cache-control", "no-store");
	ctx.setHeader("pragma", "no-cache");
}

function recoveryLockoutIsEnabled(ctx: GenericEndpointContext): boolean {
	const options = ctx.context.getPlugin("two-factor")?.options as
		| TwoFactorOptions
		| undefined;
	return options?.accountLockout?.enabled !== false;
}

async function expireRecoveryCookie(ctx: GenericEndpointContext): Promise<void> {
	const cookie = ctx.context.createAuthCookie(RECOVERY_FACTOR_REPAIR_COOKIE, {
		httpOnly: true,
		sameSite: "lax",
	});
	await ctx.setSignedCookie(cookie.name, "", ctx.context.secret, {
		...cookie.attributes,
		maxAge: 0,
	});
}

function factorIsPendingRecoveryEnrollment(
	factor: TwoFactorTable,
	lineage: NonNullable<ReturnType<typeof inspectRecoveryFactorRepairAuthority>>,
): factor is TwoFactorTable & {
	pendingSecret: string;
	pendingBackupCodes: string;
} {
	return (
		factor.id === lineage.recoveryFactorId &&
		factor.userId === lineage.subjectId &&
		factor.trustDeviceGeneration === lineage.trustDeviceGeneration &&
		factor.verified === false &&
		typeof factor.pendingSecret === "string" &&
		factor.pendingSecret.length > 0 &&
		typeof factor.pendingBackupCodes === "string" &&
		factor.pendingBackupCodes.length > 0
	);
}

/** Recovery-only TOTP enrollment: it rotates only the repair capability. */
export const createRecoveryTOTPRepairEndpoints = (
	configuration: RecoveryTOTPConfiguration,
) => {
	const digits = configuration.options?.digits || 6;
	const period = configuration.options?.period || 30;
	const options = createAuthEndpoint(
		"/managed-authentication/recovery-repair/totp/options",
		{ method: "POST", body: emptyBodySchema },
		async (ctx) => {
			setRecoveryHeaders(ctx);
			if (configuration.options?.disable || !recoveryLockoutIsEnabled(ctx)) {
				return recoveryInvalid();
			}
			const preloaded = await preloadRecoveryFactorRepairCapability(ctx, {
				stage: "select_repair",
				binding: "initial",
				repairFactor: "totp",
			});
			if (!preloaded) return recoveryInvalid();

			try {
				const result = await runWithTransaction(ctx.context.adapter, async () => {
					const authority = await consumePreloadedRecoveryFactorRepairCapability(
						ctx,
						preloaded,
					);
					const lineage = authority
						? inspectRecoveryFactorRepairAuthority(authority)
						: null;
					if (
						!lineage ||
						lineage.repairFactor !== "totp" ||
						lineage.twoFactorTable !== configuration.twoFactorTable ||
						lineage.expiresAt <= new Date() ||
						!(await recoveryFactorRepairSelectionAuthorityIsExact(
							ctx,
							authority!,
						))
					) {
						return { kind: "invalid" as const };
					}
					const adapter = await getCurrentAdapter(ctx.context.adapter);
					const user = (await lockAndReadActiveUser(
						adapter,
						lineage.subjectId,
					)) as UserWithTwoFactor | null;
					const factor = await adapter.findOne<TwoFactorTable>({
						model: lineage.twoFactorTable,
						where: [
							{ field: "id", value: lineage.recoveryFactorId },
							{ field: "userId", value: lineage.subjectId },
						],
					});
					if (
						!user ||
						!factor ||
						factor.verified !== false ||
						factor.trustDeviceGeneration !== lineage.trustDeviceGeneration ||
						factor.pendingSecret != null ||
						factor.pendingBackupCodes != null ||
						factor.lastUsedTotpCounter !== -1
					) {
						return { kind: "invalid" as const };
					}
					const secret = generateRandomString(32);
					const pendingSecret = await symmetricEncrypt({
						key: ctx.context.secretConfig,
						data: secret,
					});
					const backupCodes = await generateBackupCodes(
						ctx.context.secretConfig,
						configuration.backupCodeOptions,
					);
					for (const code of backupCodes.backupCodes) {
						if (
							(await digestRecoveryRepairCode(
								ctx,
								lineage.twoFactorTable,
								factor.id,
								code,
							)) === lineage.consumedRecoveryCodeDigest ||
							(
								await verifyBackupCode(
									{ backupCodes: factor.backupCodes, code },
									ctx.context.secretConfig,
									configuration.backupCodeOptions,
								)
							).status
						) {
							throw new Error("Recovery backup codes overlap source authority");
						}
					}
					const pending = await adapter.incrementOne<TwoFactorTable>({
						model: lineage.twoFactorTable,
						where: [
							{ field: "id", value: factor.id },
							{ field: "userId", value: lineage.subjectId },
							{ field: "secret", value: factor.secret },
							{ field: "backupCodes", value: factor.backupCodes },
							{ field: "verified", value: false },
							{
								field: "trustDeviceGeneration",
								value: lineage.trustDeviceGeneration,
							},
							{ field: "pendingSecret", value: null },
							{ field: "pendingBackupCodes", value: null },
							{ field: "lastUsedTotpCounter", value: -1 },
						],
						increment: {},
						set: {
							pendingSecret,
							pendingBackupCodes: backupCodes.encryptedBackupCodes,
							failedVerificationCount: 0,
							activeVerificationReservations: "[]",
							lockedUntil: null,
						},
					});
					if (!pending) return { kind: "invalid" as const };
					const binding = await createRecoveryTOTPEnrollmentBinding(
						lineage,
						pending,
					);
					const next = await rotateRecoveryFactorRepairCapability(ctx, authority!, {
						stage: "totp_enrollment_verification",
						binding,
					});
					return {
						kind: "ready" as const,
						totpURI: createOTP(secret, { period, digits }).url(
							configuration.options?.issuer || ctx.context.appName,
							user.email,
						),
						backupCodes: backupCodes.backupCodes,
						expiresAt: next.expiresAt,
					};
				});
				if (result.kind !== "ready") return recoveryInvalid();
				return ctx.json({
					mode: "enrollment" as const,
					totpURI: result.totpURI,
					backupCodes: result.backupCodes,
					expiresAt: result.expiresAt,
				});
			} catch (error) {
				if (error instanceof AfterTransactionHookError) {
					await expireRecoveryCookie(ctx);
				}
				return recoveryInvalid();
			}
		},
	);

	const verify = createAuthEndpoint(
		"/managed-authentication/recovery-repair/totp/verify",
		{ method: "POST", body: verifyBodySchema },
		async (ctx) => {
			setRecoveryHeaders(ctx);
			if (configuration.options?.disable || !recoveryLockoutIsEnabled(ctx)) {
				return recoveryInvalid();
			}
			const preloaded = await preloadRecoveryFactorRepairCapability(ctx, {
				stage: "totp_enrollment_verification",
				repairFactor: "totp",
			});
			if (!preloaded) return recoveryInvalid();

			const gate = await runWithTransaction(ctx.context.adapter, async () => {
				const authority = await consumePreloadedRecoveryFactorRepairCapability(
					ctx,
					preloaded,
				);
				const lineage = authority
					? inspectRecoveryFactorRepairAuthority(authority)
					: null;
				if (
					!authority ||
					!lineage ||
					lineage.repairFactor !== "totp" ||
					lineage.twoFactorTable !== configuration.twoFactorTable ||
					lineage.expiresAt <= new Date()
				) {
					return { kind: "invalid" as const };
				}
				const adapter = await getCurrentAdapter(ctx.context.adapter);
				const user = (await lockAndReadActiveUser(
					adapter,
					lineage.subjectId,
				)) as UserWithTwoFactor | null;
				const factor = await adapter.findOne<TwoFactorTable>({
					model: lineage.twoFactorTable,
					where: [
						{ field: "id", value: lineage.recoveryFactorId },
						{ field: "userId", value: lineage.subjectId },
					],
				});
				if (!user || !factor || !factorIsPendingRecoveryEnrollment(factor, lineage)) {
					return { kind: "invalid" as const };
				}
				const binding = await createRecoveryTOTPEnrollmentBinding(
					lineage,
					factor,
				);
				if (
					binding !== lineage.binding ||
					!(await recoveryTOTPVerificationAuthorityIsExact(ctx, authority))
				) {
					return { kind: "invalid" as const };
				}
				try {
					await assertTwoFactorNotLocked(ctx, lineage.twoFactorTable, factor, adapter);
				} catch {
					return { kind: "invalid" as const };
				}
				return {
					kind: "ready" as const,
					authority: authority!,
					lineage,
					factor,
					attempt: await reserveTwoFactorAttempt(
						ctx,
						lineage.twoFactorTable,
						factor,
						adapter,
					),
				};
			}).catch(() => null);
			if (!gate || gate.kind !== "ready") return recoveryInvalid();

			let counter: number | null;
			try {
				const secret = await symmetricDecrypt({
					key: ctx.context.secretConfig,
					data: gate.factor.pendingSecret,
				});
				counter = await createOTP(secret, { period, digits }).verifyWithCounter(
					ctx.body.code,
				);
			} catch (error) {
				await gate.attempt.restore(ctx.context.adapter);
				throw error;
			}
			if (counter === null) {
				try {
					await runWithTransaction(ctx.context.adapter, async () => {
						const adapter = await getCurrentAdapter(ctx.context.adapter);
						await gate.attempt.recordFailure(adapter);
						await reissueRecoveryTOTPVerificationCapability(
							ctx,
							gate.authority,
							gate.lineage.binding,
						);
					});
				} catch (error) {
					if (error instanceof AfterTransactionHookError) {
						await expireRecoveryCookie(ctx);
					}
					return recoveryInvalid();
				}
				return invalidCode();
			}

			try {
				const completed = await runWithTransaction(ctx.context.adapter, async () => {
					const adapter = await getCurrentAdapter(ctx.context.adapter);
					const user = (await lockAndReadActiveUser(
						adapter,
						gate.lineage.subjectId,
					)) as UserWithTwoFactor | null;
					const factor = await adapter.findOne<TwoFactorTable>({
						model: gate.lineage.twoFactorTable,
						where: [
							{ field: "id", value: gate.factor.id },
							{ field: "userId", value: gate.lineage.subjectId },
						],
					});
					if (!user || !factor || !factorIsPendingRecoveryEnrollment(factor, gate.lineage)) {
						return null;
					}
					const binding = await createRecoveryTOTPEnrollmentBinding(
						gate.lineage,
						factor,
					);
					if (
						binding !== gate.lineage.binding ||
						!(await recoveryTOTPVerificationAuthorityIsExact(
							ctx,
							gate.authority,
						))
					) {
						return null;
					}
					if (
						!(await consumeTotpCounter(
							ctx,
							gate.lineage.twoFactorTable,
							factor,
							counter,
							adapter,
						))
					) {
						return null;
					}
					const activated = await adapter.incrementOne<TwoFactorTable>({
						model: gate.lineage.twoFactorTable,
						where: [
							{ field: "id", value: factor.id },
							{ field: "userId", value: gate.lineage.subjectId },
							{ field: "secret", value: factor.secret },
							{ field: "backupCodes", value: factor.backupCodes },
							{ field: "pendingSecret", value: factor.pendingSecret },
							{
								field: "pendingBackupCodes",
								value: factor.pendingBackupCodes,
							},
							{ field: "verified", value: false },
							{
								field: "trustDeviceGeneration",
								value: gate.lineage.trustDeviceGeneration,
							},
							{ field: "lastUsedTotpCounter", value: counter },
						],
						increment: {},
						set: {
							secret: factor.pendingSecret,
							backupCodes: factor.pendingBackupCodes,
							pendingSecret: null,
							pendingBackupCodes: null,
							verified: true,
							failedVerificationCount: 0,
							activeVerificationReservations: "[]",
							lockedUntil: null,
						},
					});
					if (!activated) return null;
					await ctx.context.internalAdapter.updateUser(gate.lineage.subjectId, {
						twoFactorEnabled: true,
					});
					return completeRecoveryFactorRepair(ctx, gate.authority, {
						binding,
						repairFactor: "totp",
						repairedFactorId: factor.id,
					});
				});
				if (!completed) {
					await gate.attempt.restore(ctx.context.adapter);
					return recoveryInvalid();
				}
				return ctx.json(completed);
			} catch (error) {
				if (error instanceof AfterTransactionHookError) {
					await expireRecoveryCookie(ctx);
					return recoveryInvalid();
				}
				await gate.attempt.restore(ctx.context.adapter);
				return recoveryInvalid();
			}
		},
	);

	return { options, verify };
};
