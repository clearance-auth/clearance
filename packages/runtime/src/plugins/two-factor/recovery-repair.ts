import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { APIError } from "@clearance/core/error";
import * as z from "zod";
import {
	RECOVERY_FACTOR_REPAIR_COOKIE,
	createRecoveryFactorRepairBridge,
	preloadRecoveryFactorRepairCapability,
	startRecoveryFactorRepair,
} from "../../internal/recovery-factor-repair-context";
import {
	appendInternalRuntimeAudit,
	attachCapturedInternalRuntimeAudit,
	getRuntimeAuditRequestContext,
	readInternalRuntimeAudit,
	type InternalRuntimeAuditDraft,
} from "@clearance/runtime/internal/runtime-audit";
import {
	STAGED_AUTHENTICATION_COOKIE,
	consumePreloadedStagedAuthenticationCapability,
	inspectStagedAuthenticationAuthority,
	preloadStagedAuthenticationCapability,
} from "../../internal/staged-authentication-context";
import { consumeBackupCodeForRecoveryRepair } from "./backup-codes";
import { TWO_FACTOR_ERROR_CODES } from "./error-code";
import type { TwoFactorOptions, TwoFactorTable } from "./types";

const recoveryRepairBodySchema = z
	.object({
		repairFactor: z.enum(["passkey", "totp"]),
		recoveryCode: z.string().min(1).max(256),
	})
	.strict();

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

function recoveryRepairInvalid(): never {
	throw APIError.from(
		"UNAUTHORIZED",
		TWO_FACTOR_ERROR_CODES.INVALID_STAGED_AUTHENTICATION,
	);
}

function setRecoveryRepairHeaders(ctx: GenericEndpointContext): void {
	ctx.setHeader("cache-control", "no-store");
	ctx.setHeader("pragma", "no-cache");
}

async function expireRepairCookies(ctx: GenericEndpointContext): Promise<void> {
	for (const name of [
		RECOVERY_FACTOR_REPAIR_COOKIE,
		STAGED_AUTHENTICATION_COOKIE,
	]) {
		const cookie = ctx.context.createAuthCookie(name, {
			httpOnly: true,
			sameSite: "lax",
		});
		await ctx.setSignedCookie(name, "", ctx.context.secret, {
			...cookie.attributes,
			maxAge: 0,
		});
	}
}

function repairFactorPluginIsAvailable(
	ctx: GenericEndpointContext,
	repairFactor: "passkey" | "totp",
): boolean {
	const twoFactor = ctx.context.getPlugin("two-factor");
	const options = twoFactor?.options as TwoFactorOptions | undefined;
	if (!twoFactor || options?.accountLockout?.enabled === false) return false;
	if (repairFactor === "passkey") {
		return Boolean(ctx.context.getPlugin("passkey"));
	}
	return options?.totpOptions?.disable !== true;
}

function recoveryRepairIsConfigured(
	ctx: GenericEndpointContext,
	twoFactorTable: string,
): boolean {
	const twoFactor = ctx.context.getPlugin("two-factor");
	const options = twoFactor?.options as
		| {
				twoFactorTable?: string | undefined;
				backupCodeOptions?: { storeBackupCodes?: unknown } | undefined;
		  }
		| undefined;
	return (
		typeof ctx.context.adapter.options?.adapterConfig.transaction === "function" &&
		(ctx.context.options.secondaryStorage === undefined ||
			ctx.context.options.session?.storeSessionInDatabase === true) &&
		Boolean(twoFactor) &&
		(options?.twoFactorTable ?? "twoFactor") === twoFactorTable &&
		options?.backupCodeOptions?.storeBackupCodes === "hashed"
	);
}

/**
 * Converts a primary-plus-backup-code staged challenge into the isolated
 * recovery-factor-repair capability. This deliberately has no session
 * middleware: recovery never becomes a login artifact.
 */
export const createRecoveryFactorRepairEndpoint = (
	options: Readonly<{ twoFactorTable: string }>,
) =>
	createAuthEndpoint(
		"/managed-authentication/recovery-repair",
		{
			method: "POST",
			body: recoveryRepairBodySchema,
		},
		async (ctx) => {
			setRecoveryRepairHeaders(ctx);
			if (
				!repairFactorPluginIsAvailable(ctx, ctx.body.repairFactor) ||
				!recoveryRepairIsConfigured(ctx, options.twoFactorTable)
			) {
				return recoveryRepairInvalid();
			}
			const preloaded = await preloadStagedAuthenticationCapability(ctx, {
				stage: "select_factor",
				binding: "initial",
			});
			if (!preloaded) return recoveryRepairInvalid();

			let bridge: object | null = null;
			let subjectId: string | null = null;
			try {
				const selected = await runWithTransaction(
					ctx.context.adapter,
					async () => {
						const authority =
							await consumePreloadedStagedAuthenticationCapability(ctx, preloaded);
						if (!authority) return null;
						const lineage = inspectStagedAuthenticationAuthority(authority);
						if (!lineage || lineage.expiresAt <= new Date()) return null;
						const stagedRecoveryBridge = await createRecoveryFactorRepairBridge(
							ctx,
							authority,
							ctx.body.repairFactor,
						);
						return { stagedRecoveryBridge, subjectId: lineage.subjectId };
					},
				);
				if (!selected) return recoveryRepairInvalid();
				bridge = selected.stagedRecoveryBridge;
				subjectId = selected.subjectId;
			} catch (error) {
				if (error instanceof AfterTransactionHookError) {
					await expireRepairCookies(ctx);
					return recoveryRepairInvalid();
				}
				return recoveryRepairInvalid();
			}
			if (!bridge || !subjectId) return recoveryRepairInvalid();

			try {
				const result = await runWithTransaction(ctx.context.adapter, async () => {
					const adapter = await getCurrentAdapter(ctx.context.adapter);
					const factor = await adapter.findOne<TwoFactorTable>({
						model: options.twoFactorTable,
						where: [{ field: "userId", value: subjectId }],
					});
					if (!factor) return { kind: "invalid" as const };
					const proof = await consumeBackupCodeForRecoveryRepair(
						ctx,
						adapter,
						options.twoFactorTable,
						factor,
						ctx.body.recoveryCode,
					);
					if (proof.kind === "invalid") return proof;
					const result = await startRecoveryFactorRepair(ctx, {
						stagedRecoveryBridge: bridge,
						recoveryProofAuthority: proof.authority,
						repairFactor: ctx.body.repairFactor,
					});
					await appendRuntimeAuditIfBound(ctx, adapter, {
						actor: subjectId,
						action: "auth.recovery.code_used",
						subjectType: "user",
						subjectId,
						outcome: "success",
						source: "system",
						organizationId: null,
						message: "Recovery code used",
						metadata: { purpose: "factor_repair" },
					});
					await appendRuntimeAuditIfBound(ctx, adapter, {
						actor: subjectId,
						action: "auth.recovery.proof_used",
						subjectType: "user",
						subjectId,
						outcome: "success",
						source: "system",
						organizationId: null,
						message: "Recovery proof used",
						metadata: { repairFactor: ctx.body.repairFactor },
					});
					return {
						kind: "authorized" as const,
						result,
					};
				});
				if (result.kind === "invalid") {
					if ("error" in result) throw result.error;
					return recoveryRepairInvalid();
				}
				return ctx.json({
					status: true,
					repairFactor: result.result.repairFactor,
					expiresAt: result.result.expiresAt,
				});
			} catch (error) {
				if (error instanceof APIError) {
					if (error.body?.code === "INVALID_BACKUP_CODE") {
						throw error;
					}
					return recoveryRepairInvalid();
				}
				if (error instanceof AfterTransactionHookError) {
					await expireRepairCookies(ctx);
				}
				return recoveryRepairInvalid();
			}
		},
	);
