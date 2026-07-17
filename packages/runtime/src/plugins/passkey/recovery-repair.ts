import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { APIError } from "@clearance/core/error";
import { base64Url } from "@clearance/utils/base64";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import {
	generateRegistrationOptions,
	verifyRegistrationResponse,
} from "@simplewebauthn/server";
import * as z from "zod";
import {
	completeRecoveryFactorRepair,
	consumePreloadedRecoveryFactorRepairCapability,
	createRecoveryFactorRepairBinding,
	inspectRecoveryFactorRepairAuthority,
	preloadRecoveryFactorRepairCapability,
	RECOVERY_FACTOR_REPAIR_COOKIE,
	recoveryFactorRepairSelectionAuthorityIsExact,
	restartRecoveryPasskeyRegistrationCapability,
	rotateRecoveryFactorRepairCapability,
} from "../../internal/recovery-factor-repair-context";
import { lockAndReadActiveUser } from "../../db/user-authority";
import {
	CHALLENGE_TTL_SECONDS,
	consumeChallengeByParsedChallenge,
	createChallenge,
	parseClientDataChallenge,
} from "./challenge";
import { PASSKEY_ERROR_CODES } from "./error-codes";
import { assertTrustedOrigin, resolveRpID } from "./origin";
import type { Passkey, PasskeyOptions } from "./types";
import {
	decodeCanonicalUserHandle,
	ensurePasskeyUserHandleForAdapter,
} from "./user-handle";
import type { TwoFactorTable } from "../two-factor/types";

const NAME_MAX_LENGTH = 100;

const transportSchema = z.enum([
	"ble",
	"cable",
	"hybrid",
	"internal",
	"nfc",
	"smart-card",
	"usb",
]);

const registrationResponseSchema = z.object({
	id: z.string().min(1).max(1024),
	rawId: z.string().min(1).max(1024),
	type: z.literal("public-key"),
	authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
	clientExtensionResults: z.record(z.string(), z.any()),
	response: z.object({
		clientDataJSON: z.string().min(1).max(8_000),
		attestationObject: z.string().min(1).max(200_000),
		authenticatorData: z.string().max(8_000).optional(),
		transports: z.array(transportSchema).max(10).optional(),
		publicKeyAlgorithm: z.number().optional(),
		publicKey: z.string().max(4_096).optional(),
	}),
});

const registrationOptionsSchema = z
	.object({
		authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
	})
	.strict()
	.optional();

function recoveryRepairFailed(): never {
	throw APIError.from("UNAUTHORIZED", PASSKEY_ERROR_CODES.REMEDIATION_FAILED);
}

async function withRecoveryRepairFailureBoundary<T>(
	operation: () => Promise<T>,
): Promise<T> {
	try {
		return await operation();
	} catch {
		recoveryRepairFailed();
	}
}

function setRecoveryRepairHeaders(ctx: GenericEndpointContext): void {
	ctx.setHeader("cache-control", "no-store");
	ctx.setHeader("pragma", "no-cache");
}

async function expireRecoveryRepairCookie(ctx: GenericEndpointContext): Promise<void> {
	const cookie = ctx.context.createAuthCookie(RECOVERY_FACTOR_REPAIR_COOKIE, {
		httpOnly: true,
		sameSite: "lax",
	});
	await ctx.setSignedCookie(cookie.name, "", ctx.context.secret, {
		...cookie.attributes,
		maxAge: 0,
	});
}

async function restartFailedRegistrationProof(
	ctx: GenericEndpointContext,
	authority: object,
): Promise<never> {
	try {
		await runWithTransaction(ctx.context.adapter, () =>
			restartRecoveryPasskeyRegistrationCapability(ctx, authority),
		);
	} catch {
		// The presented bearer has already been consumed. Clear it whenever the
		// recovery-only successor cannot be published, including an
		// after-commit cookie-publication failure, so a client never retains a
		// stale capability cookie after a failed retry handoff.
		await expireRecoveryRepairCookie(ctx);
	}
	return recoveryRepairFailed();
}

function assertRecoveryRepairConfiguration(ctx: GenericEndpointContext): void {
	if (
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function" ||
		(ctx.context.options.secondaryStorage !== undefined &&
			ctx.context.options.session?.storeSessionInDatabase !== true)
	) {
		throw new Error("Recovery repair requires rollback-capable persistence");
	}
}

async function registrationBinding(
	authority: object,
	challenge: Readonly<{ digestId: string }>,
): Promise<string | null> {
	const lineage = inspectRecoveryFactorRepairAuthority(authority);
	if (!lineage || lineage.stage !== "passkey_registration") return null;
	return createRecoveryFactorRepairBinding(lineage, [
		"recovery-registration",
		challenge.digestId,
	]);
}

export const generatePasskeyRecoveryRepairRegistrationOptions = (
	options: PasskeyOptions | undefined,
) =>
	createAuthEndpoint(
		"/passkey/generate-recovery-repair-registration-options",
		{
			method: "POST",
			body: registrationOptionsSchema,
		},
		async (ctx) => {
			setRecoveryRepairHeaders(ctx);
			return withRecoveryRepairFailureBoundary(async () => {
				assertRecoveryRepairConfiguration(ctx);
				const preloaded = await preloadRecoveryFactorRepairCapability(ctx, {
					stage: "select_repair",
					repairFactor: "passkey",
				});
				if (!preloaded) recoveryRepairFailed();
				const rpID = resolveRpID(ctx, options);
				const origin = assertTrustedOrigin(ctx, options, rpID);

				try {
					return await runWithTransaction(ctx.context.adapter, async () => {
						const authority = await consumePreloadedRecoveryFactorRepairCapability(
							ctx,
							preloaded,
						);
						if (!authority) recoveryRepairFailed();
						const initial = inspectRecoveryFactorRepairAuthority(authority);
						if (
							!initial ||
							initial.stage !== "select_repair" ||
							initial.repairFactor !== "passkey" ||
							!(await recoveryFactorRepairSelectionAuthorityIsExact(
								ctx,
								authority,
							))
						) {
							recoveryRepairFailed();
						}
						const adapter = await getCurrentAdapter(ctx.context.adapter);
						const user = await lockAndReadActiveUser(adapter, initial.subjectId);
						if (!user) recoveryRepairFailed();
						const recoveryFactor = await adapter.findOne<TwoFactorTable>({
							model: initial.twoFactorTable,
							where: [
								{ field: "id", value: initial.recoveryFactorId },
								{ field: "userId", value: user.id },
							],
						});
						if (
							!recoveryFactor ||
							recoveryFactor.verified !== true ||
							typeof recoveryFactor.secret !== "string" ||
							typeof recoveryFactor.backupCodes !== "string" ||
							recoveryFactor.trustDeviceGeneration !== initial.trustDeviceGeneration
						) {
							recoveryRepairFailed();
						}
						const existingPasskeys = await adapter.findMany<Passkey>({
							model: "passkey",
							where: [{ field: "userId", value: user.id }],
							limit: 1,
						});
						if (existingPasskeys.length !== 0) recoveryRepairFailed();
						const userHandle = await ensurePasskeyUserHandleForAdapter(adapter, user.id);
						const registrationOptions = await generateRegistrationOptions({
							rpName: options?.rpName || ctx.context.appName,
							rpID,
							userID: new Uint8Array(decodeCanonicalUserHandle(userHandle)),
							userName: user.email || user.id,
							userDisplayName: user.name || user.email || user.id,
							attestationType: "none",
							timeout: CHALLENGE_TTL_SECONDS * 1_000,
							excludeCredentials: [],
							authenticatorSelection: {
								...options?.authenticatorSelection,
								...(ctx.body?.authenticatorAttachment
									? { authenticatorAttachment: ctx.body.authenticatorAttachment }
									: {}),
								residentKey: "required",
								requireResidentKey: true,
								userVerification: "required",
							},
						});
						const issued = await createChallenge(
							ctx,
							"recovery-registration",
							registrationOptions.challenge,
							{
								rpID,
								origin,
								userId: user.id,
								userHandle,
								expiresAt: initial.expiresAt,
							},
						);
						const binding = await createRecoveryFactorRepairBinding(initial, [
							"recovery-registration",
							issued.digestId,
						]);
						await rotateRecoveryFactorRepairCapability(ctx, authority, {
							stage: "passkey_registration",
							binding,
						});
						return registrationOptions;
					});
				} catch (error) {
					if (error instanceof AfterTransactionHookError) {
						await expireRecoveryRepairCookie(ctx);
					}
					throw error;
				}
			});
		},
	);

export const verifyPasskeyRecoveryRepairRegistration = (
	options: PasskeyOptions | undefined,
) =>
	createAuthEndpoint(
		"/passkey/verify-recovery-repair-registration",
		{
			method: "POST",
			body: z.object({
				response: registrationResponseSchema,
				name: z.string().trim().min(1).max(NAME_MAX_LENGTH).optional(),
			}).strict(),
		},
		async (ctx) => {
			setRecoveryRepairHeaders(ctx);
			return withRecoveryRepairFailureBoundary(async () => {
				assertRecoveryRepairConfiguration(ctx);
				const preloaded = await preloadRecoveryFactorRepairCapability(ctx, {
					stage: "passkey_registration",
					repairFactor: "passkey",
				});
				if (!preloaded) recoveryRepairFailed();
				// Consume recovery authority before parsing or trusting any proof input.
				// A malformed clientDataJSON has no safe challenge identifier to delete,
				// yet it must still burn the bearer that authorized this ceremony. Any
				// parseable challenge is consumed in the same transaction as that bearer.
				const challenge = parseClientDataChallenge(
					ctx.body.response.response.clientDataJSON,
				);

				const consumed = await runWithTransaction(ctx.context.adapter, async () => {
					const authority = await consumePreloadedRecoveryFactorRepairCapability(
						ctx,
						preloaded,
					);
					const challengeRecord = challenge
						? await consumeChallengeByParsedChallenge(
								ctx,
								"recovery-registration",
								challenge,
							)
						: null;
					return { authority, challengeRecord };
				});
				const authority = consumed.authority;
				if (!authority) recoveryRepairFailed();

				let rpID: string;
				let origin: string;
				let lineage: ReturnType<typeof inspectRecoveryFactorRepairAuthority>;
				let expectedBinding: string | null;
				try {
					rpID = resolveRpID(ctx, options);
					origin = assertTrustedOrigin(ctx, options, rpID);
					lineage = inspectRecoveryFactorRepairAuthority(authority);
					expectedBinding = consumed.challengeRecord
						? await registrationBinding(authority, consumed.challengeRecord)
						: null;
				} catch {
					return restartFailedRegistrationProof(ctx, authority);
				}
				if (
					!challenge ||
					!lineage ||
					!consumed.challengeRecord ||
					!expectedBinding ||
					lineage.binding !== expectedBinding ||
					lineage.subjectId !== consumed.challengeRecord.userId ||
					consumed.challengeRecord.rpID !== rpID ||
					consumed.challengeRecord.origin !== origin ||
					!consumed.challengeRecord.userHandle ||
					consumed.challengeRecord.expiresAt > lineage.expiresAt
				) {
					return restartFailedRegistrationProof(ctx, authority);
				}
				const challengeRecord = consumed.challengeRecord;

				let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
				try {
					verification = await verifyRegistrationResponse({
						response: ctx.body.response as unknown as RegistrationResponseJSON,
						expectedChallenge: challenge,
						expectedOrigin: origin,
						expectedRPID: rpID,
						requireUserVerification: true,
					});
				} catch {
					return restartFailedRegistrationProof(ctx, authority);
				}
				if (!verification.verified || !verification.registrationInfo) {
					return restartFailedRegistrationProof(ctx, authority);
				}

				const { aaguid, credential, credentialDeviceType, credentialBackedUp } =
					verification.registrationInfo;
				try {
					return await runWithTransaction(ctx.context.adapter, async () => {
						const lineage = inspectRecoveryFactorRepairAuthority(authority);
						if (
							!lineage ||
							lineage.stage !== "passkey_registration" ||
							lineage.repairFactor !== "passkey" ||
							lineage.subjectId !== challengeRecord.userId
						) {
							recoveryRepairFailed();
						}
						const binding = await registrationBinding(
							authority,
							challengeRecord,
						);
						if (!binding || binding !== lineage.binding) recoveryRepairFailed();
						const adapter = await getCurrentAdapter(ctx.context.adapter);
						const user = await lockAndReadActiveUser(adapter, lineage.subjectId);
						if (!user || !challengeRecord.userHandle) recoveryRepairFailed();
						const userHandle = await ensurePasskeyUserHandleForAdapter(adapter, user.id);
						if (userHandle !== challengeRecord.userHandle) recoveryRepairFailed();
						const existingPasskey = await adapter.findOne<Passkey>({
							model: "passkey",
							where: [{ field: "userId", value: user.id }],
						});
						if (existingPasskey) recoveryRepairFailed();
						const existingCredential = await adapter.findOne<Passkey>({
							model: "passkey",
							where: [{ field: "credentialID", value: credential.id }],
						});
						if (existingCredential) recoveryRepairFailed();

						let created: Passkey;
						try {
							created = await adapter.create<Omit<Passkey, "id">, Passkey>({
								model: "passkey",
								data: {
									userId: user.id,
									name: ctx.body.name,
									credentialID: credential.id,
									publicKey: base64Url.encode(credential.publicKey, { padding: false }),
									userHandle,
									counter: credential.counter,
									deviceType: credentialDeviceType,
									backedUp: credentialBackedUp,
									transports: ctx.body.response.response.transports?.join(","),
									aaguid,
									createdAt: new Date(),
									updatedAt: new Date(),
								} as Omit<Passkey, "id">,
							});
						} catch {
							const conflicting = await adapter.findOne<Passkey>({
								model: "passkey",
								where: [{ field: "credentialID", value: credential.id }],
							});
							if (conflicting) recoveryRepairFailed();
							throw new Error("Recovery repair credential creation failed");
						}
						if (!created || created.userId !== user.id) recoveryRepairFailed();
						return completeRecoveryFactorRepair(ctx, authority, {
							binding,
							repairFactor: "passkey",
							repairedFactorId: created.id,
						});
					});
				} catch (error) {
					if (error instanceof AfterTransactionHookError) {
						await expireRecoveryRepairCookie(ctx);
					}
					throw error;
				}
			});
		},
	);
