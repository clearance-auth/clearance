import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import type { DBTransactionAdapter, Where } from "@clearance/core/db/adapter";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import { safeJSONParse } from "@clearance/core/utils/json";
import { createHMAC } from "@clearance/utils/hmac";
import { createOTP } from "@clearance/utils/otp";
import * as z from "zod";
import { sensitiveSessionMiddleware } from "../../../api";
import { expireCookie, setSessionCookie } from "../../../cookies";
import type { SecretConfig } from "../../../crypto";
import {
	constantTimeEqual,
	symmetricDecrypt,
	symmetricEncrypt,
} from "../../../crypto";
import { generateRandomString } from "../../../crypto/random";
import { parseUserOutput } from "../../../db/schema";
import {
	captureInternalSessionIssuanceContext,
} from "../../../internal/session-issuance-context";
import { shouldRequirePassword } from "../../../utils/password";
import { PACKAGE_VERSION } from "../../../version";
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
	reserveTwoFactorAttempt,
	resetTwoFactorFailures,
	verifyTwoFactor,
} from "../verify-two-factor";

export interface BackupCodeOptions {
	/**
	 * The amount of backup codes to generate
	 *
	 * @default 10
	 */
	amount?: number | undefined;
	/**
	 * The length of the backup codes
	 *
	 * @default 10
	 */
	length?: number | undefined;
	/**
	 * An optional custom function to generate backup codes
	 */
	customBackupCodesGenerate?: (() => string[]) | undefined;
	/**
	 * How to store the backup codes in the database. Hashed storage is one-way
	 * and should be preferred for recovery credentials.
	 */
	storeBackupCodes?:
		| (
				| "plain"
				| "encrypted"
				| "hashed"
				| {
						encrypt: (token: string) => Promise<string>;
						decrypt: (token: string) => Promise<string>;
				  }
		  )
		| undefined;
	/**
	 * Allow generating backup codes without a password when the user does not
	 * have a credential account.
	 * When enabled, password is still required if a credential account exists.
	 * @default false
	 */
	allowPasswordless?: boolean | undefined;
}

const HASHED_BACKUP_CODES_PREFIX = "clr-recovery:v1:";
const RECOVERY_CODE_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MAX_RECOVERY_CODES = 100;

type HashedBackupCodesEnvelope = {
	version: 1;
	encryptedPepper: string;
	digests: string[];
};

function parseHashedBackupCodes(
	value: string,
): HashedBackupCodesEnvelope | null {
	if (!value.startsWith(HASHED_BACKUP_CODES_PREFIX)) return null;
	const envelope = safeJSONParse<HashedBackupCodesEnvelope>(
		value.slice(HASHED_BACKUP_CODES_PREFIX.length),
	);
	if (
		envelope?.version !== 1 ||
		typeof envelope.encryptedPepper !== "string" ||
		envelope.encryptedPepper.length === 0 ||
		!Array.isArray(envelope.digests) ||
		envelope.digests.length > MAX_RECOVERY_CODES ||
		envelope.digests.some(
			(digest) =>
				typeof digest !== "string" ||
				!RECOVERY_CODE_DIGEST_PATTERN.test(digest),
		) ||
		new Set(envelope.digests).size !== envelope.digests.length
	) {
		return null;
	}
	return envelope;
}

export function isOneWayBackupCodeEnvelope(value: string): boolean {
	return parseHashedBackupCodes(value) !== null;
}

function assertValidRecoveryCodes(codes: string[]): void {
	if (
		codes.length > MAX_RECOVERY_CODES ||
		codes.some((code) => code.length === 0 || code.length > 256) ||
		new Set(codes).size !== codes.length
	) {
		throw new Error(
			`Recovery codes must contain at most ${MAX_RECOVERY_CODES} unique non-empty values`,
		);
	}
}

function parseLegacyRecoveryCodes(value: string): string[] | null {
	const parsed = safeJSONParse<unknown>(value);
	if (
		!Array.isArray(parsed) ||
		parsed.some((code) => typeof code !== "string")
	) {
		return null;
	}
	try {
		assertValidRecoveryCodes(parsed);
		return parsed;
	} catch {
		return null;
	}
}

function generateBackupCodesFn(options?: BackupCodeOptions | undefined) {
	return Array.from({ length: options?.amount ?? 10 })
		.fill(null)
		.map(() => generateRandomString(options?.length ?? 10, "a-z", "0-9", "A-Z"))
		.map((code) => `${code.slice(0, 5)}-${code.slice(5)}`);
}

export async function encodeBackupCodes(
	codes: string[],
	secret: string | SecretConfig,
	options?: BackupCodeOptions | undefined,
): Promise<string> {
	assertValidRecoveryCodes(codes);
	const json = JSON.stringify(codes);
	if (options?.storeBackupCodes === "hashed") {
		const pepper = generateRandomString(64, "a-z", "0-9", "A-Z");
		const hmac = createHMAC("SHA-256", "base64urlnopad");
		const digests = await Promise.all(
			codes.map((code) => hmac.sign(pepper, code)),
		);
		const envelope: HashedBackupCodesEnvelope = {
			version: 1,
			encryptedPepper: await symmetricEncrypt({ data: pepper, key: secret }),
			digests,
		};
		return `${HASHED_BACKUP_CODES_PREFIX}${JSON.stringify(envelope)}`;
	}
	if (options?.storeBackupCodes === "encrypted") {
		return symmetricEncrypt({ data: json, key: secret });
	}
	if (
		typeof options?.storeBackupCodes === "object" &&
		"encrypt" in options?.storeBackupCodes
	) {
		return options.storeBackupCodes.encrypt(json);
	}
	return json;
}

export async function generateBackupCodes(
	secret: string | SecretConfig,
	options?: BackupCodeOptions | undefined,
) {
	const backupCodes = options?.customBackupCodesGenerate
		? options.customBackupCodesGenerate()
		: generateBackupCodesFn(options);
	if (backupCodes.length === 0) {
		throw new Error("At least one recovery code must be generated");
	}
	assertValidRecoveryCodes(backupCodes);
	return {
		backupCodes,
		encryptedBackupCodes: await encodeBackupCodes(backupCodes, secret, options),
	};
}

export async function verifyBackupCode(
	data: {
		backupCodes: string;
		code: string;
	},
	key: string | SecretConfig,
	options?: BackupCodeOptions | undefined,
) {
	if (options?.storeBackupCodes === "hashed") {
		const envelope = parseHashedBackupCodes(data.backupCodes);
		if (!envelope) {
			if (data.backupCodes.startsWith("clr-recovery:")) {
				return { status: false, updated: null };
			}
			let legacyCodes = parseLegacyRecoveryCodes(data.backupCodes);
			if (!legacyCodes) {
				try {
					legacyCodes = parseLegacyRecoveryCodes(
						await symmetricDecrypt({ key, data: data.backupCodes }),
					);
				} catch {
					return { status: false, updated: null };
				}
			}
			if (!legacyCodes) return { status: false, updated: null };
			let legacyMatch = -1;
			for (let index = 0; index < legacyCodes.length; index++) {
				if (
					constantTimeEqual(data.code, legacyCodes[index]!) &&
					legacyMatch === -1
				) {
					legacyMatch = index;
				}
			}
			if (legacyMatch === -1) return { status: false, updated: null };
			return {
				status: true,
				updated: await encodeBackupCodes(
					legacyCodes.filter((_, index) => index !== legacyMatch),
					key,
					options,
				),
			};
		}
		let pepper: string;
		try {
			pepper = await symmetricDecrypt({
				key,
				data: envelope.encryptedPepper,
			});
		} catch {
			return { status: false, updated: null };
		}
		const hmac = createHMAC("SHA-256", "base64urlnopad");
		let match = -1;
		for (let index = 0; index < envelope.digests.length; index++) {
			const matches = await hmac.verify(
				pepper,
				data.code,
				envelope.digests[index]!,
			);
			if (matches && match === -1) match = index;
		}
		if (match === -1) return { status: false, updated: null };
		const updated: HashedBackupCodesEnvelope = {
			version: 1,
			encryptedPepper: await symmetricEncrypt({ data: pepper, key }),
			digests: envelope.digests.filter((_, index) => index !== match),
		};
		return {
			status: true,
			updated: `${HASHED_BACKUP_CODES_PREFIX}${JSON.stringify(updated)}`,
		};
	}
	const codes = await getBackupCodes(data.backupCodes, key, options);
	if (!codes) {
		return {
			status: false,
			updated: null,
		};
	}
	return {
		status: codes.includes(data.code),
		updated: await encodeBackupCodes(
			codes.filter((code) => code !== data.code),
			key,
			options,
		),
	};
}

export async function proveFactorStepUp(
	ctx: GenericEndpointContext,
	adapter: DBTransactionAdapter,
	twoFactorTable: string,
	twoFactor: TwoFactorTable,
	stepUp: {
		currentCode?: string | undefined;
		recoveryCode?: string | undefined;
	},
	options: {
		backupCodeOptions?: BackupCodeOptions | undefined;
		totpOptions?: { digits?: number | undefined; period?: number | undefined };
	},
): Promise<{
	where: Where[];
	set: Record<string, unknown>;
	restoreAttempt: () => Promise<void>;
}> {
	if (Boolean(stepUp.currentCode) === Boolean(stepUp.recoveryCode)) {
		throw APIError.from(
			"BAD_REQUEST",
			TWO_FACTOR_ERROR_CODES.FACTOR_STEP_UP_REQUIRED,
		);
	}
	await assertTwoFactorNotLocked(ctx, twoFactorTable, twoFactor, adapter);
	const accountAttempt = await reserveTwoFactorAttempt(
		ctx,
		twoFactorTable,
		twoFactor,
		adapter,
	);

	if (stepUp.currentCode) {
		let counter: number | null;
		try {
			const secret = await symmetricDecrypt({
				key: ctx.context.secretConfig,
				data: twoFactor.secret,
			});
			counter = await createOTP(secret, {
				digits: options.totpOptions?.digits ?? 6,
				period: options.totpOptions?.period,
			}).verifyWithCounter(stepUp.currentCode);
		} catch (error) {
			await accountAttempt.restore();
			throw error;
		}
		if (counter === null) {
			await accountAttempt.recordFailure();
			throw APIError.from("UNAUTHORIZED", TWO_FACTOR_ERROR_CODES.INVALID_CODE);
		}
		if (twoFactor.lastUsedTotpCounter == null) {
			await adapter.incrementOne<TwoFactorTable>({
				model: twoFactorTable,
				where: [
					{ field: "id", value: twoFactor.id },
					{ field: "secret", value: twoFactor.secret },
					{ field: "lastUsedTotpCounter", value: null },
				],
				increment: {},
				set: { lastUsedTotpCounter: -1 },
			});
		}
		return {
			where: [
				{ field: "secret", value: twoFactor.secret },
				{
					field: "lastUsedTotpCounter",
					operator: "lt",
					value: counter,
				},
			],
			set: { lastUsedTotpCounter: counter },
			restoreAttempt: accountAttempt.restore,
		};
	}

	let verified: Awaited<ReturnType<typeof verifyBackupCode>>;
	try {
		verified = await verifyBackupCode(
			{
				backupCodes: twoFactor.backupCodes,
				code: stepUp.recoveryCode!,
			},
			ctx.context.secretConfig,
			options.backupCodeOptions,
		);
	} catch (error) {
		await accountAttempt.restore();
		throw error;
	}
	if (!verified.status || !verified.updated) {
		await accountAttempt.recordFailure();
		throw APIError.from(
			"UNAUTHORIZED",
			TWO_FACTOR_ERROR_CODES.INVALID_BACKUP_CODE,
		);
	}
	return {
		where: [{ field: "backupCodes", value: twoFactor.backupCodes }],
		set: { backupCodes: verified.updated },
		restoreAttempt: accountAttempt.restore,
	};
}

export async function getBackupCodes(
	backupCodes: string,
	key: string | SecretConfig,
	options?: BackupCodeOptions | undefined,
) {
	if (options?.storeBackupCodes === "hashed") return null;
	if (options?.storeBackupCodes === "encrypted") {
		const decrypted = await symmetricDecrypt({ key, data: backupCodes });
		return safeJSONParse<string[]>(decrypted);
	}
	if (
		typeof options?.storeBackupCodes === "object" &&
		"decrypt" in options?.storeBackupCodes
	) {
		const decrypted = await options?.storeBackupCodes.decrypt(backupCodes);
		return safeJSONParse<string[]>(decrypted);
	}

	return safeJSONParse<string[]>(backupCodes);
}

const verifyBackupCodeBodySchema = z.object({
	code: z.string().meta({
		description: `A backup code to verify. Eg: "123456"`,
	}),
	/**
	 * Disable setting the session cookie
	 */
	disableSession: z
		.boolean()
		.meta({
			description: "If true, the session cookie will not be set.",
		})
		.optional(),
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

const viewBackupCodesBodySchema = z.object({
	userId: z.coerce.string().meta({
		description: `The user ID to view all backup codes. Eg: "user-id"`,
	}),
});

export const backupCode2fa = (
	opts: BackupCodeOptions,
	totpOptions?: { digits?: number | undefined; period?: number | undefined },
) => {
	const twoFactorTable = "twoFactor";
	const passwordSchema = z.string().meta({
		description: "The users password.",
	});
	const generateBackupCodesBodySchema = opts.allowPasswordless
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
		id: "backup_code",
		version: PACKAGE_VERSION,
		endpoints: {
			/**
			 * ### Endpoint
			 *
			 * POST `/two-factor/verify-backup-code`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.verifyBackupCode`
			 *
			 * **client:**
			 * `authClient.twoFactor.verifyBackupCode`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			verifyBackupCode: createAuthEndpoint(
				"/two-factor/verify-backup-code",

				{
					method: "POST",
					body: verifyBackupCodeBodySchema,
					metadata: {
						openapi: {
							description: "Verify a backup code for two-factor authentication",
							responses: {
								"200": {
									description: "Backup code verified successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
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
															twoFactorEnabled: {
																type: "boolean",
																description:
																	"Whether two-factor authentication is enabled for the user",
															},
															createdAt: {
																type: "string",
																format: "date-time",
																description:
																	"Timestamp when the user was created",
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
															"twoFactorEnabled",
															"createdAt",
															"updatedAt",
														],
														description:
															"The authenticated user object with two-factor details",
													},
													session: {
														type: "object",
														properties: {
															token: {
																type: "string",
																description: "Session token",
															},
															userId: {
																type: "string",
																description:
																	"ID of the user associated with the session",
															},
															createdAt: {
																type: "string",
																format: "date-time",
																description:
																	"Timestamp when the session was created",
															},
															expiresAt: {
																type: "string",
																format: "date-time",
																description:
																	"Timestamp when the session expires",
															},
														},
														required: [
															"token",
															"userId",
															"createdAt",
															"expiresAt",
														],
														description:
															"The current session object, included unless disableSession is true",
													},
												},
												required: ["user", "session"],
											},
										},
									},
								},
							},
						},
					},
				},
				async (ctx) => {
					const { session, valid, beginAttempt } = await verifyTwoFactor(ctx);
					const user = session.user as UserWithTwoFactor;
					const isSignIn = !session.session;
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
							TWO_FACTOR_ERROR_CODES.BACKUP_CODES_NOT_ENABLED,
						);
					}
					if (isSignIn) {
						await assertTwoFactorNotLocked(ctx, twoFactorTable, twoFactor);
					}
					// Enforce the per-challenge attempt budget on the sign-in path.
					// The re-verify branch (already authenticated) is not gated.
					const attempt = isSignIn
						? await beginAttempt(DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS)
						: null;
					const accountAttempt = isSignIn
						? await reserveTwoFactorAttempt(ctx, twoFactorTable, twoFactor)
						: null;
					let validate: Awaited<ReturnType<typeof verifyBackupCode>>;
					try {
						validate = await verifyBackupCode(
							{
								backupCodes: twoFactor.backupCodes,
								code: ctx.body.code,
							},
							ctx.context.secretConfig,
							opts,
						);
					} catch (error) {
						// A server error before the code is checked must not spend the slot.
						await attempt?.restore();
						await accountAttempt?.restore();
						throw error;
					}
					if (!validate.status || !validate.updated) {
						await attempt?.recordFailure();
						await accountAttempt?.recordFailure();
						throw APIError.from(
							"UNAUTHORIZED",
							TWO_FACTOR_ERROR_CODES.INVALID_BACKUP_CODE,
						);
					}
					const updated = await ctx.context.adapter.incrementOne({
						model: twoFactorTable,
						where: [
							{
								field: "id",
								value: twoFactor.id,
							},
							{
								field: "backupCodes",
								value: twoFactor.backupCodes,
							},
						],
						increment: {},
						set: {
							backupCodes: validate.updated,
						},
					});
					if (!updated) {
						await attempt?.restore();
						await accountAttempt?.restore();
						throw APIError.fromStatus("CONFLICT", {
							message: "Failed to verify backup code. Please try again.",
						});
					}

					if (isSignIn) {
						await accountAttempt?.recordSuccess();
					}
					if (!ctx.body.disableSession) {
						return valid(ctx);
					}
					return ctx.json({
						token: session.session?.token,
						user: parseUserOutput(ctx.context.options, session.user),
					});
				},
			),
			/**
			 * ### Endpoint
			 *
			 * POST `/two-factor/generate-backup-codes`
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.generateBackupCodes`
			 *
			 * **client:**
			 * `authClient.twoFactor.generateBackupCodes`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			generateBackupCodes: createAuthEndpoint(
				"/two-factor/generate-backup-codes",
				{
					method: "POST",
					body: generateBackupCodesBodySchema,
					use: [sensitiveSessionMiddleware],
					metadata: {
						openapi: {
							description:
								"Generate new backup codes for two-factor authentication",
							responses: {
								"200": {
									description: "Backup codes generated successfully",
									content: {
										"application/json": {
											schema: {
												type: "object",
												properties: {
													status: {
														type: "boolean",
														description:
															"Indicates if the backup codes were generated successfully",
														enum: [true],
													},
													backupCodes: {
														type: "array",
														items: { type: "string" },
														description:
															"Array of generated backup codes in plain text",
													},
												},
												required: ["status", "backupCodes"],
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
					if (!user.twoFactorEnabled) {
						throw APIError.from(
							"BAD_REQUEST",
							TWO_FACTOR_ERROR_CODES.TWO_FACTOR_NOT_ENABLED,
						);
					}
					const requirePassword = await shouldRequirePassword(
						ctx,
						user.id,
						opts.allowPasswordless,
					);
					if (requirePassword) {
						if (!ctx.body.password) {
							throw APIError.from(
								"BAD_REQUEST",
								BASE_ERROR_CODES.INVALID_PASSWORD,
							);
						}
						await ctx.context.password.checkPassword(user.id, ctx);
					}

					const twoFactor = await ctx.context.adapter.findOne<TwoFactorTable>({
						model: twoFactorTable,
						where: [{ field: "userId", value: user.id }],
					});
					if (!twoFactor || twoFactor.verified === false) {
						throw APIError.from(
							"BAD_REQUEST",
							TWO_FACTOR_ERROR_CODES.TWO_FACTOR_NOT_ENABLED,
						);
					}
					// Keep a failed step-up reservation durable by performing it before
					// the lifecycle transaction. The exact-old-value guards below still
					// serialize recovery consumption and factor mutation.
					const proof = await proveFactorStepUp(
						ctx,
						ctx.context.adapter,
						twoFactorTable,
						twoFactor,
						{
							currentCode: ctx.body.currentCode,
							recoveryCode: ctx.body.recoveryCode,
						},
						{ backupCodeOptions: opts, totpOptions },
					);
					const rotated = await runWithTransaction(
						ctx.context.adapter,
						async () => {
							const replacementIssuanceContext =
								await captureInternalSessionIssuanceContext(
									ctx.context.internalAdapter,
									{
										purpose: "replacement",
										sourceSessionToken:
											ctx.context.session.session.token,
									},
								);
							const adapter = await getCurrentAdapter(ctx.context.adapter);
							const generated = await generateBackupCodes(
								ctx.context.secretConfig,
								opts,
							);
							const authorized = await adapter.incrementOne<TwoFactorTable>({
								model: twoFactorTable,
								where: [{ field: "id", value: twoFactor.id }, ...proof.where],
								increment: {},
								set: {
									...proof.set,
									backupCodes: generated.encryptedBackupCodes,
									trustDeviceGeneration: generateRandomString(32),
									failedVerificationCount: 0,
									activeVerificationReservations: "[]",
									lockedUntil: null,
								},
							});
							if (!authorized) {
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
									preserveSessionLifetime(ctx.context.session.session),
									false,
									replacementIssuanceContext,
								);
							return { generated, replacementSession, updatedUser };
						},
					).catch(async (error) => {
						await proof.restoreAttempt();
						throw error;
					});
					await setSessionCookie(ctx, {
						session: rotated.replacementSession,
						user: rotated.updatedUser,
					});
					expireCookie(
						ctx,
						ctx.context.createAuthCookie(TRUST_DEVICE_COOKIE_NAME, {
							maxAge: TRUST_DEVICE_COOKIE_MAX_AGE,
						}),
					);
					return ctx.json({
						status: true,
						backupCodes: rotated.generated.backupCodes,
					});
				},
			),
			/**
			 * A server-only function that returns a user's decrypted two-factor
			 * backup codes. It is not exposed over HTTP and has no client method;
			 * call it from trusted server code with a `userId` taken from an
			 * authenticated session.
			 *
			 * ### API Methods
			 *
			 * **server:**
			 * `auth.api.viewBackupCodes`
			 *
			 * @see [Read our docs to learn more.](https://github.com/clearance-auth/clearance)
			 */
			viewBackupCodes: createAuthEndpoint.serverOnly(
				{
					method: "POST",
					body: viewBackupCodesBodySchema,
				},
				async (ctx) => {
					const twoFactor = await ctx.context.adapter.findOne<TwoFactorTable>({
						model: twoFactorTable,
						where: [
							{
								field: "userId",
								value: ctx.body.userId,
							},
						],
					});
					if (!twoFactor) {
						throw APIError.from(
							"BAD_REQUEST",
							TWO_FACTOR_ERROR_CODES.BACKUP_CODES_NOT_ENABLED,
						);
					}
					const decryptedBackupCodes = await getBackupCodes(
						twoFactor.backupCodes,
						ctx.context.secretConfig,
						opts,
					);

					if (!decryptedBackupCodes) {
						throw APIError.from(
							"BAD_REQUEST",
							TWO_FACTOR_ERROR_CODES.INVALID_BACKUP_CODE,
						);
					}
					return ctx.json({
						status: true,
						backupCodes: decryptedBackupCodes,
					});
				},
			),
		},
	} satisfies TwoFactorProvider;
};
