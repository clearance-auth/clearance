import type { GenericEndpointContext } from "@clearance/core";
import {
	getCurrentAdapter,
	queueAfterTransactionHook,
} from "@clearance/core/context";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { APIError } from "@clearance/core/error";
import { createHMAC } from "@clearance/utils/hmac";
import { getSessionFromCtx } from "../../api";
import { expireCookie, setSessionCookie } from "../../cookies";
import { generateRandomString } from "../../crypto/random";
import { parseUserOutput } from "../../db/schema";
import {
	runManagedAuthenticationTransaction,
	usesManagedAuthenticationPolicy,
} from "../../internal/managed-authentication-transaction";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallenge,
} from "../../internal/verification-challenge-context";
import {
	DEFAULT_ACCOUNT_LOCKOUT_DURATION_SECONDS,
	DEFAULT_ACCOUNT_LOCKOUT_MAX_FAILED_ATTEMPTS,
	TRUST_DEVICE_COOKIE_MAX_AGE,
	TRUST_DEVICE_COOKIE_NAME,
	TWO_FACTOR_COOKIE_NAME,
} from "./constant";
import { TWO_FACTOR_ERROR_CODES } from "./error-code";
import type {
	TwoFactorOptions,
	TwoFactorTable,
	UserWithTwoFactor,
} from "./types";
import {
	recordTrustGeneration,
	TWO_FACTOR_CHALLENGE_PURPOSE,
} from "./utils";

export async function verifyTwoFactor(ctx: GenericEndpointContext) {
	const invalid = (errorKey: keyof typeof TWO_FACTOR_ERROR_CODES) => {
		throw APIError.from("UNAUTHORIZED", TWO_FACTOR_ERROR_CODES[errorKey]);
	};

	const session = await getSessionFromCtx(ctx);
	if (!session) {
		const twoFactorCookie = ctx.context.createAuthCookie(
			TWO_FACTOR_COOKIE_NAME,
		);
		const signedTwoFactorCookie = await ctx.getSignedCookie(
			twoFactorCookie.name,
			ctx.context.secret,
		);
		if (!signedTwoFactorCookie) {
			throw APIError.from(
				"UNAUTHORIZED",
				TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE,
			);
		}
		const verificationToken =
			await ctx.context.internalAdapter.findVerificationValueAndPruneExpired(
				signedTwoFactorCookie,
			);
		if (!verificationToken) {
			throw APIError.from(
				"UNAUTHORIZED",
				TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE,
			);
		}
		const user = (await ctx.context.internalAdapter.findUserById(
			verificationToken.value,
		)) as UserWithTwoFactor;
		if (!user) {
			throw APIError.from(
				"UNAUTHORIZED",
				TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE,
			);
		}
		const dontRememberMe = await ctx.getSignedCookie(
			ctx.context.authCookies.dontRememberToken.name,
			ctx.context.secret,
		);
		return {
			valid: async (ctx: GenericEndpointContext) => {
				const managed = usesManagedAuthenticationPolicy(ctx);
				const session = await runManagedAuthenticationTransaction(
					ctx,
					async () => {
						// The challenge consume and every session/trust mutation it
						// authorizes share the managed primary transaction. Cookie writes
						// are queued until that transaction commits.
						const consumed = await consumeInternalVerificationChallenge(
							ctx.context.internalAdapter,
							{
								purpose: TWO_FACTOR_CHALLENGE_PURPOSE.signIn,
								subject: user.id,
								identifier: signedTwoFactorCookie,
							},
						);
						if (!consumed || consumed.value !== user.id) return null;
						const createdSession =
							await ctx.context.internalAdapter.createSession(
								consumed.value,
								!!dontRememberMe,
							);
						if (!createdSession) {
							throw APIError.from("INTERNAL_SERVER_ERROR", {
								message: "failed to create session",
								code: "FAILED_TO_CREATE_SESSION",
							});
						}

						let trustCookie:
							| {
									name: string;
									value: string;
									attributes: Parameters<typeof ctx.setSignedCookie>[3];
							  }
							| undefined;
						if (ctx.body.trustDevice) {
							const plugin = ctx.context.getPlugin("two-factor");
							const maxAge =
								plugin!.options?.trustDeviceMaxAge ??
								TRUST_DEVICE_COOKIE_MAX_AGE;
							const trustDeviceCookie = ctx.context.createAuthCookie(
								TRUST_DEVICE_COOKIE_NAME,
								{ maxAge },
							);
							const adapter = await getCurrentAdapter(ctx.context.adapter);
							const factor = await adapter.findOne<TwoFactorTable>({
								model: plugin!.options?.twoFactorTable ?? "twoFactor",
								where: [{ field: "userId", value: user.id }],
							});
							const trustGeneration = factor?.trustDeviceGeneration;
							if (trustGeneration) {
								const identifier = `trust-device-${generateRandomString(32)}`;
								const expiresAt = new Date(Date.now() + maxAge * 1000);
								const token = await createHMAC(
									"SHA-256",
									"base64urlnopad",
								).sign(
									ctx.context.secret,
									`${user.id}!${identifier}!${trustGeneration}`,
								);
								await createInternalVerificationChallenge(
									ctx.context.internalAdapter,
									{
										purpose: TWO_FACTOR_CHALLENGE_PURPOSE.trustDevice,
										subject: user.id,
									},
									{
										value: `${user.id}!${trustGeneration}`,
										identifier,
										expiresAt,
									},
								);
								await recordTrustGeneration(
									ctx,
									user.id,
									trustGeneration,
									expiresAt,
								);
								trustCookie = {
									name: trustDeviceCookie.name,
									value: `${token}!${identifier}!${trustGeneration}`,
									attributes: trustDeviceCookie.attributes,
								};
							}
						}

						const publishCookies = async () => {
							await setSessionCookie(ctx, {
								session: createdSession,
								user,
							});
							expireCookie(ctx, twoFactorCookie);
							if (trustCookie) {
								await ctx.setSignedCookie(
									trustCookie.name,
									trustCookie.value,
									ctx.context.secret,
									trustCookie.attributes,
								);
								expireCookie(ctx, ctx.context.authCookies.dontRememberToken);
							}
						};
						if (managed) {
							await queueAfterTransactionHook(
								publishCookies,
								ctx.context.adapter,
							);
						} else {
							await publishCookies();
						}
						return createdSession;
					},
				);
				if (!session) {
					expireCookie(ctx, twoFactorCookie);
					throw APIError.from(
						"UNAUTHORIZED",
						TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE,
					);
				}
				return ctx.json({
					token: session.token,
					user: parseUserOutput(ctx.context.options, user),
				});
			},
			invalid,
			session: {
				session: null,
				user,
			},
			key: signedTwoFactorCookie,
			beginAttempt: async (allowedAttempts: number) => {
				const identifier = `2fa-attempts-${signedTwoFactorCookie}`;
				const managed = usesManagedAuthenticationPolicy(ctx);
				const gate = await runManagedAuthenticationTransaction(ctx, async () => {
					// Consume the precreated counter as the atomic race gate; a missing
					// row means a lost race or an expired challenge.
					let consumed;
					try {
						consumed = await consumeInternalVerificationChallenge(
							ctx.context.internalAdapter,
							{
								purpose: TWO_FACTOR_CHALLENGE_PURPOSE.attemptBudget,
								subject: user.id,
								identifier,
							},
						);
					} catch (error) {
						if (managed) throw error;
						consumed = null;
					}
					if (!consumed) return { kind: "invalid" as const };
					const parsed = Number(consumed.value);
					const attempts =
						Number.isInteger(parsed) && parsed >= 0 ? parsed : allowedAttempts;
					if (attempts >= allowedAttempts) {
						// Budget spent: cancel the whole challenge in the same transaction
						// as the counter consume. Returning commits both consumes before the
						// public error is raised below.
						try {
							await consumeInternalVerificationChallenge(
								ctx.context.internalAdapter,
								{
									purpose: TWO_FACTOR_CHALLENGE_PURPOSE.signIn,
									subject: user.id,
									identifier: signedTwoFactorCookie,
								},
							);
						} catch (error) {
							if (managed) throw error;
						}
						return { kind: "spent" as const };
					}
					return {
						kind: "ready" as const,
						attempts,
						expiresAt: consumed.expiresAt,
					};
				});
				if (gate.kind === "invalid") {
					throw APIError.from(
						"UNAUTHORIZED",
						TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE,
					);
				}
				if (gate.kind === "spent") {
					expireCookie(ctx, twoFactorCookie);
					throw APIError.from(
						"BAD_REQUEST",
						TWO_FACTOR_ERROR_CODES.TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE,
					);
				}
				const rearm = async (count: number) => {
					try {
						await runManagedAuthenticationTransaction(ctx, () =>
							createInternalVerificationChallenge(
								ctx.context.internalAdapter,
								{
									purpose: TWO_FACTOR_CHALLENGE_PURPOSE.attemptBudget,
									subject: user.id,
								},
								{
									value: `${count}`,
									identifier,
									expiresAt: gate.expiresAt,
								},
							),
						);
					} catch (error) {
						if (managed) throw error;
					}
				};
				return {
					// recordFailure spends a slot; restore returns it on a server
					// error. Both swallow write errors (fail closed).
					recordFailure: () => rearm(gate.attempts + 1),
					restore: () => rearm(gate.attempts),
				};
			},
		};
	}
	return {
		valid: async (ctx: GenericEndpointContext) => {
			return ctx.json({
				token: session.session.token,
				user: parseUserOutput(ctx.context.options, session.user),
			});
		},
		invalid,
		session,
		key: `${session.user.id}!${session.session.id}`,
		// Re-verification is already authenticated, so it carries no attempt cap.
		beginAttempt: async (_allowedAttempts: number) => ({
			recordFailure: async () => {},
			restore: async () => {},
		}),
	};
}

function resolveAccountLockoutConfig(ctx: GenericEndpointContext) {
	const options = ctx.context.getPlugin("two-factor")?.options as
		TwoFactorOptions | undefined;
	const lockout = options?.accountLockout;
	return {
		enabled: lockout?.enabled ?? true,
		maxFailedAttempts:
			lockout?.maxFailedAttempts ?? DEFAULT_ACCOUNT_LOCKOUT_MAX_FAILED_ATTEMPTS,
		durationMs:
			(lockout?.durationSeconds ?? DEFAULT_ACCOUNT_LOCKOUT_DURATION_SECONDS) *
			1000,
	};
}

/**
 * Reject the verification when the account is locked, and lazily clear an
 * expired lock. The lock caps consecutive failed verifications per account,
 * across challenges and factors (NIST SP 800-63B §5.2.2).
 */
export async function assertTwoFactorNotLocked(
	ctx: GenericEndpointContext,
	twoFactorTable: string,
	twoFactor: TwoFactorTable,
	adapter: DBTransactionAdapter = ctx.context.adapter,
): Promise<void> {
	const { enabled } = resolveAccountLockoutConfig(ctx);
	if (!enabled || !twoFactor.lockedUntil) return;
	const lockedUntil = new Date(twoFactor.lockedUntil);
	if (lockedUntil.getTime() > Date.now()) {
		throw APIError.from(
			"TOO_MANY_REQUESTS",
			TWO_FACTOR_ERROR_CODES.ACCOUNT_TEMPORARILY_LOCKED,
		);
	}
	// Clear the expired lock, guarded on it still being expired, so a lock set
	// by a concurrent request after this read is not wiped.
	await adapter.incrementOne({
		model: twoFactorTable,
		where: [
			{ field: "id", value: twoFactor.id },
			{ field: "lockedUntil", operator: "lte", value: new Date() },
		],
		increment: {},
		set: {
			failedVerificationCount: 0,
			activeVerificationReservations: "[]",
			lockedUntil: null,
		},
	});
}

/** Reserve one verification attempt before comparing attacker-controlled input. */
export async function reserveTwoFactorAttempt(
	ctx: GenericEndpointContext,
	twoFactorTable: string,
	twoFactor: TwoFactorTable,
	adapter: DBTransactionAdapter = ctx.context.adapter,
): Promise<{
	restore: (settlementAdapter?: DBTransactionAdapter) => Promise<void>;
	recordFailure: (settlementAdapter?: DBTransactionAdapter) => Promise<void>;
	recordSuccess: (settlementAdapter?: DBTransactionAdapter) => Promise<void>;
}> {
	const { enabled, maxFailedAttempts, durationMs } =
		resolveAccountLockoutConfig(ctx);
	const noop = async () => {};
	if (!enabled) {
		return { restore: noop, recordFailure: noop, recordSuccess: noop };
	}
	const reservation = generateRandomString(32);
	const parseReservations = (value: string | null | undefined) => {
		if (value == null) return [] as string[];
		try {
			const parsed = JSON.parse(value) as unknown;
			return Array.isArray(parsed) &&
				parsed.every((entry) => typeof entry === "string")
				? parsed
				: null;
		} catch {
			return null;
		}
	};

	for (let attempt = 0; attempt < 8; attempt++) {
		const current = await adapter.findOne<TwoFactorTable>({
			model: twoFactorTable,
			where: [{ field: "id", value: twoFactor.id }],
		});
		if (!current) {
			throw APIError.fromStatus("CONFLICT", {
				message: "Two-factor state changed. Please try again.",
			});
		}
		await assertTwoFactorNotLocked(ctx, twoFactorTable, current, adapter);
		const reservations = parseReservations(
			current.activeVerificationReservations,
		);
		if (!reservations) {
			throw APIError.fromStatus("CONFLICT", {
				message: "Two-factor attempt reservations are invalid.",
			});
		}
		const count = current.failedVerificationCount ?? 0;
		const nextCount = count + 1;
		const reserved = await adapter.incrementOne<TwoFactorTable>({
			model: twoFactorTable,
			where: [
				{ field: "id", value: twoFactor.id },
				{
					field: "failedVerificationCount",
					value: current.failedVerificationCount ?? null,
				},
				{
					field: "activeVerificationReservations",
					value: current.activeVerificationReservations ?? null,
				},
				{ field: "lockedUntil", value: null },
			],
			increment:
				current.failedVerificationCount == null
					? {}
					: { failedVerificationCount: 1 },
			set: {
				...(current.failedVerificationCount == null
					? { failedVerificationCount: 1 }
					: {}),
				activeVerificationReservations: JSON.stringify([
					...reservations,
					reservation,
				]),
				lockedUntil:
					nextCount >= maxFailedAttempts
						? new Date(Date.now() + durationMs)
						: null,
			},
		});
		if (!reserved) continue;

		let settled = false;
		const settle = async (
			failure: boolean,
			settlementAdapter: DBTransactionAdapter = adapter,
		) => {
			if (settled) return;
			settled = true;
			for (let retry = 0; retry < 8; retry++) {
				const latest = await settlementAdapter.findOne<TwoFactorTable>({
					model: twoFactorTable,
					where: [{ field: "id", value: twoFactor.id }],
				});
				if (!latest) return;
				const active = parseReservations(latest.activeVerificationReservations);
				if (!active) return;
				const index = active.indexOf(reservation);
				const latestCount = latest.failedVerificationCount ?? 0;
				if (index === -1) {
					if (!failure) return;
					const nextFailureCount = latestCount + 1;
					const recorded =
						await settlementAdapter.incrementOne<TwoFactorTable>({
							model: twoFactorTable,
							where: [
								{ field: "id", value: twoFactor.id },
								{
									field: "failedVerificationCount",
									value: latest.failedVerificationCount ?? null,
								},
								{
									field: "activeVerificationReservations",
									value: latest.activeVerificationReservations ?? null,
								},
								{ field: "lockedUntil", value: null },
							],
							increment:
								latest.failedVerificationCount == null
									? {}
									: { failedVerificationCount: 1 },
							set: {
								...(latest.failedVerificationCount == null
									? { failedVerificationCount: 1 }
									: {}),
								lockedUntil:
									nextFailureCount >= maxFailedAttempts
										? new Date(Date.now() + durationMs)
										: null,
							},
						});
					if (recorded) return;
					continue;
				}
				const remaining = active.filter((entry) => entry !== reservation);
				const nextCount = failure ? latestCount : Math.max(0, latestCount - 1);
				const updated = await settlementAdapter.incrementOne<TwoFactorTable>({
					model: twoFactorTable,
					where: [
						{ field: "id", value: twoFactor.id },
						{
							field: "failedVerificationCount",
							value: latest.failedVerificationCount ?? null,
						},
						{
							field: "activeVerificationReservations",
							value: latest.activeVerificationReservations ?? null,
						},
						{
							field: "lockedUntil",
							value: latest.lockedUntil ?? null,
						},
					],
					increment: failure ? {} : { failedVerificationCount: -1 },
					set: {
						activeVerificationReservations: JSON.stringify(remaining),
						lockedUntil:
							nextCount >= maxFailedAttempts ? latest.lockedUntil : null,
					},
				});
				if (updated) return;
			}
		};
		return {
			restore: (settlementAdapter) => settle(false, settlementAdapter),
			recordFailure: (settlementAdapter) => settle(true, settlementAdapter),
			recordSuccess: async (settlementAdapter = adapter) => {
				if (settled) return;
				settled = true;
				await settlementAdapter.update({
					model: twoFactorTable,
					where: [{ field: "id", value: twoFactor.id }],
					update: {
						failedVerificationCount: 0,
						activeVerificationReservations: "[]",
						lockedUntil: null,
					},
				});
			},
		};
	}
	throw APIError.fromStatus("CONFLICT", {
		message: "Two-factor attempt budget changed. Please try again.",
	});
}

/**
 * Clear the account-level failure budget after a successful verification, so the
 * count tracks only consecutive failures. The write is unconditional: a snapshot
 * read at the start of the request can miss a concurrent failure, so skipping it
 * could leave the counter non-zero after a success.
 */
export async function resetTwoFactorFailures(
	ctx: GenericEndpointContext,
	twoFactorTable: string,
	twoFactor: TwoFactorTable,
	adapter: DBTransactionAdapter = ctx.context.adapter,
): Promise<void> {
	const { enabled } = resolveAccountLockoutConfig(ctx);
	if (!enabled) return;
	await adapter.update({
		model: twoFactorTable,
		where: [{ field: "id", value: twoFactor.id }],
		update: {
			failedVerificationCount: 0,
			activeVerificationReservations: "[]",
			lockedUntil: null,
		},
	});
}

export async function consumeTotpCounter(
	ctx: GenericEndpointContext,
	twoFactorTable: string,
	twoFactor: TwoFactorTable,
	counter: number,
	adapter: DBTransactionAdapter = ctx.context.adapter,
): Promise<boolean> {
	if (counter <= (twoFactor.lastUsedTotpCounter ?? -1)) return false;
	if (twoFactor.lastUsedTotpCounter == null) {
		await adapter.incrementOne<TwoFactorTable>({
			model: twoFactorTable,
			where: [
				{ field: "id", value: twoFactor.id },
				{ field: "secret", value: twoFactor.secret },
				{
					field: "trustDeviceGeneration",
					value: twoFactor.trustDeviceGeneration ?? null,
				},
				{ field: "lastUsedTotpCounter", value: null },
			],
			increment: {},
			set: { lastUsedTotpCounter: -1 },
		});
	}
	const updated = await adapter.incrementOne<TwoFactorTable>({
		model: twoFactorTable,
		where: [
			{ field: "id", value: twoFactor.id },
			{ field: "secret", value: twoFactor.secret },
			{
				field: "trustDeviceGeneration",
				value: twoFactor.trustDeviceGeneration ?? null,
			},
			{ field: "lastUsedTotpCounter", operator: "lt", value: counter },
		],
		increment: {},
		set: { lastUsedTotpCounter: counter },
	});
	return updated !== null;
}
