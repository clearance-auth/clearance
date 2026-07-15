import type { GenericEndpointContext } from "@clearance/core";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { APIError } from "@clearance/core/error";
import { createHMAC } from "@clearance/utils/hmac";
import { getSessionFromCtx } from "../../api";
import { expireCookie, setSessionCookie } from "../../cookies";
import { generateRandomString } from "../../crypto/random";
import { parseUserOutput } from "../../db/schema";
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
import { recordTrustGeneration } from "./utils";

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
			await ctx.context.internalAdapter.findVerificationValue(
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
				// The 2FA challenge is single-use and time-bounded. Burn it
				// atomically before issuing a session so a stale (expired) replay
				// or two concurrent verifications of the same cookie cannot each
				// mint a session: the consume returns null for an expired or
				// already-consumed row, and only the first racer wins it.
				const consumed =
					await ctx.context.internalAdapter.consumeVerificationValue(
						signedTwoFactorCookie,
					);
				if (!consumed || consumed.value !== user.id) {
					expireCookie(ctx, twoFactorCookie);
					throw APIError.from(
						"UNAUTHORIZED",
						TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE,
					);
				}
				const session = await ctx.context.internalAdapter.createSession(
					consumed.value,
					!!dontRememberMe,
				);
				if (!session) {
					throw APIError.from("INTERNAL_SERVER_ERROR", {
						message: "failed to create session",
						code: "FAILED_TO_CREATE_SESSION",
					});
				}
				await setSessionCookie(ctx, {
					session,
					user,
				});
				// Always clear the two factor cookie after successful verification
				expireCookie(ctx, twoFactorCookie);
				if (ctx.body.trustDevice) {
					const plugin = ctx.context.getPlugin("two-factor");
					const trustDeviceMaxAge = plugin!.options?.trustDeviceMaxAge;
					const maxAge = trustDeviceMaxAge ?? TRUST_DEVICE_COOKIE_MAX_AGE;
					const trustDeviceCookie = ctx.context.createAuthCookie(
						TRUST_DEVICE_COOKIE_NAME,
						{
							maxAge,
						},
					);
					const factor = await ctx.context.adapter.findOne<TwoFactorTable>({
						model: plugin!.options?.twoFactorTable ?? "twoFactor",
						where: [{ field: "userId", value: user.id }],
					});
					const trustGeneration = factor?.trustDeviceGeneration;
					if (trustGeneration) {
						const trustIdentifier = `trust-device-${generateRandomString(32)}`;
						const trustExpiresAt = new Date(Date.now() + maxAge * 1000);
						const token = await createHMAC("SHA-256", "base64urlnopad").sign(
							ctx.context.secret,
							`${user.id}!${trustIdentifier}!${trustGeneration}`,
						);
						await ctx.context.internalAdapter.createVerificationValue({
							value: `${user.id}!${trustGeneration}`,
							identifier: trustIdentifier,
							expiresAt: trustExpiresAt,
						});
						await recordTrustGeneration(
							ctx,
							user.id,
							trustGeneration,
							trustExpiresAt,
						);
						await ctx.setSignedCookie(
							trustDeviceCookie.name,
							`${token}!${trustIdentifier}!${trustGeneration}`,
							ctx.context.secret,
							trustDeviceCookie.attributes,
						);
						expireCookie(ctx, ctx.context.authCookies.dontRememberToken);
					}
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
				// Consume the precreated counter as the atomic race gate; a missing
				// row means a lost race or an expired challenge.
				const consumed = await ctx.context.internalAdapter
					.consumeVerificationValue(identifier)
					.catch(() => null);
				if (!consumed) {
					throw APIError.from(
						"UNAUTHORIZED",
						TWO_FACTOR_ERROR_CODES.INVALID_TWO_FACTOR_COOKIE,
					);
				}
				const parsed = Number(consumed.value);
				// A corrupt counter fails closed (treated as spent).
				const attempts =
					Number.isInteger(parsed) && parsed >= 0 ? parsed : allowedAttempts;
				if (attempts >= allowedAttempts) {
					// Budget spent: cancel the whole challenge so every factor must
					// start a new sign-in, and clear the now-dead cookie.
					await ctx.context.internalAdapter
						.consumeVerificationValue(signedTwoFactorCookie)
						.catch(() => {});
					expireCookie(ctx, twoFactorCookie);
					throw APIError.from(
						"BAD_REQUEST",
						TWO_FACTOR_ERROR_CODES.TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE,
					);
				}
				const rearm = (count: number) =>
					ctx.context.internalAdapter
						.createVerificationValue({
							value: `${count}`,
							identifier,
							expiresAt: verificationToken.expiresAt,
						})
						.catch(() => {});
				return {
					// recordFailure spends a slot; restore returns it on a server
					// error. Both swallow write errors (fail closed).
					recordFailure: () => rearm(attempts + 1),
					restore: () => rearm(attempts),
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
	restore: () => Promise<void>;
	recordFailure: () => Promise<void>;
	recordSuccess: () => Promise<void>;
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
		const settle = async (failure: boolean) => {
			if (settled) return;
			settled = true;
			for (let retry = 0; retry < 8; retry++) {
				const latest = await adapter.findOne<TwoFactorTable>({
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
					const recorded = await adapter.incrementOne<TwoFactorTable>({
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
				const updated = await adapter.incrementOne<TwoFactorTable>({
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
			restore: () => settle(false),
			recordFailure: () => settle(true),
			recordSuccess: async () => {
				if (settled) return;
				settled = true;
				await adapter.update({
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
): Promise<void> {
	const { enabled } = resolveAccountLockoutConfig(ctx);
	if (!enabled) return;
	await ctx.context.adapter.update({
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
): Promise<boolean> {
	if (counter <= (twoFactor.lastUsedTotpCounter ?? -1)) return false;
	if (twoFactor.lastUsedTotpCounter == null) {
		await ctx.context.adapter.incrementOne<TwoFactorTable>({
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
	const updated = await ctx.context.adapter.incrementOne<TwoFactorTable>({
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
