import type { GenericEndpointContext } from "@clearance/core";
import type { Account } from "@clearance/core/db";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import { generateRandomString } from "../crypto/random";

const DEFAULT_MAX_FAILED_ATTEMPTS = 10;
const DEFAULT_LOCKOUT_DURATION_SECONDS = 15 * 60;
const MIN_RESERVATION_TTL_MS = 5 * 60_000;
const MAX_CAS_ATTEMPTS = 128;

type PasswordAccount = Account & {
	failedPasswordAttempts?: number | null;
	activePasswordAttemptReservations?: string | null;
	passwordLockedUntil?: Date | null;
};

type Reservation = {
	id: string;
	expiresAt: number;
	failureFenced?: boolean;
};

function lockoutError(): never {
	throw APIError.from("TOO_MANY_REQUESTS", BASE_ERROR_CODES.PASSWORD_ACCOUNT_LOCKED);
}

function stateError(): never {
	throw APIError.fromStatus("INTERNAL_SERVER_ERROR", {
		message: "Unable to verify credentials",
	});
}

function config(ctx: GenericEndpointContext) {
	const input = ctx.context.options.emailAndPassword?.accountLockout;
	const maxFailedAttempts = input?.maxFailedAttempts ?? DEFAULT_MAX_FAILED_ATTEMPTS;
	const durationSeconds =
		input?.durationSeconds ?? DEFAULT_LOCKOUT_DURATION_SECONDS;
	if (
		!Number.isSafeInteger(maxFailedAttempts) ||
		maxFailedAttempts < 3 ||
		maxFailedAttempts > 100 ||
		!Number.isSafeInteger(durationSeconds) ||
		durationSeconds < 30 ||
		durationSeconds > 24 * 60 * 60
	) {
		stateError();
	}
	return {
		enabled: input?.enabled ?? true,
		maxFailedAttempts,
		durationMs: durationSeconds * 1000,
		reservationTtlMs: Math.max(
			durationSeconds * 1000,
			MIN_RESERVATION_TTL_MS,
		),
	};
}

function parseReservations(value: string | null | undefined): Reservation[] | null {
	if (value == null) return [];
	try {
		const parsed = JSON.parse(value) as unknown;
		if (
			!Array.isArray(parsed) ||
			!parsed.every(
				(entry) =>
					entry !== null &&
					typeof entry === "object" &&
					typeof (entry as Reservation).id === "string" &&
					(entry as Reservation).id.length > 0 &&
					Number.isSafeInteger((entry as Reservation).expiresAt) &&
					(entry as Reservation).expiresAt > 0 &&
					((entry as Reservation).failureFenced === undefined ||
						typeof (entry as Reservation).failureFenced === "boolean"),
			)
		) {
			return null;
		}
		const ids = new Set(parsed.map((entry: Reservation) => entry.id));
		return ids.size === parsed.length ? (parsed as Reservation[]) : null;
	} catch {
		return null;
	}
}

function validFailureCount(value: number | null | undefined): value is number {
	return Number.isSafeInteger(value) && (value ?? -1) >= 0;
}

async function readAccount(
	ctx: GenericEndpointContext,
	accountId: string,
): Promise<PasswordAccount> {
	const current = await ctx.context.adapter.findOne<PasswordAccount>({
		model: "account",
		where: [{ field: "id", value: accountId }],
	});
	if (!current || current.providerId !== "credential" || !current.password) {
		stateError();
	}
	return current;
}

async function reservePasswordAttempt(
	ctx: GenericEndpointContext,
	account: PasswordAccount,
): Promise<{
	recordFailure(): Promise<void>;
	recordSuccess(): Promise<boolean>;
	cancel(): Promise<void>;
}> {
	const policy = config(ctx);
	const noop = async () => {};
	if (!policy.enabled) {
		return {
			recordFailure: noop,
			recordSuccess: async () => true,
			cancel: noop,
		};
	}
	const reservationId = generateRandomString(32);
	if (!account.password) stateError();
	const passwordGeneration = account.password;

	for (let attempt = 0; attempt < MAX_CAS_ATTEMPTS; attempt++) {
		const current = await readAccount(ctx, account.id);
		if (current.password !== passwordGeneration) stateError();
		const now = Date.now();
		const lockedUntil = current.passwordLockedUntil
			? new Date(current.passwordLockedUntil)
			: null;
		if (lockedUntil && !Number.isFinite(lockedUntil.getTime())) stateError();
		if (lockedUntil && lockedUntil.getTime() > now) lockoutError();

		const reservations = parseReservations(
			current.activePasswordAttemptReservations,
		);
		if (!reservations) stateError();
		const failures = current.failedPasswordAttempts ?? 0;
		if (!validFailureCount(failures)) stateError();
		if (lockedUntil) {
			const cleared = await ctx.context.adapter.incrementOne<PasswordAccount>({
				model: "account",
				where: [
					{ field: "id", value: current.id },
					{ field: "password", value: passwordGeneration },
					{
						field: "passwordLockedUntil",
						value: current.passwordLockedUntil ?? null,
					},
				],
				increment: {},
				set: {
					failedPasswordAttempts: 0,
					activePasswordAttemptReservations: "[]",
					passwordLockedUntil: null,
				},
			});
			if (cleared) continue;
			continue;
		}
		if (failures >= policy.maxFailedAttempts) {
			const locked = await ctx.context.adapter.incrementOne<PasswordAccount>({
				model: "account",
				where: [
					{ field: "id", value: current.id },
					{ field: "password", value: passwordGeneration },
					{
						field: "failedPasswordAttempts",
						value: current.failedPasswordAttempts ?? null,
					},
					{
						field: "activePasswordAttemptReservations",
						value: current.activePasswordAttemptReservations ?? null,
					},
					{ field: "passwordLockedUntil", value: null },
				],
				increment: {},
				set: {
					activePasswordAttemptReservations: JSON.stringify(
						reservations.filter((entry) => entry.expiresAt > now),
					),
					passwordLockedUntil: new Date(now + policy.durationMs),
				},
			});
			if (locked) lockoutError();
			continue;
		}

		const live = reservations.filter((entry) => entry.expiresAt > now);
		if (failures + live.length >= policy.maxFailedAttempts) lockoutError();
		const next = [
			...live,
			{ id: reservationId, expiresAt: now + policy.reservationTtlMs },
		];
		const reserved = await ctx.context.adapter.incrementOne<PasswordAccount>({
			model: "account",
			where: [
				{ field: "id", value: current.id },
				{ field: "password", value: passwordGeneration },
				{
					field: "failedPasswordAttempts",
					value: current.failedPasswordAttempts ?? null,
				},
				{
					field: "activePasswordAttemptReservations",
					value: current.activePasswordAttemptReservations ?? null,
				},
				{ field: "passwordLockedUntil", value: null },
			],
			increment: {},
			set: {
				...(current.failedPasswordAttempts == null
					? { failedPasswordAttempts: 0 }
					: {}),
				activePasswordAttemptReservations: JSON.stringify(next),
			},
		});
		if (!reserved) continue;

		let settled = false;
		const settle = async (
			outcome: "failure" | "success" | "cancel",
		): Promise<boolean> => {
			if (settled) return outcome !== "success";
			settled = true;
			for (let retry = 0; retry < MAX_CAS_ATTEMPTS; retry++) {
				const latest = await readAccount(ctx, account.id);
				if (latest.password !== passwordGeneration) {
					return outcome !== "success";
				}
				const active = parseReservations(
					latest.activePasswordAttemptReservations,
				);
				if (!active) stateError();
				if (!validFailureCount(latest.failedPasswordAttempts ?? 0)) stateError();
				const reservation = active.find((entry) => entry.id === reservationId);
				if (!reservation) {
					return outcome !== "success";
				}
				const remaining = active.filter((entry) => entry.id !== reservationId);
				const currentFailures = latest.failedPasswordAttempts ?? 0;
				const nextFailures =
					outcome === "failure" && !reservation.failureFenced
						? Math.min(policy.maxFailedAttempts, currentFailures + 1)
						: outcome === "success"
							? 0
							: currentFailures;
				const nextReservations =
					outcome === "success"
						? remaining.map((entry) => ({
								...entry,
								failureFenced: true,
							}))
						: remaining;
				const updated = await ctx.context.adapter.incrementOne<PasswordAccount>({
					model: "account",
					where: [
						{ field: "id", value: latest.id },
						{ field: "password", value: passwordGeneration },
						{
							field: "failedPasswordAttempts",
							value: latest.failedPasswordAttempts ?? null,
						},
						{
							field: "activePasswordAttemptReservations",
							value: latest.activePasswordAttemptReservations ?? null,
						},
						{
							field: "passwordLockedUntil",
							value: latest.passwordLockedUntil ?? null,
						},
					],
					increment: {},
					set: {
						failedPasswordAttempts: nextFailures,
						activePasswordAttemptReservations:
							JSON.stringify(nextReservations),
						passwordLockedUntil:
							outcome === "failure" &&
							!reservation.failureFenced &&
							nextFailures >= policy.maxFailedAttempts
								? latest.passwordLockedUntil ??
									new Date(Date.now() + policy.durationMs)
								: outcome === "success"
									? null
									: latest.passwordLockedUntil ?? null,
					},
				});
				if (updated) return true;
			}
			stateError();
		};
		return {
			recordFailure: async () => {
				await settle("failure");
			},
			recordSuccess: () => settle("success"),
			cancel: async () => {
				await settle("cancel");
			},
		};
	}
	stateError();
}

export async function verifyPasswordForSignIn(
	ctx: GenericEndpointContext,
	account: PasswordAccount,
	password: string,
): Promise<boolean> {
	const attempt = await reservePasswordAttempt(ctx, account);
	const passwordMatched = await ctx.context.password
		.verify({
			hash: account.password!,
			password,
		})
		.catch(async (error) => {
			await attempt.cancel();
			throw error;
		});
	const accepted = passwordMatched && (await attempt.recordSuccess());
	if (!passwordMatched) await attempt.recordFailure();
	return accepted;
}
