import type { User } from "@clearance/core/db";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { PASSKEY_SESSION_GENERATION_FIELD } from "./passkey-session-generation";
import { TWO_FACTOR_SESSION_GENERATION_FIELD } from "./two-factor-session-generation";

const USER_ID_MAX_LENGTH = 1_024;
const SESSION_GENERATION_MAX_LENGTH = 512;

function validOpaqueString(value: unknown, maximum: number): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= maximum &&
		value.trim() === value &&
		!value.includes("\0")
	);
}

function validateObservedGeneration(
	value: string | null | undefined,
): string | null {
	if (value == null) return null;
	if (!validOpaqueString(value, SESSION_GENERATION_MAX_LENGTH)) {
		throw new TypeError("Invalid observed factor session generation");
	}
	return value;
}

function validateNextGeneration(value: string): string {
	if (!validOpaqueString(value, SESSION_GENERATION_MAX_LENGTH)) {
		throw new TypeError("Invalid next factor session generation");
	}
	return value;
}

/**
 * Atomically rotates both factor lifecycle fences from one exact user snapshot.
 * Missing and null legacy values share the adapter's canonical null predicate;
 * every non-legacy value remains an exact compare-and-swap guard.
 */
export async function rotateFactorSessionGenerations(
	adapter: DBTransactionAdapter,
	userId: string,
	observedPasskeySessionGeneration: string | null | undefined,
	observedTwoFactorSessionGeneration: string | null | undefined,
	nextPasskeySessionGeneration: string,
	nextTwoFactorSessionGeneration: string,
): Promise<(User & Record<string, unknown>) | null> {
	if (!validOpaqueString(userId, USER_ID_MAX_LENGTH)) {
		throw new TypeError("Invalid user id for factor session generation rotation");
	}
	const observedPasskey = validateObservedGeneration(
		observedPasskeySessionGeneration,
	);
	const observedTwoFactor = validateObservedGeneration(
		observedTwoFactorSessionGeneration,
	);
	const nextPasskey = validateNextGeneration(nextPasskeySessionGeneration);
	const nextTwoFactor = validateNextGeneration(nextTwoFactorSessionGeneration);
	if (
		nextPasskey === observedPasskey ||
		nextTwoFactor === observedTwoFactor
	) {
		throw new TypeError("Factor session generations must rotate to fresh values");
	}

	return adapter.incrementOne<User & Record<string, unknown>>({
		model: "user",
		where: [
			{ field: "id", value: userId },
			{
				field: PASSKEY_SESSION_GENERATION_FIELD,
				value: observedPasskey,
			},
			{
				field: TWO_FACTOR_SESSION_GENERATION_FIELD,
				value: observedTwoFactor,
			},
		],
		increment: {},
		set: {
			[PASSKEY_SESSION_GENERATION_FIELD]: nextPasskey,
			[TWO_FACTOR_SESSION_GENERATION_FIELD]: nextTwoFactor,
		},
	});
}
