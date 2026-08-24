import type { ClearanceOptions } from "@clearance/core";
import type { User } from "@clearance/core/db";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";

export const PASSKEY_SESSION_GENERATION_FIELD = "passkeySessionGeneration";

export function hasPasskeySessionGeneration(
	options: Pick<ClearanceOptions, "plugins">,
): boolean {
	return options.plugins?.some((plugin) => plugin.id === "passkey") ?? false;
}

export function sessionMatchesPasskeyGeneration(
	session: Record<string, unknown>,
	user: Record<string, unknown>,
): boolean {
	const current = user[PASSKEY_SESSION_GENERATION_FIELD];
	const bound = session[PASSKEY_SESSION_GENERATION_FIELD];
	if (current == null || bound == null) {
		return current == null && bound == null;
	}
	return (
		typeof current === "string" &&
		typeof bound === "string" &&
		bound === current
	);
}

/**
 * Rotate the passkey lifecycle fence exactly once from an observed generation.
 * Every destructive factor mutation shares this guarded authority so two
 * concurrent removals cannot both decide that the other factor will survive.
 */
export function rotatePasskeySessionGeneration(
	adapter: DBTransactionAdapter,
	userId: string,
	observedGeneration: string,
	nextGeneration: string,
): Promise<(User & Record<string, unknown>) | null> {
	return adapter.incrementOne<User & Record<string, unknown>>({
		model: "user",
		where: [
			{ field: "id", value: userId },
			{
				field: PASSKEY_SESSION_GENERATION_FIELD,
				value: observedGeneration,
			},
		],
		increment: {},
		set: { [PASSKEY_SESSION_GENERATION_FIELD]: nextGeneration },
	});
}
