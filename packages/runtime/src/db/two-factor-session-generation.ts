import type { ClearanceOptions } from "@clearance/core";
import type { User } from "@clearance/core/db";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";

export const TWO_FACTOR_SESSION_GENERATION_FIELD = "twoFactorSessionGeneration";

export function hasTwoFactorSessionGeneration(
	options: Pick<ClearanceOptions, "plugins">,
): boolean {
	return options.plugins?.some((plugin) => plugin.id === "two-factor") ?? false;
}

export function sessionMatchesTwoFactorGeneration(
	session: Record<string, unknown>,
	user: Record<string, unknown>,
): boolean {
	const current = user[TWO_FACTOR_SESSION_GENERATION_FIELD];
	return (
		typeof current !== "string" ||
		session[TWO_FACTOR_SESSION_GENERATION_FIELD] === current
	);
}

export function rotateTwoFactorSessionGeneration(
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
				field: TWO_FACTOR_SESSION_GENERATION_FIELD,
				value: observedGeneration,
			},
		],
		increment: {},
		set: { [TWO_FACTOR_SESSION_GENERATION_FIELD]: nextGeneration },
	});
}
