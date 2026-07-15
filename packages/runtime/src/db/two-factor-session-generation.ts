import type { ClearanceOptions } from "@clearance/core";

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
