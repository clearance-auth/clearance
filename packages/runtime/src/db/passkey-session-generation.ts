import type { ClearanceOptions } from "@clearance/core";

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
