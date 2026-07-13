import type { ClearanceOptions } from "@clearance/core";

export function hasServerSessionStore(options: ClearanceOptions): boolean {
	return !!options.database || !!options.secondaryStorage;
}

function hasServerAccountStore(options: ClearanceOptions): boolean {
	return !!options.database;
}

export function shouldBindAccountCookieToSessionUser(
	options: ClearanceOptions,
): boolean {
	return hasServerAccountStore(options);
}
