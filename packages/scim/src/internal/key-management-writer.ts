import type { SCIMOptions } from "../types.js";

type ScimTokenStorage = Extract<
	NonNullable<SCIMOptions["storeSCIMToken"]>,
	{ encrypt: unknown; decrypt: unknown }
>;

const clearanceManagedWriters = new WeakSet<ScimTokenStorage>();

export function attachSCIMKeyManagementWriter<T extends ScimTokenStorage>(
	storage: T,
): T {
	clearanceManagedWriters.add(storage);
	return storage;
}

export function isSCIMKeyManagementWriter(
	storage: SCIMOptions["storeSCIMToken"],
): boolean {
	return (
		typeof storage === "object" &&
		storage !== null &&
		"encrypt" in storage &&
		clearanceManagedWriters.has(storage as ScimTokenStorage)
	);
}
