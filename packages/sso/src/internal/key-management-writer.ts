import type { SSOOptions } from "../types.js";

type OidcSecretStorage = NonNullable<SSOOptions["storeOIDCClientSecret"]>;

const clearanceManagedWriters = new WeakSet<OidcSecretStorage>();

export function attachSSOKeyManagementWriter<T extends OidcSecretStorage>(
	storage: T,
): T {
	clearanceManagedWriters.add(storage);
	return storage;
}

export function isSSOKeyManagementWriter(
	storage: SSOOptions["storeOIDCClientSecret"],
): boolean {
	return storage !== undefined && clearanceManagedWriters.has(storage);
}
