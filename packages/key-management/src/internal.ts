import { createHash } from "node:crypto";
import { KeyManagementError } from "./error.js";
import type { KeyEncryptionProvider } from "./types.js";

type ProviderSeparationMetadata = Readonly<{
	localKeys: readonly Uint8Array[];
	cloudKeyReferences: readonly string[];
}>;

const separationMetadata = new WeakMap<KeyEncryptionProvider, ProviderSeparationMetadata>();

export function registerProviderSeparationMetadata(
	provider: KeyEncryptionProvider,
	metadata: ProviderSeparationMetadata,
): void {
	if (separationMetadata.has(provider)) {
		throw new KeyManagementError("KEY_REGISTRY_INVALID", "Key provider metadata is already registered");
	}
	separationMetadata.set(provider, Object.freeze({
		localKeys: Object.freeze(metadata.localKeys.map((key) => new Uint8Array(key))),
		cloudKeyReferences: Object.freeze([...metadata.cloudKeyReferences]),
	}));
}

export function getProviderSeparationMetadata(
	provider: KeyEncryptionProvider,
): ProviderSeparationMetadata {
	const metadata = separationMetadata.get(provider);
	if (!metadata) {
		throw new KeyManagementError("KEY_REGISTRY_INVALID", "Key provider is not a registered Clearance provider");
	}
	return metadata;
}

export function redactedKeyReference(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 16);
}
