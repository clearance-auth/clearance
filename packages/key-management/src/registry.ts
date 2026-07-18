import { KeyManagementError } from "./error.js";
import { timingSafeEqual } from "node:crypto";
import { getProviderSeparationMetadata } from "./internal.js";
import {
	KEY_PURPOSES,
	type KeyEncryptionProvider,
	type KeyProviderReadiness,
	type KeyPurpose,
	type PurposeKeyProviders,
} from "./types.js";

export type KeyProviderRegistry = Readonly<{
	providerFor(purpose: KeyPurpose): KeyEncryptionProvider;
	readiness(): Promise<Readonly<{ ready: boolean; purposes: Readonly<Record<KeyPurpose, KeyProviderReadiness>> }>>;
}>;

export function createKeyProviderRegistry(
	providers: PurposeKeyProviders,
): KeyProviderRegistry {
	if (!providers || typeof providers !== "object" || Array.isArray(providers)) {
		throw new KeyManagementError("KEY_REGISTRY_INVALID", "Key provider registry is invalid");
	}
	if (Object.keys(providers).sort().join("\u0000") !== [...KEY_PURPOSES].sort().join("\u0000")) {
		throw new KeyManagementError("KEY_REGISTRY_INVALID", "Key provider purposes are invalid");
	}
	const exact = {} as Record<KeyPurpose, KeyEncryptionProvider>;
	const claimedLocalKeys: Array<readonly [Uint8Array, KeyPurpose]> = [];
	const claimedCloudReferences = new Map<string, KeyPurpose>();
	for (const purpose of KEY_PURPOSES) {
		const provider = providers[purpose];
		if (
			!provider ||
			typeof provider !== "object" ||
			provider.purpose !== purpose ||
			typeof provider.seal !== "function" ||
			typeof provider.open !== "function" ||
			typeof provider.readiness !== "function"
		) {
			throw new KeyManagementError("KEY_REGISTRY_INVALID", `Key provider for ${purpose} is missing`);
		}
		const metadata = getProviderSeparationMetadata(provider);
		for (const key of metadata.localKeys) {
			const duplicate = claimedLocalKeys.find(([candidate]) =>
				candidate.length === key.length && timingSafeEqual(candidate, key),
			);
			if (duplicate && duplicate[1] !== purpose) {
				throw new KeyManagementError("KEY_PURPOSE_REUSE", "Key identity is reused across purposes");
			}
			claimedLocalKeys.push([key, purpose]);
		}
		for (const reference of metadata.cloudKeyReferences) {
			const owner = claimedCloudReferences.get(reference);
			if (owner && owner !== purpose) {
				throw new KeyManagementError("KEY_PURPOSE_REUSE", "Key identity is reused across purposes");
			}
			claimedCloudReferences.set(reference, purpose);
		}
		exact[purpose] = provider;
	}
	Object.freeze(exact);
	return Object.freeze({
		providerFor(purpose: KeyPurpose) {
			const provider = exact[purpose];
			if (!provider) {
				throw new KeyManagementError("KEY_REGISTRY_INVALID", "Key purpose is not configured");
			}
			return provider;
		},
		async readiness() {
			const entries = await Promise.all(
				KEY_PURPOSES.map(async (purpose) => [purpose, await exact[purpose].readiness()] as const),
			);
			const purposes = Object.freeze(Object.fromEntries(entries)) as Readonly<Record<KeyPurpose, KeyProviderReadiness>>;
			return Object.freeze({
				ready: entries.every(([, status]) => status.ready),
				purposes,
			});
		},
	});
}
