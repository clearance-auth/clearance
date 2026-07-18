import type { OIDCConfig, SSOOptions } from "./types";

export const OIDC_SECRET_ENVELOPE_PREFIX = "clr-sso:v1:";

const MAX_PROVIDER_ID_CHARACTERS = 512;

function validateProviderId(providerId: string): string {
	if (
		typeof providerId !== "string" ||
		providerId.length === 0 ||
		providerId.length > MAX_PROVIDER_ID_CHARACTERS ||
		providerId.trim() !== providerId ||
		/[\u0000-\u001f\u007f]/.test(providerId)
	) {
		throw new Error("OIDC providerId is invalid");
	}
	return providerId;
}

export async function encryptOIDCConfig(
	config: OIDCConfig,
	providerId: string,
	options?: SSOOptions,
): Promise<OIDCConfig> {
	const storage = options?.storeOIDCClientSecret;
	if (!storage || !config.clientSecret) return config;
	const exactProviderId = validateProviderId(providerId);
	if (config.clientSecret.startsWith(OIDC_SECRET_ENVELOPE_PREFIX)) return config;
	return {
		...config,
		clientSecret: `${OIDC_SECRET_ENVELOPE_PREFIX}${await storage.encrypt(config.clientSecret, exactProviderId)}`,
	};
}

export async function decryptOIDCConfig(
	config: OIDCConfig,
	providerId: string,
	options?: SSOOptions,
): Promise<OIDCConfig> {
	const storage = options?.storeOIDCClientSecret;
	if (!storage) return config;
	const exactProviderId = validateProviderId(providerId);
	if (!config.clientSecret.startsWith(OIDC_SECRET_ENVELOPE_PREFIX)) {
		throw new Error("Refusing plaintext OIDC client secret while encrypted storage is configured");
	}
	return {
		...config,
		clientSecret: await storage.decrypt(
			config.clientSecret.slice(OIDC_SECRET_ENVELOPE_PREFIX.length),
			exactProviderId,
		),
	};
}
