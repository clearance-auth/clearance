import type { OIDCConfig, SSOOptions } from "./types";

export const OIDC_SECRET_ENVELOPE_PREFIX = "clr-sso:v1:";

export async function encryptOIDCConfig(
	config: OIDCConfig,
	options?: SSOOptions,
): Promise<OIDCConfig> {
	const storage = options?.storeOIDCClientSecret;
	if (!storage || !config.clientSecret) return config;
	if (config.clientSecret.startsWith(OIDC_SECRET_ENVELOPE_PREFIX)) return config;
	return {
		...config,
		clientSecret: `${OIDC_SECRET_ENVELOPE_PREFIX}${await storage.encrypt(config.clientSecret)}`,
	};
}

export async function decryptOIDCConfig(
	config: OIDCConfig,
	options?: SSOOptions,
): Promise<OIDCConfig> {
	const storage = options?.storeOIDCClientSecret;
	if (!storage) return config;
	if (!config.clientSecret.startsWith(OIDC_SECRET_ENVELOPE_PREFIX)) {
		throw new Error("Refusing plaintext OIDC client secret while encrypted storage is configured");
	}
	return {
		...config,
		clientSecret: await storage.decrypt(
			config.clientSecret.slice(OIDC_SECRET_ENVELOPE_PREFIX.length),
		),
	};
}
