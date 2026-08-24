import type { AuthContext } from "@clearance/core";
import { symmetricDecrypt, symmetricEncrypt } from "../crypto";

const OAUTH_TOKEN_PREFIX = "clr-oauth:";
const OAUTH_TOKEN_V1_PREFIX = `${OAUTH_TOKEN_PREFIX}v1:`;
const MINIMUM_LEGACY_CIPHERTEXT_HEX_LENGTH = 80;

function isLegacyBareCiphertextCandidate(token: string): boolean {
	return token.length % 2 === 0 && /^[0-9a-f]+$/i.test(token);
}

export async function decryptOAuthToken(token: string, ctx: AuthContext) {
	if (!token) return token;
	if (ctx.options.account?.encryptOAuthTokens) {
		if (token.startsWith(OAUTH_TOKEN_V1_PREFIX)) {
			const payload = token.slice(OAUTH_TOKEN_V1_PREFIX.length);
			if (
				!payload.startsWith("$ba$") &&
				(!isLegacyBareCiphertextCandidate(payload) ||
					payload.length < MINIMUM_LEGACY_CIPHERTEXT_HEX_LENGTH)
			) {
				return token;
			}
			return symmetricDecrypt({
				key: ctx.secretConfig,
				data: payload,
			});
		}
		const unsupportedEnvelope = /^clr-oauth:v\d+:(.*)$/.exec(token);
		if (
			unsupportedEnvelope &&
			(unsupportedEnvelope[1]?.startsWith("$ba$") ||
				(isLegacyBareCiphertextCandidate(unsupportedEnvelope[1] ?? "") &&
					(unsupportedEnvelope[1]?.length ?? 0) >=
						MINIMUM_LEGACY_CIPHERTEXT_HEX_LENGTH))
		) {
			throw new Error("Unsupported OAuth token encryption envelope");
		}
		if (token.startsWith("$ba$")) {
			return symmetricDecrypt({
				key: ctx.secretConfig,
				data: token,
			});
		}
		if (isLegacyBareCiphertextCandidate(token)) {
			try {
				return await symmetricDecrypt({
					key: ctx.secretConfig,
					data: token,
				});
			} catch (error) {
				// XChaCha20-Poly1305 legacy ciphertext includes a 24-byte nonce and
				// 16-byte tag. Anything at least that long is ambiguous and must fail
				// closed; shorter valid-looking hex can only be legacy plaintext.
				if (token.length >= MINIMUM_LEGACY_CIPHERTEXT_HEX_LENGTH) throw error;
				return token;
			}
		}
	}
	return token;
}

export async function setTokenUtil(
	token: string | null | undefined,
	ctx: AuthContext,
) {
	if (ctx.options.account?.encryptOAuthTokens && token) {
		const ciphertext = await symmetricEncrypt({
			key: ctx.secretConfig,
			data: token,
		});
		return `${OAUTH_TOKEN_V1_PREFIX}${ciphertext}`;
	}
	return token;
}
