import type { AuthContext } from "@clearance/core";
import { describe, expect, it } from "vitest";
import { symmetricEncrypt } from "../crypto";
import { decryptOAuthToken, setTokenUtil } from "./utils";

// Mock minimal AuthContext for testing
function createMockContext(encryptOAuthTokens: boolean): AuthContext {
	return {
		secret: "test-secret-key-for-encryption",
		secretConfig: "test-secret-key-for-encryption",
		options: {
			account: {
				encryptOAuthTokens,
			},
		},
	} as unknown as AuthContext;
}

function createRotatingMockContext(): AuthContext {
	const secret = "test-secret-key-for-encryption";
	return {
		secret,
		secretConfig: {
			keys: new Map([[1, secret]]),
			currentVersion: 1,
			legacySecret: secret,
		},
		options: {
			account: {
				encryptOAuthTokens: true,
			},
		},
	} as unknown as AuthContext;
}

describe("decryptOAuthToken", () => {
	it("should return empty token as-is", async () => {
		const ctx = createMockContext(true);
		const result = await decryptOAuthToken("", ctx);
		expect(result).toBe("");
	});

	it("should return token as-is when encryption is disabled", async () => {
		const ctx = createMockContext(false);
		const plainToken = "ya29.a0ARW5m7hQ_some_oauth_token";
		const result = await decryptOAuthToken(plainToken, ctx);
		expect(result).toBe(plainToken);
	});

	it("should decrypt encrypted token when encryption is enabled", async () => {
		const ctx = createMockContext(true);
		const originalToken = "test-access-token";

		// Encrypt the token first
		const encryptedToken = await symmetricEncrypt({
			key: ctx.secret,
			data: originalToken,
		});

		// Decrypt should return original
		const result = await decryptOAuthToken(encryptedToken, ctx);
		expect(result).toBe(originalToken);
	});

	it("decrypts existing versioned symmetric envelopes", async () => {
		const ctx = createRotatingMockContext();
		const originalToken = "existing-oauth-token";
		const encryptedToken = await symmetricEncrypt({
			key: ctx.secretConfig,
			data: originalToken,
		});

		expect(encryptedToken).toMatch(/^\$ba\$1\$/);
		await expect(decryptOAuthToken(encryptedToken, ctx)).resolves.toBe(
			originalToken,
		);
	});

	it("should handle migration: return unencrypted token as-is when encryption is enabled", async () => {
		const ctx = createMockContext(true);

		// Simulate a token that was stored before encryption was enabled
		// OAuth tokens typically contain dots, underscores, hyphens - not valid hex
		const plainOAuthToken = "ya29.a0ARW5m7hQ_some_oauth_token_with-dashes";

		// This should NOT throw, and should return the token as-is
		const result = await decryptOAuthToken(plainOAuthToken, ctx);
		expect(result).toBe(plainOAuthToken);
	});

	it("should handle migration: JWT-style tokens should be returned as-is", async () => {
		const ctx = createMockContext(true);

		// JWT tokens contain dots which are not valid hex characters
		const jwtToken =
			"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

		const result = await decryptOAuthToken(jwtToken, ctx);
		expect(result).toBe(jwtToken);
	});

	it("should handle migration: token with odd length should be returned as-is", async () => {
		const ctx = createMockContext(true);

		// Odd length hex-like string cannot be valid encrypted data
		const oddLengthToken = "abc";

		const result = await decryptOAuthToken(oddLengthToken, ctx);
		expect(result).toBe(oddLengthToken);
	});

	it("returns legacy plaintext that is valid even-length hex unchanged", async () => {
		const ctx = createRotatingMockContext();

		await expect(decryptOAuthToken("deadbeef", ctx)).resolves.toBe("deadbeef");
	});

	it("fails closed when a prefixed ciphertext is corrupt", async () => {
		const ctx = createRotatingMockContext();
		const encrypted = await setTokenUtil("authenticated-token", ctx);
		const ciphertext = encrypted as string;
		const tampered = `${ciphertext.slice(0, -1)}${ciphertext.endsWith("0") ? "1" : "0"}`;

		await expect(decryptOAuthToken(tampered, ctx)).rejects.toThrow();
	});

	it("fails closed for unsupported OAuth token envelope versions", async () => {
		const ctx = createRotatingMockContext();

		await expect(
			decryptOAuthToken(`clr-oauth:v2:${"ab".repeat(40)}`, ctx),
		).rejects.toThrow("Unsupported OAuth token encryption envelope");
	});

	it("preserves legacy plaintext that merely begins with the envelope namespace", async () => {
		const ctx = createRotatingMockContext();

		await expect(decryptOAuthToken("clr-oauth:legacy-provider-token", ctx)).resolves.toBe(
			"clr-oauth:legacy-provider-token",
		);
	});

	it("preserves short legacy plaintext that collides with the v1 namespace", async () => {
		const ctx = createRotatingMockContext();

		await expect(decryptOAuthToken("clr-oauth:v1:deadbeef", ctx)).resolves.toBe(
			"clr-oauth:v1:deadbeef",
		);
	});

	it("fails closed for ambiguous long bare-hex values", async () => {
		const ctx = createRotatingMockContext();

		await expect(decryptOAuthToken("ab".repeat(40), ctx)).rejects.toThrow();
	});
});

/**
 * @see https://github.com/clearance-auth/clearance
 */
describe("migration scenario - issue #6018", () => {
	it("should handle Google OAuth token stored before encryption was enabled", async () => {
		// Simulate the exact bug scenario from issue #6018:
		// 1. User logs in with Google OAuth when encryptOAuthTokens: false
		// 2. Access token stored as plain text: "ya29.a0ARW5m7..."
		// 3. User enables encryptOAuthTokens: true
		// 4. Access token expires, system tries to decrypt the plain text token
		// 5. Previously: "hex string expected, got unpadded hex of length 253" /* cspell:disable-line */
		// 6. Now: should return the token as-is

		const ctx = createMockContext(true); // encryption now enabled

		// Real-world Google OAuth access token format (contains non-hex chars)
		const googleAccessToken =
			"ya29.a0ARW5m7hQ_test-token_with.dots-and_underscores";

		// This should NOT throw "hex string expected, got unpadded hex of length X" /* cspell:disable-line */
		const result = await decryptOAuthToken(googleAccessToken, ctx);
		expect(result).toBe(googleAccessToken);
	});

	it("should handle refresh token that was stored unencrypted", async () => {
		const ctx = createMockContext(true);

		// Google refresh tokens have this format
		const googleRefreshToken =
			"1//0gxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // cspell:disable-line

		const result = await decryptOAuthToken(googleRefreshToken, ctx);
		expect(result).toBe(googleRefreshToken);
	});

	it("should still decrypt properly encrypted tokens", async () => {
		const ctx = createMockContext(true);
		const originalToken = "ya29.newToken_after_encryption_enabled";

		// Simulate a token that was stored AFTER encryption was enabled
		const encryptedToken = await setTokenUtil(originalToken, ctx);

		// Should decrypt correctly
		const result = await decryptOAuthToken(encryptedToken as string, ctx);
		expect(result).toBe(originalToken);
	});
});

describe("setTokenUtil", () => {
	it("should return null/undefined as-is", async () => {
		const ctx = createMockContext(true);
		expect(await setTokenUtil(null, ctx)).toBe(null);
		expect(await setTokenUtil(undefined, ctx)).toBe(undefined);
	});

	it("should return token as-is when encryption is disabled", async () => {
		const ctx = createMockContext(false);
		const token = "test-token";
		const result = await setTokenUtil(token, ctx);
		expect(result).toBe(token);
	});

	it("should encrypt token when encryption is enabled", async () => {
		const ctx = createMockContext(true);
		const token = "test-token";
		const result = await setTokenUtil(token, ctx);

		expect(result).not.toBe(token);
		expect(result).toMatch(/^clr-oauth:v1:[0-9a-f]+$/i);
	});

	it("wraps rotating-key ciphertext in the OAuth token envelope", async () => {
		const ctx = createRotatingMockContext();
		const encrypted = await setTokenUtil("test-token", ctx);

		expect(encrypted).toMatch(/^clr-oauth:v1:\$ba\$1\$/);
	});

	it("should produce tokens that can be decrypted", async () => {
		const ctx = createMockContext(true);
		const originalToken = "my-secret-access-token";

		const encrypted = await setTokenUtil(originalToken, ctx);
		const decrypted = await decryptOAuthToken(encrypted as string, ctx);

		expect(decrypted).toBe(originalToken);
	});
});
