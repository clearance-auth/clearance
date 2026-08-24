import type { SecretConfig } from "@clearance/core";
import { constantTimeEqual } from "./buffer";
import { makeSignature } from "./index";

const OTP_VERIFIER_PREFIX = "$clearance-otp$";

/**
 * Creates a versioned, server-secret-keyed OTP verifier. The server secret is
 * deliberately never stored alongside the challenge, and the caller supplied
 * domain prevents a verifier from one OTP feature being usable in another.
 */
export async function createOTPVerifier(input: {
	secretConfig: string | SecretConfig;
	domain: string;
	otp: string;
}): Promise<string> {
	const version =
		typeof input.secretConfig === "string"
			? -1
			: input.secretConfig.currentVersion;
	const secret =
		typeof input.secretConfig === "string"
			? input.secretConfig
			: input.secretConfig.keys.get(version);
	if (!secret) {
		throw new Error(
			`Secret version ${version} not found in keys`,
		);
	}
	const signature = await makeSignature(
		`${input.domain}\0${input.otp}`,
		secret,
	);
	return `${OTP_VERIFIER_PREFIX}${version}$${signature}`;
}

/** Verify an OTP verifier without exposing or persisting the OTP itself. */
export async function verifyOTPVerifier(input: {
	secretConfig: string | SecretConfig;
	domain: string;
	otp: string;
	verifier: string;
}): Promise<boolean> {
	if (!input.verifier.startsWith(OTP_VERIFIER_PREFIX)) return false;
	const versionEnd = input.verifier.indexOf("$", OTP_VERIFIER_PREFIX.length);
	if (versionEnd === -1) return false;
	const version = Number.parseInt(
		input.verifier.slice(OTP_VERIFIER_PREFIX.length, versionEnd),
		10,
	);
	if (!Number.isInteger(version) || version < -1) return false;
	const secret =
		typeof input.secretConfig === "string"
			? version === -1
				? input.secretConfig
				: undefined
			: input.secretConfig.keys.get(version);
	if (!secret) return false;
	const expected = `${OTP_VERIFIER_PREFIX}${version}$${await makeSignature(
		`${input.domain}\0${input.otp}`,
		secret,
	)}`;
	return constantTimeEqual(input.verifier, expected);
}
