import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";

export type EmailOTPChallengeType =
	| "email-verification"
	| "sign-in"
	| "forget-password"
	| "change-email";

export function toOTPIdentifier(
	type: EmailOTPChallengeType,
	email: string,
) {
	return `${type}-otp-${email}`;
}

export function emailOTPChallenge(
	type: EmailOTPChallengeType,
	subject: string,
) {
	return {
		purpose: `email-otp:${type}`,
		subject,
		identifier: toOTPIdentifier(type, subject),
	} as const;
}

export const defaultKeyHasher = async (otp: string) => {
	const hash = await createHash("SHA-256").digest(
		new TextEncoder().encode(otp),
	);
	const hashed = base64Url.encode(new Uint8Array(hash), {
		padding: false,
	});
	return hashed;
};

export function splitAtLastColon(input: string): [string, string] {
	const idx = input.lastIndexOf(":");
	if (idx === -1) {
		return [input, ""];
	}
	return [input.slice(0, idx), input.slice(idx + 1)];
}
