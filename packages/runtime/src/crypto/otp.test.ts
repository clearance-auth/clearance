import type { SecretConfig } from "@clearance/core";
import { describe, expect, it } from "vitest";
import { createOTPVerifier, verifyOTPVerifier } from "./otp";

const secretConfig = (secret: string): SecretConfig => ({
	keys: new Map([[0, secret]]),
	currentVersion: 0,
});

describe("OTP verifiers", () => {
	it("stores no OTP and cannot be enumerated offline without the application secret", async () => {
		const otp = "731944";
		const verifier = await createOTPVerifier({
			secretConfig: secretConfig("application-secret"),
			domain: "clearance:email-otp:v1",
			otp,
		});

		expect(verifier).not.toContain(otp);
		// A database-only attacker cannot use the one million possible six-digit
		// values as candidates because each needs the application secret's HMAC.
		let matchedRawCandidate = false;
		for (let candidate = 0; candidate < 1_000_000; candidate += 1) {
			matchedRawCandidate ||= verifier === candidate.toString().padStart(6, "0");
		}
		expect(matchedRawCandidate).toBe(false);
		expect(
			await verifyOTPVerifier({
				secretConfig: secretConfig("different-secret"),
				domain: "clearance:email-otp:v1",
				otp,
				verifier,
			}),
		).toBe(false);
		expect(
			await verifyOTPVerifier({
				secretConfig: secretConfig("application-secret"),
				domain: "clearance:email-otp:v1",
				otp,
				verifier,
			}),
		).toBe(true);
		expect(
			await verifyOTPVerifier({
				secretConfig: secretConfig("application-secret"),
				domain: "clearance:email-otp:v1",
				otp: "000000",
				verifier,
			}),
		).toBe(false);
	});
});
