import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { validateSamlProviderConfig } from "../services/sso-real.js";

const certificate = readFileSync(
	new URL("../../../../fixtures/sso/test-certificate.pem", import.meta.url),
	"utf8",
);

describe("SAML provider configuration", () => {
	it("accepts an HTTPS entry point and a currently valid X.509 certificate", () => {
		const result = validateSamlProviderConfig({
			entryPoint: "https://customer.okta.test/app/clearance/sso/saml",
			certificate,
		});
		expect(result.entryPoint).toBe(
			"https://customer.okta.test/app/clearance/sso/saml",
		);
		expect(result.certificate).toContain("BEGIN CERTIFICATE");
		expect(result.fingerprint).toMatch(/^[a-f0-9]{64}$/);
	});

	it("fails closed on missing, malformed, or insecure provider material", () => {
		expect(() => validateSamlProviderConfig({})).toThrow(/required/i);
		expect(() =>
			validateSamlProviderConfig({
				entryPoint: "https://customer.okta.test/sso",
				certificate: "not-a-certificate",
			}),
		).toThrow(/valid X.509/i);
		expect(() =>
			validateSamlProviderConfig({
				entryPoint: "http://customer.okta.test/sso",
				certificate,
			}),
		).toThrow(/HTTPS/i);
	});
});
