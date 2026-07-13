import { describe, expect, it } from "vitest";
import { requireSAMLAssertionId } from "./saml-pipeline";

describe("SAML assertion replay identifier", () => {
	it("returns a replay-stable assertion ID", () => {
		const response = `
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
				xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion ID="assertion-123" />
			</samlp:Response>
		`;

		expect(requireSAMLAssertionId(response)).toBe("assertion-123");
	});

	it("returns the ID from a decrypted root assertion", () => {
		const assertion = `
			<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
				ID="encrypted-assertion-123" />
		`;

		expect(requireSAMLAssertionId(assertion)).toBe("encrypted-assertion-123");
	});

	it("rejects an assertion without a replay-stable identifier", () => {
		const response = `
			<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
				xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
				<saml:Assertion />
			</samlp:Response>
		`;

		expect(() => requireSAMLAssertionId(response)).toThrow(
			expect.objectContaining({
				body: expect.objectContaining({
					code: "SAML_ASSERTION_ID_REQUIRED",
				}),
			}),
		);
	});
});
