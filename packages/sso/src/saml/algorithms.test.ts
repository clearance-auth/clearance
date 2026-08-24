/* cspell:ignore xenc */
import { describe, expect, it, vi } from "vitest";
import * as alg from "./algorithms";

function signed(
	xml: string,
	{
		signature = alg.SignatureAlgorithm.RSA_SHA256,
		digests = [alg.DigestAlgorithm.SHA256],
	}: { signature?: string; digests?: string[] } = {},
): string {
	const references = digests
		.map(
			(digest) => `
				<ds:Reference URI="#assertion">
					<ds:DigestMethod Algorithm="${digest}" />
					<ds:DigestValue>test</ds:DigestValue>
				</ds:Reference>`,
		)
		.join("");
	const signatureXml = `
		<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
			<ds:SignedInfo>
				<ds:SignatureMethod Algorithm="${signature}" />
				${references}
			</ds:SignedInfo>
			<ds:SignatureValue>test</ds:SignatureValue>
		</ds:Signature>`;

	return xml.replace(/(<(?:\w+:)?Response\b[^>]*>)/, `$1${signatureXml}`);
}

const encryptedAssertionXml = signed(`
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<xenc:EncryptedKey>
					<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
				</xenc:EncryptedKey>
			</ds:KeyInfo>
		</xenc:EncryptedData>
	</saml:EncryptedAssertion>
</samlp:Response>
`);

const deprecatedEncryptionXml = signed(`
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<xenc:EncryptedKey>
					<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
				</xenc:EncryptedKey>
			</ds:KeyInfo>
		</xenc:EncryptedData>
	</saml:EncryptedAssertion>
</samlp:Response>
`);

const deprecatedKeyEncryptionXml = signed(`
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<xenc:EncryptedKey>
					<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
				</xenc:EncryptedKey>
			</ds:KeyInfo>
		</xenc:EncryptedData>
	</saml:EncryptedAssertion>
</samlp:Response>
`);

const deprecatedDataEncryptionXml = signed(`
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
			<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
			<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
				<xenc:EncryptedKey>
					<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
				</xenc:EncryptedKey>
			</ds:KeyInfo>
		</xenc:EncryptedData>
	</saml:EncryptedAssertion>
</samlp:Response>
`);

const plainAssertionXml = `
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
		<saml:Subject>test</saml:Subject>
	</saml:Assertion>
</samlp:Response>
`;

describe("validateSAMLAlgorithms", () => {
	describe("signature validation", () => {
		it("should accept secure signature algorithms", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
					samlContent: signed(plainAssertionXml),
				}),
			).not.toThrow();
		});

		it("should accept the RSA-PSS algorithm supported by the verifier", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					samlContent: signed(plainAssertionXml, {
						signature: alg.SignatureAlgorithm.RSA_PSS_SHA256,
					}),
				}),
			).not.toThrow();
		});

		it("should accept matching Response and Assertion signatures", () => {
			const responseSigned = signed(plainAssertionXml);
			const signature = responseSigned.match(
				/<ds:Signature\b[\s\S]*?<\/ds:Signature>/,
			)?.[0];
			expect(signature).toBeTruthy();
			const dualSigned = responseSigned.replace(
				/(<saml:Assertion\b[^>]*>)/,
				`$1${signature}`,
			);

			expect(() =>
				alg.validateSAMLAlgorithms({ samlContent: dualSigned }),
			).not.toThrow();
		});

		it("should reject deprecated signature algorithms by default", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: alg.SignatureAlgorithm.RSA_SHA1,
					samlContent: signed(plainAssertionXml, {
						signature: alg.SignatureAlgorithm.RSA_SHA1,
					}),
				}),
			).toThrow(/deprecated/i);
		});

		it("should warn for deprecated signature algorithms when opted in", () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			expect(() =>
				alg.validateSAMLAlgorithms(
					{
						sigAlg: alg.SignatureAlgorithm.RSA_SHA1,
						samlContent: signed(plainAssertionXml, {
							signature: alg.SignatureAlgorithm.RSA_SHA1,
						}),
					},
					{ onDeprecated: "warn" },
				),
			).not.toThrow();
			expect(warnSpy).toHaveBeenCalledWith(
				expect.stringContaining("SAML Security Warning"),
			);
		});

		it("should reject deprecated signature with onDeprecated: reject", () => {
			expect(() =>
				alg.validateSAMLAlgorithms(
					{
						sigAlg: alg.SignatureAlgorithm.RSA_SHA1,
						samlContent: signed(plainAssertionXml, {
							signature: alg.SignatureAlgorithm.RSA_SHA1,
						}),
					},
					{ onDeprecated: "reject" },
				),
			).toThrow(/deprecated/i);
		});

		it("should silently allow deprecated with onDeprecated: allow", () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			expect(() =>
				alg.validateSAMLAlgorithms(
					{
						sigAlg: alg.SignatureAlgorithm.RSA_SHA1,
						samlContent: signed(plainAssertionXml, {
							signature: alg.SignatureAlgorithm.RSA_SHA1,
						}),
					},
					{ onDeprecated: "allow" },
				),
			).not.toThrow();

			expect(warnSpy).not.toHaveBeenCalled();
		});

		it("should enforce custom signature allow-list", () => {
			expect(() =>
				alg.validateSAMLAlgorithms(
					{
						sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
						samlContent: signed(plainAssertionXml),
					},
					{ allowedSignatureAlgorithms: [alg.SignatureAlgorithm.RSA_SHA512] },
				),
			).toThrow(/not in allow-list/i);
		});

		it("should enforce the embedded signature when POST sigAlg is absent", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: null,
					samlContent: signed(plainAssertionXml),
				}),
			).not.toThrow();
		});

		it("should reject unknown signature algorithms", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: "http://example.com/unknown-algo",
					samlContent: signed(plainAssertionXml, {
						signature: "http://example.com/unknown-algo",
					}),
				}),
			).toThrow(/not recognized/i);
		});

		it("should reject a deprecated embedded signature when POST sigAlg is absent", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					samlContent: signed(plainAssertionXml, {
						signature: alg.SignatureAlgorithm.RSA_SHA1,
					}),
				}),
			).toThrow(/deprecated signature algorithm/i);
		});

		it("should reject an unsigned algorithm declaration outside the verified signature location", () => {
			const wrapped = signed(plainAssertionXml).replace(
				"<saml:Subject>test</saml:Subject>",
				`<saml:Subject>test</saml:Subject>
				<Wrapper><ds:Signature><ds:SignedInfo /></ds:Signature></Wrapper>`,
			);

			expect(() =>
				alg.validateSAMLAlgorithms({ samlContent: wrapped }),
			).toThrow(/ambiguous XML signatures/i);
		});

		it("should reject a missing embedded signature even when sigAlg is supplied", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
					samlContent: plainAssertionXml,
				}),
			).toThrow(/missing an embedded XML signature/i);
		});
	});

	describe("digest validation", () => {
		it("should enforce the digest allow-list from embedded signed references", () => {
			expect(() =>
				alg.validateSAMLAlgorithms(
					{ samlContent: signed(plainAssertionXml) },
					{ allowedDigestAlgorithms: [alg.DigestAlgorithm.SHA512] },
				),
			).toThrow(/digest algorithm not in allow-list/i);
		});

		it("should reject deprecated embedded digest algorithms", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					samlContent: signed(plainAssertionXml, {
						digests: [alg.DigestAlgorithm.SHA1],
					}),
				}),
			).toThrow(/deprecated digest algorithm/i);
		});

		it("should accept an explicitly allow-listed digest algorithm", () => {
			expect(() =>
				alg.validateSAMLAlgorithms(
					{
						samlContent: signed(plainAssertionXml, {
							digests: [alg.DigestAlgorithm.SHA512],
						}),
					},
					{ allowedDigestAlgorithms: ["sha512"] },
				),
			).not.toThrow();
		});

		it("should reject unknown embedded digest algorithms", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					samlContent: signed(plainAssertionXml, {
						digests: ["https://example.com/unknown-digest"],
					}),
				}),
			).toThrow(/digest algorithm not recognized/i);
		});

		it("should reject mixed digest algorithms across signed references", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					samlContent: signed(plainAssertionXml, {
						digests: [
							alg.DigestAlgorithm.SHA256,
							alg.DigestAlgorithm.SHA512,
						],
					}),
				}),
			).toThrow(/mixed digest algorithms/i);
		});

		it("should reject a missing digest method", () => {
			const missingDigest = signed(plainAssertionXml).replace(
				/<ds:DigestMethod[^>]+\/>/,
				"",
			);
			expect(() =>
				alg.validateSAMLAlgorithms({ samlContent: missingDigest }),
			).toThrow(/must declare exactly one digest algorithm/i);
		});
	});

	describe("encryption validation", () => {
		it("should accept secure encryption algorithms", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
					samlContent: encryptedAssertionXml,
				}),
			).not.toThrow();
		});

		it("should reject deprecated key encryption algorithms by default", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
					samlContent: deprecatedKeyEncryptionXml,
				}),
			).toThrow(/deprecated key encryption algorithm/i);
		});

		it("should reject deprecated data encryption algorithms by default", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
					samlContent: deprecatedDataEncryptionXml,
				}),
			).toThrow(/deprecated data encryption algorithm/i);
		});

		it("should warn for deprecated encryption algorithms when opted in", () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			expect(() =>
				alg.validateSAMLAlgorithms(
					{
						sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
						samlContent: deprecatedEncryptionXml,
					},
					{ onDeprecated: "warn" },
				),
			).not.toThrow();

			expect(warnSpy).toHaveBeenCalledTimes(2);
		});

		it("should reject deprecated encryption with onDeprecated: reject", () => {
			expect(() =>
				alg.validateSAMLAlgorithms(
					{
						sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
						samlContent: deprecatedEncryptionXml,
					},
					{ onDeprecated: "reject" },
				),
			).toThrow(/deprecated/i);
		});

		it("should ignore wrapped encryption decoys and validate the direct encrypted assertion", () => {
			const secureDecoy = `
				<Wrapper>
					<xenc:EncryptedData>
						<xenc:EncryptionMethod Algorithm="${alg.DataEncryptionAlgorithm.AES_256_GCM}" />
						<ds:KeyInfo><xenc:EncryptedKey>
							<xenc:EncryptionMethod Algorithm="${alg.KeyEncryptionAlgorithm.RSA_OAEP}" />
						</xenc:EncryptedKey></ds:KeyInfo>
					</xenc:EncryptedData>
				</Wrapper>`;
			const decoyBeforeAssertion = deprecatedEncryptionXml.replace(
				"<saml:EncryptedAssertion",
				`${secureDecoy}<saml:EncryptedAssertion`,
			);

			expect(() =>
				alg.validateSAMLAlgorithms({
					samlContent: decoyBeforeAssertion,
				}),
			).toThrow(/deprecated key encryption algorithm/i);
		});

		it("should reject unknown key encryption algorithms", () => {
			const unknownKey = encryptedAssertionXml.replace(
				alg.KeyEncryptionAlgorithm.RSA_OAEP,
				"urn:example:unknown-key-encryption",
			);

			expect(() =>
				alg.validateSAMLAlgorithms({ samlContent: unknownKey }),
			).toThrow(/key encryption algorithm not recognized/i);
		});

		it("should reject unknown data encryption algorithms", () => {
			const unknownData = encryptedAssertionXml.replace(
				alg.DataEncryptionAlgorithm.AES_256_CBC,
				"urn:example:unknown-data-encryption",
			);

			expect(() =>
				alg.validateSAMLAlgorithms({ samlContent: unknownData }),
			).toThrow(/data encryption algorithm not recognized/i);
		});

		it("should skip encryption validation for plain assertions", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
					samlContent: signed(plainAssertionXml),
				}),
			).not.toThrow();
		});

		it("should handle malformed XML gracefully", () => {
			expect(() =>
				alg.validateSAMLAlgorithms({
					sigAlg: alg.SignatureAlgorithm.RSA_SHA256,
					samlContent: "not valid xml",
				}),
			).toThrow(/missing a Response or Assertion root/i);
		});
	});
});

describe("algorithm constants", () => {
	it("should export signature algorithm constants", () => {
		expect(alg.SignatureAlgorithm.RSA_SHA256).toBe(
			"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		);
		expect(alg.SignatureAlgorithm.RSA_SHA1).toBe(
			"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
		);
	});

	it("should export encryption algorithm constants", () => {
		expect(alg.KeyEncryptionAlgorithm.RSA_OAEP).toBe(
			"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
		);
		expect(alg.DataEncryptionAlgorithm.AES_256_GCM).toBe(
			"http://www.w3.org/2009/xmlenc11#aes256-gcm",
		);
	});
});

describe("validateConfigAlgorithms", () => {
	describe("signature algorithm validation", () => {
		it("should accept secure signature algorithms", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA256,
				}),
			).not.toThrow();
		});

		it("should reject deprecated signature algorithms by default", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA1,
				}),
			).toThrow(/deprecated/i);
		});

		it("should warn for deprecated signature algorithms when opted in", () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			expect(() =>
				alg.validateConfigAlgorithms(
					{ signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA1 },
					{ onDeprecated: "warn" },
				),
			).not.toThrow();
			expect(warnSpy).toHaveBeenCalledWith(
				expect.stringContaining("SAML Security Warning"),
			);
		});

		it("should reject deprecated signature with onDeprecated: reject", () => {
			expect(() =>
				alg.validateConfigAlgorithms(
					{ signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA1 },
					{ onDeprecated: "reject" },
				),
			).toThrow(/deprecated/i);
		});

		it("should silently allow deprecated with onDeprecated: allow", () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			expect(() =>
				alg.validateConfigAlgorithms(
					{ signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA1 },
					{ onDeprecated: "allow" },
				),
			).not.toThrow();

			expect(warnSpy).not.toHaveBeenCalled();
		});

		it("should enforce custom signature allow-list", () => {
			expect(() =>
				alg.validateConfigAlgorithms(
					{ signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA256 },
					{ allowedSignatureAlgorithms: [alg.SignatureAlgorithm.RSA_SHA512] },
				),
			).toThrow(/not in allow-list/i);
		});

		it("should reject unknown signature algorithms", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					signatureAlgorithm: "http://example.com/unknown-algo",
				}),
			).toThrow(/not recognized/i);
		});

		it("should pass undefined signatureAlgorithm without error", () => {
			expect(() => alg.validateConfigAlgorithms({})).not.toThrow();
		});

		it("should accept short-form signature algorithm names", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					signatureAlgorithm: "rsa-sha256",
				}),
			).not.toThrow();
		});

		it("should accept digest-style short-form for signature (backward compat)", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					signatureAlgorithm: "sha256",
				}),
			).not.toThrow();
		});

		it("should reject typos in short-form signature algorithm names", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					signatureAlgorithm: "rsa-sha257",
				}),
			).toThrow(/not recognized/i);
		});

		it("should reject deprecated short-form signature algorithms by default", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					signatureAlgorithm: "rsa-sha1",
				}),
			).toThrow(/deprecated/i);
		});

		it("should support short-form names in signature allow-list", () => {
			expect(() =>
				alg.validateConfigAlgorithms(
					{ signatureAlgorithm: "rsa-sha256" },
					{ allowedSignatureAlgorithms: ["rsa-sha256", "rsa-sha512"] },
				),
			).not.toThrow();
		});
	});

	describe("digest algorithm validation", () => {
		it("should accept secure digest algorithms", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					digestAlgorithm: alg.DigestAlgorithm.SHA256,
				}),
			).not.toThrow();
		});

		it("should reject deprecated digest algorithms by default", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					digestAlgorithm: alg.DigestAlgorithm.SHA1,
				}),
			).toThrow(/deprecated/i);
		});

		it("should warn for deprecated digest algorithms when opted in", () => {
			const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

			expect(() =>
				alg.validateConfigAlgorithms(
					{ digestAlgorithm: alg.DigestAlgorithm.SHA1 },
					{ onDeprecated: "warn" },
				),
			).not.toThrow();
			expect(warnSpy).toHaveBeenCalledWith(
				expect.stringContaining("SAML Security Warning"),
			);
		});

		it("should reject deprecated digest with onDeprecated: reject", () => {
			expect(() =>
				alg.validateConfigAlgorithms(
					{ digestAlgorithm: alg.DigestAlgorithm.SHA1 },
					{ onDeprecated: "reject" },
				),
			).toThrow(/deprecated/i);
		});

		it("should enforce custom digest allow-list", () => {
			expect(() =>
				alg.validateConfigAlgorithms(
					{ digestAlgorithm: alg.DigestAlgorithm.SHA256 },
					{ allowedDigestAlgorithms: [alg.DigestAlgorithm.SHA512] },
				),
			).toThrow(/not in allow-list/i);
		});

		it("should reject unknown digest algorithms", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					digestAlgorithm: "http://example.com/unknown-digest",
				}),
			).toThrow(/not recognized/i);
		});

		it("should accept short-form digest algorithm names", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					digestAlgorithm: "sha256",
				}),
			).not.toThrow();
		});

		it("should reject typos in short-form digest algorithm names", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					digestAlgorithm: "sha257",
				}),
			).toThrow(/not recognized/i);
		});

		it("should reject deprecated short-form digest algorithms by default", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					digestAlgorithm: "sha1",
				}),
			).toThrow(/deprecated/i);
		});

		it("should support short-form names in digest allow-list", () => {
			expect(() =>
				alg.validateConfigAlgorithms(
					{ digestAlgorithm: "sha256" },
					{ allowedDigestAlgorithms: ["sha256", "sha512"] },
				),
			).not.toThrow();
		});
	});

	describe("combined validation", () => {
		it("should validate both signature and digest algorithms", () => {
			expect(() =>
				alg.validateConfigAlgorithms({
					signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA256,
					digestAlgorithm: alg.DigestAlgorithm.SHA256,
				}),
			).not.toThrow();
		});

		it("should reject if signature is deprecated even if digest is secure", () => {
			expect(() =>
				alg.validateConfigAlgorithms(
					{
						signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA1,
						digestAlgorithm: alg.DigestAlgorithm.SHA256,
					},
					{ onDeprecated: "reject" },
				),
			).toThrow(/deprecated/i);
		});

		it("should reject if digest is deprecated even if signature is secure", () => {
			expect(() =>
				alg.validateConfigAlgorithms(
					{
						signatureAlgorithm: alg.SignatureAlgorithm.RSA_SHA256,
						digestAlgorithm: alg.DigestAlgorithm.SHA1,
					},
					{ onDeprecated: "reject" },
				),
			).toThrow(/deprecated/i);
		});
	});
});
