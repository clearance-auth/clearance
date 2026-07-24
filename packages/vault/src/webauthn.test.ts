import { afterEach, describe, expect, it, vi } from "vitest";
import {
	parseRegistrationOptions,
	registrationCreationOptions,
	registrationResponse,
} from "./webauthn";

afterEach(() => vi.unstubAllGlobals());

describe("Vault WebAuthn extensions", () => {
	it("parses and forwards only the closed extension contract", () => {
		const options = parseRegistrationOptions({
			challenge: "AQI",
			rp: { id: "example.test", name: "Example" },
			user: { id: "AwQ", name: "owner@example.test", displayName: "Owner" },
			pubKeyCredParams: [{ alg: -7, type: "public-key" }],
			timeout: 60_000,
			authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
			attestation: "none",
			extensions: {
				appid: "https://example.test",
				largeBlob: { support: "required", write: "BQY" },
				prf: { eval: { first: "Bwg", second: "CQ" } },
			},
		});
		const browser = registrationCreationOptions(options);
		expect(browser.rp).toEqual({ id: "example.test", name: "Example" });
		expect(browser.extensions?.largeBlob?.write).toEqual(new Uint8Array([5, 6]).buffer);
		expect(browser.extensions?.prf?.eval?.first).toEqual(new Uint8Array([7, 8]).buffer);
		expect(() => parseRegistrationOptions({
			challenge: "AQI", rp: { id: "example.test", name: "Example" },
			user: { id: "AwQ", name: "owner@example.test", displayName: "Owner" },
			pubKeyCredParams: [{ alg: -7, type: "public-key" }], timeout: 60_000,
			authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
			attestation: "none", extensions: { unrecognized: true },
		})).toThrow("invalid passkey registration extensions");
	});

	it("recursively base64url encodes supported binary extension results", () => {
		class FakeAttestationResponse {
			clientDataJSON = new Uint8Array([1]).buffer;
			attestationObject = new Uint8Array([2]).buffer;
			getTransports = () => [] as AuthenticatorTransport[];
			getPublicKey = () => null;
			getAuthenticatorData = () => undefined;
			getPublicKeyAlgorithm = () => -7;
		}
		vi.stubGlobal("AuthenticatorAttestationResponse", FakeAttestationResponse);
		const credential = {
			id: "credential_1",
			rawId: new Uint8Array([3]).buffer,
			response: new FakeAttestationResponse(),
			authenticatorAttachment: null,
			getClientExtensionResults: () => ({
				largeBlob: { blob: new Uint8Array([4, 5]).buffer, supported: true },
				prf: { results: { first: new Uint8Array([6, 7]), second: new Uint8Array([8]).buffer } },
			}),
		} as unknown as PublicKeyCredential;
		expect(registrationResponse(credential).clientExtensionResults).toEqual({
			largeBlob: { blob: "BAU", supported: true },
			prf: { results: { first: "Bgc", second: "CA" } },
		});
		const unsupported = {
			...credential,
			getClientExtensionResults: () => ({ unexpected: true }),
		} as unknown as PublicKeyCredential;
		expect(() => registrationResponse(unsupported)).toThrow("unsupported passkey extension result");
	});
});
