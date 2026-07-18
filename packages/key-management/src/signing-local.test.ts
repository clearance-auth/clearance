import {
	createPublicKey,
	generateKeyPairSync,
	verify,
} from "node:crypto";
import { describe, expect, it } from "vitest";
import { KeyManagementError } from "./error.js";
import { createLocalSigningProvider } from "./signing-local.js";

function p256Pkcs8(): Buffer {
	return generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
		format: "der",
		type: "pkcs8",
	}) as Buffer;
}

describe("local ES256 signing provider", () => {
	it("signs with a canonical P-256 key, publishes retained JWKS metadata, and rejects invalid or leaked configuration", async () => {
		const retiredAt = new Date("2025-01-01T00:00:00.000Z");
		const currentReference = "current-private-key-reference";
		const retainedReference = "retained-private-key-reference";
		const provider = createLocalSigningProvider({
			providerId: "local-jwt-provider",
			currentKeyReference: currentReference,
			keys: {
				[currentReference]: p256Pkcs8().toString("base64url"),
				[retainedReference]: p256Pkcs8(),
			},
			retainedKeys: [{ keyReference: retainedReference, retiredAt }],
		});

		const input = Buffer.from("header.payload", "ascii");
		const signature = await provider.sign(input);
		expect(signature).toHaveLength(64);
		const keys = await provider.publicKeys();
		expect(keys).toHaveLength(2);
		expect(keys[0]).toMatchObject({
			id: provider.currentKeyId,
			createdAt: new Date(0),
			publicJwk: { alg: "ES256", use: "sig", kid: provider.currentKeyId },
		});
		expect(keys[0]?.expiresAt).toBeUndefined();
		expect(keys[1]?.createdAt).toEqual(new Date(0));
		expect(keys[1]?.expiresAt).toEqual(retiredAt);
		expect(Object.isFrozen(keys[0]?.publicJwk)).toBe(true);
		expect(
			verify(
				"sha256",
				input,
				{ key: createPublicKey({ key: keys[0]!.publicJwk, format: "jwk" }), dsaEncoding: "ieee-p1363" },
				signature,
			),
		).toBe(true);

		const readiness = await provider.readiness();
		expect(JSON.stringify(readiness)).not.toContain(currentReference);
		expect(JSON.stringify(readiness)).not.toContain(retainedReference);
		expect(readiness.ready).toBe(true);
		await expect(provider.sign(new Uint8Array())).rejects.toMatchObject({
			code: "KEY_INPUT_INVALID",
		});
		expect(() => createLocalSigningProvider({
			providerId: "invalid-jwt-provider",
			currentKeyReference: "invalid",
			keys: { invalid: "not-a-private-key" },
		})).toThrow(KeyManagementError);
	});
});
