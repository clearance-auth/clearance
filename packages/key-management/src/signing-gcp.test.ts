import {
	createHash,
	generateKeyPairSync,
	sign as signWithPrivateKey,
	verify,
} from "node:crypto";
import type { KeyManagementServiceClient } from "@google-cloud/kms";
import { describe, expect, it } from "vitest";
import { createGcpKmsSigningProvider } from "./signing-gcp.js";
import { crc32c } from "./signing-utils.js";

const current =
	"projects/project-one/locations/global/keyRings/clearance/cryptoKeys/access/cryptoKeyVersions/1";
const retained =
	"projects/project-one/locations/global/keyRings/clearance/cryptoKeys/access/cryptoKeyVersions/2";

describe("GCP KMS ES256 signing provider", () => {
	it("binds a SHA-256 digest, normalizes real KMS material, rejects invalid responses, and redacts readiness", async () => {
		const { privateKey, publicKey } = generateKeyPairSync("ec", {
			namedCurve: "prime256v1",
		});
		const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
		let input = Buffer.alloc(0);
		let failure: "name" | "missing-name" | "crc" | "signature" | undefined;
		const client = {
			async asymmetricSign(request: {
				name: string;
				digest: { sha256: Uint8Array };
				digestCrc32c: { value: number };
			}) {
				expect(request.name).toBe(current);
				const digest = createHash("sha256").update(input).digest();
				expect(Buffer.from(request.digest.sha256)).toEqual(digest);
				expect(request.digestCrc32c.value).toBe(crc32c(digest));
				if (failure === "name") {
					const signature = Buffer.from([1]);
					return [{
						name: retained,
						signature,
						signatureCrc32c: { value: crc32c(signature) },
						verifiedDigestCrc32c: true,
					}];
				}
				if (failure === "missing-name") {
					const signature = signWithPrivateKey("sha256", input, {
						key: privateKey,
						dsaEncoding: "der",
					});
					return [{
						signature,
						signatureCrc32c: { value: crc32c(signature) },
						verifiedDigestCrc32c: true,
					}];
				}
				if (failure === "crc") {
					const signature = signWithPrivateKey("sha256", input, {
						key: privateKey,
						dsaEncoding: "der",
					});
					return [{
						name: current,
						signature,
						signatureCrc32c: { value: crc32c(signature) },
						verifiedDigestCrc32c: false,
					}];
				}
				if (failure === "signature") {
					const signature = Buffer.from([0x30, 0x00]);
					return [{
						name: current,
						signature,
						signatureCrc32c: { value: crc32c(signature) },
						verifiedDigestCrc32c: true,
					}];
				}
				const signature = signWithPrivateKey("sha256", input, {
					key: privateKey,
					dsaEncoding: "der",
				});
				return [{
					name: current,
					signature,
					signatureCrc32c: { value: crc32c(signature) },
					verifiedDigestCrc32c: true,
				}];
			},
			async getPublicKey(request: { name: string }) {
				return [{
					name: request.name,
					algorithm: "EC_SIGN_P256_SHA256",
					pem,
					pemCrc32c: { value: crc32c(Buffer.from(pem, "utf8")) },
				}];
			},
		} as unknown as KeyManagementServiceClient;
		const provider = createGcpKmsSigningProvider({
			providerId: "gcp-access",
			currentKeyReference: current,
			retainedKeys: [{ keyReference: retained, retiredAt: new Date("2026-07-01T00:00:00.000Z") }],
			client,
		});

		input = Buffer.from("header.payload", "ascii");
		const signature = await provider.sign(input);
		expect(verify("sha256", input, {
			key: publicKey,
			dsaEncoding: "ieee-p1363",
		}, signature)).toBe(true);
		const keys = await provider.publicKeys();
		expect(keys).toHaveLength(2);
		expect(keys[0]?.id).toBe(provider.currentKeyId);
		expect(keys[1]?.expiresAt?.toISOString()).toBe("2026-07-01T00:00:00.000Z");
		expect(JSON.stringify(keys)).not.toContain(current);
		expect(JSON.stringify(keys)).not.toContain(retained);

		failure = "name";
		await expect(provider.sign(input)).rejects.toMatchObject({ code: "KEY_OPERATION_FAILED" });
		failure = "missing-name";
		await expect(provider.sign(input)).rejects.toMatchObject({ code: "KEY_OPERATION_FAILED" });
		failure = "crc";
		await expect(provider.sign(input)).rejects.toMatchObject({ code: "KEY_OPERATION_FAILED" });
		failure = "signature";
		await expect(provider.sign(input)).rejects.toMatchObject({ code: "KEY_OPERATION_FAILED" });
		failure = undefined;
		const readiness = await provider.readiness();
		expect(readiness.ready).toBe(true);
		expect(JSON.stringify(readiness)).not.toContain(current);
		expect(JSON.stringify(readiness)).not.toContain(retained);
		expect(() => createGcpKmsSigningProvider({
			providerId: "gcp-access",
			currentKeyReference: current.replace("/1", "/0"),
			client,
		})).toThrowError(expect.objectContaining({ code: "KEY_INPUT_INVALID" }));
	});
});
