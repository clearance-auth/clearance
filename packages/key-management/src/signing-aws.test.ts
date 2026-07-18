import {
	createHash,
	generateKeyPairSync,
	sign as signWithPrivateKey,
} from "node:crypto";
import {
	DescribeKeyCommand,
	GetPublicKeyCommand,
	type KMSClient,
	SignCommand,
} from "@aws-sdk/client-kms";
import { describe, expect, it } from "vitest";
import { createAwsKmsSigningProvider } from "./signing-aws.js";

const currentReference = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111";
const retainedReference = "22222222-2222-4222-8222-222222222222";
const currentRawId = "11111111-1111-4111-8111-111111111111";
const createdAt = new Date("2026-01-01T00:00:00.000Z");
const retiredAt = new Date("2026-06-01T00:00:00.000Z");

describe("AWS KMS ES256 signing provider", () => {
	it("binds KMS signing and public-key semantics without exposing key references", async () => {
		const { privateKey, publicKey } = generateKeyPairSync("ec", {
			namedCurve: "prime256v1",
		});
		const publicDer = publicKey.export({ type: "spki", format: "der" });
		const calls: unknown[] = [];
		let responseKeyId = currentRawId;
		let signature = signWithPrivateKey(null, Buffer.from("header.payload"), {
			key: privateKey,
			dsaEncoding: "der",
		});
		const client = {
			async send(command: unknown) {
				calls.push(command);
				if (command instanceof SignCommand) {
					return {
						KeyId: responseKeyId,
						SigningAlgorithm: "ECDSA_SHA_256",
						Signature: signature,
					};
				}
				if (command instanceof GetPublicKeyCommand) {
					return {
						KeyId: command.input.KeyId === currentReference
							? responseKeyId
							: retainedReference,
						KeyUsage: "SIGN_VERIFY",
						KeySpec: "ECC_NIST_P256",
						SigningAlgorithms: ["ECDSA_SHA_256"],
						PublicKey: publicDer,
					};
				}
				if (command instanceof DescribeKeyCommand) {
					return {
						KeyMetadata: {
							KeyId: command.input.KeyId === currentReference
								? currentRawId
								: retainedReference,
							Enabled: true,
							KeyState: "Enabled",
							KeyUsage: "SIGN_VERIFY",
							KeySpec: "ECC_NIST_P256",
							CreationDate: createdAt,
						},
					};
				}
				throw new Error("unexpected KMS command");
			},
		} as unknown as KMSClient;

		expect(() => createAwsKmsSigningProvider({
			providerId: "aws-jwt",
			currentKeyReference: "alias/clearance-jwt",
			region: "us-east-1",
			client,
		})).toThrowError(expect.objectContaining({ code: "KEY_INPUT_INVALID" }));
		expect(() => createAwsKmsSigningProvider({
			providerId: "aws-jwt",
			currentKeyReference: currentReference,
			region: "us-east-1",
			client: {} as KMSClient,
		})).toThrowError(expect.objectContaining({ code: "KEY_INPUT_INVALID" }));

		const signer = createAwsKmsSigningProvider({
			providerId: "aws-jwt",
			currentKeyReference: currentReference,
			retainedKeys: [{ keyReference: retainedReference, retiredAt }],
			region: "us-east-1",
			client,
		});
		const joseSignature = await signer.sign(Buffer.from("header.payload"));
		expect(joseSignature).toHaveLength(64);
		const signCommand = calls.find((call) => call instanceof SignCommand) as SignCommand;
		expect(signCommand.input).toMatchObject({
			KeyId: currentReference,
			Message: createHash("sha256").update("header.payload").digest(),
			MessageType: "DIGEST",
			SigningAlgorithm: "ECDSA_SHA_256",
		});

		const publicKeys = await signer.publicKeys();
		expect(publicKeys).toHaveLength(2);
		expect(publicKeys[0]).toMatchObject({
			publicJwk: { alg: "ES256", crv: "P-256", kty: "EC", use: "sig" },
			createdAt,
		});
		expect(publicKeys[1]?.expiresAt).toEqual(retiredAt);
		expect(JSON.stringify(publicKeys)).not.toContain(currentReference);
		expect(JSON.stringify(publicKeys)).not.toContain(retainedReference);

		const readiness = await signer.readiness();
		expect(readiness.ready).toBe(true);
		expect(JSON.stringify(readiness)).not.toContain(currentReference);
		expect(JSON.stringify(readiness)).not.toContain(retainedReference);

		responseKeyId = "33333333-3333-4333-8333-333333333333";
		await expect(signer.sign(Buffer.from("header.payload"))).rejects.toMatchObject({
			code: "KEY_OPERATION_FAILED",
		});

		responseKeyId = currentRawId;
		signature = Buffer.from([0x30, 0x00]);
		await expect(signer.sign(Buffer.from("header.payload"))).rejects.toMatchObject({
			code: "KEY_OPERATION_FAILED",
		});
	});
});
