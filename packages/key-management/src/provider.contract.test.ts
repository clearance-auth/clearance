import { createHash, randomBytes } from "node:crypto";
import {
	DecryptCommand,
	DescribeKeyCommand,
	EncryptCommand,
	type KMSClient,
} from "@aws-sdk/client-kms";
import type { KeyManagementServiceClient } from "@google-cloud/kms";
import { describe, expect, it } from "vitest";
import { createAwsKmsKeyProvider } from "./aws.js";
import { KeyManagementError } from "./error.js";
import { createGcpKmsKeyProvider } from "./gcp.js";
import { createLocalKeyProvider } from "./local.js";
import { createKeyProviderRegistry } from "./registry.js";
import type { KeyPurpose } from "./types.js";

const context = Object.freeze({
	projectId: "project_test",
	environmentId: "environment_test",
	resourceId: "resource_test",
});

function provider(
	providerId: string,
	purpose: KeyPurpose,
	currentKeyId: string,
	keys: Record<string, Uint8Array>,
) {
	return createLocalKeyProvider({ providerId, purpose, currentKeyId, keys });
}

describe("purpose-bound local key provider", () => {
	it("round-trips under the current key and reads retained rotations", async () => {
		const oldKey = randomBytes(32);
		const first = provider("oidc", "oidc-client-secret", "old", { old: oldKey });
		const envelope = await first.seal(Buffer.from("secret"), context);
		const rotated = provider("oidc", "oidc-client-secret", "new", { old: oldKey, new: randomBytes(32) });
		expect(Buffer.from(await rotated.open(envelope, context)).toString()).toBe("secret");
		expect(rotated.retainedKeyIds).toEqual(["old"]);
	});

	it("rejects scope mismatches before decryption", async () => {
		const local = provider("oidc", "oidc-client-secret", "one", { one: randomBytes(32) });
		const envelope = await local.seal(Buffer.from("secret"), context);
		await expect(
			local.open(envelope, { ...context, resourceId: "other" }),
		).rejects.toMatchObject({ code: "KEY_CONTEXT_MISMATCH" });
	});

	it("binds service-account credential replays to their canonical resource identity", async () => {
		const replay = provider(
			"replay",
			"service-account-credential-replay",
			"one",
			{ one: randomBytes(32) },
		);
		const binding = JSON.stringify({
			projectId: context.projectId,
			environmentId: context.environmentId,
			organizationId: "organization_test",
			actorId: "actor_test",
			serviceAccountId: "service_account_test",
			operationId: "operation_test",
			operationKind: "service_account_credential.create",
		});
		const resourceIdFor = (value: string) =>
			`service-account-credential-replay:${createHash("sha256")
				.update(JSON.stringify({ binding: value }))
				.digest("hex")}`;
		const resourceId = resourceIdFor(binding);
		const envelope = await replay.seal(Buffer.from('{"secret":"once"}'), {
			...context,
			resourceId,
		});
		expect(Buffer.from(await replay.open(envelope, { ...context, resourceId })).toString()).toBe('{"secret":"once"}');
		await expect(
			replay.open(envelope, {
				...context,
				resourceId: resourceIdFor(binding.replace("actor_test", "actor_changed")),
			}),
		).rejects.toMatchObject({ code: "KEY_CONTEXT_MISMATCH" });
	});

	it("rejects malformed and oversized envelopes", async () => {
		const local = provider("oidc", "oidc-client-secret", "one", { one: randomBytes(32) });
		await expect(local.open("clrkm$v1$***", context)).rejects.toBeInstanceOf(
			KeyManagementError,
		);
		await expect(
			local.open(`clrkm$v1$${"A".repeat(70_000)}`, context),
		).rejects.toMatchObject({ code: "KEY_ENVELOPE_INVALID" });
	});

	it("requires distinct key material across every configured purpose", () => {
		const reused = randomBytes(32);
		expect(() =>
			createKeyProviderRegistry({
				"oidc-client-secret": provider("oidc", "oidc-client-secret", "one", { one: reused }),
				"scim-bearer-token": provider("scim", "scim-bearer-token", "one", { one: reused }),
				"service-account-credential-replay": provider("replay", "service-account-credential-replay", "one", { one: randomBytes(32) }),
				"access-token-signing-key": provider("jwt", "access-token-signing-key", "one", { one: randomBytes(32) }),
			}),
		).toThrowError(expect.objectContaining({ code: "KEY_PURPOSE_REUSE" }));
	});

	it("rejects a provider installed into a different purpose slot", () => {
		expect(() =>
			createKeyProviderRegistry({
				"oidc-client-secret": provider("wrong", "scim-bearer-token", "one", {
					one: randomBytes(32),
				}),
				"scim-bearer-token": provider("scim", "scim-bearer-token", "one", {
					one: randomBytes(32),
				}),
				"service-account-credential-replay": provider(
					"replay",
					"service-account-credential-replay",
					"one",
					{ one: randomBytes(32) },
				),
				"access-token-signing-key": provider(
					"jwt",
					"access-token-signing-key",
					"one",
					{ one: randomBytes(32) },
				),
			}),
		).toThrowError(expect.objectContaining({ code: "KEY_REGISTRY_INVALID" }));
	});

	it("binds AWS KMS encryption context and proves readiness through an injected client", async () => {
		const calls: unknown[] = [];
		const awsClient = {
			async send(command: unknown) {
				calls.push(command);
				if (command instanceof EncryptCommand) {
					expect(command.input.EncryptionContext).toEqual({
						environmentId: context.environmentId,
						keyId: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
						projectId: context.projectId,
						provider: "aws-kms",
						providerId: "aws-oidc",
						purpose: "oidc-client-secret",
						resourceId: context.resourceId,
						version: "1",
					});
					return {
						CiphertextBlob: Buffer.from("aws-ciphertext"),
						EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
					};
				}
				if (command instanceof DecryptCommand) {
					return {
						Plaintext: Buffer.from("aws-secret"),
						EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
					};
				}
				if (command instanceof DescribeKeyCommand) {
					return {
						KeyMetadata: {
							Enabled: true,
							KeyState: "Enabled",
							KeyUsage: "ENCRYPT_DECRYPT",
							KeySpec: "SYMMETRIC_DEFAULT",
						},
					};
				}
				throw new Error("unexpected command");
			},
		} as unknown as KMSClient;
		expect(() =>
			createAwsKmsKeyProvider({
				providerId: "aws-alias",
				purpose: "oidc-client-secret",
				currentKeyId: "alias/clearance-oidc",
				region: "us-east-1",
				client: awsClient,
			}),
		).toThrowError(expect.objectContaining({ code: "KEY_INPUT_INVALID" }));
		const aws = createAwsKmsKeyProvider({
			providerId: "aws-oidc",
			purpose: "oidc-client-secret",
			currentKeyId: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
			region: "us-east-1",
			client: awsClient,
		});
		const envelope = await aws.seal(Buffer.from("aws-secret"), context);
		expect(Buffer.from(await aws.open(envelope, context)).toString()).toBe("aws-secret");
		expect((await aws.readiness()).ready).toBe(true);
		const beforeMismatch = calls.length;
		await expect(aws.open(envelope, { ...context, resourceId: "wrong" })).rejects.toMatchObject({
			code: "KEY_CONTEXT_MISMATCH",
		});
		expect(calls).toHaveLength(beforeMismatch);
	});

	it("binds GCP additional authenticated data and proves enabled primary readiness", async () => {
		const keyName =
			"projects/project-one/locations/global/keyRings/clearance/cryptoKeys/scim";
		let aad: string | undefined;
		const gcpClient = {
			async encrypt(request: { name: string; additionalAuthenticatedData: Uint8Array }) {
				aad = Buffer.from(request.additionalAuthenticatedData).toString("utf8");
				return [{
					name: `${request.name}/cryptoKeyVersions/1`,
					ciphertext: Buffer.from("gcp-ciphertext"),
				}];
			},
			async decrypt(request: { additionalAuthenticatedData: Uint8Array }) {
				expect(Buffer.from(request.additionalAuthenticatedData).toString("utf8")).toBe(aad);
				return [{ plaintext: Buffer.from("gcp-secret") }];
			},
			async getCryptoKey(request: { name: string }) {
				return [{
					name: request.name,
					purpose: "ENCRYPT_DECRYPT",
					primary: {
						name: `${request.name}/cryptoKeyVersions/1`,
						state: "ENABLED",
					},
				}];
			},
		} as unknown as KeyManagementServiceClient;
		const gcp = createGcpKmsKeyProvider({
			providerId: "gcp-scim",
			purpose: "scim-bearer-token",
			currentKeyId: keyName,
			client: gcpClient,
		});
		const envelope = await gcp.seal(Buffer.from("gcp-secret"), context);
		expect(Buffer.from(await gcp.open(envelope, context)).toString()).toBe("gcp-secret");
		expect((await gcp.readiness()).ready).toBe(true);
		expect(JSON.parse(aad ?? "null")).toEqual({
			version: "1",
			provider: "gcp-kms",
			providerId: "gcp-scim",
			keyId: keyName,
			purpose: "scim-bearer-token",
			projectId: context.projectId,
			environmentId: context.environmentId,
			resourceId: context.resourceId,
		});
	});
});
