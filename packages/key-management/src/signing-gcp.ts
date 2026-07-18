import { createHash, createPublicKey } from "node:crypto";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import { KeyManagementError } from "./error.js";
import { redactedKeyReference } from "./internal.js";
import {
	ACCESS_TOKEN_SIGNING_ALGORITHM,
	type KeySigningProvider,
	type RetainedSigningKey,
	type SigningPublicKey,
} from "./signing-types.js";
import {
	crc32c,
	crc32cMatches,
	derEs256ToJose,
	es256PublicJwk,
	signingKeyId,
	validateSigningInput,
} from "./signing-utils.js";
import type {
	KeyProviderReadiness,
	KeyProviderReadinessReason,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 30_000;
const MAX_RETAINED_KEYS = 64;
const MAX_KEY_NAME_CHARACTERS = 1_024;
const CRYPTO_KEY_VERSION_NAME =
	/^projects\/[A-Za-z0-9._~-]{1,128}\/locations\/[A-Za-z0-9._~-]{1,128}\/keyRings\/[A-Za-z0-9._~-]{1,128}\/cryptoKeys\/[A-Za-z0-9._~-]{1,128}\/cryptoKeyVersions\/[1-9][0-9]*$/;

type GcpClientOptions = ConstructorParameters<typeof KeyManagementServiceClient>[0];

export type GcpKmsSigningProviderOptions = Readonly<{
	providerId: string;
	currentKeyReference: string;
	retainedKeys?: readonly RetainedSigningKey[];
	client?: KeyManagementServiceClient;
	clientOptions?: GcpClientOptions;
	timeoutMs?: number;
}>;

type ConfiguredKey = Readonly<{
	keyReference: string;
	retiredAt?: Date;
}>;

function invalidOptions(message: string): never {
	throw new KeyManagementError("KEY_INPUT_INVALID", message);
}

function operationFailure(message: string): KeyManagementError {
	return new KeyManagementError("KEY_OPERATION_FAILED", message);
}

function validateKeyReference(value: unknown): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_KEY_NAME_CHARACTERS ||
		value.trim() !== value ||
		!CRYPTO_KEY_VERSION_NAME.test(value)
	) {
		return invalidOptions("GCP KMS signing key must be an immutable CryptoKeyVersion name");
	}
	return value;
}

function validateProviderId(value: unknown): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 128 ||
		value.trim() !== value ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		return invalidOptions("GCP KMS signing provider identity is invalid");
	}
	return value;
}

function validateTimeout(value: unknown): number {
	if (value === undefined) return DEFAULT_TIMEOUT_MS;
	if (
		typeof value !== "number" ||
		!Number.isInteger(value) ||
		value < MIN_TIMEOUT_MS ||
		value > MAX_TIMEOUT_MS
	) {
		return invalidOptions("GCP KMS signing timeout is invalid");
	}
	return value;
}

function validateRetainedKeys(
	currentKeyReference: string,
	value: readonly RetainedSigningKey[] | undefined,
): readonly ConfiguredKey[] {
	if (value !== undefined && !Array.isArray(value)) {
		return invalidOptions("GCP KMS retained signing keys are invalid");
	}
	if ((value?.length ?? 0) > MAX_RETAINED_KEYS) {
		return invalidOptions("GCP KMS retained signing keys are invalid");
	}
	const seen = new Set<string>([currentKeyReference]);
	const retained: ConfiguredKey[] = [];
	for (const candidate of value ?? []) {
		if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
			return invalidOptions("GCP KMS retained signing keys are invalid");
		}
		const keyReference = validateKeyReference(candidate.keyReference);
		if (!(candidate.retiredAt instanceof Date) || Number.isNaN(candidate.retiredAt.valueOf())) {
			return invalidOptions("GCP KMS retained signing key retirement is invalid");
		}
		if (candidate.retiredAt.getTime() > Date.now()) {
			return invalidOptions("GCP KMS retained signing key retirement cannot be in the future");
		}
		if (seen.has(keyReference)) {
			return invalidOptions("GCP KMS signing key references must be unique");
		}
		seen.add(keyReference);
		retained.push(Object.freeze({
			keyReference,
			retiredAt: new Date(candidate.retiredAt),
		}));
	}
	return Object.freeze(retained.sort((a, b) =>
		a.keyReference.localeCompare(b.keyReference),
	));
}

function configuredClient(value: unknown): value is KeyManagementServiceClient {
	if (!value || typeof value !== "object") return false;
	const candidate = value as KeyManagementServiceClient;
	return (
		typeof candidate.asymmetricSign === "function" &&
		typeof candidate.getPublicKey === "function"
	);
}

function isEs256Algorithm(value: unknown): boolean {
	return value === 12 || value === "EC_SIGN_P256_SHA256";
}

function publicJwkFromPem(pem: string, kid: string) {
	try {
		const key = createPublicKey({ key: pem, format: "pem", type: "spki" });
		return es256PublicJwk(key.export({ format: "jwk" }), kid);
	} catch {
		throw operationFailure("GCP KMS signing public key is invalid");
	}
}

function configuredKeyId(providerId: string, keyReference: string): string {
	return signingKeyId(providerId, keyReference);
}

/**
 * ES256 signing backed by immutable GCP KMS CryptoKeyVersions. Raw resource
 * names remain private to the provider; external key identifiers are hashes.
 */
export function createGcpKmsSigningProvider(
	options: GcpKmsSigningProviderOptions,
): KeySigningProvider {
	if (!options || typeof options !== "object" || Array.isArray(options)) {
		return invalidOptions("GCP KMS signing provider options are invalid");
	}
	const providerId = validateProviderId(options.providerId);
	const currentKeyReference = validateKeyReference(options.currentKeyReference);
	const retainedKeys = validateRetainedKeys(
		currentKeyReference,
		options.retainedKeys,
	);
	const timeoutMs = validateTimeout(options.timeoutMs);
	if (options.client !== undefined && !configuredClient(options.client)) {
		return invalidOptions("GCP KMS signing client is invalid");
	}
	if (options.client !== undefined && options.clientOptions !== undefined) {
		return invalidOptions("GCP KMS signing clientOptions cannot accompany an injected client");
	}
	const client = options.client ?? new KeyManagementServiceClient(options.clientOptions);
	const configuredKeys = Object.freeze([
		Object.freeze({ keyReference: currentKeyReference }),
		...retainedKeys,
	]);

	async function loadPublicKey(configuredKey: ConfiguredKey): Promise<SigningPublicKey> {
		const keyReference = configuredKey.keyReference;
		const [result] = await client.getPublicKey(
			{ name: keyReference },
			{ timeout: timeoutMs },
		);
		const pemBytes = Buffer.from(result.pem ?? "", "utf8");
		if (
			result.name !== keyReference ||
			!isEs256Algorithm(result.algorithm) ||
			typeof result.pem !== "string" ||
			result.pem.length === 0 ||
			!crc32cMatches(result.pemCrc32c, pemBytes)
		) {
			throw operationFailure("GCP KMS signing public key is invalid");
		}
		const id = configuredKeyId(providerId, keyReference);
		return Object.freeze({
			id,
			publicJwk: publicJwkFromPem(result.pem, id),
			// GetPublicKey does not return a creation timestamp. A stable epoch
			// sentinel avoids inventing cloud metadata while preserving the contract.
			createdAt: new Date(0),
			...(configuredKey.retiredAt === undefined
				? {}
				: { expiresAt: new Date(configuredKey.retiredAt) }),
		});
	}

	const provider: KeySigningProvider = {
		kind: "gcp-kms",
		providerId,
		purpose: "access-token-signing-key",
		algorithm: ACCESS_TOKEN_SIGNING_ALGORITHM,
		currentKeyId: configuredKeyId(providerId, currentKeyReference),
		retainedKeyIds: Object.freeze(retainedKeys.map((key) =>
			configuredKeyId(providerId, key.keyReference),
		)),
		async sign(signingInput) {
			const exactInput = validateSigningInput(signingInput);
			const digest = createHash("sha256").update(exactInput).digest();
			try {
				const [result] = await client.asymmetricSign(
					{
						name: currentKeyReference,
						digest: { sha256: digest },
						digestCrc32c: { value: crc32c(digest) },
					},
					{ timeout: timeoutMs },
				);
				const signature = result.signature;
				if (
					!(signature instanceof Uint8Array) ||
					signature.length === 0 ||
					(result.name !== undefined && result.name !== currentKeyReference) ||
					result.verifiedDigestCrc32c !== true ||
					!crc32cMatches(result.signatureCrc32c, signature)
				) {
					throw operationFailure("GCP KMS signing failed");
				}
				return derEs256ToJose(signature);
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw operationFailure("GCP KMS signing failed");
			}
		},
		async publicKeys(): Promise<readonly SigningPublicKey[]> {
			try {
				return Object.freeze(await Promise.all(configuredKeys.map(loadPublicKey)));
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw operationFailure("GCP KMS signing public key retrieval failed");
			}
		},
		async readiness(): Promise<KeyProviderReadiness> {
			const statuses = await Promise.all(configuredKeys.map(async (configuredKey) => {
				const role = configuredKey.keyReference === currentKeyReference
					? "current" as const
					: "retained" as const;
				try {
					await loadPublicKey(configuredKey);
					return Object.freeze({
						role,
						keyRef: redactedKeyReference(configuredKey.keyReference),
						status: "ready" as const,
					});
				} catch (error) {
					return Object.freeze({
						role,
						keyRef: redactedKeyReference(configuredKey.keyReference),
						status: error instanceof KeyManagementError
							? "invalid" as const
							: "unavailable" as const,
					});
				}
			}));
			const reasons = new Set<KeyProviderReadinessReason>();
			for (const status of statuses) {
				if (status.status === "invalid") reasons.add("KEY_CONFIGURATION_INVALID");
				if (status.status === "unavailable") {
					reasons.add(status.role === "current"
						? "CURRENT_KEY_UNAVAILABLE"
						: "RETAINED_KEY_UNAVAILABLE");
				}
			}
			if (statuses.every((status) => status.status === "unavailable")) {
				reasons.add("PROVIDER_UNAVAILABLE");
			}
			return Object.freeze({
				ready: statuses.every((status) => status.status === "ready"),
				kind: "gcp-kms",
				providerRef: redactedKeyReference(providerId),
				currentKeyRef: redactedKeyReference(currentKeyReference),
				keys: Object.freeze(statuses),
				reasons: Object.freeze([...reasons].sort()),
			});
		},
	};
	return Object.freeze(provider);
}
