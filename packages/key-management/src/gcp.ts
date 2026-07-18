import { KeyManagementServiceClient } from "@google-cloud/kms";
import { KeyManagementError } from "./error.js";
import {
	assertEnvelopeAuthority,
	createKeyOperationAuthority,
	formatKeyEnvelope,
	keyOperationAad,
	parseKeyEnvelope,
	validateKeyContext,
	validateKeyPurpose,
	validateProviderIdentifier,
} from "./envelope.js";
import {
	redactedKeyReference,
	registerProviderSeparationMetadata,
} from "./internal.js";
import type {
	KeyEncryptionProvider,
	KeyProviderReadiness,
	KeyProviderReadinessReason,
	KeyPurpose,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 30_000;
const MAX_RETAINED_KEYS = 64;
const MAX_PLAINTEXT_BYTES = 16_384;
const MAX_CIPHERTEXT_BYTES = 32_768;
const MAX_KEY_NAME_CHARACTERS = 1_024;
const CRYPTO_KEY_NAME =
	/^projects\/[A-Za-z0-9._~-]{1,128}\/locations\/[A-Za-z0-9._~-]{1,128}\/keyRings\/[A-Za-z0-9._~-]{1,128}\/cryptoKeys\/[A-Za-z0-9._~-]{1,128}$/;
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]+$/;

type GcpClientOptions = ConstructorParameters<typeof KeyManagementServiceClient>[0];

export type GcpKmsKeyProviderOptions = Readonly<{
	providerId: string;
	purpose: KeyPurpose;
	currentKeyId: string;
	retainedKeyIds?: readonly string[];
	client?: KeyManagementServiceClient;
	clientOptions?: GcpClientOptions;
	timeoutMs?: number;
}>;

function invalidOptions(message: string): never {
	throw new KeyManagementError("KEY_INPUT_INVALID", message);
}

function validateTimeout(value: unknown): number {
	if (value === undefined) return DEFAULT_TIMEOUT_MS;
	if (
		typeof value !== "number" ||
		!Number.isInteger(value) ||
		value < MIN_TIMEOUT_MS ||
		value > MAX_TIMEOUT_MS
	) {
		return invalidOptions("GCP KMS timeout is invalid");
	}
	return value;
}

function validateCryptoKeyName(value: unknown): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_KEY_NAME_CHARACTERS ||
		value.trim() !== value ||
		!CRYPTO_KEY_NAME.test(value)
	) {
		return invalidOptions("GCP KMS CryptoKey name is invalid");
	}
	return value;
}

function validateKeyIds(
	current: string,
	retained: readonly string[] | undefined,
): readonly string[] {
	if (retained !== undefined && !Array.isArray(retained)) {
		return invalidOptions("GCP KMS retained key names are invalid");
	}
	if ((retained?.length ?? 0) > MAX_RETAINED_KEYS) {
		return invalidOptions("GCP KMS retained key names are invalid");
	}
	const seen = new Set<string>([current]);
	const validated: string[] = [];
	for (const raw of retained ?? []) {
		const keyId = validateCryptoKeyName(raw);
		if (seen.has(keyId)) {
			return invalidOptions("GCP KMS key names must be unique");
		}
		seen.add(keyId);
		validated.push(keyId);
	}
	return Object.freeze(validated.sort());
}

function configuredClient(value: unknown): value is KeyManagementServiceClient {
	if (!value || typeof value !== "object") return false;
	const candidate = value as KeyManagementServiceClient;
	return (
		typeof candidate.encrypt === "function" &&
		typeof candidate.decrypt === "function" &&
		typeof candidate.getCryptoKey === "function"
	);
}

function operationFailure(message: string): KeyManagementError {
	return new KeyManagementError("KEY_OPERATION_FAILED", message);
}

function decodeCiphertext(value: string): Uint8Array {
	if (!CANONICAL_BASE64URL.test(value)) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "GCP KMS ciphertext is invalid");
	}
	const ciphertext = Buffer.from(value, "base64url");
	if (
		ciphertext.length === 0 ||
		ciphertext.length > MAX_CIPHERTEXT_BYTES ||
		ciphertext.toString("base64url") !== value
	) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "GCP KMS ciphertext is invalid");
	}
	return ciphertext;
}

export function createGcpKmsKeyProvider(
	options: GcpKmsKeyProviderOptions,
): KeyEncryptionProvider {
	if (!options || typeof options !== "object" || Array.isArray(options)) {
		return invalidOptions("GCP KMS provider options are invalid");
	}
	let providerId: string;
	try {
		providerId = validateProviderIdentifier(options.providerId, "providerId");
	} catch {
		return invalidOptions("GCP KMS provider identity is invalid");
	}
	const purpose = validateKeyPurpose(options.purpose);
	const currentKeyId = validateCryptoKeyName(options.currentKeyId);
	const retainedKeyIds = validateKeyIds(currentKeyId, options.retainedKeyIds);
	const timeoutMs = validateTimeout(options.timeoutMs);
	if (options.client !== undefined && !configuredClient(options.client)) {
		return invalidOptions("GCP KMS client is invalid");
	}
	if (
		options.client !== undefined &&
		options.clientOptions !== undefined
	) {
		return invalidOptions("GCP KMS clientOptions cannot accompany an injected client");
	}
	const client = options.client ?? new KeyManagementServiceClient(options.clientOptions);
	const configuredKeyIds = Object.freeze([currentKeyId, ...retainedKeyIds]);
	const configuredKeyIdSet = new Set(configuredKeyIds);

	const provider: KeyEncryptionProvider = {
		kind: "gcp-kms",
		providerId,
		purpose,
		currentKeyId,
		retainedKeyIds,
		async seal(plaintext, context) {
			const exact = validateKeyContext(context);
			if (
				!(plaintext instanceof Uint8Array) ||
				plaintext.length === 0 ||
				plaintext.length > MAX_PLAINTEXT_BYTES
			) {
				throw new KeyManagementError("KEY_INPUT_INVALID", "GCP KMS plaintext size is invalid");
			}
			const authority = createKeyOperationAuthority(
				"gcp-kms",
				providerId,
				currentKeyId,
				purpose,
				exact,
			);
			try {
				const [result] = await client.encrypt(
					{
						name: currentKeyId,
						plaintext,
						additionalAuthenticatedData: keyOperationAad(authority),
					},
					{ timeout: timeoutMs },
				);
				const ciphertext = result.ciphertext;
				if (
					!(ciphertext instanceof Uint8Array) ||
					ciphertext.length === 0 ||
					ciphertext.length > MAX_CIPHERTEXT_BYTES ||
					typeof result.name !== "string" ||
					!result.name.startsWith(`${currentKeyId}/cryptoKeyVersions/`)
				) {
					throw operationFailure("GCP KMS encryption failed");
				}
				return formatKeyEnvelope({
					v: 1,
					provider: "gcp-kms",
					providerId,
					keyId: currentKeyId,
					purpose,
					...exact,
					ciphertext: Buffer.from(ciphertext).toString("base64url"),
				});
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw operationFailure("GCP KMS encryption failed");
			}
		},
		async open(envelope, context) {
			const payload = parseKeyEnvelope(envelope);
			assertEnvelopeAuthority(payload, "gcp-kms", providerId, purpose, context);
			if (!configuredKeyIdSet.has(payload.keyId)) {
				throw new KeyManagementError("KEY_NOT_AVAILABLE", "GCP KMS envelope key is not retained");
			}
			const ciphertext = decodeCiphertext(payload.ciphertext);
			const authority = createKeyOperationAuthority(
				"gcp-kms",
				providerId,
				payload.keyId,
				purpose,
				context,
			);
			try {
				const [result] = await client.decrypt(
					{
						name: payload.keyId,
						ciphertext,
						additionalAuthenticatedData: keyOperationAad(authority),
					},
					{ timeout: timeoutMs },
				);
				const plaintext = result.plaintext;
				if (
					!(plaintext instanceof Uint8Array) ||
					plaintext.length === 0 ||
					plaintext.length > MAX_PLAINTEXT_BYTES
				) {
					throw operationFailure("GCP KMS decryption failed");
				}
				return new Uint8Array(plaintext);
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw operationFailure("GCP KMS decryption failed");
			}
		},
		async readiness(): Promise<KeyProviderReadiness> {
			const statuses = await Promise.all(configuredKeyIds.map(async (keyId) => {
				const role = keyId === currentKeyId ? "current" as const : "retained" as const;
				try {
					const [key] = await client.getCryptoKey(
						{ name: keyId },
						{ timeout: timeoutMs },
					);
					const purposeReady =
						key.purpose === 1 || key.purpose === "ENCRYPT_DECRYPT";
					const primaryReady =
						(key.primary?.state === 1 || key.primary?.state === "ENABLED") &&
						typeof key.primary?.name === "string" &&
						key.primary.name.startsWith(`${keyId}/cryptoKeyVersions/`);
					const ready = key.name === keyId && purposeReady && primaryReady;
					return Object.freeze({
						role,
						keyRef: redactedKeyReference(keyId),
						status: ready ? "ready" as const : "invalid" as const,
					});
				} catch {
					return Object.freeze({
						role,
						keyRef: redactedKeyReference(keyId),
						status: "unavailable" as const,
					});
				}
			}));
			const reasons = new Set<KeyProviderReadinessReason>();
			for (const status of statuses) {
				if (status.status === "invalid") reasons.add("KEY_CONFIGURATION_INVALID");
				if (status.status === "unavailable") {
					reasons.add(
						status.role === "current"
							? "CURRENT_KEY_UNAVAILABLE"
							: "RETAINED_KEY_UNAVAILABLE",
					);
				}
			}
			if (statuses.every((status) => status.status === "unavailable")) {
				reasons.add("PROVIDER_UNAVAILABLE");
			}
			return Object.freeze({
				ready: statuses.every((status) => status.status === "ready"),
				kind: "gcp-kms",
				providerRef: redactedKeyReference(providerId),
				currentKeyRef: redactedKeyReference(currentKeyId),
				keys: Object.freeze(statuses),
				reasons: Object.freeze([...reasons].sort()),
			});
		},
	};
	const frozen = Object.freeze(provider);
	registerProviderSeparationMetadata(frozen, {
		localKeys: [],
		cloudKeyReferences: configuredKeyIds.map((keyId) => `gcp-kms:${keyId}`),
	});
	return frozen;
}
