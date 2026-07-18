import {
	DecryptCommand,
	DescribeKeyCommand,
	EncryptCommand,
	KMSClient,
} from "@aws-sdk/client-kms";
import { KeyManagementError } from "./error.js";
import {
	assertEnvelopeAuthority,
	createKeyOperationAuthority,
	formatKeyEnvelope,
	keyOperationEncryptionContext,
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
const MAX_REGION_CHARACTERS = 64;
const MAX_ENDPOINT_CHARACTERS = 2_048;
const MAX_RETAINED_KEYS = 64;
const MAX_PLAINTEXT_BYTES = 4_096;
const MAX_CIPHERTEXT_BYTES = 8_192;
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]+$/;
const RAW_AWS_KEY_ID =
	/^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/;
const AWS_KEY_ARN =
	/^arn:(?:aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b):kms:[a-z0-9-]{1,64}:[0-9]{12}:key\/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/;

export type AwsKmsKeyProviderOptions = Readonly<{
	providerId: string;
	purpose: KeyPurpose;
	currentKeyId: string;
	retainedKeyIds?: readonly string[];
	region: string;
	endpoint?: string;
	allowInsecureLoopbackHttp?: boolean;
	client?: KMSClient;
	timeoutMs?: number;
}>;

function invalidOptions(message: string): never {
	throw new KeyManagementError("KEY_INPUT_INVALID", message);
}

function validateRegion(value: unknown): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_REGION_CHARACTERS ||
		value.trim() !== value ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		return invalidOptions("AWS KMS region is invalid");
	}
	return value;
}

function validateAwsKeyId(value: unknown): string {
	if (
		typeof value !== "string" ||
		(!RAW_AWS_KEY_ID.test(value) && !AWS_KEY_ARN.test(value))
	) {
		return invalidOptions("AWS KMS key id must be an immutable key ARN or raw key id");
	}
	return value;
}

function validateEndpoint(
	value: unknown,
	allowInsecureLoopbackHttp: boolean,
): string | undefined {
	if (value === undefined) return undefined;
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_ENDPOINT_CHARACTERS ||
		value.trim() !== value ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		return invalidOptions("AWS KMS endpoint is invalid");
	}
	let endpoint: URL;
	try {
		endpoint = new URL(value);
	} catch {
		return invalidOptions("AWS KMS endpoint is invalid");
	}
	if (
		(endpoint.protocol !== "https:" && endpoint.protocol !== "http:") ||
		endpoint.username !== "" ||
		endpoint.password !== ""
	) {
		return invalidOptions("AWS KMS endpoint is invalid");
	}
	if (endpoint.protocol === "http:") {
		const loopback =
			endpoint.hostname === "localhost" ||
			endpoint.hostname === "127.0.0.1" ||
			endpoint.hostname === "[::1]";
		if (
			!allowInsecureLoopbackHttp ||
			!loopback ||
			process.env.NODE_ENV === "production"
		) {
			return invalidOptions("AWS KMS endpoint must use HTTPS");
		}
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
		return invalidOptions("AWS KMS timeout is invalid");
	}
	return value;
}

function validateKeyIds(
	current: string,
	retained: readonly string[] | undefined,
): readonly string[] {
	if (retained !== undefined && !Array.isArray(retained)) {
		return invalidOptions("AWS KMS retained key ids are invalid");
	}
	if ((retained?.length ?? 0) > MAX_RETAINED_KEYS) {
		return invalidOptions("AWS KMS retained key ids are invalid");
	}
	const seen = new Set<string>([current]);
	const validated: string[] = [];
	for (const raw of retained ?? []) {
		const keyId = validateAwsKeyId(raw);
		if (seen.has(keyId)) {
			return invalidOptions("AWS KMS key ids must be unique");
		}
		seen.add(keyId);
		validated.push(keyId);
	}
	return Object.freeze(validated.sort());
}

function configuredClient(value: unknown): value is KMSClient {
	return Boolean(value && typeof value === "object" && typeof (value as KMSClient).send === "function");
}

function operationFailure(message: string): KeyManagementError {
	return new KeyManagementError("KEY_OPERATION_FAILED", message);
}

function decodeCiphertext(value: string): Uint8Array {
	if (!CANONICAL_BASE64URL.test(value)) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "AWS KMS ciphertext is invalid");
	}
	const ciphertext = Buffer.from(value, "base64url");
	if (
		ciphertext.length === 0 ||
		ciphertext.length > MAX_CIPHERTEXT_BYTES ||
		ciphertext.toString("base64url") !== value
	) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "AWS KMS ciphertext is invalid");
	}
	return ciphertext;
}

export function createAwsKmsKeyProvider(
	options: AwsKmsKeyProviderOptions,
): KeyEncryptionProvider {
	if (!options || typeof options !== "object" || Array.isArray(options)) {
		return invalidOptions("AWS KMS provider options are invalid");
	}

	let providerId: string;
	let currentKeyId: string;
	try {
		providerId = validateProviderIdentifier(options.providerId, "providerId");
	} catch {
		return invalidOptions("AWS KMS provider identity is invalid");
	}
	currentKeyId = validateAwsKeyId(options.currentKeyId);
	const purpose = validateKeyPurpose(options.purpose);
	const retainedKeyIds = validateKeyIds(currentKeyId, options.retainedKeyIds);
	const region = validateRegion(options.region);
	if (
		options.allowInsecureLoopbackHttp !== undefined &&
		typeof options.allowInsecureLoopbackHttp !== "boolean"
	) {
		return invalidOptions("AWS KMS development HTTP option is invalid");
	}
	const endpoint = validateEndpoint(
		options.endpoint,
		options.allowInsecureLoopbackHttp === true,
	);
	const timeoutMs = validateTimeout(options.timeoutMs);
	if (options.client !== undefined && !configuredClient(options.client)) {
		return invalidOptions("AWS KMS client is invalid");
	}
	const client = options.client ?? new KMSClient({
		region,
		...(endpoint === undefined ? {} : { endpoint }),
	});
	const configuredKeyIds = Object.freeze([currentKeyId, ...retainedKeyIds]);
	const configuredKeyIdSet = new Set(configuredKeyIds);

	const provider: KeyEncryptionProvider = {
		kind: "aws-kms",
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
				throw new KeyManagementError("KEY_INPUT_INVALID", "AWS KMS plaintext size is invalid");
			}
			const authority = createKeyOperationAuthority(
				"aws-kms",
				providerId,
				currentKeyId,
				purpose,
				exact,
			);
			try {
				const result = await client.send(
					new EncryptCommand({
						KeyId: currentKeyId,
						Plaintext: plaintext,
						EncryptionContext: keyOperationEncryptionContext(authority),
						EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
					}),
					{ abortSignal: AbortSignal.timeout(timeoutMs) },
				);
				const ciphertext = result.CiphertextBlob;
				if (
					!(ciphertext instanceof Uint8Array) ||
					ciphertext.length === 0 ||
					ciphertext.length > MAX_CIPHERTEXT_BYTES ||
					(result.EncryptionAlgorithm !== undefined &&
						result.EncryptionAlgorithm !== "SYMMETRIC_DEFAULT")
				) {
					throw operationFailure("AWS KMS encryption failed");
				}
				return formatKeyEnvelope({
					v: 1,
					provider: "aws-kms",
					providerId,
					keyId: currentKeyId,
					purpose,
					...exact,
					ciphertext: Buffer.from(ciphertext).toString("base64url"),
				});
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw operationFailure("AWS KMS encryption failed");
			}
		},
		async open(envelope, context) {
			const payload = parseKeyEnvelope(envelope);
			assertEnvelopeAuthority(payload, "aws-kms", providerId, purpose, context);
			if (!configuredKeyIdSet.has(payload.keyId)) {
				throw new KeyManagementError("KEY_NOT_AVAILABLE", "AWS KMS envelope key is not retained");
			}
			const ciphertext = decodeCiphertext(payload.ciphertext);
			const authority = createKeyOperationAuthority(
				"aws-kms",
				providerId,
				payload.keyId,
				purpose,
				context,
			);
			try {
				const result = await client.send(
					new DecryptCommand({
						KeyId: payload.keyId,
						CiphertextBlob: ciphertext,
						EncryptionContext: keyOperationEncryptionContext(authority),
						EncryptionAlgorithm: "SYMMETRIC_DEFAULT",
					}),
					{ abortSignal: AbortSignal.timeout(timeoutMs) },
				);
				const plaintext = result.Plaintext;
				if (
					!(plaintext instanceof Uint8Array) ||
					plaintext.length === 0 ||
					plaintext.length > MAX_PLAINTEXT_BYTES ||
					(result.EncryptionAlgorithm !== undefined &&
						result.EncryptionAlgorithm !== "SYMMETRIC_DEFAULT")
				) {
					throw operationFailure("AWS KMS decryption failed");
				}
				return new Uint8Array(plaintext);
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw operationFailure("AWS KMS decryption failed");
			}
		},
		async readiness(): Promise<KeyProviderReadiness> {
			const statuses = await Promise.all(configuredKeyIds.map(async (keyId) => {
				const role = keyId === currentKeyId ? "current" as const : "retained" as const;
				try {
					const result = await client.send(
						new DescribeKeyCommand({ KeyId: keyId }),
						{ abortSignal: AbortSignal.timeout(timeoutMs) },
					);
					const metadata = result.KeyMetadata;
					const ready =
						metadata?.Enabled === true &&
						metadata.KeyState === "Enabled" &&
						metadata.KeyUsage === "ENCRYPT_DECRYPT" &&
						metadata.KeySpec === "SYMMETRIC_DEFAULT";
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
				kind: "aws-kms",
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
		cloudKeyReferences: configuredKeyIds.map((keyId) => `aws-kms:${keyId}`),
	});
	return frozen;
}
