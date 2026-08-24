import { createHash, createPublicKey } from "node:crypto";
import {
	DescribeKeyCommand,
	GetPublicKeyCommand,
	KMSClient,
	SignCommand,
} from "@aws-sdk/client-kms";
import { KeyManagementError } from "./error.js";
import { redactedKeyReference } from "./internal.js";
import {
	ACCESS_TOKEN_SIGNING_ALGORITHM,
	type KeySigningProvider,
	type RetainedSigningKey,
	type SigningPublicKey,
} from "./signing-types.js";
import {
	derEs256ToJose,
	es256PublicJwk,
	signingKeyId,
	validateSigningInput,
} from "./signing-utils.js";
import type {
	KeyProviderKeyStatus,
	KeyProviderReadiness,
	KeyProviderReadinessReason,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 30_000;
const MAX_REGION_CHARACTERS = 64;
const MAX_ENDPOINT_CHARACTERS = 2_048;
const MAX_RETAINED_KEYS = 64;
const RAW_AWS_KEY_ID =
	/^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/;
const AWS_KEY_ARN =
	/^arn:(?:aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b):kms:[a-z0-9-]{1,64}:[0-9]{12}:key\/(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/;

export type AwsKmsSigningProviderOptions = Readonly<{
	providerId: string;
	currentKeyReference: string;
	retainedKeys?: readonly RetainedSigningKey[];
	region: string;
	endpoint?: string;
	allowInsecureLoopbackHttp?: boolean;
	strictSecrets?: boolean;
	client?: KMSClient;
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

function validateProviderId(value: unknown): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 128 ||
		value.trim() !== value ||
		!/^[a-zA-Z0-9][a-zA-Z0-9._:-]*$/.test(value)
	) {
		return invalidOptions("AWS KMS signing provider identity is invalid");
	}
	return value;
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

function validateKeyReference(value: unknown): string {
	if (
		typeof value !== "string" ||
		(!RAW_AWS_KEY_ID.test(value) && !AWS_KEY_ARN.test(value))
	) {
		return invalidOptions("AWS KMS signing key must be an immutable key ARN or raw key id");
	}
	return value;
}

function keyIdentity(value: string): string {
	const marker = ":key/";
	const markerIndex = value.lastIndexOf(marker);
	return markerIndex === -1 ? value : value.slice(markerIndex + marker.length);
}

function matchingKeyIdentity(configured: string, response: unknown): boolean {
	return typeof response === "string" && keyIdentity(configured) === keyIdentity(response);
}

function validateEndpoint(
	value: unknown,
	allowInsecureLoopbackHttp: boolean,
	strictSecrets: boolean,
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
		const isLoopback =
			endpoint.hostname === "localhost" ||
			endpoint.hostname === "127.0.0.1" ||
			endpoint.hostname === "[::1]";
		if (
			!allowInsecureLoopbackHttp ||
			!isLoopback ||
			strictSecrets
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

function configuredClient(value: unknown): value is KMSClient {
	return Boolean(value && typeof value === "object" && typeof (value as KMSClient).send === "function");
}

function validateRetainedKeys(
	currentKeyReference: string,
	value: unknown,
): readonly ConfiguredKey[] {
	if (value === undefined) return Object.freeze([]);
	if (!Array.isArray(value) || value.length > MAX_RETAINED_KEYS) {
		return invalidOptions("AWS KMS retained signing keys are invalid");
	}
	const seen = new Set<string>([keyIdentity(currentKeyReference)]);
	const retained: ConfiguredKey[] = [];
	for (const entry of value) {
		if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
			return invalidOptions("AWS KMS retained signing keys are invalid");
		}
		const record = entry as Record<string, unknown>;
		const keyReference = validateKeyReference(record.keyReference);
		const retiredAt = record.retiredAt;
		if (!(retiredAt instanceof Date) || Number.isNaN(retiredAt.getTime())) {
			return invalidOptions("AWS KMS retained signing key retirement is invalid");
		}
		if (retiredAt.getTime() > Date.now()) {
			return invalidOptions("AWS KMS retained signing key retirement cannot be in the future");
		}
		const identity = keyIdentity(keyReference);
		if (seen.has(identity)) {
			return invalidOptions("AWS KMS signing key references must be unique");
		}
		seen.add(identity);
		retained.push(Object.freeze({
			keyReference,
			retiredAt: new Date(retiredAt.getTime()),
		}));
	}
	return Object.freeze(retained.sort((left, right) =>
		left.keyReference.localeCompare(right.keyReference),
	));
}

function asCreationDate(value: unknown): Date {
	if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
		throw operationFailure("AWS KMS signing key metadata is invalid");
	}
	return new Date(value.getTime());
}

export function createAwsKmsSigningProvider(
	options: AwsKmsSigningProviderOptions,
): KeySigningProvider {
	if (!options || typeof options !== "object" || Array.isArray(options)) {
		return invalidOptions("AWS KMS signing provider options are invalid");
	}
	const providerId = validateProviderId(options.providerId);
	const currentKeyReference = validateKeyReference(options.currentKeyReference);
	const retainedKeys = validateRetainedKeys(currentKeyReference, options.retainedKeys);
	const region = validateRegion(options.region);
	if (
		options.allowInsecureLoopbackHttp !== undefined &&
		typeof options.allowInsecureLoopbackHttp !== "boolean"
	) {
		return invalidOptions("AWS KMS development HTTP option is invalid");
	}
	if (options.strictSecrets !== undefined && typeof options.strictSecrets !== "boolean") {
		return invalidOptions("AWS KMS signing strict secrets option is invalid");
	}
	const endpoint = validateEndpoint(
		options.endpoint,
		options.allowInsecureLoopbackHttp === true,
		options.strictSecrets === true,
	);
	const timeoutMs = validateTimeout(options.timeoutMs);
	if (options.client !== undefined && !configuredClient(options.client)) {
		return invalidOptions("AWS KMS client is invalid");
	}
	const client = options.client ?? new KMSClient({
		region,
		...(endpoint === undefined ? {} : { endpoint }),
	});
	const configuredKeys = Object.freeze<readonly ConfiguredKey[]>([
		Object.freeze({ keyReference: currentKeyReference }),
		...retainedKeys,
	]);

	async function getPublicKey(keyReference: string, preserveAvailabilityFailure = false) {
		try {
			const result = await client.send(
				new GetPublicKeyCommand({ KeyId: keyReference }),
				{ abortSignal: AbortSignal.timeout(timeoutMs) },
			);
			if (
				!matchingKeyIdentity(keyReference, result.KeyId) ||
				result.KeyUsage !== "SIGN_VERIFY" ||
				result.KeySpec !== "ECC_NIST_P256" ||
				!result.SigningAlgorithms?.includes("ECDSA_SHA_256") ||
				!(result.PublicKey instanceof Uint8Array) ||
				result.PublicKey.length === 0
			) {
				throw operationFailure("AWS KMS signing public key is invalid");
			}
			let jwk: unknown;
			try {
				jwk = createPublicKey({
					key: Buffer.from(result.PublicKey),
					format: "der",
					type: "spki",
				}).export({ format: "jwk" });
			} catch {
				throw operationFailure("AWS KMS signing public key is invalid");
			}
			return es256PublicJwk(jwk, signingKeyId(providerId, keyReference));
		} catch (error) {
			if (error instanceof KeyManagementError || preserveAvailabilityFailure) throw error;
			throw operationFailure("AWS KMS signing public key is unavailable");
		}
	}

	async function describeSigningKey(
		keyReference: string,
		preserveAvailabilityFailure = false,
	): Promise<Date> {
		try {
			const result = await client.send(
				new DescribeKeyCommand({ KeyId: keyReference }),
				{ abortSignal: AbortSignal.timeout(timeoutMs) },
			);
			const metadata = result.KeyMetadata;
			if (
				metadata?.Enabled !== true ||
				!matchingKeyIdentity(keyReference, metadata.KeyId) ||
				metadata.KeyState !== "Enabled" ||
				metadata.KeyUsage !== "SIGN_VERIFY" ||
				metadata.KeySpec !== "ECC_NIST_P256"
			) {
				throw operationFailure("AWS KMS signing key metadata is invalid");
			}
			return asCreationDate(metadata.CreationDate);
		} catch (error) {
			if (error instanceof KeyManagementError || preserveAvailabilityFailure) throw error;
			throw operationFailure("AWS KMS signing key is unavailable");
		}
	}

	const provider: KeySigningProvider = {
		kind: "aws-kms",
		providerId,
		purpose: "access-token-signing-key",
		algorithm: ACCESS_TOKEN_SIGNING_ALGORITHM,
		currentKeyId: signingKeyId(providerId, currentKeyReference),
		retainedKeyIds: Object.freeze(retainedKeys.map(({ keyReference }) =>
			signingKeyId(providerId, keyReference),
		)),
		async sign(input) {
			const signingInput = validateSigningInput(input);
			const digest = createHash("sha256").update(signingInput).digest();
			try {
				const result = await client.send(
					new SignCommand({
						KeyId: currentKeyReference,
						Message: digest,
						MessageType: "DIGEST",
						SigningAlgorithm: "ECDSA_SHA_256",
					}),
					{ abortSignal: AbortSignal.timeout(timeoutMs) },
				);
				if (
					result.SigningAlgorithm !== "ECDSA_SHA_256" ||
					!matchingKeyIdentity(currentKeyReference, result.KeyId) ||
					!(result.Signature instanceof Uint8Array)
				) {
					throw operationFailure("AWS KMS signing failed");
				}
				return derEs256ToJose(result.Signature);
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw operationFailure("AWS KMS signing failed");
			}
		},
		async publicKeys(): Promise<readonly SigningPublicKey[]> {
			const keys = await Promise.all(configuredKeys.map(async (configured) => {
				const [publicJwk, createdAt] = await Promise.all([
					getPublicKey(configured.keyReference),
					describeSigningKey(configured.keyReference),
				]);
				return Object.freeze({
					id: signingKeyId(providerId, configured.keyReference),
					publicJwk,
					createdAt,
					...(configured.retiredAt === undefined
						? {}
						: { expiresAt: new Date(configured.retiredAt.getTime()) }),
				});
			}));
			return Object.freeze(keys);
		},
		async readiness(): Promise<KeyProviderReadiness> {
			const statuses = await Promise.all(configuredKeys.map(async (configured) => {
				const role = configured.keyReference === currentKeyReference ? "current" as const : "retained" as const;
				try {
					await Promise.all([
						describeSigningKey(configured.keyReference, true),
						getPublicKey(configured.keyReference, true),
					]);
					return Object.freeze({
						role,
						keyRef: redactedKeyReference(configured.keyReference),
						status: "ready" as const,
					});
				} catch (error) {
					const status = error instanceof KeyManagementError && error.code === "KEY_OPERATION_FAILED"
						? "invalid" as const
						: "unavailable" as const;
					return Object.freeze({
						role,
						keyRef: redactedKeyReference(configured.keyReference),
						status,
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
				kind: "aws-kms",
				providerRef: redactedKeyReference(providerId),
				currentKeyRef: redactedKeyReference(currentKeyReference),
				keys: Object.freeze(statuses satisfies readonly KeyProviderKeyStatus[]),
				reasons: Object.freeze([...reasons].sort()),
			});
		},
	};
	return Object.freeze(provider);
}
