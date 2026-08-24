import {
	createCipheriv, createDecipheriv, randomBytes, timingSafeEqual,
} from "node:crypto";
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
import { redactedKeyReference, registerProviderSeparationMetadata } from "./internal.js";
import {
	type KeyContext,
	type KeyEncryptionProvider,
	type KeyProviderReadiness,
	type KeyPurpose,
} from "./types.js";

const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_PLAINTEXT_BYTES = 16_384;
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]+$/;

export type LocalKeyMaterial = string | Uint8Array;

export type LocalKeyProviderOptions = Readonly<{
	providerId: string;
	purpose: KeyPurpose;
	currentKeyId: string;
	keys: Readonly<Record<string, LocalKeyMaterial>>;
}>;

function parseKey(value: LocalKeyMaterial): Buffer {
	if (typeof value !== "string") {
		const key = Buffer.from(value);
		if (key.length !== KEY_BYTES) {
			throw new KeyManagementError("KEY_INPUT_INVALID", "Local key must be 32 bytes");
		}
		return key;
	}
	if (/^[0-9a-f]{64}$/.test(value)) return Buffer.from(value, "hex");
	if (!CANONICAL_BASE64URL.test(value)) {
		throw new KeyManagementError("KEY_INPUT_INVALID", "Local key encoding is invalid");
	}
	const key = Buffer.from(value, "base64url");
	if (key.length !== KEY_BYTES || key.toString("base64url") !== value) {
		throw new KeyManagementError("KEY_INPUT_INVALID", "Local key must be canonical 32-byte base64url");
	}
	return key;
}

export function createLocalKeyProvider(
	options: LocalKeyProviderOptions,
): KeyEncryptionProvider {
	if (!options || typeof options !== "object" || Array.isArray(options)) {
		throw new KeyManagementError("KEY_INPUT_INVALID", "Local key provider options are invalid");
	}
	const providerId = validateProviderIdentifier(options.providerId, "providerId");
	const purpose = validateKeyPurpose(options.purpose);
	const currentKeyId = validateProviderIdentifier(options.currentKeyId, "currentKeyId");
	if (!options.keys || typeof options.keys !== "object" || Array.isArray(options.keys)) {
		throw new KeyManagementError("KEY_INPUT_INVALID", "Local keyring is invalid");
	}
	const keys = new Map<string, Buffer>();
	for (const [keyId, raw] of Object.entries(options.keys)) {
		validateProviderIdentifier(keyId, "keyId");
		const key = parseKey(raw);
		if ([...keys.values()].some((candidate) => timingSafeEqual(candidate, key))) {
			throw new KeyManagementError("KEY_INPUT_INVALID", "Local key material is duplicated");
		}
		keys.set(keyId, key);
	}
	if (!keys.has(currentKeyId)) {
		throw new KeyManagementError("KEY_NOT_AVAILABLE", "Current local key is not configured");
	}
	const retainedKeyIds = Object.freeze([...keys.keys()].filter((keyId) => keyId !== currentKeyId).sort());

	const provider: KeyEncryptionProvider = {
		kind: "local",
		providerId,
		purpose,
		currentKeyId,
		retainedKeyIds,
		async seal(plaintext, context) {
			const exact = validateKeyContext(context);
			if (!(plaintext instanceof Uint8Array) || plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_BYTES) {
				throw new KeyManagementError("KEY_INPUT_INVALID", "Key plaintext size is invalid");
			}
			const key = keys.get(currentKeyId)!;
			const iv = randomBytes(IV_BYTES);
			const aad = keyOperationAad(
				createKeyOperationAuthority("local", providerId, currentKeyId, purpose, exact),
			);
			try {
				const cipher = createCipheriv("aes-256-gcm", key, iv);
				cipher.setAAD(aad);
				const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
				const packed = Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url");
				return formatKeyEnvelope({
					v: 1,
					provider: "local",
					providerId,
					keyId: currentKeyId,
					purpose,
					...exact,
					ciphertext: packed,
				});
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw new KeyManagementError("KEY_OPERATION_FAILED", "Local key encryption failed");
			}
		},
		async open(envelope, context) {
			const payload = parseKeyEnvelope(envelope);
			assertEnvelopeAuthority(payload, "local", providerId, purpose, context);
			const key = keys.get(payload.keyId);
			if (!key) {
				throw new KeyManagementError("KEY_NOT_AVAILABLE", "Envelope local key is not retained");
			}
			const packed = Buffer.from(payload.ciphertext, "base64url");
			if (
				packed.length <= IV_BYTES + TAG_BYTES ||
				packed.length > IV_BYTES + TAG_BYTES + MAX_PLAINTEXT_BYTES ||
				packed.toString("base64url") !== payload.ciphertext
			) {
				throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Local key ciphertext is invalid");
			}
			const iv = packed.subarray(0, IV_BYTES);
			const tag = packed.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
			const ciphertext = packed.subarray(IV_BYTES + TAG_BYTES);
			const aad = keyOperationAad(
				createKeyOperationAuthority("local", providerId, payload.keyId, purpose, context),
			);
			try {
				const decipher = createDecipheriv("aes-256-gcm", key, iv);
				decipher.setAAD(aad);
				decipher.setAuthTag(tag);
				const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
				if (plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_BYTES) {
					throw new KeyManagementError("KEY_OPERATION_FAILED", "Local key plaintext size is invalid");
				}
				return new Uint8Array(plaintext);
			} catch {
				throw new KeyManagementError("KEY_OPERATION_FAILED", "Local key decryption failed");
			}
		},
		async readiness(): Promise<KeyProviderReadiness> {
			return Object.freeze({
				ready: true,
				kind: "local",
				providerRef: redactedKeyReference(providerId),
				currentKeyRef: redactedKeyReference(currentKeyId),
				keys: Object.freeze([...keys.keys()].sort().map((keyId) => Object.freeze({
					role: keyId === currentKeyId ? "current" as const : "retained" as const,
					keyRef: redactedKeyReference(keyId),
					status: "ready" as const,
				}))),
				reasons: Object.freeze([]),
			});
		},
	};
	const frozen = Object.freeze(provider);
	registerProviderSeparationMetadata(frozen, {
		localKeys: [...keys.values()],
		cloudKeyReferences: [],
	});
	return frozen;
}
