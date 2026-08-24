import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createHmac,
	hkdfSync,
	randomBytes,
	timingSafeEqual,
} from "node:crypto";
import { DeliveryError } from "./errors.js";
import type { DeliveryChannel } from "./redaction.js";

const KEY_BYTES = 32;
const IV_BYTES = 12;
export const MAX_DELIVERY_PAYLOAD_BYTES = 10_485_760;
const MAX_DELIVERY_CIPHERTEXT_BASE64URL_BYTES = Math.ceil(MAX_DELIVERY_PAYLOAD_BYTES * 4 / 3) + 4;
const ENVELOPE_PREFIX = "clrd$v1$";
const WEBHOOK_ENDPOINT_ENVELOPE_PREFIX = "clrwe$v1$";
const WEBHOOK_ENDPOINT_CONFIG_MAX_BYTES = 16_384;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;

export type DeliveryKeyring = {
	currentKeyId: string;
	keys: ReadonlyMap<string, Buffer>;
	currentFingerprintKeyId: string;
	fingerprintKeys: ReadonlyMap<string, Buffer>;
	sourceDedupeKey: Buffer;
};

export type DeliveryPayloadAad = {
	version: 1;
	eventId: string;
	kind: string;
	channel: DeliveryChannel;
	projectId: string;
	environmentId: string;
	destinationFingerprint: string;
	expiresAt: string;
};

export type WebhookEndpointConfig = {
	url: string;
	signingSecret: string;
};

export type WebhookEndpointConfigAad = {
	version: 1;
	endpointId: string;
	projectId: string;
	environmentId: string;
	secretVersion: number;
};

type DeliveryEncryptionKeyInput = {
	currentKeyId: string;
	keys: Record<string, string | Buffer>;
};

export type DeliveryKeyringInput = DeliveryEncryptionKeyInput & {
	/**
	 * Rotation procedure: migrate v1/v2 with its explicit legacy key id first;
	 * add the new key while retaining old keys; switch this id; deploy producers
	 * and workers; then use DeliveryStore.assertFingerprintKeysAvailable before
	 * retiring keys. Keep sourceDedupeKey unchanged across these rotations.
	 */
	currentFingerprintKeyId: string;
	fingerprintKeys: Record<string, string | Buffer>;
	sourceDedupeKey: string | Buffer;
};

function b64url(value: Buffer): string {
	return value.toString("base64url");
}

function decodeKey(raw: string, label: string): Buffer {
	const value = raw.trim();
	let decoded: Buffer;
	if (/^[0-9a-fA-F]{64}$/.test(value)) {
		decoded = Buffer.from(value, "hex");
	} else if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) {
		decoded = Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
	} else {
		throw new DeliveryError(
			"DELIVERY_KEY_INVALID",
			`${label} must be exactly 32 bytes encoded as hex or base64`,
		);
	}
	if (decoded.length !== KEY_BYTES) {
		throw new DeliveryError(
			"DELIVERY_KEY_INVALID",
			`${label} must decode to exactly 32 bytes`,
		);
	}
	return decoded;
}

export function createDeliveryKeyring(input: DeliveryKeyringInput): DeliveryKeyring {
	if (!KEY_ID.test(input.currentKeyId)) {
		throw new DeliveryError("DELIVERY_KEY_ID_INVALID", "Invalid current delivery key id");
	}
	const keys = new Map<string, Buffer>();
	for (const [keyId, material] of Object.entries(input.keys)) {
		if (!KEY_ID.test(keyId)) {
			throw new DeliveryError("DELIVERY_KEY_ID_INVALID", `Invalid delivery key id ${keyId}`);
		}
		if (!Buffer.isBuffer(material) && typeof material !== "string") {
			throw new DeliveryError(
				"DELIVERY_KEY_INVALID",
				`Delivery key ${keyId} must be encoded as hex or base64`,
			);
		}
		const key = Buffer.isBuffer(material)
			? Buffer.from(material)
			: decodeKey(material, `delivery key ${keyId}`);
		if (key.length !== KEY_BYTES) {
			throw new DeliveryError("DELIVERY_KEY_INVALID", `Delivery key ${keyId} must be 32 bytes`);
		}
		keys.set(keyId, key);
	}
	if (!keys.has(input.currentKeyId)) {
		throw new DeliveryError(
			"DELIVERY_CURRENT_KEY_MISSING",
			"Current delivery key id is not present in the keyring",
		);
	}
	if (!KEY_ID.test(input.currentFingerprintKeyId)) {
		throw new DeliveryError(
			"DELIVERY_FINGERPRINT_KEY_ID_INVALID",
			"Invalid current delivery fingerprint key id",
		);
	}
	const fingerprintKeys = new Map<string, Buffer>();
	for (const [keyId, material] of Object.entries(input.fingerprintKeys)) {
		if (!KEY_ID.test(keyId)) {
			throw new DeliveryError(
				"DELIVERY_FINGERPRINT_KEY_ID_INVALID",
				`Invalid delivery fingerprint key id ${keyId}`,
			);
		}
		if (!Buffer.isBuffer(material) && typeof material !== "string") {
			throw new DeliveryError(
				"DELIVERY_KEY_INVALID",
				`Delivery fingerprint key ${keyId} must be encoded as hex or base64`,
			);
		}
		const key = Buffer.isBuffer(material)
			? Buffer.from(material)
			: decodeKey(material, `delivery fingerprint key ${keyId}`);
		if (key.length !== KEY_BYTES) {
			throw new DeliveryError(
				"DELIVERY_KEY_INVALID",
				`Delivery fingerprint key ${keyId} must be 32 bytes`,
			);
		}
		fingerprintKeys.set(keyId, key);
	}
	if (!fingerprintKeys.has(input.currentFingerprintKeyId)) {
		throw new DeliveryError(
			"DELIVERY_CURRENT_FINGERPRINT_KEY_MISSING",
			"Current delivery fingerprint key id is not present in the fingerprint keyring",
		);
	}
	const sourceDedupeKey = Buffer.isBuffer(input.sourceDedupeKey)
		? Buffer.from(input.sourceDedupeKey)
		: decodeKey(input.sourceDedupeKey, "delivery source dedupe key");
	if (sourceDedupeKey.length !== KEY_BYTES) {
		throw new DeliveryError("DELIVERY_KEY_INVALID", "Delivery source dedupe key must be 32 bytes");
	}
	const purposeKeys = [...keys.values(), ...fingerprintKeys.values(), sourceDedupeKey];
	for (let left = 0; left < purposeKeys.length; left += 1) {
		for (let right = left + 1; right < purposeKeys.length; right += 1) {
			if (!timingSafeEqual(purposeKeys[left]!, purposeKeys[right]!)) continue;
			throw new DeliveryError(
				"DELIVERY_KEY_PURPOSE_REUSE",
				"Delivery encryption, fingerprint, and source dedupe keys must use different material",
			);
		}
	}
	return {
		currentKeyId: input.currentKeyId,
		keys,
		currentFingerprintKeyId: input.currentFingerprintKeyId,
		fingerprintKeys,
		sourceDedupeKey,
	};
}

export function resolveDeliveryKeyring(
	env: NodeJS.ProcessEnv = process.env,
): DeliveryKeyring {
	const currentKeyId = env.CLEARANCE_DELIVERY_KEY_ID?.trim();
	const keysJson = env.CLEARANCE_DELIVERY_KEYS_JSON?.trim();
	const currentFingerprintKeyId = env.CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID?.trim();
	const fingerprintKeysJson = env.CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON?.trim();
	const sourceDedupeKey = env.CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY?.trim();
	if (!currentKeyId || !keysJson || !currentFingerprintKeyId || !fingerprintKeysJson || !sourceDedupeKey) {
		throw new DeliveryError(
			"DELIVERY_KEYRING_REQUIRED",
			"CLEARANCE_DELIVERY_KEY_ID, CLEARANCE_DELIVERY_KEYS_JSON, CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID, CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON, and CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY are required",
		);
	}
	let keys: Record<string, string>;
	let fingerprintKeys: Record<string, string>;
	try {
		const parsed: unknown = JSON.parse(keysJson);
		if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error();
		keys = parsed as Record<string, string>;
	} catch {
		throw new DeliveryError(
			"DELIVERY_KEYRING_INVALID",
			"CLEARANCE_DELIVERY_KEYS_JSON must be an object mapping key ids to 32-byte keys",
		);
	}
	try {
		const parsed: unknown = JSON.parse(fingerprintKeysJson);
		if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") throw new Error();
		fingerprintKeys = parsed as Record<string, string>;
	} catch {
		throw new DeliveryError(
			"DELIVERY_KEYRING_INVALID",
			"CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON must be an object mapping key ids to 32-byte keys",
		);
	}
	return createDeliveryKeyring({
		currentKeyId,
		keys,
		currentFingerprintKeyId,
		fingerprintKeys,
		sourceDedupeKey,
	});
}

function aadBytes(aad: DeliveryPayloadAad): Buffer {
	return Buffer.from(
		JSON.stringify({
			version: aad.version,
			eventId: aad.eventId,
			kind: aad.kind,
			channel: aad.channel,
			projectId: aad.projectId,
			environmentId: aad.environmentId,
			destinationFingerprint: aad.destinationFingerprint,
			expiresAt: aad.expiresAt,
		}),
		"utf8",
	);
}

function webhookEndpointAadBytes(aad: WebhookEndpointConfigAad): Buffer {
	return Buffer.from(JSON.stringify({
		purpose: "webhook-endpoint-config",
		version: aad.version,
		endpointId: aad.endpointId,
		projectId: aad.projectId,
		environmentId: aad.environmentId,
		secretVersion: aad.secretVersion,
	}), "utf8");
}

function webhookEndpointKey(key: Buffer): Buffer {
	return Buffer.from(hkdfSync(
		"sha256",
		key,
		Buffer.from("clearance-delivery-webhook-endpoint-v1", "utf8"),
		Buffer.from("aes-256-gcm-config", "utf8"),
		KEY_BYTES,
	));
}

function validWebhookEndpointConfig(value: unknown): value is WebhookEndpointConfig {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const record = value as Record<string, unknown>;
	return Object.keys(record).length === 2 &&
		typeof record.url === "string" && record.url.length > 0 && record.url.length <= 8_192 &&
		typeof record.signingSecret === "string" &&
		/^whsec_[A-Za-z0-9_-]{40,128}$/.test(record.signingSecret);
}

export function webhookEndpointSecretFingerprint(secret: string): string {
	if (!/^whsec_[A-Za-z0-9_-]{40,128}$/.test(secret)) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_SECRET_INVALID", "Webhook endpoint secret is invalid");
	}
	return createHash("sha256").update(secret, "utf8").digest("hex");
}

export function encryptWebhookEndpointConfig(
	config: WebhookEndpointConfig,
	aad: WebhookEndpointConfigAad,
	ring: DeliveryKeyring,
): { envelope: string; keyId: string; envelopeVersion: 1 } {
	if (!validWebhookEndpointConfig(config)) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_CONFIG_INVALID", "Webhook endpoint configuration is invalid");
	}
	const plaintext = JSON.stringify({ url: config.url, signingSecret: config.signingSecret });
	if (Buffer.byteLength(plaintext, "utf8") > WEBHOOK_ENDPOINT_CONFIG_MAX_BYTES) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_CONFIG_TOO_LARGE", "Webhook endpoint configuration is too large");
	}
	const rootKey = ring.keys.get(ring.currentKeyId);
	if (!rootKey) throw new DeliveryError("DELIVERY_CURRENT_KEY_MISSING", "Current delivery key is unavailable");
	const iv = randomBytes(IV_BYTES);
	const cipher = createCipheriv("aes-256-gcm", webhookEndpointKey(rootKey), iv);
	cipher.setAAD(webhookEndpointAadBytes(aad));
	const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return {
		envelope: `${WEBHOOK_ENDPOINT_ENVELOPE_PREFIX}${ring.currentKeyId}$${b64url(iv)}$${b64url(tag)}$${b64url(ciphertext)}`,
		keyId: ring.currentKeyId,
		envelopeVersion: 1,
	};
}

export function decryptWebhookEndpointConfig(
	envelope: string,
	aad: WebhookEndpointConfigAad,
	ring: DeliveryKeyring,
	expectedKeyId?: string,
): WebhookEndpointConfig {
	if (!envelope.startsWith(WEBHOOK_ENDPOINT_ENVELOPE_PREFIX)) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_ENVELOPE_INVALID", "Unknown webhook endpoint envelope");
	}
	const parts = envelope.slice(WEBHOOK_ENDPOINT_ENVELOPE_PREFIX.length).split("$");
	if (parts.length !== 4) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_ENVELOPE_INVALID", "Malformed webhook endpoint envelope");
	}
	const [keyId, ivRaw, tagRaw, ciphertextRaw] = parts;
	if (!keyId || !ivRaw || !tagRaw || ciphertextRaw === undefined ||
		Buffer.byteLength(ciphertextRaw, "utf8") > Math.ceil(WEBHOOK_ENDPOINT_CONFIG_MAX_BYTES * 4 / 3) + 4) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_ENVELOPE_INVALID", "Malformed webhook endpoint envelope");
	}
	if (expectedKeyId !== undefined && keyId !== expectedKeyId) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_ENVELOPE_INVALID", "Webhook endpoint envelope key reference differs");
	}
	const rootKey = ring.keys.get(keyId);
	if (!rootKey) throw new DeliveryError("DELIVERY_KEY_UNAVAILABLE", `Delivery key ${keyId} is unavailable`);
	const iv = Buffer.from(ivRaw, "base64url");
	const tag = Buffer.from(tagRaw, "base64url");
	if (iv.length !== IV_BYTES || tag.length !== 16) {
		throw new DeliveryError("WEBHOOK_ENDPOINT_ENVELOPE_INVALID", "Malformed webhook endpoint envelope");
	}
	try {
		const decipher = createDecipheriv("aes-256-gcm", webhookEndpointKey(rootKey), iv);
		decipher.setAAD(webhookEndpointAadBytes(aad));
		decipher.setAuthTag(tag);
		const plaintext = Buffer.concat([
			decipher.update(Buffer.from(ciphertextRaw, "base64url")),
			decipher.final(),
		]);
		if (plaintext.length > WEBHOOK_ENDPOINT_CONFIG_MAX_BYTES) throw new Error("oversized");
		const parsed: unknown = JSON.parse(plaintext.toString("utf8"));
		if (!validWebhookEndpointConfig(parsed)) throw new Error("invalid");
		return parsed;
	} catch {
		throw new DeliveryError(
			"WEBHOOK_ENDPOINT_CONFIG_AUTH_FAILED",
			"Webhook endpoint configuration authentication failed",
		);
	}
}

export function fingerprintDestination(
	destination: string,
	ring: DeliveryKeyring,
	keyId: string = ring.currentFingerprintKeyId,
): string {
	if (!destination.trim()) {
		throw new DeliveryError("DELIVERY_DESTINATION_REQUIRED", "Delivery destination is required");
	}
	const key = ring.fingerprintKeys.get(keyId);
	if (!key) {
		throw new DeliveryError(
			"DELIVERY_FINGERPRINT_KEY_UNAVAILABLE",
			`Delivery fingerprint key ${keyId} is unavailable`,
		);
	}
	return createHmac("sha256", key)
		.update("destination\0", "utf8")
		.update(destination.trim(), "utf8")
		.digest("hex");
}

export function fingerprintSource(
	projectId: string,
	environmentId: string,
	kind: string,
	sourceKey: string,
	ring: DeliveryKeyring,
	keyId: string = ring.currentFingerprintKeyId,
): string {
	if (!projectId.trim() || !environmentId.trim() || !kind.trim() || !sourceKey) {
		throw new DeliveryError(
			"DELIVERY_SOURCE_REQUIRED",
			"Delivery project, environment, kind, and source key are required",
		);
	}
	const key = ring.fingerprintKeys.get(keyId);
	if (!key) {
		throw new DeliveryError(
			"DELIVERY_FINGERPRINT_KEY_UNAVAILABLE",
			`Delivery fingerprint key ${keyId} is unavailable`,
		);
	}
	return createHmac("sha256", key)
		.update("source\0", "utf8")
		.update(projectId, "utf8")
		.update("\0", "utf8")
		.update(environmentId, "utf8")
		.update("\0", "utf8")
		.update(kind, "utf8")
		.update("\0", "utf8")
		.update(sourceKey, "utf8")
		.digest("hex");
}

/**
 * Stable source-generation authority. Keep this purpose-separated key stable
 * across operational fingerprint-key rotations so a rotation cannot create a
 * second delivery for the same logical source generation.
 */
export function fingerprintSourceDedupe(
	projectId: string,
	environmentId: string,
	kind: string,
	sourceKey: string,
	ring: DeliveryKeyring,
): string {
	if (!projectId.trim() || !environmentId.trim() || !kind.trim() || !sourceKey) {
		throw new DeliveryError(
			"DELIVERY_SOURCE_REQUIRED",
			"Delivery project, environment, kind, and source key are required",
		);
	}
	return createHmac("sha256", ring.sourceDedupeKey)
		.update("source-dedupe\0", "utf8")
		.update(projectId, "utf8")
		.update("\0", "utf8")
		.update(environmentId, "utf8")
		.update("\0", "utf8")
		.update(kind, "utf8")
		.update("\0", "utf8")
		.update(sourceKey, "utf8")
		.digest("hex");
}

export function encryptDeliveryPayload(
	payload: unknown,
	aad: DeliveryPayloadAad,
	ring: DeliveryKeyring,
): { envelope: string; keyId: string } {
	let plaintext: string | undefined;
	try {
		plaintext = JSON.stringify(payload);
	} catch {
		throw new DeliveryError("DELIVERY_PAYLOAD_INVALID", "Delivery payload must be JSON serializable");
	}
	if (plaintext === undefined) {
		throw new DeliveryError("DELIVERY_PAYLOAD_INVALID", "Delivery payload must be JSON serializable");
	}
	if (Buffer.byteLength(plaintext, "utf8") > MAX_DELIVERY_PAYLOAD_BYTES) {
		throw new DeliveryError(
			"DELIVERY_PAYLOAD_TOO_LARGE",
			`Delivery payload exceeds ${MAX_DELIVERY_PAYLOAD_BYTES} bytes`,
		);
	}
	const key = ring.keys.get(ring.currentKeyId);
	if (!key) throw new DeliveryError("DELIVERY_CURRENT_KEY_MISSING", "Current delivery key is unavailable");
	const iv = randomBytes(IV_BYTES);
	const cipher = createCipheriv("aes-256-gcm", key, iv);
	cipher.setAAD(aadBytes(aad));
	const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return {
		envelope: `${ENVELOPE_PREFIX}${ring.currentKeyId}$${b64url(iv)}$${b64url(tag)}$${b64url(ciphertext)}`,
		keyId: ring.currentKeyId,
	};
}

export function decryptDeliveryPayload<T = unknown>(
	envelope: string,
	aad: DeliveryPayloadAad,
	ring: DeliveryKeyring,
): T {
	if (!envelope.startsWith(ENVELOPE_PREFIX)) {
		throw new DeliveryError("DELIVERY_ENVELOPE_INVALID", "Unknown delivery payload envelope");
	}
	const parts = envelope.slice(ENVELOPE_PREFIX.length).split("$");
	if (parts.length !== 4) {
		throw new DeliveryError("DELIVERY_ENVELOPE_INVALID", "Malformed delivery payload envelope");
	}
	const [keyId, ivRaw, tagRaw, ciphertextRaw] = parts;
	if (!keyId || !ivRaw || !tagRaw || ciphertextRaw === undefined) {
		throw new DeliveryError("DELIVERY_ENVELOPE_INVALID", "Malformed delivery payload envelope");
	}
	if (Buffer.byteLength(ciphertextRaw, "utf8") > MAX_DELIVERY_CIPHERTEXT_BASE64URL_BYTES) {
		throw new DeliveryError("DELIVERY_PAYLOAD_TOO_LARGE", "Encrypted delivery payload exceeds the supported size");
	}
	const key = ring.keys.get(keyId);
	if (!key) throw new DeliveryError("DELIVERY_KEY_UNAVAILABLE", `Delivery key ${keyId} is unavailable`);
	const iv = Buffer.from(ivRaw, "base64url");
	const tag = Buffer.from(tagRaw, "base64url");
	if (iv.length !== IV_BYTES || tag.length !== 16) {
		throw new DeliveryError("DELIVERY_ENVELOPE_INVALID", "Malformed delivery payload nonce or tag");
	}
	try {
		const decipher = createDecipheriv("aes-256-gcm", key, iv);
		decipher.setAAD(aadBytes(aad));
		decipher.setAuthTag(tag);
		const plaintext = Buffer.concat([
			decipher.update(Buffer.from(ciphertextRaw, "base64url")),
			decipher.final(),
		]);
		if (plaintext.length > MAX_DELIVERY_PAYLOAD_BYTES) {
			throw new DeliveryError("DELIVERY_PAYLOAD_TOO_LARGE", "Decrypted delivery payload exceeds the supported size");
		}
		return JSON.parse(plaintext.toString("utf8")) as T;
	} catch (cause) {
		throw new DeliveryError(
			"DELIVERY_PAYLOAD_AUTH_FAILED",
			cause instanceof Error ? "Delivery payload authentication failed" : "Delivery payload decryption failed",
		);
	}
}
