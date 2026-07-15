import {
	createCipheriv,
	createDecipheriv,
	createHmac,
	randomBytes,
	timingSafeEqual,
} from "node:crypto";
import { DeliveryError } from "./errors.js";

const KEY_BYTES = 32;
const IV_BYTES = 12;
export const MAX_DELIVERY_PAYLOAD_BYTES = 10_485_760;
const MAX_DELIVERY_CIPHERTEXT_BASE64URL_BYTES = Math.ceil(MAX_DELIVERY_PAYLOAD_BYTES * 4 / 3) + 4;
const ENVELOPE_PREFIX = "clrd$v1$";
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;

export type DeliveryKeyring = {
	currentKeyId: string;
	keys: ReadonlyMap<string, Buffer>;
	fingerprintKey: Buffer;
};

export type DeliveryPayloadAad = {
	version: 1;
	eventId: string;
	kind: string;
	channel: "email" | "webhook";
	projectId: string;
	environmentId: string;
	destinationFingerprint: string;
	expiresAt: string;
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

export function createDeliveryKeyring(input: {
	currentKeyId: string;
	keys: Record<string, string | Buffer>;
	fingerprintKey: string | Buffer;
}): DeliveryKeyring {
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
	const fingerprintKey = Buffer.isBuffer(input.fingerprintKey)
		? Buffer.from(input.fingerprintKey)
		: decodeKey(input.fingerprintKey, "delivery fingerprint key");
	if (fingerprintKey.length !== KEY_BYTES) {
		throw new DeliveryError("DELIVERY_KEY_INVALID", "Delivery fingerprint key must be 32 bytes");
	}
	for (const key of keys.values()) {
		if (timingSafeEqual(key, fingerprintKey)) {
			throw new DeliveryError(
				"DELIVERY_KEY_PURPOSE_REUSE",
				"Delivery encryption and fingerprint keys must use different material",
			);
		}
	}
	return { currentKeyId: input.currentKeyId, keys, fingerprintKey };
}

export function resolveDeliveryKeyring(
	env: NodeJS.ProcessEnv = process.env,
): DeliveryKeyring {
	const currentKeyId = env.CLEARANCE_DELIVERY_KEY_ID?.trim();
	const keysJson = env.CLEARANCE_DELIVERY_KEYS_JSON?.trim();
	const fingerprintKey = env.CLEARANCE_DELIVERY_FINGERPRINT_KEY?.trim();
	if (!currentKeyId || !keysJson || !fingerprintKey) {
		throw new DeliveryError(
			"DELIVERY_KEYRING_REQUIRED",
			"CLEARANCE_DELIVERY_KEY_ID, CLEARANCE_DELIVERY_KEYS_JSON, and CLEARANCE_DELIVERY_FINGERPRINT_KEY are required",
		);
	}
	let keys: Record<string, string>;
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
	return createDeliveryKeyring({ currentKeyId, keys, fingerprintKey });
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

export function fingerprintDestination(
	destination: string,
	ring: DeliveryKeyring,
): string {
	if (!destination.trim()) {
		throw new DeliveryError("DELIVERY_DESTINATION_REQUIRED", "Delivery destination is required");
	}
	return createHmac("sha256", ring.fingerprintKey)
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
): string {
	if (!projectId.trim() || !environmentId.trim() || !kind.trim() || !sourceKey) {
		throw new DeliveryError(
			"DELIVERY_SOURCE_REQUIRED",
			"Delivery project, environment, kind, and source key are required",
		);
	}
	return createHmac("sha256", ring.fingerprintKey)
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
