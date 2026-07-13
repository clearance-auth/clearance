/**
 * Versioned authenticated encryption for control-plane credential material
 * (SSO client secrets, SCIM bearer tokens). Uses AES-256-GCM with a configured
 * key id so operators can rotate without rewriting domain models.
 *
 * Envelope format: clr$v1$<keyId>$<iv_b64url>$<tag_b64url>$<ct_b64url>
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { isForbiddenDefaultSecret } from "./secrets.js";

const ENVELOPE_PREFIX = "clr$v1$";
const ALGO = "aes-256-gcm" as const;
const IV_LEN = 12;
const KEY_LEN = 32;

export type CredentialKeyring = {
	currentKeyId: string;
	/** keyId → 32-byte key material */
	keys: Map<string, Buffer>;
};

export type EncryptedCredential = {
	/** Versioned AEAD envelope (never the plaintext) */
	ciphertext: string;
	keyId: string;
	/** Short fingerprint of plaintext for comparison without disclosure */
	fingerprint: string;
};

function b64url(buf: Buffer): string {
	return buf
		.toString("base64")
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
}

function fromB64url(s: string): Buffer {
	const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
	const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
	return Buffer.from(b64, "base64");
}

function deriveKeyMaterial(raw: string): Buffer {
	// Accept base64, hex, or arbitrary secret string → 32-byte key via SHA-256
	const trimmed = raw.trim();
	if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
		return Buffer.from(trimmed, "hex");
	}
	try {
		const asB64 = Buffer.from(trimmed, "base64");
		if (asB64.length === KEY_LEN) return asB64;
	} catch {
		/* fall through */
	}
	return createHash("sha256").update(trimmed, "utf8").digest();
}

export function fingerprintCredential(value: string): string {
	return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 16);
}

/**
 * Resolve keyring from environment.
 * - CLEARANCE_CREDENTIAL_KEY + CLEARANCE_CREDENTIAL_KEY_ID (required outside dev/test)
 * - Optional CLEARANCE_CREDENTIAL_PREVIOUS_KEY / CLEARANCE_CREDENTIAL_PREVIOUS_KEY_ID for rotation
 * - CLEARANCE_CREDENTIAL_KEYS_JSON: {"kid":"secret",...} with CLEARANCE_CREDENTIAL_KEY_ID as current
 */
export function resolveCredentialKeyring(
	env: NodeJS.ProcessEnv = process.env,
): CredentialKeyring | null {
	const currentKeyId =
		env.CLEARANCE_CREDENTIAL_KEY_ID?.trim() ||
		env.CLEARANCE_CREDENTIALS_KEY_ID?.trim() ||
		"";
	const currentKey =
		env.CLEARANCE_CREDENTIAL_KEY?.trim() ||
		env.CLEARANCE_CREDENTIALS_KEY?.trim() ||
		"";

	const keys = new Map<string, Buffer>();

	const multi = env.CLEARANCE_CREDENTIAL_KEYS_JSON?.trim();
	if (multi) {
		try {
			const parsed = JSON.parse(multi) as Record<string, string>;
			for (const [kid, secret] of Object.entries(parsed)) {
				if (kid && secret) keys.set(kid, deriveKeyMaterial(secret));
			}
		} catch {
			throw new Error(
				"CLEARANCE_CREDENTIAL_KEYS_JSON must be a JSON object of keyId → secret",
			);
		}
	}

	if (currentKey && currentKeyId) {
		keys.set(currentKeyId, deriveKeyMaterial(currentKey));
	}

	const prevKey = env.CLEARANCE_CREDENTIAL_PREVIOUS_KEY?.trim();
	const prevId = env.CLEARANCE_CREDENTIAL_PREVIOUS_KEY_ID?.trim();
	if (prevKey && prevId) {
		keys.set(prevId, deriveKeyMaterial(prevKey));
	}

	if (!currentKeyId || keys.size === 0 || !keys.has(currentKeyId)) {
		return null;
	}

	return { currentKeyId, keys };
}

export function isDevelopmentLike(env: NodeJS.ProcessEnv = process.env): boolean {
	const nodeEnv = env.NODE_ENV ?? "development";
	if (nodeEnv === "production") return false;
	if (env.CLEARANCE_STRICT_SECRETS === "1") return false;
	if (env.VITEST === "true" || env.NODE_ENV === "test") return true;
	return nodeEnv === "development" || nodeEnv === "test";
}

/**
 * Fail closed outside development/test when credential key is missing or weak.
 */
export function assertCredentialKeyConfigured(
	env: NodeJS.ProcessEnv = process.env,
): CredentialKeyring {
	const ring = resolveCredentialKeyring(env);
	if (ring) {
		const material = ring.keys.get(ring.currentKeyId);
		if (!material || material.length !== KEY_LEN) {
			throw new Error("CLEARANCE_CREDENTIAL_KEY must resolve to 32 bytes");
		}
		const raw =
			env.CLEARANCE_CREDENTIAL_KEY ?? env.CLEARANCE_CREDENTIALS_KEY ?? "";
		if (
			(env.NODE_ENV === "production" || env.CLEARANCE_STRICT_SECRETS === "1") &&
			isForbiddenDefaultSecret(raw)
		) {
			throw new Error(
				"Production refuses default/weak CLEARANCE_CREDENTIAL_KEY",
			);
		}
		return ring;
	}

	if (isDevelopmentLike(env)) {
		// Deterministic lab key — never used when production env vars are set.
		const lab = deriveKeyMaterial(
			env.CLEARANCE_SECRET ?? "dev-only-credential-key-not-for-production",
		);
		return {
			currentKeyId: "dev",
			keys: new Map([["dev", lab]]),
		};
	}

	throw new Error(
		"CLEARANCE_CREDENTIAL_KEY and CLEARANCE_CREDENTIAL_KEY_ID are required outside development/test",
	);
}

export function getCredentialKeyring(
	env: NodeJS.ProcessEnv = process.env,
): CredentialKeyring {
	return assertCredentialKeyConfigured(env);
}

export function encryptCredential(
	plaintext: string,
	ring: CredentialKeyring = getCredentialKeyring(),
): EncryptedCredential {
	const key = ring.keys.get(ring.currentKeyId);
	if (!key) {
		throw new Error(`Credential key id ${ring.currentKeyId} not in keyring`);
	}
	const iv = randomBytes(IV_LEN);
	const cipher = createCipheriv(ALGO, key, iv);
	const ct = Buffer.concat([
		cipher.update(plaintext, "utf8"),
		cipher.final(),
	]);
	const tag = cipher.getAuthTag();
	const ciphertext = `${ENVELOPE_PREFIX}${ring.currentKeyId}$${b64url(iv)}$${b64url(tag)}$${b64url(ct)}`;
	return {
		ciphertext,
		keyId: ring.currentKeyId,
		fingerprint: fingerprintCredential(plaintext),
	};
}

export function parseCredentialEnvelope(envelope: string): {
	version: 1;
	keyId: string;
	iv: Buffer;
	tag: Buffer;
	ct: Buffer;
} {
	if (!envelope.startsWith(ENVELOPE_PREFIX)) {
		throw new Error("Unrecognized credential envelope (expected clr$v1$)");
	}
	const rest = envelope.slice(ENVELOPE_PREFIX.length);
	const parts = rest.split("$");
	if (parts.length !== 4) {
		throw new Error("Malformed credential envelope");
	}
	const [keyId, ivB, tagB, ctB] = parts;
	if (!keyId || !ivB || !tagB || !ctB) {
		throw new Error("Malformed credential envelope parts");
	}
	return {
		version: 1,
		keyId,
		iv: fromB64url(ivB),
		tag: fromB64url(tagB),
		ct: fromB64url(ctB),
	};
}

export function decryptCredential(
	envelope: string,
	ring: CredentialKeyring = getCredentialKeyring(),
): string {
	const parsed = parseCredentialEnvelope(envelope);
	const key = ring.keys.get(parsed.keyId);
	if (!key) {
		throw new Error(
			`Credential key id ${parsed.keyId} not available (rotate keys or restore previous key)`,
		);
	}
	const decipher = createDecipheriv(ALGO, key, parsed.iv);
	decipher.setAuthTag(parsed.tag);
	const pt = Buffer.concat([decipher.update(parsed.ct), decipher.final()]);
	return pt.toString("utf8");
}

/** Re-encrypt under the current key id (rotation). */
export function rotateCredential(
	envelope: string,
	ring: CredentialKeyring = getCredentialKeyring(),
): EncryptedCredential {
	const plaintext = decryptCredential(envelope, ring);
	return encryptCredential(plaintext, ring);
}

/** True when value looks like our envelope (not plaintext). */
export function isCredentialEnvelope(value: string | undefined | null): boolean {
	return typeof value === "string" && value.startsWith(ENVELOPE_PREFIX);
}
