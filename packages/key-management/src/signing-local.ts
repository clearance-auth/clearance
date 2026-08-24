import {
	createPrivateKey,
	createPublicKey,
	sign as cryptoSign,
	timingSafeEqual,
	type KeyObject,
} from "node:crypto";
import { KeyManagementError } from "./error.js";
import { redactedKeyReference } from "./internal.js";
import {
	ACCESS_TOKEN_SIGNING_ALGORITHM,
	type Es256PublicJwk,
	type KeySigningProvider,
	type RetainedSigningKey,
} from "./signing-types.js";
import { es256PublicJwk, signingKeyId, validateSigningInput } from "./signing-utils.js";
import type { KeyProviderReadiness } from "./types.js";
import { validateProviderIdentifier } from "./envelope.js";

const MAX_RETAINED_KEYS = 64;
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]+$/;

export type LocalSigningKeyMaterial = string | Uint8Array;

export type LocalSigningProviderOptions = Readonly<{
	providerId: string;
	currentKeyReference: string;
	keys: Readonly<Record<string, LocalSigningKeyMaterial>>;
	retainedKeys?: readonly RetainedSigningKey[];
}>;

type ParsedLocalSigningKey = Readonly<{
	keyReference: string;
	privateKey: KeyObject;
	privateKeyDer: Buffer;
	publicJwk: Es256PublicJwk;
}>;

type ParsedRetainedSigningKey = Readonly<{
	key: ParsedLocalSigningKey;
	retiredAt: number;
}>;

function inputFailure(message: string): KeyManagementError {
	return new KeyManagementError("KEY_INPUT_INVALID", message);
}

function canonicalPkcs8(value: LocalSigningKeyMaterial): Buffer {
	if (typeof value === "string") {
		if (!CANONICAL_BASE64URL.test(value)) {
			throw inputFailure("Local signing key encoding is invalid");
		}
		const decoded = Buffer.from(value, "base64url");
		if (decoded.length === 0 || decoded.toString("base64url") !== value) {
			throw inputFailure("Local signing key encoding is invalid");
		}
		return decoded;
	}
	if (!(value instanceof Uint8Array) || value.length === 0) {
		throw inputFailure("Local signing key is invalid");
	}
	return Buffer.from(value);
}

function parsePrivateKey(
	keyReference: string,
	value: LocalSigningKeyMaterial,
	providerId: string,
): ParsedLocalSigningKey {
	const input = canonicalPkcs8(value);
	let privateKey: KeyObject;
	try {
		privateKey = createPrivateKey({ key: input, format: "der", type: "pkcs8" });
	} catch {
		throw inputFailure("Local signing key is not PKCS#8");
	}
	const curve = privateKey.asymmetricKeyDetails?.namedCurve;
	if (privateKey.asymmetricKeyType !== "ec" || curve !== "prime256v1") {
		throw inputFailure("Local signing key must use P-256");
	}
	let privateKeyDer: Buffer;
	let publicJwk: Es256PublicJwk;
	try {
		privateKeyDer = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" }));
		if (privateKeyDer.length !== input.length || !timingSafeEqual(privateKeyDer, input)) {
			throw inputFailure("Local signing key must use canonical PKCS#8 DER");
		}
		publicJwk = es256PublicJwk(
			createPublicKey(privateKey).export({ format: "jwk" }),
			signingKeyId(providerId, keyReference),
		);
	} catch (error) {
		if (error instanceof KeyManagementError) throw error;
		throw inputFailure("Local signing key is invalid");
	}
	return Object.freeze({
		keyReference,
		privateKey,
		privateKeyDer,
		publicJwk,
	});
}

/**
 * Creates a process-local ES256 signer. The configured references are never
 * exposed: every public identifier is a provider-scoped hash.
 */
export function createLocalSigningProvider(
	options: LocalSigningProviderOptions,
): KeySigningProvider {
	if (!options || typeof options !== "object" || Array.isArray(options)) {
		throw inputFailure("Local signing provider options are invalid");
	}
	const providerId = validateProviderIdentifier(options.providerId, "providerId");
	const currentKeyReference = validateProviderIdentifier(
		options.currentKeyReference,
		"currentKeyReference",
	);
	if (!options.keys || typeof options.keys !== "object" || Array.isArray(options.keys)) {
		throw inputFailure("Local signing keyring is invalid");
	}
	const keys = new Map<string, ParsedLocalSigningKey>();
	for (const [rawReference, material] of Object.entries(options.keys)) {
		const keyReference = validateProviderIdentifier(rawReference, "keyReference");
		const parsed = parsePrivateKey(keyReference, material, providerId);
		for (const candidate of keys.values()) {
			if (
				candidate.privateKeyDer.length === parsed.privateKeyDer.length &&
				timingSafeEqual(candidate.privateKeyDer, parsed.privateKeyDer)
			) {
				throw inputFailure("Local signing key material is duplicated");
			}
		}
		keys.set(keyReference, parsed);
	}
	const current = keys.get(currentKeyReference);
	if (!current) {
		throw new KeyManagementError("KEY_NOT_AVAILABLE", "Current local signing key is not configured");
	}

	const configuredRetained = options.retainedKeys ?? [];
	if (!Array.isArray(configuredRetained) || configuredRetained.length > MAX_RETAINED_KEYS) {
		throw inputFailure("Retained signing keys are invalid");
	}
	const retainedReferences = new Set<string>();
	const retained: ParsedRetainedSigningKey[] = [];
	for (const entry of configuredRetained) {
		if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
			throw inputFailure("Retained signing key is invalid");
		}
		const keyReference = validateProviderIdentifier(entry.keyReference, "retained keyReference");
		if (keyReference === currentKeyReference || retainedReferences.has(keyReference)) {
			throw inputFailure("Retained signing key references are duplicated");
		}
		if (!(entry.retiredAt instanceof Date) || !Number.isFinite(entry.retiredAt.getTime())) {
			throw inputFailure("Retained signing key retirement is invalid");
		}
		const retiredAt = entry.retiredAt.getTime();
		if (retiredAt > Date.now()) {
			throw inputFailure("Retained signing key retirement cannot be in the future");
		}
		const key = keys.get(keyReference);
		if (!key) {
			throw new KeyManagementError("KEY_NOT_AVAILABLE", "Retained local signing key is not configured");
		}
		retainedReferences.add(keyReference);
		retained.push(Object.freeze({ key, retiredAt }));
	}
	if (keys.size !== retained.length + 1) {
		throw inputFailure("Every non-current local signing key must be retained");
	}

	const currentKeyId = signingKeyId(providerId, currentKeyReference);
	const retainedKeyIds = Object.freeze(retained.map(({ key }) => signingKeyId(providerId, key.keyReference)));
	const publicKeys: readonly Readonly<{
		id: string;
		publicJwk: Es256PublicJwk;
		createdAt: number;
		expiresAt?: number;
	}>[] = Object.freeze([
		Object.freeze({
			id: currentKeyId,
			publicJwk: current.publicJwk,
			createdAt: 0,
		}),
		...retained.map(({ key, retiredAt }) => Object.freeze({
			id: signingKeyId(providerId, key.keyReference),
			publicJwk: key.publicJwk,
			createdAt: 0,
			expiresAt: retiredAt,
		})),
	]);

	const provider: KeySigningProvider = {
		kind: "local",
		providerId,
		purpose: "access-token-signing-key",
		algorithm: ACCESS_TOKEN_SIGNING_ALGORITHM,
		currentKeyId,
		retainedKeyIds,
		async sign(signingInput: Uint8Array) {
			const input = validateSigningInput(signingInput);
			try {
				const signature = cryptoSign("sha256", input, {
					key: current.privateKey,
					dsaEncoding: "ieee-p1363",
				});
				if (signature.length !== 64) {
					throw new Error("unexpected ES256 signature length");
				}
				return new Uint8Array(signature);
			} catch (error) {
				if (error instanceof KeyManagementError) throw error;
				throw new KeyManagementError("KEY_OPERATION_FAILED", "Local JWT signing failed");
			}
		},
		async publicKeys() {
			return Object.freeze(publicKeys.map((value) => Object.freeze(
				value.expiresAt === undefined
					? {
						id: value.id,
						publicJwk: value.publicJwk,
						createdAt: new Date(value.createdAt),
					}
					: {
						id: value.id,
						publicJwk: value.publicJwk,
						createdAt: new Date(value.createdAt),
						expiresAt: new Date(value.expiresAt),
					},
			)));
		},
		async readiness(): Promise<KeyProviderReadiness> {
			return Object.freeze({
				ready: true,
				kind: "local",
				providerRef: redactedKeyReference(providerId),
				currentKeyRef: redactedKeyReference(currentKeyReference),
				keys: Object.freeze([
					Object.freeze({
						role: "current" as const,
						keyRef: redactedKeyReference(currentKeyReference),
						status: "ready" as const,
					}),
					...retained.map(({ key }) => Object.freeze({
						role: "retained" as const,
						keyRef: redactedKeyReference(key.keyReference),
						status: "ready" as const,
					})),
				]),
				reasons: Object.freeze([]),
			});
		},
	};
	return Object.freeze(provider);
}
