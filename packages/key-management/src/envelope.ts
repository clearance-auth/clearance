import { KeyManagementError } from "./error.js";
import { KEY_PURPOSES, type KeyContext, type KeyProviderKind, type KeyPurpose } from "./types.js";

const ENVELOPE_PREFIX = "clrkm$v1$";
const MAX_ENVELOPE_BYTES = 65_536;
const MAX_CIPHERTEXT_CHARACTERS = 49_152;
const MAX_ID_CHARACTERS = 512;
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]+$/;

export type KeyEnvelopePayload = Readonly<{
	v: 1;
	provider: KeyProviderKind;
	providerId: string;
	keyId: string;
	purpose: KeyPurpose;
	projectId: string;
	environmentId: string;
	resourceId: string;
	ciphertext: string;
}>;

function assertIdentifier(value: unknown, label: string): asserts value is string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > MAX_ID_CHARACTERS ||
		value.trim() !== value ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		throw new KeyManagementError("KEY_CONTEXT_INVALID", `${label} is invalid`);
	}
}

export function validateKeyContext(context: KeyContext): KeyContext {
	if (!context || typeof context !== "object" || Array.isArray(context)) {
		throw new KeyManagementError("KEY_CONTEXT_INVALID", "Key context is invalid");
	}
	assertIdentifier(context.projectId, "projectId");
	assertIdentifier(context.environmentId, "environmentId");
	assertIdentifier(context.resourceId, "resourceId");
	return Object.freeze({
		projectId: context.projectId,
		environmentId: context.environmentId,
		resourceId: context.resourceId,
	});
}

export function validateProviderIdentifier(value: string, label: string): string {
	assertIdentifier(value, label);
	return value;
}

export function validateKeyPurpose(value: unknown): KeyPurpose {
	if (!KEY_PURPOSES.includes(value as KeyPurpose)) {
		throw new KeyManagementError("KEY_CONTEXT_INVALID", "Key purpose is invalid");
	}
	return value as KeyPurpose;
}

export function validateProviderKind(value: unknown): KeyProviderKind {
	if (value !== "local" && value !== "aws-kms" && value !== "gcp-kms") {
		throw new KeyManagementError("KEY_CONTEXT_INVALID", "Key provider kind is invalid");
	}
	return value;
}

function canonicalPayload(payload: KeyEnvelopePayload): string {
	return JSON.stringify({
		v: 1,
		provider: payload.provider,
		providerId: payload.providerId,
		keyId: payload.keyId,
		purpose: payload.purpose,
		projectId: payload.projectId,
		environmentId: payload.environmentId,
		resourceId: payload.resourceId,
		ciphertext: payload.ciphertext,
	});
}

export type KeyOperationAuthority = Readonly<{
	version: "1";
	provider: KeyProviderKind;
	providerId: string;
	keyId: string;
	purpose: KeyPurpose;
	projectId: string;
	environmentId: string;
	resourceId: string;
}>;

export function createKeyOperationAuthority(
	provider: KeyProviderKind,
	providerId: string,
	keyId: string,
	purpose: KeyPurpose,
	context: KeyContext,
): KeyOperationAuthority {
	const exact = validateKeyContext(context);
	validateProviderKind(provider);
	validateProviderIdentifier(providerId, "providerId");
	validateProviderIdentifier(keyId, "keyId");
	validateKeyPurpose(purpose);
	return Object.freeze({
		version: "1",
		provider,
		providerId,
		keyId,
		purpose,
		projectId: exact.projectId,
		environmentId: exact.environmentId,
		resourceId: exact.resourceId,
	});
}

export function keyOperationAad(authority: KeyOperationAuthority): Uint8Array {
	return Buffer.from(JSON.stringify(authority), "utf8");
}

export function keyOperationEncryptionContext(
	authority: KeyOperationAuthority,
): Readonly<Record<string, string>> {
	return Object.freeze({ ...authority });
}

export function formatKeyEnvelope(payload: KeyEnvelopePayload): string {
	validateProviderKind(payload.provider);
	validateProviderIdentifier(payload.providerId, "providerId");
	validateProviderIdentifier(payload.keyId, "keyId");
	validateKeyContext(payload);
	validateKeyPurpose(payload.purpose);
	if (
		typeof payload.ciphertext !== "string" ||
		payload.ciphertext.length === 0 ||
		payload.ciphertext.length > MAX_CIPHERTEXT_CHARACTERS ||
		!CANONICAL_BASE64URL.test(payload.ciphertext)
	) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key ciphertext is invalid");
	}
	const encoded = Buffer.from(canonicalPayload(payload), "utf8").toString("base64url");
	const envelope = `${ENVELOPE_PREFIX}${encoded}`;
	if (Buffer.byteLength(envelope, "utf8") > MAX_ENVELOPE_BYTES) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope is too large");
	}
	return envelope;
}

export function parseKeyEnvelope(envelope: string): KeyEnvelopePayload {
	if (
		typeof envelope !== "string" ||
		Buffer.byteLength(envelope, "utf8") > MAX_ENVELOPE_BYTES ||
		!envelope.startsWith(ENVELOPE_PREFIX)
	) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope is invalid");
	}
	const encoded = envelope.slice(ENVELOPE_PREFIX.length);
	if (!CANONICAL_BASE64URL.test(encoded)) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope encoding is invalid");
	}
	let decoded: string;
	let value: unknown;
	try {
		const bytes = Buffer.from(encoded, "base64url");
		if (bytes.toString("base64url") !== encoded) throw new Error("noncanonical");
		decoded = bytes.toString("utf8");
		value = JSON.parse(decoded);
	} catch {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope encoding is invalid");
	}
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope payload is invalid");
	}
	const record = value as Record<string, unknown>;
	const exactKeys = [
		"ciphertext", "environmentId", "keyId", "projectId", "provider",
		"providerId", "purpose", "resourceId", "v",
	].sort();
	if (Object.keys(record).sort().join("\u0000") !== exactKeys.join("\u0000")) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope fields are invalid");
	}
	if (
		record.v !== 1 ||
		!(["local", "aws-kms", "gcp-kms"] as unknown[]).includes(record.provider) ||
		!KEY_PURPOSES.includes(record.purpose as KeyPurpose)
	) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope metadata is invalid");
	}
	try {
		validateProviderIdentifier(record.providerId as string, "providerId");
		validateProviderIdentifier(record.keyId as string, "keyId");
		validateKeyContext(record as unknown as KeyContext);
	} catch {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope context is invalid");
	}
	if (
		typeof record.ciphertext !== "string" ||
		record.ciphertext.length === 0 ||
		record.ciphertext.length > MAX_CIPHERTEXT_CHARACTERS ||
		!CANONICAL_BASE64URL.test(record.ciphertext)
	) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope ciphertext is invalid");
	}
	const payload = record as unknown as KeyEnvelopePayload;
	if (canonicalPayload(payload) !== decoded) {
		throw new KeyManagementError("KEY_ENVELOPE_INVALID", "Key envelope payload is not canonical");
	}
	return Object.freeze({ ...payload });
}

export function assertEnvelopeAuthority(
	payload: KeyEnvelopePayload,
	provider: KeyProviderKind,
	providerId: string,
	purpose: KeyPurpose,
	context: KeyContext,
): void {
	const exact = validateKeyContext(context);
	if (payload.provider !== provider || payload.providerId !== providerId) {
		throw new KeyManagementError("KEY_PROVIDER_MISMATCH", "Key envelope provider does not match");
	}
	if (
		payload.purpose !== purpose ||
		payload.projectId !== exact.projectId ||
		payload.environmentId !== exact.environmentId ||
		payload.resourceId !== exact.resourceId
	) {
		throw new KeyManagementError("KEY_CONTEXT_MISMATCH", "Key envelope authority does not match");
	}
}
