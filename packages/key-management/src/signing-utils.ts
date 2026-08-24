import { createHash } from "node:crypto";
import { KeyManagementError } from "./error.js";
import type {
	Es256PublicJwk,
	KeySigningProvider,
} from "./signing-types.js";

const MAX_SIGNING_INPUT_BYTES = 32_768;
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]+$/;
const CRC32C_POLYNOMIAL = 0x82f63b78;

const CRC32C_TABLE = Object.freeze(
	Array.from({ length: 256 }, (_, index) => {
		let value = index;
		for (let bit = 0; bit < 8; bit += 1) {
			value = (value & 1) === 1
				? (value >>> 1) ^ CRC32C_POLYNOMIAL
				: value >>> 1;
		}
		return value >>> 0;
	}),
);

function signingFailure(message: string): KeyManagementError {
	return new KeyManagementError("KEY_OPERATION_FAILED", message);
}

export function signingKeyId(providerId: string, keyReference: string): string {
	return `${providerId}:${createHash("sha256").update(keyReference).digest("hex")}`;
}

/** Castagnoli CRC32C used by Google Cloud KMS request and response integrity fields. */
export function crc32c(input: Uint8Array): number {
	let checksum = 0xffffffff;
	for (const byte of input) {
		checksum =
			(checksum >>> 8) ^ CRC32C_TABLE[(checksum ^ byte) & 0xff]!;
	}
	return (checksum ^ 0xffffffff) >>> 0;
}

export function crc32cMatches(value: unknown, input: Uint8Array): boolean {
	let parsed: number;
	if (typeof value === "number") {
		parsed = value;
	} else if (typeof value === "string" && /^[0-9]+$/.test(value)) {
		parsed = Number(value);
	} else if (
		value &&
		typeof value === "object" &&
		"value" in value
	) {
		return crc32cMatches((value as { value: unknown }).value, input);
	} else if (
		value &&
		typeof value === "object" &&
		typeof (value as { toString?: unknown }).toString === "function"
	) {
		const text = (value as { toString(): string }).toString();
		if (!/^[0-9]+$/.test(text)) return false;
		parsed = Number(text);
	} else {
		return false;
	}
	return (
		Number.isSafeInteger(parsed) &&
		parsed >= 0 &&
		parsed <= 0xffffffff &&
		parsed === crc32c(input)
	);
}

function coordinate(value: unknown, label: string): string {
	if (typeof value !== "string" || !CANONICAL_BASE64URL.test(value)) {
		throw new KeyManagementError("KEY_INPUT_INVALID", `${label} is invalid`);
	}
	const bytes = Buffer.from(value, "base64url");
	if (bytes.length !== 32 || bytes.toString("base64url") !== value) {
		throw new KeyManagementError("KEY_INPUT_INVALID", `${label} is invalid`);
	}
	return value;
}

export function es256PublicJwk(
	value: unknown,
	kid: string,
): Es256PublicJwk {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new KeyManagementError("KEY_INPUT_INVALID", "ES256 public key is invalid");
	}
	const input = value as Record<string, unknown>;
	if (input.kty !== "EC" || input.crv !== "P-256") {
		throw new KeyManagementError("KEY_INPUT_INVALID", "ES256 public key is invalid");
	}
	return Object.freeze({
		kty: "EC",
		crv: "P-256",
		x: coordinate(input.x, "ES256 x coordinate"),
		y: coordinate(input.y, "ES256 y coordinate"),
		alg: "ES256",
		use: "sig",
		kid,
	});
}

function readDerLength(input: Uint8Array, offset: number): [number, number] {
	const first = input[offset];
	if (first === undefined) throw signingFailure("ECDSA signature is invalid");
	if (first < 0x80) return [first, offset + 1];
	const count = first & 0x7f;
	if (count < 1 || count > 2 || offset + count >= input.length) {
		throw signingFailure("ECDSA signature is invalid");
	}
	let length = 0;
	for (let index = 0; index < count; index += 1) {
		length = (length << 8) | input[offset + 1 + index]!;
	}
	if (length < 0x80) throw signingFailure("ECDSA signature is invalid");
	return [length, offset + 1 + count];
}

function readDerInteger(input: Uint8Array, offset: number): [Buffer, number] {
	if (input[offset] !== 0x02) throw signingFailure("ECDSA signature is invalid");
	const [length, start] = readDerLength(input, offset + 1);
	const end = start + length;
	if (length < 1 || end > input.length) {
		throw signingFailure("ECDSA signature is invalid");
	}
	let value = Buffer.from(input.subarray(start, end));
	if ((value[0]! & 0x80) !== 0) throw signingFailure("ECDSA signature is invalid");
	if (value.length > 1 && value[0] === 0) {
		if ((value[1]! & 0x80) === 0) throw signingFailure("ECDSA signature is invalid");
		value = value.subarray(1);
	}
	if (value.length > 32) throw signingFailure("ECDSA signature is invalid");
	return [Buffer.concat([Buffer.alloc(32 - value.length), value]), end];
}

/** Convert canonical ASN.1 DER ECDSA into the 64-byte JOSE/P1363 form. */
export function derEs256ToJose(signature: Uint8Array): Uint8Array {
	if (!(signature instanceof Uint8Array) || signature.length < 8 || signature[0] !== 0x30) {
		throw signingFailure("ECDSA signature is invalid");
	}
	const [sequenceLength, sequenceStart] = readDerLength(signature, 1);
	if (sequenceStart + sequenceLength !== signature.length) {
		throw signingFailure("ECDSA signature is invalid");
	}
	const [r, afterR] = readDerInteger(signature, sequenceStart);
	const [s, afterS] = readDerInteger(signature, afterR);
	if (afterS !== signature.length) throw signingFailure("ECDSA signature is invalid");
	return new Uint8Array(Buffer.concat([r, s]));
}

export function validateSigningInput(input: Uint8Array): Uint8Array {
	if (
		!(input instanceof Uint8Array) ||
		input.length === 0 ||
		input.length > MAX_SIGNING_INPUT_BYTES
	) {
		throw new KeyManagementError("KEY_INPUT_INVALID", "Signing input size is invalid");
	}
	return input;
}

function encodeJson(value: unknown): string {
	return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

export async function signJwtPayload(
	provider: KeySigningProvider,
	payload: Readonly<Record<string, unknown>>,
): Promise<string> {
	if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
		throw new KeyManagementError("KEY_INPUT_INVALID", "JWT payload is invalid");
	}
	const header = encodeJson({
		alg: "ES256",
		kid: provider.currentKeyId,
		typ: "JWT",
	});
	const body = encodeJson(payload);
	const signingInput = Buffer.from(`${header}.${body}`, "ascii");
	let signature: Uint8Array;
	try {
		signature = await provider.sign(signingInput);
	} catch (error) {
		if (error instanceof KeyManagementError) throw error;
		throw signingFailure("JWT signing failed");
	}
	if (!(signature instanceof Uint8Array) || signature.length !== 64) {
		throw signingFailure("JWT signing failed");
	}
	return `${header}.${body}.${Buffer.from(signature).toString("base64url")}`;
}
