import { base64Url } from "@clearance/utils/base64";

const CREDENTIAL_OPERATION_KEY_PREFIX = "clr_op_v1_";
const CREDENTIAL_OPERATION_KEY_BYTES = 32;
const CREDENTIAL_OPERATION_KEY_PAYLOAD_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function isDegenerateCredentialOperationKeyPayload(payload: Uint8Array): boolean {
	return (
		payload.every((byte) => byte === 0) ||
		payload.every((byte, index) => byte === index)
	);
}

export const CREDENTIAL_OPERATION_KEY_REQUIREMENT =
	"Idempotency-Key must use clr_op_v1_<43 canonical base64url characters> (a versioned 256-bit opaque operation token)";

export function generateCredentialOperationKey(): string {
	const payload = base64Url.encode(
		crypto.getRandomValues(new Uint8Array(CREDENTIAL_OPERATION_KEY_BYTES)),
		{ padding: false },
	);
	return `${CREDENTIAL_OPERATION_KEY_PREFIX}${payload}`;
}

/**
 * Enforces the versioned credential-operation token syntax and canonical
 * encoding. This parser intentionally makes no claim about how caller-supplied
 * payload bytes were generated; callers use generateCredentialOperationKey()
 * when they need a CSPRNG-backed key.
 *
 * The fixed version and 256-bit payload contract also rejects legacy UUIDs,
 * unversioned base64url values, and shorter structured vectors.
 */
export function parseCredentialOperationKey(value: unknown): string | null {
	if (typeof value !== "string") return null;
	if (!value.startsWith(CREDENTIAL_OPERATION_KEY_PREFIX)) return null;
	const payload = value.slice(CREDENTIAL_OPERATION_KEY_PREFIX.length);
	if (!CREDENTIAL_OPERATION_KEY_PAYLOAD_PATTERN.test(payload)) return null;

	let decoded: Uint8Array;
	try {
		decoded = base64Url.decode(payload);
	} catch {
		return null;
	}
	if (
		decoded.byteLength !== CREDENTIAL_OPERATION_KEY_BYTES ||
		base64Url.encode(new Uint8Array(decoded).buffer, { padding: false }) !== payload
	) {
		return null;
	}
	if (isDegenerateCredentialOperationKeyPayload(decoded)) return null;

	return value;
}
