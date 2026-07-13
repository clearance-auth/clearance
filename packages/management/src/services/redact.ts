/**
 * Secret redaction for audit events, traces, and persisted JSON.
 * Never persist raw secrets, tokens, or passwords in control-plane storage.
 */
import type {
	DirectoryConnection,
	IdentityConnection,
} from "../types/resources.js";

const SENSITIVE_KEY =
	/(secret|password|token|authorization|bearer|client_secret|private_key|api[_-]?key|credential|encrypted)/i;

const SENSITIVE_VALUE =
	/^(sk_|pk_|scimtok_|Bearer\s+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|clr\$v1\$)/i;

export function redactValue(value: unknown, keyHint = ""): unknown {
	if (value == null) return value;
	if (typeof value === "string") {
		if (SENSITIVE_KEY.test(keyHint) || SENSITIVE_VALUE.test(value)) {
			return "[redacted]";
		}
		return value;
	}
	if (Array.isArray(value)) {
		return value.map((v, i) => redactValue(v, `${keyHint}[${i}]`));
	}
	if (typeof value === "object") {
		return redactRecord(value as Record<string, unknown>);
	}
	return value;
}

export function redactRecord(
	input: Record<string, unknown> | undefined | null,
): Record<string, unknown> | undefined {
	if (!input) return undefined;
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(input)) {
		if (SENSITIVE_KEY.test(k)) {
			out[k] = "[redacted]";
			continue;
		}
		out[k] = redactValue(v, k);
	}
	return out;
}

/** Keys that must never appear on connection/audit records */
export const WRITE_ONLY_SECRET_FIELDS = [
	"clientSecret",
	"bearerToken",
	"password",
	"token",
	"_token",
	"scimToken",
	"clientSecretEncrypted",
	"bearerTokenEncrypted",
] as const;

/** Public domain view of SSO connection — encrypted material stripped. */
export function publicIdentityConnection(
	conn: IdentityConnection,
): Omit<IdentityConnection, "clientSecretEncrypted" | "clientSecretKeyId"> & {
	hasClientSecret: boolean;
} {
	const {
		clientSecretEncrypted: _e,
		clientSecretKeyId: _k,
		...rest
	} = conn;
	return {
		...rest,
		hasClientSecret: Boolean(conn.clientSecretFingerprint || _e),
	};
}

/** Public domain view of SCIM connection — encrypted material stripped. */
export function publicDirectoryConnection(
	conn: DirectoryConnection,
): Omit<
	DirectoryConnection,
	"bearerTokenEncrypted" | "bearerTokenKeyId"
> & { hasBearerToken: boolean } {
	const { bearerTokenEncrypted: _e, bearerTokenKeyId: _k, ...rest } = conn;
	return {
		...rest,
		hasBearerToken: Boolean(conn.bearerTokenFingerprint || _e),
	};
}
