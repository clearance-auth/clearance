import { generateId } from "@clearance/core/utils/id";
import { createHash } from "@clearance/utils/hash";

export const SESSION_CREDENTIAL_MODEL = "sessionCredential";
export const SESSION_CREDENTIAL_DIGEST_VERSION = 1;
export const SESSION_REFRESH_PREFIX = "clr_rt_";
export const SESSION_HANDLE_PREFIX = "clr_sid_";
export const SESSION_ROTATION_RECOVERY_WINDOW_MS = 30_000;
const SESSION_CREDENTIAL_DIGEST_DOMAIN = "clearance:session-refresh:v1:";
const SESSION_ROTATION_NONCE_DIGEST_DOMAIN =
	"clearance:session-rotation-nonce:v1:";

export type SessionCredentialStatus = "active" | "consumed" | "revoked";

export type SessionCredential = {
	id: string;
	selector: string;
	sessionId?: string | null;
	familyId: string;
	secretDigest: string;
	digestVersion: number;
	status: SessionCredentialStatus;
	rotationCounter: number;
	parentCredentialId?: string | null;
	expiresAt: Date;
	consumedAt?: Date | null;
	revokedAt?: Date | null;
	reuseDetectedAt?: Date | null;
	rotationNonceDigest?: string | null;
	recoverySecretCiphertext?: string | null;
	recoveryExpiresAt?: Date | null;
	createdAt: Date;
	updatedAt: Date;
};

export function createSessionRefreshSecret(
	credentialId: string,
	secretMaterial = generateId(48),
): string {
	// `.` is reserved by the signed-cookie wire format, so the selector and
	// secret use a cookie-safe delimiter that cannot be confused with the HMAC.
	return `${SESSION_REFRESH_PREFIX}${credentialId}~${secretMaterial}`;
}

export function createSessionHandle(sessionId: string): string {
	return `${SESSION_HANDLE_PREFIX}${sessionId}`;
}

export function sessionIdFromHandle(value: unknown): string | null {
	if (typeof value !== "string" || !value.startsWith(SESSION_HANDLE_PREFIX)) {
		return null;
	}
	const sessionId = value.slice(SESSION_HANDLE_PREFIX.length);
	return sessionId.length > 0 ? sessionId : null;
}

export async function digestSessionRefreshSecret(secret: string): Promise<string> {
	const digest = await createHash("SHA-256", "base64urlnopad").digest(
		`${SESSION_CREDENTIAL_DIGEST_DOMAIN}${secret}`,
	);
	return `v${SESSION_CREDENTIAL_DIGEST_VERSION}:${digest}`;
}

export async function digestSessionRotationNonce(nonce: string): Promise<string> {
	const digest = await createHash("SHA-256", "base64urlnopad").digest(
		`${SESSION_ROTATION_NONCE_DIGEST_DOMAIN}${nonce}`,
	);
	return `v1:${digest}`;
}

export function credentialIdFromRefreshSecret(value: unknown): string | null {
	if (typeof value !== "string" || !value.startsWith(SESSION_REFRESH_PREFIX)) {
		return null;
	}
	const separator = value.indexOf("~", SESSION_REFRESH_PREFIX.length);
	if (separator === -1) return null;
	const credentialId = value.slice(SESSION_REFRESH_PREFIX.length, separator);
	return credentialId.length > 0 ? credentialId : null;
}

export function isSessionRefreshSecret(value: string): boolean {
	return value.startsWith(SESSION_REFRESH_PREFIX);
}
