/**
 * Production secret policy for control plane and auth runtime.
 */
import {
	FORBIDDEN_DEFAULT_SECRETS,
	MINIMUM_SECRET_LENGTH,
	isForbiddenDefaultSecret,
} from "@clearance/auth/secret-policy";

export {
	FORBIDDEN_DEFAULT_SECRETS,
	MINIMUM_SECRET_LENGTH,
	isForbiddenDefaultSecret,
};

export function assertProductionSecret(
	secret: string | undefined,
	label = "CLEARANCE_SECRET",
): void {
	const nodeEnv = process.env.NODE_ENV ?? "development";
	if (nodeEnv !== "production") return;
	if (isForbiddenDefaultSecret(secret)) {
		throw new Error(
			`Production refuses default/weak ${label}. Set a strong random secret (openssl rand -base64 32).`,
		);
	}
}

export function requireOperatorToken(): string {
	const token =
		process.env.CLEARANCE_OPERATOR_TOKEN ?? process.env.CLEARANCE_API_TOKEN;
	if (!token || token.length < MINIMUM_SECRET_LENGTH) {
		throw new Error(
			"CLEARANCE_OPERATOR_TOKEN (or CLEARANCE_API_TOKEN) required (≥16 chars) for management API",
		);
	}
	const nodeEnv = process.env.NODE_ENV ?? "development";
	if (nodeEnv === "production" && isForbiddenDefaultSecret(token)) {
		throw new Error("Production refuses default CLEARANCE_OPERATOR_TOKEN");
	}
	return token;
}

/**
 * Production startup guard for credential encryption key material.
 * Call from management API / console when NODE_ENV=production.
 */
export function assertProductionCredentialKey(
	env: NodeJS.ProcessEnv = process.env,
): void {
	const nodeEnv = env.NODE_ENV ?? "development";
	if (nodeEnv !== "production" && env.CLEARANCE_STRICT_SECRETS !== "1") {
		return;
	}
	const key =
		env.CLEARANCE_CREDENTIAL_KEY?.trim() ||
		env.CLEARANCE_CREDENTIALS_KEY?.trim();
	const keyId =
		env.CLEARANCE_CREDENTIAL_KEY_ID?.trim() ||
		env.CLEARANCE_CREDENTIALS_KEY_ID?.trim();
	if (!key || !keyId) {
		throw new Error(
			"Production requires CLEARANCE_CREDENTIAL_KEY and CLEARANCE_CREDENTIAL_KEY_ID",
		);
	}
	if (isForbiddenDefaultSecret(key)) {
		throw new Error("Production refuses default/weak CLEARANCE_CREDENTIAL_KEY");
	}
}

export function parseCorsOrigins(): string[] {
	const raw =
		process.env.CLEARANCE_CORS_ORIGINS ??
		process.env.CLEARANCE_CONSOLE_URL ??
		"http://localhost:3100";
	return raw
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean);
}
