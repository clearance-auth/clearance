export const MINIMUM_SECRET_LENGTH = 16;

/** Known-insecure product defaults that strict and production modes refuse. */
export const FORBIDDEN_DEFAULT_SECRETS = [
	"dev-secret-change-me",
	"dev-secret-change-me-please-32chars!!",
	"secret",
	"local-compose-secret-change-me-32",
	"test-secret-value-32-characters",
	"test-secret-value-that-is-long-enough",
	"test-secret-value-that-is-long-enough-32",
	"change-me",
	"password",
	"clearance",
	"clearance-secret",
] as const;

const FORBIDDEN_SECRET_FRAGMENTS = ["change-me", "dev-secret"] as const;
const FORBIDDEN_SECRET_SET = new Set(
	FORBIDDEN_DEFAULT_SECRETS.map((secret) => secret.toLowerCase()),
);

/** Deterministic, environment-independent default/weak-secret classification. */
export function isForbiddenDefaultSecret(
	secret: string | null | undefined,
): boolean {
	if (!secret) return true;
	const normalized = secret.trim().toLowerCase();
	if (normalized.length < MINIMUM_SECRET_LENGTH) return true;
	if (FORBIDDEN_SECRET_SET.has(normalized)) return true;
	return FORBIDDEN_SECRET_FRAGMENTS.some((fragment) =>
		normalized.includes(fragment)
	);
}
