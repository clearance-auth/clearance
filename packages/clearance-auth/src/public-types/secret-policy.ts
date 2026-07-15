export declare const MINIMUM_SECRET_LENGTH = 16;
export declare const FORBIDDEN_DEFAULT_SECRETS: readonly string[];
export declare function isForbiddenDefaultSecret(
	secret: string | null | undefined,
): boolean;
