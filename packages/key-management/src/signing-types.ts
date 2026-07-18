import type {
	KeyProviderKind,
	KeyProviderReadiness,
} from "./types.js";

export const ACCESS_TOKEN_SIGNING_ALGORITHM = "ES256" as const;

export type Es256PublicJwk = Readonly<{
	kty: "EC";
	crv: "P-256";
	x: string;
	y: string;
	alg: "ES256";
	use: "sig";
	kid: string;
}>;

export type SigningPublicKey = Readonly<{
	id: string;
	publicJwk: Es256PublicJwk;
	createdAt: Date;
	expiresAt?: Date;
}>;

export type RetainedSigningKey = Readonly<{
	keyReference: string;
	retiredAt: Date;
}>;

/**
 * Provider-neutral ES256 signing. Cloud key references remain provider-private;
 * JWT `kid` values and readiness surfaces use stable hashed identifiers.
 */
export interface KeySigningProvider {
	readonly kind: KeyProviderKind;
	readonly providerId: string;
	readonly purpose: "access-token-signing-key";
	readonly algorithm: typeof ACCESS_TOKEN_SIGNING_ALGORITHM;
	readonly currentKeyId: string;
	readonly retainedKeyIds: readonly string[];
	sign(signingInput: Uint8Array): Promise<Uint8Array>;
	publicKeys(): Promise<readonly SigningPublicKey[]>;
	readiness(): Promise<KeyProviderReadiness>;
}
