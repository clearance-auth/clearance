export const KEY_PURPOSES = Object.freeze([
	"oidc-client-secret",
	"scim-bearer-token",
	"access-token-signing-key",
] as const);

export type KeyPurpose = (typeof KEY_PURPOSES)[number];
export type KeyProviderKind = "local" | "aws-kms" | "gcp-kms";

export type KeyContext = Readonly<{
	projectId: string;
	environmentId: string;
	resourceId: string;
}>;

export type KeyProviderKeyStatus = Readonly<{
	role: "current" | "retained";
	keyRef: string;
	status: "ready" | "unavailable" | "invalid";
}>;

export type KeyProviderReadinessReason =
	| "CURRENT_KEY_UNAVAILABLE"
	| "RETAINED_KEY_UNAVAILABLE"
	| "KEY_CONFIGURATION_INVALID"
	| "PROVIDER_UNAVAILABLE";

export type KeyProviderReadiness = Readonly<{
	ready: boolean;
	kind: KeyProviderKind;
	providerRef: string;
	currentKeyRef: string;
	keys: readonly KeyProviderKeyStatus[];
	reasons: readonly KeyProviderReadinessReason[];
}>;

export interface KeyEncryptionProvider {
	readonly kind: KeyProviderKind;
	readonly providerId: string;
	readonly purpose: KeyPurpose;
	readonly currentKeyId: string;
	readonly retainedKeyIds: readonly string[];
	seal(
		plaintext: Uint8Array,
		context: KeyContext,
	): Promise<string>;
	open(
		envelope: string,
		context: KeyContext,
	): Promise<Uint8Array>;
	readiness(): Promise<KeyProviderReadiness>;
}

export type PurposeKeyProviders = Readonly<Record<KeyPurpose, KeyEncryptionProvider>>;
