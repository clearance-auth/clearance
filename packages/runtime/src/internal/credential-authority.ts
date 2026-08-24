type InternalCredentialAuthorityConfig = {
	generation: "legacy-v1" | "digest-v1";
	migrationDrainId?: string;
};

const internalCredentialAuthorities = new WeakMap<
	object,
	Readonly<InternalCredentialAuthorityConfig>
>();

export function attachInternalCredentialAuthority<Target extends object>(
	target: Target,
	config: InternalCredentialAuthorityConfig,
): Target {
	internalCredentialAuthorities.set(target, Object.freeze({ ...config }));
	return target;
}

export function readInternalCredentialAuthority(
	target: object,
): InternalCredentialAuthorityConfig | undefined {
	return internalCredentialAuthorities.get(target);
}
