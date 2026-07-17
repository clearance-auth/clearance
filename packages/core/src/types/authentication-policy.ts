import type { DBTransactionAdapter } from "../db/adapter";

export type AuthenticationAssuranceLevel =
	"single_factor" | "multi_factor" | "phishing_resistant";

export type AuthenticationPrimaryMethod =
	| "password"
	| "password_enrollment"
	| "federated"
	| "email_link"
	| "email_otp"
	| "phone_otp"
	| "wallet_signature"
	| "passkey"
	| "anonymous"
	| "admin_impersonation";

export type AuthenticationFactorMethod =
	"passkey" | "totp" | "otp" | "recovery_code";

export interface RuntimeAuthenticationPolicyIdentity {
	readonly projectId: string;
	readonly environmentId: string;
}

export interface RuntimeAuthenticationPolicy {
	readonly passwordLockout: Readonly<{
		enabled: boolean;
		maxFailedAttempts: number;
		durationSeconds: number;
	}>;
	readonly factorLockout: Readonly<{
		enabled: boolean;
		maxFailedAttempts: number;
		durationSeconds: number;
	}>;
	readonly minimumAssurance: AuthenticationAssuranceLevel;
	readonly allowedFactors: Readonly<{
		totp: boolean;
		passkey: boolean;
	}>;
	readonly trustedDevice: Readonly<{
		enabled: boolean;
		maxAgeSeconds: number;
	}>;
	readonly assuranceMaxAgeSeconds: number | null;
}

export interface RuntimeAuthenticationPolicyOverride {
	readonly passwordLockout?: Readonly<{
		readonly enabled?: boolean;
		readonly maxFailedAttempts?: number;
		readonly durationSeconds?: number;
	}>;
	readonly factorLockout?: Readonly<{
		readonly enabled?: boolean;
		readonly maxFailedAttempts?: number;
		readonly durationSeconds?: number;
	}>;
	readonly minimumAssurance?: AuthenticationAssuranceLevel;
	readonly allowedFactors?: Readonly<{
		readonly totp?: boolean;
		readonly passkey?: boolean;
	}>;
	readonly trustedDevice?: Readonly<{
		readonly enabled?: boolean;
		readonly maxAgeSeconds?: number;
	}>;
	readonly assuranceMaxAgeSeconds?: number | null;
}

export interface RuntimeAuthenticationPolicyReaderInput {
	readonly subjectId: string;
	readonly organizationId?: string;
	readonly minimumRevision?: string;
	readonly transaction?: DBTransactionAdapter;
}

export interface RuntimeAuthenticationPolicyReaderResult {
	readonly scope: RuntimeAuthenticationPolicyIdentity;
	readonly subjectId: string;
	readonly revision: string;
	readonly environment: RuntimeAuthenticationPolicy;
	readonly organizationMembership: Readonly<{
		subjectId: string;
		organizationId: string;
	}> | null;
	readonly organizationOverride: Readonly<{
		scope: RuntimeAuthenticationPolicyIdentity;
		organizationId: string;
		revision: string;
		policy: RuntimeAuthenticationPolicyOverride;
	}> | null;
	readonly effective: RuntimeAuthenticationPolicy;
}

export interface RuntimeAuthenticationPolicyReader {
	/**
	 * Perform an uncached authoritative policy read. When `organizationId` is
	 * present, the returned membership attestation and organization override
	 * must be resolved for that subject and organization in the same read.
	 */
	readForSubject(
		input: RuntimeAuthenticationPolicyReaderInput,
	): Promise<RuntimeAuthenticationPolicyReaderResult>;
}

export type VerifiedAuthenticationEvidence =
	| Readonly<{
			kind: "primary";
			primaryMethod: AuthenticationPrimaryMethod;
	  }>
	| Readonly<{
			kind: "factor";
			factorMethod: AuthenticationFactorMethod;
	  }>;

export type RuntimeAuthenticationSessionField =
	| "authenticationAssuranceVersion"
	| "authenticationPolicyProjectId"
	| "authenticationPolicyEnvironmentId"
	| "authenticationPrimaryMethod"
	| "authenticationPrimaryAt"
	| "authenticationFactorMethod"
	| "authenticationFactorAt"
	| "authenticationPolicyOrganizationId"
	| "authenticationPolicyRevision"
	| "authenticationAssuranceExpiresAt"
	| "authenticationRecoveryRestricted";

/** Prevents generic session mutation inputs from accepting runtime authority. */
export type RuntimeAuthenticationSessionMutationGuard = Readonly<{
	[Field in RuntimeAuthenticationSessionField]?: never;
}>;

declare const sessionIssuanceContextBrand: unique symbol;

type BrandedSessionIssuanceContext = Readonly<{
	[sessionIssuanceContextBrand]: true;
}>;

export type SessionIssuanceContext = (
	| Readonly<{
			purpose: "interactive";
			evidence: readonly VerifiedAuthenticationEvidence[];
			targetOrganizationId?: string | null;
	  }>
	| Readonly<{
			purpose: "impersonation";
			evidence: readonly VerifiedAuthenticationEvidence[];
			targetOrganizationId?: string | null;
	  }>
	| Readonly<{
			purpose: "replacement";
			sourceSessionToken: string;
			targetOrganizationId?: string | null;
	  }>
	| Readonly<{
			purpose: "device";
			sourceSessionToken: string;
			targetOrganizationId?: string | null;
	  }>
	| Readonly<{
			/**
			 * A one-use, transaction-bound successor authority for changing the
			 * active organization. Only the runtime capture API can mint this.
			 */
			purpose: "organization";
			sourceSessionToken: string;
			targetOrganizationId?: string | null;
	  }>
) &
	BrandedSessionIssuanceContext;

declare const verificationChallengeCreationContextBrand: unique symbol;
declare const verificationChallengeConsumptionContextBrand: unique symbol;

/** Opaque runtime provenance for a managed verification challenge creation. */
export type VerificationChallengeCreationContext = Readonly<{
	[verificationChallengeCreationContextBrand]: true;
}>;

/** Opaque runtime provenance for a managed verification challenge consumption. */
export type VerificationChallengeConsumptionContext = Readonly<{
	[verificationChallengeConsumptionContextBrand]: true;
}>;
