import type {
	AuthenticationAssuranceLevel,
	AuthenticationFactorMethod,
	AuthenticationPrimaryMethod,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
	RuntimeAuthenticationSessionField,
	VerifiedAuthenticationEvidence,
} from "@clearance/core";
import { normalizeRuntimeAuthenticationPolicy } from "../internal/authentication-policy";

export const SESSION_ASSURANCE_RESERVED_FIELDS = [
	"authenticationAssuranceVersion",
	"authenticationPolicyProjectId",
	"authenticationPolicyEnvironmentId",
	"authenticationPrimaryMethod",
	"authenticationPrimaryAt",
	"authenticationFactorMethod",
	"authenticationFactorAt",
	"authenticationPolicyOrganizationId",
	"authenticationPolicyRevision",
	"authenticationAssuranceExpiresAt",
	"authenticationRecoveryRestricted",
] as const satisfies readonly RuntimeAuthenticationSessionField[];

export type SessionAssuranceReservedField =
	(typeof SESSION_ASSURANCE_RESERVED_FIELDS)[number];

export interface SessionAssuranceFields {
	readonly authenticationAssuranceVersion: 1;
	readonly authenticationPolicyProjectId: string;
	readonly authenticationPolicyEnvironmentId: string;
	readonly authenticationPrimaryMethod: AuthenticationPrimaryMethod;
	readonly authenticationPrimaryAt: Date;
	readonly authenticationFactorMethod: AuthenticationFactorMethod | null;
	readonly authenticationFactorAt: Date | null;
	readonly authenticationPolicyOrganizationId: string | null;
	readonly authenticationPolicyRevision: string;
	readonly authenticationAssuranceExpiresAt: Date | null;
	readonly authenticationRecoveryRestricted: boolean;
}

const validatedAssurance = Symbol("validated-session-assurance");

type CanonicalAssuranceSnapshot = Readonly<{
	authenticationAssuranceVersion: 1;
	authenticationPolicyProjectId: string;
	authenticationPolicyEnvironmentId: string;
	authenticationPrimaryMethod: AuthenticationPrimaryMethod;
	authenticationPrimaryAtMs: number;
	authenticationFactorMethod: AuthenticationFactorMethod | null;
	authenticationFactorAtMs: number | null;
	authenticationPolicyOrganizationId: string | null;
	authenticationPolicyRevision: string;
	authenticationAssuranceExpiresAtMs: number | null;
	authenticationRecoveryRestricted: boolean;
}>;

const validatedAssuranceSnapshots = new WeakMap<
	object,
	CanonicalAssuranceSnapshot
>();

export type ValidatedSessionAssuranceFields = SessionAssuranceFields & {
	readonly [validatedAssurance]: true;
};

export interface SessionAssurancePolicySnapshot {
	readonly identity: RuntimeAuthenticationPolicyIdentity;
	readonly organizationId: string | null;
	readonly revision: string;
	readonly policy: RuntimeAuthenticationPolicy;
}

export type SessionAssuranceRequirementReason =
	| "invalid_policy"
	| "invalid_evidence"
	| "invalid_source_assurance"
	| "source_scope_mismatch"
	| "policy_revision_changed"
	| "primary_required"
	| "anonymous_not_allowed"
	| "impersonation_insufficient"
	| "trusted_device_not_allowed"
	| "factor_required"
	| "phishing_resistant_required"
	| "recovery_restricted"
	| "assurance_expired";

export interface SessionAssuranceRequirement {
	readonly reason: SessionAssuranceRequirementReason;
	readonly projectId: string;
	readonly environmentId: string;
	readonly organizationId: string | null;
	readonly revision: string;
	readonly minimumAssurance: AuthenticationAssuranceLevel;
	readonly allowedFactors: Readonly<{
		totp: boolean;
		passkey: boolean;
	}>;
}

export interface EvaluateSessionIssuanceInput {
	readonly purpose: "interactive" | "impersonation" | "replacement" | "device";
	readonly policy: SessionAssurancePolicySnapshot;
	readonly now: Date;
	readonly evidence: readonly VerifiedAuthenticationEvidence[];
	readonly sourceAssurance?: ValidatedSessionAssuranceFields | undefined;
}

export type EvaluateSessionIssuanceResult =
	| Readonly<{
			kind: "satisfied";
			fields: ValidatedSessionAssuranceFields;
	  }>
	| Readonly<{
			kind: "required";
			requirement: SessionAssuranceRequirement;
	  }>;

export type InvalidStoredSessionAssuranceReason =
	| "malformed_authority"
	| "unsupported_assurance_version"
	| "invalid_policy"
	| "policy_scope_mismatch"
	| "policy_organization_mismatch"
	| "live_revision_regressed"
	| "future_authentication_timestamp"
	| "forged_assurance_expiry";

export interface ValidateStoredSessionAssuranceInput {
	readonly stored: unknown;
	readonly policy: SessionAssurancePolicySnapshot;
	readonly now: Date;
}

export type ValidateStoredSessionAssuranceResult =
	| Readonly<{
			kind: "accepted";
			fields: ValidatedSessionAssuranceFields;
	  }>
	| Readonly<{
			kind: "required";
			requirement: SessionAssuranceRequirement;
	  }>
	| Readonly<{
			kind: "invalid";
			reason: InvalidStoredSessionAssuranceReason;
	  }>;

export interface DeriveReplacementEvidenceInput {
	readonly source: ValidatedSessionAssuranceFields;
	readonly freshEvidence: readonly VerifiedAuthenticationEvidence[];
	readonly now: Date;
}

export interface DerivedSessionAssuranceProof {
	readonly primaryMethod: AuthenticationPrimaryMethod | null;
	readonly primaryAt: Date | null;
	readonly factorMethod: AuthenticationFactorMethod | null;
	readonly factorAt: Date | null;
	readonly recoveryRestricted: boolean;
	readonly sourceAssuranceExpiresAt: Date | null;
}

const PRIMARY_METHODS = new Set<AuthenticationPrimaryMethod>([
	"password",
	"password_enrollment",
	"federated",
	"email_link",
	"email_otp",
	"phone_otp",
	"wallet_signature",
	"passkey",
	"anonymous",
	"admin_impersonation",
]);

const FACTOR_METHODS = new Set<AuthenticationFactorMethod>([
	"passkey",
	"totp",
	"otp",
	"recovery_code",
]);

const RESERVED_FIELD_SET = new Set<string>(SESSION_ASSURANCE_RESERVED_FIELDS);
const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;

type MutableProof = {
	primaryMethod: AuthenticationPrimaryMethod | null;
	primaryAt: Date | null;
	factorMethod: AuthenticationFactorMethod | null;
	factorAt: Date | null;
	recoveryRestricted: boolean;
	sourceAssuranceExpiresAt: Date | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
	return typeof value === "string" && value.length > 0;
}

function isCanonicalRevision(value: unknown): value is string {
	if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) return false;
	try {
		const parsed = BigInt(value);
		return parsed > 0n && parsed <= POSTGRES_BIGINT_MAX;
	} catch {
		return false;
	}
}

function compareRevisions(left: string, right: string): -1 | 0 | 1 {
	const leftRevision = BigInt(left);
	const rightRevision = BigInt(right);
	return leftRevision < rightRevision
		? -1
		: leftRevision > rightRevision
			? 1
			: 0;
}

function cloneDate(value: Date): Date {
	return new Date(value.getTime());
}

function parseDate(value: unknown): Date | null {
	if (!(value instanceof Date)) return null;
	const time = value.getTime();
	return Number.isFinite(time) ? new Date(time) : null;
}

function parseNullableDate(
	value: unknown,
): { valid: true; value: Date | null } | { valid: false } {
	if (value === null) return { valid: true, value: null };
	const parsed = parseDate(value);
	return parsed ? { valid: true, value: parsed } : { valid: false };
}

function isPrimaryMethod(value: unknown): value is AuthenticationPrimaryMethod {
	return (
		typeof value === "string" &&
		PRIMARY_METHODS.has(value as AuthenticationPrimaryMethod)
	);
}

function isFactorMethod(value: unknown): value is AuthenticationFactorMethod {
	return (
		typeof value === "string" &&
		FACTOR_METHODS.has(value as AuthenticationFactorMethod)
	);
}

function isIdentifier(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.length > 0 &&
		value.length <= 1_024 &&
		value.trim() === value &&
		!value.includes("\0")
	);
}

function normalizePolicySnapshot(
	snapshot: SessionAssurancePolicySnapshot,
): SessionAssurancePolicySnapshot | null {
	if (
		!isRecord(snapshot) ||
		!isRecord(snapshot.identity) ||
		!isIdentifier(snapshot.identity.projectId) ||
		!isIdentifier(snapshot.identity.environmentId) ||
		(snapshot.organizationId !== null &&
			!isIdentifier(snapshot.organizationId)) ||
		!isCanonicalRevision(snapshot.revision)
	) {
		return null;
	}
	try {
		return {
			identity: {
				projectId: snapshot.identity.projectId,
				environmentId: snapshot.identity.environmentId,
			},
			organizationId: snapshot.organizationId,
			revision: snapshot.revision,
			policy: normalizeRuntimeAuthenticationPolicy(snapshot.policy),
		};
	} catch {
		return null;
	}
}

function makeRequirement(
	policy: SessionAssurancePolicySnapshot,
	reason: SessionAssuranceRequirementReason,
): SessionAssuranceRequirement {
	return {
		reason,
		projectId: policy.identity.projectId,
		environmentId: policy.identity.environmentId,
		organizationId: policy.organizationId,
		revision: policy.revision,
		minimumAssurance: policy.policy.minimumAssurance,
		allowedFactors: {
			totp: policy.policy.allowedFactors.totp,
			passkey: policy.policy.allowedFactors.passkey,
		},
	};
}

function makeInvalidPolicyRequirement(
	policy: SessionAssurancePolicySnapshot,
): SessionAssuranceRequirement {
	const identity: Record<string, unknown> = isRecord(policy?.identity)
		? policy.identity
		: {};
	const rawPolicy: Record<string, unknown> = isRecord(policy?.policy)
		? policy.policy
		: {};
	const allowedFactors = isRecord(rawPolicy.allowedFactors)
		? rawPolicy.allowedFactors
		: ({} as Record<string, unknown>);
	const minimum = rawPolicy.minimumAssurance;
	return {
		reason: "invalid_policy",
		projectId: isNonEmptyString(identity.projectId) ? identity.projectId : "",
		environmentId: isNonEmptyString(identity.environmentId)
			? identity.environmentId
			: "",
		organizationId:
			policy?.organizationId === null ||
			isNonEmptyString(policy?.organizationId)
				? policy.organizationId
				: null,
		revision: isNonEmptyString(policy?.revision) ? policy.revision : "",
		minimumAssurance:
			minimum === "single_factor" ||
			minimum === "multi_factor" ||
			minimum === "phishing_resistant"
				? minimum
				: "phishing_resistant",
		allowedFactors: {
			totp: allowedFactors.totp === true,
			passkey: allowedFactors.passkey === true,
		},
	};
}

function required(
	policy: SessionAssurancePolicySnapshot,
	reason: SessionAssuranceRequirementReason,
): EvaluateSessionIssuanceResult {
	return { kind: "required", requirement: makeRequirement(policy, reason) };
}

function brandFields(
	fields: SessionAssuranceFields,
): ValidatedSessionAssuranceFields {
	const snapshot = Object.freeze<CanonicalAssuranceSnapshot>({
		authenticationAssuranceVersion: 1,
		authenticationPolicyProjectId: fields.authenticationPolicyProjectId,
		authenticationPolicyEnvironmentId: fields.authenticationPolicyEnvironmentId,
		authenticationPrimaryMethod: fields.authenticationPrimaryMethod,
		authenticationPrimaryAtMs: fields.authenticationPrimaryAt.getTime(),
		authenticationFactorMethod: fields.authenticationFactorMethod,
		authenticationFactorAtMs: fields.authenticationFactorAt?.getTime() ?? null,
		authenticationPolicyOrganizationId:
			fields.authenticationPolicyOrganizationId,
		authenticationPolicyRevision: fields.authenticationPolicyRevision,
		authenticationAssuranceExpiresAtMs:
			fields.authenticationAssuranceExpiresAt?.getTime() ?? null,
		authenticationRecoveryRestricted: fields.authenticationRecoveryRestricted,
	});
	const branded = {
		...fields,
		authenticationPrimaryAt: new Date(snapshot.authenticationPrimaryAtMs),
		authenticationFactorAt:
			snapshot.authenticationFactorAtMs === null
				? null
				: new Date(snapshot.authenticationFactorAtMs),
		authenticationAssuranceExpiresAt:
			snapshot.authenticationAssuranceExpiresAtMs === null
				? null
				: new Date(snapshot.authenticationAssuranceExpiresAtMs),
	} as SessionAssuranceFields & {
		[validatedAssurance]?: true;
	};
	Object.defineProperty(branded, validatedAssurance, {
		value: true,
		enumerable: false,
		writable: false,
		configurable: false,
	});
	validatedAssuranceSnapshots.set(branded, snapshot);
	return branded as ValidatedSessionAssuranceFields;
}

function getValidatedAssurance(value: unknown): SessionAssuranceFields | null {
	if (!isRecord(value)) return null;
	const snapshot = validatedAssuranceSnapshots.get(value);
	if (!snapshot) return null;
	return {
		authenticationAssuranceVersion: 1,
		authenticationPolicyProjectId: snapshot.authenticationPolicyProjectId,
		authenticationPolicyEnvironmentId:
			snapshot.authenticationPolicyEnvironmentId,
		authenticationPrimaryMethod: snapshot.authenticationPrimaryMethod,
		authenticationPrimaryAt: new Date(snapshot.authenticationPrimaryAtMs),
		authenticationFactorMethod: snapshot.authenticationFactorMethod,
		authenticationFactorAt:
			snapshot.authenticationFactorAtMs === null
				? null
				: new Date(snapshot.authenticationFactorAtMs),
		authenticationPolicyOrganizationId:
			snapshot.authenticationPolicyOrganizationId,
		authenticationPolicyRevision: snapshot.authenticationPolicyRevision,
		authenticationAssuranceExpiresAt:
			snapshot.authenticationAssuranceExpiresAtMs === null
				? null
				: new Date(snapshot.authenticationAssuranceExpiresAtMs),
		authenticationRecoveryRestricted: snapshot.authenticationRecoveryRestricted,
	};
}

function factorStrength(method: AuthenticationFactorMethod): number {
	switch (method) {
		case "passkey":
			return 4;
		case "totp":
			return 3;
		case "otp":
			return 2;
		case "recovery_code":
			return 1;
	}
}

function applyEvidence(
	proof: MutableProof,
	evidence: readonly VerifiedAuthenticationEvidence[],
	now: Date,
): boolean {
	for (const item of evidence as readonly unknown[]) {
		if (
			!isRecord(item) ||
			(item.kind !== "primary" && item.kind !== "factor")
		) {
			return false;
		}

		if (item.kind === "primary") {
			if (!isPrimaryMethod(item.primaryMethod)) return false;
			const method = item.primaryMethod;
			if (method === "admin_impersonation") return false;
			const upgradesToPasskey =
				method === "passkey" &&
				proof.primaryMethod !== null &&
				proof.primaryMethod !== "passkey";
			if (
				proof.primaryMethod === null ||
				proof.primaryMethod === "anonymous" ||
				(method === "passkey" && proof.primaryMethod !== "passkey")
			) {
				proof.primaryMethod = method;
				proof.primaryAt = cloneDate(now);
				if (upgradesToPasskey) {
					proof.factorMethod = null;
					proof.factorAt = null;
				}
			}
			continue;
		}

		if (!isFactorMethod(item.factorMethod)) return false;
		const method = item.factorMethod;
		if (method === "recovery_code") proof.recoveryRestricted = true;
		if (proof.factorMethod === method) continue;
		if (
			proof.factorMethod === null ||
			factorStrength(method) > factorStrength(proof.factorMethod)
		) {
			proof.factorMethod = method;
			proof.factorAt = cloneDate(now);
		}
	}
	return true;
}

export function deriveReplacementEvidence(
	input: DeriveReplacementEvidenceInput,
): DerivedSessionAssuranceProof | null {
	const source = getValidatedAssurance(input.source);
	if (!source || !parseDate(input.now)) return null;
	const proof: MutableProof = {
		primaryMethod: source.authenticationPrimaryMethod,
		primaryAt: cloneDate(source.authenticationPrimaryAt),
		factorMethod: source.authenticationFactorMethod,
		factorAt: source.authenticationFactorAt
			? cloneDate(source.authenticationFactorAt)
			: null,
		recoveryRestricted: source.authenticationRecoveryRestricted,
		sourceAssuranceExpiresAt: source.authenticationAssuranceExpiresAt
			? cloneDate(source.authenticationAssuranceExpiresAt)
			: null,
	};
	if (!applyEvidence(proof, input.freshEvidence, input.now)) return null;
	return proof;
}

function proofForInput(
	input: EvaluateSessionIssuanceInput,
): MutableProof | null {
	if (!parseDate(input.now)) return null;

	if (input.purpose === "impersonation") {
		if (
			input.sourceAssurance !== undefined ||
			input.evidence.length !== 1 ||
			input.evidence[0]?.kind !== "primary" ||
			input.evidence[0].primaryMethod !== "admin_impersonation"
		) {
			return null;
		}
		return {
			primaryMethod: "admin_impersonation",
			primaryAt: cloneDate(input.now),
			factorMethod: null,
			factorAt: null,
			recoveryRestricted: false,
			sourceAssuranceExpiresAt: null,
		};
	}

	if (input.purpose === "interactive") {
		if (input.sourceAssurance !== undefined) return null;
		const proof: MutableProof = {
			primaryMethod: null,
			primaryAt: null,
			factorMethod: null,
			factorAt: null,
			recoveryRestricted: false,
			sourceAssuranceExpiresAt: null,
		};
		return applyEvidence(proof, input.evidence, input.now) ? proof : null;
	}

	if (!input.sourceAssurance) return null;
	const derived = deriveReplacementEvidence({
		source: input.sourceAssurance,
		freshEvidence: input.evidence,
		now: input.now,
	});
	return derived ? { ...derived } : null;
}

function scopeMatches(
	fields: SessionAssuranceFields,
	policy: SessionAssurancePolicySnapshot,
): boolean {
	return (
		fields.authenticationPolicyProjectId === policy.identity.projectId &&
		fields.authenticationPolicyEnvironmentId ===
			policy.identity.environmentId &&
		fields.authenticationPolicyOrganizationId === policy.organizationId
	);
}

function satisfyingProofAt(
	proof: MutableProof,
	minimum: AuthenticationAssuranceLevel,
): Date | null {
	if (!proof.primaryMethod || !proof.primaryAt) return null;
	if (minimum === "single_factor") return proof.primaryAt;
	if (proof.primaryMethod === "passkey") return proof.primaryAt;
	if (proof.factorMethod === "passkey" || proof.factorMethod === "totp") {
		return proof.factorAt;
	}
	return null;
}

function insufficiencyReason(
	proof: MutableProof,
	policy: RuntimeAuthenticationPolicy,
	_purpose: EvaluateSessionIssuanceInput["purpose"],
): SessionAssuranceRequirementReason | null {
	if (!proof.primaryMethod || !proof.primaryAt) return "primary_required";
	if (proof.primaryMethod === "anonymous") return "anonymous_not_allowed";
	if (
		proof.primaryMethod === "admin_impersonation" &&
		policy.minimumAssurance !== "single_factor"
	) {
		return "impersonation_insufficient";
	}
	if (proof.recoveryRestricted) return "recovery_restricted";
	if (policy.minimumAssurance === "single_factor") return null;

	const hasAllowedPasskey =
		policy.allowedFactors.passkey &&
		(proof.primaryMethod === "passkey" || proof.factorMethod === "passkey");
	if (policy.minimumAssurance === "phishing_resistant") {
		return hasAllowedPasskey ? null : "phishing_resistant_required";
	}

	const hasAllowedTotp =
		policy.allowedFactors.totp && proof.factorMethod === "totp";
	return hasAllowedPasskey || hasAllowedTotp ? null : "factor_required";
}

function computeAssuranceExpiry(
	proof: MutableProof,
	policy: RuntimeAuthenticationPolicy,
): Date | null {
	const maxAge = policy.assuranceMaxAgeSeconds;
	const proofAt = satisfyingProofAt(proof, policy.minimumAssurance);
	let computed: Date | null = null;
	if (maxAge !== null && proofAt) {
		computed = new Date(proofAt.getTime() + maxAge * 1000);
	}
	if (!proof.sourceAssuranceExpiresAt) return computed;
	if (!computed) return cloneDate(proof.sourceAssuranceExpiresAt);
	return proof.sourceAssuranceExpiresAt < computed
		? cloneDate(proof.sourceAssuranceExpiresAt)
		: computed;
}

export function evaluateSessionIssuance(
	input: EvaluateSessionIssuanceInput,
): EvaluateSessionIssuanceResult {
	const normalizedPolicy = normalizePolicySnapshot(input.policy);
	if (!normalizedPolicy || !parseDate(input.now)) {
		return {
			kind: "required",
			requirement: makeInvalidPolicyRequirement(input.policy),
		};
	}
	const normalizedInput = { ...input, policy: normalizedPolicy };
	if (
		normalizedInput.purpose === "device" &&
		!normalizedPolicy.policy.trustedDevice.enabled
	) {
		return required(normalizedPolicy, "trusted_device_not_allowed");
	}

	if (normalizedInput.sourceAssurance) {
		const source = getValidatedAssurance(normalizedInput.sourceAssurance);
		if (!source) {
			return required(normalizedPolicy, "invalid_source_assurance");
		}
		if (source.authenticationPrimaryMethod === "admin_impersonation") {
			return required(normalizedPolicy, "invalid_source_assurance");
		}
		if (!scopeMatches(source, normalizedPolicy)) {
			return required(normalizedPolicy, "source_scope_mismatch");
		}
		if (
			source.authenticationPrimaryAt.getTime() >
				normalizedInput.now.getTime() ||
			(source.authenticationFactorAt?.getTime() ?? 0) >
				normalizedInput.now.getTime()
		) {
			return required(normalizedPolicy, "invalid_source_assurance");
		}
		if (source.authenticationPolicyRevision !== normalizedPolicy.revision) {
			return required(normalizedPolicy, "policy_revision_changed");
		}
	}

	const proof = proofForInput(normalizedInput);
	if (!proof) return required(normalizedPolicy, "invalid_evidence");
	const reason = insufficiencyReason(
		proof,
		normalizedPolicy.policy,
		normalizedInput.purpose,
	);
	if (reason) return required(normalizedPolicy, reason);

	let assuranceExpiresAt = computeAssuranceExpiry(
		proof,
		normalizedPolicy.policy,
	);
	if (normalizedInput.purpose === "device") {
		const deviceExpiresAt = new Date(
			normalizedInput.now.getTime() +
				normalizedPolicy.policy.trustedDevice.maxAgeSeconds * 1000,
		);
		if (!assuranceExpiresAt || deviceExpiresAt < assuranceExpiresAt) {
			assuranceExpiresAt = deviceExpiresAt;
		}
	}
	if (
		assuranceExpiresAt &&
		assuranceExpiresAt.getTime() <= normalizedInput.now.getTime()
	) {
		return required(normalizedPolicy, "assurance_expired");
	}

	return {
		kind: "satisfied",
		fields: brandFields({
			authenticationAssuranceVersion: 1,
			authenticationPolicyProjectId: normalizedPolicy.identity.projectId,
			authenticationPolicyEnvironmentId:
				normalizedPolicy.identity.environmentId,
			authenticationPrimaryMethod: proof.primaryMethod!,
			authenticationPrimaryAt: cloneDate(proof.primaryAt!),
			authenticationFactorMethod: proof.factorMethod,
			authenticationFactorAt: proof.factorAt ? cloneDate(proof.factorAt) : null,
			authenticationPolicyOrganizationId: normalizedPolicy.organizationId,
			authenticationPolicyRevision: normalizedPolicy.revision,
			authenticationAssuranceExpiresAt: assuranceExpiresAt,
			authenticationRecoveryRestricted: proof.recoveryRestricted,
		}),
	};
}

function parseStoredFields(stored: unknown):
	| { kind: "ok"; fields: SessionAssuranceFields }
	| {
			kind: "invalid";
			reason: "malformed_authority" | "unsupported_assurance_version";
	  } {
	if (!isRecord(stored))
		return { kind: "invalid", reason: "malformed_authority" };
	for (const field of SESSION_ASSURANCE_RESERVED_FIELDS) {
		if (!Object.prototype.hasOwnProperty.call(stored, field)) {
			return { kind: "invalid", reason: "malformed_authority" };
		}
	}
	if (stored.authenticationAssuranceVersion !== 1) {
		return { kind: "invalid", reason: "unsupported_assurance_version" };
	}
	if (
		!isNonEmptyString(stored.authenticationPolicyProjectId) ||
		!isNonEmptyString(stored.authenticationPolicyEnvironmentId) ||
		!isPrimaryMethod(stored.authenticationPrimaryMethod) ||
		!isCanonicalRevision(stored.authenticationPolicyRevision) ||
		(stored.authenticationPolicyOrganizationId !== null &&
			!isNonEmptyString(stored.authenticationPolicyOrganizationId)) ||
		typeof stored.authenticationRecoveryRestricted !== "boolean"
	) {
		return { kind: "invalid", reason: "malformed_authority" };
	}

	const primaryAt = parseDate(stored.authenticationPrimaryAt);
	const factorMethod = stored.authenticationFactorMethod;
	const factorAt = parseNullableDate(stored.authenticationFactorAt);
	const expiresAt = parseNullableDate(stored.authenticationAssuranceExpiresAt);
	if (
		!primaryAt ||
		(factorMethod !== null && !isFactorMethod(factorMethod)) ||
		!factorAt.valid ||
		!expiresAt.valid ||
		(factorMethod === null) !== (factorAt.value === null) ||
		(factorMethod === "recovery_code" &&
			stored.authenticationRecoveryRestricted !== true) ||
		(stored.authenticationPrimaryMethod === "admin_impersonation" &&
			(factorMethod !== null ||
				stored.authenticationRecoveryRestricted !== false))
	) {
		return { kind: "invalid", reason: "malformed_authority" };
	}

	return {
		kind: "ok",
		fields: {
			authenticationAssuranceVersion: 1,
			authenticationPolicyProjectId: stored.authenticationPolicyProjectId,
			authenticationPolicyEnvironmentId:
				stored.authenticationPolicyEnvironmentId,
			authenticationPrimaryMethod: stored.authenticationPrimaryMethod,
			authenticationPrimaryAt: primaryAt,
			authenticationFactorMethod: factorMethod,
			authenticationFactorAt: factorAt.value,
			authenticationPolicyOrganizationId:
				stored.authenticationPolicyOrganizationId,
			authenticationPolicyRevision: stored.authenticationPolicyRevision,
			authenticationAssuranceExpiresAt: expiresAt.value,
			authenticationRecoveryRestricted: stored.authenticationRecoveryRestricted,
		},
	};
}

export function validateStoredSessionAssurance(
	input: ValidateStoredSessionAssuranceInput,
): ValidateStoredSessionAssuranceResult {
	const normalizedPolicy = normalizePolicySnapshot(input.policy);
	if (!normalizedPolicy || !parseDate(input.now)) {
		return { kind: "invalid", reason: "invalid_policy" };
	}
	const parsed = parseStoredFields(input.stored);
	if (parsed.kind === "invalid") return parsed;
	const fields = parsed.fields;

	if (
		fields.authenticationPolicyProjectId !==
			normalizedPolicy.identity.projectId ||
		fields.authenticationPolicyEnvironmentId !==
			normalizedPolicy.identity.environmentId
	) {
		return { kind: "invalid", reason: "policy_scope_mismatch" };
	}
	if (
		fields.authenticationPolicyOrganizationId !==
		normalizedPolicy.organizationId
	) {
		return { kind: "invalid", reason: "policy_organization_mismatch" };
	}

	const revisionComparison = compareRevisions(
		fields.authenticationPolicyRevision,
		normalizedPolicy.revision,
	);
	if (revisionComparison > 0) {
		return { kind: "invalid", reason: "live_revision_regressed" };
	}
	if (revisionComparison < 0) {
		return {
			kind: "required",
			requirement: makeRequirement(normalizedPolicy, "policy_revision_changed"),
		};
	}

	if (
		fields.authenticationPrimaryAt.getTime() > input.now.getTime() ||
		(fields.authenticationFactorAt?.getTime() ?? 0) > input.now.getTime()
	) {
		return { kind: "invalid", reason: "future_authentication_timestamp" };
	}
	if (
		fields.authenticationFactorAt !== null &&
		fields.authenticationFactorAt.getTime() <
			fields.authenticationPrimaryAt.getTime()
	) {
		return { kind: "invalid", reason: "malformed_authority" };
	}

	const proof: MutableProof = {
		primaryMethod: fields.authenticationPrimaryMethod,
		primaryAt: fields.authenticationPrimaryAt,
		factorMethod: fields.authenticationFactorMethod,
		factorAt: fields.authenticationFactorAt,
		recoveryRestricted: fields.authenticationRecoveryRestricted,
		sourceAssuranceExpiresAt: null,
	};
	const reason = insufficiencyReason(
		proof,
		normalizedPolicy.policy,
		"interactive",
	);
	if (reason) {
		return {
			kind: "required",
			requirement: makeRequirement(normalizedPolicy, reason),
		};
	}

	const maximumExpiry = computeAssuranceExpiry(proof, normalizedPolicy.policy);
	const storedExpiry = fields.authenticationAssuranceExpiresAt;
	if (
		maximumExpiry &&
		(!storedExpiry || storedExpiry.getTime() > maximumExpiry.getTime())
	) {
		return { kind: "invalid", reason: "forged_assurance_expiry" };
	}
	if (storedExpiry && storedExpiry.getTime() <= input.now.getTime()) {
		return {
			kind: "required",
			requirement: makeRequirement(normalizedPolicy, "assurance_expired"),
		};
	}

	return { kind: "accepted", fields: brandFields(fields) };
}

export function stripReservedSessionAuthority<
	T extends Record<string, unknown>,
>(input: T): Omit<T, SessionAssuranceReservedField> {
	const stripped: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(input)) {
		if (!RESERVED_FIELD_SET.has(key)) stripped[key] = value;
	}
	return stripped as Omit<T, SessionAssuranceReservedField>;
}
