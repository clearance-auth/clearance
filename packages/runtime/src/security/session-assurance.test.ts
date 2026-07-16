import type {
	RuntimeAuthenticationPolicy,
	VerifiedAuthenticationEvidence,
} from "@clearance/core";
import { describe, expect, it } from "vitest";
import {
	SESSION_ASSURANCE_RESERVED_FIELDS,
	deriveReplacementEvidence,
	evaluateSessionIssuance,
	stripReservedSessionAuthority,
	validateStoredSessionAssurance,
	type SessionAssuranceFields,
	type SessionAssurancePolicySnapshot,
	type ValidatedSessionAssuranceFields,
} from "./session-assurance";

const NOW = new Date("2026-07-17T10:00:00.000Z");

function policy(
	overrides: Partial<RuntimeAuthenticationPolicy> = {},
): RuntimeAuthenticationPolicy {
	return {
		passwordLockout: {
			enabled: true,
			maxFailedAttempts: 5,
			durationSeconds: 300,
		},
		factorLockout: {
			enabled: true,
			maxFailedAttempts: 5,
			durationSeconds: 300,
		},
		minimumAssurance: "single_factor",
		allowedFactors: { totp: true, passkey: true },
		trustedDevice: { enabled: false, maxAgeSeconds: 0 },
		assuranceMaxAgeSeconds: 300,
		...overrides,
	};
}

function snapshot(
	overrides: Partial<SessionAssurancePolicySnapshot> = {},
): SessionAssurancePolicySnapshot {
	return {
		identity: { projectId: "project-1", environmentId: "environment-1" },
		organizationId: "organization-1",
		revision: "7",
		policy: policy(),
		...overrides,
	};
}

function deviceSnapshot(
	overrides: Partial<SessionAssurancePolicySnapshot> = {},
	maxAgeSeconds = 120,
): SessionAssurancePolicySnapshot {
	const base = snapshot(overrides);
	return {
		...base,
		policy: policy({
			...base.policy,
			trustedDevice: { enabled: true, maxAgeSeconds },
		}),
	};
}

function issue(
	evidence: readonly VerifiedAuthenticationEvidence[],
	policySnapshot = snapshot(),
) {
	return evaluateSessionIssuance({
		purpose: "interactive",
		policy: policySnapshot,
		now: NOW,
		evidence,
	});
}

function satisfied(
	evidence: readonly VerifiedAuthenticationEvidence[],
	policySnapshot = snapshot(),
): ValidatedSessionAssuranceFields {
	const result = issue(evidence, policySnapshot);
	expect(result.kind).toBe("satisfied");
	if (result.kind !== "satisfied")
		throw new Error("expected satisfied assurance");
	return result.fields;
}

function stored(fields: SessionAssuranceFields): Record<string, unknown> {
	return { ...fields };
}

function mutateAssuranceView(fields: ValidatedSessionAssuranceFields): void {
	Object.assign(fields as object, {
		authenticationPolicyProjectId: "forged-project",
		authenticationPolicyEnvironmentId: "forged-environment",
		authenticationPrimaryMethod: "anonymous",
		authenticationFactorMethod: "recovery_code",
		authenticationPolicyOrganizationId: "forged-organization",
		authenticationPolicyRevision: "999",
		authenticationRecoveryRestricted: true,
	});
	fields.authenticationPrimaryAt.setTime(0);
	fields.authenticationFactorAt?.setTime(0);
	fields.authenticationAssuranceExpiresAt?.setTime(8_640_000_000_000_000);
}

describe("evaluateSessionIssuance", () => {
	it("uses runtime now and ignores caller-supplied assurance labels and timestamps", () => {
		const evidence = {
			kind: "primary",
			primaryMethod: "password",
			verifiedAt: new Date("1999-01-01T00:00:00.000Z"),
			assurance: "phishing_resistant",
		} as unknown as VerifiedAuthenticationEvidence;
		const fields = satisfied([evidence]);
		expect(fields.authenticationPrimaryAt).toEqual(NOW);
		expect(fields.authenticationPrimaryMethod).toBe("password");
	});

	it("rejects unknown methods instead of trusting structural casts", () => {
		const result = issue([
			{ kind: "primary", primaryMethod: "root_override" } as never,
		]);
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "invalid_evidence" },
		});
	});

	it("rejects the admin impersonation primary outside impersonation purpose", () => {
		for (const purpose of ["interactive", "replacement", "device"] as const) {
			const source =
				purpose === "interactive"
					? undefined
					: satisfied([{ kind: "primary", primaryMethod: "password" }]);
			const result = evaluateSessionIssuance({
				purpose,
				policy: purpose === "device" ? deviceSnapshot() : snapshot(),
				now: NOW,
				evidence: [{ kind: "primary", primaryMethod: "admin_impersonation" }],
				...(source ? { sourceAssurance: source } : {}),
			});
			expect(result).toMatchObject({
				kind: "required",
				requirement: { reason: "invalid_evidence" },
			});
		}
	});

	it("fails closed on malformed, out-of-bounds, and inconsistent policy", () => {
		const invalidPolicies = [
			{ ...policy(), assuranceMaxAgeSeconds: 59 },
			{
				...policy(),
				passwordLockout: {
					...policy().passwordLockout,
					maxFailedAttempts: 2,
				},
			},
			{
				...policy(),
				minimumAssurance: "multi_factor",
				allowedFactors: { totp: false, passkey: false },
			},
			{
				...policy(),
				minimumAssurance: "phishing_resistant",
				trustedDevice: { enabled: true, maxAgeSeconds: 300 },
			},
			{
				...policy(),
				allowedFactors: { totp: true, passkey: true, sms: true },
			},
		] as unknown as RuntimeAuthenticationPolicy[];

		for (const invalidPolicy of invalidPolicies) {
			const result = issue(
				[{ kind: "primary", primaryMethod: "passkey" }],
				snapshot({ policy: invalidPolicy }),
			);
			expect(result).toMatchObject({
				kind: "required",
				requirement: { reason: "invalid_policy" },
			});
		}
	});

	it("rejects revisions outside the positive PostgreSQL bigint range", () => {
		for (const revision of ["0", "9223372036854775808"]) {
			const result = issue(
				[{ kind: "primary", primaryMethod: "password" }],
				snapshot({ revision }),
			);
			expect(result).toMatchObject({
				kind: "required",
				requirement: { reason: "invalid_policy" },
			});
		}
	});

	it("accepts one non-anonymous primary for single-factor policy", () => {
		const fields = satisfied([{ kind: "primary", primaryMethod: "password" }]);
		expect(fields).toMatchObject({
			authenticationAssuranceVersion: 1,
			authenticationPolicyProjectId: "project-1",
			authenticationPolicyEnvironmentId: "environment-1",
			authenticationPolicyOrganizationId: "organization-1",
			authenticationPolicyRevision: "7",
			authenticationPrimaryMethod: "password",
			authenticationFactorMethod: null,
			authenticationRecoveryRestricted: false,
		});
	});

	it("does not let duplicate primary evidence manufacture MFA", () => {
		const result = issue(
			[
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "primary", primaryMethod: "password" },
			],
			snapshot({ policy: policy({ minimumAssurance: "multi_factor" }) }),
		);
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "factor_required" },
		});
	});

	it("treats passkey primary authentication as phishing-resistant and MFA", () => {
		const fields = satisfied(
			[{ kind: "primary", primaryMethod: "passkey" }],
			snapshot({
				policy: policy({ minimumAssurance: "phishing_resistant" }),
			}),
		);
		expect(fields.authenticationPrimaryMethod).toBe("passkey");
		expect(fields.authenticationFactorMethod).toBeNull();
		expect(fields.authenticationAssuranceExpiresAt).toEqual(
			new Date("2026-07-17T10:05:00.000Z"),
		);
	});

	it("accepts TOTP only with a non-anonymous primary", () => {
		const multiFactor = snapshot({
			policy: policy({ minimumAssurance: "multi_factor" }),
		});
		const fields = satisfied(
			[
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
			multiFactor,
		);
		expect(fields.authenticationFactorMethod).toBe("totp");
		expect(fields.authenticationFactorAt).toEqual(NOW);

		const missingPrimary = issue(
			[{ kind: "factor", factorMethod: "totp" }],
			multiFactor,
		);
		expect(missingPrimary).toMatchObject({
			kind: "required",
			requirement: { reason: "primary_required" },
		});
	});

	it("does not accept generic OTP as managed TOTP", () => {
		const result = issue(
			[
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "otp" },
			],
			snapshot({ policy: policy({ minimumAssurance: "multi_factor" }) }),
		);
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "factor_required" },
		});
	});

	it("marks recovery evidence restricted and never grants general MFA", () => {
		const result = issue(
			[
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "recovery_code" },
			],
			snapshot({ policy: policy({ minimumAssurance: "multi_factor" }) }),
		);
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "recovery_restricted" },
		});
	});

	it("respects the policy factor allowlist", () => {
		const result = issue(
			[
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "passkey" },
			],
			snapshot({
				policy: policy({
					minimumAssurance: "multi_factor",
					allowedFactors: { passkey: false, totp: true },
				}),
			}),
		);
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "factor_required" },
		});
	});

	it("rejects anonymous authentication for every managed general session", () => {
		const result = issue([{ kind: "primary", primaryMethod: "anonymous" }]);
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "anonymous_not_allowed" },
		});
	});

	it("allows valid impersonation only at single factor and never inherits a source", () => {
		const single = evaluateSessionIssuance({
			purpose: "impersonation",
			policy: deviceSnapshot(),
			now: NOW,
			evidence: [{ kind: "primary", primaryMethod: "admin_impersonation" }],
		});
		expect(single.kind).toBe("satisfied");

		const high = evaluateSessionIssuance({
			purpose: "impersonation",
			policy: snapshot({
				policy: policy({ minimumAssurance: "multi_factor" }),
			}),
			now: NOW,
			evidence: [{ kind: "primary", primaryMethod: "admin_impersonation" }],
		});
		expect(high).toMatchObject({
			kind: "required",
			requirement: { reason: "impersonation_insufficient" },
		});

		const inherited = evaluateSessionIssuance({
			purpose: "impersonation",
			policy: deviceSnapshot(),
			now: NOW,
			evidence: [{ kind: "primary", primaryMethod: "admin_impersonation" }],
			sourceAssurance: satisfied([
				{ kind: "primary", primaryMethod: "passkey" },
			]),
		});
		expect(inherited).toMatchObject({
			kind: "required",
			requirement: { reason: "invalid_evidence" },
		});
	});
});

describe("replacement and device derivation", () => {
	it("preserves source proof timestamps exactly", () => {
		const sourceNow = new Date("2026-07-17T09:58:00.000Z");
		const sourceResult = evaluateSessionIssuance({
			purpose: "interactive",
			policy: snapshot(),
			now: sourceNow,
			evidence: [{ kind: "primary", primaryMethod: "password" }],
		});
		if (sourceResult.kind !== "satisfied") throw new Error("source failed");
		const result = evaluateSessionIssuance({
			purpose: "device",
			policy: deviceSnapshot({}, 300),
			now: NOW,
			evidence: [],
			sourceAssurance: sourceResult.fields,
		});
		expect(result.kind).toBe("satisfied");
		if (result.kind !== "satisfied") return;
		expect(result.fields.authenticationPrimaryAt).toEqual(sourceNow);
		expect(result.fields.authenticationAssuranceExpiresAt).toEqual(
			new Date("2026-07-17T10:03:00.000Z"),
		);
	});

	it("rejects device derivation when trusted-device policy is disabled", () => {
		const source = satisfied([{ kind: "primary", primaryMethod: "password" }]);
		const result = evaluateSessionIssuance({
			purpose: "device",
			policy: snapshot(),
			now: NOW,
			evidence: [],
			sourceAssurance: source,
		});
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "trusted_device_not_allowed" },
		});
	});

	it("caps device assurance by trusted-device max age and the existing source cap", () => {
		const source = satisfied([{ kind: "primary", primaryMethod: "password" }]);
		const trustedDeviceCap = evaluateSessionIssuance({
			purpose: "device",
			policy: deviceSnapshot({}, 120),
			now: NOW,
			evidence: [],
			sourceAssurance: source,
		});
		expect(trustedDeviceCap.kind).toBe("satisfied");
		if (trustedDeviceCap.kind !== "satisfied") return;
		expect(trustedDeviceCap.fields.authenticationAssuranceExpiresAt).toEqual(
			new Date("2026-07-17T10:02:00.000Z"),
		);

		const olderSourceTime = new Date("2026-07-17T09:56:00.000Z");
		const olderSource = evaluateSessionIssuance({
			purpose: "interactive",
			policy: snapshot(),
			now: olderSourceTime,
			evidence: [{ kind: "primary", primaryMethod: "password" }],
		});
		if (olderSource.kind !== "satisfied") throw new Error("source failed");
		const sourceCap = evaluateSessionIssuance({
			purpose: "device",
			policy: deviceSnapshot({}, 300),
			now: NOW,
			evidence: [],
			sourceAssurance: olderSource.fields,
		});
		expect(sourceCap.kind).toBe("satisfied");
		if (sourceCap.kind !== "satisfied") return;
		expect(sourceCap.fields.authenticationAssuranceExpiresAt).toEqual(
			new Date("2026-07-17T10:01:00.000Z"),
		);
	});

	it("adds explicit fresh factor evidence without extending the source cap", () => {
		const sourceNow = new Date("2026-07-17T09:58:00.000Z");
		const sourceResult = evaluateSessionIssuance({
			purpose: "interactive",
			policy: snapshot(),
			now: sourceNow,
			evidence: [{ kind: "primary", primaryMethod: "password" }],
		});
		if (sourceResult.kind !== "satisfied") throw new Error("source failed");
		const result = evaluateSessionIssuance({
			purpose: "replacement",
			policy: snapshot({
				policy: policy({ minimumAssurance: "multi_factor" }),
			}),
			now: NOW,
			evidence: [{ kind: "factor", factorMethod: "totp" }],
			sourceAssurance: sourceResult.fields,
		});
		// The source was validated under the same identity/revision but its original
		// five-minute cap remains the upper bound after fresh factor evidence.
		expect(result.kind).toBe("satisfied");
		if (result.kind !== "satisfied") return;
		expect(result.fields.authenticationPrimaryAt).toEqual(sourceNow);
		expect(result.fields.authenticationFactorAt).toEqual(NOW);
		expect(result.fields.authenticationAssuranceExpiresAt).toEqual(
			new Date("2026-07-17T10:03:00.000Z"),
		);
	});

	it("clears a retained factor when fresh passkey becomes the primary proof", () => {
		const sourceNow = new Date("2026-07-17T09:59:00.000Z");
		const managedPolicy = snapshot({
			policy: policy({ minimumAssurance: "multi_factor" }),
		});
		const sourceResult = evaluateSessionIssuance({
			purpose: "interactive",
			policy: managedPolicy,
			now: sourceNow,
			evidence: [
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
		});
		if (sourceResult.kind !== "satisfied") throw new Error("source failed");

		const replacement = evaluateSessionIssuance({
			purpose: "replacement",
			policy: managedPolicy,
			now: NOW,
			evidence: [{ kind: "primary", primaryMethod: "passkey" }],
			sourceAssurance: sourceResult.fields,
		});

		expect(replacement.kind).toBe("satisfied");
		if (replacement.kind !== "satisfied") return;
		expect(replacement.fields.authenticationPrimaryMethod).toBe("passkey");
		expect(replacement.fields.authenticationPrimaryAt).toEqual(NOW);
		expect(replacement.fields.authenticationFactorMethod).toBeNull();
		expect(replacement.fields.authenticationFactorAt).toBeNull();
		expect(replacement.fields.authenticationAssuranceExpiresAt).toEqual(
			new Date("2026-07-17T10:04:00.000Z"),
		);
	});

	it("does not refresh a same-kind source factor with duplicate evidence", () => {
		const sourceNow = new Date("2026-07-17T09:59:00.000Z");
		const sourceResult = evaluateSessionIssuance({
			purpose: "interactive",
			policy: snapshot({
				policy: policy({ minimumAssurance: "multi_factor" }),
			}),
			now: sourceNow,
			evidence: [
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
		});
		if (sourceResult.kind !== "satisfied") throw new Error("source failed");
		const derived = deriveReplacementEvidence({
			source: sourceResult.fields,
			freshEvidence: [
				{ kind: "factor", factorMethod: "totp" },
				{ kind: "factor", factorMethod: "totp" },
			],
			now: NOW,
		});
		expect(derived?.factorAt).toEqual(sourceNow);
	});

	it("derives from the immutable issuance snapshot after public scalar and Date mutation", () => {
		const sourceNow = new Date("2026-07-17T09:59:00.000Z");
		const sourcePolicy = snapshot({
			policy: policy({ minimumAssurance: "multi_factor" }),
		});
		const sourceResult = evaluateSessionIssuance({
			purpose: "interactive",
			policy: sourcePolicy,
			now: sourceNow,
			evidence: [
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
		});
		if (sourceResult.kind !== "satisfied") throw new Error("source failed");
		mutateAssuranceView(sourceResult.fields);

		const derived = deriveReplacementEvidence({
			source: sourceResult.fields,
			freshEvidence: [],
			now: NOW,
		});
		expect(derived).toMatchObject({
			primaryMethod: "password",
			primaryAt: sourceNow,
			factorMethod: "totp",
			factorAt: sourceNow,
			recoveryRestricted: false,
			sourceAssuranceExpiresAt: new Date("2026-07-17T10:04:00.000Z"),
		});

		const replacement = evaluateSessionIssuance({
			purpose: "replacement",
			policy: sourcePolicy,
			now: NOW,
			evidence: [],
			sourceAssurance: sourceResult.fields,
		});
		expect(replacement.kind).toBe("satisfied");
		if (replacement.kind !== "satisfied") return;
		expect(replacement.fields.authenticationPolicyProjectId).toBe("project-1");
		expect(replacement.fields.authenticationPrimaryAt).toEqual(sourceNow);
		expect(replacement.fields.authenticationFactorMethod).toBe("totp");
	});

	it("rejects an arbitrary source-shaped object without the validation brand", () => {
		const forged = stored(
			satisfied([{ kind: "primary", primaryMethod: "password" }]),
		) as unknown as ValidatedSessionAssuranceFields;
		const result = evaluateSessionIssuance({
			purpose: "replacement",
			policy: snapshot(),
			now: NOW,
			evidence: [],
			sourceAssurance: forged,
		});
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "invalid_source_assurance" },
		});
	});

	it("rejects branded source proof whose timestamps are in the caller's future", () => {
		const futureSource = evaluateSessionIssuance({
			purpose: "interactive",
			policy: snapshot(),
			now: new Date(NOW.getTime() + 1),
			evidence: [{ kind: "primary", primaryMethod: "password" }],
		});
		if (futureSource.kind !== "satisfied") throw new Error("source failed");
		const result = evaluateSessionIssuance({
			purpose: "device",
			policy: deviceSnapshot(),
			now: NOW,
			evidence: [],
			sourceAssurance: futureSource.fields,
		});
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "invalid_source_assurance" },
		});
	});

	it("rejects source assurance bound to another organization or scope", () => {
		const source = satisfied([{ kind: "primary", primaryMethod: "password" }]);
		for (const target of [
			deviceSnapshot({ organizationId: "organization-2" }),
			deviceSnapshot({
				identity: { projectId: "project-2", environmentId: "environment-1" },
			}),
		]) {
			const result = evaluateSessionIssuance({
				purpose: "device",
				policy: target,
				now: NOW,
				evidence: [],
				sourceAssurance: source,
			});
			expect(result).toMatchObject({
				kind: "required",
				requirement: { reason: "source_scope_mismatch" },
			});
		}
	});
});

describe("validateStoredSessionAssurance", () => {
	const acceptedFields = () =>
		satisfied(
			[
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
			snapshot({ policy: policy({ minimumAssurance: "multi_factor" }) }),
		);
	const multiPolicy = () =>
		snapshot({ policy: policy({ minimumAssurance: "multi_factor" }) });

	it("accepts complete authority and returns a source usable for replacement", () => {
		const validation = validateStoredSessionAssurance({
			stored: stored(acceptedFields()),
			policy: multiPolicy(),
			now: NOW,
		});
		expect(validation.kind).toBe("accepted");
		if (validation.kind !== "accepted") return;
		expect(
			deriveReplacementEvidence({
				source: validation.fields,
				freshEvidence: [],
				now: NOW,
			}),
		).not.toBeNull();
	});

	it("derives from the immutable validation snapshot after public scalar and Date mutation", () => {
		const sourceNow = new Date("2026-07-17T09:59:00.000Z");
		const issued = evaluateSessionIssuance({
			purpose: "interactive",
			policy: multiPolicy(),
			now: sourceNow,
			evidence: [
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
		});
		if (issued.kind !== "satisfied") throw new Error("issuance failed");
		const validation = validateStoredSessionAssurance({
			stored: stored(issued.fields),
			policy: multiPolicy(),
			now: NOW,
		});
		if (validation.kind !== "accepted") throw new Error("validation failed");
		mutateAssuranceView(validation.fields);

		const derived = deriveReplacementEvidence({
			source: validation.fields,
			freshEvidence: [],
			now: NOW,
		});
		expect(derived).toMatchObject({
			primaryMethod: "password",
			primaryAt: sourceNow,
			factorMethod: "totp",
			factorAt: sourceNow,
			recoveryRestricted: false,
			sourceAssuranceExpiresAt: new Date("2026-07-17T10:04:00.000Z"),
		});

		const replacement = evaluateSessionIssuance({
			purpose: "replacement",
			policy: multiPolicy(),
			now: NOW,
			evidence: [],
			sourceAssurance: validation.fields,
		});
		expect(replacement.kind).toBe("satisfied");
		if (replacement.kind !== "satisfied") return;
		expect(replacement.fields.authenticationPolicyProjectId).toBe("project-1");
		expect(replacement.fields.authenticationPrimaryAt).toEqual(sourceNow);
		expect(replacement.fields.authenticationFactorMethod).toBe("totp");
	});

	it("rejects missing legacy and malformed state without throwing", () => {
		for (const candidate of [
			{},
			{ authenticationAssuranceVersion: 1 },
			{
				...stored(acceptedFields()),
				authenticationPrimaryAt: "2026-07-17T10:00:00.000Z",
			},
			{
				...stored(acceptedFields()),
				authenticationFactorMethod: "super_factor",
			},
			{
				...stored(acceptedFields()),
				authenticationFactorAt: null,
			},
		]) {
			expect(
				validateStoredSessionAssurance({
					stored: candidate,
					policy: multiPolicy(),
					now: NOW,
				}),
			).toMatchObject({ kind: "invalid" });
		}
	});

	it("rejects unsupported assurance versions", () => {
		const result = validateStoredSessionAssurance({
			stored: {
				...stored(acceptedFields()),
				authenticationAssuranceVersion: 2,
			},
			policy: multiPolicy(),
			now: NOW,
		});
		expect(result).toEqual({
			kind: "invalid",
			reason: "unsupported_assurance_version",
		});
	});

	it("distinguishes exact scope and organization mismatches", () => {
		const fields = stored(acceptedFields());
		expect(
			validateStoredSessionAssurance({
				stored: fields,
				policy: snapshot({
					identity: {
						projectId: "project-1",
						environmentId: "environment-2",
					},
				}),
				now: NOW,
			}),
		).toEqual({ kind: "invalid", reason: "policy_scope_mismatch" });
		expect(
			validateStoredSessionAssurance({
				stored: fields,
				policy: snapshot({ organizationId: "organization-2" }),
				now: NOW,
			}),
		).toEqual({ kind: "invalid", reason: "policy_organization_mismatch" });
	});

	it("requires reauthentication on a newer revision and flags live regression", () => {
		const fields = stored(acceptedFields());
		const newer = validateStoredSessionAssurance({
			stored: fields,
			policy: snapshot({ revision: "8" }),
			now: NOW,
		});
		expect(newer).toMatchObject({
			kind: "required",
			requirement: { reason: "policy_revision_changed", revision: "8" },
		});

		const regressed = validateStoredSessionAssurance({
			stored: fields,
			policy: snapshot({ revision: "6" }),
			now: NOW,
		});
		expect(regressed).toEqual({
			kind: "invalid",
			reason: "live_revision_regressed",
		});
	});

	it("reevaluates exact-revision state against stricter assurance", () => {
		const single = stored(
			satisfied([{ kind: "primary", primaryMethod: "password" }]),
		);
		const result = validateStoredSessionAssurance({
			stored: single,
			policy: snapshot({
				policy: policy({ minimumAssurance: "phishing_resistant" }),
			}),
			now: NOW,
		});
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "phishing_resistant_required" },
		});
	});

	it("rejects stored impersonation authority with a factor or recovery restriction", () => {
		const impersonation = evaluateSessionIssuance({
			purpose: "impersonation",
			policy: snapshot(),
			now: NOW,
			evidence: [{ kind: "primary", primaryMethod: "admin_impersonation" }],
		});
		if (impersonation.kind !== "satisfied") {
			throw new Error("impersonation source failed");
		}
		for (const malformed of [
			{
				...stored(impersonation.fields),
				authenticationFactorMethod: "passkey",
				authenticationFactorAt: NOW,
			},
			{
				...stored(impersonation.fields),
				authenticationRecoveryRestricted: true,
			},
		]) {
			expect(
				validateStoredSessionAssurance({
					stored: malformed,
					policy: snapshot(),
					now: NOW,
				}),
			).toEqual({ kind: "invalid", reason: "malformed_authority" });
		}
	});

	it("treats the exact expiry boundary as insufficient", () => {
		const fields = stored(acceptedFields());
		fields.authenticationAssuranceExpiresAt = new Date(NOW);
		const result = validateStoredSessionAssurance({
			stored: fields,
			policy: multiPolicy(),
			now: NOW,
		});
		expect(result).toMatchObject({
			kind: "required",
			requirement: { reason: "assurance_expired" },
		});
	});

	it("rejects an expiry later than the policy-derived maximum", () => {
		const fields = stored(acceptedFields());
		fields.authenticationAssuranceExpiresAt = new Date(NOW.getTime() + 301_000);
		expect(
			validateStoredSessionAssurance({
				stored: fields,
				policy: multiPolicy(),
				now: NOW,
			}),
		).toEqual({ kind: "invalid", reason: "forged_assurance_expiry" });
	});

	it("rejects future primary and factor timestamps", () => {
		for (const field of [
			"authenticationPrimaryAt",
			"authenticationFactorAt",
		] as const) {
			const fields = stored(acceptedFields());
			fields[field] = new Date(NOW.getTime() + 1);
			expect(
				validateStoredSessionAssurance({
					stored: fields,
					policy: multiPolicy(),
					now: NOW,
				}),
			).toEqual({
				kind: "invalid",
				reason: "future_authentication_timestamp",
			});
		}
	});

	it("rejects stored factor authority that predates its primary", () => {
		const fields = stored(acceptedFields());
		fields.authenticationPrimaryAt = new Date("2026-07-17T09:59:30.000Z");
		fields.authenticationFactorAt = new Date("2026-07-17T09:59:00.000Z");
		fields.authenticationAssuranceExpiresAt = new Date(
			"2026-07-17T10:04:00.000Z",
		);

		expect(
			validateStoredSessionAssurance({
				stored: fields,
				policy: multiPolicy(),
				now: NOW,
			}),
		).toEqual({ kind: "invalid", reason: "malformed_authority" });
	});

	it("rejects non-canonical revisions as malformed authority", () => {
		for (const revision of [
			"0",
			"07",
			"-1",
			"latest",
			"",
			"9223372036854775808",
		]) {
			const result = validateStoredSessionAssurance({
				stored: {
					...stored(acceptedFields()),
					authenticationPolicyRevision: revision,
				},
				policy: multiPolicy(),
				now: NOW,
			});
			expect(result).toMatchObject({
				kind: "invalid",
				reason: "malformed_authority",
			});
		}
	});
});

describe("stripReservedSessionAuthority", () => {
	it("removes every reserved authority field and preserves unrelated data", () => {
		const authority = stored(
			satisfied([{ kind: "primary", primaryMethod: "password" }]),
		);
		const input = {
			...authority,
			activeOrganizationId: "organization-1",
			expiresAt: new Date("2026-07-18T00:00:00.000Z"),
			custom: { nested: true },
		};
		const stripped = stripReservedSessionAuthority(input);
		expect(stripped).toEqual({
			activeOrganizationId: "organization-1",
			expiresAt: new Date("2026-07-18T00:00:00.000Z"),
			custom: { nested: true },
		});
		for (const field of SESSION_ASSURANCE_RESERVED_FIELDS) {
			expect(Object.prototype.hasOwnProperty.call(stripped, field)).toBe(false);
		}
	});
});
