import type {
	InternalAdapter,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyReader,
	RuntimeAuthenticationPolicyReaderResult,
	SessionIssuanceContext,
} from "@clearance/core";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { describe, expect, it, vi } from "vitest";
import {
	applyRuntimeAuthenticationPolicyOverride,
	attachCapturedInternalAuthenticationPolicy,
	attachInternalAuthenticationPolicy,
	InvalidRuntimeAuthenticationPolicyError,
	normalizeRuntimeAuthenticationPolicy,
	normalizeRuntimeAuthenticationPolicyOverride,
	readInternalAuthenticationPolicy,
	resolveRuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyReaderError,
} from "./authentication-policy";

// @ts-expect-error issuance contexts require the runtime-private authority brand
const structurallyForgedIssuanceContext: SessionIssuanceContext = {
	purpose: "interactive",
	evidence: [],
};
void structurallyForgedIssuanceContext;

function assertReservedSessionMutationContracts(
	adapter: InternalAdapter,
): void {
	void adapter.createSession("user_1", false, {
		customSessionField: "allowed",
	});
	void adapter.updateSession("session_1", { customSessionField: "allowed" });
	void adapter.createSession("user_1", false, {
		// @ts-expect-error runtime authentication authority cannot enter generic overrides
		authenticationPolicyRevision: "7",
	});
	void adapter.updateSession("session_1", {
		// @ts-expect-error runtime authentication authority cannot enter generic updates
		authenticationPolicyRevision: "7",
	});
}
void assertReservedSessionMutationContracts;

const identity = Object.freeze({
	projectId: "project_1",
	environmentId: "env_1",
});

function policy(
	override: Partial<RuntimeAuthenticationPolicy> = {},
): RuntimeAuthenticationPolicy {
	return {
		passwordLockout: {
			enabled: true,
			maxFailedAttempts: 10,
			durationSeconds: 900,
		},
		factorLockout: {
			enabled: true,
			maxFailedAttempts: 10,
			durationSeconds: 900,
		},
		minimumAssurance: "single_factor",
		allowedFactors: { totp: true, passkey: true },
		trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
		assuranceMaxAgeSeconds: null,
		...override,
	};
}

function result(
	override: Partial<RuntimeAuthenticationPolicyReaderResult> = {},
): RuntimeAuthenticationPolicyReaderResult {
	const environment = policy();
	return {
		scope: identity,
		subjectId: "user_1",
		revision: "5",
		environment,
		organizationMembership: null,
		organizationOverride: null,
		effective: environment,
		...override,
	};
}

function reader(response: RuntimeAuthenticationPolicyReaderResult) {
	return {
		readForSubject: vi.fn(async () => structuredClone(response)),
	} satisfies RuntimeAuthenticationPolicyReader;
}

describe("runtime authentication policy normalization", () => {
	it("normalizes and deeply freezes a complete bounded policy", () => {
		const normalized = normalizeRuntimeAuthenticationPolicy(policy());

		expect(normalized).toEqual(policy());
		expect(Object.isFrozen(normalized)).toBe(true);
		expect(Object.isFrozen(normalized.passwordLockout)).toBe(true);
		expect(Object.isFrozen(normalized.factorLockout)).toBe(true);
		expect(Object.isFrozen(normalized.allowedFactors)).toBe(true);
		expect(Object.isFrozen(normalized.trustedDevice)).toBe(true);
	});

	it.each([
		{ ...policy(), unexpected: true },
		{
			...policy(),
			passwordLockout: { ...policy().passwordLockout, unexpected: true },
		},
		{
			...policy(),
			passwordLockout: { ...policy().passwordLockout, maxFailedAttempts: 2 },
		},
		{
			...policy(),
			passwordLockout: { ...policy().passwordLockout, durationSeconds: 86_401 },
		},
		{
			...policy(),
			factorLockout: { ...policy().factorLockout, maxFailedAttempts: 101 },
		},
		{
			...policy(),
			factorLockout: { ...policy().factorLockout, durationSeconds: 29 },
		},
		{ ...policy(), assuranceMaxAgeSeconds: 59 },
		{ ...policy(), trustedDevice: { enabled: true, maxAgeSeconds: 59 } },
		{
			...policy(),
			minimumAssurance: "multi_factor",
			allowedFactors: { totp: false, passkey: false },
		},
		{
			...policy(),
			minimumAssurance: "phishing_resistant",
			allowedFactors: { totp: true, passkey: false },
			trustedDevice: { enabled: false, maxAgeSeconds: 0 },
		},
		{
			...policy(),
			minimumAssurance: "phishing_resistant",
			trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
		},
	])(
		"rejects malformed, out-of-bounds, and cross-field-invalid policy %#",
		(value) => {
			expect(() => normalizeRuntimeAuthenticationPolicy(value)).toThrow(
				InvalidRuntimeAuthenticationPolicyError,
			);
		},
	);

	it("strictly normalizes partial overrides and validates the merged policy", () => {
		const override = normalizeRuntimeAuthenticationPolicyOverride({
			minimumAssurance: "multi_factor",
			allowedFactors: { passkey: true },
			trustedDevice: { enabled: false },
			assuranceMaxAgeSeconds: 300,
		});
		const effective = applyRuntimeAuthenticationPolicyOverride(
			policy(),
			override,
		);

		expect(effective.minimumAssurance).toBe("multi_factor");
		expect(effective.allowedFactors).toEqual({ totp: true, passkey: true });
		expect(effective.trustedDevice).toEqual({
			enabled: false,
			maxAgeSeconds: 86_400,
		});
		expect(effective.assuranceMaxAgeSeconds).toBe(300);
		expect(() =>
			normalizeRuntimeAuthenticationPolicyOverride({
				allowedFactors: { sms: true },
			}),
		).toThrow(InvalidRuntimeAuthenticationPolicyError);
		expect(() =>
			applyRuntimeAuthenticationPolicyOverride(policy(), {
				minimumAssurance: "multi_factor",
				allowedFactors: { totp: false, passkey: false },
			}),
		).toThrow(InvalidRuntimeAuthenticationPolicyError);
	});

	it("accepts null-prototype data and rejects inherited, accessor, and symbol authority", () => {
		const nullPrototype = Object.assign(Object.create(null), {
			minimumAssurance: "multi_factor",
		});
		expect(normalizeRuntimeAuthenticationPolicyOverride(nullPrototype)).toEqual(
			{
				minimumAssurance: "multi_factor",
			},
		);

		const inherited = Object.create({ minimumAssurance: "multi_factor" });
		const accessor = {} as Record<string, unknown>;
		Object.defineProperty(accessor, "minimumAssurance", {
			enumerable: true,
			get: () => "multi_factor",
		});
		const symbolAuthority = { [Symbol("authority")]: true };
		for (const value of [inherited, accessor, symbolAuthority]) {
			expect(() => normalizeRuntimeAuthenticationPolicyOverride(value)).toThrow(
				InvalidRuntimeAuthenticationPolicyError,
			);
		}
	});
});

describe("runtime authentication policy reader binding", () => {
	it("stores a frozen captured non-enumerable binding", () => {
		const target = {};
		const other = {};
		const policyReader = reader(result());
		attachInternalAuthenticationPolicy(target, {
			identity,
			reader: policyReader,
		});

		const binding = readInternalAuthenticationPolicy(target);
		expect(binding?.identity).toEqual(identity);
		expect(binding?.reader).not.toBe(policyReader);
		expect(Object.isFrozen(binding)).toBe(true);
		expect(Object.isFrozen(binding?.identity)).toBe(true);
		expect(Object.isFrozen(binding?.reader)).toBe(true);
		expect(Object.keys(target)).toEqual([]);
		expect(readInternalAuthenticationPolicy(other)).toBeUndefined();
	});

	it("captures the reader method and rejects authority reattachment", async () => {
		const target = {};
		const policyReader = reader(result());
		attachInternalAuthenticationPolicy(target, {
			identity,
			reader: policyReader,
		});
		policyReader.readForSubject = vi.fn(async () =>
			result({
				scope: { projectId: "forged", environmentId: "forged" },
			}),
		);

		await expect(
			resolveRuntimeAuthenticationPolicy(target, { subjectId: "user_1" }),
		).resolves.toMatchObject({ scope: identity, subjectId: "user_1" });
		expect(policyReader.readForSubject).not.toHaveBeenCalled();
		expect(() =>
			attachInternalAuthenticationPolicy(target, {
				identity: { projectId: "forged", environmentId: "forged" },
				reader: reader(result()),
			}),
		).toThrow(InvalidRuntimeAuthenticationPolicyError);
	});

	it("propagates only the exact captured binding and permits idempotent reuse", () => {
		const source = {};
		const target = {};
		attachInternalAuthenticationPolicy(source, {
			identity,
			reader: reader(result()),
		});
		const binding = readInternalAuthenticationPolicy(source)!;

		expect(
			attachCapturedInternalAuthenticationPolicy(target, binding),
		).toBe(target);
		expect(readInternalAuthenticationPolicy(target)).toBe(binding);
		expect(
			attachCapturedInternalAuthenticationPolicy(target, binding),
		).toBe(target);
		expect(() =>
			attachCapturedInternalAuthenticationPolicy({}, {
				identity,
				reader: reader(result()),
			}),
		).toThrow(InvalidRuntimeAuthenticationPolicyError);

		const other = {};
		attachInternalAuthenticationPolicy(other, {
			identity,
			reader: reader(result()),
		});
		expect(() =>
			attachCapturedInternalAuthenticationPolicy(
				target,
				readInternalAuthenticationPolicy(other)!,
			),
		).toThrow(InvalidRuntimeAuthenticationPolicyError);
	});

	it("calls the reader for every resolution and forwards the ambient transaction", async () => {
		const target = {};
		const policyReader = reader(result());
		const transaction = {} as DBTransactionAdapter;
		attachInternalAuthenticationPolicy(target, {
			identity,
			reader: policyReader,
		});

		await resolveRuntimeAuthenticationPolicy(target, {
			subjectId: "user_1",
			transaction,
		});
		await resolveRuntimeAuthenticationPolicy(target, {
			subjectId: "user_1",
			transaction,
		});

		expect(policyReader.readForSubject).toHaveBeenCalledTimes(2);
		expect(policyReader.readForSubject).toHaveBeenNthCalledWith(1, {
			subjectId: "user_1",
			transaction,
		});
	});

	it("recomputes an exact organization override instead of trusting effective", async () => {
		const target = {};
		const environment = policy();
		const effective = policy({
			minimumAssurance: "multi_factor",
			trustedDevice: { enabled: false, maxAgeSeconds: 86_400 },
		});
		attachInternalAuthenticationPolicy(target, {
			identity,
			reader: reader(
				result({
					environment,
					organizationMembership: {
						subjectId: "user_1",
						organizationId: "org_1",
					},
					organizationOverride: {
						scope: identity,
						organizationId: "org_1",
						revision: "4",
						policy: {
							minimumAssurance: "multi_factor",
							trustedDevice: { enabled: false },
						},
					},
					effective,
				}),
			),
		});

		const resolved = await resolveRuntimeAuthenticationPolicy(target, {
			subjectId: "user_1",
			organizationId: "org_1",
		});

		expect(resolved.effective).toEqual(effective);
		expect(resolved.effective).not.toBe(effective);
		expect(Object.isFrozen(resolved.effective)).toBe(true);
	});

	it("requires an exact same-read subject and organization membership attestation", async () => {
		const cases = [
			{
				response: result({ subjectId: "user_2" }),
				request: { subjectId: "user_1" },
			},
			{
				response: result(),
				request: { subjectId: "user_1", organizationId: "org_1" },
			},
			{
				response: result({
					organizationMembership: {
						subjectId: "user_2",
						organizationId: "org_1",
					},
				}),
				request: { subjectId: "user_1", organizationId: "org_1" },
			},
			{
				response: result({
					organizationMembership: {
						subjectId: "user_1",
						organizationId: "org_2",
					},
				}),
				request: { subjectId: "user_1", organizationId: "org_1" },
			},
			{
				response: result({
					organizationMembership: {
						subjectId: "user_1",
						organizationId: "org_1",
					},
				}),
				request: { subjectId: "user_1" },
			},
		];

		for (const { response, request } of cases) {
			const target = {};
			attachInternalAuthenticationPolicy(target, {
				identity,
				reader: reader(response),
			});
			await expect(
				resolveRuntimeAuthenticationPolicy(target, request),
			).rejects.toBeInstanceOf(InvalidRuntimeAuthenticationPolicyError);
		}
	});

	it.each([
		result({ scope: { projectId: "other", environmentId: "env_1" } }),
		result({ revision: "0" }),
		result({ revision: "01" }),
		result({ revision: "-1" }),
		result({ revision: "9223372036854775808" }),
		result({ effective: policy({ assuranceMaxAgeSeconds: 300 }) }),
	])(
		"rejects invalid scope, revision, or claimed effective response %#",
		async (response) => {
			const target = {};
			attachInternalAuthenticationPolicy(target, {
				identity,
				reader: reader(response),
			});
			await expect(
				resolveRuntimeAuthenticationPolicy(target, { subjectId: "user_1" }),
			).rejects.toBeInstanceOf(InvalidRuntimeAuthenticationPolicyError);
		},
	);

	it("rejects wrong organizations, ahead overrides, and revision rollback", async () => {
		const override = {
			scope: identity,
			organizationId: "org_2",
			revision: "6",
			policy: {},
		};
		const target = {};
		attachInternalAuthenticationPolicy(target, {
			identity,
			reader: reader(
				result({
					organizationMembership: {
						subjectId: "user_1",
						organizationId: "org_1",
					},
					organizationOverride: override,
				}),
			),
		});

		await expect(
			resolveRuntimeAuthenticationPolicy(target, {
				subjectId: "user_1",
				organizationId: "org_1",
			}),
		).rejects.toBeInstanceOf(InvalidRuntimeAuthenticationPolicyError);

		const rollbackTarget = {};
		attachInternalAuthenticationPolicy(rollbackTarget, {
			identity,
			reader: reader(result({ revision: "5" })),
		});
		await expect(
			resolveRuntimeAuthenticationPolicy(rollbackTarget, {
				subjectId: "user_1",
				minimumRevision: "6",
			}),
		).rejects.toBeInstanceOf(InvalidRuntimeAuthenticationPolicyError);
	});

	it("keeps reader failures distinguishable from invalid authority responses", async () => {
		const target = {};
		attachInternalAuthenticationPolicy(target, {
			identity,
			reader: {
				readForSubject: async () => {
					throw new Error("database details must remain hidden");
				},
			},
		});

		await expect(
			resolveRuntimeAuthenticationPolicy(target, { subjectId: "user_1" }),
		).rejects.toMatchObject({
			name: "RuntimeAuthenticationPolicyReaderError",
			code: "AUTHENTICATION_POLICY_READER_UNAVAILABLE",
			message: "Authentication policy authority is unavailable",
		});
		await expect(
			resolveRuntimeAuthenticationPolicy({}, { subjectId: "user_1" }),
		).rejects.toBeInstanceOf(RuntimeAuthenticationPolicyReaderError);
	});
});
