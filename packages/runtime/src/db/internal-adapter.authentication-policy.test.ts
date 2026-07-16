import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
	RuntimeAuthenticationPolicyReader,
	RuntimeAuthenticationPolicyReaderInput,
	RuntimeAuthenticationPolicyReaderResult,
	SessionIssuanceContext,
} from "@clearance/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { afterEach, describe, expect, it, vi } from "vitest";
import { init } from "../context/init";
import {
	attachInternalAuthenticationPolicy,
	InvalidRuntimeAuthenticationPolicyError,
} from "../internal/authentication-policy";
import {
	createInternalSessionIssuanceContext,
	ManagedSessionIssuanceError,
} from "../internal/session-issuance-context";
import { getMigrations } from "./get-migration";

const identity = Object.freeze({
	projectId: "project_1",
	environmentId: "environment_1",
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
		assuranceMaxAgeSeconds: 300,
		...override,
	};
}

function policyResult(
	input: RuntimeAuthenticationPolicyReaderInput,
	options: {
		policy?: RuntimeAuthenticationPolicy;
		revision?: string;
		scope?: RuntimeAuthenticationPolicyIdentity;
		membershipOrganizationId?: string | null;
	} = {},
): RuntimeAuthenticationPolicyReaderResult {
	const effective = options.policy ?? policy();
	const membershipOrganizationId =
		options.membershipOrganizationId === undefined
			? (input.organizationId ?? null)
			: options.membershipOrganizationId;
	return {
		scope: options.scope ?? identity,
		subjectId: input.subjectId,
		revision: options.revision ?? "7",
		environment: effective,
		organizationMembership: membershipOrganizationId
			? {
				subjectId: input.subjectId,
				organizationId: membershipOrganizationId,
			}
			: null,
		organizationOverride: null,
		effective,
	};
}

type ReaderImplementation = (
	input: RuntimeAuthenticationPolicyReaderInput,
) => RuntimeAuthenticationPolicyReaderResult;

const databases: DatabaseSync[] = [];

async function setupManagedRuntime(options?: {
	reader?: ReaderImplementation;
	options?: Omit<ClearanceOptions, "baseURL" | "secret" | "database">;
}) {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	const readForSubject = vi.fn(async (input: RuntimeAuthenticationPolicyReaderInput) =>
		(options?.reader ?? ((request) => policyResult(request)))(input),
	);
	const runtimeOptions = {
		baseURL: "http://localhost:3000",
		secret: "managed-session-issuance-integration-secret",
		database,
		...options?.options,
	} satisfies ClearanceOptions;
	attachInternalAuthenticationPolicy(runtimeOptions, {
		identity,
		reader: { readForSubject } satisfies RuntimeAuthenticationPolicyReader,
	});
	await (await getMigrations(runtimeOptions)).runMigrations();
	const context = await init(runtimeOptions);
	const user = await context.internalAdapter.createUser({
		email: `managed-${databases.length}@example.com`,
		name: "Managed Session User",
	});
	return { context, database, readForSubject, runtimeOptions, user };
}

async function authorityRows(
	context: Awaited<ReturnType<typeof init>>,
) {
	return context.adapter.findMany<Record<string, unknown>>({
		model: "session",
	});
}

async function expectNoIssuance(
	context: Awaited<ReturnType<typeof init>>,
) {
	expect(await context.adapter.count({ model: "session" })).toBe(0);
	expect(await context.adapter.count({ model: "sessionCredential" })).toBe(0);
}

afterEach(() => {
	vi.restoreAllMocks();
	for (const database of databases.splice(0)) database.close();
});

describe("managed session issuance", () => {
	it("reads policy uncached in the ambient transaction and stamps password authority", async () => {
		const { context, readForSubject, user } = await setupManagedRuntime();
		await context.internalAdapter.createSession(
			user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		await context.internalAdapter.createSession(
			user.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);

		expect(readForSubject).toHaveBeenCalledTimes(2);
		for (const [request] of readForSubject.mock.calls) {
			expect(request).toMatchObject({ subjectId: user.id });
			expect(request.transaction).toBeDefined();
		}
		const rows = await authorityRows(context);
		expect(rows).toHaveLength(2);
		for (const row of rows) {
			expect(row).toMatchObject({
				authenticationAssuranceVersion: 1,
				authenticationPolicyProjectId: identity.projectId,
				authenticationPolicyEnvironmentId: identity.environmentId,
				authenticationPrimaryMethod: "password",
				authenticationFactorMethod: null,
				authenticationPolicyOrganizationId: null,
				authenticationPolicyRevision: "7",
				authenticationRecoveryRestricted: false,
			});
			expect(row.authenticationPrimaryAt).toBeInstanceOf(Date);
			expect(row.authenticationAssuranceExpiresAt).toBeInstanceOf(Date);
		}
	});

	it.each([
		{
			label: "passkey",
			minimumAssurance: "phishing_resistant" as const,
			purpose: "interactive" as const,
			evidence: [{ kind: "primary" as const, primaryMethod: "passkey" as const }],
			expectedPrimaryMethod: "passkey",
		},
		{
			label: "impersonation",
			minimumAssurance: "single_factor" as const,
			purpose: "impersonation" as const,
			evidence: [
				{
					kind: "primary" as const,
					primaryMethod: "admin_impersonation" as const,
				},
			],
			expectedPrimaryMethod: "admin_impersonation",
		},
	])("stamps valid $label evidence", async (testCase) => {
		const { context, user } = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					policy: policy({
						minimumAssurance: testCase.minimumAssurance,
						trustedDevice: {
							enabled: false,
							maxAgeSeconds: 0,
						},
					}),
				}),
		});
		const issuanceContext = createInternalSessionIssuanceContext({
			purpose: testCase.purpose,
			subjectId: user.id,
			evidence: testCase.evidence,
		});

		await context.internalAdapter.createSession(
			user.id,
			false,
			undefined,
			false,
			issuanceContext,
		);

		expect(await authorityRows(context)).toEqual([
			expect.objectContaining({
				authenticationPrimaryMethod: testCase.expectedPrimaryMethod,
				authenticationPolicyRevision: "7",
			}),
		]);
	});

	it("fails closed for missing, forged, unsupported, and insufficient contexts without persistence or publication", async () => {
		const secondarySet = vi.fn(async () => {});
		const { context, user } = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					policy: policy({ minimumAssurance: "multi_factor" }),
				}),
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-session-issuance-test",
					get: async () => null,
					set: secondarySet,
					delete: async () => {},
				},
			},
		});
		const forged = {
			purpose: "interactive",
			evidence: [
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
		} as unknown as SessionIssuanceContext;
		const insufficient = createInternalSessionIssuanceContext({
			purpose: "interactive",
			subjectId: user.id,
			evidence: [{ kind: "primary", primaryMethod: "password" }],
		});
		const wrongSubject = createInternalSessionIssuanceContext({
			purpose: "interactive",
			subjectId: "another-user",
			evidence: [
				{ kind: "primary", primaryMethod: "password" },
				{ kind: "factor", factorMethod: "totp" },
			],
		});
		const replacement = createInternalSessionIssuanceContext({
			purpose: "replacement",
			sourceSessionToken: "source-session-token",
		});

		await expect(context.internalAdapter.createSession(user.id)).rejects.toMatchObject({
			code: "MANAGED_SESSION_ISSUANCE_FAILED",
			reason: "context_required",
		});
		await expect(
			context.internalAdapter.createSession(user.id, false, undefined, false, forged),
		).rejects.toMatchObject({ reason: "context_invalid" });
		await expect(
			context.internalAdapter.createSession(
				user.id,
				false,
				undefined,
				false,
				wrongSubject,
			),
		).rejects.toMatchObject({ reason: "subject_mismatch" });
		await expect(
			context.internalAdapter.createSession(
				user.id,
				false,
				undefined,
				false,
				replacement,
			),
		).rejects.toMatchObject({ reason: "unsupported_purpose" });

		const failure = await context.internalAdapter
			.createSession(user.id, false, undefined, false, insufficient)
			.catch((error: unknown) => error);
		expect(failure).toBeInstanceOf(ManagedSessionIssuanceError);
		if (!(failure instanceof ManagedSessionIssuanceError)) {
			throw failure;
		}
		if (!failure.requirement) throw new Error("Missing policy requirement");
		expect(failure).toMatchObject({
			reason: "policy_unsatisfied",
			requirement: {
				reason: "factor_required",
				projectId: identity.projectId,
				environmentId: identity.environmentId,
				organizationId: null,
				revision: "7",
				minimumAssurance: "multi_factor",
				allowedFactors: { totp: true, passkey: true },
			},
		});
		expect(Object.isFrozen(failure.requirement)).toBe(true);
		expect(Object.isFrozen(failure.requirement.allowedFactors)).toBe(true);
		await expectNoIssuance(context);
		expect(secondarySet).not.toHaveBeenCalled();
	});

	it.each([
		{
			label: "cross-scope policy",
			targetOrganizationId: null,
			reader: (input: RuntimeAuthenticationPolicyReaderInput) =>
				policyResult(input, {
					scope: { ...identity, environmentId: "environment_2" },
				}),
		},
		{
			label: "missing organization membership",
			targetOrganizationId: "organization_1",
			reader: (input: RuntimeAuthenticationPolicyReaderInput) =>
				policyResult(input, { membershipOrganizationId: null }),
		},
		{
			label: "cross-organization membership",
			targetOrganizationId: "organization_1",
			reader: (input: RuntimeAuthenticationPolicyReaderInput) =>
				policyResult(input, {
					membershipOrganizationId: "organization_2",
				}),
		},
	])("rejects $label before any authority is persisted", async (testCase) => {
		const { context, user } = await setupManagedRuntime({
			reader: testCase.reader,
		});
		const issuanceContext = createInternalSessionIssuanceContext({
			purpose: "interactive",
			subjectId: user.id,
			evidence: [{ kind: "primary", primaryMethod: "password" }],
			targetOrganizationId: testCase.targetOrganizationId,
		});

		await expect(
			context.internalAdapter.createSession(
				user.id,
				false,
				undefined,
				false,
				issuanceContext,
			),
		).rejects.toBeInstanceOf(InvalidRuntimeAuthenticationPolicyError);
		await expectNoIssuance(context);
	});

	it("overwrites reserved defaults, overrides, and hook output with evaluator authority", async () => {
		const { context, user } = await setupManagedRuntime({
			options: {
				session: {
					additionalFields: {
						authenticationPolicyRevision: {
							type: "string",
							defaultValue: "forged-default",
						},
					},
				},
				databaseHooks: {
					session: {
						create: {
							before: async (session) => ({
								data: {
									...session,
									authenticationAssuranceVersion: 999,
									authenticationPolicyProjectId: "forged-project",
									authenticationPolicyEnvironmentId: "forged-environment",
									authenticationPrimaryMethod: "anonymous",
									authenticationPolicyRevision: "999",
									authenticationRecoveryRestricted: true,
								},
							}),
						},
					},
				},
			},
		});
		const issuanceContext = createInternalSessionIssuanceContext({
			purpose: "interactive",
			subjectId: user.id,
			evidence: [{ kind: "primary", primaryMethod: "password" }],
		});

		await context.internalAdapter.createSession(
			user.id,
			false,
			{
				authenticationAssuranceVersion: 999,
				authenticationPolicyProjectId: "forged-project",
				authenticationPolicyEnvironmentId: "forged-environment",
				authenticationPrimaryMethod: "anonymous",
				authenticationPolicyRevision: "999",
				authenticationRecoveryRestricted: true,
			} as never,
			false,
			issuanceContext,
		);

		expect(await authorityRows(context)).toEqual([
			expect.objectContaining({
				authenticationAssuranceVersion: 1,
				authenticationPolicyProjectId: identity.projectId,
				authenticationPolicyEnvironmentId: identity.environmentId,
				authenticationPrimaryMethod: "password",
				authenticationPolicyRevision: "7",
				authenticationRecoveryRestricted: false,
			}),
		]);
	});

	it("preserves legacy session creation when no policy binding exists", async () => {
		const database = new DatabaseSync(":memory:");
		databases.push(database);
		const options = {
			baseURL: "http://localhost:3000",
			secret: "legacy-session-issuance-integration-secret",
			database,
		} satisfies ClearanceOptions;
		await (await getMigrations(options)).runMigrations();
		const context = await init(options);
		const user = await context.internalAdapter.createUser({
			email: "legacy@example.com",
			name: "Legacy Session User",
		});

		await expect(context.internalAdapter.createSession(user.id)).resolves.toBeDefined();
		expect(await authorityRows(context)).toEqual([
			expect.objectContaining({
				authenticationAssuranceVersion: null,
				authenticationPolicyRevision: null,
			}),
		]);
	});

	it("keeps managed issuance on its suspended owner across alternating runtime transactions", async () => {
		const first = await setupManagedRuntime();
		let secondPolicyTransaction: unknown;
		const second = await setupManagedRuntime({
			reader: (input) => {
				secondPolicyTransaction = input.transaction;
				return policyResult(input);
			},
		});
		let firstTransaction: unknown;
		let secondTransaction: unknown;

		await runWithTransaction(first.context.adapter, async () => {
			firstTransaction = await getCurrentAdapter(first.context.adapter);
			await runWithTransaction(second.context.adapter, async () => {
				secondTransaction = await getCurrentAdapter(second.context.adapter);
				await runWithTransaction(first.context.adapter, async () => {
					await second.context.internalAdapter.createSession(
						second.user.id,
						false,
						undefined,
						false,
						createInternalSessionIssuanceContext({
							purpose: "interactive",
							subjectId: second.user.id,
							evidence: [
								{ kind: "primary", primaryMethod: "password" },
							],
						}),
					);
				});
			});
		});

		expect(secondPolicyTransaction).toBeDefined();
		expect(secondPolicyTransaction).not.toBe(firstTransaction);
		expect(secondPolicyTransaction).toBe(secondTransaction);
		expect(await first.context.adapter.count({ model: "session" })).toBe(0);
		expect(await first.context.adapter.count({ model: "sessionCredential" })).toBe(
			0,
		);
		expect(await second.context.adapter.count({ model: "session" })).toBe(1);
		expect(
			await second.context.adapter.count({ model: "sessionCredential" }),
		).toBe(1);
	});
});
