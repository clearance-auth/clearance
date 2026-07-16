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
	AfterTransactionHookError,
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { afterEach, describe, expect, it, vi } from "vitest";
import { init } from "../context/init";
import {
	attachInternalAuthenticationPolicy,
	InvalidRuntimeAuthenticationPolicyError,
	RuntimeAuthenticationPolicyReaderError,
} from "../internal/authentication-policy";
import {
	createInternalSessionIssuanceContext,
	ManagedSessionIssuanceError,
} from "../internal/session-issuance-context";
import { attachInternalCredentialAuthority } from "../internal/credential-authority";
import { getMigrations } from "./get-migration";
import { generateCredentialOperationKey } from "../utils/operation-key";
import { SESSION_ASSURANCE_RESERVED_FIELDS } from "../security/session-assurance";
import { schema as passkeySchema } from "../plugins/passkey/schema";
import { schema as twoFactorSchema } from "../plugins/two-factor/schema";
import {
	createSessionHandle,
	digestSessionRefreshSecret,
	SESSION_ROTATION_RECOVERY_WINDOW_MS,
} from "./session-credential";

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
) =>
	| RuntimeAuthenticationPolicyReaderResult
	| Promise<RuntimeAuthenticationPolicyReaderResult>;

const databases: DatabaseSync[] = [];

function deferred() {
	let resolve!: () => void;
	const promise = new Promise<void>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

async function setupManagedRuntime(options?: {
	reader?: ReaderImplementation;
	options?: Omit<ClearanceOptions, "baseURL" | "secret" | "database">;
	credentialAuthority?: "legacy-v1";
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
	if (options?.credentialAuthority) {
		attachInternalCredentialAuthority(runtimeOptions, {
			generation: options.credentialAuthority,
		});
	}
	attachInternalAuthenticationPolicy(runtimeOptions, {
		identity,
		reader: { readForSubject } satisfies RuntimeAuthenticationPolicyReader,
	});
	await (await getMigrations(runtimeOptions)).runMigrations();
	if (options?.credentialAuthority === "legacy-v1") {
		database.exec(
			'DROP TRIGGER IF EXISTS "clearance_session_credential_authority_v1_insert"',
		);
		database.exec(
			'DROP TRIGGER IF EXISTS "clearance_session_credential_authority_v1_update"',
		);
	}
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

type ManagedRuntime = Awaited<ReturnType<typeof setupManagedRuntime>>;

async function issuePasswordSession(
	runtime: ManagedRuntime,
	options: {
		activeOrganizationId?: string;
		targetOrganizationId?: string;
	} = {},
) {
	return runtime.context.internalAdapter.createSession(
		runtime.user.id,
		false,
		options.activeOrganizationId
			? { activeOrganizationId: options.activeOrganizationId }
			: undefined,
		false,
		createInternalSessionIssuanceContext({
			purpose: "interactive",
			subjectId: runtime.user.id,
			evidence: [{ kind: "primary", primaryMethod: "password" }],
			targetOrganizationId: options.targetOrganizationId,
		}),
	);
}

async function credentialRows(runtime: ManagedRuntime) {
	return runtime.context.adapter.findMany<Record<string, unknown>>({
		model: "sessionCredential",
		sortBy: { field: "rotationCounter", direction: "asc" },
	});
}

afterEach(() => {
	vi.useRealTimers();
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

		expect(readForSubject).toHaveBeenCalledTimes(4);
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

	it("rolls back creation when an async before hook crosses policy or assurance authority", async () => {
		vi.useFakeTimers({ now: new Date("2033-01-01T00:00:00.000Z") });
		let liveRevision = "7";
		const revisionEntered = deferred();
		const revisionRelease = deferred();
		const revisionSet = vi.fn(async () => {});
		const revisionRuntime = await setupManagedRuntime({
			reader: (input) => policyResult(input, { revision: liveRevision }),
			options: {
				databaseHooks: {
					session: {
						create: {
							before: async (data) => {
								revisionEntered.resolve();
								await revisionRelease.promise;
								return { data };
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-create-revision-race-test",
					get: async () => null,
					set: revisionSet,
					delete: async () => {},
				},
			},
		});
		const revisionPending = issuePasswordSession(revisionRuntime);
		await revisionEntered.promise;
		liveRevision = "8";
		revisionRelease.resolve();
		await expect(revisionPending).rejects.toBeInstanceOf(
			ManagedSessionIssuanceError,
		);
		await expectNoIssuance(revisionRuntime.context);
		expect(revisionSet).not.toHaveBeenCalled();

		const deadlineEntered = deferred();
		const deadlineRelease = deferred();
		const deadlineSet = vi.fn(async () => {});
		const deadlineRuntime = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					policy: policy({ assuranceMaxAgeSeconds: 60 }),
				}),
			options: {
				databaseHooks: {
					session: {
						create: {
							before: async (data) => {
								deadlineEntered.resolve();
								await deadlineRelease.promise;
								return { data };
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-create-deadline-race-test",
					get: async () => null,
					set: deadlineSet,
					delete: async () => {},
				},
			},
		});
		const deadlinePending = issuePasswordSession(deadlineRuntime);
		await deadlineEntered.promise;
		await vi.advanceTimersByTimeAsync(61_000);
		deadlineRelease.resolve();
		await expect(deadlinePending).rejects.toBeInstanceOf(
			ManagedSessionIssuanceError,
		);
		await expectNoIssuance(deadlineRuntime.context);
		expect(deadlineSet).not.toHaveBeenCalled();
	});

	it("rolls back rollback-critical create hook authority mutation and failure", async () => {
		const secondarySet = vi.fn(async () => {});
		let hookMode: "mutate" | "throw" = "mutate";
		let runtime!: ManagedRuntime;
		runtime = await setupManagedRuntime({
			options: {
				databaseHookFailureMode: "rollback",
				databaseHooks: {
					session: {
						create: {
							after: async (created) => {
								if (hookMode === "throw") {
									throw new Error("managed create after hook failed");
								}
								const currentAdapter = await getCurrentAdapter(
									runtime.context.adapter,
								);
								await currentAdapter.update({
									model: "session",
									where: [{ field: "id", value: created.id }],
									update: {
										authenticationPolicyRevision: "forged",
										expiresAt: new Date(Date.now() + 120_000),
									},
								});
								await currentAdapter.updateMany({
									model: "sessionCredential",
									where: [{ field: "sessionId", value: created.id }],
									update: {
										familyId: "forged-family",
										rotationCounter: 99,
									},
								});
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-create-after-hook-test",
					get: async () => null,
					set: secondarySet,
					delete: async () => {},
				},
			},
		});

		await expect(issuePasswordSession(runtime)).rejects.toBeInstanceOf(
			ManagedSessionIssuanceError,
		);
		await expectNoIssuance(runtime.context);
		expect(secondarySet).not.toHaveBeenCalled();

		hookMode = "throw";
		await expect(issuePasswordSession(runtime)).rejects.toThrow(
			"managed create after hook failed",
		);
		await expectNoIssuance(runtime.context);
		expect(secondarySet).not.toHaveBeenCalled();
	});

	it.each(["consumed", "revoked"] as const)(
		"rolls back a modern create with an injected extra %s credential row",
		async (status) => {
			const secondarySet = vi.fn(async () => {});
			let runtime!: ManagedRuntime;
			runtime = await setupManagedRuntime({
				options: {
					databaseHookFailureMode: "rollback",
					databaseHooks: {
						session: {
							create: {
								after: async (created) => {
									const currentAdapter = await getCurrentAdapter(
										runtime.context.adapter,
									);
									const root = await currentAdapter.findOne<
										Record<string, unknown>
									>({
										model: "sessionCredential",
										where: [{ field: "sessionId", value: created.id }],
									});
									const now = new Date();
									await currentAdapter.create({
										model: "sessionCredential",
										forceAllowId: true,
										data: {
											id: `extra-${status}`,
											selector: `extra-selector-${status}`,
											sessionId: created.id,
											familyId: String(root!.familyId),
											secretDigest: `v1:extra-${status}`,
											digestVersion: 1,
											status,
											rotationCounter: 1,
											parentCredentialId: root!.id,
											expiresAt: root!.expiresAt,
											consumedAt: status === "consumed" ? now : null,
											revokedAt: status === "revoked" ? now : null,
											reuseDetectedAt: null,
											rotationNonceDigest: null,
											recoverySecretCiphertext: null,
											recoveryExpiresAt: null,
											createdAt: now,
											updatedAt: now,
										},
									});
								},
							},
						},
					},
					session: { storeSessionInDatabase: true },
					secondaryStorage: {
						namespace: `managed-create-extra-${status}-test`,
						get: async () => null,
						set: secondarySet,
						delete: async () => {},
					},
				},
			});

			await expect(issuePasswordSession(runtime)).rejects.toBeInstanceOf(
				ManagedSessionIssuanceError,
			);
			await expectNoIssuance(runtime.context);
			expect(secondarySet).not.toHaveBeenCalled();
		},
	);

	it("rolls back a legacy create with any injected credential row", async () => {
		const secondarySet = vi.fn(async () => {});
		let runtime!: ManagedRuntime;
		runtime = await setupManagedRuntime({
			credentialAuthority: "legacy-v1",
			options: {
				databaseHookFailureMode: "rollback",
				databaseHooks: {
					session: {
						create: {
							after: async (created) => {
								const now = new Date();
								await (
									await getCurrentAdapter(runtime.context.adapter)
								).create({
									model: "sessionCredential",
									forceAllowId: true,
									data: {
										id: "legacy-extra-credential",
										selector: "legacy-extra-selector",
										sessionId: created.id,
										familyId: "legacy-extra-family",
										secretDigest: "v1:legacy-extra",
										digestVersion: 1,
										status: "active",
										rotationCounter: 0,
										parentCredentialId: null,
										expiresAt: created.expiresAt,
										consumedAt: null,
										revokedAt: null,
										reuseDetectedAt: null,
										rotationNonceDigest: null,
										recoverySecretCiphertext: null,
										recoveryExpiresAt: null,
										createdAt: now,
										updatedAt: now,
									},
								});
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-create-legacy-extra-credential-test",
					get: async () => null,
					set: secondarySet,
					delete: async () => {},
				},
			},
		});

		await expect(issuePasswordSession(runtime)).rejects.toBeInstanceOf(
			ManagedSessionIssuanceError,
		);
		await expectNoIssuance(runtime.context);
		expect(secondarySet).not.toHaveBeenCalled();
	});

	it.each([
		{ label: "modern", credentialAuthority: undefined },
		{ label: "legacy", credentialAuthority: "legacy-v1" as const },
	])(
		"publishes exact $label create authority once and only after outer commit",
		async ({ label, credentialAuthority }) => {
			const namespace = `managed-create-${label}-publication-test`;
			const store = new Map<string, string>();
			const publishedKeys: string[] = [];
			const secondarySet = vi.fn(async (key: string, value: string) => {
				publishedKeys.push(key);
				store.set(key, value);
			});
			const secondaryDelete = vi.fn(async (key: string) => {
				store.delete(key);
			});
			const runtime = await setupManagedRuntime({
				...(credentialAuthority ? { credentialAuthority } : {}),
				options: {
					session: { storeSessionInDatabase: true },
					secondaryStorage: {
						namespace,
						get: async (key) => store.get(key) ?? null,
						set: secondarySet,
						delete: secondaryDelete,
					},
				},
			});

			await expect(
				runWithTransaction(runtime.context.adapter, async () => {
					await issuePasswordSession(runtime);
					expect(secondarySet).not.toHaveBeenCalled();
					expect(secondaryDelete).not.toHaveBeenCalled();
					throw new Error(`${label} create outer rollback`);
				}),
			).rejects.toThrow(`${label} create outer rollback`);
			await expectNoIssuance(runtime.context);
			expect(store).toEqual(new Map());
			expect(secondarySet).not.toHaveBeenCalled();
			expect(secondaryDelete).not.toHaveBeenCalled();

			let issued!: Awaited<ReturnType<typeof issuePasswordSession>>;
			await runWithTransaction(runtime.context.adapter, async () => {
				issued = await issuePasswordSession(runtime);
				expect(secondarySet).not.toHaveBeenCalled();
				expect(secondaryDelete).not.toHaveBeenCalled();
			});

			const persistedSession = (await authorityRows(runtime.context))[0]!;
			const persistedUser = await runtime.context.adapter.findOne<
				Record<string, unknown>
			>({
				model: "user",
				where: [{ field: "id", value: runtime.user.id }],
			});
			const credentials = await credentialRows(runtime);
			const expectedDigest =
				credentialAuthority === "legacy-v1"
					? await digestSessionRefreshSecret(issued.token)
					: String(credentials[0]!.secretDigest);
			const credentialKey =
				`clearance:${namespace}:session-credential:${expectedDigest}`;
			const handleKey = `clearance:${namespace}:session-handle:${issued.id}`;
			const indexKey =
				`clearance:${namespace}:active-sessions:${runtime.user.id}`;

			expect(credentials).toHaveLength(
				credentialAuthority === "legacy-v1" ? 0 : 1,
			);
			if (credentialAuthority !== "legacy-v1") {
				expect(credentials[0]).toMatchObject({
					sessionId: issued.id,
					status: "active",
					rotationCounter: 0,
					parentCredentialId: null,
				});
				expect(credentials[0]!.familyId).toEqual(expect.any(String));
				expect((credentials[0]!.expiresAt as Date).getTime()).toBe(
					(persistedSession.expiresAt as Date).getTime(),
				);
			}
			expect(publishedKeys).toEqual([credentialKey, handleKey, indexKey]);
			expect(secondarySet).toHaveBeenCalledTimes(3);
			expect(secondaryDelete).not.toHaveBeenCalled();
			expect(JSON.parse(store.get(credentialKey)!)).toEqual({
				session: JSON.parse(
					JSON.stringify({ ...persistedSession, token: null }),
				),
				user: JSON.parse(JSON.stringify(persistedUser)),
			});
			expect(JSON.parse(store.get(handleKey)!)).toEqual({ credentialKey });
			expect(JSON.parse(store.get(indexKey)!)).toEqual([
				{
					sessionId: issued.id,
					credentialKey,
					expiresAt: (persistedSession.expiresAt as Date).getTime(),
				},
			]);
		},
	);

	it("publishes the latest managed update committed before create publication", async () => {
		const store = new Map<string, string>();
		const createHookEntered = deferred();
		const createHookRelease = deferred();
		let createdSessionId = "";
		const runtime = await setupManagedRuntime({
			options: {
				databaseHooks: {
					session: {
						create: {
							after: async (created) => {
								createdSessionId = created.id;
								createHookEntered.resolve();
								await createHookRelease.promise;
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-create-update-serializer-test",
					get: async (key) => store.get(key) ?? null,
					set: async (key, value) => {
						store.set(key, value);
					},
					delete: async (key) => {
						store.delete(key);
					},
				},
			},
		});

		const pendingCreate = issuePasswordSession(runtime);
		await createHookEntered.promise;
		try {
			await expect(
				runtime.context.internalAdapter.updateSession(
					createSessionHandle(createdSessionId),
					{ ipAddress: "192.0.2.90" },
				),
			).resolves.toMatchObject({ ipAddress: "192.0.2.90" });
		} finally {
			createHookRelease.resolve();
		}
		const issued = await pendingCreate;
		const persistedSession = (await authorityRows(runtime.context))[0]!;
		const persistedUser = await runtime.context.adapter.findOne<
			Record<string, unknown>
		>({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
		});
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${issued.id}`),
		)!;
		const credentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		expect(JSON.parse(store.get(credentialKey)!)).toEqual({
			session: JSON.parse(
				JSON.stringify({ ...persistedSession, token: null }),
			),
			user: JSON.parse(JSON.stringify(persistedUser)),
		});
		expect(persistedSession.ipAddress).toBe("192.0.2.90");
	});

	it("publishes a verified rotation descendant committed before create publication", async () => {
		const store = new Map<string, string>();
		const createHookEntered = deferred();
		const createHookRelease = deferred();
		let createdSessionId = "";
		const runtime = await setupManagedRuntime({
			options: {
				databaseHooks: {
					session: {
						create: {
							after: async (created) => {
								createdSessionId = created.id;
								createHookEntered.resolve();
								await createHookRelease.promise;
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-create-newer-successor-test",
					get: async (key) => store.get(key) ?? null,
					set: async (key, value) => {
						store.set(key, value);
					},
					delete: async (key) => {
						store.delete(key);
					},
				},
			},
		});

		const pendingCreate = issuePasswordSession(runtime);
		await createHookEntered.promise;
		let successorDigest = "";
		try {
			await runWithTransaction(runtime.context.adapter, async () => {
				const currentAdapter = await getCurrentAdapter(runtime.context.adapter);
				const root = await currentAdapter.findOne<Record<string, unknown>>({
					model: "sessionCredential",
					where: [{ field: "sessionId", value: createdSessionId }],
				});
				const now = new Date();
				await currentAdapter.update({
					model: "sessionCredential",
					where: [{ field: "id", value: String(root!.id) }],
					update: {
						status: "consumed",
						consumedAt: now,
						rotationNonceDigest: "create-race-operation",
						recoveryExpiresAt: new Date(
							now.getTime() + SESSION_ROTATION_RECOVERY_WINDOW_MS,
						),
						updatedAt: now,
					},
				});
				const successorId = `create-race-${String(root!.id)}`;
				successorDigest = `digest-${successorId}`;
				await currentAdapter.create({
					model: "sessionCredential",
					forceAllowId: true,
					data: {
						...root,
						id: successorId,
						selector: `selector-${successorId}`,
						secretDigest: successorDigest,
						status: "active",
						rotationCounter: 1,
						parentCredentialId: root!.id,
						consumedAt: null,
						revokedAt: null,
						reuseDetectedAt: null,
						rotationNonceDigest: null,
						recoverySecretCiphertext: null,
						recoveryExpiresAt: null,
						createdAt: now,
						updatedAt: now,
					},
				});
			});
		} finally {
			createHookRelease.resolve();
		}
		const issued = await pendingCreate;
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${issued.id}`),
		)!;
		const successorKey =
			`clearance:managed-create-newer-successor-test:` +
			`session-credential:${successorDigest}`;
		expect(JSON.parse(store.get(handleKey)!)).toEqual({
			credentialKey: successorKey,
		});
		expect(store.has(successorKey)).toBe(true);
	});

	it.each(["policy", "delete"] as const)(
		"cleans owned create publication state after a committed %s invalidation",
		async (invalidation) => {
			const store = new Map<string, string>();
			const createHookEntered = deferred();
			const createHookRelease = deferred();
			let createdSessionId = "";
			let liveRevision = "7";
			const namespace = `managed-create-${invalidation}-cleanup-test`;
			const runtime = await setupManagedRuntime({
				reader: (input) => policyResult(input, { revision: liveRevision }),
				options: {
					databaseHooks: {
						session: {
							create: {
								after: async (created) => {
									createdSessionId = created.id;
									createHookEntered.resolve();
									await createHookRelease.promise;
								},
							},
						},
					},
					session: { storeSessionInDatabase: true },
					secondaryStorage: {
						namespace,
						get: async (key) => store.get(key) ?? null,
						set: async (key, value) => {
							store.set(key, value);
						},
						delete: async (key) => {
							store.delete(key);
						},
					},
				},
			});

			const pendingCreate = issuePasswordSession(runtime);
			await createHookEntered.promise;
			const credential = await runtime.context.adapter.findOne<
				Record<string, unknown>
			>({
				model: "sessionCredential",
				where: [{ field: "sessionId", value: createdSessionId }],
			});
			const expectedKey =
				`clearance:${namespace}:session-credential:${String(credential!.secretDigest)}`;
			const mappedKey = `clearance:${namespace}:session-credential:mapped`;
			const unrelatedKey = `clearance:${namespace}:session-credential:unrelated`;
			const handleKey =
				`clearance:${namespace}:session-handle:${createdSessionId}`;
			const indexKey =
				`clearance:${namespace}:active-sessions:${runtime.user.id}`;
			store.set(expectedKey, JSON.stringify({ session: { id: createdSessionId } }));
			store.set(mappedKey, JSON.stringify({ session: { id: createdSessionId } }));
			store.set(unrelatedKey, JSON.stringify({ session: { id: "other" } }));
			store.set(handleKey, JSON.stringify({ credentialKey: mappedKey }));
			store.set(
				indexKey,
				JSON.stringify([
					{
						sessionId: createdSessionId,
						credentialKey: mappedKey,
						expiresAt: Date.now() + 600_000,
					},
					{
						sessionId: "other",
						credentialKey: unrelatedKey,
						expiresAt: Date.now() + 600_000,
					},
				]),
			);
			try {
				if (invalidation === "policy") {
					liveRevision = "8";
				} else {
					await runtime.context.internalAdapter.deleteSessionById(
						createdSessionId,
					);
				}
			} finally {
				createHookRelease.resolve();
			}
			await expect(pendingCreate).rejects.toBeInstanceOf(
				AfterTransactionHookError,
			);
			expect(store.has(expectedKey)).toBe(false);
			expect(store.has(mappedKey)).toBe(false);
			expect(store.has(handleKey)).toBe(false);
			expect(store.get(unrelatedKey)).toBe(
				JSON.stringify({ session: { id: "other" } }),
			);
			expect(JSON.parse(store.get(indexKey)!)).toEqual([
				{
					sessionId: "other",
					credentialKey: unrelatedKey,
					expiresAt: expect.any(Number),
				},
			]);
		},
	);

	it("cleans every discovered owned credential envelope after invalid create publication", async () => {
		const namespace = "managed-create-discovered-cleanup-test";
		const store = new Map<string, string>();
		let expectedKey = "";
		let unexpectedKey = "";
		let malformedKey = "";
		const crossSessionKey =
			`clearance:${namespace}:session-credential:cross-session`;
		let handleKey = "";
		let indexKey = "";
		let createdSessionId = "";
		const createHookEntered = deferred();
		const createHookRelease = deferred();
		let runtime!: ManagedRuntime;
		runtime = await setupManagedRuntime({
			options: {
				databaseHooks: {
					session: {
						create: {
							after: async (created) => {
								createdSessionId = created.id;
								createHookEntered.resolve();
								await createHookRelease.promise;
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace,
					get: async (key) => store.get(key) ?? null,
					set: async (key, value) => {
						store.set(key, value);
					},
					delete: async (key) => {
						store.delete(key);
					},
				},
			},
		});

		const pendingCreate = issuePasswordSession(runtime);
		await createHookEntered.promise;
		try {
			await runWithTransaction(runtime.context.adapter, async () => {
				const currentAdapter = await getCurrentAdapter(runtime.context.adapter);
				const root = await currentAdapter.findOne<Record<string, unknown>>({
					model: "sessionCredential",
					where: [{ field: "sessionId", value: createdSessionId }],
				});
				const now = new Date();
				const createUnexpected = async (input: {
					id: string;
					secretDigest: string;
					status: "consumed" | "revoked";
					parentCredentialId: unknown;
					rotationCounter: number;
				}) =>
					currentAdapter.create({
						model: "sessionCredential",
						forceAllowId: true,
						data: {
							...root,
							id: input.id,
							selector: `selector-${input.id}`,
							secretDigest: input.secretDigest,
							status: input.status,
							rotationCounter: input.rotationCounter,
							parentCredentialId: input.parentCredentialId,
							consumedAt: input.status === "consumed" ? now : null,
							revokedAt: input.status === "revoked" ? now : null,
							reuseDetectedAt: null,
							rotationNonceDigest: null,
							recoverySecretCiphertext: null,
							recoveryExpiresAt: null,
							createdAt: now,
							updatedAt: now,
						},
					});
				const unexpectedDigest = `v1:${"A".repeat(43)}`;
				const malformedEnvelopeDigest = `v1:${"B".repeat(43)}`;
				await createUnexpected({
					id: "unexpected-consumed-credential",
					secretDigest: unexpectedDigest,
					status: "consumed",
					parentCredentialId: root!.id,
					rotationCounter: 1,
				});
				await createUnexpected({
					id: "unexpected-revoked-credential",
					secretDigest: malformedEnvelopeDigest,
					status: "revoked",
					parentCredentialId: "unexpected-consumed-credential",
					rotationCounter: 2,
				});
				expectedKey =
					`clearance:${namespace}:session-credential:` +
					String(root!.secretDigest);
				unexpectedKey =
					`clearance:${namespace}:session-credential:${unexpectedDigest}`;
				malformedKey =
					`clearance:${namespace}:session-credential:${malformedEnvelopeDigest}`;
				handleKey =
					`clearance:${namespace}:session-handle:${createdSessionId}`;
				indexKey =
					`clearance:${namespace}:active-sessions:${runtime.user.id}`;
				store.set(
					expectedKey,
					JSON.stringify({ session: { id: createdSessionId } }),
				);
				store.set(
					unexpectedKey,
					JSON.stringify({ session: { id: createdSessionId } }),
				);
				store.set(malformedKey, "not-json");
				store.set(
					crossSessionKey,
					JSON.stringify({ session: { id: "other-session" } }),
				);
				store.set(handleKey, JSON.stringify({ credentialKey: crossSessionKey }));
				store.set(
					indexKey,
					JSON.stringify([
						{
							sessionId: createdSessionId,
							credentialKey: unexpectedKey,
							expiresAt: Date.now() + 600_000,
						},
						{
							sessionId: "other-session",
							credentialKey: crossSessionKey,
							expiresAt: Date.now() + 600_000,
						},
					]),
				);
			});
		} finally {
			createHookRelease.resolve();
		}
		await expect(pendingCreate).rejects.toBeInstanceOf(
			AfterTransactionHookError,
		);
		expect(store.has(expectedKey)).toBe(false);
		expect(store.has(unexpectedKey)).toBe(false);
		expect(store.get(malformedKey)).toBe("not-json");
		expect(store.get(crossSessionKey)).toBe(
			JSON.stringify({ session: { id: "other-session" } }),
		);
		expect(store.has(handleKey)).toBe(false);
		expect(JSON.parse(store.get(indexKey)!)).toEqual([
			{
				sessionId: "other-session",
				credentialKey: crossSessionKey,
				expiresAt: expect.any(Number),
			},
		]);
	});

	it("reports create publication failure after committing exact database authority", async () => {
		const secondarySet = vi.fn(async () => {
			throw new Error("managed create publication failed");
		});
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-create-publication-failure-test",
					get: async () => null,
					set: secondarySet,
					delete: async () => {},
				},
			},
		});

		await expect(issuePasswordSession(runtime)).rejects.toBeInstanceOf(
			AfterTransactionHookError,
		);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(
			await runtime.context.adapter.count({ model: "sessionCredential" }),
		).toBe(1);
		expect(secondarySet).toHaveBeenCalledTimes(1);
	});
});

describe("managed stored session authority", () => {
	it("rechecks assurance, session, and credential expiry after a delayed reader", async () => {
		vi.useFakeTimers({ now: new Date("2030-01-01T00:00:00.000Z") });
		let gate: ReturnType<typeof deferred> | null = null;
		let readerEntered: ReturnType<typeof deferred> | null = null;
		const runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (gate && readerEntered) {
					readerEntered.resolve();
					await gate.promise;
				}
				return policyResult(input);
			},
		});
		const crossExpiry = async (operation: () => Promise<unknown>) => {
			gate = deferred();
			readerEntered = deferred();
			const pending = operation();
			await readerEntered.promise;
			await vi.advanceTimersByTimeAsync(2_000);
			gate.resolve();
			const result = await pending;
			gate = null;
			readerEntered = null;
			return result;
		};

		const assuranceSession = await issuePasswordSession(runtime);
		await runtime.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: assuranceSession.id }],
			update: {
				authenticationAssuranceExpiresAt: new Date(Date.now() + 1_000),
			},
		});
		expect(
			await crossExpiry(() =>
				runtime.context.internalAdapter.findSession(assuranceSession.token),
			),
		).toBeNull();

		const expiringSession = await issuePasswordSession(runtime);
		await runtime.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: expiringSession.id }],
			update: { expiresAt: new Date(Date.now() + 1_000) },
		});
		expect(
			await crossExpiry(() =>
				runtime.context.internalAdapter.findSession(expiringSession.token),
			),
		).toBeNull();

		const credentialSession = await issuePasswordSession(runtime);
		await runtime.context.adapter.update({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: credentialSession.id }],
			update: { expiresAt: new Date(Date.now() + 1_000) },
		});
		expect(
			await crossExpiry(() =>
				runtime.context.internalAdapter.findSession(credentialSession.token),
			),
		).toBeNull();
	});

	it("re-reads accepted findSession authority uncached in the owning transaction", async () => {
		const runtime = await setupManagedRuntime();
		const session = await issuePasswordSession(runtime);
		runtime.readForSubject.mockClear();
		let ownerTransaction: unknown;

		await runWithTransaction(runtime.context.adapter, async () => {
			ownerTransaction = await getCurrentAdapter(runtime.context.adapter);
			const found = await runtime.context.internalAdapter.findSession(
				session.token,
			);
			expect(found?.session.id).toBe(session.id);
			expect(
				(found?.session as Record<string, unknown>)
					?.authenticationPolicyRevision,
			).toBeUndefined();
		});

		expect(runtime.readForSubject).toHaveBeenCalledOnce();
		expect(runtime.readForSubject.mock.calls[0]?.[0].transaction).toBe(
			ownerTransaction,
		);
		await expect(
			runtime.context.internalAdapter.findSession(session.token),
		).resolves.toMatchObject({ session: { id: session.id } });
		expect(runtime.readForSubject).toHaveBeenCalledTimes(2);
	});

	it("fails the same stored session after revision, policy, expiry, or authority corruption", async () => {
		let liveRevision = "7";
		let livePolicy = policy();
		const runtime = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					revision: liveRevision,
					policy: livePolicy,
				}),
		});

		const revisionSession = await issuePasswordSession(runtime);
		liveRevision = "8";
		await expect(
			runtime.context.internalAdapter.findSession(revisionSession.token),
		).resolves.toBeNull();
		liveRevision = "7";

		const stricterSession = await issuePasswordSession(runtime);
		livePolicy = policy({ minimumAssurance: "multi_factor" });
		await expect(
			runtime.context.internalAdapter.findSession(stricterSession.token),
		).resolves.toBeNull();
		livePolicy = policy();

		const expiredAssurance = await issuePasswordSession(runtime);
		await runtime.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: expiredAssurance.id }],
			update: {
				authenticationAssuranceExpiresAt: new Date(Date.now() - 1_000),
			},
		});
		await expect(
			runtime.context.internalAdapter.findSession(expiredAssurance.token),
		).resolves.toBeNull();

		const malformedAuthority = await issuePasswordSession(runtime);
		await runtime.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: malformedAuthority.id }],
			update: { authenticationAssuranceVersion: 2 },
		});
		await expect(
			runtime.context.internalAdapter.findSession(malformedAuthority.token),
		).resolves.toBeNull();
	});

	it("rejects active organization mismatch before consulting the policy reader", async () => {
		const runtime = await setupManagedRuntime({
			options: {
				session: {
					additionalFields: {
						activeOrganizationId: {
							type: "string",
							required: false,
						},
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime, {
			activeOrganizationId: "organization_1",
			targetOrganizationId: "organization_1",
		});
		await runtime.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: session.id }],
			update: { activeOrganizationId: "organization_2" },
		});
		runtime.readForSubject.mockClear();

		await expect(
			runtime.context.internalAdapter.findSession(session.token),
		).resolves.toBeNull();
		await expect(
			runtime.context.internalAdapter.findSessionById(session.id),
		).resolves.toBeNull();
		expect(runtime.readForSubject).not.toHaveBeenCalled();
	});

	it("applies identical live authority enforcement to findSessionById", async () => {
		let liveRevision = "7";
		const runtime = await setupManagedRuntime({
			reader: (input) => policyResult(input, { revision: liveRevision }),
		});
		const session = await issuePasswordSession(runtime);
		runtime.readForSubject.mockClear();

		await expect(
			runtime.context.internalAdapter.findSessionById(session.id),
		).resolves.toMatchObject({ session: { id: session.id } });
		expect(runtime.readForSubject).toHaveBeenCalledOnce();
		expect(runtime.readForSubject.mock.calls[0]?.[0].transaction).toBeDefined();

		liveRevision = "8";
		await expect(
			runtime.context.internalAdapter.findSessionById(session.id),
		).resolves.toBeNull();
		expect(runtime.readForSubject).toHaveBeenCalledTimes(2);
	});

	it("does not consume, create, or publish rotation state after policy change", async () => {
		let liveRevision = "7";
		const secondarySet = vi.fn(async () => {});
		const secondaryDelete = vi.fn(async () => {});
		const runtime = await setupManagedRuntime({
			reader: (input) => policyResult(input, { revision: liveRevision }),
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-live-rotation-test",
					get: async () => null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const before = structuredClone(await credentialRows(runtime));
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		liveRevision = "8";

		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			),
		).resolves.toBeNull();
		expect(await credentialRows(runtime)).toEqual(before);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("does not rotate after the matched credential expires during a delayed reader", async () => {
		vi.useFakeTimers({ now: new Date("2030-01-01T00:00:00.000Z") });
		let gate: ReturnType<typeof deferred> | null = null;
		const readerEntered = deferred();
		const secondarySet = vi.fn(async () => {});
		const secondaryDelete = vi.fn(async () => {});
		const runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (gate) {
					readerEntered.resolve();
					await gate.promise;
				}
				return policyResult(input);
			},
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-delayed-rotation-test",
					get: async () => null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		await runtime.context.adapter.update({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: session.id }],
			update: { expiresAt: new Date(Date.now() + 1_000) },
		});
		const before = structuredClone(await credentialRows(runtime));
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		gate = deferred();

		const pending = runtime.context.internalAdapter.rotateSessionCredential(
			session.token,
			generateCredentialOperationKey(),
		);
		await readerEntered.promise;
		await vi.advanceTimersByTimeAsync(2_000);
		gate.resolve();
		await expect(pending).resolves.toBeNull();
		expect(await credentialRows(runtime)).toEqual(before);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("serializes managed expiry updates on both sides of the rotation reread", async () => {
		let updateBeforeReread = false;
		let firstSessionId = "";
		const beforeRereadExpiry = new Date(Date.now() + 180_000);
		const firstRuntime = await setupManagedRuntime({
			reader: async (input) => {
				if (updateBeforeReread) {
					updateBeforeReread = false;
					await input.transaction!.update({
						model: "session",
						where: [{ field: "id", value: firstSessionId }],
						update: { expiresAt: beforeRereadExpiry },
					});
					await input.transaction!.updateMany({
						model: "sessionCredential",
						where: [{ field: "sessionId", value: firstSessionId }],
						update: { expiresAt: beforeRereadExpiry },
					});
				}
				return policyResult(input);
			},
		});
		const firstSession = await issuePasswordSession(firstRuntime);
		firstSessionId = firstSession.id;
		updateBeforeReread = true;
		const firstRotation = await firstRuntime.context.internalAdapter.rotateSessionCredential(
			firstSession.token,
			generateCredentialOperationKey(),
		);
		expect(firstRotation).not.toBeNull();
		const firstRows = await credentialRows(firstRuntime);
		expect(firstRows).toHaveLength(2);
		expect(
			firstRows.every(
				(row) =>
					(row.expiresAt as Date).getTime() === beforeRereadExpiry.getTime(),
			),
		).toBe(true);
		expect(
			((await authorityRows(firstRuntime.context))[0]!.expiresAt as Date).getTime(),
		).toBe(beforeRereadExpiry.getTime());

		let secondRuntime!: ManagedRuntime;
		let secondSessionId = "";
		let updateAtCasBoundary = false;
		let generatedId = 0;
		const raceSecondarySet = vi.fn(async () => {});
		const raceSecondaryDelete = vi.fn(async () => {});
		const casBoundaryExpiry = new Date(Date.now() + 240_000);
		secondRuntime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-rotation-expiry-race-test",
					get: async () => null,
					set: raceSecondarySet,
					delete: raceSecondaryDelete,
				},
				advanced: {
					database: {
						generateId: ({ model }) => {
							if (
								updateAtCasBoundary &&
								model === "sessionCredential"
							) {
								updateAtCasBoundary = false;
								const stored = secondRuntime.database
									.prepare(
										'SELECT "expiresAt" FROM "session" WHERE "id" = ?',
									)
									.get(secondSessionId) as { expiresAt: number | string };
								const encodedExpiry =
									typeof stored.expiresAt === "number"
										? casBoundaryExpiry.getTime()
										: casBoundaryExpiry.toISOString();
								secondRuntime.database
									.prepare(
										'UPDATE "session" SET "expiresAt" = ? WHERE "id" = ?',
									)
									.run(encodedExpiry, secondSessionId);
								secondRuntime.database
									.prepare(
										'UPDATE "sessionCredential" SET "expiresAt" = ? WHERE "sessionId" = ?',
									)
									.run(encodedExpiry, secondSessionId);
							}
							generatedId += 1;
							return `${model}-${generatedId}`;
						},
					},
				},
			},
		});
		const secondSession = await issuePasswordSession(secondRuntime);
		secondSessionId = secondSession.id;
		raceSecondarySet.mockClear();
		raceSecondaryDelete.mockClear();
		updateAtCasBoundary = true;
		await expect(
			secondRuntime.context.internalAdapter.rotateSessionCredential(
				secondSession.token,
				generateCredentialOperationKey(),
			),
		).resolves.toBeNull();
		const secondRows = await credentialRows(secondRuntime);
		expect(secondRows).toHaveLength(1);
		expect(secondRows[0]).toMatchObject({ status: "active", rotationCounter: 0 });
		expect((secondRows[0]!.expiresAt as Date).getTime()).toBe(
			casBoundaryExpiry.getTime(),
		);
		expect(await secondRuntime.context.adapter.count({ model: "session" })).toBe(1);
		expect(raceSecondarySet).not.toHaveBeenCalled();
		expect(raceSecondaryDelete).not.toHaveBeenCalled();
	});

	it("rolls back a post-CAS authority race and returns null", async () => {
		let racePostCas = false;
		let rotationPolicyReads = 0;
		let rotationSessionId = "";
		let runtime!: ManagedRuntime;
		const secondarySet = vi.fn(async () => {});
		const secondaryDelete = vi.fn(async () => {});
		runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (racePostCas) {
					rotationPolicyReads += 1;
					if (rotationPolicyReads === 2) {
						await input.transaction!.updateMany({
							model: "sessionCredential",
							where: [{ field: "sessionId", value: rotationSessionId }],
							update: { expiresAt: new Date(Date.now() + 180_000) },
						});
					}
				}
				return policyResult(input);
			},
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-rotation-post-cas-race-test",
					get: async () => null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		rotationSessionId = session.id;
		const beforeCredentials = structuredClone(await credentialRows(runtime));
		const beforeSession = structuredClone(await authorityRows(runtime.context));
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		racePostCas = true;

		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			),
		).resolves.toBeNull();
		expect(await credentialRows(runtime)).toEqual(beforeCredentials);
		expect(await authorityRows(runtime.context)).toEqual(beforeSession);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();

		rotationPolicyReads = 0;
		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await expect(
					runtime.context.internalAdapter.rotateSessionCredential(
						session.token,
						generateCredentialOperationKey(),
					),
				).rejects.toThrow("ambient transaction must roll back");
			}),
		).rejects.toThrow(
			"ambient transaction must roll back",
		);
		expect(await credentialRows(runtime)).toEqual(beforeCredentials);
		expect(await authorityRows(runtime.context)).toEqual(beforeSession);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("publishes a committed successor after its recovery window closes", async () => {
		vi.useFakeTimers({ now: new Date("2032-01-01T00:00:00.000Z") });
		const store = new Map<string, string>();
		let rotationPolicyReads = 0;
		let gatePublication = false;
		const publicationEntered = deferred();
		const publicationRelease = deferred();
		const runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (gatePublication) {
					rotationPolicyReads += 1;
					if (rotationPolicyReads === 3) {
						publicationEntered.resolve();
						await publicationRelease.promise;
					}
				}
				return policyResult(input);
			},
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-rotation-recovery-window-publication-test",
					get: async (key) => store.get(key) ?? null,
					set: async (key, value) => {
						store.set(key, value);
					},
					delete: async (key) => {
						store.delete(key);
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const oldCredentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		gatePublication = true;
		const pending = runtime.context.internalAdapter.rotateSessionCredential(
			session.token,
			generateCredentialOperationKey(),
		);
		await publicationEntered.promise;
		await vi.advanceTimersByTimeAsync(
			SESSION_ROTATION_RECOVERY_WINDOW_MS + 1_000,
		);
		publicationRelease.resolve();
		await expect(pending).resolves.not.toBeNull();

		const successorCredentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		expect(successorCredentialKey).not.toBe(oldCredentialKey);
		expect(store.has(successorCredentialKey)).toBe(true);
		expect(store.has(oldCredentialKey)).toBe(false);
	});

	it("cleans only owned secondary residue when final rotation authority is invalid", async () => {
		const store = new Map<string, string>();
		let rotationPolicyReads = 0;
		let invalidatePublication = false;
		let invalidSessionId = "";
		let malformedExpectedKey = "";
		const runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (invalidatePublication) rotationPolicyReads += 1;
				if (invalidatePublication && rotationPolicyReads === 3) {
					const active = await input.transaction!.findOne<
						Record<string, unknown>
					>({
						model: "sessionCredential",
						where: [
							{ field: "sessionId", value: invalidSessionId },
							{ field: "status", value: "active" },
						],
					});
					malformedExpectedKey =
						`clearance:managed-rotation-invalid-cleanup-test:` +
						`session-credential:${String(active!.secretDigest)}`;
					store.set(malformedExpectedKey, "not-json");
				}
				return policyResult(input, {
					revision:
						invalidatePublication && rotationPolicyReads === 3 ? "8" : "7",
				});
			},
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-rotation-invalid-cleanup-test",
					get: async (key) => store.get(key) ?? null,
					set: async (key, value) => {
						store.set(key, value);
					},
					delete: async (key) => {
						store.delete(key);
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		invalidSessionId = session.id;
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const oldCredentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		const unrelated = {
			sessionId: "unrelated-session",
			credentialKey: "unrelated-credential",
			expiresAt: Date.now() - 1_000,
		};
		const crossSessionCredentialKey = "cross-session-credential";
		store.set(
			unrelated.credentialKey,
			JSON.stringify({ session: { id: unrelated.sessionId } }),
		);
		store.set(
			crossSessionCredentialKey,
			JSON.stringify({ session: { id: "other-session" } }),
		);
		store.set(
			handleKey,
			JSON.stringify({ credentialKey: crossSessionCredentialKey }),
		);
		store.set(
			indexKey,
			JSON.stringify([
				...(JSON.parse(store.get(indexKey)!) as unknown[]),
				unrelated,
			]),
		);
		invalidatePublication = true;

		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			),
		).rejects.toBeInstanceOf(AfterTransactionHookError);
		expect(await credentialRows(runtime)).toHaveLength(2);
		expect(store.has(oldCredentialKey)).toBe(false);
		expect(store.has(handleKey)).toBe(false);
		expect(store.has(indexKey)).toBe(false);
		expect(store.has(unrelated.credentialKey)).toBe(true);
		expect(store.has(crossSessionCredentialKey)).toBe(true);
		expect(store.get(malformedExpectedKey)).toBe("not-json");
	});

	it("canonically repairs stale duplicate topology for a gated newer successor", async () => {
		const store = new Map<string, string>();
		let rotationPolicyReads = 0;
		let interleaveNewerSuccessor = false;
		let sessionId = "";
		const publicationEntered = deferred();
		const newerCommitted = deferred();
		let newerCredentialKey = "";
		let capturedOldCredentialKey = "";
		let capturedSuccessorCredentialKey = "";
		const runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (interleaveNewerSuccessor) {
					rotationPolicyReads += 1;
					if (rotationPolicyReads === 3) {
						publicationEntered.resolve();
						await newerCommitted.promise;
						const active = await input.transaction!.findOne<
							Record<string, unknown>
						>({
							model: "sessionCredential",
							where: [
								{ field: "sessionId", value: sessionId },
								{ field: "status", value: "active" },
							],
						});
						const now = new Date();
						await input.transaction!.update({
							model: "sessionCredential",
							where: [{ field: "id", value: String(active!.id) }],
							update: {
								status: "consumed",
								consumedAt: now,
								rotationNonceDigest: "newer-operation",
								recoveryExpiresAt: new Date(
									now.getTime() + SESSION_ROTATION_RECOVERY_WINDOW_MS,
								),
								updatedAt: now,
							},
						});
						const newerId = `newer-${String(active!.id)}`;
						await input.transaction!.create({
							model: "sessionCredential",
							forceAllowId: true,
							data: {
								...active,
								id: newerId,
								selector: `selector-${newerId}`,
								secretDigest: `digest-${newerId}`,
								status: "active",
								rotationCounter: Number(active!.rotationCounter) + 1,
								parentCredentialId: active!.id,
								consumedAt: null,
								revokedAt: null,
								reuseDetectedAt: null,
								rotationNonceDigest: null,
								recoverySecretCiphertext: null,
								recoveryExpiresAt: null,
								createdAt: now,
								updatedAt: now,
							},
						});
						const storedSession = await input.transaction!.findOne<
							Record<string, unknown>
						>({
							model: "session",
							where: [{ field: "id", value: sessionId }],
						});
						const storedUser = await input.transaction!.findOne<
							Record<string, unknown>
						>({
							model: "user",
							where: [{ field: "id", value: String(storedSession!.userId) }],
						});
						newerCredentialKey =
							`clearance:managed-rotation-newer-successor-test:` +
							`session-credential:digest-${newerId}`;
						capturedSuccessorCredentialKey =
							`clearance:managed-rotation-newer-successor-test:` +
							`session-credential:${String(active!.secretDigest)}`;
						store.set(
							capturedSuccessorCredentialKey,
							JSON.stringify({ session: { id: sessionId }, consumed: true }),
						);
						store.set(
							newerCredentialKey,
							JSON.stringify({
								session: { ...storedSession, token: null, ipAddress: "stale" },
								user: { ...storedUser, name: "Stale User" },
							}),
						);
						const handleKey = [...store.keys()].find((key) =>
							key.endsWith(`:session-handle:${sessionId}`),
						)!;
						const indexKey = [...store.keys()].find((key) =>
							key.endsWith(`:active-sessions:${storedSession!.userId}`),
						)!;
						store.set(handleKey, JSON.stringify({ credentialKey: newerCredentialKey }));
						store.set(
							indexKey,
							JSON.stringify([
								{
									sessionId,
									credentialKey: newerCredentialKey,
									expiresAt: (active!.expiresAt as Date).getTime(),
								},
								{
									sessionId,
									credentialKey: "duplicate-stale-credential",
									expiresAt: (active!.expiresAt as Date).getTime(),
								},
							]),
						);
					}
				}
				return policyResult(input);
			},
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-rotation-newer-successor-test",
					get: async (key) => store.get(key) ?? null,
					set: async (key, value) => {
						store.set(key, value);
					},
					delete: async (key) => {
						store.delete(key);
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		sessionId = session.id;
		const issuedHandleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		capturedOldCredentialKey = (
			JSON.parse(store.get(issuedHandleKey)!) as { credentialKey: string }
		).credentialKey;
		interleaveNewerSuccessor = true;
		const pending = runtime.context.internalAdapter.rotateSessionCredential(
			session.token,
			generateCredentialOperationKey(),
		);
		await publicationEntered.promise;
		newerCommitted.resolve();
		await expect(pending).resolves.not.toBeNull();

		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		expect(JSON.parse(store.get(handleKey)!)).toEqual({
			credentialKey: newerCredentialKey,
		});
		const currentSession = (await authorityRows(runtime.context))[0]!;
		const currentUser = await runtime.context.adapter.findOne<
			Record<string, unknown>
		>({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
		});
		expect(JSON.parse(store.get(indexKey)!)).toEqual([
			{
				sessionId: session.id,
				credentialKey: newerCredentialKey,
				expiresAt: (currentSession.expiresAt as Date).getTime(),
			},
		]);
		expect(JSON.parse(store.get(newerCredentialKey)!)).toEqual({
			session: JSON.parse(
				JSON.stringify({ ...currentSession, token: null }),
			),
			user: JSON.parse(JSON.stringify(currentUser)),
		});
		expect(store.has(capturedOldCredentialKey)).toBe(false);
		expect(store.has(capturedSuccessorCredentialKey)).toBe(false);
	});

	it("cleans secondary authority and errors on broken newer lineage", async () => {
		const store = new Map<string, string>();
		let rotationPolicyReads = 0;
		let breakPublicationLineage = false;
		let sessionId = "";
		let successorCredentialKey = "";
		const runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (breakPublicationLineage) {
					rotationPolicyReads += 1;
					if (rotationPolicyReads === 3) {
						const active = await input.transaction!.findOne<
							Record<string, unknown>
						>({
							model: "sessionCredential",
							where: [
								{ field: "sessionId", value: sessionId },
								{ field: "status", value: "active" },
							],
						});
						successorCredentialKey =
							`clearance:managed-rotation-broken-lineage-test:` +
							`session-credential:${String(active!.secretDigest)}`;
						store.set(
							successorCredentialKey,
							JSON.stringify({ session: { id: sessionId }, stale: true }),
						);
						await input.transaction!.update({
							model: "sessionCredential",
							where: [{ field: "id", value: String(active!.id) }],
							update: { parentCredentialId: null },
						});
					}
				}
				return policyResult(input);
			},
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-rotation-broken-lineage-test",
					get: async (key) => store.get(key) ?? null,
					set: async (key, value) => {
						store.set(key, value);
					},
					delete: async (key) => {
						store.delete(key);
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		sessionId = session.id;
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const oldCredentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		breakPublicationLineage = true;

		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			),
		).rejects.toBeInstanceOf(AfterTransactionHookError);
		expect(store.has(oldCredentialKey)).toBe(false);
		expect(store.has(successorCredentialKey)).toBe(false);
		expect(store.has(handleKey)).toBe(false);
		expect(store.has(indexKey)).toBe(false);
		const rows = await credentialRows(runtime);
		expect(rows).toHaveLength(2);
		expect(rows.find((row) => row.status === "active")!.parentCredentialId).toBe(
			rows.find((row) => row.status === "consumed")!.id,
		);
	});

	it("publishes rotation only after outer commit and repairs both recovery paths", async () => {
		const store = new Map<string, string>();
		const secondarySet = vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		});
		const secondaryDelete = vi.fn(async (key: string) => {
			store.delete(key);
		});
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-rotation-postcommit-test",
					get: async (key) => store.get(key) ?? null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const oldCredentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		const oldEnvelope = store.get(oldCredentialKey)!;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		const initialStore = new Map(store);
		const initialCredentials = structuredClone(await credentialRows(runtime));
		const operationKey = generateCredentialOperationKey();
		secondarySet.mockClear();
		secondaryDelete.mockClear();

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				const result = await runtime.context.internalAdapter.rotateSessionCredential(
					session.token,
					operationKey,
				);
				expect(result).not.toBeNull();
				expect(secondarySet).not.toHaveBeenCalled();
				expect(secondaryDelete).not.toHaveBeenCalled();
				throw new Error("rotation outer rollback");
			}),
		).rejects.toThrow("rotation outer rollback");
		expect(store).toEqual(initialStore);
		expect(await credentialRows(runtime)).toEqual(initialCredentials);

		let rotated: Awaited<
			ReturnType<
				typeof runtime.context.internalAdapter.rotateSessionCredential
			>
		> = null;
		await runWithTransaction(runtime.context.adapter, async () => {
			rotated = await runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			);
			expect(rotated).not.toBeNull();
			expect(secondarySet).not.toHaveBeenCalled();
			expect(secondaryDelete).not.toHaveBeenCalled();
		});
		expect(rotated).not.toBeNull();
		const rows = await credentialRows(runtime);
		const parent = rows.find((row) => row.status === "consumed")!;
		const successor = rows.find((row) => row.status === "active")!;
		expect(successor).toMatchObject({
			familyId: parent.familyId,
			parentCredentialId: parent.id,
			rotationCounter: Number(parent.rotationCounter) + 1,
		});
		expect((successor.expiresAt as Date).getTime()).toBe(
			(parent.expiresAt as Date).getTime(),
		);
		const persistedSession = (await authorityRows(runtime.context))[0]!;
		expect((successor.expiresAt as Date).getTime()).toBe(
			(persistedSession.expiresAt as Date).getTime(),
		);
		const successorCredentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		expect(successorCredentialKey).not.toBe(oldCredentialKey);
		expect(store.has(oldCredentialKey)).toBe(false);
		expect(JSON.parse(store.get(indexKey)!)).toEqual([
			{
				sessionId: session.id,
				credentialKey: successorCredentialKey,
				expiresAt: (successor.expiresAt as Date).getTime(),
			},
		]);
		const readExactEnvelope = async () => {
			const currentSession = (await authorityRows(runtime.context))[0]!;
			const currentUser = await runtime.context.adapter.findOne<
				Record<string, unknown>
			>({
				model: "user",
				where: [{ field: "id", value: runtime.user.id }],
			});
			return {
				session: JSON.parse(
					JSON.stringify({ ...currentSession, token: null }),
				),
				user: JSON.parse(JSON.stringify(currentUser)),
			};
		};
		expect(JSON.parse(store.get(successorCredentialKey)!)).toEqual(
			await readExactEnvelope(),
		);
		expect(
			secondaryDelete.mock.calls.filter(([key]) => key === oldCredentialKey),
		).toHaveLength(1);

		const preparePartialPublication = () => {
			store.set(oldCredentialKey, oldEnvelope);
			store.delete(successorCredentialKey);
			secondarySet.mockClear();
			secondaryDelete.mockClear();
		};
		preparePartialPublication();
		const partialStore = new Map(store);
		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await expect(
					runtime.context.internalAdapter.recoverSessionCredential(
						session.token,
						operationKey,
					),
				).resolves.not.toBeNull();
				expect(secondarySet).not.toHaveBeenCalled();
				expect(secondaryDelete).not.toHaveBeenCalled();
				throw new Error("recovery outer rollback");
			}),
		).rejects.toThrow("recovery outer rollback");
		expect(store).toEqual(partialStore);

		await expect(
			runtime.context.internalAdapter.recoverSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.toMatchObject({ refreshToken: rotated!.refreshToken });
		expect(JSON.parse(store.get(successorCredentialKey)!)).toEqual(
			await readExactEnvelope(),
		);
		expect(store.has(oldCredentialKey)).toBe(false);
		expect(
			secondaryDelete.mock.calls.filter(([key]) => key === oldCredentialKey),
		).toHaveLength(1);

		preparePartialPublication();
		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.toMatchObject({ refreshToken: rotated!.refreshToken });
		expect(JSON.parse(store.get(successorCredentialKey)!)).toEqual(
			await readExactEnvelope(),
		);
		expect(store.has(oldCredentialKey)).toBe(false);
		expect(
			secondaryDelete.mock.calls.filter(([key]) => key === oldCredentialKey),
		).toHaveLength(1);
	});

	it("reports rotation publication failure after commit and repairs it by recovery", async () => {
		const store = new Map<string, string>();
		let failPublication = false;
		const secondarySet = vi.fn(async (key: string, value: string) => {
			if (failPublication) throw new Error("rotation cache unavailable");
			store.set(key, value);
		});
		const secondaryDelete = vi.fn(async (key: string) => {
			store.delete(key);
		});
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-rotation-publication-failure-test",
					get: async (key) => store.get(key) ?? null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const operationKey = generateCredentialOperationKey();
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const oldCredentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		failPublication = true;

		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			),
		).rejects.toBeInstanceOf(AfterTransactionHookError);
		const committedRows = await credentialRows(runtime);
		expect(committedRows).toHaveLength(2);
		expect(committedRows.map((row) => row.status).sort()).toEqual([
			"active",
			"consumed",
		]);
		expect(store.has(oldCredentialKey)).toBe(true);
		expect(secondaryDelete).not.toHaveBeenCalled();

		failPublication = false;
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		const recovered = await runtime.context.internalAdapter.recoverSessionCredential(
			session.token,
			operationKey,
		);
		expect(recovered).not.toBeNull();
		const successorCredentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		expect(successorCredentialKey).not.toBe(oldCredentialKey);
		expect(store.has(successorCredentialKey)).toBe(true);
		expect(store.has(oldCredentialKey)).toBe(false);
		expect(
			secondaryDelete.mock.calls.filter(([key]) => key === oldCredentialKey),
		).toHaveLength(1);
	});

	it("fails stale lost-response recovery without revoking or publishing", async () => {
		let liveRevision = "7";
		const secondarySet = vi.fn(async () => {});
		const secondaryDelete = vi.fn(async () => {});
		const runtime = await setupManagedRuntime({
			reader: (input) => policyResult(input, { revision: liveRevision }),
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-live-recovery-test",
					get: async () => null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const operationKey = generateCredentialOperationKey();
		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.not.toBeNull();
		const afterRotation = structuredClone(await credentialRows(runtime));
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		liveRevision = "8";

		await expect(
			runtime.context.internalAdapter.recoverSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.toBeNull();
		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.toBeNull();
		expect(await credentialRows(runtime)).toEqual(afterRotation);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("does not recover after parent or successor expiry during a delayed reader", async () => {
		vi.useFakeTimers({ now: new Date("2030-01-01T00:00:00.000Z") });
		let gate: ReturnType<typeof deferred> | null = null;
		let readerEntered: ReturnType<typeof deferred> | null = null;
		const secondarySet = vi.fn(async () => {});
		const secondaryDelete = vi.fn(async () => {});
		const runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (gate && readerEntered) {
					readerEntered.resolve();
					await gate.promise;
				}
				return policyResult(input);
			},
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-delayed-recovery-test",
					get: async () => null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const operationKey = generateCredentialOperationKey();
		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.not.toBeNull();
		const rows = await credentialRows(runtime);
		const parent = rows.find((row) => row.rotationCounter === 0)!;
		const successor = rows.find((row) => row.rotationCounter === 1)!;
		secondarySet.mockClear();
		secondaryDelete.mockClear();

		await runtime.context.adapter.update({
			model: "sessionCredential",
			where: [{ field: "id", value: String(successor.id) }],
			update: { expiresAt: new Date(Date.now() + 1_000) },
		});
		let before = structuredClone(await credentialRows(runtime));
		gate = deferred();
		readerEntered = deferred();
		let pending = runtime.context.internalAdapter.recoverSessionCredential(
			session.token,
			operationKey,
		);
		await readerEntered.promise;
		await vi.advanceTimersByTimeAsync(2_000);
		gate.resolve();
		await expect(pending).resolves.toBeNull();
		expect(await credentialRows(runtime)).toEqual(before);

		await runtime.context.adapter.update({
			model: "sessionCredential",
			where: [{ field: "id", value: String(successor.id) }],
			update: { expiresAt: new Date(Date.now() + 60_000) },
		});
		await runtime.context.adapter.update({
			model: "sessionCredential",
			where: [{ field: "id", value: String(parent.id) }],
			update: { recoveryExpiresAt: new Date(Date.now() + 1_000) },
		});
		before = structuredClone(await credentialRows(runtime));
		gate = deferred();
		readerEntered = deferred();
		pending = runtime.context.internalAdapter.rotateSessionCredential(
			session.token,
			operationKey,
		);
		await readerEntered.promise;
		await vi.advanceTimersByTimeAsync(2_000);
		gate.resolve();
		await expect(pending).resolves.toBeNull();
		expect(await credentialRows(runtime)).toEqual(before);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("propagates reader failure without mutating session or credential authority", async () => {
		let readerFails = false;
		const runtime = await setupManagedRuntime({
			reader: (input) => {
				if (readerFails) throw new Error("policy unavailable");
				return policyResult(input);
			},
		});
		const session = await issuePasswordSession(runtime);
		const before = structuredClone(await credentialRows(runtime));
		readerFails = true;

		await expect(
			runtime.context.internalAdapter.findSession(session.token),
		).rejects.toBeInstanceOf(RuntimeAuthenticationPolicyReaderError);
		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			),
		).rejects.toBeInstanceOf(RuntimeAuthenticationPolicyReaderError);
		expect(await credentialRows(runtime)).toEqual(before);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
	});

	it("preserves unmanaged session lookup behavior", async () => {
		const database = new DatabaseSync(":memory:");
		databases.push(database);
		const options = {
			baseURL: "http://localhost:3000",
			secret: "unmanaged-live-session-authority-secret",
			database,
		} satisfies ClearanceOptions;
		await (await getMigrations(options)).runMigrations();
		const context = await init(options);
		const user = await context.internalAdapter.createUser({
			email: "unmanaged-live-session@example.com",
			name: "Unmanaged Live Session User",
		});
		const session = await context.internalAdapter.createSession(user.id);

		await expect(
			context.internalAdapter.findSession(session.token),
		).resolves.toMatchObject({ session: { id: session.id } });
		await expect(
			context.internalAdapter.findSessionById(session.id),
		).resolves.toMatchObject({ session: { id: session.id } });
	});

	it("atomically updates expiry while preserving hook-protected authority", async () => {
		const runtime = await setupManagedRuntime({
			options: {
				databaseHooks: {
					session: {
						update: {
							before: async (data) => ({
								data: {
									...data,
									...Object.fromEntries(
										SESSION_ASSURANCE_RESERVED_FIELDS.map((field) => [
											field,
											`hook-${field}`,
										]),
									),
									id: "hook-id",
									token: "hook-token",
									userId: "hook-user",
									twoFactorSessionGeneration: "hook-two-factor",
									passkeySessionGeneration: "hook-passkey",
									authenticationPolicyRevision: "999",
									authenticationPrimaryMethod: "anonymous",
								},
							}),
						},
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const originalCredential = (await credentialRows(runtime))[0]!;
		await runtime.context.adapter.create({
			model: "sessionCredential",
			forceAllowId: true,
			data: {
				...originalCredential,
				id: `${originalCredential.id}-consumed`,
				selector: `${originalCredential.selector}-consumed`,
				secretDigest: `${originalCredential.secretDigest}-consumed`,
				status: "consumed",
				rotationCounter: 1,
				parentCredentialId: originalCredential.id,
				consumedAt: new Date(),
			},
		});
		const before = (await authorityRows(runtime.context))[0]!;
		const newExpiry = new Date(session.expiresAt.getTime() + 60_000);
		const directForgery = Object.fromEntries(
			SESSION_ASSURANCE_RESERVED_FIELDS.map((field) => [field, "forged"]),
		);

		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				...directForgery,
				id: "direct-id",
				token: "direct-token",
				userId: "direct-user",
				twoFactorSessionGeneration: "direct-two-factor",
				passkeySessionGeneration: "direct-passkey",
				expiresAt: newExpiry,
			} as never),
		).resolves.toMatchObject({ id: session.id, token: session.token });

		const after = (await authorityRows(runtime.context))[0]!;
		for (const field of [
			"id",
			"token",
			"userId",
			"twoFactorSessionGeneration",
			"passkeySessionGeneration",
			...SESSION_ASSURANCE_RESERVED_FIELDS,
		]) {
			expect(after[field]).toEqual(before[field]);
		}
		expect(after.expiresAt).toEqual(newExpiry);
		const updatedCredentials = await credentialRows(runtime);
		expect(updatedCredentials).toHaveLength(2);
		expect(
			updatedCredentials.every(
				(credential) =>
					(credential.expiresAt as Date).getTime() === newExpiry.getTime(),
			),
		).toBe(true);
		const stableSession = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				expiresAt: new Date(Number.NaN),
			}),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
	});

	it("enforces managed organization deltas from direct and hook updates", async () => {
		let hookOrganization: unknown;
		const runtime = await setupManagedRuntime({
			options: {
				session: {
					additionalFields: {
						activeOrganizationId: { type: "string", required: false },
					},
				},
				databaseHooks: {
					session: {
						update: {
							before: async (data) => ({
								data:
									hookOrganization === undefined
										? data
										: { ...data, activeOrganizationId: hookOrganization },
							}),
						},
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime, {
			activeOrganizationId: "organization_1",
			targetOrganizationId: "organization_1",
		});

		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				activeOrganizationId: "organization_1",
			}),
		).resolves.not.toBeNull();
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				activeOrganizationId: null,
			}),
		).resolves.not.toBeNull();
		const stable = structuredClone(await authorityRows(runtime.context));
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				activeOrganizationId: "organization_2",
			}),
		).resolves.toBeNull();
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				activeOrganizationId: 42,
			} as never),
		).resolves.toBeNull();
		hookOrganization = "organization_2";
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.9",
			}),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stable);
	});

	it("propagates update reader failure and rejects expired credentials without mutation", async () => {
		let readerFails = false;
		const runtime = await setupManagedRuntime({
			reader: (input) => {
				if (readerFails) throw new Error("update policy unavailable");
				return policyResult(input);
			},
			options: {
				user: {
					additionalFields: {
						banned: { type: "boolean", defaultValue: false },
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		let stableSession = structuredClone(await authorityRows(runtime.context));
		let stableCredentials = structuredClone(await credentialRows(runtime));
		readerFails = true;
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.10",
			}),
		).rejects.toBeInstanceOf(RuntimeAuthenticationPolicyReaderError);
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);

		readerFails = false;
		await runtime.context.adapter.update({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
			update: { banned: true },
		});
		stableSession = structuredClone(await authorityRows(runtime.context));
		stableCredentials = structuredClone(await credentialRows(runtime));
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.11",
			}),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		await runtime.context.adapter.update({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
			update: { banned: false },
		});

		await runtime.context.adapter.updateMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: session.id }],
			update: { expiresAt: new Date(Date.now() - 1_000) },
		});
		stableSession = structuredClone(await authorityRows(runtime.context));
		stableCredentials = structuredClone(await credentialRows(runtime));
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.12",
			}),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
	});

	it("rejects two-factor and passkey generation mismatch without mutation", async () => {
		const runtime = await setupManagedRuntime({
			options: {
				plugins: [
					{ id: "two-factor", schema: twoFactorSchema },
					{ id: "passkey", schema: passkeySchema },
				],
			},
		});
		await runtime.context.adapter.update({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
			update: {
				twoFactorSessionGeneration: "generation-1",
				passkeySessionGeneration: "generation-1",
			},
		});
		const session = await issuePasswordSession(runtime);
		await runtime.context.adapter.update({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
			update: {
				twoFactorSessionGeneration: "generation-2",
				passkeySessionGeneration: "generation-2",
			},
		});
		const stableSession = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));

		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.13",
			}),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
	});

	it("rejects stale policy and post-hook authority changes without after hooks", async () => {
		let liveRevision = "7";
		const hookEntered = deferred();
		const hookRelease = deferred();
		const afterHook = vi.fn();
		let blockHook = false;
		const runtime = await setupManagedRuntime({
			reader: (input) => policyResult(input, { revision: liveRevision }),
			options: {
				databaseHooks: {
					session: {
						update: {
							before: async (data) => {
								if (blockHook) {
									hookEntered.resolve();
									await hookRelease.promise;
								}
								return { data };
							},
							after: afterHook,
						},
					},
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const beforeSession = structuredClone(await authorityRows(runtime.context));
		const beforeCredentials = structuredClone(await credentialRows(runtime));
		blockHook = true;
		const pending = runtime.context.internalAdapter.updateSession(session.token, {
			ipAddress: "192.0.2.1",
		});
		await hookEntered.promise;
		liveRevision = "8";
		hookRelease.resolve();

		await expect(pending).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(beforeSession);
		expect(await credentialRows(runtime)).toEqual(beforeCredentials);
		expect(afterHook).not.toHaveBeenCalled();
	});

	it("rejects session-assurance and credential deadlines crossed inside an async before hook", async () => {
		vi.useFakeTimers({ now: new Date("2031-01-01T00:00:00.000Z") });
		let hookGate: ReturnType<typeof deferred> | null = null;
		let hookEntered: ReturnType<typeof deferred> | null = null;
		const afterHook = vi.fn();
		const runtime = await setupManagedRuntime({
			options: {
				databaseHooks: {
					session: {
						update: {
							before: async (data) => {
								if (hookGate && hookEntered) {
									hookEntered.resolve();
									await hookGate.promise;
								}
								return { data };
							},
							after: afterHook,
						},
					},
				},
			},
		});
		const crossDeadline = async (token: string) => {
			hookGate = deferred();
			hookEntered = deferred();
			const pending = runtime.context.internalAdapter.updateSession(token, {
				ipAddress: "192.0.2.14",
			});
			await hookEntered.promise;
			await vi.advanceTimersByTimeAsync(2_000);
			hookGate.resolve();
			await expect(pending).resolves.toBeNull();
			hookGate = null;
			hookEntered = null;
		};

		const sessionDeadline = await issuePasswordSession(runtime);
		await runtime.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: sessionDeadline.id }],
			update: {
				expiresAt: new Date(Date.now() + 1_000),
				authenticationAssuranceExpiresAt: new Date(Date.now() + 1_000),
			},
		});
		let stableSession = structuredClone(await authorityRows(runtime.context));
		let stableCredentials = structuredClone(await credentialRows(runtime));
		await crossDeadline(sessionDeadline.token);
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);

		const credentialDeadline = await issuePasswordSession(runtime);
		await runtime.context.adapter.updateMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: credentialDeadline.id }],
			update: { expiresAt: new Date(Date.now() + 1_000) },
		});
		stableSession = structuredClone(await authorityRows(runtime.context));
		stableCredentials = structuredClone(await credentialRows(runtime));
		await crossDeadline(credentialDeadline.token);
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		expect(afterHook).not.toHaveBeenCalled();
	});

	it("rejects duplicate active credentials for handle and refresh updates", async () => {
		const runtime = await setupManagedRuntime();
		const session = await issuePasswordSession(runtime);
		const credential = (await credentialRows(runtime))[0]!;
		await runtime.context.adapter.create({
			model: "sessionCredential",
			forceAllowId: true,
			data: {
				...credential,
				id: `${credential.id}-duplicate`,
				selector: `${credential.selector}-duplicate`,
				secretDigest: `${credential.secretDigest}-duplicate`,
			},
		});
		const beforeSession = structuredClone(await authorityRows(runtime.context));
		const beforeCredentials = structuredClone(await credentialRows(runtime));

		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.2",
			}),
		).resolves.toBeNull();
		await expect(
			runtime.context.internalAdapter.updateSession(
				String(beforeSession[0]!.token),
				{ ipAddress: "192.0.2.3" },
			),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(beforeSession);
		expect(await credentialRows(runtime)).toEqual(beforeCredentials);
	});

	it("publishes the final DB snapshot only after outer commit and never on rollback", async () => {
		const store = new Map<string, string>();
		const secondarySet = vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		});
		const secondaryDelete = vi.fn(async (key: string) => {
			store.delete(key);
		});
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-update-publication-test",
					get: async (key) => store.get(key) ?? null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const expectedHandleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const expectedCredentialKey = (
			JSON.parse(store.get(expectedHandleKey)!) as { credentialKey: string }
		).credentialKey;
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		const beforeStore = new Map(store);
		const beforeSession = structuredClone(await authorityRows(runtime.context));
		const beforeCredentials = structuredClone(await credentialRows(runtime));

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await runtime.context.internalAdapter.updateSession(session.token, {
					ipAddress: "192.0.2.4",
				});
				expect(secondarySet).not.toHaveBeenCalled();
				throw new Error("outer rollback");
			}),
		).rejects.toThrow("outer rollback");
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
		expect(store).toEqual(beforeStore);
		expect(await authorityRows(runtime.context)).toEqual(beforeSession);
		expect(await credentialRows(runtime)).toEqual(beforeCredentials);

		await runtime.context.internalAdapter.updateSession(session.token, {
			ipAddress: "192.0.2.5",
		});
		expect(secondarySet).toHaveBeenCalled();
		const persistedSession = (await authorityRows(runtime.context))[0]!;
		const persistedCredentials = await credentialRows(runtime);
		const persistedExpiry = (persistedSession.expiresAt as Date).getTime();
		expect(
			persistedCredentials.every(
				(credential) =>
					(credential.expiresAt as Date).getTime() === persistedExpiry,
			),
		).toBe(true);
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		);
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		);
		expect(handleKey).toBeDefined();
		expect(indexKey).toBeDefined();
		expect(handleKey).toBe(expectedHandleKey);
		const handle = JSON.parse(store.get(handleKey!)!) as {
			credentialKey: string;
		};
		expect(handle).toEqual({ credentialKey: expectedCredentialKey });
		const index = JSON.parse(store.get(indexKey!)!) as Array<{
			sessionId: string;
			credentialKey: string;
			expiresAt: number;
		}>;
		expect(index).toEqual([
			{
				sessionId: session.id,
				credentialKey: handle.credentialKey,
				expiresAt: persistedExpiry,
			},
		]);
		const envelope = JSON.parse(store.get(handle.credentialKey)!) as {
			session: Record<string, unknown>;
			user: Record<string, unknown>;
		};
		const persistedUser = await runtime.context.adapter.findOne<
			Record<string, unknown>
		>({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
		});
		expect(envelope).toEqual({
			session: JSON.parse(
				JSON.stringify({ ...persistedSession, token: null }),
			),
			user: JSON.parse(JSON.stringify(persistedUser)),
		});
	});

	it("removes only expired managed secondary material after commit and preserves it on outer rollback", async () => {
		const store = new Map<string, string>();
		const secondarySet = vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		});
		const secondaryDelete = vi.fn(async (key: string) => {
			store.delete(key);
		});
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-update-expired-publication-test",
					get: async (key) => store.get(key) ?? null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		const originalHandle = JSON.parse(store.get(handleKey)!) as {
			credentialKey: string;
		};
		const unrelated = {
			sessionId: "unrelated-session",
			credentialKey: "unrelated-credential-key",
			expiresAt: Date.now() + 600_000,
		};
		const staleCredentialKey = "stale-mapped-credential-key";
		store.set(
			staleCredentialKey,
			JSON.stringify({ session: { id: session.id }, stale: true }),
		);
		store.set(unrelated.credentialKey, JSON.stringify({ unrelated: true }));
		store.set(handleKey, JSON.stringify({ credentialKey: staleCredentialKey }));
		store.set(
			indexKey,
			JSON.stringify([
				...(JSON.parse(store.get(indexKey)!) as unknown[]),
				unrelated,
			]),
		);
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		const stableStore = new Map(store);
		const stableSession = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));
		const expiredAt = new Date(Date.now() - 1_000);

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await runtime.context.internalAdapter.updateSession(session.token, {
					expiresAt: expiredAt,
				});
				expect(secondarySet).not.toHaveBeenCalled();
				expect(secondaryDelete).not.toHaveBeenCalled();
				throw new Error("expired outer rollback");
			}),
		).rejects.toThrow("expired outer rollback");
		expect(store).toEqual(stableStore);
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);

		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				expiresAt: expiredAt,
			}),
		).resolves.toMatchObject({ id: session.id });
		expect(store.has(originalHandle.credentialKey)).toBe(false);
		expect(store.has(staleCredentialKey)).toBe(false);
		expect(store.has(handleKey)).toBe(false);
		expect(store.get(unrelated.credentialKey)).toBe(
			JSON.stringify({ unrelated: true }),
		);
		expect(JSON.parse(store.get(indexKey)!)).toEqual([unrelated]);
		const persistedSession = (await authorityRows(runtime.context))[0]!;
		expect((persistedSession.expiresAt as Date).getTime()).toBe(
			expiredAt.getTime(),
		);
		expect(
			(await credentialRows(runtime)).every(
				(credential) =>
					(credential.expiresAt as Date).getTime() === expiredAt.getTime(),
			),
		).toBe(true);
	});

	it("preserves secondary material owned by another session across future and expired updates", async () => {
		const store = new Map<string, string>();
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-update-cross-session-key-test",
					get: async (key) => store.get(key) ?? null,
					set: async (key, value) => {
						store.set(key, value);
					},
					delete: async (key) => {
						store.delete(key);
					},
				},
			},
		});
		const sessionA = await issuePasswordSession(runtime);
		const sessionB = await issuePasswordSession(runtime);
		const handleKey = (sessionId: string) =>
			[...store.keys()].find((key) =>
				key.endsWith(`:session-handle:${sessionId}`),
			)!;
		const aHandleKey = handleKey(sessionA.id);
		const bHandleKey = handleKey(sessionB.id);
		const aCredentialKey = (
			JSON.parse(store.get(aHandleKey)!) as { credentialKey: string }
		).credentialKey;
		const bHandleValue = store.get(bHandleKey)!;
		const bCredentialKey = (
			JSON.parse(bHandleValue) as { credentialKey: string }
		).credentialKey;
		const bEnvelope = store.get(bCredentialKey)!;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		const bIndexEntry = (
			JSON.parse(store.get(indexKey)!) as Array<{
				sessionId: string;
				credentialKey: string;
				expiresAt: number;
			}>
		).find((entry) => entry.sessionId === sessionB.id)!;

		store.set(aHandleKey, JSON.stringify({ credentialKey: bCredentialKey }));
		await expect(
			runtime.context.internalAdapter.updateSession(sessionA.token, {
				ipAddress: "192.0.2.18",
			}),
		).resolves.toMatchObject({ id: sessionA.id });
		expect(store.get(bCredentialKey)).toBe(bEnvelope);
		expect(store.get(bHandleKey)).toBe(bHandleValue);
		expect(JSON.parse(store.get(indexKey)!)).toContainEqual(bIndexEntry);
		await expect(
			runtime.context.internalAdapter.findSession(sessionB.token),
		).resolves.toMatchObject({ session: { id: sessionB.id } });

		const malformedKey = "malformed-stale-credential-key";
		store.set(malformedKey, "not-json");
		store.set(aHandleKey, JSON.stringify({ credentialKey: malformedKey }));
		await runtime.context.internalAdapter.updateSession(sessionA.token, {
			ipAddress: "192.0.2.19",
		});
		expect(store.get(malformedKey)).toBe("not-json");

		store.set(aHandleKey, JSON.stringify({ credentialKey: bCredentialKey }));
		const expiredAt = new Date(Date.now() - 1_000);
		await expect(
			runtime.context.internalAdapter.updateSession(sessionA.token, {
				expiresAt: expiredAt,
			}),
		).resolves.toMatchObject({ id: sessionA.id });
		expect(store.has(aCredentialKey)).toBe(false);
		expect(store.has(aHandleKey)).toBe(false);
		expect(store.get(bCredentialKey)).toBe(bEnvelope);
		expect(store.get(bHandleKey)).toBe(bHandleValue);
		expect(JSON.parse(store.get(indexKey)!)).toEqual([bIndexEntry]);
		await expect(
			runtime.context.internalAdapter.findSession(sessionB.token),
		).resolves.toMatchObject({ session: { id: sessionB.id } });
	});

	it("captures and publishes managed legacy authority only after commit", async () => {
		const store = new Map<string, string>();
		const secondarySet = vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		});
		const secondaryDelete = vi.fn(async (key: string) => {
			store.delete(key);
		});
		let runtime: ManagedRuntime;
		let hookMode: "none" | "mutate" | "throw" = "none";
		runtime = await setupManagedRuntime({
			credentialAuthority: "legacy-v1",
			options: {
				databaseHookFailureMode: "rollback",
				databaseHooks: {
					session: {
						update: {
							after: async (updated) => {
								if (hookMode === "throw") {
									throw new Error("legacy rollback hook failed");
								}
								if (hookMode === "mutate") {
									await (
										await getCurrentAdapter(runtime.context.adapter)
									).update({
										model: "session",
										where: [{ field: "id", value: updated.id }],
										update: {
											expiresAt: new Date(Date.now() + 120_000),
										},
									});
								}
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-legacy-update-publication-test",
					get: async (key) => store.get(key) ?? null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		expect(await credentialRows(runtime)).toEqual([]);
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const credentialKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		const stableSession = structuredClone(await authorityRows(runtime.context));
		const stableStore = new Map(store);
		secondarySet.mockClear();
		secondaryDelete.mockClear();

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await runtime.context.internalAdapter.updateSession(session.token, {
					ipAddress: "192.0.2.20",
				});
				expect(secondarySet).not.toHaveBeenCalled();
				throw new Error("legacy outer rollback");
			}),
		).rejects.toThrow("legacy outer rollback");
		expect(store).toEqual(stableStore);
		expect(await authorityRows(runtime.context)).toEqual(stableSession);

		hookMode = "mutate";
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.21",
			}),
		).resolves.toBeNull();
		expect(store).toEqual(stableStore);
		expect(await authorityRows(runtime.context)).toEqual(stableSession);

		hookMode = "throw";
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.22",
			}),
		).rejects.toThrow("legacy rollback hook failed");
		expect(store).toEqual(stableStore);
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();

		hookMode = "none";
		const newExpiry = new Date(session.expiresAt.getTime() + 60_000);
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.23",
				expiresAt: newExpiry,
			}),
		).resolves.toMatchObject({ token: session.token });
		const persistedSession = (await authorityRows(runtime.context))[0]!;
		const persistedUser = await runtime.context.adapter.findOne<
			Record<string, unknown>
		>({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
		});
		expect(JSON.parse(store.get(handleKey)!)).toEqual({ credentialKey });
		expect(JSON.parse(store.get(indexKey)!)).toEqual([
			{
				sessionId: session.id,
				credentialKey,
				expiresAt: newExpiry.getTime(),
			},
		]);
		expect(JSON.parse(store.get(credentialKey)!)).toEqual({
			session: JSON.parse(
				JSON.stringify({ ...persistedSession, token: null }),
			),
			user: JSON.parse(JSON.stringify(persistedUser)),
		});

		secondarySet.mockClear();
		secondaryDelete.mockClear();
		const stableHandle = createSessionHandle(session.id);
		const beforeHandleStore = new Map(store);
		const beforeHandleSession = structuredClone(
			await authorityRows(runtime.context),
		);
		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				const result = await runtime.context.internalAdapter.updateSession(
					stableHandle,
					{ ipAddress: "192.0.2.24" },
				);
				expect(result?.token).toBe(session.token);
				expect(secondarySet).not.toHaveBeenCalled();
				expect(secondaryDelete).not.toHaveBeenCalled();
				throw new Error("legacy handle outer rollback");
			}),
		).rejects.toThrow("legacy handle outer rollback");
		expect(store).toEqual(beforeHandleStore);
		expect(await authorityRows(runtime.context)).toEqual(beforeHandleSession);

		await expect(
			runtime.context.internalAdapter.updateSession(stableHandle, {
				ipAddress: "192.0.2.25",
			}),
		).resolves.toMatchObject({ token: session.token });
		const handlePersistedSession = (
			await authorityRows(runtime.context)
		)[0]!;
		const handlePersistedUser = await runtime.context.adapter.findOne<
			Record<string, unknown>
		>({
			model: "user",
			where: [{ field: "id", value: runtime.user.id }],
		});
		expect(JSON.parse(store.get(handleKey)!)).toEqual({ credentialKey });
		expect(JSON.parse(store.get(indexKey)!)).toEqual([
			{
				sessionId: session.id,
				credentialKey,
				expiresAt: newExpiry.getTime(),
			},
		]);
		expect(JSON.parse(store.get(credentialKey)!)).toEqual({
			session: JSON.parse(
				JSON.stringify({ ...handlePersistedSession, token: null }),
			),
			user: JSON.parse(JSON.stringify(handlePersistedUser)),
		});
	});

	it("runs final capture after rollback-critical update hooks and rolls back hook failure", async () => {
		const store = new Map<string, string>();
		const secondarySet = vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		});
		const secondaryDelete = vi.fn(async (key: string) => {
			store.delete(key);
		});
		let runtime: ManagedRuntime;
		let hookMode: "none" | "mutate" | "lineage" | "throw" = "none";
		runtime = await setupManagedRuntime({
			options: {
				databaseHookFailureMode: "rollback",
				databaseHooks: {
					session: {
						update: {
							after: async (updated) => {
								if (hookMode === "throw") throw new Error("rollback hook failed");
								if (hookMode === "mutate" || hookMode === "lineage") {
									const currentAdapter = await getCurrentAdapter(
										runtime.context.adapter,
									);
									const credential = await currentAdapter.findOne<
										Record<string, unknown>
									>({
										model: "sessionCredential",
										where: [{ field: "sessionId", value: updated.id }],
									});
									await currentAdapter.updateMany({
										model: "sessionCredential",
										where: [{ field: "sessionId", value: updated.id }],
										update:
											hookMode === "mutate"
												? { expiresAt: new Date(Date.now() + 120_000) }
												: {
													familyId: "forged-family",
													rotationCounter: 99,
													parentCredentialId: credential?.id,
												},
									});
								}
							},
						},
					},
				},
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: "managed-update-rollback-hook-test",
					get: async (key) => store.get(key) ?? null,
					set: secondarySet,
					delete: secondaryDelete,
				},
			},
		});
		const session = await issuePasswordSession(runtime);
		const stableSession = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));
		const stableStore = new Map(store);
		secondarySet.mockClear();
		secondaryDelete.mockClear();

		hookMode = "mutate";
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.15",
			}),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();

		hookMode = "lineage";
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.17",
			}),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();

		hookMode = "throw";
		await expect(
			runtime.context.internalAdapter.updateSession(session.token, {
				ipAddress: "192.0.2.16",
			}),
		).rejects.toThrow("rollback hook failed");
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});
});
