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
import { createSessionHandle } from "./session-credential";

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
