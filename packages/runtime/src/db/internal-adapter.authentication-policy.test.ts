import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	GenericEndpointContext,
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
	isTransactionActive,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
import { ClearanceError } from "@clearance/core/error";
import { safeJSONParse } from "@clearance/core/utils/json";
import { afterEach, describe, expect, it, vi } from "vitest";
import { init } from "../context/init";
import {
	attachInternalAuthenticationPolicy,
	InvalidRuntimeAuthenticationPolicyError,
	RuntimeAuthenticationPolicyReaderError,
} from "../internal/authentication-policy";
import {
	captureInternalSessionIssuanceContext,
	createInternalSessionIssuanceContext,
	ManagedSessionIssuanceError,
} from "../internal/session-issuance-context";
import {
	captureInternalSessionDerivativeAuthority,
	validateInternalSessionDerivativeAuthority,
} from "../internal/session-derivative-authority";
import {
	consumeInternalVerificationChallenge,
	createInternalVerificationChallengeContext,
	createInternalVerificationChallenge,
	ManagedVerificationChallengeError,
} from "../internal/verification-challenge-context";
import { attachInternalCredentialAuthority } from "../internal/credential-authority";
import { getMigrations } from "./get-migration";
import { createInternalAdapter } from "./internal-adapter";
import { generateCredentialOperationKey } from "../utils/operation-key";
import { SESSION_ASSURANCE_RESERVED_FIELDS } from "../security/session-assurance";
import type { Session, User } from "../types";
import { getOrgAdapter } from "../plugins/organization/adapter";
import { schema as passkeySchema } from "../plugins/passkey/schema";
import { schema as twoFactorSchema } from "../plugins/two-factor/schema";
import {
	createSessionHandle,
	digestSessionRefreshSecret,
	digestSessionRotationNonce,
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
		membershipSubjectId?: string;
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
				subjectId: options.membershipSubjectId ?? input.subjectId,
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

function spyOnManagedPublicationFailure(runtime: ManagedRuntime) {
	return vi
		.spyOn(runtime.context.logger, "error")
		.mockImplementation(() => {});
}

function expectManagedPublicationFailure(
	logger: ReturnType<typeof spyOnManagedPublicationFailure>,
	message = "Managed session publication authority became invalid after commit",
) {
	expect(logger).toHaveBeenCalledWith(
		message,
		expect.any(Error),
	);
}

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

function organizationEndpointContext(
	runtime: ManagedRuntime,
	session: Session,
): GenericEndpointContext {
	return {
		context: {
			...runtime.context,
			session: { session, user: runtime.user },
		},
	} as unknown as GenericEndpointContext;
}

async function credentialRows(runtime: ManagedRuntime) {
	return runtime.context.adapter.findMany<Record<string, unknown>>({
		model: "sessionCredential",
		sortBy: { field: "rotationCounter", direction: "asc" },
	});
}

async function setupManagedDeletionRuntime(input: {
	namespace: string;
	reader?: ReaderImplementation;
	credentialAuthority?: "legacy-v1";
	options?: Omit<ClearanceOptions, "baseURL" | "secret" | "database">;
	set?: (key: string, value: string) => Promise<void>;
	delete?: (key: string) => Promise<void>;
}) {
	const store = new Map<string, string>();
	const secondarySet = vi.fn(
		input.set ??
			(async (key: string, value: string) => {
				store.set(key, value);
			}),
	);
	const secondaryDelete = vi.fn(
		input.delete ??
			(async (key: string) => {
				store.delete(key);
			}),
	);
	const runtime = await setupManagedRuntime({
		...(input.reader ? { reader: input.reader } : {}),
		...(input.credentialAuthority
			? { credentialAuthority: input.credentialAuthority }
			: {}),
		options: {
			...input.options,
			session: {
				...input.options?.session,
				storeSessionInDatabase: true,
			},
			secondaryStorage: {
				namespace: input.namespace,
				get: async (key) => store.get(key) ?? null,
				set: secondarySet,
				delete: secondaryDelete,
			},
		},
	});
	return { runtime, store, secondarySet, secondaryDelete };
}

async function setupDatabaseBackedCompatibilityRuntime(input: {
	namespace: string;
	options?: Omit<ClearanceOptions, "baseURL" | "secret" | "database">;
}) {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	const store = new Map<string, string>();
	const secondarySet = vi.fn(async (key: string, value: string) => {
		store.set(key, value);
	});
	const secondaryDelete = vi.fn(async (key: string) => {
		store.delete(key);
	});
	const runtimeOptions = {
		baseURL: "http://localhost:3000",
		secret: "database-backed-compatibility-secret",
		database,
		...input.options,
		session: {
			...input.options?.session,
		},
		secondaryStorage: {
			namespace: input.namespace,
			get: async (key: string) => store.get(key) ?? null,
			set: secondarySet,
			delete: secondaryDelete,
			runExclusive<T>(_name: string, operation: () => T): T {
				return operation();
			},
			assertNoLegacySessionWriters() {},
		},
	} satisfies ClearanceOptions;
	await (await getMigrations(runtimeOptions)).runMigrations();
	const context = await init(runtimeOptions);
	const user = await context.internalAdapter.createUser({
		email: `compatibility-${databases.length}@example.com`,
		name: "Compatibility User",
	});
	return {
		context,
		database,
		runtimeOptions,
		user,
		store,
		secondarySet,
		secondaryDelete,
	};
}

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
	for (const database of databases.splice(0)) database.close();
});

describe("managed verification challenge authority", () => {
	const createChallenge = (
		runtime: ManagedRuntime,
		data: {
			identifier: string;
			value: string;
			expiresAt: Date;
			createdAt?: Date;
		},
		binding: { purpose: string; subject: string } = {
			purpose: "managed-test-challenge",
			subject: data.identifier,
		},
	) => {
		const { createdAt, ...challenge } = data;
		if (!createdAt) {
			return createInternalVerificationChallenge(
				runtime.context.internalAdapter,
				binding,
				challenge,
			);
		}
		return runtime.context.internalAdapter.createVerificationValue(
			{ ...challenge, createdAt },
			createInternalVerificationChallengeContext({ ...binding, ...challenge }),
		);
	};
	const consumeChallenge = (
		runtime: ManagedRuntime,
		identifier: string,
		binding: { purpose: string; subject: string } = {
			purpose: "managed-test-challenge",
			subject: identifier,
		},
	) =>
		consumeInternalVerificationChallenge(runtime.context.internalAdapter, {
			...binding,
			identifier,
		});

	function secondaryStorage(
		store: Map<string, string>,
		controls: {
			failDelete?: boolean | ((key: string) => boolean);
		} = {},
	) {
		return {
			namespace: `managed-verification-${databases.length}`,
			get: async (key: string) => store.get(key) ?? null,
			set: async (key: string, value: string) => {
				store.set(key, value);
			},
			delete: async (key: string) => {
				if (
					controls.failDelete === true ||
					(typeof controls.failDelete === "function" &&
						controls.failDelete(key))
				) {
					throw new Error("cache delete failed");
				}
				store.delete(key);
			},
			runExclusive<T>(_name: string, operation: () => T): T {
				return operation();
			},
			assertNoLegacySessionWriters() {},
		};
	}

	function serializingSecondaryStorage(
		store: Map<string, string>,
		controls: {
			failDelete?: boolean | ((key: string) => boolean);
		} = {},
	) {
		const storage = secondaryStorage(store, controls);
		const leases = new Map<string, Promise<void>>();
		storage.runExclusive = (async (name, operation) => {
			const previous = leases.get(name) ?? Promise.resolve();
			let release!: () => void;
			const current = new Promise<void>((resolve) => {
				release = resolve;
			});
			const next = previous.catch(() => {}).then(() => current);
			leases.set(name, next);
			await previous.catch(() => {});
			try {
				return await operation();
			} finally {
				release();
				if (leases.get(name) === next) leases.delete(name);
			}
		}) as typeof storage.runExclusive;
		return storage;
	}

	async function setupMixedAliasRuntimes(input: {
		verification: NonNullable<ClearanceOptions["verification"]>;
		secondaryStorage: NonNullable<ClearanceOptions["secondaryStorage"]>;
	}) {
		const database = new DatabaseSync(":memory:");
		databases.push(database);
		const makeOptions = (storeIdentifier: "plain" | "hashed") => {
			const options = {
				baseURL: "http://localhost:3000",
				secret: "managed-mixed-alias-integration-secret",
				database,
				session: { storeSessionInDatabase: true },
				verification: { ...input.verification, storeIdentifier },
				secondaryStorage: input.secondaryStorage,
			} satisfies ClearanceOptions;
			const readForSubject = vi.fn(
				async (request: RuntimeAuthenticationPolicyReaderInput) =>
					policyResult(request),
			);
			attachInternalAuthenticationPolicy(options, {
				identity,
			reader: { readForSubject } satisfies RuntimeAuthenticationPolicyReader,
			});
			return options;
		};
		const plainOptions = makeOptions("plain");
		const hashedOptions = makeOptions("hashed");
		await (await getMigrations(hashedOptions)).runMigrations();
		const hashedContext = await init(hashedOptions);
		const plainContext = {
			...hashedContext,
			options: plainOptions,
			internalAdapter: createInternalAdapter(hashedContext.adapter, {
				options: plainOptions,
				logger: hashedContext.logger,
				hooks: [],
				generateId: hashedContext.generateId,
				secretConfig: hashedContext.secretConfig,
			}),
		};
		return {
			plain: { context: plainContext, runtimeOptions: plainOptions } as ManagedRuntime,
			hashed: {
				context: hashedContext,
				runtimeOptions: hashedOptions,
			} as ManagedRuntime,
		};
	}

	async function challengeMarkers(runtime: ManagedRuntime) {
		return runtime.context.adapter.findMany<Record<string, unknown>>({
			model: "securityMigration",
			where: [
				{
					field: "state",
					value: "managed-verification-challenge-v2",
				},
			],
		});
	}

	it("publishes neither marker nor secondary proof when issuance rolls back", async () => {
		const store = new Map<string, string>();
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				verification: { storeInDatabase: false },
				secondaryStorage: secondaryStorage(store),
			},
		});
		const identifier = "managed-secondary-issuance-rollback";
		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await createChallenge(runtime, {
					identifier,
					value: "proof-value",
					expiresAt: new Date(Date.now() + 60_000),
				});
				expect(store.has(`verification:${identifier}`)).toBe(false);
				throw new Error("rollback managed issuance");
			}),
		).rejects.toThrow("rollback managed issuance");
		expect(store.has(`verification:${identifier}`)).toBe(false);
		expect(await challengeMarkers(runtime)).toHaveLength(0);
	});

	it("keeps a secondary-only proof and marker on rollback, then consumes both on retry", async () => {
		const store = new Map<string, string>();
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				verification: { storeInDatabase: false },
				secondaryStorage: secondaryStorage(store),
			},
		});
		const identifier = "managed-secondary-rollback";
		const created = await createChallenge(runtime, {
			identifier,
			value: "proof-value",
			expiresAt: new Date(Date.now() + 60_000),
		});
		expect(created.id).toEqual(expect.any(String));
		expect(store.has(`verification:${identifier}`)).toBe(true);
		expect(await challengeMarkers(runtime)).toHaveLength(1);

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				const consumed = await consumeChallenge(runtime, identifier);
				expect(consumed?.id).toBe(created.id);
				throw new Error("rollback managed verification");
			}),
		).rejects.toThrow("rollback managed verification");
		expect(store.has(`verification:${identifier}`)).toBe(true);
		expect(await challengeMarkers(runtime)).toHaveLength(1);

		const retried = await runWithTransaction(runtime.context.adapter, () =>
			consumeChallenge(runtime, identifier),
		);
		expect(retried?.id).toBe(created.id);
		expect(store.has(`verification:${identifier}`)).toBe(false);
		expect(await challengeMarkers(runtime)).toHaveLength(0);
	});

	it("rolls back and retries exact database-backed challenge consumption", async () => {
		const runtime = await setupManagedRuntime();
		const identifier = "managed-database-rollback";
		const created = await createChallenge(runtime, {
			identifier,
			value: "proof-value",
			expiresAt: new Date(Date.now() + 60_000),
		});
		expect(await challengeMarkers(runtime)).toHaveLength(1);

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				const consumed = await consumeChallenge(runtime, identifier);
				expect(consumed?.id).toBe(created.id);
				throw new Error("rollback database verification");
			}),
		).rejects.toThrow("rollback database verification");
		await expect(
			runtime.context.internalAdapter.findVerificationValue(identifier),
		).resolves.toMatchObject({ id: created.id });
		expect(await challengeMarkers(runtime)).toHaveLength(1);

		await expect(
			runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			),
		).resolves.toMatchObject({ id: created.id });
		await expect(
			runtime.context.internalAdapter.findVerificationValue(identifier),
		).resolves.toBeNull();
		expect(await challengeMarkers(runtime)).toHaveLength(0);
	});

	it("removes primary authority even when post-commit cache deletion fails", async () => {
		const store = new Map<string, string>();
		const controls = { failDelete: false };
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				verification: { storeInDatabase: false },
				secondaryStorage: secondaryStorage(store, controls),
			},
		});
		const identifier = "managed-secondary-delete-failure";
		await createChallenge(runtime, {
			identifier,
			value: "proof-value",
			expiresAt: new Date(Date.now() + 60_000),
		});
		controls.failDelete = true;
		const logger = vi
			.spyOn(runtime.context.logger, "error")
			.mockImplementation(() => {});
		expect(
			await runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			),
		).not.toBeNull();
		expect(store.has(`verification:${identifier}`)).toBe(true);
		expect(await challengeMarkers(runtime)).toHaveLength(0);
		expect(
			await runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			),
		).toBeNull();
		expect(logger).toHaveBeenCalledWith(
			"Managed verification cache cleanup failed after commit",
		);
	});

	it("has one primary winner under concurrent managed secondary consume", async () => {
		const store = new Map<string, string>();
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				verification: { storeInDatabase: false },
				secondaryStorage: secondaryStorage(store),
			},
		});
		const identifier = "managed-secondary-concurrent";
		await createChallenge(runtime, {
			identifier,
			value: "proof-value",
			expiresAt: new Date(Date.now() + 60_000),
		});
		const results = await Promise.all([
			runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			),
			runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			),
		]);
		expect(results.filter(Boolean)).toHaveLength(1);
		expect(await challengeMarkers(runtime)).toHaveLength(0);
	});

	it("atomically consumes mixed-config database aliases through one managed marker gate", async () => {
		const store = new Map<string, string>();
		const storage = serializingSecondaryStorage(store);
		const { plain, hashed } = await setupMixedAliasRuntimes({
			verification: { storeInDatabase: true },
			secondaryStorage: storage,
		});
		const identifier = "managed-database-hashed-alias";
		const createdAt = new Date(Date.now());
		const legacyPlain = await createChallenge(plain, {
			identifier,
			value: "legacy-plain-proof",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt,
		});
		const hashedChallenge = await createChallenge(hashed, {
			identifier,
			value: "hashed-proof",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(createdAt.getTime() + 1),
		});
		expect(await challengeMarkers(plain)).toHaveLength(2);
		const start = deferred();
		const consume = async (runtime: ManagedRuntime) => {
			await start.promise;
			return runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			);
		};
		const plainConsume = consume(plain);
		const hashedConsume = consume(hashed);
		start.resolve();
		const results = await Promise.all([plainConsume, hashedConsume]);

		expect(results.filter(Boolean)).toHaveLength(1);
		expect(results.find(Boolean)?.id).toBe(hashedChallenge.id);
		expect(results.find(Boolean)?.id).not.toBe(legacyPlain.id);
		expect(await challengeMarkers(plain)).toHaveLength(0);
		expect(
			await plain.context.adapter.findMany({ model: "verification" }),
		).toHaveLength(0);
		expect(store.has(`verification:${hashedChallenge.identifier}`)).toBe(false);
		expect(store.has(`verification:${identifier}`)).toBe(false);
	});

	it("serializes mixed-config managed secondary aliases and retires every marker", async () => {
		const store = new Map<string, string>();
		const storage = serializingSecondaryStorage(store);
		const runExclusive = vi.spyOn(storage, "runExclusive");
		const { plain, hashed } = await setupMixedAliasRuntimes({
			verification: { storeInDatabase: false },
			secondaryStorage: storage,
		});
		const identifier = "managed-secondary-hashed-alias";
		const createdAt = new Date(Date.now());
		const legacyPlain = await createChallenge(plain, {
			identifier,
			value: "legacy-plain-proof",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt,
		});
		const hashedChallenge = await createChallenge(hashed, {
			identifier,
			value: "hashed-proof",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(createdAt.getTime() + 1),
		});
		expect(await challengeMarkers(plain)).toHaveLength(2);
		runExclusive.mockClear();
		const start = deferred();
		const consume = async (runtime: ManagedRuntime) => {
			await start.promise;
			return runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			);
		};
		const plainConsume = consume(plain);
		const hashedConsume = consume(hashed);
		start.resolve();
		const results = await Promise.all([plainConsume, hashedConsume]);

		expect(results.filter(Boolean)).toHaveLength(1);
		expect(results.find(Boolean)?.id).toBe(hashedChallenge.id);
		expect(results.find(Boolean)?.id).not.toBe(legacyPlain.id);
		expect(runExclusive).toHaveBeenCalledTimes(2);
		expect(
			runExclusive.mock.calls.every(([name]) =>
				/^verification-consume-v2:/.test(name),
			),
		).toBe(true);
		expect(await challengeMarkers(plain)).toHaveLength(0);
		expect(store.has(`verification:${hashedChallenge.identifier}`)).toBe(false);
		expect(store.has(`verification:${identifier}`)).toBe(false);
	});

	it("burns every managed alias marker when post-commit cleanup partially fails", async () => {
		const store = new Map<string, string>();
		const controls: {
			failDelete?: boolean | ((key: string) => boolean);
		} = {};
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				verification: { storeInDatabase: false, storeIdentifier: "hashed" },
				secondaryStorage: secondaryStorage(store, controls),
			},
		});
		const identifier = "managed-secondary-partial-cleanup";
		const createdAt = new Date(Date.now());
		runtime.runtimeOptions.verification!.storeIdentifier = "plain";
		const legacyPlain = await createChallenge(runtime, {
			identifier,
			value: "legacy-plain-proof",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt,
		});
		runtime.runtimeOptions.verification!.storeIdentifier = "hashed";
		const hashed = await createChallenge(runtime, {
			identifier,
			value: "hashed-proof",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(createdAt.getTime() + 1),
		});
		controls.failDelete = (key) => key === `verification:${identifier}`;

		expect(
			await runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			),
		).toMatchObject({ id: hashed.id });
		expect(await challengeMarkers(runtime)).toHaveLength(0);
		expect(store.has(`verification:${hashed.identifier}`)).toBe(false);
		expect(store.has(`verification:${identifier}`)).toBe(true);
		expect(
			await runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			),
		).toBeNull();
		expect(store.has(`verification:${identifier}`)).toBe(true);
		controls.failDelete = false;
		const replacement = await createChallenge(runtime, {
			identifier,
			value: "fresh-proof",
			expiresAt: new Date(Date.now() + 60_000),
			createdAt: new Date(createdAt.getTime() + 2),
		});
		runtime.runtimeOptions.verification!.storeIdentifier = "plain";
		expect(
			await runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier),
			),
		).toMatchObject({ id: replacement.id });
		expect(replacement.id).not.toBe(legacyPlain.id);
	});

	it("publishes a consume-then-recreate replacement after cache deletion", async () => {
		const store = new Map<string, string>();
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				verification: { storeInDatabase: false },
				secondaryStorage: secondaryStorage(store),
			},
		});
		const identifier = "managed-secondary-wrong-attempt";
		await createChallenge(runtime, {
			identifier,
			value: "otp:0",
			expiresAt: new Date(Date.now() + 60_000),
		});
		const replacement = await runWithTransaction(
			runtime.context.adapter,
			async () => {
				const consumed = await consumeChallenge(runtime, identifier);
				expect(consumed?.value).toBe("otp:0");
				return createChallenge(runtime, {
					identifier,
					value: "otp:1",
					expiresAt: consumed!.expiresAt,
				});
			},
		);
		const cached = JSON.parse(store.get(`verification:${identifier}`)!) as {
			id: string;
			value: string;
		};
		expect(cached).toMatchObject({ id: replacement.id, value: "otp:1" });
		expect(await challengeMarkers(runtime)).toHaveLength(1);
	});

	it("stores only opaque marker metadata and rejects consumption outside a transaction", async () => {
		const store = new Map<string, string>();
		const runtime = await setupManagedRuntime({
			options: {
				session: { storeSessionInDatabase: true },
				verification: { storeInDatabase: false },
				secondaryStorage: secondaryStorage(store),
			},
		});
		const identifier = "raw-phone-or-email@example.test";
		const value = "raw-otp-or-proof";
		await createChallenge(runtime, {
			identifier,
			value,
			expiresAt: new Date(Date.now() + 60_000),
		});
		const [marker] = await challengeMarkers(runtime);
		expect(marker?.state).toBe("managed-verification-challenge-v2");
		expect(JSON.stringify(marker)).not.toContain(identifier);
		expect(JSON.stringify(marker)).not.toContain(value);
		await expect(
			consumeChallenge(runtime, identifier),
		).rejects.toThrow("requires an active primary transaction");
	});

	it("rejects caller-forged managed challenge creation without runtime provenance", async () => {
		const runtime = await setupManagedRuntime();
		const identifier = "forged-email-otp:target@example.test";
		await expect(
			runtime.context.internalAdapter.createVerificationValue({
				identifier,
				value: "known-attacker-proof",
				expiresAt: new Date(Date.now() + 60_000),
			}),
		).rejects.toMatchObject({
			name: "ManagedVerificationChallengeError",
			reason: "context_required",
		});
		expect(await challengeMarkers(runtime)).toHaveLength(0);
		await expect(
			runtime.context.internalAdapter.findVerificationValue(identifier),
		).resolves.toBeNull();
	});

	it("rejects verification hooks that substitute the runtime-issued proof", async () => {
		const runtime = await setupManagedRuntime({
			options: {
				databaseHooks: {
					verification: {
						create: {
							before: async (data) => ({
								data: { ...data, value: "hook-forged-proof" },
							}),
						},
					},
				},
			},
		});
		const identifier = "managed-hook-substitution";
		await expect(
			createChallenge(runtime, {
				identifier,
				value: "runtime-proof",
				expiresAt: new Date(Date.now() + 60_000),
			}),
		).rejects.toBeInstanceOf(ManagedVerificationChallengeError);
		expect(await challengeMarkers(runtime)).toHaveLength(0);
		await expect(
			runtime.context.internalAdapter.findVerificationValue(identifier),
		).resolves.toBeNull();
	});

	it("binds managed consumption to the issuing purpose and subject", async () => {
		const runtime = await setupManagedRuntime();
		const identifier = "email-otp:target@example.test";
		await createChallenge(
			runtime,
			{
				identifier,
				value: "opaque-proof",
				expiresAt: new Date(Date.now() + 60_000),
			},
			{ purpose: "email-otp-sign-in", subject: "target@example.test" },
		);
		await expect(
			runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier, {
					purpose: "password-reset",
					subject: "target@example.test",
				}),
			),
		).resolves.toBeNull();
		expect(await challengeMarkers(runtime)).toHaveLength(1);
		await expect(
			runWithTransaction(runtime.context.adapter, () =>
				consumeChallenge(runtime, identifier, {
					purpose: "email-otp-sign-in",
					subject: "target@example.test",
				}),
			),
		).resolves.toMatchObject({ value: "opaque-proof" });
		expect(await challengeMarkers(runtime)).toHaveLength(0);
	});

	it.each(["serial", "uuid"] as const)(
		"supports %s-generated security marker ids with opaque secondary challenge ids",
		async (generateIdStrategy) => {
			const store = new Map<string, string>();
			const runtime = await setupManagedRuntime({
				options: {
					advanced: { database: { generateId: generateIdStrategy } },
					session: { storeSessionInDatabase: true },
					verification: { storeInDatabase: false },
					secondaryStorage: secondaryStorage(store),
				},
			});
			const identifier = `managed-${generateIdStrategy}-challenge`;
			const created = await createChallenge(runtime, {
				identifier,
				value: "proof-value",
				expiresAt: new Date(Date.now() + 60_000),
			});
			expect(created.id).toMatch(/^[A-Za-z0-9_-]+$/);
			const [marker] = await challengeMarkers(runtime);
			if (generateIdStrategy === "serial") {
				expect(marker?.id).toMatch(/^\d+$/);
			} else {
				expect(marker?.id).toMatch(
					/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
				);
			}
			expect(
				await runWithTransaction(runtime.context.adapter, () =>
					consumeChallenge(runtime, identifier),
				),
			).not.toBeNull();
		},
	);
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

	it("captures replacement authority only in the live source transaction and preserves its exact assurance and lifetime ceiling", async () => {
		const runtime = await setupManagedRuntime({
			options: {
				databaseHooks: {
					session: {
						create: {
							before: async (data) => ({
								data: {
									...data,
									expiresAt: new Date(
										new Date(data.expiresAt).getTime() + 86_400_000,
									),
								},
							}),
						},
					},
				},
			},
		});
		const sourceCeiling = new Date(Date.now() + 60_000);
		const source = await runtime.context.internalAdapter.createSession(
			runtime.user.id,
			false,
			{
				expiresAt: sourceCeiling,
				__preserveSessionExpiresAt: true,
			},
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: runtime.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		const [sourceAuthority] = await authorityRows(runtime.context);
		let successor!: Session;

		await runWithTransaction(runtime.context.adapter, async () => {
			const replacement = await captureInternalSessionIssuanceContext(
				runtime.context.internalAdapter,
				{
					purpose: "replacement",
					sourceSessionToken: source.token,
				},
			);
			await runtime.context.internalAdapter.deleteSession(source.token);
			successor = await runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				undefined,
				false,
				replacement,
			);
		});

		const [successorAuthority] = await authorityRows(runtime.context);
		expect(successorAuthority).toMatchObject({
			id: successor.id,
			authenticationPrimaryMethod: "password",
			authenticationFactorMethod: null,
			authenticationPolicyRevision: "7",
		});
		expect(successorAuthority?.authenticationPrimaryAt).toEqual(
			sourceAuthority?.authenticationPrimaryAt,
		);
		expect(successorAuthority?.authenticationAssuranceExpiresAt).toEqual(
			sourceAuthority?.authenticationAssuranceExpiresAt,
		);
		expect(successorAuthority?.expiresAt).toEqual(sourceCeiling);
	});

	it("rolls replacement issuance back when its captured source remains authoritative", async () => {
		const runtime = await setupManagedRuntime();
		const source = await issuePasswordSession(runtime);

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				const captured = await captureInternalSessionIssuanceContext(
					runtime.context.internalAdapter,
					{
						purpose: "replacement",
						sourceSessionToken: source.token,
					},
				);
				await runtime.context.internalAdapter.createSession(
					runtime.user.id,
					false,
					undefined,
					false,
					captured,
				);
			}),
		).rejects.toMatchObject({ reason: "policy_unsatisfied" });
		expect(await authorityRows(runtime.context)).toHaveLength(1);
		expect(await credentialRows(runtime)).toHaveLength(1);
	});

	it.each(["revision", "membership"] as const)(
		"rolls an organization transition back when target %s changes before commit",
		async (race) => {
			let targetRevision = "8";
			let targetMembershipPresent = true;
			let armRace = false;
			const runtime = await setupManagedRuntime({
				reader: (input) =>
					policyResult(input, {
						revision: input.organizationId ? targetRevision : "7",
						membershipOrganizationId: input.organizationId
							? targetMembershipPresent
								? input.organizationId
								: null
							: null,
					}),
				options: {
					databaseHooks: {
					session: {
						create: {
							before: async (data) => {
									if (!armRace) return { data };
									if (race === "revision") targetRevision = "9";
									else targetMembershipPresent = false;
									return { data };
								},
							},
						},
					},
				},
			});
			const source = await issuePasswordSession(runtime);
			armRace = true;
			await expect(
				runWithTransaction(runtime.context.adapter, async () => {
					const transition = await captureInternalSessionIssuanceContext(
						runtime.context.internalAdapter,
						{
							purpose: "organization",
							sourceSessionToken: source.token,
							targetOrganizationId: "organization_b",
						},
					);
					await runtime.context.internalAdapter.deleteSession(source.token);
					await runtime.context.internalAdapter.createSession(
						runtime.user.id,
						false,
						undefined,
						false,
						transition,
					);
				}),
			).rejects.toBeInstanceOf(
				race === "revision"
					? ManagedSessionIssuanceError
					: InvalidRuntimeAuthenticationPolicyError,
			);
			expect(await authorityRows(runtime.context)).toHaveLength(1);
			expect(await credentialRows(runtime)).toHaveLength(1);
		},
	);

	it("rejects forged, reused, and out-of-transaction organization contexts", async () => {
		const runtime = await setupManagedRuntime();
		const source = await issuePasswordSession(runtime);
		const forged = createInternalSessionIssuanceContext({
			purpose: "organization",
			sourceSessionToken: source.token,
			targetOrganizationId: "organization_b",
		});
		await expect(
			runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				undefined,
				false,
				forged,
			),
		).rejects.toMatchObject({ reason: "unsupported_purpose" });
		await expect(
			captureInternalSessionIssuanceContext(runtime.context.internalAdapter, {
				purpose: "organization",
				sourceSessionToken: source.token,
				targetOrganizationId: "organization_b",
			}),
		).rejects.toMatchObject({ reason: "context_invalid" });

		const capturedOutside = await runWithTransaction(
			runtime.context.adapter,
			() =>
				captureInternalSessionIssuanceContext(runtime.context.internalAdapter, {
					purpose: "organization",
					sourceSessionToken: source.token,
					targetOrganizationId: "organization_b",
				}),
		);
		await expect(
			runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				undefined,
				false,
				capturedOutside,
			),
		).rejects.toMatchObject({ reason: "context_invalid" });

		const reusableSource = await issuePasswordSession(runtime);
		await runWithTransaction(runtime.context.adapter, async () => {
			const captured = await captureInternalSessionIssuanceContext(
				runtime.context.internalAdapter,
				{
					purpose: "organization",
					sourceSessionToken: reusableSource.token,
					targetOrganizationId: "organization_b",
				},
			);
			await runtime.context.internalAdapter.deleteSession(reusableSource.token);
			await runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				undefined,
				false,
				captured,
			);
			await expect(
				runtime.context.internalAdapter.createSession(
					runtime.user.id,
					false,
					undefined,
					false,
					captured,
				),
			).rejects.toMatchObject({ reason: "context_invalid" });
		});
	});

	it("allows at most one organization successor from competing source captures", async () => {
		const runtime = await setupManagedRuntime();
		const source = await issuePasswordSession(runtime);
		const attempt = () =>
			runWithTransaction(runtime.context.adapter, async () => {
				const transition = await captureInternalSessionIssuanceContext(
					runtime.context.internalAdapter,
					{
						purpose: "organization",
						sourceSessionToken: source.token,
						targetOrganizationId: "organization_b",
					},
				);
				await runtime.context.internalAdapter.deleteSession(source.token);
				return runtime.context.internalAdapter.createSession(
					runtime.user.id,
					false,
					undefined,
					false,
					transition,
				);
			});
		const attempts = await Promise.allSettled([attempt(), attempt()]);
		expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(
			1,
		);
		expect(await authorityRows(runtime.context)).toHaveLength(1);
		const activeCredentials = (await credentialRows(runtime)).filter(
			(credential) => credential.status === "active",
		);
		expect(activeCredentials).toHaveLength(1);
	});

	it("issues an organization-bound successor only after retiring its exact source", async () => {
		const sourceCeiling = new Date(Date.now() + 60_000);
		let corruptSuccessorHook = false;
		const runtime = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					revision: input.organizationId === "organization_b" ? "8" : "7",
				}),
			options: {
				databaseHooks: {
					session: {
						create: {
							before: async (data) => ({
								data: corruptSuccessorHook
									? {
											...data,
											activeOrganizationId: "organization_hook",
											activeTeamId: "team_hook",
										}
									: data,
							}),
						},
					},
				},
				session: {
					additionalFields: {
						activeOrganizationId: { type: "string", required: false },
						activeTeamId: { type: "string", required: false },
					},
				},
			},
		});
		const source = await runtime.context.internalAdapter.createSession(
			runtime.user.id,
			false,
			{
				activeOrganizationId: "organization_a",
				activeTeamId: "team_a",
				expiresAt: sourceCeiling,
				__preserveSessionExpiresAt: true,
			},
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: runtime.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
				targetOrganizationId: "organization_a",
			}),
		);
		const [sourceAuthority] = await authorityRows(runtime.context);
		let successor!: Session;
		corruptSuccessorHook = true;

		await runWithTransaction(runtime.context.adapter, async () => {
			const transition = await captureInternalSessionIssuanceContext(
				runtime.context.internalAdapter,
				{
					purpose: "organization",
					sourceSessionToken: source.token,
					targetOrganizationId: "organization_b",
				},
			);
			await runtime.context.internalAdapter.deleteSession(source.token);
			successor = await runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				{
					activeOrganizationId: "organization_override",
					activeTeamId: "team_override",
				},
				true,
				transition,
			);
		});

		const [successorAuthority] = await authorityRows(runtime.context);
		expect(successorAuthority).toMatchObject({
			id: successor.id,
			activeOrganizationId: "organization_b",
			activeTeamId: null,
			authenticationPolicyOrganizationId: "organization_b",
			authenticationPolicyRevision: "8",
		});
		expect(successorAuthority?.authenticationPrimaryAt).toEqual(
			sourceAuthority?.authenticationPrimaryAt,
		);
		expect(successorAuthority?.authenticationAssuranceExpiresAt).toEqual(
			sourceAuthority?.authenticationAssuranceExpiresAt,
		);
		expect(successorAuthority?.expiresAt).toEqual(sourceCeiling);
		await expect(
			runtime.context.internalAdapter.findSession(source.token),
		).resolves.toBeNull();
		await expect(
			runtime.context.internalAdapter.updateSession(successor.token, {
				activeOrganizationId: "organization_c",
			}),
		).resolves.toBeNull();
	});

	it("rolls organization transition issuance back while its source remains active", async () => {
		const runtime = await setupManagedRuntime();
		const source = await issuePasswordSession(runtime);

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				const transition = await captureInternalSessionIssuanceContext(
					runtime.context.internalAdapter,
					{
						purpose: "organization",
						sourceSessionToken: source.token,
						targetOrganizationId: "organization_b",
					},
				);
				await runtime.context.internalAdapter.createSession(
					runtime.user.id,
					false,
					undefined,
					false,
					transition,
				);
			}),
		).rejects.toMatchObject({ reason: "policy_unsatisfied" });
		expect(await authorityRows(runtime.context)).toHaveLength(1);
	});

	it.each([
		{ label: "null to organization", sourceOrganizationId: null, targetOrganizationId: "organization_b" },
		{ label: "organization to null", sourceOrganizationId: "organization_a", targetOrganizationId: null },
	])("transitions $label while clearing the active team", async (testCase) => {
		const runtime = await setupManagedRuntime({
			options: {
				session: {
					additionalFields: {
						activeOrganizationId: { type: "string", required: false },
						activeTeamId: { type: "string", required: false },
					},
				},
			},
		});
		const source = await runtime.context.internalAdapter.createSession(
			runtime.user.id,
			false,
			testCase.sourceOrganizationId === null
				? { activeTeamId: "team_a" }
				: {
						activeOrganizationId: testCase.sourceOrganizationId,
						activeTeamId: "team_a",
					},
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: runtime.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
				targetOrganizationId: testCase.sourceOrganizationId,
			}),
		);
		let successor!: Session;
		await runWithTransaction(runtime.context.adapter, async () => {
			const transition = await captureInternalSessionIssuanceContext(
				runtime.context.internalAdapter,
				{
					purpose: "organization",
					sourceSessionToken: source.token,
					targetOrganizationId: testCase.targetOrganizationId,
				},
			);
			await runtime.context.internalAdapter.deleteSession(source.token);
			successor = await runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				undefined,
				false,
				transition,
			);
		});
		const [authority] = await authorityRows(runtime.context);
		expect(authority).toMatchObject({
			id: successor.id,
			activeOrganizationId: testCase.targetOrganizationId,
			activeTeamId: null,
			authenticationPolicyOrganizationId: testCase.targetOrganizationId,
		});
	});

	it.each([
		{
			label: "missing target membership",
			reader: (input: RuntimeAuthenticationPolicyReaderInput) =>
				policyResult(input, { membershipOrganizationId: null }),
			error: InvalidRuntimeAuthenticationPolicyError,
		},
		{
			label: "wrong-subject target membership",
			reader: (input: RuntimeAuthenticationPolicyReaderInput) =>
				policyResult(input, {
					membershipOrganizationId: input.organizationId
						? input.organizationId
						: null,
					membershipSubjectId: "user_other",
				}),
			error: InvalidRuntimeAuthenticationPolicyError,
		},
		{
			label: "stricter target policy",
			reader: (input: RuntimeAuthenticationPolicyReaderInput) =>
				policyResult(input, {
					policy: input.organizationId
						? policy({ minimumAssurance: "multi_factor" })
						: policy(),
				}),
			error: ManagedSessionIssuanceError,
		},
	])("rolls organization transition back for $label", async (testCase) => {
		const runtime = await setupManagedRuntime({ reader: testCase.reader });
		const source = await issuePasswordSession(runtime);
		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				const transition = await captureInternalSessionIssuanceContext(
					runtime.context.internalAdapter,
					{
						purpose: "organization",
						sourceSessionToken: source.token,
						targetOrganizationId: "organization_b",
					},
				);
				await runtime.context.internalAdapter.deleteSession(source.token);
				await runtime.context.internalAdapter.createSession(
					runtime.user.id,
					false,
					undefined,
					false,
					transition,
				);
			}),
		).rejects.toBeInstanceOf(testCase.error);
		expect(await authorityRows(runtime.context)).toHaveLength(1);
		expect(await credentialRows(runtime)).toHaveLength(1);
	});

	it("rejects replacement capture outside a transaction and use outside the capturing transaction", async () => {
		const runtime = await setupManagedRuntime();
		const source = await issuePasswordSession(runtime);

		await expect(
			captureInternalSessionIssuanceContext(runtime.context.internalAdapter, {
				purpose: "replacement",
				sourceSessionToken: source.token,
			}),
		).rejects.toMatchObject({ reason: "context_invalid" });

		const captured = await runWithTransaction(runtime.context.adapter, () =>
			captureInternalSessionIssuanceContext(runtime.context.internalAdapter, {
				purpose: "replacement",
				sourceSessionToken: source.token,
			}),
		);
		await expect(
			runtime.context.internalAdapter.createSession(
				runtime.user.id,
				false,
				undefined,
				false,
				captured,
			),
		).rejects.toMatchObject({ reason: "context_invalid" });
		expect(await authorityRows(runtime.context)).toHaveLength(1);
	});

	it("binds captured replacement authority to the source subject and the live policy revision", async () => {
		let revision = "7";
		const runtime = await setupManagedRuntime({
			reader: (input) => policyResult(input, { revision }),
		});
		const otherUser = await runtime.context.internalAdapter.createUser({
			email: "managed-replacement-other@example.com",
			name: "Other Managed User",
		});
		const source = await issuePasswordSession(runtime);

		await runWithTransaction(runtime.context.adapter, async () => {
			const captured = await captureInternalSessionIssuanceContext(
				runtime.context.internalAdapter,
				{
					purpose: "replacement",
					sourceSessionToken: source.token,
				},
			);
			await expect(
				runtime.context.internalAdapter.createSession(
					otherUser.id,
					false,
					undefined,
					false,
					captured,
				),
			).rejects.toMatchObject({ reason: "subject_mismatch" });
		});

		await runWithTransaction(runtime.context.adapter, async () => {
			const captured = await captureInternalSessionIssuanceContext(
				runtime.context.internalAdapter,
				{
					purpose: "replacement",
					sourceSessionToken: source.token,
				},
			);
			revision = "8";
			await expect(
				runtime.context.internalAdapter.createSession(
					runtime.user.id,
					false,
					undefined,
					false,
					captured,
				),
			).rejects.toMatchObject({ reason: "policy_unsatisfied" });
		});
		expect(await authorityRows(runtime.context)).toHaveLength(1);
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

	it.each([
		{
			label: "valid",
			successorDigest: `v1:${"C".repeat(43)}`,
			publishes: true,
		},
		{ label: "malformed", successorDigest: "malformed", publishes: false },
	])(
		"handles a $label rotation descendant committed before create publication",
		async ({ label, successorDigest, publishes }) => {
			const store = new Map<string, string>();
			const createHookEntered = deferred();
			const createHookRelease = deferred();
			let createdSessionId = "";
			const namespace = `managed-create-newer-${label}-successor-test`;
			let malformedCleanupState: {
				credentialKey: string;
				handleKey: string;
				indexKey: string;
				sentinelKey: string;
				sentinelValue: string;
			} | null = null;
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
			const publicationLogger = spyOnManagedPublicationFailure(runtime);

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
					await currentAdapter.update({
						model: "sessionCredential",
						where: [{ field: "id", value: String(root!.id) }],
						update: {
							status: "consumed",
							consumedAt: now,
							rotationNonceDigest: await digestSessionRotationNonce(
								"create-race-operation",
							),
							recoveryExpiresAt: new Date(
								now.getTime() + SESSION_ROTATION_RECOVERY_WINDOW_MS,
							),
							updatedAt: now,
						},
					});
					const successorId = `create-race-${String(root!.id)}`;
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
				if (!publishes) {
					const root = (await credentialRows(runtime)).find(
						(credential) => credential.rotationCounter === 0,
					)!;
					const persistedSession = (await authorityRows(runtime.context))[0]!;
					const persistedUser = await runtime.context.adapter.findOne<
						Record<string, unknown>
					>({
						model: "user",
						where: [{ field: "id", value: runtime.user.id }],
					});
					const credentialKey =
						`clearance:${namespace}:session-credential:${String(root.secretDigest)}`;
					const handleKey =
						`clearance:${namespace}:session-handle:${createdSessionId}`;
					const indexKey =
						`clearance:${namespace}:active-sessions:${runtime.user.id}`;
					const sentinelKey = `clearance:${namespace}:unrelated-sentinel`;
					const sentinelValue = JSON.stringify({ owner: "unrelated" });
					store.set(
						credentialKey,
						JSON.stringify({
							session: JSON.parse(
								JSON.stringify({ ...persistedSession, token: null }),
							),
							user: JSON.parse(JSON.stringify(persistedUser)),
						}),
					);
					store.set(handleKey, JSON.stringify({ credentialKey }));
					store.set(
						indexKey,
						JSON.stringify([
							{
								sessionId: createdSessionId,
								credentialKey,
								expiresAt: (persistedSession.expiresAt as Date).getTime(),
							},
						]),
					);
					store.set(sentinelKey, sentinelValue);
					malformedCleanupState = {
						credentialKey,
						handleKey,
						indexKey,
						sentinelKey,
						sentinelValue,
					};
				}
			} finally {
				createHookRelease.resolve();
			}
			if (!publishes) {
				const issued = await pendingCreate;
				expect(issued.id).toBe(createdSessionId);
				expectManagedPublicationFailure(publicationLogger);
				expect(malformedCleanupState).not.toBeNull();
				const cleanupState = malformedCleanupState!;
				expect(store.has(cleanupState.credentialKey)).toBe(false);
				expect(store.has(cleanupState.handleKey)).toBe(false);
				expect(store.has(cleanupState.indexKey)).toBe(false);
				expect(store.get(cleanupState.sentinelKey)).toBe(
					cleanupState.sentinelValue,
				);
				expect(store).toEqual(
					new Map([
						[cleanupState.sentinelKey, cleanupState.sentinelValue],
					]),
				);
				expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
				expect(
					await runtime.context.adapter.count({ model: "sessionCredential" }),
				).toBe(2);
				return;
			}
			const issued = await pendingCreate;
			expect(publicationLogger).not.toHaveBeenCalled();
			const handleKey = [...store.keys()].find((key) =>
				key.endsWith(`:session-handle:${issued.id}`),
			)!;
			const successorKey =
				`clearance:${namespace}:session-credential:${successorDigest}`;
			expect(JSON.parse(store.get(handleKey)!)).toEqual({
				credentialKey: successorKey,
			});
			expect(store.has(successorKey)).toBe(true);
		},
	);

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
			const publicationLogger = spyOnManagedPublicationFailure(runtime);

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
			const issued = await pendingCreate;
			expect(issued.id).toBe(createdSessionId);
			expectManagedPublicationFailure(publicationLogger);
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
			expect(
				await runtime.context.adapter.count({ model: "session" }),
			).toBe(invalidation === "policy" ? 1 : 0);
			const committedCredentials = await credentialRows(runtime);
			expect(committedCredentials).toHaveLength(1);
			expect(committedCredentials[0]!.status).toBe(
				invalidation === "policy" ? "active" : "revoked",
			);
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
		const publicationLogger = spyOnManagedPublicationFailure(runtime);

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
		const issued = await pendingCreate;
		expect(issued.id).toBe(createdSessionId);
		expectManagedPublicationFailure(publicationLogger);
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
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(await credentialRows(runtime)).toHaveLength(3);
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
		const publicationLogger = spyOnManagedPublicationFailure(runtime);

		const issued = await issuePasswordSession(runtime);
		expect(issued.token).toMatch(/^clr_rt_/);
		expectManagedPublicationFailure(
			publicationLogger,
			"Managed session cache publication failed after commit",
		);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(
			await runtime.context.adapter.count({ model: "sessionCredential" }),
		).toBe(1);
		expect(secondarySet).toHaveBeenCalledTimes(1);
	});
});

describe("managed organization adapter transitions", () => {
	const sessionFields = {
		activeOrganizationId: { type: "string", required: false },
		activeTeamId: { type: "string", required: false },
		transitionMetadata: {
			type: "string",
			required: false,
			defaultValue: "configured-default",
		},
	} as const;

	async function issueOrganizationSource(
		runtime: ManagedRuntime,
		expiresAt = new Date(Date.now() + 120_000),
		dontRememberMe = false,
	) {
		return runtime.context.internalAdapter.createSession(
			runtime.user.id,
			dontRememberMe,
			{
				activeOrganizationId: "organization_a",
				activeTeamId: "team_a",
				transitionMetadata: "preserve-me",
				expiresAt,
				__preserveSessionExpiresAt: true,
			},
			true,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: runtime.user.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
				targetOrganizationId: "organization_a",
			}),
		);
	}

	it.each([
		{ label: "organization to organization", target: "organization_b" },
		{ label: "organization to environment", target: null },
	])(
		"rotates the exact adapter source for $label while preserving its ceiling and custom fields",
		async ({ target }) => {
			const runtime = await setupManagedRuntime({
				reader: (input) =>
					policyResult(input, {
						revision: input.organizationId === "organization_b" ? "8" : "7",
					}),
				options: { session: { additionalFields: sessionFields } },
			});
			const sourceCeiling = new Date(Date.now() + 120_000);
			const source = await issueOrganizationSource(runtime, sourceCeiling);
			const successor = await getOrgAdapter(runtime.context).setActiveOrganization(
				source.token,
				target,
				organizationEndpointContext(runtime, source),
			);

			expect(successor.id).not.toBe(source.id);
			expect(successor.token).not.toBe(source.token);
			expect(successor).toMatchObject({
				userId: runtime.user.id,
				activeOrganizationId: target,
				activeTeamId: null,
				transitionMetadata: "preserve-me",
				authenticationPolicyOrganizationId: target,
				authenticationPolicyRevision: target ? "8" : "7",
			});
			expect(successor.expiresAt).toEqual(sourceCeiling);
			await expect(
				runtime.context.internalAdapter.findSession(source.token),
			).resolves.toBeNull();
			await expect(
				runtime.context.internalAdapter.findSession(successor.token),
			).resolves.toMatchObject({ session: { id: successor.id } });
			expect(await authorityRows(runtime.context)).toHaveLength(1);
			expect(
				(await credentialRows(runtime)).filter(
					(credential) => credential.status === "active",
				),
			).toHaveLength(1);
		},
	);

	it("allows exactly one successor from concurrent adapter transitions", async () => {
		const runtime = await setupManagedRuntime({
			options: { session: { additionalFields: sessionFields } },
		});
		const source = await issueOrganizationSource(runtime);
		const orgAdapter = getOrgAdapter(runtime.context);
		const transition = () =>
			orgAdapter.setActiveOrganization(
				source.token,
				"organization_b",
				organizationEndpointContext(runtime, source),
			);
		const outcomes = await Promise.allSettled([transition(), transition()]);

		expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(
			1,
		);
		await expect(
			runtime.context.internalAdapter.findSession(source.token),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toHaveLength(1);
		expect(
			(await credentialRows(runtime)).filter(
				(credential) => credential.status === "active",
			),
		).toHaveLength(1);
	});

	it("runs lifecycle work after capture in the owning transaction", async () => {
		const runtime = await setupManagedRuntime({
			options: { session: { additionalFields: sessionFields } },
		});
		const source = await issueOrganizationSource(runtime);
		let callbackRan = false;

		await getOrgAdapter(runtime.context).setActiveOrganization(
			source.token,
			"organization_b",
			organizationEndpointContext(runtime, source),
			{
				afterCapture: async () => {
					callbackRan = true;
					expect(await getCurrentAdapter(runtime.context.adapter)).not.toBe(
						runtime.context.adapter,
					);
					expect(runtime.readForSubject).toHaveBeenCalled();
					await (
						await getCurrentAdapter(runtime.context.adapter)
					).update<User>({
						model: "user",
						where: [{ field: "id", value: runtime.user.id }],
						update: { name: "Lifecycle callback committed" },
					});
				},
			},
		);

		expect(callbackRan).toBe(true);
		await expect(runtime.context.internalAdapter.findUserById(runtime.user.id)).resolves
			.toMatchObject({ name: "Lifecycle callback committed" });
	});

	it("rolls the source and lifecycle work back when the callback fails", async () => {
		const runtime = await setupManagedRuntime({
			options: { session: { additionalFields: sessionFields } },
		});
		const source = await issueOrganizationSource(runtime);
		const failure = new Error("lifecycle callback failed");

		await expect(
			getOrgAdapter(runtime.context).setActiveOrganization(
				source.token,
				"organization_b",
				organizationEndpointContext(runtime, source),
				{
					afterCapture: async () => {
						await (
							await getCurrentAdapter(runtime.context.adapter)
						).update<User>({
							model: "user",
							where: [{ field: "id", value: runtime.user.id }],
							update: { name: "Must roll back" },
						});
						throw failure;
					},
				},
			),
		).rejects.toBe(failure);
		await expect(
			runtime.context.internalAdapter.findSession(source.token),
		).resolves.toMatchObject({ session: { id: source.id } });
		await expect(runtime.context.internalAdapter.findUserById(runtime.user.id)).resolves
			.toMatchObject({ name: runtime.user.name });
		expect(await authorityRows(runtime.context)).toHaveLength(1);
	});

	it.each(["delete", "rotate", "recursive"] as const)(
		"rejects and rolls back lifecycle callback %s misuse",
		async (misuse) => {
			const runtime = await setupManagedRuntime({
				options: { session: { additionalFields: sessionFields } },
			});
			const source = await issueOrganizationSource(runtime);
			const adapter = getOrgAdapter(runtime.context);

			await expect(
				adapter.setActiveOrganization(
					source.token,
					"organization_b",
					organizationEndpointContext(runtime, source),
					{
						afterCapture: async () => {
							if (misuse === "delete") {
								await runtime.context.internalAdapter.deleteSession(source.token);
								return;
							}
							if (misuse === "rotate") {
								await runtime.context.internalAdapter.rotateSessionCredential(
									source.token,
									generateCredentialOperationKey(),
								);
								return;
							}
							try {
								await adapter.setActiveOrganization(
									source.token,
									"organization_b",
									organizationEndpointContext(runtime, source),
								);
							} catch {
								// The outer transition must remain tainted even if misuse is swallowed.
							}
						},
					},
				),
			).rejects.toBeInstanceOf(ClearanceError);
			await expect(
				runtime.context.internalAdapter.findSession(source.token),
			).resolves.toMatchObject({ session: { id: source.id } });
			expect(await authorityRows(runtime.context)).toHaveLength(1);
			expect(
				(await credentialRows(runtime)).filter(
					(credential) => credential.status === "active",
				),
			).toHaveLength(1);
		},
	);

	it("rejects downgraded contexts and non-exact request bearers", async () => {
		const runtime = await setupManagedRuntime({
			options: { session: { additionalFields: sessionFields } },
		});
		const source = await issueOrganizationSource(runtime);
		const adapter = getOrgAdapter(runtime.context);
		const downgraded = organizationEndpointContext(runtime, source);
		downgraded.context.options = {};
		await expect(
			adapter.setActiveOrganization(source.token, "organization_b", downgraded),
		).rejects.toBeInstanceOf(ClearanceError);

		const wrongBearer = organizationEndpointContext(runtime, {
			...source,
			token: "another-presented-bearer",
		});
		await expect(
			adapter.setActiveOrganization(source.token, "organization_b", wrongBearer),
		).rejects.toBeInstanceOf(ClearanceError);
		await expect(
			adapter.setActiveOrganization(
				source.token,
				"organization_b",
				organizationEndpointContext(runtime, source),
				{ dontRememberMe: "true" as never },
			),
		).rejects.toBeInstanceOf(ClearanceError);
		await expect(
			runtime.context.internalAdapter.findSession(source.token),
		).resolves.toMatchObject({ session: { id: source.id } });
	});

	it.each([true, false])(
		"passes explicit dontRememberMe=%s through trusted server orchestration",
		async (dontRememberMe) => {
			const runtime = await setupManagedRuntime({
				options: { session: { additionalFields: sessionFields } },
			});
			const source = await issueOrganizationSource(
				runtime,
				new Date(Date.now() + 120_000),
				dontRememberMe,
			);
			const createSession = vi.spyOn(runtime.context.internalAdapter, "createSession");
			await getOrgAdapter(runtime.context).setActiveOrganization(
				source.token,
				"organization_b",
				organizationEndpointContext(runtime, source),
				{ dontRememberMe },
			);
			expect(createSession.mock.calls.at(-1)?.[1]).toBe(dontRememberMe);
		},
	);

	it("exposes a prepared successor to an outer transaction owner", async () => {
		const runtime = await setupManagedRuntime({
			options: { session: { additionalFields: sessionFields } },
		});
		const source = await issueOrganizationSource(runtime);
		let prepared: Session | undefined;

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await getOrgAdapter(runtime.context).setActiveOrganization(
					source.token,
					"organization_b",
					organizationEndpointContext(runtime, source),
					{ onSuccessorPrepared: (successor) => (prepared = successor) },
				);
				await queueAfterTransactionHook(async () => {
					throw new Error("outer publication failed");
				}, runtime.context.adapter);
			}),
		).rejects.toBeInstanceOf(AfterTransactionHookError);
		expect(prepared).toBeDefined();
		await expect(
			runtime.context.internalAdapter.findSession(prepared!.token),
		).resolves.toMatchObject({ session: { id: prepared!.id } });
	});

	it("rolls lifecycle work and source retirement back when target issuance fails", async () => {
		let rejectTarget = false;
		const runtime = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					membershipOrganizationId:
						rejectTarget && input.organizationId === "organization_b"
							? null
							: undefined,
				}),
			options: { session: { additionalFields: sessionFields } },
		});
		const source = await issueOrganizationSource(runtime);

		await expect(
			getOrgAdapter(runtime.context).setActiveOrganization(
				source.token,
				"organization_b",
				organizationEndpointContext(runtime, source),
				{
					afterCapture: async () => {
						await (
							await getCurrentAdapter(runtime.context.adapter)
						).update<User>({
							model: "user",
							where: [{ field: "id", value: runtime.user.id }],
							update: { name: "Issuance must roll back" },
						});
						rejectTarget = true;
					},
				},
			),
		).rejects.toBeInstanceOf(InvalidRuntimeAuthenticationPolicyError);
		await expect(
			runtime.context.internalAdapter.findSession(source.token),
		).resolves.toMatchObject({ session: { id: source.id } });
		await expect(runtime.context.internalAdapter.findUserById(runtime.user.id)).resolves
			.toMatchObject({ name: runtime.user.name });
		expect(await authorityRows(runtime.context)).toHaveLength(1);
	});

	it("allows atomic current-membership removal before issuing the environment successor", async () => {
		let currentMembershipExists = true;
		const runtime = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					membershipOrganizationId:
						input.organizationId === "organization_a" &&
						!currentMembershipExists
							? null
							: undefined,
				}),
			options: { session: { additionalFields: sessionFields } },
		});
		const source = await issueOrganizationSource(runtime);
		const successor = await getOrgAdapter(runtime.context).setActiveOrganization(
			source.token,
			null,
			organizationEndpointContext(runtime, source),
			{
				afterCapture: () => {
					currentMembershipExists = false;
				},
			},
		);

		expect((successor as Session & { activeOrganizationId: string | null }).activeOrganizationId)
			.toBeNull();
		await expect(
			runtime.context.internalAdapter.findSession(source.token),
		).resolves.toBeNull();
		await expect(
			runtime.context.internalAdapter.findSession(successor.token),
		).resolves.toMatchObject({ session: { id: successor.id } });
	});

	it("returns the committed successor when source cache cleanup fails after commit", async () => {
		let failCleanup = true;
		const setup = await setupManagedDeletionRuntime({
			namespace: "organization-transition-publication-failure",
			options: { session: { additionalFields: sessionFields } },
			delete: async () => {
				if (failCleanup) throw new Error("source cache cleanup failed");
			},
		});
		const source = await issueOrganizationSource(setup.runtime);

		const successor = await getOrgAdapter(
			setup.runtime.context,
		).setActiveOrganization(
			source.token,
			"organization_b",
			organizationEndpointContext(setup.runtime, source),
		);

		expect(successor.id).not.toBe(source.id);
		failCleanup = false;
		await expect(
			setup.runtime.context.internalAdapter.findSession(successor.token),
		).resolves.toMatchObject({ session: { id: successor.id } });
		await expect(
			setup.runtime.context.internalAdapter.findSession(source.token),
		).resolves.toBeNull();
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

	it("rolls rotation back when policy changes after successor validation but before commit", async () => {
		let rotationReads = 0;
		let rotating = false;
		const runtime = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					revision: rotating && ++rotationReads >= 3 ? "8" : "7",
				}),
		});
		const session = await issuePasswordSession(runtime);
		const before = structuredClone(await credentialRows(runtime));
		rotating = true;

		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			),
		).resolves.toBeNull();
		expect(rotationReads).toBeGreaterThanOrEqual(3);
		expect(await credentialRows(runtime)).toEqual(before);
		expect(await authorityRows(runtime.context)).toHaveLength(1);
		expect((await authorityRows(runtime.context))[0]?.id).toBe(session.id);
	});

	it("withholds idempotent recovery when policy changes before commit", async () => {
		let recoveryReads = 0;
		let recovering = false;
		const runtime = await setupManagedRuntime({
			reader: (input) =>
				policyResult(input, {
					revision: recovering && ++recoveryReads >= 2 ? "8" : "7",
				}),
		});
		const session = await issuePasswordSession(runtime);
		const operationKey = generateCredentialOperationKey();
		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.not.toBeNull();
		recovering = true;

		await expect(
			runtime.context.internalAdapter.recoverSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.toBeNull();
		expect(recoveryReads).toBeGreaterThanOrEqual(2);
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
					if (rotationPolicyReads === 4) {
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
				if (invalidatePublication && rotationPolicyReads === 4) {
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
						invalidatePublication && rotationPolicyReads === 4 ? "8" : "7",
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
		const publicationLogger = spyOnManagedPublicationFailure(runtime);

		const rotated =
			await runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			);
		expect(rotated).toMatchObject({ rotationCounter: 1 });
		expectManagedPublicationFailure(publicationLogger);
		const committedCredentials = await credentialRows(runtime);
		expect(committedCredentials).toHaveLength(2);
		expect(committedCredentials.map((row) => row.status).sort()).toEqual([
			"active",
			"consumed",
		]);
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
					if (rotationPolicyReads === 4) {
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
								rotationNonceDigest: await digestSessionRotationNonce(
									"newer-operation",
								),
								recoveryExpiresAt: new Date(
									now.getTime() + SESSION_ROTATION_RECOVERY_WINDOW_MS,
								),
								updatedAt: now,
							},
						});
						const newerId = `newer-${String(active!.id)}`;
						const newerDigest = `v1:${"D".repeat(43)}`;
						await input.transaction!.create({
							model: "sessionCredential",
							forceAllowId: true,
							data: {
								...active,
								id: newerId,
								selector: `selector-${newerId}`,
								secretDigest: newerDigest,
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
						if (active!.parentCredentialId) {
							await input.transaction!.update({
								model: "sessionCredential",
								where: [
									{
										field: "id",
										value: String(active!.parentCredentialId),
									},
								],
								update: {
									rotationNonceDigest: null,
									recoverySecretCiphertext: null,
									recoveryExpiresAt: null,
									updatedAt: now,
								},
							});
						}
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
							`session-credential:${newerDigest}`;
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

	it("rolls back contradictory publication metadata and returns the committed rotation", async () => {
		const store = new Map<string, string>();
		let rotationPolicyReads = 0;
		let breakPublicationLifecycle = false;
		let sessionId = "";
		let successorCredentialKey = "";
		const runtime = await setupManagedRuntime({
			reader: async (input) => {
				if (breakPublicationLifecycle) {
					rotationPolicyReads += 1;
					if (rotationPolicyReads === 4) {
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
						update: { consumedAt: new Date() },
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
		breakPublicationLifecycle = true;
		const publicationLogger = spyOnManagedPublicationFailure(runtime);

		const rotated =
			await runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			);
		expect(rotated).toMatchObject({ rotationCounter: 1 });
		expectManagedPublicationFailure(publicationLogger);
		expect(store.has(oldCredentialKey)).toBe(false);
		expect(store.has(successorCredentialKey)).toBe(false);
		expect(store.has(handleKey)).toBe(false);
		expect(store.has(indexKey)).toBe(false);
		const rows = await credentialRows(runtime);
		expect(rows).toHaveLength(2);
		const active = rows.find((row) => row.status === "active")!;
		expect(active.parentCredentialId).toBe(
			rows.find((row) => row.status === "consumed")!.id,
		);
		expect(active.consumedAt).toBeNull();
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
		const publicationLogger = spyOnManagedPublicationFailure(runtime);

		const rotated =
			await runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			);
		expect(rotated).toMatchObject({ rotationCounter: 1 });
		expectManagedPublicationFailure(
			publicationLogger,
			"Managed session cache publication failed after commit",
		);
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
		const rotated = await runtime.context.internalAdapter.rotateSessionCredential(
			session.token,
			generateCredentialOperationKey(),
		);
		expect(rotated).not.toBeNull();
		const currentToken = rotated!.refreshToken;
		const before = (await authorityRows(runtime.context))[0]!;
		const newExpiry = new Date(session.expiresAt.getTime() + 60_000);
		const directForgery = Object.fromEntries(
			SESSION_ASSURANCE_RESERVED_FIELDS.map((field) => [field, "forged"]),
		);

		await expect(
			runtime.context.internalAdapter.updateSession(currentToken, {
				...directForgery,
				id: "direct-id",
				token: "direct-token",
				userId: "direct-user",
				twoFactorSessionGeneration: "direct-two-factor",
				passkeySessionGeneration: "direct-passkey",
				expiresAt: newExpiry,
			} as never),
		).resolves.toMatchObject({ id: session.id, token: currentToken });

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
			runtime.context.internalAdapter.updateSession(currentToken, {
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
		const sessionDeadlineAt = new Date(Date.now() + 1_000);
		await runtime.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: sessionDeadline.id }],
			update: {
				expiresAt: sessionDeadlineAt,
				authenticationAssuranceExpiresAt: sessionDeadlineAt,
			},
		});
		await runtime.context.adapter.updateMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: sessionDeadline.id }],
			update: { expiresAt: sessionDeadlineAt },
		});
		let stableSession = structuredClone(await authorityRows(runtime.context));
		let stableCredentials = structuredClone(await credentialRows(runtime));
		await crossDeadline(sessionDeadline.token);
		expect(await authorityRows(runtime.context)).toEqual(stableSession);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);

		const credentialDeadline = await issuePasswordSession(runtime);
		const credentialDeadlineAt = new Date(Date.now() + 1_000);
		await runtime.context.adapter.update({
			model: "session",
			where: [{ field: "id", value: credentialDeadline.id }],
			update: { expiresAt: credentialDeadlineAt },
		});
		await runtime.context.adapter.updateMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: credentialDeadline.id }],
			update: { expiresAt: credentialDeadlineAt },
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

	it.each(["update", "rotate"] as const)(
		"rejects a disconnected managed lineage before %s mutation without secondary storage",
		async (operation) => {
			const runtime = await setupManagedRuntime();
			const session = await issuePasswordSession(runtime);
			const credential = (await credentialRows(runtime))[0]!;
			await runtime.context.adapter.create({
				model: "sessionCredential",
				forceAllowId: true,
				data: {
					...credential,
					id: `${credential.id}-disconnected`,
					selector: "D".repeat(32),
					secretDigest: await digestSessionRefreshSecret(
						`disconnected-${operation}`,
					),
					status: "consumed",
					familyId: `${credential.familyId}-disconnected`,
					parentCredentialId: null,
					rotationCounter: 0,
					consumedAt: new Date(),
				},
			});
			const stableSessions = structuredClone(
				await authorityRows(runtime.context),
			);
			const stableCredentials = structuredClone(await credentialRows(runtime));

			await expect(
				runtime.context.internalAdapter.findSession(session.token),
			).resolves.toBeNull();
			const result =
				operation === "update"
					? runtime.context.internalAdapter.updateSession(session.token, {
							ipAddress: "192.0.2.200",
						})
					: runtime.context.internalAdapter.rotateSessionCredential(
							session.token,
							generateCredentialOperationKey(),
						);
			await expect(result).resolves.toBeNull();
			expect(await authorityRows(runtime.context)).toEqual(stableSessions);
			expect(await credentialRows(runtime)).toEqual(stableCredentials);
		},
	);

	it.each(["update", "rotate"] as const)(
		"rejects contradictory active lifecycle metadata before %s mutation",
		async (operation) => {
			const runtime = await setupManagedRuntime();
			const session = await issuePasswordSession(runtime);
			await runtime.context.adapter.updateMany({
				model: "sessionCredential",
				where: [{ field: "sessionId", value: session.id }],
				update: { consumedAt: new Date() },
			});
			const stableSessions = structuredClone(
				await authorityRows(runtime.context),
			);
			const stableCredentials = structuredClone(await credentialRows(runtime));

			await expect(
				runtime.context.internalAdapter.findSession(session.token),
			).resolves.toBeNull();
			const result =
				operation === "update"
					? runtime.context.internalAdapter.updateSession(session.token, {
							ipAddress: "192.0.2.201",
						})
					: runtime.context.internalAdapter.rotateSessionCredential(
							session.token,
							generateCredentialOperationKey(),
						);
			await expect(result).resolves.toBeNull();
			expect(await authorityRows(runtime.context)).toEqual(stableSessions);
			expect(await credentialRows(runtime)).toEqual(stableCredentials);
		},
	);

	it("rejects contradictory consumed lifecycle metadata in both DB-only recovery paths", async () => {
		const runtime = await setupManagedRuntime();
		const session = await issuePasswordSession(runtime);
		const operationKey = generateCredentialOperationKey();
		const rotated = await runtime.context.internalAdapter.rotateSessionCredential(
			session.token,
			operationKey,
		);
		expect(rotated).not.toBeNull();
		await expect(
			runtime.context.internalAdapter.findSession(rotated!.refreshToken),
		).resolves.toMatchObject({ session: { id: session.id } });
		await expect(
			runtime.context.internalAdapter.recoverSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.toMatchObject({ refreshToken: rotated!.refreshToken });
		await expect(
			runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				operationKey,
			),
		).resolves.toMatchObject({ refreshToken: rotated!.refreshToken });

		const parent = (await credentialRows(runtime)).find(
			(credential) => credential.status === "consumed",
		)!;
		await runtime.context.adapter.update({
			model: "sessionCredential",
			where: [{ field: "id", value: String(parent.id) }],
			update: { recoverySecretCiphertext: "contradictory-ciphertext" },
		});
		const stableSessions = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));

		await expect(
			runtime.context.internalAdapter.findSession(rotated!.refreshToken),
		).resolves.toBeNull();
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
		expect(await authorityRows(runtime.context)).toEqual(stableSessions);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
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

describe("managed single-session authoritative revocation", () => {
	it.each(["active", "consumed", "revoked"] as const)(
		"deletes a modern session presented by an exact %s bearer",
		async (status) => {
			const { runtime, store } = await setupManagedDeletionRuntime({
				namespace: `managed-delete-modern-${status}-test`,
			});
			const session = await issuePasswordSession(runtime);
			const stableStore = new Map(store);
			await runtime.context.internalAdapter.deleteSession("unknown-bearer");
			expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
			expect(store).toEqual(stableStore);
			if (status !== "active") {
				const now = new Date();
				await runtime.context.adapter.updateMany({
					model: "sessionCredential",
					where: [{ field: "sessionId", value: session.id }],
					update: {
						status,
						consumedAt: status === "consumed" ? now : null,
						revokedAt: status === "revoked" ? now : null,
					},
				});
			}

			await runtime.context.internalAdapter.deleteSession(session.token);
			expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
			expect(await credentialRows(runtime)).toEqual([
				expect.objectContaining({
					sessionId: null,
					status: "revoked",
					rotationNonceDigest: null,
					recoverySecretCiphertext: null,
					recoveryExpiresAt: null,
				}),
			]);
			expect(store).toEqual(new Map());
		},
	);

	it.each([
		{ label: "modern handle", legacy: false, operation: "handle" },
		{ label: "modern exact id", legacy: false, operation: "id" },
		{ label: "legacy bearer", legacy: true, operation: "bearer" },
		{ label: "legacy handle", legacy: true, operation: "handle" },
		{ label: "legacy exact id", legacy: true, operation: "id" },
	] as const)("deletes by $label authority", async (testCase) => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: `managed-delete-${testCase.label.replaceAll(" ", "-")}-test`,
			...(testCase.legacy ? { credentialAuthority: "legacy-v1" as const } : {}),
		});
		const session = await issuePasswordSession(runtime);
		if (testCase.operation === "id") {
			await runtime.context.internalAdapter.deleteSessionById(session.id);
		} else {
			await runtime.context.internalAdapter.deleteSession(
				testCase.operation === "handle"
					? createSessionHandle(session.id)
					: session.token,
			);
		}

		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect(store).toEqual(new Map());
	});

	it("uses only DB authority and canonically rewrites corrupted secondary state", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-corrupt-secondary-test",
		});
		const target = await issuePasswordSession(runtime);
		const survivor = await issuePasswordSession(runtime);
		const targetHandleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${target.id}`),
		)!;
		const survivorHandleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${survivor.id}`),
		)!;
		const targetCredentialKey = (
			JSON.parse(store.get(targetHandleKey)!) as { credentialKey: string }
		).credentialKey;
		const survivorCredentialKey = (
			JSON.parse(store.get(survivorHandleKey)!) as { credentialKey: string }
		).credentialKey;
		const survivorEnvelope = store.get(survivorCredentialKey)!;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		const survivorEntry = (
			JSON.parse(store.get(indexKey)!) as Array<{
				sessionId: string;
				credentialKey: string;
				expiresAt: number;
			}>
		).find((entry) => entry.sessionId === survivor.id)!;
		const futureEarlier = {
			sessionId: "future-earlier",
			credentialKey: "future-earlier-key",
			expiresAt: Date.now() + 300_000,
		};
		const futureLater = {
			sessionId: "future-later",
			credentialKey: "future-later-key",
			expiresAt: Date.now() + 900_000,
		};
		store.set(targetHandleKey, JSON.stringify({ credentialKey: survivorCredentialKey }));
		store.set(
			indexKey,
			JSON.stringify([
				futureLater,
				{
					sessionId: target.id,
					credentialKey: targetCredentialKey,
					expiresAt: target.expiresAt.getTime(),
				},
				{
					sessionId: target.id,
					credentialKey: "duplicate-target-key",
					expiresAt: target.expiresAt.getTime(),
				},
				{
					sessionId: "expired-other",
					credentialKey: "expired-other-key",
					expiresAt: Date.now() - 1,
				},
				futureEarlier,
				survivorEntry,
			]),
		);

		await runtime.context.internalAdapter.deleteSession(
			createSessionHandle(target.id),
		);
		expect(
			await runtime.context.adapter.findOne({
				model: "session",
				where: [{ field: "id", value: target.id }],
			}),
		).toBeNull();
		expect(
			await runtime.context.adapter.findOne({
				model: "session",
				where: [{ field: "id", value: survivor.id }],
			}),
		).not.toBeNull();
		expect(store.has(targetCredentialKey)).toBe(false);
		expect(store.get(survivorCredentialKey)).toBe(survivorEnvelope);
		expect(store.has(targetHandleKey)).toBe(false);
		expect(JSON.parse(store.get(indexKey)!)).toEqual([
			futureEarlier,
			futureLater,
			survivorEntry,
		]);
	});

	it.each(["missing", "malformed"] as const)(
		"deletes the expected owned envelope with a %s handle",
		async (handleState) => {
			const { runtime, store } = await setupManagedDeletionRuntime({
				namespace: `managed-delete-${handleState}-handle-test`,
			});
			const session = await issuePasswordSession(runtime);
			const handleKey = [...store.keys()].find((key) =>
				key.endsWith(`:session-handle:${session.id}`),
			)!;
			const credentialKey = (
				JSON.parse(store.get(handleKey)!) as { credentialKey: string }
			).credentialKey;
			if (handleState === "missing") store.delete(handleKey);
			else store.set(handleKey, "not-json");

			await runtime.context.internalAdapter.deleteSession(session.token);
			expect(store.has(credentialKey)).toBe(false);
			expect(store.has(handleKey)).toBe(false);
		},
	);

	it("preserves a malformed mapped envelope while deleting owned authority", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-malformed-mapped-test",
		});
		const session = await issuePasswordSession(runtime);
		const handleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${session.id}`),
		)!;
		const expectedKey = (
			JSON.parse(store.get(handleKey)!) as { credentialKey: string }
		).credentialKey;
		const malformedKey =
			"clearance:managed-delete-malformed-mapped-test:session-credential:malformed";
		store.set(malformedKey, "not-json");
		store.set(handleKey, JSON.stringify({ credentialKey: malformedKey }));

		await runtime.context.internalAdapter.deleteSessionById(session.id);
		expect(store.has(expectedKey)).toBe(false);
		expect(store.get(malformedKey)).toBe("not-json");
		expect(store.has(handleKey)).toBe(false);
	});

	it("preserves database and cache authority across an outer rollback", async () => {
		const { runtime, store, secondarySet, secondaryDelete } =
			await setupManagedDeletionRuntime({
				namespace: "managed-delete-outer-rollback-test",
			});
		const session = await issuePasswordSession(runtime);
		const stableSessions = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));
		const stableStore = new Map(store);
		secondarySet.mockClear();
		secondaryDelete.mockClear();

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await runtime.context.internalAdapter.deleteSession(session.token);
				expect(secondarySet).not.toHaveBeenCalled();
				expect(secondaryDelete).not.toHaveBeenCalled();
				throw new Error("delete outer rollback");
			}),
		).rejects.toThrow("delete outer rollback");
		expect(await authorityRows(runtime.context)).toEqual(stableSessions);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it.each(["veto", "before_throw", "rollback_after"] as const)(
		"fully rolls back delete hook mode %s",
		async (mode) => {
			const before = vi.fn(async () => {
				if (mode === "veto") return false;
				if (mode === "before_throw") throw new Error("delete before failed");
			});
			const after = vi.fn(async () => {
				if (mode === "rollback_after") {
					throw new Error("delete rollback after failed");
				}
			});
			const { runtime, store, secondarySet, secondaryDelete } =
				await setupManagedDeletionRuntime({
					namespace: `managed-delete-${mode}-test`,
					options: {
						databaseHookFailureMode:
							mode === "rollback_after" ? "rollback" : undefined,
						databaseHooks: {
							session: { delete: { before, after } },
						},
					},
				});
			const session = await issuePasswordSession(runtime);
			const stableSessions = structuredClone(
				await authorityRows(runtime.context),
			);
			const stableCredentials = structuredClone(await credentialRows(runtime));
			const stableStore = new Map(store);
			secondarySet.mockClear();
			secondaryDelete.mockClear();

			const deletion = runtime.context.internalAdapter.deleteSession(session.token);
			if (mode === "veto") await expect(deletion).resolves.toBeUndefined();
			else if (mode === "before_throw") {
				await expect(deletion).rejects.toThrow("delete before failed");
			} else {
				await expect(deletion).rejects.toThrow("delete rollback after failed");
			}
			expect(await authorityRows(runtime.context)).toEqual(stableSessions);
			expect(await credentialRows(runtime)).toEqual(stableCredentials);
			expect(store).toEqual(stableStore);
			expect(secondarySet).not.toHaveBeenCalled();
			expect(secondaryDelete).not.toHaveBeenCalled();
			expect(before).toHaveBeenCalledTimes(1);
			expect(after).toHaveBeenCalledTimes(mode === "rollback_after" ? 1 : 0);
		},
	);

	it("preserves observe-mode after-hook semantics and then cleans cache", async () => {
		const after = vi.fn(async () => {
			throw new Error("observed delete hook failure");
		});
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-observe-after-test",
			options: {
				databaseHooks: { session: { delete: { after } } },
			},
		});
		const session = await issuePasswordSession(runtime);

		await expect(
			runtime.context.internalAdapter.deleteSession(session.token),
		).resolves.toBeUndefined();
		expect(after).toHaveBeenCalledTimes(1);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect(store).toEqual(new Map());
	});

	it("reports cleanup failure after retaining the committed DB delete", async () => {
		const secondaryDelete = vi.fn(async () => {
			throw new Error("delete cleanup failed");
		});
		const { runtime } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-cleanup-failure-test",
			delete: secondaryDelete,
		});
		const session = await issuePasswordSession(runtime);

		await expect(
			runtime.context.internalAdapter.deleteSession(session.token),
		).rejects.toBeInstanceOf(AfterTransactionHookError);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect(await credentialRows(runtime)).toEqual([
			expect.objectContaining({ status: "revoked", sessionId: null }),
		]);
		expect(secondaryDelete).toHaveBeenCalled();
	});

	it("revokes modern credentials while preserving the configured session row", async () => {
		const before = vi.fn(async () => {});
		const after = vi.fn(async () => {});
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-preserve-session-test",
			options: {
				session: { preserveSessionInDatabase: true },
				databaseHooks: { session: { delete: { before, after } } },
			},
		});
		const session = await issuePasswordSession(runtime);
		await runtime.context.adapter.updateMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: session.id }],
			update: {
				rotationNonceDigest: "pending-recovery",
				recoverySecretCiphertext: "ciphertext",
				recoveryExpiresAt: new Date(Date.now() + 60_000),
			},
		});

		await runtime.context.internalAdapter.deleteSession(session.token);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(await credentialRows(runtime)).toEqual([
			expect.objectContaining({
				sessionId: session.id,
				status: "revoked",
				rotationNonceDigest: null,
				recoverySecretCiphertext: null,
				recoveryExpiresAt: null,
			}),
		]);
		expect(store).toEqual(new Map());
		expect(before).not.toHaveBeenCalled();
		expect(after).not.toHaveBeenCalled();
	});

	it.each(["intact", "missing", "malformed"] as const)(
		"cleans zero-credential preserved authority with an %s handle",
		async (handleState) => {
			const { runtime, store } = await setupManagedDeletionRuntime({
				namespace: `managed-delete-zero-credential-${handleState}-test`,
				options: { session: { preserveSessionInDatabase: true } },
			});
			const session = await issuePasswordSession(runtime);
			const handleKey = [...store.keys()].find((key) =>
				key.endsWith(`:session-handle:${session.id}`),
			)!;
			const credentialKey = (
				JSON.parse(store.get(handleKey)!) as { credentialKey: string }
			).credentialKey;
			await runtime.context.adapter.deleteMany({
				model: "sessionCredential",
				where: [{ field: "sessionId", value: session.id }],
			});
			if (handleState === "missing") store.delete(handleKey);
			else if (handleState === "malformed") store.set(handleKey, "not-json");

			await runtime.context.internalAdapter.deleteSession(
				createSessionHandle(session.id),
			);
			expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
			expect(await credentialRows(runtime)).toEqual([]);
			expect(store.has(credentialKey)).toBe(false);
			expect(store.has(handleKey)).toBe(false);
			expect(
				[...store.keys()].some((key) => key.includes(":active-sessions:")),
			).toBe(false);
		},
	);

	it("defers zero-credential preserved cleanup through an outer rollback", async () => {
		const { runtime, store, secondarySet, secondaryDelete } =
			await setupManagedDeletionRuntime({
				namespace: "managed-delete-zero-credential-rollback-test",
				options: { session: { preserveSessionInDatabase: true } },
			});
		const session = await issuePasswordSession(runtime);
		await runtime.context.adapter.deleteMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: session.id }],
		});
		const stableStore = new Map(store);
		secondarySet.mockClear();
		secondaryDelete.mockClear();

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await runtime.context.internalAdapter.deleteSession(
					createSessionHandle(session.id),
				);
				expect(secondarySet).not.toHaveBeenCalled();
				expect(secondaryDelete).not.toHaveBeenCalled();
				throw new Error("zero-credential cleanup rollback");
			}),
		).rejects.toThrow("zero-credential cleanup rollback");
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(1);
		expect(await credentialRows(runtime)).toEqual([]);
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("preserves unrelated and cross-session authority during zero-credential cleanup", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-zero-credential-ownership-test",
			options: { session: { preserveSessionInDatabase: true } },
		});
		const target = await issuePasswordSession(runtime);
		const survivor = await issuePasswordSession(runtime);
		const targetHandleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${target.id}`),
		)!;
		const survivorHandleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${survivor.id}`),
		)!;
		const targetCredentialKey = (
			JSON.parse(store.get(targetHandleKey)!) as { credentialKey: string }
		).credentialKey;
		const survivorCredentialKey = (
			JSON.parse(store.get(survivorHandleKey)!) as { credentialKey: string }
		).credentialKey;
		const expiredTargetCredentialKey =
			"clearance:managed-delete-zero-credential-ownership-test:session-credential:expired-target";
		store.set(expiredTargetCredentialKey, store.get(targetCredentialKey)!);
		const survivorEnvelope = store.get(survivorCredentialKey)!;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		const survivorEntry = (
			JSON.parse(store.get(indexKey)!) as Array<{
				sessionId: string;
				credentialKey: string;
				expiresAt: number;
			}>
		).find((entry) => entry.sessionId === survivor.id)!;
		const unrelated = {
			sessionId: "unrelated-session",
			credentialKey: "unrelated-credential",
			expiresAt: Date.now() + 60_000,
		};
		await runtime.context.adapter.deleteMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: target.id }],
		});
		store.set(
			targetHandleKey,
			JSON.stringify({ credentialKey: survivorCredentialKey }),
		);
		store.set(
			indexKey,
			JSON.stringify([
				{
					sessionId: target.id,
					credentialKey: targetCredentialKey,
					expiresAt: target.expiresAt.getTime(),
				},
				{
					sessionId: target.id,
					credentialKey: survivorCredentialKey,
					expiresAt: target.expiresAt.getTime(),
				},
				{
					sessionId: target.id,
					credentialKey: expiredTargetCredentialKey,
					expiresAt: Date.now() - 1,
				},
				unrelated,
				survivorEntry,
			]),
		);

		await runtime.context.internalAdapter.deleteSessionById(target.id);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(2);
		expect(store.has(targetCredentialKey)).toBe(false);
		expect(store.has(expiredTargetCredentialKey)).toBe(false);
		expect(store.get(survivorCredentialKey)).toBe(survivorEnvelope);
		expect(store.has(targetHandleKey)).toBe(false);
		expect(JSON.parse(store.get(indexKey)!)).toEqual([
			unrelated,
			survivorEntry,
		]);
	});

	it("deletes legacy bearer authority even when session preservation is configured", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-legacy-preserve-test",
			credentialAuthority: "legacy-v1",
			options: { session: { preserveSessionInDatabase: true } },
		});
		const session = await issuePasswordSession(runtime);

		await runtime.context.internalAdapter.deleteSession(session.token);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect(store).toEqual(new Map());
	});

	it("cleans secondary authority without mutating DB on a non-active managed token read", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-replay-cleanup-test",
		});
		const session = await issuePasswordSession(runtime);
		await runtime.context.internalAdapter.rotateSessionCredential(
			session.token,
			generateCredentialOperationKey(),
		);
		const root = (await credentialRows(runtime))[0]!;
		await runtime.context.adapter.update({
			model: "sessionCredential",
			where: [{ field: "id", value: String(root.id) }],
			update: { recoveryExpiresAt: new Date(Date.now() - 1_000) },
		});
		const stableSessions = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));

		await expect(
			runtime.context.internalAdapter.findSession(session.token),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stableSessions);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		expect(store).toEqual(new Map());
	});

	it("cleans an exact administrative-ID orphan without a DB target", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-delete-orphan-id-test",
		});
		const orphanId = "orphan-session-id";
		const envelopeKey =
			"clearance:managed-delete-orphan-id-test:session-credential:orphan";
		const handleKey =
			`clearance:managed-delete-orphan-id-test:session-handle:${orphanId}`;
		store.set(envelopeKey, JSON.stringify({ session: { id: orphanId } }));
		store.set(handleKey, JSON.stringify({ credentialKey: envelopeKey }));

		await runtime.context.internalAdapter.deleteSessionById(orphanId);
		expect(store.has(envelopeKey)).toBe(false);
		expect(store.has(handleKey)).toBe(false);
	});
});

describe("managed bulk session authoritative revocation", () => {
	it("atomically deletes mixed modern histories and canonically cleans every captured authority", async () => {
		const namespace = "managed-bulk-mixed-test";
		const { runtime, store } = await setupManagedDeletionRuntime({ namespace });
		const rotatedSession = await issuePasswordSession(runtime);
		await runtime.context.internalAdapter.rotateSessionCredential(
			rotatedSession.token,
			generateCredentialOperationKey(),
		);
		const plainSession = await issuePasswordSession(runtime);
		const credentials = await credentialRows(runtime);
		const expectedCredentialKeys = credentials.map(
			(credential) =>
				`clearance:${namespace}:session-credential:${String(credential.secretDigest)}`,
		);
		for (const credential of credentials) {
			store.set(
				`clearance:${namespace}:session-credential:${String(credential.secretDigest)}`,
				JSON.stringify({ session: { id: credential.sessionId } }),
			);
		}
		const rotatedHandleKey = `clearance:${namespace}:session-handle:${rotatedSession.id}`;
		const plainHandleKey = `clearance:${namespace}:session-handle:${plainSession.id}`;
		store.delete(plainHandleKey);
		const malformedEnvelopeKey = `clearance:${namespace}:session-credential:malformed`;
		const crossEnvelopeKey = `clearance:${namespace}:session-credential:cross`;
		store.set(malformedEnvelopeKey, "not-json");
		store.set(
			crossEnvelopeKey,
			JSON.stringify({ session: { id: "other-session" } }),
		);
		store.set(
			rotatedHandleKey,
			JSON.stringify({ credentialKey: crossEnvelopeKey }),
		);
		const indexKey = `clearance:${namespace}:active-sessions:${runtime.user.id}`;
		const unrelated = {
			sessionId: "future-session",
			credentialKey: "future-credential",
			expiresAt: Date.now() + 120_000,
		};
		store.set(
			indexKey,
			JSON.stringify([
				...expectedCredentialKeys.map((credentialKey, index) => ({
					sessionId: index < 2 ? rotatedSession.id : plainSession.id,
					credentialKey,
					expiresAt: Date.now() + 60_000,
				})),
				{
					sessionId: rotatedSession.id,
					credentialKey: expectedCredentialKeys[0],
					expiresAt: Date.now() - 1,
				},
				{
					sessionId: rotatedSession.id,
					credentialKey: malformedEnvelopeKey,
					expiresAt: Date.now() + 60_000,
				},
				{ broken: true },
				unrelated,
			]),
		);

		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);

		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		const revoked = await credentialRows(runtime);
		expect(revoked).toHaveLength(credentials.length);
		expect(
			revoked.every(
				(credential) =>
					credential.status === "revoked" &&
					credential.sessionId === null &&
					credential.rotationNonceDigest === null &&
					credential.recoverySecretCiphertext === null &&
					credential.recoveryExpiresAt === null,
			),
		).toBe(true);
		for (const credentialKey of expectedCredentialKeys) {
			expect(store.has(credentialKey)).toBe(false);
		}
		expect(store.has(rotatedHandleKey)).toBe(false);
		expect(store.has(plainHandleKey)).toBe(false);
		expect(store.get(malformedEnvelopeKey)).toBe("not-json");
		expect(store.has(crossEnvelopeKey)).toBe(true);
		expect(JSON.parse(store.get(indexKey)!)).toEqual([unrelated]);
		await expect(
			runtime.context.internalAdapter.findSession(plainSession.token),
		).resolves.toBeNull();
	});

	it("preserves every modern row while revoking mixed and zero-credential sessions without delete hooks", async () => {
		const before = vi.fn(async () => {});
		const after = vi.fn(async () => {});
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-bulk-preserve-test",
			options: {
				session: { preserveSessionInDatabase: true },
				databaseHooks: { session: { delete: { before, after } } },
			},
		});
		const credentialSession = await issuePasswordSession(runtime);
		const zeroCredentialSession = await issuePasswordSession(runtime);
		const credentialHandleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${credentialSession.id}`),
		)!;
		const zeroCredentialHandleKey = [...store.keys()].find((key) =>
			key.endsWith(`:session-handle:${zeroCredentialSession.id}`),
		)!;
		const zeroCredentialKey = (
			JSON.parse(store.get(zeroCredentialHandleKey)!) as { credentialKey: string }
		).credentialKey;
		const indexKey = [...store.keys()].find((key) =>
			key.endsWith(`:active-sessions:${runtime.user.id}`),
		)!;
		await runtime.context.adapter.updateMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: credentialSession.id }],
			update: {
				rotationNonceDigest: "pending",
				recoverySecretCiphertext: "ciphertext",
				recoveryExpiresAt: new Date(Date.now() + 60_000),
			},
		});
		await runtime.context.adapter.deleteMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: zeroCredentialSession.id }],
		});
		store.delete(zeroCredentialHandleKey);
		store.set(
			credentialHandleKey,
			JSON.stringify({ credentialKey: zeroCredentialKey }),
		);
		store.set(
			indexKey,
			JSON.stringify(
				(
					JSON.parse(store.get(indexKey)!) as Array<{ sessionId: string }>
				).filter((entry) => entry.sessionId !== zeroCredentialSession.id),
			),
		);

		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);

		expect(await runtime.context.adapter.count({ model: "session" })).toBe(2);
		expect(await credentialRows(runtime)).toEqual([
			expect.objectContaining({
				sessionId: credentialSession.id,
				status: "revoked",
				rotationNonceDigest: null,
				recoverySecretCiphertext: null,
				recoveryExpiresAt: null,
			}),
		]);
		expect(store).toEqual(new Map());
		expect(before).not.toHaveBeenCalled();
		expect(after).not.toHaveBeenCalled();
	});

	it.each(["zero", "partial"] as const)(
		"rolls back preserve mode when the adapter reports a %s credential update",
		async (mode) => {
			const { runtime, store, secondarySet, secondaryDelete } =
				await setupManagedDeletionRuntime({
					namespace: `managed-bulk-preserve-${mode}-update-test`,
					options: { session: { preserveSessionInDatabase: true } },
				});
			const session = await issuePasswordSession(runtime);
			await runtime.context.internalAdapter.rotateSessionCredential(
				session.token,
				generateCredentialOperationKey(),
			);
			const stableSessions = structuredClone(
				await authorityRows(runtime.context),
			);
			const stableCredentials = structuredClone(await credentialRows(runtime));
			const stableStore = new Map(store);
			secondarySet.mockClear();
			secondaryDelete.mockClear();
			const originalTransaction = runtime.context.adapter.transaction.bind(
				runtime.context.adapter,
			);
			let armed = true;
			vi.spyOn(runtime.context.adapter, "transaction").mockImplementation(
				async (callback) =>
					originalTransaction(async (transactionAdapter) => {
						if (!armed) return callback(transactionAdapter);
						armed = false;
						const originalUpdateMany =
							transactionAdapter.updateMany.bind(transactionAdapter);
						transactionAdapter.updateMany = (async (input) => {
							if (input.model !== "sessionCredential") {
								return originalUpdateMany(input);
							}
							if (mode === "zero") return 0;
							return originalUpdateMany({
								...input,
								where: [
									{
										field: "id",
										value: String(stableCredentials[0]!.id),
									},
								],
							});
						}) as typeof transactionAdapter.updateMany;
						return callback(transactionAdapter);
					}),
			);

			await expect(
				runtime.context.internalAdapter.deleteUserSessions(runtime.user.id),
			).rejects.toThrow("Bulk session credential revocation count mismatch");
			expect(await authorityRows(runtime.context)).toEqual(stableSessions);
			expect(await credentialRows(runtime)).toEqual(stableCredentials);
			expect(store).toEqual(stableStore);
			expect(secondarySet).not.toHaveBeenCalled();
			expect(secondaryDelete).not.toHaveBeenCalled();
		},
	);

	it("deletes legacy rows despite preserveSessionInDatabase", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-bulk-legacy-preserve-test",
			credentialAuthority: "legacy-v1",
			options: { session: { preserveSessionInDatabase: true } },
		});
		await issuePasswordSession(runtime);
		await issuePasswordSession(runtime);
		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect(store).toEqual(new Map());
	});

	it.each(["veto", "before_throw", "rollback_after"] as const)(
		"rolls back the entire bulk group for %s hooks",
		async (mode) => {
			const before = vi.fn(async () => {
				if (mode === "veto") return false;
				if (mode === "before_throw") throw new Error("bulk before failed");
			});
			const after = vi.fn(async () => {
				if (mode === "rollback_after") throw new Error("bulk after failed");
			});
			const { runtime, store, secondarySet, secondaryDelete } =
				await setupManagedDeletionRuntime({
					namespace: `managed-bulk-${mode}-test`,
					options: {
						databaseHookFailureMode:
							mode === "rollback_after" ? "rollback" : undefined,
						databaseHooks: { session: { delete: { before, after } } },
					},
				});
			await issuePasswordSession(runtime);
			await issuePasswordSession(runtime);
			const stableSessions = structuredClone(await authorityRows(runtime.context));
			const stableCredentials = structuredClone(await credentialRows(runtime));
			const stableStore = new Map(store);
			secondarySet.mockClear();
			secondaryDelete.mockClear();

			const deletion = runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);
			if (mode === "veto") await expect(deletion).resolves.toBeUndefined();
			else {
				await expect(deletion).rejects.toThrow(
					mode === "before_throw" ? "bulk before failed" : "bulk after failed",
				);
			}
			expect(await authorityRows(runtime.context)).toEqual(stableSessions);
			expect(await credentialRows(runtime)).toEqual(stableCredentials);
			expect(store).toEqual(stableStore);
			expect(secondarySet).not.toHaveBeenCalled();
			expect(secondaryDelete).not.toHaveBeenCalled();
			expect(before).toHaveBeenCalledTimes(
				mode === "rollback_after" ? 2 : 1,
			);
			expect(after).toHaveBeenCalledTimes(mode === "rollback_after" ? 1 : 0);
		},
	);

	it("runs observe after hooks before the single cleanup pass", async () => {
		const order: string[] = [];
		const after = vi.fn(async (session: { id: string }) => {
			order.push(`after:${session.id}`);
			throw new Error("observed bulk after");
		});
		const { runtime, secondaryDelete } = await setupManagedDeletionRuntime({
			namespace: "managed-bulk-observe-test",
			options: { databaseHooks: { session: { delete: { after } } } },
			delete: async (key) => {
				order.push(`cleanup:${key}`);
			},
		});
		await issuePasswordSession(runtime);
		await issuePasswordSession(runtime);
		order.length = 0;
		secondaryDelete.mockClear();

		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);

		expect(after).toHaveBeenCalledTimes(2);
		expect(order.slice(0, 2).every((entry) => entry.startsWith("after:"))).toBe(true);
		expect(order.slice(2).some((entry) => entry.startsWith("cleanup:"))).toBe(true);
	});

	it("fails closed when a before hook changes the locked target set", async () => {
		let runtimeRef: ManagedRuntime | null = null;
		let driftSessionId = "";
		let changed = false;
		const after = vi.fn(async () => {});
		const before = vi.fn(async () => {
			if (changed) return;
			changed = true;
			await (
				await getCurrentAdapter(runtimeRef!.context.adapter)
			).delete({
				model: "session",
				where: [{ field: "id", value: driftSessionId }],
			});
		});
		const setup = await setupManagedDeletionRuntime({
			namespace: "managed-bulk-target-drift-test",
			options: { databaseHooks: { session: { delete: { before, after } } } },
		});
		runtimeRef = setup.runtime;
		await issuePasswordSession(setup.runtime);
		const driftSession = await issuePasswordSession(setup.runtime);
		driftSessionId = driftSession.id;
		const stableSessions = structuredClone(
			await authorityRows(setup.runtime.context),
		);
		const stableCredentials = structuredClone(await credentialRows(setup.runtime));
		const stableStore = new Map(setup.store);
		setup.secondarySet.mockClear();
		setup.secondaryDelete.mockClear();

		await expect(
			setup.runtime.context.internalAdapter.deleteUserSessions(
				setup.runtime.user.id,
			),
		).rejects.toThrow("Locked bulk session revocation target set changed");
		expect(await authorityRows(setup.runtime.context)).toEqual(stableSessions);
		expect(await credentialRows(setup.runtime)).toEqual(stableCredentials);
		expect(setup.store).toEqual(stableStore);
		expect(after).not.toHaveBeenCalled();
		expect(setup.secondarySet).not.toHaveBeenCalled();
		expect(setup.secondaryDelete).not.toHaveBeenCalled();
	});

	it("defers the complete cleanup through outer rollback", async () => {
		const { runtime, store, secondarySet, secondaryDelete } =
			await setupManagedDeletionRuntime({
				namespace: "managed-bulk-outer-rollback-test",
			});
		await issuePasswordSession(runtime);
		await issuePasswordSession(runtime);
		const stableSessions = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));
		const stableStore = new Map(store);
		secondarySet.mockClear();
		secondaryDelete.mockClear();

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);
				throw new Error("bulk outer rollback");
			}),
		).rejects.toThrow("bulk outer rollback");
		expect(await authorityRows(runtime.context)).toEqual(stableSessions);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("surfaces postcommit cleanup failure while retaining the committed group delete", async () => {
		const { runtime } = await setupManagedDeletionRuntime({
			namespace: "managed-bulk-cleanup-failure-test",
			delete: async () => {
				throw new Error("bulk cleanup failed");
			},
		});
		await issuePasswordSession(runtime);
		await issuePasswordSession(runtime);
		await expect(
			runtime.context.internalAdapter.deleteUserSessions(runtime.user.id),
		).rejects.toBeInstanceOf(AfterTransactionHookError);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect(
			(await credentialRows(runtime)).every(
				(credential) => credential.status === "revoked" && credential.sessionId === null,
			),
		).toBe(true);
	});

	it("is idempotent for an empty user", async () => {
		const { runtime, secondarySet, secondaryDelete } =
			await setupManagedDeletionRuntime({
				namespace: "managed-bulk-empty-test",
			});
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);
		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("serializes a concurrent new session after revocation owns the user lock", async () => {
		const cleanupEntered = deferred();
		const cleanupGate = deferred();
		let blockCleanup = false;
		let storeRef: Map<string, string> | null = null;
		const setup = await setupManagedDeletionRuntime({
			namespace: "managed-bulk-revoke-before-create-test",
			delete: async (key) => {
				if (blockCleanup) {
					blockCleanup = false;
					cleanupEntered.resolve();
					await cleanupGate.promise;
				}
				storeRef!.delete(key);
			},
		});
		const { runtime, store } = setup;
		storeRef = store;
		const revoked = await issuePasswordSession(runtime);
		blockCleanup = true;
		const deletion = runtime.context.internalAdapter.deleteUserSessions(
			runtime.user.id,
		);
		await cleanupEntered.promise;
		const creation = issuePasswordSession(runtime);
		cleanupGate.resolve();
		await deletion;
		const created = await creation;
		const rows = await authorityRows(runtime.context);
		expect(rows.map((row) => row.id)).toEqual([created.id]);
		expect(
			[...store.values()].some((value) => value.includes(revoked.id)),
		).toBe(false);
		expect(
			[...store.values()].some((value) => value.includes(created.id)),
		).toBe(true);
	});

	it("captures a concurrent creation that owns the user lock before revocation", async () => {
		const creationEntered = deferred();
		const creationGate = deferred();
		let blockCreation = false;
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-bulk-create-lock-first-test",
			reader: async (input) => {
				if (blockCreation) {
					blockCreation = false;
					creationEntered.resolve();
					await creationGate.promise;
				}
				return policyResult(input);
			},
		});
		const original = await issuePasswordSession(runtime);
		blockCreation = true;
		const creation = issuePasswordSession(runtime);
		await creationEntered.promise;
		const deletion = runtime.context.internalAdapter.deleteUserSessions(
			runtime.user.id,
		);
		creationGate.resolve();
		const creationResult = await creation.then(
			(value) => ({ kind: "created" as const, value }),
			(error: unknown) => ({ kind: "failed" as const, error }),
		);
		await deletion;
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		expect(
			[...store.values()].some((value) => value.includes(original.id)),
		).toBe(false);
		if (creationResult.kind === "created") {
			expect(
				[...store.values()].some((value) =>
					value.includes(creationResult.value.id),
				),
			).toBe(false);
		} else {
			expect(creationResult.error).toBeInstanceOf(AfterTransactionHookError);
		}
		const survivor = await issuePasswordSession(runtime);
		expect((await authorityRows(runtime.context)).map((row) => row.id)).toEqual([
			survivor.id,
		]);
		expect(
			[...store.values()].some((value) => value.includes(survivor.id)),
		).toBe(true);
	});

	it("prevents pending captured publication from resurrecting authority and keeps the post-revocation successor", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-bulk-create-before-revoke-test",
		});
		let captured: Awaited<ReturnType<typeof issuePasswordSession>> | null = null;
		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				captured = await issuePasswordSession(runtime);
				await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);
			}),
		).rejects.toBeInstanceOf(ManagedSessionIssuanceError);
		const survivor = await issuePasswordSession(runtime);
		const rows = await authorityRows(runtime.context);
		expect(rows.map((row) => row.id)).toEqual([survivor.id]);
		expect(
			[...store.values()].some((value) => value.includes(captured!.id)),
		).toBe(false);
		expect(
			[...store.values()].some((value) => value.includes(survivor.id)),
		).toBe(true);
	});
});

describe("database-backed bulk deletion without authentication policy", () => {
	it.each([false, true])(
		"keeps compatibility with preserveSessionInDatabase=%s and rewrites the active index once",
		async (preserveSessionInDatabase) => {
			const namespace = `compatibility-bulk-preserve-${preserveSessionInDatabase}`;
			const runtime = await setupDatabaseBackedCompatibilityRuntime({
				namespace,
				options: {
					session: {
						storeSessionInDatabase: true,
						preserveSessionInDatabase,
					},
				},
			});
			await runtime.context.internalAdapter.createSession(runtime.user.id);
			await runtime.context.internalAdapter.createSession(runtime.user.id);
			const indexKey = `clearance:${namespace}:active-sessions:${runtime.user.id}`;
			const unrelated = {
				sessionId: "compatibility-future-session",
				credentialKey: "compatibility-future-credential",
				expiresAt: Date.now() + 120_000,
			};
			runtime.store.set(
				indexKey,
				JSON.stringify([
					...(JSON.parse(runtime.store.get(indexKey)!) as unknown[]),
					unrelated,
				]),
			);
			runtime.secondarySet.mockClear();
			runtime.secondaryDelete.mockClear();

			await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);

			expect(
				await runtime.context.adapter.count({ model: "session" }),
			).toBe(preserveSessionInDatabase ? 2 : 0);
			const credentials = await runtime.context.adapter.findMany<
				Record<string, unknown>
			>({ model: "sessionCredential" });
			expect(credentials).toHaveLength(2);
			expect(
				credentials.every(
					(credential) =>
						credential.status === "revoked" &&
						(preserveSessionInDatabase
							? typeof credential.sessionId === "string"
							: credential.sessionId === null),
				),
			).toBe(true);
			expect(JSON.parse(runtime.store.get(indexKey)!)).toEqual([unrelated]);
			const indexWrites = runtime.secondarySet.mock.calls.filter(
				([key]) => key === indexKey,
			);
			expect(indexWrites).toHaveLength(1);
		},
	);

	it("runs every compatibility delete hook before mutation and every observe hook before cleanup", async () => {
		const order: string[] = [];
		const runtime = await setupDatabaseBackedCompatibilityRuntime({
			namespace: "compatibility-bulk-hook-order",
			options: {
				session: { storeSessionInDatabase: true },
				databaseHooks: {
					session: {
						delete: {
							before: async (session) => {
								order.push(`before:${session.id}`);
							},
							after: async (session) => {
								order.push(`after:${session.id}`);
							},
						},
					},
				},
			},
		});
		await runtime.context.internalAdapter.createSession(runtime.user.id);
		await runtime.context.internalAdapter.createSession(runtime.user.id);
		const originalDelete = runtime.secondaryDelete.getMockImplementation()!;
		runtime.secondaryDelete.mockImplementation(async (key) => {
			order.push(`cleanup:${key}`);
			await originalDelete(key);
		});

		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);

		const firstAfter = order.findIndex((entry) => entry.startsWith("after:"));
		const firstCleanup = order.findIndex((entry) => entry.startsWith("cleanup:"));
		expect(order.slice(0, firstAfter)).toHaveLength(2);
		expect(order.slice(0, firstAfter).every((entry) => entry.startsWith("before:"))).toBe(
			true,
		);
		expect(order.slice(firstAfter, firstCleanup)).toHaveLength(2);
		expect(
			order
				.slice(firstAfter, firstCleanup)
				.every((entry) => entry.startsWith("after:")),
		).toBe(true);
		expect(firstCleanup).toBeGreaterThan(firstAfter);
	});

	it("honors a compatibility delete-hook veto without DB or secondary mutation", async () => {
		const after = vi.fn(async () => {});
		const before = vi.fn(async () => false);
		const runtime = await setupDatabaseBackedCompatibilityRuntime({
			namespace: "compatibility-bulk-hook-veto",
			options: {
				session: { storeSessionInDatabase: true },
				databaseHooks: { session: { delete: { before, after } } },
			},
		});
		await runtime.context.internalAdapter.createSession(runtime.user.id);
		await runtime.context.internalAdapter.createSession(runtime.user.id);
		const stableSessions = structuredClone(
			await runtime.context.adapter.findMany({ model: "session" }),
		);
		const stableCredentials = structuredClone(
			await runtime.context.adapter.findMany({ model: "sessionCredential" }),
		);
		const stableStore = new Map(runtime.store);
		runtime.secondarySet.mockClear();
		runtime.secondaryDelete.mockClear();

		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);

		expect(await runtime.context.adapter.findMany({ model: "session" })).toEqual(
			stableSessions,
		);
		expect(
			await runtime.context.adapter.findMany({ model: "sessionCredential" }),
		).toEqual(stableCredentials);
		expect(runtime.store).toEqual(stableStore);
		expect(before).toHaveBeenCalledTimes(1);
		expect(after).not.toHaveBeenCalled();
		expect(runtime.secondarySet).not.toHaveBeenCalled();
		expect(runtime.secondaryDelete).not.toHaveBeenCalled();
	});

	it("preserves secondary-authoritative compatibility deletion", async () => {
		const runtime = await setupDatabaseBackedCompatibilityRuntime({
			namespace: "compatibility-bulk-secondary-only",
			options: { session: { storeSessionInDatabase: false } },
		});
		await runtime.context.internalAdapter.createSession(runtime.user.id);
		await runtime.context.internalAdapter.createSession(runtime.user.id);
		expect(runtime.store.size).toBeGreaterThan(0);

		await runtime.context.internalAdapter.deleteUserSessions(runtime.user.id);

		expect([...runtime.store.keys()]).toEqual([
			"clearance:compatibility-bulk-secondary-only:session-storage-epoch",
		]);
	});
});

describe("managed complete-topology session reads", () => {
	it("rejects a real stale-policy token read, cleans owner cache, and leaves DB unchanged", async () => {
		let revision = "7";
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-read-stale-policy-token",
			reader: (input) => policyResult(input, { revision }),
		});
		const session = await issuePasswordSession(runtime);
		const stableSessions = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));
		revision = "8";

		await expect(
			runtime.context.internalAdapter.findSession(session.token),
		).resolves.toBeNull();
		expect(await authorityRows(runtime.context)).toEqual(stableSessions);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		expect(store).toEqual(new Map());
	});

	it.each(["token", "id"] as const)(
		"rejects and owner-cleans duplicate active authority by %s without DB mutation",
		async (access) => {
			const { runtime, store } = await setupManagedDeletionRuntime({
				namespace: `managed-read-duplicate-${access}`,
			});
			const session = await issuePasswordSession(runtime);
			const credential = (await credentialRows(runtime))[0]!;
			await runtime.context.adapter.create({
				model: "sessionCredential",
				forceAllowId: true,
				data: {
					...credential,
					id: `${credential.id}-duplicate`,
					selector: `${credential.selector}-duplicate`,
					secretDigest: await digestSessionRefreshSecret(
						`duplicate-${access}`,
					),
				},
			});
			const stableSessions = structuredClone(await authorityRows(runtime.context));
			const stableCredentials = structuredClone(await credentialRows(runtime));

			const result =
				access === "token"
					? runtime.context.internalAdapter.findSession(session.token)
					: runtime.context.internalAdapter.findSessionById(session.id);
			await expect(result).resolves.toBeNull();
			expect(await authorityRows(runtime.context)).toEqual(stableSessions);
			expect(await credentialRows(runtime)).toEqual(stableCredentials);
			expect(store).toEqual(new Map());
		},
	);

	it.each([
		"disconnected",
		"expiry_mismatch",
		"malformed_digest",
		"malformed_selector",
	] as const)(
		"rejects %s topology and cleans every owned candidate",
		async (mode) => {
			const namespace = `managed-read-${mode}`;
			const { runtime, store } = await setupManagedDeletionRuntime({ namespace });
			const session = await issuePasswordSession(runtime);
			const credential = (await credentialRows(runtime))[0]!;
			if (mode === "disconnected") {
				await runtime.context.adapter.create({
					model: "sessionCredential",
					forceAllowId: true,
					data: {
						...credential,
						id: `${credential.id}-disconnected`,
						selector: `${credential.selector}-disconnected`,
						secretDigest: await digestSessionRefreshSecret("disconnected"),
						status: "consumed",
						familyId: `${credential.familyId}-disconnected`,
						consumedAt: new Date(),
					},
				});
			} else if (mode === "expiry_mismatch") {
				await runtime.context.adapter.update({
					model: "sessionCredential",
					where: [{ field: "id", value: String(credential.id) }],
					update: { expiresAt: new Date(session.expiresAt.getTime() - 1_000) },
				});
			} else if (mode === "malformed_digest") {
				const handleKey = [...store.keys()].find((key) =>
					key.endsWith(`:session-handle:${session.id}`),
				)!;
				const oldKey = (
					JSON.parse(store.get(handleKey)!) as { credentialKey: string }
				).credentialKey;
				const malformedKey = `clearance:${namespace}:session-credential:malformed`;
				store.set(malformedKey, store.get(oldKey)!);
				store.delete(oldKey);
				store.delete(handleKey);
				const indexKey = `clearance:${namespace}:active-sessions:${runtime.user.id}`;
				store.set(
					indexKey,
					JSON.stringify([
						{
							sessionId: session.id,
							credentialKey: malformedKey,
							expiresAt: session.expiresAt.getTime(),
						},
					]),
				);
				await runtime.context.adapter.update({
					model: "sessionCredential",
					where: [{ field: "id", value: String(credential.id) }],
					update: { secretDigest: "malformed" },
				});
			} else {
				await runtime.context.adapter.update({
					model: "sessionCredential",
					where: [{ field: "id", value: String(credential.id) }],
					update: { selector: "malformed selector" },
				});
			}
			const stableSessions = structuredClone(await authorityRows(runtime.context));
			const stableCredentials = structuredClone(await credentialRows(runtime));

			await expect(
				runtime.context.internalAdapter.findSessionById(session.id),
			).resolves.toBeNull();
			expect(await authorityRows(runtime.context)).toEqual(stableSessions);
			expect(await credentialRows(runtime)).toEqual(stableCredentials);
			expect(store).toEqual(new Map());
		},
	);

	it("defers invalid-read cleanup through an outer rollback", async () => {
		const { runtime, store, secondarySet, secondaryDelete } =
			await setupManagedDeletionRuntime({
				namespace: "managed-read-outer-rollback",
			});
		const session = await issuePasswordSession(runtime);
		const credential = (await credentialRows(runtime))[0]!;
		await runtime.context.adapter.create({
			model: "sessionCredential",
			forceAllowId: true,
			data: {
				...credential,
				id: `${credential.id}-duplicate`,
				selector: `${credential.selector}-duplicate`,
				secretDigest: await digestSessionRefreshSecret("rollback-duplicate"),
			},
		});
		const stableStore = new Map(store);
		secondarySet.mockClear();
		secondaryDelete.mockClear();

		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await expect(
					runtime.context.internalAdapter.findSessionById(session.id),
				).resolves.toBeNull();
				throw new Error("invalid read rollback");
			}),
		).rejects.toThrow("invalid read rollback");
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it.each(["token", "id"] as const)(
		"owner-cleans an orphaned managed %s read",
		async (access) => {
			const { runtime, store } = await setupManagedDeletionRuntime({
				namespace: `managed-read-orphan-${access}`,
			});
			const session = await issuePasswordSession(runtime);
			await runtime.context.adapter.delete({
				model: "session",
				where: [{ field: "id", value: session.id }],
			});
			expect(store.size).toBeGreaterThan(0);
			const result =
				access === "token"
					? runtime.context.internalAdapter.findSession(session.token)
					: runtime.context.internalAdapter.findSessionById(session.id);
			await expect(result).resolves.toBeNull();
			const remainingSessionKeys = [...store.keys()].filter(
				(key) => !key.includes(":active-sessions:"),
			);
			expect(remainingSessionKeys).toEqual(
				access === "token"
					? [`clearance:managed-read-orphan-token:session-handle:${session.id}`]
					: [],
			);
		},
	);

	it("never derives handle or index cleanup authority from a poisoned orphan envelope", async () => {
		const namespace = "managed-read-poisoned-orphan";
		const { runtime, store } = await setupManagedDeletionRuntime({ namespace });
		const orphan = await issuePasswordSession(runtime);
		const live = await issuePasswordSession(runtime);
		const orphanHandleKey = `clearance:${namespace}:session-handle:${orphan.id}`;
		const liveHandleKey = `clearance:${namespace}:session-handle:${live.id}`;
		const orphanCredentialKey = (
			JSON.parse(store.get(orphanHandleKey)!) as { credentialKey: string }
		).credentialKey;
		const liveCredentialKey = (
			JSON.parse(store.get(liveHandleKey)!) as { credentialKey: string }
		).credentialKey;
		const indexKey = `clearance:${namespace}:active-sessions:${runtime.user.id}`;
		await runtime.context.adapter.delete({
			model: "session",
			where: [{ field: "id", value: orphan.id }],
		});
		await runtime.context.adapter.updateMany({
			model: "sessionCredential",
			where: [{ field: "sessionId", value: null }],
			update: { status: "revoked", revokedAt: new Date() },
		});
		store.set(
			orphanCredentialKey,
			JSON.stringify({
				session: { id: live.id, userId: runtime.user.id },
				user: { id: runtime.user.id },
			}),
		);
		const stableLiveEnvelope = store.get(liveCredentialKey)!;
		const stableLiveHandle = store.get(liveHandleKey)!;
		const stableIndex = store.get(indexKey)!;
		const stableSessions = structuredClone(await authorityRows(runtime.context));
		const stableCredentials = structuredClone(await credentialRows(runtime));

		await expect(
			runtime.context.internalAdapter.findSession(orphan.token),
		).resolves.toBeNull();
		expect(store.has(orphanCredentialKey)).toBe(false);
		expect(store.get(liveCredentialKey)).toBe(stableLiveEnvelope);
		expect(store.get(liveHandleKey)).toBe(stableLiveHandle);
		expect(store.get(indexKey)).toBe(stableIndex);
		expect(await authorityRows(runtime.context)).toEqual(stableSessions);
		expect(await credentialRows(runtime)).toEqual(stableCredentials);
		await expect(
			runtime.context.internalAdapter.findSession(live.token),
		).resolves.not.toBeNull();
	});

	it.each(["selector", "digest"] as const)(
		"fails closed when a corrupted adapter returns duplicate %s candidates",
		async (mode) => {
			const { runtime, store } = await setupManagedDeletionRuntime({
				namespace: `managed-read-duplicate-${mode}-lookup`,
			});
			const session = await issuePasswordSession(runtime);
			const stableStore = new Map(store);
			const stableSessions = structuredClone(await authorityRows(runtime.context));
			const stableCredentials = structuredClone(await credentialRows(runtime));
			const originalTransaction = runtime.context.adapter.transaction.bind(
				runtime.context.adapter,
			);
			vi.spyOn(runtime.context.adapter, "transaction").mockImplementation(
				async (callback) =>
					originalTransaction(async (transactionAdapter) => {
						const originalFindMany =
							transactionAdapter.findMany.bind(transactionAdapter);
						transactionAdapter.findMany = (async (input) => {
							const rows = await originalFindMany(input);
							const lookupField = input.where?.[0]?.field;
							if (
								input.model === "sessionCredential" &&
								lookupField ===
									(mode === "selector" ? "selector" : "secretDigest") &&
								rows.length === 1
							) {
								const row = rows[0] as Record<string, unknown>;
								return [
									...rows,
									{
										...row,
										id: `${String(row.id)}-corrupt`,
										...(mode === "selector"
											? {
												secretDigest:
													await digestSessionRefreshSecret("other-digest"),
											  }
											: { selector: "A".repeat(32) }),
									},
								] as never;
							}
							return rows;
						}) as typeof transactionAdapter.findMany;
						return callback(transactionAdapter);
					}),
			);

			await expect(
				runtime.context.internalAdapter.findSession(session.token),
			).resolves.toBeNull();
			expect(store).toEqual(stableStore);
			expect(await authorityRows(runtime.context)).toEqual(stableSessions);
			expect(await credentialRows(runtime)).toEqual(stableCredentials);
		},
	);

	it("preserves legacy and unmanaged successful reads", async () => {
		const legacy = await setupManagedDeletionRuntime({
			namespace: "managed-read-legacy",
			credentialAuthority: "legacy-v1",
		});
		const legacySession = await issuePasswordSession(legacy.runtime);
		await expect(
			legacy.runtime.context.internalAdapter.findSession(legacySession.token),
		).resolves.not.toBeNull();
		await expect(
			legacy.runtime.context.internalAdapter.findSessionById(legacySession.id),
		).resolves.not.toBeNull();

		const unmanaged = await setupDatabaseBackedCompatibilityRuntime({
			namespace: "managed-read-unmanaged",
			options: { session: { storeSessionInDatabase: false } },
		});
		const unmanagedSession =
			await unmanaged.context.internalAdapter.createSession(unmanaged.user.id);
		await expect(
			unmanaged.context.internalAdapter.findSession(unmanagedSession.token),
		).resolves.not.toBeNull();
	});
});

describe("managed session derivative authority", () => {
		it("requires an owning transaction and survives credential rotation for the same source session", async () => {
			const runtime = await setupManagedRuntime();
			const session = await issuePasswordSession(runtime);
			await expect(
				captureInternalSessionDerivativeAuthority(
					runtime.context.internalAdapter,
					{ purpose: "jwt", sourceSessionToken: session.token },
				),
			).rejects.toMatchObject({ reason: "authority_invalid" });

			const [fromToken, fromId] = await runWithTransaction(
				runtime.context.adapter,
				async () =>
					Promise.all([
						captureInternalSessionDerivativeAuthority(
							runtime.context.internalAdapter,
							{ purpose: "jwt", sourceSessionToken: session.token },
						),
						captureInternalSessionDerivativeAuthority(
							runtime.context.internalAdapter,
							{ purpose: "jwt", sourceSessionId: session.id },
						),
					]),
			);
			expect(fromToken).toBe(fromId);
			expect(fromToken).not.toContain(session.token);

			const read = () =>
				runWithTransaction(runtime.context.adapter, () =>
					validateInternalSessionDerivativeAuthority(
						runtime.context.internalAdapter,
						fromToken,
						{ purpose: "jwt", subjectId: runtime.user.id },
					),
				);
			await expect(read()).resolves.toMatchObject({
				sourceSessionId: session.id,
				sourceSubjectId: runtime.user.id,
			});
			await expect(
				runtime.context.internalAdapter.rotateSessionCredential(session.token),
			).resolves.toBeTruthy();
			await expect(read()).resolves.toMatchObject({ sourceSessionId: session.id });

			let releaseDetached!: () => void;
			const detachedRelease = new Promise<void>((resolve) => {
				releaseDetached = resolve;
			});
			let detachedCapture!: Promise<unknown>;
			let detachedValidation!: Promise<unknown>;
			let detachedState!: Promise<{
				active: boolean;
				adapter: object;
			}>;
			await runWithTransaction(runtime.context.adapter, async () => {
				detachedState = (async () => {
					await detachedRelease;
					return {
						active: await isTransactionActive(runtime.context.adapter),
						adapter: await getCurrentAdapter(runtime.context.adapter),
					};
				})();
				detachedCapture = (async () => {
					await detachedRelease;
					return captureInternalSessionDerivativeAuthority(
						runtime.context.internalAdapter,
						{ purpose: "jwt", sourceSessionId: session.id },
					);
				})();
				detachedValidation = (async () => {
					await detachedRelease;
					return validateInternalSessionDerivativeAuthority(
						runtime.context.internalAdapter,
						fromToken,
						{ purpose: "jwt", subjectId: runtime.user.id },
					);
				})();
			});
			releaseDetached();
			await expect(detachedState).resolves.toEqual({
				active: false,
				adapter: runtime.context.adapter,
			});
			await expect(
				Promise.allSettled([detachedCapture, detachedValidation]),
			).resolves.toEqual([
				{
					status: "rejected",
					reason: expect.objectContaining({ reason: "authority_invalid" }),
				},
				{
					status: "rejected",
					reason: expect.objectContaining({ reason: "authority_invalid" }),
				},
			]);
		});

		it("fails a captured derivative authority after live policy, expiry, and revocation changes", async () => {
			let revision = "7";
			const runtime = await setupManagedRuntime({
				reader: (input) => policyResult(input, { revision }),
			});
			const capture = async () => {
				const session = await issuePasswordSession(runtime);
				const binding = await runWithTransaction(
					runtime.context.adapter,
					() =>
						captureInternalSessionDerivativeAuthority(
							runtime.context.internalAdapter,
							{ purpose: "oidc", sourceSessionId: session.id },
						),
				);
				const validate = () =>
					runWithTransaction(runtime.context.adapter, () =>
						validateInternalSessionDerivativeAuthority(
							runtime.context.internalAdapter,
							binding,
							{ purpose: "oidc" },
						),
					);
				return { session, validate };
			};

			const policyChanged = await capture();
			revision = "8";
			await expect(policyChanged.validate()).rejects.toMatchObject({
				reason: "authority_stale",
			});
			revision = "7";

			const expired = await capture();
			await runtime.context.adapter.update({
				model: "session",
				where: [{ field: "id", value: expired.session.id }],
				update: { expiresAt: new Date(Date.now() - 1_000) },
			});
			await expect(expired.validate()).rejects.toMatchObject({
				reason: "authority_stale",
			});

			const revoked = await capture();
			await runtime.context.internalAdapter.deleteSession(revoked.session.token);
			await expect(revoked.validate()).rejects.toMatchObject({
				reason: "authority_stale",
			});
		});
});

describe("managed user session reconciliation", () => {
	it("publishes the committed DB user after updateUser and updateUserByEmail", async () => {
		const { runtime, store } = await setupManagedDeletionRuntime({
			namespace: "managed-user-refresh-commit",
		});
		const session = await issuePasswordSession(runtime);
		await runtime.context.internalAdapter.updateUser(runtime.user.id, {
			name: "First committed name",
		});
		await runtime.context.internalAdapter.updateUserByEmail(runtime.user.email, {
			name: "Final committed name",
		});
		const envelope = [...store.values()]
			.map((value) => safeJSONParse<{ session?: Session; user?: User }>(value))
			.find((value) => value?.session?.id === session.id)!;
		expect(envelope.user?.name).toBe("Final committed name");
		expect(
			await runtime.context.adapter.findOne({
				model: "user",
				where: [{ field: "id", value: runtime.user.id }],
			}),
		).toEqual(expect.objectContaining({ name: "Final committed name" }));
	});

	it("defers managed user reconciliation through outer rollback", async () => {
		const { runtime, store, secondarySet, secondaryDelete } =
			await setupManagedDeletionRuntime({
				namespace: "managed-user-refresh-rollback",
			});
		await issuePasswordSession(runtime);
		const stableStore = new Map(store);
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		await expect(
			runWithTransaction(runtime.context.adapter, async () => {
				await runtime.context.internalAdapter.updateUser(runtime.user.id, {
					name: "Rolled back name",
				});
				throw new Error("user refresh rollback");
			}),
		).rejects.toThrow("user refresh rollback");
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
	});

	it("cleans stale-policy and banned-user authority after committed updates", async () => {
		let revision = "7";
		const stale = await setupManagedDeletionRuntime({
			namespace: "managed-user-refresh-stale-policy",
			reader: (input) => policyResult(input, { revision }),
		});
		await issuePasswordSession(stale.runtime);
		revision = "8";
		await stale.runtime.context.internalAdapter.updateUser(stale.runtime.user.id, {
			name: "Policy changed",
		});
		expect(stale.store).toEqual(new Map());

		const banned = await setupManagedDeletionRuntime({
			namespace: "managed-user-refresh-banned",
			options: {
				user: {
					additionalFields: {
						banned: { type: "boolean", defaultValue: false },
					},
				},
			},
		});
		await issuePasswordSession(banned.runtime);
		await banned.runtime.context.internalAdapter.updateUser(banned.runtime.user.id, {
			banned: true,
		});
		expect(banned.store).toEqual(new Map());
	});

	it("cleans cached authority when an earlier observe hook deletes the updated user", async () => {
		let runtimeRef: ManagedRuntime | null = null;
		const setup = await setupManagedDeletionRuntime({
			namespace: "managed-user-refresh-deleted",
			options: {
				databaseHooks: {
					user: {
						update: {
							after: async (user) => {
								await runtimeRef!.context.adapter.delete({
									model: "user",
									where: [{ field: "id", value: user.id }],
								});
							},
						},
					},
				},
			},
		});
		runtimeRef = setup.runtime;
		await issuePasswordSession(setup.runtime);
		await setup.runtime.context.internalAdapter.updateUser(setup.runtime.user.id, {
			name: "Deleted by observe hook",
		});
		expect(
			await setup.runtime.context.adapter.findOne({
				model: "user",
				where: [{ field: "id", value: setup.runtime.user.id }],
			}),
		).toBeNull();
		expect(setup.store).toEqual(new Map());
	});

	it("propagates reader failure with zero secondary mutation after the DB commit", async () => {
		let readerFails = false;
		const { runtime, store, secondarySet, secondaryDelete } =
			await setupManagedDeletionRuntime({
				namespace: "managed-user-refresh-reader-failure",
				reader: (input) => {
					if (readerFails) throw new Error("refresh policy unavailable");
					return policyResult(input);
				},
			});
		await issuePasswordSession(runtime);
		const stableStore = new Map(store);
		secondarySet.mockClear();
		secondaryDelete.mockClear();
		readerFails = true;
		await expect(
			runtime.context.internalAdapter.updateUser(runtime.user.id, {
				name: "Committed despite reader outage",
			}),
		).rejects.toBeInstanceOf(AfterTransactionHookError);
		expect(store).toEqual(stableStore);
		expect(secondarySet).not.toHaveBeenCalled();
		expect(secondaryDelete).not.toHaveBeenCalled();
		expect(
			await runtime.context.adapter.findOne({
				model: "user",
				where: [{ field: "id", value: runtime.user.id }],
			}),
		).toEqual(expect.objectContaining({ name: "Committed despite reader outage" }));
	});

	it.each(["duplicate", "disconnected", "branch", "expiry_mismatch"] as const)(
		"does not publish %s credential topology during user reconciliation",
		async (mode) => {
			const { runtime, store } = await setupManagedDeletionRuntime({
				namespace: `managed-user-refresh-${mode}`,
			});
			const session = await issuePasswordSession(runtime);
			let credential = (await credentialRows(runtime))[0]!;
			if (mode === "branch") {
				await runtime.context.internalAdapter.rotateSessionCredential(
					session.token,
					generateCredentialOperationKey(),
				);
				const credentials = await credentialRows(runtime);
				const active = credentials.find((row) => row.status === "active")!;
				await runtime.context.adapter.create({
					model: "sessionCredential",
					forceAllowId: true,
					data: {
						...active,
						id: `${active.id}-branch`,
						selector: `${active.selector}-branch`,
						secretDigest: await digestSessionRefreshSecret("branch"),
						status: "consumed",
						parentCredentialId: null,
						rotationCounter: 0,
						familyId: `${active.familyId}-branch`,
						consumedAt: new Date(),
					},
				});
			} else if (mode === "expiry_mismatch") {
				await runtime.context.adapter.update({
					model: "sessionCredential",
					where: [{ field: "id", value: String(credential.id) }],
					update: { expiresAt: new Date(session.expiresAt.getTime() - 1_000) },
				});
			} else {
				await runtime.context.adapter.create({
					model: "sessionCredential",
					forceAllowId: true,
					data: {
						...credential,
						id: `${credential.id}-${mode}`,
						selector: `${credential.selector}-${mode}`,
						secretDigest: await digestSessionRefreshSecret(mode),
						...(mode === "disconnected"
							? {
								status: "consumed",
								familyId: `${credential.familyId}-other`,
								consumedAt: new Date(),
							  }
							: {}),
					},
				});
			}
			await runtime.context.internalAdapter.updateUser(runtime.user.id, {
				name: `Topology ${mode}`,
			});
			expect(store).toEqual(new Map());
		},
	);

	it("prunes cross-owner poisoning without deleting the other session authority", async () => {
		const namespace = "managed-user-refresh-cross-owner";
		const { runtime, store } = await setupManagedDeletionRuntime({ namespace });
		const target = await issuePasswordSession(runtime);
		const otherUser = await runtime.context.internalAdapter.createUser({
			email: "managed-other-owner@example.com",
			name: "Other owner",
		});
		const other = await runtime.context.internalAdapter.createSession(
			otherUser.id,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: otherUser.id,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		const targetIndexKey = `clearance:${namespace}:active-sessions:${runtime.user.id}`;
		const otherIndexKey = `clearance:${namespace}:active-sessions:${otherUser.id}`;
		const otherEntry = (
			JSON.parse(store.get(otherIndexKey)!) as Array<{ sessionId: string }>
		).find((entry) => entry.sessionId === other.id)!;
		store.set(
			targetIndexKey,
			JSON.stringify([
				...(JSON.parse(store.get(targetIndexKey)!) as unknown[]),
				otherEntry,
			]),
		);
		const otherStore = [...store.entries()].filter(
			([key, value]) =>
				key !== targetIndexKey &&
				(key.includes(other.id) || value.includes(other.id)),
		);

		await runtime.context.internalAdapter.updateUser(runtime.user.id, {
			name: "Cross owner pruned",
		});

		expect(JSON.parse(store.get(targetIndexKey)!)).toEqual([
			expect.objectContaining({ sessionId: target.id }),
		]);
		for (const [key, value] of otherStore) expect(store.get(key)).toBe(value);
	});

	it("serializes concurrent user refresh publishers so the newer DB user wins", async () => {
		const olderPublicationEntered = deferred();
		const olderPublicationGate = deferred();
		let blockOlderPublication = false;
		let storeRef: Map<string, string> | null = null;
		const setup = await setupManagedDeletionRuntime({
			namespace: "managed-user-refresh-concurrent",
			set: async (key, value) => {
				if (blockOlderPublication && value.includes("Older concurrent name")) {
					blockOlderPublication = false;
					olderPublicationEntered.resolve();
					await olderPublicationGate.promise;
				}
				storeRef!.set(key, value);
			},
		});
		storeRef = setup.store;
		const session = await issuePasswordSession(setup.runtime);
		blockOlderPublication = true;
		const older = setup.runtime.context.internalAdapter.updateUser(
			setup.runtime.user.id,
			{ name: "Older concurrent name" },
		);
		await olderPublicationEntered.promise;
		const newer = setup.runtime.context.internalAdapter.updateUser(
			setup.runtime.user.id,
			{ name: "Newer concurrent name" },
		);
		olderPublicationGate.resolve();
		await older;
		await newer;
		const envelope = [...setup.store.values()]
			.map((value) => safeJSONParse<{ session?: Session; user?: User }>(value))
			.find((value) => value?.session?.id === session.id)!;
		expect(envelope.user?.name).toBe("Newer concurrent name");
	});

	it("preserves unmanaged refresh compatibility", async () => {
		const runtime = await setupDatabaseBackedCompatibilityRuntime({
			namespace: "managed-user-refresh-unmanaged",
			options: { session: { storeSessionInDatabase: false } },
		});
		const session = await runtime.context.internalAdapter.createSession(runtime.user.id);
		await runtime.context.internalAdapter.updateUser(runtime.user.id, {
			name: "Unmanaged updated",
		});
		const envelope = [...runtime.store.values()]
			.map((value) => safeJSONParse<{ session?: Session; user?: User }>(value))
			.find((value) => value?.session?.id === session.id)!;
		expect(envelope.user?.name).toBe("Unmanaged updated");
	});
});
