import type {
	AuthContext,
	ClearanceOptions,
	InternalAdapter,
} from "@clearance/core";
import {
	getCurrentAdapter,
	getCurrentAuthContext,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
import type { DBAdapter, Where } from "@clearance/core/db/adapter";
import type { InternalLogger } from "@clearance/core/env";
import { generateId } from "@clearance/core/utils/id";
import { getIp } from "@clearance/core/utils/ip";
import { safeJSONParse } from "@clearance/core/utils/json";
import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";
import { createHMAC } from "@clearance/utils/hmac";
import type { Account, Session, User, Verification } from "../types";
import { constantTimeEqual } from "../crypto";
import { getDate } from "../utils/date";
import {
	CREDENTIAL_OPERATION_KEY_REQUIREMENT,
	parseCredentialOperationKey,
} from "../utils/operation-key";
import {
	getSessionDefaultFields,
	parseInternalSessionOutput,
	parseSessionOutput,
	parseUserOutput,
} from "./schema";
import {
	getStorageOption,
	processIdentifier,
} from "./verification-token-storage";
import {
	createSessionHandle,
	createSessionRefreshSecret,
	credentialIdFromRefreshSecret,
	digestSessionRotationNonce,
	digestSessionRefreshSecret,
	SESSION_CREDENTIAL_DIGEST_VERSION,
	SESSION_CREDENTIAL_MODEL,
	SESSION_ROTATION_RECOVERY_WINDOW_MS,
	sessionIdFromHandle,
	type SessionCredential,
} from "./session-credential";
import { getSecondarySessionKeys } from "./session-credential-migration";
import {
	hasPasskeySessionGeneration,
	PASSKEY_SESSION_GENERATION_FIELD,
	sessionMatchesPasskeyGeneration,
} from "./passkey-session-generation";
import {
	hasTwoFactorSessionGeneration,
	sessionMatchesTwoFactorGeneration,
	TWO_FACTOR_SESSION_GENERATION_FIELD,
} from "./two-factor-session-generation";
import {
	lockAndReadActiveUser,
	lockAndReadUser,
} from "./user-authority";
import type { DatabaseHooksEntry } from "./with-hooks";
import { getWithHooks } from "./with-hooks";
import { readInternalCredentialAuthority } from "../internal/credential-authority";

function getTTLSeconds(expiresAt: Date | number, now = Date.now()): number {
	const expiresMs =
		typeof expiresAt === "number" ? expiresAt : expiresAt.getTime();
	return Math.max(Math.floor((expiresMs - now) / 1000), 0);
}

export const createInternalAdapter = (
	adapter: DBAdapter<ClearanceOptions>,
	ctx: {
		options: Omit<ClearanceOptions, "logger">;
		logger: InternalLogger;
		hooks: DatabaseHooksEntry[];
		generateId: AuthContext["generateId"];
		secretConfig: AuthContext["secretConfig"];
	},
): InternalAdapter => {
	const logger = ctx.logger;
	const options = ctx.options;
	const secondaryStorage = options.secondaryStorage;
	const credentialAuthority = readInternalCredentialAuthority(options);
	const legacyCredentialAuthority =
		credentialAuthority?.generation === "legacy-v1";
	const storesSessionsInDatabase =
		!secondaryStorage || options.session?.storeSessionInDatabase === true;
	const secondarySessionKeys =
		secondaryStorage ? getSecondarySessionKeys(options) : null;
	const verificationConsumeLocks = new Map<string, Promise<void>>();
	// Warn at most once when a single-use value is consumed through the
	// non-atomic secondary-storage fallback (see consumeVerificationValue).
	let warnedNonAtomicConsume = false;
	const sessionExpiration = options.session?.expiresIn || 60 * 60 * 24 * 7; // 7 days
	const bindsTwoFactorSessionGeneration =
		hasTwoFactorSessionGeneration(options);
	const bindsPasskeySessionGeneration = hasPasskeySessionGeneration(options);
	const serializesUserCredentialAuthority =
		storesSessionsInDatabase ||
		bindsPasskeySessionGeneration ||
		options.plugins?.some((plugin) => plugin.id === "admin") === true ||
		options.user?.additionalFields?.banned !== undefined;

	type SessionWithUser = Session & { user: User | null };
	type SecondarySessionIndexEntry = {
		sessionId: string;
		credentialKey: string;
		expiresAt: number;
	};
	type SessionRotationResult = {
		session: Session;
		user: User;
		refreshToken: string;
		familyId: string;
		rotationCounter: number;
		oldDigest: string;
		successorDigest: string;
	};

	const sessionMatchesSecurityGenerations = (
		session: Record<string, unknown>,
		user: Record<string, unknown>,
	) =>
		(!bindsTwoFactorSessionGeneration ||
			sessionMatchesTwoFactorGeneration(session, user)) &&
		(!bindsPasskeySessionGeneration ||
			sessionMatchesPasskeyGeneration(session, user));

	const secondaryCredentialKey = (digest: string) =>
		secondarySessionKeys?.credential(digest) ?? `session-credential:${digest}`;
	const secondaryHandleKey = (sessionId: string) =>
		secondarySessionKeys?.handle(sessionId) ?? `session-handle:${sessionId}`;
	const secondaryActiveSessionsKey = (userId: string) =>
		secondarySessionKeys?.activeSessions(userId) ?? `active-sessions-${userId}`;
	const parseSecondaryHandle = (value: unknown): string | null =>
		safeJSONParse<{ credentialKey?: string }>(value)?.credentialKey ?? null;

	async function revokeCredentialFamily(
		familyId: string,
		revokedAt = new Date(),
	): Promise<void> {
		if (!storesSessionsInDatabase) return;
		const currentAdapter = await getCurrentAdapter(adapter);
		await currentAdapter.updateMany({
			model: SESSION_CREDENTIAL_MODEL,
			where: [
				{ field: "familyId", value: familyId },
				{ field: "status", value: "revoked", operator: "ne" },
			],
			update: {
				status: "revoked",
				revokedAt,
				rotationNonceDigest: null,
				recoverySecretCiphertext: null,
				recoveryExpiresAt: null,
				updatedAt: revokedAt,
			},
		});
	}

	async function findSessionRecordById(
		sessionId: string,
	): Promise<SessionWithUser | null> {
		return (await getCurrentAdapter(adapter)).findOne<SessionWithUser>({
			model: "session",
			where: [{ field: "id", value: sessionId }],
			join: { user: true },
		});
	}

	async function createCredentialRecord(input: {
		id?: string | undefined;
		selector: string;
		sessionId: string;
		familyId: string;
		secretDigest: string;
		expiresAt: Date;
		parentCredentialId?: string | undefined;
		rotationCounter?: number | undefined;
	}): Promise<SessionCredential> {
		const now = new Date();
		return (await getCurrentAdapter(adapter)).create<
			Record<string, unknown>,
			SessionCredential
		>({
			model: SESSION_CREDENTIAL_MODEL,
			forceAllowId: input.id !== undefined,
			data: {
				...(input.id ? { id: input.id } : {}),
				selector: input.selector,
				sessionId: input.sessionId,
				familyId: input.familyId,
				secretDigest: input.secretDigest,
				digestVersion: SESSION_CREDENTIAL_DIGEST_VERSION,
				status: "active",
				rotationCounter: input.rotationCounter ?? 0,
				parentCredentialId: input.parentCredentialId ?? null,
				expiresAt: input.expiresAt,
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
	}

	function createCredentialIdentity(): {
		id?: string | undefined;
		selector: string;
	} {
		const generatedId = ctx.generateId({ model: SESSION_CREDENTIAL_MODEL });
		return {
			...(generatedId === false ? {} : { id: generatedId }),
			selector: generateId(),
		};
	}

	const {
		createWithHooks,
		updateWithHooks,
		updateManyWithHooks,
		deleteWithHooks,
		deleteManyWithHooks,
		consumeOneWithHooks,
	} = getWithHooks(adapter, ctx);

	async function refreshUserSessions(user: User) {
		if (!secondaryStorage) return;

		const listRaw = await secondaryStorage.get(
			secondaryActiveSessionsKey(user.id),
		);
		if (!listRaw) return;

		const now = Date.now();
		const list = safeJSONParse<SecondarySessionIndexEntry[]>(listRaw) || [];
		const validSessions = list.filter((s) => s.expiresAt > now);

		await Promise.all(
			validSessions.map(async ({ credentialKey }) => {
				const cached = await secondaryStorage.get(credentialKey);
				if (!cached) return;
				const parsed = safeJSONParse<{ session: Session; user: User }>(cached);
				if (!parsed) return;

				const sessionTTL = getTTLSeconds(parsed.session.expiresAt, now);

				await secondaryStorage.set(
					credentialKey,
					JSON.stringify({
						session: { ...parsed.session, token: null },
						user,
					}),
					Math.floor(sessionTTL),
				);
			}),
		);
	}

	async function withVerificationConsumeLock<T>(
		key: string,
		fn: () => Promise<T>,
	): Promise<T> {
		const previous = verificationConsumeLocks.get(key) ?? Promise.resolve();
		let release!: () => void;
		const current = new Promise<void>((resolve) => {
			release = resolve;
		});
		const next = previous.catch(() => {}).then(() => current);
		verificationConsumeLocks.set(key, next);
		await previous.catch(() => {});
		try {
			return await fn();
		} finally {
			release();
			if (verificationConsumeLocks.get(key) === next) {
				verificationConsumeLocks.delete(key);
			}
		}
	}

	async function revokeCredentialFamiliesBySessionId(
		sessionId: string,
		reuseDetectedAt?: Date | undefined,
	): Promise<void> {
		if (!storesSessionsInDatabase) return;
		const currentAdapter = await getCurrentAdapter(adapter);
		const revokedAt = reuseDetectedAt ?? new Date();
		await currentAdapter.updateMany({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "sessionId", value: sessionId }],
			update: {
				status: "revoked",
				revokedAt,
				...(reuseDetectedAt ? { reuseDetectedAt } : {}),
				rotationNonceDigest: null,
				recoverySecretCiphertext: null,
				recoveryExpiresAt: null,
				updatedAt: revokedAt,
			},
		});
	}

	async function revokeAndDeleteSessionById(
		sessionId: string,
		reuseDetectedAt?: Date | undefined,
	): Promise<void> {
		if (storesSessionsInDatabase) {
			await revokeCredentialFamiliesBySessionId(sessionId, reuseDetectedAt);
			if (!ctx.options.session?.preserveSessionInDatabase) {
				await deleteWithHooks(
					[{ field: "id", value: sessionId }],
					"session",
					undefined,
				);
			}
		}
	}

	async function findDatabaseSessionByCredential(
		presentedSecret: string,
	): Promise<{ session: Session; user: User; credential: SessionCredential } | null> {
		const secretDigest = await digestSessionRefreshSecret(presentedSecret);
		const credentialId = credentialIdFromRefreshSecret(presentedSecret);
		const currentAdapter = await getCurrentAdapter(adapter);
		let credential = credentialId
			? await currentAdapter.findOne<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "selector", value: credentialId }],
				})
			: await currentAdapter.findOne<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "secretDigest", value: secretDigest }],
				});

		if (
			!credential ||
			!constantTimeEqual(credential.secretDigest, secretDigest)
		) {
			return null;
		}

		if (credential.status === "consumed") {
			// During the lost-response recovery window the consumed parent must
			// fail closed for ordinary authentication without revoking the
			// family. Recovery itself is only available through
			// rotateSessionCredential with the exact same operation key.
			// After the window expires, presenting the parent is replay.
			const recoveryStillValid =
				credential.recoveryExpiresAt != null &&
				credential.recoveryExpiresAt > new Date();
			if (!recoveryStillValid) {
				const reuseDetectedAt = new Date();
				await runWithTransaction(adapter, () =>
					revokeAndDeleteSessionById(
						credential!.sessionId ?? "",
						reuseDetectedAt,
					),
				);
			}
			return null;
		}
		if (
			credential.status !== "active" ||
			credential.expiresAt <= new Date() ||
			!credential.sessionId
		) {
			return null;
		}

		const record = await findSessionRecordById(credential.sessionId);
		if (!record?.user) return null;
		const { user, ...storedSession } = record;
		return {
			session: { ...storedSession, token: presentedSecret },
			user,
			credential,
		};
	}

	async function findDatabaseSessionIdByCredential(
		presentedSecret: string,
	): Promise<string | null> {
		const secretDigest = await digestSessionRefreshSecret(presentedSecret);
		const credentialId = credentialIdFromRefreshSecret(presentedSecret);
		const currentAdapter = await getCurrentAdapter(adapter);
		const credential = credentialId
			? await currentAdapter.findOne<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "selector", value: credentialId }],
				})
			: await currentAdapter.findOne<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "secretDigest", value: secretDigest }],
				});
		if (
			!credential?.sessionId ||
			!constantTimeEqual(credential.secretDigest, secretDigest)
		) {
			return null;
		}
		return credential.sessionId;
	}

	async function recoverRecentSessionRotation(
		credential: SessionCredential,
		rotationNonceDigest: string,
		rotationOperation: string,
		oldDigest: string,
	): Promise<SessionRotationResult | null> {
		if (
			credential.status !== "consumed" ||
			!credential.sessionId ||
			!credential.rotationNonceDigest ||
			!credential.recoveryExpiresAt ||
			credential.recoveryExpiresAt <= new Date() ||
			!constantTimeEqual(
				credential.rotationNonceDigest,
				rotationNonceDigest,
			)
		) {
			return null;
		}

		const successor = await (
			await getCurrentAdapter(adapter)
		).findOne<SessionCredential>({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "parentCredentialId", value: credential.id }],
		});
		if (
			!successor ||
			successor.status !== "active" ||
			successor.sessionId !== credential.sessionId ||
			successor.expiresAt <= new Date() ||
			!successor.secretDigest
		) {
			return null;
		}
		const candidates = await deriveRotationSuccessors(
			credential,
			rotationOperation,
		);
		const recovered = candidates.find((candidate) =>
			constantTimeEqual(successor.secretDigest, candidate.digest),
		);
		if (!recovered) return null;
		const record = await findSessionRecordById(credential.sessionId);
		if (!record?.user || record.expiresAt <= new Date()) return null;
		const currentAdapter = await getCurrentAdapter(adapter);
		const activeUser = await lockAndReadActiveUser(
			currentAdapter,
			record.user.id,
		);
		if (!activeUser) return null;
		const { user: _, ...session } = record;
		if (
			bindsPasskeySessionGeneration &&
			!sessionMatchesPasskeyGeneration(
				session as unknown as Record<string, unknown>,
				activeUser as unknown as Record<string, unknown>,
			)
		) {
			return null;
		}
		return {
			session: { ...session, token: recovered.refreshToken },
			user: activeUser,
			refreshToken: recovered.refreshToken,
			familyId: credential.familyId,
			rotationCounter: successor.rotationCounter,
			oldDigest,
			successorDigest: recovered.digest,
		};
	}

	async function deriveRotationSuccessors(
		credential: SessionCredential,
		rotationOperation: string,
	): Promise<Array<{ selector: string; refreshToken: string; digest: string }>> {
		const keys =
			typeof ctx.secretConfig === "string"
				? [ctx.secretConfig]
				: [
						ctx.secretConfig.keys.get(ctx.secretConfig.currentVersion),
						...ctx.secretConfig.keys.values(),
					].filter((key, index, all): key is string =>
						Boolean(key) && all.indexOf(key) === index,
					);
		const hmac = createHMAC("SHA-256", "base64urlnopad");
		return Promise.all(
			keys.map(async (key) => {
				const authority = [
					"clearance:session-rotation-successor:v1",
					credential.id,
					credential.secretDigest,
					rotationOperation,
				].join(":");
				const selector = await hmac.sign(key, `${authority}:selector`);
				const material = await hmac.sign(key, `${authority}:secret`);
				const refreshToken = createSessionRefreshSecret(selector, material);
				return {
					selector,
					refreshToken,
					digest: await digestSessionRefreshSecret(refreshToken),
				};
			}),
		);
	}

	const internalAdapter: InternalAdapter = {
		createOAuthUser: async (
			user: Omit<User, "id" | "createdAt" | "updatedAt">,
			account: Omit<Account, "userId" | "id" | "createdAt" | "updatedAt"> &
				Partial<Account>,
		) => {
			return runWithTransaction(adapter, async () => {
				const createdUser = await createWithHooks(
					{
						// todo: we should remove auto setting createdAt and updatedAt in the next major release, since the db generators already handle that
						createdAt: new Date(),
						updatedAt: new Date(),
						...user,
						email: user.email?.toLowerCase(),
					},
					"user",
					undefined,
				);
				const createdAccount = await createWithHooks(
					{
						...account,
						userId: createdUser!.id,
						// todo: we should remove auto setting createdAt and updatedAt in the next major release, since the db generators already handle that
						createdAt: new Date(),
						updatedAt: new Date(),
					},
					"account",
					undefined,
				);
				return {
					user: createdUser,
					account: createdAccount,
				};
			});
		},
		createUser: async <T>(
			user: Omit<User, "id" | "createdAt" | "updatedAt" | "emailVerified"> &
				Partial<User> &
				Record<string, any>,
		) => {
			const createdUser = await runWithTransaction(adapter, () =>
				createWithHooks(
					{
						// todo: we should remove auto setting createdAt and updatedAt in the next major release, since the db generators already handle that
						createdAt: new Date(),
						updatedAt: new Date(),
						...user,
						email: user.email?.toLowerCase(),
					},
					"user",
					undefined,
				),
			);

			return createdUser as T & User;
		},
		createAccount: async <T extends Record<string, any>>(
			account: Omit<Account, "id" | "createdAt" | "updatedAt"> &
				Partial<Account> &
				T,
		) => {
			const createdAccount = await createWithHooks(
				{
					// todo: we should remove auto setting createdAt and updatedAt in the next major release, since the db generators already handle that
					createdAt: new Date(),
					updatedAt: new Date(),
					...account,
				},
				"account",
				undefined,
			);
			return createdAccount as T & Account;
		},
		listSessions: async (
			userId: string,
			options?: { onlyActiveSessions?: boolean | undefined } | undefined,
		) => {
			if (secondaryStorage && !storesSessionsInDatabase) {
				const currentUser = bindsPasskeySessionGeneration
					? await (
							await getCurrentAdapter(adapter)
						).findOne<User>({
							model: "user",
							where: [{ field: "id", value: userId }],
						})
					: null;
				if (bindsPasskeySessionGeneration && !currentUser) return [];
				const currentList = await secondaryStorage.get(
					secondaryActiveSessionsKey(userId),
				);
				if (!currentList) return [];

				const list:
					| (SecondarySessionIndexEntry | {
							token: string;
							expiresAt: number;
					  })[] = safeJSONParse(currentList) || [];
				const now = Date.now();

				const seenSessionIds = new Set<string>();
				const sessions: Session[] = [];
				const migratedIndex: SecondarySessionIndexEntry[] = [];

				for (const entry of list) {
					if (entry.expiresAt <= now) continue;
					let credentialKey =
						"credentialKey" in entry ? entry.credentialKey : undefined;
					let sessionId = "sessionId" in entry ? entry.sessionId : undefined;
					if (!credentialKey && "token" in entry) {
						const legacy = await internalAdapter.findSession(entry.token);
						if (!legacy) continue;
						sessionId = legacy.session.id;
						credentialKey = secondaryCredentialKey(
							await digestSessionRefreshSecret(entry.token),
						);
					}
					if (
						!credentialKey ||
						!sessionId ||
						seenSessionIds.has(sessionId)
					) {
						continue;
					}
					seenSessionIds.add(sessionId);

					const data = await secondaryStorage.get(credentialKey);
					if (!data) continue;

					try {
						const parsed = (
							typeof data === "string" ? JSON.parse(data) : data
						) as {
							session: Session;
							user: User;
						};
						if (
							!parsed?.session ||
							(bindsPasskeySessionGeneration &&
								!sessionMatchesPasskeyGeneration(
									parsed.session as unknown as Record<string, unknown>,
									currentUser as unknown as Record<string, unknown>,
								))
						) {
							continue;
						}

						sessions.push(
							parseInternalSessionOutput(ctx.options, {
								...parsed.session,
								expiresAt: new Date(parsed.session.expiresAt),
							}),
						);
						migratedIndex.push({
							sessionId,
							credentialKey,
							expiresAt: entry.expiresAt,
						});
					} catch {
						continue;
					}
				}
				if (migratedIndex.length > 0) {
					const furthestExpiry = Math.max(
						...migratedIndex.map((entry) => entry.expiresAt),
					);
					await secondaryStorage.set(
						secondaryActiveSessionsKey(userId),
						JSON.stringify(migratedIndex),
						getTTLSeconds(furthestExpiry, now),
					);
				} else {
					await secondaryStorage.delete(secondaryActiveSessionsKey(userId));
				}
				return sessions;
			}

			const sessions = await (
				await getCurrentAdapter(adapter)
			).findMany<Session>({
				model: "session",
				where: [
					{
						field: "userId",
						value: userId,
					},
					...(options?.onlyActiveSessions
						? [
								{
									field: "expiresAt",
									value: new Date(),
									operator: "gt",
								} satisfies Where,
							]
						: []),
				],
			});
			if (!bindsPasskeySessionGeneration) return sessions;
			const currentUser = await (
				await getCurrentAdapter(adapter)
			).findOne<User>({
				model: "user",
				where: [{ field: "id", value: userId }],
			});
			if (!currentUser) return [];
			return sessions.filter((session) =>
				sessionMatchesPasskeyGeneration(
					session as unknown as Record<string, unknown>,
					currentUser as unknown as Record<string, unknown>,
				),
			);
		},
		listUsers: async (
			limit?: number | undefined,
			offset?: number | undefined,
			sortBy?:
				| {
						field: string;
						direction: "asc" | "desc";
				  }
				| undefined,
			where?: Where[] | undefined,
		) => {
			const users = await (
				await getCurrentAdapter(adapter)
			).findMany<User>({
				model: "user",
				limit,
				offset,
				sortBy,
				where,
			});
			return users;
		},
		countTotalUsers: async (where?: Where[] | undefined) => {
			const total = await (
				await getCurrentAdapter(adapter)
			).count({
				model: "user",
				where,
			});
			if (typeof total === "string") {
				return parseInt(total);
			}
			return total;
		},
		deleteUser: async (userId: string) => {
			await internalAdapter.deleteUserSessions(userId);
			await deleteManyWithHooks(
				[
					{
						field: "userId",
						value: userId,
					},
				],
				"account",
				undefined,
			);

			await deleteWithHooks(
				[
					{
						field: "id",
						value: userId,
					},
				],
				"user",
				undefined,
			);
		},
		createSession: async (
			userId: string,
			dontRememberMe?: boolean | undefined,
			override?: (Partial<Session> & Record<string, any>) | undefined,
			overrideAll?: boolean | undefined,
		) => {
			const headers: Headers | undefined = await (async () => {
				const ctx = await getCurrentAuthContext().catch(() => null);
				return ctx?.headers || ctx?.request?.headers;
			})();
			const storeInDb = options.session?.storeSessionInDatabase;
			if (
				serializesUserCredentialAuthority &&
				typeof adapter.options?.adapterConfig.transaction !== "function"
			) {
				throw new Error(
					"Session creation with serialized user authority requires an adapter with rollback-capable transactions",
				);
			}
			const {
				// Authority and identity fields are always derived by the runtime.
				id: _discardedId,
				token: _discardedToken,
				userId: _discardedUserId,
				[PASSKEY_SESSION_GENERATION_FIELD]: _discardedPasskeySessionGeneration,
				__preserveSessionExpiresAt,
				...rest
			} = override || {};

			// A stable id is the public administrative handle. The independently
			// generated refresh secret exists only at the issuance boundary.
			const generatedSessionId = ctx.generateId({ model: "session" });
			const requestedSessionId =
				generatedSessionId !== false
					? generatedSessionId
					: storesSessionsInDatabase
						? undefined
						: generateId();
			const credentialIdentity = createCredentialIdentity();
			const refreshSecret = legacyCredentialAuthority
				? generateId(32)
				: createSessionRefreshSecret(credentialIdentity.selector);
			const refreshDigest = await digestSessionRefreshSecret(refreshSecret);
			const credentialKey = secondaryCredentialKey(refreshDigest);
			const familyId = generateId();

			// we're parsing default values for session additional fields
			const defaultAdditionalFields = getSessionDefaultFields(options);
			const policyExpiresAt = dontRememberMe
				? getDate(60 * 60 * 24, "sec")
				: getDate(sessionExpiration, "sec");
			const inheritedExpiresAt = new Date(rest.expiresAt ?? Number.NaN);
			const expiresAt =
				__preserveSessionExpiresAt === true &&
				Number.isFinite(inheritedExpiresAt.getTime()) &&
				inheritedExpiresAt > new Date() &&
				inheritedExpiresAt < policyExpiresAt
					? inheritedExpiresAt
					: policyExpiresAt;
			const buildSessionData = (
				twoFactorSessionGeneration?: string,
				passkeySessionGeneration?: string,
			) => ({
				...(requestedSessionId ? { id: requestedSessionId } : {}),
				ipAddress: headers ? getIp(headers, options) || "" : "",
				userAgent: headers?.get("user-agent") || "",
				...rest,
				/**
				 * If the user doesn't want to be remembered
				 * set the session to expire in 1 day.
				 * The cookie will be set to expire at the end of the session
				 */
				expiresAt,
				userId,
				// Keep a unique non-secret handle in the retired legacy column. This
				// remains compatible with upgraded schemas that still enforce the old
				// NOT NULL + UNIQUE contract while all authentication uses the digest
				// credential ledger.
				token: legacyCredentialAuthority
					? refreshSecret
					: createSessionHandle(
							requestedSessionId ?? credentialIdentity.selector,
						),
				// todo: we should remove auto setting createdAt and updatedAt in the next major release, since the db generators already handle that
				createdAt: new Date(),
				updatedAt: new Date(),
				...defaultAdditionalFields,
				...(twoFactorSessionGeneration
					? {
							[TWO_FACTOR_SESSION_GENERATION_FIELD]: twoFactorSessionGeneration,
						}
					: {}),
				...(overrideAll ? rest : {}),
				...(passkeySessionGeneration
					? {
							[PASSKEY_SESSION_GENERATION_FIELD]: passkeySessionGeneration,
						}
					: {}),
			}) satisfies Partial<Session>;
			const enforceSessionAuthority = <
				T extends Partial<Session> & Record<string, any>,
			>(
				hookedData: T,
				twoFactorSessionGeneration?: string,
				passkeySessionGeneration?: string,
			): T => {
				const {
					id: _hookedId,
					token: _hookedToken,
					userId: _hookedUserId,
					[TWO_FACTOR_SESSION_GENERATION_FIELD]: _hookedTwoFactorSessionGeneration,
					[PASSKEY_SESSION_GENERATION_FIELD]: _hookedPasskeySessionGeneration,
					...safeHookedData
				} = hookedData;
				return {
					...safeHookedData,
					...(requestedSessionId ? { id: requestedSessionId } : {}),
					userId,
					token: legacyCredentialAuthority
						? refreshSecret
						: createSessionHandle(
								requestedSessionId ?? credentialIdentity.selector,
							),
					...(twoFactorSessionGeneration
						? {
								[TWO_FACTOR_SESSION_GENERATION_FIELD]:
									twoFactorSessionGeneration,
							}
						: {}),
					...(passkeySessionGeneration
						? {
								[PASSKEY_SESSION_GENERATION_FIELD]: passkeySessionGeneration,
							}
						: {}),
				} as T;
			};
			const persistSecondarySession = async (
				sessionData: Record<string, any>,
			) => {
				if (!secondaryStorage) return sessionData;
				const persistedSessionId = String(sessionData.id);
				const persistedExpiresAt = new Date(sessionData.expiresAt);
				const user = await (
					await getCurrentAdapter(adapter)
				).findOne<User>({
					model: "user",
					where: [{ field: "id", value: userId }],
				});
				if (
					(bindsPasskeySessionGeneration || bindsTwoFactorSessionGeneration) &&
					(!user ||
						!sessionMatchesSecurityGenerations(
							sessionData,
							user as unknown as Record<string, unknown>,
						))
				) {
					if (storesSessionsInDatabase) return sessionData;
					throw new Error("Session security generation changed during creation");
				}
				/**
				 * store the session token for the user
				 * so we can retrieve it later for listing sessions
				 */
				const currentList = await secondaryStorage.get(
					secondaryActiveSessionsKey(userId),
				);

				let list: SecondarySessionIndexEntry[] = [];
				const now = Date.now();

				if (currentList) {
					list = safeJSONParse(currentList) || [];
					list = list.filter(
						(session) =>
							session.expiresAt > now &&
							session.sessionId !== persistedSessionId,
					);
				}

				const sorted = [
					...list,
					{
						sessionId: persistedSessionId,
						credentialKey,
						expiresAt: persistedExpiresAt.getTime(),
					},
				].sort((a, b) => a.expiresAt - b.expiresAt);
				const furthestSessionExp =
					sorted.at(-1)?.expiresAt ?? persistedExpiresAt.getTime();
				const furthestSessionTTL = getTTLSeconds(furthestSessionExp, now);
				if (furthestSessionTTL > 0) {
					await secondaryStorage.set(
						secondaryActiveSessionsKey(userId),
						JSON.stringify(sorted),
						furthestSessionTTL,
					);
				}

				const sessionTTL = getTTLSeconds(persistedExpiresAt, now);
				if (sessionTTL > 0) {
					await secondaryStorage.set(
						credentialKey,
						JSON.stringify({
							session: { ...sessionData, token: null },
							user,
						}),
						sessionTTL,
					);
					await secondaryStorage.set(
						secondaryHandleKey(persistedSessionId),
						JSON.stringify({ credentialKey }),
						sessionTTL,
					);
				}

				return sessionData;
			};

			const create = async () => {
				let lockedUser: (User & Record<string, unknown>) | null = null;
				if (serializesUserCredentialAuthority) {
					const currentAdapter = await getCurrentAdapter(adapter);
					lockedUser = await lockAndReadUser(
						currentAdapter,
						userId,
					) as (User & Record<string, unknown>) | null;
					if (!lockedUser) {
						throw new Error("Cannot create a session for an unavailable user");
					}
				}
				const currentAdapter = await getCurrentAdapter(adapter);
				const authorityUser =
					bindsTwoFactorSessionGeneration || bindsPasskeySessionGeneration
						? (lockedUser ??
							(await currentAdapter.findOne<User & Record<string, unknown>>({
								model: "user",
								where: [{ field: "id", value: userId }],
							})))
						: null;
				if (
					(bindsTwoFactorSessionGeneration || bindsPasskeySessionGeneration) &&
					!authorityUser
				) {
					throw new Error("Cannot create a session for an unavailable user");
				}

				let twoFactorSessionGeneration: string | undefined;
				if (bindsTwoFactorSessionGeneration) {
					const currentGeneration =
						authorityUser?.[TWO_FACTOR_SESSION_GENERATION_FIELD];
					if (currentGeneration == null) {
						if (storesSessionsInDatabase) {
							twoFactorSessionGeneration = generateId(32);
							const initialized = await currentAdapter.update<
								Record<string, unknown>
							>({
								model: "user",
								where: [{ field: "id", value: userId }],
								update: {
									[TWO_FACTOR_SESSION_GENERATION_FIELD]:
										twoFactorSessionGeneration,
								},
							});
							if (!initialized) {
								throw new Error("Could not bind the session security generation");
							}
							await currentAdapter.updateMany({
								model: "session",
								where: [
									{ field: "userId", value: userId },
									{
										field: TWO_FACTOR_SESSION_GENERATION_FIELD,
										value: null,
									},
								],
								update: {
									[TWO_FACTOR_SESSION_GENERATION_FIELD]:
										twoFactorSessionGeneration,
								},
							});
						}
					} else if (typeof currentGeneration === "string") {
						twoFactorSessionGeneration = currentGeneration;
					} else {
						throw new Error("Could not bind the session security generation");
					}
				}

				let passkeySessionGeneration: string | undefined;
				if (bindsPasskeySessionGeneration) {
					const currentGeneration =
						authorityUser?.[PASSKEY_SESSION_GENERATION_FIELD];
					if (currentGeneration == null) {
						if (storesSessionsInDatabase) {
							passkeySessionGeneration = generateId(32);
							const initialized = await currentAdapter.update<
								Record<string, unknown>
							>({
								model: "user",
								where: [{ field: "id", value: userId }],
								update: {
									[PASSKEY_SESSION_GENERATION_FIELD]:
										passkeySessionGeneration,
								},
							});
							if (!initialized) {
								throw new Error("Could not bind the passkey session generation");
							}
							await currentAdapter.updateMany({
								model: "session",
								where: [
									{ field: "userId", value: userId },
									{
										field: PASSKEY_SESSION_GENERATION_FIELD,
										value: null,
									},
								],
								update: {
									[PASSKEY_SESSION_GENERATION_FIELD]:
										passkeySessionGeneration,
								},
							});
						}
					} else if (typeof currentGeneration === "string") {
						passkeySessionGeneration = currentGeneration;
					} else {
						throw new Error("Could not bind the passkey session generation");
					}
				}
				const data = buildSessionData(
					twoFactorSessionGeneration,
					passkeySessionGeneration,
				);
				const persistDatabaseSession =
					bindsTwoFactorSessionGeneration || bindsPasskeySessionGeneration
					? async (sessionData: Record<string, any>) => {
							const currentUser = await currentAdapter.findOne<User>({
								model: "user",
								where: [{ field: "id", value: userId }],
							});
							if (
								!currentUser ||
								!sessionMatchesSecurityGenerations(
									sessionData,
									currentUser as unknown as Record<string, unknown>,
								)
							) {
								throw new Error(
									"Session security generation changed during creation",
								);
							}
							return currentAdapter.create<Record<string, any>>({
								model: "session",
								data: sessionData,
								forceAllowId: true,
							});
						}
					: null;
				// Dual-write (DB session + secondary cache): create only the primary
				// session row here. Secondary active-index / credential / handle
				// publication is deferred via queueAfterTransactionHook after the
				// credential row succeeds, so a later rollback leaves no ghosts.
				// Secondary-authoritative mode still publishes immediately.
				const res = await createWithHooks(
					data,
					"session",
					secondaryStorage && !storesSessionsInDatabase
						? {
								fn: persistSecondarySession,
								executeMainFn: storeInDb,
							}
						: persistDatabaseSession
							? {
									fn: persistDatabaseSession,
									executeMainFn: false,
								}
							: undefined,
					(hookedData) =>
						enforceSessionAuthority(
							hookedData,
							twoFactorSessionGeneration,
							passkeySessionGeneration,
						),
				);
				if (!res) {
					throw new Error("Session creation was rejected by a database hook");
				}
				if (storesSessionsInDatabase && !legacyCredentialAuthority) {
					const persistedSessionId = (res as Session).id;
					const stableHandle = createSessionHandle(persistedSessionId);
					if ((res as Session).token !== stableHandle) {
						await (await getCurrentAdapter(adapter)).update<Session>({
							model: "session",
							where: [{ field: "id", value: persistedSessionId }],
							update: { token: stableHandle },
						});
					}
					await createCredentialRecord({
						...credentialIdentity,
						sessionId: persistedSessionId,
						familyId,
						secretDigest: refreshDigest,
						expiresAt,
					});
				}
				if (secondaryStorage && storesSessionsInDatabase) {
					await queueAfterTransactionHook(async () => {
						await persistSecondarySession(res as Record<string, any>);
					});
				}
				return {
					...(res as Session),
					token: refreshSecret,
				};
			};

			return storesSessionsInDatabase || serializesUserCredentialAuthority
				? runWithTransaction(adapter, create)
				: create();
		},
		findSession: async (
			token: string,
		): Promise<{
			session: Session & Record<string, any>;
			user: User & Record<string, any>;
		} | null> => {
			if (legacyCredentialAuthority && storesSessionsInDatabase) {
				const record = await (
					await getCurrentAdapter(adapter)
				).findOne<SessionWithUser>({
					model: "session",
					where: [{ field: "token", value: token }],
					join: { user: true },
				});
				if (!record?.user) return null;
				const { user, ...session } = record;
				if (
					(user as User & { banned?: boolean | null }).banned === true ||
					!sessionMatchesSecurityGenerations(
						session as Record<string, unknown>,
						user as unknown as Record<string, unknown>,
					)
				) {
					return null;
				}
				return {
					session: parseInternalSessionOutput(ctx.options, session),
					user: parseUserOutput(ctx.options, user),
				};
			}

			if (secondaryStorage && !storesSessionsInDatabase) {
				const digest = await digestSessionRefreshSecret(token);
				const credentialKey = secondaryCredentialKey(digest);
				const sessionStringified =
					await secondaryStorage.get(credentialKey);
				if (!sessionStringified) return null;
				const stored = safeJSONParse<{
					session: Session;
					user: User;
				}>(sessionStringified);
				if (!stored) return null;
				const currentUser = await (
					await getCurrentAdapter(adapter)
				).findOne<User & { banned?: boolean | null }>({
					model: "user",
					where: [{ field: "id", value: stored.user.id }],
				});
				if (
					!currentUser ||
					currentUser.banned === true ||
					!sessionMatchesSecurityGenerations(
						stored.session as unknown as Record<string, unknown>,
						currentUser,
					)
				) {
					await secondaryStorage.delete(credentialKey);
					return null;
				}
				const parsedSession = parseInternalSessionOutput(ctx.options, {
					...stored.session,
					expiresAt: new Date(stored.session.expiresAt),
					createdAt: new Date(stored.session.createdAt),
					updatedAt: new Date(stored.session.updatedAt),
				});
				const parsedUser = parseUserOutput(ctx.options, {
					...currentUser,
					createdAt: new Date(currentUser.createdAt),
					updatedAt: new Date(currentUser.updatedAt),
				});
				return {
					session: { ...parsedSession, token },
					user: parsedUser,
				};
			}

			const result = await findDatabaseSessionByCredential(token);
			if (!result) return null;
			const { user, session } = result;
			if (
				(user as User & { banned?: boolean | null }).banned === true ||
				!sessionMatchesSecurityGenerations(
					session as Record<string, unknown>,
					user as unknown as Record<string, unknown>,
				)
			) {
				return null;
			}
			return {
				session: parseInternalSessionOutput(ctx.options, session),
				user: parseUserOutput(ctx.options, user),
			};
		},
		findSessionById: async (sessionId: string) => {
			if (!storesSessionsInDatabase) {
				if (!secondaryStorage) return null;
				const credentialKey = parseSecondaryHandle(
					await secondaryStorage.get(secondaryHandleKey(sessionId)),
				);
				if (!credentialKey) return null;
				const serialized = await secondaryStorage.get(credentialKey);
				const parsed = safeJSONParse<{ session: Session; user: User }>(serialized);
				if (!parsed) return null;
				if (bindsPasskeySessionGeneration) {
					const currentUser = await (
						await getCurrentAdapter(adapter)
					).findOne<User>({
						model: "user",
						where: [{ field: "id", value: parsed.user.id }],
					});
					if (
						!currentUser ||
						!sessionMatchesPasskeyGeneration(
							parsed.session as unknown as Record<string, unknown>,
							currentUser as unknown as Record<string, unknown>,
						)
					) {
						await secondaryStorage.delete(credentialKey);
						return null;
					}
					parsed.user = currentUser;
				}
				return {
					session: parseInternalSessionOutput(ctx.options, {
						...parsed.session,
						expiresAt: new Date(parsed.session.expiresAt),
						createdAt: new Date(parsed.session.createdAt),
						updatedAt: new Date(parsed.session.updatedAt),
					}),
					user: parseUserOutput(ctx.options, {
						...parsed.user,
						createdAt: new Date(parsed.user.createdAt),
						updatedAt: new Date(parsed.user.updatedAt),
					}),
				};
			}
			const record = await findSessionRecordById(sessionId);
			if (!record?.user) return null;
			const { user, ...session } = record;
			if (
				bindsPasskeySessionGeneration &&
				!sessionMatchesPasskeyGeneration(
					session as unknown as Record<string, unknown>,
					user as unknown as Record<string, unknown>,
				)
			) {
				return null;
			}
			if (legacyCredentialAuthority) {
				return {
					session: parseInternalSessionOutput(ctx.options, session),
					user: parseUserOutput(ctx.options, user),
				};
			}
			const credentials = await (
				await getCurrentAdapter(adapter)
			).findMany<SessionCredential>({
				model: SESSION_CREDENTIAL_MODEL,
				where: [
					{ field: "sessionId", value: sessionId },
					{ field: "status", value: "active" },
				],
				limit: 1,
			});
			if (!credentials[0] || credentials[0].expiresAt <= new Date()) return null;
			return {
				session: parseInternalSessionOutput(ctx.options, session),
				user: parseUserOutput(ctx.options, user),
			};
		},
		recoverSessionCredential: async (
			token: string,
			idempotencyKey: string,
		) => {
			if (legacyCredentialAuthority) return null;
			if (!storesSessionsInDatabase) return null;
			const operationKey = parseCredentialOperationKey(idempotencyKey);
			if (!operationKey) return null;
			const recovered = await runWithTransaction(adapter, async () => {
				const currentAdapter = await getCurrentAdapter(adapter);
				const digest = await digestSessionRefreshSecret(token);
				const credentialId = credentialIdFromRefreshSecret(token);
				const credential = credentialId
					? await currentAdapter.findOne<SessionCredential>({
							model: SESSION_CREDENTIAL_MODEL,
							where: [{ field: "selector", value: credentialId }],
						})
					: await currentAdapter.findOne<SessionCredential>({
							model: SESSION_CREDENTIAL_MODEL,
							where: [{ field: "secretDigest", value: digest }],
						});
				if (
					!credential ||
					credential.status !== "consumed" ||
					!constantTimeEqual(credential.secretDigest, digest)
				) {
					return null;
				}
				return recoverRecentSessionRotation(
					credential,
					await digestSessionRotationNonce(operationKey),
					operationKey,
					digest,
				);
			});
			if (!recovered) return null;
			const { oldDigest: _, successorDigest: __, ...result } = recovered;
			return result;
		},
		rotateSessionCredential: async (token: string, idempotencyKey?: string) => {
			if (legacyCredentialAuthority) {
				throw new Error(
					"Session credential rotation is unavailable during the legacy bridge generation",
				);
			}
			if (!storesSessionsInDatabase) {
				throw new Error(
					"Session credential rotation requires database-backed sessions with transactional compare-and-swap support",
				);
			}
			if (
				typeof adapter.options?.adapterConfig.transaction !== "function"
			) {
				throw new Error(
					"Session credential rotation requires an adapter with rollback-capable transactions",
				);
			}
			const suppliedOperationKey =
				idempotencyKey === undefined
					? undefined
					: parseCredentialOperationKey(idempotencyKey);
			if (idempotencyKey !== undefined && !suppliedOperationKey) {
				throw new Error(CREDENTIAL_OPERATION_KEY_REQUIREMENT);
			}
			const rotationOperation = suppliedOperationKey ?? generateId(32);
			const rotationNonceDigest =
				await digestSessionRotationNonce(rotationOperation);
			const rotated = await runWithTransaction(adapter, async () => {
				const currentAdapter = await getCurrentAdapter(adapter);
				const digest = await digestSessionRefreshSecret(token);
				const credentialId = credentialIdFromRefreshSecret(token);
				const credential = credentialId
					? await currentAdapter.findOne<SessionCredential>({
							model: SESSION_CREDENTIAL_MODEL,
							where: [{ field: "selector", value: credentialId }],
						})
					: await currentAdapter.findOne<SessionCredential>({
							model: SESSION_CREDENTIAL_MODEL,
							where: [{ field: "secretDigest", value: digest }],
						});
				if (
					!credential ||
					!constantTimeEqual(credential.secretDigest, digest) ||
					!credential.sessionId
				) {
					return null;
				}
				if (credential.status !== "active") {
					if (credential.status === "consumed") {
						const recovered = await recoverRecentSessionRotation(
							credential,
							rotationNonceDigest,
							rotationOperation,
							digest,
						);
						if (recovered) return recovered;
						await revokeAndDeleteSessionById(
							credential.sessionId,
							new Date(),
						);
					}
					return null;
				}
				if (credential.expiresAt <= new Date()) return null;

				const record = await findSessionRecordById(credential.sessionId);
				if (!record?.user || record.expiresAt <= new Date()) return null;
				const activeUser = await lockAndReadActiveUser(
					currentAdapter,
					record.user.id,
				);
				if (!activeUser) return null;
				const { user: _, ...session } = record;
				if (
					bindsPasskeySessionGeneration &&
					!sessionMatchesPasskeyGeneration(
						session as unknown as Record<string, unknown>,
						activeUser as unknown as Record<string, unknown>,
					)
				) {
					return null;
				}

				const [derivedSuccessor] = await deriveRotationSuccessors(
					credential,
					rotationOperation,
				);
				if (!derivedSuccessor) return null;
				const successorIdentity = {
					...createCredentialIdentity(),
					selector: derivedSuccessor.selector,
				};
				const successorSecret = derivedSuccessor.refreshToken;
				const successorDigest = derivedSuccessor.digest;
				const consumedAt = new Date();
				const recoveryExpiresAt = new Date(
					consumedAt.getTime() + SESSION_ROTATION_RECOVERY_WINDOW_MS,
				);
				const consumed = await currentAdapter.incrementOne<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [
						{ field: "id", value: credential.id },
						{ field: "status", value: "active" },
						{ field: "secretDigest", value: digest },
					],
					increment: {},
					set: {
						status: "consumed",
						consumedAt,
						rotationNonceDigest,
						recoverySecretCiphertext: null,
						recoveryExpiresAt,
						updatedAt: consumedAt,
					},
				});
				if (!consumed) {
					const currentParent = await currentAdapter.findOne<SessionCredential>({
						model: SESSION_CREDENTIAL_MODEL,
						where: [{ field: "id", value: credential.id }],
					});
					if (currentParent) {
						const recovered = await recoverRecentSessionRotation(
							currentParent,
							rotationNonceDigest,
							rotationOperation,
							digest,
						);
						if (recovered) return recovered;
					}
					await revokeAndDeleteSessionById(credential.sessionId, new Date());
					return null;
				}

				await createCredentialRecord({
					...successorIdentity,
					sessionId: credential.sessionId,
					familyId: credential.familyId,
					secretDigest: successorDigest,
					expiresAt: credential.expiresAt,
					parentCredentialId: credential.id,
					rotationCounter: credential.rotationCounter + 1,
				});
				if (credential.parentCredentialId) {
					await currentAdapter.update<SessionCredential>({
						model: SESSION_CREDENTIAL_MODEL,
						where: [
							{ field: "id", value: credential.parentCredentialId },
						],
						update: {
							rotationNonceDigest: null,
							recoverySecretCiphertext: null,
							recoveryExpiresAt: null,
							updatedAt: consumedAt,
						},
					});
				}
				return {
					session: { ...session, token: successorSecret },
					user: activeUser,
					refreshToken: successorSecret,
					familyId: credential.familyId,
					rotationCounter: credential.rotationCounter + 1,
					oldDigest: digest,
					successorDigest,
				};
			});

			if (rotated && secondaryStorage) {
				const oldKey = secondaryCredentialKey(rotated.oldDigest);
				const successorKey = secondaryCredentialKey(rotated.successorDigest);
				const ttl = getTTLSeconds(rotated.session.expiresAt);
				if (ttl > 0) {
					await secondaryStorage.set(
						successorKey,
						JSON.stringify({
							session: {
								...rotated.session,
								token: null,
							},
							user: rotated.user,
						}),
						ttl,
					);
					await secondaryStorage.set(
						secondaryHandleKey(rotated.session.id),
						JSON.stringify({ credentialKey: successorKey }),
						ttl,
					);
				}
				await secondaryStorage.delete(oldKey);
			}

			if (!rotated) return null;
			const { oldDigest: _, successorDigest: __, ...result } = rotated;
			return result;
		},
		findSessions: async (
			sessionTokens: string[],
			options?:
				| {
						onlyActiveSessions?: boolean | undefined;
				  }
				| undefined,
		) => {
			const sessions: { session: Session; user: User }[] = [];
			for (const sessionToken of sessionTokens) {
				const resolved = await internalAdapter.findSession(sessionToken);
				if (!resolved) continue;
				if (
					options?.onlyActiveSessions &&
					resolved.session.expiresAt <= new Date()
				) {
					continue;
				}
				sessions.push(resolved);
			}
			return sessions;
		},
		updateSession: async (
			sessionToken: string,
			session: Partial<Session> & Record<string, any>,
		) => {
			const {
				token: _discardedToken,
				id: _discardedId,
				userId: _discardedUserId,
				...safeSessionUpdate
				} = session;
				const handleSessionId = sessionIdFromHandle(sessionToken);
				const resolved = storesSessionsInDatabase
					? legacyCredentialAuthority
						? await (
								await getCurrentAdapter(adapter)
							).findOne<Session>({
								model: "session",
								where: [{ field: "token", value: sessionToken }],
							})
						: handleSessionId
							? await findSessionRecordById(handleSessionId)
							: await findDatabaseSessionByCredential(sessionToken)
					: null;
			const sessionId =
				handleSessionId ??
				(resolved
					? "session" in resolved
						? resolved.session.id
						: resolved.id
					: undefined);
			if (storesSessionsInDatabase && !sessionId) return null;
			const secondaryKey = secondaryStorage
				? handleSessionId
					? parseSecondaryHandle(
							await secondaryStorage.get(
								secondaryHandleKey(handleSessionId),
							),
						)
					: secondaryCredentialKey(
							await digestSessionRefreshSecret(sessionToken),
						)
				: null;
			const updatedSession = await updateWithHooks<Session>(
				safeSessionUpdate,
				[
					storesSessionsInDatabase
						? { field: "id", value: sessionId! }
						: { field: "token", value: createSessionHandle(sessionId ?? "") },
				],
				"session",
				secondaryStorage
					? {
							async fn(data) {
								if (!secondaryKey) return null;
								const currentSession = await secondaryStorage.get(secondaryKey);
								if (!currentSession) {
									return null;
								}

								const parsedSession = safeJSONParse<{
									session: Session;
									user: User;
								}>(currentSession);
								if (!parsedSession) return null;

								const mergedSession = {
									...parsedSession.session,
									...data,
									expiresAt: new Date(
										data.expiresAt ?? parsedSession.session.expiresAt,
									),
									createdAt: new Date(parsedSession.session.createdAt),
									updatedAt: new Date(
										data.updatedAt ?? parsedSession.session.updatedAt,
									),
								};

								const updatedSession = parseInternalSessionOutput(
									ctx.options,
									mergedSession,
								);

								const now = Date.now();
								const expiresMs = new Date(updatedSession.expiresAt).getTime();
								const sessionTTL = getTTLSeconds(expiresMs, now);

								if (sessionTTL > 0) {
									await secondaryStorage.set(
										secondaryKey,
									JSON.stringify({
										session: { ...updatedSession, token: null },
											user: parsedSession.user,
										}),
										sessionTTL,
									);

									const listKey = secondaryActiveSessionsKey(
										updatedSession.userId,
									);
									const listRaw = await secondaryStorage.get(listKey);
									const list: SecondarySessionIndexEntry[] = listRaw
										? safeJSONParse(listRaw) || []
										: [];

									const filtered = list
										.filter(
											(s) =>
												s.sessionId !== updatedSession.id && s.expiresAt > now,
										)
										.concat([
											{
												sessionId: updatedSession.id,
												credentialKey: secondaryKey,
												expiresAt: expiresMs,
											},
										]);

									const sorted = filtered.sort(
										(a, b) => a.expiresAt - b.expiresAt,
									);
									const furthestSessionExp = sorted.at(-1)?.expiresAt;

									if (furthestSessionExp && furthestSessionExp > now) {
										await secondaryStorage.set(
											listKey,
											JSON.stringify(sorted),
											getTTLSeconds(furthestSessionExp, now),
										);
									} else {
										await secondaryStorage.delete(listKey);
									}
								}

								return updatedSession;
							},
							executeMainFn: options.session?.storeSessionInDatabase,
						}
					: undefined,
				(hookedData) => {
					const {
						id: _hookedId,
						token: _hookedToken,
						userId: _hookedUserId,
						...safeHookedData
					} = hookedData;
					return safeHookedData as Session;
				},
			);
				if (
					storesSessionsInDatabase &&
					!legacyCredentialAuthority &&
					updatedSession &&
					sessionId
				) {
				await (
					await getCurrentAdapter(adapter)
				).updateMany({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "sessionId", value: sessionId }],
					update: {
						expiresAt: updatedSession.expiresAt,
						updatedAt: new Date(),
					},
				});
			}
			return updatedSession
				? {
						...updatedSession,
						token: handleSessionId ? updatedSession.token : sessionToken,
					}
				: null;
			},
			deleteSession: async (token: string) => {
				if (typeof token !== "string" || token.length === 0) return;
				if (legacyCredentialAuthority && storesSessionsInDatabase) {
					await deleteWithHooks(
						[{ field: "token", value: token }],
						"session",
						undefined,
					);
					return;
				}
				const handleSessionId = sessionIdFromHandle(token);
			const databaseSession = storesSessionsInDatabase
				? handleSessionId
					? await findSessionRecordById(handleSessionId)
					: await findDatabaseSessionByCredential(token)
				: null;
			let sessionId =
				handleSessionId ??
				(databaseSession
					? "session" in databaseSession
						? databaseSession.session.id
						: databaseSession.id
					: undefined);
			if (storesSessionsInDatabase && !sessionId && !handleSessionId) {
				sessionId =
					(await findDatabaseSessionIdByCredential(token)) ?? undefined;
			}
			let credentialKey: string | null = null;
			let secondaryUserId = databaseSession
				? "session" in databaseSession
					? databaseSession.session.userId
					: databaseSession.userId
				: undefined;
			let cleanupSecondarySession: (() => Promise<void>) | null = null;
			if (secondaryStorage) {
				credentialKey = handleSessionId
					? parseSecondaryHandle(
							await secondaryStorage.get(
								secondaryHandleKey(handleSessionId),
							),
						)
					: secondaryCredentialKey(await digestSessionRefreshSecret(token));
				const data = credentialKey
					? await secondaryStorage.get(credentialKey)
					: null;
				if (data) {
					const { session } =
						safeJSONParse<{
							session: Session;
							user: User;
						}>(data) ?? {};
					if (!session) {
						logger.error("Session not found in secondary storage");
						return;
					}
					sessionId ??= session.id;
					secondaryUserId = session.userId;
				}

				cleanupSecondarySession = async () => {
					if (secondaryUserId) {
						const currentList = await secondaryStorage.get(
							secondaryActiveSessionsKey(secondaryUserId),
						);
					if (currentList) {
						const list: SecondarySessionIndexEntry[] =
							safeJSONParse(currentList) || [];
						const now = Date.now();

						const filtered = list.filter(
							(session) =>
								session.expiresAt > now && session.sessionId !== sessionId,
						);
						const sorted = filtered.sort((a, b) => a.expiresAt - b.expiresAt);
						const furthestSessionExp = sorted.at(-1)?.expiresAt;

						if (
							filtered.length > 0 &&
							furthestSessionExp &&
							furthestSessionExp > Date.now()
						) {
							await secondaryStorage.set(
								secondaryActiveSessionsKey(secondaryUserId),
								JSON.stringify(filtered),
								getTTLSeconds(furthestSessionExp, now),
							);
						} else {
							await secondaryStorage.delete(
								secondaryActiveSessionsKey(secondaryUserId),
							);
						}
					} else {
						logger.error("Active sessions list not found in secondary storage");
					}
					}

					if (credentialKey) await secondaryStorage.delete(credentialKey);
					if (sessionId) {
						await secondaryStorage.delete(secondaryHandleKey(sessionId));
					}
				};

				if (!options.session?.storeSessionInDatabase) {
					await queueAfterTransactionHook(cleanupSecondarySession);
					return;
				}
			}

			if (sessionId) {
				await runWithTransaction(adapter, () =>
					revokeAndDeleteSessionById(sessionId!),
				);
			}
			if (cleanupSecondarySession) {
				await queueAfterTransactionHook(cleanupSecondarySession);
			}
		},
		deleteSessionById: async (sessionId: string) => {
			await internalAdapter.deleteSession(createSessionHandle(sessionId));
		},
		deleteAccounts: async (userId: string) => {
			await deleteManyWithHooks(
				[
					{
						field: "userId",
						value: userId,
					},
				],
				"account",
				undefined,
			);
		},
		/**
		 * Delete an account by its primary key.
		 *
		 * @param id - The account row's primary key (the `id` column, not the `accountId` column).
		 */
		deleteAccount: async (id: string) => {
			await deleteWithHooks(
				[
					{
						field: "id",
						value: id,
					},
				],
				"account",
				undefined,
			);
		},
		deleteUserSessions: async (userId: string) => {
			const sessions = storesSessionsInDatabase
				? await runWithTransaction(adapter, async () => {
						const currentAdapter = await getCurrentAdapter(adapter);
						const rows = await currentAdapter.findMany<Session>({
							model: "session",
							where: [{ field: "userId", value: userId }],
						});
							for (const session of rows) {
								if (!legacyCredentialAuthority) {
									await revokeCredentialFamiliesBySessionId(session.id);
								}
						}
						if (!ctx.options.session?.preserveSessionInDatabase) {
							await deleteManyWithHooks(
								[{ field: "userId", value: userId }],
								"session",
								undefined,
							);
						}
						return rows;
					})
				: await internalAdapter.listSessions(userId);
			await queueAfterTransactionHook(async () => {
				if (secondaryStorage && storesSessionsInDatabase) {
					for (const session of sessions) {
						const handleKey = secondaryHandleKey(session.id);
						const credentialKey = parseSecondaryHandle(
							await secondaryStorage.get(handleKey),
						);
						if (credentialKey) await secondaryStorage.delete(credentialKey);
						await secondaryStorage.delete(handleKey);
					}
					await secondaryStorage.delete(secondaryActiveSessionsKey(userId));
				}
				if (!storesSessionsInDatabase) {
					for (const session of sessions) {
						await internalAdapter.deleteSession(createSessionHandle(session.id));
					}
					await secondaryStorage?.delete(secondaryActiveSessionsKey(userId));
				}
			});
		},
		revokeUserOAuthTokenFamilies: async (userId: string) => {
			const hasOAuthTokenAuthority = ctx.options.plugins?.some(
				(plugin) => plugin.id === "oidc-provider" || plugin.id === "mcp",
			);
			if (!hasOAuthTokenAuthority) return;
			await runWithTransaction(adapter, async () => {
				const currentAdapter = await getCurrentAdapter(adapter);
				const revokedAt = new Date();
				await currentAdapter.updateMany({
					model: "oauthAccessToken",
					where: [{ field: "userId", value: userId }],
					update: {
						refreshStatus: "revoked",
						revokedAt,
						rotationNonceDigest: null,
						recoveryExpiresAt: null,
						updatedAt: revokedAt,
					},
				});
			});
		},
		deleteSessions: async (sessionTokens: string[]) => {
			await runWithTransaction(adapter, async () => {
				for (const sessionToken of sessionTokens) {
					await internalAdapter.deleteSession(sessionToken);
				}
			});
		},
		findOAuthUser: async (
			email: string,
			accountId: string,
			providerId: string,
		) => {
			// we need to find account first to avoid missing user if the email changed with the provider for the same account
			const account = await (
				await getCurrentAdapter(adapter)
			).findOne<Account & { user: User | null }>({
				model: "account",
				where: [
					{
						value: accountId,
						field: "accountId",
					},
					{
						value: providerId,
						field: "providerId",
					},
				],
				join: {
					user: true,
				},
			});
			if (account) {
				if (account.user) {
					return {
						user: account.user,
						linkedAccount: account,
						accounts: [account],
					};
				} else {
					const user = await (
						await getCurrentAdapter(adapter)
					).findOne<User>({
						model: "user",
						where: [
							{
								value: email.toLowerCase(),
								field: "email",
							},
						],
					});
					if (user) {
						return {
							user,
							linkedAccount: account,
							accounts: [account],
						};
					}
					return null;
				}
			} else {
				const user = await (
					await getCurrentAdapter(adapter)
				).findOne<User>({
					model: "user",
					where: [
						{
							value: email.toLowerCase(),
							field: "email",
						},
					],
				});
				if (user) {
					const accounts = await (
						await getCurrentAdapter(adapter)
					).findMany<Account>({
						model: "account",
						where: [
							{
								value: user.id,
								field: "userId",
							},
						],
					});
					return {
						user,
						linkedAccount: null,
						accounts: accounts || [],
					};
				} else {
					return null;
				}
			}
		},
		findUserByEmail: async (
			email: string,
			options?: { includeAccounts: boolean } | undefined,
		) => {
			const currentAdapter = await getCurrentAdapter(adapter);
			const result = await currentAdapter.findOne<
				User & { account: Account[] | undefined }
			>({
				model: "user",
				where: [
					{
						value: email.toLowerCase(),
						field: "email",
					},
				],
				join: {
					...(options?.includeAccounts ? { account: true } : {}),
				},
			});
			if (!result) return null;
			const { account: accounts, ...user } = result;
			return {
				user,
				accounts: accounts ?? [],
			};
		},
		findUserById: async (userId: string) => {
			if (!userId) return null;
			const user = await (
				await getCurrentAdapter(adapter)
			).findOne<User>({
				model: "user",
				where: [
					{
						field: "id",
						value: userId,
					},
				],
			});
			return user;
		},
		linkAccount: async (
			account: Omit<Account, "id" | "createdAt" | "updatedAt"> &
				Partial<Account>,
		) => {
			const _account = await createWithHooks(
				{
					// todo: we should remove auto setting createdAt and updatedAt in the next major release, since the db generators already handle that
					createdAt: new Date(),
					updatedAt: new Date(),
					...account,
				},
				"account",
				undefined,
			);
			return _account;
		},
		updateUser: async (
			userId: string,
			data: Partial<User> & Record<string, any>,
		) => {
			const user = await updateWithHooks<User>(
				{
					...data,
					...(data.email ? { email: data.email.toLowerCase() } : {}),
				},
				[
					{
						field: "id",
						value: userId,
					},
				],
				"user",
				undefined,
			);
			await refreshUserSessions(user);
			return user;
		},
		updateUserByEmail: async (
			email: string,
			data: Partial<User & Record<string, any>>,
		) => {
			const user = await updateWithHooks<User>(
				{
					...data,
					...(data.email ? { email: data.email.toLowerCase() } : {}),
				},
				[
					{
						field: "email",
						value: email.toLowerCase(),
					},
				],
				"user",
				undefined,
			);
			await refreshUserSessions(user);
			return user;
		},
		updatePassword: async (userId: string, password: string) => {
			await updateManyWithHooks(
				{
					password,
				},
				[
					{
						field: "userId",
						value: userId,
					},
					{
						field: "providerId",
						value: "credential",
					},
				],
				"account",
				undefined,
			);
		},
		findAccounts: async (userId: string) => {
			const accounts = await (
				await getCurrentAdapter(adapter)
			).findMany<Account>({
				model: "account",
				where: [
					{
						field: "userId",
						value: userId,
					},
				],
			});
			return accounts;
		},
		findAccountByProviderId: async (accountId: string, providerId: string) => {
			const account = await (
				await getCurrentAdapter(adapter)
			).findOne<Account>({
				model: "account",
				where: [
					{
						field: "accountId",
						value: accountId,
					},
					{
						field: "providerId",
						value: providerId,
					},
				],
			});
			return account;
		},
		findAccountByUserId: async (userId: string) => {
			const account = await (
				await getCurrentAdapter(adapter)
			).findMany<Account>({
				model: "account",
				where: [
					{
						field: "userId",
						value: userId,
					},
				],
			});
			return account;
		},
		updateAccount: async (id: string, data: Partial<Account>) => {
			const account = await updateWithHooks<Account>(
				data,
				[{ field: "id", value: id }],
				"account",
				undefined,
			);
			return account;
		},
		createVerificationValue: async (
			data: Omit<Verification, "createdAt" | "id" | "updatedAt"> &
				Partial<Verification>,
		) => {
			const storageOption = getStorageOption(
				data.identifier,
				options.verification?.storeIdentifier,
			);
			const storedIdentifier = await processIdentifier(
				data.identifier,
				storageOption,
			);

			const verification = await createWithHooks(
				{
					// todo: we should remove auto setting createdAt and updatedAt in the next major release, since the db generators already handle that
					createdAt: new Date(),
					updatedAt: new Date(),
					...data,
					identifier: storedIdentifier,
				},
				"verification",
				secondaryStorage
					? {
							async fn(verificationData) {
								const ttl = getTTLSeconds(verificationData.expiresAt);
								if (ttl > 0) {
									await secondaryStorage.set(
										`verification:${storedIdentifier}`,
										JSON.stringify(verificationData),
										ttl,
									);
								}
								return verificationData;
							},
							executeMainFn: options.verification?.storeInDatabase,
						}
					: undefined,
			);
			return verification as Verification;
		},
		findVerificationValue: async (identifier: string) => {
			const storageOption = getStorageOption(
				identifier,
				options.verification?.storeIdentifier,
			);
			const storedIdentifier = await processIdentifier(
				identifier,
				storageOption,
			);

			if (secondaryStorage) {
				const cached = await secondaryStorage.get(
					`verification:${storedIdentifier}`,
				);
				if (cached) {
					const parsed = safeJSONParse<Verification>(cached);
					if (parsed) {
						return parsed;
					}
				}
				if (storageOption && storageOption !== "plain") {
					const plainCached = await secondaryStorage.get(
						`verification:${identifier}`,
					);
					if (plainCached) {
						const parsed = safeJSONParse<Verification>(plainCached);
						if (parsed) {
							return parsed;
						}
					}
				}
				if (!options.verification?.storeInDatabase) {
					return null;
				}
			}

			const currentAdapter = await getCurrentAdapter(adapter);

			async function findByIdentifier(id: string) {
				return currentAdapter.findMany<Verification>({
					model: "verification",
					where: [{ field: "identifier", value: id }],
					sortBy: { field: "createdAt", direction: "desc" },
					limit: 1,
				});
			}

			let verification = await findByIdentifier(storedIdentifier);

			if (!verification.length && storageOption && storageOption !== "plain") {
				verification = await findByIdentifier(identifier);
			}

			if (!options.verification?.disableCleanup) {
				await deleteManyWithHooks(
					[
						{
							field: "expiresAt",
							value: new Date(),
							operator: "lt",
						},
					],
					"verification",
					undefined,
				);
			}

			return (verification[0] as Verification) || null;
		},
		deleteVerificationByIdentifier: async (identifier: string) => {
			const storageOption = getStorageOption(
				identifier,
				options.verification?.storeIdentifier,
			);
			const storedIdentifier = await processIdentifier(
				identifier,
				storageOption,
			);

			if (secondaryStorage) {
				await secondaryStorage.delete(`verification:${storedIdentifier}`);
			}

			if (!secondaryStorage || options.verification?.storeInDatabase) {
				await deleteWithHooks(
					[{ field: "identifier", value: storedIdentifier }],
					"verification",
					undefined,
				);
			}
		},
		/**
		 * Atomically consume a single-use verification row by `identifier` and
		 * return it. The first concurrent caller receives the latest row for the
		 * identifier; every other caller racing against it receives `null`.
		 *
		 * Race-safe replacement for the `findVerificationValue` then
		 * `deleteVerificationByIdentifier` pair. Callers MUST gate any state
		 * change (issue session, mint token, change password) on a non-null
		 * return value, because consuming one row invalidates the whole
		 * identifier and stale rows cannot be replayed.
		 *
		 * Rows past their `expiresAt` are treated as already invalid: the row
		 * is still deleted (so it cannot be replayed later) but `null` is
		 * returned. Callers do not need their own `expiresAt` gate.
		 *
		 * The secondary-storage-only path (`storeInDatabase: false`) is atomic
		 * only when the configured storage implements `getAndDelete`; otherwise
		 * it falls back to an in-process lock around `get` then `delete` and
		 * warns once, since that fallback cannot coordinate across processes.
		 *
		 * FIXME(consume-atomic): make `SecondaryStorage.getAndDelete` required
		 * in the next breaking release, or require database-backed verification
		 * storage for security-sensitive consume paths, so the non-atomic
		 * fallback can be removed entirely.
		 */
		consumeVerificationValue: async (
			identifier: string,
		): Promise<Verification | null> => {
			const storageOption = getStorageOption(
				identifier,
				options.verification?.storeIdentifier,
			);
			const storedIdentifier = await processIdentifier(
				identifier,
				storageOption,
			);
			const identifiersToTry =
				storageOption && storageOption !== "plain"
					? [storedIdentifier, identifier]
					: [storedIdentifier];

			// After a JSON round-trip `expiresAt` arrives as a string, so coerce
			// it back to a valid `Date` to match what the DB adapter returns.
			const hydrateCachedVerification = (raw: unknown): Verification | null => {
				if (!raw) return null;
				const candidate =
					typeof raw === "string"
						? safeJSONParse<Verification>(raw)
						: typeof raw === "object"
							? (raw as Verification)
							: null;
				if (!candidate) return null;
				const expiresAt = new Date(candidate.expiresAt);
				if (!Number.isFinite(expiresAt.getTime())) return null;
				return { ...candidate, expiresAt };
			};

			let consumed: Verification | null = null;

			if (secondaryStorage && !options.verification?.storeInDatabase) {
				const consumeCacheKey = async (key: string) => {
					if (secondaryStorage.getAndDelete) {
						return hydrateCachedVerification(
							await secondaryStorage.getAndDelete(key),
						);
					}
					if (!warnedNonAtomicConsume) {
						warnedNonAtomicConsume = true;
						logger.warn(
							"Secondary storage does not implement `getAndDelete`, so single-use verification values cannot be consumed atomically across processes. Implement `getAndDelete` or use database-backed verification storage to guarantee single use.",
						);
					}
					return withVerificationConsumeLock(key, async () => {
						const raw = await secondaryStorage.get(key);
						const parsed = hydrateCachedVerification(raw);
						if (!parsed) return null;
						await secondaryStorage.delete(key);
						return parsed;
					});
				};

				for (const stored of identifiersToTry) {
					const cacheKey = `verification:${stored}`;
					const cached = await consumeCacheKey(cacheKey);
					if (!cached) continue;
					await Promise.all(
						identifiersToTry
							.filter((candidate) => candidate !== stored)
							.map((candidate) =>
								secondaryStorage.delete(`verification:${candidate}`),
							),
					);
					consumed = cached;
					break;
				}
			} else {
				const consumeByIdentifier = async (
					id: string,
				): Promise<Verification | null> =>
					withVerificationConsumeLock(`verification:${id}`, () =>
						runWithTransaction(adapter, async () => {
							const txAdapter = await getCurrentAdapter(adapter);
							const where = [{ field: "identifier", value: id }];
							const rows = await txAdapter.findMany<Verification>({
								model: "verification",
								where,
								sortBy: { field: "createdAt", direction: "desc" },
								limit: 1,
							});
							const latest = rows[0] ?? null;
							if (!latest) return null;

							// FIXME(consume-identifier-atomic): add an adapter primitive that
							// deletes all rows for an identifier and returns the latest row in
							// one operation. Until then, consume the latest row as the race gate
							// and invalidate stale rows inside the same transaction/local lock.
							return consumeOneWithHooks<Verification>(
								"verification",
								[{ field: "id", value: latest.id }],
								async () => {
									const row = await txAdapter.consumeOne<Verification>({
										model: "verification",
										where: [{ field: "id", value: latest.id }],
									});
									if (!row) return null;
									await txAdapter.deleteMany({
										model: "verification",
										where,
									});
									return row;
								},
								latest,
							);
						}),
					);

				for (const stored of identifiersToTry) {
					consumed = await consumeByIdentifier(stored);
					if (consumed) break;
				}

				if (consumed && secondaryStorage) {
					await Promise.all(
						identifiersToTry.map((stored) =>
							secondaryStorage.delete(`verification:${stored}`),
						),
					);
				}
			}

			// Single expiry gate. A row past its `expiresAt` is treated as already
			// invalid, so callers can rely on a non-null return meaning "valid".
			if (!consumed || consumed.expiresAt < new Date()) return null;
			return consumed;
		},
		/**
		 * First-writer-wins create keyed by a deterministic primary key derived
		 * from `identifier`. Returns `true` when this caller created the row and
		 * `false` when a row for the same identifier already existed.
		 *
		 * The dual of `consumeVerificationValue`: where consume races to delete a
		 * marker exactly once, reserve races to create a marker exactly once. Use
		 * it for replay tombstones (a SAML assertion id, a JWT `jti`) where the
		 * first caller wins and every later caller must observe that the marker is
		 * already taken.
		 *
		 * The `verification.identifier` column is non-unique, so uniqueness comes
		 * from a deterministic primary key (`SHA-256` of `reserve:<identifier>`).
		 * The database path is atomic: the primary key turns the INSERT into the
		 * first-writer-wins gate, and a duplicate is detected portably by
		 * re-reading the row rather than matching adapter-specific errors. The
		 * secondary-storage-only path has no primary key to enforce uniqueness, so
		 * it is best-effort under concurrency.
		 *
		 * The atomic guarantee requires the configured adapter to reject a
		 * duplicate primary key on insert, which every real database enforces. The
		 * in-memory adapter does not enforce primary-key uniqueness, so reservation
		 * is best-effort there (it is intended for development and tests).
		 */
		reserveVerificationValue: async (data: {
			identifier: string;
			value: string;
			expiresAt: Date;
		}): Promise<boolean> => {
			const reservationId = base64Url.encode(
				new Uint8Array(
					await createHash("SHA-256").digest(
						new TextEncoder().encode("reserve:" + data.identifier),
					),
				),
				{ padding: false },
			);
			const storageOption = getStorageOption(
				data.identifier,
				options.verification?.storeIdentifier,
			);
			const storedIdentifier = await processIdentifier(
				data.identifier,
				storageOption,
			);

			if (secondaryStorage && !options.verification?.storeInDatabase) {
				// Best-effort under concurrency: without a database primary key there
				// is no first-writer-wins gate, so two callers racing a get-then-set
				// can both observe an empty key and both win (mirrors the non-atomic
				// secondary fallback in consumeVerificationValue).
				// FIXME(reserve-secondary-atomic): require an atomic conditional set
				// (set-if-absent) on SecondaryStorage, or require database-backed
				// verification storage for reservations, so this path can guarantee
				// first-writer-wins across processes.
				const cacheKey = `verification:${storedIdentifier}`;
				const existing = await secondaryStorage.get(cacheKey);
				if (existing) return false;
				await secondaryStorage.set(
					cacheKey,
					JSON.stringify({
						id: reservationId,
						identifier: storedIdentifier,
						value: data.value,
						expiresAt: data.expiresAt,
					}),
					getTTLSeconds(data.expiresAt),
				);
				return true;
			}

			try {
				await adapter.create({
					model: "verification",
					data: {
						id: reservationId,
						identifier: storedIdentifier,
						value: data.value,
						expiresAt: data.expiresAt,
						createdAt: new Date(),
						updatedAt: new Date(),
					},
					forceAllowId: true,
				});
			} catch (error) {
				// A create error is ambiguous across adapters: confirm it was a
				// duplicate (the row exists) rather than a real failure before
				// reporting "lost".
				const existing = await adapter.findOne<Verification>({
					model: "verification",
					where: [{ field: "id", value: reservationId }],
				});
				if (existing) return false;
				throw error;
			}

			if (secondaryStorage) {
				const ttl = getTTLSeconds(data.expiresAt);
				if (ttl > 0) {
					await secondaryStorage.set(
						`verification:${storedIdentifier}`,
						JSON.stringify({
							id: reservationId,
							identifier: storedIdentifier,
							value: data.value,
							expiresAt: data.expiresAt,
						}),
						ttl,
					);
				}
			}

			return true;
		},
		updateVerificationByIdentifier: async (
			identifier: string,
			data: Partial<Verification>,
		) => {
			const storageOption = getStorageOption(
				identifier,
				options.verification?.storeIdentifier,
			);
			const storedIdentifier = await processIdentifier(
				identifier,
				storageOption,
			);

			if (secondaryStorage) {
				const cached = await secondaryStorage.get(
					`verification:${storedIdentifier}`,
				);
				if (cached) {
					const parsed = safeJSONParse<Verification>(cached);
					if (parsed) {
						const updated = { ...parsed, ...data };
						const expiresAt = updated.expiresAt ?? parsed.expiresAt;
						const ttl = getTTLSeconds(
							expiresAt instanceof Date ? expiresAt : new Date(expiresAt),
						);
						if (ttl > 0) {
							await secondaryStorage.set(
								`verification:${storedIdentifier}`,
								JSON.stringify(updated),
								ttl,
							);
						}
						if (!options.verification?.storeInDatabase) {
							return updated;
						}
					}
				}
			}

			if (!secondaryStorage || options.verification?.storeInDatabase) {
				const verification = await updateWithHooks<Verification>(
					data,
					[{ field: "identifier", value: storedIdentifier }],
					"verification",
					undefined,
				);
				return verification;
			}
			return data as Verification;
		},
		refreshUserSessions,
	};
	return internalAdapter;
};
