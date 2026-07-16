import type {
	AuthContext,
	ClearanceOptions,
	InternalAdapter,
	SessionIssuanceContext,
} from "@clearance/core";
import {
	getCurrentAdapter,
	getCurrentAuthContext,
	isTransactionActive,
	queueAfterTransactionHook,
	queueBeforeTransactionCommitHook,
	runWithTransaction,
} from "@clearance/core/context";
import type {
	DBAdapter,
	DBTransactionAdapter,
	Where,
} from "@clearance/core/db/adapter";
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
import {
	readInternalAuthenticationPolicy,
	resolveRuntimeAuthenticationPolicy,
} from "../internal/authentication-policy";
import {
	ManagedSessionIssuanceError,
	requireInternalSessionIssuanceContext,
} from "../internal/session-issuance-context";
import {
	evaluateSessionIssuance,
	SESSION_ASSURANCE_RESERVED_FIELDS,
	stripReservedSessionAuthority,
	type SessionAssuranceFields,
	validateStoredSessionAssurance,
} from "../security/session-assurance";

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
	const authenticationPolicy = readInternalAuthenticationPolicy(options);
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
		Boolean(authenticationPolicy) ||
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
		parentCredential: SessionCredential;
		successorCredential: SessionCredential;
	};
	const recoveryCredentialRejected = Symbol("recovery-credential-rejected");
	type SessionRecoveryAttempt =
		| SessionRotationResult
		| typeof recoveryCredentialRejected
		| null;
	class ManagedSessionUpdateRejected extends Error {}
	class ManagedSessionRotationRejected extends Error {}

	const sessionMatchesSecurityGenerations = (
		session: Record<string, unknown>,
		user: Record<string, unknown>,
	) =>
		(!bindsTwoFactorSessionGeneration ||
			sessionMatchesTwoFactorGeneration(session, user)) &&
		(!bindsPasskeySessionGeneration ||
			sessionMatchesPasskeyGeneration(session, user));

	async function validateRawSessionAuthority(
		session: Record<string, unknown>,
		user: User & Record<string, unknown>,
		allowExpiredSession = false,
	): Promise<boolean> {
		if (
			(user as User & { banned?: boolean | null }).banned === true ||
			!sessionMatchesSecurityGenerations(session, user)
		) {
			return false;
		}
		if (!authenticationPolicy) {
			const now = new Date();
			return (
				session.expiresAt instanceof Date &&
				Number.isFinite(session.expiresAt.getTime()) &&
				session.expiresAt > now
			);
		}

		const storedOrganizationId = session.authenticationPolicyOrganizationId;
		if (
			storedOrganizationId !== null &&
			(typeof storedOrganizationId !== "string" ||
				storedOrganizationId.length === 0 ||
				storedOrganizationId.length > 1_024 ||
				storedOrganizationId.trim() !== storedOrganizationId ||
				storedOrganizationId.includes("\0"))
		) {
			return false;
		}
		const organizationId = storedOrganizationId as string | null;
		const activeOrganizationId = session.activeOrganizationId;
		if (
			activeOrganizationId !== null &&
			activeOrganizationId !== undefined &&
			(typeof activeOrganizationId !== "string" ||
				activeOrganizationId !== organizationId)
		) {
			return false;
		}

		const resolvedPolicy = await resolveRuntimeAuthenticationPolicy(options, {
			subjectId: user.id,
			...(organizationId ? { organizationId } : {}),
			transaction: await getCurrentAdapter(adapter),
		});
		const now = new Date();
		if (
			!(session.expiresAt instanceof Date) ||
			!Number.isFinite(session.expiresAt.getTime()) ||
			(!allowExpiredSession && session.expiresAt <= now)
		) {
			return false;
		}
		return (
			validateStoredSessionAssurance({
				stored: session,
				policy: {
					identity: resolvedPolicy.scope,
					organizationId,
					revision: resolvedPolicy.revision,
					policy: resolvedPolicy.effective,
				},
				now,
			}).kind === "accepted"
		);
	}

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

	type ValidatedSessionAuthority = {
		session: Session & Record<string, unknown>;
		user: User & Record<string, unknown>;
	};

	async function loadValidatedSessionAuthority(
		sessionId: string,
		allowExpiredSession = false,
	): Promise<ValidatedSessionAuthority | null> {
		const record = await findSessionRecordById(sessionId);
		if (!record?.user) return null;
		const activeUser = await lockAndReadActiveUser(
			await getCurrentAdapter(adapter),
			record.user.id,
		);
		if (!activeUser) return null;
		const { user: _, ...session } = record;
		if (
			!(await validateRawSessionAuthority(
				session as Record<string, unknown>,
				activeUser as User & Record<string, unknown>,
				allowExpiredSession,
			))
		) {
			return null;
		}
		return {
			session: session as Session & Record<string, unknown>,
			user: activeUser as User & Record<string, unknown>,
		};
	}

	type ManagedSessionUpdateAuthority = ValidatedSessionAuthority & {
		credential: SessionCredential | null;
	};

	async function findUniqueFutureActiveCredential(
		sessionId: string,
		expected?: SessionCredential,
		requireFuture = true,
	): Promise<SessionCredential | null> {
		const now = new Date();
		const active = await (
				await getCurrentAdapter(adapter)
			).findMany<SessionCredential>({
				model: SESSION_CREDENTIAL_MODEL,
				where: [
					{ field: "sessionId", value: sessionId },
					{ field: "status", value: "active" },
				],
			});
		if (
			active.length !== 1 ||
			(requireFuture && active[0]!.expiresAt <= now)
		) {
			return null;
		}
		if (expected && active[0]!.id !== expected.id) return null;
		return expected
			? requireFuture
				? rereadActiveCredential(expected)
				: rereadExactCredential(expected)
			: (active[0] ?? null);
	}

	async function resolveManagedSessionUpdateAuthority(
		presentedToken: string,
		allowExpired = false,
	): Promise<ManagedSessionUpdateAuthority | null> {
		const currentAdapter = await getCurrentAdapter(adapter);
		const handleSessionId = sessionIdFromHandle(presentedToken);
		let credential: SessionCredential | null = null;
		let sessionId = handleSessionId;
		if (!legacyCredentialAuthority) {
			if (handleSessionId) {
				credential = await findUniqueFutureActiveCredential(
					handleSessionId,
					undefined,
					!allowExpired,
				);
			} else {
				const digest = await digestSessionRefreshSecret(presentedToken);
				const credentialId = credentialIdFromRefreshSecret(presentedToken);
				credential = credentialId
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
					!constantTimeEqual(credential.secretDigest, digest)
				) {
					return null;
				}
				sessionId = credential.sessionId ?? null;
			}
			if (!credential || !sessionId) return null;
			credential = await findUniqueFutureActiveCredential(
				sessionId,
				credential,
				!allowExpired,
			);
			if (!credential) return null;
		}
		if (!sessionId) {
			const legacy = await currentAdapter.findOne<Session>({
				model: "session",
				where: [{ field: "token", value: presentedToken }],
			});
			sessionId = legacy?.id ?? null;
		}
		if (!sessionId) return null;
		const authority = await loadValidatedSessionAuthority(
			sessionId,
			allowExpired,
		);
		if (!authority) return null;
		if (credential) {
			const currentCredential = await findUniqueFutureActiveCredential(
				sessionId,
				credential,
				!allowExpired,
			);
			if (!currentCredential || currentCredential.sessionId !== sessionId) {
				return null;
			}
			credential = currentCredential;
		}
		return { ...authority, credential };
	}

	const immutableSessionUpdateFields = (
		stored: Record<string, unknown>,
	): Record<string, unknown> => {
		const immutable: Record<string, unknown> = {};
		for (const field of [
			"id",
			"token",
			"userId",
			TWO_FACTOR_SESSION_GENERATION_FIELD,
			PASSKEY_SESSION_GENERATION_FIELD,
			...SESSION_ASSURANCE_RESERVED_FIELDS,
		]) {
			if (Object.hasOwn(stored, field)) immutable[field] = stored[field];
		}
		return immutable;
	};

	const stripSessionUpdateAuthority = (
		input: Record<string, unknown>,
	): Record<string, unknown> => {
		const stripped = stripReservedSessionAuthority(input);
		for (const field of [
			"id",
			"token",
			"userId",
			TWO_FACTOR_SESSION_GENERATION_FIELD,
			PASSKEY_SESSION_GENERATION_FIELD,
		]) {
			delete stripped[field];
		}
		return stripped;
	};

	const sameImmutableSessionAuthority = (
		left: Record<string, unknown>,
		right: Record<string, unknown>,
	): boolean => {
		for (const field of [
			"id",
			"token",
			"userId",
			TWO_FACTOR_SESSION_GENERATION_FIELD,
			PASSKEY_SESSION_GENERATION_FIELD,
			...SESSION_ASSURANCE_RESERVED_FIELDS,
		]) {
			const leftValue = left[field];
			const rightValue = right[field];
			if (leftValue instanceof Date && rightValue instanceof Date) {
				if (leftValue.getTime() !== rightValue.getTime()) return false;
			} else if (leftValue !== rightValue) {
				return false;
			}
		}
		return true;
	};

	const managedOrganizationUpdateAllowed = (
		update: Record<string, unknown>,
		stored: Record<string, unknown>,
	): boolean => {
		if (!Object.hasOwn(update, "activeOrganizationId")) return true;
		const requested = update.activeOrganizationId;
		if (requested === null) return true;
		if (typeof requested !== "string" || requested.length === 0) return false;
		return (
			requested === stored.activeOrganizationId ||
			requested === stored.authenticationPolicyOrganizationId
		);
	};

	async function publishSecondarySessionUpdate(input: {
		session: Session & Record<string, unknown>;
		user: User & Record<string, unknown>;
		credentialKey: string;
		previousCredentialKeys?: readonly string[] | undefined;
	}): Promise<void> {
		if (!secondaryStorage) return;
		const credentialKey = input.credentialKey;
		const handleKey = secondaryHandleKey(input.session.id);
		const oldCredentialKey = parseSecondaryHandle(
			await secondaryStorage.get(handleKey),
		);
		const listKey = secondaryActiveSessionsKey(input.session.userId);
		const now = Date.now();
		const expiresAt = input.session.expiresAt.getTime();
		const ttl = getTTLSeconds(expiresAt, now);
		const listRaw = await secondaryStorage.get(listKey);
		const list: SecondarySessionIndexEntry[] = listRaw
			? safeJSONParse(listRaw) || []
			: [];
		const remaining = list.filter(
			(entry) =>
				entry.sessionId !== input.session.id && entry.expiresAt > now,
		);
		const deleteOwnedPreviousCredentials = async () => {
			for (const previousCredentialKey of new Set([
				oldCredentialKey,
				...(input.previousCredentialKeys ?? []),
			])) {
				if (
					previousCredentialKey &&
					previousCredentialKey !== credentialKey &&
					(await secondaryCredentialBelongsToSession(
						previousCredentialKey,
						input.session.id,
					))
				) {
					await secondaryStorage.delete(previousCredentialKey);
				}
			}
		};
		if (ttl > 0) {
			const next = [
				...remaining,
				{
					sessionId: input.session.id,
					credentialKey,
					expiresAt,
				},
			].sort((left, right) => left.expiresAt - right.expiresAt);
			await secondaryStorage.set(
				credentialKey,
				JSON.stringify({
					session: { ...input.session, token: null },
					user: input.user,
				}),
				ttl,
			);
			await secondaryStorage.set(
				handleKey,
				JSON.stringify({ credentialKey }),
				ttl,
			);
			const indexTTL = getTTLSeconds(next.at(-1)!.expiresAt, now);
			if (indexTTL <= 0) {
				await secondaryStorage.delete(listKey);
				return;
			}
			await secondaryStorage.set(
				listKey,
				JSON.stringify(next),
				indexTTL,
			);
			await deleteOwnedPreviousCredentials();
			return;
		}
		await secondaryStorage.delete(credentialKey);
		await deleteOwnedPreviousCredentials();
		await secondaryStorage.delete(handleKey);
		if (remaining.length > 0) {
			const indexTTL = getTTLSeconds(remaining.at(-1)!.expiresAt, now);
			if (indexTTL <= 0) {
				await secondaryStorage.delete(listKey);
				return;
			}
			await secondaryStorage.set(
				listKey,
				JSON.stringify(remaining),
				indexTTL,
			);
		} else {
			await secondaryStorage.delete(listKey);
		}
	}

	async function secondaryCredentialBelongsToSession(
		credentialKey: string,
		sessionId: string,
	): Promise<boolean> {
		if (!secondaryStorage) return false;
		const envelope = safeJSONParse<{ session?: { id?: unknown } }>(
			await secondaryStorage.get(credentialKey),
		);
		return envelope?.session?.id === sessionId;
	}

	async function cleanupInvalidManagedSessionSecondary(input: {
		sessionId: string;
		userId: string;
		expectedCredentialKeys: readonly string[];
	}): Promise<void> {
		if (!secondaryStorage) return;
		const handleKey = secondaryHandleKey(input.sessionId);
		const mappedCredentialKey = parseSecondaryHandle(
			await secondaryStorage.get(handleKey),
		);
		for (const credentialKey of new Set([
			...input.expectedCredentialKeys,
			mappedCredentialKey,
		])) {
			if (
				credentialKey &&
				(await secondaryCredentialBelongsToSession(
					credentialKey,
					input.sessionId,
				))
			) {
				await secondaryStorage.delete(credentialKey);
			}
		}
		await secondaryStorage.delete(handleKey);
		const listKey = secondaryActiveSessionsKey(input.userId);
		const list = safeJSONParse<SecondarySessionIndexEntry[]>(
			await secondaryStorage.get(listKey),
		);
		if (!Array.isArray(list)) return;
		const remaining = list.filter(
			(entry) => entry.sessionId !== input.sessionId,
		);
		if (remaining.length === list.length) return;
		if (remaining.length === 0) {
			await secondaryStorage.delete(listKey);
			return;
		}
		const ttl = getTTLSeconds(
			Math.max(...remaining.map((entry) => entry.expiresAt)),
		);
		if (ttl > 0) {
			await secondaryStorage.set(listKey, JSON.stringify(remaining), ttl);
		} else {
			await secondaryStorage.delete(listKey);
		}
	}

	type ManagedSessionPublicationExpectation = {
		session: Session & Record<string, unknown>;
		userId: string;
		credentialAnchors: readonly SessionCredential[];
		expectedCredentialKeys: readonly string[];
		allowExpiredSession?: boolean;
	};
	const isValidSessionCredentialDigest = (value: unknown): value is string =>
		typeof value === "string" &&
		new RegExp(
			`^v${SESSION_CREDENTIAL_DIGEST_VERSION}:[A-Za-z0-9_-]{43}$`,
		).test(value);

	async function findCanonicalManagedCredentialLineage(input: {
		session: Session & Record<string, unknown>;
		credentialAnchors: readonly SessionCredential[];
		allowExpiredSession?: boolean;
		credentials?: readonly SessionCredential[];
	}): Promise<{
		active: SessionCredential;
		consumed: SessionCredential[];
	} | null> {
		const all = input.credentials
			? [...input.credentials]
			: await (
					await getCurrentAdapter(adapter)
				).findMany<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "sessionId", value: input.session.id }],
				});
		if (
			legacyCredentialAuthority ||
			input.credentialAnchors.length === 0 ||
			!(input.session.expiresAt instanceof Date)
		) {
			return null;
		}
		const expiresAt = input.session.expiresAt.getTime();
		const byId = new Map(all.map((credential) => [credential.id, credential]));
		for (const expected of input.credentialAnchors) {
			const current = byId.get(expected.id);
			if (
				!current ||
				current.selector !== expected.selector ||
				current.sessionId !== expected.sessionId ||
				current.familyId !== expected.familyId ||
				current.parentCredentialId !== expected.parentCredentialId ||
				current.rotationCounter !== expected.rotationCounter ||
				current.digestVersion !== expected.digestVersion ||
				!constantTimeEqual(current.secretDigest, expected.secretDigest) ||
				current.status === "revoked" ||
				(expected.status === "consumed" && current.status !== "consumed")
			) {
				return null;
			}
		}
		if (
			all.length === 0 ||
			all.some(
				(credential) =>
					credential.sessionId !== input.session.id ||
					credential.digestVersion !== SESSION_CREDENTIAL_DIGEST_VERSION ||
					typeof credential.selector !== "string" ||
					credential.selector.length === 0 ||
					typeof credential.secretDigest !== "string" ||
					credential.secretDigest.length === 0 ||
					(credential.status !== "active" &&
						credential.status !== "consumed") ||
					credential.expiresAt.getTime() !== expiresAt,
			)
		) {
			return null;
		}
		const active = all.filter(
			(credential) =>
				credential.status === "active" &&
				(input.allowExpiredSession || credential.expiresAt > new Date()),
		);
		if (active.length !== 1) return null;
		const chain: SessionCredential[] = [];
		const visited = new Set<string>();
		let child = active[0]!;
		while (true) {
			if (visited.has(child.id)) return null;
			visited.add(child.id);
			chain.push(child);
			if (child.parentCredentialId == null) {
				if (child.rotationCounter !== 0) return null;
				break;
			}
			const parent = byId.get(child.parentCredentialId);
			if (
				!parent ||
				parent.status !== "consumed" ||
				parent.sessionId !== child.sessionId ||
				parent.familyId !== child.familyId ||
				child.rotationCounter !== parent.rotationCounter + 1
			) {
				return null;
			}
			child = parent;
		}
		if (chain.length !== all.length) return null;
		return {
			active: active[0]!,
			consumed: chain.filter((credential) => credential.status === "consumed"),
		};
	}

	async function publishManagedSessionAfterCommit(
		expectation: ManagedSessionPublicationExpectation,
	): Promise<void> {
		if (!secondaryStorage) return;
		await runWithTransaction(adapter, async () => {
			const currentAdapter = await getCurrentAdapter(adapter);
			const activeUser = await lockAndReadActiveUser(
				currentAdapter,
				expectation.userId,
			);
			const record = await findSessionRecordById(expectation.session.id);
			let authority: ValidatedSessionAuthority | null = null;
			if (activeUser && record?.user?.id === activeUser.id) {
				const { user: _, ...session } = record;
				if (
					sameImmutableSessionAuthority(session, expectation.session) &&
					(await validateRawSessionAuthority(
						session as Record<string, unknown>,
						activeUser as User & Record<string, unknown>,
						expectation.allowExpiredSession,
					))
				) {
					authority = {
						session: session as Session & Record<string, unknown>,
						user: activeUser as User & Record<string, unknown>,
					};
				}
			}
			const credentials = await currentAdapter.findMany<SessionCredential>({
				model: SESSION_CREDENTIAL_MODEL,
				where: [{ field: "sessionId", value: expectation.session.id }],
			});
			const discoveredCredentialKeys = credentials
				.filter((credential) =>
					isValidSessionCredentialDigest(credential.secretDigest),
				)
				.map((credential) =>
					secondaryCredentialKey(credential.secretDigest),
				);

			let credentialKey: string | null = null;
			let previousCredentialKeys: string[] = [];
			if (authority && legacyCredentialAuthority) {
				const token = authority.session.token;
				if (
					credentials.length === 0 &&
					typeof token === "string" &&
					token.length > 0
				) {
					credentialKey = secondaryCredentialKey(
						await digestSessionRefreshSecret(token),
					);
				}
			} else if (authority) {
				const lineage = await findCanonicalManagedCredentialLineage({
					session: authority.session,
					credentialAnchors: expectation.credentialAnchors,
					allowExpiredSession: expectation.allowExpiredSession,
					credentials,
				});
				if (lineage) {
					credentialKey = secondaryCredentialKey(lineage.active.secretDigest);
					previousCredentialKeys = lineage.consumed.map((credential) =>
						secondaryCredentialKey(credential.secretDigest),
					);
				}
			}

			if (authority && credentialKey) {
				await publishSecondarySessionUpdate({
					...authority,
					credentialKey,
					previousCredentialKeys,
				});
				return;
			}

			await cleanupInvalidManagedSessionSecondary({
				sessionId: expectation.session.id,
				userId: expectation.userId,
				expectedCredentialKeys: [
					...expectation.expectedCredentialKeys,
					...discoveredCredentialKeys,
				],
			});
			throw new Error("Managed session publication authority is invalid");
		});
	}

	async function allSessionCredentialExpiriesMatch(
		transactionAdapter: DBTransactionAdapter,
		sessionId: string,
		expiresAt: Date,
	): Promise<boolean> {
		const credentials = await transactionAdapter.findMany<SessionCredential>({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "sessionId", value: sessionId }],
		});
		return (
			credentials.length > 0 &&
			credentials.every(
				(credential) =>
					credential.expiresAt.getTime() === expiresAt.getTime(),
			)
		);
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

	async function rereadExactCredential(
		expected: SessionCredential,
	): Promise<SessionCredential | null> {
		const current = await (
			await getCurrentAdapter(adapter)
		).findOne<SessionCredential>({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "id", value: expected.id }],
		});
		if (
			!current ||
			current.sessionId !== expected.sessionId ||
			current.familyId !== expected.familyId ||
			current.rotationCounter !== expected.rotationCounter ||
			current.parentCredentialId !== expected.parentCredentialId ||
			!constantTimeEqual(current.secretDigest, expected.secretDigest)
		) {
			return null;
		}
		return current;
	}

	async function rereadActiveCredential(
		expected: SessionCredential,
	): Promise<SessionCredential | null> {
		const current = await rereadExactCredential(expected);
		const now = new Date();
		return current?.status === "active" && current.expiresAt > now
			? current
			: null;
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
		validatedAuthority?: ValidatedSessionAuthority,
	): Promise<SessionRecoveryAttempt> {
		if (credential.status !== "consumed" || !credential.sessionId) return null;
		const authority =
			validatedAuthority ??
			(await loadValidatedSessionAuthority(credential.sessionId));
		if (!authority) return null;

		const readRecoveryCredentials = async (): Promise<
			| {
					parent: SessionCredential;
					successor: SessionCredential;
			  }
			| typeof recoveryCredentialRejected
			| null
		> => {
			const parent = await rereadExactCredential(credential);
			if (!parent || parent.status !== "consumed") {
				return recoveryCredentialRejected;
			}
			if (!parent.rotationNonceDigest) return recoveryCredentialRejected;
			if (!constantTimeEqual(parent.rotationNonceDigest, rotationNonceDigest)) {
				return null;
			}
			const now = new Date();
			if (
				parent.expiresAt <= now ||
				!parent.recoveryExpiresAt ||
				parent.recoveryExpiresAt <= now
			) {
				return recoveryCredentialRejected;
			}
			const successor = await (
				await getCurrentAdapter(adapter)
			).findOne<SessionCredential>({
				model: SESSION_CREDENTIAL_MODEL,
				where: [{ field: "parentCredentialId", value: parent.id }],
			});
			if (
				!successor ||
				successor.status !== "active" ||
				successor.sessionId !== parent.sessionId ||
				successor.familyId !== parent.familyId ||
				successor.rotationCounter !== parent.rotationCounter + 1 ||
				!successor.secretDigest ||
				successor.expiresAt.getTime() !== parent.expiresAt.getTime() ||
				parent.expiresAt.getTime() !== authority.session.expiresAt.getTime()
			) {
				return recoveryCredentialRejected;
			}
			if (successor.expiresAt <= new Date()) {
				return recoveryCredentialRejected;
			}
			return { parent, successor };
		};

		const initialCredentials = await readRecoveryCredentials();
		if (
			!initialCredentials ||
			initialCredentials === recoveryCredentialRejected
		) {
			return initialCredentials;
		}
		const candidates = await deriveRotationSuccessors(
			initialCredentials.parent,
			rotationOperation,
		);
		const currentCredentials = await readRecoveryCredentials();
		if (
			!currentCredentials ||
			currentCredentials === recoveryCredentialRejected
		) {
			return currentCredentials;
		}
		const recovered = candidates.find((candidate) =>
			constantTimeEqual(
				currentCredentials.successor.secretDigest,
				candidate.digest,
			),
		);
		if (!recovered) return recoveryCredentialRejected;
		return {
			session: { ...authority.session, token: recovered.refreshToken },
			user: authority.user,
			refreshToken: recovered.refreshToken,
			familyId: currentCredentials.parent.familyId,
			rotationCounter: currentCredentials.successor.rotationCounter,
			oldDigest,
			successorDigest: recovered.digest,
			parentCredential: currentCredentials.parent,
			successorCredential: currentCredentials.successor,
		};
	}

	async function queueManagedRotationPublication(
		rotation: SessionRotationResult,
	): Promise<void> {
		if (!secondaryStorage) return;
		await queueAfterTransactionHook(
			() =>
				publishManagedSessionAfterCommit({
					session: {
						...rotation.session,
						token: createSessionHandle(rotation.session.id),
					},
					userId: rotation.session.userId,
					credentialAnchors: [
						rotation.parentCredential,
						rotation.successorCredential,
					],
					expectedCredentialKeys: [
						secondaryCredentialKey(rotation.oldDigest),
						secondaryCredentialKey(rotation.successorDigest),
					],
				}),
			adapter,
		);
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
			issuanceContext?: SessionIssuanceContext | undefined,
		) => {
			const managedIssuanceContext = authenticationPolicy
				? requireInternalSessionIssuanceContext(issuanceContext)
				: undefined;
			if (
				(managedIssuanceContext?.purpose === "interactive" ||
					managedIssuanceContext?.purpose === "impersonation") &&
				managedIssuanceContext.subjectId !== userId
			) {
				throw new ManagedSessionIssuanceError("subject_mismatch");
			}
			if (
				managedIssuanceContext?.purpose === "replacement" ||
				managedIssuanceContext?.purpose === "device"
			) {
				throw new ManagedSessionIssuanceError("unsupported_purpose");
			}
			const supportedManagedIssuanceContext =
				managedIssuanceContext?.purpose === "interactive" ||
				managedIssuanceContext?.purpose === "impersonation"
					? managedIssuanceContext
					: undefined;
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
			const safeOverride = stripReservedSessionAuthority(
				(override ?? {}) as Record<string, unknown>,
			);
			const {
				// Authority and identity fields are always derived by the runtime.
				id: _discardedId,
				token: _discardedToken,
				userId: _discardedUserId,
				[PASSKEY_SESSION_GENERATION_FIELD]: _discardedPasskeySessionGeneration,
				__preserveSessionExpiresAt,
				...rest
			} = safeOverride;

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
			const defaultAdditionalFields = stripReservedSessionAuthority(
				getSessionDefaultFields(options),
			);
			const policyExpiresAt = dontRememberMe
				? getDate(60 * 60 * 24, "sec")
				: getDate(sessionExpiration, "sec");
			const inheritedExpiresAt = new Date(
				(rest.expiresAt as string | number | Date | undefined) ?? Number.NaN,
			);
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
				assuranceFields?: SessionAssuranceFields,
			): T => {
				const {
					id: _hookedId,
					token: _hookedToken,
					userId: _hookedUserId,
					[TWO_FACTOR_SESSION_GENERATION_FIELD]: _hookedTwoFactorSessionGeneration,
					[PASSKEY_SESSION_GENERATION_FIELD]: _hookedPasskeySessionGeneration,
					...unsafeHookedData
				} = hookedData;
				const safeHookedData = stripReservedSessionAuthority(
					unsafeHookedData,
				);
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
					...(assuranceFields ?? {}),
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
				let assuranceFields: SessionAssuranceFields | undefined;
				if (authenticationPolicy && supportedManagedIssuanceContext) {
					const targetOrganizationId =
						supportedManagedIssuanceContext.targetOrganizationId ?? undefined;
					const resolvedPolicy = await resolveRuntimeAuthenticationPolicy(
						options,
						{
							subjectId: userId,
							...(targetOrganizationId
								? { organizationId: targetOrganizationId }
								: {}),
							transaction: currentAdapter,
						},
					);
					const evaluation = evaluateSessionIssuance({
						purpose: supportedManagedIssuanceContext.purpose,
						policy: {
							identity: resolvedPolicy.scope,
							organizationId: targetOrganizationId ?? null,
							revision: resolvedPolicy.revision,
							policy: resolvedPolicy.effective,
						},
						now: new Date(),
						evidence: supportedManagedIssuanceContext.evidence,
					});
					if (evaluation.kind !== "satisfied") {
						throw new ManagedSessionIssuanceError("policy_unsatisfied", {
							requirement: evaluation.requirement,
						});
					}
					assuranceFields = evaluation.fields;
				}
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
					? async (
							sessionData: Record<string, any>,
							transactionAdapter: DBTransactionAdapter,
						) => {
							const currentUser = await transactionAdapter.findOne<User>({
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
							return transactionAdapter.create<Record<string, any>>({
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
									usesTransactionAdapter: true,
								}
							: undefined,
					(hookedData) =>
						enforceSessionAuthority(
							hookedData,
							twoFactorSessionGeneration,
							passkeySessionGeneration,
							assuranceFields,
						),
				);
				if (!res) {
					throw new Error("Session creation was rejected by a database hook");
				}
				let expectedCredential: SessionCredential | null = null;
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
					expectedCredential = await createCredentialRecord({
						...credentialIdentity,
						sessionId: persistedSessionId,
						familyId,
						secretDigest: refreshDigest,
						expiresAt,
					});
				}
				if (authenticationPolicy && storesSessionsInDatabase) {
					const persistedSessionId = String((res as Session).id);
					const issuedRecord = await findSessionRecordById(persistedSessionId);
					if (!issuedRecord?.user) {
						throw new ManagedSessionIssuanceError("policy_unsatisfied");
					}
					const { user: _, ...issuedSession } = issuedRecord;
					const issuedAuthority = issuedSession as Session &
						Record<string, unknown>;
					const issuedExpiry = issuedAuthority.expiresAt;
					await queueBeforeTransactionCommitHook(async () => {
						const currentAdapter = await getCurrentAdapter(adapter);
						const activeUser = await lockAndReadActiveUser(
							currentAdapter,
							userId,
						);
						const finalRecord = await findSessionRecordById(persistedSessionId);
						const { user: _finalUser, ...finalSessionData } = finalRecord ?? {};
						const finalSession = finalSessionData as Session &
							Record<string, unknown>;
						if (
							!activeUser ||
							finalRecord?.user?.id !== activeUser.id ||
							!(await validateRawSessionAuthority(
								finalSession,
								activeUser as User & Record<string, unknown>,
							)) ||
							!sameImmutableSessionAuthority(finalSession, issuedAuthority) ||
							!(issuedExpiry instanceof Date) ||
							!(finalSession.expiresAt instanceof Date) ||
							finalSession.expiresAt.getTime() !== issuedExpiry.getTime()
						) {
							throw new ManagedSessionIssuanceError("policy_unsatisfied");
						}
						let expectedCredentialKeys: string[];
						if (legacyCredentialAuthority) {
							const credentials =
								await currentAdapter.findMany<SessionCredential>({
									model: SESSION_CREDENTIAL_MODEL,
									where: [
										{ field: "sessionId", value: persistedSessionId },
									],
								});
							if (
								credentials.length !== 0 ||
								typeof finalSession.token !== "string" ||
								finalSession.token.length === 0
							) {
								throw new ManagedSessionIssuanceError("policy_unsatisfied");
							}
							expectedCredentialKeys = [
								secondaryCredentialKey(
									await digestSessionRefreshSecret(finalSession.token),
								),
							];
						} else {
							if (!expectedCredential) {
								throw new ManagedSessionIssuanceError("policy_unsatisfied");
							}
							const lineage = await findCanonicalManagedCredentialLineage({
								session: finalSession,
								credentialAnchors: [expectedCredential],
							});
							if (
								!lineage ||
								lineage.active.id !== expectedCredential.id ||
								lineage.active.status !== "active" ||
								lineage.active.sessionId !== persistedSessionId ||
								lineage.active.familyId !== familyId ||
								lineage.active.parentCredentialId !== null ||
								lineage.active.rotationCounter !== 0 ||
								!constantTimeEqual(
									lineage.active.secretDigest,
									refreshDigest,
								)
							) {
								throw new ManagedSessionIssuanceError("policy_unsatisfied");
							}
							expectedCredentialKeys = [
								secondaryCredentialKey(lineage.active.secretDigest),
							];
						}
						if (secondaryStorage) {
							await queueAfterTransactionHook(
								() =>
									publishManagedSessionAfterCommit({
										session: finalSession,
										userId,
										credentialAnchors: expectedCredential
											? [expectedCredential]
											: [],
										expectedCredentialKeys,
									}),
								adapter,
							);
						}
					}, adapter);
				} else if (secondaryStorage && storesSessionsInDatabase) {
					await queueAfterTransactionHook(async () => {
						await persistSecondarySession(res as Record<string, any>);
					}, adapter);
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
			const find = async () => {
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
						!(await validateRawSessionAuthority(
							session as Record<string, unknown>,
							user as User & Record<string, unknown>,
						))
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
					const sessionStringified = await secondaryStorage.get(credentialKey);
					if (!sessionStringified) return null;
					const stored = safeJSONParse<{
						session: Session;
						user: User;
					}>(sessionStringified);
					if (!stored) return null;
					const currentUser = await (
						await getCurrentAdapter(adapter)
					).findOne<User & Record<string, unknown>>({
						model: "user",
						where: [{ field: "id", value: stored.user.id }],
					});
					const rawSession = {
						...stored.session,
						expiresAt: new Date(stored.session.expiresAt),
						createdAt: new Date(stored.session.createdAt),
						updatedAt: new Date(stored.session.updatedAt),
					};
					if (
						!currentUser ||
						!(await validateRawSessionAuthority(rawSession, currentUser))
					) {
						await secondaryStorage.delete(credentialKey);
						return null;
					}
					const parsedSession = parseInternalSessionOutput(
						ctx.options,
						rawSession,
					);
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
					!(await validateRawSessionAuthority(
						session as Record<string, unknown>,
						user as User & Record<string, unknown>,
					))
				) {
					return null;
				}
				if (
					authenticationPolicy &&
					!(await rereadActiveCredential(result.credential))
				) {
					return null;
				}
				return {
					session: parseInternalSessionOutput(ctx.options, session),
					user: parseUserOutput(ctx.options, user),
				};
			};
			return authenticationPolicy && storesSessionsInDatabase
				? runWithTransaction(adapter, find)
				: find();
		},
		findSessionById: async (sessionId: string) => {
			const find = async () => {
				if (!storesSessionsInDatabase) {
					if (!secondaryStorage) return null;
					const credentialKey = parseSecondaryHandle(
						await secondaryStorage.get(secondaryHandleKey(sessionId)),
					);
					if (!credentialKey) return null;
					const serialized = await secondaryStorage.get(credentialKey);
					const parsed = safeJSONParse<{ session: Session; user: User }>(serialized);
					if (!parsed) return null;
					const currentUser = await (
						await getCurrentAdapter(adapter)
					).findOne<User & Record<string, unknown>>({
						model: "user",
						where: [{ field: "id", value: parsed.user.id }],
					});
					const rawSession = {
						...parsed.session,
						expiresAt: new Date(parsed.session.expiresAt),
						createdAt: new Date(parsed.session.createdAt),
						updatedAt: new Date(parsed.session.updatedAt),
					};
					if (
						!currentUser ||
						!(await validateRawSessionAuthority(rawSession, currentUser))
					) {
						await secondaryStorage.delete(credentialKey);
						return null;
					}
					return {
						session: parseInternalSessionOutput(ctx.options, rawSession),
						user: parseUserOutput(ctx.options, {
							...currentUser,
							createdAt: new Date(currentUser.createdAt),
							updatedAt: new Date(currentUser.updatedAt),
						}),
					};
				}
				const record = await findSessionRecordById(sessionId);
				if (!record?.user) return null;
				const { user, ...session } = record;
				let matchedCredential: SessionCredential | undefined;
				if (!legacyCredentialAuthority) {
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
					if (!credentials[0] || credentials[0].expiresAt <= new Date()) {
						return null;
					}
					matchedCredential = credentials[0];
				}
				if (
					!(await validateRawSessionAuthority(
						session as Record<string, unknown>,
						user as User & Record<string, unknown>,
					))
				) {
					return null;
				}
				if (
					authenticationPolicy &&
					matchedCredential &&
					!(await rereadActiveCredential(matchedCredential))
				) {
					return null;
				}
				return {
					session: parseInternalSessionOutput(ctx.options, session),
					user: parseUserOutput(ctx.options, user),
				};
			};
			return authenticationPolicy && storesSessionsInDatabase
				? runWithTransaction(adapter, find)
				: find();
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
				const recovery = await recoverRecentSessionRotation(
					credential,
					await digestSessionRotationNonce(operationKey),
					operationKey,
					digest,
				);
				if (recovery && recovery !== recoveryCredentialRejected) {
					await queueManagedRotationPublication(recovery);
				}
				return recovery;
			});
			if (!recovered || recovered === recoveryCredentialRejected) return null;
			const {
				oldDigest: _,
				successorDigest: __,
				parentCredential: ___,
				successorCredential: ____,
				...result
			} = recovered;
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
			const joinedAmbientTransaction = await isTransactionActive(adapter);
			let rotated: SessionRotationResult | null;
			try {
				rotated = await runWithTransaction(adapter, async () => {
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
						const authority = await loadValidatedSessionAuthority(
							credential.sessionId,
						);
						if (!authority) return null;
						const recovered = await recoverRecentSessionRotation(
							credential,
							rotationNonceDigest,
							rotationOperation,
							digest,
							authority,
						);
						if (recovered === recoveryCredentialRejected) return null;
						if (recovered) {
							await queueManagedRotationPublication(recovered);
							return recovered;
						}
						await revokeAndDeleteSessionById(
							credential.sessionId,
							new Date(),
						);
					}
					return null;
				}
				if (credential.expiresAt <= new Date()) return null;

				const authority = await loadValidatedSessionAuthority(
					credential.sessionId,
				);
				if (!authority) return null;

				const [derivedSuccessor] = await deriveRotationSuccessors(
					credential,
					rotationOperation,
				);
				if (!derivedSuccessor) return null;
				const activeCredential = await rereadActiveCredential(credential);
				if (!activeCredential?.sessionId) return null;
				const activeSessionId = activeCredential.sessionId;
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
						{ field: "id", value: activeCredential.id },
						{ field: "sessionId", value: activeSessionId },
						{ field: "status", value: "active" },
						{ field: "secretDigest", value: digest },
						{ field: "familyId", value: activeCredential.familyId },
						{
							field: "rotationCounter",
							value: activeCredential.rotationCounter,
						},
						{
							field: "parentCredentialId",
							value: activeCredential.parentCredentialId ?? null,
						},
						{ field: "expiresAt", value: activeCredential.expiresAt },
						{ field: "expiresAt", value: consumedAt, operator: "gt" },
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
					const exactParent = await rereadExactCredential(activeCredential);
					if (exactParent?.status === "active") return null;
					if (exactParent?.status === "consumed") {
						const recovered = await recoverRecentSessionRotation(
							exactParent,
							rotationNonceDigest,
							rotationOperation,
							digest,
							authority,
						);
						if (recovered === recoveryCredentialRejected) return null;
						if (recovered) {
							await queueManagedRotationPublication(recovered);
							return recovered;
						}
					}
					await revokeAndDeleteSessionById(
						activeSessionId,
						new Date(),
					);
					return null;
				}

				const committedAuthority = await loadValidatedSessionAuthority(
					activeSessionId,
				);
				const persistedParent = await rereadExactCredential(consumed);
				if (
					!persistedParent ||
					persistedParent.status !== "consumed" ||
					persistedParent.expiresAt <= consumedAt ||
					!committedAuthority ||
					committedAuthority.session.expiresAt.getTime() !==
						persistedParent.expiresAt.getTime()
				) {
					throw new ManagedSessionRotationRejected();
				}

				const createdSuccessor = await createCredentialRecord({
					...successorIdentity,
					sessionId: activeSessionId,
					familyId: persistedParent.familyId,
					secretDigest: successorDigest,
					expiresAt: persistedParent.expiresAt,
					parentCredentialId: persistedParent.id,
					rotationCounter: persistedParent.rotationCounter + 1,
				});
				const persistedSuccessor = await rereadExactCredential(createdSuccessor);
				if (
					!persistedSuccessor ||
					persistedSuccessor.status !== "active" ||
					persistedSuccessor.sessionId !== persistedParent.sessionId ||
					persistedSuccessor.familyId !== persistedParent.familyId ||
					persistedSuccessor.parentCredentialId !== persistedParent.id ||
					persistedSuccessor.rotationCounter !==
						persistedParent.rotationCounter + 1 ||
					persistedSuccessor.expiresAt.getTime() !==
						persistedParent.expiresAt.getTime()
				) {
					throw new ManagedSessionRotationRejected();
				}
				if (persistedParent.parentCredentialId) {
					await currentAdapter.update<SessionCredential>({
						model: SESSION_CREDENTIAL_MODEL,
						where: [
							{ field: "id", value: persistedParent.parentCredentialId },
						],
						update: {
							rotationNonceDigest: null,
							recoverySecretCiphertext: null,
							recoveryExpiresAt: null,
							updatedAt: consumedAt,
						},
					});
				}
				const result: SessionRotationResult = {
					session: {
						...committedAuthority.session,
						token: successorSecret,
					},
					user: committedAuthority.user,
					refreshToken: successorSecret,
					familyId: persistedParent.familyId,
					rotationCounter: persistedSuccessor.rotationCounter,
					oldDigest: digest,
					successorDigest,
					parentCredential: persistedParent,
					successorCredential: persistedSuccessor,
				};
				await queueManagedRotationPublication(result);
				return result;
				});
			} catch (error) {
				if (error instanceof ManagedSessionRotationRejected) {
					if (joinedAmbientTransaction) {
						const rollbackRequired = new Error(
							"Managed session rotation authority changed after credential consumption; the ambient transaction must roll back",
						);
						await queueBeforeTransactionCommitHook(async () => {
							throw rollbackRequired;
						}, adapter);
						throw rollbackRequired;
					}
					return null;
				}
				throw error;
			}

			if (!rotated) return null;
			const {
				oldDigest: _,
				successorDigest: __,
				parentCredential: ___,
				successorCredential: ____,
				...result
			} = rotated;
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
			if (authenticationPolicy && storesSessionsInDatabase) {
				try {
					return await runWithTransaction(adapter, async () => {
						const initial = await resolveManagedSessionUpdateAuthority(
							sessionToken,
						);
						if (!initial) return null;
						const directUpdate = stripSessionUpdateAuthority(session);
						if (
							!managedOrganizationUpdateAllowed(directUpdate, initial.session)
						) {
							return null;
						}
						const immutable = immutableSessionUpdateFields(initial.session);
						let committedExpiresAt: Date | null = null;
						let committedCredential: SessionCredential | null = null;
						const updatedSession = await updateWithHooks<Session>(
							directUpdate,
							[{ field: "id", value: initial.session.id }],
							"session",
							{
								executeMainFn: false,
								usesTransactionAdapter: true,
								async fn(hookedData, transactionAdapter) {
									const current = await resolveManagedSessionUpdateAuthority(
										sessionToken,
									);
									if (
										!current ||
										current.session.id !== initial.session.id ||
										current.credential?.id !== initial.credential?.id ||
										!sameImmutableSessionAuthority(
											current.session,
											initial.session,
										)
									) {
										throw new ManagedSessionUpdateRejected();
									}
									if (
										!managedOrganizationUpdateAllowed(
											hookedData,
											initial.session,
										)
									) {
										throw new ManagedSessionUpdateRejected();
									}
									const finalData = {
										...current.session,
										...hookedData,
										...immutable,
									} as Session & Record<string, unknown>;
									if (
										!(finalData.expiresAt instanceof Date) ||
										!Number.isFinite(finalData.expiresAt.getTime())
									) {
										throw new ManagedSessionUpdateRejected();
									}
									const mutationTime = new Date();
									if (current.credential) {
										const guarded =
											await transactionAdapter.incrementOne<SessionCredential>({
												model: SESSION_CREDENTIAL_MODEL,
												where: [
													{ field: "id", value: current.credential.id },
													{
														field: "sessionId",
														value: initial.session.id,
													},
													{ field: "status", value: "active" },
													{
														field: "secretDigest",
														value: current.credential.secretDigest,
													},
													{
														field: "expiresAt",
														value: current.credential.expiresAt,
													},
												],
												increment: {},
												set: { updatedAt: mutationTime },
											});
										if (!guarded) throw new ManagedSessionUpdateRejected();
									}
									const persisted = await transactionAdapter.update<Session>({
										model: "session",
										where: [{ field: "id", value: initial.session.id }],
										update: finalData,
									});
									if (!persisted) {
										throw new Error("Managed session update did not persist");
									}
									if (current.credential) {
										const count = await transactionAdapter.updateMany({
											model: SESSION_CREDENTIAL_MODEL,
											where: [
												{ field: "sessionId", value: initial.session.id },
											],
											update: {
												expiresAt: finalData.expiresAt,
												updatedAt: mutationTime,
											},
										});
										if (Number(count) < 1) {
											throw new Error(
												"Managed credential expiry did not persist",
											);
										}
										if (
											!(await allSessionCredentialExpiriesMatch(
												transactionAdapter,
												initial.session.id,
												finalData.expiresAt,
											))
										) {
											throw new Error("Managed credential expiries diverged");
										}
										committedCredential = await rereadExactCredential(
											current.credential,
										);
										if (
											!committedCredential ||
											committedCredential.status !== "active" ||
											committedCredential.expiresAt.getTime() !==
												finalData.expiresAt.getTime()
										) {
											throw new Error("Managed credential authority changed");
										}
									}
									committedExpiresAt = finalData.expiresAt;
									return parseInternalSessionOutput(ctx.options, persisted);
								},
							},
							(hookedData) =>
								({
									...stripSessionUpdateAuthority(hookedData),
									...immutable,
								}) as Session,
						);
						if (!updatedSession || !committedExpiresAt) return null;
						const finalExpiresAt = committedExpiresAt as Date;
						await queueBeforeTransactionCommitHook(async () => {
							const final = await resolveManagedSessionUpdateAuthority(
								sessionToken,
								true,
							);
							if (
								!final ||
								final.session.id !== initial.session.id ||
								final.session.expiresAt.getTime() !==
									finalExpiresAt.getTime() ||
								!sameImmutableSessionAuthority(final.session, initial.session)
							) {
								throw new ManagedSessionUpdateRejected();
							}
							if (
								legacyCredentialAuthority &&
								(typeof final.session.token !== "string" ||
									final.session.token.length === 0)
							) {
								throw new ManagedSessionUpdateRejected();
							}
							if (committedCredential) {
								const finalCredential = final.credential;
								const exactCredential = await rereadExactCredential(
									committedCredential,
								);
								const currentAdapter = await getCurrentAdapter(adapter);
								if (
									!finalCredential ||
									!exactCredential ||
									finalCredential.id !== exactCredential.id ||
									exactCredential.status !== "active" ||
									exactCredential.expiresAt.getTime() !==
										finalExpiresAt.getTime() ||
									!(await allSessionCredentialExpiriesMatch(
										currentAdapter,
										initial.session.id,
										finalExpiresAt,
									))
								) {
									throw new ManagedSessionUpdateRejected();
								}
							}
							if (secondaryStorage) {
								const legacyToken = final.session.token;
								if (
									!committedCredential &&
									(typeof legacyToken !== "string" || legacyToken.length === 0)
								) {
									throw new ManagedSessionUpdateRejected();
								}
								const credentialKey = committedCredential
									? secondaryCredentialKey(committedCredential.secretDigest)
									: secondaryCredentialKey(
											await digestSessionRefreshSecret(legacyToken as string),
										);
								await queueAfterTransactionHook(
									() =>
										publishManagedSessionAfterCommit({
											session: final.session,
											userId: final.session.userId,
											credentialAnchors: committedCredential
												? [committedCredential]
												: [],
											expectedCredentialKeys: [credentialKey],
											allowExpiredSession: true,
										}),
									adapter,
								);
							}
						}, adapter);
						return {
							...updatedSession,
							token: legacyCredentialAuthority
								? updatedSession.token
								: sessionToken,
						};
					});
				} catch (error) {
					if (error instanceof ManagedSessionUpdateRejected) return null;
					throw error;
				}
			}
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
					await queueAfterTransactionHook(cleanupSecondarySession, adapter);
					return;
				}
			}

			if (sessionId) {
				await runWithTransaction(adapter, () =>
					revokeAndDeleteSessionById(sessionId!),
				);
			}
			if (cleanupSecondarySession) {
				await queueAfterTransactionHook(cleanupSecondarySession, adapter);
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
			}, adapter);
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
			const currentAdapter = await getCurrentAdapter(adapter);
			const account = await currentAdapter.findOne<Account>({
				model: "account",
				where: [
					{ field: "userId", value: userId },
					{ field: "providerId", value: "credential" },
				],
			});
			if (!account) return;
			const where = [
				{ field: "id", value: account.id },
				{ field: "password", value: account.password ?? null },
			] satisfies Where[];
			const updated = await updateWithHooks<Account>(
				{
					password,
					failedPasswordAttempts: 0,
					activePasswordAttemptReservations: "[]",
					passwordLockedUntil: null,
				},
				where,
				"account",
				{
					executeMainFn: false,
					usesTransactionAdapter: true,
					async fn(data, transactionAdapter) {
						const result = await transactionAdapter.incrementOne<Account>({
							model: "account",
							where,
							increment: {},
							set: data,
						});
						if (!result) {
							throw new Error("Password credential changed concurrently");
						}
						return result;
					},
				},
				(data) => ({
					...data,
					failedPasswordAttempts: 0,
					activePasswordAttemptReservations: "[]",
					passwordLockedUntil: null,
				}),
			);
			if (!updated) throw new Error("Password credential update was rejected");
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
								async (transactionAdapter) => {
									const row = await transactionAdapter.consumeOne<Verification>({
										model: "verification",
										where: [{ field: "id", value: latest.id }],
									});
									if (!row) return null;
									await transactionAdapter.deleteMany({
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
