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
	attachInternalSessionIssuanceCaptureAuthority,
	ManagedSessionIssuanceError,
	requireCapturedSessionIssuanceAuthority,
	requireInternalSessionIssuanceContext,
} from "../internal/session-issuance-context";
import {
	attachInternalSessionDerivativeAuthority,
	ManagedSessionDerivativeAuthorityError,
	validateInternalSessionDerivativeAuthority,
} from "../internal/session-derivative-authority";
import {
	attachStagedAuthenticationContinuation,
	digestStagedAuthenticationPolicy,
	requireStagedSessionIssuanceAuthority,
	STAGED_AUTHENTICATION_TTL_SECONDS,
} from "../internal/staged-authentication-context";
import {
	appendInternalRuntimeAudit,
	attachCapturedInternalRuntimeAudit,
	classifyRuntimeInteractiveAuthenticationRoute,
	getRuntimeAuditRequestContext,
	readInternalRuntimeAudit,
} from "../internal/runtime-audit";
import {
	ManagedVerificationChallengeError,
	requireInternalVerificationChallengeContext,
	requireInternalVerificationConsumptionContext,
	type InternalVerificationChallengeBinding,
} from "../internal/verification-challenge-context";
import {
	evaluateSessionIssuance,
	evaluateStagedSessionIssuance,
	SESSION_ASSURANCE_RESERVED_FIELDS,
	stripReservedSessionAuthority,
	type SessionAssuranceFields,
	type ValidatedSessionAssuranceFields,
	validateStoredSessionAssurance,
} from "../security/session-assurance";

function getTTLSeconds(expiresAt: Date | number, now = Date.now()): number {
	const expiresMs =
		typeof expiresAt === "number" ? expiresAt : expiresAt.getTime();
	return Math.max(Math.floor((expiresMs - now) / 1000), 0);
}

const runtimeAuditAuthenticationMethods = new Set<string>([
	"password",
	"password_enrollment",
	"federated",
	"email_link",
	"email_otp",
	"phone_otp",
	"wallet_signature",
	"passkey",
	"anonymous",
	"totp",
	"otp",
	"recovery_code",
	"magic_link",
	"sso",
]);

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
	let warnedManagedVerificationCleanupFailure = false;
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
	type VerificationReservationTombstone = {
		id: string;
		key: string;
		state: "verification-reservation-v1";
		phase: string;
		cursor: string;
		revision: number;
		completedAt: Date;
		createdAt: Date;
		updatedAt: Date;
	};
	type ManagedVerificationChallengeMarker = {
		id: string;
		key: string;
		state: "managed-verification-challenge-v2";
		phase: string;
		cursor: string;
		revision: 2;
		completedAt: Date;
		createdAt: Date;
		updatedAt: Date;
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
	class ManagedSessionPublicationAuthorityInvalid extends Error {
		constructor() {
			super("Managed session publication authority is invalid");
			this.name = "ManagedSessionPublicationAuthorityInvalid";
		}
	}
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

	async function resolveRawSessionAssurance(
		session: Record<string, unknown>,
		user: User & Record<string, unknown>,
		allowExpiredSession = false,
	): Promise<ValidatedSessionAssuranceFields | null> {
		if (
			(user as User & { banned?: boolean | null }).banned === true ||
			!sessionMatchesSecurityGenerations(session, user)
		) {
			return null;
		}
		if (!authenticationPolicy) return null;

		const storedOrganizationId = session.authenticationPolicyOrganizationId;
		if (
			storedOrganizationId !== null &&
			(typeof storedOrganizationId !== "string" ||
				storedOrganizationId.length === 0 ||
				storedOrganizationId.length > 1_024 ||
				storedOrganizationId.trim() !== storedOrganizationId ||
				storedOrganizationId.includes("\0"))
		) {
			return null;
		}
		const organizationId = storedOrganizationId as string | null;
		const activeOrganizationId = session.activeOrganizationId;
		if (
			activeOrganizationId !== null &&
			activeOrganizationId !== undefined &&
			(typeof activeOrganizationId !== "string" ||
				activeOrganizationId !== organizationId)
		) {
			return null;
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
			return null;
		}
		const validation = validateStoredSessionAssurance({
			stored: session,
			policy: {
				identity: resolvedPolicy.scope,
				organizationId,
				revision: resolvedPolicy.revision,
				policy: resolvedPolicy.effective,
			},
			now,
		});
		return validation.kind === "accepted" ? validation.fields : null;
	}

	async function validateRawSessionAuthority(
		session: Record<string, unknown>,
		user: User & Record<string, unknown>,
		allowExpiredSession = false,
	): Promise<boolean> {
		if (!authenticationPolicy) {
			const now = new Date();
			return (
				(user as User & { banned?: boolean | null }).banned !== true &&
				sessionMatchesSecurityGenerations(session, user) &&
				session.expiresAt instanceof Date &&
				Number.isFinite(session.expiresAt.getTime()) &&
				(allowExpiredSession || session.expiresAt > now)
			);
		}
		return (
			(await resolveRawSessionAssurance(
				session,
				user,
				allowExpiredSession,
			)) !== null
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
	type AssuredValidatedSessionAuthority = ValidatedSessionAuthority & {
		assurance: ValidatedSessionAssuranceFields | null;
	};

	async function loadValidatedSessionAuthority(
		sessionId: string,
		allowExpiredSession = false,
	): Promise<AssuredValidatedSessionAuthority | null> {
		const record = await findSessionRecordById(sessionId);
		if (!record?.user) return null;
		const activeUser = await lockAndReadActiveUser(
			await getCurrentAdapter(adapter),
			record.user.id,
		);
		if (!activeUser) return null;
		const { user: _, ...session } = record;
		const assurance = authenticationPolicy
			? await resolveRawSessionAssurance(
					session as Record<string, unknown>,
					activeUser as User & Record<string, unknown>,
					allowExpiredSession,
				)
			: null;
		if (
			authenticationPolicy
				? assurance === null
				: !(await validateRawSessionAuthority(
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
			assurance,
		};
	}

	type ManagedSessionUpdateAuthority = AssuredValidatedSessionAuthority & {
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
		if (!legacyCredentialAuthority) {
			if (!credential) return null;
			const authority = await loadStrictManagedSessionAuthority(
				sessionId,
				[credential],
				allowExpired,
			);
			if (!authority || authority.lineage.active.id !== credential.id) {
				return null;
			}
			return {
				session: authority.session,
				user: authority.user,
				assurance: authority.assurance,
				credential: authority.lineage.active,
			};
		}
		const authority = await loadValidatedSessionAuthority(
			sessionId,
			allowExpired,
		);
		return authority ? { ...authority, credential: null } : null;
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
		userId?: string | undefined;
		expectedCredentialKeys: readonly string[];
	}): Promise<void> {
		await cleanupInvalidManagedSessionsSecondary({
			userId: input.userId,
			targets: [input],
		});
	}

	async function cleanupInvalidManagedSessionsSecondary(input: {
		userId?: string | undefined;
		targets: readonly {
			sessionId: string;
			expectedCredentialKeys: readonly string[];
		}[];
	}): Promise<void> {
		if (!secondaryStorage) return;
		const targetsById = new Map(
			input.targets.map((target) => [target.sessionId, target]),
		);
		if (targetsById.size === 0) return;
		const now = Date.now();
		const listKey = input.userId
			? secondaryActiveSessionsKey(input.userId)
			: null;
		const parsedList = listKey
			? safeJSONParse<SecondarySessionIndexEntry[]>(
					await secondaryStorage.get(listKey),
				)
			: null;
		const list = Array.isArray(parsedList) ? parsedList : null;
		const credentialKeys = new Set<string>();
		const addCredentialKey = (credentialKey: unknown) => {
			if (typeof credentialKey !== "string" || credentialKey.length === 0) {
				return;
			}
			credentialKeys.add(credentialKey);
		};
		for (const target of targetsById.values()) {
			for (const credentialKey of target.expectedCredentialKeys) {
				addCredentialKey(credentialKey);
			}
			const handleKey = secondaryHandleKey(target.sessionId);
			addCredentialKey(parseSecondaryHandle(await secondaryStorage.get(handleKey)));
		}
		if (list) {
			for (const entry of list) {
				if (
					typeof entry?.sessionId === "string" &&
					targetsById.has(entry.sessionId)
				) {
					addCredentialKey(entry.credentialKey);
				}
			}
		}
		for (const credentialKey of credentialKeys) {
			const envelope = safeJSONParse<{ session?: { id?: unknown } }>(
				await secondaryStorage.get(credentialKey),
			);
			if (
				typeof envelope?.session?.id === "string" &&
				targetsById.has(envelope.session.id)
			) {
				await secondaryStorage.delete(credentialKey);
			}
		}
		for (const sessionId of targetsById.keys()) {
			await secondaryStorage.delete(secondaryHandleKey(sessionId));
		}
		if (!listKey) return;
		if (!list) {
			await secondaryStorage.delete(listKey);
			return;
		}
		const remaining = list
			.filter(
				(entry) =>
					typeof entry?.sessionId === "string" &&
					typeof entry.credentialKey === "string" &&
					typeof entry.expiresAt === "number" &&
					Number.isFinite(entry.expiresAt) &&
					!targetsById.has(entry.sessionId) &&
					entry.expiresAt > now,
			)
			.sort(
				(left, right) =>
					left.expiresAt - right.expiresAt ||
					left.sessionId.localeCompare(right.sessionId) ||
					left.credentialKey.localeCompare(right.credentialKey),
			);
		if (remaining.length === 0) {
			await secondaryStorage.delete(listKey);
			return;
		}
		const ttl = getTTLSeconds(
			Math.max(...remaining.map((entry) => entry.expiresAt)),
			now,
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
	const isValidRotationNonceDigest = (value: unknown): value is string =>
		typeof value === "string" && /^v1:[A-Za-z0-9_-]{43}$/.test(value);
	const isValidCredentialDate = (value: unknown): value is Date =>
		value instanceof Date && Number.isFinite(value.getTime());

	async function findCanonicalManagedCredentialLineage(input: {
		session: Session & Record<string, unknown>;
		credentialAnchors: readonly SessionCredential[];
		allowExpiredSession?: boolean;
		requireValidDigests?: boolean;
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
			(input.requireValidDigests &&
				(new Set(all.map((credential) => credential.selector)).size !==
					all.length ||
					new Set(all.map((credential) => credential.secretDigest)).size !==
						all.length)) ||
			all.some(
				(credential) =>
					credential.sessionId !== input.session.id ||
					credential.digestVersion !== SESSION_CREDENTIAL_DIGEST_VERSION ||
					typeof credential.selector !== "string" ||
					credential.selector.length === 0 ||
					(input.requireValidDigests &&
						!(/^[A-Za-z0-9_-]{32,128}$/).test(credential.selector)) ||
					typeof credential.secretDigest !== "string" ||
					credential.secretDigest.length === 0 ||
					(input.requireValidDigests &&
						!isValidSessionCredentialDigest(credential.secretDigest)) ||
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
		const activeCredential = chain[0]!;
		if (
			!isValidCredentialDate(activeCredential.createdAt) ||
			!isValidCredentialDate(activeCredential.updatedAt) ||
			activeCredential.updatedAt < activeCredential.createdAt ||
			activeCredential.consumedAt !== null ||
			activeCredential.revokedAt !== null ||
			activeCredential.reuseDetectedAt !== null ||
			activeCredential.rotationNonceDigest !== null ||
			activeCredential.recoverySecretCiphertext !== null ||
			activeCredential.recoveryExpiresAt !== null
		) {
			return null;
		}
		for (let index = 1; index < chain.length; index += 1) {
			const credential = chain[index]!;
			if (
				!isValidCredentialDate(credential.createdAt) ||
				!isValidCredentialDate(credential.updatedAt) ||
				!isValidCredentialDate(credential.consumedAt) ||
				credential.updatedAt < credential.createdAt ||
				credential.consumedAt < credential.createdAt ||
				credential.updatedAt < credential.consumedAt ||
				credential.revokedAt !== null ||
				credential.reuseDetectedAt !== null ||
				credential.recoverySecretCiphertext !== null
			) {
				return null;
			}
			const hasNoRecoveryTuple =
				credential.rotationNonceDigest === null &&
				credential.recoveryExpiresAt === null;
			if (index > 1) {
				if (!hasNoRecoveryTuple) return null;
				continue;
			}
			const hasCompleteRecoveryTuple =
				isValidRotationNonceDigest(credential.rotationNonceDigest) &&
				isValidCredentialDate(credential.recoveryExpiresAt) &&
				credential.recoveryExpiresAt > credential.consumedAt &&
				credential.recoveryExpiresAt.getTime() <=
					credential.consumedAt.getTime() +
						SESSION_ROTATION_RECOVERY_WINDOW_MS;
			if (!hasNoRecoveryTuple && !hasCompleteRecoveryTuple) return null;
		}
		return {
			active: activeCredential,
			consumed: chain.filter((credential) => credential.status === "consumed"),
		};
	}

	type StrictManagedSessionAuthority = AssuredValidatedSessionAuthority & {
		lineage: {
			active: SessionCredential;
			consumed: SessionCredential[];
		};
	};

	async function loadStrictManagedSessionAuthority(
		sessionId: string,
		credentialAnchors: readonly SessionCredential[],
		allowExpiredSession = false,
	): Promise<StrictManagedSessionAuthority | null> {
		if (legacyCredentialAuthority || credentialAnchors.length === 0) return null;
		let authority = await loadValidatedSessionAuthority(
			sessionId,
			allowExpiredSession,
		);
		if (!authority) return null;
		const validateLineage = () =>
			findCanonicalManagedCredentialLineage({
				session: authority!.session,
				credentialAnchors,
				allowExpiredSession,
				requireValidDigests: true,
			});
		let lineage = await validateLineage();
		if (!lineage) {
			const refreshed = await findSessionRecordById(sessionId);
			const refreshedExpiresAt = refreshed?.expiresAt;
			if (
				refreshed?.user &&
				refreshedExpiresAt instanceof Date &&
				refreshedExpiresAt.getTime() !== authority.session.expiresAt.getTime()
			) {
				authority = await loadValidatedSessionAuthority(
					sessionId,
					allowExpiredSession,
				);
				if (!authority) return null;
				lineage = await validateLineage();
			}
		}
		return lineage ? { ...authority, lineage } : null;
	}

	async function loadStrictManagedSessionAuthorityById(
		sessionId: string,
	): Promise<StrictManagedSessionAuthority | null> {
		if (legacyCredentialAuthority) return null;
		const credentials = await (
			await getCurrentAdapter(adapter)
		).findMany<SessionCredential>({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "sessionId", value: sessionId }],
		});
		if (credentials.length === 0) return null;
		return loadStrictManagedSessionAuthority(sessionId, credentials);
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
					requireValidDigests: true,
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
			throw new ManagedSessionPublicationAuthorityInvalid();
		});
	}

	async function publishManagedSessionAfterCommitSafely(
		expectation: ManagedSessionPublicationExpectation,
	): Promise<void> {
		try {
			await publishManagedSessionAfterCommit(expectation);
		} catch (error) {
			logger.error(
				error instanceof ManagedSessionPublicationAuthorityInvalid
					? "Managed session publication authority became invalid after commit"
					: "Managed session cache publication failed after commit",
				error,
			);
		}
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

	const managedVerificationMarkerKey = async (verificationId: string) => {
		const digest = base64Url.encode(
			new Uint8Array(
				await createHash("SHA-256").digest(
					new TextEncoder().encode(
						`managed-verification-challenge-v2:${verificationId}`,
					),
				),
			),
			{ padding: false },
		);
		return `managed-verification-challenge-v2:${digest}`;
	};

	const managedVerificationBindingDigest = async (
		binding: InternalVerificationChallengeBinding,
		verification: Verification,
	) =>
		base64Url.encode(
			new Uint8Array(
				await createHash("SHA-256").digest(
					new TextEncoder().encode(
						JSON.stringify([
							"managed-verification-challenge-v2",
							binding.purpose,
							binding.subject,
							binding.identifier,
							verification.value,
							verification.expiresAt.toISOString(),
						]),
					),
				),
			),
			{ padding: false },
		);

	const consumeExactManagedVerificationMarker = async (
		transactionAdapter: DBTransactionAdapter<ClearanceOptions>,
		marker: ManagedVerificationChallengeMarker,
	) =>
		transactionAdapter.consumeOne<ManagedVerificationChallengeMarker>({
			model: "securityMigration",
			where: [
				{ field: "id", value: marker.id },
				{ field: "key", value: marker.key },
				{ field: "state", value: marker.state },
				{ field: "phase", value: marker.phase },
				{ field: "cursor", value: marker.cursor },
				{ field: "revision", value: marker.revision },
				{ field: "completedAt", value: marker.completedAt },
				{ field: "createdAt", value: marker.createdAt },
				{ field: "updatedAt", value: marker.updatedAt },
			],
		});

	async function reclaimExpiredManagedVerificationMarkers(
		transactionAdapter: DBTransactionAdapter<ClearanceOptions>,
		now: Date,
	): Promise<void> {
		const expired =
			await transactionAdapter.findMany<ManagedVerificationChallengeMarker>({
				model: "securityMigration",
				where: [
					{ field: "state", value: "managed-verification-challenge-v2" },
					{ field: "completedAt", value: now, operator: "lte" },
				],
				sortBy: { field: "completedAt", direction: "asc" },
				limit: 8,
			});
		for (const marker of expired) {
			if (
				marker.state !== "managed-verification-challenge-v2" ||
				!(marker.completedAt instanceof Date) ||
				!Number.isFinite(marker.completedAt.getTime()) ||
				marker.completedAt > now
			) {
				continue;
			}
			await consumeExactManagedVerificationMarker(transactionAdapter, marker);
		}
	}

	async function createManagedVerificationMarker(
		transactionAdapter: DBTransactionAdapter<ClearanceOptions>,
		verification: Verification,
		binding: InternalVerificationChallengeBinding,
	): Promise<void> {
		const verificationId = String(verification.id ?? "");
		if (
			verificationId.length === 0 ||
			!(verification.expiresAt instanceof Date) ||
			!Number.isFinite(verification.expiresAt.getTime())
		) {
			throw new Error("Managed verification challenge is malformed");
		}
		const now = new Date();
		await reclaimExpiredManagedVerificationMarkers(transactionAdapter, now);
		const idStrategy = options.advanced?.database?.generateId;
		const databaseGeneratesId = idStrategy === "serial" || idStrategy === "uuid";
		await transactionAdapter.create({
			model: "securityMigration",
			forceAllowId: !databaseGeneratesId,
			data: {
				...(databaseGeneratesId ? {} : { id: generateId() }),
				key: await managedVerificationMarkerKey(verificationId),
				state: "managed-verification-challenge-v2",
				phase: generateId(),
				cursor: await managedVerificationBindingDigest(binding, verification),
				revision: 2,
				completedAt: verification.expiresAt,
				createdAt: now,
				updatedAt: now,
			},
		});
	}

	async function consumeManagedVerificationMarker(
		transactionAdapter: DBTransactionAdapter<ClearanceOptions>,
		verification: Verification,
		binding: InternalVerificationChallengeBinding,
	): Promise<ManagedVerificationChallengeMarker | null> {
		const verificationId = String(verification.id ?? "");
		if (
			verificationId.length === 0 ||
			!(verification.expiresAt instanceof Date) ||
			!Number.isFinite(verification.expiresAt.getTime()) ||
			verification.expiresAt <= new Date()
		) {
			return null;
		}
		const key = await managedVerificationMarkerKey(verificationId);
		const bindingDigest = await managedVerificationBindingDigest(
			binding,
			verification,
		);
		const marker =
			await transactionAdapter.findOne<ManagedVerificationChallengeMarker>({
				model: "securityMigration",
				where: [{ field: "key", value: key }],
			});
		if (
			!marker ||
			marker.key !== key ||
			marker.state !== "managed-verification-challenge-v2" ||
			typeof marker.phase !== "string" ||
			marker.phase.length === 0 ||
			marker.cursor !== bindingDigest ||
			marker.revision !== 2 ||
			!(marker.completedAt instanceof Date) ||
			marker.completedAt.getTime() !== verification.expiresAt.getTime() ||
			marker.completedAt <= new Date()
		) {
			return null;
		}
		return consumeExactManagedVerificationMarker(transactionAdapter, marker);
	}

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

	type ManagedUserSessionReconciliation = {
		sessionId: string;
		handleKey: string;
		candidateCredentialKeys: string[];
		owned: boolean;
		validAuthority?:
			| {
					session: Session & Record<string, unknown>;
					user: User & Record<string, unknown>;
					credentialKey: string;
			  }
			| undefined;
	};

	async function reconcileManagedUserSessions(userId: string): Promise<void> {
		if (!secondaryStorage) return;
		await runWithTransaction(adapter, async () => {
			const currentAdapter = await getCurrentAdapter(adapter);
			const lockedUser = await lockAndReadUser(currentAdapter, userId);
			const activeUser =
				lockedUser &&
				(lockedUser as User & { banned?: boolean | null }).banned !== true
					? (lockedUser as User & Record<string, unknown>)
					: null;
			const indexKey = secondaryActiveSessionsKey(userId);
			const parsedIndex = safeJSONParse<SecondarySessionIndexEntry[]>(
				await secondaryStorage.get(indexKey),
			);
			const index = Array.isArray(parsedIndex) ? parsedIndex : [];
			const candidateSessionIds = [
				...new Set(
					index
						.map((entry) => entry?.sessionId)
						.filter(
							(sessionId): sessionId is string =>
								typeof sessionId === "string" && sessionId.length > 0,
						),
				),
			];
			const envelopeByKey = new Map<
				string,
				{ session?: { id?: unknown; userId?: unknown } } | null
			>();
			const readEnvelope = async (credentialKey: string) => {
				if (!envelopeByKey.has(credentialKey)) {
					envelopeByKey.set(
						credentialKey,
						safeJSONParse<{ session?: { id?: unknown; userId?: unknown } }>(
							await secondaryStorage.get(credentialKey),
						),
					);
				}
				return envelopeByKey.get(credentialKey) ?? null;
			};
			const decisions: ManagedUserSessionReconciliation[] = [];

			// Evaluation phase: secondary reads are allowed, writes are deferred until
			// every candidate and live policy read has succeeded.
			for (const sessionId of candidateSessionIds) {
				const handleKey = secondaryHandleKey(sessionId);
				const mappedCredentialKey = parseSecondaryHandle(
					await secondaryStorage.get(handleKey),
				);
				const indexedCredentialKeys = index
					.filter(
						(entry) =>
							entry?.sessionId === sessionId &&
							typeof entry.credentialKey === "string" &&
							entry.credentialKey.length > 0,
					)
					.map((entry) => entry.credentialKey);
				const session = await currentAdapter.findOne<
					Session & Record<string, unknown>
				>({
					model: "session",
					where: [{ field: "id", value: sessionId }],
				});
				const credentials = session
					? await currentAdapter.findMany<SessionCredential>({
							model: SESSION_CREDENTIAL_MODEL,
							where: [{ field: "sessionId", value: sessionId }],
						})
					: [];
				const expectedCredentialKeys = credentials
					.filter((credential) =>
						typeof credential.secretDigest === "string" &&
						credential.secretDigest.length > 0,
					)
					.map((credential) =>
						secondaryCredentialKey(credential.secretDigest),
					);
				if (
					legacyCredentialAuthority &&
					session &&
					typeof session.token === "string" &&
					session.token.length > 0
				) {
					expectedCredentialKeys.push(
						secondaryCredentialKey(
							await digestSessionRefreshSecret(session.token),
						),
					);
				}
				const candidateCredentialKeys = [
					...new Set([
						...expectedCredentialKeys,
						...(mappedCredentialKey ? [mappedCredentialKey] : []),
						...indexedCredentialKeys,
					]),
				];
				for (const credentialKey of candidateCredentialKeys) {
					await readEnvelope(credentialKey);
				}
				const cachedOwnership = candidateCredentialKeys.some((credentialKey) => {
					const envelope = envelopeByKey.get(credentialKey);
					return (
						envelope?.session?.id === sessionId &&
						envelope.session.userId === userId
					);
				});
				const owned = session?.userId === userId || (!session && cachedOwnership);
				let validAuthority:
					| ManagedUserSessionReconciliation["validAuthority"]
					| undefined;
				if (session?.userId === userId && activeUser) {
					const policyValid = await validateRawSessionAuthority(session, activeUser);
					let credentialKey: string | null = null;
					if (
						policyValid &&
						legacyCredentialAuthority &&
						credentials.length === 0 &&
						typeof session.token === "string" &&
						session.token.length > 0
					) {
						credentialKey = secondaryCredentialKey(
							await digestSessionRefreshSecret(session.token),
						);
					} else if (policyValid && !legacyCredentialAuthority) {
						const lineage = await findCanonicalManagedCredentialLineage({
							session,
							credentialAnchors: credentials,
							requireValidDigests: true,
							credentials,
						});
						credentialKey = lineage
							? secondaryCredentialKey(lineage.active.secretDigest)
							: null;
					}
					if (credentialKey) {
						validAuthority = {
							session,
							user: activeUser,
							credentialKey,
						};
					}
				}
				decisions.push({
					sessionId,
					handleKey,
					candidateCredentialKeys,
					owned,
					validAuthority,
				});
			}

			// Apply phase: every policy/topology decision above is complete.
			const now = Date.now();
			const nextIndex: SecondarySessionIndexEntry[] = [];
			for (const decision of decisions) {
				if (decision.validAuthority) {
					const { session, user, credentialKey } = decision.validAuthority;
					const ttl = getTTLSeconds(session.expiresAt, now);
					if (ttl > 0) {
						await secondaryStorage.set(
							credentialKey,
							JSON.stringify({ session: { ...session, token: null }, user }),
							ttl,
						);
						await secondaryStorage.set(
							decision.handleKey,
							JSON.stringify({ credentialKey }),
							ttl,
						);
						nextIndex.push({
							sessionId: decision.sessionId,
							credentialKey,
							expiresAt: session.expiresAt.getTime(),
						});
					}
					for (const candidateKey of decision.candidateCredentialKeys) {
						if (
							candidateKey !== credentialKey &&
							envelopeByKey.get(candidateKey)?.session?.id === decision.sessionId
						) {
							await secondaryStorage.delete(candidateKey);
						}
					}
					continue;
				}
				if (decision.owned) {
					for (const candidateKey of decision.candidateCredentialKeys) {
						if (
							envelopeByKey.get(candidateKey)?.session?.id === decision.sessionId
						) {
							await secondaryStorage.delete(candidateKey);
						}
					}
					await secondaryStorage.delete(decision.handleKey);
				}
			}
			nextIndex.sort(
				(left, right) =>
					left.expiresAt - right.expiresAt ||
					left.sessionId.localeCompare(right.sessionId) ||
					left.credentialKey.localeCompare(right.credentialKey),
			);
			if (nextIndex.length === 0) {
				await secondaryStorage.delete(indexKey);
				return;
			}
			const ttl = getTTLSeconds(nextIndex.at(-1)!.expiresAt, now);
			if (ttl > 0) {
				await secondaryStorage.set(indexKey, JSON.stringify(nextIndex), ttl);
			} else {
				await secondaryStorage.delete(indexKey);
			}
		});
	}

	async function queueManagedUserSessionReconciliation(userId: string) {
		if (!secondaryStorage) return;
		await queueAfterTransactionHook(
			() => reconcileManagedUserSessions(userId),
			adapter,
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

	type DatabaseSessionRevocationTarget =
		| {
				kind: "id";
				sessionId: string;
				allowOrphanCleanup?: boolean;
		  }
		| { kind: "token"; token: string };
	type ResolvedDatabaseSessionRevocation = {
		session: Session;
		credential: SessionCredential | null;
	};
	type DatabaseSessionRevocationOutcome =
		| { kind: "noop" }
		| {
				kind:
					| "revoked"
					| "deleted"
					| "orphan_cleanup"
					| "authority_cleanup";
				sessionId: string;
				userId?: string | undefined;
				expectedCredentialKeys: string[];
		  };

	async function resolveDatabaseSessionRevocation(
		target: DatabaseSessionRevocationTarget,
		transactionAdapter: DBTransactionAdapter,
	): Promise<ResolvedDatabaseSessionRevocation | null> {
		if (target.kind === "id") {
			const session = await transactionAdapter.findOne<Session>({
				model: "session",
				where: [{ field: "id", value: target.sessionId }],
			});
			return session ? { session, credential: null } : null;
		}
		const handleSessionId = sessionIdFromHandle(target.token);
		if (handleSessionId) {
			const session = await transactionAdapter.findOne<Session>({
				model: "session",
				where: [{ field: "id", value: handleSessionId }],
			});
			return session ? { session, credential: null } : null;
		}
		if (legacyCredentialAuthority) {
			const session = await transactionAdapter.findOne<Session>({
				model: "session",
				where: [{ field: "token", value: target.token }],
			});
			return session ? { session, credential: null } : null;
		}
		const digest = await digestSessionRefreshSecret(target.token);
		const selector = credentialIdFromRefreshSecret(target.token);
		const credential = selector
			? await transactionAdapter.findOne<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "selector", value: selector }],
				})
			: await transactionAdapter.findOne<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "secretDigest", value: digest }],
				});
		if (
			!credential?.sessionId ||
			!constantTimeEqual(credential.secretDigest, digest)
		) {
			return null;
		}
		const session = await transactionAdapter.findOne<Session>({
			model: "session",
			where: [{ field: "id", value: credential.sessionId }],
		});
		return session ? { session, credential } : null;
	}

	async function readSessionRevocationCredentialKeys(
		transactionAdapter: DBTransactionAdapter,
		session: Session,
	): Promise<{ credentials: SessionCredential[]; keys: string[] }> {
		const credentials = await transactionAdapter.findMany<SessionCredential>({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "sessionId", value: session.id }],
		});
		const keys = credentials
			.filter(
				(credential) =>
					typeof credential.secretDigest === "string" &&
					credential.secretDigest.length > 0,
			)
			.map((credential) =>
				secondaryCredentialKey(credential.secretDigest),
			);
		if (
			legacyCredentialAuthority &&
			typeof session.token === "string" &&
			session.token.length > 0
		) {
			keys.push(
				secondaryCredentialKey(
					await digestSessionRefreshSecret(session.token),
				),
			);
		}
		return { credentials, keys: [...new Set(keys)] };
	}

	async function queueDatabaseSessionRevocationCleanup(
		outcome: Exclude<DatabaseSessionRevocationOutcome, { kind: "noop" }>,
	): Promise<void> {
		if (!secondaryStorage) return;
		await queueAfterTransactionHook(
			async () => {
				await runWithTransaction(adapter, async () => {
					if (outcome.userId) {
						await lockAndReadUser(
							await getCurrentAdapter(adapter),
							outcome.userId,
						);
					}
					await cleanupInvalidManagedSessionSecondary({
						sessionId: outcome.sessionId,
						userId: outcome.userId,
						expectedCredentialKeys: outcome.expectedCredentialKeys,
					});
				});
			},
			adapter,
		);
	}

	type BulkDatabaseSessionRevocationTarget = {
		session: Session;
		credentials: SessionCredential[];
		expectedCredentialKeys: string[];
	};

	async function readBulkDatabaseSessionRevocationTargets(
		transactionAdapter: DBTransactionAdapter,
		sessions: readonly Session[],
	): Promise<BulkDatabaseSessionRevocationTarget[]> {
		const targets: BulkDatabaseSessionRevocationTarget[] = [];
		for (const session of sessions) {
			const captured = await readSessionRevocationCredentialKeys(
				transactionAdapter,
				session,
			);
			targets.push({
				session,
				credentials: captured.credentials,
				expectedCredentialKeys: captured.keys,
			});
		}
		return targets;
	}

	const sameCredentialDate = (
		left: Date | null | undefined,
		right: Date | null | undefined,
	): boolean =>
		left == null || right == null
			? left == null && right == null
			: left.getTime() === right.getTime();

	async function revokeAndVerifyBulkDatabaseSessionCredentials(
		transactionAdapter: DBTransactionAdapter,
		targets: readonly BulkDatabaseSessionRevocationTarget[],
		revokedAt: Date,
	): Promise<void> {
		for (const target of targets) {
			const updated = await transactionAdapter.updateMany({
				model: SESSION_CREDENTIAL_MODEL,
				where: [{ field: "sessionId", value: target.session.id }],
				update: {
					status: "revoked",
					revokedAt,
					rotationNonceDigest: null,
					recoverySecretCiphertext: null,
					recoveryExpiresAt: null,
					updatedAt: revokedAt,
				},
			});
			if (Number(updated) !== target.credentials.length) {
				throw new Error("Bulk session credential revocation count mismatch");
			}
			const currentCredentials =
				await transactionAdapter.findMany<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "sessionId", value: target.session.id }],
				});
			if (currentCredentials.length !== target.credentials.length) {
				throw new Error("Bulk session credential authority set changed");
			}
			const expectedById = new Map(
				target.credentials.map((credential) => [credential.id, credential]),
			);
			for (const current of currentCredentials) {
				const expected = expectedById.get(current.id);
				if (
					!expected ||
					current.selector !== expected.selector ||
					current.sessionId !== target.session.id ||
					expected.sessionId !== target.session.id ||
					current.familyId !== expected.familyId ||
					!constantTimeEqual(current.secretDigest, expected.secretDigest) ||
					current.digestVersion !== expected.digestVersion ||
					current.rotationCounter !== expected.rotationCounter ||
					current.parentCredentialId !== expected.parentCredentialId ||
					!sameCredentialDate(current.expiresAt, expected.expiresAt) ||
					!sameCredentialDate(current.consumedAt, expected.consumedAt) ||
					!sameCredentialDate(current.reuseDetectedAt, expected.reuseDetectedAt) ||
					!sameCredentialDate(current.createdAt, expected.createdAt) ||
					current.status !== "revoked" ||
					!sameCredentialDate(current.revokedAt, revokedAt) ||
					current.rotationNonceDigest !== null ||
					current.recoverySecretCiphertext !== null ||
					current.recoveryExpiresAt !== null ||
					!sameCredentialDate(current.updatedAt, revokedAt)
				) {
					throw new Error("Bulk session credential revocation verification failed");
				}
			}
		}
	}

	async function queueBulkDatabaseSessionRevocationCleanup(input: {
		userId: string;
		targets: readonly BulkDatabaseSessionRevocationTarget[];
	}): Promise<void> {
		if (!secondaryStorage || input.targets.length === 0) return;
		await queueAfterTransactionHook(
			async () => {
				await runWithTransaction(adapter, async () => {
					const currentAdapter = await getCurrentAdapter(adapter);
					await lockAndReadUser(currentAdapter, input.userId);
					await cleanupInvalidManagedSessionsSecondary({
						userId: input.userId,
						targets: input.targets.map((target) => ({
							sessionId: target.session.id,
							expectedCredentialKeys: target.expectedCredentialKeys,
						})),
					});
				});
			},
			adapter,
		);
	}

	async function queueManagedInvalidSessionReadCleanup(input: {
		sessionId: string;
		userId?: string | undefined;
		expectedCredentialKeys: readonly string[];
	}): Promise<void> {
		if (!secondaryStorage) return;
		await queueAfterTransactionHook(
			async () => {
				await runWithTransaction(adapter, async () => {
					const currentAdapter = await getCurrentAdapter(adapter);
					if (input.userId) {
						await lockAndReadUser(currentAdapter, input.userId);
					}
					await cleanupInvalidManagedSessionSecondary(input);
				});
			},
			adapter,
		);
	}

	async function queueManagedOrphanCredentialCleanup(
		credentialKey: string,
		observedValue: string,
	): Promise<void> {
		if (!secondaryStorage) return;
		await queueAfterTransactionHook(
			async () => {
				const current = await secondaryStorage.get(credentialKey);
				if (current === observedValue) {
					await secondaryStorage.delete(credentialKey);
				}
			},
			adapter,
		);
	}

	async function findExactManagedCredentialCandidate(
		presentedSecret: string,
	): Promise<SessionCredential | null> {
		const secretDigest = await digestSessionRefreshSecret(presentedSecret);
		const selector = credentialIdFromRefreshSecret(presentedSecret);
		const currentAdapter = await getCurrentAdapter(adapter);
		const digestCandidates = await currentAdapter.findMany<SessionCredential>({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "secretDigest", value: secretDigest }],
		});
		const exactDigestCandidates = digestCandidates.filter((candidate) =>
			constantTimeEqual(candidate.secretDigest, secretDigest),
		);
		if (exactDigestCandidates.length !== 1) return null;
		if (!selector) return exactDigestCandidates[0]!;
		const selectorCandidates = await currentAdapter.findMany<SessionCredential>({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "selector", value: selector }],
		});
		if (
			selectorCandidates.length !== 1 ||
			selectorCandidates[0]!.id !== exactDigestCandidates[0]!.id ||
			!constantTimeEqual(selectorCandidates[0]!.secretDigest, secretDigest)
		) {
			return null;
		}
		return exactDigestCandidates[0]!;
	}

	async function loadManagedModernDatabaseSession(input: {
		sessionId: string;
		presentedCredential?: SessionCredential | undefined;
		presentedToken?: string | undefined;
	}): Promise<ValidatedSessionAuthority | null> {
		const record = await findSessionRecordById(input.sessionId);
		if (!record) {
			await queueManagedInvalidSessionReadCleanup({
				sessionId: input.sessionId,
				expectedCredentialKeys: input.presentedCredential
					? [secondaryCredentialKey(input.presentedCredential.secretDigest)]
					: [],
			});
			return null;
		}
		const { user, ...session } = record;
		const currentAdapter = await getCurrentAdapter(adapter);
		const credentials = await currentAdapter.findMany<SessionCredential>({
			model: SESSION_CREDENTIAL_MODEL,
			where: [{ field: "sessionId", value: input.sessionId }],
		});
		const expectedCredentialKeys = credentials
			.filter((credential) =>
				typeof credential.secretDigest === "string" &&
				credential.secretDigest.length > 0,
			)
			.map((credential) => secondaryCredentialKey(credential.secretDigest));
		const policyValid = user
			? await validateRawSessionAuthority(
					session as Record<string, unknown>,
					user as User & Record<string, unknown>,
				)
			: false;
		const lineage = user
			? await findCanonicalManagedCredentialLineage({
					session: session as Session & Record<string, unknown>,
					credentialAnchors: credentials,
					requireValidDigests: true,
					credentials,
				})
			: null;
		const presentedCredentialValid = input.presentedCredential
			? lineage?.active.id === input.presentedCredential.id &&
				constantTimeEqual(
					lineage.active.secretDigest,
					input.presentedCredential.secretDigest,
				)
			: true;
		if (!user || !policyValid || !lineage || !presentedCredentialValid) {
			await queueManagedInvalidSessionReadCleanup({
				sessionId: input.sessionId,
				userId: session.userId,
				expectedCredentialKeys,
			});
			return null;
		}
		return {
			session: {
				...(session as Session & Record<string, unknown>),
				...(input.presentedToken ? { token: input.presentedToken } : {}),
			},
			user: user as User & Record<string, unknown>,
		};
	}

	async function revokeDatabaseSession(
		target: DatabaseSessionRevocationTarget,
		reuseDetectedAt?: Date | undefined,
	): Promise<DatabaseSessionRevocationOutcome> {
		if (!storesSessionsInDatabase) return { kind: "noop" };
		return runWithTransaction(adapter, async () => {
			const currentAdapter = await getCurrentAdapter(adapter);
			const initial = await resolveDatabaseSessionRevocation(
				target,
				currentAdapter,
			);
			if (!initial) {
				if (target.kind === "id" && target.allowOrphanCleanup) {
					const outcome = {
						kind: "orphan_cleanup" as const,
						sessionId: target.sessionId,
						expectedCredentialKeys: [],
					};
					await queueDatabaseSessionRevocationCleanup(outcome);
					return outcome;
				}
				return { kind: "noop" };
			}
			const initialUser = await currentAdapter.findOne<User>({
				model: "user",
				where: [{ field: "id", value: initial.session.userId }],
			});
			if (initialUser) {
				await lockAndReadUser(currentAdapter, initialUser.id);
			}
			const locked = await resolveDatabaseSessionRevocation(
				target,
				currentAdapter,
			);
			if (!locked || locked.session.id !== initial.session.id) {
				return { kind: "noop" };
			}
			let captured = await readSessionRevocationCredentialKeys(
				currentAdapter,
				locked.session,
			);
			const userId = locked.session.userId;
			const preserveModernSession =
				!legacyCredentialAuthority &&
				ctx.options.session?.preserveSessionInDatabase === true;
			if (preserveModernSession) {
				if (captured.credentials.length === 0) {
					const outcome = {
						kind: "authority_cleanup" as const,
						sessionId: locked.session.id,
						userId,
						expectedCredentialKeys: captured.keys,
					};
					await queueDatabaseSessionRevocationCleanup(outcome);
					return outcome;
				}
				const revokedAt = reuseDetectedAt ?? new Date();
				const count = await currentAdapter.updateMany({
					model: SESSION_CREDENTIAL_MODEL,
					where: [{ field: "sessionId", value: locked.session.id }],
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
				if (Number(count) < 1) return { kind: "noop" };
				const outcome = {
					kind: "revoked" as const,
					sessionId: locked.session.id,
					userId,
					expectedCredentialKeys: captured.keys,
				};
				await queueDatabaseSessionRevocationCleanup(outcome);
				return outcome;
			}

			let mutationCompleted = false;
			const deleted = await deleteWithHooks<Session>(
				[{ field: "id", value: locked.session.id }],
				"session",
				{
					executeMainFn: false,
					usesTransactionAdapter: true,
					async fn(_where, transactionAdapter) {
						const reconfirmed = await resolveDatabaseSessionRevocation(
							target,
							transactionAdapter,
						);
						if (!reconfirmed || reconfirmed.session.id !== locked.session.id) {
							return null;
						}
						captured = await readSessionRevocationCredentialKeys(
							transactionAdapter,
							reconfirmed.session,
						);
						const revokedAt = reuseDetectedAt ?? new Date();
						await transactionAdapter.updateMany({
							model: SESSION_CREDENTIAL_MODEL,
							where: [{ field: "sessionId", value: locked.session.id }],
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
						await transactionAdapter.delete({
							model: "session",
							where: [{ field: "id", value: locked.session.id }],
						});
						mutationCompleted = !(await transactionAdapter.findOne<Session>({
							model: "session",
							where: [{ field: "id", value: locked.session.id }],
						}));
						return mutationCompleted ? reconfirmed.session : null;
					},
				},
			);
			if (!deleted || !mutationCompleted) return { kind: "noop" };
			const outcome = {
				kind: "deleted" as const,
				sessionId: locked.session.id,
				userId,
				expectedCredentialKeys: captured.keys,
			};
			await queueDatabaseSessionRevocationCleanup(outcome);
			return outcome;
		});
	}

	async function revokeAndDeleteSessionById(
		sessionId: string,
		reuseDetectedAt?: Date | undefined,
	): Promise<DatabaseSessionRevocationOutcome> {
		return revokeDatabaseSession({ kind: "id", sessionId }, reuseDetectedAt);
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
			const lineage = await findCanonicalManagedCredentialLineage({
				session: authority.session,
				credentialAnchors: [parent, successor],
				requireValidDigests: true,
			});
			if (
				!lineage ||
				lineage.active.id !== successor.id ||
				!lineage.consumed.some((candidate) => candidate.id === parent.id)
			) {
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
		const expectedSession = {
			...rotation.session,
			token: createSessionHandle(rotation.session.id),
		} as Session & Record<string, unknown>;
		await queueBeforeTransactionCommitHook(async () => {
			const authority = await loadStrictManagedSessionAuthority(
				rotation.session.id,
				[rotation.parentCredential, rotation.successorCredential],
			);
			if (
				!authority ||
				authority.user.id !== rotation.user.id ||
				authority.lineage.active.id !== rotation.successorCredential.id ||
				!authority.lineage.consumed.some(
					(candidate) => candidate.id === rotation.parentCredential.id,
				) ||
				!sameImmutableSessionAuthority(authority.session, expectedSession)
			) {
				throw new ManagedSessionRotationRejected();
			}
		}, adapter);
		if (!secondaryStorage) return;
		await queueAfterTransactionHook(
			() =>
				publishManagedSessionAfterCommitSafely({
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
			const stagedIssuanceAuthority = authenticationPolicy
				? requireStagedSessionIssuanceAuthority(issuanceContext)
				: null;
			const managedIssuanceContext = authenticationPolicy && !stagedIssuanceAuthority
				? requireInternalSessionIssuanceContext(issuanceContext)
				: undefined;
			const capturedIssuanceAuthority =
				managedIssuanceContext?.purpose === "replacement" ||
				managedIssuanceContext?.purpose === "device" ||
				managedIssuanceContext?.purpose === "organization" ||
				managedIssuanceContext?.purpose === "impersonation"
					? requireCapturedSessionIssuanceAuthority(issuanceContext)
					: undefined;
			if (
				(managedIssuanceContext?.purpose === "interactive" ||
					managedIssuanceContext?.purpose === "impersonation") &&
				managedIssuanceContext.subjectId !== userId
			) {
				throw new ManagedSessionIssuanceError("subject_mismatch");
			}
			if (
				capturedIssuanceAuthority &&
				managedIssuanceContext?.purpose !== "impersonation" &&
				capturedIssuanceAuthority.sourceSubjectId !== userId
			) {
				throw new ManagedSessionIssuanceError("subject_mismatch");
			}
			if (
				stagedIssuanceAuthority &&
				(stagedIssuanceAuthority.subjectId !== userId ||
					stagedIssuanceAuthority.dontRememberMe !== Boolean(dontRememberMe))
			) {
				throw new ManagedSessionIssuanceError("subject_mismatch");
			}
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
			if (
				authenticationPolicy &&
				managedIssuanceContext?.purpose !== "impersonation" &&
				Object.hasOwn(safeOverride, "impersonatedBy")
			) {
				throw new ManagedSessionIssuanceError("context_invalid");
			}
			if (
				managedIssuanceContext?.purpose === "impersonation" &&
				(!capturedIssuanceAuthority ||
					safeOverride.impersonatedBy !==
						capturedIssuanceAuthority.sourceSubjectId)
			) {
				throw new ManagedSessionIssuanceError("context_invalid");
			}
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
			if (authenticationPolicy) delete defaultAdditionalFields.impersonatedBy;
			const policyExpiresAt = dontRememberMe
				? getDate(60 * 60 * 24, "sec")
				: getDate(sessionExpiration, "sec");
			const inheritedExpiresAt = new Date(
				(rest.expiresAt as string | number | Date | undefined) ?? Number.NaN,
			);
			const requestedExpiresAt =
				__preserveSessionExpiresAt === true &&
				Number.isFinite(inheritedExpiresAt.getTime()) &&
				inheritedExpiresAt > new Date() &&
				inheritedExpiresAt < policyExpiresAt
					? inheritedExpiresAt
					: policyExpiresAt;
			const expiresAt =
				capturedIssuanceAuthority?.sourceExpiresAt &&
				capturedIssuanceAuthority.sourceExpiresAt < requestedExpiresAt
					? new Date(capturedIssuanceAuthority.sourceExpiresAt)
					: requestedExpiresAt;
			const managedSessionTargetOrganizationId =
				managedIssuanceContext?.purpose === "organization" ||
				managedIssuanceContext?.purpose === "device" ||
				managedIssuanceContext?.purpose === "impersonation"
					? managedIssuanceContext.targetOrganizationId
					: undefined;
			const impersonatedBy =
				managedIssuanceContext?.purpose === "impersonation"
					? capturedIssuanceAuthority?.sourceSubjectId
					: undefined;
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
				...(managedSessionTargetOrganizationId !== undefined
					? {
							activeOrganizationId: managedSessionTargetOrganizationId,
							activeTeamId: null,
						}
					: {}),
				...(impersonatedBy ? { impersonatedBy } : {}),
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
				if (authenticationPolicy) delete safeHookedData.impersonatedBy;
				return {
					...safeHookedData,
					...(requestedSessionId ? { id: requestedSessionId } : {}),
					expiresAt,
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
					...(managedSessionTargetOrganizationId !== undefined
						? {
								activeOrganizationId: managedSessionTargetOrganizationId,
								activeTeamId: null,
							}
						: {}),
					...(impersonatedBy ? { impersonatedBy } : {}),
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
				if (
					capturedIssuanceAuthority &&
					(capturedIssuanceAuthority.transactionAdapter !== currentAdapter ||
						capturedIssuanceAuthority.sourceExpiresAt <= new Date())
				) {
					throw new ManagedSessionIssuanceError("context_invalid");
				}
				if (
					stagedIssuanceAuthority &&
					(stagedIssuanceAuthority.transactionAdapter !== currentAdapter ||
						stagedIssuanceAuthority.expiresAt <= new Date())
				) {
					throw new ManagedSessionIssuanceError("context_invalid");
				}
				let assuranceFields: SessionAssuranceFields | undefined;
				if (
					authenticationPolicy &&
					(managedIssuanceContext || stagedIssuanceAuthority)
				) {
					const requestedTargetOrganizationId =
						managedIssuanceContext?.purpose === "organization" ||
						managedIssuanceContext?.purpose === "device" ||
						managedIssuanceContext?.purpose === "impersonation"
							? managedIssuanceContext.targetOrganizationId
							: (capturedIssuanceAuthority?.sourceOrganizationId ??
									managedIssuanceContext?.targetOrganizationId);
					const targetOrganizationId =
						requestedTargetOrganizationId || undefined;
					const resolvedPolicy = await resolveRuntimeAuthenticationPolicy(
						options,
						{
							subjectId: userId,
							...(targetOrganizationId
								? { organizationId: targetOrganizationId }
								: {}),
							...(stagedIssuanceAuthority
								? { minimumRevision: stagedIssuanceAuthority.policyRevision }
								: {}),
							transaction: currentAdapter,
						},
					);
					const policySnapshot = {
						identity: resolvedPolicy.scope,
						organizationId: targetOrganizationId ?? null,
						revision: resolvedPolicy.revision,
						policy: resolvedPolicy.effective,
					} as const;
					if (stagedIssuanceAuthority) {
						if (
							resolvedPolicy.scope.projectId !==
								stagedIssuanceAuthority.projectId ||
							resolvedPolicy.scope.environmentId !==
								stagedIssuanceAuthority.environmentId ||
							resolvedPolicy.revision !==
								stagedIssuanceAuthority.policyRevision ||
							(await digestStagedAuthenticationPolicy(
								resolvedPolicy.effective,
							)) !== stagedIssuanceAuthority.policyDigest
						) {
							throw new ManagedSessionIssuanceError("policy_unsatisfied");
						}
					}
					const issuanceNow = new Date();
					const evaluation = stagedIssuanceAuthority
						? evaluateStagedSessionIssuance({
								policy: policySnapshot,
								now: issuanceNow,
								primaryMethod: stagedIssuanceAuthority.primaryMethod,
								primaryAt: stagedIssuanceAuthority.primaryAt,
								factorMethod: stagedIssuanceAuthority.factorMethod,
								factorAt: stagedIssuanceAuthority.factorAt,
							})
						: evaluateSessionIssuance({
								purpose: managedIssuanceContext!.purpose,
								policy: policySnapshot,
								now: issuanceNow,
								evidence:
									managedIssuanceContext!.purpose === "interactive" ||
									managedIssuanceContext!.purpose === "impersonation"
										? managedIssuanceContext!.evidence
										: [],
								...(capturedIssuanceAuthority &&
								managedIssuanceContext?.purpose !== "impersonation"
									? {
											sourceAssurance:
												capturedIssuanceAuthority.sourceAssurance,
										}
									: {}),
							});
					if (evaluation.kind !== "satisfied") {
						const failure = new ManagedSessionIssuanceError("policy_unsatisfied", {
							requirement: evaluation.requirement,
						});
						const evidence =
							managedIssuanceContext?.purpose === "interactive"
								? managedIssuanceContext.evidence
								: [];
						const primary = evidence.length === 1 ? evidence[0] : undefined;
						const passkeyAvailable = Boolean(
							options.plugins?.some((plugin) => plugin.id === "passkey"),
						);
						const twoFactorPlugin = options.plugins?.find(
							(plugin) => plugin.id === "two-factor",
						);
						const totpAvailable = Boolean(
							twoFactorPlugin &&
								(
									twoFactorPlugin.options as
										| { totpOptions?: { disable?: boolean } }
										| undefined
								)?.totpOptions?.disable !== true,
						);
						const allowedFactors = (
							evaluation.requirement.reason === "phishing_resistant_required"
								? (["passkey"] as const)
								: ([
										...(evaluation.requirement.allowedFactors.passkey
											? (["passkey"] as const)
											: []),
										...(evaluation.requirement.allowedFactors.totp
											? (["totp"] as const)
											: []),
									] as const)
						).filter(
							(factor) =>
								(factor === "passkey" && passkeyAvailable) ||
								(factor === "totp" && totpAvailable),
						);
						if (
							!stagedIssuanceAuthority &&
							managedIssuanceContext?.purpose === "interactive" &&
							managedIssuanceContext.targetOrganizationId === null &&
							primary?.kind === "primary" &&
							primary.primaryMethod !== "anonymous" &&
							primary.primaryMethod !== "admin_impersonation" &&
							(evaluation.requirement.reason === "factor_required" ||
								evaluation.requirement.reason ===
									"phishing_resistant_required") &&
							allowedFactors.length > 0
						) {
							await attachStagedAuthenticationContinuation(failure, {
								subjectId: userId,
								projectId: resolvedPolicy.scope.projectId,
								environmentId: resolvedPolicy.scope.environmentId,
								organizationId: null,
								policyRevision: resolvedPolicy.revision,
								policyDigest: await digestStagedAuthenticationPolicy(
									resolvedPolicy.effective,
								),
								primaryMethod: primary.primaryMethod,
								primaryAt: issuanceNow,
								dontRememberMe: Boolean(dontRememberMe),
								allowedFactors,
								expiresAt: new Date(
									issuanceNow.getTime() +
										STAGED_AUTHENTICATION_TTL_SECONDS * 1_000,
								),
							});
						}
						throw failure;
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
						let stagedPolicyUnchanged = true;
						if (stagedIssuanceAuthority) {
							stagedPolicyUnchanged =
								stagedIssuanceAuthority.transactionAdapter ===
									currentAdapter &&
								stagedIssuanceAuthority.expiresAt > new Date();
							const finalPolicy = await resolveRuntimeAuthenticationPolicy(
								options,
								{
									subjectId: userId,
									minimumRevision:
										stagedIssuanceAuthority.policyRevision,
									transaction: currentAdapter,
								},
							);
							stagedPolicyUnchanged =
								stagedPolicyUnchanged &&
								finalPolicy.scope.projectId ===
									stagedIssuanceAuthority.projectId &&
								finalPolicy.scope.environmentId ===
									stagedIssuanceAuthority.environmentId &&
								finalPolicy.revision ===
									stagedIssuanceAuthority.policyRevision &&
								(await digestStagedAuthenticationPolicy(
									finalPolicy.effective,
								)) === stagedIssuanceAuthority.policyDigest;
						}
						let capturedReplacementSourceRetired = true;
						if (
							(managedIssuanceContext?.purpose === "replacement" ||
								managedIssuanceContext?.purpose === "organization") &&
							capturedIssuanceAuthority
						) {
							const sourceSession = await currentAdapter.findOne<Session>({
								model: "session",
								where: [
									{
										field: "id",
										value: capturedIssuanceAuthority.sourceSessionId,
									},
								],
							});
							if (legacyCredentialAuthority) {
								capturedReplacementSourceRetired = sourceSession === null;
							} else {
								const activeSourceCredentials =
									await currentAdapter.findMany<SessionCredential>({
										model: SESSION_CREDENTIAL_MODEL,
										where: [
											{
												field: "sessionId",
												value:
													capturedIssuanceAuthority.sourceSessionId,
											},
											{ field: "status", value: "active" },
										],
									});
								const capturedSourceCredential =
									capturedIssuanceAuthority.sourceCredentialId === null
										? null
										: await currentAdapter.findOne<SessionCredential>({
												model: SESSION_CREDENTIAL_MODEL,
												where: [
													{
														field: "id",
														value:
															capturedIssuanceAuthority.sourceCredentialId,
													},
												],
											});
								capturedReplacementSourceRetired =
									activeSourceCredentials.length === 0 &&
									capturedSourceCredential?.status !== "active";
							}
						}
						let capturedDerivativeSourceUnchanged = true;
						if (
							capturedIssuanceAuthority &&
							managedIssuanceContext?.purpose === "device"
						) {
							try {
								const source = await validateInternalSessionDerivativeAuthority(
									internalAdapter,
									managedIssuanceContext.sourceSessionDerivativeAuthority,
									{
										purpose: "device",
										subjectId: userId,
										organizationId:
											managedIssuanceContext.targetOrganizationId,
									},
								);
								capturedDerivativeSourceUnchanged =
									source !== undefined &&
									source.sourceSessionId ===
										capturedIssuanceAuthority.sourceSessionId &&
									source.sourceSubjectId ===
										capturedIssuanceAuthority.sourceSubjectId &&
									source.sourceOrganizationId ===
										capturedIssuanceAuthority.sourceOrganizationId &&
									source.sourceExpiresAt ===
										capturedIssuanceAuthority.sourceExpiresAt.getTime() &&
									source.policyProjectId ===
										capturedIssuanceAuthority.sourceAssurance
											.authenticationPolicyProjectId &&
									source.policyEnvironmentId ===
										capturedIssuanceAuthority.sourceAssurance
											.authenticationPolicyEnvironmentId &&
									source.policyRevision ===
										capturedIssuanceAuthority.sourceAssurance
											.authenticationPolicyRevision;
							} catch {
								capturedDerivativeSourceUnchanged = false;
							}
						}
						if (
							capturedIssuanceAuthority &&
							managedIssuanceContext?.purpose === "impersonation"
						) {
							try {
								const source = await loadStrictManagedSessionAuthorityById(
									capturedIssuanceAuthority.sourceSessionId,
								);
								const sourceExpiresAt = source?.session.expiresAt;
								const sourceAssurance = source?.assurance;
								capturedDerivativeSourceUnchanged =
									Boolean(source && sourceAssurance) &&
									source!.user.id === capturedIssuanceAuthority.sourceSubjectId &&
									sourceAssurance!.authenticationPolicyOrganizationId ===
										capturedIssuanceAuthority.sourceOrganizationId &&
									sourceExpiresAt instanceof Date &&
									sourceExpiresAt.getTime() ===
										capturedIssuanceAuthority.sourceExpiresAt.getTime() &&
									sourceAssurance!.authenticationPolicyProjectId ===
										capturedIssuanceAuthority.sourceAssurance
											.authenticationPolicyProjectId &&
									sourceAssurance!.authenticationPolicyEnvironmentId ===
										capturedIssuanceAuthority.sourceAssurance
											.authenticationPolicyEnvironmentId &&
									sourceAssurance!.authenticationPolicyRevision ===
										capturedIssuanceAuthority.sourceAssurance
											.authenticationPolicyRevision;
							} catch {
								capturedDerivativeSourceUnchanged = false;
							}
						}
						if (
							!activeUser ||
							!stagedPolicyUnchanged ||
							!capturedReplacementSourceRetired ||
							!capturedDerivativeSourceUnchanged ||
							capturedIssuanceAuthority?.sourceSessionId ===
								persistedSessionId ||
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
								requireValidDigests: true,
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
									publishManagedSessionAfterCommitSafely({
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
				// Runtime audit is a product-bound, database-transaction-only authority.
				// Secondary-authoritative sessions have no equivalent atomic outbox, so they
				// deliberately remain outside this audit path.
				if (storesSessionsInDatabase) {
					const transactionAdapter = await getCurrentAdapter(adapter);
					const runtimeAudit =
						readInternalRuntimeAudit(transactionAdapter) ??
						readInternalRuntimeAudit(adapter) ??
						(adapter.options
							? readInternalRuntimeAudit(adapter.options)
							: undefined);
					if (runtimeAudit) {
						attachCapturedInternalRuntimeAudit(
							transactionAdapter,
							runtimeAudit,
						);
						const persistedSession = await transactionAdapter.findOne<
							Session & Record<string, unknown>
						>({
							model: "session",
							where: [{ field: "id", value: String((res as Session).id) }],
						});
						if (!persistedSession || !(persistedSession.expiresAt instanceof Date)) {
							throw new Error("Could not read the persisted session for audit");
						}

						const issuancePurpose = stagedIssuanceAuthority
							? "interactive"
							: (managedIssuanceContext?.purpose ?? "direct");
						const actor =
							capturedIssuanceAuthority?.sourceSubjectId ??
							(managedIssuanceContext?.purpose === "interactive" ||
							managedIssuanceContext?.purpose === "impersonation"
								? managedIssuanceContext.subjectId
								: undefined) ??
							stagedIssuanceAuthority?.subjectId ??
							userId;
						const primaryMethod = persistedSession.authenticationPrimaryMethod;
						const factorMethod = persistedSession.authenticationFactorMethod;
						const assuranceLevel =
							typeof primaryMethod !== "string"
								? null
								: primaryMethod === "passkey" || factorMethod === "passkey"
									? "phishing_resistant"
									: factorMethod === null || factorMethod === undefined
										? "single_factor"
										: "multi_factor";
						const request =
							(await getRuntimeAuditRequestContext()) ??
							Object.freeze({
								correlationId: `rt_${generateId(24)}`,
								operationId: "internal.createSession",
								route: "/internal/session",
								method: "INTERNAL",
								clientIp: null,
								userAgent: null,
							});
						const managedInteractive =
							stagedIssuanceAuthority !== null ||
							managedIssuanceContext?.purpose === "interactive";
						const unmanagedMethod =
							stagedIssuanceAuthority || managedIssuanceContext
								? null
									: classifyRuntimeInteractiveAuthenticationRoute(request.route);
						const managedMethods = stagedIssuanceAuthority
							? [
									stagedIssuanceAuthority.primaryMethod,
									stagedIssuanceAuthority.factorMethod,
								]
							: managedIssuanceContext?.purpose === "interactive"
								? managedIssuanceContext.evidence.map((evidence) =>
										evidence.kind === "primary"
											? evidence.primaryMethod
											: evidence.factorMethod,
									)
								: [];
						const methods: string[] = Array.from(
							new Set(
								managedMethods.filter((method) =>
									runtimeAuditAuthenticationMethods.has(method),
								),
							),
						);
						if (unmanagedMethod) methods.push(unmanagedMethod);
						const metadata = {
							issuancePurpose,
							targetUserId: userId,
							expiresAt: persistedSession.expiresAt.toISOString(),
							assuranceLevel,
							primaryMethod: typeof primaryMethod === "string" ? primaryMethod : null,
							factorMethod: typeof factorMethod === "string" ? factorMethod : null,
							...(typeof persistedSession.impersonatedBy === "string"
								? { impersonatedBy: persistedSession.impersonatedBy }
								: {}),
						};
						await appendInternalRuntimeAudit(transactionAdapter, {
							actor,
							action: "auth.session.created",
							subjectType: "session",
							subjectId: persistedSession.id,
							outcome: "success",
							source: "system",
							organizationId:
								typeof persistedSession.activeOrganizationId === "string"
									? persistedSession.activeOrganizationId
									: null,
							message: "Session created",
							metadata,
							request,
						});
						if (managedInteractive || unmanagedMethod !== null) {
							await appendInternalRuntimeAudit(transactionAdapter, {
								actor,
								action: "auth.login.succeeded",
								subjectType: "session",
								subjectId: persistedSession.id,
								outcome: "success",
								source: "system",
								organizationId:
									typeof persistedSession.activeOrganizationId === "string"
										? persistedSession.activeOrganizationId
										: null,
								message: "Interactive authentication succeeded",
								metadata: { ...metadata, methods },
								request,
							});
						}
					}
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
				if (
					authenticationPolicy &&
					storesSessionsInDatabase &&
					!legacyCredentialAuthority
				) {
					const credential = await findExactManagedCredentialCandidate(token);
					if (!credential) return null;
					if (!credential.sessionId) {
						const credentialKey = secondaryCredentialKey(
							credential.secretDigest,
						);
						const observedValue = secondaryStorage
							? await secondaryStorage.get(credentialKey)
							: null;
						if (typeof observedValue === "string") {
							await queueManagedOrphanCredentialCleanup(
								credentialKey,
								observedValue,
							);
						}
						return null;
					}
					const authority = await loadManagedModernDatabaseSession({
						sessionId: credential.sessionId,
						presentedCredential: credential,
						presentedToken: token,
					});
					if (!authority) return null;
					return {
						session: parseInternalSessionOutput(
							ctx.options,
							authority.session,
						),
						user: parseUserOutput(ctx.options, authority.user),
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
				if (
					authenticationPolicy &&
					storesSessionsInDatabase &&
					!legacyCredentialAuthority
				) {
					const authority = await loadManagedModernDatabaseSession({ sessionId });
					if (!authority) return null;
					return {
						session: parseInternalSessionOutput(
							ctx.options,
							authority.session,
						),
						user: parseUserOutput(ctx.options, authority.user),
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
			let recovered: SessionRecoveryAttempt;
			try {
				recovered = await runWithTransaction(adapter, async () => {
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
			} catch (error) {
				if (error instanceof ManagedSessionRotationRejected) return null;
				throw error;
			}
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
				const recoverConsumedCredential = async (
					consumedCredential: SessionCredential,
					validatedAuthority: ValidatedSessionAuthority,
				): Promise<SessionRotationResult | null> => {
					const recovered = await recoverRecentSessionRotation(
						consumedCredential,
						rotationNonceDigest,
						rotationOperation,
						digest,
						validatedAuthority,
					);
					if (recovered === recoveryCredentialRejected) return null;
					if (recovered) {
						await queueManagedRotationPublication(recovered);
						return recovered;
					}
					await revokeAndDeleteSessionById(
						consumedCredential.sessionId!,
						new Date(),
					);
					return null;
				};
				if (credential.status !== "active") {
					if (credential.status === "consumed") {
						const authority = await loadValidatedSessionAuthority(credential.sessionId);
						if (!authority) return null;
						return recoverConsumedCredential(credential, authority);
					}
					return null;
				}
				if (credential.expiresAt <= new Date()) return null;

				const authority = await loadStrictManagedSessionAuthority(
					credential.sessionId,
					[credential],
				);
				if (!authority) return null;
				if (authority.lineage.active.id !== credential.id) {
					const transitionedCredential = await rereadExactCredential(credential);
					if (transitionedCredential?.status === "consumed") {
						return recoverConsumedCredential(
							transitionedCredential,
							authority,
						);
					}
					return null;
				}

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
				const rotationGuard: Where[] = [
					{ field: "id", value: activeCredential.id },
					{ field: "sessionId", value: activeSessionId },
					{ field: "status", value: "active" },
					{ field: "secretDigest", value: digest },
					{ field: "familyId", value: activeCredential.familyId },
					{
						field: "rotationCounter",
						value: activeCredential.rotationCounter,
					},
					{ field: "expiresAt", value: activeCredential.expiresAt },
					{ field: "expiresAt", value: consumedAt, operator: "gt" },
				];
				// Serial-ID adapters transform reference operands through Number().
				// Omitting the already-validated root null avoids turning SQL NULL into 0;
				// every non-root rotation still binds the exact parent foreign key.
				if (activeCredential.parentCredentialId != null) {
					rotationGuard.push({
						field: "parentCredentialId",
						value: activeCredential.parentCredentialId,
					});
				}
				const consumed = await currentAdapter.incrementOne<SessionCredential>({
					model: SESSION_CREDENTIAL_MODEL,
					where: rotationGuard,
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

				const persistedParent = await rereadExactCredential(consumed);
				if (
					!persistedParent ||
					persistedParent.status !== "consumed" ||
					persistedParent.expiresAt <= consumedAt
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
				const committedAuthority = await loadStrictManagedSessionAuthority(
					activeSessionId,
					[persistedParent, persistedSuccessor],
				);
				if (
					!committedAuthority ||
					committedAuthority.lineage.active.id !== persistedSuccessor.id ||
					!committedAuthority.lineage.consumed.some(
						(candidate) => candidate.id === persistedParent.id,
					)
				) {
					throw new ManagedSessionRotationRejected();
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
										publishManagedSessionAfterCommitSafely({
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
				if (storesSessionsInDatabase) {
					await revokeDatabaseSession({ kind: "token", token });
					return;
				}
				const handleSessionId = sessionIdFromHandle(token);
			let sessionId = handleSessionId ?? undefined;
			let credentialKey: string | null = null;
			let secondaryUserId: string | undefined;
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

				await queueAfterTransactionHook(cleanupSecondarySession, adapter);
			}
		},
		deleteSessionById: async (sessionId: string) => {
			if (storesSessionsInDatabase) {
				await revokeDatabaseSession({
					kind: "id",
					sessionId,
					allowOrphanCleanup: true,
				});
				return;
			}
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
			if (storesSessionsInDatabase) {
				await runWithTransaction(adapter, async () => {
					const currentAdapter = await getCurrentAdapter(adapter);
					await lockAndReadUser(currentAdapter, userId);
					const lockedSessions = await currentAdapter.findMany<Session>({
						model: "session",
						where: [{ field: "userId", value: userId }],
					});
					if (lockedSessions.length === 0) return;

					const lockedSessionIds = [...lockedSessions]
						.map((session) => session.id)
						.sort();
					const preserveModernSessions =
						!legacyCredentialAuthority &&
						ctx.options.session?.preserveSessionInDatabase === true;
					if (preserveModernSessions) {
						const targets = await readBulkDatabaseSessionRevocationTargets(
							currentAdapter,
							lockedSessions,
						);
						const revokedAt = new Date();
						await revokeAndVerifyBulkDatabaseSessionCredentials(
							currentAdapter,
							targets,
							revokedAt,
						);
						await queueBulkDatabaseSessionRevocationCleanup({ userId, targets });
						return;
					}

					let targets: BulkDatabaseSessionRevocationTarget[] = [];
					let mutationCompleted = false;
					const deleted = await deleteManyWithHooks<Session>(
						[{ field: "userId", value: userId }],
						"session",
						{
							executeMainFn: false,
							usesTransactionAdapter: true,
							async fn(_where, transactionAdapter) {
								const reconfirmed = await transactionAdapter.findMany<Session>({
									model: "session",
									where: [{ field: "userId", value: userId }],
								});
								const reconfirmedIds = reconfirmed
									.map((session) => session.id)
									.sort();
								if (
									reconfirmedIds.length !== lockedSessionIds.length ||
									reconfirmedIds.some(
										(sessionId, index) => sessionId !== lockedSessionIds[index],
									)
								) {
									throw new Error(
										"Locked bulk session revocation target set changed",
									);
								}
								targets = await readBulkDatabaseSessionRevocationTargets(
									transactionAdapter,
									reconfirmed,
								);
								const revokedAt = new Date();
								await revokeAndVerifyBulkDatabaseSessionCredentials(
									transactionAdapter,
									targets,
									revokedAt,
								);
								for (const sessionId of lockedSessionIds) {
									await transactionAdapter.delete({
										model: "session",
										where: [{ field: "id", value: sessionId }],
									});
								}
								const remaining = await transactionAdapter.findMany<Session>({
									model: "session",
									where: [{ field: "userId", value: userId }],
								});
								mutationCompleted = remaining.length === 0;
								if (!mutationCompleted) {
									throw new Error(
										"Locked bulk session revocation delete was incomplete",
									);
								}
								return reconfirmed;
							},
						},
					);
					if (!deleted || !mutationCompleted) return;
					await queueBulkDatabaseSessionRevocationCleanup({ userId, targets });
				});
				return;
			}

			const sessions = await internalAdapter.listSessions(userId);
			await queueAfterTransactionHook(async () => {
				for (const session of sessions) {
					await internalAdapter.deleteSession(createSessionHandle(session.id));
				}
				await secondaryStorage?.delete(secondaryActiveSessionsKey(userId));
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
			if (authenticationPolicy && storesSessionsInDatabase) {
				return runWithTransaction(adapter, async () => {
					const currentAdapter = await getCurrentAdapter(adapter);
					const authoritativeUser = await currentAdapter.findOne<User>({
						model: "user",
						where: [{ field: "id", value: userId }],
					});
					const user = await updateWithHooks<User>(
						{
							...data,
							...(data.email ? { email: data.email.toLowerCase() } : {}),
						},
						[{ field: "id", value: userId }],
						"user",
						undefined,
					);
					if (authoritativeUser && user) {
						await queueManagedUserSessionReconciliation(authoritativeUser.id);
					}
					return user;
				});
			}
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
			if (authenticationPolicy && storesSessionsInDatabase) {
				return runWithTransaction(adapter, async () => {
					const currentAdapter = await getCurrentAdapter(adapter);
					const authoritativeUser = await currentAdapter.findOne<User>({
						model: "user",
						where: [{ field: "email", value: email.toLowerCase() }],
					});
					const user = await updateWithHooks<User>(
						{
							...data,
							...(data.email ? { email: data.email.toLowerCase() } : {}),
						},
						[{ field: "email", value: email.toLowerCase() }],
						"user",
						undefined,
					);
					if (authoritativeUser && user) {
						await queueManagedUserSessionReconciliation(authoritativeUser.id);
					}
					return user;
				});
			}
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
			challengeContext,
		) => {
			const storageOption = getStorageOption(
				data.identifier,
				options.verification?.storeIdentifier,
			);
			const storedIdentifier = await processIdentifier(
				data.identifier,
				storageOption,
			);
			if (authenticationPolicy) {
				const provenance = requireInternalVerificationChallengeContext(
					challengeContext,
				);
				if (
					provenance.identifier !== data.identifier ||
					provenance.value !== data.value ||
					!(data.expiresAt instanceof Date) ||
					provenance.expiresAt.getTime() !== data.expiresAt.getTime()
				) {
					throw new ManagedVerificationChallengeError("challenge_mismatch");
				}
				if (
					typeof adapter.options?.adapterConfig.transaction !== "function"
				) {
					throw new Error(
						"Managed verification challenge issuance requires rollback-capable database transactions",
					);
				}
				return runWithTransaction(adapter, async () => {
					const secondaryOnly =
						Boolean(secondaryStorage) &&
						options.verification?.storeInDatabase !== true;
					const now = new Date();
					const assertUnchangedChallenge = (
						verification: Verification,
					) => {
						if (
							verification.identifier !== storedIdentifier ||
							verification.value !== provenance.value ||
							!(verification.expiresAt instanceof Date) ||
							verification.expiresAt.getTime() !==
								provenance.expiresAt.getTime()
						) {
							throw new ManagedVerificationChallengeError(
								"challenge_mismatch",
							);
						}
					};
					const verification = (await createWithHooks(
						{
							...data,
							...(secondaryOnly ? { id: generateId() } : {}),
							identifier: storedIdentifier,
							createdAt: data.createdAt ?? now,
							updatedAt: data.updatedAt ?? now,
						},
						"verification",
						secondaryStorage
							? {
									executeMainFn:
										options.verification?.storeInDatabase === true,
									usesTransactionAdapter: true,
									async fn(verificationData, transactionAdapter) {
										const created = verificationData as Verification;
										assertUnchangedChallenge(created);
										await createManagedVerificationMarker(
											transactionAdapter,
											created,
											provenance,
										);
										await queueAfterTransactionHook(async () => {
											const ttl = getTTLSeconds(created.expiresAt);
											if (ttl <= 0) return;
											await secondaryStorage.set(
												`verification:${storedIdentifier}`,
												JSON.stringify(created),
												ttl,
											);
										}, adapter);
										return created;
									},
								}
								: undefined,
					)) as Verification;
					assertUnchangedChallenge(verification);
					if (!secondaryStorage) {
						await createManagedVerificationMarker(
							await getCurrentAdapter(adapter),
							verification,
							provenance,
						);
					}
					return verification;
				});
			}

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
		 * Secondary-storage-only verification requires provider-level atomic
		 * `getAndDelete`. Hashed identifier compatibility additionally requires a
		 * provider-level exclusive lease so its hashed and legacy-plain aliases
		 * are consumed as one logical credential across every process.
		 */
		consumeVerificationValue: async (
			identifier: string,
			challengeContext,
		): Promise<Verification | null> => {
			const storageOption = getStorageOption(
				identifier,
				options.verification?.storeIdentifier,
			);
			const storedIdentifier = await processIdentifier(
				identifier,
				storageOption,
			);
			const hashedIdentifier = await processIdentifier(identifier, "hashed");
			// Every reader recognizes the stable hashed representation and the
			// legacy plain representation, regardless of its current write setting.
			// Include the configured representation as well for custom hash options.
			const identifiersToTry = Array.from(
				new Set([hashedIdentifier, identifier, storedIdentifier]),
			);
			const consumeLockName = `verification-consume-v2:${base64Url.encode(
				new Uint8Array(
					await createHash("SHA-256").digest(
						new TextEncoder().encode(
							`verification-consume-v2:${identifier}`,
						),
					),
				),
				{ padding: false },
			)}`;

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
				const createdAt = new Date(candidate.createdAt);
				const updatedAt = new Date(candidate.updatedAt);
				if (
					!Number.isFinite(expiresAt.getTime()) ||
					!Number.isFinite(createdAt.getTime()) ||
					!Number.isFinite(updatedAt.getTime())
				) {
					return null;
				}
				return { ...candidate, expiresAt, createdAt, updatedAt };
			};

			if (authenticationPolicy) {
				if (!(await isTransactionActive(adapter))) {
					throw new Error(
						"Managed verification challenge consumption requires an active primary transaction",
					);
				}
				const provenance = requireInternalVerificationConsumptionContext(
					challengeContext,
				);
				if (provenance.identifier !== identifier) {
					throw new ManagedVerificationChallengeError("binding_mismatch");
				}
				const transactionAdapter = await getCurrentAdapter(adapter);
				const queueSecondaryCleanup = async () => {
					if (!secondaryStorage) return;
					await queueAfterTransactionHook(async () => {
						try {
							await Promise.all(
								identifiersToTry.map((stored) =>
									secondaryStorage.delete(`verification:${stored}`),
								),
							);
						} catch {
							if (!warnedManagedVerificationCleanupFailure) {
								warnedManagedVerificationCleanupFailure = true;
								logger.error(
									"Managed verification cache cleanup failed after commit",
								);
							}
						}
					}, adapter);
				};
				const selectLatestManagedVerification = (
					candidates: Verification[],
				): Verification | null =>
					candidates.sort((left, right) => {
						const createdAt =
							right.createdAt.getTime() - left.createdAt.getTime();
						if (createdAt !== 0) return createdAt;
						const alias =
							identifiersToTry.indexOf(left.identifier) -
							identifiersToTry.indexOf(right.identifier);
						if (alias !== 0) return alias;
						return left.id.localeCompare(right.id);
					})[0] ?? null;
				const retireManagedVerificationAliasMarkers = async (
					canonical: Verification,
					candidates: Verification[],
				): Promise<boolean> => {
					const marker = await consumeManagedVerificationMarker(
						transactionAdapter,
						canonical,
						provenance,
					);
					if (!marker) return false;
					for (const candidate of candidates) {
						if (candidate.id === canonical.id) continue;
						const aliasMarker =
							await transactionAdapter.findOne<ManagedVerificationChallengeMarker>({
								model: "securityMigration",
								where: [
									{
										field: "key",
										value: await managedVerificationMarkerKey(String(candidate.id)),
									},
								],
							});
						if (aliasMarker) {
							await consumeExactManagedVerificationMarker(
								transactionAdapter,
								aliasMarker,
							);
						}
					}
					return true;
				};

				if (secondaryStorage && !options.verification?.storeInDatabase) {
					if (identifiersToTry.length > 1 && !secondaryStorage.runExclusive) {
						throw new Error(
							"Secondary verification storage requires `runExclusive` to consume hashed managed verification identifier aliases",
						);
					}
					const consumeCachedAliases = async (): Promise<Verification | null> => {
						const cachedAliases: Verification[] = [];
						for (const stored of identifiersToTry) {
							const cached = hydrateCachedVerification(
								await secondaryStorage.get(`verification:${stored}`),
							);
							if (cached) cachedAliases.push(cached);
						}
						const cached = selectLatestManagedVerification(cachedAliases);
						if (
							!cached ||
							typeof cached.id !== "string" ||
							cached.id.length === 0 ||
							cached.expiresAt <= new Date()
						) {
							return null;
						}
						if (
							!(await retireManagedVerificationAliasMarkers(
								cached,
								cachedAliases,
							))
						) {
							return null;
						}
						await queueSecondaryCleanup();
						return cached;
					};
					return identifiersToTry.length > 1
						? secondaryStorage.runExclusive!(consumeLockName, consumeCachedAliases)
						: consumeCachedAliases();
				}

				const allAliasRows = (
					await Promise.all(
						identifiersToTry.map((stored) =>
							transactionAdapter.findMany<Verification>({
								model: "verification",
								where: [{ field: "identifier", value: stored }],
							}),
						),
					)
				).flat();
				const latest = selectLatestManagedVerification(allAliasRows);
				if (
					!latest ||
					!(latest.expiresAt instanceof Date) ||
					latest.expiresAt <= new Date()
				) {
					return null;
				}
				let markerConsumed = false;
				const consumed = await consumeOneWithHooks<Verification>(
					"verification",
					[{ field: "id", value: latest.id }],
					async (currentAdapter) => {
						markerConsumed = await retireManagedVerificationAliasMarkers(
							latest!,
							allAliasRows,
						);
						if (!markerConsumed) return null;
						const row = await currentAdapter.consumeOne<Verification>({
							model: "verification",
							where: [{ field: "id", value: latest!.id }],
						});
						if (!row) return null;
						for (const identifierAlias of identifiersToTry) {
							await currentAdapter.deleteMany({
								model: "verification",
								where: [{ field: "identifier", value: identifierAlias }],
							});
						}
						return row;
					},
					latest,
				);
				if (!consumed && markerConsumed) {
					throw new Error(
						"Managed verification challenge changed during consumption",
					);
				}
				await queueSecondaryCleanup();
				return consumed;
			}

			let consumed: Verification | null = null;

			if (secondaryStorage && !options.verification?.storeInDatabase) {
				if (!secondaryStorage.getAndDelete) {
					throw new Error(
						"Secondary verification storage requires `getAndDelete` for single-use verification consumption",
					);
				}
				if (identifiersToTry.length > 1 && !secondaryStorage.runExclusive) {
					throw new Error(
						"Secondary verification storage requires `runExclusive` to consume hashed verification identifier aliases",
					);
				}

				const consumeAliases = async () => {
					for (const stored of identifiersToTry) {
						const cached = hydrateCachedVerification(
							await secondaryStorage.getAndDelete!(
								`verification:${stored}`,
							),
						);
						if (!cached) continue;
						await Promise.all(
							identifiersToTry
								.filter((candidate) => candidate !== stored)
								.map((candidate) =>
									secondaryStorage.delete(`verification:${candidate}`),
								),
						);
						return cached;
					}
					return null;
				};

				consumed =
					identifiersToTry.length > 1
						? await secondaryStorage.runExclusive!(consumeLockName, consumeAliases)
						: await consumeAliases();
			} else {
				const consumeByIdentifiers = async (): Promise<Verification | null> =>
					await withVerificationConsumeLock(consumeLockName, () =>
						runWithTransaction(adapter, async () => {
							const txAdapter = await getCurrentAdapter(adapter);
							const rows = (
								await Promise.all(
									identifiersToTry.map((candidate) =>
										txAdapter.findMany<Verification>({
											model: "verification",
											where: [
												{ field: "identifier", value: candidate },
											],
										}),
									),
								)
							).flat();
							const latest = rows.sort((left, right) => {
								const createdAt = right.createdAt.getTime() - left.createdAt.getTime();
								if (createdAt !== 0) return createdAt;
								const alias =
									identifiersToTry.indexOf(left.identifier) -
									identifiersToTry.indexOf(right.identifier);
								if (alias !== 0) return alias;
								return left.id.localeCompare(right.id);
							})[0] ?? null;
							if (!latest) return null;

							return consumeOneWithHooks<Verification>(
								"verification",
								[{ field: "id", value: latest.id }],
								async (transactionAdapter) => {
									const row = await transactionAdapter.consumeOne<Verification>({
										model: "verification",
										where: [{ field: "id", value: latest.id }],
									});
									if (!row) return null;
									for (const identifierAlias of identifiersToTry) {
										await transactionAdapter.deleteMany({
											model: "verification",
											where: [
												{ field: "identifier", value: identifierAlias },
											],
										});
									}
									return row;
								},
								latest,
							);
						}),
					);

				consumed = await consumeByIdentifiers();

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
		 * First-writer-wins create keyed by a deterministic database key derived
		 * from `identifier`. Returns `true` when this caller created the row and
		 * `false` when a row for the same identifier already existed.
		 *
		 * The dual of `consumeVerificationValue`: where consume races to delete a
		 * marker exactly once, reserve races to create a marker exactly once. Use
		 * it for replay tombstones (a SAML assertion id, a JWT `jti`) where the
		 * first caller wins and every later caller must observe that the marker is
		 * already taken.
		 *
		 * Uniqueness comes from a digest-keyed row in the always-present primary
		 * security ledger. Its unique `key` is authoritative for every configured id
		 * strategy and verification storage mode. The reservation primitive never
		 * copies raw replay material into secondary storage.
		 *
		 * The adapter's native create-if-absent operation classifies an expected
		 * conflict without raising a uniqueness error, so losers remain usable even
		 * inside PostgreSQL transactions.
		 */
		reserveVerificationValue: async (data: {
			identifier: string;
			value: string;
			expiresAt: Date;
		}): Promise<boolean> => {
			const primaryReservationAdapter = await getCurrentAdapter(adapter);
			const reservationId = base64Url.encode(
				new Uint8Array(
					await createHash("SHA-256").digest(
						new TextEncoder().encode("reserve:" + data.identifier),
					),
				),
				{ padding: false },
			);
			// Use the always-present primary security ledger as the reservation gate
			// for every id strategy and storage mode. Only digests enter this row.
			const tombstoneKey = `verification-reservation-v1:${reservationId}`;
			const idStrategy = options.advanced?.database?.generateId;
			const databaseGeneratesTombstoneId =
				idStrategy === "serial" || idStrategy === "uuid";
			const valueDigest = base64Url.encode(
				new Uint8Array(
					await createHash("SHA-256").digest(
						new TextEncoder().encode("value:" + data.value),
					),
				),
				{ padding: false },
			);
			const reclaimExact = async (
				tombstone: VerificationReservationTombstone,
			): Promise<boolean> =>
				Boolean(
					await primaryReservationAdapter.consumeOne<VerificationReservationTombstone>({
						model: "securityMigration",
						where: [
							{ field: "id", value: tombstone.id },
							{ field: "key", value: tombstone.key },
							{ field: "state", value: tombstone.state },
							{ field: "phase", value: tombstone.phase },
							{ field: "cursor", value: tombstone.cursor },
							{ field: "revision", value: tombstone.revision },
							{ field: "completedAt", value: tombstone.completedAt },
							{ field: "updatedAt", value: tombstone.updatedAt },
						],
					}),
				);

			// Reclaim a bounded global batch because one-time JTIs rarely collide again.
			// Exact predicates keep a concurrently replaced row safe.
			const gcNow = new Date();
			const expired =
				await primaryReservationAdapter.findMany<VerificationReservationTombstone>({
					model: "securityMigration",
					where: [
						{ field: "state", value: "verification-reservation-v1" },
						{ field: "completedAt", value: gcNow, operator: "lte" },
					],
					sortBy: { field: "completedAt", direction: "asc" },
					limit: 8,
				});
			for (const tombstone of expired) {
				await reclaimExact(tombstone);
			}

			for (let attempt = 0; attempt < 2; attempt += 1) {
				const now = new Date();
				const existing =
					await primaryReservationAdapter.findOne<VerificationReservationTombstone>({
						model: "securityMigration",
						where: [{ field: "key", value: tombstoneKey }],
					});
				if (existing) {
					if (
						existing.state !== "verification-reservation-v1" ||
						existing.key !== tombstoneKey
					) {
						throw new Error("Verification reservation key is occupied");
					}
					if (existing.completedAt > now) return false;
					if (!(await reclaimExact(existing))) return false;
				}

				const cleanupNonce = generateId();
				const candidate = {
					...(databaseGeneratesTombstoneId ? {} : { id: reservationId }),
					key: tombstoneKey,
					state: "verification-reservation-v1" as const,
					phase: cleanupNonce,
					cursor: valueDigest,
					revision: 1,
					completedAt: data.expiresAt,
					createdAt: now,
					updatedAt: now,
				};
				const claimed =
					await primaryReservationAdapter.createIfAbsent<VerificationReservationTombstone>({
						model: "securityMigration",
						data: candidate as VerificationReservationTombstone,
						uniqueBy: { field: "key", value: tombstoneKey },
						attemptBy: { field: "phase", value: cleanupNonce },
						forceAllowId: !databaseGeneratesTombstoneId,
					});
				if (claimed) return true;

				const winner =
					await primaryReservationAdapter.findOne<VerificationReservationTombstone>({
						model: "securityMigration",
						where: [{ field: "key", value: tombstoneKey }],
					});
				if (!winner) continue;
				if (
					winner.state !== "verification-reservation-v1" ||
					winner.key !== tombstoneKey
				) {
					throw new Error("Verification reservation key is occupied");
				}
				if (winner.completedAt > new Date()) return false;
				if (attempt === 0 && (await reclaimExact(winner))) continue;
				return false;
			}
			return false;
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
	if (authenticationPolicy) {
		const derivativeAuthorityFromSource = (
			source: AssuredValidatedSessionAuthority,
		) => {
			const sourceAssurance = source.assurance;
			const sourceExpiresAt = source.session.expiresAt;
			if (
				!sourceAssurance ||
				!(sourceExpiresAt instanceof Date) ||
				!Number.isFinite(sourceExpiresAt.getTime()) ||
				sourceExpiresAt <= new Date()
			) {
				throw new ManagedSessionDerivativeAuthorityError("authority_stale");
			}
			return Object.freeze({
				sourceSessionId: source.session.id,
				sourceSubjectId: source.user.id,
				sourceOrganizationId:
					sourceAssurance.authenticationPolicyOrganizationId,
				sourceExpiresAt: sourceExpiresAt.getTime(),
				policyProjectId: sourceAssurance.authenticationPolicyProjectId,
				policyEnvironmentId: sourceAssurance.authenticationPolicyEnvironmentId,
				policyRevision: sourceAssurance.authenticationPolicyRevision,
			});
		};
		const requireDerivativeAuthorityTransaction = async () => {
			if (!(await isTransactionActive(adapter))) {
				throw new ManagedSessionDerivativeAuthorityError("authority_invalid");
			}
			const transactionAdapter = await getCurrentAdapter(adapter);
			if (transactionAdapter === adapter) {
				throw new ManagedSessionDerivativeAuthorityError("authority_invalid");
			}
			return transactionAdapter;
		};
		const derivativeAuthorityHmac = createHMAC(
			"SHA-256",
			"base64urlnopad",
		);
		const derivativeAuthoritySignatureInput = (payload: string) =>
			`clearance:session-derivative-authority:v1:${payload}`;
		const derivativeAuthorityCurrentVersion = () => {
			if (typeof ctx.secretConfig === "string") {
				return -1;
			}
			const secret = ctx.secretConfig.keys.get(
				ctx.secretConfig.currentVersion,
			);
			if (!secret) {
				throw new ManagedSessionDerivativeAuthorityError("authority_invalid");
			}
			return ctx.secretConfig.currentVersion;
		};
		const derivativeAuthorityVerificationKey = (version: number) => {
			if (typeof ctx.secretConfig === "string") {
				return version === -1 ? ctx.secretConfig : undefined;
			}
			if (version === -1) return ctx.secretConfig.legacySecret;
			return ctx.secretConfig.keys.get(version);
		};
		attachInternalSessionDerivativeAuthority(internalAdapter, {
			capture: async (input) => {
				await requireDerivativeAuthorityTransaction();
				if ("sourceSessionToken" in input) {
					const source = await resolveManagedSessionUpdateAuthority(
						input.sourceSessionToken,
					);
					if (!source || !source.assurance || !source.credential) {
						throw new ManagedSessionDerivativeAuthorityError("authority_stale");
					}
					return derivativeAuthorityFromSource(source);
				}
				const source = await loadStrictManagedSessionAuthorityById(
					input.sourceSessionId,
				);
				if (!source) {
					throw new ManagedSessionDerivativeAuthorityError("authority_stale");
				}
				return derivativeAuthorityFromSource(source);
			},
			validate: async (sourceSessionId) => {
				await requireDerivativeAuthorityTransaction();
				const source = await loadStrictManagedSessionAuthorityById(sourceSessionId);
				if (!source) {
					throw new ManagedSessionDerivativeAuthorityError("authority_stale");
				}
				return derivativeAuthorityFromSource(source);
			},
			signatureVersion: derivativeAuthorityCurrentVersion,
			sign: async (payload, version) => {
				const secret = derivativeAuthorityVerificationKey(version);
				if (!secret) {
					throw new ManagedSessionDerivativeAuthorityError("authority_invalid");
				}
				return derivativeAuthorityHmac.sign(
					secret,
					derivativeAuthoritySignatureInput(payload),
				);
			},
			verify: async (payload, version, signature) => {
				const secret = derivativeAuthorityVerificationKey(version);
				return secret
					? derivativeAuthorityHmac.verify(
							secret,
							derivativeAuthoritySignatureInput(payload),
							signature,
						)
					: false;
			},
		});

		// A single transaction can derive at most one organization successor from
		// a source authority. Source resolution locks the user for cross-
		// transaction contenders; this closes duplicate capture in one owner.
		const capturedOrganizationTransitionSources = new WeakMap<
			object,
			Set<string>
		>();
		attachInternalSessionIssuanceCaptureAuthority(
			internalAdapter,
			async (issuanceContext, derivativeAuthority) => {
				if (!(await isTransactionActive(adapter))) {
					throw new ManagedSessionIssuanceError("context_invalid");
				}
				const transactionAdapter = await getCurrentAdapter(adapter);
				if (transactionAdapter === adapter) {
					throw new ManagedSessionIssuanceError("context_invalid");
				}
				const source =
					issuanceContext.purpose === "device"
						? derivativeAuthority
							? await loadStrictManagedSessionAuthorityById(
									derivativeAuthority.sourceSessionId,
								)
							: null
						: await resolveManagedSessionUpdateAuthority(
							issuanceContext.sourceSessionToken,
						);
				if (!source) {
					throw new ManagedSessionIssuanceError("policy_unsatisfied");
				}
				if (issuanceContext.purpose === "organization") {
					const capturedSources =
						capturedOrganizationTransitionSources.get(transactionAdapter) ??
						new Set<string>();
					if (capturedSources.has(source.session.id)) {
						throw new ManagedSessionIssuanceError("context_invalid");
					}
					capturedSources.add(source.session.id);
					capturedOrganizationTransitionSources.set(
						transactionAdapter,
						capturedSources,
					);
				}
				const sourceAssurance = source.assurance;
				const sourceExpiresAt = source.session.expiresAt;
				if (
					!sourceAssurance ||
					!(sourceExpiresAt instanceof Date) ||
					!Number.isFinite(sourceExpiresAt.getTime()) ||
					sourceExpiresAt <= new Date() ||
					(issuanceContext.purpose !== "organization" &&
						issuanceContext.purpose !== "impersonation" &&
						issuanceContext.targetOrganizationId !== null &&
						issuanceContext.targetOrganizationId !==
							sourceAssurance.authenticationPolicyOrganizationId)
				) {
					throw new ManagedSessionIssuanceError("policy_unsatisfied");
				}
				if (
					issuanceContext.purpose === "device" &&
					(!derivativeAuthority ||
						derivativeAuthority.sourceSessionId !== source.session.id ||
						derivativeAuthority.sourceSubjectId !== source.user.id ||
						derivativeAuthority.sourceOrganizationId !==
							sourceAssurance.authenticationPolicyOrganizationId ||
						derivativeAuthority.sourceExpiresAt !==
							sourceExpiresAt.getTime() ||
						derivativeAuthority.policyProjectId !==
							sourceAssurance.authenticationPolicyProjectId ||
						derivativeAuthority.policyEnvironmentId !==
							sourceAssurance.authenticationPolicyEnvironmentId ||
						derivativeAuthority.policyRevision !==
							sourceAssurance.authenticationPolicyRevision)
				) {
					throw new ManagedSessionIssuanceError("policy_unsatisfied");
				}
				return Object.freeze({
					sourceSessionId: source.session.id,
					sourceCredentialId:
						"lineage" in source
							? source.lineage.active.id
							: source.credential?.id ?? null,
					sourceSubjectId: source.user.id,
					sourceOrganizationId:
						sourceAssurance.authenticationPolicyOrganizationId,
					sourceExpiresAt: new Date(sourceExpiresAt),
					sourceAssurance,
					transactionAdapter,
				});
			},
		);
	}
	return internalAdapter;
};
