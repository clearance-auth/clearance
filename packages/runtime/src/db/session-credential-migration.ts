import type { ClearanceOptions } from "@clearance/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import type {
	DBAdapter,
	DBTransactionAdapter,
} from "@clearance/core/db/adapter";
import { APIError } from "@clearance/core/error";
import { generateId } from "@clearance/core/utils/id";
import { safeJSONParse } from "@clearance/core/utils/json";
import { createHMAC } from "@clearance/utils/hmac";
import { constantTimeEqual } from "../crypto";
import type { Session, User } from "../types";
import { DEFAULT_SECRET } from "../utils/constants";
import {
	createSessionHandle,
	digestSessionRefreshSecret,
	SESSION_CREDENTIAL_DIGEST_VERSION,
	SESSION_CREDENTIAL_MODEL,
	sessionIdFromHandle,
	type SessionCredential,
} from "./session-credential";

export const SESSION_CREDENTIAL_MIGRATION_ID = "session-credential-digests-v1";
export const OAUTH_TOKEN_MIGRATION_ID = "oauth-token-digests-v1";
export const SECONDARY_SESSION_EPOCH = "digest-v1";

/** base64urlnopad alphabet; rejects padding and other encodings. */
const SECONDARY_SESSION_EPOCH_SIGNATURE = /^[A-Za-z0-9_-]+$/;

function secondarySessionSigningSecret(options: ClearanceOptions): string {
	return options.secrets?.[0]?.value ?? options.secret ?? DEFAULT_SECRET;
}

function secondarySessionVerificationSecrets(
	options: ClearanceOptions,
): readonly string[] {
	if (options.secrets && options.secrets.length > 0) {
		return options.secrets.map((entry) => entry.value);
	}
	return [options.secret ?? DEFAULT_SECRET];
}

function secondarySessionEpochPayload(
	namespace: string,
	generation: string,
): string {
	return `clearance:secondary-session-epoch:v1:${namespace}:${generation}`;
}

/**
 * Strict parser for the durable secondary-storage epoch value.
 * Accepts only `${SECONDARY_SESSION_EPOCH}:${base64urlnopad signature}`.
 */
function parseSecondarySessionEpochValue(
	raw: string,
): { generation: string; signature: string } | null {
	const separator = raw.indexOf(":");
	if (separator <= 0) return null;
	if (raw.indexOf(":", separator + 1) !== -1) return null;
	const generation = raw.slice(0, separator);
	const signature = raw.slice(separator + 1);
	if (generation !== SECONDARY_SESSION_EPOCH) return null;
	if (
		signature.length === 0 ||
		!SECONDARY_SESSION_EPOCH_SIGNATURE.test(signature)
	) {
		return null;
	}
	return { generation, signature };
}

/**
 * Normalize a secondary-storage get() result into a parsed epoch, accepting
 * either the raw signed value or the JSON-string representation migration writes.
 */
function normalizeStoredSecondarySessionEpoch(
	stored: unknown,
): { generation: string; signature: string } | null {
	if (typeof stored !== "string" || stored.length === 0) return null;
	const direct = parseSecondarySessionEpochValue(stored);
	if (direct) return direct;
	const unwrapped = safeJSONParse<unknown>(stored);
	if (typeof unwrapped !== "string" || unwrapped.length === 0) return null;
	return parseSecondarySessionEpochValue(unwrapped);
}

async function secondarySessionEpochSignatureValid(
	options: ClearanceOptions,
	namespace: string,
	epoch: { generation: string; signature: string },
): Promise<boolean> {
	const hmac = createHMAC("SHA-256", "base64urlnopad");
	const payload = secondarySessionEpochPayload(namespace, epoch.generation);
	for (const secret of secondarySessionVerificationSecrets(options)) {
		const expected = await hmac.sign(secret, payload);
		if (constantTimeEqual(expected, epoch.signature)) return true;
	}
	return false;
}

type SecurityMigration = {
	id: string | number;
	key: string;
	state: string;
	phase?: string | null;
	cursor?: string | null;
	revision?: number | null;
	completedAt: Date;
	createdAt: Date;
	updatedAt: Date;
};

type SecondarySessionIndexEntry = {
	sessionId: string;
	credentialKey: string;
	expiresAt: number;
};

type LegacySecondarySessionIndexEntry = {
	token: string;
	expiresAt: number;
};

type SecondarySessionMigrationPhase = "migrate" | "verify" | "publish";

type SecondarySessionMigrationProgress = {
	version: 1;
	generation: string;
	phase: SecondarySessionMigrationPhase;
	cursor?: ["string" | "number", string | number];
};

// A secondary lease handles one user and no more than this much indexed
// session state. Operators must compact or revoke pathological per-user state
// before retrying instead of letting migration lock time grow without bound.
const SECONDARY_SESSION_INDEX_MAX_BYTES = 64 * 1024;
const SECONDARY_SESSION_INDEX_MAX_ENTRIES = 128;
const SECONDARY_SESSION_PROGRESS_MAX_BYTES = 4 * 1024;

function serializedByteLengthWithin(
	value: string,
	maximum: number,
): number | undefined {
	// Reject obviously oversized values before UTF-8 measurement allocates or
	// scans another representation of attacker-controlled storage contents.
	if (value.length > maximum) return undefined;
	const length = new TextEncoder().encode(value).byteLength;
	return length <= maximum ? length : undefined;
}

function parseSecondarySessionIndex(
	raw: unknown,
	key: string,
	kind: "legacy" | "namespaced",
): (SecondarySessionIndexEntry | LegacySecondarySessionIndexEntry)[] {
	if (raw == null) return [];
	if (typeof raw !== "string" && !(kind === "namespaced" && Array.isArray(raw))) {
		throw new Error(
			`Secondary session credential migration requires ${kind} index ${key} to be a serialized JSON string`,
		);
	}
	if (
		typeof raw === "string" &&
		serializedByteLengthWithin(raw, SECONDARY_SESSION_INDEX_MAX_BYTES) ===
			undefined
	) {
		throw new Error(
			`Secondary ${kind} session index ${key} exceeds the ${SECONDARY_SESSION_INDEX_MAX_BYTES}-byte migration bound; compact or revoke sessions for this user before retrying`,
		);
	}
	const entries = typeof raw === "string" ? safeJSONParse<unknown>(raw) : raw;
	if (!Array.isArray(entries)) {
		throw new Error(
			`Secondary ${kind} session index ${key} is not a JSON array`,
		);
	}
	if (entries.length > SECONDARY_SESSION_INDEX_MAX_ENTRIES) {
		throw new Error(
			`Secondary ${kind} session index ${key} exceeds the ${SECONDARY_SESSION_INDEX_MAX_ENTRIES}-entry migration bound; compact or revoke sessions for this user before retrying`,
		);
	}
	for (const entry of entries) {
		if (
			typeof entry !== "object" ||
			entry == null ||
			!("expiresAt" in entry) ||
			typeof entry.expiresAt !== "number" ||
			!Number.isFinite(entry.expiresAt) ||
			(kind === "legacy"
				? !("token" in entry) ||
					typeof entry.token !== "string" ||
					entry.token.length === 0
				: !("sessionId" in entry) ||
					typeof entry.sessionId !== "string" ||
					entry.sessionId.length === 0 ||
					!("credentialKey" in entry) ||
					typeof entry.credentialKey !== "string" ||
					entry.credentialKey.length === 0)
		) {
			throw new Error(
				`Secondary ${kind} session index ${key} contains an invalid entry`,
			);
		}
	}
	return entries as (
		| SecondarySessionIndexEntry
		| LegacySecondarySessionIndexEntry
	)[];
}

function encodeSecondarySessionCursor(
	id: string | number,
): ["string" | "number", string | number] {
	return typeof id === "string" ? ["string", id] : ["number", id];
}

function decodeSecondarySessionCursor(
	cursor: SecondarySessionMigrationProgress["cursor"],
): string | number | undefined {
	if (!cursor) return undefined;
	if (
		(cursor[0] === "string" && typeof cursor[1] === "string") ||
		(cursor[0] === "number" &&
			typeof cursor[1] === "number" &&
			Number.isFinite(cursor[1]))
	) {
		return cursor[1];
	}
	throw new Error("Secondary session migration progress has an invalid cursor");
}

function parseSecondarySessionProgress(
	raw: unknown,
	generation: string,
): SecondarySessionMigrationProgress {
	const initial: SecondarySessionMigrationProgress = {
		version: 1,
		generation,
		phase: "migrate",
	};
	if (raw == null) return initial;
	if (
		typeof raw === "string" &&
		serializedByteLengthWithin(raw, SECONDARY_SESSION_PROGRESS_MAX_BYTES) ===
			undefined
	) {
		throw new Error(
			"Secondary session migration progress is invalid or exceeds its durable bound",
		);
	}
	const parsed =
		typeof raw === "string"
			? safeJSONParse<SecondarySessionMigrationProgress>(raw)
			: (raw as SecondarySessionMigrationProgress);
	if (
		parsed?.version !== 1 ||
		parsed.generation !== generation ||
		!(["migrate", "verify", "publish"] as const).includes(parsed.phase)
	) {
		return initial;
	}
	decodeSecondarySessionCursor(parsed.cursor);
	return parsed;
}

export function getSecondarySessionNamespace(options: ClearanceOptions): string {
	const namespace = options.secondaryStorage?.namespace;
	if (!namespace || !/^[A-Za-z0-9._:-]{1,128}$/.test(namespace)) {
		throw new Error(
			"Secondary session storage requires a unique namespace containing only letters, numbers, dot, underscore, colon, or hyphen",
		);
	}
	return namespace;
}

export function getSecondarySessionKeys(options: ClearanceOptions) {
	const prefix = `clearance:${getSecondarySessionNamespace(options)}:`;
	return {
		activeSessions: (userId: string) => `${prefix}active-sessions:${userId}`,
		credential: (digest: string) => `${prefix}session-credential:${digest}`,
		handle: (sessionId: string) => `${prefix}session-handle:${sessionId}`,
	};
}

export async function getSecondarySessionEpoch(options: ClearanceOptions): Promise<{
	key: string;
	value: string;
}> {
	const namespace = getSecondarySessionNamespace(options);
	// Generation is intentionally independent of primary secret version so
	// retained-secret promotion does not invalidate a published epoch.
	const writerGeneration = SECONDARY_SESSION_EPOCH;
	const signature = await createHMAC("SHA-256", "base64urlnopad").sign(
		secondarySessionSigningSecret(options),
		secondarySessionEpochPayload(namespace, writerGeneration),
	);
	return {
		key: `clearance:${namespace}:session-storage-epoch`,
		value: `${writerGeneration}:${signature}`,
	};
}

export async function recordSecurityMigrationComplete(
	adapter: DBAdapter<any> | DBTransactionAdapter<any>,
	migrationId: string,
	options?: ClearanceOptions,
): Promise<void> {
	const now = new Date();
	const current = await adapter.findOne<SecurityMigration>({
		model: "securityMigration",
		where: [{ field: "key", value: migrationId }],
	});
	if (current?.state === "complete") return;
	if (current) {
		await adapter.update({
			model: "securityMigration",
			where: [{ field: "key", value: migrationId }],
			update: {
				state: "complete",
				phase: null,
				cursor: null,
				revision: (current.revision ?? 0) + 1,
				completedAt: now,
				updatedAt: now,
			},
		});
		return;
	}
	try {
		const idStrategy = options?.advanced?.database?.generateId;
		const databaseGeneratesId = idStrategy === "serial" || idStrategy === false;
		const id =
			idStrategy === "uuid" ? crypto.randomUUID() : generateId();
		await adapter.create({
			model: "securityMigration",
			forceAllowId: !databaseGeneratesId,
			data: {
				...(databaseGeneratesId ? {} : { id }),
					key: migrationId,
					state: "complete",
					phase: null,
					cursor: null,
					revision: 0,
				completedAt: now,
				createdAt: now,
				updatedAt: now,
			},
		});
	} catch (error) {
		const raced = await adapter.findOne<SecurityMigration>({
			model: "securityMigration",
			where: [{ field: "key", value: migrationId }],
		});
		if (raced?.state !== "complete") throw error;
	}
}

export async function assertSecurityMigrationComplete(
	adapter: DBAdapter<any>,
	migrationId: string,
): Promise<void> {
	const migration = await adapter.findOne<SecurityMigration>({
		model: "securityMigration",
		where: [{ field: "key", value: migrationId }],
	});
	if (migration?.state === "complete") return;
	throw new APIError(
		"SERVICE_UNAVAILABLE",
		{
			code: "SECURITY_MIGRATION_REQUIRED",
			message: `Security migration ${migrationId} must complete before authentication traffic is accepted`,
		},
		{ "Retry-After": "5" },
	);
}

export async function assertSessionCredentialMigrationComplete(
	adapter: DBAdapter<any>,
	options: ClearanceOptions,
): Promise<void> {
	if (
		options.secondaryStorage &&
		options.session?.storeSessionInDatabase !== true
	) {
		// Read-only: never publish, re-sign, or otherwise mutate secondary storage
		// from the traffic assertion path.
		const namespace = getSecondarySessionNamespace(options);
		const epochKey = `clearance:${namespace}:session-storage-epoch`;
		const storedEpoch = await options.secondaryStorage.get(epochKey);
		const parsed = normalizeStoredSecondarySessionEpoch(storedEpoch);
		if (
			parsed &&
			(await secondarySessionEpochSignatureValid(options, namespace, parsed))
		) {
			return;
		}
		throw new APIError(
			"SERVICE_UNAVAILABLE",
			{
				code: "SECURITY_MIGRATION_REQUIRED",
				message: `Security migration ${SESSION_CREDENTIAL_MIGRATION_ID} must complete before authentication traffic is accepted`,
			},
			{ "Retry-After": "5" },
		);
	}

	// Clearance's built-in database and memory adapter are process-local, start
	// empty, and can contain only credentials written by this runtime. Durable
	// external databases and adapters require migration proof before traffic.
	if (options.database == null || adapter.id === "memory") return;

	await assertSecurityMigrationComplete(
		adapter,
		SESSION_CREDENTIAL_MIGRATION_ID,
	);
}

async function migrateSecondarySessionCredentials(
	adapter: DBAdapter<any>,
	options: ClearanceOptions,
): Promise<void> {
	const secondary = options.secondaryStorage;
	if (!secondary) return;
	const epoch = await getSecondarySessionEpoch(options);
	const namespace = getSecondarySessionNamespace(options);
	const keys = getSecondarySessionKeys(options);
	if (!secondary.runExclusive || !secondary.assertNoLegacySessionWriters) {
		throw new Error(
			"Secondary session credential migration requires runExclusive and assertNoLegacySessionWriters provider guarantees",
		);
	}
	const leaseName = `clearance:${namespace}:session-credential-migration`;
	const progressKey = `clearance:${namespace}:session-credential-migration-progress`;
	for (;;) {
		const complete = await secondary.runExclusive(leaseName, async () => {
			await secondary.assertNoLegacySessionWriters!({
				namespace,
				nextGeneration: epoch.value,
			});
			const progress = parseSecondarySessionProgress(
				await secondary.get(progressKey),
				epoch.value,
			);
			if (progress.phase === "publish") {
				// Reconfirm the writer fence immediately before making the epoch visible.
				await secondary.assertNoLegacySessionWriters!({
					namespace,
					nextGeneration: epoch.value,
				});
				await secondary.set(epoch.key, JSON.stringify(epoch.value));
				const storedEpoch = await secondary.get(epoch.key);
				if (
					(storedEpoch === epoch.value
						? storedEpoch
						: safeJSONParse<string>(storedEpoch)) !== epoch.value
				) {
					throw new Error(
						"Secondary storage did not durably retain its migration epoch",
					);
				}
				await secondary.delete(progressKey);
				return true;
			}

			const cursor = decodeSecondarySessionCursor(progress.cursor);
			const users = await adapter.findMany<User>({
				model: "user",
				limit: 1,
				where:
					cursor === undefined
						? undefined
						: [{ field: "id", value: cursor, operator: "gt" }],
				sortBy: { field: "id", direction: "asc" },
			});
			const user = users[0];
			if (!user) {
				await secondary.set(
					progressKey,
					JSON.stringify({
						version: 1,
						generation: epoch.value,
						phase: progress.phase === "migrate" ? "verify" : "publish",
					} satisfies SecondarySessionMigrationProgress),
				);
				return false;
			}

			const legacyIndexKey = `active-sessions-${user.id}`;
			const indexKey = keys.activeSessions(user.id);
			if (progress.phase === "verify") {
				if ((await secondary.get(legacyIndexKey)) != null) {
					throw new Error(
						`Secondary storage retained the legacy session index for ${user.id}`,
					);
				}
				const entries = parseSecondarySessionIndex(
					await secondary.get(indexKey),
					indexKey,
					"namespaced",
				) as SecondarySessionIndexEntry[];
				for (const entry of entries) {
					if (
						!entry.credentialKey.startsWith(
							`clearance:${namespace}:session-credential:`,
						) ||
						(await secondary.get(entry.credentialKey)) == null ||
						safeJSONParse<{ credentialKey?: string }>(
							await secondary.get(keys.handle(entry.sessionId)),
						)?.credentialKey !== entry.credentialKey
					) {
						throw new Error(
							`Secondary session keyspace verification failed for ${entry.sessionId}`,
						);
					}
				}
				await secondary.set(
					progressKey,
					JSON.stringify({
						...progress,
						cursor: encodeSecondarySessionCursor(user.id),
					} satisfies SecondarySessionMigrationProgress),
				);
				return false;
			}

			const currentEntries = parseSecondarySessionIndex(
				await secondary.get(indexKey),
				indexKey,
				"namespaced",
			) as SecondarySessionIndexEntry[];
			const legacyEntries = parseSecondarySessionIndex(
				await secondary.get(legacyIndexKey),
				legacyIndexKey,
				"legacy",
			) as LegacySecondarySessionIndexEntry[];
			const migratedBySession = new Map<
				string,
				SecondarySessionIndexEntry
			>();
			const legacySourceKeys = new Set(
				legacyEntries.map((entry) => entry.token),
			);
			for (const entry of [...legacyEntries, ...currentEntries]) {
				const sourceKey =
					"credentialKey" in entry ? entry.credentialKey : entry.token;
				const raw = await secondary.get(sourceKey);
				const parsed = safeJSONParse<{ session: Session; user: User }>(raw);
				if (!parsed?.session?.id) {
					await secondary.delete(sourceKey);
					continue;
				}
				const expiresAt = new Date(parsed.session.expiresAt).getTime();
				const ttl = Math.max(
					Math.floor((expiresAt - Date.now()) / 1000),
					0,
				);
				if (ttl <= 0) {
					await secondary.delete(sourceKey);
					continue;
				}
				const digest =
					"token" in entry
						? await digestSessionRefreshSecret(entry.token)
						: entry.credentialKey.slice(
								entry.credentialKey.indexOf("session-credential:") +
									"session-credential:".length,
							);
				if (!digest.startsWith(`v${SESSION_CREDENTIAL_DIGEST_VERSION}:`)) {
					throw new Error(
						`Secondary session ${parsed.session.id} has an invalid credential digest key`,
					);
				}
				const credentialKey = keys.credential(digest);
				await secondary.set(
					credentialKey,
					JSON.stringify({
						session: { ...parsed.session, token: null },
						user: parsed.user,
					}),
					ttl,
				);
				await secondary.set(
					keys.handle(parsed.session.id),
					JSON.stringify({ credentialKey }),
					ttl,
				);
				if (sourceKey !== credentialKey) await secondary.delete(sourceKey);
				migratedBySession.set(parsed.session.id, {
					sessionId: parsed.session.id,
					credentialKey,
					expiresAt,
				});
			}
			const migrated = [...migratedBySession.values()];
			if (migrated.length > 0) {
				const ttl = Math.max(
					Math.floor(
						(Math.max(...migrated.map((entry) => entry.expiresAt)) -
							Date.now()) /
							1000,
					),
					1,
				);
				await secondary.set(indexKey, JSON.stringify(migrated), ttl);
			} else {
				await secondary.delete(indexKey);
			}
			await secondary.delete(legacyIndexKey);
			if ((await secondary.get(legacyIndexKey)) != null) {
				throw new Error(
					`Secondary storage retained the legacy session index for ${user.id}`,
				);
			}
			for (const sourceKey of legacySourceKeys) {
				if ((await secondary.get(sourceKey)) != null) {
					throw new Error(
						`Secondary storage retained replayable legacy session material for ${user.id}`,
					);
				}
			}
			await secondary.set(
				progressKey,
				JSON.stringify({
					...progress,
					cursor: encodeSecondarySessionCursor(user.id),
				} satisfies SecondarySessionMigrationProgress),
			);
			return false;
		});
		if (complete) return;
	}
}

function credentialIdentity(options: ClearanceOptions): {
	id?: string | undefined;
	selector: string;
} {
	const strategy = options.advanced?.database?.generateId;
	const configured =
		typeof strategy === "function"
			? strategy({ model: SESSION_CREDENTIAL_MODEL })
			: strategy === "uuid"
				? crypto.randomUUID()
				: strategy === "serial" || strategy === false
					? false
					: generateId();
	return {
		...(configured === false ? {} : { id: configured }),
		selector: generateId(),
	};
}

type MigrationCursor = string | number | undefined;

function encodeMigrationCursor(cursor: MigrationCursor): string | null {
	return cursor === undefined ? null : JSON.stringify([typeof cursor, cursor]);
}

function decodeMigrationCursor(cursor: string | null | undefined): MigrationCursor {
	if (!cursor) return undefined;
	const parsed = safeJSONParse<["string" | "number", string | number]>(cursor);
	if (!parsed || (parsed[0] !== "string" && parsed[0] !== "number")) {
		throw new Error("Credential migration cursor is invalid");
	}
	return parsed[0] === "number" ? Number(parsed[1]) : String(parsed[1]);
}

function migrationIdentity(options: ClearanceOptions): {
	id?: string | undefined;
} {
	const strategy = options.advanced?.database?.generateId;
	const configured =
		typeof strategy === "function"
			? strategy({ model: "securityMigration" })
			: strategy === "uuid"
				? crypto.randomUUID()
				: strategy === "serial" || strategy === false
					? false
					: generateId();
	return configured === false ? {} : { id: configured };
}

async function ensureMigrationProgress(
	adapter: DBAdapter<any>,
	options: ClearanceOptions,
	migrationId: string,
): Promise<void> {
	const key = `${migrationId}:progress`;
	if (
		await adapter.findOne<SecurityMigration>({
			model: "securityMigration",
			where: [{ field: "key", value: key }],
		})
	) {
		return;
	}
	const now = new Date();
	const identity = migrationIdentity(options);
	try {
		await adapter.create({
			model: "securityMigration",
			forceAllowId: identity.id !== undefined,
			data: {
				...(identity.id ? { id: identity.id } : {}),
				key,
				state: "running",
				phase: "migrate",
				cursor: null,
				revision: 0,
				completedAt: now,
				createdAt: now,
				updatedAt: now,
			},
		});
	} catch (error) {
		const raced = await adapter.findOne<SecurityMigration>({
			model: "securityMigration",
			where: [{ field: "key", value: key }],
		});
		if (!raced) throw error;
	}
}

export async function runSecurityMigrationPage(
	adapter: DBAdapter<any>,
	options: ClearanceOptions,
	migrationId: string,
	work: (
		tx: DBAdapter<any> | DBTransactionAdapter<any>,
		progress: { phase: string; cursor: MigrationCursor },
	) => Promise<{
		phase: string;
		cursor: MigrationCursor;
		ready: boolean;
	}>,
): Promise<boolean> {
	await ensureMigrationProgress(adapter, options, migrationId);
	return runWithTransaction(adapter, async () => {
		const tx = await getCurrentAdapter(adapter);
		const key = `${migrationId}:progress`;
		const progress = await tx.findOne<SecurityMigration>({
			model: "securityMigration",
			where: [{ field: "key", value: key }],
		});
		if (!progress) {
			throw new Error(
				`Credential migration ${migrationId} lost its progress row`,
			);
		}
		if (progress.state === "ready") return true;
		const revision = progress.revision ?? 0;
		const owner = generateId();
		const claimed = await tx.incrementOne<SecurityMigration>({
			model: "securityMigration",
			where: [
				{ field: "key", value: key },
				{ field: "revision", value: revision },
			],
			increment: { revision: 1 },
			set: { state: `running:${owner}`, updatedAt: new Date() },
		});
		if (!claimed) return false;
		const result = await work(tx, {
			phase: progress.phase ?? "migrate",
			cursor: decodeMigrationCursor(progress.cursor),
		});
		const persisted = await tx.incrementOne<SecurityMigration>({
			model: "securityMigration",
			where: [
				{ field: "key", value: key },
				{ field: "state", value: `running:${owner}` },
				{ field: "revision", value: revision + 1 },
			],
			increment: { revision: 1 },
			set: {
				state: result.ready ? "ready" : "running",
				phase: result.phase,
				cursor: encodeMigrationCursor(result.cursor),
				updatedAt: new Date(),
			},
		});
		if (!persisted) {
			throw new Error(
				`Credential migration ${migrationId} lost its progress lease`,
			);
		}
		return result.ready;
	});
}

function groupActiveCredentials(
	credentials: SessionCredential[],
): Map<string, SessionCredential[]> {
	const bySession = new Map<string, SessionCredential[]>();
	for (const credential of credentials) {
		if (credential.sessionId == null) continue;
		const key = String(credential.sessionId);
		const grouped = bySession.get(key) ?? [];
		grouped.push(credential);
		bySession.set(key, grouped);
	}
	return bySession;
}

/**
 * Removes replayable legacy session bearers in restartable fixed-size
 * transactions. The progress row and each page mutate atomically, so a crash
 * resumes from the last committed cursor without retaining a dataset-sized
 * transaction or lock.
 */
export async function migrateLegacySessionCredentials(
	adapter: DBAdapter<any>,
	options: ClearanceOptions,
): Promise<void> {
	if (
		options.secondaryStorage &&
		options.session?.storeSessionInDatabase !== true
	) {
		await migrateSecondarySessionCredentials(adapter, options);
		return;
	}
	if (typeof adapter.options?.adapterConfig.transaction !== "function") {
		throw new Error(
			"Session credential migration requires rollback-capable database transactions",
		);
	}
	const pageSize = 500;
	for (;;) {
		const ready = await runSecurityMigrationPage(
			adapter,
			options,
			SESSION_CREDENTIAL_MIGRATION_ID,
			async (tx, progress) => {
				const sessions = await tx.findMany<Session>({
					model: "session",
					limit: pageSize,
					where:
						progress.cursor === undefined
							? undefined
							: [{ field: "id", value: progress.cursor, operator: "gt" }],
					sortBy: { field: "id", direction: "asc" },
				});
				const activeCredentials =
					sessions.length === 0
						? []
						: await tx.findMany<SessionCredential>({
								model: SESSION_CREDENTIAL_MODEL,
								limit: pageSize + 1,
								where: [
									{
										field: "sessionId",
										value: sessions.map((session) => session.id),
										operator: "in",
									},
									{ field: "status", value: "active" },
								],
							});
				if (activeCredentials.length > sessions.length) {
					throw new Error(
						"A session migration page contains multiple active credentials",
					);
				}
				const credentialsBySession = groupActiveCredentials(activeCredentials);
				if (progress.phase === "verify") {
					for (const session of sessions) {
						const credentials = credentialsBySession.get(String(session.id)) ?? [];
						if (
							(session.token && !sessionIdFromHandle(session.token)) ||
							(session.expiresAt > new Date() && credentials.length !== 1)
						) {
							throw new Error(
								`Session ${session.id} failed credential migration verification`,
							);
						}
					}
					const done = sessions.length < pageSize;
					return {
						phase: done ? "ready" : "verify",
						cursor: done ? undefined : sessions.at(-1)!.id,
						ready: done,
					};
				}

				for (const session of sessions) {
					const credentials = credentialsBySession.get(String(session.id)) ?? [];
					if (credentials.length > 1) {
						throw new Error(`Session ${session.id} has multiple active credentials`);
					}
					const rawToken =
						typeof session.token === "string" && session.token.length > 0
							? session.token
							: null;
					const isRawToken = Boolean(rawToken && !sessionIdFromHandle(rawToken));
					if (credentials.length === 0 && !isRawToken) {
						if (session.expiresAt > new Date()) {
							throw new Error(
								`Live session ${session.id} has no recoverable refresh credential`,
							);
						}
						continue;
					}
					if (credentials.length === 0 && isRawToken) {
						const claimed = await tx.incrementOne<Session>({
							model: "session",
							where: [
								{ field: "id", value: session.id },
								{ field: "token", value: rawToken! },
							],
							increment: {},
							set: {
								token: createSessionHandle(session.id),
								updatedAt: new Date(),
							},
						});
						if (!claimed) {
							throw new Error(
								`Session ${session.id} changed during credential migration; retry the migration`,
							);
						}
						const identity = credentialIdentity(options);
						const now = new Date();
						await tx.create({
							model: SESSION_CREDENTIAL_MODEL,
							forceAllowId: identity.id !== undefined,
							data: {
								...(identity.id ? { id: identity.id } : {}),
								selector: identity.selector,
								sessionId: session.id,
								familyId: generateId(),
								secretDigest: await digestSessionRefreshSecret(rawToken!),
								digestVersion: SESSION_CREDENTIAL_DIGEST_VERSION,
								status: "active",
								rotationCounter: 0,
								parentCredentialId: null,
								expiresAt: session.expiresAt,
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
					} else if (isRawToken) {
						const cleared = await tx.incrementOne<Session>({
							model: "session",
							where: [
								{ field: "id", value: session.id },
								{ field: "token", value: rawToken },
							],
							increment: {},
							set: {
								token: createSessionHandle(session.id),
								updatedAt: new Date(),
							},
						});
						if (!cleared) {
							throw new Error(
								`Session ${session.id} changed during credential migration; retry the migration`,
							);
						}
					}
				}
				const done = sessions.length < pageSize;
				return {
					phase: done ? "verify" : "migrate",
					cursor: done ? undefined : sessions.at(-1)!.id,
					ready: false,
				};
			},
		);
		if (ready) return;
	}
}
