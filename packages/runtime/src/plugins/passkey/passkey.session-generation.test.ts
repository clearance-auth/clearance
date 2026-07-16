import { describe, expect, it } from "vitest";
import type { Session, User } from "../../types";
import { getTestInstance } from "../../test-utils/test-instance";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getCookieCache, getSessionCookie } from "../../cookies";
import {
	createSessionHandle,
	digestSessionRefreshSecret,
	SESSION_CREDENTIAL_DIGEST_VERSION,
} from "../../db/session-credential";
import {
	PASSKEY_SESSION_GENERATION_FIELD,
	sessionMatchesPasskeyGeneration,
} from "../../db/passkey-session-generation";
import { generateCredentialOperationKey } from "../../utils/operation-key";
import { passkey } from ".";
import { twoFactor } from "../two-factor";

const SECRET = "passkey-session-generation-test-secret";

describe("passkey session generation", () => {
	it("initializes once and backfills only the user's legacy sessions", async () => {
		const { auth, db, signInWithTestUser } = await getTestInstance({
			secret: SECRET,
			plugins: [passkey()],
		});
		const legacy = await signInWithTestUser();
		const context = await auth.$context;
		const otherUser = await context.internalAdapter.createUser({
			email: "other-passkey-generation-user@example.test",
			emailVerified: true,
			name: "Other passkey generation user",
			image: null,
		});
		await context.internalAdapter.createSession(otherUser.id);
		await db.update({
			model: "user",
			where: [{ field: "id", value: legacy.user.id }],
			update: { passkeySessionGeneration: null },
		});
		await db.updateMany({
			model: "session",
			where: [{ field: "userId", value: legacy.user.id }],
			update: { passkeySessionGeneration: null },
		});
		await db.update({
			model: "user",
			where: [{ field: "id", value: otherUser.id }],
			update: { passkeySessionGeneration: null },
		});
		await db.updateMany({
			model: "session",
			where: [{ field: "userId", value: otherUser.id }],
			update: { passkeySessionGeneration: null },
		});

		await context.internalAdapter.createSession(legacy.user.id);
		const user = await db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: legacy.user.id }],
		});
		const generation = user?.passkeySessionGeneration;
		expect(typeof generation).toBe("string");
		let sessions = await db.findMany<Session & Record<string, unknown>>({
			model: "session",
			where: [{ field: "userId", value: legacy.user.id }],
		});
		expect(
			sessions.every(
				(session) => session.passkeySessionGeneration === generation,
			),
		).toBe(true);
		const untouchedOtherUser = await db.findOne<
			User & Record<string, unknown>
		>({
			model: "user",
			where: [{ field: "id", value: otherUser.id }],
		});
		const untouchedOtherSessions = await db.findMany<
			Session & Record<string, unknown>
		>({
			model: "session",
			where: [{ field: "userId", value: otherUser.id }],
		});
		expect(untouchedOtherUser?.passkeySessionGeneration).toBeNull();
		expect(
			untouchedOtherSessions.every(
				(session) => session.passkeySessionGeneration == null,
			),
		).toBe(true);

		await context.internalAdapter.createSession(legacy.user.id);
		sessions = await db.findMany<Session & Record<string, unknown>>({
			model: "session",
			where: [{ field: "userId", value: legacy.user.id }],
		});
		expect(
			sessions.every(
				(session) => session.passkeySessionGeneration === generation,
			),
		).toBe(true);
	});

	it("keeps generation binding inside creation and rejects a forced pre-insert rotation", async () => {
		let forceRotation = false;
		let rotateUser: ((userId: string) => Promise<void>) | undefined;
		const { auth, db, signInWithTestUser } = await getTestInstance({
			secret: SECRET,
			plugins: [passkey()],
			databaseHooks: {
				session: {
					create: {
						before: async (session) => {
							if (forceRotation) await rotateUser?.(session.userId);
							return {
								data: {
									...session,
									passkeySessionGeneration: "hook-controlled-generation",
								},
							};
						},
					},
				},
			},
		});
		rotateUser = async (userId) => {
			await db.update({
				model: "user",
				where: [{ field: "id", value: userId }],
				update: { passkeySessionGeneration: "forced-rotated-generation" },
			});
		};
		const signedIn = await signInWithTestUser();
		const context = await auth.$context;
		const authority = await db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		const generation = authority?.passkeySessionGeneration;
		expect(typeof generation).toBe("string");

		const protectedSession = await context.internalAdapter.createSession(
			signedIn.user.id,
			false,
			{ passkeySessionGeneration: "caller-controlled-generation" },
			true,
		);
		const persistedProtectedSession = await db.findOne<
			Session & Record<string, unknown>
		>({
			model: "session",
			where: [{ field: "id", value: protectedSession.id }],
		});
		expect(persistedProtectedSession?.passkeySessionGeneration).toBe(generation);

		const before = await db.count({
			model: "session",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		forceRotation = true;
		await expect(
			context.internalAdapter.createSession(signedIn.user.id),
		).rejects.toThrow("Session security generation changed during creation");
		const after = await db.count({
			model: "session",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		expect(after).toBe(before);
		const rolledBackAuthority = await db.findOne<
			User & Record<string, unknown>
		>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		expect(rolledBackAuthority?.passkeySessionGeneration).toBe(generation);
	});

	it("rejects a concurrent two-factor generation rotation before combined session insertion", async () => {
		let forceRotation = false;
		let rotateUser: ((userId: string) => Promise<void>) | undefined;
		const { auth, db, signInWithTestUser } = await getTestInstance({
			secret: SECRET,
			plugins: [passkey(), twoFactor()],
			databaseHooks: {
				session: {
					create: {
						before: async (session) => {
							if (forceRotation) await rotateUser?.(session.userId);
						},
					},
				},
			},
		});
		rotateUser = async (userId) => {
			await db.update({
				model: "user",
				where: [{ field: "id", value: userId }],
				update: { twoFactorSessionGeneration: "forced-two-factor-generation" },
			});
		};
		const signedIn = await signInWithTestUser();
		const context = await auth.$context;
		const authority = await db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		expect(typeof authority?.passkeySessionGeneration).toBe("string");
		expect(typeof authority?.twoFactorSessionGeneration).toBe("string");

		const before = await db.count({
			model: "session",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		forceRotation = true;
		await expect(
			context.internalAdapter.createSession(signedIn.user.id),
		).rejects.toThrow("Session security generation changed during creation");
		const after = await db.count({
			model: "session",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		expect(after).toBe(before);
		const rolledBackAuthority = await db.findOne<
			User & Record<string, unknown>
		>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		expect(rolledBackAuthority?.twoFactorSessionGeneration).toBe(
			authority?.twoFactorSessionGeneration,
		);
	});

	it("preserves legacy secondary sessions until user authority is explicitly established", async () => {
		const store = new Map<string, string>();
		const secondaryStorage = {
			get(key: string) {
				return store.get(key) ?? null;
			},
			set(key: string, value: string) {
				store.set(key, value);
			},
			delete(key: string) {
				store.delete(key);
			},
		};
		const { auth, db, signInWithTestUser } = await getTestInstance({
			secret: SECRET,
			plugins: [passkey()],
			secondaryStorage,
		});
		const legacy = await signInWithTestUser();
		const legacyToken = getSessionCookie(legacy.headers)?.split(".")[0];
		if (!legacyToken) throw new Error("legacy secondary token missing");
		const context = await auth.$context;
		const legacyResolved = await context.internalAdapter.findSession(legacyToken);
		expect(legacyResolved).not.toBeNull();
		const ordinary = await context.internalAdapter.createSession(legacy.user.id);
		const authority = await db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: legacy.user.id }],
		});
		expect(authority?.passkeySessionGeneration).toBeNull();
		expect(await context.internalAdapter.findSession(legacyToken)).not.toBeNull();
		expect(await context.internalAdapter.findSession(ordinary.token)).not.toBeNull();
		expect(
			(await context.internalAdapter.listSessions(legacy.user.id)).map(
				(session) => session.id,
			),
		).toEqual(expect.arrayContaining([legacyResolved!.session.id, ordinary.id]));
		expect(
			await context.internalAdapter.findSessionById(legacyResolved!.session.id),
		).not.toBeNull();

		await db.update({
			model: "user",
			where: [{ field: "id", value: legacy.user.id }],
			update: { passkeySessionGeneration: "established-generation" },
		});
		await expect(
			context.internalAdapter.findSession(legacyToken),
		).resolves.toBeNull();
		await expect(
			context.internalAdapter.findSessionById(ordinary.id),
		).resolves.toBeNull();
		expect(await context.internalAdapter.listSessions(legacy.user.id)).toEqual([]);
		const established = await context.internalAdapter.createSession(legacy.user.id);
		expect(
			(established as Session & Record<string, unknown>)
				.passkeySessionGeneration,
		).toBe("established-generation");
		expect(
			await context.internalAdapter.findSession(established.token),
		).not.toBeNull();
	});

	it("rejects prior sessions and a late stale insert after generation rotation", async () => {
		const { auth, db, signInWithTestUser } = await getTestInstance({
			secret: SECRET,
			plugins: [passkey()],
		});
		const signedIn = await signInWithTestUser();
		const context = await auth.$context;
		const signedInSession = await auth.api.getSession({
			headers: signedIn.headers,
		});
		if (!signedInSession) throw new Error("signed-in session missing");
		const sourceToken = getSessionCookie(signedIn.headers)?.split(".")[0];
		if (!sourceToken) throw new Error("signed-in session token missing");
		const source = await db.findOne<Session & Record<string, unknown>>({
			model: "session",
			where: [{ field: "id", value: signedInSession.session.id }],
		});
		const staleGeneration = source?.passkeySessionGeneration;
		expect(typeof staleGeneration).toBe("string");
		const operationKey = generateCredentialOperationKey();
		const rotatedCredential = await context.internalAdapter.rotateSessionCredential(
			sourceToken,
			operationKey,
		);
		expect(rotatedCredential).not.toBeNull();

		await db.update({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
			update: { passkeySessionGeneration: "rotated-passkey-generation" },
		});
		await expect(
			auth.api.getSession({ headers: signedIn.headers }),
		).resolves.toBeNull();
		await expect(
			context.internalAdapter.findSession(rotatedCredential!.refreshToken),
		).resolves.toBeNull();
		await expect(
			context.internalAdapter.findSessionById(signedInSession.session.id),
		).resolves.toBeNull();
		expect(
			(await context.internalAdapter.listSessions(signedIn.user.id)).some(
				(session) => session.id === signedInSession.session.id,
			),
		).toBe(false);
		await expect(
			context.internalAdapter.rotateSessionCredential(
				rotatedCredential!.refreshToken,
				generateCredentialOperationKey(),
			),
		).resolves.toBeNull();
		await expect(
			context.internalAdapter.recoverSessionCredential(
				sourceToken,
				operationKey,
			),
		).resolves.toBeNull();

		const staleToken = "late-stale-passkey-session-token";
		const staleSessionId = "late-stale-passkey-session-id";
		const { id: _sourceId, ...sourceData } = source!;
		await db.create({
			model: "session",
			forceAllowId: true,
			data: {
				...sourceData,
				id: staleSessionId,
				token: createSessionHandle(staleSessionId),
				createdAt: new Date(),
				updatedAt: new Date(),
				expiresAt: new Date(Date.now() + 60 * 60 * 1000),
				passkeySessionGeneration: staleGeneration,
			},
		});
		const now = new Date();
		await db.create({
			model: "sessionCredential",
			forceAllowId: true,
			data: {
				id: "late-stale-passkey-session-credential",
				selector: "late-stale-passkey-session-selector",
				sessionId: staleSessionId,
				familyId: "late-stale-passkey-session-family",
				secretDigest: await digestSessionRefreshSecret(staleToken),
				digestVersion: SESSION_CREDENTIAL_DIGEST_VERSION,
				status: "active",
				rotationCounter: 0,
				parentCredentialId: null,
				expiresAt: new Date(Date.now() + 60 * 60 * 1000),
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
		await expect(context.internalAdapter.findSession(staleToken)).resolves.toBeNull();
	});

	it("does not let a signed cookie-cache snapshot resurrect a rotated session", async () => {
		const { auth, db, testUser } = await getTestInstance({
			secret: SECRET,
			plugins: [passkey()],
			session: {
				cookieCache: { enabled: true, maxAge: 300 },
			},
		});
		const response = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		const headers = convertSetCookieToCookie(response.headers);
		expect(headers.get("cookie")).toContain("clearance.session_data=");
		const cached = await getCookieCache(headers, { secret: SECRET });
		expect(cached).not.toBeNull();
		expect(typeof cached?.session.passkeySessionGeneration).toBe("string");
		expect(cached?.user.passkeySessionGeneration).toBe(
			cached?.session.passkeySessionGeneration,
		);
		const signedIn = await auth.api.getSession({ headers });
		expect(signedIn).not.toBeNull();

		await db.update({
			model: "user",
			where: [{ field: "id", value: signedIn!.user.id }],
			update: { passkeySessionGeneration: "cookie-cache-rotated-generation" },
		});
		await expect(auth.api.getSession({ headers })).resolves.toBeNull();
	});

	it("matches only absent pairs or equal string generations", () => {
		expect(sessionMatchesPasskeyGeneration({}, {})).toBe(true);
		expect(
			sessionMatchesPasskeyGeneration(
				{ [PASSKEY_SESSION_GENERATION_FIELD]: "same" },
				{ [PASSKEY_SESSION_GENERATION_FIELD]: "same" },
			),
		).toBe(true);
		expect(
			sessionMatchesPasskeyGeneration(
				{ [PASSKEY_SESSION_GENERATION_FIELD]: "stale" },
				{},
			),
		).toBe(false);
		expect(
			sessionMatchesPasskeyGeneration(
				{},
				{ [PASSKEY_SESSION_GENERATION_FIELD]: "current" },
			),
		).toBe(false);
		expect(
			sessionMatchesPasskeyGeneration(
				{ [PASSKEY_SESSION_GENERATION_FIELD]: "1" },
				{ [PASSKEY_SESSION_GENERATION_FIELD]: 1 },
			),
		).toBe(false);
	});
});
