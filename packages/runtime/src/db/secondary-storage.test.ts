import { runWithTransaction } from "@clearance/core/context";
import { safeJSONParse } from "@clearance/core/utils/json";
import { beforeEach, describe, expect, it } from "vitest";
import { admin } from "../plugins/admin/admin";
import { adminClient } from "../plugins/admin/client";
import { anonymous } from "../plugins/anonymous";
import { anonymousClient } from "../plugins/anonymous/client";
import { getTestInstance } from "../test-utils/test-instance";

function getCredentialKey(
	store: Map<string, string>,
	sessionId: string,
): string {
	const handleKey = [...store.keys()].find((key) =>
		key.endsWith(`:session-handle:${sessionId}`),
	);
	const handle = safeJSONParse<{ credentialKey?: string }>(
		handleKey ? store.get(handleKey) : null,
	);
	if (!handle?.credentialKey)
		throw new Error("Missing session credential handle");
	return handle.credentialKey;
}

function findSessionHandleKey(
	store: Map<string, string>,
	sessionId: string,
): string | undefined {
	return [...store.keys()].find((key) =>
		key.endsWith(`:session-handle:${sessionId}`),
	);
}

function findActiveSessionsKey(
	store: Map<string, string>,
	userId: string,
): string | undefined {
	return [...store.keys()].find(
		(key) =>
			key.endsWith(`:active-sessions:${userId}`) ||
			key.endsWith(`active-sessions-${userId}`),
	);
}

function secondaryMaterialForSession(
	store: Map<string, string>,
	sessionId: string,
	userId: string,
): {
	handleKey: string | undefined;
	credentialKey: string | undefined;
	activeEntry: { sessionId: string; credentialKey: string } | undefined;
} {
	const handleKey = findSessionHandleKey(store, sessionId);
	const handle = safeJSONParse<{ credentialKey?: string }>(
		handleKey ? store.get(handleKey) : null,
	);
	const credentialKey = handle?.credentialKey;
	const activeKey = findActiveSessionsKey(store, userId);
	const activeList = activeKey
		? safeJSONParse<Array<{ sessionId: string; credentialKey: string }>>(
				store.get(activeKey),
			) || []
		: [];
	return {
		handleKey,
		credentialKey:
			credentialKey && store.has(credentialKey) ? credentialKey : undefined,
		activeEntry: activeList.find((entry) => entry.sessionId === sessionId),
	};
}

describe("secondary storage - banned user authority", () => {
	it("rejects and removes a cached credential for a banned user", async () => {
		const store = new Map<string, string>();
		const { auth, db } = await getTestInstance(
			{
				plugins: [admin()],
				secondaryStorage: {
					namespace: "secondary-banned-user",
					set(key, value) {
						store.set(key, value);
					},
					get(key) {
						return store.get(key) ?? null;
					},
					delete(key) {
						store.delete(key);
					},
				},
			},
			{ disableTestUser: true },
		);
		const context = await auth.$context;
		const user = await context.internalAdapter.createUser({
			email: "secondary-banned-user@example.test",
			emailVerified: true,
			name: "Secondary banned user",
			image: null,
		});
		const session = await context.internalAdapter.createSession(user.id);
		const credentialKey = getCredentialKey(store, session.id);
		expect(store.has(credentialKey)).toBe(true);
		await db.update({
			model: "user",
			where: [{ field: "id", value: user.id }],
			update: { banned: true, updatedAt: new Date() },
		});

		await expect(
			context.internalAdapter.findSession(session.token),
		).resolves.toBeNull();
		expect(store.has(credentialKey)).toBe(false);
	});
});

describe("secondary storage - get returns JSON string", async () => {
	const namespace = "secondary-string-test";
	const migrationEpochKey = `clearance:${namespace}:session-storage-epoch`;
	const store = new Map<string, string>();

	const { client, signInWithTestUser } = await getTestInstance({
		secondaryStorage: {
			namespace,
			set(key, value, ttl) {
				store.set(key, value);
			},
			get(key) {
				return store.get(key) || null;
			},
			delete(key) {
				store.delete(key);
			},
		},
		rateLimit: {
			enabled: false,
		},
	});

	beforeEach(() => {
		const migrationEpoch = store.get(migrationEpochKey);
		store.clear();
		if (migrationEpoch) store.set(migrationEpochKey, migrationEpoch);
	});

	it("should work end-to-end with string return", async () => {
		expect(safeJSONParse<string>(store.get(migrationEpochKey))).toMatch(
			/^digest-v1:[A-Za-z0-9_-]+$/,
		);
		const { headers } = await signInWithTestUser();
		expect(store.size).toBe(4);

		const s1 = await client.getSession({
			fetchOptions: { headers },
		});
		expect(s1.data).toMatchObject({
			session: {
				userId: expect.any(String),
				expiresAt: expect.any(Date),
				ipAddress: expect.any(String),
				userAgent: expect.any(String),
			},
			user: {
				id: expect.any(String),
				name: "test user",
				email: "test@test.com",
				emailVerified: false,
				image: null,
				createdAt: expect.any(Date),
				updatedAt: expect.any(Date),
			},
		});
		expect(s1.data?.session.token).toBe(s1.data?.session.id);
		const signedCookie = headers.get("cookie") || "";
		const rawToken = signedCookie
			.split("clearance.session_token=")[1]
			?.split(".")[0];
		expect(rawToken).toBeDefined();
		expect(JSON.stringify([...store.entries()])).not.toContain(rawToken);

		const list = await client.listSessions({ fetchOptions: { headers } });
		expect(list.data?.length).toBe(1);

		const id = s1.data!.session.id;
		const revoke = await client.revokeSession({
			fetchOptions: { headers },
			id,
		});
		expect(revoke.data?.status).toBe(true);

		const after = await client.getSession({ fetchOptions: { headers } });
		expect(after.data).toBeNull();
		expect([...store.keys()]).toEqual([migrationEpochKey]);
	});
});

describe("secondary storage - get returns already-parsed object", async () => {
	const namespace = "secondary-object-test";
	const migrationEpochKey = `clearance:${namespace}:session-storage-epoch`;
	const store = new Map<string, any>();

	const { client, signInWithTestUser } = await getTestInstance({
		secondaryStorage: {
			namespace,
			set(key, value, ttl) {
				store.set(key, safeJSONParse(value));
			},
			get(key) {
				return store.get(key);
			},
			delete(key) {
				store.delete(key);
			},
		},
		rateLimit: {
			enabled: false,
		},
	});

	beforeEach(() => {
		const migrationEpoch = store.get(migrationEpochKey);
		store.clear();
		if (migrationEpoch) store.set(migrationEpochKey, migrationEpoch);
	});

	it("should work end-to-end with object return", async () => {
		expect(store.get(migrationEpochKey)).toMatch(
			/^digest-v1:[A-Za-z0-9_-]+$/,
		);
		const { headers } = await signInWithTestUser();

		const s1 = await client.getSession({ fetchOptions: { headers } });
		expect(s1.data).not.toBeNull();

		const userId = s1.data!.session.userId;
		const activeList = store.get(
			`clearance:${namespace}:active-sessions:${userId}`,
		);
		expect(Array.isArray(activeList)).toBe(true);
		expect(activeList.length).toBe(1);

		const list = await client.listSessions({ fetchOptions: { headers } });
		expect(list.data?.length).toBe(1);

		const id = s1.data!.session.id;
		const revoke = await client.revokeSession({
			fetchOptions: { headers },
			id,
		});
		expect(revoke.data?.status).toBe(true);

		const after = await client.getSession({ fetchOptions: { headers } });
		expect(after.data).toBeNull();
		const activeAfter = store.get(
			`clearance:${namespace}:active-sessions:${userId}`,
		);
		expect(activeAfter ?? null).toBeNull();
		expect([...store.keys()]).toEqual([migrationEpochKey]);
	});
});

describe("secondary storage - storeSessionInDatabase", () => {
	describe("preserveSessionInDatabase: false", async () => {
		const store = new Map<string, string>();

		const { client, signInWithTestUser } = await getTestInstance({
			secondaryStorage: {
				set(key, value, ttl) {
					store.set(key, value);
				},
				get(key) {
					return store.get(key) || null;
				},
				delete(key) {
					store.delete(key);
				},
			},
			session: {
				storeSessionInDatabase: true,
				preserveSessionInDatabase: false,
			},
			rateLimit: {
				enabled: false,
			},
		});

		beforeEach(() => {
			store.clear();
		});

		it("should not return a revoked session when it is deleted from both storages", async () => {
			const { headers } = await signInWithTestUser();

			const s1 = await client.getSession({ fetchOptions: { headers } });
			expect(s1.data).not.toBeNull();
			const id = s1.data!.session.id;

			expect(
				[...store.keys()].some((key) => key.includes(":session-credential:")),
			).toBe(true);

			const revoke = await client.revokeSession({
				fetchOptions: { headers },
				id,
			});
			expect(revoke.data?.status).toBe(true);

			expect(
				[...store.keys()].some((key) => key.includes(":session-credential:")),
			).toBe(false);

			// Revoke deletes from both secondary storage and database,
			// so the session should not be usable
			const after = await client.getSession({ fetchOptions: { headers } });
			expect(after.data).toBeNull();
		});
	});

	describe("preserveSessionInDatabase: true", async () => {
		const store = new Map<string, string>();

		const { client, signInWithTestUser } = await getTestInstance({
			secondaryStorage: {
				set(key, value, ttl) {
					store.set(key, value);
				},
				get(key) {
					return store.get(key) || null;
				},
				delete(key) {
					store.delete(key);
				},
			},
			session: {
				storeSessionInDatabase: true,
				preserveSessionInDatabase: true,
			},
			rateLimit: {
				enabled: false,
			},
		});

		beforeEach(() => {
			store.clear();
		});

		it("should not return a revoked session even if it exists in database", async () => {
			const { headers } = await signInWithTestUser();

			const s1 = await client.getSession({ fetchOptions: { headers } });
			expect(s1.data).not.toBeNull();
			const id = s1.data!.session.id;

			// Session should exist in secondary storage
			expect(
				[...store.keys()].some((key) => key.includes(":session-credential:")),
			).toBe(true);

			// Revoke the session
			const revoke = await client.revokeSession({
				fetchOptions: { headers },
				id,
			});
			expect(revoke.data?.status).toBe(true);

			// Session should be removed from secondary storage
			expect(
				[...store.keys()].some((key) => key.includes(":session-credential:")),
			).toBe(false);

			// Session should NOT be usable anymore, even though it's preserved in database
			const after = await client.getSession({ fetchOptions: { headers } });
			expect(after.data).toBeNull();
		});
	});
});

describe("secondary storage - dual-write createSession publication", () => {
	it("leaves zero secondary ghost material when the outer transaction rolls back", async () => {
		const namespace = "secondary-dual-write-rollback";
		const store = new Map<string, string>();
		const { auth } = await getTestInstance(
			{
				secondaryStorage: {
					namespace,
					set(key, value) {
						store.set(key, value);
					},
					get(key) {
						return store.get(key) ?? null;
					},
					delete(key) {
						store.delete(key);
					},
				},
				session: {
					storeSessionInDatabase: true,
				},
				rateLimit: {
					enabled: false,
				},
			},
			{ disableTestUser: true },
		);
		const context = await auth.$context;
		const user = await context.internalAdapter.createUser({
			email: "dual-write-rollback@example.test",
			emailVerified: true,
			name: "Dual write rollback",
			image: null,
		});

		const establishedKey = `clearance:${namespace}:unrelated-established`;
		store.set(establishedKey, "keep-me");
		const keysBefore = new Set(store.keys());

		let attemptedSessionId: string | undefined;
		let attemptedToken: string | undefined;

		await expect(
			runWithTransaction(context.adapter, async () => {
				const session = await context.internalAdapter.createSession(user.id);
				attemptedSessionId = session.id;
				attemptedToken = session.token;
				// Nested createSession must not flush secondary publication before
				// the outermost commit.
				expect(
					secondaryMaterialForSession(store, session.id, user.id),
				).toEqual({
					handleKey: undefined,
					credentialKey: undefined,
					activeEntry: undefined,
				});
				throw new Error("force dual-write outer rollback");
			}),
		).rejects.toThrow("force dual-write outer rollback");

		expect(attemptedSessionId).toBeDefined();
		expect(store.has(establishedKey)).toBe(true);

		const material = secondaryMaterialForSession(
			store,
			attemptedSessionId!,
			user.id,
		);
		expect(material).toEqual({
			handleKey: undefined,
			credentialKey: undefined,
			activeEntry: undefined,
		});

		const newSessionKeys = [...store.keys()].filter(
			(key) =>
				!keysBefore.has(key) &&
				(key.includes("session-credential:") ||
					key.includes("session-handle:") ||
					key.includes("active-sessions")),
		);
		expect(newSessionKeys).toEqual([]);

		for (const [key, value] of store) {
			if (keysBefore.has(key)) continue;
			expect(value).not.toContain(attemptedSessionId);
		}

		await expect(
			context.internalAdapter.findSession(attemptedToken!),
		).resolves.toBeNull();
	});

	it("publishes credential, handle, and active-index after a successful dual-write commit", async () => {
		const namespace = "secondary-dual-write-commit";
		const store = new Map<string, string>();
		const { auth } = await getTestInstance(
			{
				secondaryStorage: {
					namespace,
					set(key, value) {
						store.set(key, value);
					},
					get(key) {
						return store.get(key) ?? null;
					},
					delete(key) {
						store.delete(key);
					},
				},
				session: {
					storeSessionInDatabase: true,
				},
				rateLimit: {
					enabled: false,
				},
			},
			{ disableTestUser: true },
		);
		const context = await auth.$context;
		const user = await context.internalAdapter.createUser({
			email: "dual-write-commit@example.test",
			emailVerified: true,
			name: "Dual write commit",
			image: null,
		});

		const establishedKey = `clearance:${namespace}:unrelated-established`;
		store.set(establishedKey, "keep-me");

		let created:
			| {
					id: string;
					token: string;
			  }
			| undefined;

		await runWithTransaction(context.adapter, async () => {
			created = await context.internalAdapter.createSession(user.id);
			// Still inside the outer transaction: publication must wait.
			expect(
				secondaryMaterialForSession(store, created.id, user.id),
			).toEqual({
				handleKey: undefined,
				credentialKey: undefined,
				activeEntry: undefined,
			});
		});

		expect(created).toBeDefined();
		const material = secondaryMaterialForSession(
			store,
			created!.id,
			user.id,
		);
		expect(material.handleKey).toBeDefined();
		expect(material.credentialKey).toBeDefined();
		expect(material.activeEntry).toMatchObject({
			sessionId: created!.id,
			credentialKey: material.credentialKey,
		});
		expect(store.has(establishedKey)).toBe(true);

		const envelope = safeJSONParse<{
			session?: { id?: string };
			user?: { id?: string } | null;
		}>(store.get(material.credentialKey!));
		expect(envelope?.session?.id).toBe(created!.id);
		expect(envelope?.user?.id).toBe(user.id);

		await expect(
			context.internalAdapter.findSession(created!.token),
		).resolves.toMatchObject({
			session: { id: created!.id, userId: user.id },
			user: { id: user.id },
		});
	});
});

/**
 * @see https://github.com/clearance-auth/clearance
 */
describe("secondary storage - admin removeUser cleans up sessions", async () => {
	const namespace = "secondary-admin-remove-user";
	const migrationEpochKey = `clearance:${namespace}:session-storage-epoch`;
	const store = new Map<string, string>();

	beforeEach(() => {
		const migrationEpoch = store.get(migrationEpochKey);
		store.clear();
		if (migrationEpoch) store.set(migrationEpochKey, migrationEpoch);
	});

	const { client, signInWithUser, customFetchImpl } = await getTestInstance({
		plugins: [admin()],
		secondaryStorage: {
			namespace,
			set(key, value, ttl) {
				store.set(key, value);
			},
			get(key) {
				return store.get(key) || null;
			},
			delete(key) {
				store.delete(key);
			},
		},
		databaseHooks: {
			user: {
				create: {
					before: async (user) => {
						if (user.email === "admin@test.com") {
							return { data: { ...user, role: "admin" } };
						}
					},
				},
			},
		},
		rateLimit: {
			enabled: false,
		},
	});

	const { createAuthClient } = await import("../client");
	const adminAuthClient = createAuthClient({
		fetchOptions: { customFetchImpl },
		plugins: [adminClient()],
		baseURL: "http://localhost:3000",
	});

	it("should clear secondary storage sessions when removing a user via admin", async () => {
		await client.signUp.email({
			email: "admin@test.com",
			password: "password",
			name: "Admin",
		});
		const { headers: adminHeaders } = await signInWithUser(
			"admin@test.com",
			"password",
		);

		await client.signUp.email({
			email: "victim@test.com",
			password: "password",
			name: "Victim",
		});
		const { headers: victimHeaders } = await signInWithUser(
			"victim@test.com",
			"password",
		);

		const victimSession = await client.getSession({
			fetchOptions: { headers: victimHeaders },
		});
		expect(victimSession.data).not.toBeNull();

		const victimId = victimSession.data!.user.id;
		const victimSessionId = victimSession.data!.session.id;
		const victimCredentialKey = getCredentialKey(store, victimSessionId);
		expect(store.has(victimCredentialKey)).toBe(true);

		await adminAuthClient.admin.removeUser(
			{ userId: victimId },
			{ headers: adminHeaders },
		);

		expect(store.has(victimCredentialKey)).toBe(false);
		expect(
			[...store.keys()].some((key) =>
				key.endsWith(`:session-handle:${victimSessionId}`),
			),
		).toBe(false);

		const after = await client.getSession({
			fetchOptions: { headers: victimHeaders },
		});
		expect(after.data).toBeNull();
	});
});

/**
 * @see https://github.com/clearance-auth/clearance
 */
describe("secondary storage - /delete-anonymous-user cleans up sessions", async () => {
	const namespace = "secondary-anonymous-delete";
	const migrationEpochKey = `clearance:${namespace}:session-storage-epoch`;
	const store = new Map<string, string>();

	beforeEach(() => {
		const migrationEpoch = store.get(migrationEpochKey);
		store.clear();
		if (migrationEpoch) store.set(migrationEpochKey, migrationEpoch);
	});

	const { client, auth, sessionSetter } = await getTestInstance(
		{
			plugins: [anonymous()],
			secondaryStorage: {
				namespace,
				set(key, value, ttl) {
					store.set(key, value);
				},
				get(key) {
					return store.get(key) || null;
				},
				delete(key) {
					store.delete(key);
				},
			},
			rateLimit: {
				enabled: false,
			},
		},
		{
			clientOptions: {
				plugins: [anonymousClient()],
			},
		},
	);

	it("should clear secondary storage sessions when an anonymous user calls /delete-anonymous-user", async () => {
		const headers = new Headers();
		await client.signIn.anonymous({
			fetchOptions: { onSuccess: sessionSetter(headers) },
		});

		const session = await client.getSession({ fetchOptions: { headers } });
		expect(session.data).not.toBeNull();

		const sessionId = session.data!.session.id;
		const credentialKey = getCredentialKey(store, sessionId);
		expect(store.has(credentialKey)).toBe(true);

		await auth.api.deleteAnonymousUser({ headers });

		expect(store.has(credentialKey)).toBe(false);
		expect(
			[...store.keys()].some((key) =>
				key.endsWith(`:session-handle:${sessionId}`),
			),
		).toBe(false);

		const after = await client.getSession({ fetchOptions: { headers } });
		expect(after.data).toBeNull();
	});
});
