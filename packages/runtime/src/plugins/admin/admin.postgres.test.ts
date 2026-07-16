import { randomUUID } from "node:crypto";
import { runWithTransaction } from "@clearance/core/context";
import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { createOAuthTokenPair } from "../oidc-provider";
import { mcp } from "../mcp";
import { admin } from ".";

const hasPostgres = Boolean(
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
		process.env.CLEARANCE_TEST_DATABASE_URL,
);

describe.skipIf(!hasPostgres)("admin credential atomicity on PostgreSQL", () => {
	it("keeps secondary session state when a later outer transaction step rolls back", async () => {
		const suffix = randomUUID();
		const secondary = new Map<string, string>();
		const { auth } = await getTestInstance(
			{
				session: { storeSessionInDatabase: true },
				secondaryStorage: {
					namespace: `delete-session-rollback-${suffix}`,
					set(key: string, value: string) {
						secondary.set(key, value);
					},
					get(key: string) {
						return secondary.get(key);
					},
					delete(key: string) {
						secondary.delete(key);
					},
				},
			},
			{ testWith: "postgres", disableTestUser: true },
		);
		const context = await auth.$context;
		const user = await context.internalAdapter.createUser({
			name: "Delete rollback target",
			email: `delete-rollback-${suffix}@example.test`,
			emailVerified: true,
			image: null,
		});
		const session = await context.internalAdapter.createSession(user.id);
		const secondaryBefore = [...secondary.entries()].sort(([a], [b]) =>
			a.localeCompare(b),
		);

		await expect(
			runWithTransaction(context.adapter, async () => {
				await context.internalAdapter.deleteSession(session.token);
				throw new Error("later outer mutation failed");
			}),
		).rejects.toThrow("later outer mutation failed");

		await expect(
			context.internalAdapter.findSession(session.token),
		).resolves.toMatchObject({ user: { id: user.id } });
		expect(
			[...secondary.entries()].sort(([a], [b]) => a.localeCompare(b)),
		).toEqual(secondaryBefore);
	});

	it("rolls back both disable routes after OAuth revocation has executed", async () => {
		const suffix = randomUUID();
		const secondary = new Map<string, string>();
		const { auth, db, signInWithTestUser } = await getTestInstance(
			{
				plugins: [admin(), mcp({ loginPage: "/login" })],
				session: { storeSessionInDatabase: true },
				verification: { storeInDatabase: true },
				secondaryStorage: {
					namespace: `admin-rollback-${suffix}`,
					runExclusive<T>(_name: string, operation: () => T): T {
						return operation();
					},
					assertNoLegacySessionWriters() {},
					set(key: string, value: string) {
						secondary.set(key, value);
					},
					get(key: string) {
						return secondary.get(key);
					},
					delete(key: string) {
						secondary.delete(key);
					},
				},
				databaseHooks: {
					user: {
						create: {
							before: async (user) => ({
								data: {
									...user,
									emailVerified: true,
									...(user.name === "Admin" ? { role: "admin" } : {}),
								},
							}),
						},
					},
				},
			},
			{ testWith: "postgres", testUser: { name: "Admin" } },
		);
		const { headers } = await signInWithTestUser();
		const context = await auth.$context;
		const target = await context.internalAdapter.createUser({
			name: "Admin rollback target",
			email: `admin-rollback-${suffix}@example.test`,
			emailVerified: true,
			image: null,
		});
			const session = await context.internalAdapter.createSession(target.id);
			const secondaryKeysBefore = [...secondary.keys()].sort();
			expect(secondaryKeysBefore.length).toBeGreaterThanOrEqual(3);
		const clientId = `admin-rollback-client-${suffix}`;
		await db.create({
			model: "oauthApplication",
			data: {
				id: randomUUID(),
				clientId,
				clientSecret: `admin-rollback-secret-${suffix}`,
				name: "Admin rollback client",
				type: "web",
				redirectUrls: "https://client.example.test/callback",
				disabled: false,
				userId: null,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
			forceAllowId: true,
		});
		const family = await createOAuthTokenPair(db, "oauthAccessToken", {
			clientId,
			userId: target.id,
			scopes: "openid offline_access",
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			issueRefreshToken: true,
		});

		const originalTransaction = context.adapter.transaction.bind(context.adapter);
		const transactionSpy = vi
			.spyOn(context.adapter, "transaction")
			.mockImplementation(async (callback) =>
				originalTransaction(async (trx) => {
					const originalUpdateMany = trx.updateMany.bind(trx);
					trx.updateMany = async (input) => {
						const result = await originalUpdateMany(input);
						if (input.model === "oauthAccessToken") {
							throw new Error("forced post-revocation rollback");
						}
						return result;
					};
					return callback(trx);
				}),
			);
		try {
			for (const mutate of [
				() =>
					auth.api.banUser({
						headers,
						body: { userId: target.id, banReason: "rollback proof" },
					}),
				() =>
					auth.api.adminUpdateUser({
						headers,
						body: {
							userId: target.id,
							data: { banned: true, banReason: "rollback proof" },
						},
					}),
			]) {
				await expect(mutate()).rejects.toThrow(
					"forced post-revocation rollback",
				);
				await expect(
					context.internalAdapter.findUserById(target.id),
				).resolves.toMatchObject({ banned: false });
					await expect(
						context.internalAdapter.findSession(session.token),
					).resolves.toMatchObject({ user: { id: target.id } });
					expect([...secondary.keys()].sort()).toEqual(secondaryKeysBefore);
				await expect(
					db.findOne<Record<string, unknown>>({
						model: "oauthAccessToken",
						where: [{ field: "id", value: family.row.id }],
					}),
				).resolves.toMatchObject({ refreshStatus: "active" });
			}
		} finally {
			transactionSpy.mockRestore();
		}
	});
});
