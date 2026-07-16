import { randomUUID } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { OAUTH_TOKEN_MIGRATION_ID } from "../../db/session-credential-migration";
import { getTestInstance } from "../../test-utils/test-instance";
import { admin } from "../admin";
import { mcp } from ".";

const hasPostgres = Boolean(
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
		process.env.CLEARANCE_TEST_DATABASE_URL,
);

describe.skipIf(!hasPostgres)("MCP credential gate on PostgreSQL", () => {
	it("rejects code redemption when an administrator ban wins the user lock", async () => {
		const suffix = randomUUID();
		const { auth, customFetchImpl, db, signInWithTestUser } =
			await getTestInstance(
				{
					plugins: [admin(), mcp({ loginPage: "/login" })],
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
			name: "MCP race target",
			email: `mcp-race-${suffix}@example.test`,
			emailVerified: true,
			image: null,
		});
		const clientId = `mcp-race-client-${suffix}`;
		const clientSecret = `mcp-race-secret-${suffix}`;
		const redirectURI = "https://client.example.test/callback";
		await db.create({
			model: "oauthApplication",
			data: {
				id: randomUUID(),
				clientId,
				clientSecret,
				name: "MCP race client",
				type: "web",
				redirectUrls: redirectURI,
				disabled: false,
				userId: null,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
			forceAllowId: true,
		});
		const code = `mcp-race-code-${suffix}`;
		await context.internalAdapter.createVerificationValue({
			identifier: code,
			value: JSON.stringify({
				clientId,
				redirectURI,
				scope: ["openid", "offline_access"],
				userId: target.id,
				authTime: Date.now(),
				requireConsent: false,
				state: null,
			}),
			expiresAt: new Date(Date.now() + 60_000),
		});

		let lockedResolve!: () => void;
		const locked = new Promise<void>((resolve) => {
			lockedResolve = resolve;
		});
		let releaseResolve!: () => void;
		const release = new Promise<void>((resolve) => {
			releaseResolve = resolve;
		});
		const originalTransaction = context.adapter.transaction.bind(context.adapter);
		const transactionSpy = vi
			.spyOn(context.adapter, "transaction")
			.mockImplementation(async (callback) =>
				originalTransaction(async (trx) => {
					const originalUpdate = trx.update;
					trx.update = async <T>(
						input: Parameters<typeof originalUpdate>[0],
					) => {
						const result = await originalUpdate<T>(input);
						if (
							input.model === "user" &&
							(input.update as { banned?: boolean }).banned === true
						) {
							lockedResolve();
							await release;
						}
						return result;
					};
					return callback(trx);
				}),
			);
		try {
			const ban = auth.api.banUser({
				headers,
				body: { userId: target.id, banReason: "race proof" },
			});
			await locked;
			let redemptionSettled = false;
			const redemption = customFetchImpl(
				"http://localhost:3000/api/auth/mcp/token",
				{
					method: "POST",
					headers: { "content-type": "application/x-www-form-urlencoded" },
					body: new URLSearchParams({
						grant_type: "authorization_code",
						code,
						redirect_uri: redirectURI,
						client_id: clientId,
						client_secret: clientSecret,
					}).toString(),
				},
			).finally(() => {
				redemptionSettled = true;
			});
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(redemptionSettled).toBe(false);
			releaseResolve();
			const [, response] = await Promise.all([ban, redemption]);
			expect(response.status).toBe(401);
			expect(await response.json()).toMatchObject({ error: "invalid_grant" });
		} finally {
			releaseResolve();
			transactionSpy.mockRestore();
		}

		const families = await db.findMany<Record<string, unknown>>({
			model: "oauthAccessToken",
			where: [{ field: "userId", value: target.id }],
		});
		expect(families).toHaveLength(0);
	});

	it("fails closed before bearer lookup when the digest marker is absent", async () => {
		const { auth, db } = await getTestInstance(
			{
				plugins: [mcp({ loginPage: "/login" })],
				logger: { level: "error" },
			},
			{ testWith: "postgres", disableTestUser: true },
		);
		await db.delete({
			model: "securityMigration",
			where: [{ field: "key", value: OAUTH_TOKEN_MIGRATION_ID }],
		});

		await expect(
			auth.handler(
				new Request("http://localhost:3000/api/auth/mcp/get-session", {
					headers: {
						authorization: "Bearer legacy-plaintext-access-token",
					},
				}),
			),
		).rejects.toMatchObject({
			status: "SERVICE_UNAVAILABLE",
			statusCode: 503,
			body: { code: "SECURITY_MIGRATION_REQUIRED" },
			headers: { "Retry-After": "5" },
		});
	});
});
