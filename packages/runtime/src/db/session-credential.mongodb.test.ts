import { randomUUID } from "node:crypto";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { describe, expect, it } from "vitest";
import { mongodbAdapter } from "../adapters/mongodb-adapter";
import { mcp } from "../plugins/mcp";
import {
	createOAuthTokenPair,
	rotateOAuthRefreshToken,
} from "../plugins/oidc-provider";
import { getTestInstance } from "../test-utils/test-instance";
import { generateCredentialOperationKey } from "../utils/operation-key";
import { migrateCredentialAuthorities } from "./credential-authority-migration";
import {
	OAUTH_TOKEN_MIGRATION_ID,
	SESSION_CREDENTIAL_MIGRATION_ID,
} from "./session-credential-migration";

const hasMongo = Boolean(process.env.CLEARANCE_TEST_MONGODB_URL);

describe.skipIf(!hasMongo)("credential authority on transactional MongoDB", () => {
	it("rolls back atomically and enforces session and OAuth credential families", async () => {
		const { auth, db, mongo } = await getTestInstance(
			{
				logger: { level: "error" },
				plugins: [mcp({ loginPage: "/login" })],
			},
			{ testWith: "mongodb", disableTestUser: true },
		);
		if (!mongo) throw new Error("Mongo test resource was not retained");
		expect(db.options?.adapterConfig.transaction).toEqual(expect.any(Function));
		const credentialIndexes = await Promise.all(
			[
				"securityMigration",
				"sessionCredential",
				"oauthAccessToken",
			].map((model) => mongo.db.collection(model).listIndexes().toArray()),
		);
		for (const name of [
			"clearance_securityMigration_key_unique_v1",
			"clearance_sessionCredential_selector_unique_v1",
			"clearance_sessionCredential_secretDigest_unique_v1",
			"clearance_sessionCredential_parentCredentialId_unique_v1",
			"clearance_oauthAccessToken_accessTokenDigest_unique_v1",
			"clearance_oauthAccessToken_refreshTokenDigest_unique_v1",
		]) {
			const installed = credentialIndexes.flat().find((index) => index.name === name);
			expect(installed, name).toMatchObject({ unique: true });
		}
		expect(
			credentialIndexes
				.flat()
				.find(
					(index) =>
						index.name ===
						"clearance_sessionCredential_parentCredentialId_unique_v1",
				)?.partialFilterExpression,
		).toEqual({ parentCredentialId: { $type: "objectId" } });
		expect(
			credentialIndexes
				.flat()
				.find(
					(index) =>
						index.name ===
						"clearance_oauthAccessToken_accessTokenDigest_unique_v1",
				)?.partialFilterExpression,
		).toEqual({ accessTokenDigest: { $type: "string" } });

		const rollbackEmail = `mongo-rollback-${randomUUID()}@example.test`;
		await expect(
			runWithTransaction(db, async () => {
				const tx = await getCurrentAdapter(db);
				await tx.create({
					model: "user",
					data: {
						name: "Rolled back",
						email: rollbackEmail,
						emailVerified: true,
						image: null,
						createdAt: new Date(),
						updatedAt: new Date(),
					},
				});
				throw new Error("transaction rollback proof");
			}),
		).rejects.toThrow("transaction rollback proof");
		expect(
			await db.findOne({
				model: "user",
				where: [{ field: "email", value: rollbackEmail }],
			}),
		).toBeNull();

		const context = await auth.$context;
		const user = await context.internalAdapter.createUser({
			name: "Mongo credential proof",
			email: `mongo-credential-${randomUUID()}@example.test`,
			emailVerified: true,
			image: null,
		});
		const retryable = await context.internalAdapter.createSession(
			user.id,
		);
		const sessionOperation = generateCredentialOperationKey();
		const firstSessionRotation =
			await context.internalAdapter.rotateSessionCredential(
				retryable.token,
				sessionOperation,
			);
		const retriedSessionRotation =
			await context.internalAdapter.rotateSessionCredential(
				retryable.token,
				sessionOperation,
			);
		expect(retriedSessionRotation).toMatchObject({
			refreshToken: firstSessionRotation!.refreshToken,
			familyId: firstSessionRotation!.familyId,
			rotationCounter: 1,
		});

		const contestedSession = await context.internalAdapter.createSession(
			user.id,
		);
		const sessionWinner = await context.internalAdapter.rotateSessionCredential(
			contestedSession.token,
			generateCredentialOperationKey(),
		);
		expect(sessionWinner).not.toBeNull();
		expect(
			await context.internalAdapter.rotateSessionCredential(
				contestedSession.token,
				generateCredentialOperationKey(),
			),
		).toBeNull();
		const revokedSessionFamily = await db.findMany<Record<string, unknown>>({
			model: "sessionCredential",
			where: [{ field: "familyId", value: sessionWinner!.familyId }],
		});
		expect(revokedSessionFamily).toHaveLength(2);
		expect(
			revokedSessionFamily.every(
				(row) => row.status === "revoked" && row.reuseDetectedAt instanceof Date,
			),
		).toBe(true);

		const oauthInput = {
			clientId: `mongo-client-${randomUUID()}`,
			userId: user.id,
			scopes: "openid offline_access",
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			issueRefreshToken: true,
		};
		const retryableOAuth = await createOAuthTokenPair(
			db,
			"oauthAccessToken",
			oauthInput,
		);
		const oauthOperation = generateCredentialOperationKey();
		const rotateRetryableOAuth = () =>
			rotateOAuthRefreshToken(db, "oauthAccessToken", {
				presentedRefreshToken: retryableOAuth.refreshToken!,
				clientId: oauthInput.clientId,
				accessTokenExpiresAt: new Date(Date.now() + 300_000),
				secretConfig: "mongo-oauth-rotation-proof-secret",
				idempotencyKey: oauthOperation,
			});
		const firstOAuthRotation = await rotateRetryableOAuth();
		const retriedOAuthRotation = await rotateRetryableOAuth();
		expect(firstOAuthRotation.kind).toBe("rotated");
		expect(retriedOAuthRotation).toMatchObject({
			kind: "rotated",
			successor: {
				accessToken:
					firstOAuthRotation.kind === "rotated"
						? firstOAuthRotation.successor.accessToken
						: "unreachable",
				refreshToken:
					firstOAuthRotation.kind === "rotated"
						? firstOAuthRotation.successor.refreshToken
						: "unreachable",
			},
		});

		const contestedOAuth = await createOAuthTokenPair(
			db,
			"oauthAccessToken",
			{
				...oauthInput,
				clientId: `${oauthInput.clientId}-contested`,
			},
		);
		const oauthWinner = await rotateOAuthRefreshToken(
			db,
			"oauthAccessToken",
			{
				presentedRefreshToken: contestedOAuth.refreshToken!,
				clientId: `${oauthInput.clientId}-contested`,
				accessTokenExpiresAt: new Date(Date.now() + 300_000),
				secretConfig: "mongo-oauth-rotation-proof-secret",
				idempotencyKey: generateCredentialOperationKey(),
			},
		);
		expect(oauthWinner.kind).toBe("rotated");
		expect(
			await rotateOAuthRefreshToken(db, "oauthAccessToken", {
				presentedRefreshToken: contestedOAuth.refreshToken!,
				clientId: `${oauthInput.clientId}-contested`,
				accessTokenExpiresAt: new Date(Date.now() + 300_000),
				secretConfig: "mongo-oauth-rotation-proof-secret",
				idempotencyKey: generateCredentialOperationKey(),
			}),
		).toEqual({ kind: "reused" });
		const revokedOAuthFamily = await db.findMany<Record<string, unknown>>({
			model: "oauthAccessToken",
			where: [{ field: "familyId", value: contestedOAuth.row.familyId! }],
		});
		expect(revokedOAuthFamily).toHaveLength(2);
		expect(
			revokedOAuthFamily.every(
				(row) =>
					row.refreshStatus === "revoked" &&
					row.reuseDetectedAt instanceof Date,
			),
		).toBe(true);

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

	it("rejects duplicate authority keys before any Mongo migration mutation", async () => {
		const { auth, db, mongo } = await getTestInstance(
			{
				logger: { level: "error" },
				plugins: [mcp({ loginPage: "/login" })],
			},
			{ testWith: "mongodb", disableTestUser: true },
		);
		if (!mongo) throw new Error("Mongo test resource was not retained");
		const markers = mongo.db.collection("securityMigration");
		await markers.dropIndex("clearance_securityMigration_key_unique_v1");
		await markers.insertMany([
			{
				key: "duplicate-authority-marker",
				state: "complete",
				createdAt: new Date(),
				updatedAt: new Date(),
			},
			{
				key: "duplicate-authority-marker",
				state: "complete",
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		]);

		await expect(
			migrateCredentialAuthorities(db, auth.options),
		).rejects.toMatchObject({ code: 11000 });
		expect(
			await markers.countDocuments({ key: "duplicate-authority-marker" }),
		).toBe(2);
	});

	it("resumes both durable authorities and publishes both markers before traffic resumes", async () => {
		const generateId = () => randomUUID();
		const instance = await getTestInstance(
			{
				logger: { level: "error" },
				plugins: [mcp({ loginPage: "/login" })],
				advanced: {
					database: {
						generateId,
					},
				},
			},
			{ testWith: "mongodb", disableTestUser: true },
		);
		const { auth, db, mongo } = instance;
		if (!mongo) throw new Error("Mongo test resource was not retained");
		const context = await auth.$context;
		const now = new Date();
		const userId = "legacy-mongo-user";
		const legacyAccessToken = "legacy-mongo-access-token";
		await mongo.db.collection("securityMigration").deleteMany({});
		await mongo.db.collection("sessionCredential").deleteMany({});
		await mongo.db.collection("session").deleteMany({});
		await mongo.db.collection("oauthAccessToken").deleteMany({});
		await mongo.db
			.collection<{ _id: string } & Record<string, unknown>>("user")
			.insertOne({
				_id: userId,
				name: "Legacy Mongo user",
				email: "legacy-mongo@example.test",
				emailVerified: true,
				image: null,
				createdAt: now,
				updatedAt: now,
			});
		await mongo.db
			.collection<{ _id: string } & Record<string, unknown>>("session")
			.insertMany(
				Array.from({ length: 501 }, (_, index) => {
					const suffix = index.toString().padStart(4, "0");
					return {
						_id: `legacy-mongo-session-${suffix}`,
						userId,
						token: `legacy-mongo-token-${suffix}`,
						expiresAt: new Date(now.getTime() + 3_600_000),
						createdAt: now,
						updatedAt: now,
					};
				}),
			);
		await mongo.db
			.collection<{ _id: string } & Record<string, unknown>>(
				"oauthApplication",
			)
			.insertOne({
				_id: "legacy-mongo-client-record",
				name: "Legacy Mongo client",
				clientId: "legacy-mongo-client",
				clientSecret: null,
				redirectUrls: "https://client.example.test/callback",
				type: "public",
				disabled: false,
				userId,
				createdAt: now,
				updatedAt: now,
			});
		await mongo.db
			.collection<{ _id: string } & Record<string, unknown>>(
				"oauthAccessToken",
			)
			.insertOne({
				_id: "legacy-mongo-oauth-token",
				accessToken: legacyAccessToken,
				refreshToken: "legacy-mongo-refresh-token",
				accessTokenExpiresAt: new Date(now.getTime() + 300_000),
				refreshTokenExpiresAt: new Date(now.getTime() + 3_600_000),
				clientId: "legacy-mongo-client",
				userId,
				scopes: "openid offline_access",
				createdAt: now,
				updatedAt: now,
			});

		await expect(
			auth.handler(
				new Request("http://localhost:3000/api/auth/mcp/get-session", {
					headers: { authorization: `Bearer ${legacyAccessToken}` },
				}),
			),
		).rejects.toMatchObject({
			statusCode: 503,
			body: { code: "SECURITY_MIGRATION_REQUIRED" },
		});

		const originalTransaction = db.transaction.bind(db);
		db.storagePersistence = "ephemeral";
		let transactions = 0;
		db.transaction = async (callback) => {
			transactions += 1;
			if (transactions === 2) {
				throw new Error("simulated process stop after one committed page");
			}
			return originalTransaction(callback);
		};
		try {
			await expect(
				migrateCredentialAuthorities(db, auth.options),
			).rejects.toThrow("simulated process stop after one committed page");
		} finally {
			db.transaction = originalTransaction;
		}
		expect(
			await mongo.db.collection("securityMigration").countDocuments({
				key: {
					$in: [
						SESSION_CREDENTIAL_MIGRATION_ID,
						OAUTH_TOKEN_MIGRATION_ID,
					],
				},
			}),
		).toBe(0);

		expect(
			await mongo.db.collection("sessionCredential").countDocuments(),
		).toBe(500);
		const interruptedProgress = await mongo.db
			.collection("securityMigration")
			.findOne({ key: `${SESSION_CREDENTIAL_MIGRATION_ID}:progress` });
		expect(interruptedProgress).toMatchObject({
			state: "running",
			phase: "migrate",
			revision: 2,
		});
		expect(interruptedProgress?.cursor).toContain("legacy-mongo-session-0499");

		await expect(
			auth.handler(
				new Request("http://localhost:3000/api/auth/get-session"),
			),
		).rejects.toMatchObject({
			statusCode: 503,
			body: { code: "SECURITY_MIGRATION_REQUIRED" },
		});

		const restartedAdapter = mongodbAdapter(mongo.db, {
			client: mongo.client,
		})(auth.options);
		restartedAdapter.storagePersistence = "ephemeral";
		await migrateCredentialAuthorities(restartedAdapter, auth.options);
		expect(
			await mongo.db.collection("securityMigration").countDocuments({
				key: {
					$in: [
						SESSION_CREDENTIAL_MIGRATION_ID,
						OAUTH_TOKEN_MIGRATION_ID,
					],
				},
				state: "complete",
			}),
		).toBe(2);
		const migratedOAuth = await mongo.db
			.collection<{ _id: string } & Record<string, unknown>>(
				"oauthAccessToken",
			)
			.findOne({ _id: "legacy-mongo-oauth-token" });
		expect(migratedOAuth).toMatchObject({
			digestVersion: 1,
			refreshStatus: "active",
		});
		expect(migratedOAuth?.accessToken).not.toBe(legacyAccessToken);
		expect(migratedOAuth?.refreshToken).not.toBe(
			"legacy-mongo-refresh-token",
		);

		expect(
			await mongo.db.collection("sessionCredential").countDocuments(),
		).toBe(501);
		expect(
			await mongo.db
				.collection("session")
				.countDocuments({ token: { $not: /^clr_sid_/ } }),
		).toBe(0);
		const completeProgress = await mongo.db
			.collection("securityMigration")
			.findOne({ key: `${SESSION_CREDENTIAL_MIGRATION_ID}:progress` });
		expect(completeProgress).toMatchObject({
			state: "ready",
			phase: "ready",
		});
		expect(completeProgress!.revision).toBeGreaterThan(2);
		expect(
			await context.internalAdapter.findSession("legacy-mongo-token-0000"),
		).toMatchObject({ session: { id: "legacy-mongo-session-0000" } });
		const admitted = await auth.handler(
			new Request("http://localhost:3000/api/auth/get-session"),
		);
		expect(admitted.status).toBe(200);
		const oauthAdmitted = await auth.handler(
			new Request("http://localhost:3000/api/auth/mcp/get-session", {
				headers: { authorization: `Bearer ${legacyAccessToken}` },
			}),
		);
		expect(oauthAdmitted.status).toBe(200);
	});
});
