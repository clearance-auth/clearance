import { randomUUID } from "node:crypto";
import type { ClearanceOptions } from "@clearance/core";
import { kyselyAdapter } from "@clearance/kysely-adapter";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";
import { describe, expect, it, vi } from "vitest";
import {
	attachInternalCredentialAuthority,
	readInternalCredentialAuthority,
} from "../../internal/credential-authority";
import { getTestInstance } from "../../test-utils/test-instance";
import { generateCredentialOperationKey } from "../../utils/operation-key";
import { admin } from "../admin";
import {
	createOAuthTokenPair,
	findOAuthTokenBySecret,
	oidcProvider,
	rotateOAuthRefreshToken,
} from ".";

const hasPostgres = Boolean(
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
		process.env.CLEARANCE_TEST_DATABASE_URL,
);
const postgresUrl =
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
	process.env.CLEARANCE_TEST_DATABASE_URL;

describe.skipIf(!hasPostgres)("OIDC refresh authority on PostgreSQL", () => {
	it("serves and rotates raw v0.2.1 tokens without digest columns during bridge mode", async () => {
		const schema = `oidc_legacy_bridge_${randomUUID().replaceAll("-", "_")}`;
		const admin = new Pool({ connectionString: postgresUrl });
		const url = new URL(postgresUrl!);
		url.searchParams.set("options", `-csearch_path=${schema}`);
		const pool = new Pool({ connectionString: url.toString() });
		const database = new Kysely({
			dialect: new PostgresDialect({ pool }),
		});
		try {
			await admin.query(`CREATE SCHEMA "${schema}"`);
			await pool.query(`
				CREATE TABLE "user" (
					id text PRIMARY KEY,
					name text NOT NULL,
					email text NOT NULL UNIQUE,
					"emailVerified" boolean NOT NULL,
					image text,
					"createdAt" timestamptz NOT NULL,
					"updatedAt" timestamptz NOT NULL
				);
				CREATE TABLE "oauthAccessToken" (
					id text PRIMARY KEY,
					"accessToken" text,
					"refreshToken" text,
					"accessTokenExpiresAt" timestamptz NOT NULL,
					"refreshTokenExpiresAt" timestamptz,
					"clientId" text NOT NULL,
					"userId" text REFERENCES "user"(id) ON DELETE CASCADE,
					scopes text NOT NULL,
					"createdAt" timestamptz NOT NULL,
					"updatedAt" timestamptz NOT NULL
				)
			`);
			const userId = `legacy-user-${randomUUID()}`;
			const rawAccess = `legacy-access-${randomUUID()}`;
			const rawRefresh = `legacy-refresh-${randomUUID()}`;
			await pool.query(
				`INSERT INTO "user" (
					id, name, email, "emailVerified", "createdAt", "updatedAt"
				 ) VALUES ($1, 'Legacy OIDC', $2, true, now(), now())`,
				[userId, `${userId}@example.test`],
			);
			await pool.query(
				`INSERT INTO "oauthAccessToken" (
					id, "accessToken", "refreshToken", "accessTokenExpiresAt",
					"refreshTokenExpiresAt", "clientId", "userId", scopes,
					"createdAt", "updatedAt"
				 ) VALUES ($1, $2, $3, now() + interval '5 minutes',
					now() + interval '1 hour', $4, $5, 'openid offline_access', now(), now())`,
				[randomUUID(), rawAccess, rawRefresh, "legacy-client", userId],
			);

			const options = attachInternalCredentialAuthority(
				{
					secret: "legacy-oidc-bridge-secret-value",
					database: {
						db: database,
						type: "postgres",
						transaction: true,
					},
					plugins: [
						oidcProvider({
							loginPage: "/login",
							__skipDeprecationWarning: true,
						}),
					],
					logger: { level: "error" },
				} satisfies ClearanceOptions,
				{ generation: "legacy-v1" },
			);
			const adapter = kyselyAdapter(database, {
				type: "postgres",
				transaction: true,
			})(options);
			attachInternalCredentialAuthority(adapter, { generation: "legacy-v1" });
			expect(readInternalCredentialAuthority(adapter)).toEqual({
				generation: "legacy-v1",
			});

			await expect(
				findOAuthTokenBySecret(
					adapter,
					"oauthAccessToken",
					"access",
					rawAccess,
				),
			).resolves.toMatchObject({ userId, clientId: "legacy-client" });
			const issued = await createOAuthTokenPair(adapter, "oauthAccessToken", {
				clientId: "legacy-client",
				userId,
				scopes: "openid offline_access",
				accessTokenExpiresAt: new Date(Date.now() + 300_000),
				refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
				issueRefreshToken: true,
			});
			const persisted = await pool.query<{
				accessToken: string;
				refreshToken: string;
			}>(
				`SELECT "accessToken", "refreshToken" FROM "oauthAccessToken" WHERE id = $1`,
				[issued.row.id],
			);
			expect(persisted.rows[0]).toEqual({
				accessToken: issued.accessToken,
				refreshToken: issued.refreshToken,
			});
			const rotated = await rotateOAuthRefreshToken(
				adapter,
				"oauthAccessToken",
				{
					presentedRefreshToken: issued.refreshToken!,
					clientId: "legacy-client",
					accessTokenExpiresAt: new Date(Date.now() + 300_000),
					secretConfig: options.secret!,
				},
			);
			expect(rotated.kind).toBe("rotated");
			const catalog = await pool.query<{ columnName: string }>(`
				SELECT column_name AS "columnName" FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name = 'oauthAccessToken'
				  AND column_name IN (
				    'accessTokenDigest', 'refreshTokenDigest', 'digestVersion',
				    'familyId', 'refreshStatus', 'rotationCounter', 'revokedAt'
				  )
			`);
			expect(catalog.rows).toEqual([]);
			const tokenCount = await pool.query<{ count: string }>(
				`SELECT count(*)::text AS count FROM "oauthAccessToken"`,
			);
			expect(tokenCount.rows[0]?.count).toBe("3");
		} finally {
			await database.destroy().catch(() => undefined);
			await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await admin.end();
		}
	});

	it("serializes code redemption with an administrator ban", async () => {
		const suffix = randomUUID();
		const { auth, customFetchImpl, db, signInWithTestUser } =
			await getTestInstance(
				{
					plugins: [
						admin(),
						oidcProvider({
							loginPage: "/login",
							__skipDeprecationWarning: true,
						}),
					],
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
			name: "OIDC race target",
			email: `oidc-race-${suffix}@example.test`,
			emailVerified: true,
			image: null,
		});
		const clientId = `oidc-race-client-${suffix}`;
		const clientSecret = `oidc-race-secret-${suffix}`;
		const redirectURI = "https://client.example.test/callback";
		await db.create({
			model: "oauthApplication",
			data: {
				id: randomUUID(),
				clientId,
				clientSecret,
				name: "OIDC race client",
				type: "web",
				redirectUrls: redirectURI,
				disabled: false,
				userId: null,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
			forceAllowId: true,
		});
		const code = `oidc-race-code-${suffix}`;
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
							!("banned" in (input.update as Record<string, unknown>))
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
			const redemption = customFetchImpl(
				"http://localhost:3000/api/auth/oauth2/token",
				{
					method: "POST",
					headers: { "content-type": "application/json" },
					body: JSON.stringify({
						grant_type: "authorization_code",
						code,
						redirect_uri: redirectURI,
						client_id: clientId,
						client_secret: clientSecret,
					}),
				},
			);
			await locked;
			let banSettled = false;
			const ban = auth.api
				.banUser({
					headers,
					body: { userId: target.id, banReason: "race proof" },
				})
				.finally(() => {
					banSettled = true;
				});
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(banSettled).toBe(false);
			releaseResolve();
			const [response] = await Promise.all([redemption, ban]);
			expect(response.status).toBe(200);
		} finally {
			releaseResolve();
			transactionSpy.mockRestore();
		}

		await expect(context.internalAdapter.findUserById(target.id)).resolves.toMatchObject(
			{ banned: true },
		);
		const families = await db.findMany<Record<string, unknown>>({
			model: "oauthAccessToken",
			where: [{ field: "userId", value: target.id }],
		});
		expect(families).toHaveLength(1);
		expect(families[0]).toMatchObject({ refreshStatus: "revoked" });
	});

	it("serializes refresh rotation with an administrator ban", async () => {
		const suffix = randomUUID();
		const { auth, db, signInWithTestUser } = await getTestInstance(
			{
				plugins: [
					admin(),
					oidcProvider({
						loginPage: "/login",
						__skipDeprecationWarning: true,
					}),
				],
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
			name: "OIDC refresh race target",
			email: `oidc-refresh-race-${suffix}@example.test`,
			emailVerified: true,
			image: null,
		});
		const clientId = `oidc-refresh-race-client-${suffix}`;
		const now = new Date();
		await db.create({
			model: "oauthApplication",
			data: {
				id: randomUUID(),
				clientId,
				clientSecret: `oidc-refresh-race-secret-${suffix}`,
				name: "OIDC refresh race client",
				type: "web",
				redirectUrls: "https://client.example.test/callback",
				disabled: false,
				userId: null,
				createdAt: now,
				updatedAt: now,
			},
			forceAllowId: true,
		});
		const issued = await createOAuthTokenPair(db, "oauthAccessToken", {
			clientId,
			userId: target.id,
			scopes: "openid offline_access",
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: new Date(Date.now() + 3_600_000),
			issueRefreshToken: true,
		});

		let lockedResolve!: () => void;
		const locked = new Promise<void>((resolve) => {
			lockedResolve = resolve;
		});
		let releaseResolve!: () => void;
		const release = new Promise<void>((resolve) => {
			releaseResolve = resolve;
		});
		const originalTransaction = db.transaction.bind(db);
		const transactionSpy = vi.spyOn(db, "transaction").mockImplementation(
			async (callback) =>
				originalTransaction(async (trx) => {
					const originalUpdate = trx.update;
					trx.update = async <T>(
						input: Parameters<typeof originalUpdate>[0],
					) => {
						const result = await originalUpdate<T>(input);
						if (
							input.model === "user" &&
							!("banned" in (input.update as Record<string, unknown>))
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
			const rotating = rotateOAuthRefreshToken(db, "oauthAccessToken", {
				presentedRefreshToken: issued.refreshToken!,
				clientId,
				accessTokenExpiresAt: new Date(Date.now() + 300_000),
				secretConfig: "oidc-refresh-race-secret",
			});
			await locked;
			let banSettled = false;
			const banning = auth.api
				.banUser({
					headers,
					body: { userId: target.id, banReason: "refresh race proof" },
				})
				.finally(() => {
					banSettled = true;
				});
			await new Promise((resolve) => setTimeout(resolve, 50));
			expect(banSettled).toBe(false);
			releaseResolve();
			await expect(rotating).resolves.toMatchObject({ kind: "rotated" });
			await banning;
		} finally {
			releaseResolve();
			transactionSpy.mockRestore();
		}

		const family = await db.findMany<Record<string, unknown>>({
			model: "oauthAccessToken",
			where: [{ field: "familyId", value: issued.row.familyId! }],
		});
		expect(family).toHaveLength(2);
		expect(family.every((row) => row.refreshStatus === "revoked")).toBe(true);
	});

	it("stores digests, recovers one operation, and revokes competing reuse", async () => {
		const { db, testUser } = await getTestInstance(
			{
				plugins: [
					oidcProvider({
						loginPage: "/login",
						__skipDeprecationWarning: true,
					}),
				],
			},
			{ testWith: "postgres" },
		);
		const user = await db.findOne<{ id: string }>({
			model: "user",
			where: [{ field: "email", value: testUser.email }],
		});
		expect(user).toBeTruthy();

		const clientId = `pg-client-${randomUUID()}`;
		const now = new Date();
		await db.create({
			model: "oauthApplication",
			data: {
				id: randomUUID(),
				clientId,
				clientSecret: "postgres-proof-secret",
				name: "PostgreSQL proof",
				type: "web",
				redirectUrls: "https://client.example.test/callback",
				disabled: false,
				userId: user!.id,
				createdAt: now,
				updatedAt: now,
			},
			forceAllowId: true,
		});

		const absoluteRefreshExpiry = new Date(Date.now() + 60 * 60 * 1000);
		const issued = await createOAuthTokenPair(db, "oauthAccessToken", {
			clientId,
			userId: user!.id,
			scopes: "openid offline_access",
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: absoluteRefreshExpiry,
			issueRefreshToken: true,
		});
		expect(issued.refreshToken).toBeTruthy();
		const stored = await db.findOne<Record<string, unknown>>({
			model: "oauthAccessToken",
			where: [{ field: "id", value: issued.row.id }],
		});
		expect(stored).toMatchObject({ refreshStatus: "active" });
		expect(stored?.accessToken).toMatch(/^clr_oauth_ref_access_/);
		expect(stored?.refreshToken).toMatch(/^clr_oauth_ref_refresh_/);
		expect(stored?.accessTokenDigest).toMatch(/^v1:/);
		expect(stored?.refreshTokenDigest).toMatch(/^v1:/);

		const rotate = () =>
			rotateOAuthRefreshToken(db, "oauthAccessToken", {
				presentedRefreshToken: issued.refreshToken!,
				clientId,
				accessTokenExpiresAt: new Date(Date.now() + 300_000),
				secretConfig: "oidc-postgres-rotation-test-secret",
			});
		const results = await Promise.all([rotate(), rotate()]);
		expect(results.map((result) => result.kind).sort()).toEqual([
			"reused",
			"rotated",
		]);
		const rotated = results.find((result) => result.kind === "rotated");
		expect(rotated?.successor.row.refreshTokenExpiresAt).toEqual(
			absoluteRefreshExpiry,
		);
		expect(issued.row.familyId).toBeTruthy();

		const familyRows = await db.findMany<Record<string, unknown>>({
			model: "oauthAccessToken",
			where: [{ field: "familyId", value: issued.row.familyId! }],
		});
		expect(familyRows).toHaveLength(2);
		expect(
			familyRows.every(
				(row) => row.refreshStatus === "revoked" && row.reuseDetectedAt,
			),
		).toBe(true);
		expect(
			await rotateOAuthRefreshToken(db, "oauthAccessToken", {
				presentedRefreshToken: rotated!.successor.refreshToken!,
				clientId,
				accessTokenExpiresAt: new Date(Date.now() + 300_000),
				secretConfig: "oidc-postgres-rotation-test-secret",
			}),
		).toEqual({ kind: "invalid" });

		const retryable = await createOAuthTokenPair(db, "oauthAccessToken", {
			clientId,
			userId: user!.id,
			scopes: "openid offline_access",
			accessTokenExpiresAt: new Date(Date.now() + 300_000),
			refreshTokenExpiresAt: absoluteRefreshExpiry,
			issueRefreshToken: true,
		});
		const retryOperation = generateCredentialOperationKey();
		const retries = await Promise.all(
			Array.from({ length: 16 }, () =>
				rotateOAuthRefreshToken(db, "oauthAccessToken", {
					presentedRefreshToken: retryable.refreshToken!,
					clientId,
					accessTokenExpiresAt: new Date(Date.now() + 300_000),
					secretConfig: "oidc-postgres-rotation-test-secret",
					idempotencyKey: retryOperation,
				}),
			),
		);
		expect(retries.every((result) => result.kind === "rotated")).toBe(true);
		const recovered = retries.filter((result) => result.kind === "rotated");
		expect(
			new Set(recovered.map((result) => result.successor.accessToken)).size,
		).toBe(1);
		expect(
			new Set(recovered.map((result) => result.successor.refreshToken)).size,
		).toBe(1);
		const retryFamily = await db.findMany<Record<string, unknown>>({
			model: "oauthAccessToken",
			where: [{ field: "familyId", value: retryable.row.familyId! }],
		});
		expect(retryFamily).toHaveLength(2);
		expect(retryFamily.map((row) => row.refreshStatus).sort()).toEqual([
			"active",
			"consumed",
		]);
	});
});
