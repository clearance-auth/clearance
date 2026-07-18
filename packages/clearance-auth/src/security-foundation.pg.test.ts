import { createHash, createHmac, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mcp } from "../../runtime/src/plugins/mcp/index.js";
import { oidcProvider } from "../../runtime/src/plugins/oidc-provider/index.js";
import {
	createClearanceAuth,
	decryptRuntimeCredential,
	encryptRuntimeCredential,
	type ClearanceAuthBundle,
} from "./create-auth.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const admin = new pg.Pool({
	connectionString: DATABASE_URL,
	connectionTimeoutMillis: 500,
});
let available = false;
try {
	await admin.query("SELECT 1");
	available = true;
} catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
		throw new Error(
			`Authentication security tests require Postgres at ${DATABASE_URL}`,
		);
	}
} finally {
	await admin.end();
}

type TwoFactorRow = {
	id: string;
	secret: string;
	backupCodes: string;
	verified: boolean;
};

type JwksRow = {
	id: string;
	publicKey: string;
	privateKey: string;
	alg: string | null;
	crv: string | null;
};

function totp(
	secret: string,
	counter = Math.floor(Date.now() / 30_000),
): string {
	const message = Buffer.alloc(8);
	message.writeBigUInt64BE(BigInt(counter));
	const digest = createHmac("sha1", secret).update(message).digest();
	const offset = digest[digest.length - 1]! & 0x0f;
	const value =
		(((digest[offset]! & 0x7f) << 24) |
			((digest[offset + 1]! & 0xff) << 16) |
			((digest[offset + 2]! & 0xff) << 8) |
			(digest[offset + 3]! & 0xff)) %
		1_000_000;
	return value.toString().padStart(6, "0");
}

function decodeJwtPart<T>(token: string, index: number): T {
	const part = token.split(".")[index];
	if (!part) throw new Error(`JWT part ${index} is missing`);
	return JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as T;
}

function signedSessionHeaders(token: string, secret: string): Headers {
	const signedToken = encodeURIComponent(
		`${token}.${createHmac("sha256", secret).update(token).digest("base64")}`,
	);
	return new Headers({
		cookie: `clearance.session_token=${signedToken}`,
	});
}

function signedLegacyIdToken(
	payload: { sub: string; iss: string; aud: string },
	secret: string,
): string {
	const now = Math.floor(Date.now() / 1_000);
	const header = Buffer.from(
		JSON.stringify({ alg: "HS256", typ: "JWT" }),
	).toString("base64url");
	const body = Buffer.from(
		JSON.stringify({ ...payload, iat: now, exp: now + 300 }),
	).toString("base64url");
	const signingInput = `${header}.${body}`;
	return `${signingInput}.${createHmac("sha256", secret)
		.update(signingInput)
		.digest("base64url")}`;
}

function sessionCredentialDigest(token: string): string {
	return `v1:${createHash("sha256")
		.update(`clearance:session-refresh:v1:${token}`)
		.digest("base64url")}`;
}

function credentialOperationKey(label: string): string {
	return `clr_op_v1_${createHash("sha256").update(label).digest("base64url")}`;
}

async function insertDigestSession(
	pool: pg.Pool,
	input: {
		userId: string;
		twoFactorSessionGeneration?: string | undefined;
	},
): Promise<string> {
	const sessionId = randomUUID();
	const credentialId = randomUUID();
	const token = `clr_rt_${credentialId}~${randomUUID().replaceAll("-", "")}`;
	const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		await client.query(
			`INSERT INTO session
			 (id, token, "userId", "expiresAt", "createdAt", "updatedAt",
			  "twoFactorSessionGeneration")
			 VALUES ($1, 'clr_sid_' || $1, $2, $3, now(), now(), $4)`,
			[
				sessionId,
				input.userId,
				expiresAt,
				input.twoFactorSessionGeneration ?? null,
			],
		);
		await client.query(
			`INSERT INTO "sessionCredential" (
			 id, selector, "sessionId", "familyId", "secretDigest",
			 "digestVersion", status, "rotationCounter", "expiresAt",
			 "createdAt", "updatedAt"
			) VALUES ($1,$1,$2,$3,$4,1,'active',0,$5,now(),now())`,
			[
				credentialId,
				sessionId,
				randomUUID(),
				sessionCredentialDigest(token),
				expiresAt,
			],
		);
		await client.query("COMMIT");
		return token;
	} catch (error) {
		await client.query("ROLLBACK").catch(() => {});
		throw error;
	} finally {
		client.release();
	}
}

describe.sequential.skipIf(!available)(
	"authentication security foundation on migrated Postgres",
	() => {
		const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
		const schema = `auth_security_${suffix}`;
		const baseURL = "http://localhost:3300/api/auth";
		const secret = "authentication-security-product-proof-secret!!";
		const password = "correct-horse-battery-staple";
		const basePool = new pg.Pool({ connectionString: DATABASE_URL });
		let bundle: ClearanceAuthBundle;
		let peerBundle: ClearanceAuthBundle;
		let scopedPool: pg.Pool;
		let headers: Headers;
		let scopedDatabaseUrl: string;
		let rotatedToken: string;
		let rotatedKid: string;

		function createBundle(): ClearanceAuthBundle {
			return createClearanceAuth({
				baseURL,
				secret,
				databaseUrl: scopedDatabaseUrl,
				rateLimitEnabled: false,
				enableSso: false,
				enableScim: false,
				authenticationSecurity: {
					twoFactor: { issuer: "Clearance Security Proof" },
					breachedPassword: { enabled: false },
					asymmetricAccessTokens: {
						rotationIntervalSeconds: 300,
						gracePeriodSeconds: 600,
					},
				},
			});
		}

		async function postAuth(
			path: string,
			body: Record<string, unknown>,
			requestHeaders: Headers,
		): Promise<Response> {
			const requestHeadersWithContentType = new Headers(requestHeaders);
			requestHeadersWithContentType.set("content-type", "application/json");
			return bundle.auth.handler(
				new Request(`${baseURL}${path}`, {
					method: "POST",
					headers: requestHeadersWithContentType,
					body: JSON.stringify(body),
				}),
			);
		}

		function sessionHeadersFromResponse(response: Response): Headers {
			const sessionCookie = response.headers
				.getSetCookie()
				.find((entry) => entry.startsWith("clearance.session_token="));
			const pair = sessionCookie?.split(";")[0];
			if (!pair || pair.endsWith("=")) {
				throw new Error("Response did not rotate the authenticated session");
			}
			return new Headers({ cookie: pair });
		}

		beforeAll(async () => {
			await basePool.query(`CREATE SCHEMA "${schema}"`);
			const url = new URL(DATABASE_URL);
			url.searchParams.set("options", `-csearch_path=${schema}`);
			scopedDatabaseUrl = url.toString();
			scopedPool = new pg.Pool({ connectionString: scopedDatabaseUrl });
			bundle = createBundle();
			await bundle.migrate();
			peerBundle = createBundle();

			const signup = await bundle.auth.api.signUpEmail({
				body: {
					email: `security-${suffix}@example.test`,
					password,
					name: "Security Proof",
				},
			});
			headers = signedSessionHeaders(signup.token, secret);
			headers.set(
				"idempotency-key",
				credentialOperationKey(
					"security-foundation-jwt-refresh-operation-0001",
				),
			);
		});

		afterAll(async () => {
			await peerBundle?.destroy();
			await bundle?.destroy();
			await scopedPool?.end();
			await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await basePool.end();
		});

		it("encrypts recovery material and activates TOTP only after verification", async () => {
			const signup = await bundle.auth.api.signUpEmail({
				body: {
					email: `totp-${suffix}@example.test`,
					password,
					name: "TOTP Proof",
				},
			});
			const twoFactorHeaders = signedSessionHeaders(signup.token, secret);
			const enrollment = await bundle.auth.api.enableTwoFactor({
				body: { password },
				headers: twoFactorHeaders,
			});
			expect(enrollment.totpURI).toContain("issuer=Clearance+Security+Proof");
			expect(enrollment.backupCodes).toHaveLength(10);

			const result = await scopedPool.query<TwoFactorRow>(
				`SELECT id, secret, "backupCodes", verified FROM "twoFactor"`,
			);
			const uniqueIndex = await scopedPool.query<{ indexdef: string }>(
				`SELECT indexdef FROM pg_indexes
				 WHERE schemaname=current_schema() AND tablename='twoFactor'
				   AND indexdef ILIKE '%UNIQUE%'
				   AND indexdef ILIKE '%("userId")%'`,
			);
			expect(uniqueIndex.rows).toHaveLength(1);
			expect(result.rows).toHaveLength(1);
			const row = result.rows[0]!;
			const rawSecret = await decryptRuntimeCredential(row.secret, secret);
			expect(row.verified).toBe(false);
			expect(row.secret).not.toContain(rawSecret);
			expect(row.backupCodes).toMatch(/^clr-recovery:v1:/);
			for (const code of enrollment.backupCodes) {
				expect(row.backupCodes).not.toContain(code);
			}

			const verified = await bundle.auth.api.verifyTOTP({
				body: { code: totp(rawSecret) },
				headers: twoFactorHeaders,
			});
			expect(verified.token).toBeTruthy();
			expect(
				(
					await scopedPool.query<{ verified: boolean }>(
						`SELECT verified FROM "twoFactor" WHERE id=$1`,
						[row.id],
					)
				).rows[0]?.verified,
			).toBe(true);

			const legacyEncryptedRecovery = await encryptRuntimeCredential(
				JSON.stringify(enrollment.backupCodes),
				secret,
			);
			await scopedPool.query(
				`UPDATE "twoFactor" SET "backupCodes"=$2 WHERE id=$1`,
				[row.id, legacyEncryptedRecovery],
			);
			await bundle.migrate();
			const migratedRecovery = (
				await scopedPool.query<{ backupCodes: string }>(
					`SELECT "backupCodes" FROM "twoFactor" WHERE id=$1`,
					[row.id],
				)
			).rows[0]!.backupCodes;
			expect(migratedRecovery).toMatch(/^clr-recovery:v1:/);
			for (const code of enrollment.backupCodes) {
				expect(migratedRecovery).not.toContain(code);
			}
		});

		it("enforces one-way recovery step-up with one race winner and lifecycle revocation", async () => {
			const email = `recovery-${suffix}@example.test`;
			const signup = await bundle.auth.api.signUpEmail({
				body: { email, password, name: "Recovery Proof" },
			});
			const originalHeaders = signedSessionHeaders(signup.token, secret);
			const additionalSession = await bundle.auth.api.signInEmail({
				body: { email, password },
			});
			const user = (
				await scopedPool.query<{ id: string }>(
					`SELECT id FROM "user" WHERE email=$1`,
					[email],
				)
			).rows[0]!;
			const enrollment = await bundle.auth.api.enableTwoFactor({
				body: { password },
				headers: originalHeaders,
			});
			const factor = (
				await scopedPool.query<
					TwoFactorRow & { trustDeviceGeneration: string }
				>(
					`SELECT id, secret, "backupCodes", verified, "trustDeviceGeneration"
					 FROM "twoFactor" WHERE "userId"=$1`,
					[user.id],
				)
			).rows[0]!;
			const rawSecret = await decryptRuntimeCredential(factor.secret, secret);
			const activated = await bundle.auth.api.verifyTOTP({
				body: { code: totp(rawSecret) },
				headers: originalHeaders,
			});
			const activeHeaders = signedSessionHeaders(activated.token, secret);
			const preRotationSessionGeneration = (
				await scopedPool.query<{ twoFactorSessionGeneration: string }>(
					`SELECT "twoFactorSessionGeneration" FROM "user" WHERE id=$1`,
					[user.id],
				)
			).rows[0]!.twoFactorSessionGeneration;
			const sessionsAfterActivation = await scopedPool.query<{
				id: string;
				token: string | null;
			}>(`SELECT id, token FROM session WHERE "userId"=$1`, [user.id]);
			expect(sessionsAfterActivation.rows).toHaveLength(1);
			expect(sessionsAfterActivation.rows[0]?.token).toBe(
				`clr_sid_${sessionsAfterActivation.rows[0]?.id}`,
			);
			const activeCredential = (
				await scopedPool.query<{
					secretDigest: string;
					status: string;
				}>(
					`SELECT "secretDigest", status FROM "sessionCredential"
					 WHERE "sessionId"=$1`,
					[sessionsAfterActivation.rows[0]!.id],
				)
			).rows[0]!;
			expect(activeCredential).toEqual({
				secretDigest: sessionCredentialDigest(activated.token),
				status: "active",
			});
			expect(activeCredential.secretDigest).not.toContain(activated.token);
			expect(activeCredential.secretDigest).not.toContain(
				additionalSession.token,
			);

			const passwordOnly = await postAuth(
				"/two-factor/generate-backup-codes",
				{ password },
				activeHeaders,
			);
			expect(passwordOnly.status).toBe(400);

			const staleSessionToken = await insertDigestSession(scopedPool, {
				userId: user.id,
			});
			const trustIdentifier = `trust-device-${randomUUID()}`;
			const activeTrustGeneration = (
				await scopedPool.query<{ trustDeviceGeneration: string }>(
					`SELECT "trustDeviceGeneration" FROM "twoFactor" WHERE id=$1`,
					[factor.id],
				)
			).rows[0]!.trustDeviceGeneration;
			await scopedPool.query(
				`INSERT INTO verification
				 (id, identifier, value, "expiresAt", "createdAt", "updatedAt")
				 VALUES ($1, $2, $3, now()+interval '1 day', now(), now())`,
				[randomUUID(), trustIdentifier, `${user.id}!${activeTrustGeneration}`],
			);

			const recoveryCode = enrollment.backupCodes[0]!;
			const racers = await Promise.all([
				postAuth(
					"/two-factor/generate-backup-codes",
					{ password, recoveryCode },
					activeHeaders,
				),
				postAuth(
					"/two-factor/generate-backup-codes",
					{ password, recoveryCode },
					activeHeaders,
				),
			]);
			const winner = racers.find((response) => response.status === 200);
			const loser = racers.find((response) => response.status !== 200);
			expect(winner).toBeDefined();
			expect(loser?.status === 401 || loser?.status === 409).toBe(true);
			const rotatedHeaders = sessionHeadersFromResponse(winner!);
			const generated = (await winner!.json()) as {
				status: true;
				backupCodes: string[];
			};
			expect(generated.backupCodes).toHaveLength(10);
			const sessionsAfterRegeneration = await scopedPool.query<{
				id: string;
				token: string | null;
			}>(`SELECT id, token FROM session WHERE "userId"=$1`, [user.id]);
			expect(sessionsAfterRegeneration.rows).toHaveLength(1);
			expect(sessionsAfterRegeneration.rows[0]?.token).toBe(
				`clr_sid_${sessionsAfterRegeneration.rows[0]?.id}`,
			);
			expect(
				await scopedPool.query(
					`SELECT id FROM "sessionCredential"
					 WHERE "secretDigest" IN ($1,$2) AND status='active'`,
					[
						sessionCredentialDigest(activated.token),
						sessionCredentialDigest(staleSessionToken),
					],
				),
			).toMatchObject({ rowCount: 0 });
			const lateStaleToken = await insertDigestSession(scopedPool, {
				userId: user.id,
				twoFactorSessionGeneration: preRotationSessionGeneration,
			});
			expect(
				await bundle.auth.api.getSession({
					headers: signedSessionHeaders(lateStaleToken, secret),
				}),
			).toBeNull();
			expect(
				(
					await scopedPool.query<{ count: number }>(
						`SELECT count(*)::int count FROM verification WHERE identifier=$1`,
						[trustIdentifier],
					)
				).rows[0]?.count,
			).toBe(0);

			const replay = await postAuth(
				"/two-factor/generate-backup-codes",
				{ password, recoveryCode },
				rotatedHeaders,
			);
			expect(replay.status).toBe(401);
			const failedVerificationCount = (
				await scopedPool.query<{ failedVerificationCount: number }>(
					`SELECT "failedVerificationCount" FROM "twoFactor" WHERE id=$1`,
					[factor.id],
				)
			).rows[0]!.failedVerificationCount;
			expect(failedVerificationCount).toBeGreaterThanOrEqual(1);
			expect(failedVerificationCount).toBeLessThanOrEqual(2);

			const disabled = await postAuth(
				"/two-factor/disable",
				{ password, recoveryCode: generated.backupCodes[0] },
				rotatedHeaders,
			);
			expect(disabled.status).toBe(200);
			const disabledHeaders = sessionHeadersFromResponse(disabled);
			expect(
				await bundle.auth.api.getSession({ headers: disabledHeaders }),
			).not.toBeNull();
			expect(
				(
					await scopedPool.query<{ count: number }>(
						`SELECT count(*)::int count FROM "twoFactor" WHERE "userId"=$1`,
						[user.id],
					)
				).rows[0]?.count,
			).toBe(0);
			expect(
				(
					await scopedPool.query<{ twoFactorEnabled: boolean }>(
						`SELECT "twoFactorEnabled" FROM "user" WHERE id=$1`,
						[user.id],
					)
				).rows[0]?.twoFactorEnabled,
			).toBe(false);
		});

		it("rotates encrypted Ed25519 signing keys with overlap and public-only JWKS", async () => {
			const first = await bundle.auth.api.getToken({ headers });
			const firstHeader = decodeJwtPart<{ alg: string; kid: string }>(
				first.token,
				0,
			);
			const firstPayload = decodeJwtPart<{
				iss: string;
				aud: string;
				iat: number;
				exp: number;
			}>(first.token, 1);
			expect(firstHeader).toMatchObject({ alg: "EdDSA" });
			expect(firstHeader.kid).toBeTruthy();
			expect(firstPayload).toMatchObject({ iss: baseURL, aud: baseURL });
			expect(firstPayload.exp - firstPayload.iat).toBe(300);

			const firstRow = (
				await scopedPool.query<JwksRow>(
					`SELECT id, "publicKey", "privateKey", alg, crv FROM jwks WHERE id=$1`,
					[firstHeader.kid],
				)
			).rows[0]!;
			expect(firstRow).toMatchObject({ alg: "EdDSA", crv: "Ed25519" });
			expect(firstRow.privateKey).not.toContain('"d"');
			expect(firstRow.publicKey).not.toContain('"d"');

			await scopedPool.query(
				`UPDATE jwks SET "expiresAt"=now()-interval '1 second' WHERE id=$1`,
				[firstHeader.kid],
			);
			const concurrent = await Promise.all(
				Array.from({ length: 8 }, (_, index) =>
					(index % 2 === 0 ? bundle : peerBundle).auth.api.getToken({
						headers,
					}),
				),
			);
			const secondHeaders = concurrent.map((entry) =>
				decodeJwtPart<{ alg: string; kid: string }>(entry.token, 0),
			);
			const secondHeader = secondHeaders[0]!;
			rotatedToken = concurrent[0]!.token;
			rotatedKid = secondHeader.kid;
			expect(secondHeader).toMatchObject({ alg: "EdDSA" });
			expect(secondHeader.kid).not.toBe(firstHeader.kid);
			expect(new Set(secondHeaders.map((entry) => entry.kid)).size).toBe(1);
			expect(
				(
					await scopedPool.query<{ count: number }>(
						"SELECT count(*)::int count FROM jwks",
					)
				).rows[0]?.count,
			).toBe(2);

			const oldToken = await bundle.auth.api.verifyJWT({
				body: { token: first.token },
			});
			expect(oldToken.payload?.iss).toBe(baseURL);
			const publicSet = await bundle.auth.api.getJwks();
			expect(publicSet.keys.map((key) => key.kid).sort()).toEqual(
				[firstHeader.kid, secondHeader.kid].sort(),
			);
			expect(JSON.stringify(publicSet)).not.toContain('"d"');
			expect(JSON.stringify(publicSet)).not.toContain("privateKey");
		});

		it("retires legacy keys on upgrade and fails closed on unknown metadata", async () => {
			const unknownId = randomUUID();
			const legacyRsaId = randomUUID();
			await scopedPool.query(
				`INSERT INTO jwks
				 (id, "publicKey", "privateKey", "createdAt", "expiresAt", alg, crv)
				 VALUES ($1, '{}', 'unusable-private-key', now(), now()+interval '1 day', NULL, NULL)`,
				[unknownId],
			);
			await scopedPool.query(
				`INSERT INTO jwks
				 (id, "publicKey", "privateKey", "createdAt", "expiresAt", alg, crv)
				 VALUES ($1, $2, 'unusable-private-key', now(), now()+interval '1 day', 'RS256', NULL)`,
				[
					legacyRsaId,
					JSON.stringify({ kty: "RSA", n: "legacy-modulus", e: "AQAB" }),
				],
			);
			await scopedPool.query(
				`UPDATE jwks SET "expiresAt"=NULL, alg=NULL, crv=NULL WHERE id=$1`,
				[rotatedKid],
			);

			await bundle.migrate();
			const upgraded = (
				await scopedPool.query<JwksRow & { expiresAt: Date }>(
					`SELECT id, "publicKey", "privateKey", "expiresAt", alg, crv
					 FROM jwks WHERE id=$1`,
					[rotatedKid],
				)
			).rows[0]!;
			expect(upgraded).toMatchObject({ alg: "EdDSA", crv: "Ed25519" });
			expect(upgraded.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
			const unknown = (
				await scopedPool.query<{ expiresAt: Date; alg: string | null }>(
					`SELECT "expiresAt", alg FROM jwks WHERE id=$1`,
					[unknownId],
				)
			).rows[0]!;
			expect(unknown.alg).toBeNull();
			expect(unknown.expiresAt.getTime()).toBeLessThan(Date.now() - 600 * 1000);
			const legacyRsa = (
				await scopedPool.query<{ expiresAt: Date; alg: string }>(
					`SELECT "expiresAt", alg FROM jwks WHERE id=$1`,
					[legacyRsaId],
				)
			).rows[0]!;
			expect(legacyRsa.alg).toBe("RS256");
			expect(legacyRsa.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
			const retiredBeyondGrace = new Date(Date.now() - 700 * 1000);
			await scopedPool.query(`UPDATE jwks SET "expiresAt"=$2 WHERE id=$1`, [
				legacyRsaId,
				retiredBeyondGrace,
			]);
			await bundle.migrate();
			const retirementAfterSecondMigration = (
				await scopedPool.query<{ expiresAt: Date }>(
					`SELECT "expiresAt" FROM jwks WHERE id=$1`,
					[legacyRsaId],
				)
			).rows[0]!.expiresAt;
			expect(retirementAfterSecondMigration.getTime()).toBe(
				retiredBeyondGrace.getTime(),
			);

			const replacement = await bundle.auth.api.getToken({ headers });
			const replacementHeader = decodeJwtPart<{ kid: string }>(
				replacement.token,
				0,
			);
			expect(replacementHeader.kid).not.toBe(rotatedKid);
			expect(replacementHeader.kid).not.toBe(legacyRsaId);
			expect(
				(await bundle.auth.api.verifyJWT({ body: { token: rotatedToken } }))
					.payload,
			).not.toBeNull();
			const publicSet = await bundle.auth.api.getJwks();
			expect(publicSet.keys.some((key) => key.kid === unknownId)).toBe(false);
			expect(publicSet.keys.some((key) => key.kid === legacyRsaId)).toBe(false);
		});
	},
);

describe.sequential.skipIf(!available)(
	"purpose-separated credential migration on Postgres",
	() => {
		it("re-encrypts legacy OIDC, SCIM, and JWT material under exact resource authority", async () => {
			const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
			const schema = `key_migration_${suffix}`;
			const secret = "purpose-separated-migration-proof-secret!!";
			const basePool = new pg.Pool({ connectionString: DATABASE_URL });
			let bundle: ClearanceAuthBundle | undefined;
			let scopedPool: pg.Pool | undefined;
			try {
				await basePool.query(`CREATE SCHEMA "${schema}"`);
				const url = new URL(DATABASE_URL);
				url.searchParams.set("options", `-csearch_path=${schema}`);
				const databaseUrl = url.toString();
				scopedPool = new pg.Pool({ connectionString: databaseUrl });
				bundle = createClearanceAuth({
					baseURL: "http://localhost:3300/api/auth",
					secret,
					databaseUrl,
					rateLimitEnabled: false,
					authenticationSecurity: {
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: {
							rotationIntervalSeconds: 300,
							gracePeriodSeconds: 600,
						},
					},
				});
				await bundle.migrate();
				// Recreate the pre-Unit-5B write boundary so legacy rows can be staged.
				await scopedPool.query(`
					DROP TRIGGER clearance_require_oidc_key_v1 ON "ssoProvider";
					DROP TRIGGER clearance_require_scim_key_v1 ON "scimProvider";
					DROP TRIGGER clearance_require_jwt_key_v1 ON jwks;
				`);
				const signup = await bundle.auth.api.signUpEmail({
					body: {
						email: `key-migration-${suffix}@example.test`,
						password: "correct-horse-battery-staple",
						name: "Key Migration Proof",
					},
				});

				const oidcProviderId = `oidc-${suffix}`;
				const scimProviderId = `scim-${suffix}`;
				const organizationId = `org-${suffix}`;
				const publicKey = JSON.stringify({
					kty: "OKP",
					crv: "Ed25519",
					x: Buffer.alloc(32, 7).toString("base64url"),
				});
				const privateKey = JSON.stringify({
					kty: "OKP",
					crv: "Ed25519",
					x: Buffer.alloc(32, 7).toString("base64url"),
					d: Buffer.alloc(32, 8).toString("base64url"),
				});
				const legacyOidc = await encryptRuntimeCredential("oidc-secret", secret);
				const legacyScim = await encryptRuntimeCredential("scim-base", secret);
				const legacyJwk = JSON.stringify(
					await encryptRuntimeCredential(privateKey, secret),
				);
				const legacyOidcConfig = JSON.stringify({
					clientId: "client",
					clientSecret: `clr-sso:v1:${legacyOidc}`,
				});
				await scopedPool.query(
					`INSERT INTO "ssoProvider"
					 (id, issuer, "oidcConfig", "samlConfig", "userId", "providerId", "organizationId", domain)
					 VALUES ($1,$2,$3,NULL,$4,$5,NULL,$6)`,
					[
						`row-${oidcProviderId}`,
						"https://issuer.example.test",
						legacyOidcConfig,
						signup.user.id,
						oidcProviderId,
						"example.test",
					],
				);
				await scopedPool.query(
					`INSERT INTO "scimProvider" (id, "providerId", "scimToken", "organizationId")
					 VALUES ($1,$2,$3,$4)`,
					[`row-${scimProviderId}`, scimProviderId, legacyScim, organizationId],
				);
				await scopedPool.query(
					`INSERT INTO jwks
					 (id, "publicKey", "privateKey", "createdAt", "expiresAt", alg, crv)
					 VALUES ($1,$2,$3,now(),now() + interval '1 hour','EdDSA','Ed25519')`,
					[`jwk-${suffix}`, publicKey, "invalid-legacy-private-key"],
				);

				await expect(bundle.migrate()).rejects.toThrow(
					`Cannot migrate invalid JWT private-key storage for key jwk-${suffix}`,
				);
				const rolledBack = (
					await scopedPool.query<{
						oidcConfig: string;
						scimToken: string;
						privateKey: string;
					}>(
						`SELECT sso."oidcConfig", scim."scimToken", jwks."privateKey"
						 FROM "ssoProvider" sso, "scimProvider" scim, jwks
						 WHERE sso."providerId"=$1 AND scim."providerId"=$2 AND jwks.id=$3`,
						[oidcProviderId, scimProviderId, `jwk-${suffix}`],
					)
				).rows[0]!;
				expect(rolledBack).toEqual({
					oidcConfig: legacyOidcConfig,
					scimToken: legacyScim,
					privateKey: "invalid-legacy-private-key",
				});
				await scopedPool.query(`UPDATE jwks SET "privateKey"=$2 WHERE id=$1`, [
					`jwk-${suffix}`,
					legacyJwk,
				]);
				await bundle.migrate();

				const oidc = (
					await scopedPool.query<{ oidcConfig: string }>(
						`SELECT "oidcConfig" FROM "ssoProvider" WHERE "providerId"=$1`,
						[oidcProviderId],
					)
				).rows[0]!;
				const scim = (
					await scopedPool.query<{ scimToken: string }>(
						`SELECT "scimToken" FROM "scimProvider" WHERE "providerId"=$1`,
						[scimProviderId],
					)
				).rows[0]!;
				const jwk = (
					await scopedPool.query<{ privateKey: string }>(
						`SELECT "privateKey" FROM jwks WHERE id=$1`,
						[`jwk-${suffix}`],
					)
				).rows[0]!;
				const oidcStored = (
					JSON.parse(oidc.oidcConfig) as { clientSecret: string }
				).clientSecret.slice("clr-sso:v1:".length);
				const scimStored = scim.scimToken.slice("clr-scim:v1:".length);
				expect(oidcStored).toMatch(/^clrkm\$v1\$/);
				expect(scimStored).toMatch(/^clrkm\$v1\$/);
				expect(jwk.privateKey).toMatch(/^clrkm\$v1\$/);
				expect(
					await bundle.keyManagement.openText(
						"oidc-client-secret",
						bundle.keyManagement.resourceId("oidc-client-secret", {
							providerId: oidcProviderId,
						}),
						oidcStored,
					),
				).toBe("oidc-secret");
				expect(
					await bundle.keyManagement.openText(
						"scim-bearer-token",
						bundle.keyManagement.resourceId("scim-bearer-token", {
							providerId: scimProviderId,
							organizationId,
						}),
						scimStored,
					),
				).toBe("scim-base");
				expect(
					await bundle.keyManagement.openText(
						"access-token-signing-key",
						bundle.keyManagement.resourceId("access-token-signing-key", {
							publicKey,
						}),
						jwk.privateKey,
					),
				).toBe(privateKey);
				await expect(
					bundle.keyManagement.openText(
						"scim-bearer-token",
						bundle.keyManagement.resourceId("scim-bearer-token", {
							providerId: scimProviderId,
							organizationId: "wrong-organization",
						}),
						scimStored,
					),
				).rejects.toThrow();
				await expect(
					scopedPool.query(
						`UPDATE "ssoProvider" SET "oidcConfig"=$2 WHERE "providerId"=$1`,
						[oidcProviderId, legacyOidcConfig],
					),
				).rejects.toMatchObject({ code: "23514" });
				await expect(
					scopedPool.query(
						`UPDATE "scimProvider" SET "scimToken"=$2 WHERE "providerId"=$1`,
						[scimProviderId, legacyScim],
					),
				).rejects.toMatchObject({ code: "23514" });
				await expect(
					scopedPool.query(`UPDATE jwks SET "privateKey"=$2 WHERE id=$1`, [
						`jwk-${suffix}`,
						legacyJwk,
					]),
				).rejects.toMatchObject({ code: "23514" });

				await bundle.migrate();
				const repeated = (
					await scopedPool.query<{
						oidcConfig: string;
						scimToken: string;
						privateKey: string;
					}>(
						`SELECT sso."oidcConfig", scim."scimToken", jwks."privateKey"
						 FROM "ssoProvider" sso, "scimProvider" scim, jwks
						 WHERE sso."providerId"=$1 AND scim."providerId"=$2 AND jwks.id=$3`,
						[oidcProviderId, scimProviderId, `jwk-${suffix}`],
					)
				).rows[0]!;
				expect(repeated).toEqual({
					oidcConfig: oidc.oidcConfig,
					scimToken: scim.scimToken,
					privateKey: jwk.privateKey,
				});
			} finally {
				await bundle?.destroy();
				await scopedPool?.end();
				await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await basePool.end();
			}
		});
	},
);

describe.sequential.skipIf(!available)(
	"authentication security schema upgrade",
	() => {
		it("rolls back signup when the durable identity bridge fails once", async () => {
			const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
			const schema = `auth_identity_bridge_${suffix}`;
			const email = `identity-rollback-${suffix}@example.test`;
			const basePool = new pg.Pool({ connectionString: DATABASE_URL });
			let bundle: ClearanceAuthBundle | undefined;
			let scopedPool: pg.Pool | undefined;
			let bridgeCalls = 0;
			try {
				await basePool.query(`CREATE SCHEMA "${schema}"`);
				const url = new URL(DATABASE_URL);
				url.searchParams.set("options", `-csearch_path=${schema}`);
				const databaseUrl = url.toString();
				scopedPool = new pg.Pool({ connectionString: databaseUrl });
				bundle = createClearanceAuth({
					baseURL: "http://localhost:3300/api/auth",
					secret: "identity-bridge-rollback-proof-secret!!",
					databaseUrl,
					rateLimitEnabled: false,
					enableSso: false,
					enableScim: false,
					authenticationSecurity: {
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: { enabled: false },
					},
					onUserCreated: async () => {
						bridgeCalls += 1;
						throw new Error("management identity sync failed");
					},
				});
				await bundle.migrate();

				await expect(
					bundle.auth.api.signUpEmail({
						body: {
							email,
							password: "correct-horse-battery-staple",
							name: "Identity Rollback",
						},
					}),
				).rejects.toThrow("management identity sync failed");
				expect(bridgeCalls).toBe(1);
				const persisted = await scopedPool.query<{ count: number }>(
					`SELECT count(*)::int AS count FROM "user" WHERE email = $1`,
					[email],
				);
				expect(persisted.rows[0]?.count).toBe(0);
			} finally {
				await bundle?.destroy();
				await scopedPool?.end();
				await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await basePool.end();
			}
		});

		it("installs and validates the durable PostgreSQL credential writer fence", async () => {
			const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
			const schema = `auth_drain_fence_${suffix}`;
			const basePool = new pg.Pool({ connectionString: DATABASE_URL });
			let bundle: ClearanceAuthBundle | undefined;
			let scopedPool: pg.Pool | undefined;
			try {
				await basePool.query(`CREATE SCHEMA "${schema}"`);
				const url = new URL(DATABASE_URL);
				url.searchParams.set("options", `-csearch_path=${schema}`);
				const databaseUrl = url.toString();
				scopedPool = new pg.Pool({ connectionString: databaseUrl });
				const now = new Date();
				await scopedPool.query(`
					CREATE TABLE "user" (
						id text PRIMARY KEY,
						name text NOT NULL,
						email text NOT NULL UNIQUE,
						"emailVerified" boolean NOT NULL,
						image text,
						"createdAt" timestamptz NOT NULL,
						"updatedAt" timestamptz NOT NULL
					);
					CREATE TABLE session (
						id text PRIMARY KEY,
						"expiresAt" timestamptz NOT NULL,
						"createdAt" timestamptz NOT NULL,
						"updatedAt" timestamptz NOT NULL,
						"userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
						token text NOT NULL UNIQUE
					)
				`);
				await scopedPool.query(
					`INSERT INTO "user" (
						id, name, email, "emailVerified", "createdAt", "updatedAt"
					) VALUES ('drain-user', 'Drain User', 'drain@example.test', true, $1, $1)`,
					[now],
				);
				await scopedPool.query(
					`INSERT INTO session (
						id, "expiresAt", "createdAt", "updatedAt", "userId", token
					) VALUES ('drain-session', $1, $2, $2, 'drain-user', 'legacy-drain-bearer')`,
					[new Date(now.getTime() + 3_600_000), now],
				);

				bundle = createClearanceAuth({
					baseURL: "http://localhost:3300/api/auth",
					secret: "bundle-migrate-drain-fence-proof-secret!!",
					databaseUrl,
					enableSso: false,
					enableScim: false,
					authenticationSecurity: {
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: { enabled: false },
					},
				});
				const directPlan = await bundle.planMigrations();
				expect(directPlan.pendingSecurityMigrations).toContain(
					"session-credential-digests-v1",
				);
				await expect(directPlan.apply()).rejects.toThrow(
					"reserved for createClearanceAuth(...).migrate()",
				);
				expect(
					await scopedPool.query(
						`SELECT to_regclass(format('%I.%I', current_schema(), 'sessionCredential')) AS table`,
					),
				).toMatchObject({ rows: [{ table: null }] });
				await bundle.migrate();

				const fence = await basePool.query<{
					kind: string;
					validated: boolean;
				}>(
					`SELECT constraint_record.contype AS kind,
					        constraint_record.convalidated AS validated
					 FROM pg_constraint constraint_record
					 JOIN pg_class table_record
					   ON table_record.oid = constraint_record.conrelid
					 JOIN pg_namespace namespace_record
					   ON namespace_record.oid = table_record.relnamespace
					 WHERE namespace_record.nspname = $1
					   AND table_record.relname = 'session'
					   AND constraint_record.conname = 'clearance_session_credential_authority_v1'`,
					[schema],
				);
				expect(fence.rows).toEqual([{ kind: "c", validated: true }]);
				const migrated = await scopedPool.query<{
					token: string;
					credentialCount: number;
				}>(
					`SELECT session.token,
					        count(credential.id)::int AS "credentialCount"
					 FROM session
					 JOIN "sessionCredential" credential
					   ON credential."sessionId" = session.id
					 WHERE session.id = 'drain-session'
					 GROUP BY session.token`,
				);
				expect(migrated.rows[0]).toEqual({
					token: "clr_sid_drain-session",
					credentialCount: 1,
				});
				await expect(
					scopedPool.query(
						`INSERT INTO session (
							id, "expiresAt", "createdAt", "updatedAt", "userId", token
						 ) VALUES (
							'legacy-writer-after-fence', $1, $2, $2,
							'drain-user', 'legacy-writer-bearer'
						 )`,
						[new Date(now.getTime() + 3_600_000), now],
					),
				).rejects.toMatchObject({
					constraint: "clearance_session_credential_authority_v1",
				});

				const beforeMarkerDrift = await bundle.credentialAuthority.status();
				await scopedPool.query(
					`DELETE FROM "securityMigration"
					 WHERE key = 'session-credential-digests-v1'`,
				);
				await expect(bundle.migrate()).rejects.toThrow(
					"markers conflict with the durable digest-live generation",
				);
				const afterMarkerDrift = await bundle.credentialAuthority.status();
				expect(afterMarkerDrift).toMatchObject({
					phase: "digest-live",
					generation: "digest-v1",
					revision: beforeMarkerDrift.revision,
				});
			} finally {
				await bundle?.destroy();
				await scopedPool?.end();
				await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await basePool.end();
			}
		});

		it("keeps legacy sessions live through bridge, drain, migration, and digest restart", async () => {
			const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
			const schema = `auth_bridge_cutover_${suffix}`;
			const baseURL = "http://localhost:3300/api/auth";
			const secret = "credential-bridge-cutover-proof-secret!!";
			const basePool = new pg.Pool({ connectionString: DATABASE_URL });
			let bridgeBundle: ClearanceAuthBundle | undefined;
			let logoutBridgeBundle: ClearanceAuthBundle | undefined;
			let staleBridgeBundle: ClearanceAuthBundle | undefined;
			let migratorBundle: ClearanceAuthBundle | undefined;
			let digestBundle: ClearanceAuthBundle | undefined;
			let scopedPool: pg.Pool | undefined;
			try {
				await basePool.query(`CREATE SCHEMA "${schema}"`);
				const url = new URL(DATABASE_URL);
				url.searchParams.set("options", `-csearch_path=${schema}`);
				const databaseUrl = url.toString();
				scopedPool = new pg.Pool({ connectionString: databaseUrl });
				const common = {
					baseURL,
					secret,
					databaseUrl,
					rateLimitEnabled: false,
					enableSso: false,
					enableScim: false,
					authenticationSecurity: {
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: { enabled: false },
					},
					plugins: [mcp({ loginPage: "/login" })],
				} as const;

				const seedUserId = `legacy-user-${suffix}`;
				const logoutUserId = `legacy-logout-user-${suffix}`;
				const legacySeedToken = `legacy-session-${randomUUID()}`;
				const legacyAccessToken = `legacy-access-${randomUUID()}`;
				const legacyRefreshToken = `legacy-refresh-${randomUUID()}`;
				const legacyLogoutAccessToken = `legacy-logout-access-${randomUUID()}`;
				const legacyLogoutRefreshToken = `legacy-logout-refresh-${randomUUID()}`;
				await scopedPool.query(`
					CREATE TABLE "user" (
						id text PRIMARY KEY,
						name text NOT NULL,
						email text NOT NULL UNIQUE,
						"emailVerified" boolean NOT NULL,
						image text,
						"createdAt" timestamptz NOT NULL,
						"updatedAt" timestamptz NOT NULL,
						banned boolean DEFAULT false,
						"banReason" text
					);
					CREATE TABLE account (
						id text PRIMARY KEY,
						"accountId" text NOT NULL,
						"providerId" text NOT NULL,
						"userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
						"accessToken" text,
						"refreshToken" text,
						"idToken" text,
						"accessTokenExpiresAt" timestamptz,
						"refreshTokenExpiresAt" timestamptz,
						scope text,
						password text,
						"createdAt" timestamptz NOT NULL,
						"updatedAt" timestamptz NOT NULL
					);
					CREATE TABLE session (
						id text PRIMARY KEY,
						"expiresAt" timestamptz NOT NULL,
						token text NOT NULL UNIQUE,
						"createdAt" timestamptz NOT NULL,
						"updatedAt" timestamptz NOT NULL,
						"ipAddress" text,
						"userAgent" text,
						"userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE
					);
					CREATE TABLE verification (
						id text PRIMARY KEY,
						identifier text NOT NULL,
						value text NOT NULL,
						"expiresAt" timestamptz NOT NULL,
							"createdAt" timestamptz,
							"updatedAt" timestamptz
						);
						CREATE TABLE "oauthApplication" (
							id text PRIMARY KEY,
							name text NOT NULL,
							icon text,
							metadata text,
							"clientId" text NOT NULL UNIQUE,
							"clientSecret" text,
							"redirectUrls" text NOT NULL,
							type text NOT NULL,
							disabled boolean DEFAULT false,
							"userId" text REFERENCES "user"(id) ON DELETE CASCADE,
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
				await scopedPool.query(
					`INSERT INTO "user" (
						id, name, email, "emailVerified", "createdAt", "updatedAt"
					) VALUES ($1, 'Bridge Seed', $2, true, now(), now())`,
					[seedUserId, `bridge-seed-${suffix}@example.test`],
				);
				await scopedPool.query(
					`INSERT INTO "user" (
						id, name, email, "emailVerified", "createdAt", "updatedAt"
					) VALUES ($1, 'Legacy Logout', $2, true, now(), now())`,
					[logoutUserId, `legacy-logout-${suffix}@example.test`],
				);
				await scopedPool.query(
					`INSERT INTO session (
						id, "expiresAt", token, "createdAt", "updatedAt", "userId"
					 ) VALUES ($1, now() + interval '1 hour', $2, now(), now(), $3)`,
					[`legacy-session-row-${suffix}`, legacySeedToken, seedUserId],
				);
				await scopedPool.query(
					`INSERT INTO "oauthApplication" (
							id, name, "clientId", "clientSecret", "redirectUrls", type,
							disabled, "createdAt", "updatedAt"
						 ) VALUES ($1, 'Legacy MCP client', 'legacy-mcp-client',
							'legacy-mcp-secret', 'https://client.example.test/callback',
							'web', false, now(), now())`,
					[randomUUID()],
				);
				await scopedPool.query(
					`INSERT INTO "oauthAccessToken" (
							id, "accessToken", "refreshToken", "accessTokenExpiresAt",
							"refreshTokenExpiresAt", "clientId", "userId", scopes,
							"createdAt", "updatedAt"
						 ) VALUES ($1, $2, $3, now() + interval '5 minutes',
							now() + interval '1 hour', 'legacy-mcp-client', $4,
							'openid offline_access', now(), now())`,
					[randomUUID(), legacyAccessToken, legacyRefreshToken, seedUserId],
				);
				await scopedPool.query(
					`INSERT INTO "oauthAccessToken" (
							id, "accessToken", "refreshToken", "accessTokenExpiresAt",
							"refreshTokenExpiresAt", "clientId", "userId", scopes,
							"createdAt", "updatedAt"
						 ) VALUES ($1, $2, $3, now() + interval '5 minutes',
							now() + interval '1 hour', 'legacy-mcp-client', $4,
							'openid offline_access', now(), now())`,
					[
						randomUUID(),
						legacyLogoutAccessToken,
						legacyLogoutRefreshToken,
						logoutUserId,
					],
				);
				const preBridgeCatalog = await scopedPool.query<{ name: string }>(`
					SELECT table_name AS name FROM information_schema.tables
					WHERE table_schema = current_schema()
					  AND table_name IN (
					    'twoFactor', 'jwks', 'passkey', 'passkeyChallenge',
					    'sessionCredential', 'securityMigration', 'credentialAuthorityFence'
					  )
				`);
				expect(preBridgeCatalog.rows).toEqual([]);

				const deploymentId = `bridge-${suffix}`;
				const drainId = `drain-${suffix}`;
				bridgeBundle = createClearanceAuth({
					...common,
					credentialAuthority: {
						generation: "legacy-v1",
						deploymentId,
						instanceId: `bridge-pod-${suffix}`,
					},
				});
				expect(Object.isFrozen(bridgeBundle.credentialAuthority)).toBe(true);
				expect(
					"withExclusiveMigrationLease" in bridgeBundle.credentialAuthority,
				).toBe(false);
				expect("releaseRuntimeLease" in bridgeBundle.credentialAuthority).toBe(
					false,
				);
				await bridgeBundle.prepareCredentialAuthorityRuntime();
				const bridgeContext = await bridgeBundle.auth.$context;
				for (const surface of [
					(bridgeBundle.auth as unknown as { options: object }).options,
					bridgeContext.options,
					bridgeContext.adapter.options,
				]) {
					expect(
						Object.getOwnPropertySymbols(surface).map(String),
					).not.toContain("Symbol(credential-authority-internal)");
				}
				const bridgeColumns = await scopedPool.query<{
					tableName: string;
					columnName: string;
				}>(`
					SELECT table_name AS "tableName", column_name AS "columnName"
					FROM information_schema.columns
					WHERE table_schema = current_schema()
					  AND (
					    (table_name = 'user' AND column_name IN (
					      'twoFactorEnabled', 'twoFactorSessionGeneration',
					      'passkeySessionGeneration', 'passkeyUserHandle'
					    ))
					    OR (table_name = 'session' AND column_name IN (
					      'twoFactorSessionGeneration', 'passkeySessionGeneration'
					    ))
					    OR (table_name = 'account' AND column_name IN (
					      'failedPasswordAttempts', 'activePasswordAttemptReservations',
					      'passwordLockedUntil'
					    ))
					    OR (table_name = 'twoFactor' AND column_name IN (
					      'pendingSecret', 'pendingBackupCodes', 'verified',
					      'failedVerificationCount', 'activeVerificationReservations',
					      'lockedUntil', 'lastUsedTotpCounter', 'trustDeviceGeneration'
					    ))
					    OR (table_name = 'jwks' AND column_name IN ('alg', 'crv'))
					  )
					ORDER BY table_name, column_name
				`);
				expect(
					bridgeColumns.rows.map((row) => `${row.tableName}.${row.columnName}`),
				).toEqual([
					"account.activePasswordAttemptReservations",
					"account.failedPasswordAttempts",
					"account.passwordLockedUntil",
					"jwks.alg",
					"jwks.crv",
					"session.passkeySessionGeneration",
					"session.twoFactorSessionGeneration",
					"twoFactor.activeVerificationReservations",
					"twoFactor.failedVerificationCount",
					"twoFactor.lastUsedTotpCounter",
					"twoFactor.lockedUntil",
					"twoFactor.pendingBackupCodes",
					"twoFactor.pendingSecret",
					"twoFactor.trustDeviceGeneration",
					"twoFactor.verified",
					"user.passkeySessionGeneration",
					"user.passkeyUserHandle",
					"user.twoFactorEnabled",
					"user.twoFactorSessionGeneration",
				]);
				const passwordLockoutColumns = await scopedPool.query<{
					columnName: string;
					type: string;
					nullable: "YES" | "NO";
					defaultValue: string | null;
				}>(`
					SELECT column_name AS "columnName", udt_name AS type,
					       is_nullable AS nullable, column_default AS "defaultValue"
					FROM information_schema.columns
					WHERE table_schema = current_schema()
					  AND table_name = 'account'
					  AND column_name IN (
					    'failedPasswordAttempts', 'activePasswordAttemptReservations',
					    'passwordLockedUntil'
					  )
				`);
				expect(
					Object.fromEntries(
						passwordLockoutColumns.rows.map((column) => [
							column.columnName,
							{
								type: column.type,
								nullable: column.nullable,
								defaultValue: column.defaultValue,
							},
						]),
					),
				).toEqual({
					activePasswordAttemptReservations: {
						type: "text",
						nullable: "YES",
						defaultValue: "'[]'::text",
					},
					failedPasswordAttempts: {
						type: "int4",
						nullable: "YES",
						defaultValue: "0",
					},
					passwordLockedUntil: {
						type: "timestamptz",
						nullable: "YES",
						defaultValue: null,
					},
				});
				const passkeyColumns = await scopedPool.query<{
					tableName: string;
					columnName: string;
					type: string;
					nullable: "YES" | "NO";
				}>(`
					SELECT table_name AS "tableName", column_name AS "columnName",
					       udt_name AS type, is_nullable AS nullable
					FROM information_schema.columns
					WHERE table_schema = current_schema()
					  AND table_name IN ('passkey', 'passkeyChallenge')
				`);
				expect(
					Object.fromEntries(
						passkeyColumns.rows.map((column) => [
							`${column.tableName}.${column.columnName}`,
							{ type: column.type, nullable: column.nullable },
						]),
					),
				).toEqual({
					"passkey.id": { type: "text", nullable: "NO" },
					"passkey.userId": { type: "text", nullable: "NO" },
					"passkey.name": { type: "text", nullable: "YES" },
					"passkey.credentialID": { type: "text", nullable: "NO" },
					"passkey.publicKey": { type: "text", nullable: "NO" },
					"passkey.userHandle": { type: "text", nullable: "NO" },
					"passkey.counter": { type: "int4", nullable: "NO" },
					"passkey.deviceType": { type: "text", nullable: "NO" },
					"passkey.backedUp": { type: "bool", nullable: "NO" },
					"passkey.transports": { type: "text", nullable: "YES" },
					"passkey.aaguid": { type: "text", nullable: "YES" },
					"passkey.createdAt": { type: "timestamptz", nullable: "NO" },
					"passkey.updatedAt": { type: "timestamptz", nullable: "NO" },
					"passkeyChallenge.id": { type: "text", nullable: "NO" },
					"passkeyChallenge.digestId": { type: "text", nullable: "NO" },
					"passkeyChallenge.ceremony": { type: "text", nullable: "NO" },
					"passkeyChallenge.rpID": { type: "text", nullable: "NO" },
					"passkeyChallenge.origin": { type: "text", nullable: "NO" },
					"passkeyChallenge.userId": { type: "text", nullable: "YES" },
					"passkeyChallenge.userHandle": { type: "text", nullable: "YES" },
					"passkeyChallenge.targetPasskeyId": {
						type: "text",
						nullable: "YES",
					},
					"passkeyChallenge.expiresAt": {
						type: "timestamptz",
						nullable: "NO",
					},
					"passkeyChallenge.createdAt": {
						type: "timestamptz",
						nullable: "NO",
					},
					"passkeyChallenge.updatedAt": {
						type: "timestamptz",
						nullable: "NO",
					},
				});
				const passkeyIndexes = await scopedPool.query<{
					name: string;
					tableName: string;
					unique: boolean;
					columns: string[];
				}>(`
					SELECT index_record.relname AS name,
					       table_record.relname AS "tableName",
					       index_state.indisunique AS "unique",
					       array_agg(attribute_record.attname::text ORDER BY index_key.ordinality) AS columns
					FROM pg_index AS index_state
					JOIN pg_class AS table_record ON table_record.oid = index_state.indrelid
					JOIN pg_namespace AS namespace_record ON namespace_record.oid = table_record.relnamespace
					JOIN pg_class AS index_record ON index_record.oid = index_state.indexrelid
					CROSS JOIN LATERAL unnest(index_state.indkey)
					  WITH ORDINALITY AS index_key(attnum, ordinality)
					JOIN pg_attribute AS attribute_record
					  ON attribute_record.attrelid = table_record.oid
					 AND attribute_record.attnum = index_key.attnum
					WHERE namespace_record.nspname = current_schema()
					  AND index_record.relname IN (
					    'user_passkeyUserHandle_uidx', 'passkey_credentialID_uidx',
					    'passkey_userId_idx', 'passkeyChallenge_digestId_uidx',
					    'passkeyChallenge_expiresAt_idx'
					  )
					GROUP BY index_record.relname, table_record.relname, index_state.indisunique
					ORDER BY index_record.relname
				`);
				expect(passkeyIndexes.rows).toEqual([
					{
						name: "passkeyChallenge_digestId_uidx",
						tableName: "passkeyChallenge",
						unique: true,
						columns: ["digestId"],
					},
					{
						name: "passkeyChallenge_expiresAt_idx",
						tableName: "passkeyChallenge",
						unique: false,
						columns: ["expiresAt"],
					},
					{
						name: "passkey_credentialID_uidx",
						tableName: "passkey",
						unique: true,
						columns: ["credentialID"],
					},
					{
						name: "passkey_userId_idx",
						tableName: "passkey",
						unique: false,
						columns: ["userId"],
					},
					{
						name: "user_passkeyUserHandle_uidx",
						tableName: "user",
						unique: true,
						columns: ["passkeyUserHandle"],
					},
				]);
				const passkeyConstraints = await scopedPool.query<{
					name: string;
					type: string;
					definition: string;
				}>(`
					SELECT constraint_record.conname AS name,
					       constraint_record.contype AS type,
					       pg_get_constraintdef(constraint_record.oid, true) AS definition
					FROM pg_constraint AS constraint_record
					JOIN pg_class AS table_record ON table_record.oid = constraint_record.conrelid
					JOIN pg_namespace AS namespace_record ON namespace_record.oid = table_record.relnamespace
					WHERE namespace_record.nspname = current_schema()
					  AND constraint_record.conname IN (
					    'passkey_pkey', 'passkeyChallenge_pkey', 'passkey_userId_fkey'
					  )
					ORDER BY constraint_record.conname
				`);
				expect(passkeyConstraints.rows).toEqual([
					{
						name: "passkeyChallenge_pkey",
						type: "p",
						definition: "PRIMARY KEY (id)",
					},
					{
						name: "passkey_pkey",
						type: "p",
						definition: "PRIMARY KEY (id)",
					},
					{
						name: "passkey_userId_fkey",
						type: "f",
						definition: 'FOREIGN KEY ("userId") REFERENCES "user"(id) ON DELETE CASCADE',
					},
				]);
				const bridgeOnlyCatalog = await scopedPool.query<{ name: string }>(`
					SELECT table_name AS name FROM information_schema.tables
					WHERE table_schema = current_schema()
					  AND table_name IN ('sessionCredential', 'securityMigration')
				`);
				expect(bridgeOnlyCatalog.rows).toEqual([]);
				const seededHeaders = signedSessionHeaders(legacySeedToken, secret);
				await expect(
					bridgeBundle.auth.api.getSession({ headers: seededHeaders }),
				).resolves.toMatchObject({ user: { id: seedUserId } });
				const legacyMcpResponse = await bridgeBundle.auth.handler(
					new Request(`${baseURL}/mcp/get-session`, {
						headers: { authorization: `Bearer ${legacyAccessToken}` },
					}),
				);
				expect(legacyMcpResponse.status).toBe(200);
				expect(await legacyMcpResponse.text()).toContain(seedUserId);
				const legacyRefreshResponse = await bridgeBundle.auth.handler(
					new Request(`${baseURL}/mcp/token`, {
						method: "POST",
						headers: {
							"content-type": "application/x-www-form-urlencoded",
						},
						body: new URLSearchParams({
							grant_type: "refresh_token",
							client_id: "legacy-mcp-client",
							client_secret: "legacy-mcp-secret",
							refresh_token: legacyRefreshToken,
						}).toString(),
					}),
				);
				expect(legacyRefreshResponse.status).toBe(200);
				expect(await legacyRefreshResponse.json()).toMatchObject({
					access_token: expect.any(String),
					refresh_token: expect.any(String),
					token_type: "Bearer",
				});
				logoutBridgeBundle = createClearanceAuth({
					...common,
					plugins: [
						oidcProvider({
							loginPage: "/login",
							__skipDeprecationWarning: true,
						}),
					],
					credentialAuthority: {
						generation: "legacy-v1",
						deploymentId,
						instanceId: `logout-bridge-pod-${suffix}`,
					},
				});
				await logoutBridgeBundle.prepareCredentialAuthorityRuntime();
				const legacyMetadataResponse = await logoutBridgeBundle.auth.handler(
					new Request(`${baseURL}/.well-known/openid-configuration`),
				);
				expect(legacyMetadataResponse.status).toBe(200);
				const legacyMetadata = (await legacyMetadataResponse.json()) as {
					issuer: string;
				};
				const legacyIdTokenWithoutSid = signedLegacyIdToken(
					{
						sub: logoutUserId,
						iss: legacyMetadata.issuer,
						aud: "legacy-mcp-client",
					},
					"legacy-mcp-secret",
				);
				const legacyLogoutUrl = new URL(`${baseURL}/oauth2/endsession`);
				legacyLogoutUrl.searchParams.set(
					"id_token_hint",
					legacyIdTokenWithoutSid,
				);
				legacyLogoutUrl.searchParams.set("client_id", "legacy-mcp-client");
				const legacyLogoutResponse = await logoutBridgeBundle.auth.handler(
					new Request(legacyLogoutUrl, {
						headers: { "Sec-Fetch-Site": "same-origin" },
					}),
				);
				expect(legacyLogoutResponse.status).toBe(200);
				expect(
					(
						await scopedPool.query<{ count: string }>(
							`SELECT count(*)::text AS count FROM "oauthAccessToken"
								 WHERE "userId" = $1 AND "clientId" = 'legacy-mcp-client'`,
							[logoutUserId],
						)
					).rows[0]?.count,
				).toBe("0");
				await logoutBridgeBundle.destroy();
				logoutBridgeBundle = undefined;
				const bridgeIssued = await bridgeBundle.auth.api.signUpEmail({
					body: {
						email: `bridge-issued-${suffix}@example.test`,
						password: "correct-horse-battery-staple",
						name: "Bridge Issued",
					},
				});
				await expect(
					bridgeBundle.auth.api.getSession({
						headers: signedSessionHeaders(bridgeIssued.token, secret),
					}),
				).resolves.toMatchObject({ user: { id: bridgeIssued.user.id } });
				await expect(
					scopedPool.query(`SELECT 1 FROM "sessionCredential"`),
				).rejects.toMatchObject({ code: "42P01" });

				await bridgeBundle.credentialAuthority.arm({
					deploymentId,
					expectedRuntimeCount: 1,
				});
				await bridgeBundle.credentialAuthority.beginDrain({
					deploymentId,
					drainId,
				});
				const beforeStaleStart = await scopedPool.query<{
					catalog: string;
					fence: string;
				}>(`
					SELECT
						md5(COALESCE(string_agg(
							table_name || ':' || column_name || ':' || data_type || ':' || is_nullable,
							',' ORDER BY table_name, ordinal_position
						), '')) AS catalog,
						(SELECT row_to_json(fence)::text FROM "credentialAuthorityFence" fence
						 WHERE id = 'credential-authority') AS fence
					FROM information_schema.columns
					WHERE table_schema = current_schema()
				`);
				staleBridgeBundle = createClearanceAuth({
					...common,
					credentialAuthority: {
						generation: "legacy-v1",
						deploymentId,
						instanceId: `stale-bridge-pod-${suffix}`,
					},
				});
				await expect(
					staleBridgeBundle.prepareCredentialAuthorityRuntime(),
				).rejects.toThrow(/draining|fenced/);
				const afterStaleStart = await scopedPool.query<{
					catalog: string;
					fence: string;
				}>(`
					SELECT
						md5(COALESCE(string_agg(
							table_name || ':' || column_name || ':' || data_type || ':' || is_nullable,
							',' ORDER BY table_name, ordinal_position
						), '')) AS catalog,
						(SELECT row_to_json(fence)::text FROM "credentialAuthorityFence" fence
						 WHERE id = 'credential-authority') AS fence
					FROM information_schema.columns
					WHERE table_schema = current_schema()
				`);
				expect(afterStaleStart.rows).toEqual(beforeStaleStart.rows);
				await staleBridgeBundle.destroy();
				staleBridgeBundle = undefined;
				const retainedBridgeContext = await bridgeBundle.auth.$context;
				await bridgeBundle.destroy();
				await expect(
					retainedBridgeContext.internalAdapter.createSession(seedUserId),
				).rejects.toThrow(/closing|draining|fenced|cannot serve/);
				bridgeBundle = undefined;

				migratorBundle = createClearanceAuth({
					...common,
					credentialAuthority: {
						generation: "digest-v1",
						deploymentId,
						instanceId: `migrator-${suffix}`,
						migrationDrainId: drainId,
					},
				});
				await migratorBundle.migrate({ drainId });
				expect(await migratorBundle.credentialAuthority.status()).toMatchObject(
					{
						phase: "digest-live",
						generation: "digest-v1",
					},
				);
				const migratedCredentials = await scopedPool.query<{
					secretDigest: string;
					status: string;
				}>(
					`SELECT "secretDigest", status FROM "sessionCredential"
					 WHERE "sessionId" IN (
						SELECT id FROM session WHERE "userId" IN ($1, $2)
					 )`,
					[seedUserId, bridgeIssued.user.id],
				);
				expect(migratedCredentials.rows).toEqual(
					expect.arrayContaining([
						expect.objectContaining({
							secretDigest: sessionCredentialDigest(legacySeedToken),
							status: "active",
						}),
						expect.objectContaining({
							secretDigest: sessionCredentialDigest(bridgeIssued.token),
							status: "active",
						}),
					]),
				);
				const migratedOAuth = await scopedPool.query<{
					accessToken: string;
					refreshToken: string;
					accessTokenDigest: string;
					refreshTokenDigest: string;
				}>(
					`SELECT "accessToken", "refreshToken", "accessTokenDigest", "refreshTokenDigest"
						 FROM "oauthAccessToken" WHERE "userId" = $1`,
					[seedUserId],
				);
				expect(migratedOAuth.rows.length).toBeGreaterThanOrEqual(2);
				for (const row of migratedOAuth.rows) {
					expect(row).toMatchObject({
						accessTokenDigest: expect.stringMatching(/^v1:/),
						refreshTokenDigest: expect.stringMatching(/^v1:/),
						accessToken: expect.stringMatching(/^clr_oauth_ref_access_/),
						refreshToken: expect.stringMatching(/^clr_oauth_ref_refresh_/),
					});
				}
				await migratorBundle.destroy();
				migratorBundle = undefined;

				digestBundle = createClearanceAuth({
					...common,
					credentialAuthority: {
						generation: "digest-v1",
						deploymentId,
						instanceId: `digest-pod-${suffix}`,
					},
				});
				await digestBundle.credentialAuthority.assertRuntimeServing();
				const digestContext = await digestBundle.auth.$context;
				await expect(
					digestContext.internalAdapter.findSession(legacySeedToken),
				).resolves.toMatchObject({ user: { id: seedUserId } });
				await expect(
					digestBundle.auth.api.getSession({ headers: seededHeaders }),
				).resolves.toMatchObject({ user: { id: seedUserId } });
				await expect(
					digestBundle.auth.api.getSession({
						headers: signedSessionHeaders(bridgeIssued.token, secret),
					}),
				).resolves.toMatchObject({ user: { id: bridgeIssued.user.id } });
				const digestMcpResponse = await digestBundle.auth.handler(
					new Request(`${baseURL}/mcp/get-session`, {
						headers: { authorization: `Bearer ${legacyAccessToken}` },
					}),
				);
				expect(digestMcpResponse.status).toBe(200);
				expect(await digestMcpResponse.text()).toContain(seedUserId);
			} finally {
				await digestBundle?.destroy();
				await migratorBundle?.destroy();
				await staleBridgeBundle?.destroy();
				await logoutBridgeBundle?.destroy();
				await bridgeBundle?.destroy();
				await scopedPool?.end();
				await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await basePool.end();
			}
		});

		it("rejects a same-named partial passkey authority index", async () => {
			const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
			const schema = `auth_partial_passkey_${suffix}`;
			const basePool = new pg.Pool({ connectionString: DATABASE_URL });
			let bundle: ClearanceAuthBundle | undefined;
			let scopedPool: pg.Pool | undefined;
			try {
				await basePool.query(`CREATE SCHEMA "${schema}"`);
				const url = new URL(DATABASE_URL);
				url.searchParams.set("options", `-csearch_path=${schema}`);
				const databaseUrl = url.toString();
				scopedPool = new pg.Pool({ connectionString: databaseUrl });
				await scopedPool.query(`
					CREATE TABLE "user" (id text PRIMARY KEY);
					CREATE TABLE session (id text PRIMARY KEY);
					CREATE TABLE account (id text PRIMARY KEY);
					CREATE TABLE passkey (
						id text PRIMARY KEY,
						"userId" text NOT NULL,
						name text,
						"credentialID" text NOT NULL,
						"publicKey" text NOT NULL,
						"userHandle" text NOT NULL,
						counter integer NOT NULL,
						"deviceType" text NOT NULL,
						"backedUp" boolean NOT NULL,
						transports text,
						aaguid text,
						"createdAt" timestamptz NOT NULL,
						"updatedAt" timestamptz NOT NULL
					);
					CREATE UNIQUE INDEX "passkey_credentialID_uidx"
						ON passkey ("credentialID")
						WHERE "credentialID" <> '';
				`);

				bundle = createClearanceAuth({
					baseURL: "http://localhost:3300/api/auth",
					secret: "partial-passkey-index-proof-secret!!",
					databaseUrl,
					rateLimitEnabled: false,
					enableSso: false,
					enableScim: false,
					authenticationSecurity: {
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: { enabled: false },
					},
					credentialAuthority: {
						generation: "legacy-v1",
						deploymentId: `partial-index-${suffix}`,
						instanceId: `partial-index-pod-${suffix}`,
					},
				});

				await expect(bundle.prepareCredentialAuthorityRuntime()).rejects.toThrow(
					"incompatible index passkey_credentialID_uidx",
				);
				const rolledBackBridge = await scopedPool.query<{ count: number }>(`
					SELECT count(*)::int AS count
					FROM information_schema.columns
					WHERE table_schema = current_schema()
					  AND table_name = 'user'
					  AND column_name = 'passkeyUserHandle'
				`);
				expect(rolledBackBridge.rows[0]?.count).toBe(0);
			} finally {
				await bundle?.destroy();
				await scopedPool?.end();
				await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await basePool.end();
			}
		});

		it("rejects a same-named NULLS NOT DISTINCT passkey authority index", async () => {
			const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
			const schema = `auth_nulls_passkey_${suffix}`;
			const basePool = new pg.Pool({ connectionString: DATABASE_URL });
			let bundle: ClearanceAuthBundle | undefined;
			let scopedPool: pg.Pool | undefined;
			try {
				await basePool.query(`CREATE SCHEMA "${schema}"`);
				const url = new URL(DATABASE_URL);
				url.searchParams.set("options", `-csearch_path=${schema}`);
				const databaseUrl = url.toString();
				scopedPool = new pg.Pool({ connectionString: databaseUrl });
				await scopedPool.query(`
					CREATE TABLE "user" (
						id text PRIMARY KEY,
						"passkeyUserHandle" text
					);
					CREATE TABLE session (id text PRIMARY KEY);
					CREATE TABLE account (id text PRIMARY KEY);
					CREATE UNIQUE INDEX "user_passkeyUserHandle_uidx"
						ON "user" ("passkeyUserHandle") NULLS NOT DISTINCT;
				`);

				bundle = createClearanceAuth({
					baseURL: "http://localhost:3300/api/auth",
					secret: "nulls-not-distinct-index-proof!!",
					databaseUrl,
					rateLimitEnabled: false,
					enableSso: false,
					enableScim: false,
					authenticationSecurity: {
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: { enabled: false },
					},
					credentialAuthority: {
						generation: "legacy-v1",
						deploymentId: `nulls-index-${suffix}`,
						instanceId: `nulls-index-pod-${suffix}`,
					},
				});

				await expect(bundle.prepareCredentialAuthorityRuntime()).rejects.toThrow(
					"incompatible index user_passkeyUserHandle_uidx",
				);
				const rolledBackBridge = await scopedPool.query<{ table: string | null }>(`
					SELECT to_regclass(format('%I.%I', current_schema(), 'passkey'))::text AS table
				`);
				expect(rolledBackBridge.rows[0]?.table).toBeNull();
			} finally {
				await bundle?.destroy();
				await scopedPool?.end();
				await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await basePool.end();
			}
		});

		it("adds signing metadata to the legacy table shape and rotates its key", async () => {
			const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
			const schema = `auth_security_upgrade_${suffix}`;
			const baseURL = "http://localhost:3300/api/auth";
			const secret = "authentication-security-upgrade-proof-secret!!";
			const basePool = new pg.Pool({ connectionString: DATABASE_URL });
			let oldBundle: ClearanceAuthBundle | undefined;
			let upgradeBundle: ClearanceAuthBundle | undefined;
			let scopedPool: pg.Pool | undefined;
			try {
				await basePool.query(`CREATE SCHEMA "${schema}"`);
				const url = new URL(DATABASE_URL);
				url.searchParams.set("options", `-csearch_path=${schema}`);
				const databaseUrl = url.toString();
				scopedPool = new pg.Pool({ connectionString: databaseUrl });
				const options = {
					baseURL,
					secret,
					databaseUrl,
					enableSso: false,
					enableScim: false,
					authenticationSecurity: {
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: {
							rotationIntervalSeconds: 300,
							gracePeriodSeconds: 600,
						},
					},
				} as const;
				oldBundle = createClearanceAuth(options);
				await oldBundle.migrate();
				const signup = await oldBundle.auth.api.signUpEmail({
					body: {
						email: `upgrade-${suffix}@example.test`,
						password: "correct-horse-battery-staple",
						name: "Upgrade Proof",
					},
				});
				const headers = signedSessionHeaders(signup.token, secret);
				headers.set(
					"idempotency-key",
					credentialOperationKey("security-upgrade-jwt-refresh-operation-0001"),
				);
				const legacyToken = await oldBundle.auth.api.getToken({ headers });
				const legacyHeader = decodeJwtPart<{ kid: string }>(
					legacyToken.token,
					0,
				);
				await oldBundle.destroy();
				oldBundle = undefined;

				await scopedPool.query(
					`ALTER TABLE jwks DROP COLUMN alg, DROP COLUMN crv`,
				);
				await scopedPool.query(`UPDATE jwks SET "expiresAt"=NULL`);
				const before = await basePool.query<{ column_name: string }>(
					`SELECT column_name FROM information_schema.columns
				 WHERE table_schema=$1 AND table_name='jwks'`,
					[schema],
				);
				expect(before.rows.map((row) => row.column_name)).not.toContain("alg");
				expect(before.rows.map((row) => row.column_name)).not.toContain("crv");

				upgradeBundle = createClearanceAuth(options);
				await upgradeBundle.migrate();
				const after = await basePool.query<{ column_name: string }>(
					`SELECT column_name FROM information_schema.columns
				 WHERE table_schema=$1 AND table_name='jwks'`,
					[schema],
				);
				expect(after.rows.map((row) => row.column_name)).toEqual(
					expect.arrayContaining(["alg", "crv"]),
				);
				const upgraded = (
					await scopedPool.query<JwksRow & { expiresAt: Date }>(
						`SELECT id, "publicKey", "privateKey", "expiresAt", alg, crv
					 FROM jwks WHERE id=$1`,
						[legacyHeader.kid],
					)
				).rows[0]!;
				expect(upgraded).toMatchObject({ alg: "EdDSA", crv: "Ed25519" });
				expect(upgraded.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());

				const replacement = await upgradeBundle.auth.api.getToken({ headers });
				const replacementHeader = decodeJwtPart<{ kid: string }>(
					replacement.token,
					0,
				);
				expect(replacementHeader.kid).not.toBe(legacyHeader.kid);
				expect(
					(
						await upgradeBundle.auth.api.verifyJWT({
							body: { token: legacyToken.token },
						})
					).payload,
				).not.toBeNull();
			} finally {
				await upgradeBundle?.destroy();
				await oldBundle?.destroy();
				await scopedPool?.end();
				await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await basePool.end();
			}
		});

		it("rejects a legacy password lock timestamp default", async () => {
			const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
			const schema = `auth_lockout_default_${suffix}`;
			const basePool = new pg.Pool({ connectionString: DATABASE_URL });
			let bridgeBundle: ClearanceAuthBundle | undefined;
			let scopedPool: pg.Pool | undefined;
			try {
				await basePool.query(`CREATE SCHEMA "${schema}"`);
				const url = new URL(DATABASE_URL);
				url.searchParams.set("options", `-csearch_path=${schema}`);
				const databaseUrl = url.toString();
				scopedPool = new pg.Pool({ connectionString: databaseUrl });
				await scopedPool.query(`
					CREATE TABLE "user" (id text PRIMARY KEY);
					CREATE TABLE session (id text PRIMARY KEY);
					CREATE TABLE account (
						id text PRIMARY KEY,
						"passwordLockedUntil" timestamptz
							DEFAULT (now() + interval '1 hour')
					);
				`);
				bridgeBundle = createClearanceAuth({
					baseURL: "http://localhost:3300/api/auth",
					secret: "lockout-default-bridge-proof-secret!!",
					databaseUrl,
					rateLimitEnabled: false,
					enableSso: false,
					enableScim: false,
					authenticationSecurity: {
						breachedPassword: { enabled: false },
						asymmetricAccessTokens: { enabled: false },
					},
					credentialAuthority: {
						generation: "legacy-v1",
						deploymentId: `lockout-default-${suffix}`,
						instanceId: `bridge-${suffix}`,
					},
				});
				await expect(
					bridgeBundle.prepareCredentialAuthorityRuntime(),
				).rejects.toThrow(
					"incompatible default for account.passwordLockedUntil",
				);
			} finally {
				await bridgeBundle?.destroy();
				await scopedPool?.end();
				await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
				await basePool.end();
			}
		});
	},
);
