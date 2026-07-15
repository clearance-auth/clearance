import { createHmac, randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	createClearanceAuth,
	decryptRuntimeCredential,
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

function totp(secret: string, counter = Math.floor(Date.now() / 30_000)): string {
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
		`${token}.${createHmac("sha256", secret)
			.update(token)
			.digest("base64")}`,
	);
	return new Headers({
		cookie: `clearance.session_token=${signedToken}`,
	});
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
			for (const code of enrollment.backupCodes) {
				expect(row.backupCodes).not.toContain(code);
			}
			const decryptedBackupCodes = JSON.parse(
				await decryptRuntimeCredential(row.backupCodes, secret),
			) as string[];
			expect(decryptedBackupCodes).toEqual(enrollment.backupCodes);

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
					(index % 2 === 0 ? bundle : peerBundle).auth.api.getToken({ headers }),
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
				(await scopedPool.query<{ count: number }>("SELECT count(*)::int count FROM jwks"))
					.rows[0]?.count,
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
			expect(unknown.expiresAt.getTime()).toBeLessThan(
				Date.now() - 600 * 1000,
			);
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

describe.sequential.skipIf(!available)("authentication security schema upgrade", () => {
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
			const legacyToken = await oldBundle.auth.api.getToken({ headers });
			const legacyHeader = decodeJwtPart<{ kid: string }>(legacyToken.token, 0);
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
				(await upgradeBundle.auth.api.verifyJWT({
					body: { token: legacyToken.token },
				})).payload,
			).not.toBeNull();
		} finally {
			await upgradeBundle?.destroy();
			await oldBundle?.destroy();
			await scopedPool?.end();
			await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await basePool.end();
		}
	});
});
