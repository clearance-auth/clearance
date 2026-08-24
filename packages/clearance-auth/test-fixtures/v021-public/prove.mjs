#!/usr/bin/env node
/** Exact public @clearance/auth@0.2.1 → current cutover proof. Bound to CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST. */
import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import pg from "pg";

const OAUTH_FIXTURE_LABEL = "v0.2.1 tag-schema-derived SQL fixtures";
const PUBLIC_INTEGRITY =
	"sha512-qkrsSXwq2Kf7iWOTbeAzMfrFKMbrXAoNv1NgzCOl3Y6Ktt/soNo7VAipGRlM2Qb/sl9X3G0rb38UfoCHFP9Tcw==";
// Known installed public-tree manifest (sha512 hex). Caller env cannot self-certify substituted bytes.
const KNOWN_PUBLIC_TREE_DIGEST =
	"01bd531bc9a19c1b6f54532ae953d398c2762873a683a1c0b055f3abaa80624f5ab6a553389d08851830b3d336c108413352dc0b6e922ea61b922d509c5b4980";
const PUBLIC_EXPORTS = [
	"CLEARANCE_AUTH_VERSION", "DEFAULT_TELEMETRY_ENDPOINT", "RUNTIME_BASELINE",
	"clearance", "createClearanceAuth", "decryptRuntimeCredential",
	"encryptRuntimeCredential", "fromNodeHeaders", "getMigrations",
	"isForbiddenDefaultSecret", "organization", "scim",
	"socialProvidersFromEnvironment", "sso", "toNodeHandler", "withClearanceDefaults",
].sort();

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(fixtureDir, "../../../..");
const fixtureModulesRoot = path.join(fixtureDir, "node_modules");
const installedPkgPath = path.join(fixtureModulesRoot, "@clearance/auth");
const currentDistPath = path.join(repoRoot, "packages/clearance-auth/dist/index.mjs");
const currentDistDir = path.join(repoRoot, "packages/clearance-auth/dist");

const assert = (c, m) => { if (!c) throw new Error(m); };
const under = (c, r) => {
	const a = path.resolve(c), b = path.resolve(r);
	return a === b || a.startsWith(b + path.sep);
};
// Manifest (same as shell): regular files; sorted "posixRel\tsha256hex\n";
// outer digest sha512-hex. MANIFEST_IGNORE empty — no npm package-local metadata.
const MANIFEST_IGNORE = new Set();
const collectManifest = (rootAbs) => {
	const rows = [];
	const rootSt = fs.lstatSync(rootAbs);
	assert(!rootSt.isSymbolicLink() && rootSt.isDirectory(), `bad package root: ${rootAbs}`);
	const rec = (abs, rel) => {
		const st = fs.lstatSync(abs);
		assert(!st.isSymbolicLink(), `symlink rejected: ${rel || "."}`);
		if (st.isDirectory()) {
			for (const name of fs.readdirSync(abs).sort())
				rec(path.join(abs, name), rel ? `${rel}/${name}` : name);
			return;
		}
		assert(st.isFile(), `non-regular file rejected: ${rel || "."}`);
		if (MANIFEST_IGNORE.has(rel)) return;
		rows.push(`${rel}\t${createHash("sha256").update(fs.readFileSync(abs)).digest("hex")}`);
	};
	rec(rootAbs, "");
	rows.sort();
	return rows.length ? `${rows.join("\n")}\n` : "";
};
const digestManifest = (t) => createHash("sha512").update(t, "utf8").digest("hex");
const equalDigest = (expected, actual) => {
	assert(/^[0-9a-f]{128}$/.test(expected) && /^[0-9a-f]{128}$/.test(actual),
		"digest must be 128 lowercase hex chars");
	const a = Buffer.from(expected, "utf8"), b = Buffer.from(actual, "utf8");
	assert(a.length === b.length && timingSafeEqual(a, b), "installed public tree digest mismatch");
};
const redact = (e) => String(e instanceof Error ? `${e.name}: ${e.message}` : e)
	.replace(/postgres(?:ql)?:\/\/[^\s"']+/gi, "[redacted-db-url]")
	.replace(/clr_[A-Za-z0-9_~.-]+/g, "[redacted-token]")
	.replace(/Bearer\s+\S+/gi, "Bearer [redacted]")
	.replace(/clearance\.session_token=[^;\s]+/gi, "clearance.session_token=[redacted]")
	.replace(/password[=:]\s*\S+/gi, "password=[redacted]")
	.replace(/secret[=:]\s*\S+/gi, "secret=[redacted]");
const sessionHeaders = (token, secret) => new Headers({
	cookie: `clearance.session_token=${encodeURIComponent(
		`${token}.${createHmac("sha256", secret).update(token).digest("base64")}`,
	)}`,
});
const idToken = (payload, secret) => {
	const now = Math.floor(Date.now() / 1e3);
	const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
	const b = Buffer.from(JSON.stringify({ ...payload, iat: now, exp: now + 300 })).toString("base64url");
	const s = `${h}.${b}`;
	return `${s}.${createHmac("sha256", secret).update(s).digest("base64url")}`;
};
const sessionDigest = (t) =>
	`v1:${createHash("sha256").update(`clearance:session-refresh:v1:${t}`).digest("base64url")}`;
const safeDestroy = async (b) => { if (b) try { await b.destroy(); } catch { /* ignore */ } };
const expectUser = async (api, token, secret, userId, msg) => {
	assert((await api.getSession({ headers: sessionHeaders(token, secret) }))?.user?.id === userId, msg);
};
const expectStatus = async (res, code, msg) => { assert(res.status === code, msg); return res; };
const countByEmail = async (q, email) => {
	const u = await q(`SELECT count(*)::text AS c FROM "user" WHERE email = $1`, [email]);
	const s = await q(
		`SELECT count(*)::text AS c FROM session s JOIN "user" u ON u.id = s."userId" WHERE u.email = $1`,
		[email]);
	return { users: Number(u.rows[0]?.c ?? "0"), sessions: Number(s.rows[0]?.c ?? "0") };
};

async function main() {
	const expectedTreeDigest = process.env.CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST;
	assert(typeof expectedTreeDigest === "string" && expectedTreeDigest.length > 0,
		"CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST is required (run via scripts/prove-v021-credential-compat.sh)");
	assert(/^[0-9a-f]{128}$/.test(expectedTreeDigest),
		"CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST must be canonical 128-char lowercase sha512 hex");
	assert(expectedTreeDigest === KNOWN_PUBLIC_TREE_DIGEST,
		"CLEARANCE_EXPECTED_PUBLIC_TREE_DIGEST must equal hardcoded known public tree digest");

	const databaseUrl = process.env.CLEARANCE_TEST_DATABASE_URL;
	assert(typeof databaseUrl === "string" && databaseUrl.length > 0,
		"CLEARANCE_TEST_DATABASE_URL is required (run via scripts/test-with-postgres.sh)");

	// Path + symlink binding (realpath / lstat)
	const fixtureModulesReal = fs.realpathSync(fixtureModulesRoot);
	assert(!fs.lstatSync(installedPkgPath).isSymbolicLink(),
		"installed @clearance/auth package root must not be a symlink");
	const installedPkgReal = fs.realpathSync(installedPkgPath);
	assert(under(installedPkgReal, fixtureModulesReal),
		"installed package realpath must stay under fixture node_modules realpath");

	const require = createRequire(path.join(fixtureDir, "package.json"));
	let publicResolved;
	try { publicResolved = require.resolve("@clearance/auth"); }
	catch { throw new Error("public @clearance/auth is not installed in the fixture"); }
	assert(!fs.lstatSync(publicResolved).isSymbolicLink(),
		"resolved public entry must not be a symlink");
	const publicEntryReal = fs.realpathSync(publicResolved);
	assert(under(publicEntryReal, installedPkgReal),
		"public entry realpath must stay under installed package realpath");
	assert(under(publicResolved, fixtureModulesRoot),
		"public @clearance/auth resolved outside fixture node_modules");
	const rr = fs.realpathSync(repoRoot);
	assert(!under(publicEntryReal, path.join(rr, "packages/clearance-auth/src"))
		&& !under(publicEntryReal, path.join(rr, "packages/clearance-auth/dist"))
		&& !under(publicEntryReal, path.join(rr, "packages/clearance-auth/node_modules"))
		&& !under(publicEntryReal, path.join(rr, "node_modules")),
		"public @clearance/auth must not resolve to workspace source, dist, package node_modules, or root node_modules");

	const distSt = fs.lstatSync(currentDistPath);
	assert(!distSt.isSymbolicLink() && distSt.isFile(),
		"current dist/index.mjs must be a regular non-symlink file");
	const currentDistReal = fs.realpathSync(currentDistPath);
	assert(under(currentDistReal, fs.realpathSync(currentDistDir)),
		"current dist realpath must stay under packages/clearance-auth/dist");

	// Installed-tree manifest (same rules as shell); nested symlinks rejected via walk.
	// Independent digest of installed bytes must equal the known constant (env cannot self-certify).
	const actualTreeDigest = digestManifest(collectManifest(installedPkgReal));
	equalDigest(KNOWN_PUBLIC_TREE_DIGEST, actualTreeDigest);
	equalDigest(expectedTreeDigest, actualTreeDigest);
	// Negative: wrong known tree digest must not certify the installed tree.
	{
		const wrongKnown = "0".repeat(128);
		assert(wrongKnown !== KNOWN_PUBLIC_TREE_DIGEST, "wrong-known sanity");
		let rejected = false;
		try { equalDigest(wrongKnown, actualTreeDigest); } catch { rejected = true; }
		assert(rejected, "wrong known tree digest must not self-certify installed tree");
	}
	const publicIntegrity = PUBLIC_INTEGRITY; // only after manifest compare

	const publicAuth = await import(pathToFileURL(publicEntryReal).href);
	const publicNames = Object.keys(publicAuth).sort();
	assert(JSON.stringify(publicNames) === JSON.stringify(PUBLIC_EXPORTS),
		`public export set mismatch: got ${publicNames.join(",")}`);
	assert(!publicNames.includes("mcp") && !publicNames.includes("oidcProvider"),
		"public 0.2.1 must not export mcp or oidcProvider");
	assert(publicAuth.CLEARANCE_AUTH_VERSION === "0.2.1",
		"public CLEARANCE_AUTH_VERSION is not 0.2.1");
	assert(publicAuth.RUNTIME_BASELINE?.package === "@clearance/runtime"
		&& publicAuth.RUNTIME_BASELINE?.version === "1.6.23",
		"public RUNTIME_BASELINE.version must be exactly 1.6.23");

	const currentAuth = await import(pathToFileURL(currentDistReal).href);
	const { createClearanceAuth: createCurrent, mcp, oidcProvider } = currentAuth;
	assert(typeof createCurrent === "function" && typeof mcp === "function"
		&& typeof oidcProvider === "function", "current dist missing required exports");

	const suffix = randomUUID().replace(/-/g, "").slice(0, 12);
	const schema = `v021_cred_compat_${suffix}`;
	const baseURL = "http://localhost:3300/api/auth";
	const secret = "v021-public-credential-compat-proof-secret!!";
	const password = "correct-horse-battery-staple";
	const deploymentId = `v021-compat-${suffix}`;
	const drainId = `drain-v021-${suffix}`;
	const publicEmail = `public-${suffix}@example.test`;
	const logoutEmail = `logout-${suffix}@example.test`;
	const staleEmail = `stale-post-cutover-${suffix}@example.test`;
	const baselineEmail = `baseline-post-cutover-${suffix}@example.test`;
	const clientId = "legacy-mcp-client";
	const clientSecret = "legacy-mcp-secret";
	const signupPath = `${baseURL}/sign-up/email`;

	const basePool = new pg.Pool({ connectionString: databaseUrl });
	let scopedPool, publicBundle, bridgeBundle, logoutBridgeBundle;
	let staleBridgeBundle, postCutoverStaleBundle, migratorBundle, digestBundle;
	let duringDrainPrepareRejected = false;
	let postCutoverStaleMutatingRequestFenced = false;
	let routeBaselineSucceeded = false;
	let zeroStaleMutation = false;
	let mcpRefreshAfterMigration = false;

	const destroyAll = async () => {
		for (const b of [digestBundle, migratorBundle, postCutoverStaleBundle, staleBridgeBundle,
			logoutBridgeBundle, bridgeBundle, publicBundle]) await safeDestroy(b);
		digestBundle = migratorBundle = postCutoverStaleBundle = staleBridgeBundle =
			logoutBridgeBundle = bridgeBundle = publicBundle = undefined;
		if (scopedPool) { try { await scopedPool.end(); } catch { /* ignore */ } scopedPool = undefined; }
		try { await basePool.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`); } catch { /* ignore */ }
		try { await basePool.end(); } catch { /* ignore */ }
	};

	try {
		await basePool.query(`CREATE SCHEMA "${schema}"`);
		const scopedUrl = new URL(databaseUrl);
		scopedUrl.searchParams.set("options", `-csearch_path=${schema}`);
		const scopedDatabaseUrl = scopedUrl.toString();
		scopedPool = new pg.Pool({ connectionString: scopedDatabaseUrl });
		const q = (sql, params) => scopedPool.query(sql, params);

		// ── Public 0.2.1 ──────────────────────────────────────────────────
		publicBundle = publicAuth.createClearanceAuth({
			baseURL, secret, databaseUrl: scopedDatabaseUrl,
			rateLimitEnabled: false, enableSso: false, enableScim: false,
		});
		await publicBundle.migrate();

		const signup = await publicBundle.auth.api.signUpEmail({
			body: { email: publicEmail, password, name: "Public Signup" },
		});
		assert(typeof signup?.token === "string" && signup.token.length > 0, "signUpEmail token");
		assert(typeof signup?.user?.id === "string", "signUpEmail user id");
		const publicUserId = signup.user.id;
		const publicSignupToken = signup.token;
		await expectUser(publicBundle.auth.api, publicSignupToken, secret, publicUserId,
			"public getSession failed for signup token");

		const signin = await publicBundle.auth.api.signInEmail({
			body: { email: publicEmail, password },
		});
		assert(typeof signin?.token === "string" && signin.token.length > 0, "signInEmail token");
		const publicSigninToken = signin.token;
		assert(publicSigninToken !== publicSignupToken, "signIn must issue distinct token");
		await expectUser(publicBundle.auth.api, publicSigninToken, secret, publicUserId,
			"public getSession failed for signin token");

		const rawSessions = await q(
			`SELECT token FROM session WHERE "userId" = $1 ORDER BY "createdAt" ASC`,
			[publicUserId],
		);
		assert(rawSessions.rows.length === 2, "expected two public session rows");
		const stored = new Set(rawSessions.rows.map((r) => r.token));
		assert(stored.has(publicSignupToken) && stored.has(publicSigninToken),
			"session rows must retain raw presented tokens under public 0.2.1");

		const catalog = await q(`
			SELECT table_name AS name FROM information_schema.tables
			WHERE table_schema = current_schema()
			  AND table_name IN ('sessionCredential','securityMigration','credentialAuthorityFence')`);
		assert(catalog.rows.length === 0,
			"public migration must not create sessionCredential, securityMigration, or credentialAuthorityFence");

		await publicBundle.destroy();
		publicBundle = undefined;

		// ── Labeled tag-schema OAuth fixture (not public-runtime-generated) ─
		// oauthFixtureLabel: v0.2.1 tag-schema-derived SQL fixtures
		const logoutUserId = `logout-user-${suffix}`;
		const legacyAccessToken = `legacy-access-${randomUUID()}`;
		const legacyRefreshToken = `legacy-refresh-${randomUUID()}`;
		const legacyLogoutAccess = `legacy-logout-access-${randomUUID()}`;
		const legacyLogoutRefresh = `legacy-logout-refresh-${randomUUID()}`;

		await q(`
			CREATE TABLE IF NOT EXISTS "oauthApplication" (
				id text PRIMARY KEY, name text NOT NULL, icon text, metadata text,
				"clientId" text NOT NULL UNIQUE, "clientSecret" text,
				"redirectUrls" text NOT NULL, type text NOT NULL,
				disabled boolean DEFAULT false,
				"userId" text REFERENCES "user"(id) ON DELETE CASCADE,
				"createdAt" timestamptz NOT NULL, "updatedAt" timestamptz NOT NULL
			);
			CREATE TABLE IF NOT EXISTS "oauthAccessToken" (
				id text PRIMARY KEY, "accessToken" text, "refreshToken" text,
				"accessTokenExpiresAt" timestamptz NOT NULL,
				"refreshTokenExpiresAt" timestamptz, "clientId" text NOT NULL,
				"userId" text REFERENCES "user"(id) ON DELETE CASCADE,
				scopes text NOT NULL, "createdAt" timestamptz NOT NULL,
				"updatedAt" timestamptz NOT NULL
			)`);
		await q(
			`INSERT INTO "user" (id, name, email, "emailVerified", "createdAt", "updatedAt")
			 VALUES ($1, 'Legacy Logout', $2, true, now(), now()) ON CONFLICT (id) DO NOTHING`,
			[logoutUserId, logoutEmail],
		);
		await q(
			`INSERT INTO "oauthApplication" (
				id, name, "clientId", "clientSecret", "redirectUrls", type,
				disabled, "createdAt", "updatedAt"
			) VALUES ($1, 'Legacy MCP client', $2, $3,
				'https://client.example.test/callback', 'web', false, now(), now())`,
			[randomUUID(), clientId, clientSecret],
		);
		const insertOauth = (access, refresh, userId) => q(
			`INSERT INTO "oauthAccessToken" (
				id, "accessToken", "refreshToken", "accessTokenExpiresAt",
				"refreshTokenExpiresAt", "clientId", "userId", scopes, "createdAt", "updatedAt"
			) VALUES ($1, $2, $3, now() + interval '5 minutes',
				now() + interval '1 hour', $4, $5, 'openid offline_access', now(), now())`,
			[randomUUID(), access, refresh, clientId, userId],
		);
		await insertOauth(legacyAccessToken, legacyRefreshToken, publicUserId);
		await insertOauth(legacyLogoutAccess, legacyLogoutRefresh, logoutUserId);

		const common = {
			baseURL, secret, databaseUrl: scopedDatabaseUrl,
			rateLimitEnabled: false, enableSso: false, enableScim: false,
			authenticationSecurity: {
				breachedPassword: { enabled: false },
				asymmetricAccessTokens: { enabled: false },
			},
			plugins: [mcp({ loginPage: "/login" })],
		};
		const mkAuth = (generation, instanceId, extra = {}) => createCurrent({
			...common,
			...extra,
			credentialAuthority: { generation, deploymentId, instanceId, ...extra.credentialAuthority },
		});

		// ── Legacy bridge ─────────────────────────────────────────────────
		bridgeBundle = mkAuth("legacy-v1", `bridge-pod-${suffix}`);
		await bridgeBundle.prepareCredentialAuthorityRuntime();

		await expectUser(bridgeBundle.auth.api, publicSignupToken, secret, publicUserId,
			"legacy bridge failed public signup session");
		await expectUser(bridgeBundle.auth.api, publicSigninToken, secret, publicUserId,
			"legacy bridge failed public signin session");

		const mcpGet = await expectStatus(
			await bridgeBundle.auth.handler(new Request(`${baseURL}/mcp/get-session`, {
				headers: { authorization: `Bearer ${legacyAccessToken}` },
			})), 200, "legacy MCP get-session failed");
		assert((await mcpGet.text()).includes(publicUserId), "legacy MCP get-session missing user");

		const mcpRefresh = await expectStatus(
			await bridgeBundle.auth.handler(new Request(`${baseURL}/mcp/token`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "refresh_token", client_id: clientId,
					client_secret: clientSecret, refresh_token: legacyRefreshToken,
				}).toString(),
			})), 200, "legacy MCP refresh failed");
		const refreshed = await mcpRefresh.json();
		assert(typeof refreshed?.access_token === "string"
			&& typeof refreshed?.refresh_token === "string"
			&& refreshed?.token_type === "Bearer", "legacy MCP refresh response shape invalid");

		// Temporary OIDC no-sid logout (second legacy-v1 bundle)
		logoutBridgeBundle = mkAuth("legacy-v1", `logout-bridge-pod-${suffix}`, {
			plugins: [oidcProvider({ loginPage: "/login", __skipDeprecationWarning: true })],
		});
		await logoutBridgeBundle.prepareCredentialAuthorityRuntime();
		const metaRes = await expectStatus(
			await logoutBridgeBundle.auth.handler(
				new Request(`${baseURL}/.well-known/openid-configuration`)),
			200, "OIDC metadata discovery failed");
		const meta = await metaRes.json();
		assert(typeof meta?.issuer === "string", "OIDC metadata missing issuer");
		const logoutUrl = new URL(`${baseURL}/oauth2/endsession`);
		logoutUrl.searchParams.set("id_token_hint", idToken(
			{ sub: logoutUserId, iss: meta.issuer, aud: clientId }, clientSecret));
		logoutUrl.searchParams.set("client_id", clientId);
		await expectStatus(
			await logoutBridgeBundle.auth.handler(new Request(logoutUrl, {
				headers: { "Sec-Fetch-Site": "same-origin" },
			})), 200, "legacy no-sid endsession failed");
		const logoutLeft = await q(
			`SELECT count(*)::text AS c FROM "oauthAccessToken" WHERE "userId"=$1 AND "clientId"=$2`,
			[logoutUserId, clientId]);
		assert(logoutLeft.rows[0]?.c === "0", "no-sid logout did not delete logout OAuth rows");
		const seedLeft = await q(
			`SELECT count(*)::text AS c FROM "oauthAccessToken" WHERE "userId"=$1 AND "clientId"=$2`,
			[publicUserId, clientId]);
		assert(Number(seedLeft.rows[0]?.c ?? "0") >= 1,
			"logout must not consume seed-user OAuth rows needed for refresh/migration");
		await logoutBridgeBundle.destroy();
		logoutBridgeBundle = undefined;

		const bridgeIssued = await bridgeBundle.auth.api.signUpEmail({
			body: { email: `bridge-issued-${suffix}@example.test`, password, name: "Bridge Issued" },
		});
		assert(typeof bridgeIssued?.token === "string" && bridgeIssued.token.length > 0,
			"bridge signUpEmail did not issue a token");
		const bridgeIssuedToken = bridgeIssued.token;
		const bridgeIssuedUserId = bridgeIssued.user.id;
		await expectUser(bridgeBundle.auth.api, bridgeIssuedToken, secret, bridgeIssuedUserId,
			"bridge-issued session did not authenticate");

		let scMissing = false;
		try { await q(`SELECT 1 FROM "sessionCredential"`); }
		catch (e) { scMissing = e?.code === "42P01"; }
		assert(scMissing, "sessionCredential must not exist yet in legacy bridge phase");

		await bridgeBundle.credentialAuthority.arm({ deploymentId, expectedRuntimeCount: 1 });
		await bridgeBundle.credentialAuthority.beginDrain({ deploymentId, drainId });

		// During-drain prepare rejection (separate from post-cutover fence).
		const staleDrainInstanceId = `stale-bridge-pod-${suffix}`;
		staleBridgeBundle = mkAuth("legacy-v1", staleDrainInstanceId);
		try {
			await staleBridgeBundle.prepareCredentialAuthorityRuntime();
		} catch (e) {
			// prepare throws plain Error (no structured code); assert exact message.
			const expectedMsg =
				`Legacy runtime ${staleDrainInstanceId} is fenced by draining/legacy-v1`;
			duringDrainPrepareRejected =
				e instanceof Error && e.message === expectedMsg;
		}
		assert(duringDrainPrepareRejected,
			"stale legacy prepare must fail with exact fenced-by-draining message while draining");
		await staleBridgeBundle.destroy();
		staleBridgeBundle = undefined;
		await bridgeBundle.destroy();
		bridgeBundle = undefined;

		// ── Digest migration + restart ────────────────────────────────────
		migratorBundle = mkAuth("digest-v1", `migrator-${suffix}`, {
			credentialAuthority: { migrationDrainId: drainId },
		});
		await migratorBundle.migrate({ drainId });
		const fenceStatus = await migratorBundle.credentialAuthority.status();
		assert(fenceStatus.phase === "digest-live" && fenceStatus.generation === "digest-v1"
			&& fenceStatus.drainId === drainId,
			"fence is not digest-live/digest-v1 with the exact drain");
		await migratorBundle.destroy();
		migratorBundle = undefined;

		digestBundle = mkAuth("digest-v1", `digest-pod-${suffix}`);
		await digestBundle.credentialAuthority.assertRuntimeServing();

		// Original presented raw sessions remain usable after digest migration
		await expectUser(digestBundle.auth.api, publicSignupToken, secret, publicUserId,
			"digest runtime lost public signup session");
		await expectUser(digestBundle.auth.api, publicSigninToken, secret, publicUserId,
			"digest runtime lost public signin session");
		await expectUser(digestBundle.auth.api, bridgeIssuedToken, secret, bridgeIssuedUserId,
			"digest runtime lost bridge-issued session");

		// Original presented OAuth secret remains usable after digest migration
		const digMcp = await expectStatus(
			await digestBundle.auth.handler(new Request(`${baseURL}/mcp/get-session`, {
				headers: { authorization: `Bearer ${legacyAccessToken}` },
			})), 200, "original raw OAuth bearer failed after digest migration");
		assert((await digMcp.text()).includes(publicUserId), "digest MCP get-session missing user");

		// ── Storage: handles/placeholders + digests ───────────────────────
		const sessions = await q(
			`SELECT id, token FROM session WHERE "userId" IN ($1,$2) ORDER BY "createdAt" ASC`,
			[publicUserId, bridgeIssuedUserId]);
		assert(sessions.rows.length === 3, "expected three sessions after migration");
		for (const row of sessions.rows) {
			assert(typeof row.token === "string" && row.token.startsWith("clr_sid_"),
				"session.token must be a clr_sid_ handle after migration");
		}

		const creds = await q(
			`SELECT "sessionId", "secretDigest", status FROM "sessionCredential"
			 WHERE "sessionId" = ANY($1::text[])`,
			[sessions.rows.map((r) => r.id)]);
		assert(creds.rows.length === 3, "expected three active sessionCredential rows");
		const expectedDigests = new Set([
			sessionDigest(publicSignupToken),
			sessionDigest(publicSigninToken),
			sessionDigest(bridgeIssuedToken),
		]);
		for (const row of creds.rows) {
			assert(row.status === "active", "sessionCredential status must be active");
			assert(typeof row.secretDigest === "string" && row.secretDigest.startsWith("v1:"),
				"sessionCredential secretDigest must be a v1: digest");
			assert(expectedDigests.has(row.secretDigest),
				"sessionCredential digest does not match a retained presented secret");
		}

		const oauth = await q(
			`SELECT "accessToken","refreshToken","accessTokenDigest","refreshTokenDigest"
			 FROM "oauthAccessToken" WHERE "userId" = $1`, [publicUserId]);
		assert(oauth.rows.length >= 1, "expected surviving OAuth rows for seed user");
		for (const row of oauth.rows) {
			assert(typeof row.accessToken === "string" && row.accessToken.startsWith("clr_oauth_ref_access_"),
				"OAuth accessToken must be a clr_oauth_ref_access_ placeholder");
			assert(typeof row.refreshToken === "string" && row.refreshToken.startsWith("clr_oauth_ref_refresh_"),
				"OAuth refreshToken must be a clr_oauth_ref_refresh_ placeholder");
			assert(typeof row.accessTokenDigest === "string" && row.accessTokenDigest.startsWith("v1:"),
				"OAuth accessTokenDigest must be a v1: digest");
			assert(typeof row.refreshTokenDigest === "string" && row.refreshTokenDigest.startsWith("v1:"),
				"OAuth refreshTokenDigest must be a v1: digest");
		}

		// securityMigration uses column state (not status)
		const markers = await q(
			`SELECT key, state FROM "securityMigration"
			 WHERE key IN ('session-credential-digests-v1','oauth-token-digests-v1')`);
		const markerMap = new Map(markers.rows.map((r) => [r.key, r.state]));
		assert(markerMap.get("session-credential-digests-v1") === "complete",
			"session-credential-digests-v1 is not complete");
		assert(markerMap.get("oauth-token-digests-v1") === "complete",
			"oauth-token-digests-v1 is not complete");

		const fence = await q(
			`SELECT phase, generation, "drainId" FROM "credentialAuthorityFence"
			 WHERE id = 'credential-authority'`);
		assert(fence.rows.length === 1, "missing credentialAuthorityFence row");
		assert(fence.rows[0].phase === "digest-live"
			&& fence.rows[0].generation === "digest-v1"
			&& fence.rows[0].drainId === drainId,
			"fence row is not exact digest-live/digest-v1 with drain");

		// MCP refresh after migration: raw pre-migration refresh_token via production handler + digest lookup.
		const mcpRefreshAfterRes = await expectStatus(
			await digestBundle.auth.handler(new Request(`${baseURL}/mcp/token`, {
				method: "POST",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({
					grant_type: "refresh_token", client_id: clientId,
					client_secret: clientSecret, refresh_token: refreshed.refresh_token,
				}).toString(),
			})), 200, "MCP refresh after migration failed");
		const mcpRefreshedAfter = await mcpRefreshAfterRes.json();
		assert(typeof mcpRefreshedAfter?.access_token === "string" && mcpRefreshedAfter.access_token.length > 0
			&& typeof mcpRefreshedAfter?.refresh_token === "string" && mcpRefreshedAfter.refresh_token.length > 0
			&& mcpRefreshedAfter?.token_type === "Bearer",
			"MCP refresh after migration response shape invalid");
		mcpRefreshAfterMigration = true;

		// Post-cutover stale legacy pod: real mutating request fenced
		postCutoverStaleBundle = mkAuth("legacy-v1", `stale-post-cutover-pod-${suffix}`);
		const beforeStale = await countByEmail(q, staleEmail);
		assert(beforeStale.users === 0 && beforeStale.sessions === 0,
			"stale email must be absent before request");
		const staleRes = await postCutoverStaleBundle.auth.handler(new Request(signupPath, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ email: staleEmail, password, name: "Stale Post-Cutover Pod" }),
		}));
		assert(staleRes.status === 503,
			`post-cutover stale signup must return HTTP 503, got ${staleRes.status}`);
		let staleBody;
		try { staleBody = await staleRes.json(); }
		catch { throw new Error("post-cutover stale response is not JSON"); }
		// Stable fence code location on guarded handler JSON body.
		assert(staleBody?.code === "CREDENTIAL_AUTHORITY_FENCED",
			"post-cutover stale response must carry exact code CREDENTIAL_AUTHORITY_FENCED at body.code");
		postCutoverStaleMutatingRequestFenced = true;
		const afterStale = await countByEmail(q, staleEmail);
		assert(afterStale.users === 0 && afterStale.sessions === 0,
			"zero stale mutation: stale email must insert zero user rows and zero session rows");
		zeroStaleMutation = true;

		// Route baseline via active digest runtime (same endpoint, different email).
		const baselineRes = await digestBundle.auth.handler(new Request(signupPath, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ email: baselineEmail, password, name: "Baseline Post-Cutover" }),
		}));
		assert(baselineRes.status === 200,
			`route baseline signup must return HTTP 200, got ${baselineRes.status}`);
		let baselineBody;
		try { baselineBody = await baselineRes.json(); }
		catch { throw new Error("route baseline response is not JSON"); }
		assert(typeof baselineBody?.user?.id === "string" && baselineBody.user.id.length > 0
			&& typeof baselineBody?.token === "string" && baselineBody.token.length > 0,
			"route baseline must return user id and session token");
		const afterBaseline = await countByEmail(q, baselineEmail);
		assert(afterBaseline.users === 1 && afterBaseline.sessions >= 1,
			"route baseline must create user and session rows");
		routeBaselineSucceeded = true;

		await safeDestroy(postCutoverStaleBundle);
		postCutoverStaleBundle = undefined;
		await digestBundle.destroy();
		digestBundle = undefined;

		console.log(JSON.stringify({
			status: "ok",
			publicPackage: "@clearance/auth",
			publicVersion: "0.2.1",
			publicIntegrity,
			publicTreeDigest: actualTreeDigest,
			publicSessions: 2,
			bridgeSessions: 1,
			totalSessionsAfterMigration: 3,
			oauthFixtureLabel: OAUTH_FIXTURE_LABEL,
			runtimeBaseline: "1.6.23",
			legacy: {
				publicSessionsAuthenticated: true,
				bridgeSessionAuthenticated: true,
				mcpGetSession: true,
				mcpRefresh: true,
				noSidLogout: true,
				duringDrainPrepareRejected,
			},
			staleRuntime: {
				duringDrainPrepareRejected,
				postCutoverStaleMutatingRequestFenced,
				routeBaselineSucceeded,
				zeroStaleMutation,
			},
			digest: {
				publicSessionsAuthenticated: true,
				bridgeSessionAuthenticated: true,
				rawOAuthBearerViaDigestLookup: true,
				mcpRefreshAfterMigration,
				sessionTokensAreHandles: true,
				sessionCredentialsActive: 3,
				oauthPlaceholders: true,
			},
			migrationMarkers: [
				"session-credential-digests-v1",
				"oauth-token-digests-v1",
			],
			fence: { phase: "digest-live", generation: "digest-v1" },
		}));
	} finally {
		await destroyAll();
	}
}

main().catch((error) => {
	console.error(JSON.stringify({ status: "error", error: redact(error) }));
	process.exit(1);
});
