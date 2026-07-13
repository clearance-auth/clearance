/**
 * Real Postgres: create runtime session row, list safely (no token), revoke,
 * confirm DB cleanup + management tombstone + audit, clean fixtures.
 */
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import {
	createUserInAuth,
	ensureAuthMigrated,
	getAuthBundle,
	listSessionsInAuth,
	resetAuthBundle,
	revokeSessionInAuth,
} from "../auth-bridge.js";
import { initProject, listEvents } from "../services/core.js";
import { resolveOperatorScope } from "../services/scope.js";
import { ClearanceError } from "../services/errors.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";

const TEST_TABLE = `clearance_mgmt_sessions_${process.pid}`;

const createdRuntimeUserIds = new Set<string>();
const createdRuntimeEmails = new Set<string>();
const createdSessionIds = new Set<string>();


function trackRuntimeUser(user: { id: string; email?: string | null }): void {
	createdRuntimeUserIds.add(user.id);
	if (user.email) createdRuntimeEmails.add(String(user.email).toLowerCase());
}

async function cleanupFixtures(): Promise<void> {
	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	try {
		const sessionIds = [...createdSessionIds];
		if (sessionIds.length > 0) {
			await pool
				.query(`delete from session where id = any($1::text[])`, [sessionIds])
				.catch(() => undefined);
		}
		const ids = [...createdRuntimeUserIds];
		if (ids.length > 0) {
			const emailRes = await pool.query(
				`select email from "user" where id = any($1::text[])`,
				[ids],
			);
			for (const row of emailRes.rows) {
				if (row.email) createdRuntimeEmails.add(String(row.email).toLowerCase());
			}
			for (const sql of [
				`delete from session where "userId" = any($1::text[])`,
				`delete from account where "userId" = any($1::text[])`,
				`delete from member where "userId" = any($1::text[])`,
			]) {
				await pool.query(sql, [ids]).catch(() => undefined);
			}
			const emails = [...createdRuntimeEmails];
			if (emails.length > 0) {
				await pool
					.query(
						`delete from verification where lower(identifier) = any($1::text[])`,
						[emails],
					)
					.catch(() => undefined);
			}
			await pool.query(`delete from "user" where id = any($1::text[])`, [ids]);
		}
	} finally {
		await pool.end().catch(() => undefined);
	}
}

const available = await gatePostgresSuite(DATABASE_URL, "sessions-pg");

describe.skipIf(!available)("sessions Postgres runtime list / revoke", () => {
	const stores: PgStore[] = [];
	const prev = {
		DATABASE_URL: process.env.DATABASE_URL,
		CLEARANCE_SECRET: process.env.CLEARANCE_SECRET,
		CLEARANCE_BASE_URL: process.env.CLEARANCE_BASE_URL,
		NODE_ENV: process.env.NODE_ENV,
		CLEARANCE_PROJECT_ID: process.env.CLEARANCE_PROJECT_ID,
		CLEARANCE_ENV_ID: process.env.CLEARANCE_ENV_ID,
	};

	process.env.DATABASE_URL = DATABASE_URL;
	process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
	process.env.CLEARANCE_BASE_URL = "http://localhost:3300";
	process.env.NODE_ENV = "development";

	afterEach(async () => {
		await cleanupFixtures().catch(() => undefined);
		createdSessionIds.clear();
		createdRuntimeUserIds.clear();
		createdRuntimeEmails.clear();
		resetAuthBundle();
	});

	afterAll(async () => {
		await cleanupFixtures().catch(() => undefined);
		for (const s of stores.splice(0)) {
			await s.destroy().catch(() => undefined);
		}
		resetAuthBundle();
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}`);
			await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_principal_email`);
			await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_organization_slug`);
		} finally {
			await pool.end().catch(() => undefined);
		}
		for (const [k, v] of Object.entries(prev)) {
			if (v === undefined) delete process.env[k];
			else process.env[k] = v;
		}
	});

	async function freshStore(): Promise<PgStore> {
		const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(store);
		await store.refresh();
		if (store.snapshot.projects.length === 0) {
			initProject(store, { name: "Sessions PG", source: "cli" });
			await store.ready();
		}
		const scope = resolveOperatorScope(store);
		process.env.CLEARANCE_PROJECT_ID = scope.projectId;
		process.env.CLEARANCE_ENV_ID = scope.environmentId;
		await ensureAuthMigrated();
		return store;
	}

	async function insertRuntimeSession(
		userId: string,
		opts?: { id?: string; token?: string; expiresAt?: Date },
	): Promise<{ id: string; token: string }> {
		const b = getAuthBundle();
		const id = opts?.id ?? `sess_test_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
		const token =
			opts?.token ??
			`tok_secret_${Date.now()}_${Math.random().toString(36).slice(2)}`;
		const expires = opts?.expiresAt ?? new Date(Date.now() + 60 * 60 * 1000);
		await b.pool.query(
			`insert into session (id, token, "userId", "expiresAt", "createdAt", "updatedAt", "ipAddress", "userAgent")
       values ($1, $2, $3, $4, now(), now(), $5, $6)`,
			[id, token, userId, expires, "127.0.0.1", "sessions-pg-test"],
		);
		createdSessionIds.add(id);
		return { id, token };
	}

	it("lists runtime session without token, revokes with DB delete + audit, idempotent re-revoke", async () => {
		const store = await freshStore();
		const scope = resolveOperatorScope(store);
		const email = `sess-${Date.now()}@sessions.test`;
		const password = "SessionsPgTest1!";
		const user = await createUserInAuth({
			email,
			name: "Sess PG",
			password,
			managementStore: store,
		});
		trackRuntimeUser(user);

		const secretToken = `never-expose-this-token-${Date.now()}`;
		const { id: sessionId } = await insertRuntimeSession(user.id, {
			token: secretToken,
		});

		const listed = await listSessionsInAuth(store, { scope });
		const hit = listed.find((s) => s.id === sessionId);
		expect(hit).toBeTruthy();
		expect(hit?.principalId).toBe(user.id);
		expect(hit?.projectId).toBe(scope.projectId);
		expect(hit?.environmentId).toBe(scope.environmentId);
		expect(hit?.status).toBe("active");
		const listedJson = JSON.stringify(listed);
		expect(listedJson).not.toContain(secretToken);
		expect(listedJson).not.toMatch(/"token"/);
		expect(hit).not.toHaveProperty("token");

		// Prove token still only in DB, not in operator view
		const b = getAuthBundle();
		const before = await b.pool.query(
			`select id, token from session where id = $1`,
			[sessionId],
		);
		expect(before.rows).toHaveLength(1);
		expect(before.rows[0]?.token).toBe(secretToken);

		const first = await revokeSessionInAuth(store, sessionId, {
			actor: "test",
			source: "api",
			scope,
		});
		expect(first.idempotent).toBe(false);
		expect(first.session.id).toBe(sessionId);
		expect(first.session.status).toBe("revoked");
		expect(JSON.stringify(first)).not.toContain(secretToken);

		const after = await b.pool.query(`select id from session where id = $1`, [
			sessionId,
		]);
		expect(after.rows).toHaveLength(0);

		// Management tombstone present for idempotent contract
		const tombstone = store.snapshot.sessions.find((s) => s.id === sessionId);
		expect(tombstone?.status).toBe("revoked");

		const second = await revokeSessionInAuth(store, sessionId, {
			actor: "test",
			source: "api",
			scope,
		});
		expect(second.idempotent).toBe(true);
		expect(second.session.status).toBe("revoked");

		const audits = listEvents(store, { limit: 50 }).filter(
			(e) => e.action === "sessions.revoke" && e.subjectId === sessionId,
		);
		expect(audits.length).toBeGreaterThanOrEqual(2);
		expect(audits[0]?.outcome).toBe("success");
		expect(audits.every((e) => !JSON.stringify(e).includes(secretToken))).toBe(
			true,
		);

		// Gone from active list
		const afterList = await listSessionsInAuth(store, { scope });
		expect(afterList.find((s) => s.id === sessionId)).toBeUndefined();
	});

	it("omits expired runtime sessions from the active list", async () => {
		const store = await freshStore();
		const scope = resolveOperatorScope(store);
		const user = await createUserInAuth({
			email: `sess-expired-${Date.now()}@sessions.test`,
			name: "Expired Sess PG",
			password: "SessionsPgTest1!",
			managementStore: store,
		});
		trackRuntimeUser(user);
		const expired = await insertRuntimeSession(user.id, {
			expiresAt: new Date(Date.now() - 60_000),
		});
		const active = await insertRuntimeSession(user.id);

		const listed = await listSessionsInAuth(store, { scope });
		expect(listed.some((session) => session.id === expired.id)).toBe(false);
		expect(listed.some((session) => session.id === active.id)).toBe(true);
	});

	it("cross-scope and missing session fail closed as SESSION_NOT_FOUND", async () => {
		const store = await freshStore();
		const scope = resolveOperatorScope(store);

		await expect(
			revokeSessionInAuth(store, "sess_does_not_exist", {
				scope,
				actor: "test",
				source: "api",
			}),
		).rejects.toMatchObject({
			code: "SESSION_NOT_FOUND",
			status: 404,
		});

		// Session for a user outside management scope (plant runtime row only)
		const b = getAuthBundle();
		const foreignUserId = `user_foreign_${Date.now()}`;
		const foreignSessionId = `sess_foreign_${Date.now()}`;
		await b.pool.query(
			`insert into "user" (id, email, name, "emailVerified", "createdAt", "updatedAt")
       values ($1, $2, $3, false, now(), now())
       on conflict do nothing`,
			[foreignUserId, `${foreignUserId}@foreign.test`, "Foreign"],
		);
		createdRuntimeUserIds.add(foreignUserId);
		createdRuntimeEmails.add(`${foreignUserId}@foreign.test`);
		await insertRuntimeSession(foreignUserId, { id: foreignSessionId });

		await expect(
			revokeSessionInAuth(store, foreignSessionId, {
				scope,
				actor: "test",
				source: "api",
			}),
		).rejects.toBeInstanceOf(ClearanceError);

		// Runtime row still present (unauthorized revoke must not delete)
		const still = await b.pool.query(`select id from session where id = $1`, [
			foreignSessionId,
		]);
		expect(still.rows).toHaveLength(1);
	});
});
