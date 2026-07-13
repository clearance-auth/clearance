/**
 * Real Postgres integration: Clearance runtime schema + management PgStore
 * coordinated user lifecycle (update / disable / delete).
 *
 * Requires Postgres (CLEARANCE_TEST_DATABASE_URL | DATABASE_URL | local default).
 *
 * Runtime user isolation: every user id created in this process is tracked and
 * hard-deleted (FK children first) in afterEach/afterAll. Cleanup never uses
 * broad email-domain wipes and never touches users not created by this run.
 */
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import {
	createUserInAuth,
	createUserWithPasswordSetupInAuth,
	deleteUserInAuth,
	disableUserInAuth,
	resetAuthBundle,
	updateUserInAuth,
	getAuthBundle,
	ensureAuthMigrated,
} from "../auth-bridge.js";
import {
	inspectUser,
	listEvents,
	listUsers,
	initProject,
	createUser,
	updateUser,
} from "../services/core.js";
import { resolveOperatorScope } from "../services/scope.js";
import { ClearanceError } from "../services/errors.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";

const TEST_TABLE = `clearance_mgmt_lifecycle_${process.pid}`;

/** Exact runtime user ids created by this process (never pre-existing rows). */
const createdRuntimeUserIds = new Set<string>();
/** Emails observed for those users (signup + later updates) for verification cleanup. */
const createdRuntimeEmails = new Set<string>();


function trackRuntimeUser(user: { id: string; email?: string | null }): void {
	createdRuntimeUserIds.add(user.id);
	if (user.email) {
		createdRuntimeEmails.add(String(user.email).toLowerCase());
	}
}

/**
 * Hard-delete only tracked runtime users. Tolerates already-stripped accounts,
 * tombstoned emails, and missing optional tables. Uses a dedicated pool so
 * cleanup works after resetAuthBundle / assertion failures.
 */
async function cleanupTrackedRuntimeUsers(): Promise<void> {
	const ids = [...createdRuntimeUserIds];
	if (ids.length === 0 && createdRuntimeEmails.size === 0) return;

	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	try {
		if (ids.length > 0) {
			// Capture current emails (covers update/tombstone renames) before delete.
			const emailRes = await pool.query(
				`select email from "user" where id = any($1::text[])`,
				[ids],
			);
			for (const row of emailRes.rows) {
				if (row.email) {
					createdRuntimeEmails.add(String(row.email).toLowerCase());
				}
			}

			// Child / FK-related rows first (idempotent; tolerate absent tables).
			const childDeletes = [
				`delete from session where "userId" = any($1::text[])`,
				`delete from account where "userId" = any($1::text[])`,
				`delete from member where "userId" = any($1::text[])`,
				`delete from invitation where "inviterId" = any($1::text[])`,
				`delete from "ssoProvider" where "userId" = any($1::text[])`,
			];
			for (const sql of childDeletes) {
				await pool.query(sql, [ids]).catch(() => undefined);
			}
		}

		const emails = [...createdRuntimeEmails];
		if (emails.length > 0) {
			// verification has no userId FK — match by identifier (email).
			await pool
				.query(
					`delete from verification where lower(identifier) = any($1::text[])`,
					[emails],
				)
				.catch(() => undefined);
		}

		if (ids.length > 0) {
			await pool.query(`delete from "user" where id = any($1::text[])`, [ids]);
		}
	} finally {
		await pool.end().catch(() => undefined);
	}
}

/** Prove this run's tracked users are gone (does not inspect pre-existing pollution). */
async function assertTrackedRuntimeUsersGone(): Promise<void> {
	const ids = [...createdRuntimeUserIds];
	if (ids.length === 0) return;

	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	try {
		const remaining = await pool.query(
			`select id, email from "user" where id = any($1::text[])`,
			[ids],
		);
		expect(
			remaining.rows,
			`tracked runtime users still present after cleanup: ${remaining.rows
				.map((r) => `${r.id}:${r.email}`)
				.join(", ")}`,
		).toHaveLength(0);
	} finally {
		await pool.end().catch(() => undefined);
	}
}

const available = await gatePostgresSuite(DATABASE_URL, "user-lifecycle-pg");

describe.skipIf(!available)("user lifecycle Postgres runtime + management", () => {
	const stores: PgStore[] = [];
	const prev = {
		DATABASE_URL: process.env.DATABASE_URL,
		CLEARANCE_SECRET: process.env.CLEARANCE_SECRET,
		CLEARANCE_BASE_URL: process.env.CLEARANCE_BASE_URL,
		NODE_ENV: process.env.NODE_ENV,
		CLEARANCE_PROJECT_ID: process.env.CLEARANCE_PROJECT_ID,
		CLEARANCE_ENV_ID: process.env.CLEARANCE_ENV_ID,
	};

	beforeAllEnv();

	function beforeAllEnv() {
		process.env.DATABASE_URL = DATABASE_URL;
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_BASE_URL = "http://localhost:3300";
		process.env.NODE_ENV = "development";
	}

	afterEach(async () => {
		// Always strip this run's runtime users, even when an assertion failed.
		await cleanupTrackedRuntimeUsers().catch(() => undefined);
		resetAuthBundle();
	});

	afterAll(async () => {
		// Safety-net cleanup (idempotent) before closing stores / dropping tables.
		await cleanupTrackedRuntimeUsers().catch(() => undefined);
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
		// Successful suite must prove current-run users are gone.
		await assertTrackedRuntimeUsersGone();
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
			initProject(store, { name: "Lifecycle PG", source: "cli" });
			await store.ready();
		}
		const scope = resolveOperatorScope(store);
		process.env.CLEARANCE_PROJECT_ID = scope.projectId;
		process.env.CLEARANCE_ENV_ID = scope.environmentId;
		await ensureAuthMigrated();
		return store;
	}

	async function createRuntimeUser(
		store: PgStore,
		email: string,
		name: string,
		password: string,
	) {
		const user = await createUserInAuth({
			email,
			name,
			password,
			managementStore: store,
		});
		trackRuntimeUser(user);
		return user;
	}

	async function runtimeUserRow(id: string) {
		const b = getAuthBundle();
		const r = await b.pool.query(
			`select id, email, name, banned, "banReason" from "user" where id = $1`,
			[id],
		);
		return r.rows[0] as
			| {
					id: string;
					email: string;
					name: string;
					banned: boolean | null;
					banReason: string | null;
			  }
			| undefined;
	}

	async function runtimeSessionCount(userId: string): Promise<number> {
		const b = getAuthBundle();
		const r = await b.pool.query(
			`select count(*)::int as c from session where "userId" = $1`,
			[userId],
		);
		return Number(r.rows[0]?.c ?? 0);
	}

	async function signIn(email: string, password: string) {
		const b = getAuthBundle();
		return b.auth.api.signInEmail({
			body: { email, password },
		});
	}

	it("passwordless provisioning returns an expiring single-use setup token, never a sign-in credential", async () => {
		const store = await freshStore();
		const email = `setup-${Date.now()}@lifecycle.test`;
		const provisioned = await createUserWithPasswordSetupInAuth({
			email,
			name: "Setup User",
			managementStore: store,
		});
		trackRuntimeUser(provisioned.user);

		expect(provisioned.passwordSetup.token).toMatch(/^[A-Za-z0-9_-]{40,}$/);
		const expiresAt = new Date(provisioned.passwordSetup.expiresAt).getTime();
		expect(expiresAt).toBeGreaterThan(Date.now());
		expect(expiresAt).toBeLessThanOrEqual(Date.now() + 60 * 60 * 1000);
		await expect(signIn(email, provisioned.passwordSetup.token)).rejects.toMatchObject({
			status: "UNAUTHORIZED",
		});

		const newPassword = "CallerChosenSetup1!";
		const b = getAuthBundle();
		await expect(b.auth.api.resetPassword({
			body: {
				newPassword,
				token: provisioned.passwordSetup.token,
			},
		})).resolves.toEqual({ status: true });
		await expect(b.auth.api.resetPassword({
			body: {
				newPassword: "SecondAttemptSetup1!",
				token: provisioned.passwordSetup.token,
			},
		})).rejects.toBeTruthy();
		await expect(signIn(email, newPassword)).resolves.toMatchObject({
			user: { id: provisioned.user.id, email },
		});
	});

	it("update parity: same id/name/email in runtime and management", async () => {
		const store = await freshStore();
		const password = "LifecycleUpdate1!";
		const email = `upd-${Date.now()}@lifecycle.test`;
		const user = await createRuntimeUser(store, email, "Before", password);

		const updated = await updateUserInAuth(store, user.id, {
			name: "After Name",
			email: `after-${Date.now()}@lifecycle.test`,
			actor: "test",
			source: "api",
		});

		expect(updated.id).toBe(user.id);
		expect(updated.name).toBe("After Name");
		expect(updated.email).toMatch(/^after-/);

		const mgmt = inspectUser(store, user.id);
		expect(mgmt.id).toBe(updated.id);
		expect(mgmt.name).toBe(updated.name);
		expect(mgmt.email).toBe(updated.email);

		const runtime = await runtimeUserRow(user.id);
		expect(runtime?.id).toBe(updated.id);
		expect(runtime?.name).toBe(updated.name);
		expect(runtime?.email).toBe(updated.email);

		const audits = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "users.update" && e.subjectId === user.id,
		);
		expect(audits).toHaveLength(1);
		expect(audits[0]?.outcome).toBe("success");
	});

	it("invalid status rejected with no mutation and no success audit", async () => {
		const store = await freshStore();
		const password = "LifecycleInvalid1!";
		const email = `inv-${Date.now()}@lifecycle.test`;
		const user = await createRuntimeUser(store, email, "Keep", password);
		const beforeRuntime = await runtimeUserRow(user.id);
		const beforeEvents = listEvents(store, { limit: 500 }).length;

		await expect(
			updateUserInAuth(store, user.id, {
				name: "NoApply",
				status: "deleted",
				actor: "test",
				source: "api",
			}),
		).rejects.toMatchObject({ code: "USER_STATUS_INVALID" });

		expect(inspectUser(store, user.id).name).toBe("Keep");
		expect(inspectUser(store, user.id).status).toBe("active");
		const afterRuntime = await runtimeUserRow(user.id);
		expect(afterRuntime?.name).toBe(beforeRuntime?.name);
		expect(afterRuntime?.email).toBe(beforeRuntime?.email);
		expect(listEvents(store, { limit: 500 }).length).toBe(beforeEvents);

		// Pure management helper also fails closed
		expect(() =>
			updateUser(store, user.id, { status: "bogus" }),
		).toThrow(ClearanceError);
	});

	it("disable invalidates runtime session and denies subsequent sign-in", async () => {
		const store = await freshStore();
		const password = "LifecycleDisable1!";
		const email = `dis-${Date.now()}@lifecycle.test`;
		const user = await createRuntimeUser(store, email, "Active", password);

		const session = await signIn(email, password);
		expect(session.user.id).toBe(user.id);
		expect(await runtimeSessionCount(user.id)).toBeGreaterThanOrEqual(1);

		const disabled = await disableUserInAuth(store, user.id, {
			actor: "test",
			source: "cli",
		});
		expect(disabled.status).toBe("disabled");
		expect(inspectUser(store, user.id).status).toBe("disabled");
		expect((await runtimeUserRow(user.id))?.banned).toBe(true);
		expect(await runtimeSessionCount(user.id)).toBe(0);

		await expect(signIn(email, password)).rejects.toBeTruthy();

		const audits = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "users.disable" && e.subjectId === user.id,
		);
		expect(audits).toHaveLength(1);

		// Explicit re-enable restores sign-in
		const enabled = await updateUserInAuth(store, user.id, {
			status: "active",
			actor: "test",
			source: "cli",
		});
		expect(enabled.status).toBe("active");
		expect((await runtimeUserRow(user.id))?.banned).toBe(false);
		const again = await signIn(email, password);
		expect(again.user.id).toBe(user.id);
	});

	it("delete invalidates session, denies sign-in, and fail-closes inspect/list", async () => {
		const store = await freshStore();
		const password = "LifecycleDelete1!";
		const email = `del-${Date.now()}@lifecycle.test`;
		const user = await createRuntimeUser(store, email, "Gone", password);
		await signIn(email, password);
		expect(await runtimeSessionCount(user.id)).toBeGreaterThanOrEqual(1);

		const deleted = await deleteUserInAuth(store, user.id, {
			actor: "test",
			source: "cli",
		});
		expect(deleted.status).toBe("deleted");
		expect(listUsers(store).some((u) => u.id === user.id)).toBe(false);
		expect(() => inspectUser(store, user.id)).toThrow(/not found/i);

		const runtime = await runtimeUserRow(user.id);
		expect(runtime?.banned).toBe(true);
		expect(runtime?.email).toMatch(/^deleted\+/);
		expect(await runtimeSessionCount(user.id)).toBe(0);

		await expect(signIn(email, password)).rejects.toBeTruthy();

		const audits = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "users.delete" && e.subjectId === user.id,
		);
		expect(audits).toHaveLength(1);

		// Original email can be reused by a new runtime identity
		const recreated = await createRuntimeUser(
			store,
			email,
			"New",
			"LifecycleRecreate1!",
		);
		expect(recreated.id).not.toBe(user.id);
		expect(recreated.status).toBe("active");
	});

	it("cross-scope mutation fails with runtime and management unchanged", async () => {
		const store = await freshStore();
		const password = "LifecycleScope1!";
		const email = `scope-${Date.now()}@lifecycle.test`;
		const user = await createRuntimeUser(store, email, "Scoped", password);
		const foreignScope = {
			projectId: "proj_other_scope",
			environmentId: "env_other_scope",
		};
		const beforeRuntime = await runtimeUserRow(user.id);
		const beforeEvents = listEvents(store, { limit: 500 }).length;

		await expect(
			updateUserInAuth(store, user.id, {
				name: "Hijacked",
				scope: foreignScope,
				actor: "test",
				source: "api",
			}),
		).rejects.toMatchObject({ code: "USER_NOT_FOUND" });

		await expect(
			disableUserInAuth(store, user.id, {
				scope: foreignScope,
				actor: "test",
			}),
		).rejects.toMatchObject({ code: "USER_NOT_FOUND" });

		await expect(
			deleteUserInAuth(store, user.id, {
				scope: foreignScope,
				actor: "test",
			}),
		).rejects.toMatchObject({ code: "USER_NOT_FOUND" });

		expect(inspectUser(store, user.id).name).toBe("Scoped");
		expect(inspectUser(store, user.id).status).toBe("active");
		const after = await runtimeUserRow(user.id);
		expect(after?.name).toBe(beforeRuntime?.name);
		expect(after?.email).toBe(beforeRuntime?.email);
		expect(after?.banned).toBeFalsy();
		expect(listEvents(store, { limit: 500 }).length).toBe(beforeEvents);

		// Missing and foreign ids are indistinguishable
		await expect(
			disableUserInAuth(store, "user_missing_xyz", {
				scope: resolveOperatorScope(store),
			}),
		).rejects.toMatchObject({ code: "USER_NOT_FOUND" });
	});

	it("management-only create without runtime fails closed on lifecycle mutation", async () => {
		const store = await freshStore();
		const onlyMgmt = createUser(store, {
			email: `mgmt-only-${Date.now()}@lifecycle.test`,
			name: "Mgmt Only",
			source: "cli",
		});
		await store.ready();

		await expect(
			disableUserInAuth(store, onlyMgmt.id, { actor: "test" }),
		).rejects.toMatchObject({ code: "USER_RUNTIME_NOT_FOUND" });

		// Management principal remains active — no partial success
		expect(inspectUser(store, onlyMgmt.id).status).toBe("active");
		const disableAudits = listEvents(store, { limit: 200 }).filter(
			(e) =>
				e.action === "users.disable" &&
				e.subjectId === onlyMgmt.id &&
				e.outcome === "success",
		);
		expect(disableAudits).toHaveLength(0);
	});
});
