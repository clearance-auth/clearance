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
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import {
	closeAuthBundle,
	createUserInAuth,
	createUserWithPasswordSetupInAuth,
	deleteUserInAuth,
	disableUserInAuth,
	resetAuthBundle,
	revokeSessionInAuth,
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
import { wrapInternalCoordinatedExecutor } from "../store/coordinated-internal.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";

const TEST_TABLE = `clearance_mgmt_lifecycle_${process.pid}`;
const RUNTIME_AUDIT_SCHEMA = `lifecycle_runtime_audit_${process.pid}`;

/** Exact runtime user ids created by this process (never pre-existing rows). */
const createdRuntimeUserIds = new Set<string>();
/** Emails observed for those users (signup + later updates) for verification cleanup. */
const createdRuntimeEmails = new Set<string>();
/** Credential tombstones detached from deleted sessions by lifecycle operations. */
const createdCredentialIds = new Set<string>();


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
		const credentialIds = [...createdCredentialIds];
		if (credentialIds.length > 0) {
			await pool
				.query(`delete from "sessionCredential" where id = any($1::text[])`, [
					credentialIds,
				])
				.catch(() => undefined);
		}
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

describe.sequential.skipIf(!available)("user lifecycle Postgres runtime + management", () => {
	const stores: PgStore[] = [];
	const prev = {
		DATABASE_URL: process.env.DATABASE_URL,
		CLEARANCE_SECRET: process.env.CLEARANCE_SECRET,
		CLEARANCE_BASE_URL: process.env.CLEARANCE_BASE_URL,
		NODE_ENV: process.env.NODE_ENV,
		CLEARANCE_PROJECT_ID: process.env.CLEARANCE_PROJECT_ID,
		CLEARANCE_ENV_ID: process.env.CLEARANCE_ENV_ID,
		CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION:
			process.env.CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION,
		CLEARANCE_RUNTIME_AUDIT_SCHEMA:
			process.env.CLEARANCE_RUNTIME_AUDIT_SCHEMA,
		CLEARANCE_RUNTIME_AUDIT_PREFIX:
			process.env.CLEARANCE_RUNTIME_AUDIT_PREFIX,
	};

	beforeAll(beforeAllEnv);

	function beforeAllEnv() {
		process.env.DATABASE_URL = DATABASE_URL;
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_BASE_URL = "http://localhost:3300";
		process.env.NODE_ENV = "development";
		process.env.CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION = "digest-v1";
		process.env.CLEARANCE_RUNTIME_AUDIT_SCHEMA = RUNTIME_AUDIT_SCHEMA;
		delete process.env.CLEARANCE_RUNTIME_AUDIT_PREFIX;
	}

	afterEach(async () => {
		// Always strip this run's runtime users, even when an assertion failed.
		await cleanupTrackedRuntimeUsers().catch(() => undefined);
		resetAuthBundle();
	});

	afterAll(async () => {
		try {
			// Safety-net cleanup (idempotent) before closing stores / dropping tables.
			await cleanupTrackedRuntimeUsers().catch(() => undefined);
			for (const s of stores.splice(0)) {
				await s.destroy().catch(() => undefined);
			}
			await resetAuthBundle();
			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}`);
				await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_principal_email`);
				await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_organization_slug`);
				await pool.query(`DROP SCHEMA IF EXISTS "${RUNTIME_AUDIT_SCHEMA}" CASCADE`);
			} finally {
				await pool.end().catch(() => undefined);
			}
			// Successful suite must prove current-run users are gone.
			await assertTrackedRuntimeUsersGone();
		} finally {
			for (const [k, v] of Object.entries(prev)) {
				if (v === undefined) delete process.env[k];
				else process.env[k] = v;
			}
		}
	});

	async function freshStore(): Promise<PgStore> {
		const auditSchema = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await auditSchema.query(`CREATE SCHEMA IF NOT EXISTS "${RUNTIME_AUDIT_SCHEMA}"`);
		} finally {
			await auditSchema.end().catch(() => undefined);
		}
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

	it("removes the runtime user and credential account when management sync fails", async () => {
		const store = await freshStore();
		const email = `sync-cleanup-${Date.now()}@lifecycle.test`;
		const syncFailure = new Error("forced management sync failure");
		const runtime = getAuthBundle();
		let deletedRuntimeUserId: string | undefined;
		const failingStore = new Proxy(store, {
			get(target, property) {
				if (property === "mutate") {
					return (apply: (data: typeof store.snapshot) => void) => {
						const draft = structuredClone(store.snapshot);
						apply(draft);
						deletedRuntimeUserId = draft.principals.find(
							(principal) => principal.email === email,
						)?.id;
						throw syncFailure;
					};
				}
				const value = Reflect.get(target, property, target);
				return typeof value === "function" ? value.bind(target) : value;
			},
		}) as PgStore;

		await expect(createUserInAuth({
			email,
			name: "Failed Management Sync",
			password: "Valid!password123",
			managementStore: failingStore,
		})).rejects.toBe(syncFailure);

		expect(deletedRuntimeUserId).toBeTruthy();
		const users = await runtime.pool.query<{ id: string }>(
			`select id from "user" where id = $1`,
			[deletedRuntimeUserId],
		);
		expect(users.rows).toHaveLength(0);
		const accounts = await runtime.pool.query<{ count: string }>(
			`select count(*)::text count
			 from account
			 where "userId" = $1`,
			[deletedRuntimeUserId],
		);
		expect(accounts.rows[0]?.count).toBe("0");
	});

	async function runtimeSessionCount(userId: string): Promise<number> {
		const b = getAuthBundle();
		const r = await b.pool.query(
			`select count(*)::int as c from session where "userId" = $1`,
			[userId],
		);
		return Number(r.rows[0]?.c ?? 0);
	}

	type CredentialTombstoneProof = {
		ids: string[];
		preservedReuseDetectedAt: Date;
	};

	async function prepareCredentialTombstoneProof(
		userId: string,
	): Promise<CredentialTombstoneProof> {
		const b = getAuthBundle();
		const credentials = await b.pool.query<{ id: string }>(
			`select credential.id
			 from "sessionCredential" credential
			 join session on session.id = credential."sessionId"
			 where session."userId" = $1
			 order by credential.id`,
			[userId],
		);
		expect(credentials.rows.length).toBeGreaterThan(0);
		const ids = credentials.rows.map((row) => row.id);
		for (const id of ids) createdCredentialIds.add(id);
		const preservedReuseDetectedAt = new Date("2026-07-01T12:00:00.000Z");
		await b.pool.query(
			`update "sessionCredential"
			 set "rotationNonceDigest" = 'rotation-nonce-digest-to-scrub',
			     "recoverySecretCiphertext" = 'recovery-ciphertext-to-scrub',
			     "recoveryExpiresAt" = now() + interval '5 minutes',
			     "reuseDetectedAt" = case when id = $2 then $3 else "reuseDetectedAt" end
			 where id = any($1::text[])`,
			[ids, ids[0], preservedReuseDetectedAt],
		);
		return { ids, preservedReuseDetectedAt };
	}

	async function expectCredentialTombstones(
		proof: CredentialTombstoneProof,
	): Promise<void> {
		const b = getAuthBundle();
		const result = await b.pool.query<{
			id: string;
			sessionId: string | null;
			status: string;
			revokedAt: Date | null;
			updatedAt: Date;
			reuseDetectedAt: Date | null;
			rotationNonceDigest: string | null;
			recoverySecretCiphertext: string | null;
			recoveryExpiresAt: Date | null;
		}>(
			`select id, "sessionId", status, "revokedAt", "updatedAt",
			        "reuseDetectedAt", "rotationNonceDigest",
			        "recoverySecretCiphertext", "recoveryExpiresAt"
			 from "sessionCredential"
			 where id = any($1::text[])
			 order by id`,
			[proof.ids],
		);
		expect(result.rows).toHaveLength(proof.ids.length);
		for (const row of result.rows) {
			expect(row.sessionId).toBeNull();
			expect(row.status).toBe("revoked");
			expect(row.revokedAt).toBeInstanceOf(Date);
			expect(row.updatedAt).toEqual(row.revokedAt);
			expect(row.rotationNonceDigest).toBeNull();
			expect(row.recoverySecretCiphertext).toBeNull();
			expect(row.recoveryExpiresAt).toBeNull();
		}
		expect(
			result.rows.find((row) => row.id === proof.ids[0])?.reuseDetectedAt,
		).toEqual(proof.preservedReuseDetectedAt);
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
		const credentialProof = await prepareCredentialTombstoneProof(user.id);

		const disabled = await disableUserInAuth(store, user.id, {
			actor: "test",
			source: "cli",
		});
		expect(disabled.status).toBe("disabled");
		expect(inspectUser(store, user.id).status).toBe("disabled");
		expect((await runtimeUserRow(user.id))?.banned).toBe(true);
		expect(await runtimeSessionCount(user.id)).toBe(0);
		await expectCredentialTombstones(credentialProof);

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

	it("serializes a real Postgres sign-in against management disable", async () => {
		const store = await freshStore();
		const password = "LifecycleDisableRace1!";
		const email = `dis-race-${Date.now()}@lifecycle.test`;
		const user = await createRuntimeUser(store, email, "Race Active", password);
		let enteredResolve!: () => void;
		const entered = new Promise<void>((resolve) => {
			enteredResolve = resolve;
		});
		let releaseResolve!: () => void;
		const release = new Promise<void>((resolve) => {
			releaseResolve = resolve;
		});
		let paused = false;
		const restore = wrapInternalCoordinatedExecutor(store, (original) => (fn) =>
			original(async (context) =>
				fn({
					...context,
					query: async (sql, params) => {
						const result = await context.query(sql, params);
						if (
							!paused &&
							sql.includes('update "user"') &&
							sql.includes("banned = true") &&
							params?.includes(user.id)
						) {
							paused = true;
							enteredResolve();
							await release;
						}
						return result;
					},
				}),
			),
		);
		try {
			const disabling = disableUserInAuth(store, user.id, {
				actor: "race-test",
				source: "api",
			});
			await entered;
			const signingIn = signIn(email, password);
			const stateWhileDisableOwnsUser = await Promise.race([
				signingIn.then(
					() => "fulfilled",
					() => "rejected",
				),
				new Promise<"pending">((resolve) =>
					setTimeout(() => resolve("pending"), 100),
				),
			]);
			expect(stateWhileDisableOwnsUser).toBe("pending");
			releaseResolve();
			await expect(disabling).resolves.toMatchObject({ status: "disabled" });
			await expect(signingIn).rejects.toBeTruthy();
			expect(await runtimeSessionCount(user.id)).toBe(0);
		} finally {
			releaseResolve();
			restore();
		}
	});

	it("status-disable revokes and scrubs joined credential tombstones", async () => {
		const store = await freshStore();
		const password = "LifecycleStatusDisable1!";
		const email = `status-dis-${Date.now()}@lifecycle.test`;
		const user = await createRuntimeUser(store, email, "Status Active", password);
		await signIn(email, password);
		const credentialProof = await prepareCredentialTombstoneProof(user.id);

		const disabled = await updateUserInAuth(store, user.id, {
			status: "disabled",
			actor: "test",
			source: "api",
		});

		expect(disabled.status).toBe("disabled");
		expect(await runtimeSessionCount(user.id)).toBe(0);
		await expectCredentialTombstones(credentialProof);
	});

	it("delete invalidates session, denies sign-in, and fail-closes inspect/list", async () => {
		const store = await freshStore();
		const password = "LifecycleDelete1!";
		const email = `del-${Date.now()}@lifecycle.test`;
		const user = await createRuntimeUser(store, email, "Gone", password);
		await signIn(email, password);
		expect(await runtimeSessionCount(user.id)).toBeGreaterThanOrEqual(1);
		const credentialProof = await prepareCredentialTombstoneProof(user.id);

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
		await expectCredentialTombstones(credentialProof);

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

	it("revokes v0.2.1 raw sessions and OAuth tokens through legacy management flows", async () => {
		const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
		const schema = `management_legacy_bridge_${suffix}`;
		const admin = new pg.Pool({ connectionString: DATABASE_URL });
		const url = new URL(DATABASE_URL);
		url.searchParams.set("options", `-csearch_path=${schema}`);
		const scopedUrl = url.toString();
		const scopedPool = new pg.Pool({ connectionString: scopedUrl });
		let legacyStore: PgStore | undefined;
		const saved = {
			DATABASE_URL: process.env.DATABASE_URL,
			CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION:
				process.env.CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION,
			CLEARANCE_DEPLOYMENT_ID: process.env.CLEARANCE_DEPLOYMENT_ID,
			CLEARANCE_INSTANCE_ID: process.env.CLEARANCE_INSTANCE_ID,
			CLEARANCE_PROJECT_ID: process.env.CLEARANCE_PROJECT_ID,
			CLEARANCE_ENV_ID: process.env.CLEARANCE_ENV_ID,
		};
		try {
			await admin.query(`CREATE SCHEMA "${schema}"`);
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

			process.env.DATABASE_URL = scopedUrl;
			process.env.CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION = "legacy-v1";
			process.env.CLEARANCE_DEPLOYMENT_ID = `legacy-management-${suffix}`;
			process.env.CLEARANCE_INSTANCE_ID = `legacy-management-pod-${suffix}`;
			delete process.env.CLEARANCE_PROJECT_ID;
			delete process.env.CLEARANCE_ENV_ID;
			resetAuthBundle();
			legacyStore = await createPgStore(scopedUrl, {
				tableName: `clearance_mgmt_legacy_${suffix}`,
			});
			await legacyStore.refresh();
			initProject(legacyStore, { name: "Legacy Management", source: "cli" });
			await legacyStore.ready();
			const scope = resolveOperatorScope(legacyStore);
			process.env.CLEARANCE_PROJECT_ID = scope.projectId;
			process.env.CLEARANCE_ENV_ID = scope.environmentId;

			const createLegacyUser = async (label: string) => {
				const user = await createUserInAuth({
					email: `${label}-${suffix}@legacy-management.test`,
					name: `Legacy ${label}`,
					password: `Legacy-${label}-Password-1!`,
					managementStore: legacyStore!,
				});
				trackRuntimeUser(user);
				return user;
			};
			const seedRawAuthorities = async (userId: string, label: string) => {
				const sessionId = `legacy-session-${label}-${suffix}`;
				await scopedPool.query(
					`INSERT INTO session (
						id, "expiresAt", token, "createdAt", "updatedAt", "userId"
					 ) VALUES ($1, now() + interval '1 hour', $2, now(), now(), $3)`,
					[sessionId, `raw-session-${label}-${suffix}`, userId],
				);
				await scopedPool.query(
					`INSERT INTO "oauthAccessToken" (
						id, "accessToken", "refreshToken", "accessTokenExpiresAt",
						"refreshTokenExpiresAt", "clientId", "userId", scopes,
						"createdAt", "updatedAt"
					 ) VALUES ($1, $2, $3, now() + interval '5 minutes',
						now() + interval '1 hour', 'legacy-client', $4,
						'openid offline_access', now(), now())`,
					[
						randomUUID(),
						`raw-access-${label}-${suffix}`,
						`raw-refresh-${label}-${suffix}`,
						userId,
					],
				);
				return sessionId;
			};

			const revokedUser = await createLegacyUser("revoke");
			const revokedSessionId = await seedRawAuthorities(
				revokedUser.id,
				"revoke",
			);
			await expect(
				revokeSessionInAuth(legacyStore, revokedSessionId, {
					actor: "legacy-test",
					scope,
				}),
			).resolves.toMatchObject({ idempotent: false });
			await expect(
				scopedPool.query(`SELECT 1 FROM "sessionCredential"`),
			).rejects.toMatchObject({ code: "42P01" });

			const disabledUser = await createLegacyUser("disable");
			await seedRawAuthorities(disabledUser.id, "disable");
			await disableUserInAuth(legacyStore, disabledUser.id, {
				actor: "legacy-test",
				scope,
			});
			const disabledAuthorities = await scopedPool.query<{ count: string }>(
				`SELECT (
					(SELECT count(*) FROM session WHERE "userId" = $1) +
					(SELECT count(*) FROM "oauthAccessToken" WHERE "userId" = $1)
				 )::text AS count`,
				[disabledUser.id],
			);
			expect(disabledAuthorities.rows[0]?.count).toBe("0");

			const deletedUser = await createLegacyUser("delete");
			await seedRawAuthorities(deletedUser.id, "delete");
			await deleteUserInAuth(legacyStore, deletedUser.id, {
				actor: "legacy-test",
				scope,
			});
			const deletedAuthorities = await scopedPool.query<{ count: string }>(
				`SELECT (
					(SELECT count(*) FROM session WHERE "userId" = $1) +
					(SELECT count(*) FROM "oauthAccessToken" WHERE "userId" = $1)
				 )::text AS count`,
				[deletedUser.id],
			);
			expect(deletedAuthorities.rows[0]?.count).toBe("0");
			expect(
				listEvents(legacyStore, { limit: 500 }).filter(
					(event) =>
						["users.disable", "users.delete", "sessions.revoke"].includes(
							event.action,
						),
				).length,
			).toBeGreaterThanOrEqual(3);
		} finally {
			await closeAuthBundle().catch(() => undefined);
			await legacyStore?.destroy().catch(() => undefined);
			await scopedPool.end().catch(() => undefined);
			createdRuntimeUserIds.clear();
			createdRuntimeEmails.clear();
			createdCredentialIds.clear();
			for (const [key, value] of Object.entries(saved)) {
				if (value === undefined) delete process.env[key];
				else process.env[key] = value;
			}
			await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await admin.end();
		}
	});
});
