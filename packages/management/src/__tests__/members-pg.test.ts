/**
 * Real Postgres integration: Clearance runtime member table + PgStore
 * coordinated membership lifecycle (add / update / remove) with role enforcement.
 *
 * Tracks exact runtime users, organizations, and memberships created by this
 * run and cleans up only those IDs — never broad deletes of pre-existing rows.
 */
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import {
	addMemberInAuth,
	createOrgInAuth,
	createUserInAuth,
	ensureAuthMigrated,
	getAuthBundle,
	removeMemberInAuth,
	resetAuthBundle,
	updateMemberInAuth,
} from "../auth-bridge.js";
import {
	createRole,
	initProject,
	listEvents,
	resolveOperatorScope,
	syncRuntimeOrganizationToManagementDurable,
} from "../index.js";
import { ClearanceError } from "../services/errors.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";

const TEST_TABLE = `clearance_mgmt_members_${process.pid}`;

const createdRuntimeUserIds = new Set<string>();
const createdRuntimeOrgIds = new Set<string>();
const createdRuntimeMemberIds = new Set<string>();
const createdRuntimeEmails = new Set<string>();


function trackUser(user: { id: string; email?: string | null }): void {
	createdRuntimeUserIds.add(user.id);
	if (user.email) createdRuntimeEmails.add(String(user.email).toLowerCase());
}

function trackOrg(org: { id: string }): void {
	createdRuntimeOrgIds.add(org.id);
}

function trackMember(id: string): void {
	createdRuntimeMemberIds.add(id);
}

async function cleanupTracked(): Promise<void> {
	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	try {
		const memberIds = [...createdRuntimeMemberIds];
		if (memberIds.length > 0) {
			await pool
				.query(`delete from member where id = any($1::text[])`, [memberIds])
				.catch(() => undefined);
		}
		// Also strip members for tracked users/orgs created this run
		const userIds = [...createdRuntimeUserIds];
		const orgIds = [...createdRuntimeOrgIds];
		if (userIds.length > 0) {
			await pool
				.query(`delete from member where "userId" = any($1::text[])`, [userIds])
				.catch(() => undefined);
		}
		if (orgIds.length > 0) {
			await pool
				.query(`delete from member where "organizationId" = any($1::text[])`, [
					orgIds,
				])
				.catch(() => undefined);
			await pool
				.query(`delete from organization where id = any($1::text[])`, [orgIds])
				.catch(() => undefined);
		}
		if (userIds.length > 0) {
			const emailRes = await pool
				.query(`select email from "user" where id = any($1::text[])`, [userIds])
				.catch(() => ({ rows: [] as { email: string }[] }));
			for (const row of emailRes.rows) {
				if (row.email) {
					createdRuntimeEmails.add(String(row.email).toLowerCase());
				}
			}
			for (const sql of [
				`delete from session where "userId" = any($1::text[])`,
				`delete from account where "userId" = any($1::text[])`,
				`delete from invitation where "inviterId" = any($1::text[])`,
			]) {
				await pool.query(sql, [userIds]).catch(() => undefined);
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
			await pool
				.query(`delete from "user" where id = any($1::text[])`, [userIds])
				.catch(() => undefined);
		}
	} finally {
		await pool.end().catch(() => undefined);
	}
}

const available = await gatePostgresSuite(DATABASE_URL, "members-pg");

describe.skipIf(!available)("membership Postgres runtime + management", () => {
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
		await cleanupTracked().catch(() => undefined);
		createdRuntimeUserIds.clear();
		createdRuntimeOrgIds.clear();
		createdRuntimeMemberIds.clear();
		createdRuntimeEmails.clear();
		resetAuthBundle();
	});

	afterAll(async () => {
		await cleanupTracked().catch(() => undefined);
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
			initProject(store, { name: "Members PG", source: "cli" });
			await store.ready();
		}
		const scope = resolveOperatorScope(store);
		process.env.CLEARANCE_PROJECT_ID = scope.projectId;
		process.env.CLEARANCE_ENV_ID = scope.environmentId;
		await ensureAuthMigrated();
		return store;
	}

	async function seedOwnerAndOrg(store: PgStore) {
		const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const owner = await createUserInAuth({
			email: `owner-${stamp}@members.test`,
			name: "Owner",
			password: "MembersTest1!",
			managementStore: store,
		});
		trackUser(owner);
		const runtimeOrg = await createOrgInAuth({
			name: `Org ${stamp}`,
			slug: `org-${stamp}`,
			userId: owner.id,
		});
		trackOrg(runtimeOrg);
		// Capture owner membership id from runtime (must equal createOrgInAuth return)
		const b = getAuthBundle();
		const mem = await b.pool.query(
			`select id from member where "organizationId" = $1 and "userId" = $2`,
			[runtimeOrg.id, owner.id],
		);
		const runtimeOwnerMembershipId = mem.rows[0]?.id
			? String(mem.rows[0].id)
			: undefined;
		if (runtimeOwnerMembershipId) trackMember(runtimeOwnerMembershipId);
		expect(runtimeOrg.ownerMembershipId).toBe(runtimeOwnerMembershipId);

		const organization = await syncRuntimeOrganizationToManagementDurable(
			store,
			runtimeOrg,
			owner.id,
			{ actor: "test", role: "owner" },
		);
		return {
			owner,
			organization,
			stamp,
			runtimeOwnerMembershipId,
			runtimeOrg,
		};
	}

	async function createMemberUser(store: PgStore, stamp: string, label: string) {
		const user = await createUserInAuth({
			email: `${label}-${stamp}@members.test`,
			name: label,
			password: "MembersTest1!",
			managementStore: store,
		});
		trackUser(user);
		return user;
	}

	async function runtimeMember(
		organizationId: string,
		userId: string,
	): Promise<{ id: string; role: string } | undefined> {
		const b = getAuthBundle();
		const r = await b.pool.query(
			`select id, role from member where "organizationId" = $1 and "userId" = $2`,
			[organizationId, userId],
		);
		const row = r.rows[0];
		return row
			? { id: String(row.id), role: String(row.role) }
			: undefined;
	}

	it("org sync preserves runtime owner membership id immediately and is idempotent", async () => {
		const store = await freshStore();
		const {
			owner,
			organization,
			runtimeOwnerMembershipId,
			runtimeOrg,
		} = await seedOwnerAndOrg(store);

		expect(runtimeOwnerMembershipId).toBeTruthy();
		expect(runtimeOrg.ownerMembershipId).toBe(runtimeOwnerMembershipId);

		const rt = await runtimeMember(organization.id, owner.id);
		expect(rt?.id).toBe(runtimeOwnerMembershipId);
		expect(rt?.role).toBe("owner");

		const mgmt = store.snapshot.memberships.filter(
			(m) =>
				m.organizationId === organization.id &&
				m.principalId === owner.id &&
				m.status === "active",
		);
		expect(mgmt).toHaveLength(1);
		// Runtime and management owner membership ids are identical immediately after sync
		expect(mgmt[0]?.id).toBe(runtimeOwnerMembershipId);
		expect(mgmt[0]?.role).toBe("owner");

		// Re-sync is idempotent: one canonical active membership, same stable id
		await syncRuntimeOrganizationToManagementDurable(
			store,
			runtimeOrg,
			owner.id,
			{ actor: "test", role: "owner" },
		);
		const after = store.snapshot.memberships.filter(
			(m) =>
				m.organizationId === organization.id &&
				m.principalId === owner.id &&
				m.status === "active",
		);
		expect(after).toHaveLength(1);
		expect(after[0]?.id).toBe(runtimeOwnerMembershipId);
		const rtAgain = await runtimeMember(organization.id, owner.id);
		expect(rtAgain?.id).toBe(runtimeOwnerMembershipId);
	});

	it("built-in role add parity: same id/role in runtime and management, one audit", async () => {
		const store = await freshStore();
		const { organization, stamp } = await seedOwnerAndOrg(store);
		const user = await createMemberUser(store, stamp, "admin");

		const membership = await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: user.id,
			role: "admin",
			actor: "test",
			auditSource: "api",
		});
		trackMember(membership.id);

		expect(membership.role).toBe("admin");
		const rt = await runtimeMember(organization.id, user.id);
		expect(rt?.id).toBe(membership.id);
		expect(rt?.role).toBe("admin");

		const mgmt = store.snapshot.memberships.find((m) => m.id === membership.id);
		expect(mgmt?.role).toBe("admin");
		expect(mgmt?.status).toBe("active");

		const audits = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "orgs.members.add" && e.subjectId === membership.id,
		);
		expect(audits).toHaveLength(1);
		expect(audits[0]?.outcome).toBe("success");
	});

	it("custom scoped role add and update parity with exactly one audit each", async () => {
		const store = await freshStore();
		const { organization, stamp } = await seedOwnerAndOrg(store);
		const user = await createMemberUser(store, stamp, "billing");
		await createRole(store, {
			name: "Billing",
			slug: "billing",
			permissions: ["billing:read"],
		});
		await store.ready();

		const membership = await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: user.id,
			role: "billing",
			actor: "test",
			auditSource: "api",
		});
		trackMember(membership.id);
		expect(membership.role).toBe("billing");
		expect((await runtimeMember(organization.id, user.id))?.role).toBe("billing");

		const updated = await updateMemberInAuth(store, membership.id, {
			role: "member",
			actor: "test",
			auditSource: "api",
		});
		expect(updated.id).toBe(membership.id);
		expect(updated.role).toBe("member");
		expect((await runtimeMember(organization.id, user.id))?.role).toBe("member");

		const adds = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "orgs.members.add" && e.subjectId === membership.id,
		);
		const updates = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "orgs.members.update" && e.subjectId === membership.id,
		);
		expect(adds).toHaveLength(1);
		expect(updates).toHaveLength(1);
	});

	it("invalid/disabled role denial writes nothing and emits no success audit", async () => {
		const store = await freshStore();
		const { organization, stamp } = await seedOwnerAndOrg(store);
		const user = await createMemberUser(store, stamp, "deny");
		const disabled = await createRole(store, {
			name: "Off",
			slug: "off-role",
			permissions: ["x:y"],
		});
		store.mutate((data) => {
			const r = data.roles.find((x) => x.id === disabled.id);
			if (r) r.status = "disabled";
		});
		await store.ready();
		const beforeEvents = listEvents(store, { limit: 500 }).length;

		await expect(
			addMemberInAuth(store, {
				organizationId: organization.id,
				principalId: user.id,
				role: "off-role",
				actor: "test",
			}),
		).rejects.toMatchObject({ code: "ROLE_DISABLED" });

		await expect(
			addMemberInAuth(store, {
				organizationId: organization.id,
				principalId: user.id,
				role: "missing-role",
				actor: "test",
			}),
		).rejects.toMatchObject({ code: "ROLE_NOT_FOUND" });

		expect(await runtimeMember(organization.id, user.id)).toBeUndefined();
		expect(
			store.snapshot.memberships.filter(
				(m) => m.principalId === user.id && m.status === "active",
			),
		).toHaveLength(0);
		expect(listEvents(store, { limit: 500 }).length).toBe(beforeEvents);
	});

	it("duplicate add is idempotent and preserves stable id", async () => {
		const store = await freshStore();
		const { organization, stamp } = await seedOwnerAndOrg(store);
		const user = await createMemberUser(store, stamp, "dup");

		const first = await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: user.id,
			role: "member",
			actor: "test",
		});
		trackMember(first.id);
		const second = await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: user.id,
			role: "admin",
			actor: "test",
		});
		expect(second.id).toBe(first.id);
		expect(second.role).toBe("member"); // does not silently change

		const adds = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "orgs.members.add" && e.subjectId === first.id,
		);
		expect(adds).toHaveLength(1);
		expect(await runtimeMember(organization.id, user.id)).toEqual({
			id: first.id,
			role: "member",
		});
	});

	it("remove parity deletes runtime member and soft-removes management with one audit", async () => {
		const store = await freshStore();
		const { organization, stamp } = await seedOwnerAndOrg(store);
		const user = await createMemberUser(store, stamp, "rm");
		const membership = await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: user.id,
			role: "member",
			actor: "test",
		});
		trackMember(membership.id);

		const removed = await removeMemberInAuth(store, membership.id, {
			actor: "test",
			auditSource: "cli",
		});
		expect(removed.status).toBe("removed");
		expect(await runtimeMember(organization.id, user.id)).toBeUndefined();
		expect(
			store.snapshot.memberships.find((m) => m.id === membership.id)?.status,
		).toBe("removed");

		const audits = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "orgs.members.remove" && e.subjectId === membership.id,
		);
		expect(audits).toHaveLength(1);
	});

	it("final-owner invariant blocks demote and remove", async () => {
		const store = await freshStore();
		const { owner, organization, stamp } = await seedOwnerAndOrg(store);
		const ownerMem = store.snapshot.memberships.find(
			(m) =>
				m.organizationId === organization.id &&
				m.principalId === owner.id &&
				m.status === "active",
		);
		expect(ownerMem).toBeTruthy();
		if (ownerMem) trackMember(ownerMem.id);

		await expect(
			updateMemberInAuth(store, ownerMem!.id, {
				role: "admin",
				actor: "test",
			}),
		).rejects.toMatchObject({ code: "MEMBER_LAST_OWNER" });

		await expect(
			removeMemberInAuth(store, ownerMem!.id, { actor: "test" }),
		).rejects.toMatchObject({ code: "MEMBER_LAST_OWNER" });

		// Still present in runtime
		expect((await runtimeMember(organization.id, owner.id))?.role).toBe("owner");

		// Promote another owner then demote
		const other = await createMemberUser(store, stamp, "coowner");
		const second = await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: other.id,
			role: "owner",
			actor: "test",
		});
		trackMember(second.id);
		const demoted = await updateMemberInAuth(store, ownerMem!.id, {
			role: "member",
			actor: "test",
		});
		expect(demoted.role).toBe("member");
	});

	it("cross-scope add fails closed with no runtime write", async () => {
		const store = await freshStore();
		const { organization, stamp } = await seedOwnerAndOrg(store);
		const user = await createMemberUser(store, stamp, "xs");
		const foreign = {
			projectId: "proj_foreign_membersx",
			environmentId: "env_foreign_membersxx",
		};

		await expect(
			addMemberInAuth(store, {
				organizationId: organization.id,
				principalId: user.id,
				role: "member",
				scope: foreign,
				actor: "test",
			}),
		).rejects.toBeInstanceOf(ClearanceError);

		expect(await runtimeMember(organization.id, user.id)).toBeUndefined();
	});
});
