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
	createUserInAuth,
	createTenantProductAdministrationFacade,
	ensureAuthMigrated,
	getAuthBundle,
	inspectEffectiveAuthorizationInAuth,
	inspectServiceAccountInAuth,
	listAuthorizationAssignmentsInAuth,
	listServiceAccountsInAuth,
	provisionOrganizationInAuth,
	reconcileAuthorizationOrganizationInAuth,
	replaceAuthorizationAssignmentsInAuth,
	createServiceAccountInAuth,
	createServiceAccountCredentialInAuth,
	revokeServiceAccountCredentialInAuth,
	removeMemberInAuth,
	resetAuthBundle,
	setServiceAccountStatusInAuth,
	updateMemberInAuth,
} from "../auth-bridge.js";
import {
	createRole,
	initProject,
	listEvents,
	resolveOperatorScope,
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
const createdSsoProviderIds = new Set<string>();


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
		const ssoProviderIds = [...createdSsoProviderIds];
		if (ssoProviderIds.length > 0) {
			await pool
				.query(`delete from "ssoProvider" where id = any($1::text[])`, [
					ssoProviderIds,
				])
				.catch(() => undefined);
		}
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
		createdSsoProviderIds.clear();
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
		const organization = await provisionOrganizationInAuth(store, {
			name: `Org ${stamp}`,
			slug: `org-${stamp}`,
			ownerUserId: owner.id,
			actor: "test",
		});
		trackOrg(organization);
		// Capture the exact owner membership id committed with the provision.
		const b = getAuthBundle();
		const mem = await b.pool.query(
			`select id from member where "organizationId" = $1 and "userId" = $2`,
			[organization.id, owner.id],
		);
		const runtimeOwnerMembershipId = mem.rows[0]?.id
			? String(mem.rows[0].id)
			: undefined;
		if (runtimeOwnerMembershipId) trackMember(runtimeOwnerMembershipId);
		return {
			owner,
			organization,
			stamp,
			runtimeOwnerMembershipId,
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

	it("provision commits the owner membership and effective owner actions without reconciliation", async () => {
		const store = await freshStore();
		const {
			owner,
			organization,
			runtimeOwnerMembershipId,
		} = await seedOwnerAndOrg(store);

		expect(runtimeOwnerMembershipId).toBeTruthy();

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

		const authorization = getAuthBundle().authorization;
		if (!authorization) throw new Error("authorization authority unavailable");
		const effective = await authorization.readEffective({
			organizationId: organization.id,
			subject: { kind: "principal", id: owner.id },
		});
		expect(effective.roleIds).toEqual(["role_builtin_owner"]);
		expect(effective.actions).toContain("organization:delete");
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
		const { organization, owner, stamp } = await seedOwnerAndOrg(store);
		const user = await createMemberUser(store, stamp, "billing");
		await createRole(store, {
			name: "Billing",
			slug: "billing",
			permissions: ["billing:read"],
		});
		await store.ready();
		const authorization = getAuthBundle().authorization;
		if (!authorization) throw new Error("authorization authority unavailable");
		const ownerEffective = await authorization.readEffective({
			organizationId: organization.id,
			subject: { kind: "principal", id: owner.id },
		});
		expect(ownerEffective.actions).toContain("organization:delete");

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
		const billingEffective = await authorization.readEffective({
			organizationId: organization.id,
			subject: { kind: "principal", id: user.id },
		});
		expect(billingEffective.actions).toEqual(["billing:read"]);
		expect(BigInt(billingEffective.revision)).toBeGreaterThan(
			BigInt(ownerEffective.revision),
		);

		const updated = await updateMemberInAuth(store, membership.id, {
			role: "member",
			actor: "test",
			auditSource: "api",
		});
		expect(updated.id).toBe(membership.id);
		expect(updated.role).toBe("member");
		expect((await runtimeMember(organization.id, user.id))?.role).toBe("member");
		const memberEffective = await authorization.readEffective({
			organizationId: organization.id,
			subject: { kind: "principal", id: user.id },
		});
		expect(memberEffective.actions).toEqual(["ac:read"]);
		expect(BigInt(memberEffective.revision)).toBeGreaterThan(
			BigInt(billingEffective.revision),
		);
		await updateMemberInAuth(store, membership.id, {
			role: "member",
			actor: "test",
			auditSource: "api",
		});
		const noOpEffective = await authorization.readEffective({
			organizationId: organization.id,
			subject: { kind: "principal", id: user.id },
		});
		expect(noOpEffective.revision).toBe(memberEffective.revision);

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
		const authorization = getAuthBundle().authorization;
		if (!authorization) throw new Error("authorization authority unavailable");
		const effective = await authorization.readEffective({
			organizationId: organization.id,
			subject: { kind: "principal", id: user.id },
		});
		expect(effective.roleIds).toEqual([]);
		expect(effective.actions).toEqual([]);

		const audits = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "orgs.members.remove" && e.subjectId === membership.id,
		);
		expect(audits).toHaveLength(1);
	});

	it("bounded reconciliation clears only stale principal assignments in its organization", async () => {
		const store = await freshStore();
		const { organization } = await seedOwnerAndOrg(store);
		const authorization = getAuthBundle().authorization;
		if (!authorization) throw new Error("authorization authority unavailable");
		const stalePrincipalId = `stale-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		await authorization.replaceSubjectRoles({
			organizationId: organization.id,
			subject: { kind: "principal", id: stalePrincipalId },
			roleIds: ["role_builtin_member"],
		});
		const preview = await reconcileAuthorizationOrganizationInAuth(store, {
			organizationId: organization.id,
			actor: "test",
		});
		expect(preview).toMatchObject({ preview: true, assignmentsChanged: 1 });
		expect(preview).not.toHaveProperty("revision");
		expect(
			await authorization.listSubjectAssignments({
				organizationId: organization.id,
				subject: { kind: "principal", id: stalePrincipalId },
			}),
		).toHaveLength(1);

		const reconciled = await reconcileAuthorizationOrganizationInAuth(store, {
			organizationId: organization.id,
			actor: "test",
			dryRun: false,
			confirm: true,
		});
		expect(reconciled.assignmentsChanged).toBe(1);
		expect(
			await authorization.listSubjectAssignments({
				organizationId: organization.id,
				subject: { kind: "principal", id: stalePrincipalId },
			}),
		).toEqual([]);
	});

	it("manages normalized authorization and service-account credentials through the coordinated bridge", async () => {
		const store = await freshStore();
		const { owner, organization } = await seedOwnerAndOrg(store);
		const ownerEffective = await inspectEffectiveAuthorizationInAuth(store, {
			organizationId: organization.id,
			subject: { kind: "principal", id: owner.id },
		});
		expect(ownerEffective.roleIds).toEqual(["role_builtin_owner"]);
		const assignmentAuditCount = listEvents(store, { limit: 200 }).filter(
			(event) => event.action === "authorization.assignments.replace",
		).length;
		await expect(
			replaceAuthorizationAssignmentsInAuth(store, {
				organizationId: organization.id,
				subject: { kind: "principal", id: `nonmember-${Date.now()}` },
				roleIds: ["role_builtin_member"],
				dryRun: false,
				confirm: true,
			}),
		).rejects.toMatchObject({ code: "AUTHORIZATION_SUBJECT_NOT_FOUND", status: 404 });
		expect((await inspectEffectiveAuthorizationInAuth(store, {
			organizationId: organization.id,
			subject: { kind: "principal", id: owner.id },
		})).revision).toBe(ownerEffective.revision);
		expect(listEvents(store, { limit: 200 }).filter(
			(event) => event.action === "authorization.assignments.replace",
		)).toHaveLength(assignmentAuditCount);

		const previewAccount = await createServiceAccountInAuth(store, {
			organizationId: organization.id,
			name: "Preview deployer",
			roleIds: ["role_builtin_member"],
			dryRun: true,
		});
		expect(previewAccount).toEqual({
			preview: true,
			serviceAccount: {
				organizationId: organization.id,
				name: "Preview deployer",
				status: "active",
			},
			roleIds: ["role_builtin_member"],
		});
		expect(previewAccount.serviceAccount).not.toHaveProperty("serviceAccountId");
		expect(await listServiceAccountsInAuth(store, { organizationId: organization.id })).toEqual([]);

		const account = await createServiceAccountInAuth(store, {
			organizationId: organization.id,
			name: "Release deployer",
			roleIds: ["role_builtin_member"],
			actor: "test",
		});
		if ("preview" in account) throw new Error("live service account creation returned a preview");
		expect(account.serviceAccount.status).toBe("active");
		expect(await listServiceAccountsInAuth(store, { organizationId: organization.id })).toEqual([account.serviceAccount]);
		expect(await inspectServiceAccountInAuth(store, {
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
		})).toEqual({
			serviceAccount: account.serviceAccount,
			assignments: [{
				organizationId: organization.id,
				subject: { kind: "service_account", id: account.serviceAccount.serviceAccountId },
				roleId: "role_builtin_member",
			}],
		});

		const assignmentPreview = await replaceAuthorizationAssignmentsInAuth(store, {
			organizationId: organization.id,
			subject: { kind: "service_account", id: account.serviceAccount.serviceAccountId },
			roleIds: ["role_builtin_admin"],
		});
		expect(assignmentPreview).toMatchObject({
			preview: true,
			assignment: {
				organizationId: organization.id,
				subject: { kind: "service_account", id: account.serviceAccount.serviceAccountId },
				roleIds: ["role_builtin_admin"],
			},
			wouldChange: true,
		});
		expect(assignmentPreview).not.toHaveProperty("revision");
		expect(await listAuthorizationAssignmentsInAuth(store, {
			organizationId: organization.id,
			subject: { kind: "service_account", id: account.serviceAccount.serviceAccountId },
		})).toEqual([{ organizationId: organization.id, subject: { kind: "service_account", id: account.serviceAccount.serviceAccountId }, roleId: "role_builtin_member" }]);
		const replacement = await replaceAuthorizationAssignmentsInAuth(store, {
			organizationId: organization.id,
			subject: { kind: "service_account", id: account.serviceAccount.serviceAccountId },
			roleIds: ["role_builtin_admin"],
			dryRun: false,
			confirm: true,
			actor: "test",
		});
		if ("preview" in replacement) throw new Error("live assignment replacement returned a preview");
		expect(replacement.revision).not.toBe(replacement.previousRevision);

		const credentialPreview = await createServiceAccountCredentialInAuth(store, {
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
			dryRun: true,
			actor: "test",
		});
		expect(credentialPreview).toEqual({
			preview: true,
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
			expiresAt: null,
			secretGenerated: false,
		});
		expect(credentialPreview).not.toHaveProperty("credential");
		expect(credentialPreview).not.toHaveProperty("credentialId");
		expect(credentialPreview).not.toHaveProperty("credentialPrefix");
		expect(credentialPreview).not.toHaveProperty("credentialFingerprint");
		expect(credentialPreview).not.toHaveProperty("revision");
		await expect(createServiceAccountCredentialInAuth(store, {
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
			dryRun: true,
			actor: "test",
			operationId: "33333333-3333-4333-8333-333333333333",
		} as never)).rejects.toMatchObject({
			code: "TENANT_OPERATION_ID_REQUIRED",
		});
		const credential = await createServiceAccountCredentialInAuth(store, {
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
			actor: "test",
			operationId: "22222222-2222-4222-8222-222222222222",
		});
		if ("preview" in credential) throw new Error("live credential creation returned a preview");
		expect(credential.secret).toMatch(/^clr_sac_v1_/);
		expect(credential.credential.expiresAt).toBeNull();
		const disabled = await setServiceAccountStatusInAuth(store, {
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
			status: "disabled",
			actor: "test",
		});
		if ("preview" in disabled) throw new Error("live status change returned a preview");
		expect(disabled.revision).not.toBe(disabled.previousRevision);
		const enabled = await setServiceAccountStatusInAuth(store, {
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
			status: "active",
			actor: "test",
		});
		if ("preview" in enabled) throw new Error("live status change returned a preview");
		const revoked = await revokeServiceAccountCredentialInAuth(store, {
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
			credentialId: credential.credential!.credentialId,
			actor: "test",
		});
		if ("preview" in revoked) throw new Error("live credential revocation returned a preview");
		expect(enabled.revision).not.toBe(enabled.previousRevision);
		expect(revoked.revision).not.toBe(revoked.previousRevision);
		const auditJson = JSON.stringify(listEvents(store, { limit: 200 }).filter((event) => event.action.startsWith("authorization.")));
		expect(auditJson).not.toContain(credential.secret!);
		expect(auditJson).not.toContain("credentialDigest");
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

	it("tenant enterprise facade reauthorizes inside the coordinated disable transaction", async () => {
		const store = await freshStore();
		const { owner, organization, stamp } = await seedOwnerAndOrg(store);
		const member = await createMemberUser(store, stamp, "tenant-enterprise");
		const membership = await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: member.id,
			role: "member",
			actor: "test",
		});
		trackMember(membership.id);

		const allowedConnectionId = `sso_tenant_allowed_${process.pid}_${Date.now()}`;
		const deniedConnectionId = `sso_tenant_denied_${process.pid}_${Date.now()}`;
		const revokedConnectionId = `sso_tenant_revoked_${process.pid}_${Date.now()}`;
		const now = new Date().toISOString();
		store.mutate((data) => {
			for (const id of [allowedConnectionId, deniedConnectionId, revokedConnectionId]) {
				data.identityConnections.push({
					id,
					organizationId: organization.id,
					protocol: "oidc",
					provider: "okta",
					status: "active",
					domains: ["example.test"],
					issuer: "https://idp.example.test/oauth2/default",
					attributeMapping: { email: "email", name: "name" },
					createdAt: now,
					updatedAt: now,
				});
			}
		});
		await store.ready();

		const runtime = getAuthBundle();
		for (const id of [allowedConnectionId, deniedConnectionId, revokedConnectionId]) {
			await runtime.pool.query(
				`insert into "ssoProvider" (
					id, issuer, "oidcConfig", "samlConfig", "userId", "providerId",
					"organizationId", domain
				 ) values ($1, $2, null, null, $3, $4, $5, $6)`,
				[
					id,
					"https://idp.example.test/oauth2/default",
					owner.id,
					`${id}_provider`,
					organization.id,
					"example.test",
				],
			);
			createdSsoProviderIds.add(id);
		}

		const scope = resolveOperatorScope(store);
		const facade = createTenantProductAdministrationFacade({ store, scope });
		await expect(
			facade.disableSso({
				organizationId: organization.id,
				actorId: owner.id,
				connectionId: allowedConnectionId,
			}),
		).resolves.toMatchObject({
			connection: { id: allowedConnectionId, status: "disabled" },
			runtimeRemoved: true,
		});

		const eventsBeforeDenied = store.snapshot.events.length;
		await expect(
			facade.disableSso({
				organizationId: organization.id,
				actorId: member.id,
				connectionId: deniedConnectionId,
			}),
		).rejects.toMatchObject({
			code: "TENANT_AUTHORIZATION_REQUIRED",
			status: 403,
		});
		expect(
			store.snapshot.identityConnections.find(
				(connection) => connection.id === deniedConnectionId,
			)?.status,
		).toBe("active");
		await expect(
			runtime.pool.query(
				`select id from "ssoProvider" where id = $1`,
				[deniedConnectionId],
			),
		).resolves.toMatchObject({
			rows: [{ id: deniedConnectionId }],
		});
		expect(store.snapshot.events).toHaveLength(eventsBeforeDenied);

		// This actor is first granted the exact update authority, then revoked
		// through the live membership lifecycle. The real facade must re-read
		// normalized authorization in its coordinated transaction; an endpoint
		// capability captured before revocation would incorrectly delete this row.
		await updateMemberInAuth(store, membership.id, { role: "owner", actor: "test" });
		await removeMemberInAuth(store, membership.id, { actor: "test" });
		const eventsBeforeRevoked = store.snapshot.events.length;
		await expect(
			facade.disableSso({
				organizationId: organization.id,
				actorId: member.id,
				connectionId: revokedConnectionId,
			}),
		).rejects.toMatchObject({
			code: "TENANT_AUTHORIZATION_REQUIRED",
			status: 403,
		});
		expect(
			store.snapshot.identityConnections.find(
				(connection) => connection.id === revokedConnectionId,
			)?.status,
		).toBe("active");
		await expect(
			runtime.pool.query(`select id from "ssoProvider" where id = $1`, [revokedConnectionId]),
		).resolves.toMatchObject({ rows: [{ id: revokedConnectionId }] });
		expect(store.snapshot.events).toHaveLength(eventsBeforeRevoked);
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
