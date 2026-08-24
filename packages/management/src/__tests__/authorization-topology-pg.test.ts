import { afterAll, describe, expect, it } from "vitest";
import pg from "pg";
import { gatePostgresSuite } from "./pg-gate.js";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import {
	addMemberInAuth,
	createOrgInAuth,
	createRoleInAuth,
	createServiceAccountCredentialInAuth,
	createServiceAccountInAuth,
	createUserInAuth,
	ensureAuthMigrated,
	getAuthBundle,
	inspectEffectiveAuthorizationInAuth,
	listRolesFromAuth,
	listServiceAccountsInAuth,
	replaceAuthorizationAssignmentsInAuth,
	resetAuthBundle,
	updateMemberInAuth,
} from "../auth-bridge.js";
import {
	initProject,
	listEvents,
	syncRuntimeOrganizationToManagementDurable,
} from "../index.js";

const DATABASE_URL =
	process.env.CLEARANCE_ORG_TEST_DATABASE_URL ??
	"postgres://user:password@127.0.0.1:55432/clearance";

if (DATABASE_URL.includes(":5434")) {
	throw new Error(
		"authorization-topology-pg must use dedicated Postgres on 55432 (CLEARANCE_ORG_TEST_DATABASE_URL); refusing shared 5434",
	);
}

const TABLE = `clearance_authz_topology_${process.pid}`;
const NORMALIZED_PREFIX = `${TABLE}_n_`;
const AUTHORIZATION_PREFIX = `authtop${process.pid}`;

const available = await gatePostgresSuite(DATABASE_URL, "authorization-topology-pg");

describe.skipIf(!available)("normalized authorization after topology cutover", () => {
	const previousEnvironment = {
		DATABASE_URL: process.env.DATABASE_URL,
		CLEARANCE_SECRET: process.env.CLEARANCE_SECRET,
		CLEARANCE_BASE_URL: process.env.CLEARANCE_BASE_URL,
		NODE_ENV: process.env.NODE_ENV,
		CLEARANCE_PROJECT_ID: process.env.CLEARANCE_PROJECT_ID,
		CLEARANCE_ENV_ID: process.env.CLEARANCE_ENV_ID,
		CLEARANCE_AUTHORIZATION_PREFIX: process.env.CLEARANCE_AUTHORIZATION_PREFIX,
	};
	let store: PgStore | undefined;
	let runtimeOrganizationId: string | undefined;
	let runtimeOwnerId: string | undefined;
	let runtimeOwnerEmail: string | undefined;
	let runtimeMemberId: string | undefined;
	let runtimeMemberEmail: string | undefined;

	async function cleanup(): Promise<void> {
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			if (runtimeOrganizationId) {
				await pool.query(
					`delete from member where "organizationId" = $1`,
					[runtimeOrganizationId],
				).catch(() => undefined);
				await pool.query(`delete from organization where id = $1`, [runtimeOrganizationId])
					.catch(() => undefined);
			}
			if (runtimeOwnerId) {
				for (const table of ["session", "account", "invitation"]) {
					await pool.query(`delete from ${table} where "userId" = $1`, [runtimeOwnerId])
						.catch(() => undefined);
				}
				if (runtimeOwnerEmail) {
					await pool.query(`delete from verification where lower(identifier) = lower($1)`, [runtimeOwnerEmail])
						.catch(() => undefined);
				}
				await pool.query(`delete from "user" where id = $1`, [runtimeOwnerId])
					.catch(() => undefined);
			}
			if (runtimeMemberId) {
				for (const table of ["session", "account", "invitation"]) {
					await pool.query(`delete from ${table} where "userId" = $1`, [runtimeMemberId])
						.catch(() => undefined);
				}
				if (runtimeMemberEmail) {
					await pool.query(`delete from verification where lower(identifier) = lower($1)`, [runtimeMemberEmail])
						.catch(() => undefined);
				}
				await pool.query(`delete from "user" where id = $1`, [runtimeMemberId])
					.catch(() => undefined);
			}
			for (const table of [
				`${AUTHORIZATION_PREFIX}_authz_actions`,
				`${AUTHORIZATION_PREFIX}_authz_role_actions`,
				`${AUTHORIZATION_PREFIX}_authz_roles`,
				`${AUTHORIZATION_PREFIX}_authz_subject_role_assignments`,
				`${AUTHORIZATION_PREFIX}_authz_service_accounts`,
				`${AUTHORIZATION_PREFIX}_authz_service_account_credentials`,
				`${AUTHORIZATION_PREFIX}_authz_revisions`,
				`${NORMALIZED_PREFIX}events`,
				`${NORMALIZED_PREFIX}principals`,
				`${NORMALIZED_PREFIX}organizations`,
				`${NORMALIZED_PREFIX}environments`,
				`${NORMALIZED_PREFIX}projects`,
				`${NORMALIZED_PREFIX}meta`,
				`${TABLE}_principal_email`,
				`${TABLE}_organization_slug`,
				`${TABLE}_idempotency`,
				TABLE,
			]) {
				await pool.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
			}
		} finally {
			await pool.end();
		}
	}

	afterAll(async () => {
		await store?.destroy().catch(() => undefined);
		await cleanup().catch(() => undefined);
		for (const [key, value] of Object.entries(previousEnvironment)) {
			if (value === undefined) delete process.env[key];
			else process.env[key] = value;
		}
		resetAuthBundle();
	});

	it("uses relational organizations for normalized authorization reads and writes", async () => {
		process.env.DATABASE_URL = DATABASE_URL;
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_BASE_URL = "http://localhost:3300";
		process.env.NODE_ENV = "development";
		process.env.CLEARANCE_AUTHORIZATION_PREFIX = AUTHORIZATION_PREFIX;
		resetAuthBundle();

		store = await createPgStore(DATABASE_URL, {
			tableName: TABLE,
			normalizedPrefix: NORMALIZED_PREFIX,
		});
		const initialized = initProject(store, {
			name: "Authorization topology cutover",
			source: "cli",
		});
		await store.ready();
		const scope = {
			projectId: initialized.project.id,
			environmentId: initialized.environment.id,
		};
		process.env.CLEARANCE_PROJECT_ID = scope.projectId;
		process.env.CLEARANCE_ENV_ID = scope.environmentId;
		await ensureAuthMigrated();

		const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		const owner = await createUserInAuth({
			email: `owner-${stamp}@authorization-topology.test`,
			name: "Authorization Owner",
			password: "AuthorizationTopology1!",
			managementStore: store,
		});
		runtimeOwnerId = owner.id;
		runtimeOwnerEmail = owner.email;
		const runtimeOrganization = await createOrgInAuth({
			name: `Authorization topology ${stamp}`,
			slug: `authorization-topology-${stamp}`,
			userId: owner.id,
		});
		runtimeOrganizationId = runtimeOrganization.id;
		const organization = await syncRuntimeOrganizationToManagementDurable(
			store,
			runtimeOrganization,
			owner.id,
			{ actor: "test", role: "owner" },
		);
		const member = await createUserInAuth({
			email: `member-${stamp}@authorization-topology.test`,
			name: "Authorization Member",
			password: "AuthorizationTopology1!",
			managementStore: store,
		});
		runtimeMemberId = member.id;
		runtimeMemberEmail = member.email;
		const initialMembership = await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: member.id,
			role: "member",
			actor: "test",
			scope,
		});

		await store.storeV2!.apply();
		await store.storeV2!.cutoverEvents();
		await store.storeV2!.cutoverTopology();
		expect(store.storeV2Topology?.authoritative).toBe(true);
		expect(store.snapshot.organizations).toEqual([]);

		const beforeRoleRead = await inspectEffectiveAuthorizationInAuth(store, {
			organizationId: organization.id,
			subject: { kind: "principal", id: owner.id },
			scope,
		});
		expect(beforeRoleRead).toMatchObject({
			organizationId: organization.id,
			roleIds: ["role_builtin_owner"],
		});
		await expect(listRolesFromAuth(store, {
			organizationId: organization.id,
			scope,
		})).resolves.toEqual(expect.arrayContaining([
			expect.objectContaining({ id: "role_builtin_owner" }),
		]));
		expect((await inspectEffectiveAuthorizationInAuth(store, {
			organizationId: organization.id,
			subject: { kind: "principal", id: owner.id },
			scope,
		})).revision).toBe(beforeRoleRead.revision);

		const authorization = getAuthBundle().authorization;
		if (!authorization) throw new Error("authorization authority unavailable");
		await authorization.replaceSubjectRoles({
			organizationId: organization.id,
			subject: { kind: "principal", id: member.id },
			roleIds: [],
		});
		const reconcileAudits = () => listEvents(store, { limit: 200 }).filter(
			(event) =>
				event.action === "authorization.assignment.reconcile" &&
				event.subjectId === member.id,
		);
		const reconcileAuditCount = () => reconcileAudits().length;
		await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: member.id,
			role: "member",
			actor: "test",
			scope,
		});
		expect(reconcileAuditCount()).toBe(1);
		expect(reconcileAudits()[0]?.metadata).toMatchObject({
			repairedPlanes: ["authorization"],
		});
		await addMemberInAuth(store, {
			organizationId: organization.id,
			principalId: member.id,
			role: "member",
			actor: "test",
			scope,
		});
		expect(reconcileAuditCount()).toBe(1);

		const runtimePool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			await runtimePool.query(`update member set role = $1 where id = $2`, [
				"admin",
				initialMembership.id,
			]);
			await addMemberInAuth(store, {
				organizationId: organization.id,
				principalId: member.id,
				role: "member",
				actor: "test",
				scope,
			});
			expect(reconcileAuditCount()).toBe(2);
			expect(reconcileAudits()[0]?.metadata).toMatchObject({
				repairedPlanes: ["membership"],
			});

			const runtimeMembershipId = `mem-runtime-${stamp}`;
			await runtimePool.query(`update member set id = $1 where id = $2`, [
				runtimeMembershipId,
				initialMembership.id,
			]);
			const repairedMembership = await updateMemberInAuth(store, initialMembership.id, {
				role: "member",
				actor: "test",
				scope,
			});
			expect(repairedMembership.id).toBe(runtimeMembershipId);
			expect(reconcileAuditCount()).toBe(3);
			expect(reconcileAudits()[0]?.metadata).toMatchObject({
				repairedPlanes: ["membership"],
			});
			await updateMemberInAuth(store, runtimeMembershipId, {
				role: "member",
				actor: "test",
				scope,
			});
			expect(reconcileAuditCount()).toBe(3);

			const customRole = await createRoleInAuth(store, {
				name: "Topology custom member",
				slug: "topology-custom-member",
				permissions: ["organization:read"],
				organizationId: organization.id,
				actor: "test",
				scope,
			});
			await updateMemberInAuth(store, runtimeMembershipId, {
				role: customRole.slug,
				actor: "test",
				scope,
			});
			await authorization.upsertRole({
				role: {
					roleId: customRole.id,
					organizationId: organization.id,
					slug: customRole.slug,
					name: "Drifted custom member",
					description: null,
					builtIn: false,
					status: "active",
				},
				actions: customRole.permissions,
			});
			const beforeCustomRoleReconcile = await inspectEffectiveAuthorizationInAuth(store, {
				organizationId: organization.id,
				subject: { kind: "principal", id: member.id },
				scope,
			});
			await addMemberInAuth(store, {
				organizationId: organization.id,
				principalId: member.id,
				role: customRole.slug,
				actor: "test",
				scope,
			});
			expect(reconcileAuditCount()).toBe(4);
			const customRoleAudit = reconcileAudits()[0];
			expect(customRoleAudit?.metadata).toMatchObject({
				repairedPlanes: ["authorization"],
				previousRevision: beforeCustomRoleReconcile.revision,
			});
			const afterCustomRoleReconcile = await inspectEffectiveAuthorizationInAuth(store, {
				organizationId: organization.id,
				subject: { kind: "principal", id: member.id },
				scope,
			});
			expect(customRoleAudit?.metadata).toMatchObject({
				revision: afterCustomRoleReconcile.revision,
			});
			await addMemberInAuth(store, {
				organizationId: organization.id,
				principalId: member.id,
				role: customRole.slug,
				actor: "test",
				scope,
			});
			expect(reconcileAuditCount()).toBe(4);
		} finally {
			await runtimePool.end();
		}

		const account = await createServiceAccountInAuth(store, {
			organizationId: organization.id,
			name: "Topology deployer",
			roleIds: ["role_builtin_member"],
			scope,
		});
		if ("preview" in account) throw new Error("expected a live service account");
		await expect(listServiceAccountsInAuth(store, {
			organizationId: organization.id,
			scope,
		})).resolves.toEqual([account.serviceAccount]);

		const replacement = await replaceAuthorizationAssignmentsInAuth(store, {
			organizationId: organization.id,
			subject: {
				kind: "service_account",
				id: account.serviceAccount.serviceAccountId,
			},
			roleIds: ["role_builtin_admin"],
			dryRun: false,
			confirm: true,
			scope,
		});
		if ("preview" in replacement) throw new Error("expected a live assignment replacement");
		expect(replacement.assignment.roleIds).toEqual(["role_builtin_admin"]);

		const credential = await createServiceAccountCredentialInAuth(store, {
			organizationId: organization.id,
			serviceAccountId: account.serviceAccount.serviceAccountId,
			actor: "topology-test",
			operationId: "11111111-1111-4111-8111-111111111111",
			scope,
		});
		if ("preview" in credential) throw new Error("expected a live credential");
		expect(credential.credential.organizationId).toBe(organization.id);
	}, 15_000);
});
