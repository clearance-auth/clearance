/**
 * Unit tests for canonical identity bridge and principal-derived scope
 * (JSON store — no Postgres required).
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { JsonStore } from "../store/json-store.js";
import {
	addMember,
	createOrganization,
	createSession,
	createUser,
	deleteUser,
	disableUser,
	initProject,
	inspectOrganization,
	inspectUser,
	listEvents,
	listUsers,
	updateUser,
} from "../services/core.js";
import {
	assertClientScopeHeaders,
	resolveOperatorScope,
} from "../services/scope.js";
import {
	syncRuntimeOrganizationToManagementDurable,
	syncRuntimeUserToManagement,
} from "../services/identity.js";
import { ClearanceError } from "../services/errors.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-id-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_PROJECT_ID;
	delete process.env.CLEARANCE_ENV_ID;
});

describe("canonical identity bridge", () => {
	it("syncs runtime user with identical stable id and scope", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Bridge App" });

		const runtimeId = "ba_runtime_user_abc123";
		const principal = syncRuntimeUserToManagement(store, {
			id: runtimeId,
			email: "signup@example.com",
			name: "Sign Up",
		});

		expect(principal.id).toBe(runtimeId);
		expect(principal.projectId).toBe(project.id);
		expect(principal.environmentId).toBe(environment.id);
		expect(listUsers(store).find((u) => u.id === runtimeId)?.email).toBe(
			"signup@example.com",
		);

		// Visible to management inspect with same id
		expect(inspectUser(store, runtimeId).id).toBe(runtimeId);

		const events = listEvents(store);
		expect(events.some((e) => e.action === "users.sync_runtime")).toBe(true);
		expect(JSON.stringify(events)).not.toMatch(/password|Bearer |scimtok_/i);
	});

	it("is idempotent and refuses parallel email records", () => {
		const store = tempStore();
		initProject(store, { name: "Idem" });

		syncRuntimeUserToManagement(store, {
			id: "id_1",
			email: "a@ex.com",
			name: "A",
		});
		const again = syncRuntimeUserToManagement(store, {
			id: "id_1",
			email: "a@ex.com",
			name: "A2",
		});
		expect(again.name).toBe("A2");
		expect(listUsers(store).filter((u) => u.email === "a@ex.com")).toHaveLength(
			1,
		);

		expect(() =>
			syncRuntimeUserToManagement(store, {
				id: "id_other",
				email: "a@ex.com",
				name: "Dup",
			}),
		).toThrow(ClearanceError);
	});

	it("syncs a runtime organization and owner with identical stable ids", async () => {
		const store = tempStore();
		initProject(store, { name: "Runtime Org" });
		const principal = syncRuntimeUserToManagement(store, {
			id: "runtime_user_owner",
			email: "owner@example.com",
			name: "Owner",
		});

		const runtimeOwnerMembershipId = "runtime_mem_owner_acme";
		const organization = await syncRuntimeOrganizationToManagementDurable(
			store,
			{
				id: "runtime_org_acme",
				name: "Acme",
				slug: "acme",
				ownerMembershipId: runtimeOwnerMembershipId,
			},
			principal.id,
		);

		expect(organization.id).toBe("runtime_org_acme");
		expect(inspectOrganization(store, organization.id).id).toBe(
			"runtime_org_acme",
		);
		const ownerMembership = store.snapshot.memberships.find(
			(m) =>
				m.organizationId === organization.id &&
				m.principalId === principal.id &&
				m.status === "active",
		);
		expect(ownerMembership?.role).toBe("owner");
		// Runtime and management owner membership ids must match immediately
		expect(ownerMembership?.id).toBe(runtimeOwnerMembershipId);
		expect(
			listEvents(store).filter((e) => e.action === "orgs.sync_runtime"),
		).toHaveLength(1);

		await syncRuntimeOrganizationToManagementDurable(
			store,
			{
				id: organization.id,
				name: "Acme Updated",
				slug: "acme",
				ownerMembershipId: runtimeOwnerMembershipId,
			},
			principal.id,
		);
		expect(store.snapshot.organizations).toHaveLength(1);
		const activeMemberships = store.snapshot.memberships.filter(
			(m) =>
				m.organizationId === organization.id &&
				m.principalId === principal.id &&
				m.status === "active",
		);
		expect(activeMemberships).toHaveLength(1);
		expect(activeMemberships[0]?.id).toBe(runtimeOwnerMembershipId);
		expect(store.snapshot.memberships).toHaveLength(1);
	});

	it("reconciles a divergent management owner membership id to the runtime id", async () => {
		const store = tempStore();
		initProject(store, { name: "Reconcile Mem" });
		const principal = syncRuntimeUserToManagement(store, {
			id: "runtime_user_reconcile",
			email: "reconcile@example.com",
			name: "Reconcile",
		});

		// First sync without runtime membership id mints a management-only id
		await syncRuntimeOrganizationToManagementDurable(
			store,
			{ id: "runtime_org_reconcile", name: "R", slug: "reconcile-org" },
			principal.id,
		);
		const minted = store.snapshot.memberships.find(
			(m) =>
				m.organizationId === "runtime_org_reconcile" &&
				m.principalId === principal.id,
		);
		expect(minted?.id).toBeTruthy();
		expect(minted?.id).not.toBe("runtime_mem_reconcile");

		// Second sync with runtime id rewrites management to the canonical id
		await syncRuntimeOrganizationToManagementDurable(
			store,
			{
				id: "runtime_org_reconcile",
				name: "R",
				slug: "reconcile-org",
				ownerMembershipId: "runtime_mem_reconcile",
			},
			principal.id,
		);
		const active = store.snapshot.memberships.filter(
			(m) =>
				m.organizationId === "runtime_org_reconcile" &&
				m.principalId === principal.id &&
				m.status === "active",
		);
		expect(active).toHaveLength(1);
		expect(active[0]?.id).toBe("runtime_mem_reconcile");
	});

	it("fails closed when owner membership id is bound to another principal", async () => {
		const store = tempStore();
		initProject(store, { name: "Conflict Mem" });
		const owner = syncRuntimeUserToManagement(store, {
			id: "owner_conflict",
			email: "owner-c@example.com",
			name: "Owner",
		});
		const other = syncRuntimeUserToManagement(store, {
			id: "other_conflict",
			email: "other-c@example.com",
			name: "Other",
		});
		await syncRuntimeOrganizationToManagementDurable(
			store,
			{
				id: "org_a",
				name: "A",
				slug: "org-a",
				ownerMembershipId: "mem_shared_conflict",
			},
			owner.id,
		);

		await expect(
			syncRuntimeOrganizationToManagementDurable(
				store,
				{
					id: "org_b",
					name: "B",
					slug: "org-b",
					ownerMembershipId: "mem_shared_conflict",
				},
				other.id,
			),
		).rejects.toMatchObject({ code: "MEMBERSHIP_ID_CONFLICT" });
	});
});

describe("principal-derived scope", () => {
	it("resolves scope from store after init", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Scoped" });
		const scope = resolveOperatorScope(store);
		expect(scope.projectId).toBe(project.id);
		expect(scope.environmentId).toBe(environment.id);
	});

	it("rejects when scope is absent", () => {
		const store = tempStore();
		expect(() => resolveOperatorScope(store)).toThrow(/SCOPE_REQUIRED|scope/i);
	});

	it("client headers cannot select a different scope", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Hdr" });
		const scope = resolveOperatorScope(store);
		assertClientScopeHeaders(scope, project.id, environment.id);
		try {
			assertClientScopeHeaders(scope, "proj_wrong", environment.id);
			expect.fail("expected SCOPE_PROJECT");
		} catch (e) {
			expect(e).toBeInstanceOf(ClearanceError);
			expect((e as ClearanceError).code).toBe("SCOPE_PROJECT");
		}
		try {
			assertClientScopeHeaders(scope, project.id, "env_wrong");
			expect.fail("expected SCOPE_ENVIRONMENT");
		} catch (e) {
			expect(e).toBeInstanceOf(ClearanceError);
			expect((e as ClearanceError).code).toBe("SCOPE_ENVIRONMENT");
		}
	});

	it("inspect fails closed across scopes", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "X" });
		const scope = { projectId: project.id, environmentId: environment.id };
		const user = createUser(store, {
			email: "ok@x.test",
			name: "Ok",
			projectId: project.id,
			environmentId: environment.id,
		});
		const org = createOrganization(store, {
			name: "Org",
			slug: "org-x",
			projectId: project.id,
			environmentId: environment.id,
		});

		// Foreign resources
		store.mutate((data) => {
			const now = new Date().toISOString();
			data.principals.push({
				id: "user_foreign",
				projectId: "proj_f",
				environmentId: "env_f",
				email: "f@f.test",
				name: "F",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
			data.organizations.push({
				id: "org_foreign",
				projectId: "proj_f",
				environmentId: "env_f",
				name: "F Org",
				slug: "f-org",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});

		expect(inspectUser(store, user.id, scope).email).toBe("ok@x.test");
		expect(inspectOrganization(store, org.id, scope).slug).toBe("org-x");
		expect(() => inspectUser(store, "user_foreign", scope)).toThrow(
			/not found/i,
		);
		expect(() => inspectOrganization(store, "org_foreign", scope)).toThrow(
			/not found/i,
		);
	});

	it("atomic user create puts audit in same mutation outcome", () => {
		const store = tempStore();
		initProject(store, { name: "Atomic" });
		const before = store.snapshot.events.length;
		createUser(store, { email: "atomic@test.com", name: "Atomic" });
		// Single mutate wrote principal + audit together — both visible
		expect(listUsers(store).some((u) => u.email === "atomic@test.com")).toBe(
			true,
		);
		expect(store.snapshot.events.length).toBe(before + 1);
		expect(store.snapshot.events[0]?.action).toBe("users.create");

		expect(() =>
			createUser(store, { email: "atomic@test.com", name: "Dup" }),
		).toThrow(/already exists/i);
		// Failed create must not add a second audit
		expect(
			store.snapshot.events.filter(
				(e) => e.action === "users.create" && e.message.includes("atomic@test.com"),
			),
		).toHaveLength(1);
	});

	it("atomic org create enforces slug uniqueness within scope", () => {
		const store = tempStore();
		initProject(store, { name: "Slug" });
		createOrganization(store, { name: "One", slug: "shared-slug" });
		expect(() =>
			createOrganization(store, { name: "Two", slug: "shared-slug" }),
		).toThrow(/slug/i);
		expect(store.snapshot.organizations.filter((o) => o.slug === "shared-slug")).toHaveLength(
			1,
		);
		expect(
			store.snapshot.events.filter((e) => e.action === "orgs.create"),
		).toHaveLength(1);
	});
});

describe("users update / disable / delete lifecycle", () => {
	it("updates name and email with audit and rejects empty patch", () => {
		const store = tempStore();
		initProject(store, { name: "Lifecycle" });
		const user = createUser(store, {
			email: "before@test.com",
			name: "Before",
		});

		expect(() => updateUser(store, user.id, {})).toThrow(/at least one/i);

		const updated = updateUser(store, user.id, {
			name: "After",
			email: "after@test.com",
			actor: "test",
			source: "api",
		});
		expect(updated.name).toBe("After");
		expect(updated.email).toBe("after@test.com");
		expect(inspectUser(store, user.id).email).toBe("after@test.com");
		expect(
			listEvents(store).some(
				(e) => e.action === "users.update" && e.subjectId === user.id,
			),
		).toBe(true);
	});

	it("disables user, revokes active sessions, and is scope-safe", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Disable" });
		const user = createUser(store, {
			email: "active@test.com",
			name: "Active",
		});
		const session = createSession(store, {
			principalId: user.id,
			environmentId: environment.id,
		});
		expect(session.status).toBe("active");

		const disabled = disableUser(store, user.id, { actor: "test", source: "cli" });
		expect(disabled.status).toBe("disabled");
		expect(
			store.snapshot.sessions.find((s) => s.id === session.id)?.status,
		).toBe("revoked");
		expect(
			listEvents(store).some(
				(e) =>
					e.action === "users.disable" &&
					e.subjectId === user.id &&
					(e.metadata as { revokedSessions?: number })?.revokedSessions === 1,
			),
		).toBe(true);

		// Still listable when disabled
		expect(listUsers(store).some((u) => u.id === user.id)).toBe(true);

		// Foreign principal fails closed
		store.mutate((data) => {
			const now = new Date().toISOString();
			data.principals.push({
				id: "user_foreign_disable",
				projectId: "proj_other",
				environmentId: "env_other",
				email: "foreign@x.test",
				name: "Foreign",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});
		const scope = { projectId: project.id, environmentId: environment.id };
		expect(() =>
			disableUser(store, "user_foreign_disable", { scope }),
		).toThrow(/not found/i);
		expect(() =>
			disableUser(store, "user_missing", { scope }),
		).toThrow(/not found/i);
	});

	it("soft-deletes user with audit, removes memberships, and fail-closes missing", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Delete" });
		const user = createUser(store, {
			email: "gone@test.com",
			name: "Gone",
		});
		const org = createOrganization(store, { name: "Mem Org" });
		const membership = addMember(store, {
			organizationId: org.id,
			principalId: user.id,
			role: "member",
		});
		const session = createSession(store, {
			principalId: user.id,
			environmentId: environment.id,
		});

		const deleted = deleteUser(store, user.id, {
			actor: "test",
			source: "cli",
		});
		expect(deleted.status).toBe("deleted");
		expect(listUsers(store).some((u) => u.id === user.id)).toBe(false);
		expect(() => inspectUser(store, user.id)).toThrow(/not found/i);
		expect(
			store.snapshot.memberships.find((m) => m.id === membership.id)?.status,
		).toBe("removed");
		expect(
			store.snapshot.sessions.find((s) => s.id === session.id)?.status,
		).toBe("revoked");
		expect(
			listEvents(store).some(
				(e) => e.action === "users.delete" && e.subjectId === user.id,
			),
		).toBe(true);

		// Second delete is fail-closed (already soft-deleted)
		expect(() => deleteUser(store, user.id)).toThrow(/not found/i);

		// Email collision does not resurrect deleted identity for a new create
		const recreated = createUser(store, {
			email: "gone@test.com",
			name: "New",
		});
		expect(recreated.id).not.toBe(user.id);
		expect(recreated.status).toBe("active");

		// Cross-scope fail closed
		store.mutate((data) => {
			const now = new Date().toISOString();
			data.principals.push({
				id: "user_foreign_del",
				projectId: "proj_other",
				environmentId: "env_other",
				email: "f@x.test",
				name: "F",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});
		expect(() =>
			deleteUser(store, "user_foreign_del", {
				scope: { projectId: project.id, environmentId: environment.id },
			}),
		).toThrow(/not found/i);
	});

	it("rejects email collision on update within scope", () => {
		const store = tempStore();
		initProject(store, { name: "Collide" });
		createUser(store, { email: "a@test.com", name: "A" });
		const b = createUser(store, { email: "b@test.com", name: "B" });
		expect(() =>
			updateUser(store, b.id, { email: "a@test.com" }),
		).toThrow(/already exists/i);
		expect(inspectUser(store, b.id).email).toBe("b@test.com");
	});

	it("re-enables a disabled user via update status=active", () => {
		const store = tempStore();
		initProject(store, { name: "Reenable" });
		const user = createUser(store, { email: "r@test.com", name: "R" });
		disableUser(store, user.id);
		const enabled = updateUser(store, user.id, { status: "active" });
		expect(enabled.status).toBe("active");
		expect(inspectUser(store, user.id).status).toBe("active");
	});

	it("rejects invalid status with no mutation and no success audit", () => {
		const store = tempStore();
		initProject(store, { name: "InvalidStatus" });
		const user = createUser(store, { email: "ok@test.com", name: "Ok" });
		const beforeEvents = listEvents(store).length;
		expect(() =>
			updateUser(store, user.id, {
				name: "ShouldNotApply",
				status: "deleted" as "active",
			}),
		).toThrow(/invalid status/i);
		expect(inspectUser(store, user.id).name).toBe("Ok");
		expect(inspectUser(store, user.id).status).toBe("active");
		expect(listEvents(store).length).toBe(beforeEvents);
		expect(() =>
			updateUser(store, user.id, { status: "nope" }),
		).toThrow(/invalid status/i);
	});
});

