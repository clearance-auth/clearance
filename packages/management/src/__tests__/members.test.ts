/**
 * Management-only membership lifecycle: role validation, owner invariant,
 * add/update/remove, audit, cross-scope fail-closed.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	ClearanceError,
	JsonStore,
	addMember,
	createOrganization,
	createRole,
	createUser,
	initProject,
	inspectMembership,
	listEvents,
	listMembers,
	planMemberImport,
	executeMemberImportPlan,
	removeMember,
	resolveAssignableRole,
	resolveOperatorScope,
	updateMember,
} from "../index.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-members-"));
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

describe("resolveAssignableRole", () => {
	it("accepts built-ins and active custom roles in scope", async () => {
		const store = tempStore();
		initProject(store, { name: "Roles" });
		const scope = resolveOperatorScope(store);
		const org = createOrganization(store, { name: "Org" });
		const custom = await createRole(store, {
			name: "Billing",
			permissions: ["billing:read"],
		});

		expect(
			resolveAssignableRole(store, "owner", {
				scope,
				organizationId: org.id,
				stage: "test",
			}).slug,
		).toBe("owner");
		expect(
			resolveAssignableRole(store, "Admin", {
				scope,
				organizationId: org.id,
				stage: "test",
			}).slug,
		).toBe("admin");
		expect(
			resolveAssignableRole(store, custom.slug, {
				scope,
				organizationId: org.id,
				stage: "test",
			}),
		).toMatchObject({ slug: "billing", kind: "custom", roleId: custom.id });
	});

	it("rejects missing, malformed, disabled, archived, and org-bound foreign roles", async () => {
		const store = tempStore();
		initProject(store, { name: "Deny" });
		const scope = resolveOperatorScope(store);
		const org = createOrganization(store, { name: "A" });
		const other = createOrganization(store, { name: "B" });

		expect(() =>
			resolveAssignableRole(store, "", {
				scope,
				organizationId: org.id,
				stage: "t",
			}),
		).toThrow(ClearanceError);

		try {
			resolveAssignableRole(store, "!!!", {
				scope,
				organizationId: org.id,
				stage: "t",
			});
			expect.fail("expected ROLE_INVALID");
		} catch (e) {
			expect(e).toBeInstanceOf(ClearanceError);
			expect((e as ClearanceError).code).toBe("ROLE_INVALID");
		}

		try {
			resolveAssignableRole(store, "nope", {
				scope,
				organizationId: org.id,
				stage: "t",
			});
			expect.fail("expected ROLE_NOT_FOUND");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_NOT_FOUND");
		}

		const disabled = await createRole(store, {
			name: "Disabled Role",
			slug: "disabled-role",
			permissions: ["x:y"],
		});
		store.mutate((data) => {
			const r = data.roles.find((x) => x.id === disabled.id);
			if (r) r.status = "disabled";
		});
		try {
			resolveAssignableRole(store, "disabled-role", {
				scope,
				organizationId: org.id,
				stage: "t",
			});
			expect.fail("expected ROLE_DISABLED");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_DISABLED");
		}

		const archived = await createRole(store, {
			name: "Archived Role",
			slug: "archived-role",
			permissions: ["x:y"],
		});
		store.mutate((data) => {
			const r = data.roles.find((x) => x.id === archived.id);
			if (r) r.status = "archived";
		});
		try {
			resolveAssignableRole(store, "archived-role", {
				scope,
				organizationId: org.id,
				stage: "t",
			});
			expect.fail("expected ROLE_ARCHIVED");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_ARCHIVED");
		}

		const bound = await createRole(store, {
			name: "Org Bound",
			slug: "org-bound",
			permissions: ["x:y"],
		});
		store.mutate((data) => {
			const r = data.roles.find((x) => x.id === bound.id);
			if (r) r.organizationId = org.id;
		});
		expect(
			resolveAssignableRole(store, "org-bound", {
				scope,
				organizationId: org.id,
				stage: "t",
			}).slug,
		).toBe("org-bound");
		try {
			resolveAssignableRole(store, "org-bound", {
				scope,
				organizationId: other.id,
				stage: "t",
			});
			expect.fail("expected ROLE_NOT_FOUND for foreign org-bound role");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_NOT_FOUND");
		}
	});
});

describe("membership lifecycle (JsonStore)", () => {
	it("plans strict JSON and CSV imports before applying any membership", async () => {
		const store = tempStore();
		initProject(store, { name: "Import" });
		const first = createUser(store, { email: "first@import.test", name: "First" });
		const second = createUser(store, { email: "second@import.test", name: "Second" });
		const org = createOrganization(store, { name: "Import Org" });

		const json = planMemberImport(store, {
			organizationId: org.id,
			format: "json",
			content: JSON.stringify({ members: [{ email: " first@import.test ", role: " ADMIN " }, { principalId: second.id }] }),
		});
		expect(json.summary).toEqual({ total: 2, wouldAdd: 2, idempotent: 0 });
		expect(json.rows.map((row) => [row.principalId, row.role])).toEqual([[first.id, "admin"], [second.id, "member"]]);

		const applied = await executeMemberImportPlan(json, async (row) => addMember(store, {
			organizationId: org.id,
			principalId: row.principalId,
			role: row.role,
			source: "import",
			actor: "cli",
			auditSource: "import",
		}));
		expect(applied).toMatchObject({ completed: true, partial: false, success: 2, failure: 0 });
		const importEvents = listEvents(store, { limit: 10 }).filter((event) => event.action === "orgs.members.add");
		expect(importEvents).toHaveLength(2);
		expect(importEvents.every((event) => event.source === "import" && event.actor === "cli")).toBe(true);

		const csv = planMemberImport(store, {
			organizationId: org.id,
			format: "csv",
			content: `user,role\n${first.id},admin`,
		});
		expect(csv.rows[0]).toMatchObject({ principalId: first.id, role: "admin", idempotent: true });
		expect(() => planMemberImport(store, {
			organizationId: org.id,
			format: "csv",
			content: `user,role\n${first.id},member`,
		})).toThrow(expect.objectContaining({ code: "MEMBER_IMPORT_ROLE_CONFLICT" }));
		expect(() => planMemberImport(store, {
			organizationId: org.id,
			format: "json",
			content: JSON.stringify([{ principalId: first.id }, { email: "first@import.test" }]),
		})).toThrow(expect.objectContaining({ code: "MEMBER_IMPORT_DUPLICATE_PRINCIPAL" }));
		expect(() => planMemberImport(store, {
			organizationId: org.id,
			format: "csv",
			content: "email,unknown\nfirst@import.test,x",
		})).toThrow(expect.objectContaining({ code: "MEMBER_IMPORT_CSV_HEADER_INVALID" }));
		expect(() => planMemberImport(store, {
			organizationId: org.id,
			format: "json",
			content: "[]",
		})).toThrow(expect.objectContaining({ code: "MEMBER_IMPORT_EMPTY" }));

		const partial = await executeMemberImportPlan(json, async (row) => {
			if (row.principalId === second.id) {
				throw new ClearanceError({
					code: "IMPORT_TEST_FAILURE",
					message: "Synthetic failure",
					stage: "orgs.members.import.apply",
				});
			}
			return store.snapshot.memberships.find(
				(membership) => membership.principalId === row.principalId,
			)!;
		});
		expect(partial).toMatchObject({ completed: true, partial: true, success: 1, failure: 1 });
		expect(partial.results[1]).toMatchObject({
			principalId: second.id,
			status: "failure",
			error: { code: "IMPORT_TEST_FAILURE" },
		});
	});

	it("adds with built-in role, audits once, and is idempotent", () => {
		const store = tempStore();
		initProject(store, { name: "Mem" });
		const user = createUser(store, { email: "a@t.com", name: "A" });
		const org = createOrganization(store, { name: "Org" });

		const m1 = addMember(store, {
			organizationId: org.id,
			principalId: user.id,
			role: "admin",
			actor: "test",
			auditSource: "api",
		});
		expect(m1.role).toBe("admin");
		expect(m1.status).toBe("active");

		const m2 = addMember(store, {
			organizationId: org.id,
			principalId: user.id,
			role: "member",
		});
		expect(m2.id).toBe(m1.id);
		expect(m2.role).toBe("admin"); // duplicate does not change role

		const adds = listEvents(store, { limit: 50 }).filter(
			(e) => e.action === "orgs.members.add" && e.subjectId === m1.id,
		);
		expect(adds).toHaveLength(1);
		expect(listMembers(store, org.id)).toHaveLength(1);
	});

	it("adds custom scoped role and updates role with audit", async () => {
		const store = tempStore();
		initProject(store, { name: "Custom" });
		const user = createUser(store, { email: "c@t.com", name: "C" });
		const org = createOrganization(store, { name: "Org" });
		await createRole(store, {
			name: "Billing",
			permissions: ["billing:read"],
		});

		const m = addMember(store, {
			organizationId: org.id,
			principalId: user.id,
			role: "billing",
		});
		expect(m.role).toBe("billing");

		const updated = updateMember(store, m.id, {
			role: "admin",
			actor: "test",
			auditSource: "cli",
		});
		expect(updated.role).toBe("admin");
		expect(inspectMembership(store, m.id).role).toBe("admin");

		const updates = listEvents(store, { limit: 50 }).filter(
			(e) => e.action === "orgs.members.update" && e.subjectId === m.id,
		);
		expect(updates).toHaveLength(1);
	});

	it("denies invalid role with no write and no success audit", () => {
		const store = tempStore();
		initProject(store, { name: "Deny" });
		const user = createUser(store, { email: "d@t.com", name: "D" });
		const org = createOrganization(store, { name: "Org" });
		const before = listEvents(store, { limit: 200 }).length;

		try {
			addMember(store, {
				organizationId: org.id,
				principalId: user.id,
				role: "not-a-role",
			});
			expect.fail("expected ROLE_NOT_FOUND");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_NOT_FOUND");
		}

		expect(listMembers(store, org.id)).toHaveLength(0);
		expect(listEvents(store, { limit: 200 }).length).toBe(before);
	});

	it("enforces final-owner invariant on demote and remove", () => {
		const store = tempStore();
		initProject(store, { name: "Owner" });
		const owner = createUser(store, { email: "o@t.com", name: "O" });
		const other = createUser(store, { email: "x@t.com", name: "X" });
		const org = createOrganization(store, { name: "Org" });

		const ownerMem = addMember(store, {
			organizationId: org.id,
			principalId: owner.id,
			role: "owner",
		});
		const memberMem = addMember(store, {
			organizationId: org.id,
			principalId: other.id,
			role: "member",
		});

		try {
			updateMember(store, ownerMem.id, { role: "admin" });
			expect.fail("expected MEMBER_LAST_OWNER");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("MEMBER_LAST_OWNER");
		}
		try {
			removeMember(store, ownerMem.id);
			expect.fail("expected MEMBER_LAST_OWNER");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("MEMBER_LAST_OWNER");
		}

		// Promote second owner, then demote original
		updateMember(store, memberMem.id, { role: "owner" });
		const demoted = updateMember(store, ownerMem.id, { role: "member" });
		expect(demoted.role).toBe("member");
		const removed = removeMember(store, demoted.id);
		expect(removed.status).toBe("removed");
		expect(() => inspectMembership(store, demoted.id)).toThrow(/not found/i);
	});

	it("cross-scope membership ops fail closed as not found", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Scope" });
		const user = createUser(store, { email: "s@t.com", name: "S" });
		const org = createOrganization(store, { name: "Org" });
		const m = addMember(store, {
			organizationId: org.id,
			principalId: user.id,
			role: "member",
		});

		const foreign = {
			projectId: "proj_foreign_xxxxxx",
			environmentId: "env_foreign_xxxxxxx",
		};
		try {
			updateMember(store, m.id, { role: "admin", scope: foreign });
			expect.fail("expected MEMBER_NOT_FOUND");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("MEMBER_NOT_FOUND");
		}
		try {
			removeMember(store, m.id, { scope: foreign });
			expect.fail("expected MEMBER_NOT_FOUND");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("MEMBER_NOT_FOUND");
		}
		try {
			addMember(store, {
				organizationId: org.id,
				principalId: user.id,
				role: "admin",
				scope: foreign,
			});
			expect.fail("expected ORG_NOT_FOUND");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ORG_NOT_FOUND");
		}

		// Same scope still works
		const scope = {
			projectId: project.id,
			environmentId: environment.id,
		};
		expect(updateMember(store, m.id, { role: "admin", scope }).role).toBe(
			"admin",
		);
	});
});
