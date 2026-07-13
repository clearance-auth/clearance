/**
 * Focused tests for canonical custom-role management:
 * list / create / update / validate with scope, audit, and permission rules.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	BUILT_IN_ROLE_SLUGS,
	ClearanceError,
	JsonStore,
	builtInRoleId,
	createRole,
	initProject,
	inspectRole,
	listEvents,
	listRoles,
	normalizeAndValidatePermissions,
	normalizeSnapshot,
	updateRole,
	validateRole,
} from "../index.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-roles-"));
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

describe("permission normalization", () => {
	it("normalizes case/whitespace, rejects empty/malformed/duplicates, stable order", () => {
		const perms = normalizeAndValidatePermissions(
			[" Member:Update ", "organization:read", "AC:Read", "member:create"],
			"roles.test",
		);
		expect(perms).toEqual([
			"ac:read",
			"member:create",
			"member:update",
			"organization:read",
		]);

		try {
			normalizeAndValidatePermissions([], "roles.test");
			expect.fail("expected empty reject");
		} catch (e) {
			expect(e).toBeInstanceOf(ClearanceError);
			expect((e as ClearanceError).code).toBe("ROLE_PERMISSIONS_EMPTY");
			expect((e as ClearanceError).stage).toBe("roles.test");
		}

		try {
			normalizeAndValidatePermissions(["not-a-permission"], "roles.test");
			expect.fail("expected malformed reject");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_PERMISSION_MALFORMED");
		}

		try {
			normalizeAndValidatePermissions(["  ", "x:y"], "roles.test");
			expect.fail("expected empty token reject");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_PERMISSION_EMPTY");
		}

		try {
			normalizeAndValidatePermissions(
				["member:create", "Member:Create"],
				"roles.test",
			);
			expect.fail("expected duplicate reject");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_PERMISSION_DUPLICATE");
		}
	});
});

describe("roles list/create/update/validate", () => {
	it("lists built-ins for empty snapshots and creates custom roles with audit", async () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Role App" });

		const listed = listRoles(store);
		expect(listed.filter((r) => r.kind === "built_in")).toHaveLength(
			BUILT_IN_ROLE_SLUGS.length,
		);
		expect(listed.map((r) => r.slug).slice(0, 3)).toEqual([
			"owner",
			"admin",
			"member",
		]);
		for (const r of listed) {
			expect(r.projectId).toBe(project.id);
			expect(r.environmentId).toBe(environment.id);
		}

		const role = await createRole(store, {
			name: "Billing Admin",
			permissions: ["billing:read", "Billing:Write", " invoices:void "],
			source: "cli",
		});
		expect(role.kind).toBe("custom");
		expect(role.slug).toBe("billing-admin");
		expect(role.permissions).toEqual([
			"billing:read",
			"billing:write",
			"invoices:void",
		]);
		expect(role.projectId).toBe(project.id);
		expect(role.environmentId).toBe(environment.id);

		const events = listEvents(store);
		const createEvt = events.find((e) => e.action === "roles.create");
		expect(createEvt).toBeTruthy();
		expect(createEvt!.outcome).toBe("success");
		expect(createEvt!.source).toBe("cli");
		expect(createEvt!.subjectType).toBe("role");
		expect(createEvt!.subjectId).toBe(role.id);
		expect(createEvt!.projectId).toBe(project.id);
		expect(createEvt!.environmentId).toBe(environment.id);
		expect(createEvt!.metadata).toMatchObject({
			slug: "billing-admin",
			permissionCount: 3,
		});
		// No secret-like material patterns
		expect(JSON.stringify(createEvt)).not.toMatch(/password|Bearer |sk_/i);

		const after = listRoles(store);
		expect(after.some((r) => r.id === role.id)).toBe(true);
		expect(after.filter((r) => r.kind === "custom")).toHaveLength(1);
	});

	it("rejects reserved built-in slugs and refuses built-in updates", async () => {
		const store = tempStore();
		initProject(store, { name: "Reserved" });

		for (const slug of BUILT_IN_ROLE_SLUGS) {
			try {
				await createRole(store, {
					name: slug,
					slug,
					permissions: ["ac:read"],
				});
				expect.fail(`should reserve ${slug}`);
			} catch (e) {
				expect((e as ClearanceError).code).toBe("ROLE_RESERVED");
				expect((e as ClearanceError).stage).toBe("roles.create");
			}
		}

		const ownerId = builtInRoleId("owner");
		try {
			await updateRole(store, ownerId, { name: "Super Owner" });
			expect.fail("built-in update should fail");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_BUILT_IN");
			expect((e as ClearanceError).stage).toBe("roles.update");
		}

		const owner = inspectRole(store, ownerId);
		expect(owner.kind).toBe("built_in");
		expect(owner.slug).toBe("owner");
	});

	it("updates custom roles with audit and enforces uniqueness", async () => {
		const store = tempStore();
		initProject(store, { name: "Update Roles" });

		const role = await createRole(store, {
			name: "Support",
			permissions: ["tickets:read"],
			source: "api",
		});
		await createRole(store, {
			name: "Auditor",
			permissions: ["audit:read"],
		});

		const updated = await updateRole(store, role.id, {
			name: "Support Lead",
			permissions: ["tickets:read", "tickets:assign"],
			source: "api",
		});
		expect(updated.name).toBe("Support Lead");
		expect(updated.permissions).toEqual(["tickets:assign", "tickets:read"]);
		// slug is stable identity key — not renamed on name change
		expect(updated.slug).toBe("support");

		const updateEvt = listEvents(store).find((e) => e.action === "roles.update");
		expect(updateEvt).toBeTruthy();
		expect(updateEvt!.source).toBe("api");
		expect(updateEvt!.outcome).toBe("success");
		expect(updateEvt!.metadata).toMatchObject({
			slug: "support",
			fields: expect.arrayContaining(["name", "permissions"]),
		});

		await expect(
			createRole(store, {
				name: "Support Dup",
				slug: "support",
				permissions: ["tickets:read"],
			}),
		).rejects.toThrow(/already exists/i);

		try {
			await createRole(store, {
				name: "Support Dup2",
				slug: "support",
				permissions: ["tickets:read"],
			});
			expect.fail("expected ROLE_EXISTS");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_EXISTS");
		}
	});

	it("validate requires scope and validates permission drafts without persisting", () => {
		const store = tempStore();
		initProject(store, { name: "Validate" });
		const before = (store.snapshot.roles ?? []).length;

		const ok = validateRole(store, {
			name: "Analyst",
			permissions: ["reports:read", "Reports:export"],
		});
		expect(ok.ok).toBe(true);
		expect(ok.slug).toBe("analyst");
		expect(ok.permissions).toEqual(["reports:export", "reports:read"]);
		expect((store.snapshot.roles ?? []).length).toBe(before);

		try {
			validateRole(store, {
				slug: "admin",
				permissions: ["ac:read"],
			});
			expect.fail("admin reserved");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_RESERVED");
			expect((e as ClearanceError).stage).toBe("roles.validate");
		}

		try {
			validateRole(store, {
				permissions: ["bad token"],
			});
			expect.fail("malformed");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_PERMISSION_MALFORMED");
		}
	});

	it("enforces projectId+environmentId scope on list/create/update/inspect", async () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Scope A" });

		const role = await createRole(store, {
			name: "Scoped",
			permissions: ["x:y"],
			scope: { projectId: project.id, environmentId: environment.id },
		});

		// Foreign scope sees only its own built-ins, not the custom role
		const foreignScope = {
			projectId: "proj_other_scope_xxxx",
			environmentId: "env_other_scope_xxxxx",
		};
		const foreignList = listRoles(store, { scope: foreignScope });
		expect(foreignList.every((r) => r.kind === "built_in")).toBe(true);
		expect(foreignList.every((r) => r.projectId === foreignScope.projectId)).toBe(
			true,
		);
		expect(foreignList.some((r) => r.id === role.id)).toBe(false);

		try {
			inspectRole(store, role.id, foreignScope);
			expect.fail("cross-scope inspect");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_NOT_FOUND");
			expect((e as ClearanceError).status).toBe(404);
		}

		try {
			await updateRole(store, role.id, {
				name: "Hijack",
				scope: foreignScope,
			});
			expect.fail("cross-scope update");
		} catch (e) {
			expect((e as ClearanceError).code).toBe("ROLE_NOT_FOUND");
		}

		// Create under foreign scope stores under that scope ids
		const foreignRole = await createRole(store, {
			name: "Foreign Custom",
			permissions: ["a:b"],
			scope: foreignScope,
		});
		expect(foreignRole.projectId).toBe(foreignScope.projectId);
		expect(listRoles(store, { scope: foreignScope }).some((r) => r.id === foreignRole.id)).toBe(
			true,
		);
		expect(listRoles(store).some((r) => r.id === foreignRole.id)).toBe(false);
	});
});

describe("snapshot backward compatibility", () => {
	it("normalizes snapshots missing roles and emptySnapshot includes roles", async () => {
		const dir = mkdtempSync(join(tmpdir(), "clr-roles-legacy-"));
		dirs.push(dir);
		const path = join(dir, "data.json");
		// Legacy snapshot without roles key
		writeFileSync(
			path,
			JSON.stringify({
				version: 1,
				releaseVersion: "0.1.0",
				projects: [],
				environments: [],
				principals: [],
				organizations: [],
				memberships: [],
				identityConnections: [],
				directoryConnections: [],
				events: [],
				traces: [],
				readinessReports: [],
				migrations: [],
				backups: [],
				sessions: [],
				setupLinks: [],
				meta: { schemaVersion: 1, config: {} },
			}),
		);

		const store = new JsonStore(path);
		expect(Array.isArray(store.snapshot.roles)).toBe(true);
		expect(store.snapshot.roles).toEqual([]);
		expect(store.resourceCounts().roles).toBe(0);

		// Direct normalize of partial object
		const partial = normalizeSnapshot({
			version: 1,
			releaseVersion: "0.1.0",
			projects: [],
			environments: [],
			principals: [],
			organizations: [],
			memberships: [],
			identityConnections: [],
			directoryConnections: [],
			// roles intentionally omitted
			events: [],
			traces: [],
			readinessReports: [],
			migrations: [],
			backups: [],
			sessions: [],
			setupLinks: [],
			meta: { schemaVersion: 1, config: {} },
		} as ReturnType<typeof normalizeSnapshot>);
		expect(partial.roles).toEqual([]);

		// Persist a role and reload
		initProject(store, { name: "Legacy Upgrade" });
		await createRole(store, { name: "After", permissions: ["z:a"] });
		const reloaded = JSON.parse(readFileSync(path, "utf8"));
		expect(Array.isArray(reloaded.roles)).toBe(true);
		expect(reloaded.roles).toHaveLength(1);
	});
});
