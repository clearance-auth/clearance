import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createSession, initProject } from "../services/core.js";
import { JsonStore } from "../store/json-store.js";
import type { ManagementStore } from "../store/types.js";
import { createManagementApplication } from "./management-application.js";

describe("ManagementApplication users", () => {
	it("previews without mutation and creates with operation context", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-application-"));
		const store = new JsonStore(join(directory, "data.json"));
		const { project, environment } = initProject(store, { name: "Application" });
		const application = createManagementApplication({ store });
		const context = {
			scope: {
				projectId: project.id,
				environmentId: environment.id,
			},
			actor: "application-test",
			source: "api" as const,
		};
		const before = {
			principals: store.snapshot.principals.length,
			events: store.snapshot.events.length,
		};

		await expect(application.users.create(context, {
			email: "  Preview@Example.test ",
			name: " Preview ",
			dryRun: true,
		})).resolves.toEqual({
			dryRun: true,
			email: "preview@example.test",
			name: "Preview",
		});
		expect(store.snapshot.principals).toHaveLength(before.principals);
		expect(store.snapshot.events).toHaveLength(before.events);

		const result = await application.users.create(context, {
			email: "Created@Example.test",
			name: "Created",
		});
		expect(result).toMatchObject({
			dryRun: false,
			user: {
				email: "created@example.test",
				projectId: project.id,
				environmentId: environment.id,
			},
		});
		expect(store.snapshot.events[0]).toMatchObject({
			action: "users.create",
			actor: context.actor,
			source: context.source,
			projectId: project.id,
			environmentId: environment.id,
		});

		await expect(application.users.create(context, {
			email: "CREATED@example.test",
			name: "Duplicate",
		})).rejects.toMatchObject({
			code: "USER_EXISTS",
			stage: "users.create",
		});
	});

	it("owns JSON update, disable, and delete lifecycle behavior", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-user-lifecycle-"));
		const store = new JsonStore(join(directory, "data.json"));
		const { project, environment } = initProject(store, { name: "Lifecycle" });
		const application = createManagementApplication({ store });
		const context = {
			scope: { projectId: project.id, environmentId: environment.id },
			actor: "lifecycle-test",
			source: "api" as const,
		};
		const created = await application.users.create(context, {
			email: "user@example.test",
			name: "Original",
		});
		if (created.dryRun) expect.fail("expected a created user");

		await expect(application.users.update(context, {
			id: created.user.id,
			name: "Preview",
			dryRun: true,
		})).resolves.toEqual({
			dryRun: true,
			id: created.user.id,
			name: "Preview",
		});
		expect(store.snapshot.principals[0]?.name).toBe("Original");

		const updated = await application.users.update(context, {
			id: created.user.id,
			name: "Updated",
			email: "UPDATED@example.test",
		});
		expect(updated).toMatchObject({
			dryRun: false,
			user: { name: "Updated", email: "updated@example.test", status: "active" },
		});

		const disabled = await application.users.disable(context, { id: created.user.id });
		expect(disabled).toMatchObject({ dryRun: false, user: { status: "disabled" } });

		const deleted = await application.users.delete(context, created.user.id);
		expect(deleted.status).toBe("deleted");
		const lifecycleEvents = store.snapshot.events.filter((event) =>
			["users.update", "users.disable", "users.delete"].includes(event.action),
		);
		expect(lifecycleEvents.map((event) => event.action)).toEqual([
			"users.delete",
			"users.disable",
			"users.update",
		]);
		expect(lifecycleEvents.every((event) => event.actor === context.actor)).toBe(true);
	});

	it("owns JSON organization, membership, and session lifecycle behavior", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-resource-lifecycle-"));
		const store = new JsonStore(join(directory, "data.json"));
		const { project, environment } = initProject(store, { name: "Resources" });
		const application = createManagementApplication({ store });
		const context = {
			scope: { projectId: project.id, environmentId: environment.id },
			actor: "resource-test",
			source: "api" as const,
		};
		const ownerResult = await application.users.create(context, {
			email: "owner@example.test",
			name: "Owner",
		});
		const memberResult = await application.users.create(context, {
			email: "member@example.test",
			name: "Member",
		});
		if (ownerResult.dryRun || memberResult.dryRun) expect.fail("expected created users");

		const organization = await application.organizations.create(context, {
			name: "Example Organization",
			ownerUserId: ownerResult.user.id,
		});
		await application.members.add(context, {
			organizationId: organization.id,
			principalId: ownerResult.user.id,
			role: "owner",
		});
		const member = await application.members.add(context, {
			organizationId: organization.id,
			principalId: memberResult.user.id,
			role: "member",
		});
		await expect(application.members.update(context, member.id, { role: "admin" }))
			.resolves.toMatchObject({ role: "admin", status: "active" });
		await expect(application.members.remove(context, member.id))
			.resolves.toMatchObject({ status: "removed" });

		const session = createSession(store, {
			principalId: ownerResult.user.id,
			environmentId: environment.id,
			scope: context.scope,
		});
		await expect(application.sessions.list(context, { limit: 10 }))
			.resolves.toMatchObject({ sessions: [{ id: session.id, status: "active" }] });
		await expect(application.sessions.inspect(context, session.id))
			.resolves.toMatchObject({ id: session.id, status: "active" });
		await expect(application.sessions.revoke(context, session.id))
			.resolves.toMatchObject({ session: { id: session.id, status: "revoked" } });

		await expect(application.organizations.update(context, organization.id, {
			name: "Renamed Organization",
		})).resolves.toMatchObject({ name: "Renamed Organization" });
		await expect(application.organizations.archive(context, organization.id, {
			confirm: true,
		})).resolves.toMatchObject({
			dryRun: false,
			organization: { status: "archived" },
		});
		expect(store.snapshot.events.filter((event) =>
			["orgs.update", "orgs.archive", "orgs.members.add", "orgs.members.update",
				"orgs.members.remove", "sessions.revoke"].includes(event.action),
		).every((event) => event.actor === context.actor)).toBe(true);
	});

	it("fails closed when a Postgres application lacks an auth runtime gateway", () => {
		expect(() => createManagementApplication({
			store: { backend: "postgres" } as ManagementStore,
		})).toThrow(/AuthRuntimeGateway/);
	});
});
