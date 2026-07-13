/**
 * Core management contracts: env inspect/promote, orgs update/archive, users export.
 */
import {
	existsSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	JsonStore,
	ClearanceError,
	addMember,
	archiveOrganization,
	createEnvironment,
	createProject,
	createOrganization,
	createUser,
	exportUsers,
	initProject,
	inspectEnvironment,
	inspectOrganization,
	listEnvironments,
	listEvents,
	listMembers,
	listOrganizations,
	promoteEnvironment,
	updateOrganization,
	USERS_EXPORT_MAX_LIMIT,
} from "../index.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-core-contracts-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
});

describe("env inspect", () => {
	it("returns canonical environment and secret-free local status", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Inspect App" });
		createUser(store, { email: "a@ex.test", name: "A" });

		const result = inspectEnvironment(store);
		expect(result.environment.id).toBe(environment.id);
		expect(result.project?.id).toBe(project.id);
		expect(result.local.active).toBe(true);
		expect(result.local.resourceCounts.principals).toBe(1);
		expect(result.local.config.hasClearanceSecret).toBeTypeOf("boolean");
		expect(result.local.releaseVersion).toBeTruthy();
		expect(result.correlationId).toBeTruthy();

		const serialized = JSON.stringify(result);
		expect(serialized).not.toMatch(/sk_live_|Bearer |password|CLEARANCE_SECRET.{0,5}:/);
		// Presence flags only — no secret material
		expect(result.local.config).not.toHaveProperty("clearanceSecret");
		expect(result.local.config).not.toHaveProperty("databaseUrl");
	});

	it("fails closed for wrong-project environment ids", () => {
		const store = tempStore();
		initProject(store, { name: "Scoped" });
		expect(() => inspectEnvironment(store, "env_foreign")).toThrow(/not found/i);
	});
});

describe("project creation", () => {
	it("creates a distinct project without changing the active project or environment", () => {
		const store = tempStore();
		const initial = initProject(store, { name: "Primary App" });
		const created = createProject(store, { name: "Second App" });

		expect(created.id).not.toBe(initial.project.id);
		expect(store.snapshot.projects.map((project) => project.id)).toEqual([
			initial.project.id,
			created.id,
		]);
		expect(store.snapshot.meta.config.projectId).toBe(initial.project.id);
		expect(store.snapshot.meta.config.environmentId).toBe(initial.environment.id);
		expect(listEvents(store).filter((event) => event.action === "project.create")).toHaveLength(1);
	});

	it("rejects case-insensitive duplicate retries atomically without auditing", () => {
		const store = tempStore();
		createProject(store, { name: "Acme Auth" });
		const projectsBefore = store.snapshot.projects.length;
		const eventsBefore = store.snapshot.events.length;

		let thrown: unknown;
		try {
			createProject(store, { name: "  acme auth  " });
		} catch (error) {
			thrown = error;
		}

		expect(thrown).toBeInstanceOf(ClearanceError);
		expect(thrown).toMatchObject({
			code: "PROJECT_ALREADY_EXISTS",
			stage: "project.create",
			retryable: false,
		});
		expect(store.snapshot.projects).toHaveLength(projectsBefore);
		expect(store.snapshot.events).toHaveLength(eventsBefore);
	});
});

describe("env promote", () => {
	it("plans dry-run with structured deployment blocker and audits confirmed attempts", () => {
		const store = tempStore();
		const { environment: source } = initProject(store, { name: "Promote App" });
		const target = createEnvironment(store, {
			projectId: source.projectId,
			name: "production",
			kind: "production",
		});
		createUser(store, { email: "u@ex.test", name: "U" });

		const plan = promoteEnvironment(store, {
			to: target.slug,
			dryRun: true,
		});
		expect(plan.dryRun).toBe(true);
		expect(plan.applied).toBe(false);
		expect(plan.blocked).toBe(true);
		expect(plan.wouldChange).toBe(false);
		expect(plan.blockers.some((b) => b.code === "ENV_PROMOTE_DEPLOYMENT_UNSUPPORTED")).toBe(
			true,
		);
		expect(plan.plan.resourceCounts.principals).toBe(1);
		// Dry-run does not audit
		expect(listEvents(store).some((e) => e.action === "env.promote")).toBe(false);

		const confirmed = promoteEnvironment(store, {
			to: target.id,
			confirm: true,
			actor: "test",
			source: "cli",
		});
		expect(confirmed.dryRun).toBe(false);
		expect(confirmed.applied).toBe(false);
		expect(confirmed.blocked).toBe(true);
		expect(confirmed.auditAction).toBe("env.promote");
		const audit = listEvents(store).find((e) => e.action === "env.promote");
		expect(audit).toBeTruthy();
		expect(audit?.outcome).toBe("failure");
		expect(audit?.metadata).toMatchObject({ blocked: true });
		// No invented deployment rows
		expect((store.snapshot as { deployments?: unknown }).deployments).toBeUndefined();
	});

	it("is idempotent when source equals target", () => {
		const store = tempStore();
		const { environment } = initProject(store, { name: "Same" });
		const result = promoteEnvironment(store, {
			to: environment.id,
			confirm: true,
		});
		expect(result.idempotent).toBe(true);
		expect(result.blocked).toBe(false);
		expect(result.blockers).toEqual([]);
		expect(listEvents(store).some((e) => e.action === "env.promote")).toBe(true);
	});

	it("requires target and rejects missing target in project", () => {
		const store = tempStore();
		initProject(store, { name: "Need Target" });
		expect(() => promoteEnvironment(store, { to: "", dryRun: true })).toThrow(
			/target/i,
		);
		expect(() =>
			promoteEnvironment(store, { to: "env_missing", dryRun: true }),
		).toThrow(/not found/i);
	});
});

describe("orgs update", () => {
	it("updates name/slug, validates, is idempotent, audits actual changes only", () => {
		const store = tempStore();
		initProject(store, { name: "Org Update" });
		const org = createOrganization(store, { name: "Acme", slug: "acme" });

		const updated = updateOrganization(store, org.id, {
			name: "Acme Corp",
			slug: "acme-corp",
			actor: "test",
		});
		expect(updated.name).toBe("Acme Corp");
		expect(updated.slug).toBe("acme-corp");
		const audits = listEvents(store).filter((e) => e.action === "orgs.update");
		expect(audits.length).toBe(1);
		expect(audits[0]?.metadata).toMatchObject({
			fields: expect.arrayContaining(["name", "slug"]),
		});

		// Idempotent re-apply: no new audit
		updateOrganization(store, org.id, {
			name: "Acme Corp",
			slug: "acme-corp",
		});
		expect(listEvents(store).filter((e) => e.action === "orgs.update").length).toBe(1);

		expect(() =>
			updateOrganization(store, org.id, {}),
		).toThrow(/name or slug/i);

		expect(() =>
			updateOrganization(store, org.id, { slug: "BAD SLUG!" }),
		).toThrow(/slug/i);

		const other = createOrganization(store, { name: "Other", slug: "other" });
		expect(() =>
			updateOrganization(store, other.id, { slug: "acme-corp" }),
		).toThrow(/exists/i);

		// Wrong scope fails closed
		expect(() =>
			updateOrganization(store, org.id, {
				name: "X",
				scope: { projectId: "proj_x", environmentId: "env_x" },
			}),
		).toThrow(/not found/i);
	});
});

describe("orgs archive", () => {
	it("requires confirm, supports dry-run, is idempotent, denies membership access", () => {
		const store = tempStore();
		initProject(store, { name: "Archive App" });
		const user = createUser(store, { email: "m@ex.test", name: "M" });
		const org = createOrganization(store, { name: "To Archive" });
		addMember(store, {
			organizationId: org.id,
			principalId: user.id,
			role: "owner",
		});

		const dry = archiveOrganization(store, org.id, { dryRun: true });
		expect(dry.dryRun).toBe(true);
		expect(dry.wouldChange).toBe(true);
		expect(org.status).toBe("active");
		expect(inspectOrganization(store, org.id).status).toBe("active");
		expect(listEvents(store).some((e) => e.action === "orgs.archive")).toBe(false);

		// Without confirm → dry-run behavior
		const implicit = archiveOrganization(store, org.id, {});
		expect(implicit.dryRun).toBe(true);

		const archived = archiveOrganization(store, org.id, {
			confirm: true,
			actor: "test",
		});
		expect(archived.dryRun).toBe(false);
		expect(archived.wouldChange).toBe(true);
		expect(archived.organization.status).toBe("archived");
		expect(listEvents(store).some((e) => e.action === "orgs.archive")).toBe(true);

		// Hidden from list/inspect
		expect(listOrganizations(store).some((o) => o.id === org.id)).toBe(false);
		expect(() => inspectOrganization(store, org.id)).toThrow(/not found/i);

		// Membership access denied under shared services
		expect(() => listMembers(store, org.id)).toThrow(/not found/i);
		expect(() =>
			addMember(store, {
				organizationId: org.id,
				principalId: user.id,
				role: "member",
			}),
		).toThrow(/not found/i);

		// Idempotent re-archive
		const again = archiveOrganization(store, org.id, { confirm: true });
		expect(again.idempotent).toBe(true);
		expect(again.wouldChange).toBe(false);
		expect(
			listEvents(store).filter((e) => e.action === "orgs.archive").length,
		).toBe(1);
	});
});

describe("users export", () => {
	it("exports deterministically, redacts secrets, respects bounds and scope", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Export Users" });
		createUser(store, { email: "b@ex.test", name: "B" });
		createUser(store, { email: "a@ex.test", name: "A" });
		// Inject secret-shaped externalId that must redact
		store.mutate((data) => {
			const u = data.principals.find((p) => p.email === "a@ex.test");
			if (u) u.externalId = "sk_live_should_redact";
		});

		const first = exportUsers(store, {
			limit: 10,
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});
		const second = exportUsers(store, {
			limit: 10,
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});

		expect(first.schemaVersion).toBe(1);
		expect(first.kind).toBe("users.export");
		expect(first.count).toBe(2);
		expect(first.users.map((u) => u.email)).toEqual(second.users.map((u) => u.email));
		// Deterministic order: email asc
		expect(first.users.map((u) => u.email)).toEqual(["a@ex.test", "b@ex.test"]);

		const serialized = JSON.stringify(first);
		expect(serialized).not.toContain("sk_live_should_redact");
		expect(serialized).toMatch(/\[redacted\]/);

		const bounded = exportUsers(store, {
			limit: 1,
			skipAudit: true,
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(bounded.count).toBe(1);
		expect(bounded.truncated).toBe(true);

		expect(() =>
			exportUsers(store, {
				limit: USERS_EXPORT_MAX_LIMIT + 1,
				skipAudit: true,
			}),
		).toThrow(/limit/i);

		expect(() =>
			exportUsers(store, { format: "csv", skipAudit: true }),
		).toThrow(/format/i);

		const foreign = exportUsers(store, {
			skipAudit: true,
			scope: { projectId: "proj_other", environmentId: "env_other" },
		});
		expect(foreign.count).toBe(0);
		expect(foreign.users).toEqual([]);
	});

	it("writes atomic file artifacts, refuses overwrite, audits without path", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "File Users" });
		createUser(store, { email: "f@ex.test", name: "F" });
		const out = join(dirs[0]!, "users-out.json");

		const envelope = exportUsers(store, {
			outputPath: out,
			format: "json",
			limit: 50,
			scope: { projectId: project.id, environmentId: environment.id },
			actor: "test",
			source: "cli",
		});
		expect(envelope.outputPath).toBe(out);
		expect(existsSync(out)).toBe(true);
		const mode = statSync(out).mode & 0o777;
		// Owner rw only (platform may mask differently on some FS; require no group/other write)
		expect(mode & 0o022).toBe(0);

		const body = JSON.parse(readFileSync(out, "utf8"));
		expect(body.kind).toBe("users.export");
		expect(body.users.length).toBe(envelope.count);

		const audit = listEvents(store).find((e) => e.action === "users.export");
		expect(audit).toBeTruthy();
		expect(audit?.metadata).toMatchObject({ wroteFile: true });
		// Must not persist local filesystem path in audit metadata
		expect(JSON.stringify(audit?.metadata ?? {})).not.toContain(out);

		expect(() =>
			exportUsers(store, {
				outputPath: out,
				force: false,
				skipAudit: true,
				scope: { projectId: project.id, environmentId: environment.id },
			}),
		).toThrow(/exists|overwrite/i);

		const again = exportUsers(store, {
			outputPath: out,
			force: true,
			skipAudit: true,
			format: "jsonl",
			scope: { projectId: project.id, environmentId: environment.id },
		});
		expect(again.format).toBe("jsonl");
		const jsonl = readFileSync(out, "utf8").trim();
		if (again.count > 0) {
			const lines = jsonl.split("\n");
			expect(lines.length).toBe(again.count);
			expect(JSON.parse(lines[0]!).email).toBeTruthy();
		}

		// No-clobber leaves existing content if force is false after recreate check
		writeFileSync(out, "preexisting\n", "utf8");
		expect(() =>
			exportUsers(store, {
				outputPath: out,
				force: false,
				skipAudit: true,
				scope: { projectId: project.id, environmentId: environment.id },
			}),
		).toThrow(/exists/i);
		expect(readFileSync(out, "utf8")).toBe("preexisting\n");
	});
});

describe("listEnvironments", () => {
	it("lists project-scoped environments deterministically", () => {
		const store = tempStore();
		const { environment } = initProject(store, { name: "List Env" });
		createEnvironment(store, {
			projectId: environment.projectId,
			name: "preview",
			kind: "preview",
		});
		const list = listEnvironments(store);
		expect(list.length).toBe(2);
		expect(list.every((e) => e.projectId === environment.projectId)).toBe(true);
	});
});
