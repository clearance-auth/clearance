import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	JsonStore,
	addMember,
	createBackup,
	createEnvironment,
	createOrganization,
	createScimConnection,
	createSsoConnection,
	createUser,
	initProject,
	listEvents,
	loadLegacyFixture,
	migrationStatus,
	planMigration,
	previewMigration,
	restoreBackup,
	rollbackMigration,
	runDoctor,
	runMigration,
	runReadinessCheck,
	testScimConnection,
	testSsoConnection,
	upgradeCheck,
	verifyBackup,
	verifyMigration,
} from "../index.js";

const dirs: string[] = [];

function tempStore(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clearance-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}

afterEach(() => {
	for (const d of dirs.splice(0)) {
		rmSync(d, { recursive: true, force: true });
	}
});

describe("core management path", () => {
	it("init, users, orgs, events with audit", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Acme Auth" });
		expect(project.id).toMatch(/^proj_/);
		expect(environment.projectId).toBe(project.id);

		const user = createUser(store, {
			email: "admin@acme.test",
			name: "Admin",
		});
		const org = createOrganization(store, { name: "Acme Enterprise" });
		addMember(store, {
			organizationId: org.id,
			principalId: user.id,
			role: "admin",
		});

		const events = listEvents(store);
		expect(events.length).toBeGreaterThanOrEqual(3);
		expect(events.some((e) => e.action === "users.create")).toBe(true);
		expect(events.some((e) => e.action === "orgs.create")).toBe(true);
	});
});

describe("doctor", () => {
	it("reports secret/schema/telemetry checks", async () => {
		const store = tempStore();
		initProject(store, { name: "Doc" });
		const result = await runDoctor(store, {
			secrets: {
				CLEARANCE_SECRET: "super-secret-value-32chars!!",
				DATABASE_URL: undefined,
			},
		});
		expect(result.checks.find((c) => c.id === "secret")?.status).toBe("pass");
		expect(result.checks.find((c) => c.id === "telemetry-sink")?.status).toBe(
			"pass",
		);
		expect(result.ok).toBe(true);
	});

	it("uses deployment-internal health URLs instead of public loopback URLs", async () => {
		const server = createServer((request, response) => {
			response.statusCode =
				request.url === "/health" || request.url === "/api/health" ? 200 : 404;
			response.end("ok");
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const address = server.address() as AddressInfo;
		const internalUrl = `http://127.0.0.1:${address.port}`;
		try {
			const store = tempStore();
			initProject(store, { name: "Container Doctor" });
			const result = await runDoctor(store, {
				secrets: {
					CLEARANCE_SECRET: "super-secret-value-32chars!!",
					DATABASE_URL: undefined,
					CLEARANCE_API_URL: "http://127.0.0.1:1",
					CLEARANCE_CONSOLE_URL: "http://127.0.0.1:1",
					CLEARANCE_API_HEALTH_URL: internalUrl,
					CLEARANCE_CONSOLE_HEALTH_URL: internalUrl,
				},
			});
			expect(result.checks.find((c) => c.id === "api-health")?.status).toBe(
				"pass",
			);
			expect(
				result.checks.find((c) => c.id === "console-health")?.status,
			).toBe("pass");
			expect(result.ok).toBe(true);
		} finally {
			await new Promise<void>((resolve, reject) =>
				server.close((error) => (error ? reject(error) : resolve())),
			);
		}
	});
});

describe("enterprise SSO/SCIM + readiness", () => {
	it("positive path and wrong-issuer diagnostic", () => {
		const store = tempStore();
		initProject(store, { name: "Ent" });
		const org = createOrganization(store, { name: "Customer Co" });
		const sso = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://okta.example/oauth2/default",
			audience: "clearance-sp",
			domains: ["customer.com"],
		});
		const ok = testSsoConnection(store, sso.id, { fixture: "ok" });
		expect(ok.pass).toBe(true);
		expect(ok.trace.stage).toBe("assertion.accept");
		expect(ok.mode).toBe("simulation");
		expect(ok.trace.mode).toBe("simulation");

		expect(() =>
			testSsoConnection(store, sso.id, { fixture: "wrong-issuer" }),
		).toThrow(/issuer/i);

		expect(() =>
			testSsoConnection(store, sso.id, {
				fixture: "not-a-real-fixture" as "ok",
			}),
		).toThrow(/unknown|fail-closed/i);

		const scim = createScimConnection(store, {
			organizationId: org.id,
			provider: "okta",
		});
		const scimResult = testScimConnection(store, scim.id, { dryRun: true });
		expect(scimResult.pass).toBe(true);
		expect(scimResult.proposed.length).toBeGreaterThan(0);

		// apply one user for membership check
		testScimConnection(store, scim.id, {
			dryRun: false,
			users: [{ userName: "it@customer.com", displayName: "IT Admin", active: true }],
		});

		const report = runReadinessCheck(store, org.id);
		expect(report.checks.length).toBeGreaterThan(3);
		expect(report.signature).toMatch(/^[a-f0-9]{16}$/);
		expect(["ready", "attention", "blocked"]).toContain(report.overall);
		// Fixture passes are simulation — never liveCertified
		expect(report.conformance.liveCertified).toBe(false);
		expect(report.conformance.mode).toBe("simulation");
		expect(report.conformance.note).toMatch(/simulation|not live/i);
		const ssoTest = report.checks.find((c) => c.id === "sso.test");
		expect(ssoTest?.simulation).toBe(true);
		expect(ssoTest?.status).toBe("warn");
		// CLI and console share same report object shape
		expect(report.checks.map((c) => c.id).sort()).toEqual(
			[
				"org.exists",
				"sso.connection",
				"sso.test",
				"scim.connection",
				"scim.test",
				"roles.mapping",
			].sort(),
		);
	});

	it("does not persist secrets in audit metadata", () => {
		const store = tempStore();
		initProject(store, { name: "Sec" });
		const org = createOrganization(store, { name: "Org" });
		const sso = createSsoConnection(store, {
			organizationId: org.id,
			protocol: "oidc",
			provider: "okta",
			issuer: "https://okta.example/oauth2/default",
			clientSecret: "super-secret-client-value",
		});
		expect(sso.clientSecretFingerprint).toBeTruthy();
		const events = listEvents(store);
		const blob = JSON.stringify(events);
		expect(blob).not.toContain("super-secret-client-value");
		const snap = JSON.stringify(store.snapshot);
		expect(snap).not.toContain("super-secret-client-value");
	});
});

describe("migration", () => {
	it("plan/run/verify/rollback with count reconciliation", () => {
		const store = tempStore();
		initProject(store, { name: "Mig" });
		const dir = dirs[dirs.length - 1];
		const fixturePath = join(dir, "export.json");
		const fixture = {
			source: "legacy" as const,
			users: [
				{ id: "ba_u1", email: "a@ex.com", name: "A" },
				{ id: "ba_u2", email: "b@ex.com", name: "B" },
			],
			organizations: [{ id: "ba_o1", name: "Org One", slug: "org-one" }],
			members: [
				{ userId: "ba_u1", organizationId: "ba_o1", role: "admin" },
				{ userId: "ba_u2", organizationId: "ba_o1", role: "member" },
			],
		};
		writeFileSync(fixturePath, JSON.stringify(fixture));
		const loaded = loadLegacyFixture(fixturePath);
		const plan = planMigration(store, loaded);
		runMigration(store, plan.id, loaded, { dryRun: true });
		runMigration(store, plan.id, loaded, { dryRun: false });
		const verified = verifyMigration(store, plan.id, loaded);
		expect(verified.reconciled).toBe(true);
		expect(verified.actual.users).toBe(2);
		expect(verified.plan.checkpoint.phase).toBe("verified");
		expect(() => runMigration(store, plan.id, loaded)).toThrowError(
			expect.objectContaining({ code: "CLEARANCE_IMPORT_PLAN_STATE_INVALID" }),
		);

		// Deliberate real mismatch: remove one imported principal from the store
		// so verifyMigration's actual counts diverge from fixture expectations.
		const imported = store.snapshot.principals.find((p) => p.externalId === "ba_u2");
		expect(imported).toBeTruthy();
		store.mutate((data) => {
			data.principals = data.principals.filter((p) => p.id !== imported!.id);
			data.memberships = data.memberships.filter(
				(m) => m.principalId !== imported!.id,
			);
		});
		expect(() => verifyMigration(store, plan.id, loaded)).toThrow(
			/reconcil|mismatch/i,
		);
		expect(() => runMigration(store, plan.id, loaded)).toThrowError(
			expect.objectContaining({ code: "CLEARANCE_IMPORT_PLAN_STATE_INVALID" }),
		);

		expect(() => rollbackMigration(store, plan.id, loaded)).toThrowError(
			expect.objectContaining({ code: "CLEARANCE_IMPORT_ROLLBACK_USER_CHANGED" }),
		);

		const migEvents = listEvents(store).filter((e) =>
			e.action.startsWith("migration."),
		);
		expect(migEvents.length).toBeGreaterThanOrEqual(3);
	});

	it("rejects wrong-source and dangling-member fixtures before planning", () => {
		const store = tempStore();
		initProject(store, { name: "Mig errors" });
		const dir = dirs[dirs.length - 1];
		const wrongSource = join(dir, "wrong-source.json");
		const danglingMember = join(dir, "dangling-member.json");
		writeFileSync(wrongSource, JSON.stringify({ source: "clerk", users: [], organizations: [], members: [] }));
		writeFileSync(danglingMember, JSON.stringify({ source: "legacy", users: [], organizations: [], members: [{ userId: "missing", organizationId: "missing" }] }));
		for (const path of [wrongSource, danglingMember]) {
			try {
				loadLegacyFixture(path);
				expect.unreachable("fixture should be rejected");
			} catch (error) {
				expect(error).toMatchObject({ name: "ClearanceError", stage: "import.legacy.fixture" });
			}
		}
		expect(store.snapshot.migrations).toHaveLength(0);
	});

	it("rejects symlinked import files", () => {
		const store = tempStore();
		initProject(store, { name: "Symlink import" });
		const dir = dirs[dirs.length - 1];
		const target = join(dir, "target.json");
		const link = join(dir, "export.json");
		writeFileSync(target, JSON.stringify({ source: "legacy", users: [], organizations: [], members: [] }));
		symlinkSync(target, link);
		expect(() => loadLegacyFixture(link)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_FILE_UNREADABLE" }));
		expect(store.snapshot.migrations).toHaveLength(0);
	});

	it("reconciles pre-existing email and slug matches without claiming or deleting them", () => {
		const store = tempStore();
		initProject(store, { name: "Existing import targets" });
		const user = createUser(store, { email: "existing@example.com", name: "Existing" });
		const organization = createOrganization(store, { name: "Existing Org", slug: "existing-org" });
		const membership = addMember(store, {
			organizationId: organization.id,
			principalId: user.id,
			role: "member",
		});
		const fixture = {
			source: "legacy" as const,
			users: [{ id: "ba_existing_user", email: user.email, name: user.name }],
			organizations: [{ id: "ba_existing_org", name: organization.name, slug: organization.slug }],
			members: [{ userId: "ba_existing_user", organizationId: "ba_existing_org", role: "member" }],
		};

		const plan = planMigration(store, fixture);
		runMigration(store, plan.id, fixture);
		expect(verifyMigration(store, plan.id, fixture).reconciled).toBe(true);
		expect(store.snapshot.migrations[0].createdResourceIds).toEqual({
			users: [],
			organizations: [],
			memberships: [],
		});

		rollbackMigration(store, plan.id, fixture);
		expect(() => runMigration(store, plan.id, fixture)).toThrowError(
			expect.objectContaining({ code: "CLEARANCE_IMPORT_PLAN_STATE_INVALID" }),
		);
		expect(store.snapshot.principals.some((candidate) => candidate.id === user.id)).toBe(true);
		expect(store.snapshot.organizations.some((candidate) => candidate.id === organization.id)).toBe(true);
		expect(store.snapshot.memberships.some((candidate) => candidate.id === membership.id)).toBe(true);
	});

	it("binds plans to the active project and environment for every plan operation", () => {
		const store = tempStore();
		const { project, environment } = initProject(store, { name: "Scoped migration" });
		const other = createEnvironment(store, { projectId: project.id, name: "preview", kind: "preview" });
		const fixture = { source: "legacy" as const, users: [], organizations: [], members: [] };
		const plan = planMigration(store, fixture);
		expect(plan).toMatchObject({ projectId: project.id, environmentId: environment.id });

		const previousProject = process.env.CLEARANCE_PROJECT_ID;
		const previousEnvironment = process.env.CLEARANCE_ENV_ID;
		process.env.CLEARANCE_PROJECT_ID = project.id;
		process.env.CLEARANCE_ENV_ID = other.id;
		try {
			for (const operation of [
				() => migrationStatus(store, plan.id),
				() => runMigration(store, plan.id, fixture),
				() => verifyMigration(store, plan.id, fixture),
				() => rollbackMigration(store, plan.id, fixture),
			]) {
				expect(operation).toThrowError(expect.objectContaining({ code: "MIGRATION_NOT_FOUND" }));
			}
			const otherPlan = planMigration(store, fixture);
			expect(otherPlan).toMatchObject({ projectId: project.id, environmentId: other.id });
		} finally {
			if (previousProject === undefined) delete process.env.CLEARANCE_PROJECT_ID;
			else process.env.CLEARANCE_PROJECT_ID = previousProject;
			if (previousEnvironment === undefined) delete process.env.CLEARANCE_ENV_ID;
			else process.env.CLEARANCE_ENV_ID = previousEnvironment;
		}
	});

	it("rejects existing membership role conflicts in preview and run, and verifies fixture roles exactly", () => {
		const store = tempStore();
		initProject(store, { name: "Membership role migration" });
		const user = createUser(store, { email: "member@example.com", name: "Member" });
		const organization = createOrganization(store, { name: "Role Org", slug: "role-org" });
		const membership = addMember(store, { organizationId: organization.id, principalId: user.id, role: "admin" });
		const fixture = {
			source: "legacy" as const,
			users: [{ id: "ba_member", email: user.email, name: user.name }],
			organizations: [{ id: "ba_org", name: organization.name, slug: organization.slug }],
			members: [{ userId: "ba_member", organizationId: "ba_org", role: "member" }],
		};
		expect(() => previewMigration(store, fixture)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_MEMBERSHIP_ROLE_CONFLICT" }));
		expect(() => planMigration(store, fixture)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_MEMBERSHIP_ROLE_CONFLICT" }));

		store.mutate((data) => {
			data.memberships[data.memberships.findIndex((candidate) => candidate.id === membership.id)]!.role = "member";
		});
		const plan = planMigration(store, fixture);
		store.mutate((data) => {
			data.memberships[data.memberships.findIndex((candidate) => candidate.id === membership.id)]!.role = "admin";
		});
		expect(() => runMigration(store, plan.id, fixture)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_MEMBERSHIP_ROLE_CONFLICT" }));

		store.mutate((data) => {
			data.memberships[data.memberships.findIndex((candidate) => candidate.id === membership.id)]!.role = "member";
		});
		runMigration(store, plan.id, fixture);
		store.mutate((data) => {
			data.memberships[data.memberships.findIndex((candidate) => candidate.id === membership.id)]!.role = "admin";
		});
		expect(() => verifyMigration(store, plan.id, fixture)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_MEMBERSHIP_ROLE_CONFLICT" }));
	});

	it("keeps the rollback ledger immutable and fails closed when created resources drift", () => {
		const store = tempStore();
		initProject(store, { name: "Rollback ledger" });
		const fixture = {
			source: "legacy" as const,
			users: [{ id: "ba_user", email: "rollback@example.com", name: "Before" }],
			organizations: [{ id: "ba_org", name: "Before Org", slug: "before-org" }],
			members: [{ userId: "ba_user", organizationId: "ba_org", role: "member" }],
		};
		const plan = planMigration(store, fixture);
		const imported = runMigration(store, plan.id, fixture);
		const originalLedger = JSON.parse(JSON.stringify(imported.rollbackResourceState));
		expect(() => runMigration(store, plan.id, fixture)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_PLAN_STATE_INVALID" }));
		expect(migrationStatus(store, plan.id).rollbackResourceState).toEqual(originalLedger);

		store.mutate((data) => {
			const principal = data.principals.find((candidate) => candidate.id === imported.createdResourceIds!.users[0]);
			const organization = data.organizations.find((candidate) => candidate.id === imported.createdResourceIds!.organizations[0]);
			const membership = data.memberships.find((candidate) => candidate.id === imported.createdResourceIds!.memberships[0]);
			principal!.name = "Changed";
			principal!.status = "disabled";
			organization!.name = "Changed Org";
			organization!.status = "archived";
			membership!.status = "removed";
		});
		expect(() => rollbackMigration(store, plan.id, fixture)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_ROLLBACK_USER_CHANGED" }));

		store.mutate((data) => {
			const principal = data.principals.find((candidate) => candidate.id === imported.createdResourceIds!.users[0]);
			principal!.name = "Before";
			principal!.status = "active";
		});
		expect(() => rollbackMigration(store, plan.id, fixture)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_ROLLBACK_ORGANIZATION_CHANGED" }));

		store.mutate((data) => {
			const organization = data.organizations.find((candidate) => candidate.id === imported.createdResourceIds!.organizations[0]);
			organization!.name = "Before Org";
			organization!.status = "active";
		});
		expect(() => rollbackMigration(store, plan.id, fixture)).toThrowError(expect.objectContaining({ code: "CLEARANCE_IMPORT_ROLLBACK_MEMBERSHIP_CHANGED" }));
	});
});

describe("backup and upgrade", () => {
	it("create/verify/restore and upgrade check", () => {
		const store = tempStore();
		initProject(store, { name: "Ops" });
		createUser(store, { email: "ops@test.com", name: "Ops" });
		const bak = createBackup(store);
		const verified = verifyBackup(store, bak.id);
		expect(verified.verified).toBe(true);

		const isolated = join(dirs[dirs.length - 1], "isolated-restore.json");
		const restored = restoreBackup(store, bak.id, isolated);
		expect(restored.counts.projects).toBe(1);
		expect(restored.checksum).toBe(bak.checksum);

		const upgrade = upgradeCheck(store);
		expect(upgrade.current).toBeTruthy();
		expect(upgrade.runtimeBaseline).toContain("1.6.23");
		expect(upgrade.action).toBe("none");
	});
});
