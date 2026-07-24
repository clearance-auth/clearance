import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const dirs: string[] = [];
const OPERATOR = "test-operator-token-32chars!!";

afterEach(() => {
	for (const directory of dirs.splice(0)) {
		rmSync(directory, { recursive: true, force: true });
	}
	delete process.env.CLEARANCE_DATA_PATH;
	delete process.env.CLEARANCE_OPERATOR_TOKEN;
	delete process.env.DATABASE_URL;
	delete process.env.CLEARANCE_CORS_ORIGINS;
	delete process.env.CLEARANCE_BACKUP_DIR;
	vi.resetModules();
});

describe("authenticated operational API contracts", () => {
	let app: { request: typeof fetch };
	let headers: Record<string, string>;
	let directory: string;

	beforeEach(async () => {
		directory = mkdtempSync(join(tmpdir(), "clr-api-ops-"));
		dirs.push(directory);
		process.env.CLEARANCE_DATA_PATH = join(directory, "data.json");
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_OPERATOR_TOKEN = OPERATOR;
		process.env.CLEARANCE_CORS_ORIGINS = "http://localhost:3100";
		process.env.CLEARANCE_BACKUP_DIR = join(directory, "backups");
		process.env.NODE_ENV = "development";
		headers = {
			authorization: `Bearer ${OPERATOR}`,
			"content-type": "application/json",
		};
		app = (await import("./server.js")).app as { request: typeof fetch };
		const initialized = await app.request("/v1/init", {
			method: "POST",
			headers,
			body: JSON.stringify({ name: "Operational API" }),
		});
		expect(initialized.status).toBe(200);
	});

	it("requires operator authentication for every operational route", async () => {
		for (const [method, path, body] of [
			["GET", "/v1/key-management/status", undefined],
			["POST", "/v1/key-management/plan", {}],
			["POST", "/v1/key-management/apply", {}],
			["GET", "/v1/dev", undefined],
			["POST", "/v1/backups", {}],
			["GET", "/v1/upgrades/check", undefined],
			["GET", "/v1/schema/status", undefined],
			["GET", "/v1/schema/credential-authority", undefined],
			["POST", "/v1/schema/credential-authority/arm", { confirm: true }],
			["POST", "/v1/schema/credential-authority/drain", { confirm: true }],
			["GET", "/v1/schema/store-v2", undefined],
			["POST", "/v1/migrations/plan", { source: "legacy", fixture: {} }],
			["GET", "/v1/organizations/org_test/authorization/effective/principal/user_test", undefined],
			["GET", "/v1/organizations/org_test/authorization/assignments", undefined],
			["PATCH", "/v1/organizations/org_test/authorization/assignments/principal/user_test", { roleIds: [] }],
			["POST", "/v1/organizations/org_test/authorization/reconcile", { confirm: true }],
			["GET", "/v1/organizations/org_test/service-accounts", undefined],
			["GET", "/v1/organizations/org_test/service-accounts/svc_test", undefined],
			["POST", "/v1/organizations/org_test/service-accounts", { name: "Automation", roleIds: [] }],
			["PATCH", "/v1/organizations/org_test/service-accounts/svc_test/status", { status: "disabled" }],
			["PATCH", "/v1/organizations/org_test/service-accounts/svc_test/status", { status: "active" }],
			["POST", "/v1/organizations/org_test/service-accounts/svc_test/credentials", {}],
			["POST", "/v1/organizations/org_test/service-accounts/svc_test/credentials/cred_test/rotate", {}],
			["POST", "/v1/organizations/org_test/service-accounts/svc_test/credentials/cred_test/revoke", {}],
		] as const) {
			const response = await app.request(path, {
				method,
				...(body === undefined ? {} : {
					headers: { "content-type": "application/json" },
					body: JSON.stringify(body),
				}),
			});
			expect(response.status, `${method} ${path}`).toBe(401);
		}
	});

	it("rejects normalized authorization on the JSON backend before authority access", async () => {
		for (const path of [
			"/v1/organizations/org_test/authorization/assignments?subjectKind=principal",
			"/v1/organizations/org_test/authorization/assignments?subjectId=user_test",
		]) {
			const response = await app.request(path, { headers });
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({
				error: { code: "AUTHORIZATION_POSTGRES_REQUIRED", stage: "authorization.api" },
			});
		}
	});

	it("rejects invalid authorization mutation input before the backend gate", async () => {
		const response = await app.request(
			"/v1/organizations/org_test/service-accounts/svc_test/credentials",
			{
				method: "POST",
				headers,
				body: "{not-json",
			},
		);
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({
			error: {
				code: "AUTHORIZATION_INPUT_INVALID",
				stage: "authorization.credentials.create",
			},
		});

		const missingRoleIds = await app.request(
			"/v1/organizations/org_test/service-accounts",
			{
				method: "POST",
				headers,
				body: JSON.stringify({ name: "Automation" }),
			},
		);
		expect(missingRoleIds.status).toBe(400);
		expect(await missingRoleIds.json()).toMatchObject({
			error: {
				code: "AUTHORIZATION_INPUT_INVALID",
				stage: "authorization.service_accounts.create",
			},
		});
	});

	it("rejects invalid key-management bodies before the PostgreSQL backend gate", async () => {
		for (const [path, body] of [
			["/v1/key-management/plan", "[]"],
			["/v1/key-management/plan", JSON.stringify({ unexpected: true })],
			[
				"/v1/key-management/apply",
				JSON.stringify({
					expectedPlanId: "a".repeat(64),
					dryRun: "true",
				}),
			],
			[
				"/v1/key-management/apply",
				JSON.stringify({
					expectedPlanId: "a".repeat(64),
					unexpected: true,
				}),
			],
		] as const) {
			const response = await app.request(path, { method: "POST", headers, body });
			expect(response.status, path).toBe(400);
			expect(await response.json()).toMatchObject({
				error: {
					code: "KEY_MANAGEMENT_INPUT_INVALID",
					stage: expect.stringMatching(/^key_management\.(plan|apply)$/),
				},
			});
		}
	});

	it("requires explicit confirmation before credential-authority arm or drain", async () => {
		for (const [path, body, code] of [
			[
				"/v1/schema/credential-authority/arm",
				{ deploymentId: "candidate-v03", expectedRuntimeCount: 2 },
				"CREDENTIAL_AUTHORITY_ARM_CONFIRMATION_REQUIRED",
			],
			[
				"/v1/schema/credential-authority/drain",
				{ deploymentId: "candidate-v03", drainId: "drain-v03" },
				"CREDENTIAL_AUTHORITY_DRAIN_CONFIRMATION_REQUIRED",
			],
		] as const) {
			const response = await app.request(path, {
				method: "POST",
				headers,
				body: JSON.stringify(body),
			});
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({ error: { code } });
		}
	});

	it("rejects malformed credential-authority arm inputs as structured 400s", async () => {
		for (const body of [
			{ confirm: true, deploymentId: "", expectedRuntimeCount: 2 },
			{ confirm: true, deploymentId: "candidate-v03", expectedRuntimeCount: "2" },
			{ confirm: true, deploymentId: "candidate-v03", expectedRuntimeCount: 0 },
			{ confirm: true, deploymentId: "candidate-v03", expectedRuntimeCount: 1.5 },
		]) {
			const response = await app.request(
				"/v1/schema/credential-authority/arm",
				{
					method: "POST",
					headers,
					body: JSON.stringify(body),
				},
			);
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({
				error: { code: "CREDENTIAL_AUTHORITY_ARM_INPUT_INVALID" },
			});
		}
	});

	it("rejects malformed credential-authority drain inputs as structured 400s", async () => {
		for (const body of [
			{ confirm: true, deploymentId: "", drainId: "drain-v03" },
			{ confirm: true, deploymentId: "candidate-v03", drainId: "" },
			{ confirm: true, deploymentId: "candidate-v03", drainId: 3 },
			{
				confirm: true,
				deploymentId: "candidate-v03",
				drainId: "x".repeat(201),
			},
		]) {
			const response = await app.request(
				"/v1/schema/credential-authority/drain",
				{
					method: "POST",
					headers,
					body: JSON.stringify(body),
				},
			);
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({
				error: { code: "CREDENTIAL_AUTHORITY_DRAIN_INPUT_INVALID" },
			});
		}
	});

	it("exposes every store-v2 route and rejects the JSON backend structurally", async () => {
		for (const [method, path, body] of [
			["GET", "/v1/schema/store-v2", undefined],
			["GET", "/v1/schema/store-v2/plan", undefined],
			["POST", "/v1/schema/store-v2/apply", { dryRun: true }],
			["GET", "/v1/schema/store-v2/verify", undefined],
			["POST", "/v1/schema/store-v2/rollback", { confirm: true }],
			["POST", "/v1/schema/store-v2/events/cutover", { confirm: true }],
			["POST", "/v1/schema/store-v2/events/rollback", { confirm: true }],
			["POST", "/v1/schema/store-v2/principals/cutover", { confirm: true }],
			["POST", "/v1/schema/store-v2/principals/rollback", { confirm: true }],
			["POST", "/v1/schema/store-v2/topology/cutover", { confirm: true }],
			["POST", "/v1/schema/store-v2/topology/rollback", { confirm: true }],
		] as const) {
			const response = await app.request(path, {
				method,
				headers,
				...(body === undefined ? {} : { body: JSON.stringify(body) }),
			});
			expect(response.status, `${method} ${path}`).toBe(400);
			expect(await response.json()).toMatchObject({
				error: {
					code: "STORE_V2_POSTGRES_REQUIRED",
					stage: expect.stringMatching(/^schema\.store-v2\./),
				},
			});
		}
	});

	it("preserves the legacy import CLI response contract through the API", async () => {
		const fixture = {
			source: "legacy",
			users: [{ id: "legacy-user", email: "legacy@example.test", name: "Legacy User" }],
			organizations: [{ id: "legacy-org", name: "Legacy Org", slug: "legacy-org" }],
			members: [{ userId: "legacy-user", organizationId: "legacy-org", role: "owner" }],
		};
		const dryRun = await app.request("/v1/import/legacy", {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture }),
		});
		expect(dryRun.status).toBe(200);
		expect(await dryRun.json()).toMatchObject({
			dryRun: true,
			storeBackend: "json",
			preview: { wouldCreate: { users: 1, organizations: 1, members: 1 } },
		});

		const applied = await app.request("/v1/import/legacy", {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture, confirm: true }),
		});
		expect(applied.status).toBe(200);
		expect(await applied.json()).toMatchObject({
			dryRun: false,
			storeBackend: "json",
			verification: { reconciled: true },
		});
	});

	it("runs legacy migration plan, apply, verify, status, and confirmed rollback through the API", async () => {
		const fixture = {
			source: "legacy",
			users: [{ id: "legacy-user", email: "legacy@example.test", name: "Legacy User" }],
			organizations: [{ id: "legacy-org", name: "Legacy Org", slug: "legacy-org" }],
			members: [{ userId: "legacy-user", organizationId: "legacy-org", role: "owner" }],
		};
		const planned = await app.request("/v1/migrations/plan", {
			method: "POST",
			headers,
			body: JSON.stringify({ source: "legacy", fixture }),
		});
		expect(planned.status).toBe(200);
		const planId = (await planned.json()).plan.id as string;

		const applied = await app.request(`/v1/migrations/${planId}/run`, {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture }),
		});
		expect(applied.status).toBe(200);
		expect((await applied.json()).plan.status).toBe("running");

		const verified = await app.request(`/v1/migrations/${planId}/verify`, {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture }),
		});
		expect(verified.status).toBe(200);
		expect((await verified.json()).reconciled).toBe(true);
		const status = await app.request(`/v1/migrations/${planId}`, { headers });
		expect(status.status).toBe(200);
		expect((await status.json()).plan.status).toBe("verified");

		const unconfirmed = await app.request(`/v1/migrations/${planId}/rollback`, {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture }),
		});
		expect(unconfirmed.status).toBe(400);
		expect((await unconfirmed.json()).error.code).toBe("MIGRATION_ROLLBACK_CONFIRM_REQUIRED");
		const rolledBack = await app.request(`/v1/migrations/${planId}/rollback`, {
			method: "POST",
			headers,
			body: JSON.stringify({ fixture, confirm: true }),
		});
		expect(rolledBack.status).toBe(200);
		expect((await rolledBack.json()).plan.status).toBe("rolled_back");
	});

	it("creates, verifies, and only restores a development backup after confirmation", async () => {
		const clientSelectedDirectory = join(directory, "client-selected-backups");
		const rejectedDirectory = await app.request("/v1/backups", {
			method: "POST",
			headers,
			body: JSON.stringify({ dir: clientSelectedDirectory }),
		});
		expect(rejectedDirectory.status).toBe(400);
		expect((await rejectedDirectory.json()).error.code).toBe(
			"BACKUP_DIRECTORY_SERVER_MANAGED",
		);
		const created = await app.request("/v1/backups", {
			method: "POST",
			headers,
			body: "{}",
		});
		expect(created.status).toBe(201);
		const backupId = (await created.json()).backup.id as string;
		const verified = await app.request(`/v1/backups/${backupId}/verify`, {
			method: "POST",
			headers,
			body: "{}",
		});
		expect(verified.status).toBe(200);
		const target = join(directory, "restored.json");
		writeFileSync(target, "must-not-be-overwritten", "utf8");
		const unconfirmed = await app.request(`/v1/backups/${backupId}/restore`, {
			method: "POST",
			headers,
			body: JSON.stringify({ target }),
		});
		expect(unconfirmed.status).toBe(400);
		const clientTarget = await app.request(`/v1/backups/${backupId}/restore`, {
			method: "POST",
			headers,
			body: JSON.stringify({ target, confirm: true }),
		});
		expect(clientTarget.status).toBe(400);
		expect((await clientTarget.json()).error.code).toBe(
			"BACKUP_RESTORE_TARGET_SERVER_MANAGED",
		);
		expect(readFileSync(target, "utf8")).toBe("must-not-be-overwritten");
		const restored = await app.request(`/v1/backups/${backupId}/restore`, {
			method: "POST",
			headers,
			body: JSON.stringify({ confirm: true }),
		});
		expect(restored.status).toBe(200);
		expect(dirname((await restored.json()).targetPath)).toBe(
			join(directory, "backups", "restores"),
		);
	});
});
