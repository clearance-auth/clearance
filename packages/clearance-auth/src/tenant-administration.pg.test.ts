import { randomUUID } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { ClearanceAuthBundle } from "./public-types/index.js";
import { createClearanceAuth } from "./create-auth.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const probe = new pg.Pool({
	connectionString: DATABASE_URL,
	connectionTimeoutMillis: 500,
});
let available = false;
try {
	await probe.query("SELECT 1");
	available = true;
} catch {
	if (process.env.CLEARANCE_REQUIRE_PG_TESTS === "1") {
		throw new Error(
			`Tenant administration tests require PostgreSQL at ${DATABASE_URL}`,
		);
	}
} finally {
	await probe.end();
}

describe.sequential.skipIf(!available)(
	"PostgreSQL tenant administration",
	() => {
		const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
		const schema = `tenant_admin_${suffix}`;
		const projectId = `project_${suffix}`;
		const environmentId = `environment_${suffix}`;
		const secret = "tenant-administration-product-test-secret!!";
		const admin = new pg.Pool({ connectionString: DATABASE_URL });
		let bundle: ClearanceAuthBundle;
		let pool: pg.Pool;
		let headers: Headers;
		let organizationId: string;
		let ownerId: string;
		let targetId: string;

		const tenantRequest = async (
			path: string,
				options?: {
					body?: Record<string, unknown>;
					requestId?: string;
					authorization?: string;
					headers?: Headers;
				},
			) => {
				const requestHeaders = new Headers(options?.headers ?? headers);
			requestHeaders.set("content-type", "application/json");
			requestHeaders.set(
				"x-request-id",
				options?.requestId ?? `tenant-${randomUUID()}`,
			);
			if (options?.authorization) {
				requestHeaders.set("authorization", options.authorization);
			}
			return bundle.auth.handler(
				new Request(`http://localhost:3300/api/auth${path}`, {
					method: options?.body ? "POST" : "GET",
					headers: requestHeaders,
					...(options?.body
						? { body: JSON.stringify(options.body) }
						: {}),
				}),
			);
		};

		beforeAll(async () => {
			await admin.query(`CREATE SCHEMA "${schema}"`);
			const scopedUrl = new URL(DATABASE_URL);
			scopedUrl.searchParams.set("options", `-csearch_path=${schema}`);
			pool = new pg.Pool({ connectionString: scopedUrl.toString() });
			bundle = createClearanceAuth({
				baseURL: "http://localhost:3300",
				secret,
				databaseUrl: scopedUrl.toString(),
				enableSso: false,
				enableScim: false,
				passkeys: false,
				rateLimitEnabled: false,
				authenticationPolicy: { projectId, environmentId },
				authorization: { projectId, environmentId, schema },
				runtimeAudit: { projectId, environmentId, schema },
				authenticationSecurity: {
					twoFactor: { enabled: false },
					breachedPassword: { enabled: false },
				},
			});
			await bundle.migrate();

			const owner = await bundle.auth.api.signUpEmail({
				body: {
					email: `owner-${suffix}@example.test`,
					password: "correct-horse-battery-staple",
					name: "Tenant Owner",
				},
			});
			ownerId = owner.user.id;
			const signIn = await bundle.auth.handler(
				new Request("http://localhost:3300/api/auth/sign-in/email", {
					method: "POST",
					headers: {
						"content-type": "application/json",
						origin: "http://localhost:3300",
					},
					body: JSON.stringify({
						email: `owner-${suffix}@example.test`,
						password: "correct-horse-battery-staple",
					}),
				}),
			);
			expect(signIn.status).toBe(200);
			const sessionCookie = signIn.headers
				.getSetCookie()
				.map((cookie) => cookie.split(";", 1)[0]!)
				.find((cookie) =>
					cookie.startsWith("clearance.session_token="),
				);
			expect(sessionCookie).toBeDefined();
			headers = new Headers({
				cookie: sessionCookie!,
				origin: "http://localhost:3300",
			});
			const organizationResponse = await bundle.auth.api.createOrganization({
				body: {
					name: "Tenant Administration",
					slug: `tenant-admin-${suffix}`,
				},
				headers,
				asResponse: true,
			});
			expect(organizationResponse.status).toBe(200);
			const organization = (await organizationResponse.json()) as {
				id: string;
			};
			organizationId = organization.id;
			const activeSessionCookie = organizationResponse.headers
				.getSetCookie()
				.map((cookie) => cookie.split(";", 1)[0]!)
				.find((cookie) =>
					cookie.startsWith("clearance.session_token="),
				);
			expect(activeSessionCookie).toBeDefined();
			headers.set("cookie", activeSessionCookie!);

			const target = await bundle.auth.api.signUpEmail({
				body: {
					email: `target-${suffix}@example.test`,
					password: "correct-horse-battery-staple",
					name: "Tenant Target",
				},
			});
			targetId = target.user.id;
			await pool.query(
				`INSERT INTO member (id, "organizationId", "userId", role, "createdAt")
				 VALUES ($1, $2, $3, 'member', now())`,
				[`member_${suffix}`, organizationId, targetId],
			);
		});

		afterAll(async () => {
			await bundle?.destroy();
			await pool?.end();
			await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await admin.end();
		});

		it("enforces the tenant boundary and commits authority plus one redacted audit atomically", async () => {
			const assignmentRequestId = `tenant-assignment-${suffix}`;
			const beforeTarget = await bundle.authorization!.readEffective({
				organizationId,
				subject: { kind: "principal", id: targetId },
			});
			const replaced = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/authorization/assignments/replace`,
				{
					requestId: assignmentRequestId,
					body: {
						subject: { kind: "principal", id: targetId },
						roleIds: ["role_builtin_member"],
						expectedRevision: beforeTarget.revision,
						dryRun: false,
						confirm: true,
					},
				},
			);
			expect(replaced.status, await replaced.clone().text()).toBe(200);
			const replacedBody = (await replaced.json()) as {
				revision: string;
				previousRevision: string;
			};
			expect(BigInt(replacedBody.revision)).toBe(
				BigInt(replacedBody.previousRevision) + 1n,
			);
			await expect(
				bundle.authorization!.readEffective({
					organizationId,
					subject: { kind: "principal", id: targetId },
				}),
			).resolves.toMatchObject({
				roleIds: ["role_builtin_member"],
				revision: replacedBody.revision,
			});
			const assignmentAudits = await pool.query<{
				actor: string;
				action: string;
				subject_id: string;
				metadata: Record<string, unknown>;
			}>(
				`SELECT actor, action, subject_id, metadata
				 FROM "${schema}".clearance_runtime_audit_events
				 WHERE correlation_id = $1`,
				[assignmentRequestId],
			);
			expect(assignmentAudits.rows).toHaveLength(1);
			expect(assignmentAudits.rows[0]).toMatchObject({
				actor: ownerId,
				action: "tenant.authorization.assignments.replace",
				subject_id: targetId,
			});
			expect(JSON.stringify(assignmentAudits.rows[0])).not.toMatch(
				/cookie|secret|bearer|jwt|api[-_]?key/i,
			);

			const lifecycleClient = await pool.connect();
			let orderedTenantMutation: Promise<Response> | undefined;
			try {
				await lifecycleClient.query("BEGIN");
				const lifecycleBackend = await lifecycleClient.query<{ pid: number }>(
					"SELECT pg_backend_pid() AS pid",
				);
				const lifecyclePid = lifecycleBackend.rows[0]!.pid;
					await lifecycleClient.query(
						`UPDATE "user" SET name = name
						 WHERE id = $1`,
						[targetId],
					);
					orderedTenantMutation = tenantRequest(
					`/tenant/v1/organizations/${organizationId}/authorization/assignments/replace`,
					{
						body: {
							subject: { kind: "principal", id: targetId },
							roleIds: ["role_builtin_member"],
							dryRun: false,
							confirm: true,
						},
					},
				);
				let tenantWaitingOnLifecycle = false;
				for (let attempt = 0; attempt < 100; attempt += 1) {
					const waiting = await pool.query<{ blocked: boolean }>(
						`SELECT EXISTS (
							SELECT 1
							FROM pg_stat_activity activity
							WHERE activity.pid <> $1
							  AND $1 = ANY(pg_blocking_pids(activity.pid))
						) AS blocked`,
						[lifecyclePid],
					);
					if (waiting.rows[0]?.blocked === true) {
						tenantWaitingOnLifecycle = true;
						break;
					}
					await new Promise((resolve) => setTimeout(resolve, 10));
					}
					expect(tenantWaitingOnLifecycle).toBe(true);
					await lifecycleClient.query("SET LOCAL lock_timeout = '3s'");
					await lifecycleClient.query(
						`UPDATE member SET role = role
						 WHERE "organizationId" = $1 AND "userId" = $2`,
						[organizationId, targetId],
					);
					await lifecycleClient.query(
					"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
					[`${schema}:clearance:authorization-mutation-v1`],
				);
				await lifecycleClient.query("COMMIT");
				const orderedResponse = await orderedTenantMutation;
				expect(
					orderedResponse.status,
					await orderedResponse.clone().text(),
				).toBe(200);
			} catch (error) {
				await lifecycleClient.query("ROLLBACK").catch(() => undefined);
				await orderedTenantMutation?.catch(() => undefined);
				throw error;
			} finally {
				lifecycleClient.release();
			}

			const bearerReplay = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/authorization/roles`,
				{ authorization: "Bearer must-not-be-accepted" },
			);
			expect(bearerReplay.status).toBe(401);

			await bundle.authorization!.upsertRole({
				role: {
					roleId: `role_escalated_${suffix}`,
					organizationId,
					slug: `escalated-${suffix}`,
					name: "Escalated",
					description: null,
					builtIn: false,
					status: "active",
				},
				actions: ["billing:delete"],
			});
			const escalated = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/authorization/assignments/replace`,
				{
					body: {
						subject: { kind: "principal", id: targetId },
						roleIds: [`role_escalated_${suffix}`],
						dryRun: false,
						confirm: true,
					},
				},
			);
			expect(escalated.status).toBe(403);
			await expect(
				bundle.authorization!.readEffective({
					organizationId,
					subject: { kind: "principal", id: targetId },
				}),
			).resolves.toMatchObject({ roleIds: ["role_builtin_member"] });

			const lastOwner = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/authorization/assignments/replace`,
				{
					body: {
						subject: { kind: "principal", id: ownerId },
						roleIds: ["role_builtin_member"],
						dryRun: false,
						confirm: true,
					},
				},
			);
			expect(lastOwner.status).toBe(409);
			await expect(
				bundle.authorization!.readEffective({
					organizationId,
					subject: { kind: "principal", id: ownerId },
				}),
			).resolves.toMatchObject({ roleIds: ["role_builtin_owner"] });

			const superior = await bundle.auth.api.signUpEmail({
				body: {
					email: `superior-${suffix}@example.test`,
					password: "correct-horse-battery-staple",
					name: "Tenant Superior",
				},
			});
			await pool.query(
				`INSERT INTO member (id, "organizationId", "userId", role, "createdAt")
				 VALUES ($1, $2, $3, 'member', now())`,
				[`superior_member_${suffix}`, organizationId, superior.user.id],
			);
			await bundle.authorization!.upsertRole({
				role: {
					roleId: `role_superior_${suffix}`,
					organizationId,
					slug: `superior-${suffix}`,
					name: "Superior",
					description: null,
					builtIn: false,
					status: "active",
				},
				actions: ["ac:read", "organization:delete"],
			});
			await bundle.authorization!.replaceSubjectRoles({
				organizationId,
				subject: { kind: "principal", id: superior.user.id },
				roleIds: [`role_superior_${suffix}`],
			});
			await bundle.authorization!.replaceSubjectRoles({
				organizationId,
				subject: { kind: "principal", id: targetId },
				roleIds: ["role_builtin_admin"],
			});
			const adminSignIn = await bundle.auth.handler(
				new Request("http://localhost:3300/api/auth/sign-in/email", {
					method: "POST",
					headers: {
						"content-type": "application/json",
						origin: "http://localhost:3300",
					},
					body: JSON.stringify({
						email: `target-${suffix}@example.test`,
						password: "correct-horse-battery-staple",
					}),
				}),
			);
			expect(adminSignIn.status).toBe(200);
			const adminHeaders = new Headers({
				cookie: adminSignIn.headers
					.getSetCookie()
					.map((cookie) => cookie.split(";", 1)[0]!)
					.find((cookie) =>
						cookie.startsWith("clearance.session_token="),
					)!,
				origin: "http://localhost:3300",
			});
			const activateAdmin = await bundle.auth.api.setActiveOrganization({
				body: { organizationId },
				headers: adminHeaders,
				asResponse: true,
			});
			expect(activateAdmin.status).toBe(200);
			adminHeaders.set(
				"cookie",
				activateAdmin.headers
					.getSetCookie()
					.map((cookie) => cookie.split(";", 1)[0]!)
					.find((cookie) =>
						cookie.startsWith("clearance.session_token="),
					)!,
			);
			const superiorDemotion = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/authorization/assignments/replace`,
				{
					headers: adminHeaders,
					body: {
						subject: { kind: "principal", id: superior.user.id },
						roleIds: ["role_builtin_member"],
						dryRun: false,
						confirm: true,
					},
				},
			);
			expect(superiorDemotion.status).toBe(403);
			await expect(superiorDemotion.json()).resolves.toMatchObject({
				code: "TENANT_ADMINISTRATION_ESCALATION_DENIED",
			});
			await expect(
				bundle.authorization!.readEffective({
					organizationId,
					subject: { kind: "principal", id: superior.user.id },
				}),
			).resolves.toMatchObject({
				roleIds: [`role_superior_${suffix}`],
			});

			const previewAuditCount = await pool.query<{ count: number }>(
				`SELECT count(*)::int AS count
				 FROM "${schema}".clearance_runtime_audit_events
				 WHERE action = 'tenant.service_accounts.create'`,
			);
			const preview = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/service-accounts`,
				{
					body: {
						name: "Preview account",
						roleIds: ["role_builtin_member"],
						dryRun: true,
					},
				},
			);
			expect(preview.status).toBe(200);
			expect(await preview.json()).toEqual({
				preview: true,
				serviceAccount: {
					organizationId,
					name: "Preview account",
					status: "active",
				},
				roleIds: ["role_builtin_member"],
			});
			expect(
				await bundle.authorization!.listServiceAccounts({ organizationId }),
			).toEqual([]);
			await expect(
				pool.query<{ count: number }>(
					`SELECT count(*)::int AS count
					 FROM "${schema}".clearance_runtime_audit_events
					 WHERE action = 'tenant.service_accounts.create'`,
				),
			).resolves.toMatchObject({
				rows: [{ count: previewAuditCount.rows[0]!.count }],
			});

			const rejectFunction = `reject_tenant_audit_${suffix}`;
			const rejectTrigger = `reject_tenant_audit_${suffix}`;
			await pool.query(`
				CREATE FUNCTION "${schema}"."${rejectFunction}"()
				RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
					IF NEW.action = 'tenant.service_accounts.create' THEN
						RAISE EXCEPTION 'forced tenant audit failure' USING ERRCODE = 'CLR02';
					END IF;
					RETURN NEW;
				END $$;
				CREATE TRIGGER "${rejectTrigger}"
				BEFORE INSERT ON "${schema}".clearance_runtime_audit_events
				FOR EACH ROW EXECUTE FUNCTION "${schema}"."${rejectFunction}"()
			`);
			const failedCreate = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/service-accounts`,
				{
					body: {
						name: "Must roll back",
						roleIds: ["role_builtin_member"],
						dryRun: false,
					},
				},
			);
			expect(failedCreate.status).toBe(503);
			expect(
				await bundle.authorization!.listServiceAccounts({ organizationId }),
			).toEqual([]);
			await pool.query(`
				DROP TRIGGER "${rejectTrigger}"
					ON "${schema}".clearance_runtime_audit_events;
				DROP FUNCTION "${schema}"."${rejectFunction}"()
			`);

			const accountRequestId = `tenant-account-${suffix}`;
			const accountResponse = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/service-accounts`,
				{
					requestId: accountRequestId,
					body: {
						name: "Automation",
						roleIds: ["role_builtin_member"],
						dryRun: false,
					},
				},
			);
			expect(accountResponse.status).toBe(200);
			const accountBody = (await accountResponse.json()) as {
				serviceAccount: { serviceAccountId: string };
			};
			const serviceAccountId =
				accountBody.serviceAccount.serviceAccountId;
			expect(serviceAccountId).toMatch(/^svc_/);
			const accountAudits = await pool.query<{ count: number }>(
				`SELECT count(*)::int AS count
				 FROM "${schema}".clearance_runtime_audit_events
				 WHERE correlation_id = $1`,
				[accountRequestId],
			);
			expect(accountAudits.rows[0]?.count).toBe(1);

			const credentialRequestId = `tenant-credential-${suffix}`;
			const credentialResponse = await tenantRequest(
				`/tenant/v1/organizations/${organizationId}/service-accounts/${serviceAccountId}/credentials`,
				{
					requestId: credentialRequestId,
					body: { dryRun: false },
				},
			);
			expect(credentialResponse.status).toBe(200);
			expect(credentialResponse.headers.get("cache-control")).toBe("no-store");
			expect(credentialResponse.headers.get("pragma")).toBe("no-cache");
			const credentialBody = (await credentialResponse.json()) as {
				secret: string;
				credential: { credentialId: string };
				revision: string;
				previousRevision: string;
			};
			expect(credentialBody.secret).toMatch(/^clr_sac_v1_/);
			expect(BigInt(credentialBody.revision)).toBe(
				BigInt(credentialBody.previousRevision) + 1n,
			);
			const credentialAudit = await pool.query<{
				count: number;
				serialized: string;
			}>(
				`SELECT count(*)::int AS count,
				        COALESCE(string_agg(metadata::text, ''), '') AS serialized
				 FROM "${schema}".clearance_runtime_audit_events
				 WHERE correlation_id = $1`,
				[credentialRequestId],
			);
			expect(credentialAudit.rows[0]?.count).toBe(1);
			expect(credentialAudit.rows[0]?.serialized).not.toContain(
				credentialBody.secret,
			);
			expect(credentialAudit.rows[0]?.serialized).not.toContain(
				credentialBody.credential.credentialId,
			);
		});
	},
);
