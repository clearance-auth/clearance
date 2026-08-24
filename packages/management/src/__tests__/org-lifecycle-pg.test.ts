/**
 * Real Postgres integration: Clearance runtime organization + member tables
 * coordinated with PgStore organization lifecycle (update / archive).
 *
 * Dedicated isolated live Postgres on port 55432 only.
 * CLEARANCE_ORG_TEST_DATABASE_URL or explicit default → 127.0.0.1:55432.
 * Never silently falls back to shared 5434.
 *
 * Tracks exact runtime user/org/member IDs created by this process and cleans
 * up only those IDs. Isolated management table names per process.
 */
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { parseKeyEnvelope } from "@clearance/key-management";
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import {
	createPgStore,
	type PgStore,
	type PgStoreDeliveryOptions,
} from "../store/pg-store.js";
import { storeV2TableNames } from "../store/store-v2-schema.js";
import { wrapInternalCoordinatedExecutor } from "../store/coordinated-internal.js";
import {
	createDeliveryKeyring,
	decryptDeliveryPayload,
	deliveryTableNames,
	qualifiedDeliveryTables,
	quoteIdentifier,
	type DeliveryPayloadAad,
} from "@clearance/delivery";
import {
	addMemberInAuth,
	archiveOrganizationInAuth,
	createServiceAccountCredentialInAuth,
	createServiceAccountInAuth,
	createOrgInAuth,
	createManagedOrganizationLifecycleFacade,
	createTenantProductAdministrationFacade,
	createUserInAuth,
	ensureAuthMigrated,
	getAuthBundle,
	provisionOrganizationInAuth,
	resetAuthBundle,
	rotateServiceAccountCredentialInAuth,
	updateOrganizationInAuth,
} from "../auth-bridge.js";
import {
	createScimConnectionReal,
	testScimConnectionReal,
} from "../services/scim-real.js";
import { createScimOperationReplayCipher } from "../services/scim.js";
import { createSetupLink } from "../services/setup-links.js";
import { createSsoConnectionReal } from "../services/sso-real.js";
import {
	rotateScimCredentialAuthoritative,
	rotateSsoCredentialAuthoritative,
	initProject,
	listEvents,
	listEventsPageOperational,
	resolveOperatorScope,
	syncRuntimeOrganizationToManagementDurable,
	} from "../index.js";
import { PostgresAuthorizationAuthority } from "../../../clearance-auth/src/authorization-authority.js";
import { createClearanceManagementAuth } from "@clearance/auth/management-internal";

const DATABASE_URL =
	process.env.CLEARANCE_ORG_TEST_DATABASE_URL ??
	"postgres://user:password@127.0.0.1:55432/clearance";

// Guard: never target shared 5434 for this suite.
if (DATABASE_URL.includes(":5434")) {
	throw new Error(
		"org-lifecycle-pg must use dedicated Postgres on 55432 (CLEARANCE_ORG_TEST_DATABASE_URL); refusing shared 5434",
	);
}

const TEST_TABLE = `clearance_mgmt_org_lc_${process.pid}`;
const TOPOLOGY_TABLE = `${TEST_TABLE}_topology`;
const TOPOLOGY_PREFIX = `${TOPOLOGY_TABLE}_n_`;
const TOPOLOGY_STORE_V2_TABLES = storeV2TableNames(TOPOLOGY_PREFIX);
const STARTUP_ABSENT_TABLE = `${TEST_TABLE}_startup_absent`;
const STARTUP_ABSENT_PREFIX = `${STARTUP_ABSENT_TABLE}_n_`;
const DELIVERY_PREFIX = `org_lc_delivery_${process.pid}_`;
const deliveryOptions = { prefix: DELIVERY_PREFIX } as const;
const deliveryKeyInput = {
	currentKeyId: "org-lifecycle-current",
	keys: { "org-lifecycle-current": randomBytes(32) },
	currentFingerprintKeyId: "org-lifecycle-fingerprint-current",
	fingerprintKeys: { "org-lifecycle-fingerprint-current": randomBytes(32) },
	sourceDedupeKey: randomBytes(32),
};
const deliveryKeyring = createDeliveryKeyring(deliveryKeyInput);
const storeDeliveryOptions: PgStoreDeliveryOptions = {
	...deliveryOptions,
	keyring: deliveryKeyInput,
};
const webhookTarget = {
	id: "primary",
	url: "https://hooks.example.test/clearance",
	signingSecret: "organization-lifecycle-signing-secret",
} as const;

const createdRuntimeUserIds = new Set<string>();
const createdRuntimeOrgIds = new Set<string>();
const createdRuntimeMemberIds = new Set<string>();
const createdRuntimeEmails = new Set<string>();

function replayCipherGuard() {
	return {
		async authorizeMutation(): Promise<void> {},
		replayCipher: createScimOperationReplayCipher(getAuthBundle().keyManagement),
	};
}


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
		const memberIds = [...createdRuntimeMemberIds];
		if (memberIds.length > 0) {
			await pool
				.query(`delete from member where id = any($1::text[])`, [memberIds])
				.catch(() => undefined);
		}
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

/**
 * After the real mutator completes (runtime + management draft applied), force
 * a SQL error so COMMIT never lands — full rollback of runtime + management + audit.
 */
function injectSqlFailureAfter(
	store: PgStore,
	match: (sql: string) => boolean,
): () => void {
	return wrapInternalCoordinatedExecutor(store, (original) => (fn) =>
		original(async (ctx) => {
			let saw = false;
			const value = await fn({
				...ctx,
				query: async (sql, params) => {
					const result = await ctx.query(sql, params);
					if (match(sql.replace(/\s+/g, " ").toLowerCase())) {
						saw = true;
					}
					return result;
				},
			});
			if (saw) {
				await ctx.query(
					`select 1 from "clearance_org_lc_poison_${process.pid}"`,
				);
			}
			return value;
		}),
	);
}

const available = await gatePostgresSuite(DATABASE_URL, "org-lifecycle-pg");

describe.skipIf(!available)(
	"organization lifecycle Postgres runtime + management",
	() => {
		const stores: PgStore[] = [];
		const prev = {
			DATABASE_URL: process.env.DATABASE_URL,
			CLEARANCE_SECRET: process.env.CLEARANCE_SECRET,
			CLEARANCE_BASE_URL: process.env.CLEARANCE_BASE_URL,
			NODE_ENV: process.env.NODE_ENV,
			CLEARANCE_PROJECT_ID: process.env.CLEARANCE_PROJECT_ID,
			CLEARANCE_ENV_ID: process.env.CLEARANCE_ENV_ID,
			CLEARANCE_AUTHORIZATION_PREFIX: process.env.CLEARANCE_AUTHORIZATION_PREFIX,
		};

		process.env.DATABASE_URL = DATABASE_URL;
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_BASE_URL = "http://localhost:3300";
		process.env.NODE_ENV = "development";

		async function resetTopologyFixture(): Promise<void> {
			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				for (const table of [
					...Object.values(TOPOLOGY_STORE_V2_TABLES),
					`${TOPOLOGY_TABLE}_principal_email`, `${TOPOLOGY_TABLE}_organization_slug`,
					`${TOPOLOGY_TABLE}_idempotency`, TOPOLOGY_TABLE,
				]) await pool.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
			} finally {
				await pool.end();
			}
		}

		afterEach(async () => {
			await cleanupTracked().catch(() => undefined);
			await resetTopologyFixture().catch(() => undefined);
			createdRuntimeUserIds.clear();
			createdRuntimeOrgIds.clear();
			createdRuntimeMemberIds.clear();
			createdRuntimeEmails.clear();
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
				const names = deliveryTableNames(deliveryOptions);
				for (const name of [
					names.attempt,
					names.job,
					names.payload,
					names.event,
					names.worker,
					names.meta,
				]) {
					await pool.query(
						`DROP TABLE IF EXISTS ${quoteIdentifier("public")}.${quoteIdentifier(name)} CASCADE`,
					);
				}
				await pool.query(
					`DROP FUNCTION IF EXISTS ${quoteIdentifier("public")}.${quoteIdentifier(names.rejectMutationFunction)}()`,
				);
				await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}`);
				await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_principal_email`);
				await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_organization_slug`);
				await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_scim_operation_replay`);
				for (const table of [
					`${STARTUP_ABSENT_PREFIX}events`,
					`${STARTUP_ABSENT_PREFIX}principals`,
					`${STARTUP_ABSENT_PREFIX}organizations`,
					`${STARTUP_ABSENT_PREFIX}environments`,
					`${STARTUP_ABSENT_PREFIX}projects`,
					`${STARTUP_ABSENT_PREFIX}meta`,
					`${STARTUP_ABSENT_TABLE}_principal_email`,
					`${STARTUP_ABSENT_TABLE}_organization_slug`,
					`${STARTUP_ABSENT_TABLE}_idempotency`,
					`${STARTUP_ABSENT_TABLE}_scim_operation_replay`,
					STARTUP_ABSENT_TABLE,
					`${TOPOLOGY_PREFIX}events`,
					`${TOPOLOGY_PREFIX}principals`,
					`${TOPOLOGY_PREFIX}organizations`,
					`${TOPOLOGY_PREFIX}environments`,
					`${TOPOLOGY_PREFIX}projects`,
					`${TOPOLOGY_PREFIX}meta`,
					TOPOLOGY_STORE_V2_TABLES.productPresentations,
					TOPOLOGY_STORE_V2_TABLES.productAuthDomains,
					TOPOLOGY_STORE_V2_TABLES.productEmailSenders,
					TOPOLOGY_STORE_V2_TABLES.productEmailTemplates,
					`${TOPOLOGY_TABLE}_principal_email`,
					`${TOPOLOGY_TABLE}_organization_slug`,
					`${TOPOLOGY_TABLE}_idempotency`,
					`${TOPOLOGY_TABLE}_scim_operation_replay`,
					TOPOLOGY_TABLE,
				]) {
					await pool.query(`DROP TABLE IF EXISTS ${table} CASCADE`);
				}
			} finally {
				await pool.end().catch(() => undefined);
			}
			for (const [k, v] of Object.entries(prev)) {
				if (v === undefined) delete process.env[k];
				else process.env[k] = v;
			}
		});

		async function freshStore(input?: { delivery?: boolean }): Promise<PgStore> {
			const store = await createPgStore(DATABASE_URL, {
				tableName: TEST_TABLE,
				...(input?.delivery ? { delivery: storeDeliveryOptions } : {}),
			});
			stores.push(store);
			await store.refresh();
			if (store.snapshot.projects.length === 0) {
				initProject(store, { name: "Org Lifecycle PG", source: "cli" });
				await store.ready();
			}
			const scope = resolveOperatorScope(store);
			process.env.CLEARANCE_PROJECT_ID = scope.projectId;
			process.env.CLEARANCE_ENV_ID = scope.environmentId;
			await ensureAuthMigrated();
			return store;
		}

		async function freshTopologyStore(): Promise<{
			store: PgStore;
			scope: { projectId: string; environmentId: string };
		}> {
			const store = await createPgStore(DATABASE_URL, {
				tableName: TOPOLOGY_TABLE,
				normalizedPrefix: TOPOLOGY_PREFIX,
			});
			stores.push(store);
			const initialized = initProject(store, {
				name: "Org Lifecycle Topology PG",
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
			return { store, scope };
		}

		it("reconciles pending authz-v2 once on normal startup after topology authority is already cut over", async () => {
			const startupTable = `${TEST_TABLE}_start`;
			const startupPrefix = `${startupTable}_n_`;
			const previousAuthorizationPrefix = process.env.CLEARANCE_AUTHORIZATION_PREFIX;
			const previousProjectId = process.env.CLEARANCE_PROJECT_ID;
			const previousEnvironmentId = process.env.CLEARANCE_ENV_ID;
			const previousSecret = process.env.CLEARANCE_SECRET;
			const prefix = `startupauthz${process.pid}`;
			let store: PgStore | undefined;
			let restarted: PgStore | undefined;
			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				store = await createPgStore(DATABASE_URL, {
					tableName: startupTable,
					normalizedPrefix: startupPrefix,
				});
				const initialized = initProject(store, {
					name: "Startup Reconciliation PG",
					source: "cli",
				});
				await store.ready();
				const scope = {
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
				};
				process.env.CLEARANCE_PROJECT_ID = scope.projectId;
				process.env.CLEARANCE_ENV_ID = scope.environmentId;
				process.env.CLEARANCE_AUTHORIZATION_PREFIX = prefix;
				resetAuthBundle();
				await store.storeV2!.apply();
				const activeOrganizationId = `org_startup_active_${process.pid}`;
				const absentOrganizationId = `org_startup_absent_${process.pid}`;
				const now = "2026-07-18T00:00:00.000Z";
				await store.mutateDurable((data) => {
				data.organizations.push({
					id: activeOrganizationId,
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					name: "Startup authority",
					slug: `startup-authority-${process.pid}`,
					status: "active",
					createdAt: now,
					updatedAt: now,
				});
				});
				// Authz-v2 is fully migrated while topology is still shadow. Its
				// terminal reconciliation must wait for the later authoritative
				// management identity, then run at normal startup.
				await ensureAuthMigrated();
				const legacy = new PostgresAuthorizationAuthority(pool, { ...scope, prefix });
				await legacy.initializeOrganization({ organizationId: activeOrganizationId });
				await legacy.initializeOrganization({ organizationId: absentOrganizationId });
				// Keep the cutover itself free of the runtime bridge so the following
				// fresh process, rather than cutover, proves the startup seam.
				delete process.env.CLEARANCE_SECRET;
				resetAuthBundle();
				await store.storeV2!.cutoverEvents();
				await store.storeV2!.cutoverTopology();
				if (previousSecret === undefined) delete process.env.CLEARANCE_SECRET;
				else process.env.CLEARANCE_SECRET = previousSecret;
				resetAuthBundle();

				restarted = await createPgStore(DATABASE_URL, {
					tableName: startupTable,
					normalizedPrefix: startupPrefix,
				});
				await expect(legacy.initializeOrganization({ organizationId: activeOrganizationId })).resolves.toMatchObject({ initialized: false });
				await expect(legacy.initializeOrganization({ organizationId: absentOrganizationId })).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
				const audit = await pool.query<{ action: string; source: string; metadata: { terminalizedOrganizations?: number; terminalizedOrganizationIds?: string[] } }>(
					`select action, source, metadata from ${startupPrefix}events where action = 'authorization.organizations.reconcile'`,
				);
				expect(audit.rows).toHaveLength(1);
				expect(audit.rows[0]).toMatchObject({
					action: "authorization.organizations.reconcile",
					source: "migration",
					metadata: { terminalizedOrganizations: 1, terminalizedOrganizationIds: [absentOrganizationId] },
				});
				const secondStartup = await createPgStore(DATABASE_URL, {
					tableName: startupTable,
					normalizedPrefix: startupPrefix,
				});
				await secondStartup.destroy();
				const repeatedAudit = await pool.query(
					`select 1 from ${startupPrefix}events where action = 'authorization.organizations.reconcile'`,
				);
				expect(repeatedAudit.rows).toHaveLength(1);
				await expect(legacy.initializeOrganization({ organizationId: activeOrganizationId })).resolves.toMatchObject({ initialized: false });
			} finally {
				await restarted?.destroy().catch(() => undefined);
				await store?.destroy().catch(() => undefined);
				await pool.query(`DROP TABLE IF EXISTS "${prefix}_authz_actions", "${prefix}_authz_role_actions", "${prefix}_authz_roles", "${prefix}_authz_subject_role_assignments", "${prefix}_authz_service_accounts", "${prefix}_authz_service_account_credentials", "${prefix}_authz_revisions" CASCADE`).catch(() => undefined);
				for (const table of [
					`${startupPrefix}events`, `${startupPrefix}principals`, `${startupPrefix}organizations`,
					`${startupPrefix}environments`, `${startupPrefix}projects`, `${startupPrefix}meta`,
					`${startupTable}_principal_email`, `${startupTable}_organization_slug`,
					`${startupTable}_idempotency`, startupTable,
				]) await pool.query(`DROP TABLE IF EXISTS ${table} CASCADE`).catch(() => undefined);
				await pool.end();
				if (previousAuthorizationPrefix === undefined) delete process.env.CLEARANCE_AUTHORIZATION_PREFIX;
				else process.env.CLEARANCE_AUTHORIZATION_PREFIX = previousAuthorizationPrefix;
				if (previousProjectId === undefined) delete process.env.CLEARANCE_PROJECT_ID;
				else process.env.CLEARANCE_PROJECT_ID = previousProjectId;
				if (previousEnvironmentId === undefined) delete process.env.CLEARANCE_ENV_ID;
				else process.env.CLEARANCE_ENV_ID = previousEnvironmentId;
				if (previousSecret === undefined) delete process.env.CLEARANCE_SECRET;
				else process.env.CLEARANCE_SECRET = previousSecret;
				resetAuthBundle();
			}
		});

		it("skips authorization reconciliation when the configured StoreV2 schema is absent", async () => {
			const store = await createPgStore(DATABASE_URL, { tableName: STARTUP_ABSENT_TABLE, normalizedPrefix: STARTUP_ABSENT_PREFIX });
			stores.push(store);
			await expect(store.storeV2!.status()).resolves.toMatchObject({ phase: "absent" });
		});

		async function seedOwnerAndOrg(store: PgStore) {
			const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
			const owner = await createUserInAuth({
				email: `owner-${stamp}@org-lc.test`,
				name: "Owner",
				password: "OrgLifecycle1!",
				managementStore: store,
			});
			trackUser(owner);
			const runtimeOrg = await createOrgInAuth({
				name: `Org ${stamp}`,
				slug: `org-${stamp}`,
				userId: owner.id,
			});
			trackOrg(runtimeOrg);
			if (runtimeOrg.ownerMembershipId) {
				trackMember(runtimeOrg.ownerMembershipId);
			}

			const organization = await syncRuntimeOrganizationToManagementDurable(
				store,
				runtimeOrg,
				owner.id,
				{ actor: "test", role: "owner" },
			);
			return { owner, organization, stamp, runtimeOrg };
		}

		async function runtimeOrgRow(
			id: string,
		): Promise<{ id: string; name: string; slug: string } | undefined> {
			const b = getAuthBundle();
			const r = await b.pool.query(
				`select id, name, slug from organization where id = $1`,
				[id],
			);
			const row = r.rows[0];
			return row
				? {
						id: String(row.id),
						name: String(row.name),
						slug: String(row.slug),
					}
				: undefined;
		}

		async function runtimeMemberCount(organizationId: string): Promise<number> {
			const b = getAuthBundle();
			const r = await b.pool.query(
				`select count(*)::int as c from member where "organizationId" = $1`,
				[organizationId],
			);
			return Number(r.rows[0]?.c ?? 0);
		}

		async function runtimeEnterpriseProviderCounts(organizationId: string): Promise<{
			sso: number;
			scim: number;
		}> {
			const b = getAuthBundle();
			const [sso, scim] = await Promise.all([
				b.pool.query(
					`select count(*)::int as count from "ssoProvider" where "organizationId" = $1`,
					[organizationId],
				),
				b.pool.query(
					`select count(*)::int as count from "scimProvider" where "organizationId" = $1`,
					[organizationId],
				),
			]);
			return {
				sso: Number(sso.rows[0]?.count ?? 0),
				scim: Number(scim.rows[0]?.count ?? 0),
			};
		}

		it("update parity: same id/name/slug in runtime and management, one audit", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const orgId = organization.id;

			const updated = await updateOrganizationInAuth(store, orgId, {
				name: "Renamed Corp",
				slug: `renamed-${organization.slug.slice(-12)}`,
				actor: "test",
				source: "api",
			});

			expect(updated.id).toBe(orgId);
			expect(updated.name).toBe("Renamed Corp");
			expect(updated.slug).toMatch(/^renamed-/);

			const mgmt = store.snapshot.organizations.find((o) => o.id === orgId);
			expect(mgmt?.name).toBe(updated.name);
			expect(mgmt?.slug).toBe(updated.slug);
			expect(mgmt?.status).toBe("active");

			const runtime = await runtimeOrgRow(orgId);
			expect(runtime?.id).toBe(orgId);
			expect(runtime?.name).toBe(updated.name);
			expect(runtime?.slug).toBe(updated.slug);

			const audits = listEvents(store, { limit: 200 }).filter(
				(e) => e.action === "orgs.update" && e.subjectId === orgId,
			);
			expect(audits).toHaveLength(1);
			expect(audits[0]?.outcome).toBe("success");
		});

		it("commits one encrypted organization.updated webhook intent with the product mutation", async () => {
			const store = await freshStore({ delivery: true });
			const { organization } = await seedOwnerAndOrg(store);
			const scope = resolveOperatorScope(store);
			const correlationId = `corr-org-update-${Date.now()}`;
			const nextName = "Webhook Transaction Corp";

			await updateOrganizationInAuth(store, organization.id, {
				name: nextName,
				actor: "webhook-test",
				source: "api",
				correlationId,
				webhookTargets: [webhookTarget],
			});

			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				const tables = qualifiedDeliveryTables(deliveryOptions);
				const result = await pool.query<{
					id: string;
					kind: string;
					project_id: string;
					environment_id: string;
					organization_id: string;
					actor_id: string;
					correlation_id: string;
					destination_fingerprint: string;
					semantic_expires_at: Date;
					channel: "webhook";
					state: "queued";
					envelope: string;
				}>(
					`SELECT e.id, e.kind, e.project_id, e.environment_id,
					 e.organization_id, e.actor_id, e.correlation_id,
					 e.destination_fingerprint, e.semantic_expires_at,
					 j.channel, j.state, p.envelope
					 FROM ${tables.event} e
					 JOIN ${tables.payload} p ON p.event_id = e.id
					 JOIN ${tables.job} j ON j.event_id = e.id
					 WHERE e.organization_id = $1`,
					[organization.id],
				);
				expect(result.rows).toHaveLength(1);
				const row = result.rows[0]!;
				expect(row).toMatchObject({
					kind: "organization.updated",
					project_id: scope.projectId,
					environment_id: scope.environmentId,
					organization_id: organization.id,
					actor_id: "webhook-test",
					correlation_id: correlationId,
					channel: "webhook",
					state: "queued",
				});
				const atRest = JSON.stringify(result.rows);
				expect(atRest).not.toContain(webhookTarget.url);
				expect(atRest).not.toContain(webhookTarget.signingSecret);

				const aad: DeliveryPayloadAad = {
					version: 1,
					eventId: row.id,
					kind: row.kind,
					channel: row.channel,
					projectId: row.project_id,
					environmentId: row.environment_id,
					destinationFingerprint: row.destination_fingerprint,
					expiresAt: row.semantic_expires_at.toISOString(),
				};
				const payload = decryptDeliveryPayload<{
					endpoint: { id: string; url: string; signingSecret: string };
					event: {
						id: string;
						type: string;
						context: { correlationId: string };
						data: { organization: { id: string; name: string } };
					};
				}>(row.envelope, aad, deliveryKeyring);
				expect(payload.endpoint).toEqual({
					id: webhookTarget.id,
					url: webhookTarget.url,
					signingSecret: webhookTarget.signingSecret,
				});
				expect(payload.event).toMatchObject({
					id: row.id,
					type: "organization.updated",
					context: { correlationId },
					data: {
						organization: { id: organization.id, name: nextName },
					},
				});
			} finally {
				await pool.end();
			}

			const audit = listEvents(store, { limit: 200 }).find(
				(event) =>
					event.action === "orgs.update" &&
					event.subjectId === organization.id,
			);
			expect(audit?.correlationId).toBe(correlationId);
			expect((await runtimeOrgRow(organization.id))?.name).toBe(nextName);
			expect(
				store.snapshot.organizations.find((org) => org.id === organization.id)?.name,
			).toBe(nextName);
		});

		it("rolls the product mutation back when delivery enqueue fails", async () => {
			const store = await freshStore({ delivery: true });
			const { organization } = await seedOwnerAndOrg(store);
			const beforeRuntime = await runtimeOrgRow(organization.id);
			const beforeEvents = listEvents(store, { limit: 500 }).length;
			const tables = qualifiedDeliveryTables(deliveryOptions);
			const names = deliveryTableNames(deliveryOptions);
			const unavailableJobTable = `${names.job}_unavailable`;
			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			await pool.query(
				`ALTER TABLE ${tables.job} RENAME TO ${quoteIdentifier(unavailableJobTable)}`,
			);
			try {
				await expect(
					updateOrganizationInAuth(store, organization.id, {
						name: "Must Roll Back",
						actor: "webhook-test",
						correlationId: `corr-enqueue-failure-${Date.now()}`,
						webhookTargets: [webhookTarget],
					}),
				).rejects.toBeTruthy();
			} finally {
				await pool.query(
					`ALTER TABLE ${quoteIdentifier("public")}.${quoteIdentifier(unavailableJobTable)} RENAME TO ${quoteIdentifier(names.job)}`,
				);
				await pool.end();
			}

			await store.refresh();
			expect((await runtimeOrgRow(organization.id))?.name).toBe(beforeRuntime?.name);
			expect(
				store.snapshot.organizations.find((org) => org.id === organization.id)?.name,
			).toBe(organization.name);
			expect(listEvents(store, { limit: 500 })).toHaveLength(beforeEvents);
			const verifyPool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				expect(
					(
						await verifyPool.query(
							`SELECT count(*)::int count FROM ${tables.event} WHERE organization_id = $1`,
							[organization.id],
						)
					).rows[0]?.count,
				).toBe(0);
			} finally {
				await verifyPool.end();
			}
		});

		it("rolls the delivery intent back when a later coordinated mutation step fails", async () => {
			const store = await freshStore({ delivery: true });
			const { organization } = await seedOwnerAndOrg(store);
			const beforeRuntime = await runtimeOrgRow(organization.id);
			const restore = injectSqlFailureAfter(store, (sql) =>
				sql.includes("update organization"),
			);
			try {
				await expect(
					updateOrganizationInAuth(store, organization.id, {
						name: "Late Failure",
						actor: "webhook-test",
						correlationId: `corr-late-failure-${Date.now()}`,
						webhookTargets: [webhookTarget],
					}),
				).rejects.toBeTruthy();
			} finally {
				restore();
			}

			await store.refresh();
			expect((await runtimeOrgRow(organization.id))?.name).toBe(beforeRuntime?.name);
			expect(
				store.snapshot.organizations.find((org) => org.id === organization.id)?.name,
			).toBe(organization.name);
			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				const tables = qualifiedDeliveryTables(deliveryOptions);
				expect(
					(
						await pool.query(
							`SELECT count(*)::int count FROM ${tables.event} WHERE organization_id = $1`,
							[organization.id],
						)
					).rows[0]?.count,
				).toBe(0);
			} finally {
				await pool.end();
			}
		});

		it("deduplicates concurrent delivery generations and isolates environments", async () => {
			const firstStore = await freshStore({ delivery: true });
			const secondStore = await freshStore({ delivery: true });
			const scope = resolveOperatorScope(firstStore);
			const now = new Date();
			const expiresAt = new Date(now.getTime() + 60_000);
			const sourceKey = `concurrent-generation-${Date.now()}`;
			const enqueue = (store: PgStore, eventId: string, environmentId: string) =>
				store.mutateCoordinated!(({ enqueueDelivery }) => {
					if (!enqueueDelivery) throw new Error("delivery enqueue unavailable");
					return enqueueDelivery({
						eventId,
						kind: "management.delivery.seam",
						sourceKey,
						projectId: scope.projectId,
						environmentId,
						channel: "email",
						destination: "delivery-seam@example.test",
						payload: { generation: sourceKey },
						semanticExpiresAt: expiresAt,
						now,
					});
				});

			const concurrent = await Promise.allSettled([
				enqueue(firstStore, `event-a-${Date.now()}`, scope.environmentId),
				enqueue(secondStore, `event-b-${Date.now()}`, scope.environmentId),
			]);
			expect(concurrent.filter((result) => result.status === "fulfilled")).toHaveLength(1);
			expect(concurrent.filter((result) => result.status === "rejected")).toHaveLength(1);
			const rejected = concurrent.find((result) => result.status === "rejected");
			expect(rejected).toMatchObject({
				status: "rejected",
				reason: { code: "DELIVERY_DUPLICATE" },
			});

			const otherEnvironmentId = `${scope.environmentId}-isolated`;
			await enqueue(firstStore, `event-other-env-${Date.now()}`, otherEnvironmentId);
			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				const tables = qualifiedDeliveryTables(deliveryOptions);
				const rows = await pool.query<{ environment_id: string }>(
					`SELECT environment_id FROM ${tables.event}
					 WHERE kind = 'management.delivery.seam'
					 ORDER BY environment_id`,
				);
				expect(rows.rows.map((row) => row.environment_id).sort()).toEqual(
					[scope.environmentId, otherEnvironmentId].sort(),
				);
			} finally {
				await pool.end();
			}
		});

		it("update idempotent no-op adds no duplicate audit", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const first = await updateOrganizationInAuth(store, organization.id, {
				name: "Stable Name",
				slug: `stable-${organization.slug.slice(-10)}`,
				actor: "test",
			});
			const again = await updateOrganizationInAuth(store, organization.id, {
				name: first.name,
				slug: first.slug,
				actor: "test",
			});
			expect(again.id).toBe(first.id);
			expect(again.name).toBe(first.name);
			expect(again.slug).toBe(first.slug);
			expect(
				listEvents(store, { limit: 200 }).filter(
					(e) => e.action === "orgs.update" && e.subjectId === organization.id,
				),
			).toHaveLength(1);
		});

		it("management no-op reconciles corrupted runtime with one audit, stable id, and TX", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const orgId = organization.id;
			const canonicalName = organization.name;
			const canonicalSlug = organization.slug;
			const corruptName = `corrupted-name-${organization.slug.slice(-8)}`;
			const corruptSlug = `corrupted-${organization.slug.slice(-12)}`;

			// Deliberately diverge runtime while management remains authoritative.
			const bundle = getAuthBundle();
			await bundle.pool.query(
				`update organization set name = $1, slug = $2 where id = $3`,
				[corruptName, corruptSlug, orgId],
			);
			const corrupted = await runtimeOrgRow(orgId);
			expect(corrupted?.name).toBe(corruptName);
			expect(corrupted?.slug).toBe(corruptSlug);
			expect(
				store.snapshot.organizations.find((o) => o.id === orgId)?.name,
			).toBe(canonicalName);
			expect(
				store.snapshot.organizations.find((o) => o.id === orgId)?.slug,
			).toBe(canonicalSlug);

			const beforeEvents = listEvents(store, { limit: 500 }).length;

			// Management no-op request (same values as snapshot) must repair runtime.
			const reconciled = await updateOrganizationInAuth(store, orgId, {
				name: canonicalName,
				slug: canonicalSlug,
				actor: "test",
				source: "api",
			});

			expect(reconciled.id).toBe(orgId);
			expect(reconciled.name).toBe(canonicalName);
			expect(reconciled.slug).toBe(canonicalSlug);

			const mgmt = store.snapshot.organizations.find((o) => o.id === orgId);
			expect(mgmt?.id).toBe(orgId);
			expect(mgmt?.name).toBe(canonicalName);
			expect(mgmt?.slug).toBe(canonicalSlug);

			const runtime = await runtimeOrgRow(orgId);
			expect(runtime?.id).toBe(orgId);
			expect(runtime?.name).toBe(canonicalName);
			expect(runtime?.slug).toBe(canonicalSlug);

			const audits = listEvents(store, { limit: 200 }).filter(
				(e) => e.action === "orgs.update" && e.subjectId === orgId,
			);
			expect(audits).toHaveLength(1);
			expect(audits[0]?.outcome).toBe("success");
			expect(audits[0]?.metadata?.reconciled).toBe(true);
			expect(audits[0]?.metadata?.runtimeBefore).toEqual({
				name: corruptName,
				slug: corruptSlug,
			});
			expect(listEvents(store, { limit: 500 }).length).toBe(
				beforeEvents + 1,
			);

			// After parity restored, same-values update is a true no-op (no second audit).
			const again = await updateOrganizationInAuth(store, orgId, {
				name: canonicalName,
				slug: canonicalSlug,
				actor: "test",
			});
			expect(again.id).toBe(orgId);
			expect(
				listEvents(store, { limit: 200 }).filter(
					(e) => e.action === "orgs.update" && e.subjectId === orgId,
				),
			).toHaveLength(1);

			// Transaction: poisoned reconcile rolls back runtime + management audit.
			await bundle.pool.query(
				`update organization set name = $1, slug = $2 where id = $3`,
				[corruptName, corruptSlug, orgId],
			);
			const eventsBeforePoison = listEvents(store, { limit: 500 }).length;
			const restore = injectSqlFailureAfter(store, (sql) =>
				sql.includes("update organization"),
			);
			try {
				await expect(
					updateOrganizationInAuth(store, orgId, {
						name: canonicalName,
						slug: canonicalSlug,
						actor: "test",
					}),
				).rejects.toBeTruthy();
			} finally {
				restore();
			}
			await store.refresh();
			expect((await runtimeOrgRow(orgId))?.name).toBe(corruptName);
			expect((await runtimeOrgRow(orgId))?.slug).toBe(corruptSlug);
			expect(
				store.snapshot.organizations.find((o) => o.id === orgId)?.name,
			).toBe(canonicalName);
			expect(
				store.snapshot.organizations.find((o) => o.id === orgId)?.slug,
			).toBe(canonicalSlug);
			expect(listEvents(store, { limit: 500 }).length).toBe(eventsBeforePoison);
			// Leave runtime corrupted is fine — afterEach cleans tracked ids.
		});

		it("slug conflict fails closed with no write and no success audit", async () => {
			const store = await freshStore();
			const a = await seedOwnerAndOrg(store);
			const b = await seedOwnerAndOrg(store);
			const beforeName = b.organization.name;
			const beforeSlug = b.organization.slug;
			const beforeEvents = listEvents(store, { limit: 500 }).length;

			await expect(
				updateOrganizationInAuth(store, b.organization.id, {
					slug: a.organization.slug,
					actor: "test",
				}),
			).rejects.toMatchObject({ code: "ORG_SLUG_EXISTS" });

			const mgmt = store.snapshot.organizations.find(
				(o) => o.id === b.organization.id,
			);
			expect(mgmt?.name).toBe(beforeName);
			expect(mgmt?.slug).toBe(beforeSlug);
			const runtime = await runtimeOrgRow(b.organization.id);
			expect(runtime?.name).toBe(beforeName);
			expect(runtime?.slug).toBe(beforeSlug);
			expect(listEvents(store, { limit: 500 }).length).toBe(beforeEvents);
		});

		it("cross-scope update fails closed with no write", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const before = await runtimeOrgRow(organization.id);
			const beforeEvents = listEvents(store, { limit: 500 }).length;

			await expect(
				updateOrganizationInAuth(store, organization.id, {
					name: "Foreign Scope",
					scope: {
						projectId: "proj_foreign_orglc",
						environmentId: "env_foreign_orglc",
					},
					actor: "test",
				}),
			).rejects.toMatchObject({ code: "ORG_NOT_FOUND" });

			expect((await runtimeOrgRow(organization.id))?.name).toBe(before?.name);
			expect(
				store.snapshot.organizations.find((o) => o.id === organization.id)?.name,
			).toBe(organization.name);
			expect(listEvents(store, { limit: 500 }).length).toBe(beforeEvents);
		});

		it("invalid slug rejected before mutation", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			await expect(
				updateOrganizationInAuth(store, organization.id, {
					slug: "BAD SLUG!",
					actor: "test",
				}),
			).rejects.toMatchObject({ code: "ORG_SLUG_INVALID" });
			expect((await runtimeOrgRow(organization.id))?.slug).toBe(
				organization.slug,
			);
		});

		it("archive hard-deletes runtime members+org, management tombstone, soft-removes memberships, one audit", async () => {
			const store = await freshStore();
			const { owner, organization, stamp } = await seedOwnerAndOrg(store);
			const member = await createUserInAuth({
				email: `mem-${stamp}@org-lc.test`,
				name: "Member",
				password: "OrgLifecycle1!",
				managementStore: store,
			});
			trackUser(member);
			const membership = await addMemberInAuth(store, {
				organizationId: organization.id,
				principalId: member.id,
				role: "member",
				actor: "test",
			});
			trackMember(membership.id);
			const authorization = getAuthBundle().authorization;
			if (!authorization) throw new Error("authorization authority unavailable");
			await authorization.createServiceAccount({
				organizationId: organization.id,
				serviceAccountId: `svc-archive-${stamp}`,
				name: "Archive machine",
				roleIds: ["role_builtin_member"],
			});
			const machineCredential = await authorization.createServiceAccountCredential({
				organizationId: organization.id,
				actorId: owner.id,
				operationId: "a11c0001-0000-4000-8000-000000000001",
				serviceAccountId: `svc-archive-${stamp}`,
				credentialId: `cred-archive-${stamp}`,
			});

			expect(await runtimeMemberCount(organization.id)).toBeGreaterThanOrEqual(2);

			const dry = await archiveOrganizationInAuth(store, organization.id, {
				dryRun: true,
				actor: "test",
			});
			expect(dry.dryRun).toBe(true);
			expect(dry.wouldChange).toBe(true);
			expect(await runtimeOrgRow(organization.id)).toBeTruthy();
			expect(
				listEvents(store, { limit: 200 }).some(
					(e) => e.action === "orgs.archive" && e.subjectId === organization.id,
				),
			).toBe(false);

			const archived = await archiveOrganizationInAuth(store, organization.id, {
				confirm: true,
				actor: "test",
				source: "cli",
			});
			expect(archived.dryRun).toBe(false);
			expect(archived.wouldChange).toBe(true);
			expect(archived.organization.id).toBe(organization.id);
			expect(archived.organization.status).toBe("archived");
			await expect(
				authorization.readEffective({
					organizationId: organization.id,
					subject: { kind: "principal", id: owner.id },
				}),
			).rejects.toMatchObject({ code: "AUTHORIZATION_ORGANIZATION_ARCHIVED" });
			await expect(
				authorization.authenticateServiceAccountCredential({
					secret: machineCredential.secret,
				}),
			).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });

			// Runtime gone
			expect(await runtimeOrgRow(organization.id)).toBeUndefined();
			expect(await runtimeMemberCount(organization.id)).toBe(0);

			// Management tombstone preserves id
			const tombstone = store.snapshot.organizations.find(
				(o) => o.id === organization.id,
			);
			expect(tombstone?.status).toBe("archived");
			expect(tombstone?.id).toBe(organization.id);

			// Memberships soft-removed (including owner)
			const mems = store.snapshot.memberships.filter(
				(m) => m.organizationId === organization.id,
			);
			expect(mems.length).toBeGreaterThanOrEqual(2);
			expect(mems.every((m) => m.status === "removed")).toBe(true);
			expect(
				mems.some((m) => m.principalId === owner.id && m.role === "owner"),
			).toBe(true);

			const audits = listEvents(store, { limit: 200 }).filter(
				(e) => e.action === "orgs.archive" && e.subjectId === organization.id,
			);
			expect(audits).toHaveLength(1);
			const authorizationPrefix =
				process.env.CLEARANCE_AUTHORIZATION_PREFIX?.trim() || "clearance";
			await getAuthBundle().pool.query(
				`update ${authorizationPrefix}_authz_service_accounts set status = 'active'
				 where "projectId" = $1 and "environmentId" = $2 and "organizationId" = $3`,
				[authorization.scope.projectId, authorization.scope.environmentId, organization.id],
			);
			await getAuthBundle().pool.query(
				`update ${authorizationPrefix}_authz_service_account_credentials
				 set status = 'active', "revokedAt" = null
				 where "projectId" = $1 and "environmentId" = $2 and "organizationId" = $3`,
				[authorization.scope.projectId, authorization.scope.environmentId, organization.id],
			);
			const healed = await archiveOrganizationInAuth(store, organization.id, {
				confirm: true,
				actor: "test",
				source: "cli",
			});
			expect(healed).toMatchObject({ idempotent: false, wouldChange: true });
			await expect(
				authorization.authenticateServiceAccountCredential({ secret: machineCredential.secret }),
			).rejects.toMatchObject({ code: "AUTHORIZATION_CREDENTIAL_INVALID" });
			expect(listEvents(store, { limit: 200 }).filter(
				(e) => e.action === "orgs.archive.reconcile" && e.subjectId === organization.id,
			)).toHaveLength(1);
		});

		it("re-archive is idempotent with no duplicate audit", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			await archiveOrganizationInAuth(store, organization.id, {
				confirm: true,
				actor: "test",
			});
			const again = await archiveOrganizationInAuth(store, organization.id, {
				confirm: true,
				actor: "test",
			});
			expect(again.idempotent).toBe(true);
			expect(again.wouldChange).toBe(false);
			expect(again.organization.status).toBe("archived");
			expect(
				listEvents(store, { limit: 200 }).filter(
					(e) => e.action === "orgs.archive" && e.subjectId === organization.id,
				),
			).toHaveLength(1);
		});

		it("settles enterprise create and archive atomically with no archived-org residue", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const beforeEvents = listEvents(store, { limit: 500 }).length;

			// A failure after the runtime insert rolls back its provider row, the
			// management connection, and the create audit as one transaction.
			const restore = injectSqlFailureAfter(store, (sql) =>
				sql.includes('insert into "ssoprovider"'),
			);
			try {
				await expect(
					createSsoConnectionReal(store, {
						organizationId: organization.id,
						provider: "okta",
						protocol: "oidc",
						issuer: "https://dev-example.okta.com/oauth2/default",
						domain: `rollback-${organization.slug}.example`,
						clientId: "rollback-client",
						clientSecret: "rollback-client-secret",
					}),
				).rejects.toBeTruthy();
			} finally {
				restore();
			}
			await store.refresh();
			expect(await runtimeEnterpriseProviderCounts(organization.id)).toEqual({
				sso: 0,
				scim: 0,
			});
			expect(
				store.snapshot.ssoConnections.some(
					(connection) => connection.organizationId === organization.id,
				),
			).toBe(false);
			expect(listEvents(store, { limit: 500 })).toHaveLength(beforeEvents);

			await createSsoConnectionReal(store, {
				organizationId: organization.id,
				provider: "okta",
				protocol: "oidc",
				issuer: "https://dev-example.okta.com/oauth2/default",
				domain: `settle-${organization.slug}.example`,
				clientId: "settle-client",
				clientSecret: "settle-client-secret",
			});
			await createScimConnectionReal(store, {
				organizationId: organization.id,
				provider: "okta",
			});
			const ssoCapability = createSetupLink(store, {
				organizationId: organization.id,
				kind: "sso",
			});
			const scimCapability = createSetupLink(store, {
				organizationId: organization.id,
				kind: "scim",
			});
			void ssoCapability;
			void scimCapability;
			expect(await runtimeEnterpriseProviderCounts(organization.id)).toEqual({
				sso: 1,
				scim: 1,
			});

			await archiveOrganizationInAuth(store, organization.id, {
				confirm: true,
				actor: "test",
			});
			expect(await runtimeEnterpriseProviderCounts(organization.id)).toEqual({
				sso: 0,
				scim: 0,
			});
			expect(
				store.snapshot.ssoConnections.some(
					(connection) => connection.organizationId === organization.id,
				),
			).toBe(false);
			expect(
				store.snapshot.scimConnections.some(
					(connection) => connection.organizationId === organization.id,
				),
			).toBe(false);
			const capabilities = (store.snapshot.setupLinks ?? []).filter(
				(capability) => capability.organizationId === organization.id,
			);
			expect(capabilities).toHaveLength(2);
			expect(capabilities.every((capability) => capability.revokedAt)).toBe(true);
			const archiveAudit = listEvents(store, { limit: 500 }).find(
				(event) => event.action === "orgs.archive" && event.subjectId === organization.id,
			);
			expect(archiveAudit?.metadata.enterpriseSettlement).toMatchObject({
				runtimeSsoProvidersDeleted: 1,
				runtimeScimProvidersDeleted: 1,
				ssoConnectionsRemoved: 1,
				scimConnectionsRemoved: 1,
				setupCapabilitiesRevoked: 2,
			});
		});

		it("replaces tenant SCIM and OIDC credentials in the runtime/control transaction", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const scope = resolveOperatorScope(store);
			const sso = await createSsoConnectionReal(store, {
				organizationId: organization.id,
				provider: "okta",
				protocol: "oidc",
				issuer: "https://dev-example.okta.com/oauth2/default",
				domain: `replace-${organization.slug}.example`,
				clientId: "replace-client",
				clientSecret: "old-oidc-client-secret",
				scope,
			});
			const scim = await createScimConnectionReal(store, {
				organizationId: organization.id,
				provider: "okta",
				scope,
			});
			const oldScimBearer = scim.bearerTokenOnce!;
			const beforeSso = store.snapshot.ssoConnections.find((row) => row.id === sso.id)!;
			const beforeScim = store.snapshot.scimConnections.find((row) => row.id === scim.id)!;
			const runtimeBefore = await getAuthBundle().pool.query<{
				id: string;
				oidcConfig: string | null;
				scimToken: string;
			}>(
				`select s.id, s."oidcConfig", c."scimToken"
				 from "ssoProvider" s cross join "scimProvider" c
				 where s.id = $1 and c.id = $2`,
				[sso.id, scim.id],
			);
			expect(runtimeBefore.rows).toHaveLength(1);

			const replacementSso = await rotateSsoCredentialAuthoritative(store, sso.id, {
				scope,
				operationId: "11111111-1111-4111-8111-111111111111",
				newClientSecret: "new-oidc-client-secret",
			});
			const replacementScim = await rotateScimCredentialAuthoritative(store, scim.id, {
				scope,
				operationId: "22222222-2222-4222-8222-222222222222",
			}, replayCipherGuard());
			await store.refresh();
			const afterSso = store.snapshot.ssoConnections.find((row) => row.id === sso.id)!;
			const afterScim = store.snapshot.scimConnections.find((row) => row.id === scim.id)!;
			expect(replacementSso.clientSecretFingerprint).not.toBe(beforeSso.clientSecretFingerprint);
			expect(afterSso.clientSecretFingerprint).toBe(replacementSso.clientSecretFingerprint);
			expect(replacementScim.bearerTokenOnce).not.toBe(oldScimBearer);
			expect(afterScim.bearerTokenFingerprint).toBe(replacementScim.bearerTokenFingerprint);
			expect(afterScim.bearerTokenFingerprint).not.toBe(beforeScim.bearerTokenFingerprint);
			const runtimeAfter = await getAuthBundle().pool.query<{
				oidcConfig: string | null;
				scimToken: string;
			}>(
				`select s."oidcConfig", c."scimToken"
				 from "ssoProvider" s cross join "scimProvider" c
				 where s.id = $1 and c.id = $2`,
				[sso.id, scim.id],
			);
			expect(runtimeAfter.rows[0]!.oidcConfig).not.toBe(runtimeBefore.rows[0]!.oidcConfig);
			expect(runtimeAfter.rows[0]!.scimToken).not.toBe(runtimeBefore.rows[0]!.scimToken);

			const oldProbe = await getAuthBundle().auth.handler(new Request(
				"http://localhost:3300/api/auth/scim/v2/Users",
				{ headers: { authorization: `Bearer ${oldScimBearer}`, origin: "http://localhost:3300" } },
			));
			const replacementProbe = await getAuthBundle().auth.handler(new Request(
				"http://localhost:3300/api/auth/scim/v2/Users",
				{ headers: { authorization: `Bearer ${replacementScim.bearerTokenOnce}`, origin: "http://localhost:3300" } },
			));
			expect(oldProbe.status).toBe(401);
			expect(replacementProbe.ok).toBe(true);
			const auditJson = JSON.stringify(listEvents(store, { limit: 100 }));
			expect(auditJson).not.toContain(replacementScim.bearerTokenOnce);
			expect(auditJson).not.toContain("new-oidc-client-secret");
		});

		it("replays committed tenant SCIM create and rotate bearers without duplicate settlement", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const scope = resolveOperatorScope(store);
			const createOperationId = "33333333-3333-4333-8333-333333333333";
			const rotateOperationId = "44444444-4444-4444-8444-444444444444";

			const created = await createScimConnectionReal(store, {
				organizationId: organization.id,
				provider: "okta",
				endpoint: "https://scim.example.test/v2",
				scope,
				actor: "service-account-replay",
				source: "system",
				operationId: createOperationId,
			}, replayCipherGuard());
			const recoveredCreate = await createScimConnectionReal(store, {
				organizationId: organization.id,
				provider: "okta",
				endpoint: "https://scim.example.test/v2",
				scope,
				actor: "service-account-replay",
				source: "system",
				operationId: createOperationId,
			}, replayCipherGuard());
			expect(recoveredCreate.id).toBe(created.id);
			expect(recoveredCreate.bearerTokenOnce).toBe(created.bearerTokenOnce);

			await expect(createScimConnectionReal(store, {
				organizationId: organization.id,
				provider: "entra",
				endpoint: "https://scim.example.test/v2",
				scope,
				actor: "service-account-replay",
				source: "system",
				operationId: createOperationId,
			}, replayCipherGuard())).rejects.toMatchObject({ code: "SCIM_OPERATION_REPLAY_CONFLICT" });

			const rotated = await rotateScimCredentialAuthoritative(store, created.id, {
				scope,
				actor: "service-account-replay",
				source: "system",
				operationId: rotateOperationId,
			}, replayCipherGuard());
			const recoveredRotate = await rotateScimCredentialAuthoritative(store, created.id, {
				scope,
				actor: "service-account-replay",
				source: "system",
				operationId: rotateOperationId,
			}, replayCipherGuard());
			expect(recoveredRotate.replayed).toBe(true);
			expect(recoveredRotate.bearerTokenOnce).toBe(rotated.bearerTokenOnce);

			await expect(rotateScimCredentialAuthoritative(store, created.id, {
				scope,
				actor: "other-service-account",
				source: "system",
				operationId: rotateOperationId,
			}, replayCipherGuard())).rejects.toMatchObject({ code: "SCIM_OPERATION_REPLAY_CONFLICT" });

			await store.refresh();
			expect(store.snapshot.scimConnections.filter(
				(connection) => connection.organizationId === organization.id,
			)).toHaveLength(1);
			const audit = listEvents(store, { limit: 500 }).filter(
				(event) => event.subjectId === created.id,
			);
			expect(audit.filter((event) => event.action === "scim.create")).toHaveLength(1);
			expect(audit.filter((event) => event.action === "scim.rotate")).toHaveLength(1);
			const runtime = await getAuthBundle().pool.query(
				`select id from "scimProvider" where id = $1 and "organizationId" = $2`,
				[created.id, organization.id],
			);
			expect(runtime.rows).toHaveLength(1);
			const authority = await getAuthBundle().pool.query<{
				operation_id: string;
				bearer_token_encrypted: string;
			}>(
				`select operation_id, bearer_token_encrypted from ${store.scimOperationReplayTable!}
				 where organization_id = $1 and operation_id = any($2::text[])`,
				[organization.id, [createOperationId, rotateOperationId]],
			);
			expect(authority.rows).toHaveLength(2);
			const replayEnvelopes = authority.rows.map((row) =>
				parseKeyEnvelope(row.bearer_token_encrypted),
			);
			expect(replayEnvelopes).toHaveLength(2);
			expect(replayEnvelopes.every((envelope) =>
				envelope.purpose === "scim-bearer-token" &&
				envelope.projectId === scope.projectId &&
				envelope.environmentId === scope.environmentId,
			)).toBe(true);
			const serialized = JSON.stringify({ audit, authority: authority.rows });
			expect(serialized).not.toContain(created.bearerTokenOnce);
			expect(serialized).not.toContain(rotated.bearerTokenOnce);
		});

		it("does not append duplicate service-account credential audits on authority replay", async () => {
			const store = await freshStore();
			const { owner, organization, stamp } = await seedOwnerAndOrg(store);
			const scope = resolveOperatorScope(store);
			const account = await createServiceAccountInAuth(store, {
				organizationId: organization.id,
				serviceAccountId: `svc-replay-${stamp}`,
				name: "Replay machine",
				actor: owner.id,
				source: "cli",
				scope,
			});
			if ("preview" in account) throw new Error("service account unexpectedly previewed");
			const createInput = {
				organizationId: organization.id,
				serviceAccountId: account.serviceAccount.serviceAccountId,
				actor: owner.id,
				source: "cli" as const,
				scope,
				operationId: "b11c0001-0000-4000-8000-000000000001",
			};
			const created = await createServiceAccountCredentialInAuth(store, createInput);
			const replayedCreate = await createServiceAccountCredentialInAuth(store, createInput);
			if ("preview" in created || "preview" in replayedCreate) throw new Error("credential unexpectedly previewed");
			expect(replayedCreate.secret).toBe(created.secret);
			const rotateInput = {
				...createInput,
				credentialId: created.credential.credentialId,
				operationId: "b11c0002-0000-4000-8000-000000000002",
			};
			const rotated = await rotateServiceAccountCredentialInAuth(store, rotateInput);
			const replayedRotate = await rotateServiceAccountCredentialInAuth(store, rotateInput);
			if ("preview" in rotated || "preview" in replayedRotate) throw new Error("credential unexpectedly previewed");
			expect(replayedRotate.secret).toBe(rotated.secret);
			const audits = listEvents(store, { limit: 500 }).filter(
				(event) => event.organizationId === organization.id,
			);
			expect(audits.filter((event) => event.action === "authorization.credentials.create")).toHaveLength(1);
			expect(audits.filter((event) => event.action === "authorization.credentials.rotate")).toHaveLength(1);
		});

		it("cross-scope archive fails closed with no write", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const beforeEvents = listEvents(store, { limit: 500 }).length;

			await expect(
				archiveOrganizationInAuth(store, organization.id, {
					confirm: true,
					scope: {
						projectId: "proj_foreign_orglc",
						environmentId: "env_foreign_orglc",
					},
					actor: "test",
				}),
			).rejects.toMatchObject({ code: "ORG_NOT_FOUND" });

			expect(await runtimeOrgRow(organization.id)).toBeTruthy();
			expect(
				store.snapshot.organizations.find((o) => o.id === organization.id)
					?.status,
			).toBe("active");
			expect(listEvents(store, { limit: 500 }).length).toBe(beforeEvents);
		});

		it("injected SQL failure rolls back update (runtime + management + audit)", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const beforeName = organization.name;
			const beforeSlug = organization.slug;
			const beforeEvents = listEvents(store, { limit: 500 }).length;

			const restore = injectSqlFailureAfter(store, (sql) =>
				sql.includes("update organization"),
			);
			try {
				await expect(
					updateOrganizationInAuth(store, organization.id, {
						name: "Poisoned Name",
						slug: `poison-${organization.slug.slice(-10)}`,
						actor: "test",
					}),
				).rejects.toBeTruthy();
			} finally {
				restore();
			}

			// Refresh in-memory from DB after failed TX
			await store.refresh();
			const mgmt = store.snapshot.organizations.find(
				(o) => o.id === organization.id,
			);
			expect(mgmt?.name).toBe(beforeName);
			expect(mgmt?.slug).toBe(beforeSlug);
			const runtime = await runtimeOrgRow(organization.id);
			expect(runtime?.name).toBe(beforeName);
			expect(runtime?.slug).toBe(beforeSlug);
			expect(listEvents(store, { limit: 500 }).length).toBe(beforeEvents);
		});

		it("injected SQL failure rolls back archive (runtime + management + audit)", async () => {
			const store = await freshStore();
			const { owner, organization } = await seedOwnerAndOrg(store);
			const authorization = getAuthBundle().authorization;
			if (!authorization) throw new Error("authorization authority unavailable");
			await authorization.createServiceAccount({
				organizationId: organization.id,
				serviceAccountId: `svc-rollback-${organization.id}`,
				name: "Rollback machine",
				roleIds: ["role_builtin_member"],
			});
			const machineCredential = await authorization.createServiceAccountCredential({
				organizationId: organization.id,
				actorId: owner.id,
				operationId: "a11c0002-0000-4000-8000-000000000002",
				serviceAccountId: `svc-rollback-${organization.id}`,
				credentialId: `cred-rollback-${organization.id}`,
			});
			const beforeMembers = await runtimeMemberCount(organization.id);
			const beforeEvents = listEvents(store, { limit: 500 }).length;

			const restore = injectSqlFailureAfter(
				store,
				(sql) =>
					sql.includes("delete from organization") ||
					sql.includes('delete from "organization"'),
			);
			try {
				await expect(
					archiveOrganizationInAuth(store, organization.id, {
						confirm: true,
						actor: "test",
					}),
				).rejects.toBeTruthy();
			} finally {
				restore();
			}

			await store.refresh();
			expect(await runtimeOrgRow(organization.id)).toBeTruthy();
			expect(await runtimeMemberCount(organization.id)).toBe(beforeMembers);
			expect(
				store.snapshot.organizations.find((o) => o.id === organization.id)
					?.status,
			).toBe("active");
			expect(
				store.snapshot.memberships.filter(
					(m) =>
						m.organizationId === organization.id && m.status === "active",
				).length,
			).toBeGreaterThanOrEqual(1);
			expect(listEvents(store, { limit: 500 }).length).toBe(beforeEvents);
			await expect(
				authorization.readEffective({
					organizationId: organization.id,
					subject: { kind: "principal", id: owner.id },
				}),
			).resolves.toMatchObject({ organizationId: organization.id });
			await expect(
				authorization.authenticateServiceAccountCredential({
					secret: machineCredential.secret,
				}),
			).resolves.toMatchObject({ organizationId: organization.id });
		});

		it("stable organization id is preserved across update and archive tombstone", async () => {
			const store = await freshStore();
			const { organization } = await seedOwnerAndOrg(store);
			const stableId = organization.id;

			const updated = await updateOrganizationInAuth(store, stableId, {
				name: "Stable Id Org",
				actor: "test",
			});
			expect(updated.id).toBe(stableId);
			expect((await runtimeOrgRow(stableId))?.id).toBe(stableId);

			const archived = await archiveOrganizationInAuth(store, stableId, {
				confirm: true,
				actor: "test",
			});
			expect(archived.organization.id).toBe(stableId);
			expect(
				store.snapshot.organizations.find((o) => o.id === stableId)?.status,
			).toBe("archived");
			expect(await runtimeOrgRow(stableId)).toBeUndefined();
		});

		it("uses relational-authoritative organizations after topology cutover", async () => {
			const { store, scope } = await freshTopologyStore();
			const { owner, organization } = await seedOwnerAndOrg(store);
			await store.storeV2!.apply();
			await store.storeV2!.cutoverEvents();
			await store.storeV2!.cutoverTopology();

			expect(store.storeV2Topology?.authoritative).toBe(true);
			expect(store.snapshot.organizations).toEqual([]);

			const provisioned = await provisionOrganizationInAuth(store, {
				name: "Relational Provisioned Org",
				slug: `relational-${organization.slug.slice(-12)}`,
				ownerUserId: owner.id,
				scope,
				actor: "test",
			});
			trackOrg(provisioned);
			expect(
				await store.storeV2Topology!.getOrganization({
					scope,
					id: provisioned.id,
				}),
			).toMatchObject({ id: provisioned.id, status: "active" });

			const updated = await updateOrganizationInAuth(store, organization.id, {
				name: "Relational Authority Org",
				scope,
				actor: "test",
			});
			expect(updated.name).toBe("Relational Authority Org");
			expect((await runtimeOrgRow(organization.id))?.name).toBe(updated.name);
			expect(
				await store.storeV2Topology!.getOrganization({
					scope,
					id: organization.id,
				}),
			).toMatchObject({ name: updated.name, status: "active" });

			const dryRun = await archiveOrganizationInAuth(store, organization.id, {
				dryRun: true,
				scope,
				actor: "test",
			});
			expect(dryRun).toMatchObject({ dryRun: true, wouldChange: true });

			const archived = await archiveOrganizationInAuth(store, organization.id, {
				confirm: true,
				scope,
				actor: "test",
			});
			expect(archived.organization).toMatchObject({
				id: organization.id,
				status: "archived",
			});
			expect(await runtimeOrgRow(organization.id)).toBeUndefined();
			expect(await runtimeMemberCount(organization.id)).toBe(0);
			expect(
				await store.storeV2Topology!.getOrganization({
					scope,
					id: organization.id,
				}),
			).toMatchObject({ status: "archived" });
			expect(
				store.snapshot.memberships.filter(
					(member) => member.organizationId === organization.id,
				).every((member) => member.status === "removed"),
			).toBe(true);

			const events = await getAuthBundle().pool.query<{
				action: string;
				subject_id: string;
			}>(
				`select action, subject_id from ${TOPOLOGY_PREFIX}events
				 where subject_id = $1 and action in ('orgs.update', 'orgs.archive')`,
				[organization.id],
			);
			expect(events.rows).toEqual(expect.arrayContaining([
				{ action: "orgs.update", subject_id: organization.id },
				{ action: "orgs.archive", subject_id: organization.id },
			]));
		});

		it("applies SCIM users atomically and rolls every plane back on a late failure", async () => {
			const { store, scope } = await freshTopologyStore();
			const { organization } = await seedOwnerAndOrg(store);
			await store.storeV2!.apply();
			await store.storeV2!.cutoverEvents();
			await store.storeV2!.cutoverPrincipals();
			await store.storeV2!.cutoverTopology();

			const connection = await createScimConnectionReal(store, {
				organizationId: organization.id,
				provider: "okta",
				scope,
			});
			const successEmail = `scim-success-${Date.now()}@org-lc.test`;
			const success = await testScimConnectionReal(store, connection.id, {
				dryRun: false,
				bearerToken: connection.bearerTokenOnce,
				scope,
				users: [{ userName: successEmail, displayName: "SCIM Success" }],
			});
			expect(success.pass).toBe(true);
			const runtime = await getAuthBundle().pool.query(
				`select id from "user" where lower(email) = lower($1)`,
				[successEmail],
			);
			expect(runtime.rows).toHaveLength(1);
			expect(
				await store.storeV2Principals!.getById({
					scope,
					id: String(runtime.rows[0]!.id),
				}),
			).toMatchObject({ email: successEmail });

			const rollbackEmail = `scim-rollback-${Date.now()}@org-lc.test`;
			const tracesBefore = store.snapshot.traces.length;
			const eventsBefore = listEvents(store, { limit: 500 }).length;
			const restore = injectSqlFailureAfter(store, (sql) =>
				sql.includes("insert into account"),
			);
			try {
				await expect(
					testScimConnectionReal(store, connection.id, {
						dryRun: false,
						bearerToken: connection.bearerTokenOnce,
						scope,
						users: [{ userName: rollbackEmail, displayName: "SCIM Rollback" }],
					}),
				).rejects.toBeTruthy();
			} finally {
				restore();
			}
			await store.refresh();
			const rolledBackRuntime = await getAuthBundle().pool.query(
				`select id from "user" where lower(email) = lower($1)`,
				[rollbackEmail],
			);
			expect(rolledBackRuntime.rows).toHaveLength(0);
			expect(
				await store.storeV2Principals!.findActiveByEmail({
					scope,
					email: rollbackEmail,
				}),
			).toBeNull();
			expect(store.snapshot.traces).toHaveLength(tracesBefore);
			expect(listEvents(store, { limit: 500 })).toHaveLength(eventsBefore);
		});

		it("executes and cleans the scoped SCIM Group lifecycle with merged runtime audits", async () => {
			const { store, scope } = await freshTopologyStore();
			const { organization } = await seedOwnerAndOrg(store);
			await store.storeV2!.apply();
			await store.storeV2!.cutoverEvents();
			await store.storeV2!.cutoverPrincipals();
			await store.storeV2!.cutoverTopology();
			const connection = await createScimConnectionReal(store, {
				organizationId: organization.id,
				provider: "group-lifecycle-primary",
				scope,
			});
			const other = await createScimConnectionReal(store, {
				organizationId: organization.id,
				provider: "group-lifecycle-other",
				scope,
			});
			await expect(testScimConnectionReal(store, other.id, {
				dryRun: false,
				scenario: "group-lifecycle",
				bearerToken: connection.bearerTokenOnce,
				scope,
			})).rejects.toMatchObject({ code: "SCIM_UNAUTHORIZED" });
			const result = await testScimConnectionReal(store, connection.id, {
				dryRun: false,
				scenario: "group-lifecycle",
				bearerToken: connection.bearerTokenOnce,
				scope,
			});
			expect(result.groupLifecycle).toMatchObject({
				group: { status: "deleted" },
				counts: { usersCreated: 2, membersCreated: 1, membersAfterPatch: 2 },
				actions: { create: 201, patch: 200, get: 200, list: 200, delete: 204 },
			});
			const merged = await listEventsPageOperational(store, {
				scope,
				organizationId: organization.id,
				limit: 100,
			});
			const lifecycle = merged.events.filter((event) => ["scim.group.created", "scim.group.updated", "scim.group.deleted"].includes(event.action));
			expect(lifecycle.map((event) => event.action).sort()).toEqual([
				"scim.group.created", "scim.group.deleted", "scim.group.updated",
			]);
			for (const event of lifecycle) {
				expect(event).toMatchObject({ projectId: scope.projectId, environmentId: scope.environmentId, organizationId: organization.id, source: "scim" });
			}
			expect(merged.events.filter((event) => event.action === "scim.test" && event.subjectId === connection.id)).toHaveLength(1);
			const serialized = JSON.stringify(merged.events);
			expect(serialized).not.toContain(connection.bearerTokenOnce!);
			expect(serialized).not.toContain("@example.invalid");
			const generated = await getAuthBundle().pool.query(`select count(*)::int as count from "user" where email like 'scim-group-%@example.invalid'`);
			expect(Number(generated.rows[0]?.count ?? 0)).toBe(0);
		});

		it("reconciles a locked runtime owner membership into normalized authorization without partial writes", async () => {
			delete process.env.CLEARANCE_PROJECT_ID;
			delete process.env.CLEARANCE_ENV_ID;
			const store = await freshStore();
			const scope = resolveOperatorScope(store);
			const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
			const owner = await createUserInAuth({
				email: `reconcile-owner-${stamp}@org-lc.test`,
				name: "Reconcile Owner",
				password: "OrgLifecycle1!",
				managementStore: store,
			});
			trackUser(owner);
			const wrongOwner = await createUserInAuth({
				email: `reconcile-wrong-${stamp}@org-lc.test`,
				name: "Wrong Owner",
				password: "OrgLifecycle1!",
				managementStore: store,
			});
			trackUser(wrongOwner);
			const runtimeOrg = await createOrgInAuth({
				name: `Reconcile ${stamp}`,
				slug: `reconcile-${stamp}`,
				userId: owner.id,
			});
			trackOrg(runtimeOrg);
			if (!runtimeOrg.ownerMembershipId) throw new Error("runtime owner membership missing");
			trackMember(runtimeOrg.ownerMembershipId);

			await expect(
				syncRuntimeOrganizationToManagementDurable(store, runtimeOrg, wrongOwner.id, {
					scope,
					actor: "test",
				}),
			).rejects.toMatchObject({ code: "RUNTIME_OWNER_MEMBERSHIP_MISMATCH" });
			expect(store.snapshot.organizations.some((organization) => organization.id === runtimeOrg.id)).toBe(false);
			expect(store.snapshot.memberships.some((membership) => membership.organizationId === runtimeOrg.id)).toBe(false);

			const reconciled = await syncRuntimeOrganizationToManagementDurable(store, runtimeOrg, owner.id, {
				scope,
				actor: "test",
			});
			expect(reconciled).toMatchObject({ id: runtimeOrg.id, slug: runtimeOrg.slug });
			expect(store.snapshot.memberships.find((membership) => membership.organizationId === runtimeOrg.id && membership.principalId === owner.id)).toMatchObject({
			id: runtimeOrg.ownerMembershipId,
			role: "owner",
			status: "active",
		});
			const authorization = getAuthBundle().authorization;
			if (!authorization) throw new Error("authorization authority unavailable");
			expect((await authorization.readEffective({
				organizationId: runtimeOrg.id,
				subject: { kind: "principal", id: owner.id },
			})).roleIds).toEqual(["role_builtin_owner"]);
			await getAuthBundle().pool.query(
				`delete from clearance_authz_subject_role_assignments
				 where "projectId" = $1 and "environmentId" = $2
				 and "organizationId" = $3 and "subjectKind" = 'principal'
				 and "subjectId" = $4 and "roleId" = 'role_builtin_owner'`,
				[scope.projectId, scope.environmentId, runtimeOrg.id, owner.id],
			);
			const authorizationAuditCount = listEvents(store, { limit: 500 }).filter(
				(event) => event.organizationId === runtimeOrg.id && event.action === "authorization.owner.reconcile",
			).length;
			await syncRuntimeOrganizationToManagementDurable(store, runtimeOrg, owner.id, {
				scope,
				actor: "test",
			});
			expect((await authorization.readEffective({
				organizationId: runtimeOrg.id,
				subject: { kind: "principal", id: owner.id },
			})).roleIds).toEqual(["role_builtin_owner"]);
			expect(listEvents(store, { limit: 500 }).filter(
				(event) => event.organizationId === runtimeOrg.id && event.action === "authorization.owner.reconcile",
			).length).toBe(authorizationAuditCount + 1);
			await syncRuntimeOrganizationToManagementDurable(store, runtimeOrg, owner.id, {
				scope,
				actor: "test",
			});
			expect(listEvents(store, { limit: 500 }).filter(
				(event) => event.organizationId === runtimeOrg.id && event.action === "authorization.owner.reconcile",
			).length).toBe(authorizationAuditCount + 1);

			const auditCount = listEvents(store, { limit: 500 }).filter(
				(event) => event.organizationId === runtimeOrg.id && event.action.startsWith("orgs."),
			).length;
			await syncRuntimeOrganizationToManagementDurable(store, runtimeOrg, owner.id, {
				scope,
				actor: "test",
			});
			expect(listEvents(store, { limit: 500 }).filter(
				(event) => event.organizationId === runtimeOrg.id && event.action.startsWith("orgs."),
			).length).toBe(auditCount);
		});

		it("commits runtime first-organization state and the scoped management projection together", async () => {
			const { store, scope } = await freshTopologyStore();
			await store.storeV2!.apply();
			await store.storeV2!.cutoverEvents();
			await store.storeV2!.cutoverPrincipals();
			await store.storeV2!.cutoverTopology();
			const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
			const lifecycle = createManagedOrganizationLifecycleFacade({ store, scope });
			const runtime = createClearanceManagementAuth({
				baseURL: "http://localhost:3300",
				secret: "managed-org-transaction-test-secret!!",
				databaseUrl: DATABASE_URL,
				enableSso: false,
				enableScim: false,
				passkeys: false,
				rateLimitEnabled: false,
				authenticationPolicy: scope,
				authorization: scope,
				tenantProductAdministration: createTenantProductAdministrationFacade({ store, scope }),
				managedOrganizationLifecycle: lifecycle,
			});
			try {
				await runtime.migrate();
				const email = `managed-create-${suffix}@org-lc.test`;
				const signedUp = await runtime.auth.api.signUpEmail({
					body: { email, password: "OrgLifecycle1!", name: "Managed Owner" },
				});
				trackUser(signedUp.user);
				const signIn = await runtime.auth.handler(new Request(
					"http://localhost:3300/api/auth/sign-in/email",
					{ method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:3300" }, body: JSON.stringify({ email, password: "OrgLifecycle1!" }) },
				));
				const cookie = signIn.headers.getSetCookie().find((value) => value.startsWith("clearance.session_token="))?.split(";", 1)[0];
				expect(cookie).toBeTruthy();
				const created = await runtime.auth.api.createOrganization({
					body: { name: "Managed Transaction", slug: `managed-${suffix}` },
					headers: new Headers({ cookie: cookie!, origin: "http://localhost:3300" }),
					asResponse: true,
				});
				expect(created.status).toBe(200);
				const organization = await created.json() as { id: string; members: Array<{ id: string }> };
				trackOrg(organization);
				trackMember(organization.members[0]!.id);
				await store.refresh();
				const normalized = await runtime.pool.query(
					`select (select count(*)::int from ${TOPOLOGY_PREFIX}principals where id = $1) as principals,
					        (select count(*)::int from ${TOPOLOGY_PREFIX}organizations where id = $2) as organizations,
					        (select count(*)::int from ${TOPOLOGY_PREFIX}events where organization_id = $2 and action = 'orgs.create.runtime_managed') as audits`,
					[signedUp.user.id, organization.id],
				);
				expect(normalized.rows[0]).toMatchObject({ principals: 1, organizations: 1, audits: 1 });
				expect(store.snapshot.memberships.find((membership) => membership.id === organization.members[0]!.id)).toMatchObject({ organizationId: organization.id, principalId: signedUp.user.id, role: "owner", status: "active" });
				expect(listEvents(store, { limit: 100 }).some((event) => event.organizationId === organization.id && event.action === "orgs.create.runtime_managed" && JSON.stringify(event.metadata).includes(email))).toBe(false);
				expect((await runtime.authorization!.readEffective({ organizationId: organization.id, subject: { kind: "principal", id: signedUp.user.id } })).roleIds).toEqual(["role_builtin_owner"]);
				const session = await runtime.pool.query(`select "activeOrganizationId" from session where "userId" = $1 order by "createdAt" desc limit 1`, [signedUp.user.id]);
				expect(session.rows[0]?.activeOrganizationId).toBe(organization.id);

				const failing = createClearanceManagementAuth({
					baseURL: "http://localhost:3300", secret: "managed-org-transaction-test-secret!!", databaseUrl: DATABASE_URL,
					enableSso: false, enableScim: false, passkeys: false, rateLimitEnabled: false, authenticationPolicy: scope, authorization: scope,
					tenantProductAdministration: createTenantProductAdministrationFacade({ store, scope }),
					managedOrganizationLifecycle: { ...lifecycle, async finalizeCreatedOrganization(input) { await lifecycle.finalizeCreatedOrganization(input); throw new Error("injected lifecycle failure"); } },
				});
				try {
					const failedEmail = `managed-rollback-${suffix}@org-lc.test`;
					const failedUser = await failing.auth.api.signUpEmail({ body: { email: failedEmail, password: "OrgLifecycle1!", name: "Rollback Owner" } });
					trackUser(failedUser.user);
					const failedSignIn = await failing.auth.handler(new Request("http://localhost:3300/api/auth/sign-in/email", { method: "POST", headers: { "content-type": "application/json", origin: "http://localhost:3300" }, body: JSON.stringify({ email: failedEmail, password: "OrgLifecycle1!" }) }));
					const failedCookie = failedSignIn.headers.getSetCookie().find((value) => value.startsWith("clearance.session_token="))?.split(";", 1)[0];
					const failedCreate = await failing.auth.handler(new Request(
						"http://localhost:3300/api/auth/organization/create",
						{ method: "POST", headers: { "content-type": "application/json", cookie: failedCookie!, origin: "http://localhost:3300" }, body: JSON.stringify({ name: "Rollback Transaction", slug: `rollback-${suffix}` }) },
					));
					expect(failedCreate.status).toBe(500);
					expect(failedCreate.headers.get("set-cookie")).toBeNull();
					expect((await failing.pool.query(`select id from organization where slug = $1`, [`rollback-${suffix}`])).rows).toHaveLength(0);
					expect((await failing.pool.query(`select id from member where "userId" = $1`, [failedUser.user.id])).rows).toHaveLength(0);
					expect((await failing.pool.query(`select 1 from clearance_authz_subject_role_assignments where "organizationId" = $1`, [`rollback-${suffix}`])).rows).toHaveLength(0);
					const failedSession = await failing.pool.query(`select "activeOrganizationId" from session where "userId" = $1 order by "createdAt" desc limit 1`, [failedUser.user.id]);
					expect(failedSession.rows[0]?.activeOrganizationId ?? null).toBeNull();
					await store.refresh();
					expect(store.snapshot.organizations.some((candidate) => candidate.slug === `rollback-${suffix}`)).toBe(false);
					expect(store.snapshot.memberships.some((membership) => membership.principalId === failedUser.user.id)).toBe(false);
					expect((await failing.pool.query(`select count(*)::int as count from ${TOPOLOGY_PREFIX}principals where id = $1`, [failedUser.user.id])).rows[0]?.count).toBe(0);
					expect((await failing.pool.query(`select count(*)::int as count from ${TOPOLOGY_PREFIX}organizations where slug = $1`, [`rollback-${suffix}`])).rows[0]?.count).toBe(0);
					expect((await failing.pool.query(`select count(*)::int as count from ${TOPOLOGY_PREFIX}events where organization_id = $1`, [`rollback-${suffix}`])).rows[0]?.count).toBe(0);
				} finally { await failing.destroy(); }
			} finally { await runtime.destroy(); }
		});
	},
);
