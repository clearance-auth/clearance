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
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import {
	createPgStore,
	type PgStore,
	type PgStoreDeliveryOptions,
} from "../store/pg-store.js";
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
	createOrgInAuth,
	createUserInAuth,
	ensureAuthMigrated,
	getAuthBundle,
	resetAuthBundle,
	updateOrganizationInAuth,
} from "../auth-bridge.js";
import {
	initProject,
	listEvents,
	resolveOperatorScope,
	syncRuntimeOrganizationToManagementDurable,
} from "../index.js";

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

type CoordinatedFn = NonNullable<PgStore["mutateCoordinated"]>;

/**
 * After the real mutator completes (runtime + management draft applied), force
 * a SQL error so COMMIT never lands — full rollback of runtime + management + audit.
 */
function injectSqlFailureAfter(
	store: PgStore,
	match: (sql: string) => boolean,
): () => void {
	const original = store.mutateCoordinated.bind(store) as CoordinatedFn;
	const wrapped: CoordinatedFn = (fn) =>
		original(async (ctx) => {
			let saw = false;
			const value = await fn({
				data: ctx.data,
				query: async (sql, params) => {
					const result = await ctx.query(sql, params);
					if (match(sql.replace(/\s+/g, " ").toLowerCase())) {
						saw = true;
					}
					return result;
				},
				...(ctx.enqueueDelivery
					? { enqueueDelivery: ctx.enqueueDelivery }
					: {}),
			});
			if (saw) {
				await ctx.query(
					`select 1 from "clearance_org_lc_poison_${process.pid}"`,
				);
			}
			return value;
		});
	store.mutateCoordinated = wrapped;
	return () => {
		store.mutateCoordinated = original;
	};
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
		};

		process.env.DATABASE_URL = DATABASE_URL;
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_BASE_URL = "http://localhost:3300";
		process.env.NODE_ENV = "development";

		afterEach(async () => {
			await cleanupTracked().catch(() => undefined);
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
						channel: "webhook",
						destination: webhookTarget.url,
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
			const { organization } = await seedOwnerAndOrg(store);
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
	},
);
