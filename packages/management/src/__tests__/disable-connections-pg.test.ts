/**
 * Live Postgres proofs for disableSsoConnectionReal / disableScimConnectionReal.
 *
 * Proves coordinated atomicity on PgStore.mutateCoordinated:
 * 1. runtime ssoProvider/scimProvider row delete + management status=disabled +
 *    exactly one matching audit event commit together;
 * 2. idempotent repeat behavior;
 * 3. cross-scope disable fails closed with zero writes;
 * 4. injected runtime SQL failure rolls back management status and audit.
 *
 * Isolation: unique management snapshot table + exact tracked runtime fixture
 * IDs only. Cleanup never touches shared/pre-existing rows.
 */
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import {
	ensureAuthMigrated,
	getAuthBundle,
	resetAuthBundle,
} from "../auth-bridge.js";
import {
	createOrganization,
	disableScimConnectionReal,
	disableSsoConnectionReal,
	initProject,
	listEvents,
	resolveOperatorScope,
} from "../index.js";
import { ClearanceError } from "../services/errors.js";
import type { ManagementStore } from "../store/types.js";
import type { DataStoreSnapshot } from "../types/resources.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	"postgres://user:password@127.0.0.1:55432/clearance";

const TEST_TABLE = `clearance_mgmt_disable_conn_${process.pid}`;
const ORG_ID = `org_dis_fx_${process.pid}`;
const ORG_FOREIGN_ID = `org_dis_fx_${process.pid}_foreign`;

/** Per-test trackers (cleared after each cleanup). */
const createdRuntimeUserIds = new Set<string>();
const createdRuntimeEmails = new Set<string>();
const createdSsoProviderIds = new Set<string>();
const createdScimProviderIds = new Set<string>();
/** Suite-lifetime trackers for afterAll safety-net cleanup. */
const allRuntimeUserIds = new Set<string>();
const allRuntimeEmails = new Set<string>();
const allSsoProviderIds = new Set<string>();
const allScimProviderIds = new Set<string>();

let fixtureSeq = 0;

/** Exact, suite-owned fixture IDs (pid + monotonic seq — never shared rows). */
function nextFixtureIds(kind: "sso" | "scim" | "sso_foreign" | "scim_foreign") {
	fixtureSeq += 1;
	const stamp = `${process.pid}_${fixtureSeq}`;
	if (kind === "sso") {
		return {
			connectionId: `sso_dis_fx_${stamp}`,
			providerId: `sso_dis_fx_${stamp}_provider`,
		};
	}
	if (kind === "scim") {
		return {
			connectionId: `scim_dis_fx_${stamp}`,
			providerId: `scim_dis_fx_${stamp}_provider`,
		};
	}
	if (kind === "sso_foreign") {
		return {
			connectionId: `sso_dis_fx_${stamp}_foreign`,
			providerId: `sso_dis_fx_${stamp}_foreign_provider`,
		};
	}
	return {
		connectionId: `scim_dis_fx_${stamp}_foreign`,
		providerId: `scim_dis_fx_${stamp}_foreign_provider`,
	};
}


function trackUser(user: { id: string; email?: string | null }): void {
	createdRuntimeUserIds.add(user.id);
	allRuntimeUserIds.add(user.id);
	if (user.email) {
		const email = String(user.email).toLowerCase();
		createdRuntimeEmails.add(email);
		allRuntimeEmails.add(email);
	}
}

function trackSso(id: string): void {
	createdSsoProviderIds.add(id);
	allSsoProviderIds.add(id);
}

function trackScim(id: string): void {
	createdScimProviderIds.add(id);
	allScimProviderIds.add(id);
}

/** Delete only exact runtime fixture IDs created by this suite. */
async function cleanupTrackedRuntime(opts?: {
	users?: Iterable<string>;
	emails?: Iterable<string>;
	sso?: Iterable<string>;
	scim?: Iterable<string>;
}): Promise<void> {
	const ssoIds = [...(opts?.sso ?? createdSsoProviderIds)];
	const scimIds = [...(opts?.scim ?? createdScimProviderIds)];
	const userIds = [...(opts?.users ?? createdRuntimeUserIds)];
	const emails = new Set(
		[...(opts?.emails ?? createdRuntimeEmails)].map((e) => e.toLowerCase()),
	);

	const pool = new pg.Pool({ connectionString: DATABASE_URL });
	try {
		if (ssoIds.length > 0) {
			await pool
				.query(`delete from "ssoProvider" where id = any($1::text[])`, [ssoIds])
				.catch(() => undefined);
		}
		if (scimIds.length > 0) {
			await pool
				.query(`delete from "scimProvider" where id = any($1::text[])`, [
					scimIds,
				])
				.catch(() => undefined);
		}
		if (userIds.length > 0) {
			const emailRes = await pool
				.query(`select email from "user" where id = any($1::text[])`, [userIds])
				.catch(() => ({ rows: [] as { email: string }[] }));
			for (const row of emailRes.rows) {
				if (row.email) emails.add(String(row.email).toLowerCase());
			}
			for (const sql of [
				`delete from session where "userId" = any($1::text[])`,
				`delete from account where "userId" = any($1::text[])`,
				`delete from member where "userId" = any($1::text[])`,
				`delete from invitation where "inviterId" = any($1::text[])`,
				`delete from "ssoProvider" where "userId" = any($1::text[])`,
			]) {
				await pool.query(sql, [userIds]).catch(() => undefined);
			}
			if (emails.size > 0) {
				await pool
					.query(
						`delete from verification where lower(identifier) = any($1::text[])`,
						[[...emails]],
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

type CoordinatedFn = NonNullable<ManagementStore["mutateCoordinated"]>;

/**
 * Wrap mutateCoordinated so runtime DELETE + management mutator/audit run in
 * the open transaction, then a deliberate runtime SQL error forces ROLLBACK of
 * the runtime row, management status, and audit together.
 */
function injectRuntimeSqlFailureAfterMutator(
	store: PgStore,
	table: "ssoProvider" | "scimProvider",
): () => void {
	const original = store.mutateCoordinated.bind(store) as CoordinatedFn;
	const wrapped: CoordinatedFn = (fn) =>
		original(async (ctx) => {
			let sawTargetDelete = false;
			const value = await fn({
				data: ctx.data,
				query: async (sql, params) => {
					const result = await ctx.query(sql, params);
					const normalized = sql.replace(/\s+/g, " ").toLowerCase();
					const quoted = `delete from "${table.toLowerCase()}"`;
					const bare = `delete from ${table.toLowerCase()}`;
					if (normalized.includes(quoted) || normalized.includes(bare)) {
						sawTargetDelete = true;
					}
					return result;
				},
			});
			if (sawTargetDelete) {
				// Fail after draft management mutation so COMMIT never lands.
				await ctx.query(
					`select 1 from "clearance_disable_conn_poison_${process.pid}"`,
				);
			}
			return value;
		});
	store.mutateCoordinated = wrapped;
	return () => {
		store.mutateCoordinated = original;
	};
}

async function runtimeSsoExists(id: string): Promise<boolean> {
	const b = getAuthBundle();
	const r = await b.pool.query(
		`select id from "ssoProvider" where id = $1 limit 1`,
		[id],
	);
	return r.rows.length > 0;
}

async function runtimeScimExists(id: string): Promise<boolean> {
	const b = getAuthBundle();
	const r = await b.pool.query(
		`select id from "scimProvider" where id = $1 limit 1`,
		[id],
	);
	return r.rows.length > 0;
}

function disableAudits(
	store: ManagementStore,
	action: "sso.disable" | "scim.disable",
	subjectId: string,
) {
	return listEvents(store, { limit: 500 }).filter(
		(e) => e.action === action && e.subjectId === subjectId,
	);
}

const available = await gatePostgresSuite(DATABASE_URL, "disable-connections-pg");

describe.skipIf(!available)(
	"disable SSO/SCIM connections Postgres coordinated",
	() => {
		const stores: PgStore[] = [];
		const prev = {
			DATABASE_URL: process.env.DATABASE_URL,
			CLEARANCE_SECRET: process.env.CLEARANCE_SECRET,
			CLEARANCE_BASE_URL: process.env.CLEARANCE_BASE_URL,
			NODE_ENV: process.env.NODE_ENV,
			CLEARANCE_PROJECT_ID: process.env.CLEARANCE_PROJECT_ID,
			CLEARANCE_ENV_ID: process.env.CLEARANCE_ENV_ID,
			CLEARANCE_CREDENTIAL_KEY: process.env.CLEARANCE_CREDENTIAL_KEY,
			CLEARANCE_CREDENTIAL_KEY_ID: process.env.CLEARANCE_CREDENTIAL_KEY_ID,
		};

		process.env.DATABASE_URL = DATABASE_URL;
		process.env.CLEARANCE_SECRET = "unit-test-secret-value-not-default!!";
		process.env.CLEARANCE_BASE_URL = "http://localhost:3300";
		process.env.NODE_ENV = "development";
		process.env.CLEARANCE_CREDENTIAL_KEY =
			"unit-test-credential-key-material-32b!!";
		process.env.CLEARANCE_CREDENTIAL_KEY_ID = "k1";

		afterEach(async () => {
			await cleanupTrackedRuntime().catch(() => undefined);
			createdRuntimeUserIds.clear();
			createdRuntimeEmails.clear();
			createdSsoProviderIds.clear();
			createdScimProviderIds.clear();
			resetAuthBundle();
		});

		afterAll(async () => {
			// Safety-net: exact suite-lifetime fixture IDs only (never shared rows).
			await cleanupTrackedRuntime({
				users: allRuntimeUserIds,
				emails: allRuntimeEmails,
				sso: allSsoProviderIds,
				scim: allScimProviderIds,
			}).catch(() => undefined);
			for (const s of stores.splice(0)) {
				await s.destroy().catch(() => undefined);
			}
			resetAuthBundle();
			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				// Drop only this suite's unique management tables.
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

		async function freshStore(): Promise<PgStore> {
			const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
			stores.push(store);
			await store.refresh();
			if (store.snapshot.projects.length === 0) {
				initProject(store, { name: "Disable Conn PG", source: "cli" });
				await store.ready();
			}
			const scope = resolveOperatorScope(store);
			process.env.CLEARANCE_PROJECT_ID = scope.projectId;
			process.env.CLEARANCE_ENV_ID = scope.environmentId;
			await ensureAuthMigrated();
			return store;
		}

		/**
		 * Runtime-only user for ssoProvider.userId FK. Avoids management
		 * principal sync so afterEach user cleanup cannot leave email conflicts.
		 */
		async function ensureFkUser(_store: PgStore): Promise<string> {
			const email = `disable-conn-${process.pid}@disable.test`;
			const b = getAuthBundle();
			const existing = await b.pool.query(
				`select id from "user" where email = $1 limit 1`,
				[email],
			);
			if (existing.rows[0]?.id) {
				const id = String(existing.rows[0].id);
				trackUser({ id, email });
				return id;
			}
			const id = `user_dis_fx_${process.pid}`;
			await b.pool.query(
				`insert into "user" (id, email, name, "emailVerified", "createdAt", "updatedAt")
         values ($1, $2, $3, false, now(), now())`,
				[id, email, "Disable Conn FK"],
			);
			trackUser({ id, email });
			return id;
		}

		async function seedScopedOrg(store: PgStore) {
			const existing = store.snapshot.organizations.find((o) => o.id === ORG_ID);
			if (existing) return existing;
			const org = createOrganization(store, {
				id: ORG_ID,
				name: "Disable Conn Org",
				slug: `dis-conn-${process.pid}`,
			});
			await store.ready();
			return org;
		}

		async function seedSsoFixture(store: PgStore): Promise<{
			connectionId: string;
			organizationId: string;
		}> {
			const org = await seedScopedOrg(store);
			const { connectionId, providerId } = nextFixtureIds("sso");
			const userId = await ensureFkUser(store);
			const now = new Date().toISOString();

			store.mutate((data: DataStoreSnapshot) => {
				data.identityConnections.push({
					id: connectionId,
					organizationId: org.id,
					protocol: "oidc",
					provider: "okta",
					status: "active",
					domains: ["example.com"],
					issuer: "https://idp.example/oauth2/default",
					attributeMapping: { email: "email", name: "name" },
					createdAt: now,
					updatedAt: now,
				});
			});
			await store.ready();

			const b = getAuthBundle();
			await b.pool.query(
				`insert into "ssoProvider" (
          id, issuer, "oidcConfig", "samlConfig", "userId", "providerId",
          "organizationId", domain
        ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
				[
					connectionId,
					"https://idp.example/oauth2/default",
					null,
					null,
					userId,
					providerId,
					org.id,
					"example.com",
				],
			);
			trackSso(connectionId);
			return { connectionId, organizationId: org.id };
		}

		async function seedScimFixture(store: PgStore): Promise<{
			connectionId: string;
			organizationId: string;
		}> {
			const org = await seedScopedOrg(store);
			const { connectionId, providerId } = nextFixtureIds("scim");
			const now = new Date().toISOString();

			store.mutate((data: DataStoreSnapshot) => {
				data.directoryConnections.push({
					id: connectionId,
					organizationId: org.id,
					provider: "okta",
					status: "active",
					endpoint: "/scim/v2",
					deprovisioningPolicy: "disable",
					createdAt: now,
					updatedAt: now,
				});
			});
			await store.ready();

			const b = getAuthBundle();
			await b.pool.query(
				`insert into "scimProvider" (id, "providerId", "scimToken", "organizationId")
         values ($1,$2,$3,$4)`,
				[
					connectionId,
					providerId,
					`scimtok_${connectionId}`,
					org.id,
				],
			);
			trackScim(connectionId);
			return { connectionId, organizationId: org.id };
		}

		async function seedForeignSso(store: PgStore): Promise<string> {
			const now = new Date().toISOString();
			const userId = await ensureFkUser(store);
			const { connectionId, providerId } = nextFixtureIds("sso_foreign");
			store.mutate((data) => {
				if (!data.organizations.some((o) => o.id === ORG_FOREIGN_ID)) {
					data.organizations.push({
						id: ORG_FOREIGN_ID,
						projectId: "proj_foreign_disable_conn",
						environmentId: "env_foreign_disable_conn",
						name: "Foreign Disable Org",
						slug: `foreign-dis-${process.pid}`,
						status: "active",
						createdAt: now,
						updatedAt: now,
					});
				}
				data.identityConnections.push({
					id: connectionId,
					organizationId: ORG_FOREIGN_ID,
					protocol: "oidc",
					provider: "okta",
					status: "active",
					domains: [],
					attributeMapping: {},
					createdAt: now,
					updatedAt: now,
				});
			});
			await store.ready();

			const b = getAuthBundle();
			await b.pool.query(
				`insert into "ssoProvider" (
          id, issuer, "oidcConfig", "samlConfig", "userId", "providerId",
          "organizationId", domain
        ) values ($1,$2,$3,$4,$5,$6,$7,$8)`,
				[
					connectionId,
					"https://foreign.example/oauth2",
					null,
					null,
					userId,
					providerId,
					ORG_FOREIGN_ID,
					"foreign.example",
				],
			);
			trackSso(connectionId);
			return connectionId;
		}

		async function seedForeignScim(store: PgStore): Promise<string> {
			const now = new Date().toISOString();
			const { connectionId, providerId } = nextFixtureIds("scim_foreign");
			store.mutate((data) => {
				if (!data.organizations.some((o) => o.id === ORG_FOREIGN_ID)) {
					data.organizations.push({
						id: ORG_FOREIGN_ID,
						projectId: "proj_foreign_disable_conn",
						environmentId: "env_foreign_disable_conn",
						name: "Foreign Disable Org",
						slug: `foreign-dis-${process.pid}`,
						status: "active",
						createdAt: now,
						updatedAt: now,
					});
				}
				data.directoryConnections.push({
					id: connectionId,
					organizationId: ORG_FOREIGN_ID,
					provider: "okta",
					status: "active",
					endpoint: "/scim/v2/foreign",
					deprovisioningPolicy: "disable",
					createdAt: now,
					updatedAt: now,
				});
			});
			await store.ready();

			const b = getAuthBundle();
			await b.pool.query(
				`insert into "scimProvider" (id, "providerId", "scimToken", "organizationId")
         values ($1,$2,$3,$4)`,
				[connectionId, providerId, `scimtok_${connectionId}`, ORG_FOREIGN_ID],
			);
			trackScim(connectionId);
			return connectionId;
		}

		// ── SSO ────────────────────────────────────────────────────────────

		it("SSO: runtime delete + status disabled + exactly one audit commit atomically", async () => {
			const store = await freshStore();
			const { connectionId } = await seedSsoFixture(store);
			const eventsBefore = store.snapshot.events.length;

			expect(await runtimeSsoExists(connectionId)).toBe(true);
			expect(
				store.snapshot.identityConnections.find((c) => c.id === connectionId)
					?.status,
			).toBe("active");

			const result = await disableSsoConnectionReal(store, connectionId, {
				actor: "test",
				source: "api",
			});

			expect(result.connection.status).toBe("disabled");
			expect(result.idempotent).toBe(false);
			expect(result.runtimeRemoved).toBe(true);
			expect(await runtimeSsoExists(connectionId)).toBe(false);
			expect(
				store.snapshot.identityConnections.find((c) => c.id === connectionId)
					?.status,
			).toBe("disabled");

			const audits = disableAudits(store, "sso.disable", connectionId);
			expect(audits).toHaveLength(1);
			expect(audits[0]?.outcome).toBe("success");
			expect(audits[0]?.source).toBe("api");
			expect(audits[0]?.actor).toBe("test");
			expect(audits[0]?.metadata?.runtimeRemoved).toBe(true);
			expect(audits[0]?.metadata?.idempotent).toBe(false);
			expect(store.snapshot.events.length).toBe(eventsBefore + 1);
		});

		it("SSO: idempotent repeat leaves runtime gone, status disabled, adds second audit", async () => {
			const store = await freshStore();
			const { connectionId } = await seedSsoFixture(store);

			const first = await disableSsoConnectionReal(store, connectionId, {
				actor: "test",
				source: "cli",
			});
			expect(first.idempotent).toBe(false);
			expect(first.runtimeRemoved).toBe(true);

			const second = await disableSsoConnectionReal(store, connectionId, {
				actor: "test",
				source: "cli",
			});
			expect(second.idempotent).toBe(true);
			expect(second.runtimeRemoved).toBe(false);
			expect(second.connection.status).toBe("disabled");
			expect(await runtimeSsoExists(connectionId)).toBe(false);

			// events are newest-first (unshift)
			const audits = disableAudits(store, "sso.disable", connectionId);
			expect(audits).toHaveLength(2);
			expect(audits[0]?.metadata?.idempotent).toBe(true);
			expect(audits[0]?.metadata?.runtimeRemoved).toBe(false);
			expect(audits[1]?.metadata?.idempotent).toBe(false);
			expect(audits[1]?.metadata?.runtimeRemoved).toBe(true);
		});

		it("SSO: cross-scope disable fails closed; runtime + management + audits unchanged", async () => {
			const store = await freshStore();
			const scope = resolveOperatorScope(store);
			const foreignId = await seedForeignSso(store);
			const eventsBefore = store.snapshot.events.length;
			const statusBefore = store.snapshot.identityConnections.find(
				(c) => c.id === foreignId,
			)?.status;

			await expect(
				disableSsoConnectionReal(store, foreignId, {
					scope,
					actor: "test",
					source: "api",
				}),
			).rejects.toMatchObject({
				code: "SSO_NOT_FOUND",
				status: 404,
			});
			await expect(
				disableSsoConnectionReal(store, foreignId, {
					scope,
					actor: "test",
					source: "api",
				}),
			).rejects.toBeInstanceOf(ClearanceError);

			expect(await runtimeSsoExists(foreignId)).toBe(true);
			expect(
				store.snapshot.identityConnections.find((c) => c.id === foreignId)
					?.status,
			).toBe(statusBefore);
			expect(disableAudits(store, "sso.disable", foreignId)).toHaveLength(0);
			expect(store.snapshot.events.length).toBe(eventsBefore);
		});

		it("SSO: injected runtime SQL failure rolls back status and audit; runtime row restored", async () => {
			const store = await freshStore();
			const { connectionId } = await seedSsoFixture(store);
			const eventsBefore = store.snapshot.events.length;
			const restore = injectRuntimeSqlFailureAfterMutator(store, "ssoProvider");

			try {
				await expect(
					disableSsoConnectionReal(store, connectionId, {
						actor: "test",
						source: "api",
					}),
				).rejects.toThrow();
			} finally {
				restore();
			}

			// Runtime delete must not stick (transaction rolled back).
			expect(await runtimeSsoExists(connectionId)).toBe(true);
			expect(
				store.snapshot.identityConnections.find((c) => c.id === connectionId)
					?.status,
			).toBe("active");
			expect(disableAudits(store, "sso.disable", connectionId)).toHaveLength(0);
			expect(store.snapshot.events.length).toBe(eventsBefore);

			// Clean path still works after injection is removed.
			const ok = await disableSsoConnectionReal(store, connectionId, {
				actor: "test",
				source: "api",
			});
			expect(ok.runtimeRemoved).toBe(true);
			expect(ok.connection.status).toBe("disabled");
			expect(await runtimeSsoExists(connectionId)).toBe(false);
			expect(disableAudits(store, "sso.disable", connectionId)).toHaveLength(1);
		});

		// ── SCIM ───────────────────────────────────────────────────────────

		it("SCIM: runtime delete + status disabled + exactly one audit commit atomically", async () => {
			const store = await freshStore();
			const { connectionId } = await seedScimFixture(store);
			const eventsBefore = store.snapshot.events.length;

			expect(await runtimeScimExists(connectionId)).toBe(true);
			expect(
				store.snapshot.directoryConnections.find((c) => c.id === connectionId)
					?.status,
			).toBe("active");

			const result = await disableScimConnectionReal(store, connectionId, {
				actor: "test",
				source: "api",
			});

			expect(result.connection.status).toBe("disabled");
			expect(result.idempotent).toBe(false);
			expect(result.runtimeRemoved).toBe(true);
			expect(await runtimeScimExists(connectionId)).toBe(false);
			expect(
				store.snapshot.directoryConnections.find((c) => c.id === connectionId)
					?.status,
			).toBe("disabled");

			const audits = disableAudits(store, "scim.disable", connectionId);
			expect(audits).toHaveLength(1);
			expect(audits[0]?.outcome).toBe("success");
			expect(audits[0]?.source).toBe("api");
			expect(audits[0]?.actor).toBe("test");
			expect(audits[0]?.metadata?.runtimeRemoved).toBe(true);
			expect(audits[0]?.metadata?.idempotent).toBe(false);
			expect(store.snapshot.events.length).toBe(eventsBefore + 1);
		});

		it("SCIM: idempotent repeat leaves runtime gone, status disabled, adds second audit", async () => {
			const store = await freshStore();
			const { connectionId } = await seedScimFixture(store);

			const first = await disableScimConnectionReal(store, connectionId, {
				actor: "test",
				source: "cli",
			});
			expect(first.idempotent).toBe(false);
			expect(first.runtimeRemoved).toBe(true);

			const second = await disableScimConnectionReal(store, connectionId, {
				actor: "test",
				source: "cli",
			});
			expect(second.idempotent).toBe(true);
			expect(second.runtimeRemoved).toBe(false);
			expect(second.connection.status).toBe("disabled");
			expect(await runtimeScimExists(connectionId)).toBe(false);

			// events are newest-first (unshift)
			const audits = disableAudits(store, "scim.disable", connectionId);
			expect(audits).toHaveLength(2);
			expect(audits[0]?.metadata?.idempotent).toBe(true);
			expect(audits[0]?.metadata?.runtimeRemoved).toBe(false);
			expect(audits[1]?.metadata?.idempotent).toBe(false);
			expect(audits[1]?.metadata?.runtimeRemoved).toBe(true);
		});

		it("SCIM: cross-scope disable fails closed; runtime + management + audits unchanged", async () => {
			const store = await freshStore();
			const scope = resolveOperatorScope(store);
			const foreignId = await seedForeignScim(store);
			const eventsBefore = store.snapshot.events.length;
			const statusBefore = store.snapshot.directoryConnections.find(
				(c) => c.id === foreignId,
			)?.status;

			await expect(
				disableScimConnectionReal(store, foreignId, {
					scope,
					actor: "test",
					source: "api",
				}),
			).rejects.toMatchObject({
				code: "SCIM_NOT_FOUND",
				status: 404,
			});

			expect(await runtimeScimExists(foreignId)).toBe(true);
			expect(
				store.snapshot.directoryConnections.find((c) => c.id === foreignId)
					?.status,
			).toBe(statusBefore);
			expect(disableAudits(store, "scim.disable", foreignId)).toHaveLength(0);
			expect(store.snapshot.events.length).toBe(eventsBefore);
		});

		it("SCIM: injected runtime SQL failure rolls back status and audit; runtime row restored", async () => {
			const store = await freshStore();
			const { connectionId } = await seedScimFixture(store);
			const eventsBefore = store.snapshot.events.length;
			const restore = injectRuntimeSqlFailureAfterMutator(store, "scimProvider");

			try {
				await expect(
					disableScimConnectionReal(store, connectionId, {
						actor: "test",
						source: "api",
					}),
				).rejects.toThrow();
			} finally {
				restore();
			}

			expect(await runtimeScimExists(connectionId)).toBe(true);
			expect(
				store.snapshot.directoryConnections.find((c) => c.id === connectionId)
					?.status,
			).toBe("active");
			expect(disableAudits(store, "scim.disable", connectionId)).toHaveLength(0);
			expect(store.snapshot.events.length).toBe(eventsBefore);

			const ok = await disableScimConnectionReal(store, connectionId, {
				actor: "test",
				source: "api",
			});
			expect(ok.runtimeRemoved).toBe(true);
			expect(ok.connection.status).toBe("disabled");
			expect(await runtimeScimExists(connectionId)).toBe(false);
			expect(disableAudits(store, "scim.disable", connectionId)).toHaveLength(1);
		});
	},
);
