/**
 * Proves two independent PgStore processes (separate Pool + in-memory caches)
 * can mutate concurrently without lost updates, and that same-email / same-slug
 * creates under concurrency yield exactly one resource and exactly one audit event.
 *
 * Requires Postgres (DATABASE_URL or CLEARANCE_TEST_DATABASE_URL or local compose).
 */
import { afterAll, describe, expect, it } from "vitest";
import { gatePostgresSuite } from "./pg-gate.js";
import pg from "pg";
import { createPgStore, type PgStore } from "../store/pg-store.js";
import {
	createOrganization,
	createUser,
	initProject,
	listEvents,
	listOrganizations,
	listUsers,
} from "../services/core.js";
import { ClearanceError } from "../services/errors.js";
import {
	inspectUser,
	inspectOrganization,
} from "../services/core.js";
import { resolveOperatorScope } from "../services/scope.js";
import { syncRuntimeUserToManagementDurable } from "../services/identity.js";
import { createSetupLink, redeemSetupLink } from "../services/setup-links.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const TEST_TABLE = `clearance_management_snapshot_test_${process.pid}`;


const available = await gatePostgresSuite(DATABASE_URL, "pg-concurrency");

describe.skipIf(!available)("PgStore two-store concurrency", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const s of stores) {
			await s.destroy().catch(() => undefined);
		}
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}`);
		await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_principal_email`);
		await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}_organization_slug`);
		await pool.end();
	});

	it("transactionally replays concurrent mutates so both writes survive", async () => {
		const storeA = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		const storeB = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(storeA, storeB);

		// Shared init via A only
		initProject(storeA, { name: "Concurrent Project", source: "cli" });
		await storeA.ready();
		await storeB.refresh();

		const emailA = `alice-concurrent-${Date.now()}@test.local`;
		const emailB = `bob-concurrent-${Date.now()}@test.local`;

		// Two long-lived processes write without sharing memory
		const [userA, userB] = await Promise.all([
			(async () => {
				const u = createUser(storeA, {
					email: emailA,
					name: "Alice",
					source: "cli",
				});
				await storeA.ready();
				return u;
			})(),
			(async () => {
				// B may still have pre-user snapshot; mutation is replayed on locked row
				const u = createUser(storeB, {
					email: emailB,
					name: "Bob",
					source: "api",
				});
				await storeB.ready();
				return u;
			})(),
		]);

		expect(userA.id).toMatch(/^user_/);
		expect(userB.id).toMatch(/^user_/);
		expect(userA.id).not.toBe(userB.id);

		// Long-lived reader refresh path (API seeing CLI writes)
		await storeA.refresh();
		await storeB.refresh();

		const fromA = listUsers(storeA).map((u) => u.email).sort();
		const fromB = listUsers(storeB).map((u) => u.email).sort();

		expect(fromA).toContain(emailA);
		expect(fromA).toContain(emailB);
		expect(fromB).toContain(emailA);
		expect(fromB).toContain(emailB);

		// Revision advanced for both writes (+ init + events; at least > 1)
		expect(storeA.currentRevision).toBeGreaterThan(1);
		expect(storeB.currentRevision).toBe(storeA.currentRevision);
	});

	it("refresh surfaces external process writes without local mutate", async () => {
		const writer = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		const reader = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(writer, reader);

		await reader.refresh();
		const before = listUsers(reader).length;

		const email = `external-${Date.now()}@test.local`;
		createUser(writer, { email, name: "External", source: "cli" });
		await writer.ready();

		// Reader still stale until refresh
		const stale = listUsers(reader).some((u) => u.email === email);
		// May or may not be present if reader shared nothing — assert refresh fixes it
		await reader.refresh();
		const after = listUsers(reader);
		expect(after.some((u) => u.email === email)).toBe(true);
		expect(after.length).toBeGreaterThanOrEqual(before + (stale ? 0 : 1));
	});

	it("concurrent same-email creates: exactly one principal and one users.create audit", async () => {
		const storeA = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		const storeB = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(storeA, storeB);

		await storeA.refresh();
		if (storeA.snapshot.projects.length === 0) {
			initProject(storeA, { name: "Same Email Project", source: "cli" });
			await storeA.ready();
		}
		await storeB.refresh();

		const email = `same-email-${Date.now()}-${process.pid}@test.local`;

		async function raceCreate(store: PgStore, name: string) {
			const u = createUser(store, { email, name, source: "cli" });
			const readyErr = await store.ready().then(
				() => null,
				(error: unknown) => error,
			);
			if (readyErr) return { ok: false as const, error: readyErr };
			// Confirm durable presence (lost race may return optimistic object)
			await store.refresh();
			const found = listUsers(store).find((x) => x.email === email && x.id === u.id);
			if (!found) return { ok: false as const, error: new Error("not durable") };
			return { ok: true as const, user: found };
		}

		const [a, b] = await Promise.all([
			raceCreate(storeA, "Racer A"),
			raceCreate(storeB, "Racer B"),
		]);

		const wins = [a, b].filter((r) => r.ok);
		const losses = [a, b].filter((r) => !r.ok);
		expect(wins).toHaveLength(1);
		expect(losses).toHaveLength(1);

		const loss = losses[0]!;
		if ("error" in loss && loss.error instanceof ClearanceError) {
			expect(loss.error.code).toBe("USER_EXISTS");
		} else {
			expect(String((loss as { error: unknown }).error)).toMatch(
				/already exists|USER_EXISTS|unique|duplicate|not durable/i,
			);
		}

		await storeA.refresh();
		await storeB.refresh();

		const matches = listUsers(storeA).filter(
			(u) => u.email.toLowerCase() === email,
		);
		expect(matches).toHaveLength(1);

		const createAudits = listEvents(storeA, { limit: 500 }).filter(
			(e) =>
				e.action === "users.create" &&
				(e.subjectId === matches[0]!.id || e.message.includes(email)),
		);
		expect(createAudits).toHaveLength(1);
		expect(JSON.stringify(createAudits)).not.toMatch(/Bearer |password|token_/i);
	});

	it("concurrent same-slug org creates: exactly one org and one orgs.create audit", async () => {
		const storeA = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		const storeB = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(storeA, storeB);

		await storeA.refresh();
		if (storeA.snapshot.projects.length === 0) {
			initProject(storeA, { name: "Same slug project", source: "cli" });
			await storeA.ready();
		}
		await storeB.refresh();

		const slug = `acme-slug-${Date.now()}-${process.pid}`;

		async function raceOrg(store: PgStore, name: string) {
			const o = createOrganization(store, { name, slug, source: "cli" });
			const readyErr = await store.ready().then(
				() => null,
				(error: unknown) => error,
			);
			if (readyErr) return { ok: false as const, error: readyErr };
			await store.refresh();
			const found = listOrganizations(store).find(
				(x) => x.slug === slug && x.id === o.id,
			);
			if (!found) return { ok: false as const, error: new Error("not durable") };
			return { ok: true as const, org: found };
		}

		const [a, b] = await Promise.all([
			raceOrg(storeA, "Acme A"),
			raceOrg(storeB, "Acme B"),
		]);

		expect([a, b].filter((r) => r.ok)).toHaveLength(1);
		expect([a, b].filter((r) => !r.ok)).toHaveLength(1);

		await storeA.refresh();
		const orgs = listOrganizations(storeA).filter((o) => o.slug === slug);
		expect(orgs).toHaveLength(1);

		const createAudits = listEvents(storeA, { limit: 500 }).filter(
			(e) => e.action === "orgs.create" && e.subjectId === orgs[0]!.id,
		);
		expect(createAudits).toHaveLength(1);
	});

	it("atomically consumes a setup capability exactly once across two stores", async () => {
		const storeA = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		const storeB = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(storeA, storeB);
		await storeA.refresh();
		const org = createOrganization(storeA, {
			name: `Setup Race ${Date.now()}`,
			slug: `setup-race-${Date.now()}`,
			source: "cli",
		});
		await storeA.ready();
		const link = createSetupLink(storeA, {
			organizationId: org.id,
			kind: "sso",
		});
		await storeA.ready();
		await storeB.refresh();

		const results = await Promise.allSettled([
			redeemSetupLink(storeA, { token: link.token, kind: "sso" }),
			redeemSetupLink(storeB, { token: link.token, kind: "sso" }),
		]);
		expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);

		const restarted = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(restarted);
		const durable = restarted.snapshot.setupLinks.find(
			(capability) => capability.id === link.capabilityId,
		);
		expect(durable?.useCount).toBe(1);
		expect(durable?.redeemedAt).toBeTruthy();
		await expect(
			redeemSetupLink(restarted, { token: link.token, kind: "sso" }),
		).rejects.toThrow(/already used/i);
	});

	it("cross-scope inspect fails closed without revealing foreign resources", async () => {
		const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(store);
		await store.refresh();
		if (store.snapshot.projects.length === 0) {
			initProject(store, { name: "Scope Isolation", source: "cli" });
			await store.ready();
		}

		const scope = resolveOperatorScope(store);
		const local = createUser(store, {
			email: `local-${Date.now()}@test.local`,
			name: "Local",
			source: "cli",
		});
		await store.ready();

		// Plant a foreign principal in another scope (direct mutate)
		const foreignId = `user_foreign_${Date.now()}`;
		const foreignOrgId = `org_foreign_${Date.now()}`;
		const now = new Date().toISOString();
		store.mutate((data) => {
			data.principals.push({
				id: foreignId,
				projectId: "proj_other_tenant",
				environmentId: "env_other_tenant",
				email: "hidden@other.tenant",
				name: "Hidden",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
			data.organizations.push({
				id: foreignOrgId,
				projectId: "proj_other_tenant",
				environmentId: "env_other_tenant",
				name: "Other Tenant Org",
				slug: `other-org-${Date.now()}`,
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});
		await store.ready();

		expect(inspectUser(store, local.id, scope).id).toBe(local.id);

		expect(() => inspectUser(store, foreignId, scope)).toThrowError(/not found/i);
		try {
			inspectUser(store, foreignId, scope);
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			expect(msg).not.toContain("hidden@other.tenant");
			expect(msg).not.toContain("proj_other_tenant");
			if (e instanceof ClearanceError) {
				expect(e.code).toBe("USER_NOT_FOUND");
				expect(e.status).toBe(404);
			}
		}

		expect(() => inspectOrganization(store, foreignOrgId, scope)).toThrowError(
			/not found/i,
		);
	});

	it("runtime identity sync uses stable id and is idempotent", async () => {
		const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(store);
		await store.refresh();
		if (store.snapshot.projects.length === 0) {
			initProject(store, { name: "Identity Bridge", source: "cli" });
			await store.ready();
		}

		const runtimeId = `rt_${Date.now()}_${process.pid}`;
		const email = `runtime-${Date.now()}@test.local`;

		const first = await syncRuntimeUserToManagementDurable(store, {
			id: runtimeId,
			email,
			name: "Runtime User",
		});
		expect(first.id).toBe(runtimeId);
		expect(first.email).toBe(email);

		const second = await syncRuntimeUserToManagementDurable(store, {
			id: runtimeId,
			email,
			name: "Runtime User Updated",
		});
		expect(second.id).toBe(runtimeId);
		expect(second.name).toBe("Runtime User Updated");

		await store.refresh();
		const matches = listUsers(store).filter((u) => u.id === runtimeId);
		expect(matches).toHaveLength(1);

		const syncAudits = listEvents(store, { limit: 200 }).filter(
			(e) => e.action === "users.sync_runtime" && e.subjectId === runtimeId,
		);
		// First sync writes audit; idempotent update path does not duplicate create-style rows unnecessarily
		expect(syncAudits.length).toBeGreaterThanOrEqual(1);
		expect(syncAudits.length).toBeLessThanOrEqual(2);
	});

	it("database uniqueness tables reject duplicate emails at the SQL layer", async () => {
		const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		stores.push(store);
		await store.refresh();
		const scope = resolveOperatorScope(store);
		const email = `db-unique-${Date.now()}@test.local`;

		createUser(store, { email, name: "One", source: "cli" });
		await store.ready();

		// Bypass service layer: push a second principal with same email into draft
		// and expect uniqueness sync to fail the transaction
		store.mutate((data) => {
			const now = new Date().toISOString();
			data.principals.push({
				id: `user_dup_${Date.now()}`,
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				email,
				name: "Dup",
				status: "active",
				createdAt: now,
				updatedAt: now,
			});
		});
		const uniqErr = await store.ready().then(
			() => null,
			(error: unknown) => error,
		);
		expect(uniqErr).toBeTruthy();
		expect(String(uniqErr)).toMatch(/unique|duplicate/i);

		// Chain recovers — subsequent writes still work; duplicate not persisted
		await store.refresh();
		expect(
			listUsers(store).filter((u) => u.email === email),
		).toHaveLength(1);
	});
});
