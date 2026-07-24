import { afterAll, describe, expect, it } from "vitest";
import pg from "pg";
import { gatePostgresSuite } from "./pg-gate.js";
import { createEnvironment, initProject } from "../services/core.js";
import {
	activateProductDomainForManagement,
	applyProductSenderForManagement,
	createProductDomainForManagement,
	disableProductDomainForManagement,
	reissueProductDomainForManagement,
	verifyProductDomainForManagement,
} from "../services/product-presentation.js";
import { createPgStore, type PgStore } from "../store/pg-store.js";

const DATABASE_URL = process.env.CLEARANCE_TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? "postgres://clearance:clearance@localhost:5434/clearance";
const TABLE = `clearance_product_presentation_${process.pid}`;
const PREFIX = `clearance_product_presentation_${process.pid}_`;
const available = await gatePostgresSuite(DATABASE_URL, "product-presentation-pg");

describe.skipIf(!available)("product presentation authority on PostgreSQL", () => {
	const stores: PgStore[] = [];

	afterAll(async () => {
		for (const store of stores) await store.destroy().catch(() => undefined);
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			const tables = await pool.query<{ tablename: string }>(
				"SELECT tablename FROM pg_tables WHERE schemaname = current_schema() AND tablename LIKE $1",
				[`${PREFIX}%`],
			);
			for (const { tablename } of tables.rows) {
				await pool.query(`DROP TABLE IF EXISTS "${tablename.replaceAll('"', '""')}" CASCADE`);
			}
			await pool.query(`DROP TABLE IF EXISTS ${TABLE}`);
			await pool.query(`DROP TABLE IF EXISTS ${TABLE}_principal_email`);
			await pool.query(`DROP TABLE IF EXISTS ${TABLE}_organization_slug`);
		} finally {
			await pool.end();
		}
	});

	it("enforces hostname claims, caller-observed CAS, one-time reissue, sender safety, and hidden public capability", async () => {
		const store = await createPgStore(DATABASE_URL, { tableName: TABLE, normalizedPrefix: PREFIX });
		stores.push(store);
		const initialized = initProject(store, { name: "Product presentation PG", source: "cli" });
		await store.ready();
		await store.storeV2!.apply();
		const other = createEnvironment(store, { projectId: initialized.project.id, name: "preview", kind: "preview" });
		await store.ready();
		const scope = { projectId: initialized.project.id, environmentId: initialized.environment.id };
		const otherScope = { projectId: initialized.project.id, environmentId: other.id };
		const context = { scope, actor: "test", source: "api" as const, correlationId: "product-pg" };
		const otherContext = { ...context, scope: otherScope };
		const previousTarget = process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET;
		process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET = "edge.clearance.test";
		try {
			const primary = await createProductDomainForManagement(store, context, { origin: "https://auth.product-pg.test" });
			expect("dnsChallenge" in primary).toBe(true);
			await expect(createProductDomainForManagement(store, otherContext, { origin: "https://auth.product-pg.test" }))
				.rejects.toMatchObject({ code: "PRODUCT_PRESENTATION_CONFLICT" });
			if (!("dnsChallenge" in primary)) throw new Error("expected one-time challenge");
			const verified = await verifyProductDomainForManagement(store, context, { origin: primary.domain.origin }, { resolveTxt: async () => [[primary.dnsChallenge.value]], resolveCname: async () => ["edge.clearance.test"] });
			await expect(activateProductDomainForManagement(store, context, { origin: primary.domain.origin, expectedVersion: 1, confirm: true }))
				.rejects.toMatchObject({ code: "PRODUCT_DOMAIN_CONFLICT" });
			const active = await activateProductDomainForManagement(store, context, { origin: primary.domain.origin, expectedVersion: verified.domain.version, confirm: true });
			expect(active.domain.state).toBe("active");
			expect(await store.productPresentation?.resolveActiveHostedDomain("AUTH.PRODUCT-PG.TEST"))
				.toMatchObject({
					origin: primary.domain.origin,
					hostname: "auth.product-pg.test",
					scope,
					domainVersion: active.domain.version,
				});
			await applyProductSenderForManagement(store, context, { displayName: "Clearance", address: "security@auth.product-pg.test", expectedVersion: 0, confirm: true });
			await expect(disableProductDomainForManagement(store, context, { origin: primary.domain.origin, expectedVersion: active.domain.version, confirm: true }))
				.rejects.toMatchObject({ code: "PRODUCT_DOMAIN_SENDER_IN_USE", remediation: "Replace the email sender first, then disable this domain." });

			const disposable = await createProductDomainForManagement(store, context, { origin: "https://reissue.product-pg.test" });
			if (!("dnsChallenge" in disposable)) throw new Error("expected disposable challenge");
			const disabled = await disableProductDomainForManagement(store, context, { origin: disposable.domain.origin, expectedVersion: disposable.domain.version, confirm: true });
			expect(await store.productPresentation?.resolveActiveHostedDomain("reissue.product-pg.test")).toBeNull();
			const reissued = await reissueProductDomainForManagement(store, context, { origin: disabled.domain.origin, expectedVersion: disabled.domain.version });
			expect(reissued).toMatchObject({ domain: { state: "pending", version: disabled.domain.version + 1 }, dnsChallenge: { name: "_clearance.reissue.product-pg.test" } });
			await expect(reissueProductDomainForManagement(store, context, { origin: disabled.domain.origin, expectedVersion: disabled.domain.version }))
				.rejects.toMatchObject({ code: "PRODUCT_DOMAIN_CONFLICT" });
			const otherDomain = await createProductDomainForManagement(store, otherContext, { origin: "https://other.product-pg.test" });
			if (!("dnsChallenge" in otherDomain)) throw new Error("expected cross-scope challenge");
			const otherVerified = await verifyProductDomainForManagement(store, otherContext, { origin: otherDomain.domain.origin }, { resolveTxt: async () => [[otherDomain.dnsChallenge.value]], resolveCname: async () => ["edge.clearance.test"] });
			await activateProductDomainForManagement(store, otherContext, { origin: otherDomain.domain.origin, expectedVersion: otherVerified.domain.version, confirm: true });
			expect(await store.productPresentation?.resolveActiveHostedDomain("other.product-pg.test"))
				.toMatchObject({ scope: otherScope, hostname: "other.product-pg.test" });
			await expect(store.mutateCoordinated!(async (capability) => Object.keys(capability))).resolves.not.toContain("productPresentation");
		} finally {
			if (previousTarget === undefined) delete process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET;
			else process.env.CLEARANCE_CUSTOM_DOMAIN_TARGET = previousTarget;
		}
	});
});
