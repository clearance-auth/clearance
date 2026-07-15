import { randomBytes, randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	deliveryTableNames,
	quoteIdentifier,
	type EnqueuedDelivery,
	type EnqueueDeliveryInput,
} from "@clearance/delivery";
import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { appendAuditEvent } from "../services/audit.js";
import { initProject } from "../services/core.js";
import { JsonStore } from "../store/json-store.js";
import { createPgStore, type PgStoreDeliveryOptions } from "../store/pg-store.js";
import type { ManagementStore } from "../store/types.js";
import { gatePostgresSuite } from "./pg-gate.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";
const suffix = `${process.pid}_${randomUUID().slice(0, 8).replace(/-/g, "")}`;
const STORE_TABLE = `clearance_delivery_atomic_${suffix}`;
const UNCONFIGURED_TABLE = `clearance_delivery_none_${suffix}`;
const DELIVERY_PREFIX = `mgdel_${suffix}_`;
const delivery = {
	prefix: DELIVERY_PREFIX,
	keyring: {
		currentKeyId: "current",
		keys: { current: randomBytes(32) },
		currentFingerprintKeyId: "fingerprint-current",
		fingerprintKeys: { "fingerprint-current": randomBytes(32) },
		sourceDedupeKey: randomBytes(32),
	},
} satisfies PgStoreDeliveryOptions;

const available = await gatePostgresSuite(
	DATABASE_URL,
	"management-delivery-atomicity-pg",
);

function deliveryInput(input: {
	eventId: string;
	jobId: string;
	projectId: string;
	environmentId: string;
	sourceKey: string;
	now: Date;
}): EnqueueDeliveryInput {
	return {
		eventId: input.eventId,
		jobId: input.jobId,
		kind: "organization.updated",
		sourceKey: input.sourceKey,
		projectId: input.projectId,
		environmentId: input.environmentId,
		channel: "webhook",
		destination: "https://hooks.example.test/clearance",
		payload: {
			endpoint: {
				url: "https://hooks.example.test/clearance",
				signingSecret: "test-only-signing-secret-that-stays-encrypted",
			},
			event: { id: input.eventId, type: "organization.updated" },
		},
		semanticExpiresAt: new Date(input.now.getTime() + 60 * 60_000),
		now: input.now,
	};
}

function requireDelivery(
	context: Parameters<NonNullable<ManagementStore["mutateCoordinated"]>>[0] extends (
		context: infer Context,
	) => unknown
		? Context
		: never,
) {
	if (!context.enqueueDelivery) {
		throw new Error("Transactional delivery outbox is required");
	}
	return context.enqueueDelivery;
}

describe.skipIf(!available)("PgStore coordinated delivery atomicity", () => {
	const stores: Array<{ destroy(): Promise<void> }> = [];
	const inspectionPool = new pg.Pool({ connectionString: DATABASE_URL });

	afterAll(async () => {
		for (const store of stores) await store.destroy().catch(() => undefined);
		const names = deliveryTableNames({ prefix: DELIVERY_PREFIX });
		const schema = quoteIdentifier("public");
		for (const name of [
			names.attempt,
			names.job,
			names.payload,
			names.event,
			names.worker,
			names.meta,
		]) {
			await inspectionPool.query(
				`DROP TABLE IF EXISTS ${schema}.${quoteIdentifier(name)} CASCADE`,
			);
		}
		await inspectionPool.query(
			`DROP FUNCTION IF EXISTS ${schema}.${quoteIdentifier(names.rejectMutationFunction)}()`,
		);
		for (const table of [STORE_TABLE, UNCONFIGURED_TABLE]) {
			for (const name of [
				`${table}_principal_email`,
				`${table}_organization_slug`,
				`${table}_idempotency`,
				table,
			]) {
				await inspectionPool.query(
					`DROP TABLE IF EXISTS ${quoteIdentifier(name)} CASCADE`,
				);
			}
		}
		await inspectionPool.end();
	});

	it("commits management state, audit, and delivery rows in one transaction", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: STORE_TABLE,
			delivery,
		});
		stores.push(store);
		const initialized = initProject(store, { name: "Delivery Atomicity" });
		await store.ready();
		const now = new Date();
		const eventId = `delivery-commit-${suffix}`;
		const jobId = `delivery-job-commit-${suffix}`;

		let enqueuePromise: Promise<EnqueuedDelivery> | undefined;
		const result = await store.mutateCoordinated!((context) => {
			context.data.projects[0]!.name = "Committed with delivery";
			appendAuditEvent(context.data, {
				actor: "operator",
				action: "delivery.atomic.commit",
				subjectType: "project",
				subjectId: initialized.project.id,
				outcome: "success",
				source: "api",
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
				message: "Committed management mutation with delivery",
			});
			enqueuePromise = requireDelivery(context)(deliveryInput({
				eventId,
				jobId,
				projectId: initialized.project.id,
				environmentId: initialized.environment.id,
				sourceKey: `commit:${suffix}`,
				now,
			}));
			return "committed" as const;
		});

		expect(result).toBe("committed");
		const enqueued = await enqueuePromise!;
		expect(enqueued).toMatchObject({ eventId, jobId, state: "queued" });
		expect(store.snapshot.projects[0]!.name).toBe("Committed with delivery");
		expect(
			store.snapshot.events.filter(
				(event) => event.action === "delivery.atomic.commit",
			),
		).toHaveLength(1);
		const names = deliveryTableNames({ prefix: DELIVERY_PREFIX });
		for (const table of [names.event, names.payload, names.job]) {
			const rows = await inspectionPool.query<{ count: string }>(
				`SELECT count(*)::text count FROM ${quoteIdentifier("public")}.${quoteIdentifier(table)}`,
			);
			expect(Number(rows.rows[0]!.count), table).toBe(1);
		}
		const persisted = await inspectionPool.query<{
			name: string;
			audit_count: number;
		}>(
			`SELECT data->'projects'->0->>'name' name,
			 jsonb_array_length(data->'events') audit_count
			 FROM ${quoteIdentifier(STORE_TABLE)} WHERE id=1`,
		);
		expect(persisted.rows[0]!.name).toBe("Committed with delivery");
		expect(persisted.rows[0]!.audit_count).toBe(store.snapshot.events.length);
	});

	it("rolls back management state, audit, and delivery rows after a forced failure", async () => {
		const store = stores[0] as Awaited<ReturnType<typeof createPgStore>>;
		const initialized = {
			project: store.snapshot.projects[0]!,
			environment: store.snapshot.environments[0]!,
		};
		const beforeName = initialized.project.name;
		const beforeAuditIds = store.snapshot.events.map((event) => event.id);
		const now = new Date();
		const eventId = `delivery-rollback-${suffix}`;
		const jobId = `delivery-job-rollback-${suffix}`;

		await expect(
			store.mutateCoordinated!(async (context) => {
				context.data.projects[0]!.name = "Must roll back";
				appendAuditEvent(context.data, {
					actor: "operator",
					action: "delivery.atomic.rollback",
					subjectType: "project",
					subjectId: initialized.project.id,
					outcome: "success",
					source: "api",
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
					message: "This event must roll back",
				});
				await requireDelivery(context)(deliveryInput({
					eventId,
					jobId,
					projectId: initialized.project.id,
					environmentId: initialized.environment.id,
					sourceKey: `rollback:${suffix}`,
					now,
				}));
				throw new Error("forced coordinated rollback");
			}),
		).rejects.toThrow("forced coordinated rollback");

		await store.refresh();
		expect(store.snapshot.projects[0]!.name).toBe(beforeName);
		expect(store.snapshot.events.map((event) => event.id)).toEqual(beforeAuditIds);
		expect(
			store.snapshot.events.some(
				(event) => event.action === "delivery.atomic.rollback",
			),
		).toBe(false);
		const names = deliveryTableNames({ prefix: DELIVERY_PREFIX });
		for (const [table, column, id] of [
			[names.event, "id", eventId],
			[names.payload, "event_id", eventId],
			[names.job, "id", jobId],
		] as const) {
			const rows = await inspectionPool.query(
				`SELECT 1 FROM ${quoteIdentifier("public")}.${quoteIdentifier(table)} WHERE ${quoteIdentifier(column)}=$1`,
				[id],
			);
			expect(rows.rowCount, table).toBe(0);
		}
	});

	it("keeps unconfigured Postgres and JSON stores delivery-free and fail-closed", async () => {
		const store = await createPgStore(DATABASE_URL, {
			tableName: UNCONFIGURED_TABLE,
		});
		stores.push(store);
		const initialized = initProject(store, { name: "No Delivery" });
		await store.ready();
		const beforeName = initialized.project.name;

		await expect(
			store.mutateCoordinated!((context) => {
				context.data.projects[0]!.name = "Must not persist";
				expect(context.enqueueDelivery).toBeUndefined();
				requireDelivery(context);
			}),
		).rejects.toThrow("Transactional delivery outbox is required");
		await store.refresh();
		expect(store.snapshot.projects[0]!.name).toBe(beforeName);

		const json = new JsonStore(join(tmpdir(), `clearance-json-delivery-${suffix}.json`));
		expect(json.backend).toBe("json");
		expect(json.mutateCoordinated).toBeUndefined();
	});
});
