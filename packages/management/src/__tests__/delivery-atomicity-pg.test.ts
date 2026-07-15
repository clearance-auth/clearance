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
import {
	controlDeliveryJob,
	getDeliveryQuotaForManagement,
	inspectDeliveryJobForManagement,
	listDeliveryJobsForManagement,
} from "../services/delivery-control.js";
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

function requireControl(
	context: Parameters<NonNullable<ManagementStore["mutateCoordinated"]>>[0] extends (
		context: infer Context,
	) => unknown
		? Context
		: never,
) {
	if (!context.controlDelivery) {
		throw new Error("Transactional delivery control is required");
	}
	return context.controlDelivery;
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
		await expect(listDeliveryJobsForManagement(store, {
			projectId: initialized.project.id,
			environmentId: initialized.environment.id,
		})).rejects.toMatchObject({ code: "DELIVERY_NOT_CONFIGURED" });

		const json = new JsonStore(join(tmpdir(), `clearance-json-delivery-${suffix}.json`));
		expect(json.backend).toBe("json");
		expect(json.mutateCoordinated).toBeUndefined();
		await expect(listDeliveryJobsForManagement(json, {
			projectId: initialized.project.id,
			environmentId: initialized.environment.id,
		})).rejects.toMatchObject({ code: "DELIVERY_POSTGRES_REQUIRED" });
	});

	it("provides scoped redacted reads, quota status, and preview-by-default control", async () => {
		const store = stores[0] as Awaited<ReturnType<typeof createPgStore>>;
		const project = store.snapshot.projects[0]!;
		const environment = store.snapshot.environments[0]!;
		const now = new Date();
		const eventId = `delivery-control-preview-${suffix}`;
		const jobId = `delivery-control-preview-job-${suffix}`;
		await store.mutateCoordinated!((context) =>
			requireDelivery(context)(deliveryInput({
				eventId,
				jobId,
				projectId: project.id,
				environmentId: environment.id,
				sourceKey: `control-preview:${suffix}`,
				now,
			})),
		);

		const page = await listDeliveryJobsForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			limit: 20,
		});
		expect(page.scope).toEqual({ projectId: project.id, environmentId: environment.id });
		expect(page.items.some((job) => job.id === jobId)).toBe(true);
		const inspected = await inspectDeliveryJobForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			jobId,
		});
		expect(inspected.job).toMatchObject({ id: jobId, state: "queued" });
		expect(JSON.stringify(inspected)).not.toContain("signingSecret");
		await expect(inspectDeliveryJobForManagement(store, {
			projectId: project.id,
			environmentId: "wrong-environment",
			jobId,
		})).rejects.toMatchObject({ code: "DELIVERY_JOB_NOT_FOUND", status: 404 });
		const quota = await getDeliveryQuotaForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			now,
		});
		expect(quota.scope).toEqual({ projectId: project.id, environmentId: environment.id });

		const auditBefore = store.snapshot.events.length;
		const preview = await controlDeliveryJob(store, {
			projectId: project.id,
			environmentId: environment.id,
			jobId,
			action: "cancel",
			actor: "operator",
			source: "cli",
			now,
		});
		expect(preview).toMatchObject({ dryRun: true, preview: { allowed: true } });
		expect(store.snapshot.events).toHaveLength(auditBefore);
		expect((await store.deliveryControl!.inspect({
			projectId: project.id,
			environmentId: environment.id,
			jobId,
		}))?.state).toBe("queued");

		const controlled = await controlDeliveryJob(store, {
			projectId: project.id,
			environmentId: environment.id,
			jobId,
			action: "cancel",
			actor: "operator",
			source: "cli",
			now,
			confirm: true,
		});
		expect(controlled).toMatchObject({ dryRun: false, result: { id: jobId, state: "cancelled" } });
		expect(store.snapshot.events[0]).toMatchObject({
			action: "delivery.job.cancel",
			subjectId: jobId,
			projectId: project.id,
			environmentId: environment.id,
		});
	});

	it("rolls audited control back and awaits a dropped control promise before commit", async () => {
		const store = stores[0] as Awaited<ReturnType<typeof createPgStore>>;
		const project = store.snapshot.projects[0]!;
		const environment = store.snapshot.environments[0]!;
		const now = new Date();
		const createJob = async (label: string) => {
			const eventId = `delivery-control-${label}-${suffix}`;
			const jobId = `delivery-control-${label}-job-${suffix}`;
			await store.mutateCoordinated!((context) => requireDelivery(context)(deliveryInput({
				eventId,
				jobId,
				projectId: project.id,
				environmentId: environment.id,
				sourceKey: `control-${label}:${suffix}`,
				now,
			})));
			return jobId;
		};
		const rollbackJobId = await createJob("rollback");
		const auditIdsBefore = store.snapshot.events.map((event) => event.id);
		await expect(store.mutateCoordinated!(async (context) => {
			await requireControl(context).cancel({
				projectId: project.id,
				environmentId: environment.id,
				jobId: rollbackJobId,
				actor: "operator",
				source: "api",
				now,
			});
			throw new Error("forced control rollback");
		})).rejects.toThrow("forced control rollback");
		await store.refresh();
		expect((await store.deliveryControl!.inspect({
			projectId: project.id,
			environmentId: environment.id,
			jobId: rollbackJobId,
		}))?.state).toBe("queued");
		expect(store.snapshot.events.map((event) => event.id)).toEqual(auditIdsBefore);

		const droppedJobId = await createJob("dropped");
		await store.mutateCoordinated!((context) => {
			void requireControl(context).cancel({
				projectId: project.id,
				environmentId: environment.id,
				jobId: droppedJobId,
				actor: "operator",
				source: "api",
				now,
			});
		});
		expect((await store.deliveryControl!.inspect({
			projectId: project.id,
			environmentId: environment.id,
			jobId: droppedJobId,
		}))?.state).toBe("cancelled");
		expect(store.snapshot.events.some((event) =>
			event.action === "delivery.job.cancel" && event.subjectId === droppedJobId,
		)).toBe(true);
	});
});
