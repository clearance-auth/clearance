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
import {
	createWebhookEndpointForManagement,
	deleteWebhookEndpointForManagement,
	rotateWebhookEndpointForManagement,
	testWebhookEndpointForManagement,
	updateWebhookEndpointForManagement,
} from "../services/webhook-endpoints.js";
import { JsonStore } from "../store/json-store.js";
import { createPgStore, type PgStoreDeliveryOptions } from "../store/pg-store.js";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";
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
		organizationId: "organization-atomicity",
		channel: "webhook",
		destination: "https://hooks.example.test/clearance",
		payload: {
			version: 1,
			endpoint: {
				id: "legacy-atomicity-target",
				url: "https://hooks.example.test/clearance",
				signingSecret: "test-only-signing-secret-that-stays-encrypted",
			},
			event: {
				id: input.eventId,
				type: "organization.updated",
				occurredAt: input.now.toISOString(),
				context: {
					projectId: input.projectId,
					environmentId: input.environmentId,
					organizationId: "organization-atomicity",
					actor: "atomicity-test",
					correlationId: input.eventId,
				},
				data: {
					organization: {
						id: "organization-atomicity",
						name: "Atomicity",
						slug: "atomicity",
						status: "active",
					},
					previous: { name: "Atomicity", slug: "atomicity" },
				},
			},
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
			names.webhookEndpoint,
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

	it("returns and audits leased cancellation as pending", async () => {
		const store = stores[0] as Awaited<ReturnType<typeof createPgStore>>;
		const project = store.snapshot.projects[0]!;
		const environment = store.snapshot.environments[0]!;
		const now = new Date();
		const eventId = `delivery-control-pending-${suffix}`;
		const jobId = `delivery-control-pending-job-${suffix}`;
		await store.mutateCoordinated!((context) => requireDelivery(context)(deliveryInput({
			eventId,
			jobId,
			projectId: project.id,
			environmentId: environment.id,
			sourceKey: `control-pending:${suffix}`,
			now,
		})));
		const names = deliveryTableNames({ prefix: DELIVERY_PREFIX });
		await inspectionPool.query(
			`UPDATE ${quoteIdentifier("public")}.${quoteIdentifier(names.job)}
			 SET state='leased', lease_token=$2, lease_owner=$3,
			     lease_expires_at=$4, updated_at=$1
			 WHERE id=$5`,
			[now, `lease-${suffix}`, `worker-${suffix}`, new Date(now.getTime() + 60_000), jobId],
		);

		const controlled = await controlDeliveryJob(store, {
			projectId: project.id,
			environmentId: environment.id,
			jobId,
			action: "cancel",
			actor: "operator",
			source: "cli",
			now: new Date(now.getTime() + 1),
			confirm: true,
		});
		expect(controlled).toMatchObject({
			dryRun: false,
			preview: {
				job: { state: "leased", cancelRequested: false },
				effect: { state: "leased", cancelRequested: true },
			},
			result: { id: jobId, state: "leased", cancelRequested: true },
		});
		expect(store.snapshot.events.find((event) => event.subjectId === jobId)).toMatchObject({
			action: "delivery.job.cancel",
			outcome: "pending",
			message: "Delivery job cancellation requested",
			metadata: { cancelRequested: true, state: "leased" },
		});
	});

	it("runs the managed endpoint lifecycle with scoped, redacted audit and atomic test enqueue", async () => {
		const store = stores[0] as Awaited<ReturnType<typeof createPgStore>>;
		const project = store.snapshot.projects[0]!;
		const environment = store.snapshot.environments[0]!;
		const audit = {
			actor: "endpoint-operator",
			source: "cli" as const,
			correlationId: `endpoint-correlation-${suffix}`,
		};
		const url = `https://managed-${suffix}.example.test/events`;
		const created = await createWebhookEndpointForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			name: "Managed organization updates",
			url,
			eventKinds: ["organization.updated"],
			...audit,
		});
		expect(created.signingSecret).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
		expect(created.endpoint).toMatchObject({
			status: "disabled",
			resourceVersion: 1,
			secretVersion: 1,
			eventKinds: ["organization.updated"],
		});

		const activated = await updateWebhookEndpointForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			endpointId: created.endpoint.id,
			expectedVersion: created.endpoint.resourceVersion,
			status: "active",
			...audit,
		});
		expect(activated.endpoint).toMatchObject({ status: "active", resourceVersion: 2 });
		expect(await store.deliveryControl!.readiness()).toMatchObject({
			ready: false,
			webhookEndpoints: { total: 1, active: 1, disabled: 0, untestedActive: 1 },
			reasons: expect.arrayContaining(["webhook_endpoint_untested"]),
		});

		const rotatePreview = await rotateWebhookEndpointForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			endpointId: created.endpoint.id,
			expectedVersion: activated.endpoint.resourceVersion,
			...audit,
		});
		expect(rotatePreview).toMatchObject({
			dryRun: true,
			preview: { action: "rotate", nextResourceVersion: 3, secretGenerated: false },
		});
		const auditBeforeRotate = store.snapshot.events.length;
		const rotated = await rotateWebhookEndpointForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			endpointId: created.endpoint.id,
			expectedVersion: activated.endpoint.resourceVersion,
			confirm: true,
			...audit,
		});
		expect(rotated.result).toMatchObject({
			endpoint: { resourceVersion: 3, secretVersion: 2 },
		});
		expect((rotated.result as { signingSecret: string }).signingSecret)
			.not.toBe(created.signingSecret);
		expect(store.snapshot.events).toHaveLength(auditBeforeRotate + 1);

		let fanoutPromise!: Promise<readonly {
			endpointId: string;
			destinationUrl: string;
			delivery: EnqueuedDelivery;
		}[]>;
		await store.mutateCoordinated!((context) => {
			if (!context.fanoutWebhookEndpoints) {
				throw new Error("Managed webhook fanout is required");
			}
			context.data.projects[0]!.name = "Managed fanout committed";
			fanoutPromise = context.fanoutWebhookEndpoints({
				context: {
					scope: { projectId: project.id, environmentId: environment.id },
					actor: audit.actor,
					source: audit.source,
					correlationId: audit.correlationId,
				},
				organization: {
					id: "organization-managed-fanout",
					projectId: project.id,
					environmentId: environment.id,
					name: "Managed Fanout",
					slug: "managed-fanout",
					status: "active",
					updatedAt: new Date().toISOString(),
				},
				before: { name: "Managed Fanout Before", slug: "managed-fanout-before" },
				occurredAt: new Date(),
			});
		});
		expect(await fanoutPromise).toMatchObject([
			{
				endpointId: created.endpoint.id,
				destinationUrl: url,
				delivery: { state: "queued" },
			},
		]);
		expect(store.snapshot.projects[0]!.name).toBe("Managed fanout committed");
		const names = deliveryTableNames({ prefix: DELIVERY_PREFIX });
		const managedEvents = await inspectionPool.query<{ count: string }>(
			`SELECT count(*)::text count
			 FROM ${quoteIdentifier("public")}.${quoteIdentifier(names.event)}
			 WHERE webhook_endpoint_id=$1 AND organization_id='organization-managed-fanout'`,
			[created.endpoint.id],
		);
		expect(Number(managedEvents.rows[0]!.count)).toBe(1);

		const tested = await testWebhookEndpointForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			endpointId: created.endpoint.id,
			expectedVersion: 3,
			confirm: true,
			...audit,
		});
		expect(tested).toMatchObject({
			dryRun: false,
			result: {
				endpoint: { resourceVersion: 4 },
				delivery: { state: "queued" },
			},
		});
		const readinessWhileTestPending = await store.deliveryControl!.readiness();
		expect(readinessWhileTestPending.webhookEndpoints).toMatchObject({
			total: 1,
			active: 1,
			untestedActive: 0,
			testPendingActive: 1,
			testFailedActive: 0,
			testSucceededActive: 0,
		});
		expect(readinessWhileTestPending.reasons).not.toContain("webhook_endpoint_untested");
		expect(readinessWhileTestPending.reasons).toContain("webhook_endpoint_test_pending");

		const testDelivery = (tested.result as { delivery: EnqueuedDelivery }).delivery;
		await inspectionPool.query(
			`UPDATE ${quoteIdentifier("public")}.${quoteIdentifier(names.job)}
			 SET state='delivered', delivered_at=now(), updated_at=now()
			 WHERE id=$1`,
			[testDelivery.jobId],
		);
		const readinessAfterTestDelivery = await store.deliveryControl!.readiness();
		expect(readinessAfterTestDelivery.webhookEndpoints).toMatchObject({
			total: 1,
			active: 1,
			untestedActive: 0,
			testPendingActive: 0,
			testFailedActive: 0,
			testSucceededActive: 1,
		});
		expect(readinessAfterTestDelivery.reasons).not.toEqual(
			expect.arrayContaining([
				"webhook_endpoint_untested",
				"webhook_endpoint_test_pending",
				"webhook_endpoint_test_failed",
			]),
		);

		const deletionPreview = await deleteWebhookEndpointForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			endpointId: created.endpoint.id,
			expectedVersion: 4,
			...audit,
		});
		expect(deletionPreview).toMatchObject({
			dryRun: true,
			preview: { action: "delete", nextResourceVersion: 5 },
		});
		const deleted = await deleteWebhookEndpointForManagement(store, {
			projectId: project.id,
			environmentId: environment.id,
			endpointId: created.endpoint.id,
			expectedVersion: 4,
			confirm: true,
			...audit,
		});
		expect(deleted).toMatchObject({
			dryRun: false,
			result: { endpoint: { status: "deleted", resourceVersion: 5 } },
		});

		const endpointAudit = store.snapshot.events.filter(
			(event) => event.subjectId === created.endpoint.id,
		);
		expect(endpointAudit.map((event) => event.action)).toEqual([
			"delivery.webhook_endpoints.delete",
			"delivery.webhook_endpoints.test",
			"delivery.webhook_endpoints.rotate",
			"delivery.webhook_endpoints.update",
			"delivery.webhook_endpoints.create",
		]);
		const serializedAudit = JSON.stringify(endpointAudit);
		expect(serializedAudit).not.toContain(url);
		expect(serializedAudit).not.toContain(created.signingSecret);
		expect(serializedAudit).not.toContain("config_envelope");
		expect(serializedAudit).not.toContain("keyId");
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

	it("clones, drains, and revokes the coordinated raw query capability", async () => {
		const store = stores[0] as Awaited<ReturnType<typeof createPgStore>>;
		let escapedQuery!: (
			sql: string,
			params?: unknown[],
		) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
		let droppedQuery!: Promise<{
			rows: Record<string, unknown>[];
			rowCount: number | null;
		}>;
		const params: unknown[] = [{ name: "captured-before-mutation" }];

		await mutateCoordinatedWithRuntimeSql(store, (context) => {
			escapedQuery = context.query;
			droppedQuery = context.query("select $1::jsonb as captured", params);
			(params[0] as { name: string }).name = "mutated-after-issuance";
		});

		expect(await droppedQuery).toMatchObject({
			rows: [{ captured: { name: "captured-before-mutation" } }],
		});
		await expect(escapedQuery("select 1")).rejects.toMatchObject({
			code: "TRANSACTION_CAPABILITY_REVOKED",
		});

		const beforeName = store.snapshot.projects[0]!.name;
		await expect(mutateCoordinatedWithRuntimeSql(store, (context) => {
			context.data.projects[0]!.name = "must roll back after dropped query failure";
			void context.query("select * from clearance_missing_transaction_table");
		})).rejects.toBeTruthy();
		await store.refresh();
		expect(store.snapshot.projects[0]!.name).toBe(beforeName);
	});

	it("rolls a coordinated mutation back when the callback rejects with undefined", async () => {
		const store = stores[0] as Awaited<ReturnType<typeof createPgStore>>;
		const beforeName = store.snapshot.projects[0]!.name;
		let rejected = false;
		try {
			await store.mutateCoordinated!((context) => {
				context.data.projects[0]!.name = "must not commit undefined rejection";
				throw undefined;
			});
		} catch (error) {
			rejected = true;
			expect(error).toBeUndefined();
		}
		expect(rejected).toBe(true);
		await store.refresh();
		expect(store.snapshot.projects[0]!.name).toBe(beforeName);
	});
});
