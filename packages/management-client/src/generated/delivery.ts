import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { resourceScopeSchema } from "./primitives.js";

const deliveryJobStateSchema = z.enum([
	"queued",
	"leased",
	"retry",
	"delivered",
	"dead",
	"cancelled",
]);

const publicDeliveryJobSchema = z.object({
	id: z.string(),
	eventId: z.string(),
	kind: z.string(),
	projectId: z.string(),
	environmentId: z.string(),
	organizationId: z.string().nullable(),
	webhookEndpointId: z.string().nullable(),
	channel: z.enum(["email", "webhook"]),
	state: deliveryJobStateSchema,
	cancelRequested: z.boolean(),
	attemptCount: z.number(),
	maxAttempts: z.number(),
	availableAt: z.string(),
	semanticExpiresAt: z.string(),
	lastErrorClass: z.string().nullable(),
	createdAt: z.string(),
	updatedAt: z.string(),
	deliveredAt: z.string().nullable(),
	deadAt: z.string().nullable(),
	cancelledAt: z.string().nullable(),
	destination: z.literal("[redacted]"),
}).strict();

const enqueuedDeliverySchema = z.object({
	eventId: z.string(),
	jobId: z.string(),
	kind: z.string(),
	channel: z.enum(["email", "webhook"]),
	state: z.literal("queued"),
	createdAt: z.string(),
	semanticExpiresAt: z.string(),
}).strict();

const deliveryControlEffectSchema = z.object({
	state: deliveryJobStateSchema.nullable(),
	cancelRequested: z.boolean().nullable(),
	maxAttempts: z.number().nullable(),
	createsEvent: z.boolean(),
	createsJob: z.boolean(),
}).strict();

const deliveryCancelPreviewSchema = z.object({
	action: z.literal("cancel"),
	allowed: z.boolean(),
	reason: z.enum([
		"active_delivery",
		"already_terminal",
		"lease_active",
		"payload_erased",
		"semantic_expired",
		"attempt_limit",
	]).nullable(),
	job: publicDeliveryJobSchema,
	effect: deliveryControlEffectSchema,
}).strict();

const deliveryRetryPreviewSchema = z.object({
	action: z.literal("retry"),
	allowed: z.boolean(),
	reason: z.enum([
		"active_delivery",
		"already_terminal",
		"lease_active",
		"payload_erased",
		"semantic_expired",
		"attempt_limit",
	]).nullable(),
	job: publicDeliveryJobSchema,
	effect: deliveryControlEffectSchema,
}).strict();

const deliveryReplayPreviewSchema = z.object({
	action: z.literal("replay"),
	allowed: z.boolean(),
	reason: z.enum([
		"active_delivery",
		"already_terminal",
		"lease_active",
		"payload_erased",
		"semantic_expired",
		"attempt_limit",
	]).nullable(),
	job: publicDeliveryJobSchema,
	effect: deliveryControlEffectSchema,
}).strict();

const publicWebhookEndpointSchema = z.object({
	id: z.string(),
	projectId: z.string(),
	environmentId: z.string(),
	name: z.string(),
	url: z.string().nullable(),
	status: z.enum(["active", "disabled", "deleted"]),
	eventKinds: z.array(z.literal("organization.updated")),
	urlFingerprint: z.string().nullable(),
	secretFingerprint: z.string().nullable(),
	secretVersion: z.number(),
	resourceVersion: z.number(),
	lastTestJobId: z.string().nullable(),
	lastTestRequestedAt: z.string().nullable(),
	createdAt: z.string(),
	updatedAt: z.string(),
	deletedAt: z.string().nullable(),
}).strict();

const webhookEndpointRotatePreviewSchema = z.object({
	action: z.literal("rotate"),
	endpoint: publicWebhookEndpointSchema,
	expectedVersion: z.number(),
	nextResourceVersion: z.number(),
	nextSecretVersion: z.number(),
	secretGenerated: z.literal(false),
}).strict();

const webhookEndpointDeletePreviewSchema = z.object({
	action: z.literal("delete"),
	endpoint: publicWebhookEndpointSchema,
	expectedVersion: z.number(),
	nextResourceVersion: z.number(),
	erasedPayloads: z.number(),
	jobs: z.object({
		queuedOrRetryCancelled: z.number(),
		leasedCancellationRequested: z.number(),
		leasedDeliveryOutcomeAmbiguous: z.boolean(),
	}).strict(),
}).strict();

const webhookEndpointTestPreviewSchema = z.object({
	action: z.literal("test"),
	endpoint: publicWebhookEndpointSchema,
	expectedVersion: z.number(),
	nextResourceVersion: z.number(),
	createsDelivery: z.literal(true),
}).strict();

const webhookEndpointCreateBaseOutputSchema = z.object({
	schemaVersion: z.literal("v1"),
	operation: z.literal("delivery.webhook_endpoints.create"),
	storeBackend: z.literal("postgres"),
	scope: resourceScopeSchema,
	endpoint: publicWebhookEndpointSchema,
});

const webhookEndpointCreateFirstOutputSchema = webhookEndpointCreateBaseOutputSchema.extend({
	signingSecret: z.string(),
}).strict();

const webhookEndpointCreateReplayOutputSchema = webhookEndpointCreateBaseOutputSchema.extend({
	secretAlreadyIssued: z.literal(true),
	oneTimeSecretsOmitted: z.tuple([z.literal("signingSecret")]),
}).strict();

const webhookEndpointRotateBaseOutputSchema = z.object({
	schemaVersion: z.literal("v1"),
	operation: z.literal("delivery.webhook_endpoints.rotate"),
	storeBackend: z.literal("postgres"),
	scope: resourceScopeSchema,
	endpointId: z.string(),
	preview: webhookEndpointRotatePreviewSchema,
});

const webhookEndpointRotateDryRunOutputSchema = webhookEndpointRotateBaseOutputSchema.extend({
	dryRun: z.literal(true),
}).strict();

const webhookEndpointRotateFirstOutputSchema = webhookEndpointRotateBaseOutputSchema.extend({
	dryRun: z.literal(false),
	result: z.object({
		endpoint: publicWebhookEndpointSchema,
		signingSecret: z.string(),
	}).strict(),
}).strict();

const webhookEndpointRotateReplayOutputSchema = webhookEndpointRotateBaseOutputSchema.extend({
	dryRun: z.literal(false),
	result: z.object({ endpoint: publicWebhookEndpointSchema }).strict(),
	secretAlreadyIssued: z.literal(true),
	oneTimeSecretsOmitted: z.tuple([z.literal("result.signingSecret")]),
}).strict();

export const DELIVERY_OPERATION_SCHEMAS = {
	"delivery.jobs.list": {
		input: z.object({
			limit: z.number().optional(),
			cursor: z.string().optional(),
			states: z.array(deliveryJobStateSchema).optional(),
			channel: z.enum(["email", "webhook"]).optional(),
			kind: z.string().optional(),
		}).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			items: z.array(publicDeliveryJobSchema),
			nextCursor: z.string().nullable(),
		}).strict(),
	},
	"delivery.jobs.inspect": {
		input: z.object({ id: z.string() }).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			job: publicDeliveryJobSchema,
		}).strict(),
	},
	"delivery.readiness": {
		input: z.object({ staleAfterMs: z.number().optional() }).strict(),
		output: z.object({
			ready: z.boolean(),
			schema: z.object({
				owner: z.string().nullable(),
				version: z.number().nullable(),
				currentVersion: z.number(),
				current: z.boolean(),
			}).strict(),
			jobs: z.object({
				queued: z.number(),
				leased: z.number(),
				retry: z.number(),
				delivered: z.number(),
				dead: z.number(),
				cancelled: z.number(),
			}).strict(),
			workers: z.object({
				total: z.number(),
				ready: z.number(),
				freshReady: z.number(),
				stale: z.number(),
				staleAfterMs: z.number(),
				lastSeenAt: z.string().nullable(),
			}).strict(),
			keys: z.object({
				checked: z.boolean(),
				available: z.boolean(),
				missingReferences: z.number(),
			}).strict(),
			webhookEndpoints: z.object({
				total: z.number(),
				active: z.number(),
				disabled: z.number(),
				untestedActive: z.number(),
				testPendingActive: z.number(),
				testFailedActive: z.number(),
				testSucceededActive: z.number(),
				lastTestRequestedAt: z.string().nullable(),
			}).strict(),
			reasons: z.array(z.enum([
				"schema_unavailable",
				"schema_outdated",
				"worker_unavailable",
				"key_unavailable",
				"webhook_endpoint_untested",
				"webhook_endpoint_test_pending",
				"webhook_endpoint_test_failed",
			])),
		}).strict(),
	},
	"delivery.quotas.get": {
		input: z.object({}).strict(),
		output: z.object({
			scope: resourceScopeSchema,
			active: z.object({ used: z.number(), limit: z.number() }).strict(),
			backlog: z.object({ used: z.number(), limit: z.number() }).strict(),
			enqueueRate: z.object({
				used: z.number(),
				limit: z.number(),
				windowMs: z.number(),
				windowStartedAt: z.string(),
				resetsAt: z.string().nullable(),
			}).strict(),
		}).strict(),
	},
	"delivery.jobs.cancel": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional(), confirm: z.boolean().optional() }).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			operation: z.literal("delivery.jobs.cancel"),
			storeBackend: z.literal("postgres"),
			scope: resourceScopeSchema,
			jobId: z.string(),
			dryRun: z.boolean(),
			preview: deliveryCancelPreviewSchema,
			result: publicDeliveryJobSchema.optional(),
		}).strict(),
	},
	"delivery.jobs.retry": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional(), confirm: z.boolean().optional() }).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			operation: z.literal("delivery.jobs.retry"),
			storeBackend: z.literal("postgres"),
			scope: resourceScopeSchema,
			jobId: z.string(),
			dryRun: z.boolean(),
			preview: deliveryRetryPreviewSchema,
			result: publicDeliveryJobSchema.optional(),
		}).strict(),
	},
	"delivery.jobs.replay": {
		input: z.object({
			id: z.string(),
			maxAttempts: z.number().optional(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			operation: z.literal("delivery.jobs.replay"),
			storeBackend: z.literal("postgres"),
			scope: resourceScopeSchema,
			jobId: z.string(),
			dryRun: z.boolean(),
			preview: deliveryReplayPreviewSchema,
			result: enqueuedDeliverySchema.optional(),
		}).strict(),
	},
	"delivery.webhook_endpoints.list": {
		input: z.object({
			limit: z.number().optional(),
			cursor: z.string().optional(),
			statuses: z.array(z.enum(["active", "disabled", "deleted"])).optional(),
			eventKind: z.literal("organization.updated").optional(),
		}).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			items: z.array(publicWebhookEndpointSchema),
			nextCursor: z.string().nullable(),
		}).strict(),
	},
	"delivery.webhook_endpoints.inspect": {
		input: z.object({ id: z.string() }).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			endpoint: publicWebhookEndpointSchema,
		}).strict(),
	},
	"delivery.webhook_endpoints.create": {
		input: z.object({
			name: z.string(),
			url: z.string(),
			eventKinds: z.array(z.literal("organization.updated")).optional(),
		}).strict(),
		output: z.union([
			webhookEndpointCreateFirstOutputSchema,
			webhookEndpointCreateReplayOutputSchema,
		]),
	},
	"delivery.webhook_endpoints.update": {
		input: z.object({
			id: z.string(),
			expectedVersion: z.number(),
			name: z.string().optional(),
			url: z.string().optional(),
			eventKinds: z.array(z.literal("organization.updated")).optional(),
			status: z.enum(["active", "disabled"]).optional(),
		}).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			operation: z.literal("delivery.webhook_endpoints.update"),
			storeBackend: z.literal("postgres"),
			scope: resourceScopeSchema,
			endpoint: publicWebhookEndpointSchema,
		}).strict(),
	},
	"delivery.webhook_endpoints.rotate": {
		input: z.object({
			id: z.string(),
			expectedVersion: z.number(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.union([
			webhookEndpointRotateDryRunOutputSchema,
			webhookEndpointRotateFirstOutputSchema,
			webhookEndpointRotateReplayOutputSchema,
		]),
	},
	"delivery.webhook_endpoints.delete": {
		input: z.object({
			id: z.string(),
			expectedVersion: z.number(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			operation: z.literal("delivery.webhook_endpoints.delete"),
			storeBackend: z.literal("postgres"),
			scope: resourceScopeSchema,
			endpointId: z.string(),
			dryRun: z.boolean(),
			preview: webhookEndpointDeletePreviewSchema,
			result: z.object({
				endpoint: publicWebhookEndpointSchema,
				erasedPayloads: z.number(),
				jobs: z.object({
					queuedOrRetryCancelled: z.number(),
					leasedCancellationRequested: z.number(),
					leasedDeliveryOutcomeAmbiguous: z.boolean(),
				}).strict(),
			}).strict().optional(),
		}).strict(),
	},
	"delivery.webhook_endpoints.test": {
		input: z.object({
			id: z.string(),
			expectedVersion: z.number(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			operation: z.literal("delivery.webhook_endpoints.test"),
			storeBackend: z.literal("postgres"),
			scope: resourceScopeSchema,
			endpointId: z.string(),
			dryRun: z.boolean(),
			preview: webhookEndpointTestPreviewSchema,
			result: z.object({
				endpoint: publicWebhookEndpointSchema,
				delivery: enqueuedDeliverySchema,
			}).strict().optional(),
		}).strict(),
	},
} satisfies OperationSchemaDomain;
