import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";

const storeV2CollectionSchema = z.enum([
	"projects",
	"environments",
	"principals",
	"organizations",
	"events",
]);

const storeV2CollectionStatusSchema = z.object({
	snapshotCount: z.number().int(),
	relationalCount: z.number().int().nullable(),
	snapshotChecksum: z.string(),
	relationalChecksum: z.string().nullable(),
	consistent: z.boolean(),
	differingIds: z.array(z.string()),
}).strict();

const storeV2StatusSchema = z.object({
	schemaVersion: z.literal(2).nullable(),
	phase: z.enum(["absent", "shadow", "hybrid", "disabled"]),
	snapshotRevision: z.number().int(),
	relationalRevision: z.number().int().nullable(),
	principalRevision: z.number().int().nullable(),
	topologyRevision: z.number().int().nullable(),
	consistent: z.boolean(),
	authoritativeCollections: z.array(storeV2CollectionSchema),
	collections: z.object({
		projects: storeV2CollectionStatusSchema,
		environments: storeV2CollectionStatusSchema,
		principals: storeV2CollectionStatusSchema,
		organizations: storeV2CollectionStatusSchema,
		events: storeV2CollectionStatusSchema,
	}).strict(),
}).strict();

const storeV2PlanSchema = z.object({
	schemaVersion: z.literal(2),
	phase: z.enum(["absent", "shadow", "hybrid", "disabled"]),
	snapshotRevision: z.number().int(),
	collections: z.array(storeV2CollectionSchema),
	rowCounts: z.object({
		projects: z.number().int(),
		environments: z.number().int(),
		principals: z.number().int(),
		organizations: z.number().int(),
		events: z.number().int(),
	}).strict(),
	blockerCount: z.number().int(),
	blockers: z.array(z.object({
		code: z.string(),
		collection: storeV2CollectionSchema,
		resourceIds: z.array(z.string()),
	}).strict()),
	canApply: z.boolean(),
}).strict();

const storeV2StatusEnvelope = <Operation extends string>(operation: Operation) =>
	z.object({
		schemaVersion: z.literal("v1"),
		operation: z.literal(operation),
		storeBackend: z.literal("postgres"),
		dryRun: z.literal(false),
		status: storeV2StatusSchema,
	}).strict();

const storeV2PlanEnvelope = <Operation extends string>(operation: Operation) =>
	z.object({
		schemaVersion: z.literal("v1"),
		operation: z.literal(operation),
		storeBackend: z.literal("postgres"),
		dryRun: z.literal(true),
		plan: storeV2PlanSchema,
	}).strict();

const runtimeSchemaPlanSchema = z.object({
	pendingTables: z.number().int(),
	pendingFields: z.number().int(),
	pendingSecurityMigrations: z.array(z.string()),
}).strict();

const credentialAuthorityStatusSchema = z.object({
	protocolVersion: z.literal(1),
	phase: z.enum(["legacy-open", "draining", "migrating", "digest-live"]),
	generation: z.enum(["legacy-v1", "digest-v1"]),
	drainId: z.string().nullable(),
	bridgeDeploymentId: z.string().nullable(),
	expectedRuntimeCount: z.number().int().nullable(),
	revision: z.number().int(),
	drainStartedAt: z.string().nullable(),
	drainedAt: z.string().nullable(),
	publishedAt: z.string().nullable(),
	activeRuntimeLeases: z.number().int(),
}).strict();

const keyManagementCountsSchema = z.object({
	oidcClientSecrets: z.number().int(),
	scimTokens: z.number().int(),
	jwks: z.number().int(),
	total: z.number().int(),
}).strict();

const keyProviderReadinessSchema = z.object({
	ready: z.boolean(),
	kind: z.enum(["local", "aws-kms", "gcp-kms"]),
	providerRef: z.string(),
	currentKeyRef: z.string(),
	keys: z.array(z.object({
		role: z.enum(["current", "retained"]),
		keyRef: z.string(),
		status: z.enum(["ready", "unavailable", "invalid"]),
	}).strict()),
	reasons: z.array(z.enum([
		"CURRENT_KEY_UNAVAILABLE",
		"RETAINED_KEY_UNAVAILABLE",
		"KEY_CONFIGURATION_INVALID",
		"PROVIDER_UNAVAILABLE",
	])),
}).strict();

const keyManagementPlanSchema = z.object({
	schemaVersion: z.literal("v1"),
	scope: z.object({ projectId: z.string(), environmentId: z.string() }).strict(),
	phase: z.enum(["setup", "batch", "complete"]),
	maxBatchSize: z.object({ perDomain: z.literal(5), total: z.literal(15) }).strict(),
	pending: keyManagementCountsSchema,
	nextBatch: keyManagementCountsSchema,
	planId: z.string().regex(/^[a-f0-9]{64}$/),
}).strict();

const keyManagementStatusSchema = z.object({
	schemaVersion: z.literal("v1"),
	scope: z.object({ projectId: z.string(), environmentId: z.string() }).strict(),
	ready: z.boolean(),
	encryption: z.object({
		ready: z.boolean(),
		purposes: z.object({
			"oidc-client-secret": keyProviderReadinessSchema,
			"scim-bearer-token": keyProviderReadinessSchema,
			"access-token-signing-key": keyProviderReadinessSchema,
		}).strict(),
	}).strict(),
	signing: z.object({
		ready: z.boolean(),
		readiness: keyProviderReadinessSchema,
		algorithm: z.literal("ES256"),
		currentIdentity: z.string(),
		retainedIdentities: z.array(z.string()),
		gracePeriodSeconds: z.number().int(),
	}).strict(),
	schema: z.object({ setup: z.enum(["ready", "pending"]) }).strict(),
	migration: z.object({
		complete: z.boolean(),
		pending: keyManagementCountsSchema,
		migrated: keyManagementCountsSchema,
	}).strict(),
}).strict();

const keyManagementResultSchema = z.object({
	applied: keyManagementCountsSchema,
	changed: z.number().int(),
	previousPlanId: z.string().regex(/^[a-f0-9]{64}$/),
	nextPlanId: z.string().regex(/^[a-f0-9]{64}$/),
	remainingPlan: keyManagementPlanSchema,
	status: keyManagementStatusSchema,
	complete: z.boolean(),
}).strict();

const confirmationInputSchema = z.object({ confirm: z.boolean().optional() }).strict();

export const SCHEMA_OPERATION_SCHEMAS = {
	"schema.status": {
		input: z.object({}).strict(),
		output: z.object({
			management: z.object({
				schemaVersion: z.number().int(),
				releaseVersion: z.string(),
				initializedAt: z.string().optional(),
			}).strict(),
			runtime: z.union([
				z.object({
					configured: z.literal(false),
					state: z.literal("unconfigured"),
					pendingTables: z.literal(0),
					pendingFields: z.literal(0),
					pendingSecurityMigrations: z.tuple([]),
				}).strict(),
				z.object({
					configured: z.literal(true),
					state: z.enum(["configured", "migration-required"]),
					...runtimeSchemaPlanSchema.shape,
				}).strict(),
			]),
		}).strict(),
	},
	"schema.generate": {
		input: z.object({}).strict(),
		output: z.object({
			kind: z.literal("schema.generate"),
			...runtimeSchemaPlanSchema.shape,
			sql: z.string(),
		}).strict(),
	},
	"schema.migrate": {
		input: z.object({ dryRun: z.boolean().optional(), confirm: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({
				kind: z.literal("schema.migrate"),
				dryRun: z.literal(true),
				...runtimeSchemaPlanSchema.shape,
			}).strict(),
			z.object({
				kind: z.literal("schema.migrate"),
				dryRun: z.literal(false),
				appliedTables: z.number().int(),
				appliedFields: z.number().int(),
			}).strict(),
		]),
	},
	"schema.credential-authority.status": {
		input: z.object({}).strict(),
		output: credentialAuthorityStatusSchema,
	},
	"schema.credential-authority.arm": {
		input: z.object({
			deploymentId: z.string().trim().min(1).max(200),
			expectedRuntimeCount: z.number().int().min(1).max(10_000),
			confirm: z.boolean().optional(),
		}).strict(),
		output: credentialAuthorityStatusSchema,
	},
	"schema.credential-authority.drain": {
		input: z.object({
			deploymentId: z.string().trim().min(1).max(200),
			drainId: z.string().trim().min(1).max(200),
			confirm: z.boolean().optional(),
		}).strict(),
		output: credentialAuthorityStatusSchema,
	},
	"schema.store-v2.status": {
		input: z.object({}).strict(),
		output: storeV2StatusEnvelope("schema.store-v2.status"),
	},
	"schema.store-v2.plan": {
		input: z.object({}).strict(),
		output: storeV2PlanEnvelope("schema.store-v2.plan"),
	},
	"schema.store-v2.apply": {
		input: z.object({ dryRun: z.boolean().optional(), confirm: z.boolean().optional() }).strict(),
		output: z.union([
			storeV2PlanEnvelope("schema.store-v2.apply"),
			storeV2StatusEnvelope("schema.store-v2.apply"),
		]),
	},
	"schema.store-v2.verify": {
		input: z.object({}).strict(),
		output: storeV2StatusEnvelope("schema.store-v2.verify"),
	},
	"schema.store-v2.rollback": {
		input: confirmationInputSchema,
		output: storeV2StatusEnvelope("schema.store-v2.rollback"),
	},
	"schema.store-v2.events.cutover": {
		input: confirmationInputSchema,
		output: storeV2StatusEnvelope("schema.store-v2.events.cutover"),
	},
	"schema.store-v2.events.rollback": {
		input: confirmationInputSchema,
		output: storeV2StatusEnvelope("schema.store-v2.events.rollback"),
	},
	"schema.store-v2.principals.cutover": {
		input: confirmationInputSchema,
		output: storeV2StatusEnvelope("schema.store-v2.principals.cutover"),
	},
	"schema.store-v2.principals.rollback": {
		input: confirmationInputSchema,
		output: storeV2StatusEnvelope("schema.store-v2.principals.rollback"),
	},
	"schema.store-v2.topology.cutover": {
		input: confirmationInputSchema,
		output: storeV2StatusEnvelope("schema.store-v2.topology.cutover"),
	},
	"schema.store-v2.topology.rollback": {
		input: confirmationInputSchema,
		output: storeV2StatusEnvelope("schema.store-v2.topology.rollback"),
	},
	"key_management.status": {
		input: z.object({}).strict(),
		output: keyManagementStatusSchema,
	},
	"key_management.plan": {
		input: z.object({}).strict(),
		output: keyManagementPlanSchema,
	},
	"key_management.apply": {
		input: z.object({
			expectedPlanId: z.string().regex(/^[a-f0-9]{64}$/),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ dryRun: z.literal(true), result: keyManagementPlanSchema }).strict(),
			z.object({ dryRun: z.literal(false), result: keyManagementResultSchema }).strict(),
		]),
	},
} satisfies OperationSchemaDomain;
