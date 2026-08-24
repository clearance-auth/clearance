import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { resourceScopeSchema } from "./primitives.js";

const presentationSchema = z
	.object({
	productLabel: z.string(),
	homeLabel: z.string(),
	accentColor: z.string(),
	logoUrl: z.string().nullable(),
	version: z.number(),
	updatedAt: z.string().nullable(),
	})
	.strict();

const presentationCandidateSchema = z
	.object({
	productLabel: z.string(),
	homeLabel: z.string(),
	accentColor: z.string(),
	logoUrl: z.string().nullable().optional(),
	})
	.strict();

const presentationPlanSchema = z
	.object({
	schemaVersion: z.literal("v1"),
	scope: resourceScopeSchema,
	expectedVersion: z.number(),
	wouldChange: z.boolean(),
	current: presentationSchema,
	candidate: presentationSchema,
	})
	.strict();

const domainSchema = z
	.object({
	origin: z.string(),
	hostname: z.string(),
	dnsName: z.string(),
	state: z.enum(["pending", "verified", "active", "disabled"]),
	version: z.number(),
	verifiedAt: z.string().nullable(),
	updatedAt: z.string(),
	})
	.strict();

const domainControlSchema = z
	.object({
	schemaVersion: z.literal("v1"),
	scope: resourceScopeSchema,
	operation: z.enum(["verify", "activate", "disable"]),
	dryRun: z.boolean(),
	wouldChange: z.boolean(),
	domain: domainSchema,
	})
	.strict();

const domainChallengeSchema = z
	.object({
	schemaVersion: z.literal("v1"),
	scope: resourceScopeSchema,
	domain: domainSchema,
		dnsChallenge: z
			.object({
		name: z.string(),
		value: z.string(),
			})
			.strict(),
	})
	.strict();

const domainChallengeReplaySchema = z
	.object({
	schemaVersion: z.literal("v1"),
	scope: resourceScopeSchema,
	domain: domainSchema,
	challengeAlreadyIssued: z.literal(true),
	oneTimeSecretsOmitted: z.tuple([z.literal("dnsChallenge.value")]),
	})
	.strict();

const senderSchema = z
	.object({
	displayName: z.string(),
	address: z.string(),
	domain: z.string(),
	version: z.number(),
	updatedAt: z.string().nullable(),
	})
	.strict();

const senderCandidateSchema = z
	.object({
	displayName: z.string(),
	address: z.string(),
	})
	.strict();

const senderPlanSchema = z
	.object({
	schemaVersion: z.literal("v1"),
	scope: resourceScopeSchema,
	expectedVersion: z.number(),
	wouldChange: z.boolean(),
	current: senderSchema.nullable(),
	candidate: senderSchema,
	})
	.strict();

const templateKindSchema = z.enum([
	"verification",
	"password-reset",
	"invitation",
	"email-change",
]);
const templateSchema = z
	.object({
	kind: templateKindSchema,
	subject: z.string(),
	plainText: z.string(),
	html: z.string(),
	variables: z.array(z.string()),
	version: z.number(),
	hash: z.string(),
	updatedAt: z.string().nullable(),
	})
	.strict();

const templateCandidateSchema = z
	.object({
	kind: templateKindSchema,
	subject: z.string(),
	plainText: z.string(),
	html: z.string(),
	})
	.strict();

const templatePlanSchema = z
	.object({
	schemaVersion: z.literal("v1"),
	scope: resourceScopeSchema,
	expectedVersion: z.number(),
	wouldChange: z.boolean(),
	current: templateSchema,
	candidate: templateSchema,
	})
	.strict();

export const PRODUCT_PRESENTATION_OPERATION_SCHEMAS = {
	"product_presentation.get": {
		input: z.object({}).strict(),
		output: z
			.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			presentation: presentationSchema,
			})
			.strict(),
	},
	"product_presentation.plan": {
		input: presentationCandidateSchema,
		output: presentationPlanSchema,
	},
	"product_presentation.apply": {
		input: presentationCandidateSchema
			.extend({
			expectedVersion: z.number(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
			})
			.strict(),
		output: z
			.object({
			dryRun: z.boolean(),
				result: presentationPlanSchema
					.extend({
				changed: z.boolean().optional(),
				previousVersion: z.number().optional(),
				version: z.number().optional(),
					})
					.strict(),
			})
			.strict(),
	},
	"product_domains.list": {
		input: z.object({}).strict(),
		output: z
			.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			domains: z.array(domainSchema),
			})
			.strict(),
	},
	"product_domains.create": {
		input: z.object({ origin: z.string() }).strict(),
		output: z.union([domainChallengeSchema, domainChallengeReplaySchema]),
	},
	"product_domains.reissue": {
		input: z
			.object({ origin: z.string(), expectedVersion: z.number() })
			.strict(),
		output: z.union([domainChallengeSchema, domainChallengeReplaySchema]),
	},
	"product_domains.verify": {
		input: z.object({ origin: z.string() }).strict(),
		output: domainControlSchema,
	},
	"product_domains.activate": {
		input: z
			.object({
			origin: z.string(),
			expectedVersion: z.number(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
			})
			.strict(),
		output: domainControlSchema,
	},
	"product_domains.disable": {
		input: z
			.object({
			origin: z.string(),
			expectedVersion: z.number(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
			})
			.strict(),
		output: domainControlSchema,
	},
	"product_sender.get": {
		input: z.object({}).strict(),
		output: z
			.object({
				schemaVersion: z.literal("v1"),
				scope: resourceScopeSchema,
				sender: senderSchema.nullable(),
			})
			.strict(),
	},
	"product_sender.plan": {
		input: senderCandidateSchema,
		output: senderPlanSchema,
	},
	"product_sender.apply": {
		input: senderCandidateSchema
			.extend({
				expectedVersion: z.number(),
				dryRun: z.boolean().optional(),
				confirm: z.boolean().optional(),
			})
			.strict(),
		output: z
			.object({
				dryRun: z.boolean(),
				result: senderPlanSchema
					.extend({
						changed: z.boolean().optional(),
						previousVersion: z.number().optional(),
						version: z.number().optional(),
					})
					.strict(),
			})
			.strict(),
	},
	"product_sender.readiness": {
		input: z.object({ staleAfterMs: z.number().optional() }).strict(),
		output: z
			.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			ready: z.boolean(),
				schema: z
					.object({
						isUpToDate: z.boolean(),
				owner: z.string().nullable(),
						installedVersion: z.number().nullable(),
						expectedVersion: z.number(),
					})
					.strict(),
				worker: z
					.object({
				freshReady: z.number(),
				lastSeenAt: z.string().nullable(),
				staleAfterMs: z.number(),
					})
					.strict(),
				keys: z
					.object({
				checked: z.boolean(),
				available: z.boolean(),
				missingReferences: z.number(),
					})
					.strict(),
			reasons: z.array(z.string()),
			})
			.strict(),
	},
	"product_templates.get": {
		input: z.object({ kind: templateKindSchema }).strict(),
		output: z
			.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			template: templateSchema,
			})
			.strict(),
	},
	"product_templates.plan": {
		input: templateCandidateSchema,
		output: templatePlanSchema,
	},
	"product_templates.apply": {
		input: templateCandidateSchema
			.extend({
			expectedVersion: z.number(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
			})
			.strict(),
		output: z
			.object({
			dryRun: z.boolean(),
				result: templatePlanSchema
					.extend({
				changed: z.boolean().optional(),
				previousVersion: z.number().optional(),
				version: z.number().optional(),
					})
					.strict(),
			})
			.strict(),
	},
} as const satisfies OperationSchemaDomain;
