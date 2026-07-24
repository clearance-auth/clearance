import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { resourceScopeSchema } from "./primitives.js";

const principalSchema = z.object({
	id: z.string(),
	projectId: z.string(),
	environmentId: z.string(),
	email: z.string(),
	name: z.string(),
	status: z.enum(["active", "disabled", "deleted"]),
	externalId: z.string().optional(),
	createdAt: z.string(),
	updatedAt: z.string(),
}).strict();

const userExportStatusSchema = z.string().refine(
	(value) => value === "active" || value === "disabled",
	"User export status must be active or disabled.",
);

const organizationSchema = z.object({
	id: z.string(),
	projectId: z.string(),
	environmentId: z.string(),
	name: z.string(),
	slug: z.string(),
	status: z.enum(["active", "archived"]),
	externalId: z.string().optional(),
	createdAt: z.string(),
	updatedAt: z.string(),
}).strict();

const membershipSchema = z.object({
	id: z.string(),
	organizationId: z.string(),
	principalId: z.string(),
	role: z.string(),
	status: z.enum(["active", "invited", "removed"]),
	source: z.enum(["manual", "scim", "sso", "import"]),
	createdAt: z.string(),
	updatedAt: z.string(),
}).strict();

const archiveOrganizationResultSchema = z.union([
	z.object({
		organization: organizationSchema,
		dryRun: z.literal(true),
		idempotent: z.boolean(),
		wouldChange: z.boolean(),
		scope: resourceScopeSchema,
	}).strict(),
	z.object({
		organization: organizationSchema,
		dryRun: z.literal(false),
		idempotent: z.boolean(),
		wouldChange: z.boolean(),
		scope: resourceScopeSchema,
	}).strict(),
]);

const memberImportPlanRowSchema = z.object({
	row: z.number(),
	principalId: z.string(),
	role: z.string(),
	idempotent: z.boolean(),
}).strict();

const memberImportSummarySchema = z.object({
	total: z.number(),
	wouldAdd: z.number(),
	idempotent: z.number(),
}).strict();

const memberImportPlanSchema = z.object({
	organizationId: z.string(),
	format: z.enum(["json", "csv"]),
	rows: z.array(memberImportPlanRowSchema),
	summary: memberImportSummarySchema,
}).strict();

const memberImportResultRowSchema = z.union([
	z.object({
		row: z.number(),
		principalId: z.string(),
		status: z.enum(["success", "idempotent"]),
	}).strict(),
	z.object({
		row: z.number(),
		principalId: z.string(),
		status: z.literal("failure"),
		error: z.object({
			code: z.string(),
			stage: z.string(),
			retryable: z.boolean(),
		}).strict(),
	}).strict(),
]);

const memberImportResultSchema = z.object({
	total: z.number(),
	wouldAdd: z.number(),
	idempotent: z.number(),
	completed: z.literal(true),
	partial: z.boolean(),
	results: z.array(memberImportResultRowSchema),
	success: z.number(),
	failure: z.number(),
}).strict();

export const RESOURCE_OPERATION_SCHEMAS = {
	"users.list": {
		input: z.object({
			limit: z.number().int().optional(),
			cursor: z.string().optional(),
		}).strict(),
		output: z.object({
			users: z.array(principalSchema),
			nextCursor: z.string().nullable().optional(),
			scope: resourceScopeSchema,
		}).strict(),
	},
	"users.inspect": {
		input: z.object({ id: z.string() }).strict(),
		output: z.object({ user: principalSchema, scope: resourceScopeSchema }).strict(),
	},
	"users.create": {
		input: z.object({
			email: z.string(),
			name: z.string(),
			password: z.string().optional(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({
				dryRun: z.literal(true),
				email: z.string(),
				name: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({ user: principalSchema }).strict(),
			z.object({
				user: principalSchema,
				passwordSetupToken: z.string(),
				passwordSetupExpiresAt: z.string(),
			}).strict(),
		]),
	},
	"users.update": {
		input: z.object({
			id: z.string(),
			email: z.string().optional(),
			name: z.string().optional(),
			status: z.string().optional(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ user: principalSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				id: z.string(),
				email: z.string().optional(),
				name: z.string().optional(),
				status: z.enum(["active", "disabled"]).optional(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"users.disable": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({ user: principalSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				user: principalSchema,
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"users.delete": {
		input: z.object({ id: z.string() }).strict(),
		output: z.object({ user: principalSchema, scope: resourceScopeSchema }).strict(),
	},
	"users.export": {
		input: z.object({
			format: z.enum(["json", "jsonl"]).optional(),
			limit: z.number().int().optional(),
			status: userExportStatusSchema.optional(),
		}).strict(),
		output: z.object({
			schemaVersion: z.literal(1),
			kind: z.literal("users.export"),
			exportedAt: z.string(),
			format: z.enum(["json", "jsonl"]),
			scope: resourceScopeSchema,
			limit: z.number(),
			count: z.number(),
			truncated: z.boolean(),
			filters: z.object({
				status: z.enum(["active", "disabled"]).optional(),
			}).strict(),
			users: z.array(principalSchema),
			correlationId: z.string(),
		}).strict(),
	},
	"organizations.list": {
		input: z.object({
			limit: z.number().int().optional(),
			cursor: z.string().optional(),
		}).strict(),
		output: z.object({
			organizations: z.array(organizationSchema),
			nextCursor: z.string().nullable().optional(),
			scope: resourceScopeSchema,
		}).strict(),
	},
	"organizations.inspect": {
		input: z.object({ id: z.string() }).strict(),
		output: z.object({ organization: organizationSchema, scope: resourceScopeSchema }).strict(),
	},
	"organizations.create": {
		input: z.object({
			name: z.string(),
			slug: z.string().optional(),
			ownerUserId: z.string().optional(),
		}).strict(),
		output: z.object({ organization: organizationSchema }).strict(),
	},
	"organizations.update": {
		input: z.object({
			id: z.string(),
			name: z.string().optional(),
			slug: z.string().optional(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ organization: organizationSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				id: z.string(),
				name: z.string().optional(),
				slug: z.string().optional(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"organizations.archive": {
		input: z.object({
			id: z.string(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: archiveOrganizationResultSchema,
	},
	"organizations.members.list": {
		input: z.object({ organizationId: z.string() }).strict(),
		output: z.object({ members: z.array(membershipSchema), scope: resourceScopeSchema }).strict(),
	},
	"organizations.members.add": {
		input: z.object({
			organizationId: z.string(),
			principalId: z.string(),
			role: z.string().optional(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ membership: membershipSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				organizationId: z.string(),
				principalId: z.string(),
				role: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"organizations.members.update": {
		input: z.object({
			organizationId: z.string(),
			membershipId: z.string(),
			role: z.string(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ membership: membershipSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				organizationId: z.string(),
				membershipId: z.string(),
				role: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"organizations.members.remove": {
		input: z.object({
			organizationId: z.string(),
			membershipId: z.string(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ membership: membershipSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				organizationId: z.string(),
				membershipId: z.string(),
				membership: membershipSchema,
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"organizations.members.import": {
		input: z.object({
			organizationId: z.string(),
			content: z.string(),
			format: z.enum(["json", "csv"]),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ dryRun: z.literal(true), scope: resourceScopeSchema })
				.extend(memberImportPlanSchema.shape)
				.strict(),
			memberImportResultSchema.extend({ scope: resourceScopeSchema }).strict(),
		]),
	},
} satisfies OperationSchemaDomain;
