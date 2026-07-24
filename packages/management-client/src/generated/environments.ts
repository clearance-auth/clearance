import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import {
	environmentInspectSchema,
	environmentPromoteSchema,
	environmentSchema,
	resourceScopeSchema,
} from "./primitives.js";

export const ENVIRONMENT_OPERATION_SCHEMAS = {
	"environments.list": {
		input: z.object({
			limit: z.number().int().min(1).max(1000).optional(),
			cursor: z.string().optional(),
		}).strict(),
		output: z.object({
			environments: z.array(environmentSchema),
			nextCursor: z.string().nullable().optional(),
			scope: resourceScopeSchema,
		}).strict(),
	},
	"environments.inspect": {
		input: z.object({ id: z.string().optional() }).strict(),
		output: environmentInspectSchema,
	},
	"environments.create": {
		input: z.object({
			name: z.string(),
			projectId: z.string().optional(),
			kind: z.enum(["development", "preview", "production"]).optional(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ environment: environmentSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				environment: z.object({
					projectId: z.string(), name: z.string(), slug: z.string(),
					kind: z.enum(["development", "preview", "production"]),
				}).strict(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"environments.promote": {
		input: z.object({
			to: z.string(), from: z.string().optional(), dryRun: z.boolean().optional(), confirm: z.boolean().optional(),
		}).strict(),
		output: environmentPromoteSchema,
	},
} satisfies OperationSchemaDomain;
