import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { overviewSchema, projectSchema, resourceScopeSchema } from "./primitives.js";

export const PROJECT_OPERATION_SCHEMAS = {
	"projects.list": {
		input: z.object({}).strict(),
		output: z.object({ projects: z.array(projectSchema), scope: resourceScopeSchema }).strict(),
	},
	"projects.inspect": {
		input: z.object({ id: z.string().optional() }).strict(),
		output: z.object({ project: projectSchema, overview: overviewSchema, scope: resourceScopeSchema }).strict(),
	},
	"projects.create": {
		input: z.object({ name: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({ project: projectSchema }).strict(),
			z.object({ dryRun: z.literal(true), project: z.object({ name: z.string(), slug: z.string() }).strict() }).strict(),
		]),
	},
} satisfies OperationSchemaDomain;
