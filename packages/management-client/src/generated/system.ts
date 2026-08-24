import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { doctorCheckSchema, environmentSchema, overviewSchema, projectSchema } from "./primitives.js";

export const SYSTEM_OPERATION_SCHEMAS = {
	"system.init": {
		input: z.object({ name: z.string().optional(), environment: z.string().optional() }).strict(),
		output: z.object({ project: projectSchema, environment: environmentSchema }).strict(),
	},
	"system.doctor": {
		input: z.object({}).strict(),
		output: z.object({ checks: z.array(doctorCheckSchema), ok: z.boolean(), releaseVersion: z.string() }).strict(),
	},
	"system.dev": {
		input: z.object({}).strict(),
		output: z.object({ commands: z.array(z.string()) }).strict(),
	},
	"system.overview": {
		input: z.object({}).strict(),
		output: overviewSchema,
	},
} satisfies OperationSchemaDomain;
