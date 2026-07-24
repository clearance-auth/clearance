import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { auditEventSchema, resourceScopeSchema } from "./primitives.js";

const diagnosticTraceSchema = z.object({
	id: z.string(),
	correlationId: z.string(),
	projectId: z.string().optional(),
	environmentId: z.string().optional(),
	organizationId: z.string().optional(),
	connectionId: z.string().optional(),
	subsystem: z.enum(["sso", "scim", "email", "webhook", "session", "migration", "deploy", "doctor"]),
	stage: z.string(),
	outcome: z.enum(["pass", "fail", "warn"]),
	mode: z.enum(["simulation", "live"]).optional(),
	cause: z.string().optional(),
	causeConfidence: z.number().optional(),
	owner: z.enum(["customer", "application", "clearance"]).optional(),
	remediation: z.string().optional(),
	redactedRequest: z.record(z.string(), z.json()).optional(),
	redactedResponse: z.record(z.string(), z.json()).optional(),
	checks: z.array(z.object({
		name: z.string(),
		pass: z.boolean(),
		detail: z.string().optional(),
	}).strict()).optional(),
	createdAt: z.string(),
}).strict();

const apiKeySchema = z.object({
	id: z.string(),
	projectId: z.string(),
	environmentId: z.string(),
	name: z.string(),
	scopes: z.array(z.string()),
	prefix: z.string(),
	fingerprint: z.string(),
	status: z.enum(["active", "revoked"]),
	createdAt: z.string(),
	updatedAt: z.string(),
	expiresAt: z.string().optional(),
	revokedAt: z.string().optional(),
	replacedById: z.string().optional(),
}).strict();

const sessionSchema = z.object({
	id: z.string(),
	principalId: z.string(),
	projectId: z.string(),
	environmentId: z.string(),
	status: z.enum(["active", "revoked"]),
	createdAt: z.string(),
	expiresAt: z.string().optional(),
	revokedAt: z.string().optional(),
	ipAddress: z.string().optional(),
	userAgent: z.string().optional(),
}).strict();

const customRoleSchema = z.object({
	id: z.string(),
	projectId: z.string(),
	environmentId: z.string(),
	name: z.string(),
	slug: z.string(),
	description: z.string().optional(),
	permissions: z.array(z.string()),
	kind: z.enum(["built_in", "custom"]),
	organizationId: z.string().optional(),
	status: z.enum(["active", "disabled", "archived"]).optional(),
	createdAt: z.string(),
	updatedAt: z.string(),
}).strict();

const roleValidationSchema = z.object({
	ok: z.literal(true),
	name: z.string().optional(),
	slug: z.string().optional(),
	permissions: z.array(z.string()).optional(),
	scope: resourceScopeSchema,
}).strict();

const eventPageSchema = z.object({
	events: z.array(auditEventSchema),
	nextCursor: z.string().nullable(),
	scope: resourceScopeSchema,
}).strict();

export const EVENTS_IDENTITY_OPERATION_SCHEMAS = {
	"events.list": {
		input: z.object({
			limit: z.number().optional(),
			cursor: z.string().optional(),
			action: z.string().optional(),
			organizationId: z.string().optional(),
		}).strict(),
		output: eventPageSchema,
	},
	"events.tail": {
		input: z.object({
			limit: z.number().optional(),
			action: z.string().optional(),
			organizationId: z.string().optional(),
		}).strict(),
		output: eventPageSchema,
	},
	"events.inspect": {
		input: z.object({ id: z.string() }).strict(),
		output: z.object({
			event: auditEventSchema.optional(),
			trace: diagnosticTraceSchema.optional(),
			scope: resourceScopeSchema,
			replayable: z.boolean(),
			replayBlocker: z.string().optional(),
		}).strict(),
	},
	"events.export": {
		input: z.object({
			format: z.enum(["json", "jsonl"]).optional(),
			limit: z.number().optional(),
			action: z.string().optional(),
			organizationId: z.string().optional(),
			before: z.string().optional(),
		}).strict(),
		output: z.object({
			schemaVersion: z.literal(1),
			kind: z.literal("events.export"),
			exportedAt: z.string(),
			format: z.enum(["json", "jsonl"]),
			scope: resourceScopeSchema,
			limit: z.number(),
			count: z.number(),
			truncated: z.boolean(),
			filters: z.object({
				organizationId: z.string().optional(),
				action: z.string().optional(),
				before: z.string().optional(),
			}).strict(),
			events: z.array(auditEventSchema),
			outputPath: z.string().optional(),
			correlationId: z.string(),
		}).strict(),
	},
	"events.replay": {
		input: z.object({
			id: z.string(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.object({
			dryRun: z.boolean(),
			idempotent: z.boolean(),
			wouldChange: z.boolean(),
			replayable: z.literal(true),
			original: diagnosticTraceSchema,
			trace: diagnosticTraceSchema,
			scope: resourceScopeSchema,
			auditAction: z.enum(["events.replay", "scim.replay"]).optional(),
		}).strict(),
	},
	"keys.list": {
		input: z.object({ includeRevoked: z.boolean().optional() }).strict(),
		output: z.object({ apiKeys: z.array(apiKeySchema), scope: resourceScopeSchema }).strict(),
	},
	"keys.create": {
		input: z.object({
			name: z.string(),
			scopes: z.array(z.string()).optional(),
			expiresAt: z.string().optional(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ apiKey: apiKeySchema, secret: z.string(), scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				apiKey: z.object({
					name: z.string(),
					scopes: z.array(z.string()),
					expiresAt: z.string().optional(),
				}).strict(),
				secretGenerated: z.literal(false),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"keys.rotate": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({
				apiKey: apiKeySchema,
				secret: z.string(),
				revokedKey: apiKeySchema,
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				apiKey: apiKeySchema,
				secretGenerated: z.literal(false),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"keys.revoke": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({ apiKey: apiKeySchema, idempotent: z.boolean(), scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				apiKey: apiKeySchema,
				wouldChange: z.boolean(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"sessions.list": {
		input: z.object({ limit: z.number().optional(), cursor: z.string().optional() }).strict(),
		output: z.object({
			sessions: z.array(sessionSchema),
			nextCursor: z.string().nullable(),
			scope: resourceScopeSchema,
		}).strict(),
	},
	"sessions.revoke": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({ session: sessionSchema, idempotent: z.boolean(), scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				session: sessionSchema,
				wouldChange: z.boolean(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"roles.list": {
		input: z.object({}).strict(),
		output: z.object({ roles: z.array(customRoleSchema), scope: resourceScopeSchema }).strict(),
	},
	"roles.validate": {
		input: z.object({
			name: z.string().optional(),
			slug: z.string().optional(),
			permissions: z.array(z.string()).optional(),
		}).strict(),
		output: roleValidationSchema,
	},
	"roles.create": {
		input: z.object({
			name: z.string(),
			slug: z.string().optional(),
			description: z.string().optional(),
			permissions: z.array(z.string()),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ role: customRoleSchema, scope: resourceScopeSchema }).strict(),
			z.object({ dryRun: z.literal(true), validation: roleValidationSchema, scope: resourceScopeSchema }).strict(),
		]),
	},
	"roles.update": {
		input: z.object({
			id: z.string(),
			name: z.string().optional(),
			description: z.string().optional(),
			permissions: z.array(z.string()).optional(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ role: customRoleSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				id: z.string(),
				validation: roleValidationSchema,
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
} satisfies OperationSchemaDomain;
