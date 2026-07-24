import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { resourceScopeSchema } from "./primitives.js";

const authorizationSubjectSchema = z.union([
	z.object({ kind: z.literal("principal"), id: z.string() }).strict(),
	z.object({ kind: z.literal("service_account"), id: z.string() }).strict(),
]);

const authorizationEffectiveSchema = z.object({
	organizationId: z.string(),
	subject: authorizationSubjectSchema,
	roleIds: z.array(z.string()),
	actions: z.array(z.string()),
	revision: z.string(),
}).strict();

const authorizationAssignmentSchema = z.object({
	organizationId: z.string(),
	subject: authorizationSubjectSchema,
	roleId: z.string(),
}).strict();

const authorizationAssignmentSetSchema = z.object({
	organizationId: z.string(),
	subject: authorizationSubjectSchema,
	roleIds: z.array(z.string()),
}).strict();

const serviceAccountSchema = z.object({
	organizationId: z.string(),
	serviceAccountId: z.string(),
	name: z.string(),
	status: z.enum(["active", "disabled"]),
}).strict();

const serviceAccountCredentialSchema = z.object({
	organizationId: z.string(),
	serviceAccountId: z.string(),
	credentialId: z.string(),
	credentialPrefix: z.string(),
	credentialFingerprint: z.string(),
	expiresAt: z.string().nullable(),
	version: z.number(),
}).strict();

/** Canonical UUID accepted by tenant-scoped credential replay authority. */
const operationIdSchema = z.string().regex(
	/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
);

const assignmentFilterInputSchema = z.union([
	z.object({
		organizationId: z.string(),
		subjectKind: z.enum(["principal", "service_account"]),
		subjectId: z.string(),
	}).strict(),
	z.object({
		organizationId: z.string(),
		subjectKind: z.never().optional(),
		subjectId: z.never().optional(),
	}).strict(),
]);

export const AUTHORIZATION_OPERATION_SCHEMAS = {
	"authorization.effective.inspect": {
		input: z.object({
			organizationId: z.string(),
			subjectKind: z.enum(["principal", "service_account"]),
			subjectId: z.string(),
		}).strict(),
		output: z.object({
			effective: authorizationEffectiveSchema,
			scope: resourceScopeSchema,
		}).strict(),
	},
	"authorization.assignments.list": {
		input: assignmentFilterInputSchema,
		output: z.object({
			assignments: z.array(authorizationAssignmentSchema),
			scope: resourceScopeSchema,
		}).strict(),
	},
	"authorization.assignments.replace": {
		input: z.object({
			organizationId: z.string(),
			subjectKind: z.enum(["principal", "service_account"]),
			subjectId: z.string(),
			roleIds: z.array(z.string()),
			expectedRevision: z.string().optional(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({
				assignment: authorizationAssignmentSetSchema,
				changed: z.boolean(),
				previousRevision: z.string(),
				revision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				assignment: authorizationAssignmentSetSchema,
				wouldChange: z.boolean(),
				currentRevision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"authorization.reconcile": {
		input: z.object({
			organizationId: z.string(),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({
				organizationId: z.string(),
				initialized: z.boolean(),
				rolesChanged: z.number(),
				assignmentsChanged: z.number(),
				revision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				organizationId: z.string(),
				initialized: z.boolean(),
				rolesChanged: z.number(),
				assignmentsChanged: z.number(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"service-accounts.list": {
		input: z.object({ organizationId: z.string() }).strict(),
		output: z.object({
			serviceAccounts: z.array(serviceAccountSchema),
			scope: resourceScopeSchema,
		}).strict(),
	},
	"service-accounts.inspect": {
		input: z.object({ organizationId: z.string(), accountId: z.string() }).strict(),
		output: z.object({
			serviceAccount: serviceAccountSchema,
			assignments: z.array(authorizationAssignmentSchema),
			scope: resourceScopeSchema,
		}).strict(),
	},
	"service-accounts.create": {
		input: z.object({
			organizationId: z.string(),
			name: z.string(),
			roleIds: z.array(z.string()),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({
				serviceAccount: serviceAccountSchema,
				previousRevision: z.string(),
				revision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				serviceAccount: z.object({
					organizationId: z.string(),
					name: z.string(),
					status: z.literal("active"),
				}).strict(),
				roleIds: z.array(z.string()),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"service-accounts.disable": {
		input: z.object({
			organizationId: z.string(),
			accountId: z.string(),
			status: z.literal("disabled"),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({
				serviceAccount: serviceAccountSchema,
				previousRevision: z.string(),
				revision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				serviceAccount: serviceAccountSchema,
				wouldChange: z.boolean(),
				currentRevision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"service-accounts.enable": {
		input: z.object({
			organizationId: z.string(),
			accountId: z.string(),
			status: z.literal("active"),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({
				serviceAccount: serviceAccountSchema,
				previousRevision: z.string(),
				revision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				serviceAccount: serviceAccountSchema,
				wouldChange: z.boolean(),
				currentRevision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"service-accounts.credentials.create": {
		input: z.union([
			z.object({
				organizationId: z.string(),
				accountId: z.string(),
				expiresAt: z.string().optional(),
				dryRun: z.literal(true),
			}).strict(),
			z.object({
				organizationId: z.string(),
				accountId: z.string(),
				expiresAt: z.string().optional(),
				dryRun: z.literal(false).optional(),
				operationId: operationIdSchema,
			}).strict(),
		]),
		output: z.union([
			z.object({
				credential: serviceAccountCredentialSchema,
				secret: z.string(),
				previousRevision: z.string(),
				revision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				organizationId: z.string(),
				serviceAccountId: z.string(),
				expiresAt: z.string().nullable(),
				secretGenerated: z.literal(false),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"service-accounts.credentials.rotate": {
		input: z.union([
			z.object({
				organizationId: z.string(),
				accountId: z.string(),
				credentialId: z.string(),
				expiresAt: z.string().optional(),
				dryRun: z.literal(true),
			}).strict(),
			z.object({
				organizationId: z.string(),
				accountId: z.string(),
				credentialId: z.string(),
				expiresAt: z.string().optional(),
				dryRun: z.literal(false).optional(),
				operationId: operationIdSchema,
			}).strict(),
		]),
		output: z.union([
			z.object({
				credential: serviceAccountCredentialSchema,
				secret: z.string(),
				previousRevision: z.string(),
				revision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				organizationId: z.string(),
				serviceAccountId: z.string(),
				credentialId: z.string(),
				expiresAt: z.string().nullable(),
				secretGenerated: z.literal(false),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"service-accounts.credentials.revoke": {
		input: z.object({
			organizationId: z.string(),
			accountId: z.string(),
			credentialId: z.string(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({
				organizationId: z.string(),
				serviceAccountId: z.string(),
				credentialId: z.string(),
				previousRevision: z.string(),
				revision: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({
				dryRun: z.literal(true),
				organizationId: z.string(),
				serviceAccountId: z.string(),
				credentialId: z.string(),
				wouldChange: z.boolean(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
} satisfies OperationSchemaDomain;
