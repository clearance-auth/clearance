import * as z from "zod";

export const resourceScopeSchema = z.object({
	projectId: z.string(),
	environmentId: z.string(),
}).strict();

export const projectSchema = z.object({
	id: z.string(),
	name: z.string(),
	slug: z.string(),
	createdAt: z.string(),
	updatedAt: z.string(),
}).strict();

export const environmentSchema = z.object({
	id: z.string(),
	projectId: z.string(),
	name: z.string(),
	slug: z.string(),
	kind: z.enum(["development", "preview", "production"]),
	createdAt: z.string(),
	updatedAt: z.string(),
}).strict();

export const doctorCheckSchema = z.object({
	id: z.string(),
	name: z.string(),
	status: z.enum(["pass", "fail", "warn"]),
	detail: z.string(),
	remediation: z.string().optional(),
}).strict();

export const auditEventSchema = z.object({
	id: z.string(),
	correlationId: z.string(),
	projectId: z.string().optional(),
	environmentId: z.string().optional(),
	organizationId: z.string().optional(),
	actor: z.string(),
	action: z.string(),
	subjectType: z.string().optional(),
	subjectId: z.string().optional(),
	outcome: z.enum(["success", "failure", "pending"]),
	source: z.enum(["cli", "console", "api", "system", "migration", "sso", "scim"]),
	message: z.string(),
	metadata: z.record(z.string(), z.json()).optional(),
	createdAt: z.string(),
}).strict();

export const resourceCountsSchema = z.object({
	projects: z.number(),
	environments: z.number(),
	principals: z.number(),
	organizations: z.number(),
	memberships: z.number(),
	ssoConnections: z.number(),
	scimConnections: z.number(),
	roles: z.number(),
	setupLinks: z.number(),
	events: z.number().nullable(),
	traces: z.number(),
	migrations: z.number(),
	sessions: z.number(),
	apiKeys: z.number(),
}).strict();

export const overviewSchema = z.object({
	totalUsers: z.number(),
	activeUsers: z.number(),
	organizations: z.number(),
	activeSessions: z.number(),
	recentEvents: z.array(auditEventSchema),
	releaseVersion: z.string(),
	schemaVersion: z.number(),
	resourceCounts: resourceCountsSchema,
}).strict();

const environmentResourceCountsSchema = z.object({
	principals: z.number(),
	organizations: z.number(),
	memberships: z.number().nullable(),
	ssoConnections: z.number().nullable(),
	scimConnections: z.number().nullable(),
	roles: z.number(),
	sessions: z.number(),
	events: z.number().nullable(),
}).strict();

export const environmentLocalStatusSchema = z.object({
	active: z.boolean(),
	storeBackend: z.enum(["json", "postgres"]),
	storePathPresent: z.boolean(),
	schemaVersion: z.number(),
	expectedSchemaVersion: z.number(),
	releaseVersion: z.string(),
	initialized: z.boolean(),
	config: z.object({
		hasClearanceSecret: z.boolean(),
		hasDatabaseUrl: z.boolean(),
		hasOperatorToken: z.boolean(),
		hasCredentialKey: z.boolean(),
		nodeEnv: z.string(),
		operatorProjectIdConfigured: z.boolean(),
		operatorEnvironmentIdConfigured: z.boolean(),
	}).strict(),
	resourceCounts: environmentResourceCountsSchema,
}).strict();

export const environmentInspectSchema = z.object({
	environment: environmentSchema,
	project: projectSchema.nullable(),
	scope: resourceScopeSchema,
	local: environmentLocalStatusSchema,
	correlationId: z.string(),
}).strict();

export const environmentPromoteSchema = z.object({
	dryRun: z.boolean(),
	applied: z.boolean(),
	blocked: z.boolean(),
	idempotent: z.boolean(),
	wouldChange: z.boolean(),
	source: environmentSchema,
	target: environmentSchema,
	scope: resourceScopeSchema,
	plan: z.object({
		action: z.literal("env.promote"),
		description: z.string(),
		resourceCounts: environmentResourceCountsSchema,
		steps: z.array(z.object({
			name: z.string(),
			status: z.enum(["planned", "blocked", "skipped", "done"]),
			detail: z.string().optional(),
		}).strict()),
	}).strict(),
	blockers: z.array(z.object({
		code: z.string(),
		message: z.string(),
		remediation: z.string(),
	}).strict()),
	correlationId: z.string(),
	auditAction: z.literal("env.promote").optional(),
}).strict();
