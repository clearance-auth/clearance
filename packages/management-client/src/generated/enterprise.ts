import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { resourceScopeSchema } from "./primitives.js";

const jsonRecordSchema = z.record(z.string(), z.json());

const diagnosticCheckSchema = z.object({
	name: z.string(),
	pass: z.boolean(),
	detail: z.string().optional(),
}).strict();

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
	redactedRequest: jsonRecordSchema.optional(),
	redactedResponse: jsonRecordSchema.optional(),
	checks: z.array(diagnosticCheckSchema).optional(),
	createdAt: z.string(),
}).strict();

const publicIdentityConnectionSchema = z.object({
	id: z.string(),
	organizationId: z.string(),
	protocol: z.enum(["saml", "oidc"]),
	provider: z.string(),
	status: z.enum(["draft", "testing", "active", "disabled"]),
	domains: z.array(z.string()),
	issuer: z.string().optional(),
	audience: z.string().optional(),
	metadataUrl: z.string().optional(),
	clientId: z.string().optional(),
	clientSecretFingerprint: z.string().optional(),
	samlEntryPoint: z.string().optional(),
	samlCertificate: z.string().optional(),
	samlCertificateFingerprint: z.string().optional(),
	certificateFingerprint: z.string().optional(),
	attributeMapping: z.record(z.string(), z.string()),
	createdAt: z.string(),
	updatedAt: z.string(),
	hasClientSecret: z.boolean(),
}).strict();

const publicDirectoryConnectionSchema = z.object({
	id: z.string(),
	organizationId: z.string(),
	provider: z.string(),
	status: z.enum(["draft", "testing", "active", "disabled"]),
	endpoint: z.string(),
	bearerTokenFingerprint: z.string().optional(),
	deprovisioningPolicy: z.enum(["disable", "delete", "suspend"]),
	createdAt: z.string(),
	updatedAt: z.string(),
	hasBearerToken: z.boolean(),
}).strict();

const setupLinkSchema = z.object({
	url: z.string(),
	expiresAt: z.string(),
	token: z.string(),
	tokenFingerprint: z.string(),
	capabilityId: z.string(),
	scope: resourceScopeSchema,
}).strict();

const setupLinkReplaySchema = setupLinkSchema.omit({ url: true, token: true }).extend({
	oneTimeSecretsOmitted: z.tuple([z.literal("token"), z.literal("url")]),
}).strict();

const ssoSimulationTestResultSchema = z.object({
	pass: z.boolean(),
	trace: diagnosticTraceSchema,
	connection: publicIdentityConnectionSchema,
	mode: z.literal("simulation"),
	certifiedExternalTenant: z.literal(false).optional(),
	evidence: z.string().optional(),
	authorizationUrl: z.string().optional(),
}).strict();

const ssoLiveTestResultSchema = z.object({
	pass: z.boolean(),
	trace: diagnosticTraceSchema,
	connection: publicIdentityConnectionSchema,
	mode: z.literal("live"),
	evidence: z.string(),
	endpoint: z.string(),
}).strict();

const scimProposedChangeSchema = z.object({
	action: z.enum(["deprovision", "upsert"]),
	email: z.string(),
}).strict();

const groupLifecycleEvidenceSchema = z.object({
	scenario: z.literal("group-lifecycle"),
	group: z.object({ id: z.string(), status: z.literal("deleted") }).strict(),
	counts: z.object({
		usersCreated: z.number(),
		membersCreated: z.number(),
		membersAfterPatch: z.number(),
	}).strict(),
	actions: z.object({
		create: z.number(),
		patch: z.number(),
		get: z.number(),
		list: z.number(),
		delete: z.number(),
	}).strict(),
}).strict();

const scimSimulationTestResultSchema = z.object({
	pass: z.boolean(),
	trace: diagnosticTraceSchema,
	proposed: z.array(scimProposedChangeSchema),
	connection: publicDirectoryConnectionSchema,
	mode: z.literal("simulation"),
	evidence: z.string().optional(),
	groupLifecycle: groupLifecycleEvidenceSchema.optional(),
	externalProviderCertified: z.literal(false).optional(),
}).strict();

const scimLiveTestResultSchema = z.object({
	pass: z.boolean(),
	trace: diagnosticTraceSchema,
	connection: publicDirectoryConnectionSchema,
	mode: z.literal("live"),
	evidence: z.string(),
	endpoint: z.string(),
}).strict();

const readinessCheckSchema = z.object({
	id: z.string(),
	name: z.string(),
	status: z.enum(["pass", "fail", "warn", "skip"]),
	detail: z.string(),
	fingerprint: z.string().optional(),
	simulation: z.boolean().optional(),
}).strict();

const readinessReportSchema = z.object({
	id: z.string(),
	organizationId: z.string(),
	generatedAt: z.string(),
	checks: z.array(readinessCheckSchema),
	overall: z.enum(["ready", "blocked", "attention"]),
	conformance: z.object({
		mode: z.enum(["simulation", "live"]),
		liveCertified: z.boolean(),
		note: z.string(),
	}).strict(),
	remainingCustomerActions: z.array(z.string()),
	signature: z.string(),
}).strict();

const scimUserSchema = z.object({
	userName: z.string(),
	displayName: z.string().optional(),
	active: z.boolean().optional(),
}).strict();

const SSO_FIXTURES = new Set([
	"ok",
	"okta",
	"entra",
	"wrong-issuer",
	"wrong-audience",
	"malformed",
	"expired",
	"clock-skew",
	"replay",
	"local-oidc",
]);
const ssoFixtureSchema = z.string().refine((value) => SSO_FIXTURES.has(value), "Unsupported SSO fixture.");

const SCIM_FIXTURES = new Set(["ok", "malformed", "unauthorized"]);
const scimFixtureSchema = z.string().refine((value) => SCIM_FIXTURES.has(value), "Unsupported SCIM fixture.");

const scimTestInputSchema = z.object({
	id: z.string(),
	fixture: scimFixtureSchema.optional(),
	live: z.boolean().default(false),
	dryRun: z.boolean().default(true),
	scenario: z.enum(["users", "group-lifecycle"]).optional(),
	users: z.array(scimUserSchema).optional(),
}).strict().superRefine((input, context) => {
	if (input.live && input.dryRun) {
		context.addIssue({
			code: "custom",
			message: "live SCIM tests require dryRun false",
			path: ["dryRun"],
		});
	}
	if (input.live && (input.fixture !== undefined || input.scenario !== undefined || input.users !== undefined)) {
		context.addIssue({
			code: "custom",
			message: "live SCIM tests cannot include simulation fields",
			path: ["live"],
		});
	}
	if (input.scenario === "group-lifecycle" && input.live) {
		context.addIssue({
			code: "custom",
			message: "group-lifecycle runs only against the bundled runtime",
			path: ["live"],
		});
	}
	if (input.scenario === "group-lifecycle" && input.users !== undefined) {
		context.addIssue({
			code: "custom",
			message: "group-lifecycle owns its SCIM users",
			path: ["users"],
		});
	}
});

export const ENTERPRISE_OPERATION_SCHEMAS = {
	"sso.list": {
		input: z.object({ organizationId: z.string().optional() }).strict(),
		output: z.object({ connections: z.array(publicIdentityConnectionSchema), scope: resourceScopeSchema }).strict(),
	},
	"sso.create": {
		input: z.object({
			organizationId: z.string(),
			provider: z.string(),
			protocol: z.enum(["oidc", "saml"]).optional(),
			issuer: z.string().optional(),
			audience: z.string().optional(),
			domain: z.string().optional(),
			samlEntryPoint: z.string().optional(),
			samlCertificate: z.string().optional(),
		}).strict(),
		output: z.object({ connection: publicIdentityConnectionSchema }).strict(),
	},
	"sso.configure": {
		input: z.object({
			id: z.string(),
			issuer: z.string().optional(),
			audience: z.string().optional(),
			domain: z.string().optional(),
			domains: z.array(z.string()).optional(),
			dryRun: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ connection: publicIdentityConnectionSchema, scope: resourceScopeSchema }).strict(),
			z.object({
				dryRun: z.literal(true),
				connection: publicIdentityConnectionSchema,
				proposed: z.object({
					issuer: z.string().optional(),
					audience: z.string().optional(),
					domains: z.array(z.string()).optional(),
				}).strict(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"sso.test": {
		input: z.object({
			id: z.string(),
			fixture: ssoFixtureSchema.optional(),
			live: z.boolean().default(false),
		}).strict(),
		output: z.union([ssoSimulationTestResultSchema, ssoLiveTestResultSchema]),
	},
	"sso.setupLink.create": {
		input: z.object({ organizationId: z.string() }).strict(),
		output: z.union([setupLinkSchema, setupLinkReplaySchema]),
	},
	"sso.rotate": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({ connection: publicIdentityConnectionSchema, scope: resourceScopeSchema }).strict(),
			z.object({ dryRun: z.literal(true), connection: publicIdentityConnectionSchema, wouldChange: z.literal(true), scope: resourceScopeSchema }).strict(),
		]),
	},
	"sso.disable": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({
				connection: publicIdentityConnectionSchema,
				idempotent: z.boolean(),
				runtimeRemoved: z.boolean().optional(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({ dryRun: z.literal(true), connection: publicIdentityConnectionSchema, wouldChange: z.boolean(), scope: resourceScopeSchema }).strict(),
		]),
	},
	"scim.list": {
		input: z.object({ organizationId: z.string().optional() }).strict(),
		output: z.object({ connections: z.array(publicDirectoryConnectionSchema), scope: resourceScopeSchema }).strict(),
	},
	"scim.create": {
		input: z.object({ organizationId: z.string(), provider: z.string(), endpoint: z.string().optional() }).strict(),
		output: z.union([
			z.object({ connection: publicDirectoryConnectionSchema.extend({ bearerTokenOnce: z.string() }).strict() }).strict(),
			z.object({
				connection: publicDirectoryConnectionSchema,
				oneTimeSecretsOmitted: z.tuple([z.literal("connection.bearerTokenOnce")]),
			}).strict(),
		]),
	},
	"scim.test": {
		input: scimTestInputSchema,
		output: z.union([scimSimulationTestResultSchema, scimLiveTestResultSchema]),
	},
	"scim.setupLink.create": {
		input: z.object({ organizationId: z.string() }).strict(),
		output: z.union([setupLinkSchema, setupLinkReplaySchema]),
	},
	"scim.rotate": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({ connection: publicDirectoryConnectionSchema, scope: resourceScopeSchema }).strict(),
			z.object({ dryRun: z.literal(true), connection: publicDirectoryConnectionSchema, wouldChange: z.literal(true), scope: resourceScopeSchema }).strict(),
		]),
	},
	"scim.disable": {
		input: z.object({ id: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({
				connection: publicDirectoryConnectionSchema,
				idempotent: z.boolean(),
				runtimeRemoved: z.boolean().optional(),
				scope: resourceScopeSchema,
			}).strict(),
			z.object({ dryRun: z.literal(true), connection: publicDirectoryConnectionSchema, wouldChange: z.boolean(), scope: resourceScopeSchema }).strict(),
		]),
	},
	"scim.replay": {
		input: z.object({ traceId: z.string(), dryRun: z.boolean().optional(), confirm: z.boolean().optional() }).strict(),
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
	"readiness.check": {
		input: z.object({ organizationId: z.string() }).strict(),
		output: z.object({ report: readinessReportSchema }).strict(),
	},
	"readiness.report": {
		input: z.object({ organizationId: z.string() }).strict(),
		output: z.object({ report: readinessReportSchema }).strict(),
	},
} satisfies OperationSchemaDomain;
