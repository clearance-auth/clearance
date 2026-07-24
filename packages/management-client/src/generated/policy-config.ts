import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";
import { resourceScopeSchema } from "./primitives.js";

const authenticationAssuranceSchema = z.enum([
	"single_factor",
	"multi_factor",
	"phishing_resistant",
]);

const lockoutPolicySchema = z.object({
	enabled: z.boolean(),
	maxFailedAttempts: z.number(),
	durationSeconds: z.number(),
}).strict();

const lockoutPolicyOverrideSchema = z.object({
	enabled: z.boolean().optional(),
	maxFailedAttempts: z.number().optional(),
	durationSeconds: z.number().optional(),
}).strict();

const authenticationPolicySchema = z.object({
	passwordLockout: lockoutPolicySchema,
	factorLockout: lockoutPolicySchema,
	minimumAssurance: authenticationAssuranceSchema,
	allowedFactors: z.object({ totp: z.boolean(), passkey: z.boolean() }).strict(),
	trustedDevice: z.object({ enabled: z.boolean(), maxAgeSeconds: z.number() }).strict(),
	assuranceMaxAgeSeconds: z.number().nullable(),
}).strict();

const authenticationPolicyOverrideSchema = z.object({
	passwordLockout: lockoutPolicyOverrideSchema.optional(),
	factorLockout: lockoutPolicyOverrideSchema.optional(),
	minimumAssurance: authenticationAssuranceSchema.optional(),
	allowedFactors: z.object({ totp: z.boolean().optional(), passkey: z.boolean().optional() }).strict().optional(),
	trustedDevice: z.object({ enabled: z.boolean().optional(), maxAgeSeconds: z.number().optional() }).strict().optional(),
	assuranceMaxAgeSeconds: z.number().nullable().optional(),
}).strict();

const policyCandidateSchema = z.union([
	authenticationPolicySchema,
	authenticationPolicyOverrideSchema,
	z.null(),
]);

const policyTargetSchema = z.union([
	z.object({ kind: z.literal("environment") }).strict(),
	z.object({ kind: z.literal("organization"), organizationId: z.string() }).strict(),
]);

const policyStateSchema = z.object({
	revision: z.string(),
	policy: policyCandidateSchema,
	effective: authenticationPolicySchema,
}).strict();

const policyPlanResultSchema = z.object({
	schemaVersion: z.literal("v1"),
	scope: resourceScopeSchema,
	target: policyTargetSchema,
	expectedRevision: z.string(),
	candidateRevision: z.string(),
	wouldChange: z.boolean(),
	current: policyStateSchema,
	candidate: policyStateSchema,
}).strict();

const policyApplyResultSchema = policyPlanResultSchema.extend({
	changed: z.boolean(),
	previousRevision: z.string(),
	revision: z.string(),
}).strict();

const environmentPolicyInputSchema = z.object({
	organizationId: z.never().optional(),
	policy: authenticationPolicySchema,
}).strict();

const organizationPolicyInputSchema = z.object({
	organizationId: z.string(),
	policy: z.union([authenticationPolicyOverrideSchema, z.null()]),
}).strict();

function rejectCompleteOrganizationPolicy(
	input: Readonly<{ organizationId?: string; policy: unknown }>,
	context: z.RefinementCtx,
): void {
	if (input.organizationId !== undefined && authenticationPolicySchema.safeParse(input.policy).success) {
		context.addIssue({
			code: z.ZodIssueCode.custom,
			path: ["policy"],
			message: "An organization policy must be a sparse override or null.",
		});
	}
}

const policyPlanInputSchema = z.union([
	environmentPolicyInputSchema,
	organizationPolicyInputSchema,
]).superRefine(rejectCompleteOrganizationPolicy);

const policyApplyControlSchema = {
	expectedRevision: z.string(),
	dryRun: z.boolean().optional(),
	confirm: z.boolean().optional(),
} as const;

const policyApplyInputSchema = z.union([
	environmentPolicyInputSchema.extend(policyApplyControlSchema).strict(),
	organizationPolicyInputSchema.extend(policyApplyControlSchema).strict(),
]).superRefine(rejectCompleteOrganizationPolicy);

const PROHIBITED_CONFIG_RECORD_KEYS = ["__proto__", "constructor", "prototype"] as const;

/**
 * Zod's record parser reconstructs the object it parses. Inspect own keys on
 * the raw input first so hostile prototype-sensitive keys cannot disappear
 * during that reconstruction.
 */
const configRecordSchema = z.custom<Record<string, string>>((input) => {
	if (!input || typeof input !== "object" || Array.isArray(input)) return false;
	if (PROHIBITED_CONFIG_RECORD_KEYS.some((key) => Object.prototype.hasOwnProperty.call(input, key))) return false;
	return Object.entries(input).every(([key, value]) =>
		key.length > 0 && typeof value === "string");
}, "Config must contain only safe string keys and string values.");

const publicConfigSchema = z.object({
	config: configRecordSchema,
	redactedKeys: z.array(z.string()),
}).strict();

const unlockCountsSchema = z.object({
	matchedRows: z.number(),
	failedAttemptRows: z.number(),
	reservationRows: z.number(),
	lockedRows: z.number(),
	wouldChangeRows: z.number(),
}).strict();

const unlockPreviewSchema = z.object({
	schemaVersion: z.literal("v1"),
	userId: z.string(),
	kind: z.enum(["password", "factor", "all"]),
	password: unlockCountsSchema,
	factor: unlockCountsSchema,
	wouldChange: z.boolean(),
}).strict();

const unlockResultSchema = unlockPreviewSchema.extend({ changed: z.boolean() }).strict();

export const POLICY_CONFIG_OPERATION_SCHEMAS = {
	"authentication_policy.get": {
		input: z.object({ organizationId: z.string().optional() }).strict(),
		output: z.object({
			schemaVersion: z.literal("v1"),
			scope: resourceScopeSchema,
			revision: z.string(),
			environment: authenticationPolicySchema,
			organizationOverride: z.object({
				organizationId: z.string(),
				revision: z.string(),
				policy: authenticationPolicyOverrideSchema,
			}).strict().nullable(),
			effective: authenticationPolicySchema,
		}).strict(),
	},
	"authentication_policy.plan": {
		input: policyPlanInputSchema,
		output: policyPlanResultSchema,
	},
	"authentication_policy.apply": {
		input: policyApplyInputSchema,
		output: z.object({
			dryRun: z.boolean(),
			result: z.union([policyPlanResultSchema, policyApplyResultSchema]),
		}).strict(),
	},
	"authentication_policy.unlock": {
		input: z.object({
			userId: z.string(),
			kind: z.enum(["password", "factor", "all"]),
			dryRun: z.boolean().optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.object({
			dryRun: z.boolean(),
			result: z.union([unlockPreviewSchema, unlockResultSchema]),
		}).strict(),
	},
	"config.get": {
		input: z.object({ key: z.string().optional() }).strict(),
		output: publicConfigSchema.extend({ scope: resourceScopeSchema }).strict(),
	},
	"config.set": {
		input: z.object({ key: z.string(), value: z.string(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			publicConfigSchema.extend({
				ok: z.literal(true),
				changed: z.boolean(),
				key: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
			publicConfigSchema.extend({
				dryRun: z.literal(true),
				changed: z.boolean(),
				key: z.string(),
				scope: resourceScopeSchema,
			}).strict(),
		]),
	},
	"config.validate": {
		input: z.object({ config: configRecordSchema.optional() }).strict(),
		output: publicConfigSchema.extend({
			ok: z.literal(true),
			source: z.enum(["current", "candidate"]),
			scope: resourceScopeSchema,
		}).strict(),
	},
	"config.diff": {
		input: z.object({ config: configRecordSchema }).strict(),
		output: z.object({
			added: z.array(z.string()),
			changed: z.array(z.string()),
			removed: z.array(z.string()),
			scope: resourceScopeSchema,
		}).strict(),
	},
} satisfies OperationSchemaDomain;
