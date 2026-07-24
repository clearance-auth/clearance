import * as z from "zod";
import type { OperationSchemaDomain } from "./assemble.js";

const countSchema = z.record(z.string(), z.number());

const legacyFixtureInputSchema = z.string();

const migrationPreviewSchema = z.object({
	source: z.literal("legacy"),
	fixtureChecksum: z.string(),
	counts: z.object({ users: z.number(), organizations: z.number(), members: z.number() }).strict(),
	wouldCreate: z.object({ users: z.number(), organizations: z.number(), members: z.number() }).strict(),
	idempotent: z.object({ users: z.number(), organizations: z.number(), members: z.number() }).strict(),
}).strict();

const migrationResourceIdsSchema = z.object({
	users: z.array(z.string()),
	organizations: z.array(z.string()),
	memberships: z.array(z.string()),
}).strict();

const migrationPlanSchema = z.object({
	id: z.string(),
	source: z.literal("legacy"),
	projectId: z.string(),
	environmentId: z.string(),
	status: z.enum(["planned", "running", "verified", "rolled_back", "failed"]),
	counts: countSchema,
	fixtureChecksum: z.string(),
	checkpoint: z.object({
		phase: z.enum(["planned", "dry_run", "imported", "verified", "failed", "rolled_back"]),
		source: z.literal("legacy"),
		fixtureChecksum: z.string(),
		counts: countSchema,
		wouldCreate: countSchema,
		idempotent: countSchema,
	}).strict(),
	createdResourceIds: migrationResourceIdsSchema.optional(),
	createdRuntimeResourceIds: migrationResourceIdsSchema.optional(),
	rollbackResourceState: z.object({
		management: z.object({
			users: z.array(z.object({
				id: z.string(), projectId: z.string(), environmentId: z.string(), email: z.string(), name: z.string(),
				status: z.enum(["active", "disabled", "deleted"]), externalId: z.string().optional(), createdAt: z.string(), updatedAt: z.string(),
			}).strict()),
			organizations: z.array(z.object({
				id: z.string(), projectId: z.string(), environmentId: z.string(), name: z.string(), slug: z.string(),
				status: z.enum(["active", "archived"]), externalId: z.string().optional(), createdAt: z.string(), updatedAt: z.string(),
			}).strict()),
			memberships: z.array(z.object({
				id: z.string(), organizationId: z.string(), principalId: z.string(), role: z.string(),
				status: z.enum(["active", "invited", "removed"]), source: z.enum(["manual", "scim", "sso", "import"]),
				createdAt: z.string(), updatedAt: z.string(),
			}).strict()),
		}).strict(),
		runtime: z.object({
			users: z.array(z.object({
				id: z.string(), email: z.string(), name: z.string(), emailVerified: z.boolean(), image: z.string().nullable(),
				banned: z.boolean(), banReason: z.string().nullable(), createdAt: z.string(), updatedAt: z.string(),
			}).strict()),
			organizations: z.array(z.object({
				id: z.string(), name: z.string(), slug: z.string(), logo: z.string().nullable(), metadata: z.string().nullable(), createdAt: z.string(),
			}).strict()),
			memberships: z.array(z.object({ id: z.string(), organizationId: z.string(), principalId: z.string(), role: z.string(), createdAt: z.string() }).strict()),
		}).strict(),
	}).strict().optional(),
	steps: z.array(z.object({
		name: z.string(),
		status: z.enum(["pending", "done", "failed", "skipped"]),
		detail: z.string().optional(),
	}).strict()),
	createdAt: z.string(),
	updatedAt: z.string(),
}).strict();

const migrationVerificationSchema = z.object({
	plan: migrationPlanSchema,
	reconciled: z.boolean(),
	actual: countSchema,
	expected: countSchema,
}).strict();

const backupSchema = z.object({
	id: z.string(),
	path: z.string(),
	createdAt: z.string(),
	checksum: z.string(),
	resourceCounts: countSchema,
	verified: z.boolean(),
}).strict();

const upgradePlanSummarySchema = z.object({
	id: z.string(),
	targetVersion: z.string(),
	status: z.string(),
}).strict();

const upgradeCheckSchema = z.object({
	current: z.string(),
	latest: z.string(),
	runtimeBaseline: z.string(),
	action: z.enum(["none", "upgrade_available", "plan_required"]),
	notes: z.array(z.string()),
}).strict();

const upgradePlanDryRunSchema = z.object({
	schemaVersion: z.literal("v1"),
	operation: z.literal("upgrade.plan"),
	dryRun: z.literal(true),
	plan: z.object({
		targetVersion: z.string(),
		currentVersion: z.string().nullable(),
		directory: z.string(),
		createsArtifacts: z.literal(false),
	}).strict(),
}).strict();

const upgradePlanResultSchema = z.object({
	schemaVersion: z.literal("v1"),
	operation: z.literal("upgrade.plan"),
	dryRun: z.literal(false),
	plan: z.object({
		id: z.string(),
		path: z.string(),
		currentVersion: z.string(),
		targetVersion: z.string(),
		status: z.string(),
	}).strict(),
}).strict();

const upgradeApplyDryRunSchema = z.object({
	schemaVersion: z.literal("v1"),
	operation: z.literal("upgrade.apply"),
	dryRun: z.literal(true),
	plan: z.object({
		id: z.string(),
		path: z.string(),
		currentVersion: z.string(),
		targetVersion: z.string(),
		status: z.string(),
	}).strict(),
	wouldRun: z.tuple([z.literal("preflight"), z.literal("verified_backup"), z.literal("version_hook")]),
}).strict();

const upgradeAppliedPlanSchema = upgradePlanSummarySchema.extend({
	backupId: z.string().nullable(),
	rollbackReference: z.json().nullable(),
}).strict();

const upgradeRollbackDryRunSchema = z.discriminatedUnion("mode", [
	z.object({
		schemaVersion: z.literal("v1"), operation: z.literal("upgrade.rollback"), dryRun: z.literal(true),
		mode: z.literal("isolated_verify_only"), activeDatabaseUntouched: z.literal(true), wouldModifyActiveDatabase: z.literal(false),
		plan: upgradePlanSummarySchema,
		wouldRun: z.tuple([z.literal("backup_checksum_check"), z.literal("isolated_restore"), z.literal("reconciliation"), z.literal("rollback_receipt")]),
	}).strict(),
	z.object({
		schemaVersion: z.literal("v1"), operation: z.literal("upgrade.rollback"), dryRun: z.literal(true),
		mode: z.literal("active_database_restore"), activeDatabaseUntouched: z.literal(true), wouldModifyActiveDatabase: z.literal(true),
		plan: upgradePlanSummarySchema,
		wouldRun: z.tuple([z.literal("advisory_lock"), z.literal("safety_backup"), z.literal("staging_restore"), z.literal("database_swap"), z.literal("live_verification"), z.literal("rollback_receipt")]),
	}).strict(),
]);

export const DATA_OPERATION_SCHEMAS = {
	"imports.legacy": {
		input: z.object({ fixture: legacyFixtureInputSchema, dryRun: z.boolean().optional(), confirm: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({ schemaVersion: z.literal("v1"), dryRun: z.literal(true), source: z.literal("legacy"), preview: migrationPreviewSchema, storeBackend: z.string() }).strict(),
			z.object({
				schemaVersion: z.literal("v1"), dryRun: z.literal(false), source: z.literal("legacy"), migration: migrationPlanSchema,
				preview: migrationPreviewSchema,
				verification: z.object({ reconciled: z.boolean(), expected: countSchema, actual: countSchema }).strict(),
				storeBackend: z.string(),
			}).strict(),
		]),
	},
	"migrations.plan": {
		input: z.object({ source: z.literal("legacy"), fixture: legacyFixtureInputSchema }).strict(),
		output: z.object({ plan: migrationPlanSchema }).strict(),
	},
	"migrations.run": {
		input: z.object({ id: z.string(), fixture: legacyFixtureInputSchema, dryRun: z.boolean().optional() }).strict(),
		output: z.object({ plan: migrationPlanSchema }).strict(),
	},
	"migrations.verify": {
		input: z.object({ id: z.string(), fixture: legacyFixtureInputSchema }).strict(),
		output: migrationVerificationSchema,
	},
	"migrations.rollback": {
		input: z.object({ id: z.string(), fixture: legacyFixtureInputSchema, confirm: z.boolean().optional() }).strict(),
		output: z.object({ plan: migrationPlanSchema }).strict(),
	},
	"migrations.status": {
		input: z.object({ id: z.string() }).strict(),
		output: z.object({ plan: migrationPlanSchema }).strict(),
	},
	"backups.create": {
		input: z.object({}).strict(),
		output: z.object({ backup: backupSchema }).strict(),
	},
	"backups.verify": {
		input: z.object({ id: z.string() }).strict(),
		output: z.object({ backup: backupSchema }).strict(),
	},
	"backups.restore": {
		input: z.object({
			id: z.string(),
			target: z.templateLiteral(["clearance_restore_", z.string()])
				.refine((value) => /^clearance_restore_[a-z0-9_]{0,45}$/.test(value), "Invalid isolated restore database name.")
				.optional(),
			confirm: z.boolean().optional(),
		}).strict(),
		output: z.union([
			z.object({ targetPath: z.string(), counts: countSchema, checksum: z.string() }).strict(),
			z.object({ database: z.string(), checksum: z.string(), verified: z.literal(true), retained: z.boolean() }).strict(),
		]),
	},
	"upgrades.check": {
		input: z.object({}).strict(),
		output: z.union([
			upgradeCheckSchema,
			upgradeCheckSchema.extend({ authTableCounts: countSchema }).strict(),
		]),
	},
	"upgrades.plan": {
		input: z.object({ target: z.string(), dir: z.string(), current: z.string().optional(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([upgradePlanDryRunSchema, upgradePlanResultSchema]),
	},
	"upgrades.apply": {
		input: z.object({ plan: z.string(), dir: z.string(), dryRun: z.boolean().optional(), confirm: z.boolean().optional() }).strict(),
		output: z.union([
			upgradeApplyDryRunSchema,
			z.object({ schemaVersion: z.literal("v1"), operation: z.literal("upgrade.apply"), dryRun: z.literal(false), plan: upgradeAppliedPlanSchema }).strict(),
		]),
	},
	"upgrades.verify": {
		input: z.object({ plan: z.string(), dir: z.string(), healthUrl: z.string().optional(), dryRun: z.boolean().optional() }).strict(),
		output: z.union([
			z.object({
				schemaVersion: z.literal("v1"), operation: z.literal("upgrade.verify"), dryRun: z.literal(true), plan: upgradePlanSummarySchema,
				wouldRun: z.array(z.enum(["backup_reference_check", "apply_marker_check", "health_url_check"])),
			}).strict(),
			z.object({
				schemaVersion: z.literal("v1"), operation: z.literal("upgrade.verify"),
				plan: upgradePlanSummarySchema.extend({ updatedAt: z.string().nullable(), backupId: z.string().nullable() }).strict(),
			}).strict(),
		]),
	},
	"upgrades.rollback": {
		input: z.object({
			plan: z.string(), dir: z.string(), dryRun: z.boolean().optional(), confirm: z.boolean().optional(),
			restoreActive: z.boolean().optional(), activeDatabaseConfirmation: z.string().optional(), backupDir: z.string().optional(),
		}).strict(),
		output: z.union([
			upgradeRollbackDryRunSchema,
			z.object({
				schemaVersion: z.literal("v1"), operation: z.literal("upgrade.rollback"), dryRun: z.literal(false),
				mode: z.enum(["isolated_verify_only", "active_database_restore"]), activeDatabaseUntouched: z.boolean(),
				plan: upgradePlanSummarySchema, rollbackReceipt: z.string(), receipt: z.record(z.string(), z.json()),
			}).strict(),
		]),
	},
} satisfies OperationSchemaDomain;
