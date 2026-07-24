import {
	BACKUP_OPERATIONS,
	ClearanceError,
	CONFIG_OPERATIONS,
	parseConfigJson,
	SCHEMA_OPERATIONS,
	UPGRADE_OPERATIONS,
	writeExportArtifact,
} from "@clearance/management";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { callManagementOperation } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	managementCallOptions,
	requireConfirmation,
	requireRemoteMutation,
} from "./shared.js";

type OperationsCommandPath =
	| CliPathOf<typeof BACKUP_OPERATIONS>
	| CliPathOf<typeof UPGRADE_OPERATIONS>
	| CliPathOf<typeof SCHEMA_OPERATIONS>
	| CliPathOf<typeof CONFIG_OPERATIONS>;

function configCandidate(path: unknown): Record<string, string> {
	let contents: string;
	try {
		contents = readFileSync(resolve(String(path)), "utf8");
	} catch {
		throw new ClearanceError({
			code: "CONFIG_FILE_UNREADABLE",
			message: "Config file could not be read.",
			stage: "config.parse",
			remediation: "Provide a readable JSON config file.",
		});
	}
	return parseConfigJson(contents);
}

export async function dispatchOperationsCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<OperationsCommandPath>): Promise<unknown> {
	switch (path) {
		case BACKUP_OPERATIONS.create.cliPath:
			if (opts.dir !== undefined) {
				throw error(
					"BACKUP_DIRECTORY_SERVER_MANAGED",
					"Backup storage is configured by the API deployment.",
					"Set CLEARANCE_BACKUP_DIR on the API and mount durable storage there.",
				);
			}
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "backups.create", {});
		case BACKUP_OPERATIONS.verify.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "backups.verify", { id: String(opts.id) });
		case BACKUP_OPERATIONS.restore.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(global, "BACKUP_RESTORE_CONFIRM_REQUIRED", "Backup restore");
			return callManagementOperation(session, "backups.restore", body({
				id: String(opts.id),
				target: opts.target,
			}) as { id: string; target?: string }, managementCallOptions(global));
		case UPGRADE_OPERATIONS.check.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "upgrades.check", {});
		case UPGRADE_OPERATIONS.plan.cliPath:
			return callManagementOperation(session, "upgrades.plan", body({
				target: opts.target,
				dir: opts.dir,
				current: opts.current,
				dryRun: global.dryRun,
			}) as Parameters<typeof callManagementOperation<"upgrades.plan">>[2], managementCallOptions(global));
		case UPGRADE_OPERATIONS.apply.cliPath:
			requireConfirmation(global, "UPGRADE_APPLY_CONFIRMATION_REQUIRED", "Upgrade apply");
			return callManagementOperation(session, "upgrades.apply", body({
				plan: opts.plan,
				dir: opts.dir,
				dryRun: global.dryRun,
			}) as Parameters<typeof callManagementOperation<"upgrades.apply">>[2], managementCallOptions(global));
		case UPGRADE_OPERATIONS.verify.cliPath:
			return callManagementOperation(session, "upgrades.verify", body({
				plan: opts.plan,
				dir: opts.dir,
				healthUrl: opts.healthUrl,
				dryRun: global.dryRun,
			}) as Parameters<typeof callManagementOperation<"upgrades.verify">>[2], managementCallOptions(global));
		case UPGRADE_OPERATIONS.rollback.cliPath:
			requireConfirmation(global, "UPGRADE_ROLLBACK_CONFIRMATION_REQUIRED", "Upgrade rollback");
			return callManagementOperation(
				session,
				"upgrades.rollback",
				body({
					plan: opts.plan,
					dir: opts.dir,
					dryRun: global.dryRun,
					restoreActive: opts.restoreActive,
					activeDatabaseConfirmation: opts.confirm,
					backupDir: opts.backupDir,
				}) as Parameters<typeof callManagementOperation<"upgrades.rollback">>[2],
				managementCallOptions(global),
			);
		case SCHEMA_OPERATIONS.status.cliPath:
			return callManagementOperation(session, "schema.status", {});
		case SCHEMA_OPERATIONS.generate.cliPath: {
			if (!opts.output) {
				throw error(
					"SCHEMA_GENERATE_OUTPUT_REQUIRED",
					"schema generate requires an explicit --output path.",
					"Provide --output <path> for the generated SQL artifact.",
				);
			}
			const result = await callManagementOperation(session, "schema.generate", {});
			const { sql, ...metadata } = result;
			if (typeof sql !== "string") {
				throw error(
					"SCHEMA_GENERATE_RESPONSE_INVALID",
					"The API did not return generated SQL.",
					"Upgrade the Clearance API and retry.",
				);
			}
			if (global.dryRun) return { ...metadata, dryRun: true };
			const outputPath = writeExportArtifact(String(opts.output), sql, Boolean(opts.force), {
				stage: "schema.generate",
				existsCode: "SCHEMA_GENERATE_EXISTS",
				writeFailedCode: "SCHEMA_GENERATE_WRITE_FAILED",
			});
			return { ...metadata, dryRun: false, outputPath };
		}
		case SCHEMA_OPERATIONS.migrate.cliPath:
			if (opts.local === true || opts.drainId !== undefined) {
				throw error(
					"SCHEMA_LOCAL_MIGRATION_DISPATCH_INVALID",
					"Local schema migration options cannot be sent to the management API.",
					"Run schema migrate --local from the one-shot migration container.",
				);
			}
			requireConfirmation(global, "SCHEMA_MIGRATE_CONFIRMATION_REQUIRED", "Schema migration");
			return callManagementOperation(session, "schema.migrate", {
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SCHEMA_OPERATIONS.credentialAuthorityStatus.cliPath:
			return callManagementOperation(session, "schema.credential-authority.status", {});
		case SCHEMA_OPERATIONS.credentialAuthorityArm.cliPath:
			requireConfirmation(
				global,
				"CREDENTIAL_AUTHORITY_ARM_CONFIRMATION_REQUIRED",
				"Credential authority arm",
			);
			return callManagementOperation(
				session,
				"schema.credential-authority.arm",
				{
					deploymentId: opts.deploymentId as string,
					expectedRuntimeCount: Number(opts.expectedRuntimes),
				},
				managementCallOptions(global),
			);
		case SCHEMA_OPERATIONS.credentialAuthorityDrain.cliPath:
			requireConfirmation(
				global,
				"CREDENTIAL_AUTHORITY_DRAIN_CONFIRMATION_REQUIRED",
				"Credential authority drain",
			);
			return callManagementOperation(
				session,
				"schema.credential-authority.drain",
				{
					deploymentId: opts.deploymentId as string,
					drainId: opts.drainId as string,
				},
				managementCallOptions(global),
			);
		case CONFIG_OPERATIONS.get.cliPath:
			return callManagementOperation(session, "config.get", body({
				key: args[0],
			}) as { key?: string });
		case CONFIG_OPERATIONS.set.cliPath:
			return callManagementOperation(session, "config.set", {
				key: String(args[0]),
				value: String(args[1]),
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case CONFIG_OPERATIONS.validate.cliPath: {
			const config = opts.file ? configCandidate(opts.file) : undefined;
			return callManagementOperation(session, "config.validate", body({ config }));
		}
		case CONFIG_OPERATIONS.diff.cliPath: {
			const config = configCandidate(opts.file);
			return callManagementOperation(session, "config.diff", { config });
		}
	}
}
