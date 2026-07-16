import {
	BACKUP_OPERATIONS,
	ClearanceError,
	CONFIG_OPERATIONS,
	parseConfigJson,
	resolveOperationPath,
	SCHEMA_OPERATIONS,
	UPGRADE_OPERATIONS,
	writeExportArtifact,
} from "@clearance/management";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { requestManagementApi } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	query,
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
			return requestManagementApi(session, {
				method: BACKUP_OPERATIONS.create.http.method,
				path: BACKUP_OPERATIONS.create.http.path,
				body: {},
			});
		case BACKUP_OPERATIONS.verify.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: BACKUP_OPERATIONS.verify.http.method,
				path: resolveOperationPath(BACKUP_OPERATIONS.verify, { id: String(opts.id) }),
				body: {},
			});
		case BACKUP_OPERATIONS.restore.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(global, "BACKUP_RESTORE_CONFIRM_REQUIRED", "Backup restore");
			return requestManagementApi(session, {
				method: BACKUP_OPERATIONS.restore.http.method,
				path: resolveOperationPath(BACKUP_OPERATIONS.restore, { id: String(opts.id) }),
				body: { target: opts.target, confirm: global.yes && !global.dryRun },
			});
		case UPGRADE_OPERATIONS.check.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: UPGRADE_OPERATIONS.check.http.method,
				path: UPGRADE_OPERATIONS.check.http.path,
			});
		case UPGRADE_OPERATIONS.plan.cliPath:
			return requestManagementApi(session, {
				method: UPGRADE_OPERATIONS.plan.http.method,
				path: UPGRADE_OPERATIONS.plan.http.path,
				body: body({ target: opts.target, dir: opts.dir, current: opts.current, dryRun: global.dryRun }),
			});
		case UPGRADE_OPERATIONS.apply.cliPath:
			requireConfirmation(global, "UPGRADE_APPLY_CONFIRMATION_REQUIRED", "Upgrade apply");
			return requestManagementApi(session, {
				method: UPGRADE_OPERATIONS.apply.http.method,
				path: UPGRADE_OPERATIONS.apply.http.path,
				body: { plan: opts.plan, dir: opts.dir, dryRun: global.dryRun, confirm: global.yes && !global.dryRun },
			});
		case UPGRADE_OPERATIONS.verify.cliPath:
			return requestManagementApi(session, {
				method: UPGRADE_OPERATIONS.verify.http.method,
				path: UPGRADE_OPERATIONS.verify.http.path,
				body: body({ plan: opts.plan, dir: opts.dir, healthUrl: opts.healthUrl, dryRun: global.dryRun }),
			});
		case UPGRADE_OPERATIONS.rollback.cliPath:
			requireConfirmation(global, "UPGRADE_ROLLBACK_CONFIRMATION_REQUIRED", "Upgrade rollback");
			return requestManagementApi(session, {
				method: UPGRADE_OPERATIONS.rollback.http.method,
				path: UPGRADE_OPERATIONS.rollback.http.path,
				body: body({
					plan: opts.plan,
					dir: opts.dir,
					dryRun: global.dryRun,
					confirm: global.yes && !global.dryRun,
					restoreActive: opts.restoreActive,
					activeDatabaseConfirmation: opts.confirm,
					backupDir: opts.backupDir,
				}),
			});
		case SCHEMA_OPERATIONS.status.cliPath:
			return requestManagementApi(session, {
				method: SCHEMA_OPERATIONS.status.http.method,
				path: SCHEMA_OPERATIONS.status.http.path,
			});
		case SCHEMA_OPERATIONS.generate.cliPath: {
			if (!opts.output) {
				throw error(
					"SCHEMA_GENERATE_OUTPUT_REQUIRED",
					"schema generate requires an explicit --output path.",
					"Provide --output <path> for the generated SQL artifact.",
				);
			}
			const result = await requestManagementApi<Record<string, unknown>>(session, {
				method: SCHEMA_OPERATIONS.generate.http.method,
				path: SCHEMA_OPERATIONS.generate.http.path,
				body: {},
			});
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
			return requestManagementApi(session, {
				method: SCHEMA_OPERATIONS.migrate.http.method,
				path: SCHEMA_OPERATIONS.migrate.http.path,
				body: { dryRun: global.dryRun, confirm: global.yes && !global.dryRun },
			});
		case SCHEMA_OPERATIONS.credentialAuthorityStatus.cliPath:
			return requestManagementApi(session, {
				method: SCHEMA_OPERATIONS.credentialAuthorityStatus.http.method,
				path: SCHEMA_OPERATIONS.credentialAuthorityStatus.http.path,
			});
		case SCHEMA_OPERATIONS.credentialAuthorityArm.cliPath:
			requireConfirmation(
				global,
				"CREDENTIAL_AUTHORITY_ARM_CONFIRMATION_REQUIRED",
				"Credential authority arm",
			);
			return requestManagementApi(session, {
				method: SCHEMA_OPERATIONS.credentialAuthorityArm.http.method,
				path: SCHEMA_OPERATIONS.credentialAuthorityArm.http.path,
				body: {
					deploymentId: opts.deploymentId,
					expectedRuntimeCount: Number(opts.expectedRuntimes),
					confirm: global.yes,
				},
			});
		case SCHEMA_OPERATIONS.credentialAuthorityDrain.cliPath:
			requireConfirmation(
				global,
				"CREDENTIAL_AUTHORITY_DRAIN_CONFIRMATION_REQUIRED",
				"Credential authority drain",
			);
			return requestManagementApi(session, {
				method: SCHEMA_OPERATIONS.credentialAuthorityDrain.http.method,
				path: SCHEMA_OPERATIONS.credentialAuthorityDrain.http.path,
				body: {
					deploymentId: opts.deploymentId,
					drainId: opts.drainId,
					confirm: global.yes,
				},
			});
		case CONFIG_OPERATIONS.get.cliPath:
			return requestManagementApi(session, {
				method: CONFIG_OPERATIONS.get.http.method,
				path: query(CONFIG_OPERATIONS.get.http.path, { key: args[0] }),
			});
		case CONFIG_OPERATIONS.set.cliPath:
			return requestManagementApi(session, {
				method: CONFIG_OPERATIONS.set.http.method,
				path: resolveOperationPath(CONFIG_OPERATIONS.set, { key: String(args[0]) }),
				body: { value: args[1], dryRun: global.dryRun },
			});
		case CONFIG_OPERATIONS.validate.cliPath: {
			const config = opts.file ? configCandidate(opts.file) : undefined;
			return requestManagementApi(session, {
				method: CONFIG_OPERATIONS.validate.http.method,
				path: CONFIG_OPERATIONS.validate.http.path,
				body: body({ config }),
			});
		}
		case CONFIG_OPERATIONS.diff.cliPath: {
			const config = configCandidate(opts.file);
			return requestManagementApi(session, {
				method: CONFIG_OPERATIONS.diff.http.method,
				path: CONFIG_OPERATIONS.diff.http.path,
				body: { config },
			});
		}
	}
}
