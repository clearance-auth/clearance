import {
	IMPORT_OPERATIONS,
	MIGRATION_OPERATIONS,
} from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import {
	type CliPathOf,
	type DispatchInput,
	localFile,
	managementCallOptions,
	requireConfirmation,
	requireRemoteMutation,
} from "./shared.js";

type MigrationCommandPath =
	| CliPathOf<typeof IMPORT_OPERATIONS>
	| CliPathOf<typeof MIGRATION_OPERATIONS>;

export async function dispatchMigrationCommand({
	session,
	path,
	opts,
	global,
}: DispatchInput<MigrationCommandPath>): Promise<unknown> {
	switch (path) {
		case IMPORT_OPERATIONS.legacy.cliPath:
			requireConfirmation(global, "CLEARANCE_IMPORT_CONFIRMATION_REQUIRED", "Legacy import");
			return callManagementOperation(
				session,
				"imports.legacy",
				{
					fixture: localFile(opts.file, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Legacy import file"),
					dryRun: Boolean(global.dryRun),
				},
				managementCallOptions(global),
			);
		case MIGRATION_OPERATIONS.plan.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "migrations.plan", {
					source: opts.source as "legacy",
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
			});
		case MIGRATION_OPERATIONS.apply.cliPath:
			return callManagementOperation(session, "migrations.apply", {
					id: String(opts.id),
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
					dryRun: global.dryRun,
			}, managementCallOptions(global));
		case MIGRATION_OPERATIONS.verify.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "migrations.verify", {
					id: String(opts.id),
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
			});
		case MIGRATION_OPERATIONS.rollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(global, "MIGRATION_ROLLBACK_CONFIRM_REQUIRED", "Migration rollback");
			return callManagementOperation(
				session,
				"migrations.rollback",
				{
					id: String(opts.id),
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
				},
				managementCallOptions(global),
			);
		case MIGRATION_OPERATIONS.status.cliPath:
			return callManagementOperation(session, "migrations.status", { id: String(opts.id) });
	}
}
