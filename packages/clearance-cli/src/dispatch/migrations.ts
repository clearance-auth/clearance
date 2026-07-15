import {
	IMPORT_OPERATIONS,
	MIGRATION_OPERATIONS,
	resolveOperationPath,
} from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	type CliPathOf,
	type DispatchInput,
	localFile,
	previewConfirmation,
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
			return requestManagementApi(session, {
				method: IMPORT_OPERATIONS.legacy.http.method,
				path: IMPORT_OPERATIONS.legacy.http.path,
				body: {
					fixture: localFile(opts.file, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Legacy import file"),
					...previewConfirmation(global),
				},
			});
		case MIGRATION_OPERATIONS.plan.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: MIGRATION_OPERATIONS.plan.http.method,
				path: MIGRATION_OPERATIONS.plan.http.path,
				body: {
					source: opts.source,
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
				},
			});
		case MIGRATION_OPERATIONS.run.cliPath:
			return requestManagementApi(session, {
				method: MIGRATION_OPERATIONS.run.http.method,
				path: resolveOperationPath(MIGRATION_OPERATIONS.run, { id: String(opts.id) }),
				body: {
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
					dryRun: global.dryRun,
				},
			});
		case MIGRATION_OPERATIONS.verify.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: MIGRATION_OPERATIONS.verify.http.method,
				path: resolveOperationPath(MIGRATION_OPERATIONS.verify, { id: String(opts.id) }),
				body: {
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
				},
			});
		case MIGRATION_OPERATIONS.rollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(global, "MIGRATION_ROLLBACK_CONFIRM_REQUIRED", "Migration rollback");
			return requestManagementApi(session, {
				method: MIGRATION_OPERATIONS.rollback.http.method,
				path: resolveOperationPath(MIGRATION_OPERATIONS.rollback, { id: String(opts.id) }),
				body: {
					fixture: localFile(opts.fixture, "CLEARANCE_IMPORT_FILE_UNREADABLE", "Migration fixture"),
					confirm: global.yes && !global.dryRun,
				},
			});
		case MIGRATION_OPERATIONS.status.cliPath:
			return requestManagementApi(session, {
				method: MIGRATION_OPERATIONS.status.http.method,
				path: resolveOperationPath(MIGRATION_OPERATIONS.status, { id: String(opts.id) }),
			});
	}
}
