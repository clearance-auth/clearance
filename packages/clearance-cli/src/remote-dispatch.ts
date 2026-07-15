import type { Command } from "commander";
import {
	API_KEY_OPERATIONS,
	BACKUP_OPERATIONS,
	CONFIG_OPERATIONS,
	ENVIRONMENT_OPERATIONS,
	EVENT_OPERATIONS,
	IMPORT_OPERATIONS,
	MANAGEMENT_OPERATIONS,
	MEMBER_OPERATIONS,
	MIGRATION_OPERATIONS,
	ORGANIZATION_OPERATIONS,
	PROJECT_OPERATIONS,
	READINESS_OPERATIONS,
	ROLE_OPERATIONS,
	SCHEMA_OPERATIONS,
	SCIM_OPERATIONS,
	SESSION_OPERATIONS,
	SSO_OPERATIONS,
	SYSTEM_OPERATIONS,
	UPGRADE_OPERATIONS,
	USER_OPERATIONS,
} from "@clearance/management";
import type { ApiSession } from "./api-client.js";
import { dispatchAccessCommand } from "./dispatch/access.js";
import { dispatchCoreCommand } from "./dispatch/core.js";
import { dispatchEnterpriseCommand } from "./dispatch/enterprise.js";
import { dispatchEventCommand } from "./dispatch/events.js";
import { dispatchMigrationCommand } from "./dispatch/migrations.js";
import { dispatchOperationsCommand } from "./dispatch/operations.js";
import { dispatchOrganizationCommand } from "./dispatch/organizations.js";
import { error } from "./dispatch/shared.js";
import { dispatchUserCommand } from "./dispatch/users.js";
import type { GlobalOpts } from "./output.js";

export {
	EVENTS_TAIL_MAX_POLL_INTERVAL_MS,
	EVENTS_TAIL_MIN_POLL_INTERVAL_MS,
} from "./dispatch/events.js";

export const REMOTE_COMMANDS = new Set<string>(
	MANAGEMENT_OPERATIONS.map((operation) => operation.cliPath),
);

export type CommandExecution = "authentication" | "remote-api" | "unavailable";

export function classifyCommandPath(path: string): CommandExecution {
	if (path === "login" || path === "logout" || path === "whoami") return "authentication";
	if (REMOTE_COMMANDS.has(path)) return "remote-api";
	return "unavailable";
}

export function commandPath(command: Command): string {
	const names: string[] = [];
	let current: Command | null = command;
	while (current?.parent) {
		names.unshift(current.name());
		current = current.parent;
	}
	return names.join(" ");
}

export async function dispatchRemoteCommand(
	session: ApiSession,
	path: string,
	args: unknown[],
	opts: Record<string, unknown>,
	global: GlobalOpts,
): Promise<unknown> {
	switch (path) {
		case SYSTEM_OPERATIONS.init.cliPath:
		case SYSTEM_OPERATIONS.doctor.cliPath:
		case SYSTEM_OPERATIONS.dev.cliPath:
		case SYSTEM_OPERATIONS.overview.cliPath:
		case PROJECT_OPERATIONS.list.cliPath:
		case PROJECT_OPERATIONS.inspect.cliPath:
		case PROJECT_OPERATIONS.create.cliPath:
		case ENVIRONMENT_OPERATIONS.list.cliPath:
		case ENVIRONMENT_OPERATIONS.inspect.cliPath:
		case ENVIRONMENT_OPERATIONS.create.cliPath:
		case ENVIRONMENT_OPERATIONS.promote.cliPath:
			return dispatchCoreCommand({ session, path, args, opts, global });
		case USER_OPERATIONS.list.cliPath:
		case USER_OPERATIONS.inspect.cliPath:
		case USER_OPERATIONS.create.cliPath:
		case USER_OPERATIONS.update.cliPath:
		case USER_OPERATIONS.disable.cliPath:
		case USER_OPERATIONS.delete.cliPath:
		case USER_OPERATIONS.export.cliPath:
			return dispatchUserCommand({ session, path, args, opts, global });
		case ORGANIZATION_OPERATIONS.list.cliPath:
		case ORGANIZATION_OPERATIONS.inspect.cliPath:
		case ORGANIZATION_OPERATIONS.create.cliPath:
		case ORGANIZATION_OPERATIONS.update.cliPath:
		case ORGANIZATION_OPERATIONS.archive.cliPath:
		case MEMBER_OPERATIONS.list.cliPath:
		case MEMBER_OPERATIONS.add.cliPath:
		case MEMBER_OPERATIONS.update.cliPath:
		case MEMBER_OPERATIONS.remove.cliPath:
		case MEMBER_OPERATIONS.import.cliPath:
			return dispatchOrganizationCommand({ session, path, args, opts, global });
		case EVENT_OPERATIONS.list.cliPath:
		case EVENT_OPERATIONS.tail.cliPath:
		case EVENT_OPERATIONS.inspect.cliPath:
		case EVENT_OPERATIONS.export.cliPath:
		case EVENT_OPERATIONS.replay.cliPath:
			return dispatchEventCommand({ session, path, args, opts, global });
		case API_KEY_OPERATIONS.list.cliPath:
		case API_KEY_OPERATIONS.create.cliPath:
		case API_KEY_OPERATIONS.rotate.cliPath:
		case API_KEY_OPERATIONS.revoke.cliPath:
		case SESSION_OPERATIONS.list.cliPath:
		case SESSION_OPERATIONS.revoke.cliPath:
		case ROLE_OPERATIONS.list.cliPath:
		case ROLE_OPERATIONS.validate.cliPath:
		case ROLE_OPERATIONS.create.cliPath:
		case ROLE_OPERATIONS.update.cliPath:
			return dispatchAccessCommand({ session, path, args, opts, global });
		case SSO_OPERATIONS.create.cliPath:
		case SSO_OPERATIONS.configure.cliPath:
		case SSO_OPERATIONS.test.cliPath:
		case SSO_OPERATIONS.list.cliPath:
		case SSO_OPERATIONS.setupLink.cliPath:
		case SSO_OPERATIONS.rotate.cliPath:
		case SSO_OPERATIONS.disable.cliPath:
		case SCIM_OPERATIONS.create.cliPath:
		case SCIM_OPERATIONS.test.cliPath:
		case SCIM_OPERATIONS.list.cliPath:
		case SCIM_OPERATIONS.setupLink.cliPath:
		case SCIM_OPERATIONS.rotate.cliPath:
		case SCIM_OPERATIONS.disable.cliPath:
		case SCIM_OPERATIONS.replay.cliPath:
		case READINESS_OPERATIONS.check.cliPath:
		case READINESS_OPERATIONS.report.cliPath:
			return dispatchEnterpriseCommand({ session, path, args, opts, global });
		case IMPORT_OPERATIONS.legacy.cliPath:
		case MIGRATION_OPERATIONS.plan.cliPath:
		case MIGRATION_OPERATIONS.run.cliPath:
		case MIGRATION_OPERATIONS.verify.cliPath:
		case MIGRATION_OPERATIONS.rollback.cliPath:
		case MIGRATION_OPERATIONS.status.cliPath:
			return dispatchMigrationCommand({ session, path, args, opts, global });
		case BACKUP_OPERATIONS.create.cliPath:
		case BACKUP_OPERATIONS.verify.cliPath:
		case BACKUP_OPERATIONS.restore.cliPath:
		case UPGRADE_OPERATIONS.check.cliPath:
		case UPGRADE_OPERATIONS.plan.cliPath:
		case UPGRADE_OPERATIONS.apply.cliPath:
		case UPGRADE_OPERATIONS.verify.cliPath:
		case UPGRADE_OPERATIONS.rollback.cliPath:
		case SCHEMA_OPERATIONS.status.cliPath:
		case SCHEMA_OPERATIONS.generate.cliPath:
		case SCHEMA_OPERATIONS.migrate.cliPath:
		case CONFIG_OPERATIONS.get.cliPath:
		case CONFIG_OPERATIONS.set.cliPath:
		case CONFIG_OPERATIONS.validate.cliPath:
		case CONFIG_OPERATIONS.diff.cliPath:
			return dispatchOperationsCommand({ session, path, args, opts, global });
		default:
			throw error(
				"CLI_REMOTE_COMMAND_UNAVAILABLE",
				`${path} has no versioned management API contract in this release.`,
				"Upgrade the Clearance API to a version that exposes this workflow.",
			);
	}
}
