import {
	ENVIRONMENT_OPERATIONS,
	PROJECT_OPERATIONS,
	SYSTEM_OPERATIONS,
} from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	firstStringArgument,
	managementCallOptions,
	requireRemoteMutation,
} from "./shared.js";

type CoreCommandPath =
	| CliPathOf<typeof SYSTEM_OPERATIONS>
	| CliPathOf<typeof PROJECT_OPERATIONS>
	| CliPathOf<typeof ENVIRONMENT_OPERATIONS>;

export async function dispatchCoreCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<CoreCommandPath>): Promise<unknown> {
	const rawId = firstStringArgument(args);
	switch (path) {
		case SYSTEM_OPERATIONS.init.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "system.init", body({
				name: opts.name,
				environment: opts.environment,
			}) as { name: string; environment?: string });
		case SYSTEM_OPERATIONS.doctor.cliPath:
			return callManagementOperation(session, "system.doctor", {});
		case SYSTEM_OPERATIONS.dev.cliPath:
			return callManagementOperation(session, "system.dev", {});
		case SYSTEM_OPERATIONS.overview.cliPath:
			return callManagementOperation(session, "system.overview", {});
		case PROJECT_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "projects.list", {});
		case PROJECT_OPERATIONS.inspect.cliPath:
			return callManagementOperation(session, "projects.inspect", rawId ? { id: rawId } : {});
		case PROJECT_OPERATIONS.create.cliPath:
			return callManagementOperation(
				session,
				"projects.create",
				{ name: String(opts.name), dryRun: global.dryRun },
				managementCallOptions(global),
			);
		case ENVIRONMENT_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "environments.list", {});
		case ENVIRONMENT_OPERATIONS.inspect.cliPath:
			return callManagementOperation(session, "environments.inspect", rawId ? { id: rawId } : {});
		case ENVIRONMENT_OPERATIONS.create.cliPath:
			return callManagementOperation(
				session,
				"environments.create",
				body({
					name: opts.name,
					projectId: opts.projectId,
					kind: opts.kind,
					dryRun: global.dryRun,
				}) as {
					name: string;
					projectId?: string;
					kind?: "production" | "development" | "preview";
					dryRun?: boolean;
				},
				managementCallOptions(global),
			);
		case ENVIRONMENT_OPERATIONS.promote.cliPath:
			return callManagementOperation(
				session,
				"environments.promote",
				body({
					to: opts.to,
					from: opts.from,
					dryRun: global.dryRun || !global.yes,
				}) as { to: string; from?: string; dryRun?: boolean },
				managementCallOptions(global),
			);
	}
}
