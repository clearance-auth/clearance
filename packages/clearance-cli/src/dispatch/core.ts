import {
	ENVIRONMENT_OPERATIONS,
	PROJECT_OPERATIONS,
	resolveOperationPath,
	SYSTEM_OPERATIONS,
} from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	firstStringArgument,
	previewConfirmation,
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
			return requestManagementApi(session, {
				method: SYSTEM_OPERATIONS.init.http.method,
				path: SYSTEM_OPERATIONS.init.http.path,
				body: body({ name: opts.name, environment: opts.environment }),
			});
		case SYSTEM_OPERATIONS.doctor.cliPath:
			return requestManagementApi(session, {
				method: SYSTEM_OPERATIONS.doctor.http.method,
				path: SYSTEM_OPERATIONS.doctor.http.path,
			});
		case SYSTEM_OPERATIONS.dev.cliPath:
			return requestManagementApi(session, {
				method: SYSTEM_OPERATIONS.dev.http.method,
				path: SYSTEM_OPERATIONS.dev.http.path,
			});
		case SYSTEM_OPERATIONS.overview.cliPath:
			return requestManagementApi(session, {
				method: SYSTEM_OPERATIONS.overview.http.method,
				path: SYSTEM_OPERATIONS.overview.http.path,
			});
		case PROJECT_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: PROJECT_OPERATIONS.list.http.method,
				path: PROJECT_OPERATIONS.list.http.path,
			});
		case PROJECT_OPERATIONS.inspect.cliPath:
			return requestManagementApi(session, {
				method: PROJECT_OPERATIONS.inspect.http.method,
				path: rawId
					? resolveOperationPath(PROJECT_OPERATIONS.inspect, { id: rawId })
					: PROJECT_OPERATIONS.inspect.http.currentPath,
			});
		case PROJECT_OPERATIONS.create.cliPath:
			return requestManagementApi(session, {
				method: PROJECT_OPERATIONS.create.http.method,
				path: PROJECT_OPERATIONS.create.http.path,
				body: { name: opts.name, dryRun: global.dryRun },
			});
		case ENVIRONMENT_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: ENVIRONMENT_OPERATIONS.list.http.method,
				path: ENVIRONMENT_OPERATIONS.list.http.path,
			});
		case ENVIRONMENT_OPERATIONS.inspect.cliPath:
			return requestManagementApi(session, {
				method: ENVIRONMENT_OPERATIONS.inspect.http.method,
				path: rawId
					? resolveOperationPath(ENVIRONMENT_OPERATIONS.inspect, { id: rawId })
					: ENVIRONMENT_OPERATIONS.inspect.http.currentPath,
			});
		case ENVIRONMENT_OPERATIONS.create.cliPath:
			return requestManagementApi(session, {
				method: ENVIRONMENT_OPERATIONS.create.http.method,
				path: ENVIRONMENT_OPERATIONS.create.http.path,
				body: body({ name: opts.name, projectId: opts.projectId, kind: opts.kind, dryRun: global.dryRun }),
			});
		case ENVIRONMENT_OPERATIONS.promote.cliPath:
			return requestManagementApi(session, {
				method: ENVIRONMENT_OPERATIONS.promote.http.method,
				path: ENVIRONMENT_OPERATIONS.promote.http.path,
				body: body({
					to: opts.to,
					from: opts.from,
					...previewConfirmation(global),
				}),
			});
	}
}
