import { resolveOperationPath, USER_OPERATIONS } from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import { writeRemoteExport } from "./export-artifact.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	firstStringArgument,
	query,
	requireConfirmation,
	requireRemoteMutation,
} from "./shared.js";

type UserCommandPath = CliPathOf<typeof USER_OPERATIONS>;

export async function dispatchUserCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<UserCommandPath>): Promise<unknown> {
	const rawId = firstStringArgument(args);
	switch (path) {
		case USER_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: USER_OPERATIONS.list.http.method,
				path: query(USER_OPERATIONS.list.http.path, { limit: opts.limit, cursor: opts.cursor }),
			});
		case USER_OPERATIONS.inspect.cliPath:
			return requestManagementApi(session, {
				method: USER_OPERATIONS.inspect.http.method,
				path: resolveOperationPath(USER_OPERATIONS.inspect, { id: rawId }),
			});
		case USER_OPERATIONS.create.cliPath:
			return requestManagementApi(session, {
				method: USER_OPERATIONS.create.http.method,
				path: USER_OPERATIONS.create.http.path,
				body: body({ email: opts.email, name: opts.name, password: opts.password, dryRun: global.dryRun }),
			});
		case USER_OPERATIONS.update.cliPath:
			return requestManagementApi(session, {
				method: USER_OPERATIONS.update.http.method,
				path: resolveOperationPath(USER_OPERATIONS.update, { id: rawId }),
				body: body({ email: opts.email, name: opts.name, status: opts.status, dryRun: global.dryRun }),
			});
		case USER_OPERATIONS.disable.cliPath:
			return requestManagementApi(session, {
				method: USER_OPERATIONS.disable.http.method,
				path: resolveOperationPath(USER_OPERATIONS.disable, { id: rawId }),
				body: { dryRun: global.dryRun },
			});
		case USER_OPERATIONS.delete.cliPath:
			requireConfirmation(global, "USER_DELETE_CONFIRM_REQUIRED", "User deletion");
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: USER_OPERATIONS.delete.http.method,
				path: resolveOperationPath(USER_OPERATIONS.delete, { id: rawId }),
			});
		case USER_OPERATIONS.export.cliPath: {
			const envelope = await requestManagementApi<Record<string, unknown>>(session, {
				method: USER_OPERATIONS.export.http.method,
				path: USER_OPERATIONS.export.http.path,
				body: body({ format: opts.format, limit: opts.limit, status: opts.status }),
			});
			return writeRemoteExport(envelope, opts, "users");
		}
	}
}
