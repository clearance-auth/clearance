import { USER_OPERATIONS } from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import { writeRemoteExport } from "./export-artifact.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	firstStringArgument,
	managementCallOptions,
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
			return callManagementOperation(session, "users.list", body({
				limit: opts.limit === undefined ? undefined : Number(opts.limit),
				cursor: opts.cursor,
			}));
		case USER_OPERATIONS.inspect.cliPath:
			return callManagementOperation(session, "users.inspect", { id: rawId });
		case USER_OPERATIONS.create.cliPath:
			return callManagementOperation(session, "users.create", body({
				email: opts.email,
				name: opts.name,
				password: opts.password,
				dryRun: global.dryRun,
			}) as { email: string; name: string; password?: string; dryRun?: boolean }, managementCallOptions(global));
		case USER_OPERATIONS.update.cliPath:
			return callManagementOperation(session, "users.update", body({
				id: rawId,
				email: opts.email,
				name: opts.name,
				status: opts.status,
				dryRun: global.dryRun,
			}) as { id: string; email?: string; name?: string; status?: "active" | "disabled"; dryRun?: boolean }, managementCallOptions(global));
		case USER_OPERATIONS.disable.cliPath:
			return callManagementOperation(session, "users.disable", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case USER_OPERATIONS.delete.cliPath:
			requireConfirmation(global, "USER_DELETE_CONFIRM_REQUIRED", "User deletion");
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "users.delete", { id: rawId }, managementCallOptions(global));
		case USER_OPERATIONS.export.cliPath: {
			const envelope = await callManagementOperation(session, "users.export", body({
				format: opts.format,
				limit: opts.limit === undefined ? undefined : Number(opts.limit),
				status: opts.status,
			}) as { format?: "json" | "jsonl"; limit?: number; status?: "active" | "disabled" });
			return writeRemoteExport(envelope, opts, "users");
		}
	}
}
