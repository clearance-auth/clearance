import {
	API_KEY_OPERATIONS,
	resolveOperationPath,
	ROLE_OPERATIONS,
	SESSION_OPERATIONS,
} from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	firstStringArgument,
	query,
	requireConfirmation,
} from "./shared.js";

type AccessCommandPath =
	| CliPathOf<typeof API_KEY_OPERATIONS>
	| CliPathOf<typeof SESSION_OPERATIONS>
	| CliPathOf<typeof ROLE_OPERATIONS>;

export async function dispatchAccessCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<AccessCommandPath>): Promise<unknown> {
	const rawId = firstStringArgument(args);
	switch (path) {
		case API_KEY_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: API_KEY_OPERATIONS.list.http.method,
				path: query(API_KEY_OPERATIONS.list.http.path, { includeRevoked: opts.includeRevoked }),
			});
		case API_KEY_OPERATIONS.create.cliPath:
			return requestManagementApi(session, {
				method: API_KEY_OPERATIONS.create.http.method,
				path: API_KEY_OPERATIONS.create.http.path,
				body: { name: opts.name, scopes: opts.scope, dryRun: global.dryRun },
			});
		case API_KEY_OPERATIONS.rotate.cliPath:
			requireConfirmation(global, "API_KEY_CONFIRMATION_REQUIRED", "API key rotation");
			return requestManagementApi(session, {
				method: API_KEY_OPERATIONS.rotate.http.method,
				path: resolveOperationPath(API_KEY_OPERATIONS.rotate, { id: rawId }),
				body: { dryRun: global.dryRun },
			});
		case API_KEY_OPERATIONS.revoke.cliPath:
			requireConfirmation(global, "API_KEY_CONFIRMATION_REQUIRED", "API key revocation");
			return requestManagementApi(session, {
				method: API_KEY_OPERATIONS.revoke.http.method,
				path: resolveOperationPath(API_KEY_OPERATIONS.revoke, { id: rawId }),
				body: { dryRun: global.dryRun },
			});
		case SESSION_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: SESSION_OPERATIONS.list.http.method,
				path: query(SESSION_OPERATIONS.list.http.path, { limit: opts.limit, cursor: opts.cursor }),
			});
		case SESSION_OPERATIONS.revoke.cliPath:
			requireConfirmation(global, "SESSION_CONFIRM_REQUIRED", "Session revocation");
			return requestManagementApi(session, {
				method: SESSION_OPERATIONS.revoke.http.method,
				path: resolveOperationPath(SESSION_OPERATIONS.revoke, { id: rawId }),
				body: { dryRun: global.dryRun },
			});
		case ROLE_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: ROLE_OPERATIONS.list.http.method,
				path: ROLE_OPERATIONS.list.http.path,
			});
		case ROLE_OPERATIONS.validate.cliPath:
			return requestManagementApi(session, {
				method: ROLE_OPERATIONS.validate.http.method,
				path: ROLE_OPERATIONS.validate.http.path,
				body: body({ name: opts.name, slug: opts.slug, permissions: opts.permission }),
			});
		case ROLE_OPERATIONS.create.cliPath:
			return requestManagementApi(session, {
				method: ROLE_OPERATIONS.create.http.method,
				path: ROLE_OPERATIONS.create.http.path,
				body: body({
					name: opts.name,
					slug: opts.slug,
					description: opts.description,
					permissions: opts.permission,
					dryRun: global.dryRun,
				}),
			});
		case ROLE_OPERATIONS.update.cliPath:
			return requestManagementApi(session, {
				method: ROLE_OPERATIONS.update.http.method,
				path: resolveOperationPath(ROLE_OPERATIONS.update, { id: rawId }),
				body: body({
					name: opts.name,
					description: opts.description,
					permissions: opts.permission,
					dryRun: global.dryRun,
				}),
			});
	}
}
