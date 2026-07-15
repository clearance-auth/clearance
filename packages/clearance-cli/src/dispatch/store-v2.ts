import { STORE_V2_OPERATIONS } from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	type CliPathOf,
	type DispatchInput,
	requireConfirmation,
	requireRemoteMutation,
} from "./shared.js";

type StoreV2CommandPath = CliPathOf<typeof STORE_V2_OPERATIONS>;

export async function dispatchStoreV2Command({
	session,
	path,
	global,
}: DispatchInput<StoreV2CommandPath>): Promise<unknown> {
	switch (path) {
		case STORE_V2_OPERATIONS.status.cliPath:
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.status.http.method,
				path: STORE_V2_OPERATIONS.status.http.path,
			});
		case STORE_V2_OPERATIONS.plan.cliPath:
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.plan.http.method,
				path: STORE_V2_OPERATIONS.plan.http.path,
			});
		case STORE_V2_OPERATIONS.apply.cliPath:
			requireConfirmation(
				global,
				"STORE_V2_APPLY_CONFIRMATION_REQUIRED",
				"Store-v2 apply",
			);
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.apply.http.method,
				path: STORE_V2_OPERATIONS.apply.http.path,
				body: {
					dryRun: global.dryRun,
					confirm: global.yes && !global.dryRun,
				},
			});
		case STORE_V2_OPERATIONS.verify.cliPath:
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.verify.http.method,
				path: STORE_V2_OPERATIONS.verify.http.path,
			});
		case STORE_V2_OPERATIONS.rollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_ROLLBACK_CONFIRMATION_REQUIRED",
				"Store-v2 rollback",
			);
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.rollback.http.method,
				path: STORE_V2_OPERATIONS.rollback.http.path,
				body: { confirm: true },
			});
	}
}
