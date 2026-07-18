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
		case STORE_V2_OPERATIONS.eventsCutover.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_EVENTS_CUTOVER_CONFIRMATION_REQUIRED",
				"Store-v2 event cutover",
			);
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.eventsCutover.http.method,
				path: STORE_V2_OPERATIONS.eventsCutover.http.path,
				body: { confirm: true },
			});
		case STORE_V2_OPERATIONS.eventsRollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_EVENTS_ROLLBACK_CONFIRMATION_REQUIRED",
				"Store-v2 event rollback",
			);
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.eventsRollback.http.method,
				path: STORE_V2_OPERATIONS.eventsRollback.http.path,
				body: { confirm: true },
			});
		case STORE_V2_OPERATIONS.principalsCutover.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_PRINCIPALS_CUTOVER_CONFIRMATION_REQUIRED",
				"Store-v2 principal cutover",
			);
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.principalsCutover.http.method,
				path: STORE_V2_OPERATIONS.principalsCutover.http.path,
				body: { confirm: true },
			});
		case STORE_V2_OPERATIONS.principalsRollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_PRINCIPALS_ROLLBACK_CONFIRMATION_REQUIRED",
				"Store-v2 principal rollback",
			);
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.principalsRollback.http.method,
				path: STORE_V2_OPERATIONS.principalsRollback.http.path,
				body: { confirm: true },
			});
		case STORE_V2_OPERATIONS.topologyCutover.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_TOPOLOGY_CUTOVER_CONFIRMATION_REQUIRED",
				"Store-v2 topology cutover",
			);
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.topologyCutover.http.method,
				path: STORE_V2_OPERATIONS.topologyCutover.http.path,
				body: { confirm: true },
			});
		case STORE_V2_OPERATIONS.topologyRollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_TOPOLOGY_ROLLBACK_CONFIRMATION_REQUIRED",
				"Store-v2 topology rollback",
			);
			return requestManagementApi(session, {
				method: STORE_V2_OPERATIONS.topologyRollback.http.method,
				path: STORE_V2_OPERATIONS.topologyRollback.http.path,
				body: { confirm: true },
			});
	}
}
