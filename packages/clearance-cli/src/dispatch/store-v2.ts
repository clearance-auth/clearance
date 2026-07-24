import { STORE_V2_OPERATIONS } from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import {
	type CliPathOf,
	type DispatchInput,
	managementCallOptions,
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
			return callManagementOperation(session, "schema.store-v2.status", {});
		case STORE_V2_OPERATIONS.plan.cliPath:
			return callManagementOperation(session, "schema.store-v2.plan", {});
		case STORE_V2_OPERATIONS.apply.cliPath:
			requireConfirmation(
				global,
				"STORE_V2_APPLY_CONFIRMATION_REQUIRED",
				"Store-v2 apply",
			);
			return callManagementOperation(session, "schema.store-v2.apply", {
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case STORE_V2_OPERATIONS.verify.cliPath:
			return callManagementOperation(session, "schema.store-v2.verify", {});
		case STORE_V2_OPERATIONS.rollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_ROLLBACK_CONFIRMATION_REQUIRED",
				"Store-v2 rollback",
			);
			return callManagementOperation(session, "schema.store-v2.rollback", {}, managementCallOptions(global));
		case STORE_V2_OPERATIONS.eventsCutover.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_EVENTS_CUTOVER_CONFIRMATION_REQUIRED",
				"Store-v2 event cutover",
			);
			return callManagementOperation(session, "schema.store-v2.events.cutover", {}, managementCallOptions(global));
		case STORE_V2_OPERATIONS.eventsRollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_EVENTS_ROLLBACK_CONFIRMATION_REQUIRED",
				"Store-v2 event rollback",
			);
			return callManagementOperation(session, "schema.store-v2.events.rollback", {}, managementCallOptions(global));
		case STORE_V2_OPERATIONS.principalsCutover.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_PRINCIPALS_CUTOVER_CONFIRMATION_REQUIRED",
				"Store-v2 principal cutover",
			);
			return callManagementOperation(session, "schema.store-v2.principals.cutover", {}, managementCallOptions(global));
		case STORE_V2_OPERATIONS.principalsRollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_PRINCIPALS_ROLLBACK_CONFIRMATION_REQUIRED",
				"Store-v2 principal rollback",
			);
			return callManagementOperation(session, "schema.store-v2.principals.rollback", {}, managementCallOptions(global));
		case STORE_V2_OPERATIONS.topologyCutover.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_TOPOLOGY_CUTOVER_CONFIRMATION_REQUIRED",
				"Store-v2 topology cutover",
			);
			return callManagementOperation(session, "schema.store-v2.topology.cutover", {}, managementCallOptions(global));
		case STORE_V2_OPERATIONS.topologyRollback.cliPath:
			requireRemoteMutation(global, path);
			requireConfirmation(
				global,
				"STORE_V2_TOPOLOGY_ROLLBACK_CONFIRMATION_REQUIRED",
				"Store-v2 topology rollback",
			);
			return callManagementOperation(session, "schema.store-v2.topology.rollback", {}, managementCallOptions(global));
	}
}
