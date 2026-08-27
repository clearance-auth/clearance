import { KEY_MANAGEMENT_OPERATIONS } from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import {
	type CliPathOf,
	type DispatchInput,
	error,
	managementCallOptions,
	requireConfirmation,
} from "./shared.js";

type KeyManagementCommandPath = CliPathOf<typeof KEY_MANAGEMENT_OPERATIONS>;

function expectedPlanId(value: unknown): string {
	if (typeof value === "string" && /^[a-f0-9]{64}$/.test(value)) return value;
	throw error(
		"KEY_MANAGEMENT_OPTION_INVALID",
		"--expected-plan must be a lowercase 64-character hexadecimal plan ID.",
		"Run key-management plan, then retry with its plan ID.",
	);
}

export async function dispatchKeyManagementCommand({
	session,
	path,
	opts,
	global,
}: DispatchInput<KeyManagementCommandPath>): Promise<unknown> {
	switch (path) {
		case KEY_MANAGEMENT_OPERATIONS.status.cliPath:
			return callManagementOperation(session, "key_management.status", {});
		case KEY_MANAGEMENT_OPERATIONS.plan.cliPath:
			return callManagementOperation(session, "key_management.plan", {});
		case KEY_MANAGEMENT_OPERATIONS.apply.cliPath:
			requireConfirmation(global, "KEY_MANAGEMENT_APPLY_CONFIRMATION_REQUIRED", "Key-management apply");
			return callManagementOperation(
				session,
				"key_management.apply",
				{
					expectedPlanId: expectedPlanId(opts.expectedPlan),
					dryRun: Boolean(global.dryRun),
				},
				managementCallOptions(global),
			);
	}
}
