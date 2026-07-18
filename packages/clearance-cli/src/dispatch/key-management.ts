import { KEY_MANAGEMENT_OPERATIONS } from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	type CliPathOf,
	type DispatchInput,
	error,
	previewConfirmation,
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
			return requestManagementApi(session, {
				method: KEY_MANAGEMENT_OPERATIONS.status.http.method,
				path: KEY_MANAGEMENT_OPERATIONS.status.http.path,
			});
		case KEY_MANAGEMENT_OPERATIONS.plan.cliPath:
			return requestManagementApi(session, {
				method: KEY_MANAGEMENT_OPERATIONS.plan.http.method,
				path: KEY_MANAGEMENT_OPERATIONS.plan.http.path,
				body: {},
			});
		case KEY_MANAGEMENT_OPERATIONS.apply.cliPath:
			return requestManagementApi(session, {
				method: KEY_MANAGEMENT_OPERATIONS.apply.http.method,
				path: KEY_MANAGEMENT_OPERATIONS.apply.http.path,
				body: {
					expectedPlanId: expectedPlanId(opts.expectedPlan),
					...previewConfirmation(global),
				},
			});
	}
}
