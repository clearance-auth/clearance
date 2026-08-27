import type { ClearanceError } from "@clearance/management";

/** Stable process statuses intended for scripts and automation. */
export const CLI_EXIT_CODE = {
	success: 0,
	failure: 1,
	checkFailed: 2,
	invalidInput: 64,
	notFound: 66,
	unavailable: 69,
	internal: 70,
	conflict: 73,
	authentication: 77,
	permission: 78,
	temporaryFailure: 75,
} as const;

export type CliExitCode = (typeof CLI_EXIT_CODE)[keyof typeof CLI_EXIT_CODE];

export function exitCodeForClearanceError(
	error: Pick<ClearanceError, "status" | "retryable">,
): CliExitCode {
	if (error.retryable || error.status === 429) return CLI_EXIT_CODE.temporaryFailure;
	if (error.status === 401) return CLI_EXIT_CODE.authentication;
	if (error.status === 403) return CLI_EXIT_CODE.permission;
	if (error.status === 404) return CLI_EXIT_CODE.notFound;
	if (error.status === 409) return CLI_EXIT_CODE.conflict;
	if (error.status === 400 || error.status === 422) {
		return CLI_EXIT_CODE.invalidInput;
	}
	if (error.status >= 500) return CLI_EXIT_CODE.unavailable;
	return CLI_EXIT_CODE.failure;
}
