import {
	AUTHENTICATION_POLICY_OPERATIONS,
} from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	localFile,
	previewConfirmation,
	query,
} from "./shared.js";

type AuthenticationPolicyCommandPath = CliPathOf<
	typeof AUTHENTICATION_POLICY_OPERATIONS
>;

function optionalIdentifier(value: unknown, name: string): string | undefined {
	if (value === undefined) return undefined;
	if (
		typeof value !== "string" ||
		value.trim() === "" ||
		value.length > 1_024 ||
		value.trim() !== value ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		throw error(
			"AUTHENTICATION_POLICY_OPTION_INVALID",
			`--${name} must be a non-empty identifier.`,
			`Pass a valid --${name} value from the active scope.`,
		);
	}
	return value;
}

function requiredIdentifier(value: unknown, name: string): string {
	const identifier = optionalIdentifier(value, name);
	if (identifier === undefined) {
		throw error(
			"AUTHENTICATION_POLICY_OPTION_INVALID",
			`${name} is required.`,
			`Pass a valid ${name} from the active scope.`,
		);
	}
	return identifier;
}

function expectedRevision(value: unknown): string {
	if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) {
		throw error(
			"AUTHENTICATION_POLICY_OPTION_INVALID",
			"--expected-revision must be a positive canonical decimal revision.",
			"Use the expectedRevision returned by auth-policy get or plan.",
		);
	}
	return value;
}

function policyDocument(
	opts: Readonly<Record<string, unknown>>,
	organizationId: string | undefined,
): unknown {
	const deletion = opts.deleteOverride === true;
	if (deletion) {
		if (!organizationId) {
			throw error(
				"AUTHENTICATION_POLICY_OPTION_INVALID",
				"--delete-override requires --organization-id.",
				"Target the organization override to delete.",
			);
		}
		if (opts.file !== undefined) {
			throw error(
				"AUTHENTICATION_POLICY_OPTION_INVALID",
				"--file and --delete-override cannot be used together.",
				"Choose a replacement document or override deletion.",
			);
		}
		return null;
	}
	if (typeof opts.file !== "string" || opts.file.trim() === "") {
		throw error(
			"AUTHENTICATION_POLICY_FILE_REQUIRED",
			"A policy JSON file is required.",
			"Pass --file <path>, or target an organization with --delete-override.",
		);
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(localFile(
			opts.file,
			"AUTHENTICATION_POLICY_FILE_UNREADABLE",
			"Authentication policy file",
		));
	} catch (cause) {
		if (
			typeof cause === "object" &&
			cause !== null &&
			"code" in cause &&
			cause.code === "AUTHENTICATION_POLICY_FILE_UNREADABLE"
		) {
			throw cause;
		}
		throw error(
			"AUTHENTICATION_POLICY_JSON_INVALID",
			"Authentication policy file is not valid JSON.",
			"Provide one JSON object using the policy schema returned by auth-policy get.",
		);
	}
	if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
		throw error(
			"AUTHENTICATION_POLICY_JSON_INVALID",
			"Authentication policy file must contain one JSON object.",
			"Provide a full environment policy or sparse organization override.",
		);
	}
	return parsed;
}

function unlockKind(value: unknown): "password" | "factor" | "all" {
	if (value === "password" || value === "factor" || value === "all") return value;
	throw error(
		"AUTHENTICATION_POLICY_OPTION_INVALID",
		"--kind must be password, factor, or all.",
		"Choose the exact lockout authority to clear.",
	);
}

export async function dispatchAuthenticationPolicyCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<AuthenticationPolicyCommandPath>): Promise<unknown> {
	const organizationId = optionalIdentifier(
		opts.organizationId,
		"organization-id",
	);
	switch (path) {
		case AUTHENTICATION_POLICY_OPERATIONS.get.cliPath:
			return requestManagementApi(session, {
				method: AUTHENTICATION_POLICY_OPERATIONS.get.http.method,
				path: query(AUTHENTICATION_POLICY_OPERATIONS.get.http.path, {
					organizationId,
				}),
			});
		case AUTHENTICATION_POLICY_OPERATIONS.plan.cliPath:
			return requestManagementApi(session, {
				method: AUTHENTICATION_POLICY_OPERATIONS.plan.http.method,
				path: AUTHENTICATION_POLICY_OPERATIONS.plan.http.path,
				body: body({
					organizationId,
					policy: policyDocument(opts, organizationId),
				}),
			});
		case AUTHENTICATION_POLICY_OPERATIONS.apply.cliPath:
			return requestManagementApi(session, {
				method: AUTHENTICATION_POLICY_OPERATIONS.apply.http.method,
				path: AUTHENTICATION_POLICY_OPERATIONS.apply.http.path,
				body: body({
					organizationId,
					policy: policyDocument(opts, organizationId),
					expectedRevision: expectedRevision(opts.expectedRevision),
					...previewConfirmation(global),
				}),
			});
		case AUTHENTICATION_POLICY_OPERATIONS.unlock.cliPath:
			return requestManagementApi(session, {
				method: AUTHENTICATION_POLICY_OPERATIONS.unlock.http.method,
				path: AUTHENTICATION_POLICY_OPERATIONS.unlock.http.path,
				body: {
					userId: requiredIdentifier(
						firstStringArgument(args),
						"user-id",
					),
					kind: unlockKind(opts.kind),
					...previewConfirmation(global),
				},
			});
	}
}
