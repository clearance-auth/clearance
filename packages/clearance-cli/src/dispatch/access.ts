import {
	API_KEY_OPERATIONS,
	AUTHORIZATION_OPERATIONS,
	ROLE_OPERATIONS,
	SESSION_OPERATIONS,
	SERVICE_ACCOUNT_OPERATIONS,
} from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	managementCallOptions,
	requireConfirmation,
} from "./shared.js";

type AccessCommandPath =
	| CliPathOf<typeof API_KEY_OPERATIONS>
	| CliPathOf<typeof SESSION_OPERATIONS>
	| CliPathOf<typeof ROLE_OPERATIONS>
	| CliPathOf<typeof AUTHORIZATION_OPERATIONS>
	| CliPathOf<typeof SERVICE_ACCOUNT_OPERATIONS>;

type AuthorizationSubjectKind = "principal" | "service_account";

function authorizationSubjectKind(value: unknown): AuthorizationSubjectKind {
	if (value === "principal" || value === "service_account") return value;
	throw error(
		"AUTHORIZATION_SUBJECT_KIND_INVALID",
		"Authorization subject kind must be principal or service_account.",
		"Pass --subject-kind principal or --subject-kind service_account.",
	);
}

function assignmentFilter(opts: Readonly<Record<string, unknown>>):
	| { subjectKind: AuthorizationSubjectKind; subjectId: string }
	| Record<string, never> {
	const hasSubject = typeof opts.subject === "string" && opts.subject.trim().length > 0;
	const hasKind = opts.subjectKind !== undefined;
	if (!hasSubject && !hasKind) return {};
	if (!hasSubject || !hasKind) {
		throw error(
			"AUTHORIZATION_ASSIGNMENT_FILTER_INVALID",
			"Authorization assignment filtering requires both --subject and --subject-kind.",
			"Pass both options together, or omit both to list every assignment.",
		);
	}
	return { subjectKind: authorizationSubjectKind(opts.subjectKind), subjectId: opts.subject as string };
}

function sortedRoleIds(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	return [...new Set(value.filter((role): role is string => typeof role === "string" && role.trim().length > 0))].sort();
}

function optionalExpectedRevision(value: unknown): string | undefined {
	if (value === undefined) return undefined;
	if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) {
		throw error(
			"AUTHORIZATION_OPTION_INVALID",
			"--expected-revision must be a positive canonical decimal revision.",
			"Use the revision returned by authorization effective or assignments replace.",
		);
	}
	return value;
}

function argumentAt(args: readonly unknown[], index: number): string {
	return typeof args[index] === "string" ? args[index] : "";
}

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
			return callManagementOperation(session, "keys.list", body({
				includeRevoked: opts.includeRevoked,
			}));
		case API_KEY_OPERATIONS.create.cliPath:
			return callManagementOperation(session, "keys.create", body({
				name: opts.name,
				scopes: opts.scope,
				expiresAt: opts.expiresAt,
				dryRun: global.dryRun,
			}) as { name: string; scopes?: string[]; expiresAt?: string; dryRun?: boolean }, managementCallOptions(global));
		case API_KEY_OPERATIONS.rotate.cliPath:
			requireConfirmation(global, "API_KEY_CONFIRMATION_REQUIRED", "API key rotation");
			return callManagementOperation(session, "keys.rotate", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case API_KEY_OPERATIONS.revoke.cliPath:
			requireConfirmation(global, "API_KEY_CONFIRMATION_REQUIRED", "API key revocation");
			return callManagementOperation(session, "keys.revoke", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SESSION_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "sessions.list", body({
				limit: opts.limit === undefined ? undefined : Number(opts.limit),
				cursor: opts.cursor,
			}));
		case SESSION_OPERATIONS.revoke.cliPath:
			requireConfirmation(global, "SESSION_CONFIRM_REQUIRED", "Session revocation");
			return callManagementOperation(session, "sessions.revoke", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case ROLE_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "roles.list", {});
		case ROLE_OPERATIONS.validate.cliPath:
			return callManagementOperation(session, "roles.validate", body({
				name: opts.name,
				slug: opts.slug,
				permissions: opts.permission,
			}) as { name?: string; slug?: string; permissions?: string[] });
		case ROLE_OPERATIONS.create.cliPath:
			return callManagementOperation(
				session,
				"roles.create",
				body({
					name: opts.name,
					slug: opts.slug,
					description: opts.description,
					permissions: opts.permission,
					dryRun: global.dryRun,
				}) as { name: string; slug?: string; description?: string; permissions: string[]; dryRun?: boolean },
				managementCallOptions(global),
			);
		case ROLE_OPERATIONS.update.cliPath:
			return callManagementOperation(
				session,
				"roles.update",
				body({
					id: rawId,
					name: opts.name,
					description: opts.description,
					permissions: opts.permission,
					dryRun: global.dryRun,
				}) as { id: string; name?: string; description?: string; permissions?: string[]; dryRun?: boolean },
				managementCallOptions(global),
			);
		case AUTHORIZATION_OPERATIONS.effectiveInspect.cliPath: {
			const subjectKind = authorizationSubjectKind(opts.subjectKind);
			return callManagementOperation(session, "authorization.effective.inspect", {
				organizationId: String(opts.org),
				subjectKind,
				subjectId: String(opts.subject),
			});
		}
		case AUTHORIZATION_OPERATIONS.assignmentsList.cliPath: {
			const filter = assignmentFilter(opts);
			return callManagementOperation(session, "authorization.assignments.list", {
				organizationId: String(opts.org),
				...filter,
			});
		}
		case AUTHORIZATION_OPERATIONS.assignmentsReplace.cliPath: {
			const subjectKind = authorizationSubjectKind(opts.subjectKind);
			const expectedRevision = optionalExpectedRevision(opts.expectedRevision);
			return callManagementOperation(
				session,
				"authorization.assignments.replace",
				body({
					organizationId: String(opts.org),
					subjectKind,
					subjectId: String(opts.subject),
					roleIds: sortedRoleIds(opts.role),
					expectedRevision,
					dryRun: global.dryRun || !global.yes,
				}) as {
					organizationId: string;
					subjectKind: AuthorizationSubjectKind;
					subjectId: string;
					roleIds: string[];
					expectedRevision?: string;
					dryRun?: boolean;
				},
				managementCallOptions(global),
			);
		}
		case AUTHORIZATION_OPERATIONS.reconcile.cliPath:
			return callManagementOperation(session, "authorization.reconcile", {
				organizationId: String(opts.org),
				dryRun: global.dryRun || !global.yes,
			}, managementCallOptions(global));
		case SERVICE_ACCOUNT_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "service-accounts.list", {
				organizationId: String(opts.org),
			});
		case SERVICE_ACCOUNT_OPERATIONS.inspect.cliPath:
			return callManagementOperation(session, "service-accounts.inspect", {
				organizationId: String(opts.org),
				accountId: rawId,
			});
		case SERVICE_ACCOUNT_OPERATIONS.create.cliPath:
			return callManagementOperation(session, "service-accounts.create", {
				organizationId: String(opts.org),
				name: String(opts.name),
				roleIds: sortedRoleIds(opts.role),
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SERVICE_ACCOUNT_OPERATIONS.disable.cliPath:
			requireConfirmation(global, "SERVICE_ACCOUNT_DISABLE_CONFIRMATION_REQUIRED", "Service-account disablement");
			return callManagementOperation(session, "service-accounts.disable", {
				organizationId: String(opts.org),
				accountId: rawId,
				status: "disabled",
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SERVICE_ACCOUNT_OPERATIONS.enable.cliPath:
			return callManagementOperation(session, "service-accounts.enable", {
				organizationId: String(opts.org),
				accountId: rawId,
				status: "active",
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case SERVICE_ACCOUNT_OPERATIONS.credentialCreate.cliPath:
			return callManagementOperation(session, "service-accounts.credentials.create", body({
				organizationId: String(opts.org),
				accountId: rawId,
				expiresAt: opts.expiresAt,
				dryRun: global.dryRun,
			}) as { organizationId: string; accountId: string; expiresAt?: string; dryRun?: boolean }, managementCallOptions(global));
		case SERVICE_ACCOUNT_OPERATIONS.credentialRotate.cliPath:
			requireConfirmation(global, "SERVICE_ACCOUNT_CREDENTIAL_ROTATE_CONFIRMATION_REQUIRED", "Service-account credential rotation");
			return callManagementOperation(session, "service-accounts.credentials.rotate", body({
				organizationId: String(opts.org),
				accountId: rawId,
				credentialId: argumentAt(args, 1),
				expiresAt: opts.expiresAt,
				dryRun: global.dryRun,
			}) as {
				organizationId: string;
				accountId: string;
				credentialId: string;
				expiresAt?: string;
				dryRun?: boolean;
			}, managementCallOptions(global));
		case SERVICE_ACCOUNT_OPERATIONS.credentialRevoke.cliPath:
			requireConfirmation(global, "SERVICE_ACCOUNT_CREDENTIAL_REVOKE_CONFIRMATION_REQUIRED", "Service-account credential revocation");
			return callManagementOperation(session, "service-accounts.credentials.revoke", {
				organizationId: String(opts.org),
				accountId: rawId,
				credentialId: argumentAt(args, 1),
				dryRun: global.dryRun,
			}, managementCallOptions(global));
	}
}
