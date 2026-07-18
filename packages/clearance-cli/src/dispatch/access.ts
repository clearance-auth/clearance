import {
	API_KEY_OPERATIONS,
	AUTHORIZATION_OPERATIONS,
	resolveOperationPath,
	ROLE_OPERATIONS,
	SESSION_OPERATIONS,
	SERVICE_ACCOUNT_OPERATIONS,
} from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	previewConfirmation,
	query,
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
			return requestManagementApi(session, {
				method: API_KEY_OPERATIONS.list.http.method,
				path: query(API_KEY_OPERATIONS.list.http.path, { includeRevoked: opts.includeRevoked }),
			});
		case API_KEY_OPERATIONS.create.cliPath:
			return requestManagementApi(session, {
				method: API_KEY_OPERATIONS.create.http.method,
				path: API_KEY_OPERATIONS.create.http.path,
					body: {
						name: opts.name,
						scopes: opts.scope,
						expiresAt: opts.expiresAt,
						dryRun: global.dryRun,
					},
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
		case AUTHORIZATION_OPERATIONS.effectiveInspect.cliPath: {
			const subjectKind = authorizationSubjectKind(opts.subjectKind);
			return requestManagementApi(session, {
				method: AUTHORIZATION_OPERATIONS.effectiveInspect.http.method,
				path: resolveOperationPath(AUTHORIZATION_OPERATIONS.effectiveInspect, {
					id: String(opts.org),
					subjectKind,
					subjectId: String(opts.subject),
				}),
			});
		}
		case AUTHORIZATION_OPERATIONS.assignmentsList.cliPath: {
			const filter = assignmentFilter(opts);
			return requestManagementApi(session, {
				method: AUTHORIZATION_OPERATIONS.assignmentsList.http.method,
				path: query(
					resolveOperationPath(AUTHORIZATION_OPERATIONS.assignmentsList, { id: String(opts.org) }),
					filter,
				),
			});
		}
		case AUTHORIZATION_OPERATIONS.assignmentsReplace.cliPath: {
			const subjectKind = authorizationSubjectKind(opts.subjectKind);
			const expectedRevision = optionalExpectedRevision(opts.expectedRevision);
			return requestManagementApi(session, {
				method: AUTHORIZATION_OPERATIONS.assignmentsReplace.http.method,
				path: resolveOperationPath(AUTHORIZATION_OPERATIONS.assignmentsReplace, {
					id: String(opts.org),
					subjectKind,
					subjectId: String(opts.subject),
				}),
				body: body({
					roleIds: sortedRoleIds(opts.role),
					expectedRevision,
					...previewConfirmation(global),
				}),
			});
		}
		case AUTHORIZATION_OPERATIONS.reconcile.cliPath:
			return requestManagementApi(session, {
				method: AUTHORIZATION_OPERATIONS.reconcile.http.method,
				path: resolveOperationPath(AUTHORIZATION_OPERATIONS.reconcile, { id: String(opts.org) }),
				body: body(previewConfirmation(global)),
			});
		case SERVICE_ACCOUNT_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: SERVICE_ACCOUNT_OPERATIONS.list.http.method,
				path: resolveOperationPath(SERVICE_ACCOUNT_OPERATIONS.list, { id: String(opts.org) }),
			});
		case SERVICE_ACCOUNT_OPERATIONS.inspect.cliPath:
			return requestManagementApi(session, {
				method: SERVICE_ACCOUNT_OPERATIONS.inspect.http.method,
				path: resolveOperationPath(SERVICE_ACCOUNT_OPERATIONS.inspect, {
					id: String(opts.org), accountId: rawId,
				}),
			});
		case SERVICE_ACCOUNT_OPERATIONS.create.cliPath:
			return requestManagementApi(session, {
				method: SERVICE_ACCOUNT_OPERATIONS.create.http.method,
				path: resolveOperationPath(SERVICE_ACCOUNT_OPERATIONS.create, { id: String(opts.org) }),
				body: body({ name: opts.name, roleIds: sortedRoleIds(opts.role), dryRun: global.dryRun }),
			});
		case SERVICE_ACCOUNT_OPERATIONS.disable.cliPath:
			requireConfirmation(global, "SERVICE_ACCOUNT_DISABLE_CONFIRMATION_REQUIRED", "Service-account disablement");
			return requestManagementApi(session, {
				method: SERVICE_ACCOUNT_OPERATIONS.disable.http.method,
				path: resolveOperationPath(SERVICE_ACCOUNT_OPERATIONS.disable, {
					id: String(opts.org), accountId: rawId,
				}),
				body: { status: "disabled", dryRun: global.dryRun },
			});
		case SERVICE_ACCOUNT_OPERATIONS.enable.cliPath:
			return requestManagementApi(session, {
				method: SERVICE_ACCOUNT_OPERATIONS.enable.http.method,
				path: resolveOperationPath(SERVICE_ACCOUNT_OPERATIONS.enable, {
					id: String(opts.org), accountId: rawId,
				}),
				body: { status: "active", dryRun: global.dryRun },
			});
		case SERVICE_ACCOUNT_OPERATIONS.credentialCreate.cliPath:
			return requestManagementApi(session, {
				method: SERVICE_ACCOUNT_OPERATIONS.credentialCreate.http.method,
				path: resolveOperationPath(SERVICE_ACCOUNT_OPERATIONS.credentialCreate, {
					id: String(opts.org), accountId: rawId,
				}),
				body: body({ expiresAt: opts.expiresAt, dryRun: global.dryRun }),
			});
		case SERVICE_ACCOUNT_OPERATIONS.credentialRotate.cliPath:
			requireConfirmation(global, "SERVICE_ACCOUNT_CREDENTIAL_ROTATE_CONFIRMATION_REQUIRED", "Service-account credential rotation");
			return requestManagementApi(session, {
				method: SERVICE_ACCOUNT_OPERATIONS.credentialRotate.http.method,
				path: resolveOperationPath(SERVICE_ACCOUNT_OPERATIONS.credentialRotate, {
					id: String(opts.org), accountId: rawId, credentialId: argumentAt(args, 1),
				}),
				body: body({ expiresAt: opts.expiresAt, dryRun: global.dryRun }),
			});
		case SERVICE_ACCOUNT_OPERATIONS.credentialRevoke.cliPath:
			requireConfirmation(global, "SERVICE_ACCOUNT_CREDENTIAL_REVOKE_CONFIRMATION_REQUIRED", "Service-account credential revocation");
			return requestManagementApi(session, {
				method: SERVICE_ACCOUNT_OPERATIONS.credentialRevoke.http.method,
				path: resolveOperationPath(SERVICE_ACCOUNT_OPERATIONS.credentialRevoke, {
					id: String(opts.org), accountId: rawId, credentialId: argumentAt(args, 1),
				}),
				body: { dryRun: global.dryRun },
			});
	}
}
