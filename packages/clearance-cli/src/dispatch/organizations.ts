import {
	MEMBER_OPERATIONS,
	ORGANIZATION_OPERATIONS,
	resolveOperationPath,
} from "@clearance/management";
import { requestManagementApi, type ApiSession } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	localFile,
	previewConfirmation,
	query,
	requireConfirmation,
	requireRemoteMutation,
} from "./shared.js";

type OrganizationCommandPath =
	| CliPathOf<typeof ORGANIZATION_OPERATIONS>
	| CliPathOf<typeof MEMBER_OPERATIONS>;

async function resolveRemoteMembershipId(
	session: ApiSession,
	organizationId: unknown,
	options: Readonly<Record<string, unknown>>,
): Promise<string> {
	if (typeof options.member === "string" && options.member.trim()) return options.member;
	if (typeof options.user !== "string" || !options.user.trim()) {
		throw error(
			"MEMBER_ID_REQUIRED",
			"Membership update or removal requires --member or --user.",
			"List organization members, then pass a membership id or principal id.",
		);
	}
	const response = await requestManagementApi<{ members?: Array<{ id: string; principalId: string; status: string }> }>(session, {
		path: `/v1/organizations/${encodeURIComponent(String(organizationId))}/members`,
	});
	const membership = (response.members ?? []).find(
		(candidate) => candidate.principalId === options.user && candidate.status !== "removed",
	);
	if (!membership) {
		throw error(
			"MEMBER_NOT_FOUND",
			"Membership not found.",
			"List organization members and verify the principal id.",
		);
	}
	return membership.id;
}

export async function dispatchOrganizationCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<OrganizationCommandPath>): Promise<unknown> {
	const rawId = firstStringArgument(args);
	switch (path) {
		case ORGANIZATION_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: ORGANIZATION_OPERATIONS.list.http.method,
				path: query(ORGANIZATION_OPERATIONS.list.http.path, { limit: opts.limit, cursor: opts.cursor }),
			});
		case ORGANIZATION_OPERATIONS.inspect.cliPath:
			return requestManagementApi(session, {
				method: ORGANIZATION_OPERATIONS.inspect.http.method,
				path: resolveOperationPath(ORGANIZATION_OPERATIONS.inspect, { id: rawId }),
			});
		case ORGANIZATION_OPERATIONS.create.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: ORGANIZATION_OPERATIONS.create.http.method,
				path: ORGANIZATION_OPERATIONS.create.http.path,
				body: body({ name: opts.name, slug: opts.slug, ownerUserId: opts.ownerUser }),
			});
		case ORGANIZATION_OPERATIONS.update.cliPath:
			return requestManagementApi(session, {
				method: ORGANIZATION_OPERATIONS.update.http.method,
				path: resolveOperationPath(ORGANIZATION_OPERATIONS.update, { id: rawId }),
				body: body({ name: opts.name, slug: opts.slug, dryRun: global.dryRun }),
			});
		case ORGANIZATION_OPERATIONS.archive.cliPath:
			return requestManagementApi(session, {
				method: ORGANIZATION_OPERATIONS.archive.http.method,
				path: resolveOperationPath(ORGANIZATION_OPERATIONS.archive, { id: rawId }),
				body: previewConfirmation(global),
			});
		case MEMBER_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: MEMBER_OPERATIONS.list.http.method,
				path: resolveOperationPath(MEMBER_OPERATIONS.list, { id: String(opts.org) }),
			});
		case MEMBER_OPERATIONS.add.cliPath:
			return requestManagementApi(session, {
				method: MEMBER_OPERATIONS.add.http.method,
				path: resolveOperationPath(MEMBER_OPERATIONS.add, { id: String(opts.org) }),
				body: body({ principalId: opts.user, role: opts.role, dryRun: global.dryRun }),
			});
		case MEMBER_OPERATIONS.update.cliPath: {
			const membershipId = await resolveRemoteMembershipId(session, opts.org, opts);
			return requestManagementApi(session, {
				method: MEMBER_OPERATIONS.update.http.method,
				path: resolveOperationPath(MEMBER_OPERATIONS.update, { id: String(opts.org), memberId: membershipId }),
				body: { role: opts.role, dryRun: global.dryRun },
			});
		}
		case MEMBER_OPERATIONS.remove.cliPath: {
			requireConfirmation(global, "MEMBER_REMOVE_CONFIRM_REQUIRED", "Membership removal");
			const membershipId = await resolveRemoteMembershipId(session, opts.org, opts);
			return requestManagementApi(session, {
				method: MEMBER_OPERATIONS.remove.http.method,
				path: resolveOperationPath(MEMBER_OPERATIONS.remove, { id: String(opts.org), memberId: membershipId }),
				body: { dryRun: global.dryRun },
			});
		}
		case MEMBER_OPERATIONS.import.cliPath: {
			requireConfirmation(global, "MEMBER_IMPORT_CONFIRMATION_REQUIRED", "Member import");
			const filename = String(opts.file);
			const lowercaseFilename = filename.toLowerCase();
			let inferredFormat: "json" | "csv" | undefined;
			if (lowercaseFilename.endsWith(".json")) inferredFormat = "json";
			if (lowercaseFilename.endsWith(".csv")) inferredFormat = "csv";
			const format = opts.format ?? inferredFormat;
			if (format !== "json" && format !== "csv") {
				throw error(
					"MEMBER_IMPORT_FORMAT_REQUIRED",
					"Member import format is required.",
					"Use a .json or .csv file, or pass --format json|csv.",
				);
			}
			return requestManagementApi(session, {
				method: MEMBER_OPERATIONS.import.http.method,
				path: resolveOperationPath(MEMBER_OPERATIONS.import, { id: String(opts.org) }),
				body: {
					content: localFile(opts.file, "MEMBER_IMPORT_FILE_UNREADABLE", "Member import file"),
					format,
					...previewConfirmation(global),
				},
			});
		}
	}
}
