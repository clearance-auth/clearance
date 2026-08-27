import {
	MEMBER_OPERATIONS,
	ORGANIZATION_OPERATIONS,
} from "@clearance/management";
import { callManagementOperation, type ApiSession } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	localFile,
	managementCallOptions,
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
	const response = await callManagementOperation(session, "organizations.members.list", {
		organizationId: String(organizationId),
	});
	const membership = response.members.find(
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
			return callManagementOperation(session, "organizations.list", body({
				limit: opts.limit === undefined ? undefined : Number(opts.limit),
				cursor: opts.cursor,
			}));
		case ORGANIZATION_OPERATIONS.inspect.cliPath:
			return callManagementOperation(session, "organizations.inspect", { id: rawId });
		case ORGANIZATION_OPERATIONS.create.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(session, "organizations.create", body({
				name: opts.name,
				slug: opts.slug,
				ownerUserId: opts.ownerUser,
			}) as { name: string; slug?: string; ownerUserId?: string });
		case ORGANIZATION_OPERATIONS.update.cliPath:
			return callManagementOperation(session, "organizations.update", body({
				id: rawId,
				name: opts.name,
				slug: opts.slug,
				dryRun: Boolean(global.dryRun),
			}) as { id: string; name?: string; slug?: string; dryRun?: boolean }, managementCallOptions(global));
		case ORGANIZATION_OPERATIONS.archive.cliPath:
			requireConfirmation(global, "ORGANIZATION_ARCHIVE_CONFIRMATION_REQUIRED", "Organization archive");
			return callManagementOperation(session, "organizations.archive", {
				id: rawId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		case MEMBER_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "organizations.members.list", {
				organizationId: String(opts.org),
			});
		case MEMBER_OPERATIONS.add.cliPath:
			return callManagementOperation(session, "organizations.members.add", body({
				organizationId: String(opts.org),
				principalId: opts.user,
				role: opts.role,
				dryRun: global.dryRun,
			}) as { organizationId: string; principalId: string; role?: string; dryRun?: boolean }, managementCallOptions(global));
		case MEMBER_OPERATIONS.update.cliPath: {
			const membershipId = await resolveRemoteMembershipId(session, opts.org, opts);
			return callManagementOperation(session, "organizations.members.update", {
				organizationId: String(opts.org),
				membershipId,
				role: String(opts.role),
				dryRun: global.dryRun,
			}, managementCallOptions(global));
		}
		case MEMBER_OPERATIONS.remove.cliPath: {
			requireConfirmation(global, "MEMBER_REMOVE_CONFIRM_REQUIRED", "Membership removal");
			const membershipId = await resolveRemoteMembershipId(session, opts.org, opts);
			return callManagementOperation(session, "organizations.members.remove", {
				organizationId: String(opts.org),
				membershipId,
				dryRun: global.dryRun,
			}, managementCallOptions(global));
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
			return callManagementOperation(session, "organizations.members.import", {
					organizationId: String(opts.org),
					content: localFile(opts.file, "MEMBER_IMPORT_FILE_UNREADABLE", "Member import file"),
					format,
					dryRun: Boolean(global.dryRun),
				}, managementCallOptions(global));
		}
	}
}
