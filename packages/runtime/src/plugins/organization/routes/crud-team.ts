import { createAuthEndpoint } from "@clearance/core/api";
import {
	getCurrentAdapter,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
import { APIError } from "@clearance/core/error";
import * as z from "zod";
import { getSessionFromCtx } from "../../../api";
import { setSessionCookie } from "../../../cookies";
import type { InferAdditionalFieldsFromPluginOptions } from "../../../db";
import { toZodSchema } from "../../../db";
import type { PrettifyDeep } from "../../../types/helper";
import { getOrgAdapter, resolveMaximumMembersPerTeam } from "../adapter";
import { orgMiddleware, orgSessionMiddleware } from "../call";
import { ORGANIZATION_ERROR_CODES } from "../error-codes";
import { hasPermission } from "../has-permission";
import type { Organization, TeamMember } from "../schema";
import { teamSchema } from "../schema";
import type { OrganizationOptions } from "../types";

const ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED = {
	code: "ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED",
	message:
		"Organization lifecycle mutations require rollback-capable database transactions",
} as const;

function requireTeamMutationTransaction(
	context: Parameters<typeof getOrgAdapter>[0],
) {
	if (typeof context.adapter.options?.adapterConfig.transaction !== "function") {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED,
		);
	}
}

const teamBaseSchema = z.object({
	name: z.string().meta({
		description: 'The name of the team. Eg: "my-team"',
	}),
	organizationId: z
		.string()
		.meta({
			description:
				'The organization ID which the team will be created in. Defaults to the active organization. Eg: "organization-id"',
		})
		.optional(),
});

export const createTeam = <O extends OrganizationOptions>(options: O) => {
	const additionalFieldsSchema = toZodSchema({
		fields: options?.schema?.team?.additionalFields ?? {},
		isClientSide: true,
	});
	return createAuthEndpoint(
		"/organization/create-team",
		{
			method: "POST",
			body: z.object({
				...teamBaseSchema.shape,
				...additionalFieldsSchema.shape,
			}),
			use: [orgMiddleware],
			metadata: {
				$Infer: {
					body: {} as z.infer<typeof teamBaseSchema> &
						InferAdditionalFieldsFromPluginOptions<"team", O>,
				},
				openapi: {
					description: "Create a new team within an organization",
					responses: {
						"200": {
							description: "Team created successfully",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											id: {
												type: "string",
												description: "Unique identifier of the created team",
											},
											name: {
												type: "string",
												description: "Name of the team",
											},
											organizationId: {
												type: "string",
												description:
													"ID of the organization the team belongs to",
											},
											createdAt: {
												type: "string",
												format: "date-time",
												description: "Timestamp when the team was created",
											},
											updatedAt: {
												type: "string",
												format: "date-time",
												description: "Timestamp when the team was last updated",
											},
										},
										required: [
											"id",
											"name",
											"organizationId",
											"createdAt",
											"updatedAt",
										],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = await getSessionFromCtx(ctx);
			const organizationId =
				ctx.body.organizationId || session?.session.activeOrganizationId;
			if (!session && (ctx.request || ctx.headers)) {
				throw APIError.fromStatus("UNAUTHORIZED");
			}

			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			const adapter = getOrgAdapter<O>(ctx.context, options as O);
			if (session) {
				const member = await adapter.findMemberByOrgId({
					userId: session.user.id,
					organizationId,
				});
				if (!member) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION,
					);
				}
				const canCreate = await hasPermission(
					{
						role: member.role,
						options: ctx.context.orgOptions,
						permissions: {
							team: ["create"],
						},
						organizationId,
					},
					ctx,
				);

				if (!canCreate) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION,
					);
				}
			}

			const maximum =
				typeof ctx.context.orgOptions.teams?.maximumTeams === "function"
					? await ctx.context.orgOptions.teams?.maximumTeams(
							{
								organizationId,
								session,
							},
							ctx,
						)
					: ctx.context.orgOptions.teams?.maximumTeams;

			const { name, organizationId: _, ...additionalFields } = ctx.body;
			const teamData = {
				name,
				organizationId,
				createdAt: new Date(),
				updatedAt: new Date(),
				...additionalFields,
			};

			requireTeamMutationTransaction(ctx.context);
			const createdTeam = await runWithTransaction(
				ctx.context.adapter,
				async () => {
					let organizationForHooks:
						| (Organization & Record<string, any>)
						| undefined;
					const result = await adapter.createTeam(
						teamData,
						maximum,
						async (organization) => {
							organizationForHooks = organization;
							if (!options?.organizationHooks?.beforeCreateTeam) {
								return teamData;
							}
							const response = await options.organizationHooks.beforeCreateTeam({
								team: { name, organizationId, ...additionalFields },
								user: session?.user,
								organization,
							});
							return response && typeof response === "object" && "data" in response
								? { ...teamData, ...response.data, organizationId }
								: teamData;
						},
					);
					if (result.status === "transactionRequired") {
						requireTeamMutationTransaction(ctx.context);
						throw new Error("unreachable");
					}
					if (result.status === "organizationNotFound") {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
						);
					}
					if (result.status === "limitReached") {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS,
						);
					}
					const team = result.team;
					if (options?.organizationHooks?.afterCreateTeam) {
						await queueAfterTransactionHook(
							async () => {
								await options.organizationHooks!.afterCreateTeam!({
									team,
									user: session?.user,
									organization: organizationForHooks!,
								});
							},
							ctx.context.adapter,
						);
					}
					return team;
				},
			);

			return ctx.json(createdTeam);
		},
	);
};

const removeTeamBodySchema = z.object({
	teamId: z.string().meta({
		description: `The team ID of the team to remove. Eg: "team-id"`,
	}),
	organizationId: z
		.string()
		.meta({
			description: `The organization ID which the team falls under. If not provided, it will default to the user's active organization. Eg: "organization-id"`,
		})
		.optional(),
});

export const removeTeam = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/remove-team",
		{
			method: "POST",
			body: removeTeamBodySchema,
			use: [orgMiddleware],
			metadata: {
				openapi: {
					description: "Remove a team from an organization",
					responses: {
						"200": {
							description: "Team removed successfully",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											message: {
												type: "string",
												description:
													"Confirmation message indicating successful removal",
												enum: ["Team removed successfully."],
											},
										},
										required: ["message"],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = await getSessionFromCtx(ctx);
			const organizationId =
				ctx.body.organizationId || session?.session.activeOrganizationId;
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			if (!session && (ctx.request || ctx.headers)) {
				throw APIError.fromStatus("UNAUTHORIZED");
			}
			requireTeamMutationTransaction(ctx.context);
			const adapter = getOrgAdapter<O>(ctx.context, options);
			if (session) {
				const member = await adapter.findMemberByOrgId({
					userId: session.user.id,
					organizationId,
				});

				if (!member || session.session?.activeTeamId === ctx.body.teamId) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM,
					);
				}

				const canRemove = await hasPermission(
					{
						role: member.role,
						options: ctx.context.orgOptions,
						permissions: {
							team: ["delete"],
						},
						organizationId,
					},
					ctx,
				);

				if (!canRemove) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION,
					);
				}
			}
			const team = await adapter.findTeamById({
				teamId: ctx.body.teamId,
				organizationId,
			});
			if (!team || team.organizationId !== organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
				);
			}

			const organization = await adapter.findOrganizationById(organizationId);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			const deleted = await adapter.deleteTeam({
				organizationId,
				teamId: team.id,
				allowRemovingAllTeams:
					ctx.context.orgOptions.teams?.allowRemovingAllTeams === true,
				beforeDelete: async ({ organization, team }) => {
					await options?.organizationHooks?.beforeDeleteTeam?.({
						team,
						user: session?.user,
						organization,
					});
				},
			});
			if (deleted.status === "transactionRequired") {
				requireTeamMutationTransaction(ctx.context);
				throw new Error("unreachable");
			}
			if (deleted.status === "organizationNotFound") {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}
			if (deleted.status === "teamNotFound") {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
				);
			}
			if (deleted.status === "lastTeam") {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.UNABLE_TO_REMOVE_LAST_TEAM,
				);
			}
			const committedTeam = deleted.team;
			const committedOrganization = deleted.organization;

			// Run afterDeleteTeam hook
			if (options?.organizationHooks?.afterDeleteTeam) {
				await options?.organizationHooks.afterDeleteTeam({
					team: committedTeam,
					user: session?.user,
					organization: committedOrganization,
				});
			}

			return ctx.json({ message: "Team removed successfully." });
		},
	);

export const updateTeam = <O extends OrganizationOptions>(options: O) => {
	const additionalFieldsSchema = toZodSchema({
		fields: options?.schema?.team?.additionalFields ?? {},
		isClientSide: true,
	});

	type Body = {
		teamId: string;
		data: Partial<
			PrettifyDeep<
				Omit<z.infer<typeof teamSchema>, "id" | "createdAt" | "updatedAt">
			> &
				InferAdditionalFieldsFromPluginOptions<"team", O>
		>;
	};

	return createAuthEndpoint(
		"/organization/update-team",
		{
			method: "POST",
			body: z.object({
				teamId: z.string().meta({
					description: `The ID of the team to be updated. Eg: "team-id"`,
				}),
				data: z
					.object({
						...teamSchema.shape,
						...additionalFieldsSchema.shape,
					})
					.partial(),
			}),
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			metadata: {
				$Infer: { body: {} as Body },
				openapi: {
					description: "Update an existing team in an organization",
					responses: {
						"200": {
							description: "Team updated successfully",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											id: {
												type: "string",
												description: "Unique identifier of the updated team",
											},
											name: {
												type: "string",
												description: "Updated name of the team",
											},
											organizationId: {
												type: "string",
												description:
													"ID of the organization the team belongs to",
											},
											createdAt: {
												type: "string",
												format: "date-time",
												description: "Timestamp when the team was created",
											},
											updatedAt: {
												type: "string",
												format: "date-time",
												description: "Timestamp when the team was last updated",
											},
										},
										required: [
											"id",
											"name",
											"organizationId",
											"createdAt",
											"updatedAt",
										],
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const session = ctx.context.session;
			const organizationId =
				ctx.body.data.organizationId || session.session.activeOrganizationId;
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const member = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId,
			});

			if (!member) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM,
				);
			}

			const canUpdate = await hasPermission(
				{
					role: member.role,
					options: ctx.context.orgOptions,
					permissions: {
						team: ["update"],
					},
					organizationId,
				},
				ctx,
			);

			if (!canUpdate) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM,
				);
			}

			const team = await adapter.findTeamById({
				teamId: ctx.body.teamId,
				organizationId,
			});

			if (!team || team.organizationId !== organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
				);
			}

			const { name, organizationId: __, ...additionalFields } = ctx.body.data;

			const organization = await adapter.findOrganizationById(organizationId);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			const updates = {
				name,
				...additionalFields,
			};

			// Run beforeUpdateTeam hook
			if (options?.organizationHooks?.beforeUpdateTeam) {
				const response = await options?.organizationHooks.beforeUpdateTeam({
					team,
					updates,
					user: session.user,
					organization,
				});
				if (response && typeof response === "object" && "data" in response) {
					// Allow the hook to modify the updates
					const modifiedUpdates = response.data;
					const updatedTeam = await adapter.updateTeam(
						team.id,
						modifiedUpdates,
					);

					// Run afterUpdateTeam hook
					if (options?.organizationHooks?.afterUpdateTeam) {
						await options?.organizationHooks.afterUpdateTeam({
							team: updatedTeam,
							user: session.user,
							organization,
						});
					}

					return ctx.json(updatedTeam);
				}
			}

			const updatedTeam = await adapter.updateTeam(team.id, updates);

			// Run afterUpdateTeam hook
			if (options?.organizationHooks?.afterUpdateTeam) {
				await options?.organizationHooks.afterUpdateTeam({
					team: updatedTeam,
					user: session.user,
					organization,
				});
			}

			return ctx.json(updatedTeam);
		},
	);
};

const listOrganizationTeamsQuerySchema = z.optional(
	z.object({
		organizationId: z
			.string()
			.meta({
				description: `The organization ID which the teams are under to list. Defaults to the users active organization. Eg: "organization-id"`,
			})
			.optional(),
	}),
);

export const listOrganizationTeams = <O extends OrganizationOptions>(
	options: O,
) =>
	createAuthEndpoint(
		"/organization/list-teams",
		{
			method: "GET",
			query: listOrganizationTeamsQuerySchema,
			metadata: {
				openapi: {
					description: "List all teams in an organization",
					responses: {
						"200": {
							description: "Teams retrieved successfully",
							content: {
								"application/json": {
									schema: {
										type: "array",
										items: {
											type: "object",
											properties: {
												id: {
													type: "string",
													description: "Unique identifier of the team",
												},
												name: {
													type: "string",
													description: "Name of the team",
												},
												organizationId: {
													type: "string",
													description:
														"ID of the organization the team belongs to",
												},
												createdAt: {
													type: "string",
													format: "date-time",
													description: "Timestamp when the team was created",
												},
												updatedAt: {
													type: "string",
													format: "date-time",
													description:
														"Timestamp when the team was last updated",
												},
											},
											required: [
												"id",
												"name",
												"organizationId",
												"createdAt",
												"updatedAt",
											],
										},
										description:
											"Array of team objects within the organization",
									},
								},
							},
						},
					},
				},
			},
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
		},
		async (ctx) => {
			const session = ctx.context.session;
			const organizationId =
				ctx.query?.organizationId || session?.session.activeOrganizationId;
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const member = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: organizationId || "",
			});
			if (!member) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION,
				);
			}
			const teams = await adapter.listTeams(organizationId);
			return ctx.json(teams);
		},
	);

const setActiveTeamBodySchema = z.object({
	teamId: z
		.string()
		.meta({
			description:
				"The team id to set as active. It can be null to unset the active team",
		})
		.nullable()
		.optional(),
});

export const setActiveTeam = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/set-active-team",
		{
			method: "POST",
			body: setActiveTeamBodySchema,
			requireHeaders: true,
			use: [orgSessionMiddleware, orgMiddleware],
			metadata: {
				openapi: {
					description:
						"Set the active team for the current active organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										description: "The team",
										$ref: "#/components/schemas/Team",
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const adapter = getOrgAdapter(ctx.context, ctx.context.orgOptions);
			const session = ctx.context.session;

			if (ctx.body.teamId === null) {
				const sessionTeamId = session.session.activeTeamId;
				if (!sessionTeamId) {
					return ctx.json(null);
				}

				const updatedSession = await adapter.setActiveTeam(
					session.session.token,
					null,
					ctx,
				);

				await setSessionCookie(ctx, {
					session: updatedSession,
					user: session.user,
				});

				return ctx.json(null);
			}

			let teamId: string;

			if (!ctx.body.teamId) {
				const sessionTeamId = session.session.activeTeamId;
				if (!sessionTeamId) {
					return ctx.json(null);
				} else {
					teamId = sessionTeamId;
				}
			} else {
				teamId = ctx.body.teamId;
			}

			const activeOrganizationId = session.session.activeOrganizationId;

			if (!activeOrganizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}

			const team = await adapter.findTeamById({
				teamId,
				organizationId: activeOrganizationId,
			});

			if (!team) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
				);
			}

			const member = await adapter.findTeamMember({
				teamId,
				userId: session.user.id,
			});

			if (!member) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_TEAM,
				);
			}

			const updatedSession = await adapter.setActiveTeam(
				session.session.token,
				team.id,
				ctx,
			);

			await setSessionCookie(ctx, {
				session: updatedSession,
				user: session.user,
			});

			return ctx.json(team);
		},
	);

export const listUserTeams = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/list-user-teams",
		{
			method: "GET",
			metadata: {
				openapi: {
					description: "List all teams that the current user is a part of.",
					responses: {
						"200": {
							description: "Teams retrieved successfully",
							content: {
								"application/json": {
									schema: {
										type: "array",
										items: {
											type: "object",
											description: "The team",
											$ref: "#/components/schemas/Team",
										},
										description:
											"Array of team objects within the organization",
									},
								},
							},
						},
					},
				},
			},
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
		},
		async (ctx) => {
			const session = ctx.context.session;
			const adapter = getOrgAdapter(ctx.context, ctx.context.orgOptions);
			const teams = await adapter.listTeamsByUser({
				userId: session.user.id,
			});

			// Only return teams that belong to an organization the caller is
			// actually a member of. A teamMember row on its own is not enough —
			// a stray row could otherwise surface another organization's team
			// metadata.
			const orgIds = [...new Set(teams.map((team) => team.organizationId))];
			const memberships = await Promise.all(
				orgIds.map((organizationId) =>
					adapter.checkMembership({
						userId: session.user.id,
						organizationId,
					}),
				),
			);
			const memberOrgIds = new Set(
				orgIds.filter((_, index) => memberships[index]),
			);

			return ctx.json(
				teams.filter((team) => memberOrgIds.has(team.organizationId)),
			);
		},
	);

const listTeamMembersQuerySchema = z.optional(
	z.object({
		teamId: z.string().optional().meta({
			description:
				"The team whose members we should return. If this is not provided the members of the current active team get returned.",
		}),
	}),
);

export const listTeamMembers = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/list-team-members",
		{
			method: "GET",
			query: listTeamMembersQuerySchema,
			metadata: {
				openapi: {
					description: "List the members of the given team.",
					responses: {
						"200": {
							description: "Teams retrieved successfully",
							content: {
								"application/json": {
									schema: {
										type: "array",
										items: {
											type: "object",
											description: "The team member",
											properties: {
												id: {
													type: "string",
													description: "Unique identifier of the team member",
												},
												userId: {
													type: "string",
													description: "The user ID of the team member",
												},
												teamId: {
													type: "string",
													description:
														"The team ID of the team the team member is in",
												},
												createdAt: {
													type: "string",
													format: "date-time",
													description:
														"Timestamp when the team member was created",
												},
											},
											required: ["id", "userId", "teamId", "createdAt"],
										},
										description: "Array of team member objects within the team",
									},
								},
							},
						},
					},
				},
			},
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
		},
		async (ctx) => {
			const session = ctx.context.session;
			const adapter = getOrgAdapter(ctx.context, ctx.context.orgOptions);
			const teamId = ctx.query?.teamId || session?.session.activeTeamId;
			if (!teamId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM,
				);
			}
			// Resolve the team to its organization and confirm the caller is a
			// member of that organization. A teamMember row alone is not
			// sufficient: a stray row pointing at another organization's team
			// would otherwise return that team's member list. Organization
			// membership is the requirement here.
			const team = await adapter.findTeamById({ teamId });
			if (!team) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
				);
			}
			const isOrgMember = await adapter.checkMembership({
				userId: session.user.id,
				organizationId: team.organizationId,
			});
			if (!isOrgMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_TEAM,
				);
			}
			const member = await adapter.findTeamMember({
				userId: session.user.id,
				teamId,
			});

			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_TEAM,
				);
			}
			const members = await adapter.listTeamMembers({
				teamId,
			});
			return ctx.json(members);
		},
	);

const addTeamMemberBodySchema = z.object({
	teamId: z.string().meta({
		description: "The team the user should be a member of.",
	}),

	userId: z.coerce.string().meta({
		description:
			"The user Id which represents the user to be added as a member.",
	}),

	organizationId: z
		.string()
		.meta({
			description:
				"The organization ID which the team falls under. If not provided, it will default to the user's active organization.",
		})
		.optional(),
});

export const addTeamMember = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/add-team-member",
		{
			method: "POST",
			body: addTeamMemberBodySchema,
			metadata: {
				openapi: {
					description: "The newly created member",
					responses: {
						"200": {
							description: "Team member created successfully",
							content: {
								"application/json": {
									schema: {
										type: "object",
										description: "The team member",
										properties: {
											id: {
												type: "string",
												description: "Unique identifier of the team member",
											},
											userId: {
												type: "string",
												description: "The user ID of the team member",
											},
											teamId: {
												type: "string",
												description:
													"The team ID of the team the team member is in",
											},
											createdAt: {
												type: "string",
												format: "date-time",
												description:
													"Timestamp when the team member was created",
											},
										},
										required: ["id", "userId", "teamId", "createdAt"],
									},
								},
							},
						},
					},
				},
			},
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
		},
		async (ctx) => {
			const session = ctx.context.session;
			const adapter = getOrgAdapter(ctx.context, ctx.context.orgOptions);

			const organizationId =
				ctx.body.organizationId || session.session.activeOrganizationId;

			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			requireTeamMutationTransaction(ctx.context);

			const userBeingAdded = await ctx.context.internalAdapter.findUserById(
				ctx.body.userId,
			);
			if (!userBeingAdded) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "User not found",
				});
			}

			const result = await adapter.admitTeamMember({
				organizationId,
				teamId: ctx.body.teamId,
				userId: ctx.body.userId,
				prepare: async ({ organization, team }) => {
					const transaction = await getCurrentAdapter(ctx.context.adapter);
					const currentMember = await adapter.findMemberByOrgId({
						userId: session.user.id,
						organizationId,
					});
					if (!currentMember) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
						);
					}
					const canUpdateMember = await hasPermission(
						{
							role: currentMember.role,
							options: ctx.context.orgOptions,
							permissions: { member: ["update"] },
							organizationId,
						},
						{ ...ctx, context: { ...ctx.context, adapter: transaction } } as never,
					);
					if (!canUpdateMember) {
						throw APIError.from(
							"FORBIDDEN",
							ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER,
						);
					}
					const target = await adapter.findMemberByOrgId({
						userId: ctx.body.userId,
						organizationId,
					});
					if (!target) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
						);
					}
					if (options?.organizationHooks?.beforeAddTeamMember) {
						await options.organizationHooks.beforeAddTeamMember({
							teamMember: { teamId: ctx.body.teamId, userId: ctx.body.userId },
							team,
							user: userBeingAdded,
							organization,
						});
					}
					return resolveMaximumMembersPerTeam(ctx.context.orgOptions.teams, {
						teamId: ctx.body.teamId,
						organizationId,
						session,
					});
				},
			});
				if (result.status === "limitReached") {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.TEAM_MEMBER_LIMIT_REACHED,
					);
				}
				if (result.status === "teamNotFound") {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
					);
				}
				if (result.status === "organizationNotFound") {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
				if (result.status === "transactionRequired") {
					requireTeamMutationTransaction(ctx.context);
					throw new Error("unreachable");
				}
			const teamMember = result.member;
			const team = result.team;
			const organization = result.organization;

			// Run afterAddTeamMember hook
			if (options?.organizationHooks?.afterAddTeamMember) {
				await options?.organizationHooks.afterAddTeamMember({
					teamMember,
					team,
					user: userBeingAdded,
					organization,
				});
			}

			return ctx.json(teamMember);
		},
	);

const removeTeamMemberBodySchema = z.object({
	teamId: z.string().meta({
		description: "The team the user should be removed from.",
	}),

	userId: z.coerce.string().meta({
		description: "The user which should be removed from the team.",
	}),

	organizationId: z
		.string()
		.meta({
			description:
				"The organization ID which the team falls under. If not provided, it will default to the user's active organization.",
		})
		.optional(),
});

export const removeTeamMember = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/remove-team-member",
		{
			method: "POST",
			body: removeTeamMemberBodySchema,
			metadata: {
				openapi: {
					description: "Remove a member from a team",
					responses: {
						"200": {
							description: "Team member removed successfully",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											message: {
												type: "string",
												description:
													"Confirmation message indicating successful removal",
												enum: ["Team member removed successfully."],
											},
										},
										required: ["message"],
									},
								},
							},
						},
					},
				},
			},
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
		},
		async (ctx) => {
			const session = ctx.context.session;
			const adapter = getOrgAdapter(ctx.context, ctx.context.orgOptions);

			const organizationId =
				ctx.body.organizationId || session.session.activeOrganizationId;

			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}

			const currentMember = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: organizationId,
			});

			if (!currentMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
				);
			}

			const canDeleteMember = await hasPermission(
				{
					role: currentMember.role,
					options: ctx.context.orgOptions,
					permissions: {
						member: ["delete"],
					},
					organizationId: organizationId,
				},
				ctx,
			);

			if (!canDeleteMember) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER,
				);
			}

			const toBeAddedMember = await adapter.findMemberByOrgId({
				userId: ctx.body.userId,
				organizationId: organizationId,
			});

			if (!toBeAddedMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
				);
			}

			const team = await adapter.findTeamById({
				teamId: ctx.body.teamId,
				organizationId: organizationId,
			});

			if (!team) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
				);
			}

			const organization = await adapter.findOrganizationById(organizationId);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			const userBeingRemoved = await ctx.context.internalAdapter.findUserById(
				ctx.body.userId,
			);
			if (!userBeingRemoved) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "User not found",
				});
			}

			const teamMember = await adapter.findTeamMember({
				teamId: ctx.body.teamId,
				userId: ctx.body.userId,
			});

			if (!teamMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_TEAM,
				);
			}

			// Run beforeRemoveTeamMember hook
			if (options?.organizationHooks?.beforeRemoveTeamMember) {
				await options?.organizationHooks.beforeRemoveTeamMember({
					teamMember,
					team,
					user: userBeingRemoved,
					organization,
				});
			}

			await adapter.removeTeamMember({
				teamId: ctx.body.teamId,
				userId: ctx.body.userId,
			});

			// Run afterRemoveTeamMember hook
			if (options?.organizationHooks?.afterRemoveTeamMember) {
				await options?.organizationHooks.afterRemoveTeamMember({
					teamMember,
					team,
					user: userBeingRemoved,
					organization,
				});
			}

			return ctx.json({ message: "Team member removed successfully." });
		},
	);
