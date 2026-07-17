import type { GenerateIdFn, LiteralString } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import * as z from "zod";
import { getSessionFromCtx } from "../../../api/routes";
import { setSessionCookie } from "../../../cookies";
import type { InferAdditionalFieldsFromPluginOptions } from "../../../db";
import { toZodSchema } from "../../../db";
import { getDate } from "../../../utils/date";
import { defaultRoles } from "../access/statement";
import { getOrgAdapter, resolveMaximumMembersPerTeam } from "../adapter";
import { orgMiddleware, orgSessionMiddleware } from "../call";
import { ORGANIZATION_ERROR_CODES } from "../error-codes";
import { hasPermission } from "../has-permission";
import { parseRoles } from "../organization";
import type {
	InferInvitation,
	InferOrganizationRolesFromOption,
	Invitation,
	Member,
} from "../schema";
import type { OrganizationOptions } from "../types";

const ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED = {
	code: "ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED",
	message:
		"Organization lifecycle mutations require rollback-capable database transactions",
} as const;

function requireOrganizationLifecycleTransaction(
	context: Parameters<typeof getOrgAdapter>[0],
) {
	if (
		typeof context.adapter.options?.adapterConfig.transaction !== "function"
	) {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED,
		);
	}
}

const baseInvitationSchema = z.object({
	email: z.string().meta({
		description: "The email address of the user to invite",
	}),
	role: z
		.union([
			z.string().meta({
				description: "The role to assign to the user",
			}),
			z.array(
				z.string().meta({
					description: "The roles to assign to the user",
				}),
			),
		])
		.meta({
			description:
				'The role(s) to assign to the user. It can be `admin`, `member`, owner. Eg: "member"',
		}),
	organizationId: z
		.string()
		.meta({
			description: "The organization ID to invite the user to",
		})
		.optional(),
	resend: z
		.boolean()
		.meta({
			description:
				"Resend the invitation email, if the user is already invited. Eg: true",
		})
		.optional(),
	teamId: z.union([
		z
			.string()
			.meta({
				description: "The team ID to invite the user to",
			})
			.optional(),
		z
			.array(z.string())
			.meta({
				description: "The team IDs to invite the user to",
			})
			.optional(),
	]),
});

type DynamicOrganizationRole<O extends OrganizationOptions> = O extends {
	dynamicAccessControl: { enabled: true };
}
	? LiteralString
	: never;

type OrganizationInvitationRole<O extends OrganizationOptions> =
	| InferOrganizationRolesFromOption<O>
	| DynamicOrganizationRole<O>;

type ConfiguredGenerateIdOption =
	| GenerateIdFn
	| false
	| "serial"
	| "uuid"
	| undefined;

const getAdvancedGenerateId = (
	advancedOptions: unknown,
): GenerateIdFn | undefined => {
	if (typeof advancedOptions !== "object" || advancedOptions === null) {
		return undefined;
	}
	const generateId = (advancedOptions as { generateId?: unknown }).generateId;
	if (typeof generateId !== "function") {
		return undefined;
	}
	return generateId as GenerateIdFn;
};

const hasBuiltInOpaqueInvitationIdGeneration = ({
	advancedGenerateId,
	databaseGenerateId,
}: {
	advancedGenerateId: GenerateIdFn | undefined;
	databaseGenerateId: ConfiguredGenerateIdOption;
}) =>
	advancedGenerateId === undefined &&
	(databaseGenerateId === undefined || databaseGenerateId === "uuid");

const shouldRequireVerifiedEmailForInvitationIdAction = ({
	organizationOptions,
	advancedGenerateId,
	databaseGenerateId,
}: {
	organizationOptions: OrganizationOptions;
	advancedGenerateId: GenerateIdFn | undefined;
	databaseGenerateId: ConfiguredGenerateIdOption;
}) => {
	if (organizationOptions.requireEmailVerificationOnInvitation !== undefined) {
		return organizationOptions.requireEmailVerificationOnInvitation;
	}
	return !hasBuiltInOpaqueInvitationIdGeneration({
		advancedGenerateId,
		databaseGenerateId,
	});
};

export const createInvitation = <O extends OrganizationOptions>(option: O) => {
	const additionalFieldsSchema = toZodSchema({
		fields: option?.schema?.invitation?.additionalFields || {},
		isClientSide: true,
	});

	return createAuthEndpoint(
		"/organization/invite-member",
		{
			method: "POST",
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			body: z.object({
				...baseInvitationSchema.shape,
				...additionalFieldsSchema.shape,
			}),
			metadata: {
				$Infer: {
					body: {} as {
						/**
						 * The email address of the user
						 * to invite
						 */
						email: string;
						/**
						 * The role to assign to the user
						 */
						role:
							| OrganizationInvitationRole<O>
							| OrganizationInvitationRole<O>[];
						/**
						 * The organization ID to invite
						 * the user to
						 */
						organizationId?: string | undefined;
						/**
						 * Resend the invitation email, if
						 * the user is already invited
						 */
						resend?: boolean | undefined;
					} & (O extends { teams: { enabled: true } }
						? {
								/**
								 * The team the user is
								 * being invited to.
								 */
								teamId?: (string | string[]) | undefined;
							}
						: {}) &
						InferAdditionalFieldsFromPluginOptions<"invitation", O, false>,
				},
				openapi: {
					operationId: "createOrganizationInvitation",
					description: "Create an invitation to an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											id: {
												type: "string",
											},
											email: {
												type: "string",
											},
											role: {
												type: "string",
											},
											organizationId: {
												type: "string",
											},
											inviterId: {
												type: "string",
											},
											status: {
												type: "string",
											},
											expiresAt: {
												type: "string",
											},
											createdAt: {
												type: "string",
											},
										},
										required: [
											"id",
											"email",
											"role",
											"organizationId",
											"inviterId",
											"status",
											"expiresAt",
											"createdAt",
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
				ctx.body.organizationId || session.session.activeOrganizationId;
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			const email = ctx.body.email.toLowerCase();
			const isValidEmail = z.email().safeParse(email);
			if (!isValidEmail.success) {
				throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_EMAIL);
			}

			const adapter = getOrgAdapter<O>(ctx.context, option as O);
			const member = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: organizationId,
			});
			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
				);
			}
			const canInvite = await hasPermission(
				{
					role: member.role,
					options: ctx.context.orgOptions,
					permissions: {
						invitation: ["create"],
					},
					organizationId,
				},
				ctx,
			);

			if (!canInvite) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION,
				);
			}

			const creatorRole = ctx.context.orgOptions.creatorRole || "owner";

			const roles = parseRoles(ctx.body.role);

			const rolesArray = roles
				.split(",")
				.map((r) => r.trim())
				.filter(Boolean);
			const defaults = Object.keys(defaultRoles);
			const customRoles = Object.keys(ctx.context.orgOptions.roles || {});
			const validStaticRoles = new Set([...defaults, ...customRoles]);

			const unknownRoles = rolesArray.filter(
				(role) => !validStaticRoles.has(role),
			);

			if (unknownRoles.length > 0) {
				if (ctx.context.orgOptions.dynamicAccessControl?.enabled) {
					const foundRoles = await ctx.context.adapter.findMany({
						model: "organizationRole",
						where: [
							{ field: "organizationId", value: organizationId },
							{ field: "role", value: unknownRoles, operator: "in" },
						],
					});
					const foundRoleNames = foundRoles.map((r: any) => r.role);
					const stillInvalid = unknownRoles.filter(
						(r) => !foundRoleNames.includes(r),
					);

					if (stillInvalid.length > 0) {
						throw new APIError("BAD_REQUEST", {
							message: `${ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND}: ${stillInvalid.join(", ")}`,
						});
					}
				} else {
					throw new APIError("BAD_REQUEST", {
						message: `${ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND}: ${unknownRoles.join(", ")}`,
					});
				}
			}

			if (
				!member.role
					.split(",")
					.map((r) => r.trim())
					.includes(creatorRole) &&
				roles.split(",").includes(creatorRole)
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE,
				);
			}

			const alreadyMember = await adapter.findMemberByEmail({
				email: email,
				organizationId: organizationId,
			});
			if (alreadyMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION,
				);
			}
			const alreadyInvited = await adapter.findPendingInvitation({
				email: email,
				organizationId: organizationId,
			});
			if (
				alreadyInvited.length &&
				!ctx.body.resend &&
				!ctx.context.orgOptions.cancelPendingInvitationsOnReInvite
			) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION,
				);
			}

			const organization = await adapter.findOrganizationById(organizationId);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			// If resend is true and there's an existing invitation, reuse it
			if (alreadyInvited.length && ctx.body.resend) {
				const existingInvitation = alreadyInvited[0];

				// Update the invitation's expiration date using the same logic as createInvitation
				const defaultExpiration = 60 * 60 * 48; // 48 hours in seconds
				const newExpiresAt = getDate(
					ctx.context.orgOptions.invitationExpiresIn || defaultExpiration,
					"sec",
				);

				const persistResend = async () => {
					const transaction = await getCurrentAdapter(ctx.context.adapter);
					await transaction.update({
						model: "invitation",
						where: [{ field: "id", value: existingInvitation!.id }],
						update: { expiresAt: newExpiresAt },
					});
					const updated = { ...existingInvitation, expiresAt: newExpiresAt };
					if (ctx.context.options.durableDelivery) {
						const invitationEmail = updated.email!.toLowerCase();
						await ctx.context.options.durableDelivery.enqueue(transaction, {
							kind: "organization.invitation",
							sourceKey: `organization-invitation:${updated.id}:${newExpiresAt.toISOString()}`,
							organizationId,
							actorId: session.user.id,
							channel: "email",
							destination: invitationEmail,
							payload: {
								template: "organization-invitation",
								to: invitationEmail,
								role: updated.role,
								organizationName: organization.name,
								inviterName: session.user.name,
								acceptanceUrl:
									ctx.context.options.durableDelivery.createInvitationUrl(
										updated.id!,
									),
							},
							semanticExpiresAt: newExpiresAt,
						});
					}
					return updated;
				};
				const updatedInvitation = ctx.context.options.durableDelivery
					? await runWithTransaction(ctx.context.adapter, persistResend)
					: await persistResend();

				if (
					!ctx.context.options.durableDelivery &&
					ctx.context.orgOptions.sendInvitationEmail
				) {
					await ctx.context.runInBackgroundOrAwait(
						ctx.context.orgOptions.sendInvitationEmail(
							{
								id: updatedInvitation.id!,
								role: updatedInvitation.role! as string,
								email: updatedInvitation.email!.toLowerCase(),
								organization: organization,
								inviter: {
									...member,
									user: session.user,
								},
								invitation: updatedInvitation as unknown as Invitation,
							},
							ctx.request,
						),
					);
				}

				return ctx.json(updatedInvitation as unknown as InferInvitation<O>);
			}

			const shouldCancelExisting =
				alreadyInvited.length &&
				Boolean(ctx.context.orgOptions.cancelPendingInvitationsOnReInvite);

			const invitationLimit =
				typeof ctx.context.orgOptions.invitationLimit === "function"
					? await ctx.context.orgOptions.invitationLimit(
							{
								user: session.user,
								organization,
								member: member as Member,
							},
							ctx.context,
						)
					: (ctx.context.orgOptions.invitationLimit ?? 100);

			const pendingInvitations = await adapter.findPendingInvitations({
				organizationId: organizationId,
			});

			if (pendingInvitations.length >= invitationLimit) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.INVITATION_LIMIT_REACHED,
				);
			}

			if (
				ctx.context.orgOptions.teams?.enabled &&
				"teamId" in ctx.body &&
				ctx.body.teamId
			) {
				const requestedTeamIds =
					typeof ctx.body.teamId === "string"
						? [ctx.body.teamId]
						: (ctx.body.teamId as string[]);
				if (requestedTeamIds.some((id) => id.includes(","))) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.INVALID_TEAM_ID,
					);
				}
				// Every requested team must belong to the organization the
				// invitation is for, so the stored team IDs stay consistent with
				// the invitation's organization. This runs regardless of whether
				// a team-size limit is configured.
				for (const teamId of requestedTeamIds) {
					const team = await adapter.findTeamById({
						teamId,
						organizationId,
					});
					if (!team) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
						);
					}
				}
			}

			if (
				ctx.context.orgOptions.teams &&
				ctx.context.orgOptions.teams.enabled &&
				typeof ctx.context.orgOptions.teams.maximumMembersPerTeam !==
					"undefined" &&
				"teamId" in ctx.body &&
				ctx.body.teamId
			) {
				const teamIds =
					typeof ctx.body.teamId === "string"
						? [ctx.body.teamId as string]
						: (ctx.body.teamId as string[]);

				for (const teamId of teamIds) {
					const team = await adapter.findTeamById({
						teamId,
						organizationId: organizationId,
						includeTeamMembers: true,
					});

					if (!team) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
						);
					}

					const maximumMembersPerTeam =
						typeof ctx.context.orgOptions.teams.maximumMembersPerTeam ===
						"function"
							? await ctx.context.orgOptions.teams.maximumMembersPerTeam({
									teamId,
									session: session,
									organizationId: organizationId,
								})
							: ctx.context.orgOptions.teams.maximumMembersPerTeam;
					if (team.members.length >= maximumMembersPerTeam) {
						throw APIError.from(
							"FORBIDDEN",
							ORGANIZATION_ERROR_CODES.TEAM_MEMBER_LIMIT_REACHED,
						);
					}
				}
			}

			const teamIds: string[] =
				"teamId" in ctx.body
					? typeof ctx.body.teamId === "string"
						? [ctx.body.teamId as string]
						: ((ctx.body.teamId as string[]) ?? [])
					: [];

			const {
				email: _,
				role: __,
				organizationId: ___,
				resend: ____,
				...additionalFields
			} = ctx.body;

			let invitationData = {
				role: roles,
				email: email,
				organizationId: organizationId,
				teamIds,
				...(additionalFields ? additionalFields : {}),
			};

			// Run beforeCreateInvitation hook
			if (option?.organizationHooks?.beforeCreateInvitation) {
				const response = await option?.organizationHooks.beforeCreateInvitation(
					{
						invitation: {
							...invitationData,
							inviterId: session.user.id,
							teamId: teamIds.length > 0 ? teamIds[0] : undefined,
						},
						inviter: session.user,
						organization,
					},
				);
				if (response && typeof response === "object" && "data" in response) {
					invitationData = {
						...invitationData,
						...response.data,
					};
				}
			}

			const persistInvitation = async () => {
				if (shouldCancelExisting) {
					await adapter.updateInvitation({
						invitationId: alreadyInvited[0]!.id,
						status: "canceled",
					});
				}
				const invitation = await adapter.createInvitation({
					invitation: invitationData,
					user: session.user,
				});
				if (ctx.context.options.durableDelivery) {
					const transaction = await getCurrentAdapter(ctx.context.adapter);
					await ctx.context.options.durableDelivery.enqueue(transaction, {
						kind: "organization.invitation",
						sourceKey: `organization-invitation:${invitation.id}:${invitation.expiresAt.toISOString()}`,
						organizationId,
						actorId: session.user.id,
						channel: "email",
						destination: invitation.email.toLowerCase(),
						payload: {
							template: "organization-invitation",
							to: invitation.email.toLowerCase(),
							role: invitation.role,
							organizationName: organization.name,
							inviterName: session.user.name,
							acceptanceUrl:
								ctx.context.options.durableDelivery.createInvitationUrl(
									invitation.id,
								),
						},
						semanticExpiresAt: invitation.expiresAt,
					});
				}
				return invitation;
			};
			const invitation = ctx.context.options.durableDelivery
				? await runWithTransaction(ctx.context.adapter, persistInvitation)
				: await persistInvitation();

			if (
				!ctx.context.options.durableDelivery &&
				ctx.context.orgOptions.sendInvitationEmail
			) {
				await ctx.context.runInBackgroundOrAwait(
					ctx.context.orgOptions.sendInvitationEmail(
						{
							id: invitation.id,
							role: invitation.role,
							email: invitation.email.toLowerCase(),
							organization: organization,
							inviter: {
								...(member as Member),
								user: session.user,
							},
							invitation,
						},
						ctx.request,
					),
				);
			}

			// Run afterCreateInvitation hook
			if (option?.organizationHooks?.afterCreateInvitation) {
				await option?.organizationHooks.afterCreateInvitation({
					invitation: invitation as unknown as Invitation,
					inviter: session.user,
					organization,
				});
			}

			return ctx.json(invitation);
		},
	);
};

const acceptInvitationBodySchema = z.object({
	invitationId: z.string().meta({
		description: "The ID of the invitation to accept",
	}),
});

export const acceptInvitation = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/accept-invitation",
		{
			method: "POST",
			body: acceptInvitationBodySchema,
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			metadata: {
				openapi: {
					description: "Accept an invitation to an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											invitation: {
												type: "object",
											},
											member: {
												type: "object",
											},
										},
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
			const adapter = getOrgAdapter<O>(ctx.context, options);
			requireOrganizationLifecycleTransaction(ctx.context);
			const invitation = await adapter.findInvitationById(
				ctx.body.invitationId,
			);

			if (
				!invitation ||
				invitation.expiresAt < new Date() ||
				invitation.status !== "pending"
			) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
				);
			}

			// TODO(#9124): `session.user.email` becomes nullable in v2 — this
			// comparison and its mirrors in rejectInvitation, getInvitation, and
			// listUserInvitations need null handling.
			if (invitation.email.toLowerCase() !== session.user.email.toLowerCase()) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION,
				);
			}

			if (
				shouldRequireVerifiedEmailForInvitationIdAction({
					organizationOptions: ctx.context.orgOptions,
					advancedGenerateId: getAdvancedGenerateId(
						ctx.context.options.advanced,
					),
					databaseGenerateId:
						ctx.context.options.advanced?.database?.generateId,
				}) &&
				!session.user.emailVerified
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION,
				);
			}

			const organization = await adapter.findOrganizationById(
				invitation.organizationId,
			);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			// Run beforeAcceptInvitation hook
			if (options?.organizationHooks?.beforeAcceptInvitation) {
				await options?.organizationHooks.beforeAcceptInvitation({
					invitation: invitation as unknown as Invitation,
					user: session.user,
					organization,
				});
			}

			type AcceptedInvitation = NonNullable<
				Awaited<ReturnType<typeof adapter.updateInvitation>>
			>;
			type AcceptedMember = Awaited<ReturnType<typeof adapter.createMember>>;
			let acceptance:
				| {
						invitation: AcceptedInvitation;
						member: AcceptedMember;
						singleTeamId: string | null;
				  }
				| undefined;
			let activeSession = await adapter.setActiveOrganization(
				session.session.token,
				invitation.organizationId,
				ctx,
				{
					afterCapture: async () => {
						// Everything that makes an invitation accepted is owned by the same
						// transaction as managed successor issuance. Re-read every mutable
						// input after capture so a stale preflight can never be committed.
						const liveInvitation = await adapter.findInvitationById(
							ctx.body.invitationId,
						);
						if (
							!liveInvitation ||
							liveInvitation.status !== "pending" ||
							liveInvitation.expiresAt < new Date() ||
							liveInvitation.organizationId !== invitation.organizationId ||
							liveInvitation.email.toLowerCase() !==
								session.user.email.toLowerCase()
						) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
							);
						}
						const transaction = await getCurrentAdapter(ctx.context.adapter);
						const organizationLock = await transaction.findOne<{
							id: string;
							name: string;
						}>({
							model: "organization",
							where: [
								{ field: "id", value: liveInvitation.organizationId },
							],
						});
						if (!organizationLock) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
							);
						}
						await transaction.update({
							model: "organization",
							where: [{ field: "id", value: organizationLock.id }],
							update: { name: organizationLock.name },
						});
						const liveOrganization = await adapter.findOrganizationById(
							organizationLock.id,
						);
						if (!liveOrganization) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
							);
						}
						const membershipLimit =
							ctx.context.orgOptions?.membershipLimit || 100;
						const limit =
							typeof membershipLimit === "number"
								? membershipLimit
								: await membershipLimit(session.user, liveOrganization);
						if (
							(await adapter.countMembers({
								organizationId: liveInvitation.organizationId,
							})) >= limit
						) {
							throw APIError.from(
								"FORBIDDEN",
								ORGANIZATION_ERROR_CODES.ORGANIZATION_MEMBERSHIP_LIMIT_REACHED,
							);
						}
						const acceptedInvitation = await adapter.updateInvitation({
							invitationId: liveInvitation.id,
							status: "accepted",
							fromStatus: "pending",
						});
						if (!acceptedInvitation) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
							);
						}

						if (
							ctx.context.orgOptions.teams &&
							ctx.context.orgOptions.teams.enabled &&
							"teamId" in acceptedInvitation &&
							acceptedInvitation.teamId
						) {
							const teamIds = (acceptedInvitation.teamId as string).split(",");

							for (const teamId of teamIds) {
								// Confirm the team still belongs to the accepted invitation's
								// organization before adding the member.
								const team = await adapter.findTeamById({
									teamId,
									organizationId: acceptedInvitation.organizationId,
								});
								if (!team) {
									throw APIError.from(
										"BAD_REQUEST",
										ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
									);
								}

								const maximumMembersPerTeam =
									await resolveMaximumMembersPerTeam(
										ctx.context.orgOptions.teams,
										{
											teamId,
											organizationId: acceptedInvitation.organizationId,
											session,
										},
									);
								if (maximumMembersPerTeam !== undefined) {
									const result = await adapter.addTeamMemberWithLimit({
										teamId,
										userId: session.user.id,
										maximumMembersPerTeam,
									});
									if (result.status === "limitReached") {
										throw APIError.from(
											"FORBIDDEN",
											ORGANIZATION_ERROR_CODES.TEAM_MEMBER_LIMIT_REACHED,
										);
									}
								} else {
									await adapter.findOrCreateTeamMember({
										teamId,
										userId: session.user.id,
									});
								}
							}
						}

						const acceptedMember = await adapter.createMember({
							organizationId: acceptedInvitation.organizationId,
							userId: session.user.id,
							role: acceptedInvitation.role,
							createdAt: new Date(),
						});
						acceptance = {
							invitation: acceptedInvitation as AcceptedInvitation,
							member: acceptedMember as AcceptedMember,
							singleTeamId:
								"teamId" in acceptedInvitation &&
								typeof acceptedInvitation.teamId === "string" &&
								!acceptedInvitation.teamId.includes(",")
									? acceptedInvitation.teamId
									: null,
						};
						},
					},
				);
			if (!acceptance) {
				throw new Error("Invitation acceptance transaction did not produce a result");
			}
			const {
				invitation: acceptedI,
				member: acceptedMember,
				singleTeamId,
			} = acceptance;
			if (singleTeamId) {
				try {
					if (
						(activeSession as typeof activeSession & {
							activeOrganizationId?: string | null;
						}).activeOrganizationId !== acceptedI.organizationId
					) {
						throw APIError.from(
							"FORBIDDEN",
							ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
						);
					}
					const [team, teamMember] = await Promise.all([
						adapter.findTeamById({
							teamId: singleTeamId,
							organizationId: acceptedI.organizationId,
						}),
						adapter.findTeamMember({
							teamId: singleTeamId,
							userId: session.user.id,
						}),
					]);
					if (!team || !teamMember) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
						);
					}
					activeSession = await adapter.setActiveTeam(
						activeSession.token,
						team.id,
						ctx,
					);
				} catch (error) {
					await setSessionCookie(ctx, { session: activeSession, user: session.user });
					throw error;
				}
			}
			await setSessionCookie(ctx, { session: activeSession, user: session.user });

			if (options?.organizationHooks?.afterAcceptInvitation) {
				await options?.organizationHooks.afterAcceptInvitation({
					invitation: acceptedI as unknown as Invitation,
					member: acceptedMember,
					user: session.user,
					organization,
				});
			}
			return ctx.json({
				invitation: acceptedI,
				member: acceptedMember,
			});
		},
	);

const rejectInvitationBodySchema = z.object({
	invitationId: z.string().meta({
		description: "The ID of the invitation to reject",
	}),
});

export const rejectInvitation = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/reject-invitation",
		{
			method: "POST",
			body: rejectInvitationBodySchema,
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			metadata: {
				openapi: {
					description: "Reject an invitation to an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											invitation: {
												type: "object",
											},
											member: {
												type: "object",
												nullable: true,
											},
										},
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
			const adapter = getOrgAdapter(ctx.context, ctx.context.orgOptions);
			const invitation = await adapter.findInvitationById(
				ctx.body.invitationId,
			);
			if (!invitation || invitation.status !== "pending") {
				throw APIError.from("BAD_REQUEST", {
					message: "Invitation not found!",
					code: "INVITATION_NOT_FOUND",
				});
			}
			if (invitation.email.toLowerCase() !== session.user.email.toLowerCase()) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION,
				);
			}

			if (
				shouldRequireVerifiedEmailForInvitationIdAction({
					organizationOptions: ctx.context.orgOptions,
					advancedGenerateId: getAdvancedGenerateId(
						ctx.context.options.advanced,
					),
					databaseGenerateId:
						ctx.context.options.advanced?.database?.generateId,
				}) &&
				!session.user.emailVerified
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION,
				);
			}

			const organization = await adapter.findOrganizationById(
				invitation.organizationId,
			);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			// Run beforeRejectInvitation hook
			if (options?.organizationHooks?.beforeRejectInvitation) {
				await options?.organizationHooks.beforeRejectInvitation({
					invitation: invitation as unknown as Invitation,
					user: session.user,
					organization,
				});
			}

			const rejectedI = await adapter.updateInvitation({
				invitationId: ctx.body.invitationId,
				status: "rejected",
			});

			// Run afterRejectInvitation hook
			if (options?.organizationHooks?.afterRejectInvitation) {
				await options?.organizationHooks.afterRejectInvitation({
					invitation: rejectedI || (invitation as unknown as Invitation),
					user: session.user,
					organization,
				});
			}

			return ctx.json({
				invitation: rejectedI,
				member: null,
			});
		},
	);

const cancelInvitationBodySchema = z.object({
	invitationId: z.string().meta({
		description: "The ID of the invitation to cancel",
	}),
});

export const cancelInvitation = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/cancel-invitation",
		{
			method: "POST",
			body: cancelInvitationBodySchema,
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			openapi: {
				operationId: "cancelOrganizationInvitation",
				description: "Cancel an invitation to an organization",
				responses: {
					"200": {
						description: "Success",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										invitation: {
											type: "object",
										},
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
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const invitation = await adapter.findInvitationById(
				ctx.body.invitationId,
			);
			if (!invitation) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
				);
			}
			const member = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: invitation.organizationId,
			});
			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
				);
			}
			const canCancel = await hasPermission(
				{
					role: member.role,
					options: ctx.context.orgOptions,
					permissions: {
						invitation: ["cancel"],
					},
					organizationId: invitation.organizationId,
				},
				ctx,
			);

			if (!canCancel) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION,
				);
			}

			const organization = await adapter.findOrganizationById(
				invitation.organizationId,
			);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			// Run beforeCancelInvitation hook
			if (options?.organizationHooks?.beforeCancelInvitation) {
				await options?.organizationHooks.beforeCancelInvitation({
					invitation: invitation as unknown as Invitation,
					cancelledBy: session.user,
					organization,
				});
			}

			const canceledI = await adapter.updateInvitation({
				invitationId: ctx.body.invitationId,
				status: "canceled",
			});

			// Run afterCancelInvitation hook
			if (options?.organizationHooks?.afterCancelInvitation) {
				await options?.organizationHooks.afterCancelInvitation({
					invitation: (canceledI as unknown as Invitation) || invitation,
					cancelledBy: session.user,
					organization,
				});
			}

			return ctx.json(canceledI);
		},
	);

const getInvitationQuerySchema = z.object({
	id: z.string().meta({
		description: "The ID of the invitation to get",
	}),
});

export const getInvitation = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/get-invitation",
		{
			method: "GET",
			use: [orgMiddleware],
			requireHeaders: true,
			query: getInvitationQuerySchema,
			metadata: {
				openapi: {
					description: "Get an invitation by ID",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											id: {
												type: "string",
											},
											email: {
												type: "string",
											},
											role: {
												type: "string",
											},
											organizationId: {
												type: "string",
											},
											inviterId: {
												type: "string",
											},
											status: {
												type: "string",
											},
											expiresAt: {
												type: "string",
											},
											organizationName: {
												type: "string",
											},
											organizationSlug: {
												type: "string",
											},
											inviterEmail: {
												type: "string",
											},
										},
										required: [
											"id",
											"email",
											"role",
											"organizationId",
											"inviterId",
											"status",
											"expiresAt",
											"organizationName",
											"organizationSlug",
											"inviterEmail",
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
			if (!session) {
				throw APIError.fromStatus("UNAUTHORIZED", {
					message: "Not authenticated",
				});
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const invitation = await adapter.findInvitationById(ctx.query.id);
			if (
				!invitation ||
				invitation.status !== "pending" ||
				invitation.expiresAt < new Date()
			) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Invitation not found!",
				});
			}
			if (invitation.email.toLowerCase() !== session.user.email.toLowerCase()) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION,
				);
			}
			if (
				shouldRequireVerifiedEmailForInvitationIdAction({
					organizationOptions: ctx.context.orgOptions,
					advancedGenerateId: getAdvancedGenerateId(
						ctx.context.options.advanced,
					),
					databaseGenerateId:
						ctx.context.options.advanced?.database?.generateId,
				}) &&
				!session.user.emailVerified
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION,
				);
			}
			const organization = await adapter.findOrganizationById(
				invitation.organizationId,
			);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}
			const member = await adapter.findMemberByOrgId({
				userId: invitation.inviterId,
				organizationId: invitation.organizationId,
			});
			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION,
				);
			}

			return ctx.json({
				...invitation,
				organizationName: organization.name,
				organizationSlug: organization.slug,
				inviterEmail: member.user.email,
			});
		},
	);

const listInvitationQuerySchema = z
	.object({
		organizationId: z
			.string()
			.meta({
				description: "The ID of the organization to list invitations for",
			})
			.optional(),
	})
	.optional();

export const listInvitations = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/list-invitations",
		{
			method: "GET",
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
			query: listInvitationQuerySchema,
		},
		async (ctx) => {
			const session = await getSessionFromCtx(ctx);
			if (!session) {
				throw APIError.fromStatus("UNAUTHORIZED", {
					message: "Not authenticated",
				});
			}
			const orgId =
				ctx.query?.organizationId || session.session.activeOrganizationId;
			if (!orgId) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Organization ID is required",
				});
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const isMember = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: orgId,
			});
			if (!isMember) {
				throw APIError.fromStatus("FORBIDDEN", {
					message: "You are not a member of this organization",
				});
			}
			const invitations = await adapter.listInvitations({
				organizationId: orgId,
			});
			return ctx.json(invitations);
		},
	);

/**
 * List all invitations a user has received
 */
export const listUserInvitations = <O extends OrganizationOptions>(
	options: O,
) =>
	createAuthEndpoint(
		"/organization/list-user-invitations",
		{
			method: "GET",
			use: [orgMiddleware],
			query: z
				.object({
					email: z
						.string()
						.meta({
							description:
								"The email of the user to list invitations for. This only works for server side API calls.",
						})
						.optional(),
				})
				.optional(),
			metadata: {
				openapi: {
					description: "List all invitations a user has received",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "array",
										items: {
											type: "object",
											properties: {
												id: {
													type: "string",
												},
												email: {
													type: "string",
												},
												role: {
													type: "string",
												},
												organizationId: {
													type: "string",
												},
												organizationName: {
													type: "string",
												},
												inviterId: {
													type: "string",
													description:
														"The ID of the user who created the invitation",
												},
												teamId: {
													type: "string",
													description:
														"The ID of the team associated with the invitation",
													nullable: true,
												},
												status: {
													type: "string",
												},
												expiresAt: {
													type: "string",
												},
												createdAt: {
													type: "string",
												},
											},
											required: [
												"id",
												"email",
												"role",
												"organizationId",
												"organizationName",
												"inviterId",
												"status",
												"expiresAt",
												"createdAt",
											],
										},
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

			if (ctx.request && ctx.query?.email) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "User email cannot be passed for client side API calls.",
				});
			}

			// When the caller has a session, require an ownership signal stronger
			// than the email string before enumerating invitations targeted at it.
			// Server-side SDK calls without a session are trusted and skip the gate.
			if (session && !session.user.emailVerified) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION,
				);
			}

			const userEmail = session?.user.email || ctx.query?.email;
			if (!userEmail) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Missing session headers, or email query parameter.",
				});
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);

			const invitations = await adapter.listUserInvitations(userEmail);
			const pendingInvitations = invitations.filter(
				(inv) => inv.status === "pending",
			);
			return ctx.json(pendingInvitations);
		},
	);
