import type { LiteralString } from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	isTransactionActive,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
import { whereOperators } from "@clearance/core/db/adapter";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import type { Endpoint } from "@clearance/call";
import * as z from "zod";
import { getSessionFromCtx, sessionMiddleware } from "../../../api";
import { rejectActiveTransactionEndpoint } from "../../../api/dispatch";
import { setSessionCookie } from "../../../cookies";
import type { InferAdditionalFieldsFromPluginOptions } from "../../../db";
import { toZodSchema } from "../../../db/to-zod";
import { readInternalAuthenticationPolicy } from "../../../internal/authentication-policy";
import { defaultRoles } from "../access/statement";
import {
	assertManagedOrganizationTransitionSupported,
	getOrgAdapter,
	resolveMaximumMembersPerTeam,
} from "../adapter";
import { orgMiddleware, orgSessionMiddleware } from "../call";
import { ORGANIZATION_ERROR_CODES } from "../error-codes";
import { hasPermission } from "../has-permission";
import type {
	InferMember,
	InferOrganizationRolesFromOption,
	Member,
} from "../schema";
import type { OrganizationOptions } from "../types";

const ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED = {
	code: "ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED",
	message:
		"Organization lifecycle mutations require rollback-capable database transactions",
} as const;

const ORGANIZATION_LIFECYCLE_NESTED_TRANSACTION = {
	code: "ORGANIZATION_LIFECYCLE_NESTED_TRANSACTION",
	message:
		"Cookie-bearing organization lifecycle routes cannot run inside an existing transaction",
} as const;

/**
 * Member roles are a comma-separated persistence field. Keep one strict parser
 * at the lifecycle boundary so hook output cannot change the meaning of an
 * authorization or owner check after the request was validated.
 */
function canonicalizeRoles(roles: string | string[]): string[] {
	const parsed = (Array.isArray(roles) ? roles : [roles])
		.flatMap((role) => role.split(","))
		.map((role) => role.trim());
	if (parsed.length === 0 || parsed.some((role) => role.length === 0)) {
		throw APIError.fromStatus("BAD_REQUEST");
	}
	if (new Set(parsed).size !== parsed.length) {
		throw APIError.fromStatus("BAD_REQUEST");
	}
	return parsed;
}

function canonicalizeMemberRole(roles: string | string[]): string {
	return canonicalizeRoles(roles).join(",");
}

async function ensureAssignedDynamicRolesExist(
	ctx: Parameters<typeof getOrgAdapter>[0],
	options: OrganizationOptions,
	organizationId: string,
	roles: string[],
) {
	const validStaticRoles = new Set([
		...Object.keys(defaultRoles),
		...Object.keys(options.roles || {}),
	]);
	const dynamicRoles = roles.filter((role) => !validStaticRoles.has(role));
	if (dynamicRoles.length === 0) return;
	if (!options.dynamicAccessControl?.enabled) {
		throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND);
	}
	const found = await ctx.adapter.findMany<{ role: string }>({
		model: "organizationRole",
		where: [
			{ field: "organizationId", value: organizationId },
			{ field: "role", value: dynamicRoles, operator: "in" },
		],
	});
	const foundNames = new Set(found.map((role) => role.role));
	const missing = dynamicRoles.filter((role) => !foundNames.has(role));
	if (missing.length > 0) {
		throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND);
	}
}

async function revokeOrganizationSessions(
	ctx: Parameters<typeof getOrgAdapter>[0],
	userId: string,
	organizationId: string,
	excludedSessionId?: string,
) {
	const transaction = await getCurrentAdapter(ctx.adapter);
	const sessions = await transaction.findMany<{ id: string }>({
		model: "session",
		where: [
			{ field: "userId", value: userId },
			{ field: "activeOrganizationId", value: organizationId },
		],
	});
	for (const session of sessions) {
		if (session.id !== excludedSessionId) {
			await ctx.internalAdapter.deleteSessionById(session.id);
		}
	}
}

function usesSecondaryOnlySessions(
	context: Parameters<typeof getOrgAdapter>[0],
) {
	return Boolean(
		context.options.secondaryStorage &&
		context.options.session?.storeSessionInDatabase !== true,
	);
}

async function revokeSecondaryOrganizationSessions(
	ctx: Parameters<typeof getOrgAdapter>[0],
	userId: string,
	organizationId: string,
	excludedSessionId?: string,
) {
	const sessions = await ctx.internalAdapter.listSessions(userId);
	for (const session of sessions) {
		const scopedSession = session as typeof session & {
			activeOrganizationId?: string | null;
		};
		if (
			scopedSession.activeOrganizationId === organizationId &&
			session.id !== excludedSessionId
		) {
			await ctx.internalAdapter.deleteSessionById(session.id);
		}
	}
}

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

async function rejectNestedCookieLifecycleTransaction(
	context: Parameters<typeof getOrgAdapter>[0],
) {
	if (await isTransactionActive(context.adapter)) {
		throw APIError.from(
			"INTERNAL_SERVER_ERROR",
			ORGANIZATION_LIFECYCLE_NESTED_TRANSACTION,
		);
	}
}

const rejectNestedCookieLifecycleRoute = createAuthMiddleware(async (ctx) => {
	await rejectNestedCookieLifecycleTransaction(ctx.context);
	return {};
}) as typeof orgMiddleware;

function rejectNestedCookieLifecycleEndpoint<T extends Endpoint>(endpoint: T): T {
	return rejectActiveTransactionEndpoint(
		endpoint,
		() =>
			APIError.from(
				"INTERNAL_SERVER_ERROR",
				ORGANIZATION_LIFECYCLE_NESTED_TRANSACTION,
			),
	);
}

async function publishSessionCookie(
	ctx: Parameters<typeof setSessionCookie>[0],
	data: Parameters<typeof setSessionCookie>[1],
) {
	if (await isTransactionActive(ctx.context.adapter)) {
		await queueAfterTransactionHook(() => setSessionCookie(ctx, data), ctx.context.adapter);
		return;
	}
	await setSessionCookie(ctx, data);
}

async function runAfterLifecycleCommit(context: Parameters<typeof getOrgAdapter>[0], hook: () => void | Promise<void>) {
	if (await isTransactionActive(context.adapter)) return queueAfterTransactionHook(() => Promise.resolve(hook()), context.adapter);
	await hook();
}

const baseMemberSchema = z.object({
	userId: z.coerce.string().meta({
		description:
			'The user Id which represents the user to be added as a member. If `null` is provided, then it\'s expected to provide session headers. Eg: "user-id"',
	}),
	role: z.union([z.string(), z.array(z.string())]).meta({
		description:
			'The role(s) to assign to the new member. Eg: ["admin", "sale"]',
	}),
	organizationId: z
		.string()
		.meta({
			description:
				'An optional organization ID to pass. If not provided, will default to the user\'s active organization. Eg: "org-id"',
		})
		.optional(),
	teamId: z
		.string()
		.meta({
			description: 'An optional team ID to add the member to. Eg: "team-id"',
		})
		.optional(),
});

export const addMember = <O extends OrganizationOptions>(option: O) => {
	const additionalFieldsSchema = toZodSchema({
		fields: option?.schema?.member?.additionalFields || {},
		isClientSide: true,
	});
	return createAuthEndpoint.serverOnly(
		{
			method: "POST",
			body: z.object({
				...baseMemberSchema.shape,
				...additionalFieldsSchema.shape,
			}),
			use: [orgMiddleware],
			metadata: {
				$Infer: {
					body: {} as {
						userId: string;
						role:
							| InferOrganizationRolesFromOption<O>
							| InferOrganizationRolesFromOption<O>[];
						organizationId?: string | undefined;
					} & (O extends { teams: { enabled: true } }
						? { teamId?: string | undefined }
						: {}) &
						InferAdditionalFieldsFromPluginOptions<"member", O>,
				},
				openapi: {
					operationId: "addOrganizationMember",
					description: "Add a member to an organization",
				},
			},
		},
		async (ctx) => {
			const session = ctx.body.userId
				? await getSessionFromCtx<{
						session: {
							activeOrganizationId?: string | undefined;
						};
					}>(ctx).catch((e) => null)
				: null;
			const orgId =
				ctx.body.organizationId || session?.session.activeOrganizationId;
			if (!orgId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}

			const teamId =
				"teamId" in ctx.body ? (ctx.body.teamId as string) : undefined;
			if (teamId && !ctx.context.orgOptions.teams?.enabled) {
				ctx.context.logger.error("Teams are not enabled");
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "Teams are not enabled",
				});
			}

			const adapter = getOrgAdapter<O>(ctx.context, option);
			requireOrganizationLifecycleTransaction(ctx.context);

			const user = await ctx.context.internalAdapter.findUserById(
				ctx.body.userId,
			);

			if (!user) {
				throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.USER_NOT_FOUND);
			}

			const alreadyMember = await adapter.findMemberByEmail({
				email: user.email,
				organizationId: orgId,
			});

			if (alreadyMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION,
				);
			}

			if (teamId) {
				const team = await adapter.findTeamById({
					teamId,
					organizationId: orgId,
				});
				if (!team || team.organizationId !== orgId) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
					);
				}
			}

			const membershipLimit = ctx.context.orgOptions?.membershipLimit || 100;
			const count = await adapter.countMembers({ organizationId: orgId });

			const organization = await adapter.findOrganizationById(orgId);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			const limit =
				typeof membershipLimit === "number"
					? membershipLimit
					: await membershipLimit(user, organization);

			if (count >= limit) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_MEMBERSHIP_LIMIT_REACHED,
				);
			}

			const {
				role: _,
				userId: __,
				organizationId: ___,
				...additionalFields
			} = ctx.body;

			let memberData = {
				organizationId: orgId,
				userId: user.id,
				role: canonicalizeMemberRole(ctx.body.role),
				createdAt: new Date(),
				...(additionalFields ? additionalFields : {}),
			};

			// Run beforeAddMember hook
			if (option?.organizationHooks?.beforeAddMember) {
				const response = await option?.organizationHooks.beforeAddMember({
					member: {
						userId: user.id,
						organizationId: orgId,
						role: canonicalizeMemberRole(ctx.body.role),
						...additionalFields,
					},
					user,
					organization,
				});
				if (response && typeof response === "object" && "data" in response) {
					memberData = {
						...memberData,
						...response.data,
						userId: user.id,
						organizationId: orgId,
					};
				}
			}
			memberData.role = canonicalizeMemberRole(memberData.role);

			const createdMember = await runWithTransaction(
				ctx.context.adapter,
				async () => {
					const transaction = await getCurrentAdapter(ctx.context.adapter);
					const lockedContext = {
						...ctx.context,
						adapter: transaction as unknown as typeof ctx.context.adapter,
					};
					const lockedOrgAdapter = getOrgAdapter(lockedContext, option);
					const lockedOrganization = await transaction.update({
						model: "organization",
						where: [{ field: "id", value: orgId }],
						update: { updatedAt: new Date() },
					});
					if (!lockedOrganization) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
						);
					}
					const liveOrganization = await lockedOrgAdapter.findOrganizationById(orgId);
					if (!liveOrganization) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
						);
					}
					await ensureAssignedDynamicRolesExist(
						lockedContext,
						option,
						orgId,
						canonicalizeRoles(memberData.role),
					);
					if (await lockedOrgAdapter.findMemberByEmail({ email: user.email, organizationId: orgId })) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION,
						);
					}
					const liveLimit =
						typeof membershipLimit === "number"
							? membershipLimit
							: await membershipLimit(user, liveOrganization);
					if ((await lockedOrgAdapter.countMembers({ organizationId: orgId })) >= liveLimit) {
						throw APIError.from(
							"FORBIDDEN",
							ORGANIZATION_ERROR_CODES.ORGANIZATION_MEMBERSHIP_LIMIT_REACHED,
						);
					}
					if (teamId) {
						const team = await lockedOrgAdapter.findTeamById({ teamId, organizationId: orgId });
						if (!team || team.organizationId !== orgId) {
							throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND);
						}
						const maximumMembersPerTeam = await resolveMaximumMembersPerTeam(
							ctx.context.orgOptions.teams,
							{ teamId, organizationId: orgId, session },
						);
						if (maximumMembersPerTeam !== undefined) {
							const result = await lockedOrgAdapter.addTeamMemberWithLimit({
								organizationId: orgId,
								teamId,
								userId: user.id,
								maximumMembersPerTeam,
							});
							if (result.status === "limitReached") {
								throw APIError.from("FORBIDDEN", ORGANIZATION_ERROR_CODES.TEAM_MEMBER_LIMIT_REACHED);
							}
						} else {
							await lockedOrgAdapter.findOrCreateTeamMember({
								organizationId: orgId,
								userId: user.id,
								teamId,
							});
						}
					}
					return lockedOrgAdapter.createMember(memberData);
				},
			);

			// Run afterAddMember hook
			if (option?.organizationHooks?.afterAddMember) {
				await runAfterLifecycleCommit(ctx.context, () => option.organizationHooks!.afterAddMember!({
					member: createdMember,
					user,
					organization,
				}));
			}

			return ctx.json(createdMember);
		},
	);
};

const removeMemberBodySchema = z.object({
	memberIdOrEmail: z.string().meta({
		description: "The ID or email of the member to remove",
	}),
	/**
	 * If not provided, the active organization will be used
	 */
	organizationId: z
		.string()
		.meta({
			description:
				'The ID of the organization to remove the member from. If not provided, the active organization will be used. Eg: "org-id"',
		})
		.optional(),
});

export const removeMember = <O extends OrganizationOptions>(options: O) =>
	rejectNestedCookieLifecycleEndpoint(createAuthEndpoint(
		"/organization/remove-member",
		{
			method: "POST",
			body: removeMemberBodySchema,
			requireHeaders: true,
			use: [rejectNestedCookieLifecycleRoute, orgMiddleware, orgSessionMiddleware],
			metadata: {
				openapi: {
					description: "Remove a member from an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											member: {
												type: "object",
												properties: {
													id: {
														type: "string",
													},
													userId: {
														type: "string",
													},
													organizationId: {
														type: "string",
													},
													role: {
														type: "string",
													},
												},
												required: ["id", "userId", "organizationId", "role"],
											},
										},
										required: ["member"],
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
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
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
			let toBeRemovedMember: InferMember<O> | null = null;
			if (ctx.body.memberIdOrEmail.includes("@")) {
				toBeRemovedMember = await adapter.findMemberByEmail({
					email: ctx.body.memberIdOrEmail,
					organizationId: organizationId,
				});
			} else {
				const result = await adapter.findMemberById(ctx.body.memberIdOrEmail);
				if (!result) toBeRemovedMember = null;
				else {
					const { user: _user, ...member } = result;
					toBeRemovedMember = member as unknown as InferMember<O>;
				}
			}
			if (!toBeRemovedMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
				);
			}
			const roles = canonicalizeRoles(toBeRemovedMember.role);
			const creatorRole = ctx.context.orgOptions?.creatorRole || "owner";
			const isOwner = roles.includes(creatorRole);
			if (isOwner) {
				if (!canonicalizeRoles(member.role).includes(creatorRole)) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER,
					);
				}
				const { members } = await adapter.listMembers({
					organizationId: organizationId,
				});
				const owners = members.filter((member) => {
					return canonicalizeRoles(member.role).includes(creatorRole);
				});
				if (owners.length <= 1) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER,
					);
				}
			}
			const canDeleteMember = await hasPermission(
				{
					role: canonicalizeMemberRole(member.role),
					options: ctx.context.orgOptions,
					permissions: {
						member: ["delete"],
					},
					organizationId,
				},
				ctx,
			);

			if (!canDeleteMember) {
				throw APIError.from(
					"UNAUTHORIZED",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER,
				);
			}

			if (toBeRemovedMember?.organizationId !== organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
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
				toBeRemovedMember.userId,
			);
			if (!userBeingRemoved) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "User not found",
				});
			}
			const removesCurrentActiveMembership =
				session.user.id === toBeRemovedMember.userId &&
				session.session.activeOrganizationId ===
					toBeRemovedMember.organizationId;
			if (removesCurrentActiveMembership) {
				await rejectNestedCookieLifecycleTransaction(ctx.context);
				assertManagedOrganizationTransitionSupported(ctx.context);
			}
			requireOrganizationLifecycleTransaction(ctx.context);
			const secondaryOnlySessions = usesSecondaryOnlySessions(ctx.context);
			const sourceSessionId = removesCurrentActiveMembership
				? session.session.id
				: undefined;
			// Run beforeRemoveMember hook
			let beforeRemoveMemberRan = false;
			if (options?.organizationHooks?.beforeRemoveMember) {
				beforeRemoveMemberRan = true;
				await options?.organizationHooks.beforeRemoveMember({
					member: toBeRemovedMember,
					user: userBeingRemoved,
					organization,
				});
			}
			const acquireOrganizationLock = async () => {
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const lockedOrganization = await transaction.update({
					model: "organization",
					where: [{ field: "id", value: organizationId }],
					update: { updatedAt: new Date() },
				});
				if (!lockedOrganization) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
			};
			const deleteMemberInOwningTransaction = async () => {
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const lockedContext = {
					...ctx.context,
					adapter: transaction as unknown as typeof ctx.context.adapter,
				};
				const currentActorMember = await adapter.findMemberByOrgId({
					userId: session.user.id,
					organizationId,
				});
				if (!currentActorMember) {
					throw APIError.from(
						"UNAUTHORIZED",
						ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER,
					);
				}
				const currentActorRole = canonicalizeMemberRole(currentActorMember.role);
				const canStillDeleteMember = await hasPermission(
					{
						role: currentActorRole,
						options: ctx.context.orgOptions,
						permissions: { member: ["delete"] },
						organizationId,
					},
					{ ...ctx, context: lockedContext },
				);
				if (!canStillDeleteMember) {
					throw APIError.from(
						"UNAUTHORIZED",
						ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER,
					);
				}
				const currentMember = await adapter.findMemberById(toBeRemovedMember.id);
				if (
					!currentMember ||
					currentMember.organizationId !== organizationId ||
					currentMember.userId !== toBeRemovedMember.userId
				) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
					);
				}
				if (
					beforeRemoveMemberRan &&
					(currentMember.id !== toBeRemovedMember.id ||
						currentMember.organizationId !== toBeRemovedMember.organizationId ||
						currentMember.userId !== toBeRemovedMember.userId ||
						currentMember.role !== toBeRemovedMember.role)
				) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
					);
				}
				if (canonicalizeRoles(currentMember.role).includes(creatorRole)) {
					const owners = (await transaction.findMany<Member>({
						model: "member",
						where: [{ field: "organizationId", value: organizationId }],
					})).filter((candidate) =>
						canonicalizeRoles(candidate.role).includes(creatorRole),
					);
					if (owners.length <= 1) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER,
						);
					}
				}
				if (secondaryOnlySessions) {
					await revokeSecondaryOrganizationSessions(
						lockedContext,
						currentMember.userId,
						organizationId,
						sourceSessionId,
					);
				} else {
					await revokeOrganizationSessions(
						lockedContext,
						currentMember.userId,
						organizationId,
						sourceSessionId,
					);
				}
				await adapter.deleteMember({
					memberId: currentMember.id,
					organizationId,
					userId: currentMember.userId,
				});
				if (options?.organizationHooks?.afterRemoveMember) {
					await runAfterLifecycleCommit(ctx.context, () =>
						options.organizationHooks!.afterRemoveMember!({
							member: currentMember,
							user: userBeingRemoved,
							organization,
						}),
					);
				}
			};
			if (removesCurrentActiveMembership) {
				let committedSuccessor: typeof session.session | undefined;
				const managedSessionTransition = Boolean(
					readInternalAuthenticationPolicy(ctx.context.options),
				);
				try {
					const updatedSession = await adapter.setActiveOrganization(
						session.session.token,
						null,
						ctx,
						{
							beforeCapture: acquireOrganizationLock,
							afterCapture: deleteMemberInOwningTransaction,
							propagateAfterTransactionHookError: true,
							onSuccessorPrepared: (successor) => {
								committedSuccessor = successor;
							},
						},
					);
					await publishSessionCookie(ctx, { session: updatedSession, user: session.user });
				} catch (error) {
						const recoveredSuccessor = managedSessionTransition
							? committedSuccessor
							: await (async () => {
								const presentingSession =
									await ctx.context.internalAdapter.findSession(session.session.token);
								if (
									!presentingSession ||
									presentingSession.session.id !== session.session.id ||
									presentingSession.user.id !== session.user.id ||
									presentingSession.session.activeOrganizationId !== null
								) {
									return undefined;
								}
								return presentingSession.session as typeof session.session;
							})();
						if (
						(error instanceof AfterTransactionHookError ||
							(error as { name?: unknown })?.name ===
								"AfterTransactionHookError") &&
							recoveredSuccessor
						) {
							await publishSessionCookie(ctx, {
								session: recoveredSuccessor,
							user: session.user,
						});
						throw APIError.fromStatus("INTERNAL_SERVER_ERROR", {
							code: "AFTER_TRANSACTION_HOOK_FAILED",
							message: "Organization removal committed but an after-transaction hook failed",
						});
					}
					throw error;
				}
			} else {
				await runWithTransaction(
					ctx.context.adapter,
					async () => {
						await acquireOrganizationLock();
						return deleteMemberInOwningTransaction();
					},
				);
			}

			return ctx.json({
				member: toBeRemovedMember,
			});
		},
	));

const updateMemberRoleBodySchema = z.object({
	role: z.union([z.string(), z.array(z.string())]).meta({
		description:
			'The new role to be applied. This can be a string or array of strings representing the roles. Eg: ["admin", "sale"]',
	}),
	memberId: z.string().meta({
		description: 'The member id to apply the role update to. Eg: "member-id"',
	}),
	organizationId: z
		.string()
		.meta({
			description:
				'An optional organization ID which the member is a part of to apply the role update. If not provided, you must provide session headers to get the active organization. Eg: "organization-id"',
		})
		.optional(),
});

export const updateMemberRole = <O extends OrganizationOptions>(option: O) =>
	createAuthEndpoint(
		"/organization/update-member-role",
		{
			method: "POST",
			body: updateMemberRoleBodySchema,
			use: [orgMiddleware, orgSessionMiddleware],
			requireHeaders: true,
			metadata: {
				$Infer: {
					body: {} as {
						role:
							| InferOrganizationRolesFromOption<O>
							| InferOrganizationRolesFromOption<O>[]
							| LiteralString
							| LiteralString[];
						memberId: string;
						/**
						 * If not provided, the active organization will be used
						 */
						organizationId?: string | undefined;
					},
				},
				openapi: {
					operationId: "updateOrganizationMemberRole",
					description: "Update the role of a member in an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										properties: {
											member: {
												type: "object",
												properties: {
													id: {
														type: "string",
													},
													userId: {
														type: "string",
													},
													organizationId: {
														type: "string",
													},
													role: {
														type: "string",
													},
												},
												required: ["id", "userId", "organizationId", "role"],
											},
										},
										required: ["member"],
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

			if (!ctx.body.role) {
				throw APIError.fromStatus("BAD_REQUEST");
			}

			const organizationId =
				ctx.body.organizationId || session.session.activeOrganizationId;

			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			requireOrganizationLifecycleTransaction(ctx.context);

			const adapter = getOrgAdapter(ctx.context, ctx.context.orgOptions);
			const roleToSet = canonicalizeRoles(ctx.body.role);

			const validStaticRoles = new Set([
				...Object.keys(defaultRoles),
				...Object.keys(ctx.context.orgOptions.roles || {}),
			]);
			const unknownRoles = roleToSet.filter(
				(role) => !validStaticRoles.has(role),
			);
			if (unknownRoles.length > 0) {
				if (ctx.context.orgOptions.dynamicAccessControl?.enabled) {
					const foundRoles = await ctx.context.adapter.findMany<{
						role: string;
					}>({
						model: "organizationRole",
						where: [
							{ field: "organizationId", value: organizationId },
							{ field: "role", value: unknownRoles, operator: "in" },
						],
					});
					const foundRoleNames = foundRoles.map((r) => r.role);
					const stillInvalid = unknownRoles.filter(
						(r) => !foundRoleNames.includes(r),
					);
					if (stillInvalid.length > 0) {
						throw new APIError("BAD_REQUEST", {
							code: ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND.code,
							message: `${ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND.code}: ${stillInvalid.join(", ")}`,
						});
					}
				} else {
					throw new APIError("BAD_REQUEST", {
						code: ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND.code,
						message: `${ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND.code}: ${unknownRoles.join(", ")}`,
					});
				}
			}

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

			const toBeUpdatedMember =
				member.id !== ctx.body.memberId
					? await adapter.findMemberById(ctx.body.memberId)
					: member;

			if (!toBeUpdatedMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
				);
			}

			const memberBelongsToOrganization =
				toBeUpdatedMember.organizationId === organizationId;

			if (!memberBelongsToOrganization) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER,
				);
			}

			const creatorRole = ctx.context.orgOptions?.creatorRole || "owner";

			const updatingMemberRoles = canonicalizeRoles(member.role);
			const toBeUpdatedMemberRoles = canonicalizeRoles(toBeUpdatedMember.role);

			const isUpdatingCreator = toBeUpdatedMemberRoles.includes(creatorRole);
			const updaterIsCreator = updatingMemberRoles.includes(creatorRole);

			const isSettingCreatorRole = roleToSet.includes(creatorRole);

			const memberIsUpdatingThemselves = member.id === toBeUpdatedMember.id;

			if (
				(isUpdatingCreator && !updaterIsCreator) ||
				(isSettingCreatorRole && !updaterIsCreator)
			) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER,
				);
			}

			if (updaterIsCreator && memberIsUpdatingThemselves) {
				const members = await ctx.context.adapter.findMany<Member>({
					model: "member",
					where: [
						{
							field: "organizationId",
							value: organizationId,
						},
					],
				});
				const owners = members.filter((member: Member) =>
					canonicalizeRoles(member.role).includes(creatorRole),
				);
				if (owners.length <= 1 && !isSettingCreatorRole) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER,
					);
				}
			}

			const canUpdateMember = await hasPermission(
				{
					role: canonicalizeMemberRole(member.role),
					options: ctx.context.orgOptions,
					permissions: {
						member: ["update"],
					},
					allowCreatorAllPermissions: true,
					organizationId,
				},
				ctx,
			);

			if (!canUpdateMember) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER,
				);
			}

			const organization = await adapter.findOrganizationById(organizationId);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			const userBeingUpdated = await ctx.context.internalAdapter.findUserById(
				toBeUpdatedMember.userId,
			);
			if (!userBeingUpdated) {
				throw APIError.fromStatus("BAD_REQUEST", {
					message: "User not found",
				});
			}

			const previousRole = toBeUpdatedMember.role;
			let lockedPreviousRole = previousRole;
			const newRole = canonicalizeMemberRole(roleToSet);
			let roleToPersist = newRole;

			// Run beforeUpdateMemberRole hook
			let beforeUpdateMemberRoleRan = false;
			if (option?.organizationHooks?.beforeUpdateMemberRole) {
				beforeUpdateMemberRoleRan = true;
				const response = await option?.organizationHooks.beforeUpdateMemberRole(
					{
						member: toBeUpdatedMember,
						newRole,
						user: userBeingUpdated,
						organization,
					},
				);
				if (response && typeof response === "object" && "data" in response) {
					roleToPersist = response.data.role || newRole;
				}
			}
			roleToPersist = canonicalizeMemberRole(roleToPersist);

			const updatedMember = await runWithTransaction(
				ctx.context.adapter,
				async () => {
					const transaction = await getCurrentAdapter(ctx.context.adapter);
					const lockedContext = {
						...ctx.context,
						adapter: transaction as unknown as typeof ctx.context.adapter,
					};
					const lockedOrgAdapter = getOrgAdapter(
						lockedContext,
						ctx.context.orgOptions,
					);
					const lockedOrganization = await transaction.update({
						model: "organization",
						where: [{ field: "id", value: organizationId }],
						update: { updatedAt: new Date() },
					});
					if (!lockedOrganization) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
						);
					}
					const currentActor = await lockedOrgAdapter.findMemberByOrgId({
						userId: session.user.id,
						organizationId,
					});
					const currentTarget = await lockedOrgAdapter.findMemberById(ctx.body.memberId);
					if (!currentActor || !currentTarget) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
						);
					}
					if (currentTarget.organizationId !== organizationId) {
						throw APIError.from(
							"FORBIDDEN",
							ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER,
						);
					}
					if (
						beforeUpdateMemberRoleRan &&
						(currentTarget.id !== toBeUpdatedMember.id ||
							currentTarget.organizationId !== toBeUpdatedMember.organizationId ||
							currentTarget.userId !== toBeUpdatedMember.userId ||
							currentTarget.role !== toBeUpdatedMember.role)
					) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
						);
					}
					lockedPreviousRole = currentTarget.role;
					const currentActorRole = canonicalizeMemberRole(currentActor.role);
					const actorIsCreator = canonicalizeRoles(currentActorRole).includes(creatorRole);
					const targetIsCreator = canonicalizeRoles(currentTarget.role).includes(creatorRole);
					const persistedRoles = canonicalizeRoles(roleToPersist);
					const setsCreator = persistedRoles.includes(creatorRole);
					await ensureAssignedDynamicRolesExist(
						lockedContext,
						ctx.context.orgOptions,
						organizationId,
						persistedRoles,
					);
					if ((targetIsCreator || setsCreator) && !actorIsCreator) {
						throw APIError.from(
							"FORBIDDEN",
							ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER,
						);
					}
					const canStillUpdate = await hasPermission(
						{
							role: currentActorRole,
							options: ctx.context.orgOptions,
							permissions: { member: ["update"] },
							allowCreatorAllPermissions: true,
							organizationId,
						},
						{ ...ctx, context: lockedContext },
					);
					if (!canStillUpdate) {
						throw APIError.from(
							"FORBIDDEN",
							ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER,
						);
					}
					if (targetIsCreator && !setsCreator) {
						const owners = (await transaction.findMany<Member>({
							model: "member",
							where: [{ field: "organizationId", value: organizationId }],
						})).filter((candidate) =>
							canonicalizeRoles(candidate.role).includes(creatorRole),
						);
						if (owners.length <= 1) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER,
							);
						}
					}
					const result = await lockedOrgAdapter.updateMember(
						currentTarget.id,
						roleToPersist,
					);
					if (!result) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
						);
					}
					return result;
				},
			);
			if (!updatedMember) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
				);
			}

			// Run afterUpdateMemberRole hook
			if (option?.organizationHooks?.afterUpdateMemberRole) {
				await runAfterLifecycleCommit(ctx.context, () => option.organizationHooks!.afterUpdateMemberRole!({
					member: updatedMember,
					previousRole: lockedPreviousRole,
					user: userBeingUpdated,
					organization,
				}));
			}

			return ctx.json(updatedMember);
		},
	);

export const getActiveMember = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/get-active-member",
		{
			method: "GET",
			use: [orgMiddleware, orgSessionMiddleware],
			requireHeaders: true,
			metadata: {
				openapi: {
					description: "Get the member details of the active organization",
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
											userId: {
												type: "string",
											},
											organizationId: {
												type: "string",
											},
											role: {
												type: "string",
											},
										},
										required: ["id", "userId", "organizationId", "role"],
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
			const organizationId = session.session.activeOrganizationId;
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
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
			return ctx.json(member);
		},
	);

const leaveOrganizationBodySchema = z.object({
	organizationId: z.string().meta({
		description:
			'The organization Id for the member to leave. Eg: "organization-id"',
	}),
});

export const leaveOrganization = <O extends OrganizationOptions>(options: O) =>
	rejectNestedCookieLifecycleEndpoint(createAuthEndpoint(
		"/organization/leave",
		{
			method: "POST",
			body: leaveOrganizationBodySchema,
			requireHeaders: true,
			use: [rejectNestedCookieLifecycleRoute, sessionMiddleware, orgMiddleware],
		},
		async (ctx) => {
			const session = ctx.context.session;
			const leavesActiveOrganization =
				session.session.activeOrganizationId === ctx.body.organizationId;
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const member = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: ctx.body.organizationId,
			});

			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
				);
			}
			const creatorRole = ctx.context.orgOptions?.creatorRole || "owner";
			const isOwnerLeaving = canonicalizeRoles(member.role).includes(creatorRole);
			if (isOwnerLeaving) {
				const members = await ctx.context.adapter.findMany<Member>({
					model: "member",
					where: [
						{
							field: "organizationId",
							value: ctx.body.organizationId,
						},
					],
				});
				const owners = members.filter((member) =>
					canonicalizeRoles(member.role).includes(creatorRole),
				);
				if (owners.length <= 1) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER,
					);
				}
			}
			if (leavesActiveOrganization) {
				await rejectNestedCookieLifecycleTransaction(ctx.context);
				assertManagedOrganizationTransitionSupported(ctx.context);
			}
			requireOrganizationLifecycleTransaction(ctx.context);
			const secondaryOnlySessions = usesSecondaryOnlySessions(ctx.context);
			const sourceSessionId = leavesActiveOrganization
				? session.session.id
				: undefined;
			const acquireOrganizationLock = async () => {
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const lockedOrganization = await transaction.update({
					model: "organization",
					where: [{ field: "id", value: ctx.body.organizationId }],
					update: { updatedAt: new Date() },
				});
				if (!lockedOrganization) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
			};
			const leaveInOwningTransaction = async () => {
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const currentMember = await adapter.findMemberByOrgId({
					userId: session.user.id,
					organizationId: ctx.body.organizationId,
				});
				if (!currentMember) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
					);
				}
				if (canonicalizeRoles(currentMember.role).includes(creatorRole)) {
					const owners = (await transaction.findMany<Member>({
						model: "member",
						where: [
							{ field: "organizationId", value: ctx.body.organizationId },
						],
					})).filter((candidate) =>
						canonicalizeRoles(candidate.role).includes(creatorRole),
					);
					if (owners.length <= 1) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER,
						);
					}
				}
				if (secondaryOnlySessions) {
					await revokeSecondaryOrganizationSessions(
						ctx.context,
						currentMember.userId,
						ctx.body.organizationId,
						sourceSessionId,
					);
				} else {
					await revokeOrganizationSessions(
						ctx.context,
						session.user.id,
						ctx.body.organizationId,
						sourceSessionId,
					);
				}
				await adapter.deleteMember({
					memberId: currentMember.id,
					organizationId: ctx.body.organizationId,
					userId: session.user.id,
				});
			};
			if (leavesActiveOrganization) {
				const updatedSession = await adapter.setActiveOrganization(
					session.session.token,
					null,
					ctx,
					{
						beforeCapture: acquireOrganizationLock,
						afterCapture: leaveInOwningTransaction,
					},
				);
				await publishSessionCookie(ctx, { session: updatedSession, user: session.user });
			} else {
				await runWithTransaction(
					ctx.context.adapter,
					async () => {
						await acquireOrganizationLock();
						return leaveInOwningTransaction();
					},
				);
			}
			return ctx.json(member);
		},
	));

export const listMembers = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/list-members",
		{
			method: "GET",
			query: z
				.object({
					limit: z
						.string()
						.meta({
							description: "The number of users to return",
						})
						.or(z.number())
						.optional(),
					offset: z
						.string()
						.meta({
							description: "The offset to start from",
						})
						.or(z.number())
						.optional(),
					sortBy: z
						.string()
						.meta({
							description: "The field to sort by",
						})
						.optional(),
					sortDirection: z
						.enum(["asc", "desc"])
						.meta({
							description: "The direction to sort by",
						})
						.optional(),
					filterField: z
						.string()
						.meta({
							description: "The field to filter by",
						})
						.optional(),
					filterValue: z
						.string()
						.meta({
							description: "The value to filter by",
						})
						.or(z.number())
						.or(z.boolean())
						.or(z.array(z.string()))
						.or(z.array(z.number()))
						.optional(),
					filterOperator: z
						.enum(whereOperators)
						.meta({
							description: "The operator to use for the filter",
						})
						.optional(),
					organizationId: z
						.string()
						.meta({
							description:
								'The organization ID to list members for. If not provided, will default to the user\'s active organization. Eg: "organization-id"',
						})
						.optional(),
					organizationSlug: z
						.string()
						.meta({
							description:
								'The organization slug to list members for. If not provided, will default to the user\'s active organization. Eg: "organization-slug"',
						})
						.optional(),
				})
				.optional(),
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
		},
		async (ctx) => {
			const session = ctx.context.session;
			let organizationId =
				ctx.query?.organizationId || session.session.activeOrganizationId;
			const adapter = getOrgAdapter<O>(ctx.context, options);
			if (ctx.query?.organizationSlug) {
				const organization = await adapter.findOrganizationBySlug(
					ctx.query?.organizationSlug,
				);
				if (!organization) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
				organizationId = organization.id;
			}
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}

			const isMember = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId,
			});
			if (!isMember) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION,
				);
			}
			const { members, total } = await adapter.listMembers({
				organizationId,
				limit: ctx.query?.limit ? Number(ctx.query.limit) : undefined,
				offset: ctx.query?.offset ? Number(ctx.query.offset) : undefined,
				sortBy: ctx.query?.sortBy,
				sortOrder: ctx.query?.sortDirection,
				filter: ctx.query?.filterField
					? {
							field: ctx.query?.filterField,
							operator: ctx.query.filterOperator,
							value: ctx.query.filterValue,
						}
					: undefined,
			});
			return ctx.json({
				members,
				total,
			});
		},
	);

const getActiveMemberRoleQuerySchema = z
	.object({
		userId: z
			.string()
			.meta({
				description:
					"The user ID to get the role for. If not provided, will default to the current user's",
			})
			.optional(),
		organizationId: z
			.string()
			.meta({
				description:
					'The organization ID to list members for. If not provided, will default to the user\'s active organization. Eg: "organization-id"',
			})
			.optional(),
		organizationSlug: z
			.string()
			.meta({
				description:
					'The organization slug to list members for. If not provided, will default to the user\'s active organization. Eg: "organization-slug"',
			})
			.optional(),
	})
	.optional();

export const getActiveMemberRole = <O extends OrganizationOptions>(
	options: O,
) =>
	createAuthEndpoint(
		"/organization/get-active-member-role",
		{
			method: "GET",
			query: getActiveMemberRoleQuerySchema,
			requireHeaders: true,
			use: [orgMiddleware, orgSessionMiddleware],
		},
		async (ctx) => {
			const session = ctx.context.session;
			let organizationId =
				ctx.query?.organizationId || session.session.activeOrganizationId;
			const adapter = getOrgAdapter<O>(ctx.context, options);
			if (ctx.query?.organizationSlug) {
				const organization = await adapter.findOrganizationBySlug(
					ctx.query?.organizationSlug,
				);
				if (!organization) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
				organizationId = organization.id;
			}
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}
			const isMember = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId,
			});
			if (!isMember) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION,
				);
			}
			if (!ctx.query?.userId) {
				return ctx.json({
					role: isMember.role,
				});
			}
			const userIdToGetRole = ctx.query?.userId;
			const member = await adapter.findMemberByOrgId({
				userId: userIdToGetRole,
				organizationId,
			});
			if (!member) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION,
				);
			}

			return ctx.json({
				role: member?.role,
			});
		},
	);
