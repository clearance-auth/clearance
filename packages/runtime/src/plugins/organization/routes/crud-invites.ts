import type { GenerateIdFn, LiteralString } from "@clearance/core";
import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	isTransactionActive,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
import { APIError, BASE_ERROR_CODES } from "@clearance/core/error";
import type { Endpoint } from "@clearance/call";
import * as z from "zod";
import { getSessionFromCtx } from "../../../api/routes";
import { rejectActiveTransactionEndpoint } from "../../../api/dispatch";
import { setSessionCookie } from "../../../cookies";
import type { InferAdditionalFieldsFromPluginOptions } from "../../../db";
import { toZodSchema } from "../../../db";
import type { Session, User } from "../../../types";
import { getDate } from "../../../utils/date";
import { defaultRoles } from "../access/statement";
import {
	assertManagedOrganizationTransitionSupported,
	getOrgAdapter,
	resolveMaximumMembersPerTeam,
} from "../adapter";
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

const ORGANIZATION_LIFECYCLE_NESTED_TRANSACTION = {
	code: "ORGANIZATION_LIFECYCLE_NESTED_TRANSACTION",
	message:
		"Cookie-bearing organization lifecycle routes cannot run inside an existing transaction",
} as const;

async function requireOrganizationLifecycleTransaction(
	context: Parameters<typeof getOrgAdapter>[0],
) {
	if (
		typeof context.adapter.options?.adapterConfig.transaction !== "function" &&
		!(await isTransactionActive(context.adapter))
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

// This must run before orgSessionMiddleware. A managed session transition
// cannot safely refresh a secondary-authoritative bearer, so do not let the
// session middleware publish a replacement before the route rejects it.
const rejectUnsupportedManagedOrganizationTransition = createAuthMiddleware(
	async (ctx) => {
		assertManagedOrganizationTransitionSupported(ctx.context);
		return {};
	},
) as typeof orgMiddleware;

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

function isAfterTransactionHookFailure(
	error: unknown,
): error is AfterTransactionHookError {
	return (
		error instanceof AfterTransactionHookError ||
		(error instanceof Error &&
			error.name === "AfterTransactionHookError" &&
			Array.isArray((error as { errors?: unknown }).errors))
	);
}

type OriginalInvitationBearer = {
	sessionId: string;
	userId: string;
	token: string;
};

function captureOriginalInvitationBearer(session: {
	session: { id: string; token: string };
	user: { id: string };
}): OriginalInvitationBearer {
	return {
		sessionId: session.session.id,
		userId: session.user.id,
		token: session.session.token,
	};
}

/**
 * A before hook is deliberately allowed to do arbitrary work. Re-read the
 * original credential in the owning transaction after it returns so hook work
 * cannot leave us persisting authority derived from a stale bearer.
 */
async function resolveLiveInvitationActor(
	context: Parameters<typeof getOrgAdapter>[0],
	bearer: OriginalInvitationBearer,
): Promise<{ session: Session; user: User }> {
	const live = await context.internalAdapter.findSession(bearer.token);
	if (
		!live ||
		live.session.id !== bearer.sessionId ||
		live.session.userId !== bearer.userId ||
		live.session.token !== bearer.token ||
		live.user.id !== bearer.userId ||
		new Date(live.session.expiresAt) <= new Date()
	) {
		throw APIError.fromStatus("UNAUTHORIZED");
	}
	return live as { session: Session; user: User };
}

function canonicalizeInvitationRole(role: string): string {
	const roles = role.split(",").map((value) => value.trim());
	if (roles.length === 0 || roles.some((value) => value.length === 0)) {
		throw APIError.fromStatus("BAD_REQUEST");
	}
	if (new Set(roles).size !== roles.length) {
		throw APIError.fromStatus("BAD_REQUEST");
	}
	return roles.join(",");
}

async function revalidateInvitationDynamicRoles(
	context: Parameters<typeof getOrgAdapter>[0],
	options: OrganizationOptions,
	organizationId: string,
	role: string,
) {
	const roles = canonicalizeInvitationRole(role).split(",");
	const staticRoles = new Set([
		...Object.keys(defaultRoles),
		...Object.keys(options.roles || {}),
	]);
	const dynamicRoles = roles.filter((value) => !staticRoles.has(value));
	if (dynamicRoles.length === 0) return;
	if (!options.dynamicAccessControl?.enabled) {
		throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND);
	}
	const transaction = await getCurrentAdapter(context.adapter);
	const found = await transaction.findMany<{ role: string }>({
		model: "organizationRole",
		where: [
			{ field: "organizationId", value: organizationId },
			{ field: "role", value: dynamicRoles, operator: "in" },
		],
	});
	const foundNames = new Set(found.map((entry) => entry.role));
	if (dynamicRoles.some((roleName) => !foundNames.has(roleName))) {
		throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND);
	}
}

async function lockAndRevalidateInvitationAuthority(
	context: Parameters<typeof getOrgAdapter>[0],
	options: OrganizationOptions,
	invitation: { organizationId: string; role: string; teamIds: string[] },
) {
	const transaction = await getCurrentAdapter(context.adapter);
	const organization = await transaction.update({
		model: "organization",
		where: [{ field: "id", value: invitation.organizationId }],
		update: { updatedAt: new Date() },
	});
	if (!organization) {
		throw APIError.from(
			"BAD_REQUEST",
			ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
		);
	}
	await revalidateInvitationDynamicRoles(
		context,
		options,
		invitation.organizationId,
		invitation.role,
	);
	for (const teamId of invitation.teamIds) {
		const team = await transaction.findOne({
			model: "team",
			where: [
				{ field: "id", value: teamId },
				{ field: "organizationId", value: invitation.organizationId },
			],
		});
		if (!team) {
			throw APIError.from(
				"BAD_REQUEST",
				ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
			);
		}
	}
	return organization as { id: string; name: string; slug: string; createdAt: Date };
}

async function lockOrganizationInvitationMutation(
	context: Parameters<typeof getOrgAdapter>[0],
	organizationId: string,
) {
	const transaction = await getCurrentAdapter(context.adapter);
	const organization = await transaction.update({
		model: "organization",
		where: [{ field: "id", value: organizationId }],
		update: { updatedAt: new Date() },
	});
	if (!organization) {
		throw APIError.from(
			"BAD_REQUEST",
			ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
		);
	}
	return organization;
}

async function revalidateInvitationCreator(
	context: Parameters<typeof getOrgAdapter>[0],
	options: OrganizationOptions,
	organizationId: string,
	role: string,
	userId: string,
) {
	const transaction = await getCurrentAdapter(context.adapter);
	const member = await transaction.findOne<Member>({
		model: "member",
		where: [
			{ field: "userId", value: userId },
			{ field: "organizationId", value: organizationId },
		],
	});
	if (!member) {
		throw APIError.from(
			"BAD_REQUEST",
			ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
		);
	}
	const transactionContext = {
		context: { ...context, adapter: transaction },
	};
	const canInvite = await hasPermission(
		{
			role: member.role,
			options,
			permissions: { invitation: ["create"] },
			organizationId,
		},
		transactionContext as Parameters<typeof hasPermission>[1],
	);
	if (!canInvite) {
		throw APIError.from(
			"FORBIDDEN",
			ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION,
		);
	}
	const creatorRole = options.creatorRole || "owner";
	if (
		!member.role.split(",").map((value) => value.trim()).includes(creatorRole) &&
		canonicalizeInvitationRole(role).split(",").includes(creatorRole)
	) {
		throw APIError.from(
			"FORBIDDEN",
			ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE,
		);
	}
	return member;
}

async function revalidateInvitationCanceler(
	context: Parameters<typeof getOrgAdapter>[0],
	options: OrganizationOptions,
	organizationId: string,
	userId: string,
) {
	const transaction = await getCurrentAdapter(context.adapter);
	const member = await transaction.findOne<Member>({
		model: "member",
		where: [
			{ field: "userId", value: userId },
			{ field: "organizationId", value: organizationId },
		],
	});
	if (!member) {
		throw APIError.from(
			"BAD_REQUEST",
			ORGANIZATION_ERROR_CODES.MEMBER_NOT_FOUND,
		);
	}
	const transactionContext = { context: { ...context, adapter: transaction } };
	const canCancel = await hasPermission(
		{
			role: member.role,
			options,
			permissions: { invitation: ["cancel"] },
			organizationId,
		},
		transactionContext as Parameters<typeof hasPermission>[1],
	);
	if (!canCancel) {
		throw APIError.from(
			"FORBIDDEN",
			ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION,
		);
	}
	return member;
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
	const protectedInvitationFields = [
		"organizationId",
		"email",
		"role",
		"teamIds",
		"teamId",
		"inviterId",
		"status",
		"expiresAt",
		"createdAt",
		"updatedAt",
		"id",
	] as const;

	const parseMutableInvitationFields = (
		data: Record<string, unknown>,
		partial: boolean,
	) => {
		const mutableData = { ...data };
		for (const field of protectedInvitationFields) {
			delete mutableData[field];
		}
		return (partial
			? additionalFieldsSchema.partial().strict()
			: additionalFieldsSchema.strict()
		).parse(mutableData);
	};

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
			await requireOrganizationLifecycleTransaction(ctx.context);
			const session = ctx.context.session;
			const originalBearer = captureOriginalInvitationBearer(session);
			const actor = { id: session.user.id, user: { ...session.user } };
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
			const transactionContext = {
				...ctx,
				context: {
					...ctx.context,
					adapter: await getCurrentAdapter(ctx.context.adapter),
				},
			};
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
				transactionContext as unknown as Parameters<typeof hasPermission>[1],
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
					const foundRoles = await transactionContext.context.adapter.findMany({
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
			const organization = await adapter.findOrganizationById(organizationId);
			if (!organization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
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
				teamId: _____,
				...additionalFields
			} = ctx.body as Record<string, unknown>;

			const invitationAuthority = {
				role: roles,
				email: email,
				organizationId: organizationId,
				teamIds,
			};
			let invitationData = {
				...parseMutableInvitationFields(additionalFields, false),
				...invitationAuthority,
			};

			// Run beforeCreateInvitation hook
			if (option?.organizationHooks?.beforeCreateInvitation) {
				const response = await option?.organizationHooks.beforeCreateInvitation(
					{
						invitation: {
							...invitationData,
							inviterId: actor.id,
							teamId: teamIds.length > 0 ? teamIds[0] : undefined,
						},
						inviter: { ...actor.user },
						organization: { ...organization },
					},
				);
				if (response && typeof response === "object" && "data" in response) {
					invitationData = {
						...invitationData,
						...parseMutableInvitationFields(response.data, true),
						// Hooks may add or update declared additional fields, but cannot
						// redirect authorization-derived invitation authority.
						...invitationAuthority,
					};
				}
			}

			const persistInvitation = async () => {
				const canonicalRole = canonicalizeInvitationRole(invitationData.role);
				const protectedInvitation = {
					...invitationData,
					role: canonicalRole,
				};
				const lockedOrganization = (await lockAndRevalidateInvitationAuthority(
					ctx.context,
					ctx.context.orgOptions,
					protectedInvitation,
				)) as typeof organization;
				const liveActor = await resolveLiveInvitationActor(
					ctx.context,
					originalBearer,
				);
				const queueLegacyInvitationEmail = async (
					invitation: InferInvitation<O, false>,
					inviter: Member,
					lockedOrganization: typeof organization,
				) => {
					if (
						ctx.context.options.durableDelivery ||
						!ctx.context.orgOptions.sendInvitationEmail
					) {
						return;
					}
					await queueAfterTransactionHook(async () => {
						await ctx.context.runInBackgroundOrAwait(
							ctx.context.orgOptions.sendInvitationEmail!({
								id: invitation.id,
								role: invitation.role,
								email: invitation.email.toLowerCase(),
								organization: lockedOrganization,
								inviter: { ...inviter, user: liveActor.user },
								invitation,
							}, ctx.request),
						);
					}, ctx.context.adapter);
				};
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const liveMember = await revalidateInvitationCreator(
					ctx.context,
					ctx.context.orgOptions,
					organizationId,
					canonicalRole,
					liveActor.user.id,
				);
				const recipient = await transaction.findOne<{ id: string }>({
					model: "user",
					where: [{ field: "email", value: email }],
				});
				if (recipient) {
					const recipientMember = await transaction.findOne({
						model: "member",
						where: [
							{ field: "userId", value: recipient.id },
							{ field: "organizationId", value: organizationId },
						],
					});
					if (recipientMember) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION,
						);
					}
				}
				const livePending = (
					await transaction.findMany<InferInvitation<O, false>>({
						model: "invitation",
						where: [
							{ field: "organizationId", value: organizationId },
						],
					})
				).filter(
					(entry) =>
						entry.status === "pending" && new Date(entry.expiresAt) > new Date(),
				);
				const livePendingForRecipient = livePending
					.filter((entry) => entry.email.toLowerCase() === email)
					.sort((left, right) => String(left.id).localeCompare(String(right.id)));
				if (ctx.body.resend && livePendingForRecipient.length > 0) {
					const existingInvitation = livePendingForRecipient[0]!;
					const expiresAt = getDate(
						ctx.context.orgOptions.invitationExpiresIn || 60 * 60 * 48,
						"sec",
					);
					const updatedInvitation = await transaction.update<InferInvitation<O, false>>({
						model: "invitation",
						where: [
							{ field: "id", value: existingInvitation.id },
							{ field: "status", value: "pending" },
						],
						update: { expiresAt },
					});
					if (!updatedInvitation) {
						throw APIError.from(
							"BAD_REQUEST",
							ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
						);
					}
					for (const duplicate of livePendingForRecipient.slice(1)) {
						const canceledDuplicate = await adapter.updateInvitation({
							invitationId: duplicate.id,
							status: "canceled",
							fromStatus: "pending",
						});
						if (!canceledDuplicate) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
							);
						}
					}
					if (ctx.context.options.durableDelivery) {
						await ctx.context.options.durableDelivery.enqueue(transaction, {
							kind: "organization.invitation",
							sourceKey: `organization-invitation:${updatedInvitation.id}:${expiresAt.toISOString()}`,
							organizationId,
							actorId: actor.id,
							channel: "email",
							destination: updatedInvitation.email.toLowerCase(),
							payload: {
								template: "organization-invitation",
								to: updatedInvitation.email.toLowerCase(),
								role: updatedInvitation.role,
								organizationName: lockedOrganization.name,
								inviterName: liveActor.user.name,
								acceptanceUrl:
									ctx.context.options.durableDelivery.createInvitationUrl(
										updatedInvitation.id,
									),
							},
							semanticExpiresAt: expiresAt,
						});
					}
					await queueLegacyInvitationEmail(updatedInvitation, liveMember as Member, lockedOrganization);
					return { invitation: updatedInvitation, member: liveMember, resent: true as const };
				}
				if (
					livePendingForRecipient.length > 0 &&
					!ctx.context.orgOptions.cancelPendingInvitationsOnReInvite
				) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION,
					);
				}
				const invitationLimit =
					typeof ctx.context.orgOptions.invitationLimit === "function"
						? await ctx.context.orgOptions.invitationLimit(
								{
									user: liveActor.user,
									organization: lockedOrganization,
									member: liveMember as Member,
								},
								{
									...ctx.context,
									adapter: transaction as typeof ctx.context.adapter,
								},
							)
						: (ctx.context.orgOptions.invitationLimit ?? 100);
				const replacingPendingInvitations =
					livePendingForRecipient.length > 0 &&
					ctx.context.orgOptions.cancelPendingInvitationsOnReInvite;
				const pendingCountAfterReplacement =
					livePending.length -
					(replacingPendingInvitations ? livePendingForRecipient.length : 0);
				if (pendingCountAfterReplacement + 1 > invitationLimit) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.INVITATION_LIMIT_REACHED,
					);
				}
				if (replacingPendingInvitations) {
					for (const pendingInvitation of livePendingForRecipient) {
						const canceledInvitation = await adapter.updateInvitation({
							invitationId: pendingInvitation.id,
							status: "canceled",
							fromStatus: "pending",
						});
						if (!canceledInvitation) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
							);
						}
					}
				}
				const invitation = await adapter.createInvitation({
					invitation: protectedInvitation,
					user: liveActor.user,
				});
				if (ctx.context.options.durableDelivery) {
					const transaction = await getCurrentAdapter(ctx.context.adapter);
					await ctx.context.options.durableDelivery.enqueue(transaction, {
						kind: "organization.invitation",
						sourceKey: `organization-invitation:${invitation.id}:${invitation.expiresAt.toISOString()}`,
						organizationId,
						actorId: actor.id,
						channel: "email",
						destination: invitation.email.toLowerCase(),
						payload: {
							template: "organization-invitation",
							to: invitation.email.toLowerCase(),
							role: invitation.role,
							organizationName: lockedOrganization.name,
							inviterName: liveActor.user.name,
							acceptanceUrl:
								ctx.context.options.durableDelivery.createInvitationUrl(
									invitation.id,
								),
						},
						semanticExpiresAt: invitation.expiresAt,
					});
				}
				await queueLegacyInvitationEmail(invitation, liveMember as Member, lockedOrganization);
				return { invitation, member: liveMember, actor: liveActor.user, organization: lockedOrganization, resent: false as const };
			};
			const persisted = await runWithTransaction(
				ctx.context.adapter,
				persistInvitation,
			);
			const invitation = persisted.invitation;

			if (persisted.resent) {
				return ctx.json(invitation as InferInvitation<O>);
			}

			// Run afterCreateInvitation hook
			if (option?.organizationHooks?.afterCreateInvitation) {
				await runAfterLifecycleCommit(ctx.context, () =>
					option.organizationHooks!.afterCreateInvitation!({
						invitation: invitation as unknown as Invitation,
						inviter: { ...persisted.actor },
						organization: persisted.organization,
					}),
				);
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
	rejectNestedCookieLifecycleEndpoint(createAuthEndpoint(
		"/organization/accept-invitation",
		{
			method: "POST",
			body: acceptInvitationBodySchema,
			requireHeaders: true,
			use: [
				rejectUnsupportedManagedOrganizationTransition,
				rejectNestedCookieLifecycleRoute,
				orgMiddleware,
				orgSessionMiddleware,
			],
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
			await rejectNestedCookieLifecycleTransaction(ctx.context);
			assertManagedOrganizationTransitionSupported(ctx.context);
			const session = ctx.context.session;
			const originalBearer = captureOriginalInvitationBearer(session);
			const actor = { id: session.user.id, user: { ...session.user } };
			const adapter = getOrgAdapter<O>(ctx.context, options);
			await requireOrganizationLifecycleTransaction(ctx.context);
			const invitation = await adapter.findInvitationById(
				ctx.body.invitationId,
			);

			if (
				!invitation ||
				invitation.expiresAt <= new Date() ||
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
					invitation: { ...invitation } as unknown as Invitation,
					user: { ...actor.user },
					organization: { ...organization },
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
			const acquireOrganizationLock = async () => {
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const lockedOrganization = await transaction.update({
					model: "organization",
					where: [{ field: "id", value: invitation.organizationId }],
					update: { updatedAt: new Date() },
				});
				if (!lockedOrganization) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
			};
			let preparedSuccessor:
				| Awaited<ReturnType<typeof adapter.setActiveOrganization>>
				| undefined;
			let activeSession: Awaited<ReturnType<typeof adapter.setActiveOrganization>>;
			let liveActor: Awaited<ReturnType<typeof resolveLiveInvitationActor>> | undefined;
			try {
				activeSession = await adapter.setActiveOrganization(
					session.session.token,
					invitation.organizationId,
					ctx,
					{
						beforeCapture: acquireOrganizationLock,
						propagateAfterTransactionHookError: true,
						onSuccessorPrepared: (successor) => {
							preparedSuccessor = successor;
						},
						afterCapture: async () => {
						const currentActor = await resolveLiveInvitationActor(
							ctx.context,
							originalBearer,
						);
						liveActor = currentActor;
						// Everything that makes an invitation accepted is owned by the same
						// transaction as managed successor issuance. Re-read every mutable
						// input after capture so a stale preflight can never be committed.
						const liveInvitation = await adapter.findInvitationById(
							ctx.body.invitationId,
						);
						if (
							!liveInvitation ||
							liveInvitation.status !== "pending" ||
							liveInvitation.expiresAt <= new Date() ||
							liveInvitation.organizationId !== invitation.organizationId ||
							liveInvitation.email.toLowerCase() !==
								 currentActor.user.email.toLowerCase()
						) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
							);
						}
						const liveOrganization = await adapter.findOrganizationById(
							liveInvitation.organizationId,
						);
						if (!liveOrganization) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
							);
						}
						if (
							await adapter.findMemberByEmail({
								email: currentActor.user.email,
								organizationId: liveInvitation.organizationId,
							})
						) {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION,
							);
						}
						const membershipLimit =
							ctx.context.orgOptions?.membershipLimit || 100;
						const limit =
							typeof membershipLimit === "number"
								? membershipLimit
								: await membershipLimit(currentActor.user, liveOrganization);
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
										organizationId: acceptedInvitation.organizationId,
										teamId,
									userId: currentActor.user.id,
										maximumMembersPerTeam,
									});
									if (result.status !== "added") {
										if (result.status === "limitReached") {
											throw APIError.from(
												"FORBIDDEN",
												ORGANIZATION_ERROR_CODES.TEAM_MEMBER_LIMIT_REACHED,
											);
										}
										if (result.status === "organizationNotFound") {
											throw APIError.from(
												"BAD_REQUEST",
												ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
											);
										}
										if (result.status === "teamNotFound") {
											throw APIError.from(
												"BAD_REQUEST",
												ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
											);
										}
										throw APIError.from(
											"INTERNAL_SERVER_ERROR",
											ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED,
										);
									}
								} else {
									const result = await adapter.findOrCreateTeamMember({
										organizationId: acceptedInvitation.organizationId,
										teamId,
										userId: currentActor.user.id,
									});
									if (result.status !== "added") {
										if (result.status === "organizationNotFound") {
											throw APIError.from(
												"BAD_REQUEST",
												ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
											);
										}
										if (result.status === "teamNotFound") {
											throw APIError.from(
												"BAD_REQUEST",
												ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
											);
										}
										throw APIError.from(
											"INTERNAL_SERVER_ERROR",
											ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED,
										);
									}
								}
							}
						}

						const acceptedRole = canonicalizeInvitationRole(
							acceptedInvitation.role,
						);
						await revalidateInvitationDynamicRoles(
							ctx.context,
							ctx.context.orgOptions,
							acceptedInvitation.organizationId,
							acceptedRole,
						);
						const acceptedMember = await adapter.createMember({
							organizationId: acceptedInvitation.organizationId,
							userId: currentActor.user.id,
							role: acceptedRole,
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
						if (options?.organizationHooks?.afterAcceptInvitation) {
							await queueAfterTransactionHook(
								() =>
									options.organizationHooks!.afterAcceptInvitation!({
										invitation: acceptedInvitation as unknown as Invitation,
										member: acceptedMember,
										user: { ...currentActor.user },
										organization: liveOrganization,
									}),
								ctx.context.adapter,
							);
						}
						},
					},
				);
			} catch (error) {
				if (isAfterTransactionHookFailure(error) && preparedSuccessor) {
					await publishSessionCookie(ctx, {
						session: preparedSuccessor,
						user: liveActor?.user ?? actor.user,
					});
					throw new APIError(
						"INTERNAL_SERVER_ERROR",
						{
							code: "AFTER_TRANSACTION_HOOK_FAILED",
							message: error.message,
							cause: error,
						},
						ctx.responseHeaders,
					);
				}
				throw error;
			}
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
							userId: liveActor?.user.id ?? actor.id,
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
					await publishSessionCookie(ctx, { session: activeSession, user: liveActor?.user ?? actor.user });
					throw error;
				}
			}
			await publishSessionCookie(ctx, { session: activeSession, user: liveActor?.user ?? actor.user });

			return ctx.json({
				invitation: acceptedI,
				member: acceptedMember,
			});
		},
	));

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
			await requireOrganizationLifecycleTransaction(ctx.context);
			const session = ctx.context.session;
			const originalBearer = captureOriginalInvitationBearer(session);
			const actor = { id: session.user.id, user: { ...session.user } };
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
					invitation: { ...invitation } as unknown as Invitation,
					user: { ...actor.user },
					organization: { ...organization },
				});
			}

			const rejectedI = await runWithTransaction(ctx.context.adapter, async () => {
				const lockedOrganization = await lockOrganizationInvitationMutation(
					ctx.context,
					invitation.organizationId,
				);
				const liveActor = await resolveLiveInvitationActor(
					ctx.context,
					originalBearer,
				);
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const liveInvitation = await transaction.findOne<Invitation>({
					model: "invitation",
					where: [{ field: "id", value: ctx.body.invitationId }],
				});
				if (!liveInvitation || liveInvitation.status !== "pending") {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
					);
				}
				if (
					liveInvitation.organizationId !== invitation.organizationId ||
					liveInvitation.email.toLowerCase() !== liveActor.user.email.toLowerCase()
				) {
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
					!liveActor.user.emailVerified
				) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION,
					);
				}
				const rejectedInvitation = await adapter.updateInvitation({
					invitationId: liveInvitation.id,
					status: "rejected",
					fromStatus: "pending",
				});
				if (!rejectedInvitation) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
					);
				}
				if (options?.organizationHooks?.afterRejectInvitation) {
					await queueAfterTransactionHook(
						() =>
							options.organizationHooks!.afterRejectInvitation!({
								invitation: rejectedInvitation as unknown as Invitation,
								user: { ...liveActor.user },
								organization: lockedOrganization as typeof organization,
							}),
						ctx.context.adapter,
					);
				}
				return rejectedInvitation;
			});

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
			await requireOrganizationLifecycleTransaction(ctx.context);
			const session = ctx.context.session;
			const originalBearer = captureOriginalInvitationBearer(session);
			const actor = { id: session.user.id, user: { ...session.user } };
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const transactionContext = {
				...ctx,
				context: {
					...ctx.context,
					adapter: await getCurrentAdapter(ctx.context.adapter),
				},
			};
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
				transactionContext as unknown as Parameters<typeof hasPermission>[1],
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
					invitation: { ...invitation } as unknown as Invitation,
					cancelledBy: { ...actor.user },
					organization: { ...organization },
				});
			}

			const canceledI = await runWithTransaction(ctx.context.adapter, async () => {
				const lockedOrganization = await lockOrganizationInvitationMutation(
					ctx.context,
					invitation.organizationId,
				);
				const liveActor = await resolveLiveInvitationActor(
					ctx.context,
					originalBearer,
				);
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const liveInvitation = await transaction.findOne<Invitation>({
					model: "invitation",
					where: [{ field: "id", value: ctx.body.invitationId }],
				});
				if (
					!liveInvitation ||
					liveInvitation.status !== "pending" ||
					liveInvitation.organizationId !== invitation.organizationId
				) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
					);
				}
				await revalidateInvitationCanceler(
					ctx.context,
					ctx.context.orgOptions,
					liveInvitation.organizationId,
					liveActor.user.id,
				);
				const canceledInvitation = await adapter.updateInvitation({
					invitationId: liveInvitation.id,
					status: "canceled",
					fromStatus: "pending",
				});
				if (!canceledInvitation) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.INVITATION_NOT_FOUND,
					);
				}
				if (options?.organizationHooks?.afterCancelInvitation) {
					await queueAfterTransactionHook(
						() =>
							options.organizationHooks!.afterCancelInvitation!({
								invitation: canceledInvitation as unknown as Invitation,
								cancelledBy: { ...liveActor.user },
								organization: lockedOrganization as typeof organization,
							}),
						ctx.context.adapter,
					);
				}
				return canceledInvitation;
			});

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
