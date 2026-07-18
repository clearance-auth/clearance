import { createAuthEndpoint, createAuthMiddleware } from "@clearance/core/api";
import {
	AfterTransactionHookError,
	getCurrentAdapter,
	isTransactionActive,
	queueAfterTransactionHook,
	runWithTransaction,
} from "@clearance/core/context";
import { APIError } from "@clearance/core/error";
import type { Endpoint } from "@clearance/call";
import * as z from "zod";
import { getSessionFromCtx, requestOnlySessionMiddleware } from "../../../api";
import { rejectActiveTransactionEndpoint } from "../../../api/dispatch";
import { deleteSessionCookie, setSessionCookie } from "../../../cookies";
import type { InferAdditionalFieldsFromPluginOptions } from "../../../db";
import { toZodSchema } from "../../../db";
import type { Session } from "../../../types";
import {
	assertManagedOrganizationTransitionSupported,
	getOrgAdapter,
} from "../adapter";
import { orgMiddleware, orgSessionMiddleware } from "../call";
import { ORGANIZATION_ERROR_CODES } from "../error-codes";
import { hasPermission } from "../has-permission";
import type {
	InferInvitation,
	InferMember,
	InferOrganization,
	InferTeam,
	Member,
	TeamMember,
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

const ORGANIZATION_SECONDARY_SESSION_REVOCATION_UNSUPPORTED = {
	code: "ORGANIZATION_SECONDARY_SESSION_REVOCATION_UNSUPPORTED",
	message:
		"Organization deletion requires database-backed sessions when secondary storage is configured",
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

const rejectUnsupportedManagedOrganizationTransition = createAuthMiddleware(
	async (ctx) => {
		assertManagedOrganizationTransitionSupported(ctx.context);
		return {};
	},
) as typeof orgMiddleware;

const rejectSecondaryOnlyOrganizationDeletion = createAuthMiddleware(
	async (ctx) => {
		if (
			ctx.context.options.secondaryStorage &&
			ctx.context.options.session?.storeSessionInDatabase !== true
		) {
			throw APIError.from(
				"INTERNAL_SERVER_ERROR",
				ORGANIZATION_SECONDARY_SESSION_REVOCATION_UNSUPPORTED,
			);
		}
		return {};
	},
) as typeof orgMiddleware;

function rejectNestedCookieLifecycleEndpoint<T extends Endpoint>(
	endpoint: T,
): T {
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

/**
 * Serialize organization-lifecycle decisions with the mutations that remove
 * membership or destroy an organization. Updating the row is intentionally
 * used as the portable row-lock primitive supported by the DB adapter.
 */
async function lockOrganizations(
	context: Parameters<typeof getOrgAdapter>[0],
	organizationIds: Array<string | null | undefined>,
) {
	const transaction = await getCurrentAdapter(context.adapter);
	const lockedOrganizationIds = new Set<string>();
	for (const organizationId of [...new Set(organizationIds.filter((id): id is string => Boolean(id)))].sort()) {
		const organization = await transaction.update({
			model: "organization",
			where: [{ field: "id", value: organizationId }],
			update: { updatedAt: new Date() },
		});
		if (organization) lockedOrganizationIds.add(organizationId);
	}
	return lockedOrganizationIds;
}

/** Serializes per-user organization admission decisions under READ COMMITTED. */
async function lockOrganizationCreator(
	context: Parameters<typeof getOrgAdapter>[0],
	userId: string,
) {
	const transaction = await getCurrentAdapter(context.adapter);
	return transaction.update({
		model: "user",
		where: [{ field: "id", value: userId }],
		update: { updatedAt: new Date() },
	});
}

/** Revoke only the original stale scope; a concurrent A -> B update wins. */
async function revokeExactStaleOrganizationSession(
	context: Parameters<typeof getOrgAdapter>[0],
	bearer: { sessionId: string; userId: string; token: string; organizationId: string },
) {
	const transaction = await getCurrentAdapter(context.adapter);
	const persistedSession = await transaction.findOne<{
		id: string;
		userId: string;
		activeOrganizationId?: string | null;
	}>({
		model: "session",
		where: [
			{ field: "id", value: bearer.sessionId },
			{ field: "userId", value: bearer.userId },
		],
	});
	const presentedSession = await context.internalAdapter.findSession(bearer.token);
	if (
		!persistedSession ||
		presentedSession?.session.id !== bearer.sessionId ||
		presentedSession.session.userId !== bearer.userId ||
		presentedSession.session.token !== bearer.token ||
		persistedSession.activeOrganizationId !== bearer.organizationId
	) return false;
	const persistedMembership = await transaction.findOne<Member>({
		model: "member",
		where: [
			{ field: "userId", value: bearer.userId },
			{ field: "organizationId", value: bearer.organizationId },
		],
	});
	if (persistedMembership) return false;
	const lockedSession = await transaction.update({
		model: "session",
		where: [
			{ field: "id", value: bearer.sessionId },
			{ field: "userId", value: bearer.userId },
			{ field: "activeOrganizationId", value: bearer.organizationId },
		],
		update: { updatedAt: new Date() },
	});
	if (!lockedSession) return false;
	// Keep database revocation and any secondary-storage cleanup owned by this
	// exact transaction. A cleanup failure is deliberately observable to callers.
	await context.internalAdapter.deleteSession(bearer.token);
	return true;
}

const baseOrganizationSchema = z.object({
	name: z.string().min(1).meta({
		description: "The name of the organization",
	}),
	slug: z.string().min(1).meta({
		description: "The slug of the organization",
	}),
	userId: z.coerce
		.string()
		.meta({
			description:
				'The user id of the organization creator. If not provided, the current user will be used. Should only be used by admins or when called by the server. server-only. Eg: "user-id"',
		})
		.optional(),
	logo: z
		.string()
		.meta({
			description: "The logo of the organization",
		})
		.nullish(),
	metadata: z
		.record(z.string(), z.any())
		.meta({
			description: "The metadata of the organization",
		})
		.optional(),
	keepCurrentActiveOrganization: z
		.boolean()
		.meta({
			description:
				"Whether to keep the current active organization active after creating a new one. Eg: true",
		})
		.optional(),
});

export const createOrganization = <O extends OrganizationOptions>(
	options?: O | undefined,
) => {
	const additionalFieldsSchema = toZodSchema({
		fields: options?.schema?.organization?.additionalFields || {},
		isClientSide: true,
	});

	type Body = InferAdditionalFieldsFromPluginOptions<"organization", O> &
		z.infer<typeof baseOrganizationSchema>;

	return rejectNestedCookieLifecycleEndpoint(createAuthEndpoint(
		"/organization/create",
		{
			method: "POST",
			body: z.object({
				...baseOrganizationSchema.shape,
				...additionalFieldsSchema.shape,
			}),
			use: [
				rejectUnsupportedManagedOrganizationTransition,
				rejectNestedCookieLifecycleRoute,
				orgMiddleware,
			],
			metadata: {
				$Infer: {
					body: {} as Body,
				},
				openapi: {
					description: "Create an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										description: "The organization that was created",
										$ref: "#/components/schemas/Organization",
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
			if (session && !ctx.body.keepCurrentActiveOrganization) {
				await rejectNestedCookieLifecycleTransaction(ctx.context);
			}

			if (!session && (ctx.request || ctx.headers)) {
				throw APIError.fromStatus("UNAUTHORIZED");
			}
			let user = session?.user || null;
			if (!user) {
				if (!ctx.body.userId) {
					throw APIError.fromStatus("UNAUTHORIZED");
				}
				user = await ctx.context.internalAdapter.findUserById(ctx.body.userId);
			}
			if (!user) {
				throw APIError.fromStatus("UNAUTHORIZED");
			}
			const options = ctx.context.orgOptions;
			const canCreateOrg =
				typeof options?.allowUserToCreateOrganization === "function"
					? await options.allowUserToCreateOrganization(user)
					: options?.allowUserToCreateOrganization === undefined
						? true
						: options.allowUserToCreateOrganization;

			const isSystemAction = !session && ctx.body.userId;

			if (!canCreateOrg && !isSystemAction) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION,
				);
			}
			const adapter = getOrgAdapter<O>(ctx.context, options as O);

			const userOrganizations = await adapter.listOrganizations(user.id);
			const hasReachedOrgLimit =
				typeof options.organizationLimit === "number"
					? userOrganizations.length >= options.organizationLimit
					: typeof options.organizationLimit === "function"
						? await options.organizationLimit(user)
						: false;

			if (hasReachedOrgLimit) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS,
				);
			}

			const existingOrganization = await adapter.findOrganizationBySlug(
				ctx.body.slug,
			);
			if (existingOrganization) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_ALREADY_EXISTS,
				);
			}

			let {
				keepCurrentActiveOrganization: _,
				userId: __,
				...orgData
			} = ctx.body;

			if (options?.organizationHooks?.beforeCreateOrganization) {
				const response =
					await options?.organizationHooks.beforeCreateOrganization({
						organization: orgData,
						user,
					});
				if (response && typeof response === "object" && "data" in response) {
					orgData = {
						...ctx.body,
						...response.data,
					};
				}
			}

			await requireOrganizationLifecycleTransaction(ctx.context);
			const { organization, member } = await runWithTransaction(
				ctx.context.adapter,
				async () => {
					if (!(await lockOrganizationCreator(ctx.context, user.id))) {
						throw APIError.fromStatus("UNAUTHORIZED");
					}
					const liveOrganizations = await adapter.listOrganizations(user.id);
					const hasReachedLockedOrganizationLimit =
						typeof options.organizationLimit === "number"
							? liveOrganizations.length >= options.organizationLimit
							: typeof options.organizationLimit === "function"
								? await options.organizationLimit(user)
								: false;
					if (hasReachedLockedOrganizationLimit) {
							throw APIError.from(
								"FORBIDDEN",
								ORGANIZATION_ERROR_CODES.YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS,
							);
					}
					const organization = await adapter.createOrganization({
						organization: { ...orgData, createdAt: new Date() },
					});
					let member: Member & InferAdditionalFieldsFromPluginOptions<"member", O, false>;
					let teamMember: TeamMember | null = null;
					let data = {
						userId: user.id,
						organizationId: organization.id,
						role: options?.creatorRole ?? "owner",
					};
					if (options?.organizationHooks?.beforeAddMember) {
						const response = await options.organizationHooks.beforeAddMember({
							member: { ...data }, user, organization,
						});
						if (response && typeof response === "object" && "data" in response) {
							data = {
								...data,
								...response.data,
								userId: user.id,
								organizationId: organization.id,
								role: options?.creatorRole ?? "owner",
							};
						}
					}
					member = await adapter.createMember(data);
					let defaultTeam: InferTeam<O> | undefined;
					if (options?.teams?.enabled && options.teams.defaultTeam?.enabled !== false) {
						let teamData = {
							organizationId: organization.id,
							name: `${organization.name}`,
							createdAt: new Date(),
						};
						if (options.organizationHooks?.beforeCreateTeam) {
							const response = await options.organizationHooks.beforeCreateTeam({
								team: { organizationId: organization.id, name: `${organization.name}` },
								user, organization,
							});
							if (response && typeof response === "object" && "data" in response) {
								teamData = {
									...teamData,
									...response.data,
									organizationId: organization.id,
								};
							}
						}
						const transactionContext = {
							...ctx,
							context: {
								...ctx.context,
								adapter: await getCurrentAdapter(ctx.context.adapter),
							},
						} as unknown as typeof ctx;
						const customDefaultTeam =
							await options.teams.defaultTeam?.customCreateDefaultTeam?.(
								organization,
								transactionContext,
							);
						let createdDefaultTeam: InferTeam<O>;
						if (customDefaultTeam) {
							createdDefaultTeam = customDefaultTeam as InferTeam<O>;
						} else {
							const createDefaultTeamResult = await adapter.createTeam(teamData);
							if (createDefaultTeamResult.status === "transactionRequired") {
								await requireOrganizationLifecycleTransaction(ctx.context);
								throw new Error("unreachable");
							}
							if (createDefaultTeamResult.status === "organizationNotFound") {
								throw APIError.from(
									"BAD_REQUEST",
									ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
								);
							}
							if (createDefaultTeamResult.status === "limitReached") {
								throw APIError.from(
									"BAD_REQUEST",
									ORGANIZATION_ERROR_CODES.YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS,
								);
							}
							createdDefaultTeam = createDefaultTeamResult.team;
						}
						defaultTeam = createdDefaultTeam;
						const defaultTeamMember = await adapter.findOrCreateTeamMember({
							organizationId: organization.id,
							teamId: createdDefaultTeam.id,
							userId: user.id,
						});
						if (defaultTeamMember.status === "transactionRequired") {
							await requireOrganizationLifecycleTransaction(ctx.context);
							throw new Error("unreachable");
						}
						if (defaultTeamMember.status === "organizationNotFound") {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
							);
						}
						if (defaultTeamMember.status === "teamNotFound") {
							throw APIError.from(
								"BAD_REQUEST",
								ORGANIZATION_ERROR_CODES.TEAM_NOT_FOUND,
							);
						}
						teamMember = defaultTeamMember.member;
					}
					let activeSession = null;
					if (ctx.context.session && !ctx.body.keepCurrentActiveOrganization) {
						activeSession = await adapter.setActiveOrganization(ctx.context.session.session.token, organization.id, ctx);
						if (teamMember) {
							const [selectedTeam, selectedTeamMember] = await Promise.all([
								adapter.findTeamById({ teamId: teamMember.teamId, organizationId: organization.id }),
								adapter.findTeamMember({ teamId: teamMember.teamId, userId: user.id }),
							]);
							if (selectedTeam && selectedTeamMember) activeSession = await adapter.setActiveTeam(activeSession.token, selectedTeam.id, ctx);
						}
					}
					if (options?.organizationHooks?.afterAddMember) await runAfterLifecycleCommit(ctx.context, () => options.organizationHooks!.afterAddMember!({ member, user, organization }));
					if (defaultTeam && options?.organizationHooks?.afterCreateTeam) await runAfterLifecycleCommit(ctx.context, () => options.organizationHooks!.afterCreateTeam!({ team: defaultTeam!, user, organization }));
					if (options?.organizationHooks?.afterCreateOrganization) await runAfterLifecycleCommit(ctx.context, () => options.organizationHooks!.afterCreateOrganization!({ organization, user, member }));
					if (activeSession) await publishSessionCookie(ctx, { session: activeSession, user: ctx.context.session!.user });
					return { organization, member };
				},
			);

			return ctx.json({
				...organization,
				metadata:
					organization.metadata && typeof organization.metadata === "string"
						? JSON.parse(organization.metadata)
						: organization.metadata,
				members: [member],
			});
		},
	));
};

const checkOrganizationSlugBodySchema = z.object({
	slug: z.string().meta({
		description: 'The organization slug to check. Eg: "my-org"',
	}),
});

export const checkOrganizationSlug = <O extends OrganizationOptions>(
	options: O,
) =>
	createAuthEndpoint(
		"/organization/check-slug",
		{
			method: "POST",
			body: checkOrganizationSlugBodySchema,
			use: [requestOnlySessionMiddleware, orgMiddleware],
		},
		async (ctx) => {
			const orgAdapter = getOrgAdapter<O>(ctx.context, options);
			const org = await orgAdapter.findOrganizationBySlug(ctx.body.slug);
			if (!org) {
				return ctx.json({
					status: true,
				});
			}
			throw APIError.from(
				"BAD_REQUEST",
				ORGANIZATION_ERROR_CODES.ORGANIZATION_SLUG_ALREADY_TAKEN,
			);
		},
	);

const baseUpdateOrganizationSchema = z.object({
	name: z
		.string()
		.min(1)
		.meta({
			description: "The name of the organization",
		})
		.optional(),
	slug: z
		.string()
		.min(1)
		.meta({
			description: "The slug of the organization",
		})
		.optional(),
	logo: z
		.string()
		.meta({
			description: "The logo of the organization",
		})
		.nullish(),
	metadata: z
		.record(z.string(), z.any())
		.meta({
			description: "The metadata of the organization",
		})
		.optional(),
});

export const updateOrganization = <O extends OrganizationOptions>(
	options?: O | undefined,
) => {
	const additionalFieldsSchema = toZodSchema({
		fields: options?.schema?.organization?.additionalFields || {},
		isClientSide: true,
	});
	type Body = {
		data: {
			name?: string | undefined;
			slug?: string | undefined;
			logo?: string | null | undefined;
			metadata?: Record<string, any> | undefined;
		} & Partial<InferAdditionalFieldsFromPluginOptions<"organization", O>>;
		organizationId?: string | undefined;
	};
	return createAuthEndpoint(
		"/organization/update",
		{
			method: "POST",
			body: z.object({
				data: z
					.object({
						...additionalFieldsSchema.shape,
						...baseUpdateOrganizationSchema.shape,
					})
					.partial(),
				organizationId: z
					.string()
					.meta({
						description: 'The organization ID. Eg: "org-id"',
					})
					.optional(),
			}),
			requireHeaders: true,
			use: [orgMiddleware],
			metadata: {
				$Infer: {
					body: {} as Body,
				},
				openapi: {
					description: "Update an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										description: "The updated organization",
										$ref: "#/components/schemas/Organization",
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
			const session = await ctx.context.getSession(ctx);
			if (!session) {
				throw APIError.fromStatus("UNAUTHORIZED", {
					message: "User not found",
				});
			}
			const organizationId =
				ctx.body.organizationId || session.session.activeOrganizationId;
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
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
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
				);
			}
			const canUpdateOrg = await hasPermission(
				{
					permissions: {
						organization: ["update"],
					},
					role: member.role,
					options: ctx.context.orgOptions,
					organizationId,
				},
				ctx,
			);
			if (!canUpdateOrg) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION,
				);
			}
			// Check if slug is being updated and validate uniqueness
			if (typeof ctx.body.data.slug === "string") {
				const existingOrganization = await adapter.findOrganizationBySlug(
					ctx.body.data.slug,
				);
				if (
					existingOrganization &&
					existingOrganization.id !== organizationId
				) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_SLUG_ALREADY_TAKEN,
					);
				}
			}
			if (options?.organizationHooks?.beforeUpdateOrganization) {
				const response =
					await options.organizationHooks.beforeUpdateOrganization({
						organization: ctx.body.data,
						user: session.user,
						member,
					});
				if (response && typeof response === "object" && "data" in response) {
					ctx.body.data = {
						...ctx.body.data,
						...response.data,
					};
				}
			}
			const { updatedOrg } = await runWithTransaction(
				ctx.context.adapter,
				async () => {
					const lockedOrganizationIds = await lockOrganizations(ctx.context, [organizationId]);
					if (!lockedOrganizationIds.has(organizationId)) {
						throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND);
					}
					const currentMember = await adapter.findMemberByOrgId({ userId: session.user.id, organizationId });
					if (!currentMember) throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION);
					const lockedContext = {
						...ctx,
						context: {
							...ctx.context,
							adapter: await getCurrentAdapter(ctx.context.adapter),
						},
					} as unknown as Parameters<typeof hasPermission>[1];
					const canStillUpdateOrg = await hasPermission({
						permissions: { organization: ["update"] },
						role: currentMember.role,
						options: ctx.context.orgOptions,
						organizationId,
					}, lockedContext);
					if (!canStillUpdateOrg) throw APIError.from("FORBIDDEN", ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION);
					if (typeof ctx.body.data.slug === "string") {
						const existingOrganization = await adapter.findOrganizationBySlug(ctx.body.data.slug);
						if (existingOrganization && existingOrganization.id !== organizationId) {
							throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ORGANIZATION_SLUG_ALREADY_TAKEN);
						}
					}
					const updatedOrg = await adapter.updateOrganization(organizationId, ctx.body.data);
					if (!updatedOrg) throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND);
					if (options?.organizationHooks?.afterUpdateOrganization) {
						await runAfterLifecycleCommit(ctx.context, () => options.organizationHooks!.afterUpdateOrganization!({ organization: updatedOrg, user: session.user, member: currentMember }));
					}
					return { updatedOrg, member: currentMember };
				},
			);
			return ctx.json(updatedOrg);
		},
		);
};

const deleteOrganizationBodySchema = z.object({
	organizationId: z.string().meta({
		description: "The organization id to delete",
	}),
});

export const deleteOrganization = <O extends OrganizationOptions>(
	options: O,
) => {
	return rejectNestedCookieLifecycleEndpoint(createAuthEndpoint(
		"/organization/delete",
		{
			method: "POST",
			body: deleteOrganizationBodySchema,
			requireHeaders: true,
			use: [
				rejectUnsupportedManagedOrganizationTransition,
				rejectSecondaryOnlyOrganizationDeletion,
				rejectNestedCookieLifecycleRoute,
				orgMiddleware,
			],
			metadata: {
				openapi: {
					description: "Delete an organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "string",
										description: "The organization id that was deleted",
									},
								},
							},
						},
					},
				},
			},
		},
		async (ctx) => {
			const disableOrganizationDeletion =
				ctx.context.orgOptions.disableOrganizationDeletion;
			if (disableOrganizationDeletion) {
				throw APIError.from("NOT_FOUND", {
					message: "Organization deletion is disabled",
					code: "ORGANIZATION_DELETION_DISABLED",
				});
			}
			const session = await ctx.context.getSession(ctx);
			if (!session) {
				throw APIError.fromStatus("UNAUTHORIZED");
			}

			const organizationId = ctx.body.organizationId;
			if (!organizationId) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
			}
			if (organizationId === session.session.activeOrganizationId) {
				await rejectNestedCookieLifecycleTransaction(ctx.context);
			}
			await requireOrganizationLifecycleTransaction(ctx.context);
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const member = await adapter.findMemberByOrgId({
				userId: session.user.id,
				organizationId: organizationId,
			});
			if (!member) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
				);
			}
			const canDeleteOrg = await hasPermission(
				{
					role: member.role,
					permissions: {
						organization: ["delete"],
					},
					organizationId,
					options: ctx.context.orgOptions,
				},
				ctx,
			);
			if (!canDeleteOrg) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION,
				);
			}
			const org = await adapter.findOrganizationById(organizationId);
			if (!org) {
				throw APIError.fromStatus("BAD_REQUEST");
			}
			if (options?.organizationHooks?.beforeDeleteOrganization) {
				await options.organizationHooks.beforeDeleteOrganization(
					{
						organization: org,
						user: session.user,
					},
					ctx,
				);
			}
			const acquireOrganizationLock = async () => {
				if (!(await lockOrganizations(ctx.context, [organizationId])).has(organizationId)) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
			};
			const revokeOtherOrganizationSessions = async () => {
				const transaction = await getCurrentAdapter(ctx.context.adapter);
				const scopedSessions = await transaction.findMany<{
					id: string;
					token: string;
					activeOrganizationId?: string | null;
				}>({
					model: "session",
					where: [{ field: "activeOrganizationId", value: organizationId }],
				});
				for (const scopedSession of scopedSessions) {
					if (scopedSession.id !== session.session.id) {
						await ctx.context.internalAdapter.deleteSession(scopedSession.token);
					}
				}
			};
			const deleteOrganizationInOwningTransaction = async () => {
				const currentMember = await adapter.findMemberByOrgId({
					userId: session.user.id,
					organizationId,
				});
				if (!currentMember) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
					);
				}
				const lockedContext = {
					...ctx,
					context: {
						...ctx.context,
						adapter: await getCurrentAdapter(ctx.context.adapter),
					},
				} as unknown as Parameters<typeof hasPermission>[1];
				const canStillDeleteOrg = await hasPermission(
					{
						role: currentMember.role,
						permissions: { organization: ["delete"] },
						organizationId,
						options: ctx.context.orgOptions,
					},
					lockedContext,
				);
				if (!canStillDeleteOrg) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION,
					);
				}
				const currentOrganization = await adapter.findOrganizationById(organizationId);
				if (!currentOrganization) {
					throw APIError.from(
						"BAD_REQUEST",
						ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
					);
				}
				await revokeOtherOrganizationSessions();
				await adapter.deleteOrganization(organizationId);
				if (options?.organizationHooks?.afterDeleteOrganization) {
					await runAfterLifecycleCommit(ctx.context, () =>
						options.organizationHooks!.afterDeleteOrganization!(
							{ organization: org, user: session.user },
							ctx,
						),
					);
				}
			};
			if (organizationId === session.session.activeOrganizationId) {
				let preparedSuccessor: Awaited<ReturnType<typeof adapter.setActiveOrganization>> | undefined;
				try {
					const updatedSession = await adapter.setActiveOrganization(
						session.session.token,
						null,
						ctx,
						{
							beforeCapture: acquireOrganizationLock,
							afterCapture: deleteOrganizationInOwningTransaction,
							propagateAfterTransactionHookError: true,
							onSuccessorPrepared: (successor) => {
								preparedSuccessor = successor;
							},
						},
					);
					await publishSessionCookie(ctx, { session: updatedSession, user: session.user });
				} catch (error) {
					const committedLegacySession =
						error instanceof AfterTransactionHookError && !preparedSuccessor
							? await ctx.context.internalAdapter
									.findSession(session.session.token)
									.then((current) =>
										current?.session.id === session.session.id &&
										current.session.userId === session.user.id &&
										current.session.token === session.session.token &&
										current.session.activeOrganizationId === null
											? (current.session as Session)
											: null,
									)
							: null;
					const committedSession = preparedSuccessor ?? committedLegacySession;
					if (error instanceof AfterTransactionHookError && committedSession) {
						await publishSessionCookie(ctx, {
							session: committedSession,
							user: session.user,
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
			} else {
				await runWithTransaction(
					ctx.context.adapter,
					async () => {
						await acquireOrganizationLock();
						return deleteOrganizationInOwningTransaction();
					},
				);
			}
			return ctx.json(org);
		},
		));
};

const getFullOrganizationQuerySchema = z.optional(
	z.object({
		organizationId: z
			.string()
			.meta({
				description: "The organization id to get",
			})
			.optional(),
		organizationSlug: z
			.string()
			.meta({
				description: "The organization slug to get",
			})
			.optional(),
		membersLimit: z
			.number()
			.or(z.string().transform((val) => parseInt(val)))
			.meta({
				description:
					"The limit of members to get. By default, it uses the membershipLimit option.",
			})
			.optional(),
	}),
);

export const getFullOrganization = <O extends OrganizationOptions>(
	options: O,
) =>
	rejectNestedCookieLifecycleEndpoint(createAuthEndpoint(
		"/organization/get-full-organization",
		{
			method: "GET",
			query: getFullOrganizationQuerySchema,
			requireHeaders: true,
			use: [rejectNestedCookieLifecycleRoute, orgMiddleware, orgSessionMiddleware],
			metadata: {
				openapi: {
					operationId: "getOrganization",
					description: "Get the full organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										description: "The organization",
										$ref: "#/components/schemas/Organization",
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
			const session = ctx.context.session;
			const organizationId =
				ctx.query?.organizationSlug ||
				ctx.query?.organizationId ||
				session.session.activeOrganizationId;
			// return null if no organization is found to avoid erroring since this is a usual scenario
			if (!organizationId) {
				return ctx.json(null, {
					status: 200,
				});
			}
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const activeOrganizationId = session.session.activeOrganizationId;
			if (
				activeOrganizationId &&
				!(await adapter.checkMembership({
					userId: session.user.id,
					organizationId: activeOrganizationId,
				}))
			) {
					let revokedStaleSession: boolean;
					try {
						revokedStaleSession = await runWithTransaction(
							ctx.context.adapter,
							() => revokeExactStaleOrganizationSession(ctx.context, {
								sessionId: session.session.id,
								userId: session.user.id,
								token: session.session.token,
								organizationId: activeOrganizationId,
							}),
						);
					} catch (error) {
						if (isAfterTransactionHookFailure(error)) {
							deleteSessionCookie(ctx);
							ctx.context.setNewSession(null);
							throw new APIError("INTERNAL_SERVER_ERROR", {
								code: "AFTER_TRANSACTION_HOOK_FAILED",
								message: error.message,
								cause: error,
							}, ctx.responseHeaders);
						}
						throw error;
					}
				if (!revokedStaleSession) {
					throw APIError.from(
						"FORBIDDEN",
						ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
					);
				}
				deleteSessionCookie(ctx);
				ctx.context.setNewSession(null);
				throw new APIError(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
					ctx.responseHeaders,
				);
			}
			const organization = await adapter.findFullOrganization({
				organizationId,
				isSlug: !!ctx.query?.organizationSlug,
				includeTeams: ctx.context.orgOptions.teams?.enabled,
				membersLimit: ctx.query?.membersLimit,
			});
			if (!organization) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
				);
			}
			const isMember = await adapter.checkMembership({
				userId: session.user.id,
				organizationId: organization.id,
			});
			if (!isMember) {
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
				);
			}

			type OrganizationReturn = O["teams"] extends { enabled: true }
				? {
						members: InferMember<O>[];
						invitations: InferInvitation<O>[];
						teams: InferTeam<O>[];
					} & InferOrganization<O>
				: {
						members: InferMember<O>[];
						invitations: InferInvitation<O>[];
					} & InferOrganization<O>;
			return ctx.json(organization as unknown as OrganizationReturn);
		},
	));

const setActiveOrganizationBodySchema = z.object({
	organizationId: z
		.string()
		.meta({
			description:
				'The organization id to set as active. It can be null to unset the active organization. Eg: "org-id"',
		})
		.nullable()
		.optional(),
	organizationSlug: z
		.string()
		.meta({
			description:
				'The organization slug to set as active. It can be null to unset the active organization if organizationId is not provided. Eg: "org-slug"',
		})
		.optional(),
});

export const setActiveOrganization = <O extends OrganizationOptions>(
	options: O,
) => {
	return rejectNestedCookieLifecycleEndpoint(createAuthEndpoint(
		"/organization/set-active",
		{
			method: "POST",
			body: setActiveOrganizationBodySchema,
			use: [
				rejectUnsupportedManagedOrganizationTransition,
				rejectNestedCookieLifecycleRoute,
				orgSessionMiddleware,
				orgMiddleware,
			],
			requireHeaders: true,
			metadata: {
				openapi: {
					operationId: "setActiveOrganization",
					description: "Set the active organization",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "object",
										description: "The organization",
										$ref: "#/components/schemas/Organization",
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
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const session = ctx.context.session;
			let targetUnavailable = false;
			const transition = async (
				targetOrganizationId: string | null,
				targetOrganizationSlug?: string,
			) => {
				const sourceOrganizationId = session.session.activeOrganizationId;
				const targetRequested =
					targetOrganizationId !== null || Boolean(targetOrganizationSlug);
				// This lookup only finds the row to lock. Authority comes from the
				// post-lock row read below, which prevents a slug reassignment from
				// selecting a stale target in a repeatable-read transaction.
				const targetCandidateId = targetOrganizationId ?? (
					targetOrganizationSlug
						? (await adapter.findOrganizationBySlug(targetOrganizationSlug))?.id ?? null
						: null
				);
				let sourceMembershipLost = false;
				let selectedOrganization: InferOrganization<O> | null = null;
				try {
					return await runWithTransaction(ctx.context.adapter, async () => {
						const updatedSession = await adapter.setActiveOrganization(
							session.session.token,
							targetCandidateId,
							ctx,
							{
								beforeCapture: async () => {
								const lockedOrganizationIds = await lockOrganizations(
									ctx.context,
									[sourceOrganizationId, targetCandidateId],
								);
								if (sourceOrganizationId && (!lockedOrganizationIds.has(sourceOrganizationId) || !(await adapter.checkMembership({
									userId: session.user.id,
									organizationId: sourceOrganizationId,
								})))) {
									sourceMembershipLost = true;
									throw new Error("active organization membership was lost");
								}
								if (targetRequested) {
									selectedOrganization =
										targetCandidateId &&
										lockedOrganizationIds.has(targetCandidateId)
											? await adapter.findOrganizationById(targetCandidateId)
										: null;
									if (
										!selectedOrganization ||
										(targetOrganizationSlug &&
											selectedOrganization.slug !== targetOrganizationSlug) ||
										!(await adapter.checkMembership({
											userId: session.user.id,
											organizationId: selectedOrganization.id,
										}))
									) {
										targetUnavailable = true;
										throw APIError.from("FORBIDDEN", ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION);
									}
								}
							},
							},
						);
						return { session: updatedSession, organization: selectedOrganization };
					});
				} catch (error) {
					if (!sourceMembershipLost || !sourceOrganizationId) throw error;
					try {
							const revokedStaleSession = await runWithTransaction(
								ctx.context.adapter,
								() => revokeExactStaleOrganizationSession(ctx.context, {
									sessionId: session.session.id,
									userId: session.user.id,
									token: session.session.token,
									organizationId: sourceOrganizationId,
								}),
							);
						if (!revokedStaleSession) {
							throw APIError.from(
								"FORBIDDEN",
								ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION,
							);
						}
					} catch (revocationError) {
						if (isAfterTransactionHookFailure(revocationError)) {
							deleteSessionCookie(ctx);
							ctx.context.setNewSession(null);
							throw new APIError(
								"INTERNAL_SERVER_ERROR",
								{
									code: "AFTER_TRANSACTION_HOOK_FAILED",
									message: revocationError.message,
									cause: revocationError,
								},
								ctx.responseHeaders,
							);
						}
						throw revocationError;
					}
					throw APIError.from("FORBIDDEN", ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION);
				}
			};
			let organizationId = ctx.body.organizationId;
			const organizationSlug = ctx.body.organizationSlug;

			if (organizationId === null) {
				const sessionOrgId = session.session.activeOrganizationId;
				const sessionTeamId = session.session.activeTeamId;
				if (!sessionOrgId && !sessionTeamId) {
					return ctx.json(null);
				}
				const { session: updatedSession } = await transition(null);
				await publishSessionCookie(ctx, {
					session: updatedSession,
					user: session.user,
				});
				return ctx.json(null);
			}

			if (!organizationId && !organizationSlug) {
				const sessionOrgId = session.session.activeOrganizationId;
				if (!sessionOrgId && !session.session.activeTeamId) {
					return ctx.json(null);
				}
				if (!sessionOrgId) {
					const { session: updatedSession } = await transition(null);
					await publishSessionCookie(ctx, {
						session: updatedSession,
						user: session.user,
					});
					return ctx.json(null);
				}
				organizationId = sessionOrgId;
			}

			if (!organizationId && !organizationSlug) {
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ORGANIZATION_NOT_FOUND,
				);
			}

			let updatedSession;
			let organization: InferOrganization<O> | null = null;
			try {
				const transitioned = await transition(
					organizationId ?? null,
					organizationSlug,
				);
				updatedSession = transitioned.session;
				organization = transitioned.organization;
			} catch (error) {
				if (!targetUnavailable) throw error;
				updatedSession = (await transition(null)).session;
				await publishSessionCookie(ctx, { session: updatedSession, user: session.user });
				throw APIError.from("FORBIDDEN", ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION);
			}
			if (!organization) throw APIError.from("FORBIDDEN", ORGANIZATION_ERROR_CODES.USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION);
			await publishSessionCookie(ctx, {
				session: updatedSession,
				user: session.user,
			});
			type OrganizationReturn = O["teams"] extends { enabled: true }
				? {
						members: InferMember<O>[];
						invitations: InferInvitation<O>[];
						teams: InferTeam<O>[];
					} & InferOrganization<O>
				: {
						members: InferMember<O>[];
						invitations: InferInvitation<O>[];
					} & InferOrganization<O>;
			return ctx.json(organization as unknown as OrganizationReturn);
		},
	));
};

export const listOrganizations = <O extends OrganizationOptions>(options: O) =>
	createAuthEndpoint(
		"/organization/list",
		{
			method: "GET",
			use: [orgMiddleware, orgSessionMiddleware],
			requireHeaders: true,
			metadata: {
				openapi: {
					description: "List all organizations",
					responses: {
						"200": {
							description: "Success",
							content: {
								"application/json": {
									schema: {
										type: "array",
										items: {
											$ref: "#/components/schemas/Organization",
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
			const adapter = getOrgAdapter<O>(ctx.context, options);
			const organizations = await adapter.listOrganizations(
				ctx.context.session.user.id,
			);
			return ctx.json(organizations);
		},
	);
