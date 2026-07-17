import type { GenericEndpointContext } from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import {
	getCurrentAdapter,
	isTransactionActive,
	runWithTransaction,
} from "@clearance/core/context";
import type { Where } from "@clearance/core/db/adapter";
import { APIError } from "@clearance/core/error";
import * as z from "zod";
import type { InferAdditionalFieldsFromPluginOptions } from "../../../db";
import { toZodSchema } from "../../../db";
import type { User } from "../../../types";
import type { AccessControl } from "../../access";
import { orgSessionMiddleware } from "../call";
import { ORGANIZATION_ERROR_CODES } from "../error-codes";
import { hasPermission } from "../has-permission";
import type { Invitation, Member, OrganizationRole } from "../schema";
import type { OrganizationOptions } from "../types";

type IsExactlyEmptyObject<T> = keyof T extends never // no keys
	? T extends {} // is assignable to {}
		? {} extends T
			? true
			: false // and {} is assignable to it
		: false
	: false;

function normalizeRoleName(role: string): string {
	const normalized = role.trim().toLowerCase();
	if (normalized.length === 0 || normalized.includes(",")) {
		throw APIError.fromStatus("BAD_REQUEST");
	}
	return normalized;
}
const DEFAULT_MAXIMUM_ROLES_PER_ORGANIZATION = Number.POSITIVE_INFINITY;

const parseRoleAssignments = (roles: string) =>
	roles.split(",").map((role) => role.trim());

const hasExactRoleAssignment = (roles: string, role: string) =>
	parseRoleAssignments(roles).includes(role);

async function hasDynamicRoleReference(
	ctx: GenericEndpointContext,
	organizationId: string,
	role: string,
): Promise<boolean> {
	const [members, invitations] = await Promise.all([
		ctx.context.adapter.findMany<Member>({
			model: "member",
			where: [
				{ field: "organizationId", value: organizationId, operator: "eq", connector: "AND" },
				{ field: "role", value: role, operator: "contains" },
			],
		}),
		ctx.context.adapter.findMany<Invitation>({
			model: "invitation",
			where: [
				{ field: "organizationId", value: organizationId, operator: "eq", connector: "AND" },
				{ field: "status", value: "pending", operator: "eq", connector: "AND" },
				{ field: "role", value: role, operator: "contains" },
			],
		}),
	]);
	return (
		members.some((member) => hasExactRoleAssignment(member.role, role)) ||
		invitations.some(
			(invitation) =>
				hasExactRoleAssignment(invitation.role, role) &&
				(!invitation.expiresAt || invitation.expiresAt > new Date()),
		)
	);
}

async function withOrganizationRoleMutationLock<T>(
	ctx: GenericEndpointContext,
	organizationId: string,
	mutation: (lockedCtx: GenericEndpointContext, transaction: Awaited<ReturnType<typeof getCurrentAdapter>>) => Promise<T>,
): Promise<T> {
	if (
		typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function" &&
		!(await isTransactionActive(ctx.context.adapter))
	) {
		throw APIError.from("INTERNAL_SERVER_ERROR", {
			code: "ORGANIZATION_LIFECYCLE_TRANSACTION_REQUIRED",
			message:
				"Organization role mutations require rollback-capable database transactions",
		});
	}
	const runLockedMutation = async () => {
		const transaction = await getCurrentAdapter(ctx.context.adapter);
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
		return mutation({
			...ctx,
			context: { ...ctx.context, adapter: transaction },
		} as GenericEndpointContext, transaction);
	};
	return runWithTransaction(ctx.context.adapter, runLockedMutation);
}

async function getLockedRoleMutationMember(
	ctx: GenericEndpointContext,
	organizationId: string,
	userId: string,
	options: OrganizationOptions,
	action: "create" | "update" | "delete",
): Promise<Member> {
	const member = await ctx.context.adapter.findOne<Member>({
		model: "member",
		where: [
			{ field: "organizationId", value: organizationId, operator: "eq", connector: "AND" },
			{ field: "userId", value: userId, operator: "eq", connector: "AND" },
		],
	});
	if (!member) {
		throw APIError.from("FORBIDDEN", ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION);
	}
	const allowed = await hasPermission(
		{ options, organizationId, permissions: { ac: [action] }, role: member.role },
		ctx,
	);
	if (!allowed) {
		const error = action === "create"
			? ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE
			: action === "update"
				? ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE
				: ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE;
		throw APIError.from("FORBIDDEN", error);
	}
	return member;
}

const getAdditionalFields = <
	O extends OrganizationOptions,
	AllPartial extends boolean = false,
>(
	options: O,
	shouldBePartial: AllPartial = false as AllPartial,
) => {
	const additionalFields =
		options?.schema?.organizationRole?.additionalFields || {};
	if (shouldBePartial) {
		for (const key in additionalFields) {
			additionalFields[key]!.required = false;
		}
	}
	const additionalFieldsSchema = toZodSchema({
		fields: additionalFields,
		isClientSide: true,
	});
	type AdditionalFields = AllPartial extends true
		? Partial<InferAdditionalFieldsFromPluginOptions<"organizationRole", O>>
		: InferAdditionalFieldsFromPluginOptions<"organizationRole", O>;
	type ReturnAdditionalFields = InferAdditionalFieldsFromPluginOptions<
		"organizationRole",
		O,
		false
	>;

	return {
		additionalFieldsSchema,
		$AdditionalFields: {} as AdditionalFields,
		$ReturnAdditionalFields: {} as ReturnAdditionalFields,
	};
};

const baseCreateOrgRoleSchema = z.object({
	organizationId: z.string().optional().meta({
		description:
			"The id of the organization to create the role in. If not provided, the user's active organization will be used.",
	}),
	role: z.string().meta({
		description: "The name of the role to create",
	}),
	permission: z.record(z.string(), z.array(z.string())).meta({
		description: "The permission to assign to the role",
	}),
});

export const createOrgRole = <O extends OrganizationOptions>(options: O) => {
	const { additionalFieldsSchema, $AdditionalFields, $ReturnAdditionalFields } =
		getAdditionalFields<O>(options, false);
	type AdditionalFields = typeof $AdditionalFields;
	type ReturnAdditionalFields = typeof $ReturnAdditionalFields;

	return createAuthEndpoint(
		"/organization/create-role",
		{
			method: "POST",
			body: baseCreateOrgRoleSchema.safeExtend({
				additionalFields: z
					.object({ ...additionalFieldsSchema.shape })
					.optional(),
			}),
			metadata: {
				$Infer: {
					body: {} as {
						organizationId?: string | undefined;
						role: string;
						permission: Record<string, string[]>;
					} & (IsExactlyEmptyObject<AdditionalFields> extends true
						? { additionalFields?: {} | undefined }
						: { additionalFields: AdditionalFields }),
				},
			},
			requireHeaders: true,
			use: [orgSessionMiddleware],
		},
		async (ctx) => {
			const { session, user } = ctx.context.session;
			let roleName = ctx.body.role;
			const permission = ctx.body.permission;
			const additionalFields = ctx.body.additionalFields;

			const ac = options.ac;
			if (!ac) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The organization plugin is missing a pre-defined ac instance.`,
					`\nSee https://github.com/clearance-auth/clearance`,
				);
				throw APIError.from(
					"NOT_IMPLEMENTED",
					ORGANIZATION_ERROR_CODES.MISSING_AC_INSTANCE,
				);
			}

			// Get the organization id where the role will be created.
			// We can verify if the org id is valid and associated with the user in the next step when we try to find the member.
			const organizationId =
				ctx.body.organizationId ?? session.activeOrganizationId;
			if (!organizationId) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The session is missing an active organization id to create a role. Either set an active org id, or pass an organizationId in the request body.`,
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE,
				);
			}

			roleName = normalizeRoleName(roleName);

			const newRole = ac.newRole(permission);

			const newRoleInDB = await withOrganizationRoleMutationLock(
				ctx,
				organizationId,
				async (lockedCtx, transaction) => {
					await checkIfRoleNameIsTakenByPreDefinedRole({ role: roleName, organizationId, options, ctx: lockedCtx });
					const lockedMember = await getLockedRoleMutationMember(
						lockedCtx, organizationId, user.id, options, "create",
					);
					const liveMaximum = typeof options.dynamicAccessControl?.maximumRolesPerOrganization === "function"
						? await options.dynamicAccessControl.maximumRolesPerOrganization(organizationId)
						: (options.dynamicAccessControl?.maximumRolesPerOrganization ?? DEFAULT_MAXIMUM_ROLES_PER_ORGANIZATION);
					if (await lockedCtx.context.adapter.count({ model: "organizationRole", where: [{ field: "organizationId", value: organizationId }] }) >= liveMaximum) {
						throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.TOO_MANY_ROLES);
					}
					await checkForInvalidResources({ ac, ctx: lockedCtx, permission });
					await checkIfMemberHasPermission({ ctx: lockedCtx, member: lockedMember, options, organizationId, permissionRequired: permission, user, action: "create" });
					await checkIfRoleNameIsTakenByRoleInDB({ ctx: lockedCtx, organizationId, role: roleName });
					const created = await transaction.create<
						Omit<OrganizationRole, "permission"> & { permission: string }
					>({
						model: "organizationRole",
						data: { createdAt: new Date(), organizationId, permission: JSON.stringify(permission), role: roleName, ...additionalFields },
					});
					return created;
				},
			);

			const data = {
				...newRoleInDB,
				permission,
			} as OrganizationRole & ReturnAdditionalFields;
			return ctx.json({
				success: true,
				roleData: data,
				statements: newRole.statements,
			});
		},
	);
};

const deleteOrgRoleBodySchema = z
	.object({
		organizationId: z.string().optional().meta({
			description:
				"The id of the organization to create the role in. If not provided, the user's active organization will be used.",
		}),
	})
	.and(
		z.union([
			z.object({
				roleName: z.string().nonempty().meta({
					description: "The name of the role to delete",
				}),
			}),
			z.object({
				roleId: z.string().nonempty().meta({
					description: "The id of the role to delete",
				}),
			}),
		]),
	);

export const deleteOrgRole = <O extends OrganizationOptions>(options: O) => {
	return createAuthEndpoint(
		"/organization/delete-role",
		{
			method: "POST",
			body: deleteOrgRoleBodySchema,
			requireHeaders: true,
			use: [orgSessionMiddleware],
			metadata: {
				$Infer: {
					body: {} as {
						roleName?: string | undefined;
						roleId?: string | undefined;
						organizationId?: string | undefined;
					},
				},
			},
		},
		async (ctx) => {
			const { session, user } = ctx.context.session;

			const organizationId =
				ctx.body.organizationId ?? session.activeOrganizationId;
			if (!organizationId) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The session is missing an active organization id to delete a role. Either set an active org id, or pass an organizationId in the request body.`,
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}

			let condition: Where;
			const roleName = ctx.body.roleName === undefined
				? undefined
				: normalizeRoleName(ctx.body.roleName);
			if (roleName !== undefined) {
				condition = {
					field: "role",
					value: roleName,
					operator: "eq",
					connector: "AND",
				};
			} else if (ctx.body.roleId) {
				condition = {
					field: "id",
					value: ctx.body.roleId,
					operator: "eq",
					connector: "AND",
				};
			} else {
				// shouldn't be able to reach here given the schema validation.
				// But just in case, throw an error.
				ctx.context.logger.error(
					`[Dynamic Access Control] The role name/id is not provided in the request body.`,
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND,
				);
			}
			await withOrganizationRoleMutationLock(ctx, organizationId, async (lockedCtx) => {
				await getLockedRoleMutationMember(lockedCtx, organizationId, user.id, options, "delete");
				if (roleName !== undefined) {
					const defaultRoles = options.roles
						? Object.keys(options.roles)
						: ["owner", "admin", "member"];
					if (defaultRoles.map((role) => role.trim().toLowerCase()).includes(roleName)) {
						throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.CANNOT_DELETE_A_PRE_DEFINED_ROLE);
					}
				}
				const liveRole = await lockedCtx.context.adapter.findOne<OrganizationRole>({
					model: "organizationRole",
					where: [
						{ field: "organizationId", value: organizationId, operator: "eq", connector: "AND" },
						condition,
					],
				});
				if (!liveRole) throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND);
				if (await hasDynamicRoleReference(lockedCtx, organizationId, liveRole.role)) {
					throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ROLE_IS_ASSIGNED_TO_MEMBERS);
				}
				await lockedCtx.context.adapter.delete({
					model: "organizationRole",
					where: [
						{ field: "organizationId", value: organizationId, operator: "eq", connector: "AND" },
						condition,
					],
				});
			});

			return ctx.json({
				success: true,
			});
		},
	);
};

const listOrgRolesQuerySchema = z
	.object({
		organizationId: z.string().optional().meta({
			description:
				"The id of the organization to list roles for. If not provided, the user's active organization will be used.",
		}),
	})
	.optional();

export const listOrgRoles = <O extends OrganizationOptions>(options: O) => {
	const { $ReturnAdditionalFields } = getAdditionalFields<O>(options, false);
	type ReturnAdditionalFields = typeof $ReturnAdditionalFields;

	return createAuthEndpoint(
		"/organization/list-roles",
		{
			method: "GET",
			requireHeaders: true,
			use: [orgSessionMiddleware],
			query: listOrgRolesQuerySchema,
		},
		async (ctx) => {
			const { session, user } = ctx.context.session;

			const organizationId =
				ctx.query?.organizationId ?? session.activeOrganizationId;
			if (!organizationId) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The session is missing an active organization id to list roles. Either set an active org id, or pass an organizationId in the request query.`,
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}

			const member = await ctx.context.adapter.findOne<Member>({
				model: "member",
				where: [
					{
						field: "organizationId",
						value: organizationId,
						operator: "eq",
						connector: "AND",
					},
					{
						field: "userId",
						value: user.id,
						operator: "eq",
						connector: "AND",
					},
				],
			});
			if (!member) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The user is not a member of the organization to list roles.`,
					{
						userId: user.id,
						organizationId,
					},
				);
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION,
				);
			}

			const canListRoles = await hasPermission(
				{
					options,
					organizationId,
					permissions: {
						ac: ["read"],
					},
					role: member.role,
				},
				ctx,
			);
			if (!canListRoles) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The user is not permitted to list roles.`,
					{
						userId: user.id,
						organizationId,
						role: member.role,
					},
				);
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE,
				);
			}

			let roles = await ctx.context.adapter.findMany<
				OrganizationRole & ReturnAdditionalFields
			>({
				model: "organizationRole",
				where: [
					{
						field: "organizationId",
						value: organizationId,
						operator: "eq",
						connector: "AND",
					},
				],
			});

			roles = roles.map((x) => ({
				...x,
				permission: JSON.parse(x.permission as never as string),
			}));

			return ctx.json(roles);
		},
	);
};

const getOrgRoleQuerySchema = z
	.object({
		organizationId: z.string().optional().meta({
			description:
				"The id of the organization to read a role for. If not provided, the user's active organization will be used.",
		}),
	})
	.and(
		z.union([
			z.object({
				roleName: z.string().nonempty().meta({
					description: "The name of the role to read",
				}),
			}),
			z.object({
				roleId: z.string().nonempty().meta({
					description: "The id of the role to read",
				}),
			}),
		]),
	)
	.optional();

export const getOrgRole = <O extends OrganizationOptions>(options: O) => {
	const { $ReturnAdditionalFields } = getAdditionalFields<O>(options, false);
	type ReturnAdditionalFields = typeof $ReturnAdditionalFields;
	return createAuthEndpoint(
		"/organization/get-role",
		{
			method: "GET",
			requireHeaders: true,
			use: [orgSessionMiddleware],
			query: getOrgRoleQuerySchema,
			metadata: {
				$Infer: {
					query: {} as {
						organizationId?: string | undefined;
						roleName?: string | undefined;
						roleId?: string | undefined;
					},
				},
			},
		},
		async (ctx) => {
			const { session, user } = ctx.context.session;

			const organizationId =
				ctx.query?.organizationId ?? session.activeOrganizationId;
			if (!organizationId) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The session is missing an active organization id to read a role. Either set an active org id, or pass an organizationId in the request query.`,
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}

			const member = await ctx.context.adapter.findOne<Member>({
				model: "member",
				where: [
					{
						field: "organizationId",
						value: organizationId,
						operator: "eq",
						connector: "AND",
					},
					{
						field: "userId",
						value: user.id,
						operator: "eq",
						connector: "AND",
					},
				],
			});
			if (!member) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The user is not a member of the organization to read a role.`,
					{
						userId: user.id,
						organizationId,
					},
				);
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION,
				);
			}

			const canListRoles = await hasPermission(
				{
					options,
					organizationId,
					permissions: {
						ac: ["read"],
					},
					role: member.role,
				},
				ctx,
			);
			if (!canListRoles) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The user is not permitted to read a role.`,
					{
						userId: user.id,
						organizationId,
						role: member.role,
					},
				);
				throw APIError.from(
					"FORBIDDEN",
					ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE,
				);
			}

			let condition: Where;
			const roleName = ctx.query?.roleName === undefined
				? undefined
				: normalizeRoleName(ctx.query.roleName);
			if (roleName !== undefined) {
				condition = {
					field: "role",
					value: roleName,
					operator: "eq",
					connector: "AND",
				};
			} else if (ctx.query.roleId) {
				condition = {
					field: "id",
					value: ctx.query.roleId,
					operator: "eq",
					connector: "AND",
				};
			} else {
				// shouldn't be able to reach here given the schema validation.
				// But just in case, throw an error.
				ctx.context.logger.error(
					`[Dynamic Access Control] The role name/id is not provided in the request query.`,
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND,
				);
			}
			const role = await ctx.context.adapter.findOne<OrganizationRole>({
				model: "organizationRole",
				where: [
					{
						field: "organizationId",
						value: organizationId,
						operator: "eq",
						connector: "AND",
					},
					condition,
				],
			});
			if (!role) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The role name/id does not exist in the database.`,
					{
						...("roleName" in ctx.query
							? { roleName: ctx.query.roleName }
							: { roleId: ctx.query.roleId }),
						organizationId,
					},
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND,
				);
			}

			role.permission = JSON.parse(role.permission as never as string);

			return ctx.json(role as OrganizationRole & ReturnAdditionalFields);
		},
	);
};

const roleNameOrIdSchema = z.union([
	z.object({
		roleName: z.string().nonempty().meta({
			description: "The name of the role to update",
		}),
	}),
	z.object({
		roleId: z.string().nonempty().meta({
			description: "The id of the role to update",
		}),
	}),
]);

export const updateOrgRole = <O extends OrganizationOptions>(options: O) => {
	const { additionalFieldsSchema, $AdditionalFields, $ReturnAdditionalFields } =
		getAdditionalFields<O, true>(options, true);
	type AdditionalFields = typeof $AdditionalFields;
	type ReturnAdditionalFields = typeof $ReturnAdditionalFields;

	return createAuthEndpoint(
		"/organization/update-role",
		{
			method: "POST",
			body: z
				.object({
					organizationId: z.string().optional().meta({
						description:
							"The id of the organization to update the role in. If not provided, the user's active organization will be used.",
					}),
					data: z.object({
						permission: z
							.record(z.string(), z.array(z.string()))
							.optional()
							.meta({
								description: "The permission to update the role with",
							}),
						roleName: z.string().optional().meta({
							description: "The name of the role to update",
						}),
						...additionalFieldsSchema.shape,
					}),
				})
				.and(roleNameOrIdSchema),
			metadata: {
				$Infer: {
					body: {} as {
						organizationId?: string | undefined;
						data: {
							permission?: Record<string, string[]> | undefined;
							roleName?: string | undefined;
						} & AdditionalFields;
						roleName?: string | undefined;
						roleId?: string | undefined;
					},
				},
			},
			requireHeaders: true,
			use: [orgSessionMiddleware],
		},
		async (ctx) => {
			const { session, user } = ctx.context.session;

			const ac = options.ac;
			if (!ac) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The organization plugin is missing a pre-defined ac instance.`,
					`\nSee https://github.com/clearance-auth/clearance`,
				);
				throw APIError.from(
					"NOT_IMPLEMENTED",
					ORGANIZATION_ERROR_CODES.MISSING_AC_INSTANCE,
				);
			}

			const organizationId =
				ctx.body.organizationId ?? session.activeOrganizationId;
			if (!organizationId) {
				ctx.context.logger.error(
					`[Dynamic Access Control] The session is missing an active organization id to update a role. Either set an active org id, or pass an organizationId in the request body.`,
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.NO_ACTIVE_ORGANIZATION,
				);
			}

			let condition: Where;
			const roleName = ctx.body.roleName === undefined
				? undefined
				: normalizeRoleName(ctx.body.roleName);
			if (roleName !== undefined) {
				condition = {
					field: "role",
					value: roleName,
					operator: "eq",
					connector: "AND",
				};
			} else if (ctx.body.roleId) {
				condition = {
					field: "id",
					value: ctx.body.roleId,
					operator: "eq",
					connector: "AND",
				};
			} else {
				// shouldn't be able to reach here given the schema validation.
				// But just in case, throw an error.
				ctx.context.logger.error(
					`[Dynamic Access Control] The role name/id is not provided in the request body.`,
				);
				throw APIError.from(
					"BAD_REQUEST",
					ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND,
				);
			}
			const {
				permission: _,
				roleName: __,
				...additionalFields
			} = ctx.body.data;

			const updateData: Partial<OrganizationRole> = {
				...additionalFields,
			};

			if (ctx.body.data.permission !== undefined) {
				const newPermission = ctx.body.data.permission;

				await checkForInvalidResources({ ac, ctx, permission: newPermission });

				updateData.permission = newPermission;
			}
			if (ctx.body.data.roleName !== undefined) {
				updateData.role = normalizeRoleName(ctx.body.data.roleName);
			}

			// -----
			// Apply the updates
			const update = {
				...updateData,
				...(updateData.permission
					? { permission: JSON.stringify(updateData.permission) }
					: {}),
			};
			// Scoped by organization + role: updateMany applies the multi-clause
			// filter portably, where a multi-clause `update` does not across adapters.
			const role = await withOrganizationRoleMutationLock(ctx, organizationId, async (lockedCtx) => {
				const lockedMember = await getLockedRoleMutationMember(lockedCtx, organizationId, user.id, options, "update");
				const liveRole = await lockedCtx.context.adapter.findOne<OrganizationRole>({
					model: "organizationRole",
					where: [
						{ field: "organizationId", value: organizationId, operator: "eq", connector: "AND" },
						condition,
					],
				});
				if (!liveRole) throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ROLE_NOT_FOUND);
				const previousRole = {
					...liveRole,
					permission: liveRole.permission
						? JSON.parse(liveRole.permission as never as string)
						: undefined,
				};
				if (ctx.body.data.permission !== undefined) {
					await checkIfMemberHasPermission({ ctx: lockedCtx, member: lockedMember, options, organizationId, permissionRequired: ctx.body.data.permission, user, action: "update" });
				}
				if (updateData.role) {
					await checkIfRoleNameIsTakenByPreDefinedRole({ ctx: lockedCtx, options, organizationId, role: updateData.role });
					await checkIfRoleNameIsTakenByRoleInDB({ ctx: lockedCtx, organizationId, role: updateData.role, excludeRoleId: liveRole.id });
					if (updateData.role !== liveRole.role && await hasDynamicRoleReference(lockedCtx, organizationId, liveRole.role)) {
						throw APIError.from("BAD_REQUEST", ORGANIZATION_ERROR_CODES.ROLE_IS_ASSIGNED_TO_MEMBERS);
					}
				}
				await lockedCtx.context.adapter.updateMany({
					model: "organizationRole",
					where: [
						{ field: "organizationId", value: organizationId, operator: "eq", connector: "AND" },
						condition,
					],
					update,
				});
				return previousRole;
			});

			// -----
			// Return the updated role
			return ctx.json({
				success: true,
				roleData: {
					...role,
					...update,
					permission: updateData.permission || role.permission || null,
				} as OrganizationRole & ReturnAdditionalFields,
			});
		},
	);
};

async function checkForInvalidResources({
	ac,
	ctx,
	permission,
}: {
	ac: AccessControl;
	ctx: GenericEndpointContext;
	permission: Record<string, string[]>;
}) {
	const validResources = Object.keys(ac.statements);
	const providedResources = Object.keys(permission);
	const hasInvalidResource = providedResources.some(
		(r) => !validResources.includes(r),
	);
	if (hasInvalidResource) {
		ctx.context.logger.error(
			`[Dynamic Access Control] The provided permission includes an invalid resource.`,
			{
				providedResources,
				validResources,
			},
		);
		throw APIError.from(
			"BAD_REQUEST",
			ORGANIZATION_ERROR_CODES.INVALID_RESOURCE,
		);
	}
}

async function checkIfMemberHasPermission({
	ctx,
	permissionRequired: permission,
	options,
	organizationId,
	member,
	user,
	action,
}: {
	ctx: GenericEndpointContext;
	permissionRequired: Record<string, string[]>;
	options: OrganizationOptions;
	organizationId: string;
	member: Member;
	user: User;
	action: "create" | "update" | "delete" | "read" | "list" | "get";
}) {
	const hasNecessaryPermissions: {
		resource: { [x: string]: string[] };
		hasPermission: boolean;
	}[] = [];
	const permissionEntries = Object.entries(permission);
	for await (const [resource, permissions] of permissionEntries) {
		for await (const perm of permissions) {
			hasNecessaryPermissions.push({
				resource: { [resource]: [perm] },
				hasPermission: await hasPermission(
					{
						options,
						organizationId,
						permissions: { [resource]: [perm] },
						role: member.role,
					},
					ctx,
				),
			});
		}
	}
	const missingPermissions = hasNecessaryPermissions
		.filter((x) => x.hasPermission === false)
		.map((x) => {
			const key = Object.keys(x.resource)[0]!;
			return `${key}:${x.resource[key]![0]}` as const;
		});
	if (missingPermissions.length > 0) {
		ctx.context.logger.error(
			`[Dynamic Access Control] The user is missing permissions necessary to ${action} a role with those set of permissions.\n`,
			{
				userId: user.id,
				organizationId,
				role: member.role,
				missingPermissions,
			},
		);
		let error: { code: string; message: string };
		if (action === "create")
			error = ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE;
		else if (action === "update")
			error = ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE;
		else if (action === "delete")
			error = ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE;
		else if (action === "read")
			error = ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE;
		else if (action === "list")
			error = ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE;
		else error = ORGANIZATION_ERROR_CODES.YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE;

		throw APIError.fromStatus("FORBIDDEN", {
			message: error.message,
			code: error.code,
			missingPermissions,
		});
	}
}

async function checkIfRoleNameIsTakenByPreDefinedRole({
	options,
	organizationId,
	role,
	ctx,
}: {
	options: OrganizationOptions;
	organizationId: string;
	role: string;
	ctx: GenericEndpointContext;
}) {
	const defaultRoles = options.roles
		? Object.keys(options.roles)
		: ["owner", "admin", "member"];
	if (defaultRoles.map((defaultRole) => defaultRole.trim().toLowerCase()).includes(role)) {
		ctx.context.logger.error(
			`[Dynamic Access Control] The role name "${role}" is already taken by a pre-defined role.`,
			{
				role,
				organizationId,
				defaultRoles,
			},
		);
		throw APIError.from(
			"BAD_REQUEST",
			ORGANIZATION_ERROR_CODES.ROLE_NAME_IS_ALREADY_TAKEN,
		);
	}
}

async function checkIfRoleNameIsTakenByRoleInDB({
	organizationId,
	role,
	excludeRoleId,
	ctx,
}: {
	ctx: GenericEndpointContext;
	organizationId: string;
	role: string;
	excludeRoleId?: string;
}) {
	const existingRoleInDB = await ctx.context.adapter.findOne<OrganizationRole>({
		model: "organizationRole",
		where: [
			{
				field: "organizationId",
				value: organizationId,
				operator: "eq",
				connector: "AND",
			},
			{
				field: "role",
				value: role,
				operator: "eq",
				connector: "AND",
			},
		],
	});
	if (existingRoleInDB && existingRoleInDB.id !== excludeRoleId) {
		ctx.context.logger.error(
			`[Dynamic Access Control] The role name "${role}" is already taken by a role in the database.`,
			{
				role,
				organizationId,
			},
		);
		throw APIError.from(
			"BAD_REQUEST",
			ORGANIZATION_ERROR_CODES.ROLE_NAME_IS_ALREADY_TAKEN,
		);
	}
}
