import type { Account, GenericEndpointContext, User } from "@clearance/runtime";
import { HIDE_METADATA } from "@clearance/runtime";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { createAuthEndpoint } from "@clearance/runtime/api";
import { getOrgAdapter, type Member, type OrganizationOptions, type Team, type TeamMember } from "@clearance/runtime/plugins";
import * as z from "zod";
import {
	appendInternalRuntimeAudit,
	attachCapturedInternalRuntimeAudit,
	getRuntimeAuditRequestContext,
	readInternalRuntimeAudit,
} from "@clearance/runtime/internal/runtime-audit";
import type { AuthMiddleware } from "./middlewares";
import { SCIMAPIError, SCIMErrorOpenAPISchemas } from "./scim-error";
import { APIGroupSchema, GroupPatchSchema, SCIMGroupResourceSchema, type APIGroup } from "./group-schemas";
import { createGroupResource, type SCIMGroupBinding } from "./group-resources";

const supportedMediaTypes = ["application/json", "application/scim+json"];
const listResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

type GroupContext = GenericEndpointContext & {
	context: GenericEndpointContext["context"] & {
		scimProvider: { providerId: string; organizationId?: string; id?: string };
	};
};

type GroupScope = {
	providerId: string;
	organizationId: string;
	orgOptions: OrganizationOptions & { teams: NonNullable<OrganizationOptions["teams"]> & { enabled: true } };
};

type MembershipChange = { added: number; removed: number };
type PatchChange = MembershipChange & { material: boolean };

function groupScope(ctx: GroupContext): GroupScope {
	const organizationId = ctx.context.scimProvider.organizationId;
	const orgOptions = ctx.context.getPlugin("organization")?.options as OrganizationOptions | undefined;
	if (!organizationId || orgOptions?.teams?.enabled !== true) {
		throw new SCIMAPIError("NOT_FOUND", { detail: "SCIM Groups are unavailable for this connection" });
	}
	return { providerId: ctx.context.scimProvider.providerId, organizationId, orgOptions: orgOptions as GroupScope["orgOptions"] };
}

function requireGroupMutationTransaction(ctx: GroupContext): void {
	if (typeof ctx.context.adapter.options?.adapterConfig.transaction !== "function") {
		throw new SCIMAPIError("INTERNAL_SERVER_ERROR", {
			detail: "SCIM Group mutations require rollback-capable database transactions",
		});
	}
}

function externalIdKey(scope: GroupScope, externalId: string | null | undefined): string | null {
	if (externalId === undefined || externalId === null) return null;
	return [scope.providerId, scope.organizationId, externalId]
		.map((value) => `${value.length}:${value}`)
		.join("|");
}

function staticTeamMaximum(scope: GroupScope): number | undefined {
	const maximum = scope.orgOptions.teams.maximumTeams;
	if (typeof maximum === "function") throw new SCIMAPIError("BAD_REQUEST", { detail: "SCIM Groups requires a numeric teams.maximumTeams configuration", scimType: "invalidValue" });
	return maximum;
}

function staticMemberMaximum(scope: GroupScope): number | undefined {
	const maximum = scope.orgOptions.teams.maximumMembersPerTeam;
	if (typeof maximum === "function") throw new SCIMAPIError("BAD_REQUEST", { detail: "SCIM Groups requires a numeric teams.maximumMembersPerTeam configuration", scimType: "invalidValue" });
	return maximum;
}

function isUniqueViolation(error: unknown): boolean {
	return error instanceof Error && /unique|duplicate/i.test(error.message);
}

async function uniqueConflict<T>(fn: () => Promise<T>): Promise<T> {
	try { return await fn(); }
	catch (error) {
		if (isUniqueViolation(error)) throw new SCIMAPIError("CONFLICT", { detail: "Group already exists", scimType: "uniqueness" });
		throw error;
	}
}

async function transactionOrgAdapter(ctx: GroupContext, scope: GroupScope) {
	return getOrgAdapter(ctx.context, scope.orgOptions);
}

function groupActor(ctx: GroupContext): string {
	const id = ctx.context.scimProvider.id;
	return id ? `scim_connection:${id}` : "scim_connection:configured";
}

async function appendGroupAudit(
	ctx: GroupContext,
	action: "scim.group.created" | "scim.group.updated" | "scim.group.deleted",
	groupId: string,
	organizationId: string,
	membershipChange?: MembershipChange,
) {
	const binding = readInternalRuntimeAudit(ctx.context.options) ?? readInternalRuntimeAudit(ctx.context.adapter);
	if (!binding) return;
	const request = await getRuntimeAuditRequestContext();
	if (!request) throw new Error("Runtime audit request context is unavailable");
	const transaction = await getCurrentAdapter(ctx.context.adapter);
	attachCapturedInternalRuntimeAudit(transaction, binding);
	await appendInternalRuntimeAudit(transaction, {
		actor: groupActor(ctx), action, subjectType: "group", subjectId: groupId,
		outcome: "success", source: "scim", organizationId,
		message: "SCIM group lifecycle completed", metadata: membershipChange ? { membersAdded: membershipChange.added, membersRemoved: membershipChange.removed } : {}, request,
	});
}

const getBinding = async (ctx: GroupContext, groupId: string): Promise<SCIMGroupBinding> => {
	const { providerId, organizationId } = groupScope(ctx);
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const binding = await adapter.findOne<SCIMGroupBinding>({
		model: "scimGroup",
		where: [
			{ field: "id", value: groupId },
			{ field: "providerId", value: providerId },
			{ field: "organizationId", value: organizationId },
		],
	});
	if (!binding) throw new SCIMAPIError("NOT_FOUND", { detail: "Group not found" });
	return binding;
};

const getBoundTeam = async (ctx: GroupContext, binding: SCIMGroupBinding): Promise<Team> => {
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const team = await adapter.findOne<Team>({
		model: "team",
		where: [{ field: "id", value: binding.teamId }, { field: "organizationId", value: binding.organizationId }],
	});
	if (!team) throw new SCIMAPIError("NOT_FOUND", { detail: "Group not found" });
	return team;
};

async function lockBoundGroup(ctx: GroupContext, groupId: string, attempt = 0): Promise<{ binding: SCIMGroupBinding; team: Team }> {
	const binding = await getBinding(ctx, groupId);
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const observed = await adapter.findOne<Team>({
		model: "team",
		where: [{ field: "id", value: binding.teamId }, { field: "organizationId", value: binding.organizationId }],
	});
	if (!observed) throw new SCIMAPIError("NOT_FOUND", { detail: "Group not found" });
	// The public adapter has no row-lock primitive. A conditional same-value
	// update acquires the row's write lock without changing durable model state;
	// the name predicate prevents a stale observation from overwriting a winner.
	const team = await adapter.update<Team>({
		model: "team",
		where: [
			{ field: "id", value: binding.teamId },
			{ field: "organizationId", value: binding.organizationId },
			{ field: "name", value: observed.name },
		],
		update: { name: observed.name, updatedAt: observed.updatedAt },
	});
	if (!team) {
		if (attempt >= 2) throw new SCIMAPIError("CONFLICT", { detail: "Group changed concurrently" });
		return lockBoundGroup(ctx, groupId, attempt + 1);
	}
	const current = await getBinding(ctx, groupId);
	if (current.teamId !== binding.teamId) throw new SCIMAPIError("NOT_FOUND", { detail: "Group not found" });
	return { binding: current, team };
}

async function assertExternalIdAvailable(
	ctx: GroupContext,
	externalId: string | null | undefined,
	exceptGroupId?: string,
) {
	if (externalId === undefined || externalId === null) return;
	const scope = groupScope(ctx);
	const key = externalIdKey(scope, externalId)!;
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const existing = await adapter.findOne<SCIMGroupBinding>({
		model: "scimGroup",
		where: [
			{ field: "externalIdKey", value: key },
		],
	});
	if (existing && existing.id !== exceptGroupId) {
		throw new SCIMAPIError("CONFLICT", { detail: "Group already exists", scimType: "uniqueness" });
	}
}

async function assertManagedMember(ctx: GroupContext, userId: string, scope = groupScope(ctx)) {
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const [account, membership] = await Promise.all([
		adapter.findOne<Account>({ model: "account", where: [{ field: "providerId", value: scope.providerId }, { field: "userId", value: userId }] }),
		adapter.findOne<Member>({ model: "member", where: [{ field: "organizationId", value: scope.organizationId }, { field: "userId", value: userId }] }),
	]);
	if (!account || !membership) {
		throw new SCIMAPIError("BAD_REQUEST", {
			detail: "Group members must be SCIM-provisioned users in this organization",
			scimType: "invalidValue",
		});
	}
}

async function managedTeamMembers(ctx: GroupContext, teamId: string, scope = groupScope(ctx)) {
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const memberships = await adapter.findMany<TeamMember>({ model: "teamMember", where: [{ field: "teamId", value: teamId }] });
	if (memberships.length === 0) return [] as TeamMember[];
	const accounts = await adapter.findMany<Account>({
		model: "account",
		where: [{ field: "providerId", value: scope.providerId }, { field: "userId", value: memberships.map((member) => member.userId), operator: "in" }],
	});
	const accountUserIds = new Set(accounts.map((account) => account.userId));
	const members = await adapter.findMany<Member>({
		model: "member",
		where: [{ field: "organizationId", value: scope.organizationId }, { field: "userId", value: [...accountUserIds], operator: "in" }],
	});
	const allowed = new Set(members.map((member) => member.userId));
	return memberships.filter((membership) => allowed.has(membership.userId));
}

async function resourceFor(ctx: GroupContext, binding: SCIMGroupBinding, team?: Team) {
	const resolvedTeam = team ?? await getBoundTeam(ctx, binding);
	const memberships = await managedTeamMembers(ctx, resolvedTeam.id);
	const adapter = await getCurrentAdapter(ctx.context.adapter);
	const users = memberships.length === 0 ? [] : await adapter.findMany<User>({
		model: "user", where: [{ field: "id", value: memberships.map((member) => member.userId), operator: "in" }],
	});
	return createGroupResource(ctx.context.baseURL, resolvedTeam, binding, users);
}

async function replaceManagedMembers(ctx: GroupContext, teamId: string, memberIds: string[]): Promise<MembershipChange> {
	const scope = groupScope(ctx);
	const desired = [...new Set(memberIds)];
	for (const userId of desired) await assertManagedMember(ctx, userId, scope);
	const current = await managedTeamMembers(ctx, teamId, scope);
	const currentByUser = new Map(current.map((member) => [member.userId, member]));
	const orgAdapter = await transactionOrgAdapter(ctx, scope);
	let removed = 0;
	let added = 0;
	for (const membership of current) {
		if (!desired.includes(membership.userId)) {
			await orgAdapter.removeTeamMember({ teamId, userId: membership.userId });
			removed += 1;
		}
	}
	for (const userId of desired) {
		if (!currentByUser.has(userId)) {
			const maximum = staticMemberMaximum(scope);
			const admission = await orgAdapter.admitTeamMember({
				organizationId: scope.organizationId,
				teamId,
				userId,
				prepare: async () => maximum,
			});
			if (admission.status === "limitReached") throw new SCIMAPIError("BAD_REQUEST", { detail: "The team member limit has been reached", scimType: "invalidValue" });
			if (admission.status !== "added") throw new SCIMAPIError("NOT_FOUND", { detail: "Group not found" });
			added += 1;
		}
	}
	return { added, removed };
}

async function addManagedMembers(ctx: GroupContext, teamId: string, memberIds: string[]): Promise<MembershipChange> {
	const existing = new Set((await managedTeamMembers(ctx, teamId)).map((member) => member.userId));
	return replaceManagedMembers(ctx, teamId, [...existing, ...memberIds]);
}

async function removeManagedMembers(ctx: GroupContext, teamId: string, memberIds?: string[]): Promise<MembershipChange> {
	const existing = await managedTeamMembers(ctx, teamId);
	const keep = memberIds ? existing.filter((member) => !memberIds.includes(member.userId)).map((member) => member.userId) : [];
	return replaceManagedMembers(ctx, teamId, keep);
}

function memberIds(value: unknown): string[] {
	if (!Array.isArray(value) || value.some((member) => !member || typeof member !== "object" || typeof (member as { value?: unknown }).value !== "string")) {
		throw new SCIMAPIError("BAD_REQUEST", { detail: "members must be an array of SCIM user references", scimType: "invalidValue" });
	}
	return value.map((member) => (member as { value: string }).value);
}

function patchMemberIds(value: unknown): string[] {
	return memberIds(Array.isArray(value) ? value : [value]);
}

function selectorMember(path: string): string | undefined {
	const match = path.match(/^members\[value\s+eq\s+"([^"]+)"\]$/i);
	return match?.[1];
}

function normalizePatchPath(path: string | undefined): string | undefined {
	if (!path) return undefined;
	const withoutLeadingSlash = path.replace(/^\//, "");
	const groupSchemaPrefix = /^urn:ietf:params:scim:schemas:core:2\.0:Group:/i;
	const unprefixed = withoutLeadingSlash.replace(groupSchemaPrefix, "");
	if (selectorMember(unprefixed)) return unprefixed;
	const token = unprefixed.toLowerCase();
	if (token === "displayname") return "displayName";
	if (token === "externalid") return "externalId";
	if (token === "members") return "members";
	return unprefixed;
}

function noTarget(): never {
	throw new SCIMAPIError("BAD_REQUEST", { detail: "The PATCH path matched no Group value", scimType: "noTarget" });
}

async function isDefinitelyNoopPatch(
	ctx: GroupContext,
	binding: SCIMGroupBinding,
	team: Team,
	operations: z.infer<typeof GroupPatchSchema>["Operations"],
): Promise<boolean> {
	let currentMembers: Set<string> | undefined;
	for (const operation of operations) {
		const path = normalizePatchPath(operation.path);
		if (!path || selectorMember(path) || operation.op === "remove") return false;
		if (path === "displayName") {
			if (typeof operation.value !== "string" || operation.value !== team.name) return false;
			continue;
		}
		if (path === "externalId") {
			if (typeof operation.value !== "string" || operation.value !== binding.externalId) return false;
			continue;
		}
		if (path === "members") {
			currentMembers ??= new Set((await managedTeamMembers(ctx, team.id)).map((member) => member.userId));
			const requested = new Set(memberIds(operation.value));
			if (operation.op === "replace") {
				if (requested.size !== currentMembers.size || [...requested].some((userId) => !currentMembers!.has(userId))) return false;
			} else if ([...requested].some((userId) => !currentMembers!.has(userId))) {
				return false;
			}
			continue;
		}
		return false;
	}
	return true;
}

async function applyPatch(ctx: GroupContext, binding: SCIMGroupBinding, team: Team, operations: z.infer<typeof GroupPatchSchema>["Operations"]): Promise<PatchChange> {
	const changes: PatchChange = { added: 0, removed: 0, material: false };
	const record = (change: MembershipChange & { material?: boolean }) => {
		changes.added += change.added;
		changes.removed += change.removed;
		changes.material ||= change.material ?? (change.added > 0 || change.removed > 0);
	};
	const orgAdapter = await transactionOrgAdapter(ctx, groupScope(ctx));
	for (const operation of operations) {
		const path = normalizePatchPath(operation.path);
		const selector = path ? selectorMember(path) : undefined;
		if (selector) {
			const current = (await managedTeamMembers(ctx, team.id)).map((member) => member.userId);
			if (!current.includes(selector)) noTarget();
			if (operation.op === "remove") {
				record(await replaceManagedMembers(ctx, team.id, current.filter((userId) => userId !== selector)));
			} else if (operation.op === "add") {
				record(await addManagedMembers(ctx, team.id, patchMemberIds(operation.value)));
			} else {
				record(await replaceManagedMembers(ctx, team.id, [...current.filter((userId) => userId !== selector), ...patchMemberIds(operation.value)]));
			}
			continue;
		}
		const value = operation.value;
		if (!path && value && typeof value === "object" && !Array.isArray(value)) {
			for (const [attribute, attributeValue] of Object.entries(value)) {
				record(await applyPatch(ctx, binding, team, [{ ...operation, path: attribute, value: attributeValue }]));
			}
			continue;
		}
		if (path === "displayName") {
			if (operation.op === "remove" || typeof value !== "string" || value.length === 0) throw new SCIMAPIError("BAD_REQUEST", { detail: "displayName is required", scimType: "invalidValue" });
			if (team.name !== value) {
				await orgAdapter.updateTeam(team.id, { name: value });
				team.name = value;
				changes.material = true;
			}
			continue;
		}
		if (path === "externalId") {
			const adapter = await getCurrentAdapter(ctx.context.adapter);
			if (operation.op === "remove") {
				if (binding.externalId === undefined || binding.externalId === null) noTarget();
				await adapter.update<SCIMGroupBinding>({ model: "scimGroup", where: [{ field: "id", value: binding.id }], update: { externalId: null, externalIdKey: null } });
				binding.externalId = null;
				changes.material = true;
			} else if (typeof value === "string") {
				if (binding.externalId !== value) {
					await assertExternalIdAvailable(ctx, value, binding.id);
					await adapter.update<SCIMGroupBinding>({ model: "scimGroup", where: [{ field: "id", value: binding.id }], update: { externalId: value, externalIdKey: externalIdKey(groupScope(ctx), value) } });
					binding.externalId = value;
					changes.material = true;
				}
			} else throw new SCIMAPIError("BAD_REQUEST", { detail: "externalId must be a string", scimType: "invalidValue" });
			continue;
		}
		if (path === "members") {
			if (operation.op === "remove") {
				const current = await managedTeamMembers(ctx, team.id);
				if (current.length === 0) noTarget();
				record(await removeManagedMembers(ctx, team.id, value === undefined ? undefined : memberIds(value)));
			}
			else if (operation.op === "add") record(await addManagedMembers(ctx, team.id, memberIds(value)));
			else record(await replaceManagedMembers(ctx, team.id, memberIds(value)));
			continue;
		}
		throw new SCIMAPIError("BAD_REQUEST", { detail: `Unsupported Group patch path: ${path ?? "(none)"}`, scimType: "invalidPath" });
	}
	return changes;
}

const groupOpenApi = { ...HIDE_METADATA, allowedMediaTypes: supportedMediaTypes, openapi: { responses: { ...SCIMErrorOpenAPISchemas } } };

export const createSCIMGroup = (authMiddleware: AuthMiddleware) => createAuthEndpoint(
	"/scim/v2/Groups", { method: "POST", body: APIGroupSchema, metadata: groupOpenApi, use: [authMiddleware] },
	async (ctx) => {
		const groupCtx = ctx as GroupContext;
		requireGroupMutationTransaction(groupCtx);
		const body = groupCtx.body as APIGroup;
		const scope = groupScope(groupCtx);
		let hookOrganization: unknown;
		const result = await uniqueConflict(() => runWithTransaction(groupCtx.context.adapter, async () => {
			await assertExternalIdAvailable(groupCtx, body.externalId);
			const orgAdapter = await transactionOrgAdapter(groupCtx, scope);
			const now = new Date();
			const beforeCreate = scope.orgOptions.organizationHooks?.beforeCreateTeam as ((payload: unknown) => Promise<{ data?: Record<string, unknown> } | void>) | undefined;
			const created = await orgAdapter.createTeam({ name: body.displayName, organizationId: scope.organizationId, createdAt: now, updatedAt: now }, staticTeamMaximum(scope), async (organization) => {
				hookOrganization = organization;
				const response = await beforeCreate?.({ team: { name: body.displayName, organizationId: scope.organizationId }, user: undefined, organization });
				return response?.data ? { name: body.displayName, organizationId: scope.organizationId, createdAt: now, updatedAt: now, ...response.data } : { name: body.displayName, organizationId: scope.organizationId, createdAt: now, updatedAt: now };
			});
			if (created.status === "limitReached") throw new SCIMAPIError("BAD_REQUEST", { detail: "The organization team limit has been reached", scimType: "invalidValue" });
			if (created.status !== "created") throw new SCIMAPIError("BAD_REQUEST", { detail: `SCIM Group creation is unavailable: ${created.status}`, scimType: "invalidValue" });
			const team = created.team as Team;
			const adapter = await getCurrentAdapter(groupCtx.context.adapter);
			const binding = await adapter.create<SCIMGroupBinding>({ model: "scimGroup", data: { providerId: scope.providerId, organizationId: scope.organizationId, teamId: team.id, externalId: body.externalId, externalIdKey: externalIdKey(scope, body.externalId), createdAt: now, updatedAt: now } });
			const membershipChange = body.members ? await replaceManagedMembers(groupCtx, team.id, body.members.map((member) => member.value)) : { added: 0, removed: 0 };
			await appendGroupAudit(groupCtx, "scim.group.created", binding.id, scope.organizationId, membershipChange);
			return { team, binding };
		}));
		const afterCreate = scope.orgOptions.organizationHooks?.afterCreateTeam as ((payload: unknown) => Promise<void>) | undefined;
		await afterCreate?.({ team: result.team, user: undefined, organization: hookOrganization });
		const resource = await resourceFor(groupCtx, result.binding, result.team);
		ctx.setStatus(201); ctx.setHeader("location", resource.meta.location); return ctx.json(resource);
	},
);

export const getSCIMGroup = (authMiddleware: AuthMiddleware) => createAuthEndpoint(
	"/scim/v2/Groups/:groupId", { method: "GET", metadata: groupOpenApi, use: [authMiddleware] },
	async (ctx) => ctx.json(await resourceFor(ctx as GroupContext, await getBinding(ctx as GroupContext, ctx.params.groupId))),
);

export const updateSCIMGroup = (authMiddleware: AuthMiddleware) => createAuthEndpoint(
	"/scim/v2/Groups/:groupId", { method: "PUT", body: APIGroupSchema, metadata: groupOpenApi, use: [authMiddleware] },
	async (ctx) => {
		const groupCtx = ctx as GroupContext; const body = groupCtx.body as APIGroup;
		requireGroupMutationTransaction(groupCtx);
		const result = await uniqueConflict(() => runWithTransaction(groupCtx.context.adapter, async () => {
			const { binding, team } = await lockBoundGroup(groupCtx, ctx.params.groupId);
			await assertExternalIdAvailable(groupCtx, body.externalId, binding.id);
			const adapter = await getCurrentAdapter(groupCtx.context.adapter); const now = new Date();
			const orgAdapter = await transactionOrgAdapter(groupCtx, groupScope(groupCtx));
			const updatedTeam = await orgAdapter.updateTeam(team.id, { name: body.displayName }) as Team | null;
			const updatedBinding = await adapter.update<SCIMGroupBinding>({ model: "scimGroup", where: [{ field: "id", value: binding.id }], update: { externalId: body.externalId ?? null, externalIdKey: externalIdKey(groupScope(groupCtx), body.externalId), updatedAt: now } });
			if (!updatedTeam || !updatedBinding) throw new SCIMAPIError("NOT_FOUND", { detail: "Group not found" });
			const membershipChange = await replaceManagedMembers(groupCtx, team.id, (body.members ?? []).map((member) => member.value));
			await appendGroupAudit(groupCtx, "scim.group.updated", binding.id, binding.organizationId, membershipChange); return { team: updatedTeam, binding: updatedBinding };
		}));
		return ctx.json(await resourceFor(groupCtx, result.binding, result.team));
	},
);

export const patchSCIMGroup = (authMiddleware: AuthMiddleware) => createAuthEndpoint(
	"/scim/v2/Groups/:groupId", { method: "PATCH", body: GroupPatchSchema, metadata: groupOpenApi, use: [authMiddleware] },
	async (ctx) => {
		const groupCtx = ctx as GroupContext;
		requireGroupMutationTransaction(groupCtx);
		const result = await uniqueConflict(() => runWithTransaction(groupCtx.context.adapter, async () => {
			const { binding, team } = await lockBoundGroup(groupCtx, ctx.params.groupId);
			if (await isDefinitelyNoopPatch(groupCtx, binding, team, groupCtx.body.Operations)) {
				return binding;
			}
			const patchChange = await applyPatch(groupCtx, binding, team, groupCtx.body.Operations);
			if (patchChange.material) {
				const updatedAt = new Date();
				const adapter = await getCurrentAdapter(groupCtx.context.adapter);
				await adapter.update<SCIMGroupBinding>({ model: "scimGroup", where: [{ field: "id", value: binding.id }], update: { updatedAt } });
				binding.updatedAt = updatedAt;
			}
			if (patchChange.material) {
				await appendGroupAudit(groupCtx, "scim.group.updated", binding.id, binding.organizationId, patchChange);
			}
			return binding;
		}));
		return ctx.json(await resourceFor(groupCtx, result));
	},
);

export const deleteSCIMGroup = (authMiddleware: AuthMiddleware) => createAuthEndpoint(
	"/scim/v2/Groups/:groupId", { method: "DELETE", metadata: groupOpenApi, use: [authMiddleware] },
	async (ctx) => {
		const groupCtx = ctx as GroupContext; const scope = groupScope(groupCtx); const afterDelete: { value: { team: Team; organization: unknown } | null } = { value: null };
		requireGroupMutationTransaction(groupCtx);
		await runWithTransaction(groupCtx.context.adapter, async () => {
			const { binding } = await lockBoundGroup(groupCtx, ctx.params.groupId);
			const orgAdapter = await transactionOrgAdapter(groupCtx, scope);
			const managedMembersRemoved = (await managedTeamMembers(groupCtx, binding.teamId, scope)).length;
			const beforeDelete = scope.orgOptions.organizationHooks?.beforeDeleteTeam as ((payload: unknown) => Promise<void>) | undefined;
			if (scope.orgOptions.teams.allowRemovingAllTeams !== true && (await orgAdapter.listTeams(binding.organizationId)).length <= 1) {
				throw new SCIMAPIError("BAD_REQUEST", { detail: "The last team cannot be removed", scimType: "invalidValue" });
			}
			const deleted = await orgAdapter.deleteTeam({ organizationId: binding.organizationId, teamId: binding.teamId, allowRemovingAllTeams: scope.orgOptions.teams.allowRemovingAllTeams === true, beforeDelete: async ({ organization, team }) => beforeDelete?.({ organization, team, user: undefined }) });
			if (deleted.status === "lastTeam") throw new SCIMAPIError("BAD_REQUEST", { detail: "The last team cannot be removed", scimType: "invalidValue" });
			if (deleted.status !== "deleted") throw new SCIMAPIError("NOT_FOUND", { detail: "Group not found" });
			afterDelete.value = { team: deleted.team, organization: deleted.organization };
			const adapter = await getCurrentAdapter(groupCtx.context.adapter);
			await adapter.delete({ model: "scimGroup", where: [{ field: "id", value: binding.id }] });
			await appendGroupAudit(groupCtx, "scim.group.deleted", binding.id, binding.organizationId, { added: 0, removed: managedMembersRemoved });
		});
		const afterHook = scope.orgOptions.organizationHooks?.afterDeleteTeam as ((payload: unknown) => Promise<void>) | undefined;
		if (afterDelete.value) await afterHook?.({ team: afterDelete.value.team, organization: afterDelete.value.organization, user: undefined });
		ctx.setStatus(204); return;
	},
);

const listGroupsQuery = z.object({ filter: z.string().optional(), startIndex: z.coerce.number().int().min(1).optional(), count: z.coerce.number().int().min(0).max(100).optional() }).optional();

function parseGroupFilter(filter?: string): { attribute: "id" | "externalId" | "displayName"; value: string } | undefined {
	if (!filter) return undefined;
	const match = filter.match(/^\s*(id|externalId|displayName)\s+eq\s+"([^"]*)"\s*$/i);
	if (!match) throw new SCIMAPIError("BAD_REQUEST", { detail: "Only id, externalId, and displayName eq filters are supported", scimType: "invalidFilter" });
	const rawAttribute = match[1]!.toLowerCase();
	return { attribute: rawAttribute === "id" ? "id" : rawAttribute === "externalid" ? "externalId" : "displayName", value: match[2]! };
}

function matchGroupFilter(binding: SCIMGroupBinding, team: Team, filter?: string): boolean {
	if (!filter) return true;
	const parsed = parseGroupFilter(filter)!;
	if (parsed.attribute === "id") return binding.id === parsed.value;
	if (parsed.attribute === "externalId") return binding.externalId === parsed.value;
	return team.name.toLowerCase() === parsed.value.toLowerCase();
}

async function resourcesForList(ctx: GroupContext, pairs: Array<{ binding: SCIMGroupBinding; team: Team }>) {
	if (pairs.length === 0) return [];
	const scope = groupScope(ctx);
	const teamIds = pairs.map(({ team }) => team.id);
	const teamMembers = await ctx.context.adapter.findMany<TeamMember>({ model: "teamMember", where: [{ field: "teamId", value: teamIds, operator: "in" }] });
	const userIds = [...new Set(teamMembers.map((member) => member.userId))];
	const [accounts, memberships, users] = userIds.length === 0 ? [[], [], []] : await Promise.all([
		ctx.context.adapter.findMany<Account>({ model: "account", where: [{ field: "providerId", value: scope.providerId }, { field: "userId", value: userIds, operator: "in" }] }),
		ctx.context.adapter.findMany<Member>({ model: "member", where: [{ field: "organizationId", value: scope.organizationId }, { field: "userId", value: userIds, operator: "in" }] }),
		ctx.context.adapter.findMany<User>({ model: "user", where: [{ field: "id", value: userIds, operator: "in" }] }),
	]);
	const allowed = new Set(accounts.map((account) => account.userId).filter((userId) => memberships.some((membership) => membership.userId === userId)));
	const usersById = new Map(users.map((user) => [user.id, user]));
	const usersByTeam = new Map<string, User[]>();
	for (const member of teamMembers) {
		const user = allowed.has(member.userId) ? usersById.get(member.userId) : undefined;
		if (user) usersByTeam.set(member.teamId, [...(usersByTeam.get(member.teamId) ?? []), user]);
	}
	return pairs.map(({ binding, team }) => createGroupResource(ctx.context.baseURL, team, binding, usersByTeam.get(team.id) ?? []));
}

export const listSCIMGroups = (authMiddleware: AuthMiddleware) => createAuthEndpoint(
	"/scim/v2/Groups", { method: "GET", query: listGroupsQuery, metadata: groupOpenApi, use: [authMiddleware] },
	async (ctx) => {
		const groupCtx = ctx as GroupContext; const scope = groupScope(groupCtx);
		const filter = parseGroupFilter(ctx.query?.filter);
		const bindings = await groupCtx.context.adapter.findMany<SCIMGroupBinding>({ model: "scimGroup", where: [{ field: "providerId", value: scope.providerId }, { field: "organizationId", value: scope.organizationId }, ...(filter?.attribute === "id" ? [{ field: "id", value: filter.value }] : []), ...(filter?.attribute === "externalId" ? [{ field: "externalIdKey", value: externalIdKey(scope, filter.value)! }] : [])], sortBy: { field: "id", direction: "asc" }, limit: 201 });
		if (bindings.length === 201) throw new SCIMAPIError("BAD_REQUEST", { detail: "SCIM Group list exceeds the supported 200-resource safety cap", scimType: "tooMany" });
		const teamIds = bindings.map((binding) => binding.teamId);
		const teams = teamIds.length === 0 ? [] : await groupCtx.context.adapter.findMany<Team>({ model: "team", where: [{ field: "id", value: teamIds, operator: "in" }, { field: "organizationId", value: scope.organizationId }] });
		const teamsById = new Map(teams.map((team) => [team.id, team]));
		const pairs = bindings.flatMap((binding) => { const team = teamsById.get(binding.teamId); return team && matchGroupFilter(binding, team, ctx.query?.filter) ? [{ binding, team }] : []; });
		const startIndex = ctx.query?.startIndex ?? 1; const count = ctx.query?.count ?? 100; const selected = pairs.slice(startIndex - 1, startIndex - 1 + count);
		return ctx.json({ schemas: [listResponseSchema], totalResults: pairs.length, startIndex, itemsPerPage: selected.length, Resources: await resourcesForList(groupCtx, selected) });
	},
);
