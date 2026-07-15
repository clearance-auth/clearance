/**
 * Canonical custom-role management on the snapshot store.
 *
 * Roles are project + environment scoped. Built-in roles (owner/admin/member)
 * are virtual system definitions — always listed, never created/updated.
 * Custom roles persist in DataStoreSnapshot.roles.
 */
import type { ManagementSnapshotReader, ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { CustomRole } from "../types/resources.js";
import { appendAuditEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import {
	assertResourceInScope,
	resolveOperatorScope,
	scopeFilter,
	type ResourceScope,
} from "./scope.js";

/** Permission token: resource:action (lowercase, stable) */
const PERMISSION_RE = /^[a-z][a-z0-9_.-]*:[a-z][a-z0-9_.-]*$/;

/** Reserved built-in role slugs — cannot be created or mutated as custom roles */
export const BUILT_IN_ROLE_SLUGS = ["owner", "admin", "member"] as const;
export type BuiltInRoleSlug = (typeof BUILT_IN_ROLE_SLUGS)[number];

const BUILT_IN_DEFINITIONS: ReadonlyArray<{
	slug: BuiltInRoleSlug;
	name: string;
	description: string;
	permissions: readonly string[];
}> = [
	{
		slug: "owner",
		name: "Owner",
		description: "Full organization control including delete and access-control management",
		permissions: [
			"ac:create",
			"ac:delete",
			"ac:read",
			"ac:update",
			"invitation:cancel",
			"invitation:create",
			"member:create",
			"member:delete",
			"member:update",
			"organization:delete",
			"organization:update",
			"team:create",
			"team:delete",
			"team:update",
		],
	},
	{
		slug: "admin",
		name: "Admin",
		description: "Manage members, invitations, teams, and access control (no organization delete)",
		permissions: [
			"ac:create",
			"ac:delete",
			"ac:read",
			"ac:update",
			"invitation:cancel",
			"invitation:create",
			"member:create",
			"member:delete",
			"member:update",
			"organization:update",
			"team:create",
			"team:delete",
			"team:update",
		],
	},
	{
		slug: "member",
		name: "Member",
		description: "Baseline organization membership with read access to roles",
		permissions: ["ac:read"],
	},
];

const EPOCH = "1970-01-01T00:00:00.000Z";

function slugify(name: string): string {
	return name
		.toLowerCase()
		.trim()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-|-$/g, "")
		.slice(0, 48);
}

export function isBuiltInRoleSlug(slug: string): slug is BuiltInRoleSlug {
	return (BUILT_IN_ROLE_SLUGS as readonly string[]).includes(slug.toLowerCase());
}

export function builtInRoleId(slug: BuiltInRoleSlug): string {
	return `role_builtin_${slug}`;
}

/** Role slug shape for membership assignment (built-in or custom). */
const ASSIGNABLE_ROLE_SLUG_RE = /^[a-z][a-z0-9_-]*$/;

export type AssignableRole = {
	slug: string;
	kind: "built_in" | "custom";
	roleId: string;
};

/**
 * Resolve a role slug for membership assignment within principal-derived scope.
 * Built-in owner/admin/member always accepted. Custom roles must be active and
 * in the same project/environment; organization-bound roles must match the org.
 * Fail closed with stable structured errors for missing/foreign/disabled/archived.
 */
export function resolveAssignableRole(
	store: ManagementSnapshotReader,
	roleInput: unknown,
	opts: {
		scope: ResourceScope;
		organizationId: string;
		stage: string;
	},
): AssignableRole {
	if (roleInput == null || roleInput === "") {
		throw new ClearanceError({
			code: "ROLE_REQUIRED",
			message: "Role is required",
			stage: opts.stage,
			status: 400,
			remediation: "Pass a built-in role (owner, admin, member) or an active custom role slug",
		});
	}
	if (typeof roleInput !== "string") {
		throw new ClearanceError({
			code: "ROLE_INVALID",
			message: "Role must be a string slug",
			stage: opts.stage,
			status: 400,
		});
	}
	const slug = roleInput.trim().toLowerCase();
	if (!slug || !ASSIGNABLE_ROLE_SLUG_RE.test(slug) || slug.length > 48) {
		throw new ClearanceError({
			code: "ROLE_INVALID",
			message: "Role slug is malformed",
			stage: opts.stage,
			status: 400,
			remediation: "Use lowercase alphanumeric role slugs with hyphens or underscores",
		});
	}

	if (isBuiltInRoleSlug(slug)) {
		return {
			slug,
			kind: "built_in",
			roleId: builtInRoleId(slug),
		};
	}

	const custom = (store.snapshot.roles ?? []).find(
		(r) =>
			r.kind === "custom" &&
			r.slug === slug &&
			r.projectId === opts.scope.projectId &&
			r.environmentId === opts.scope.environmentId,
	);

	// Foreign-scope / missing are indistinguishable
	if (!custom) {
		throw new ClearanceError({
			code: "ROLE_NOT_FOUND",
			message: "Role not found",
			stage: opts.stage,
			status: 404,
		});
	}

	const status = custom.status ?? "active";
	if (status === "disabled") {
		throw new ClearanceError({
			code: "ROLE_DISABLED",
			message: "Role is disabled and cannot be assigned",
			stage: opts.stage,
			status: 409,
			remediation: "Enable the role or choose a different role slug",
		});
	}
	if (status === "archived") {
		throw new ClearanceError({
			code: "ROLE_ARCHIVED",
			message: "Role is archived and cannot be assigned",
			stage: opts.stage,
			status: 409,
			remediation: "Choose an active role slug",
		});
	}

	if (
		custom.organizationId &&
		custom.organizationId !== opts.organizationId
	) {
		// Org-bound role from another org → fail closed as not found
		throw new ClearanceError({
			code: "ROLE_NOT_FOUND",
			message: "Role not found",
			stage: opts.stage,
			status: 404,
		});
	}

	return {
		slug: custom.slug,
		kind: "custom",
		roleId: custom.id,
	};
}

function isBuiltInRoleId(id: string): boolean {
	return id.startsWith("role_builtin_");
}

function virtualBuiltInRoles(scope: ResourceScope): CustomRole[] {
	return BUILT_IN_DEFINITIONS.map((def) => ({
		id: builtInRoleId(def.slug),
		projectId: scope.projectId,
		environmentId: scope.environmentId,
		name: def.name,
		slug: def.slug,
		description: def.description,
		permissions: [...def.permissions],
		kind: "built_in" as const,
		createdAt: EPOCH,
		updatedAt: EPOCH,
	}));
}

/**
 * Normalize and validate permission tokens.
 * - trim + lowercase
 * - reject empty / malformed / duplicates
 * - return stably sorted unique list
 */
export function normalizeAndValidatePermissions(
	input: unknown,
	stage: string,
): string[] {
	if (input == null) {
		throw new ClearanceError({
			code: "ROLE_PERMISSIONS_REQUIRED",
			message: "permissions array is required",
			stage,
			status: 400,
			remediation: 'Pass permissions as string[] of "resource:action" tokens',
		});
	}
	if (!Array.isArray(input)) {
		throw new ClearanceError({
			code: "ROLE_PERMISSIONS_INVALID",
			message: "permissions must be an array of strings",
			stage,
			status: 400,
		});
	}
	if (input.length === 0) {
		throw new ClearanceError({
			code: "ROLE_PERMISSIONS_EMPTY",
			message: "permissions must not be empty",
			stage,
			status: 400,
			remediation: "Provide at least one resource:action permission",
		});
	}

	const seen = new Set<string>();
	const normalized: string[] = [];

	for (let i = 0; i < input.length; i++) {
		const raw = input[i];
		if (typeof raw !== "string") {
			throw new ClearanceError({
				code: "ROLE_PERMISSION_MALFORMED",
				message: `Permission at index ${i} must be a string`,
				stage,
				status: 400,
			});
		}
		const token = raw.trim().toLowerCase();
		if (!token) {
			throw new ClearanceError({
				code: "ROLE_PERMISSION_EMPTY",
				message: `Permission at index ${i} is empty`,
				stage,
				status: 400,
			});
		}
		if (!PERMISSION_RE.test(token)) {
			throw new ClearanceError({
				code: "ROLE_PERMISSION_MALFORMED",
				message: `Permission "${raw}" is malformed; expected resource:action (lowercase alphanumerics, _ . -)`,
				stage,
				status: 400,
				remediation: 'Use tokens like "member:create" or "organization:update"',
			});
		}
		if (seen.has(token)) {
			throw new ClearanceError({
				code: "ROLE_PERMISSION_DUPLICATE",
				message: `Duplicate permission "${token}"`,
				stage,
				status: 400,
			});
		}
		seen.add(token);
		normalized.push(token);
	}

	normalized.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
	return normalized;
}

export function validateRoleName(name: unknown, stage: string): string {
	if (typeof name !== "string" || !name.trim()) {
		throw new ClearanceError({
			code: "ROLE_NAME_REQUIRED",
			message: "Role name is required",
			stage,
			status: 400,
		});
	}
	const trimmed = name.trim();
	if (trimmed.length > 64) {
		throw new ClearanceError({
			code: "ROLE_NAME_INVALID",
			message: "Role name must be at most 64 characters",
			stage,
			status: 400,
		});
	}
	return trimmed;
}

export function validateRoleSlug(slug: unknown, stage: string): string {
	if (slug == null || slug === "") {
		throw new ClearanceError({
			code: "ROLE_SLUG_REQUIRED",
			message: "Role slug is required",
			stage,
			status: 400,
		});
	}
	if (typeof slug !== "string") {
		throw new ClearanceError({
			code: "ROLE_SLUG_INVALID",
			message: "Role slug must be a string",
			stage,
			status: 400,
		});
	}
	const normalized = slugify(slug);
	if (!normalized || !/^[a-z][a-z0-9-]*$/.test(normalized)) {
		throw new ClearanceError({
			code: "ROLE_SLUG_INVALID",
			message: `Role slug "${slug}" is invalid; use lowercase alphanumeric with hyphens`,
			stage,
			status: 400,
		});
	}
	if (isBuiltInRoleSlug(normalized)) {
		throw new ClearanceError({
			code: "ROLE_RESERVED",
			message: `Role slug "${normalized}" is reserved for a built-in role`,
			stage,
			status: 409,
			remediation: "Choose a different slug; owner, admin, and member are reserved",
		});
	}
	return normalized;
}

/**
 * Pure validation of a role draft (name/slug/permissions).
 * Requires scope resolution for API consistency even though nothing is persisted.
 */
export function validateRole(
	store: ManagementStore,
	input: {
		name?: unknown;
		slug?: unknown;
		permissions?: unknown;
		scope?: ResourceScope;
		projectId?: string;
		environmentId?: string;
	},
): {
	ok: true;
	name?: string;
	slug?: string;
	permissions?: string[];
	scope: ResourceScope;
} {
	const scope =
		input.scope ??
		resolveOperatorScope(store, {
			projectId: input.projectId,
			environmentId: input.environmentId,
		});

	const result: {
		ok: true;
		name?: string;
		slug?: string;
		permissions?: string[];
		scope: ResourceScope;
	} = { ok: true, scope };

	if (input.name !== undefined) {
		result.name = validateRoleName(input.name, "roles.validate");
	}
	if (input.slug !== undefined) {
		result.slug = validateRoleSlug(input.slug, "roles.validate");
	} else if (result.name) {
		// Derived slug must also pass reserved checks when name implies a slug
		const derived = slugify(result.name);
		if (derived) {
			result.slug = validateRoleSlug(derived, "roles.validate");
		}
	}
	if (input.permissions !== undefined) {
		result.permissions = normalizeAndValidatePermissions(
			input.permissions,
			"roles.validate",
		);
	}

	if (
		result.name === undefined &&
		result.slug === undefined &&
		result.permissions === undefined
	) {
		throw new ClearanceError({
			code: "ROLE_VALIDATE_EMPTY",
			message: "Provide name, slug, and/or permissions to validate",
			stage: "roles.validate",
			status: 400,
		});
	}

	return result;
}

export function listRoles(
	store: ManagementStore,
	filter?: { scope?: ResourceScope },
): CustomRole[] {
	const scope = filter?.scope ?? resolveOperatorScope(store);
	const inScope = scopeFilter(scope);
	const custom = (store.snapshot.roles ?? []).filter(
		(r) => r.kind === "custom" && inScope(r),
	);
	// Stable order: built-ins first (owner, admin, member), then custom by slug
	const builtIns = virtualBuiltInRoles(scope);
	const sortedCustom = [...custom].sort((a, b) =>
		a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0,
	);
	return [...builtIns, ...sortedCustom];
}

export function inspectRole(
	store: ManagementStore,
	id: string,
	scope?: ResourceScope,
): CustomRole {
	const resolved = scope ?? resolveOperatorScope(store);

	if (isBuiltInRoleId(id)) {
		const builtIn = virtualBuiltInRoles(resolved).find((r) => r.id === id);
		if (!builtIn) {
			throw new ClearanceError({
				code: "ROLE_NOT_FOUND",
				message: "Role not found",
				stage: "roles.inspect",
				status: 404,
			});
		}
		return builtIn;
	}

	const role = (store.snapshot.roles ?? []).find((r) => r.id === id);
	if (!role) {
		throw new ClearanceError({
			code: "ROLE_NOT_FOUND",
			message: "Role not found",
			stage: "roles.inspect",
			status: 404,
		});
	}
	assertResourceInScope(role, resolved, {
		code: "ROLE_NOT_FOUND",
		stage: "roles.inspect",
		label: "Role",
	});
	return role;
}

export async function createRole(
	store: ManagementStore,
	input: {
		name: string;
		slug?: string;
		description?: string;
		permissions: string[];
		projectId?: string;
		environmentId?: string;
		actor?: string;
		source?: "cli" | "console" | "api";
		scope?: ResourceScope;
	},
): Promise<CustomRole> {
	const scope =
		input.scope ??
		resolveOperatorScope(store, {
			projectId: input.projectId,
			environmentId: input.environmentId,
		});

	const name = validateRoleName(input.name, "roles.create");
	const slug = validateRoleSlug(
		input.slug?.trim() ? input.slug : name,
		"roles.create",
	);
	const permissions = normalizeAndValidatePermissions(
		input.permissions,
		"roles.create",
	);
	const description =
		typeof input.description === "string" && input.description.trim()
			? input.description.trim().slice(0, 256)
			: undefined;

	const now = nowIso();
	const role: CustomRole = {
		id: newId("role"),
		projectId: scope.projectId,
		environmentId: scope.environmentId,
		name,
		slug,
		description,
		permissions,
		kind: "custom",
		createdAt: now,
		updatedAt: now,
	};

	return store.mutateDurable((data) => {
		if (!Array.isArray(data.roles)) data.roles = [];

		const conflict = data.roles.find(
			(r) =>
				r.slug === slug &&
				r.projectId === scope.projectId &&
				r.environmentId === scope.environmentId,
		);
		if (conflict) {
			throw new ClearanceError({
				code: "ROLE_EXISTS",
				message: `Role slug "${slug}" already exists in this project/environment`,
				stage: "roles.create",
				status: 409,
			});
		}

		data.roles.push(role);
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "roles.create",
			subjectType: "role",
			subjectId: role.id,
			outcome: "success",
			source: input.source ?? "cli",
			projectId: scope.projectId,
			environmentId: scope.environmentId,
			message: `Created role ${role.slug}`,
			metadata: {
				slug: role.slug,
				permissionCount: role.permissions.length,
				permissions: role.permissions,
			},
		});
		return { ...role, permissions: [...role.permissions] };
	});
}

export async function updateRole(
	store: ManagementStore,
	id: string,
	input: {
		name?: string;
		description?: string | null;
		permissions?: string[];
		actor?: string;
		source?: "cli" | "console" | "api";
		scope?: ResourceScope;
	},
): Promise<CustomRole> {
	const scope = input.scope ?? resolveOperatorScope(store);

	if (isBuiltInRoleId(id) || isBuiltInRoleSlug(id.replace(/^role_builtin_/, ""))) {
		throw new ClearanceError({
			code: "ROLE_BUILT_IN",
			message: "Built-in roles cannot be updated",
			stage: "roles.update",
			status: 403,
			remediation: "Create a custom role instead of mutating owner/admin/member",
		});
	}

	const hasName = input.name !== undefined;
	const hasDescription = input.description !== undefined;
	const hasPermissions = input.permissions !== undefined;
	if (!hasName && !hasDescription && !hasPermissions) {
		throw new ClearanceError({
			code: "ROLE_UPDATE_EMPTY",
			message: "At least one of name, description, or permissions is required",
			stage: "roles.update",
			status: 400,
		});
	}

	const name = hasName ? validateRoleName(input.name, "roles.update") : undefined;
	const permissions = hasPermissions
		? normalizeAndValidatePermissions(input.permissions, "roles.update")
		: undefined;
	const description = hasDescription
		? input.description === null ||
			(typeof input.description === "string" && !input.description.trim())
			? null
			: String(input.description).trim().slice(0, 256)
		: undefined;

	const now = nowIso();

	return store.mutateDurable((data) => {
		if (!Array.isArray(data.roles)) data.roles = [];
		const role = data.roles.find((r) => r.id === id);
		if (!role || role.kind === "built_in") {
			// Fail closed: missing or built-in (if ever persisted) → not found / built-in
			if (role?.kind === "built_in") {
				throw new ClearanceError({
					code: "ROLE_BUILT_IN",
					message: "Built-in roles cannot be updated",
					stage: "roles.update",
					status: 403,
				});
			}
			throw new ClearanceError({
				code: "ROLE_NOT_FOUND",
				message: "Role not found",
				stage: "roles.update",
				status: 404,
			});
		}
		assertResourceInScope(role, scope, {
			code: "ROLE_NOT_FOUND",
			stage: "roles.update",
			label: "Role",
		});

		if (name !== undefined) role.name = name;
		if (description !== undefined) {
			if (description === null) {
				delete role.description;
			} else {
				role.description = description;
			}
		}
		if (permissions !== undefined) role.permissions = permissions;
		role.updatedAt = now;

		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "roles.update",
			subjectType: "role",
			subjectId: role.id,
			outcome: "success",
			source: input.source ?? "cli",
			projectId: role.projectId,
			environmentId: role.environmentId,
			message: `Updated role ${role.slug}`,
			metadata: {
				slug: role.slug,
				fields: [
					...(hasName ? ["name"] : []),
					...(hasDescription ? ["description"] : []),
					...(hasPermissions ? ["permissions"] : []),
				],
				permissionCount: role.permissions.length,
				...(hasPermissions ? { permissions: role.permissions } : {}),
			},
		});
		return { ...role, permissions: [...role.permissions] };
	});
}
