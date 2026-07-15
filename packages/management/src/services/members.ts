/**
 * Canonical organization membership lifecycle on the management snapshot.
 *
 * Role assignment validates built-in and active custom roles in principal-
 * derived project/environment scope. Owner invariants prevent removing or
 * demoting the final active owner. JsonStore path is management-only;
 * with DATABASE_URL + PgStore prefer addMemberInAuth / updateMemberInAuth /
 * removeMemberInAuth for runtime parity.
 *
 * Intentionally does not import core.ts (core re-exports these helpers).
 */
import type {
	ManagementSnapshotReader,
	ManagementUnitOfWork,
} from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { AuditEvent, Membership, Organization, Principal } from "../types/resources.js";
import { appendAuditEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { resolveAssignableRole } from "./roles.js";
import {
	assertResourceInScope,
	type ResourceScope,
} from "./scope.js";

export type MembershipSource = Membership["source"];
export type MembershipActorSource = AuditEvent["source"] | "import";

function requireOrganization(
	store: ManagementSnapshotReader,
	id: string,
	scope: ResourceScope | undefined,
	stage: string,
): Organization {
	const org = store.snapshot.organizations.find((o) => o.id === id);
	if (!org || org.status === "archived") {
		throw new ClearanceError({
			code: "ORG_NOT_FOUND",
			message: "Organization not found",
			stage,
			status: 404,
		});
	}
	if (scope) {
		assertResourceInScope(org, scope, {
			code: "ORG_NOT_FOUND",
			stage,
			label: "Organization",
		});
	}
	return org;
}

function requirePrincipal(
	store: ManagementSnapshotReader,
	id: string,
	scope: ResourceScope | undefined,
	stage: string,
): Principal {
	const user = store.snapshot.principals.find((p) => p.id === id);
	if (!user || user.status === "deleted") {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage,
			status: 404,
		});
	}
	if (scope) {
		assertResourceInScope(user, scope, {
			code: "USER_NOT_FOUND",
			stage,
			label: "User",
		});
	}
	return user;
}

function activeMembershipsForOrg(
	data: { memberships: Membership[] },
	organizationId: string,
): Membership[] {
	return data.memberships.filter(
		(m) => m.organizationId === organizationId && m.status === "active",
	);
}

/**
 * Fail closed when the target is the sole active owner and the mutation would
 * remove ownership (demote or remove). At least one owner is required.
 */
export function assertOwnerInvariant(
	data: { memberships: Membership[] },
	opts: {
		organizationId: string;
		membership: Membership;
		/** Next role after update; omit for remove */
		nextRole?: string;
		stage: string;
	},
): void {
	const isOwner = opts.membership.role === "owner";
	if (!isOwner) return;

	const demoting =
		opts.nextRole !== undefined && opts.nextRole !== "owner";
	const removing = opts.nextRole === undefined;
	if (!demoting && !removing) return;

	const owners = activeMembershipsForOrg(data, opts.organizationId).filter(
		(m) => m.role === "owner",
	);
	if (owners.length <= 1) {
		throw new ClearanceError({
			code: "MEMBER_LAST_OWNER",
			message:
				"Cannot remove or demote the final active owner; at least one owner is required",
			stage: opts.stage,
			status: 409,
			remediation:
				"Promote another member to owner before demoting or removing this membership",
		});
	}
}

export function listMembers(
	store: ManagementSnapshotReader,
	organizationId: string,
	opts?: { scope?: ResourceScope; includeRemoved?: boolean },
): Membership[] {
	const org = requireOrganization(
		store,
		organizationId,
		opts?.scope,
		"orgs.members.list",
	);
	return store.snapshot.memberships.filter((m) => {
		if (m.organizationId !== org.id) return false;
		if (!opts?.includeRemoved && m.status !== "active") return false;
		return true;
	});
}

export function inspectMembership(
	store: ManagementSnapshotReader,
	id: string,
	scope?: ResourceScope,
): Membership {
	const stage = "orgs.members.inspect";
	const membership = store.snapshot.memberships.find((m) => m.id === id);
	if (!membership || membership.status === "removed") {
		throw new ClearanceError({
			code: "MEMBER_NOT_FOUND",
			message: "Membership not found",
			stage,
			status: 404,
		});
	}
	// Scope via parent organization — foreign org ids fail as membership not found
	try {
		requireOrganization(store, membership.organizationId, scope, stage);
	} catch (e) {
		if (e instanceof ClearanceError && e.code === "ORG_NOT_FOUND") {
			throw new ClearanceError({
				code: "MEMBER_NOT_FOUND",
				message: "Membership not found",
				stage,
				status: 404,
			});
		}
		throw e;
	}
	return membership;
}

/**
 * Find active membership by org + principal. Cross-scope ids fail as not found
 * when scope is provided.
 */
export function findActiveMembership(
	store: ManagementSnapshotReader,
	organizationId: string,
	principalId: string,
	scope?: ResourceScope,
): Membership | undefined {
	requireOrganization(store, organizationId, scope, "orgs.members.find");
	requirePrincipal(store, principalId, scope, "orgs.members.find");
	return store.snapshot.memberships.find(
		(m) =>
			m.organizationId === organizationId &&
			m.principalId === principalId &&
			m.status === "active",
	);
}

function assertPrincipalOrgScope(
	org: { projectId: string; environmentId: string },
	principal: { projectId: string; environmentId: string },
	stage: string,
): void {
	if (
		org.projectId !== principal.projectId ||
		org.environmentId !== principal.environmentId
	) {
		// Indistinguishable from missing user
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage,
			status: 404,
		});
	}
}

/**
 * Management-only add. Prefer addMemberInAuth when DATABASE_URL + PgStore.
 * Idempotent: returns existing active membership without a second audit.
 * Invalid roles fail closed with no write.
 */
export function addMember(
	store: ManagementUnitOfWork,
	input: {
		organizationId: string;
		principalId: string;
		role?: string;
		source?: MembershipSource;
		actor?: string;
		auditSource?: MembershipActorSource;
		scope?: ResourceScope;
		/** Force a specific membership id (runtime id preservation) */
		id?: string;
	},
): Membership {
	const stage = "orgs.members.add";
	const org = requireOrganization(store, input.organizationId, input.scope, stage);
	const principal = requirePrincipal(store, input.principalId, input.scope, stage);
	assertPrincipalOrgScope(org, principal, stage);

	const roleSlug = input.role ?? "member";
	const resolved = resolveAssignableRole(store, roleSlug, {
		scope: {
			projectId: org.projectId,
			environmentId: org.environmentId,
		},
		organizationId: org.id,
		stage,
	});

	const existing = store.snapshot.memberships.find(
		(m) =>
			m.organizationId === org.id &&
			m.principalId === principal.id &&
			m.status === "active",
	);
	if (existing) {
		// Idempotent add: no role change, no second audit
		return existing;
	}

	const now = nowIso();
	const membership: Membership = {
		id: input.id ?? newId("mem"),
		organizationId: org.id,
		principalId: principal.id,
		role: resolved.slug,
		status: "active",
		source: input.source ?? "manual",
		createdAt: now,
		updatedAt: now,
	};

	store.mutate((data) => {
		// Re-check inside mutator for concurrent-safe local path
		const race = data.memberships.find(
			(m) =>
				m.organizationId === org.id &&
				m.principalId === principal.id &&
				m.status === "active",
		);
		if (race) {
			Object.assign(membership, race);
			return;
		}
		data.memberships.push(membership);
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "orgs.members.add",
			subjectType: "membership",
			subjectId: membership.id,
			outcome: "success",
			source: (input.auditSource as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Added ${principal.email} to ${org.name} as ${membership.role}`,
			metadata: {
				role: membership.role,
				roleKind: resolved.kind,
				principalId: principal.id,
			},
		});
	});
	return membership;
}

/**
 * Update membership role (management-only). Prefer updateMemberInAuth with
 * DATABASE_URL + PgStore.
 */
export function updateMember(
	store: ManagementUnitOfWork,
	id: string,
	input: {
		role: string;
		actor?: string;
		auditSource?: MembershipActorSource;
		scope?: ResourceScope;
	},
): Membership {
	const stage = "orgs.members.update";
	if (input.role == null || input.role === "") {
		throw new ClearanceError({
			code: "ROLE_REQUIRED",
			message: "Role is required",
			stage,
			status: 400,
		});
	}

	const membership = inspectMembership(store, id, input.scope);
	const org = requireOrganization(
		store,
		membership.organizationId,
		input.scope,
		stage,
	);

	const resolved = resolveAssignableRole(store, input.role, {
		scope: {
			projectId: org.projectId,
			environmentId: org.environmentId,
		},
		organizationId: org.id,
		stage,
	});

	if (membership.role === resolved.slug) {
		return membership;
	}

	const now = nowIso();
	let updated: Membership | null = null;

	store.mutate((data) => {
		const row = data.memberships.find(
			(m) => m.id === id && m.status === "active",
		);
		if (!row) {
			throw new ClearanceError({
				code: "MEMBER_NOT_FOUND",
				message: "Membership not found",
				stage,
				status: 404,
			});
		}
		assertOwnerInvariant(data, {
			organizationId: org.id,
			membership: row,
			nextRole: resolved.slug,
			stage,
		});
		const previousRole = row.role;
		row.role = resolved.slug;
		row.updatedAt = now;
		updated = { ...row };
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "orgs.members.update",
			subjectType: "membership",
			subjectId: row.id,
			outcome: "success",
			source: (input.auditSource as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Updated membership role ${previousRole} → ${row.role}`,
			metadata: {
				previousRole,
				role: row.role,
				roleKind: resolved.kind,
				principalId: row.principalId,
			},
		});
	});

	if (!updated) {
		throw new ClearanceError({
			code: "MEMBER_NOT_FOUND",
			message: "Membership not found",
			stage,
			status: 404,
		});
	}
	return updated;
}

/**
 * Soft-remove membership (management-only). Prefer removeMemberInAuth with
 * DATABASE_URL + PgStore. Destructive; CLI requires --yes.
 */
export function removeMember(
	store: ManagementUnitOfWork,
	id: string,
	input?: {
		actor?: string;
		auditSource?: MembershipActorSource;
		scope?: ResourceScope;
	},
): Membership {
	const stage = "orgs.members.remove";
	const membership = inspectMembership(store, id, input?.scope);
	const org = requireOrganization(
		store,
		membership.organizationId,
		input?.scope,
		stage,
	);
	const now = nowIso();
	let removed: Membership | null = null;

	store.mutate((data) => {
		const row = data.memberships.find(
			(m) => m.id === id && m.status === "active",
		);
		if (!row) {
			throw new ClearanceError({
				code: "MEMBER_NOT_FOUND",
				message: "Membership not found",
				stage,
				status: 404,
			});
		}
		assertOwnerInvariant(data, {
			organizationId: org.id,
			membership: row,
			stage,
		});
		row.status = "removed";
		row.updatedAt = now;
		removed = { ...row };
		appendAuditEvent(data, {
			actor: input?.actor ?? "operator",
			action: "orgs.members.remove",
			subjectType: "membership",
			subjectId: row.id,
			outcome: "success",
			source: (input?.auditSource as "cli") ?? "cli",
			organizationId: org.id,
			projectId: org.projectId,
			environmentId: org.environmentId,
			message: `Removed membership for principal ${row.principalId} from ${org.name}`,
			metadata: {
				role: row.role,
				principalId: row.principalId,
			},
		});
	});

	if (!removed) {
		throw new ClearanceError({
			code: "MEMBER_NOT_FOUND",
			message: "Membership not found",
			stage,
			status: 404,
		});
	}
	return removed;
}

/**
 * Update or remove by organization + principal (CLI convenience).
 * Fails closed when membership missing (same as inspect).
 */
export function resolveMembershipId(
	store: ManagementSnapshotReader,
	input: {
		organizationId: string;
		principalId?: string;
		membershipId?: string;
		scope?: ResourceScope;
	},
	stage: string,
): string {
	if (input.membershipId) {
		const m = inspectMembership(store, input.membershipId, input.scope);
		if (
			input.organizationId &&
			m.organizationId !== input.organizationId
		) {
			throw new ClearanceError({
				code: "MEMBER_NOT_FOUND",
				message: "Membership not found",
				stage,
				status: 404,
			});
		}
		return m.id;
	}
	if (!input.principalId) {
		throw new ClearanceError({
			code: "MEMBER_IDENTITY_REQUIRED",
			message: "Membership id or user id is required",
			stage,
			status: 400,
			remediation: "Pass membership id or --user with --org",
		});
	}
	const found = findActiveMembership(
		store,
		input.organizationId,
		input.principalId,
		input.scope,
	);
	if (!found) {
		throw new ClearanceError({
			code: "MEMBER_NOT_FOUND",
			message: "Membership not found",
			stage,
			status: 404,
		});
	}
	return found.id;
}
