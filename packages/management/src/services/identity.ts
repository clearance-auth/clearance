/**
 * Canonical runtime ↔ management identity bridge.
 *
 * Runtime signups (Clearance `user` rows) and management principals share one
 * stable ID. Management metadata (projectId/environmentId/status) is scoped;
 * the identity id/email/name come from the runtime user record.
 *
 * Idempotent: re-syncing the same runtime user returns the existing principal.
 * Failures are not swallowed — callers must handle errors (and await ready()
 * / use the durable helper for Postgres).
 */
import type { ManagementStore } from "../store/types.js";
import type { AuditEvent, Organization, Principal } from "../types/resources.js";
import { newId, nowIso } from "../store/json-store.js";
import { appendAuditEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { resolveOperatorScope, type ResourceScope } from "./scope.js";

export type RuntimeUserIdentity = {
	/** Canonical Clearance / runtime user id — becomes management principal id */
	id: string;
	email: string;
	name: string;
	createdAt?: string | Date;
	updatedAt?: string | Date;
};

export type RuntimeOrganizationIdentity = {
	id: string;
	name: string;
	slug: string;
	createdAt?: string | Date;
	/**
	 * Canonical Clearance owner membership id. When present, management
	 * membership for the owner uses this exact stable id (create or reconcile).
	 */
	ownerMembershipId?: string;
};

function toIso(value: string | Date | undefined, fallback: string): string {
	if (!value) return fallback;
	if (value instanceof Date) return value.toISOString();
	const d = new Date(value);
	return Number.isNaN(d.getTime()) ? fallback : d.toISOString();
}

/**
 * Persist a runtime user into the management store with the identical stable id.
 * Safe to call repeatedly (idempotent by id and by email-within-scope).
 *
 * For Postgres, call syncRuntimeUserToManagementDurable (or await store.ready())
 * so durability and constraint failures surface.
 */
export function syncRuntimeUserToManagement(
	store: ManagementStore,
	runtimeUser: RuntimeUserIdentity,
	opts?: {
		projectId?: string;
		environmentId?: string;
		actor?: string;
		source?: AuditEvent["source"];
	},
): Principal {
	if (!runtimeUser.id?.trim()) {
		throw new ClearanceError({
			code: "IDENTITY_ID_REQUIRED",
			message: "Runtime user id is required for canonical identity sync",
			stage: "identity.sync",
			status: 400,
		});
	}
	if (!runtimeUser.email?.trim()) {
		throw new ClearanceError({
			code: "IDENTITY_EMAIL_REQUIRED",
			message: "Runtime user email is required for canonical identity sync",
			stage: "identity.sync",
			status: 400,
		});
	}

	const scope: ResourceScope = resolveOperatorScope(store, {
		projectId: opts?.projectId,
		environmentId: opts?.environmentId,
	});

	const email = runtimeUser.email.toLowerCase();
	const name = runtimeUser.name?.trim() || email;
	const now = nowIso();
	const createdAt = toIso(runtimeUser.createdAt, now);
	const updatedAt = toIso(runtimeUser.updatedAt, now);

	// Build return object outside mutate (PgStore applies mutators asynchronously)
	const principal: Principal = {
		id: runtimeUser.id,
		projectId: scope.projectId,
		environmentId: scope.environmentId,
		email,
		name,
		status: "active",
		createdAt,
		updatedAt,
	};

	store.mutate((data) => {
		const byId = data.principals.find((p) => p.id === runtimeUser.id);
		if (byId) {
			if (
				byId.projectId !== scope.projectId ||
				byId.environmentId !== scope.environmentId
			) {
				throw new ClearanceError({
					code: "IDENTITY_SCOPE_CONFLICT",
					message: "Runtime user id is already bound to another project/environment",
					stage: "identity.sync",
					status: 409,
				});
			}
			byId.email = email;
			byId.name = name;
			byId.updatedAt = updatedAt;
			if (byId.status === "deleted") byId.status = "active";
			principal.createdAt = byId.createdAt;
			principal.email = byId.email;
			principal.name = byId.name;
			principal.status = byId.status;
			return;
		}

		const byEmail = data.principals.find(
			(p) =>
				p.email.toLowerCase() === email &&
				p.projectId === scope.projectId &&
				p.environmentId === scope.environmentId &&
				p.status !== "deleted",
		);
		if (byEmail) {
			if (byEmail.id !== runtimeUser.id) {
				throw new ClearanceError({
					code: "IDENTITY_EMAIL_CONFLICT",
					message: `User ${email} already exists with a different stable id`,
					stage: "identity.sync",
					status: 409,
				});
			}
			return;
		}

		data.principals.push({
			id: runtimeUser.id,
			projectId: scope.projectId,
			environmentId: scope.environmentId,
			email,
			name,
			status: "active",
			createdAt,
			updatedAt,
		});
		appendAuditEvent(data, {
			actor: opts?.actor ?? email,
			action: "users.sync_runtime",
			subjectType: "principal",
			subjectId: runtimeUser.id,
			outcome: "success",
			source: opts?.source ?? "system",
			projectId: scope.projectId,
			environmentId: scope.environmentId,
			message: `Synced runtime user ${email} into management (canonical id)`,
			metadata: { origin: "runtime", stableId: runtimeUser.id },
		});
	});

	return principal;
}

/**
 * Async variant that awaits durable commit (required for Postgres backend).
 * Does not swallow failures — rethrows after ready().
 */
export async function syncRuntimeUserToManagementDurable(
	store: ManagementStore,
	runtimeUser: RuntimeUserIdentity,
	opts?: {
		projectId?: string;
		environmentId?: string;
		actor?: string;
		source?: AuditEvent["source"];
	},
): Promise<Principal> {
	const principal = syncRuntimeUserToManagement(store, runtimeUser, opts);
	await store.ready();
	const found = store.snapshot.principals.find((p) => p.id === principal.id);
	if (!found || found.status === "deleted") {
		throw new ClearanceError({
			code: "IDENTITY_SYNC_NOT_DURABLE",
			message: "Identity sync did not persist durably",
			stage: "identity.sync",
			status: 500,
			remediation: "Retry signup sync; check DATABASE_URL / management store health",
		});
	}
	return found;
}

/**
 * Mirror a runtime organization and its owner membership into the canonical
 * scoped management view while preserving the runtime organization id.
 * When ownerMembershipId is provided, management uses that exact stable
 * membership id (create or reconcile). Organization, membership, and audit
 * records commit in one store mutation.
 */
export async function syncRuntimeOrganizationToManagementDurable(
	store: ManagementStore,
	runtimeOrganization: RuntimeOrganizationIdentity,
	ownerPrincipalId: string,
	opts?: {
		projectId?: string;
		environmentId?: string;
		actor?: string;
		role?: string;
	},
): Promise<Organization> {
	if (!runtimeOrganization.id?.trim() || !runtimeOrganization.slug?.trim()) {
		throw new ClearanceError({
			code: "ORGANIZATION_IDENTITY_REQUIRED",
			message: "Runtime organization id and slug are required",
			stage: "identity.organization_sync",
			status: 400,
		});
	}
	const ownerMembershipId = runtimeOrganization.ownerMembershipId?.trim() || undefined;
	const scope = resolveOperatorScope(store, opts);
	const now = nowIso();
	const createdAt = toIso(runtimeOrganization.createdAt, now);
	const organization: Organization = {
		id: runtimeOrganization.id,
		projectId: scope.projectId,
		environmentId: scope.environmentId,
		name: runtimeOrganization.name,
		slug: runtimeOrganization.slug,
		status: "active",
		createdAt,
		updatedAt: now,
	};

	store.mutate((data) => {
		const principal = data.principals.find(
			(p) =>
				p.id === ownerPrincipalId &&
				p.projectId === scope.projectId &&
				p.environmentId === scope.environmentId &&
				p.status !== "deleted",
		);
		if (!principal) {
			throw new ClearanceError({
				code: "USER_NOT_FOUND",
				message: "Organization owner was not found in the authorized scope",
				stage: "identity.organization_sync",
				status: 404,
			});
		}

		const slugConflict = data.organizations.find(
			(o) =>
				o.id !== runtimeOrganization.id &&
				o.slug === runtimeOrganization.slug &&
				o.projectId === scope.projectId &&
				o.environmentId === scope.environmentId &&
				o.status !== "archived",
		);
		if (slugConflict) {
			throw new ClearanceError({
				code: "ORG_SLUG_EXISTS",
				message: `Organization slug ${runtimeOrganization.slug} already exists`,
				stage: "identity.organization_sync",
				status: 409,
			});
		}

		const existing = data.organizations.find(
			(o) => o.id === runtimeOrganization.id,
		);
		if (existing) {
			if (
				existing.projectId !== scope.projectId ||
				existing.environmentId !== scope.environmentId
			) {
				throw new ClearanceError({
					code: "ORGANIZATION_SCOPE_CONFLICT",
					message: "Runtime organization id is already bound to another scope",
					stage: "identity.organization_sync",
					status: 409,
				});
			}
			existing.name = runtimeOrganization.name;
			existing.slug = runtimeOrganization.slug;
			existing.updatedAt = now;
			existing.status = "active";
			Object.assign(organization, existing);
		} else {
			data.organizations.push(organization);
			appendAuditEvent(data, {
				actor: opts?.actor ?? principal.email,
				action: "orgs.sync_runtime",
				subjectType: "organization",
				subjectId: organization.id,
				outcome: "success",
				source: "system",
				organizationId: organization.id,
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				message: `Synced runtime organization ${organization.slug}`,
			});
		}

		// Fail closed: runtime membership id must not be bound to another org/principal
		if (ownerMembershipId) {
			const idHolder = data.memberships.find((m) => m.id === ownerMembershipId);
			if (
				idHolder &&
				(idHolder.organizationId !== organization.id ||
					idHolder.principalId !== principal.id)
			) {
				throw new ClearanceError({
					code: "MEMBERSHIP_ID_CONFLICT",
					message:
						"Runtime owner membership id is already bound to a different organization or principal",
					stage: "identity.organization_sync",
					status: 409,
				});
			}
		}

		const membership = data.memberships.find(
			(m) =>
				m.organizationId === organization.id &&
				m.principalId === principal.id &&
				m.status === "active",
		);
		if (!membership) {
			const membershipId = ownerMembershipId ?? newId("mem");
			// Same id may already exist as non-active for this org+principal — revive
			const byId = data.memberships.find((m) => m.id === membershipId);
			if (byId) {
				if (
					byId.organizationId !== organization.id ||
					byId.principalId !== principal.id
				) {
					throw new ClearanceError({
						code: "MEMBERSHIP_ID_CONFLICT",
						message:
							"Runtime owner membership id is already bound to a different organization or principal",
						stage: "identity.organization_sync",
						status: 409,
					});
				}
				byId.status = "active";
				byId.role = opts?.role ?? byId.role ?? "owner";
				byId.updatedAt = now;
			} else {
				data.memberships.push({
					id: membershipId,
					organizationId: organization.id,
					principalId: principal.id,
					role: opts?.role ?? "owner",
					status: "active",
					source: "manual",
					createdAt: now,
					updatedAt: now,
				});
			}
			appendAuditEvent(data, {
				actor: opts?.actor ?? principal.email,
				action: "orgs.members.sync_runtime",
				subjectType: "membership",
				subjectId: membershipId,
				outcome: "success",
				source: "system",
				organizationId: organization.id,
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				message: `Synced runtime owner ${principal.email}`,
			});
		} else if (ownerMembershipId && membership.id !== ownerMembershipId) {
			// Prefer runtime id as canonical; rewrite management id deterministically
			const taken = data.memberships.find(
				(m) =>
					m.id === ownerMembershipId &&
					m !== membership &&
					(m.organizationId !== organization.id ||
						m.principalId !== principal.id),
			);
			if (taken) {
				throw new ClearanceError({
					code: "MEMBERSHIP_ID_CONFLICT",
					message:
						"Runtime owner membership id is already bound to a different organization or principal",
					stage: "identity.organization_sync",
					status: 409,
				});
			}
			// Drop a stale non-active row that already holds the target id for this pair
			const staleSameBinding = data.memberships.find(
				(m) =>
					m !== membership &&
					m.id === ownerMembershipId &&
					m.organizationId === organization.id &&
					m.principalId === principal.id,
			);
			if (staleSameBinding) {
				const idx = data.memberships.indexOf(staleSameBinding);
				if (idx >= 0) data.memberships.splice(idx, 1);
			}
			membership.id = ownerMembershipId;
			membership.updatedAt = now;
		}
	});

	await store.ready();
	const durable = store.snapshot.organizations.find(
		(o) => o.id === runtimeOrganization.id && o.status !== "archived",
	);
	if (!durable) {
		throw new ClearanceError({
			code: "ORGANIZATION_SYNC_NOT_DURABLE",
			message: "Runtime organization sync did not persist durably",
			stage: "identity.organization_sync",
			status: 500,
		});
	}
	return durable;
}
