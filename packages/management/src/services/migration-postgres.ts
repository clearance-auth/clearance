import { ensureAuthMigrated } from "../auth-bridge.js";
import type { ManagementStore } from "../store/types.js";
import { nowIso } from "../store/json-store.js";
import type { DataStoreSnapshot, Membership, MigrationPlan } from "../types/resources.js";
import { appendAuditEvent } from "./audit.js";
import { addMember, createOrganization, createUser } from "./core.js";
import { ClearanceError } from "./errors.js";
import {
	type LegacyExportFixture,
	assertMigrationRunnable,
	migrationStatus,
	previewMigration,
	rollbackMigration,
	runMigration,
	verifyMigration,
} from "./migration.js";
import { resolveOperatorScope } from "./scope.js";

type Query = (
	sql: string,
	params?: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;

function draftStore(data: DataStoreSnapshot): ManagementStore {
	return {
		backend: "json",
		path: "",
		get snapshot() { return data; },
		mutate(fn) { fn(data); return data; },
	} as ManagementStore;
}

function requireCoordinated(store: ManagementStore, stage: string) {
	if (store.backend !== "postgres" || typeof store.mutateCoordinated !== "function") {
		throw new ClearanceError({
			code: "CLEARANCE_IMPORT_POSTGRES_UNSUPPORTED",
			message: "Clearance import requires the coordinated Postgres management store",
			stage,
			remediation: "Set DATABASE_URL and use the Postgres management backend, or use the JSON local profile.",
		});
	}
	return store.mutateCoordinated.bind(store);
}

function checkpointMismatch(stage: string): never {
	throw new ClearanceError({
		code: "CLEARANCE_IMPORT_CHECKPOINT_MISMATCH",
		message: "Fixture does not match this migration checkpoint",
		stage,
		remediation: "Use the original fixture for this migration, or create a new import.",
	});
}

function runtimeConflict(kind: "user" | "organization" | "membership", detail: string): never {
	throw new ClearanceError({
		code: `CLEARANCE_IMPORT_RUNTIME_${kind.toUpperCase()}_CONFLICT`,
		message: `Clearance ${kind} conflicts with an existing runtime record`,
		stage: "import.legacy.run",
		status: 409,
		remediation: detail,
	});
}

function rollbackStateConflict(kind: "user" | "organization" | "membership", id: string): never {
	throw new ClearanceError({
		code: `CLEARANCE_IMPORT_ROLLBACK_${kind.toUpperCase()}_CHANGED`,
		message: `Imported ${kind} ${id} no longer matches its rollback checkpoint`,
		stage: "import.legacy.rollback",
		status: 409,
		remediation: "Inspect changes made after import, restore the checkpointed identity and relationship fields, then retry rollback.",
	});
}

function sourceSlug(source: LegacyExportFixture["organizations"][number]): string {
	return source.slug ?? source.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
}

function fixtureMemberRole(member: LegacyExportFixture["members"][number]): string {
	return member.role ?? "member";
}

function nullableString(value: unknown): string | null {
	return value === null || value === undefined ? null : String(value);
}

function isoTimestamp(value: unknown): string {
	return new Date(value as string | Date).toISOString();
}

async function runtimeUser(query: Query, sourceId: string, email: string) {
	const result = await query(
		`select id, email, name from "user" where id = $1 or lower(email) = lower($2)`,
		[sourceId, email],
	);
	if (result.rows.length > 1) runtimeConflict("user", "Resolve the runtime id/email collision before retrying.");
	const row = result.rows[0];
	if (row && String(row.email).toLowerCase() !== email.toLowerCase()) runtimeConflict("user", "The source user id is already assigned to another runtime email.");
	return row ? { id: String(row.id), email: String(row.email).toLowerCase(), name: String(row.name ?? email) } : null;
}

async function runtimeOrganization(query: Query, sourceId: string, slug: string) {
	const result = await query(
		`select id, slug, name from organization where id = $1 or slug = $2`,
		[sourceId, slug],
	);
	if (result.rows.length > 1) runtimeConflict("organization", "Resolve the runtime id/slug collision before retrying.");
	const row = result.rows[0];
	if (row && String(row.slug) !== slug) runtimeConflict("organization", "The source organization id is already assigned to another runtime slug.");
	return row ? { id: String(row.id), slug: String(row.slug), name: String(row.name) } : null;
}

function migrationEvent(data: DataStoreSnapshot, planId: string, action: string, message: string, outcome: "success" | "failure", metadata?: Record<string, unknown>) {
	const scope = resolveOperatorScope(draftStore(data));
	appendAuditEvent(data, {
		actor: "operator",
		action,
		subjectType: "migration",
		subjectId: planId,
		outcome,
		source: "migration",
		projectId: scope.projectId,
		environmentId: scope.environmentId,
		message,
		metadata,
	});
}

export async function runMigrationDurable(
	store: ManagementStore,
	planId: string,
	fixture: LegacyExportFixture,
	opts: { dryRun?: boolean } = {},
): Promise<MigrationPlan> {
	if (store.backend === "json") return runMigration(store, planId, fixture, opts);
	const initial = migrationStatus(store, planId);
	const preview = previewMigration(store, fixture);
	if (initial.fixtureChecksum !== preview.fixtureChecksum) checkpointMismatch("import.legacy.run");
	assertMigrationRunnable(initial, "import.legacy.run");
	if (opts.dryRun) return { ...initial, checkpoint: { phase: "dry_run", ...preview }, updatedAt: nowIso() };

	await ensureAuthMigrated();
	const mutate = requireCoordinated(store, "import.legacy.run");
	return mutate(async ({ data, query }) => {
		const draft = draftStore(data);
		const plan = migrationStatus(draft, planId);
		const txPreview = previewMigration(draft, fixture);
		if (plan.fixtureChecksum !== txPreview.fixtureChecksum) checkpointMismatch("import.legacy.run");
		assertMigrationRunnable(plan, "import.legacy.run");
		const scope = resolveOperatorScope(draft);
		const userMap = new Map<string, string>();
		const organizationMap = new Map<string, string>();
		const createdResourceIds = { users: [] as string[], organizations: [] as string[], memberships: [] as string[] };
		const createdRuntimeResourceIds = { users: [] as string[], organizations: [] as string[], memberships: [] as string[] };
		const rollbackResourceState: NonNullable<MigrationPlan["rollbackResourceState"]> = {
			management: { users: [], organizations: [], memberships: [] },
			runtime: { users: [], organizations: [], memberships: [] },
		};

		for (const source of fixture.users) {
			const existing = data.principals.find((candidate) =>
				candidate.projectId === scope.projectId && candidate.environmentId === scope.environmentId && candidate.status !== "deleted" &&
				(candidate.externalId === source.id || candidate.email.toLowerCase() === source.email));
			const runtime = await runtimeUser(query, source.id, source.email);
			if (existing && runtime && existing.id !== runtime.id) runtimeConflict("user", "Runtime and management identities must share one stable id.");
			const id = existing?.id ?? runtime?.id;
			const principal = existing ?? createUser(draft, { ...(id ? { id } : {}), email: source.email, name: source.name, externalId: source.id, source: "import", actor: "cli", projectId: scope.projectId, environmentId: scope.environmentId });
			if (!existing) {
				createdResourceIds.users.push(principal.id);
				rollbackResourceState.management.users.push({ id: principal.id, projectId: principal.projectId, environmentId: principal.environmentId, email: principal.email, name: principal.name, status: principal.status, ...(principal.externalId ? { externalId: principal.externalId } : {}), updatedAt: principal.updatedAt });
			}
			if (!runtime) {
				const inserted = await query(
					`insert into "user" (id, email, name, "emailVerified", "createdAt", "updatedAt") values ($1, $2, $3, false, now(), now()) returning id, email, name, "emailVerified", image, banned, "banReason", "updatedAt"`,
					[principal.id, source.email, source.name],
				);
				createdRuntimeResourceIds.users.push(principal.id);
				const row = inserted.rows[0]!;
				rollbackResourceState.runtime.users.push({ id: String(row.id), email: String(row.email).toLowerCase(), name: String(row.name), emailVerified: Boolean(row.emailVerified), image: nullableString(row.image), banned: Boolean(row.banned), banReason: nullableString(row.banReason), updatedAt: isoTimestamp(row.updatedAt) });
			}
			userMap.set(source.id, principal.id);
		}

		for (const source of fixture.organizations) {
			const slug = sourceSlug(source);
			const existing = data.organizations.find((candidate) =>
				candidate.projectId === scope.projectId && candidate.environmentId === scope.environmentId && candidate.status !== "archived" &&
				(candidate.externalId === source.id || candidate.slug === slug));
			const runtime = await runtimeOrganization(query, source.id, slug);
			if (existing && runtime && existing.id !== runtime.id) runtimeConflict("organization", "Runtime and management organizations must share one stable id.");
			const id = existing?.id ?? runtime?.id;
			const organization = existing ?? createOrganization(draft, { ...(id ? { id } : {}), name: source.name, slug, externalId: source.id, source: "import", actor: "cli", projectId: scope.projectId, environmentId: scope.environmentId });
			if (!existing) {
				createdResourceIds.organizations.push(organization.id);
				rollbackResourceState.management.organizations.push({ id: organization.id, projectId: organization.projectId, environmentId: organization.environmentId, name: organization.name, slug: organization.slug, status: organization.status, ...(organization.externalId ? { externalId: organization.externalId } : {}), updatedAt: organization.updatedAt });
			}
			if (!runtime) {
				const inserted = await query(
					`insert into organization (id, name, slug, "createdAt") values ($1, $2, $3, now()) returning id, name, slug, logo, metadata`,
					[organization.id, source.name, slug],
				);
				createdRuntimeResourceIds.organizations.push(organization.id);
				const row = inserted.rows[0]!;
				rollbackResourceState.runtime.organizations.push({ id: String(row.id), name: String(row.name), slug: String(row.slug), logo: nullableString(row.logo), metadata: nullableString(row.metadata) });
			}
			organizationMap.set(source.id, organization.id);
		}

		for (const source of fixture.members) {
			const principalId = userMap.get(source.userId)!;
			const organizationId = organizationMap.get(source.organizationId)!;
			const existing = data.memberships.find((candidate) => candidate.status === "active" && candidate.principalId === principalId && candidate.organizationId === organizationId);
			const runtimeResult = await query(`select id, role from member where "organizationId" = $1 and "userId" = $2`, [organizationId, principalId]);
			if (runtimeResult.rows.length > 1) runtimeConflict("membership", "Remove duplicate runtime memberships before retrying.");
			const runtime = runtimeResult.rows[0] ? { id: String(runtimeResult.rows[0].id), role: String(runtimeResult.rows[0].role) } : null;
			if (existing && runtime && existing.id !== runtime.id) runtimeConflict("membership", "Runtime and management memberships must share one stable id.");
			if (existing && runtime && existing.role !== runtime.role) runtimeConflict("membership", "Reconcile the runtime and management membership roles before retrying.");
			if (runtime && runtime.role !== fixtureMemberRole(source)) runtimeConflict("membership", "The existing runtime membership role does not match the fixture.");
			let membership: Membership;
			if (existing) membership = existing;
			else if (runtime) {
				const now = nowIso();
				membership = { id: runtime.id, organizationId, principalId, role: runtime.role, status: "active", source: "import", createdAt: now, updatedAt: now };
				data.memberships.push(membership);
				createdResourceIds.memberships.push(membership.id);
				rollbackResourceState.management.memberships.push({ id: membership.id, organizationId, principalId, role: membership.role, status: membership.status, source: membership.source, updatedAt: membership.updatedAt });
			} else {
				membership = addMember(draft, { organizationId, principalId, role: source.role ?? "member", source: "import", actor: "cli", auditSource: "import" });
				createdResourceIds.memberships.push(membership.id);
				rollbackResourceState.management.memberships.push({ id: membership.id, organizationId, principalId, role: membership.role, status: membership.status, source: membership.source, updatedAt: membership.updatedAt });
			}
			if (!runtime) {
				await query(
					`insert into member (id, "organizationId", "userId", role, "createdAt") values ($1, $2, $3, $4, now())`,
					[membership.id, organizationId, principalId, membership.role],
				);
				createdRuntimeResourceIds.memberships.push(membership.id);
				rollbackResourceState.runtime.memberships.push({ id: membership.id, organizationId, principalId, role: membership.role });
			}
		}

		const updated: MigrationPlan = {
			...plan,
			status: "running",
			createdResourceIds,
			createdRuntimeResourceIds,
			rollbackResourceState,
			checkpoint: { phase: "imported", ...previewMigration(draft, fixture) },
			updatedAt: nowIso(),
			steps: [
				{ name: "validate_fixture", status: "done" },
				{ name: "import_users", status: "done", detail: `${fixture.users.length} users; password reset required where credentials were not exported` },
				{ name: "import_organizations", status: "done", detail: `${fixture.organizations.length} organizations` },
				{ name: "import_memberships", status: "done", detail: `${fixture.members.length} memberships` },
				{ name: "verify_counts", status: "pending" },
			],
		};
		data.migrations[data.migrations.findIndex((candidate) => candidate.id === planId)] = updated;
		migrationEvent(data, planId, "migration.run", "Legacy runtime and management import committed atomically", "success", { source: "legacy", counts: fixture.users.length + fixture.organizations.length + fixture.members.length, credentialTransition: "password_reset_required_if_credentials_absent" });
		return updated;
	});
}

export async function verifyMigrationDurable(store: ManagementStore, planId: string, fixture: LegacyExportFixture) {
	if (store.backend === "json") return verifyMigration(store, planId, fixture);
	await ensureAuthMigrated();
	const mutate = requireCoordinated(store, "import.legacy.verify");
	const result = await mutate(async ({ data, query }) => {
		const draft = draftStore(data);
		const plan = migrationStatus(draft, planId);
		const preview = previewMigration(draft, fixture);
		if (plan.fixtureChecksum !== preview.fixtureChecksum) checkpointMismatch("import.legacy.verify");
		const scope = resolveOperatorScope(draft);
		const expected = { users: fixture.users.length, organizations: fixture.organizations.length, members: fixture.members.length };
		const userMap = new Map(fixture.users.flatMap((source) => {
			const found = data.principals.find((candidate) => candidate.projectId === scope.projectId && candidate.environmentId === scope.environmentId && candidate.status !== "deleted" && (candidate.externalId === source.id || candidate.email.toLowerCase() === source.email));
			return found ? [[source.id, found.id] as const] : [];
		}));
		const organizationMap = new Map(fixture.organizations.flatMap((source) => {
			const slug = sourceSlug(source);
			const found = data.organizations.find((candidate) => candidate.projectId === scope.projectId && candidate.environmentId === scope.environmentId && candidate.status !== "archived" && (candidate.externalId === source.id || candidate.slug === slug));
			return found ? [[source.id, found.id] as const] : [];
		}));
		let users = 0;
		for (const source of fixture.users) {
			const id = userMap.get(source.id);
			if (id && (await query(`select id from "user" where id = $1 and lower(email) = lower($2)`, [id, source.email])).rows[0]) users += 1;
		}
		let organizations = 0;
		for (const source of fixture.organizations) {
			const id = organizationMap.get(source.id);
			if (id && (await query(`select id from organization where id = $1 and slug = $2`, [id, sourceSlug(source)])).rows[0]) organizations += 1;
		}
		let members = 0;
		for (const source of fixture.members) {
			const principalId = userMap.get(source.userId);
			const organizationId = organizationMap.get(source.organizationId);
				const management = data.memberships.find((candidate) => candidate.status === "active" && candidate.principalId === principalId && candidate.organizationId === organizationId && candidate.role === fixtureMemberRole(source));
				if (management && (await query(`select id from member where id = $1 and "organizationId" = $2 and "userId" = $3 and role = $4`, [management.id, organizationId, principalId, fixtureMemberRole(source)])).rows[0]) members += 1;
		}
		const actual = { users, organizations, members };
		const reconciled = users === expected.users && organizations === expected.organizations && members === expected.members;
		const updated: MigrationPlan = { ...plan, status: reconciled ? "verified" : "failed", checkpoint: { phase: reconciled ? "verified" : "failed", ...preview }, updatedAt: nowIso(), steps: plan.steps.map((step) => step.name === "verify_counts" ? { name: "verify_counts", status: reconciled ? "done" : "failed", detail: `expected ${JSON.stringify(expected)} actual ${JSON.stringify(actual)}` } : step) };
		data.migrations[data.migrations.findIndex((candidate) => candidate.id === planId)] = updated;
		migrationEvent(data, planId, "migration.verify", reconciled ? "Clearance runtime and management counts reconciled" : "Clearance runtime and management count mismatch", reconciled ? "success" : "failure", { expected, actual });
		return { plan: updated, reconciled, actual, expected };
	});
	if (!result.reconciled) {
		throw new ClearanceError({ code: "MIGRATION_COUNT_MISMATCH", message: "Runtime and management resource counts do not reconcile", stage: "import.legacy.verify", remediation: "Inspect actual versus expected counts, repair the failed plane, and verify again." });
	}
	return result;
}

export async function rollbackMigrationDurable(store: ManagementStore, planId: string, fixture: LegacyExportFixture): Promise<MigrationPlan> {
	if (store.backend === "json") return rollbackMigration(store, planId, fixture);
	await ensureAuthMigrated();
	const mutate = requireCoordinated(store, "import.legacy.rollback");
	return mutate(async ({ data, query }) => {
		const draft = draftStore(data);
		const plan = migrationStatus(draft, planId);
		const preview = previewMigration(draft, fixture);
		if (plan.fixtureChecksum !== preview.fixtureChecksum) checkpointMismatch("import.legacy.rollback");
		if (!plan.createdResourceIds || !plan.createdRuntimeResourceIds || !plan.rollbackResourceState) {
			throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Migration checkpoint does not identify exact runtime and management resources", stage: "import.legacy.rollback", remediation: "Use a checkpoint created by the coordinated Postgres importer." });
		}
		if (plan.status === "rolled_back") return plan;
		const state = plan.rollbackResourceState;
		if (state.management.users.length !== plan.createdResourceIds.users.length || state.management.organizations.length !== plan.createdResourceIds.organizations.length || state.management.memberships.length !== plan.createdResourceIds.memberships.length || state.runtime.users.length !== plan.createdRuntimeResourceIds.users.length || state.runtime.organizations.length !== plan.createdRuntimeResourceIds.organizations.length || state.runtime.memberships.length !== plan.createdRuntimeResourceIds.memberships.length) {
			throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Migration rollback checkpoint is incomplete", stage: "import.legacy.rollback", remediation: "Inspect the migration checkpoint and restore complete rollback state before retrying." });
		}

		for (const expected of state.management.users) {
			const current = data.principals.find((candidate) => candidate.id === expected.id && candidate.projectId === expected.projectId && candidate.environmentId === expected.environmentId && candidate.email === expected.email && candidate.name === expected.name && candidate.status === expected.status && candidate.externalId === expected.externalId && candidate.updatedAt === expected.updatedAt);
			if (!current) rollbackStateConflict("user", expected.id);
		}
		for (const expected of state.management.organizations) {
			const current = data.organizations.find((candidate) => candidate.id === expected.id && candidate.projectId === expected.projectId && candidate.environmentId === expected.environmentId && candidate.name === expected.name && candidate.slug === expected.slug && candidate.status === expected.status && candidate.externalId === expected.externalId && candidate.updatedAt === expected.updatedAt);
			if (!current) rollbackStateConflict("organization", expected.id);
		}
		for (const expected of state.management.memberships) {
			const current = data.memberships.find((candidate) => candidate.id === expected.id && candidate.status === expected.status && candidate.organizationId === expected.organizationId && candidate.principalId === expected.principalId && candidate.role === expected.role && candidate.source === expected.source && candidate.updatedAt === expected.updatedAt);
			if (!current) rollbackStateConflict("membership", expected.id);
		}

		for (const expected of state.runtime.users) {
			const row = (await query(`select id, email, name, "emailVerified", image, banned, "banReason", "updatedAt" from "user" where id = $1`, [expected.id])).rows[0];
			if (!row || String(row.email).toLowerCase() !== expected.email.toLowerCase() || String(row.name) !== expected.name || Boolean(row.emailVerified) !== expected.emailVerified || nullableString(row.image) !== expected.image || Boolean(row.banned) !== expected.banned || nullableString(row.banReason) !== expected.banReason || isoTimestamp(row.updatedAt) !== expected.updatedAt) {
				rollbackStateConflict("user", expected.id);
			}
		}
		for (const expected of state.runtime.organizations) {
			const row = (await query(`select id, name, slug, logo, metadata from organization where id = $1`, [expected.id])).rows[0];
			if (!row || String(row.name) !== expected.name || String(row.slug) !== expected.slug || nullableString(row.logo) !== expected.logo || nullableString(row.metadata) !== expected.metadata) {
				rollbackStateConflict("organization", expected.id);
			}
		}
		for (const expected of state.runtime.memberships) {
			if (!(await query(`select id from member where id = $1 and "organizationId" = $2 and "userId" = $3 and role = $4`, [expected.id, expected.organizationId, expected.principalId, expected.role])).rows[0]) {
				rollbackStateConflict("membership", expected.id);
			}
		}
		const membershipIds = new Set(plan.createdResourceIds.memberships);
		const userIds = new Set(plan.createdResourceIds.users);
		const organizationIds = new Set(plan.createdResourceIds.organizations);
		const dependentMembership = data.memberships.find((membership) => !membershipIds.has(membership.id) && (userIds.has(membership.principalId) || organizationIds.has(membership.organizationId)));
		if (dependentMembership) rollbackStateConflict("membership", dependentMembership.id);
		const dependentSession = data.sessions.find((session) => userIds.has(session.principalId));
		if (dependentSession) rollbackStateConflict("user", dependentSession.principalId);
		const dependentOrganizationId =
			data.identityConnections.find((connection) => organizationIds.has(connection.organizationId))?.organizationId ??
			data.directoryConnections.find((connection) => organizationIds.has(connection.organizationId))?.organizationId ??
			data.roles.find((role) => role.organizationId && organizationIds.has(role.organizationId))?.organizationId ??
			data.setupLinks.find((link) => organizationIds.has(link.organizationId))?.organizationId;
		if (dependentOrganizationId) rollbackStateConflict("organization", dependentOrganizationId);

		const runtimeMembershipIds = new Set(plan.createdRuntimeResourceIds.memberships);
		for (const expected of state.runtime.users) {
			const relatedMembers = await query(`select id from member where "userId" = $1`, [expected.id]);
			if (relatedMembers.rows.some((row) => !runtimeMembershipIds.has(String(row.id)))) rollbackStateConflict("user", expected.id);
			if ((await query(`select id from session where "userId" = $1 limit 1`, [expected.id])).rows[0]) rollbackStateConflict("user", expected.id);
			if ((await query(`select id from account where "userId" = $1 limit 1`, [expected.id])).rows[0]) rollbackStateConflict("user", expected.id);
		}
		for (const expected of state.runtime.organizations) {
			const relatedMembers = await query(`select id from member where "organizationId" = $1`, [expected.id]);
			if (relatedMembers.rows.some((row) => !runtimeMembershipIds.has(String(row.id)))) rollbackStateConflict("organization", expected.id);
		}
		for (const id of plan.createdRuntimeResourceIds.memberships) await query(`delete from member where id = $1`, [id]);
		for (const id of plan.createdRuntimeResourceIds.organizations) await query(`delete from organization where id = $1`, [id]);
		for (const id of plan.createdRuntimeResourceIds.users) await query(`delete from "user" where id = $1`, [id]);
		data.memberships = data.memberships.filter((membership) => !membershipIds.has(membership.id));
		data.principals = data.principals.filter((principal) => !userIds.has(principal.id));
		data.organizations = data.organizations.filter((organization) => !organizationIds.has(organization.id));
		const updated: MigrationPlan = { ...plan, status: "rolled_back", checkpoint: { ...plan.checkpoint, phase: "rolled_back" }, updatedAt: nowIso(), steps: [...plan.steps, { name: "rollback", status: "done", detail: "Exact imported runtime and management resources removed atomically" }] };
		data.migrations[data.migrations.findIndex((candidate) => candidate.id === planId)] = updated;
		migrationEvent(data, planId, "migration.rollback", "Legacy runtime and management import rolled back atomically", "success");
		return updated;
	});
}
