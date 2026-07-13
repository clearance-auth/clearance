import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { MigrationPlan } from "../types/resources.js";
import { recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { BUILT_IN_ROLE_SLUGS } from "./roles.js";
import { resolveOperatorScope } from "./scope.js";
import { addMember, createOrganization, createUser, listOrganizations, listUsers } from "./core.js";

/** Deliberately small, portable Clearance export contract accepted by Clearance. */
export interface LegacyExportFixture {
	source: "legacy";
	users: Array<{ id: string; email: string; name: string }>;
	organizations: Array<{ id: string; name: string; slug?: string }>;
	members: Array<{ userId: string; organizationId: string; role?: string }>;
}

export type MigrationPreview = {
	source: "legacy";
	fixtureChecksum: string;
	counts: { users: number; organizations: number; members: number };
	wouldCreate: { users: number; organizations: number; members: number };
	idempotent: { users: number; organizations: number; members: number };
};

type RollbackResourceState = NonNullable<MigrationPlan["rollbackResourceState"]>;

function fixtureMemberRole(member: LegacyExportFixture["members"][number]): string {
	return member.role ?? "member";
}

const fixtureKeys = new Set(["source", "users", "organizations", "members"]);
const MAX_FIXTURE_BYTES = 25 * 1024 * 1024;
const MAX_RESOURCES_PER_TYPE = 10_000;

function fixtureError(code: string, message: string, remediation: string): never {
	throw new ClearanceError({ code, message, stage: "import.legacy.fixture", remediation });
}

function rollbackStateConflict(kind: "user" | "organization" | "membership", id: string): never {
	throw new ClearanceError({
		code: `CLEARANCE_IMPORT_ROLLBACK_${kind.toUpperCase()}_CHANGED`,
		message: `Imported ${kind} ${id} no longer matches its rollback checkpoint`,
		stage: "import.legacy.rollback",
		status: 409,
		remediation: "Inspect changes made after import, restore the checkpointed resource, then retry rollback.",
	});
}

function object(value: unknown, label: string): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		fixtureError("CLEARANCE_IMPORT_FIXTURE_INVALID", `${label} must be an object`, "Provide a JSON object matching the legacy export fixture schema.");
	}
	return value as Record<string, unknown>;
}

function string(value: unknown, label: string, maxLength = 256): string {
	if (typeof value !== "string" || !value.trim() || value.trim().length > maxLength) {
		fixtureError("CLEARANCE_IMPORT_FIELD_INVALID", `${label} must be a non-empty string of at most ${maxLength} characters`, "Correct the fixture field and retry.");
	}
	return value.trim();
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
	if (Object.keys(value).some((key) => !allowed.includes(key))) {
		fixtureError("CLEARANCE_IMPORT_FIELD_INVALID", `${label} contains unsupported fields`, `Use only ${allowed.join(", ")} fields in ${label}.`);
	}
}

function array(value: unknown, label: string): unknown[] {
	if (!Array.isArray(value)) {
		fixtureError("CLEARANCE_IMPORT_FIELD_INVALID", `${label} must be an array`, "Provide users, organizations, and members arrays.");
	}
	return value;
}

function fixtureChecksum(fixture: LegacyExportFixture): string {
	return createHash("sha256").update(JSON.stringify(fixture)).digest("hex");
}

function organizationSlug(name: string): string {
	return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
}

/** Reads and fully validates the one Legacy fixture shape supported by this lane. */
export function loadLegacyFixture(path: string): LegacyExportFixture {
	let parsed: unknown;
	let file: number | undefined;
	try {
		file = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
		const stat = fstatSync(file);
		if (!stat.isFile()) {
			fixtureError(
				"CLEARANCE_IMPORT_FILE_UNREADABLE",
				"Legacy fixture must be a regular file",
				"Provide a local, non-symlinked JSON export file.",
			);
		}
		if (stat.size > MAX_FIXTURE_BYTES) {
			fixtureError(
				"CLEARANCE_IMPORT_FILE_TOO_LARGE",
				"Legacy fixture exceeds the 25 MiB limit",
				"Split the export into smaller tenant-scoped fixtures.",
			);
		}
		parsed = JSON.parse(readFileSync(file, "utf8"));
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		const code = error instanceof SyntaxError ? "CLEARANCE_IMPORT_JSON_INVALID" : "CLEARANCE_IMPORT_FILE_UNREADABLE";
		fixtureError(code, code === "CLEARANCE_IMPORT_JSON_INVALID" ? "Legacy fixture is not valid JSON" : "Legacy fixture could not be read", "Provide a readable JSON export fixture.");
	} finally {
		if (file !== undefined) closeSync(file);
	}
	const raw = object(parsed, "fixture");
	onlyKeys(raw, [...fixtureKeys], "fixture");
	if (raw.source !== "legacy") {
		fixtureError("CLEARANCE_IMPORT_SOURCE_INVALID", 'Fixture source must be "legacy"', "Export from the legacy source and set source to \"legacy\".");
	}

	const userIds = new Set<string>();
	const emails = new Set<string>();
	const rawUsers = array(raw.users, "users");
	const rawOrganizations = array(raw.organizations, "organizations");
	const rawMembers = array(raw.members, "members");
	if ([rawUsers, rawOrganizations, rawMembers].some((values) => values.length > MAX_RESOURCES_PER_TYPE)) {
		fixtureError(
			"CLEARANCE_IMPORT_RESOURCE_LIMIT",
			"Legacy fixture exceeds the 10,000-resource per-type limit",
			"Split the export into smaller tenant-scoped fixtures.",
		);
	}

	const users = rawUsers.map((entry, index) => {
		const user = object(entry, `users[${index}]`);
		onlyKeys(user, ["id", "email", "name"], `users[${index}]`);
		const id = string(user.id, `users[${index}].id`, 128);
		const email = string(user.email, `users[${index}].email`, 254).toLowerCase();
		const name = string(user.name, `users[${index}].name`);
		if (!email.includes("@")) fixtureError("CLEARANCE_IMPORT_FIELD_INVALID", `users[${index}].email must be an email address`, "Provide a valid email address.");
		if (userIds.has(id) || emails.has(email)) fixtureError("CLEARANCE_IMPORT_DUPLICATE_IDENTITY", "User ids and emails must be unique", "Remove duplicate users from the fixture.");
		userIds.add(id); emails.add(email);
		return { id, email, name };
	});

	const organizationIds = new Set<string>();
	const slugs = new Set<string>();
	const organizations = rawOrganizations.map((entry, index) => {
		const organization = object(entry, `organizations[${index}]`);
		onlyKeys(organization, ["id", "name", "slug"], `organizations[${index}]`);
		const id = string(organization.id, `organizations[${index}].id`, 128);
		const name = string(organization.name, `organizations[${index}].name`);
		const slug = organization.slug === undefined ? organizationSlug(name) : string(organization.slug, `organizations[${index}].slug`, 48).toLowerCase();
		if (!slug || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) fixtureError("CLEARANCE_IMPORT_FIELD_INVALID", `organizations[${index}].slug is invalid`, "Use a lowercase slug with letters, numbers, and hyphens.");
		if (organizationIds.has(id) || slugs.has(slug)) fixtureError("CLEARANCE_IMPORT_DUPLICATE_ORGANIZATION", "Organization ids and slugs must be unique", "Remove duplicate organizations from the fixture.");
		organizationIds.add(id); slugs.add(slug);
		return { id, name, slug };
	});

	const memberships = new Set<string>();
	const members = rawMembers.map((entry, index) => {
		const member = object(entry, `members[${index}]`);
		onlyKeys(member, ["userId", "organizationId", "role"], `members[${index}]`);
		const userId = string(member.userId, `members[${index}].userId`, 128);
		const organizationId = string(member.organizationId, `members[${index}].organizationId`, 128);
		const role = member.role === undefined ? undefined : string(member.role, `members[${index}].role`, 48).toLowerCase();
		if (!userIds.has(userId) || !organizationIds.has(organizationId)) fixtureError("CLEARANCE_IMPORT_REFERENCE_INVALID", "Membership references a user or organization outside this fixture", "Include the referenced user and organization in the fixture.");
		if (role && !(BUILT_IN_ROLE_SLUGS as readonly string[]).includes(role)) fixtureError("CLEARANCE_IMPORT_ROLE_INVALID", "Only Clearance owner, admin, and member roles are supported", "Use owner, admin, or member roles in this import.");
		const key = `${organizationId}\u0000${userId}`;
		if (memberships.has(key)) fixtureError("CLEARANCE_IMPORT_DUPLICATE_MEMBERSHIP", "Each user may appear once per organization", "Remove duplicate memberships from the fixture.");
		memberships.add(key);
		return { userId, organizationId, ...(role ? { role } : {}) };
	});

	return { source: "legacy", users, organizations, members };
}

function compatibleFixture(store: ManagementStore, fixture: LegacyExportFixture): MigrationPreview {
	const scope = resolveOperatorScope(store);
	const users = store.snapshot.principals.filter((principal) => principal.projectId === scope.projectId && principal.environmentId === scope.environmentId && principal.status !== "deleted");
	const organizations = store.snapshot.organizations.filter((organization) => organization.projectId === scope.projectId && organization.environmentId === scope.environmentId && organization.status !== "archived");
	const userMap = new Map<string, string>();
	const organizationMap = new Map<string, string>();

	for (const user of fixture.users) {
		const byExternalId = users.find((candidate) => candidate.externalId === user.id);
		const byEmail = users.find((candidate) => candidate.email.toLowerCase() === user.email);
		if (byExternalId && byEmail && byExternalId.id !== byEmail.id) fixtureError("CLEARANCE_IMPORT_USER_CONFLICT", `User ${user.email} maps to different existing identities`, "Resolve the conflicting external id or email before retrying.");
		if (byExternalId && byExternalId.email.toLowerCase() !== user.email) fixtureError("CLEARANCE_IMPORT_USER_CONFLICT", `User id ${user.id} has a different email in Clearance`, "Resolve the conflicting identity before retrying.");
		if (byEmail && byEmail.externalId && byEmail.externalId !== user.id) fixtureError("CLEARANCE_IMPORT_USER_CONFLICT", `User ${user.email} belongs to a different import source`, "Resolve the conflicting external id before retrying.");
		const existing = byExternalId ?? byEmail;
		if (existing) userMap.set(user.id, existing.id);
	}
	for (const organization of fixture.organizations) {
		const byExternalId = organizations.find((candidate) => candidate.externalId === organization.id);
		const bySlug = organizations.find((candidate) => candidate.slug === organization.slug);
		if (byExternalId && bySlug && byExternalId.id !== bySlug.id) fixtureError("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization ${organization.id} maps to different existing organizations`, "Resolve the conflicting organization id or slug before retrying.");
		if (byExternalId && byExternalId.slug !== organization.slug) fixtureError("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization id ${organization.id} has a different slug in Clearance`, "Resolve the conflicting organization before retrying.");
		if (bySlug && bySlug.externalId && bySlug.externalId !== organization.id) fixtureError("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization slug ${organization.slug} belongs to a different import source`, "Resolve the conflicting external id before retrying.");
		const existing = byExternalId ?? bySlug;
		if (existing) organizationMap.set(organization.id, existing.id);
	}
	let existingMembers = 0;
	for (const member of fixture.members) {
		const principalId = userMap.get(member.userId);
		const organizationId = organizationMap.get(member.organizationId);
		const existing = principalId && organizationId
			? store.snapshot.memberships.find((candidate) => candidate.status === "active" && candidate.principalId === principalId && candidate.organizationId === organizationId)
			: undefined;
		if (existing && existing.role !== fixtureMemberRole(member)) {
			fixtureError("CLEARANCE_IMPORT_MEMBERSHIP_ROLE_CONFLICT", `Membership for user ${member.userId} in organization ${member.organizationId} has role ${existing.role}, not ${fixtureMemberRole(member)}`, "Align the existing membership role with the fixture, or import into a new environment.");
		}
		if (existing) existingMembers += 1;
	}
	return {
		source: "legacy", fixtureChecksum: fixtureChecksum(fixture),
		counts: { users: fixture.users.length, organizations: fixture.organizations.length, members: fixture.members.length },
		wouldCreate: { users: fixture.users.length - userMap.size, organizations: fixture.organizations.length - organizationMap.size, members: fixture.members.length - existingMembers },
		idempotent: { users: userMap.size, organizations: organizationMap.size, members: existingMembers },
	};
}

/** Validate conflicts and calculate a non-mutating Clearance import preview. */
export function previewMigration(store: ManagementStore, fixture: LegacyExportFixture): MigrationPreview {
	return compatibleFixture(store, fixture);
}

export function planMigration(store: ManagementStore, fixture: LegacyExportFixture): MigrationPlan {
	const preview = compatibleFixture(store, fixture);
	const scope = resolveOperatorScope(store);
	const plan: MigrationPlan = {
		id: newId("mig"), source: "legacy", projectId: scope.projectId, environmentId: scope.environmentId, status: "planned", counts: preview.counts,
		fixtureChecksum: preview.fixtureChecksum,
		checkpoint: { phase: "planned", ...preview },
		steps: [{ name: "validate_fixture", status: "done", detail: "Legacy fixture schema and references validated" }, { name: "import_users", status: "pending" }, { name: "import_organizations", status: "pending" }, { name: "import_memberships", status: "pending" }, { name: "verify_counts", status: "pending" }],
		createdAt: nowIso(), updatedAt: nowIso(),
	};
	store.mutate((data) => { data.migrations.unshift(plan); });
	recordEvent(store, { actor: "operator", action: "migration.plan", subjectType: "migration", subjectId: plan.id, outcome: "success", source: "migration", message: `Planned Clearance import of ${plan.counts.users} users`, metadata: { source: plan.source, fixtureChecksum: plan.fixtureChecksum, counts: plan.counts } });
	return plan;
}

export function assertMigrationRunnable(plan: MigrationPlan, stage: string): void {
	if (plan.status !== "planned") {
		throw new ClearanceError({
			code: "CLEARANCE_IMPORT_PLAN_STATE_INVALID",
			message: `Migration ${plan.id} is already ${plan.status} and cannot be run again`,
			stage,
			status: 409,
			remediation: "Create a new migration plan. The original rollback ledger is immutable after import starts.",
		});
	}
}

function checkpointManagementState(
	plan: MigrationPlan,
	store: ManagementStore,
): RollbackResourceState {
	const created = plan.createdResourceIds!;
	const userIds = new Set(created.users);
	const organizationIds = new Set(created.organizations);
	const membershipIds = new Set(created.memberships);
	return {
		management: {
			users: store.snapshot.principals.filter((principal) => userIds.has(principal.id)).map((principal) => ({ id: principal.id, projectId: principal.projectId, environmentId: principal.environmentId, email: principal.email, name: principal.name, status: principal.status, ...(principal.externalId ? { externalId: principal.externalId } : {}), updatedAt: principal.updatedAt })),
			organizations: store.snapshot.organizations.filter((organization) => organizationIds.has(organization.id)).map((organization) => ({ id: organization.id, projectId: organization.projectId, environmentId: organization.environmentId, name: organization.name, slug: organization.slug, status: organization.status, ...(organization.externalId ? { externalId: organization.externalId } : {}), updatedAt: organization.updatedAt })),
			memberships: store.snapshot.memberships.filter((membership) => membershipIds.has(membership.id)).map((membership) => ({ id: membership.id, organizationId: membership.organizationId, principalId: membership.principalId, role: membership.role, status: membership.status, source: membership.source, updatedAt: membership.updatedAt })),
		},
		runtime: { users: [], organizations: [], memberships: [] },
	};
}

export function runMigration(store: ManagementStore, planId: string, fixture: LegacyExportFixture, opts: { dryRun?: boolean } = {}): MigrationPlan {
	const plan = migrationStatus(store, planId);
	if (plan.source !== "legacy" || plan.fixtureChecksum !== fixtureChecksum(fixture)) throw new ClearanceError({ code: "CLEARANCE_IMPORT_CHECKPOINT_MISMATCH", message: "Fixture does not match this migration checkpoint", stage: "import.legacy.run", remediation: "Use the original fixture for this migration, or create a new import." });
	assertMigrationRunnable(plan, "import.legacy.run");
	const preview = compatibleFixture(store, fixture);
	if (opts.dryRun) return { ...plan, checkpoint: { phase: "dry_run", ...preview }, updatedAt: nowIso() };
	if (store.backend !== "json") {
		throw new ClearanceError({
			code: "CLEARANCE_IMPORT_POSTGRES_UNSUPPORTED",
			message: "Clearance import cannot safely write the Postgres runtime yet",
			stage: "import.legacy.run",
			remediation: "Use the JSON local profile for this importer release; Postgres import must update runtime and management records atomically.",
		});
	}

	const userMap = new Map<string, string>();
	const organizationMap = new Map<string, string>();
	const createdResourceIds = {
		users: [] as string[],
		organizations: [] as string[],
		memberships: [] as string[],
	};
	const scope = resolveOperatorScope(store);
	for (const user of fixture.users) {
		const existing = store.snapshot.principals.find((candidate) => candidate.projectId === scope.projectId && candidate.environmentId === scope.environmentId && (candidate.externalId === user.id || candidate.email.toLowerCase() === user.email));
		const principal = existing ?? createUser(store, { email: user.email, name: user.name, externalId: user.id, source: "import", actor: "cli" });
		if (!existing) createdResourceIds.users.push(principal.id);
		userMap.set(user.id, principal.id);
	}
	for (const organization of fixture.organizations) {
		const existing = store.snapshot.organizations.find((candidate) => candidate.projectId === scope.projectId && candidate.environmentId === scope.environmentId && (candidate.externalId === organization.id || candidate.slug === organization.slug));
		const org = existing ?? createOrganization(store, { name: organization.name, slug: organization.slug, externalId: organization.id, source: "import", actor: "cli" });
		if (!existing) createdResourceIds.organizations.push(org.id);
		organizationMap.set(organization.id, org.id);
	}
	for (const member of fixture.members) {
		const organizationId = organizationMap.get(member.organizationId)!;
		const principalId = userMap.get(member.userId)!;
		const existing = store.snapshot.memberships.find((candidate) => candidate.status === "active" && candidate.organizationId === organizationId && candidate.principalId === principalId);
		const membership = addMember(store, { organizationId, principalId, role: member.role ?? "member", source: "import", actor: "cli", auditSource: "import" });
		if (!existing) createdResourceIds.memberships.push(membership.id);
	}

	const imported: MigrationPlan = { ...plan, status: "running", createdResourceIds, checkpoint: { phase: "imported", ...previewMigration(store, fixture) }, updatedAt: nowIso(), steps: [{ name: "validate_fixture", status: "done" }, { name: "import_users", status: "done", detail: `${fixture.users.length} users` }, { name: "import_organizations", status: "done", detail: `${fixture.organizations.length} organizations` }, { name: "import_memberships", status: "done", detail: `${fixture.members.length} memberships` }, { name: "verify_counts", status: "pending" }] };
	const updated: MigrationPlan = { ...imported, rollbackResourceState: checkpointManagementState(imported, store) };
	store.mutate((data) => { data.migrations[data.migrations.findIndex((migration) => migration.id === planId)] = updated; });
	recordEvent(store, { actor: "operator", action: "migration.run", subjectType: "migration", subjectId: planId, outcome: "success", source: "migration", message: "Clearance import completed — ready for verification", metadata: preview });
	return updated;
}

export function verifyMigration(store: ManagementStore, planId: string, fixture: LegacyExportFixture): { plan: MigrationPlan; reconciled: boolean; actual: Record<string, number>; expected: Record<string, number> } {
	const plan = migrationStatus(store, planId);
	if (plan.fixtureChecksum !== fixtureChecksum(fixture)) throw new ClearanceError({ code: "CLEARANCE_IMPORT_CHECKPOINT_MISMATCH", message: "Fixture does not match this migration checkpoint", stage: "import.legacy.verify", remediation: "Use the original fixture for this migration." });
	const scope = resolveOperatorScope(store);
	const expected = { users: fixture.users.length, organizations: fixture.organizations.length, members: fixture.members.length };
	const users = listUsers(store, { scope: { projectId: scope.projectId, environmentId: scope.environmentId } });
	const organizations = listOrganizations(store, { scope: { projectId: scope.projectId, environmentId: scope.environmentId } });
	const userBySourceId = new Map(fixture.users.flatMap((source) => {
		const user = users.find((candidate) => candidate.externalId === source.id || candidate.email.toLowerCase() === source.email);
		return user ? [[source.id, user.id] as const] : [];
	}));
	const organizationBySourceId = new Map(fixture.organizations.flatMap((source) => {
		const slug = source.slug ?? organizationSlug(source.name);
		const organization = organizations.find((candidate) => candidate.externalId === source.id || candidate.slug === slug);
		return organization ? [[source.id, organization.id] as const] : [];
	}));
	const actual = { users: userBySourceId.size, organizations: organizationBySourceId.size, members: fixture.members.filter((member) => store.snapshot.memberships.some((candidate) => candidate.status === "active" && candidate.principalId === userBySourceId.get(member.userId) && candidate.organizationId === organizationBySourceId.get(member.organizationId) && candidate.role === fixtureMemberRole(member))).length };
	const reconciled = actual.users === expected.users && actual.organizations === expected.organizations && actual.members === expected.members;
	const updated: MigrationPlan = { ...plan, status: reconciled ? "verified" : "failed", checkpoint: { phase: reconciled ? "verified" : "failed", ...previewMigration(store, fixture) }, updatedAt: nowIso(), steps: plan.steps.map((step) => step.name === "verify_counts" ? { name: "verify_counts", status: reconciled ? "done" : "failed", detail: `expected ${JSON.stringify(expected)} actual ${JSON.stringify(actual)}` } : step) };
	store.mutate((data) => { data.migrations[data.migrations.findIndex((migration) => migration.id === planId)] = updated; });
	recordEvent(store, { actor: "operator", action: "migration.verify", subjectType: "migration", subjectId: planId, outcome: reconciled ? "success" : "failure", source: "migration", message: reconciled ? "Legacy import counts reconciled" : "Legacy import count mismatch", metadata: { source: "legacy", expected, actual } });
	if (!reconciled) throw new ClearanceError({ code: "MIGRATION_COUNT_MISMATCH", message: "Resource counts do not reconcile", stage: "import.legacy.verify", remediation: "Inspect actual versus expected counts; fix the fixture or run a new import." });
	return { plan: updated, reconciled, actual, expected };
}

export function rollbackMigration(store: ManagementStore, planId: string, fixture: LegacyExportFixture): MigrationPlan {
	const plan = migrationStatus(store, planId);
	if (plan.fixtureChecksum !== fixtureChecksum(fixture)) throw new ClearanceError({ code: "CLEARANCE_IMPORT_CHECKPOINT_MISMATCH", message: "Fixture does not match this migration checkpoint", stage: "import.legacy.rollback", remediation: "Use the original fixture for this migration." });
	if (plan.status === "rolled_back") return plan;
	if (!plan.createdResourceIds || !plan.rollbackResourceState) {
		throw new ClearanceError({
			code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE",
			message: "Migration checkpoint does not identify resources created by this import",
			stage: "import.legacy.rollback",
			remediation: "Do not delete resources by external id; use a checkpoint created by the current importer.",
		});
	}
	const userIds = new Set(plan.createdResourceIds.users);
	const organizationIds = new Set(plan.createdResourceIds.organizations);
	const membershipIds = new Set(plan.createdResourceIds.memberships);
	const state = plan.rollbackResourceState;
	if (state.management.users.length !== userIds.size || state.management.organizations.length !== organizationIds.size || state.management.memberships.length !== membershipIds.size) {
		throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Migration rollback checkpoint is incomplete", stage: "import.legacy.rollback", remediation: "Inspect the migration checkpoint and restore complete rollback state before retrying." });
	}
	for (const expected of state.management.users) {
		const current = store.snapshot.principals.find((principal) => principal.id === expected.id);
		if (!current || current.projectId !== expected.projectId || current.environmentId !== expected.environmentId || current.email !== expected.email || current.name !== expected.name || current.status !== expected.status || current.externalId !== expected.externalId || current.updatedAt !== expected.updatedAt) rollbackStateConflict("user", expected.id);
	}
	for (const expected of state.management.organizations) {
		const current = store.snapshot.organizations.find((organization) => organization.id === expected.id);
		if (!current || current.projectId !== expected.projectId || current.environmentId !== expected.environmentId || current.name !== expected.name || current.slug !== expected.slug || current.status !== expected.status || current.externalId !== expected.externalId || current.updatedAt !== expected.updatedAt) rollbackStateConflict("organization", expected.id);
	}
	for (const expected of state.management.memberships) {
		const current = store.snapshot.memberships.find((membership) => membership.id === expected.id);
		if (!current || current.organizationId !== expected.organizationId || current.principalId !== expected.principalId || current.role !== expected.role || current.status !== expected.status || current.source !== expected.source || current.updatedAt !== expected.updatedAt) rollbackStateConflict("membership", expected.id);
	}
	store.mutate((data) => {
		const dependentMembership = data.memberships.find((membership) => !membershipIds.has(membership.id) && (userIds.has(membership.principalId) || organizationIds.has(membership.organizationId)));
		if (dependentMembership) rollbackStateConflict("membership", dependentMembership.id);
		const dependentSession = data.sessions.find((session) => userIds.has(session.principalId));
		if (dependentSession) rollbackStateConflict("user", dependentSession.principalId);
		const dependentOrganizationId = data.identityConnections.find((connection) => organizationIds.has(connection.organizationId))?.organizationId ?? data.directoryConnections.find((connection) => organizationIds.has(connection.organizationId))?.organizationId ?? data.roles.find((role) => role.organizationId && organizationIds.has(role.organizationId))?.organizationId ?? data.setupLinks.find((link) => organizationIds.has(link.organizationId))?.organizationId;
		if (dependentOrganizationId) rollbackStateConflict("organization", dependentOrganizationId);
		data.memberships = data.memberships.filter((membership) => !membershipIds.has(membership.id));
		data.principals = data.principals.filter((principal) => !userIds.has(principal.id));
		data.organizations = data.organizations.filter((organization) => !organizationIds.has(organization.id));
	});
	const updated: MigrationPlan = { ...plan, status: "rolled_back", checkpoint: { ...plan.checkpoint, phase: "rolled_back" }, updatedAt: nowIso(), steps: [...plan.steps, { name: "rollback", status: "done", detail: "Imported Clearance resources removed" }] };
	store.mutate((data) => { data.migrations[data.migrations.findIndex((migration) => migration.id === planId)] = updated; });
	recordEvent(store, { actor: "operator", action: "migration.rollback", subjectType: "migration", subjectId: planId, outcome: "success", source: "migration", message: "Clearance import rolled back" });
	return updated;
}

export function migrationStatus(store: ManagementStore, planId: string): MigrationPlan {
	const plan = store.snapshot.migrations.find((migration) => migration.id === planId);
	if (!plan) throw new ClearanceError({ code: "MIGRATION_NOT_FOUND", message: `Migration ${planId} not found`, stage: "migration.status", status: 404 });
	const scope = resolveOperatorScope(store);
	if (plan.projectId !== scope.projectId || plan.environmentId !== scope.environmentId) {
		throw new ClearanceError({ code: "MIGRATION_NOT_FOUND", message: `Migration ${planId} not found`, stage: "migration.status", status: 404 });
	}
	return plan;
}
