import { createHash } from "node:crypto";
import { ensureAuthMigrated } from "../auth-bridge.js";
import type {
	InternalManagementCoordinatedMutationContext,
	ManagementStore,
	StoreV2TopologyRepository,
	StoreV2TopologyReader,
} from "../store/types.js";
import { mutateCoordinatedWithRuntimeSql } from "../store/coordinated-internal.js";
import { hardDeleteImportedPrincipalForRollback } from "../store/store-v2-principals.js";
import { hardDeleteImportedOrganizationForRollback } from "../store/store-v2-topology.js";
import { newId, nowIso } from "../store/json-store.js";
import type { DataStoreSnapshot, Membership, MigrationPlan, Organization, Principal } from "../types/resources.js";
import { recordEvent } from "./audit.js";
import { addMember, createOrganization, createUser } from "./core.js";
import { ClearanceError } from "./errors.js";
import {
	type LegacyExportFixture,
	type MigrationPreview,
	assertMigrationRunnable,
	migrationStatus,
	planMigration,
	previewMigration,
	rollbackMigration,
	runMigration,
	verifyMigration,
} from "./migration.js";
import { resolveOperatorScopeAuthoritative } from "./scope.js";

type Query = (
	sql: string,
	params?: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;

const ROLLBACK_FENCE_TABLE = `"public"."clearance_import_rollback_tombstones"`;
const ROLLBACK_FENCE_FUNCTION = `"public"."clearance_import_rollback_guard_v1"`;
const ROLLBACK_FENCE_NAMESPACE = "clearance-import-rollback:v1";

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
	return <T>(
		fn: (
			context: InternalManagementCoordinatedMutationContext,
		) => Promise<T> | T,
	) => mutateCoordinatedWithRuntimeSql(store, fn);
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

function migrationFixtureChecksum(fixture: LegacyExportFixture): string {
	return createHash("sha256").update(JSON.stringify(fixture)).digest("hex");
}

function migrationFixtureConflict(
	code: string,
	message: string,
	remediation: string,
): never {
	throw new ClearanceError({
		code,
		message,
		stage: "import.legacy.preview",
		status: 409,
		remediation,
	});
}

async function migrationScope(
	data: DataStoreSnapshot,
	topology?: StoreV2TopologyReader,
) {
	return resolveOperatorScopeAuthoritative({
		snapshot: data,
		...(topology ? { storeV2Topology: topology } : {}),
	});
}

async function migrationOrganization(
	topology: StoreV2TopologyReader,
	scope: { projectId: string; environmentId: string },
	source: LegacyExportFixture["organizations"][number],
): Promise<Organization | undefined> {
	const slug = sourceSlug(source);
	const [byExternalId, bySlug] = await Promise.all([
		topology.getOrganizationByExternalId({ scope, externalId: source.id }),
		topology.getOrganizationBySlug({ scope, slug }),
	]);
	return reconcileMigrationOrganization(source, byExternalId, bySlug);
}

async function lockTopologyScope(
	topology: StoreV2TopologyRepository,
	scope: { projectId: string; environmentId: string },
): Promise<boolean> {
	if (!await topology.lockProject({ id: scope.projectId })) return false;
	return Boolean(await topology.lockEnvironment({
		projectId: scope.projectId,
		id: scope.environmentId,
	}));
}

async function lockTopologyOrganization(
	topology: StoreV2TopologyRepository,
	scope: { projectId: string; environmentId: string },
	id: string,
): Promise<Organization | null> {
	if (!await lockTopologyScope(topology, scope)) return null;
	return topology.lockOrganization({ scope, id });
}

function lockedMigrationOrganization(
	source: LegacyExportFixture["organizations"][number],
	organization: Organization | null,
): Organization {
	if (!organization) {
		migrationFixtureConflict("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization ${source.id} changed while import was acquiring its transaction lock`, "Retry after concurrent organization changes finish.");
	}
	const reconciled = reconcileMigrationOrganization(
		source,
		organization.externalId === source.id ? organization : undefined,
		organization.slug === sourceSlug(source) ? organization : undefined,
	);
	if (!reconciled) {
		migrationFixtureConflict("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization ${source.id} no longer matches its import identity after transaction locking`, "Retry after concurrent organization changes finish.");
	}
	return reconciled;
}

function lockedScopeUnavailable(stage: string): never {
	throw new ClearanceError({
		code: "SCOPE_INVALID",
		message: "Operator scope no longer matches normalized project/environment topology",
		stage,
		status: 409,
		remediation: "Restore the configured project and environment scope, then retry.",
	});
}

function assertExactCheckpointIds(
	label: string,
	ids: readonly string[],
	resources: readonly { id: string }[],
): void {
	const idSet = new Set(ids);
	const resourceIds = resources.map((resource) => resource.id);
	const resourceSet = new Set(resourceIds);
	if (
		idSet.size !== ids.length ||
		resourceSet.size !== resourceIds.length ||
		idSet.size !== resourceSet.size ||
		[...idSet].some((id) => !resourceSet.has(id))
	) {
		throw new ClearanceError({
			code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE",
			message: `Migration rollback checkpoint ${label} ids are not an exact unique resource set`,
			stage: "import.legacy.rollback",
			remediation: "Use the original unmodified coordinated migration checkpoint before retrying rollback.",
		});
	}
}

async function lockRuntimeRollbackParents(
	query: Query,
	state: NonNullable<MigrationPlan["rollbackResourceState"]>,
): Promise<void> {
	for (const expected of [...state.runtime.organizations].sort((left, right) => left.id.localeCompare(right.id))) {
		if (!(await query(`select id from organization where id = $1 for update`, [expected.id])).rows[0]) {
			rollbackStateConflict("organization", expected.id);
		}
	}
	for (const expected of [...state.runtime.users].sort((left, right) => left.id.localeCompare(right.id))) {
		if (!(await query(`select id from "user" where id = $1 for update`, [expected.id])).rows[0]) {
			rollbackStateConflict("user", expected.id);
		}
	}
	for (const expected of [...state.runtime.memberships].sort((left, right) => left.id.localeCompare(right.id))) {
		if (!(await query(`select id from member where id = $1 for update`, [expected.id])).rows[0]) {
			rollbackStateConflict("membership", expected.id);
		}
	}
}

type RollbackFenceKind = "organization" | "principal";

function rollbackFenceEntries(
	state: NonNullable<MigrationPlan["rollbackResourceState"]>,
): Array<{ kind: RollbackFenceKind; id: string }> {
	const entries = [
		...state.runtime.organizations.map(({ id }) => ({ kind: "organization" as const, id })),
		...state.runtime.users.map(({ id }) => ({ kind: "principal" as const, id })),
	];
	return [...new Map(entries.map((entry) => [`${entry.kind}\u0000${entry.id}`, entry])).values()]
		.sort((left, right) => left.kind.localeCompare(right.kind) || left.id.localeCompare(right.id));
}

async function installRollbackFenceTrigger(
	query: Query,
	table: string,
	argumentsSql: string,
): Promise<void> {
	await query(`DROP TRIGGER IF EXISTS clearance_import_rollback_guard_v1 ON ${table}`);
	await query(`CREATE TRIGGER clearance_import_rollback_guard_v1
		BEFORE INSERT OR UPDATE ON ${table}
		FOR EACH ROW EXECUTE FUNCTION ${ROLLBACK_FENCE_FUNCTION}(${argumentsSql})`);
}

/**
 * Installs a database-owned serialization fence before destructive rollback.
 * Trigger DDL drains pre-existing writers. Afterwards every non-FK writer
 * takes the same transaction advisory key as rollback and rejects identities
 * that rollback has durably tombstoned, covering both writer-first and
 * rollback-first races without relying on application call-site discipline.
 */
async function installRollbackFences(query: Query): Promise<void> {
	await query(`CREATE TABLE IF NOT EXISTS ${ROLLBACK_FENCE_TABLE} (
		kind text NOT NULL CHECK (kind IN ('organization', 'principal')),
		resource_id text NOT NULL,
		tombstoned_at timestamptz NOT NULL DEFAULT now(),
		PRIMARY KEY (kind, resource_id)
	)`);
	await query(`CREATE OR REPLACE FUNCTION ${ROLLBACK_FENCE_FUNCTION}()
		RETURNS trigger
		LANGUAGE plpgsql
		AS $rollback_fence$
		DECLARE
			argument_index integer := 0;
			fence_kind text;
			reference_column text;
			condition_column text;
			condition_value text;
			reference_id text;
			row_data jsonb := to_jsonb(NEW);
		BEGIN
			WHILE argument_index < TG_NARGS LOOP
				fence_kind := TG_ARGV[argument_index];
				reference_column := TG_ARGV[argument_index + 1];
				condition_column := TG_ARGV[argument_index + 2];
				condition_value := TG_ARGV[argument_index + 3];
				reference_id := row_data ->> reference_column;
				IF reference_id IS NOT NULL AND (
					condition_column = '' OR row_data ->> condition_column = condition_value
				) THEN
					PERFORM pg_advisory_xact_lock(hashtextextended(
						'${ROLLBACK_FENCE_NAMESPACE}:' || fence_kind || ':' || reference_id,
						0
					));
					IF EXISTS (
						SELECT 1 FROM ${ROLLBACK_FENCE_TABLE}
						WHERE kind = fence_kind AND resource_id = reference_id
					) THEN
						RAISE EXCEPTION 'Clearance rollback-fenced resource cannot be referenced'
							USING ERRCODE = '23503';
					END IF;
				END IF;
				argument_index := argument_index + 4;
			END LOOP;
			RETURN NEW;
		END
		$rollback_fence$`);

	if (await runtimeTableExists(query, "passkeyChallenge")) {
		await installRollbackFenceTrigger(
			query,
			`"passkeyChallenge"`,
			`'principal', 'userId', '', '', 'principal', 'stagedSubjectId', '', ''`,
		);
	}
	const authorization = authorizationStorage();
	if (authorization) {
		const assignments = rollbackQualifiedTable(
			authorization.schema,
			`${authorization.prefix}_authz_subject_role_assignments`,
		);
		await installRollbackFenceTrigger(
			query,
			assignments,
			`'organization', 'organizationId', '', '', 'principal', 'subjectId', 'subjectKind', 'principal'`,
		);
	}
	await installRollbackFenceTrigger(
		query,
		runtimeAuditEventTable(),
		`'organization', 'organization_id', '', ''`,
	);
	const delivery = deliveryEventTable();
	if (delivery) {
		await installRollbackFenceTrigger(
			query,
			delivery,
			`'organization', 'organization_id', '', '', 'principal', 'actor_id', '', ''`,
		);
	}
}

async function lockRollbackFenceEntries(
	query: Query,
	entries: readonly { kind: RollbackFenceKind; id: string }[],
): Promise<void> {
	for (const entry of entries) {
		await query(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [
			`${ROLLBACK_FENCE_NAMESPACE}:${entry.kind}:${entry.id}`,
		]);
	}
}

async function tombstoneRollbackFenceEntries(
	query: Query,
	entries: readonly { kind: RollbackFenceKind; id: string }[],
): Promise<void> {
	for (const entry of entries) {
		await query(`INSERT INTO ${ROLLBACK_FENCE_TABLE} (kind, resource_id)
			VALUES ($1, $2)
			ON CONFLICT (kind, resource_id) DO NOTHING`, [entry.kind, entry.id]);
	}
}

function reconcileMigrationOrganization(
	source: LegacyExportFixture["organizations"][number],
	byExternalId: Organization | undefined | null,
	bySlug: Organization | undefined | null,
): Organization | undefined {
	const slug = sourceSlug(source);
	if (byExternalId && bySlug && byExternalId.id !== bySlug.id) {
		migrationFixtureConflict("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization ${source.id} maps to different existing organizations`, "Resolve the conflicting organization id or slug before retrying.");
	}
	if (byExternalId && byExternalId.slug !== slug) {
		migrationFixtureConflict("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization id ${source.id} has a different slug in Clearance`, "Resolve the conflicting organization before retrying.");
	}
	if (bySlug?.externalId && bySlug.externalId !== source.id) {
		migrationFixtureConflict("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization slug ${slug} belongs to a different import source`, "Resolve the conflicting external id before retrying.");
	}
	return byExternalId ?? bySlug ?? undefined;
}

type SnapshotOrganizationLookup = {
	byExternalId: ReadonlyMap<string, Organization>;
	bySlug: ReadonlyMap<string, Organization>;
};

type SnapshotPrincipalLookup = {
	byExternalId: ReadonlyMap<string, Principal>;
	byEmail: ReadonlyMap<string, Principal>;
};

function snapshotPrincipalLookup(
	data: DataStoreSnapshot,
	scope: { projectId: string; environmentId: string },
): SnapshotPrincipalLookup {
	const byExternalId = new Map<string, Principal>();
	const byEmail = new Map<string, Principal>();
	for (const principal of data.principals) {
		if (
			principal.projectId !== scope.projectId ||
			principal.environmentId !== scope.environmentId ||
			principal.status === "deleted"
		) continue;
		byEmail.set(principal.email.toLowerCase(), principal);
		if (principal.externalId) byExternalId.set(principal.externalId, principal);
	}
	return { byExternalId, byEmail };
}

type SnapshotMembershipLookup = ReadonlyMap<string, Membership>;

function membershipLookupKey(principalId: string, organizationId: string): string {
	return `${principalId}\u0000${organizationId}`;
}

function snapshotMembershipLookup(data: DataStoreSnapshot): SnapshotMembershipLookup {
	const memberships = new Map<string, Membership>();
	for (const membership of data.memberships) {
		if (membership.status === "active") {
			memberships.set(membershipLookupKey(membership.principalId, membership.organizationId), membership);
		}
	}
	return memberships;
}

function snapshotOrganizationLookup(
	data: DataStoreSnapshot,
	scope: { projectId: string; environmentId: string },
): SnapshotOrganizationLookup {
	const byExternalId = new Map<string, Organization>();
	const bySlug = new Map<string, Organization>();
	for (const organization of data.organizations) {
		if (
			organization.projectId !== scope.projectId ||
			organization.environmentId !== scope.environmentId ||
			organization.status === "archived"
		) continue;
		bySlug.set(organization.slug, organization);
		if (organization.externalId) byExternalId.set(organization.externalId, organization);
	}
	return { byExternalId, bySlug };
}

function snapshotMigrationOrganization(
	lookup: SnapshotOrganizationLookup,
	source: LegacyExportFixture["organizations"][number],
): Organization | undefined {
	return reconcileMigrationOrganization(
		source,
		lookup.byExternalId.get(source.id),
		lookup.bySlug.get(sourceSlug(source)),
	);
}

async function relationalPreview(
	store: ManagementStore,
	fixture: LegacyExportFixture,
	reader = store.storeV2Principals,
	topology = store.storeV2Topology,
): Promise<MigrationPreview> {
	if (!reader?.authoritative && !topology?.authoritative) return previewMigration(store, fixture);
	const scope = await migrationScope(store.snapshot, topology);
	const userMap = new Map<string, string>();
	const organizationMap = new Map<string, string>();
	const snapshotPrincipals = reader?.authoritative === true
		? undefined
		: snapshotPrincipalLookup(store.snapshot, scope);
	const snapshotOrganizations = topology?.authoritative
		? undefined
		: snapshotOrganizationLookup(store.snapshot, scope);
	const snapshotMemberships = snapshotMembershipLookup(store.snapshot);
	for (const user of fixture.users) {
		const [byExternalId, byEmail] = reader?.authoritative === true
			? await Promise.all([
				reader.findActiveByExternalId({ scope, externalId: user.id }),
				reader.findActiveByEmail({ scope, email: user.email }),
			])
			: [
				snapshotPrincipals!.byExternalId.get(user.id),
				snapshotPrincipals!.byEmail.get(user.email.toLowerCase()),
			];
		if (byExternalId && byEmail && byExternalId.id !== byEmail.id) {
			migrationFixtureConflict("CLEARANCE_IMPORT_USER_CONFLICT", `User ${user.email} maps to different existing identities`, "Resolve the conflicting external id or email before retrying.");
		}
		if (byExternalId && byExternalId.email.toLowerCase() !== user.email) {
			migrationFixtureConflict("CLEARANCE_IMPORT_USER_CONFLICT", `User id ${user.id} has a different email in Clearance`, "Resolve the conflicting identity before retrying.");
		}
		if (byEmail?.externalId && byEmail.externalId !== user.id) {
			migrationFixtureConflict("CLEARANCE_IMPORT_USER_CONFLICT", `User ${user.email} belongs to a different import source`, "Resolve the conflicting external id before retrying.");
		}
		const existing = byExternalId ?? byEmail;
		if (existing) userMap.set(user.id, existing.id);
	}
	for (const organization of fixture.organizations) {
		const existing = topology?.authoritative
			? await migrationOrganization(topology, scope, organization)
			: snapshotMigrationOrganization(snapshotOrganizations!, organization);
		if (existing) organizationMap.set(organization.id, existing.id);
	}
	let existingMembers = 0;
	for (const member of fixture.members) {
		const principalId = userMap.get(member.userId);
		const organizationId = organizationMap.get(member.organizationId);
		const existing = principalId && organizationId
			? snapshotMemberships.get(membershipLookupKey(principalId, organizationId))
			: undefined;
		if (existing && existing.role !== fixtureMemberRole(member)) migrationFixtureConflict("CLEARANCE_IMPORT_MEMBERSHIP_ROLE_CONFLICT", `Membership for user ${member.userId} in organization ${member.organizationId} has role ${existing.role}, not ${fixtureMemberRole(member)}`, "Align the existing membership role with the fixture, or import into a new environment.");
		if (existing) existingMembers += 1;
	}
	return {
		source: "legacy",
		fixtureChecksum: migrationFixtureChecksum(fixture),
		counts: { users: fixture.users.length, organizations: fixture.organizations.length, members: fixture.members.length },
		wouldCreate: { users: fixture.users.length - userMap.size, organizations: fixture.organizations.length - organizationMap.size, members: fixture.members.length - existingMembers },
		idempotent: { users: userMap.size, organizations: organizationMap.size, members: existingMembers },
	};
}

export async function previewMigrationDurable(
	store: ManagementStore,
	fixture: LegacyExportFixture,
): Promise<MigrationPreview> {
	return relationalPreview(store, fixture);
}

export async function planMigrationDurable(
	store: ManagementStore,
	fixture: LegacyExportFixture,
): Promise<MigrationPlan> {
	if (!store.storeV2Principals?.authoritative && !store.storeV2Topology?.authoritative) return planMigration(store, fixture);
	const preview = await relationalPreview(store, fixture);
	const scope = await migrationScope(store.snapshot, store.storeV2Topology);
	const now = nowIso();
	const plan: MigrationPlan = {
		id: newId("mig"), source: "legacy", projectId: scope.projectId, environmentId: scope.environmentId,
		status: "planned", counts: preview.counts, fixtureChecksum: preview.fixtureChecksum,
		checkpoint: { phase: "planned", ...preview },
		steps: [{ name: "validate_fixture", status: "done", detail: "Legacy fixture schema and references validated" }, { name: "import_users", status: "pending" }, { name: "import_organizations", status: "pending" }, { name: "import_memberships", status: "pending" }, { name: "verify_counts", status: "pending" }],
		createdAt: now, updatedAt: now,
	};
	store.mutate((data) => {
		data.migrations.unshift(plan);
	});
	recordEvent(store, { actor: "operator", action: "migration.plan", subjectType: "migration", subjectId: plan.id, outcome: "success", source: "migration", projectId: scope.projectId, environmentId: scope.environmentId, message: `Planned Clearance import of ${plan.counts.users} users`, metadata: { source: plan.source, fixtureChecksum: plan.fixtureChecksum, counts: plan.counts } });
	return plan;
}

function nullableString(value: unknown): string | null {
	return value === null || value === undefined ? null : String(value);
}

function isoTimestamp(value: unknown): string {
	return new Date(value as string | Date).toISOString();
}

async function runtimeUser(query: Query, sourceId: string, email: string) {
	const normalizedEmail = email.trim().toLowerCase();
	const result = await query(
		`select id, email, name from "user" where id = $1 or email = $2`,
		[sourceId, normalizedEmail],
	);
	if (result.rows.length > 1) runtimeConflict("user", "Resolve the runtime id/email collision before retrying.");
	const row = result.rows[0];
	if (row && String(row.email).toLowerCase() !== normalizedEmail) runtimeConflict("user", "The source user id is already assigned to another runtime email.");
	return row ? { id: String(row.id), email: String(row.email).toLowerCase(), name: String(row.name ?? normalizedEmail) } : null;
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

function migrationEvent(
	appendAudit: InternalManagementCoordinatedMutationContext["appendAudit"],
	scope: { projectId: string; environmentId: string },
	planId: string,
	action: string,
	message: string,
	outcome: "success" | "failure",
	metadata?: Record<string, unknown>,
) {
	appendAudit({
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

const POSTGRES_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;

function rollbackQualifiedTable(
	schema: string | undefined,
	table: string,
): string {
	if (!POSTGRES_IDENTIFIER.test(table) || table.length > 63) {
		throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Rollback dependency table configuration is invalid", stage: "import.legacy.rollback", remediation: "Correct the configured runtime storage identifiers before retrying rollback." });
	}
	if (!schema) return `"${table}"`;
	if (!POSTGRES_IDENTIFIER.test(schema) || schema.length > 63) {
		throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Rollback dependency schema configuration is invalid", stage: "import.legacy.rollback", remediation: "Correct the configured runtime storage identifiers before retrying rollback." });
	}
	return `"${schema}"."${table}"`;
}

function runtimeAuditEventTable(): string {
	const prefix = process.env.CLEARANCE_RUNTIME_AUDIT_PREFIX?.trim();
	const table = prefix
		? `${prefix}_runtime_audit_events`
		: "clearance_runtime_audit_events";
	return rollbackQualifiedTable(
		process.env.CLEARANCE_RUNTIME_AUDIT_SCHEMA?.trim() || "public",
		table,
	);
}

async function hasRelationalOrganizationDependency(
	query: Query,
	table: string,
	projectId: string,
	environmentId: string,
	organizationId: string,
): Promise<boolean> {
	return Boolean((await query(
		`select 1 from ${table} where project_id = $1 and environment_id = $2 and organization_id = $3 limit 1`,
		[projectId, environmentId, organizationId],
	)).rows[0]);
}

async function hasAuthorizationOrganizationDependency(
	query: Query,
	projectId: string,
	environmentId: string,
	organizationId: string,
): Promise<string | null> {
	if (process.env.CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION === "legacy-v1") {
		return null;
	}
	const schema = process.env.CLEARANCE_AUTHORIZATION_SCHEMA?.trim() || "public";
	const prefix = process.env.CLEARANCE_AUTHORIZATION_PREFIX?.trim() || "clearance";
	if (!POSTGRES_IDENTIFIER.test(prefix) || prefix.length > 24) {
		throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Rollback authorization table configuration is invalid", stage: "import.legacy.rollback", remediation: "Correct CLEARANCE_AUTHORIZATION_PREFIX before retrying rollback." });
	}
	for (const [label, suffix] of [
		["authorization role", "roles"],
		["authorization assignment", "subject_role_assignments"],
		["authorization service account", "service_accounts"],
		["authorization credential", "service_account_credentials"],
		["authorization revision", "revisions"],
	] as const) {
		const table = rollbackQualifiedTable(schema, `${prefix}_authz_${suffix}`);
		const result = await query(
			`select 1 from ${table} where "projectId" = $1 and "environmentId" = $2 and "organizationId" = $3 limit 1`,
			[projectId, environmentId, organizationId],
		);
		if (result.rows[0]) return label;
	}
	return null;
}

async function runtimeTableExists(query: Query, table: string): Promise<boolean> {
	return Boolean((await query(
		`select to_regclass(format('%I.%I', current_schema(), $1::text)) as relation`,
		[table],
	)).rows[0]?.relation);
}

function authorizationStorage(): { schema: string; prefix: string } | null {
	if (process.env.CLEARANCE_CREDENTIAL_AUTHORITY_GENERATION === "legacy-v1") {
		return null;
	}
	const schema = process.env.CLEARANCE_AUTHORIZATION_SCHEMA?.trim() || "public";
	const prefix = process.env.CLEARANCE_AUTHORIZATION_PREFIX?.trim() || "clearance";
	if (!POSTGRES_IDENTIFIER.test(prefix) || prefix.length > 24) {
		throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Rollback authorization table configuration is invalid", stage: "import.legacy.rollback", remediation: "Correct CLEARANCE_AUTHORIZATION_PREFIX before retrying rollback." });
	}
	return { schema, prefix };
}

async function hasAuthorizationPrincipalDependency(
	query: Query,
	projectId: string,
	environmentId: string,
	principalId: string,
): Promise<string | null> {
	const storage = authorizationStorage();
	if (!storage) return null;
	const tableName = `${storage.prefix}_authz_subject_role_assignments`;
	const columns = await query(
		`select column_name from information_schema.columns where table_schema = $1 and table_name = $2`,
		[storage.schema, tableName],
	);
	const available = new Set(columns.rows.map((row) => String(row.column_name)));
	if (available.size === 0) {
		throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Rollback authorization subject-assignment table is missing", stage: "import.legacy.rollback", remediation: "Restore the configured normalized authorization schema before retrying rollback." });
	}
	if (!available.has("subjectKind") || !available.has("subjectId")) {
		throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Rollback authorization subject-assignment table is not the canonical normalized schema", stage: "import.legacy.rollback", remediation: "Restore the configured normalized authorization schema before retrying rollback." });
	}
	const table = rollbackQualifiedTable(storage.schema, tableName);
	if ((await query(
		`select 1 from ${table} where "projectId" = $1 and "environmentId" = $2 and "subjectKind" = 'principal' and "subjectId" = $3 limit 1`,
		[projectId, environmentId, principalId],
	)).rows[0]) return "authorization principal assignment";
	return null;
}

function deliveryEventTable(): string | null {
	const deliveryConfigured = [
		"CLEARANCE_DELIVERY_KEY_ID",
		"CLEARANCE_DELIVERY_KEYS_JSON",
		"CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID",
		"CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON",
		"CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY",
	].some((name) => Boolean(process.env[name]?.trim()));
	if (!deliveryConfigured) return null;
	const deliveryPrefix = process.env.CLEARANCE_DELIVERY_PREFIX?.trim() || "delivery_";
	if (!POSTGRES_IDENTIFIER.test(deliveryPrefix) || deliveryPrefix.length > 63) {
		throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Rollback delivery table configuration is invalid", stage: "import.legacy.rollback", remediation: "Correct CLEARANCE_DELIVERY_PREFIX before retrying rollback." });
	}
	return rollbackQualifiedTable(
		process.env.CLEARANCE_DELIVERY_SCHEMA?.trim() || "public",
		`${deliveryPrefix}event`,
	);
}

async function hasRuntimePrincipalDependency(
	query: Query,
	projectId: string,
	environmentId: string,
	principalId: string,
): Promise<string | null> {
	for (const [label, sql] of [
		["runtime account", `select 1 from account where "userId" = $1 limit 1`],
		["runtime passkey", `select 1 from passkey where "userId" = $1 limit 1`],
		["runtime two-factor credential", `select 1 from "twoFactor" where "userId" = $1 limit 1`],
		["runtime passkey challenge", `select 1 from "passkeyChallenge" where "userId" = $1 or "stagedSubjectId" = $1 limit 1`],
	] as const) {
		if ((await query(sql, [principalId])).rows[0]) return label;
	}
	for (const [label, table] of [
		["runtime OAuth access or refresh token", "oauthAccessToken"],
		["runtime OAuth consent", "oauthConsent"],
	] as const) {
		if (await runtimeTableExists(query, table) && (await query(
			`select 1 from "${table}" where "userId" = $1 limit 1`,
			[principalId],
		)).rows[0]) return label;
	}
	const deliveryTable = deliveryEventTable();
	if (deliveryTable && (await query(
		`select 1 from ${deliveryTable} where project_id = $1 and environment_id = $2 and actor_id = $3 limit 1`,
		[projectId, environmentId, principalId],
	)).rows[0]) return "delivery actor";
	return hasAuthorizationPrincipalDependency(query, projectId, environmentId, principalId);
}

async function hasRuntimeOrganizationDependency(
	query: Query,
	projectId: string,
	environmentId: string,
	organizationId: string,
	runtimeMembershipIds: readonly string[],
): Promise<string | null> {
	for (const [label, sql, params] of [
		["runtime session", `select 1 from session where "activeOrganizationId" = $1 limit 1`, [organizationId]],
		["runtime member", `select 1 from member where "organizationId" = $1 and not (id = any($2::text[])) limit 1`, [organizationId, runtimeMembershipIds]],
		["runtime invitation", `select 1 from invitation where "organizationId" = $1 limit 1`, [organizationId]],
		["runtime SSO provider", `select 1 from "ssoProvider" where "organizationId" = $1 limit 1`, [organizationId]],
		["runtime SCIM provider", `select 1 from "scimProvider" where "organizationId" = $1 limit 1`, [organizationId]],
		["authentication policy override", `select 1 from "authenticationPolicyOrganizationOverride" where "projectId" = $1 and "environmentId" = $2 and "organizationId" = $3 limit 1`, [projectId, environmentId, organizationId]],
	] as const) {
		if ((await query(sql, [...params])).rows[0]) return label;
	}

	if (await runtimeTableExists(query, "team")) {
		if ((await query(`select 1 from team where "organizationId" = $1 limit 1`, [organizationId])).rows[0]) {
			return "runtime team";
		}
		if (await runtimeTableExists(query, "teamMember") && (await query(
			`select 1 from "teamMember" membership join team on team.id = membership."teamId" where team."organizationId" = $1 limit 1`,
			[organizationId],
		)).rows[0]) return "runtime team member";
	}

	if (await hasRelationalOrganizationDependency(
		query,
		runtimeAuditEventTable(),
		projectId,
		environmentId,
		organizationId,
	)) return "runtime audit event";

	const deliveryTable = deliveryEventTable();
	if (deliveryTable) {
		if (await hasRelationalOrganizationDependency(
			query,
			deliveryTable,
			projectId,
			environmentId,
			organizationId,
		)) return "delivery event or job";
	}
	return hasAuthorizationOrganizationDependency(query, projectId, environmentId, organizationId);
}

async function assertNoRollbackDependencies(
	data: DataStoreSnapshot,
	query: Query,
	input: {
		organizationIds: ReadonlySet<string>;
		organizations: readonly Pick<Organization, "id" | "projectId" | "environmentId">[];
		users: readonly Pick<Principal, "id" | "projectId" | "environmentId">[];
		membershipIds: ReadonlySet<string>;
		runtimeMembershipIds: readonly string[];
		userIds: ReadonlySet<string>;
	},
): Promise<void> {
	const dependentMembership = data.memberships.find((membership) =>
		!input.membershipIds.has(membership.id) &&
		(input.userIds.has(membership.principalId) || input.organizationIds.has(membership.organizationId)),
	);
	if (dependentMembership) rollbackStateConflict("membership", dependentMembership.id);
	const dependentSession = data.sessions.find((session) => input.userIds.has(session.principalId));
	if (dependentSession) rollbackStateConflict("user", dependentSession.principalId);
	const snapshotOrganizationDependency =
		data.identityConnections.find((connection) => input.organizationIds.has(connection.organizationId))?.organizationId ??
		data.directoryConnections.find((connection) => input.organizationIds.has(connection.organizationId))?.organizationId ??
		data.roles.find((role) => role.organizationId && input.organizationIds.has(role.organizationId))?.organizationId ??
		data.setupLinks.find((link) => input.organizationIds.has(link.organizationId))?.organizationId ??
		data.readinessReports.find((report) => input.organizationIds.has(report.organizationId))?.organizationId ??
		data.traces.find((trace) => trace.organizationId && input.organizationIds.has(trace.organizationId))?.organizationId;
	if (snapshotOrganizationDependency) rollbackStateConflict("organization", snapshotOrganizationDependency);

	for (const principal of input.users) {
		const dependent = await hasRuntimePrincipalDependency(
			query,
			principal.projectId,
			principal.environmentId,
			principal.id,
		);
		if (dependent) rollbackStateConflict("user", principal.id);
	}

	for (const organization of input.organizations) {
		const dependent = await hasRuntimeOrganizationDependency(
			query,
			organization.projectId,
			organization.environmentId,
			organization.id,
			input.runtimeMembershipIds,
		);
		if (dependent) rollbackStateConflict("organization", organization.id);
	}
}

export async function runMigrationDurable(
	store: ManagementStore,
	planId: string,
	fixture: LegacyExportFixture,
	opts: { dryRun?: boolean } = {},
): Promise<MigrationPlan> {
	if (store.backend === "json") return runMigration(store, planId, fixture, opts);
	const initial = migrationStatus(store, planId);
	if (initial.fixtureChecksum !== migrationFixtureChecksum(fixture)) checkpointMismatch("import.legacy.run");
	assertMigrationRunnable(initial, "import.legacy.run");
	if (opts.dryRun) return { ...initial, checkpoint: { phase: "dry_run", ...await relationalPreview(store, fixture) }, updatedAt: nowIso() };

	await ensureAuthMigrated();
	const mutate = requireCoordinated(store, "import.legacy.run");
	return mutate(async ({ data, principals, topology, query, appendAudit }) => {
		const draft = draftStore(data);
		const plan = migrationStatus(draft, planId);
		if (plan.fixtureChecksum !== migrationFixtureChecksum(fixture)) checkpointMismatch("import.legacy.run");
		const txPreview = await relationalPreview(draft, fixture, principals, topology);
		assertMigrationRunnable(plan, "import.legacy.run");
		const scope = await migrationScope(data, topology);
		if (topology && !await lockTopologyScope(topology, scope)) {
			lockedScopeUnavailable("import.legacy.run");
		}
		const userMap = new Map<string, string>();
		const organizationMap = new Map<string, string>();
		const snapshotPrincipals = principals
			? undefined
			: snapshotPrincipalLookup(data, scope);
		const snapshotOrganizations = topology?.authoritative
			? undefined
			: snapshotOrganizationLookup(data, scope);
		const snapshotMemberships = snapshotMembershipLookup(data);
		const createdResourceIds = { users: [] as string[], organizations: [] as string[], memberships: [] as string[] };
		const createdRuntimeResourceIds = { users: [] as string[], organizations: [] as string[], memberships: [] as string[] };
		const rollbackResourceState: NonNullable<MigrationPlan["rollbackResourceState"]> = {
			management: { users: [], organizations: [], memberships: [] },
			runtime: { users: [], organizations: [], memberships: [] },
		};

		for (const source of fixture.users) {
			const existing = principals
				? (await principals.findActiveByExternalId({ scope, externalId: source.id })) ??
					(await principals.findActiveByEmail({ scope, email: source.email }))
				: snapshotPrincipals!.byExternalId.get(source.id) ??
					snapshotPrincipals!.byEmail.get(source.email.toLowerCase());
			const runtime = await runtimeUser(query, source.id, source.email);
			if (existing && runtime && existing.id !== runtime.id) runtimeConflict("user", "Runtime and management identities must share one stable id.");
			const id = existing?.id ?? runtime?.id;
			let principal: Principal;
			if (existing) principal = existing;
			else if (principals) {
				const now = nowIso();
				principal = await principals.insert({
					id: id ?? newId("user"),
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					email: source.email.toLowerCase(),
					name: source.name,
					status: "active",
					externalId: source.id,
					createdAt: now,
					updatedAt: now,
				});
			} else {
				principal = createUser(draft, { ...(id ? { id } : {}), email: source.email, name: source.name, externalId: source.id, source: "import", actor: "cli", projectId: scope.projectId, environmentId: scope.environmentId });
			}
			if (!existing) {
				createdResourceIds.users.push(principal.id);
				rollbackResourceState.management.users.push({ id: principal.id, projectId: principal.projectId, environmentId: principal.environmentId, email: principal.email, name: principal.name, status: principal.status, ...(principal.externalId ? { externalId: principal.externalId } : {}), createdAt: principal.createdAt, updatedAt: principal.updatedAt });
			}
			if (!runtime) {
				const inserted = await query(
					`insert into "user" (id, email, name, "emailVerified", "createdAt", "updatedAt") values ($1, $2, $3, false, now(), now()) returning id, email, name, "emailVerified", image, banned, "banReason", "createdAt"::text as created_at_identity, "updatedAt"`,
					[principal.id, source.email, source.name],
				);
				createdRuntimeResourceIds.users.push(principal.id);
				const row = inserted.rows[0]!;
				rollbackResourceState.runtime.users.push({ id: String(row.id), email: String(row.email).toLowerCase(), name: String(row.name), emailVerified: Boolean(row.emailVerified), image: nullableString(row.image), banned: Boolean(row.banned), banReason: nullableString(row.banReason), createdAt: String(row.created_at_identity), updatedAt: isoTimestamp(row.updatedAt) });
			}
			userMap.set(source.id, principal.id);
		}

		for (const source of fixture.organizations) {
			const slug = sourceSlug(source);
			const preflight = topology?.authoritative
				? await migrationOrganization(topology, scope, source)
				: snapshotMigrationOrganization(snapshotOrganizations!, source);
			const existing = topology && preflight
				? lockedMigrationOrganization(
					source,
					await lockTopologyOrganization(topology, scope, preflight.id),
				)
				: preflight;
			const runtime = await runtimeOrganization(query, source.id, slug);
			if (existing && runtime && existing.id !== runtime.id) runtimeConflict("organization", "Runtime and management organizations must share one stable id.");
			const id = existing?.id ?? runtime?.id;
			const now = nowIso();
			const organization = existing ?? (topology
				? {
					id: id ?? newId("org"),
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					name: source.name,
					slug,
					status: "active" as const,
					externalId: source.id,
					createdAt: now,
					updatedAt: now,
				}
				: createOrganization(draft, { ...(id ? { id } : {}), name: source.name, slug, externalId: source.id, source: "import", actor: "cli", projectId: scope.projectId, environmentId: scope.environmentId }));
			if (!existing) {
				if (topology) {
					if (await topology.organizationIdExists(organization.id)) {
						const scopedExisting = await lockTopologyOrganization(
							topology,
							scope,
							organization.id,
						);
						if (!scopedExisting) {
							migrationFixtureConflict("CLEARANCE_IMPORT_ORGANIZATION_CONFLICT", `Organization id ${organization.id} already exists outside the import scope`, "Resolve the conflicting organization id before retrying.");
						}
					}
					await topology.upsertOrganization(organization);
				}
				createdResourceIds.organizations.push(organization.id);
				rollbackResourceState.management.organizations.push(organization);
			}
			if (!runtime) {
				const inserted = await query(
					`insert into organization (id, name, slug, "createdAt") values ($1, $2, $3, now()) returning id, name, slug, logo, metadata, "createdAt"`,
					[organization.id, source.name, slug],
				);
				createdRuntimeResourceIds.organizations.push(organization.id);
				const row = inserted.rows[0]!;
				rollbackResourceState.runtime.organizations.push({ id: String(row.id), name: String(row.name), slug: String(row.slug), logo: nullableString(row.logo), metadata: nullableString(row.metadata), createdAt: isoTimestamp(row.createdAt) });
			}
			organizationMap.set(source.id, organization.id);
		}

		for (const source of fixture.members) {
			const principalId = userMap.get(source.userId)!;
			const organizationId = organizationMap.get(source.organizationId)!;
			const existing = snapshotMemberships.get(
				membershipLookupKey(principalId, organizationId),
			);
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
				rollbackResourceState.management.memberships.push({ id: membership.id, organizationId, principalId, role: membership.role, status: membership.status, source: membership.source, createdAt: membership.createdAt, updatedAt: membership.updatedAt });
			} else {
				if (principals) {
					const now = nowIso();
					membership = {
						id: newId("mem"),
						organizationId,
						principalId,
						role: source.role ?? "member",
						status: "active",
						source: "import",
						createdAt: now,
						updatedAt: now,
					};
					data.memberships.push(membership);
				} else {
					membership = addMember(draft, { organizationId, principalId, role: source.role ?? "member", source: "import", actor: "cli", auditSource: "import" });
				}
				createdResourceIds.memberships.push(membership.id);
				rollbackResourceState.management.memberships.push({ id: membership.id, organizationId, principalId, role: membership.role, status: membership.status, source: membership.source, createdAt: membership.createdAt, updatedAt: membership.updatedAt });
			}
			if (!runtime) {
				const inserted = await query(
					`insert into member (id, "organizationId", "userId", role, "createdAt") values ($1, $2, $3, $4, now()) returning "createdAt"`,
					[membership.id, organizationId, principalId, membership.role],
				);
				createdRuntimeResourceIds.memberships.push(membership.id);
				rollbackResourceState.runtime.memberships.push({ id: membership.id, organizationId, principalId, role: membership.role, createdAt: isoTimestamp(inserted.rows[0]!.createdAt) });
			}
		}

		const updated: MigrationPlan = {
			...plan,
			status: "running",
			createdResourceIds,
			createdRuntimeResourceIds,
			rollbackResourceState,
			checkpoint: { phase: "imported", ...await relationalPreview(draft, fixture, principals, topology) },
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
		migrationEvent(appendAudit, scope, planId, "migration.run", "Legacy runtime and management import committed atomically", "success", { source: "legacy", counts: fixture.users.length + fixture.organizations.length + fixture.members.length, credentialTransition: "password_reset_required_if_credentials_absent" });
		return updated;
	});
}

export async function verifyMigrationDurable(store: ManagementStore, planId: string, fixture: LegacyExportFixture) {
	if (store.backend === "json") return verifyMigration(store, planId, fixture);
	await ensureAuthMigrated();
	const mutate = requireCoordinated(store, "import.legacy.verify");
	const result = await mutate(async ({ data, principals, topology, query, appendAudit }) => {
		const draft = draftStore(data);
		const plan = migrationStatus(draft, planId);
		if (plan.fixtureChecksum !== migrationFixtureChecksum(fixture)) checkpointMismatch("import.legacy.verify");
		const preview = await relationalPreview(draft, fixture, principals, topology);
		const scope = await migrationScope(data, topology);
		const expected = { users: fixture.users.length, organizations: fixture.organizations.length, members: fixture.members.length };
		const userMap = new Map<string, string>();
		const snapshotPrincipals = principals
			? undefined
			: snapshotPrincipalLookup(data, scope);
		const snapshotOrganizations = topology?.authoritative
			? undefined
			: snapshotOrganizationLookup(data, scope);
		const snapshotMemberships = snapshotMembershipLookup(data);
		for (const source of fixture.users) {
			const found = principals
				? (await principals.findActiveByExternalId({ scope, externalId: source.id })) ??
					(await principals.findActiveByEmail({ scope, email: source.email }))
				: snapshotPrincipals!.byExternalId.get(source.id) ??
					snapshotPrincipals!.byEmail.get(source.email.toLowerCase());
			if (found) userMap.set(source.id, found.id);
		}
		const organizationMap = new Map<string, string>();
		for (const source of fixture.organizations) {
			const found = topology?.authoritative
				? await migrationOrganization(topology, scope, source)
				: snapshotMigrationOrganization(snapshotOrganizations!, source);
			if (found) organizationMap.set(source.id, found.id);
		}
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
				const management = principalId && organizationId
					? snapshotMemberships.get(membershipLookupKey(principalId, organizationId))
					: undefined;
				const matchingManagement = management?.role === fixtureMemberRole(source)
					? management
					: undefined;
				if (matchingManagement && (await query(`select id from member where id = $1 and "organizationId" = $2 and "userId" = $3 and role = $4`, [matchingManagement.id, organizationId, principalId, fixtureMemberRole(source)])).rows[0]) members += 1;
		}
		const actual = { users, organizations, members };
		const reconciled = users === expected.users && organizations === expected.organizations && members === expected.members;
		const updated: MigrationPlan = { ...plan, status: reconciled ? "verified" : "failed", checkpoint: { phase: reconciled ? "verified" : "failed", ...preview }, updatedAt: nowIso(), steps: plan.steps.map((step) => step.name === "verify_counts" ? { name: "verify_counts", status: reconciled ? "done" : "failed", detail: `expected ${JSON.stringify(expected)} actual ${JSON.stringify(actual)}` } : step) };
		data.migrations[data.migrations.findIndex((candidate) => candidate.id === planId)] = updated;
		migrationEvent(appendAudit, scope, planId, "migration.verify", reconciled ? "Clearance runtime and management counts reconciled" : "Clearance runtime and management count mismatch", reconciled ? "success" : "failure", { expected, actual });
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
	return mutate(async ({ data, principals, topology, query, appendAudit }) => {
		const draft = draftStore(data);
		const plan = migrationStatus(draft, planId);
		if (plan.fixtureChecksum !== migrationFixtureChecksum(fixture)) checkpointMismatch("import.legacy.rollback");
		if (!plan.createdResourceIds || !plan.createdRuntimeResourceIds || !plan.rollbackResourceState) {
			throw new ClearanceError({ code: "CLEARANCE_IMPORT_ROLLBACK_UNSAFE", message: "Migration checkpoint does not identify exact runtime and management resources", stage: "import.legacy.rollback", remediation: "Use a checkpoint created by the coordinated Postgres importer." });
		}
		if (plan.status === "rolled_back") return plan;
		const state = plan.rollbackResourceState;
		assertExactCheckpointIds("management users", plan.createdResourceIds.users, state.management.users);
		assertExactCheckpointIds("management organizations", plan.createdResourceIds.organizations, state.management.organizations);
		assertExactCheckpointIds("management memberships", plan.createdResourceIds.memberships, state.management.memberships);
		assertExactCheckpointIds("runtime users", plan.createdRuntimeResourceIds.users, state.runtime.users);
		assertExactCheckpointIds("runtime organizations", plan.createdRuntimeResourceIds.organizations, state.runtime.organizations);
		assertExactCheckpointIds("runtime memberships", plan.createdRuntimeResourceIds.memberships, state.runtime.memberships);
		await installRollbackFences(query);
		const rollbackFenceEntriesToLock = rollbackFenceEntries(state);
		await lockRollbackFenceEntries(query, rollbackFenceEntriesToLock);
		await lockRuntimeRollbackParents(query, state);
		const snapshotPrincipalsById = new Map(data.principals.map((principal) => [principal.id, principal]));
		const snapshotOrganizationsById = new Map(data.organizations.map((organization) => [organization.id, organization]));
		const snapshotMembershipsById = new Map(data.memberships.map((membership) => [membership.id, membership]));

		for (const expected of state.management.users) {
			const current = principals
				? await principals.getById({
						scope: { projectId: expected.projectId, environmentId: expected.environmentId },
						id: expected.id,
						includeDeleted: true,
					})
				: snapshotPrincipalsById.get(expected.id);
			const matches = current && current.projectId === expected.projectId && current.environmentId === expected.environmentId && current.email === expected.email && current.name === expected.name && current.status === expected.status && current.externalId === expected.externalId && current.createdAt === expected.createdAt && current.updatedAt === expected.updatedAt;
			if (!matches) rollbackStateConflict("user", expected.id);
		}
		for (const expected of state.management.organizations) {
			const current = topology
				? await lockTopologyOrganization(topology, {
					projectId: expected.projectId,
					environmentId: expected.environmentId,
				}, expected.id)
				: snapshotOrganizationsById.get(expected.id);
			if (!current || current.projectId !== expected.projectId || current.environmentId !== expected.environmentId || current.name !== expected.name || current.slug !== expected.slug || current.status !== expected.status || current.externalId !== expected.externalId || current.createdAt !== expected.createdAt || current.updatedAt !== expected.updatedAt) {
				rollbackStateConflict("organization", expected.id);
			}
		}
		for (const expected of state.management.memberships) {
			const current = snapshotMembershipsById.get(expected.id);
			const matches = current && current.status === expected.status && current.organizationId === expected.organizationId && current.principalId === expected.principalId && current.role === expected.role && current.source === expected.source && current.createdAt === expected.createdAt && current.updatedAt === expected.updatedAt;
			if (!matches) rollbackStateConflict("membership", expected.id);
		}

		for (const expected of state.runtime.users) {
			const row = (await query(`select id, email, name, "emailVerified", image, banned, "banReason", "createdAt"::text as created_at_identity, "updatedAt" from "user" where id = $1`, [expected.id])).rows[0];
			if (!row || String(row.email).toLowerCase() !== expected.email.toLowerCase() || String(row.name) !== expected.name || Boolean(row.emailVerified) !== expected.emailVerified || nullableString(row.image) !== expected.image || Boolean(row.banned) !== expected.banned || nullableString(row.banReason) !== expected.banReason || String(row.created_at_identity) !== expected.createdAt || isoTimestamp(row.updatedAt) !== expected.updatedAt) {
				rollbackStateConflict("user", expected.id);
			}
		}
		for (const expected of state.runtime.organizations) {
			const row = (await query(`select id, name, slug, logo, metadata, "createdAt" from organization where id = $1`, [expected.id])).rows[0];
			if (!row || String(row.name) !== expected.name || String(row.slug) !== expected.slug || nullableString(row.logo) !== expected.logo || nullableString(row.metadata) !== expected.metadata || isoTimestamp(row.createdAt) !== expected.createdAt) {
				rollbackStateConflict("organization", expected.id);
			}
		}
		for (const expected of state.runtime.memberships) {
			const row = (await query(`select "createdAt" from member where id = $1 and "organizationId" = $2 and "userId" = $3 and role = $4`, [expected.id, expected.organizationId, expected.principalId, expected.role])).rows[0];
			if (!row || isoTimestamp(row.createdAt) !== expected.createdAt) {
				rollbackStateConflict("membership", expected.id);
			}
		}
		const membershipIds = new Set(plan.createdResourceIds.memberships);
		const userIds = new Set(plan.createdResourceIds.users);
		const organizationIds = new Set(plan.createdResourceIds.organizations);
		const runtimeMembershipIds = new Set(plan.createdRuntimeResourceIds.memberships);
		await assertNoRollbackDependencies(data, query, {
			organizationIds,
			organizations: state.management.organizations,
			users: state.management.users,
			membershipIds,
			runtimeMembershipIds: [...runtimeMembershipIds],
			userIds,
		});

		for (const expected of state.runtime.users) {
			if ((await query(`select 1 from member where "userId" = $1 and not (id = any($2::text[])) limit 1`, [expected.id, [...runtimeMembershipIds]])).rows[0]) rollbackStateConflict("user", expected.id);
			if ((await query(`select id from session where "userId" = $1 limit 1`, [expected.id])).rows[0]) rollbackStateConflict("user", expected.id);
			if ((await query(`select id from account where "userId" = $1 limit 1`, [expected.id])).rows[0]) rollbackStateConflict("user", expected.id);
		}
		for (const expected of state.runtime.organizations) {
			if ((await query(`select 1 from member where "organizationId" = $1 and not (id = any($2::text[])) limit 1`, [expected.id, [...runtimeMembershipIds]])).rows[0]) rollbackStateConflict("organization", expected.id);
		}
		await tombstoneRollbackFenceEntries(query, rollbackFenceEntriesToLock);
		for (const id of plan.createdRuntimeResourceIds.memberships) await query(`delete from member where id = $1`, [id]);
		for (const id of plan.createdRuntimeResourceIds.organizations) await query(`delete from organization where id = $1`, [id]);
		for (const expected of state.runtime.users) {
			if ((await query(`delete from "user" where id = $1 and "createdAt"::text = $2`, [expected.id, expected.createdAt])).rowCount !== 1) {
				rollbackStateConflict("user", expected.id);
			}
		}
		data.memberships = data.memberships.filter((membership) => !membershipIds.has(membership.id));
		if (principals) {
			for (const expected of state.management.users) {
				if (!(await hardDeleteImportedPrincipalForRollback(principals, expected))) {
					rollbackStateConflict("user", expected.id);
				}
			}
		} else {
			data.principals = data.principals.filter((principal) => !userIds.has(principal.id));
		}
		if (topology) {
			for (const expected of state.management.organizations) {
				if (!await hardDeleteImportedOrganizationForRollback(
					topology,
					expected as Organization,
				)) rollbackStateConflict("organization", expected.id);
			}
		} else {
			data.organizations = data.organizations.filter((organization) => !organizationIds.has(organization.id));
		}
		const updated: MigrationPlan = { ...plan, status: "rolled_back", checkpoint: { ...plan.checkpoint, phase: "rolled_back" }, updatedAt: nowIso(), steps: [...plan.steps, { name: "rollback", status: "done", detail: "Exact imported runtime and management resources removed atomically" }] };
		data.migrations[data.migrations.findIndex((candidate) => candidate.id === planId)] = updated;
		const scope = await migrationScope(data, topology);
		migrationEvent(appendAudit, scope, planId, "migration.rollback", "Legacy runtime and management import rolled back atomically", "success");
		return updated;
	});
}
