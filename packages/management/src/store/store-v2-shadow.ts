import { createHash } from "node:crypto";
import pg from "pg";
import type {
	AuditEvent,
	Environment,
	Organization,
	Principal,
	Project,
	DataStoreSnapshot,
} from "../types/resources.js";
import type { StoreV2EventReader } from "./types.js";
import { cloneSnapshot, normalizeSnapshot } from "./snapshot.js";
import {
	STORE_V2_COLLECTIONS,
	type StoreV2Collection,
	type StoreV2CollectionStatus,
	type StoreV2MigrationControl,
	type StoreV2Phase,
	type StoreV2Plan,
	type StoreV2PlanBlocker,
	type StoreV2Status,
} from "./types.js";
import {
	STORE_V2_SCHEMA_VERSION,
	storeV2SchemaStatements,
	storeV2TableNames,
	type StoreV2TableNames,
} from "./store-v2-schema.js";
import {
	appendStoreV2Events,
	listStoreV2EventsPage,
	readStoreV2Events,
	replaceStoreV2Events,
	type StoreV2EventDelta,
} from "./store-v2-events.js";

const MAX_DIFFERING_IDS = 20;
const META_SCHEMA_VERSION = "store_v2_schema_version";
const META_PHASE = "store_v2_phase";
const META_SNAPSHOT_REVISION = "store_v2_snapshot_revision";
const META_COLLECTIONS = "store_v2_collections";
const META_ENABLED_AT = "store_v2_enabled_at";
const META_AUTHORITATIVE_COLLECTIONS = "store_v2_authoritative_collections";

type StoreV2Resource = Project | Environment | Principal | Organization | AuditEvent;
type Queryable = pg.Pool | pg.PoolClient;

export interface StoreV2SyncResult {
	phase: StoreV2Phase;
	persistedSnapshot: DataStoreSnapshot;
	eventDelta?: StoreV2EventDelta;
}

interface SnapshotRow {
	data: DataStoreSnapshot;
	revision: string | number;
}

interface MetaRow {
	key: string;
	value: unknown;
}

interface ProjectRow {
	id: string;
	name: string;
	slug: string;
	created_at: Date | string;
	updated_at: Date | string;
}

interface EnvironmentRow extends ProjectRow {
	project_id: string;
	kind: Environment["kind"];
}

interface PrincipalRow extends ProjectRow {
	project_id: string;
	environment_id: string;
	email: string;
	status: Principal["status"];
	external_id: string | null;
}

interface OrganizationRow extends ProjectRow {
	project_id: string;
	environment_id: string;
	status: Organization["status"];
	external_id: string | null;
}

export class StoreV2MigrationError extends Error {
	readonly code: string;
	readonly blockers?: StoreV2PlanBlocker[];

	constructor(code: string, message: string, blockers?: StoreV2PlanBlocker[]) {
		super(message);
		this.name = "StoreV2MigrationError";
		this.code = code;
		this.blockers = blockers;
	}
}

function stableValue(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(stableValue);
	if (value && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value as Record<string, unknown>)
				.filter(([, child]) => child !== undefined)
				.sort(([left], [right]) => left.localeCompare(right))
				.map(([key, child]) => [key, stableValue(child)]),
		);
	}
	return value;
}

function stableJson(value: unknown): string {
	return JSON.stringify(stableValue(value));
}

function canonicalResource(resource: StoreV2Resource): StoreV2Resource {
	return {
		...resource,
		createdAt: iso(resource.createdAt),
		...( "updatedAt" in resource ? { updatedAt: iso(resource.updatedAt) } : {}),
	};
}

function resourceMap(resources: readonly StoreV2Resource[]): Map<string, string> {
	return new Map(
		resources.map((resource) => [
			resource.id,
			stableJson(canonicalResource(resource)),
		]),
	);
}

export function storeV2CollectionDigest(
	resources: readonly StoreV2Resource[],
): string {
	const canonical = [...resources]
		.sort((left, right) => left.id.localeCompare(right.id))
		.map((resource) => stableValue(canonicalResource(resource)));
	return createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
}

export function compareStoreV2Collections(
	snapshotResources: readonly StoreV2Resource[],
	relationalResources: readonly StoreV2Resource[] | null,
): StoreV2CollectionStatus {
	const snapshotChecksum = storeV2CollectionDigest(snapshotResources);
	if (!relationalResources) {
		return {
			snapshotCount: snapshotResources.length,
			relationalCount: null,
			snapshotChecksum,
			relationalChecksum: null,
			consistent: false,
			differingIds: [],
		};
	}

	const snapshot = resourceMap(snapshotResources);
	const relational = resourceMap(relationalResources);
	const differingIds = [...new Set([...snapshot.keys(), ...relational.keys()])]
		.filter((id) => snapshot.get(id) !== relational.get(id))
		.sort()
		.slice(0, MAX_DIFFERING_IDS);
	const relationalChecksum = storeV2CollectionDigest(relationalResources);

	return {
		snapshotCount: snapshotResources.length,
		relationalCount: relationalResources.length,
		snapshotChecksum,
		relationalChecksum,
		consistent:
			snapshotResources.length === relationalResources.length &&
			snapshotChecksum === relationalChecksum,
		differingIds,
	};
}

function duplicateGroups<T>(
	resources: readonly T[],
	key: (resource: T) => string | null,
	id: (resource: T) => string,
): string[][] {
	const groups = new Map<string, string[]>();
	for (const resource of resources) {
		const value = key(resource);
		if (value === null) continue;
		const ids = groups.get(value) ?? [];
		ids.push(id(resource));
		groups.set(value, ids);
	}
	return [...groups.values()].filter((ids) => ids.length > 1);
}

function addDuplicateBlockers<T>(
	blockers: StoreV2PlanBlocker[],
	collection: StoreV2Collection,
	code: string,
	resources: readonly T[],
	key: (resource: T) => string | null,
	id: (resource: T) => string,
): void {
	for (const resourceIds of duplicateGroups(resources, key, id)) {
		blockers.push({ code, collection, resourceIds: resourceIds.slice(0, 20) });
	}
}

export function planStoreV2Snapshot(
	snapshot: DataStoreSnapshot,
	snapshotRevision: number,
	phase: StoreV2Phase = "absent",
): StoreV2Plan {
	const blockers: StoreV2PlanBlocker[] = [];
	const projectIds = new Set(snapshot.projects.map((project) => project.id));
	const environmentScopes = new Set(
		snapshot.environments.map(
			(environment) => `${environment.projectId}\u0000${environment.id}`,
		),
	);

	addDuplicateBlockers(
		blockers,
		"projects",
		"STORE_V2_DUPLICATE_PROJECT_ID",
		snapshot.projects,
		(project) => project.id,
		(project) => project.id,
	);
	addDuplicateBlockers(
		blockers,
		"projects",
		"STORE_V2_DUPLICATE_PROJECT_NAME",
		snapshot.projects,
		(project) => project.name.toLowerCase(),
		(project) => project.id,
	);
	addDuplicateBlockers(
		blockers,
		"projects",
		"STORE_V2_DUPLICATE_PROJECT_SLUG",
		snapshot.projects,
		(project) => project.slug.toLowerCase(),
		(project) => project.id,
	);
	addDuplicateBlockers(
		blockers,
		"environments",
		"STORE_V2_DUPLICATE_ENVIRONMENT_ID",
		snapshot.environments,
		(environment) => environment.id,
		(environment) => environment.id,
	);
	for (const environment of snapshot.environments) {
		if (!projectIds.has(environment.projectId)) {
			blockers.push({
				code: "STORE_V2_ENVIRONMENT_PROJECT_MISSING",
				collection: "environments",
				resourceIds: [environment.id],
			});
		}
	}

	addDuplicateBlockers(
		blockers,
		"principals",
		"STORE_V2_DUPLICATE_PRINCIPAL_ID",
		snapshot.principals,
		(principal) => principal.id,
		(principal) => principal.id,
	);
	addDuplicateBlockers(
		blockers,
		"principals",
		"STORE_V2_DUPLICATE_ACTIVE_PRINCIPAL_EMAIL",
		snapshot.principals,
		(principal) =>
			principal.status === "deleted"
				? null
				: `${principal.projectId}\u0000${principal.environmentId}\u0000${principal.email.toLowerCase()}`,
		(principal) => principal.id,
	);
	for (const principal of snapshot.principals) {
		if (!environmentScopes.has(`${principal.projectId}\u0000${principal.environmentId}`)) {
			blockers.push({
				code: "STORE_V2_PRINCIPAL_ENVIRONMENT_MISSING",
				collection: "principals",
				resourceIds: [principal.id],
			});
		}
	}

	addDuplicateBlockers(
		blockers,
		"organizations",
		"STORE_V2_DUPLICATE_ORGANIZATION_ID",
		snapshot.organizations,
		(organization) => organization.id,
		(organization) => organization.id,
	);
	addDuplicateBlockers(
		blockers,
		"organizations",
		"STORE_V2_DUPLICATE_ACTIVE_ORGANIZATION_SLUG",
		snapshot.organizations,
		(organization) =>
			organization.status === "archived"
				? null
				: `${organization.projectId}\u0000${organization.environmentId}\u0000${organization.slug}`,
		(organization) => organization.id,
	);
	for (const organization of snapshot.organizations) {
		if (
			!environmentScopes.has(
				`${organization.projectId}\u0000${organization.environmentId}`,
			)
		) {
			blockers.push({
				code: "STORE_V2_ORGANIZATION_ENVIRONMENT_MISSING",
				collection: "organizations",
				resourceIds: [organization.id],
			});
		}
	}

	return {
		schemaVersion: STORE_V2_SCHEMA_VERSION,
		phase,
		snapshotRevision,
		collections: STORE_V2_COLLECTIONS,
		rowCounts: {
			projects: snapshot.projects.length,
			environments: snapshot.environments.length,
			principals: snapshot.principals.length,
			organizations: snapshot.organizations.length,
			events: snapshot.events.length,
		},
		blockerCount: blockers.length,
		blockers: blockers.slice(0, 50),
		canApply: blockers.length === 0,
	};
}

function iso(value: Date | string): string {
	return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function optional<T extends object, K extends string>(
	key: K,
	value: string | null,
): T | Record<K, string> {
	return value === null ? ({} as T) : ({ [key]: value } as Record<K, string>);
}

function mapProject(row: ProjectRow): Project {
	return {
		id: row.id,
		name: row.name,
		slug: row.slug,
		createdAt: iso(row.created_at),
		updatedAt: iso(row.updated_at),
	};
}

function mapEnvironment(row: EnvironmentRow): Environment {
	return {
		id: row.id,
		projectId: row.project_id,
		name: row.name,
		slug: row.slug,
		kind: row.kind,
		createdAt: iso(row.created_at),
		updatedAt: iso(row.updated_at),
	};
}

function mapPrincipal(row: PrincipalRow): Principal {
	return {
		id: row.id,
		projectId: row.project_id,
		environmentId: row.environment_id,
		email: row.email,
		name: row.name,
		status: row.status,
		...optional<Principal, "externalId">("externalId", row.external_id),
		createdAt: iso(row.created_at),
		updatedAt: iso(row.updated_at),
	};
}

function mapOrganization(row: OrganizationRow): Organization {
	return {
		id: row.id,
		projectId: row.project_id,
		environmentId: row.environment_id,
		name: row.name,
		slug: row.slug,
		status: row.status,
		...optional<Organization, "externalId">("externalId", row.external_id),
		createdAt: iso(row.created_at),
		updatedAt: iso(row.updated_at),
	};
}

function selectedCollections(snapshot: DataStoreSnapshot): Record<
	StoreV2Collection,
	StoreV2Resource[]
> {
	return {
		projects: snapshot.projects,
		environments: snapshot.environments,
		principals: snapshot.principals,
		organizations: snapshot.organizations,
		events: snapshot.events,
	};
}

async function tableExists(queryable: Queryable, table: string): Promise<boolean> {
	const result = await queryable.query<{ table_name: string | null }>(
		"SELECT to_regclass($1) AS table_name",
		[table],
	);
	return Boolean(result.rows[0]?.table_name);
}

async function readMeta(
	queryable: Queryable,
	tables: StoreV2TableNames,
): Promise<Map<string, unknown>> {
	if (!(await tableExists(queryable, tables.meta))) return new Map();
	const result = await queryable.query<MetaRow>(
		`SELECT key, value FROM ${tables.meta}`,
	);
	return new Map(result.rows.map((row) => [row.key, row.value]));
}

async function existingStoreV2Tables(
	queryable: Queryable,
	tables: StoreV2TableNames,
): Promise<string[]> {
	const existing: string[] = [];
	for (const table of Object.values(tables)) {
		if (await tableExists(queryable, table)) existing.push(table);
	}
	return existing;
}

function phaseFromMeta(meta: Map<string, unknown>): StoreV2Phase {
	const phase = meta.get(META_PHASE);
	if (phase === undefined) return "absent";
	if (phase === "shadow" || phase === "hybrid" || phase === "disabled") return phase;
	throw new StoreV2MigrationError(
		"STORE_V2_PHASE_INVALID",
		"The store-v2 phase marker is invalid.",
	);
}

function numberFromMeta(value: unknown): number | null {
	if (typeof value === "number" && Number.isSafeInteger(value)) return value;
	if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
	return null;
}

async function readSnapshot(
	queryable: Queryable,
	snapshotTable: string,
	lock = false,
): Promise<{ snapshot: DataStoreSnapshot; revision: number }> {
	const result = await queryable.query<SnapshotRow>(
		`SELECT data, revision FROM ${snapshotTable} WHERE id = 1${lock ? " FOR UPDATE" : ""}`,
	);
	const row = result.rows[0];
	if (!row?.data) {
		throw new StoreV2MigrationError(
			"STORE_V2_SNAPSHOT_MISSING",
			"The authoritative management snapshot row is missing.",
		);
	}
	return {
		snapshot: normalizeSnapshot(cloneSnapshot(row.data)),
		revision: Number(row.revision ?? 0),
	};
}

async function relationalCollections(
	queryable: Queryable,
	tables: StoreV2TableNames,
): Promise<Record<StoreV2Collection, StoreV2Resource[]> | null> {
	for (const collection of STORE_V2_COLLECTIONS) {
		if (!(await tableExists(queryable, tables[collection]))) return null;
	}

	const projects = await queryable.query<ProjectRow>(
		`SELECT * FROM ${tables.projects}`,
	);
	const environments = await queryable.query<EnvironmentRow>(
		`SELECT * FROM ${tables.environments}`,
	);
	const principals = await queryable.query<PrincipalRow>(
		`SELECT * FROM ${tables.principals}`,
	);
	const organizations = await queryable.query<OrganizationRow>(
		`SELECT * FROM ${tables.organizations}`,
	);
	const events = await readStoreV2Events(queryable, tables);
	return {
		projects: projects.rows.map(mapProject),
		environments: environments.rows.map(mapEnvironment),
		principals: principals.rows.map(mapPrincipal),
		organizations: organizations.rows.map(mapOrganization),
		events,
	};
}

async function buildStatus(
	queryable: Queryable,
	tables: StoreV2TableNames,
	snapshotTable: string,
): Promise<StoreV2Status> {
	const { snapshot, revision } = await readSnapshot(queryable, snapshotTable);
	const meta = await readMeta(queryable, tables);
	const phase = phaseFromMeta(meta);
	const relational =
		phase === "absent" ? null : await relationalCollections(queryable, tables);
	const selected = selectedCollections(
		phase === "hybrid" && relational
			? { ...snapshot, events: relational.events as AuditEvent[] }
			: snapshot,
	);
	const collections = Object.fromEntries(
		STORE_V2_COLLECTIONS.map((collection) => [
			collection,
			compareStoreV2Collections(
				selected[collection],
				relational?.[collection] ?? null,
			),
		]),
	) as Record<StoreV2Collection, StoreV2CollectionStatus>;
	const schemaVersion =
		numberFromMeta(meta.get(META_SCHEMA_VERSION)) === STORE_V2_SCHEMA_VERSION
			? STORE_V2_SCHEMA_VERSION
			: null;
	const relationalRevision = numberFromMeta(meta.get(META_SNAPSHOT_REVISION));

	return {
		schemaVersion,
		phase,
		snapshotRevision: revision,
		relationalRevision,
		consistent:
			phase !== "absent" &&
			schemaVersion === STORE_V2_SCHEMA_VERSION &&
			relationalRevision === revision &&
			STORE_V2_COLLECTIONS.every(
				(collection) => collections[collection].consistent,
			) && (phase !== "hybrid" || snapshot.events.length === 0),
		authoritativeCollections: phase === "hybrid" ? ["events"] : [],
		collections,
	};
}

async function writeMeta(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	key: string,
	value: unknown,
): Promise<void> {
	await client.query(
		`INSERT INTO ${tables.meta} (key, value, updated_at)
		 VALUES ($1, $2::jsonb, now())
		 ON CONFLICT (key) DO UPDATE
		 SET value = EXCLUDED.value, updated_at = now()`,
		[key, JSON.stringify(value)],
	);
}

async function replaceAll(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	snapshot: DataStoreSnapshot,
	revision: number,
): Promise<void> {
	await client.query(`DELETE FROM ${tables.principals}`);
	await client.query(`DELETE FROM ${tables.organizations}`);
	await client.query(`DELETE FROM ${tables.environments}`);
	await client.query(`DELETE FROM ${tables.projects}`);

	await client.query(
		`INSERT INTO ${tables.projects} (id, name, slug, created_at, updated_at)
		 SELECT item.id, item.name, item.slug,
		        item.created_at::timestamptz, item.updated_at::timestamptz
		 FROM jsonb_to_recordset($1::jsonb)
		 AS item(id text, name text, slug text, created_at text, updated_at text)`,
		[
			JSON.stringify(
				snapshot.projects.map((project) => ({
					id: project.id,
					name: project.name,
					slug: project.slug,
					created_at: project.createdAt,
					updated_at: project.updatedAt,
				})),
			),
		],
	);
	await client.query(
		`INSERT INTO ${tables.environments}
		 (id, project_id, name, slug, kind, created_at, updated_at)
		 SELECT item.id, item.project_id, item.name, item.slug, item.kind,
		        item.created_at::timestamptz, item.updated_at::timestamptz
		 FROM jsonb_to_recordset($1::jsonb)
		 AS item(id text, project_id text, name text, slug text, kind text,
		         created_at text, updated_at text)`,
		[
			JSON.stringify(
				snapshot.environments.map((environment) => ({
					id: environment.id,
					project_id: environment.projectId,
					name: environment.name,
					slug: environment.slug,
					kind: environment.kind,
					created_at: environment.createdAt,
					updated_at: environment.updatedAt,
				})),
			),
		],
	);
	await client.query(
		`INSERT INTO ${tables.principals}
		 (id, project_id, environment_id, email, name, status, external_id,
		  created_at, updated_at)
		 SELECT item.id, item.project_id, item.environment_id, item.email,
		        item.name, item.status, item.external_id,
		        item.created_at::timestamptz, item.updated_at::timestamptz
		 FROM jsonb_to_recordset($1::jsonb)
		 AS item(id text, project_id text, environment_id text, email text,
		         name text, status text, external_id text, created_at text,
		         updated_at text)`,
		[
			JSON.stringify(
				snapshot.principals.map((principal) => ({
					id: principal.id,
					project_id: principal.projectId,
					environment_id: principal.environmentId,
					email: principal.email,
					name: principal.name,
					status: principal.status,
					external_id: principal.externalId ?? null,
					created_at: principal.createdAt,
					updated_at: principal.updatedAt,
				})),
			),
		],
	);
	await client.query(
		`INSERT INTO ${tables.organizations}
		 (id, project_id, environment_id, name, slug, status, external_id,
		  created_at, updated_at)
		 SELECT item.id, item.project_id, item.environment_id, item.name,
		        item.slug, item.status, item.external_id,
		        item.created_at::timestamptz, item.updated_at::timestamptz
		 FROM jsonb_to_recordset($1::jsonb)
		 AS item(id text, project_id text, environment_id text, name text,
		         slug text, status text, external_id text, created_at text,
		         updated_at text)`,
		[
			JSON.stringify(
				snapshot.organizations.map((organization) => ({
					id: organization.id,
					project_id: organization.projectId,
					environment_id: organization.environmentId,
					name: organization.name,
					slug: organization.slug,
					status: organization.status,
					external_id: organization.externalId ?? null,
					created_at: organization.createdAt,
					updated_at: organization.updatedAt,
				})),
			),
		],
	);
	await replaceStoreV2Events(client, tables, snapshot.events, revision);
}

function changedResources<T extends { id: string }>(
	before: readonly T[],
	after: readonly T[],
): { deletedIds: string[]; upserted: T[] } {
	const previous = new Map(before.map((resource) => [resource.id, stableJson(resource)]));
	const nextIds = new Set(after.map((resource) => resource.id));
	return {
		deletedIds: before
			.filter((resource) => !nextIds.has(resource.id))
			.map((resource) => resource.id),
		upserted: after.filter(
			(resource) => previous.get(resource.id) !== stableJson(resource),
		),
	};
}

async function deleteIds(
	client: pg.PoolClient,
	table: string,
	ids: string[],
): Promise<void> {
	if (ids.length === 0) return;
	await client.query(`DELETE FROM ${table} WHERE id = ANY($1::text[])`, [ids]);
}

async function neutralizeUniqueValues(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	input: {
		projectIds: string[];
		principalIds: string[];
		organizationIds: string[];
	},
): Promise<void> {
	if (input.projectIds.length > 0) {
		await client.query(
			`UPDATE ${tables.projects}
			 SET name = chr(1) || 'clearance-shadow-' || md5(id || '-' || txid_current()::text),
			     slug = chr(1) || 'clearance-shadow-' || md5(id || '-' || txid_current()::text)
			 WHERE id = ANY($1::text[])`,
			[input.projectIds],
		);
	}
	if (input.principalIds.length > 0) {
		await client.query(
			`UPDATE ${tables.principals}
			 SET email = chr(1) || 'clearance-shadow-' || md5(id || '-' || txid_current()::text) || '@invalid',
			     status = 'deleted'
			 WHERE id = ANY($1::text[])`,
			[input.principalIds],
		);
	}
	if (input.organizationIds.length > 0) {
		await client.query(
			`UPDATE ${tables.organizations}
			 SET slug = chr(1) || 'clearance-shadow-' || md5(id || '-' || txid_current()::text),
			     status = 'archived'
			 WHERE id = ANY($1::text[])`,
			[input.organizationIds],
		);
	}
}

async function syncDiff(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	before: DataStoreSnapshot,
	after: DataStoreSnapshot,
): Promise<void> {
	const projects = changedResources(before.projects, after.projects);
	const environments = changedResources(before.environments, after.environments);
	const principals = changedResources(before.principals, after.principals);
	const organizations = changedResources(
		before.organizations,
		after.organizations,
	);
	const previousEnvironments = new Map(
		before.environments.map((environment) => [environment.id, environment]),
	);
	const reparentedEnvironmentIds = environments.upserted
		.filter(
			(environment) =>
				previousEnvironments.get(environment.id)?.projectId !== undefined &&
				previousEnvironments.get(environment.id)?.projectId !== environment.projectId,
		)
		.map((environment) => environment.id);
	if (reparentedEnvironmentIds.length > 0) {
		await client.query(
			`DELETE FROM ${tables.principals} WHERE environment_id = ANY($1::text[])`,
			[reparentedEnvironmentIds],
		);
		await client.query(
			`DELETE FROM ${tables.organizations} WHERE environment_id = ANY($1::text[])`,
			[reparentedEnvironmentIds],
		);
		for (const principal of after.principals) {
			if (
				reparentedEnvironmentIds.includes(principal.environmentId) &&
				!principals.upserted.some((candidate) => candidate.id === principal.id)
			) principals.upserted.push(principal);
		}
		for (const organization of after.organizations) {
			if (
				reparentedEnvironmentIds.includes(organization.environmentId) &&
				!organizations.upserted.some((candidate) => candidate.id === organization.id)
			) organizations.upserted.push(organization);
		}
	}

	await deleteIds(client, tables.principals, principals.deletedIds);
	await deleteIds(client, tables.organizations, organizations.deletedIds);
	await neutralizeUniqueValues(client, tables, {
		projectIds: [
			...new Set([
				...projects.upserted.map((project) => project.id),
				...projects.deletedIds,
			]),
		],
		principalIds: principals.upserted.map((principal) => principal.id),
		organizationIds: organizations.upserted.map(
			(organization) => organization.id,
		),
	});

	for (const project of projects.upserted) {
		await client.query(
			`INSERT INTO ${tables.projects} (id, name, slug, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (id) DO UPDATE SET
			 name = EXCLUDED.name, slug = EXCLUDED.slug,
			 created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at`,
			[project.id, project.name, project.slug, project.createdAt, project.updatedAt],
		);
	}
	for (const environment of environments.upserted) {
		await client.query(
			`INSERT INTO ${tables.environments}
			 (id, project_id, name, slug, kind, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)
			 ON CONFLICT (id) DO UPDATE SET
			 project_id = EXCLUDED.project_id, name = EXCLUDED.name,
			 slug = EXCLUDED.slug, kind = EXCLUDED.kind,
			 created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at`,
			[
				environment.id,
				environment.projectId,
				environment.name,
				environment.slug,
				environment.kind,
				environment.createdAt,
				environment.updatedAt,
			],
		);
	}
	for (const principal of principals.upserted) {
		await client.query(
			`INSERT INTO ${tables.principals}
			 (id, project_id, environment_id, email, name, status, external_id,
			  created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (id) DO UPDATE SET
			 project_id = EXCLUDED.project_id,
			 environment_id = EXCLUDED.environment_id,
			 email = EXCLUDED.email, name = EXCLUDED.name,
			 status = EXCLUDED.status, external_id = EXCLUDED.external_id,
			 created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at`,
			[
				principal.id,
				principal.projectId,
				principal.environmentId,
				principal.email,
				principal.name,
				principal.status,
				principal.externalId ?? null,
				principal.createdAt,
				principal.updatedAt,
			],
		);
	}
	for (const organization of organizations.upserted) {
		await client.query(
			`INSERT INTO ${tables.organizations}
			 (id, project_id, environment_id, name, slug, status, external_id,
			  created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 ON CONFLICT (id) DO UPDATE SET
			 project_id = EXCLUDED.project_id,
			 environment_id = EXCLUDED.environment_id,
			 name = EXCLUDED.name, slug = EXCLUDED.slug,
			 status = EXCLUDED.status, external_id = EXCLUDED.external_id,
			 created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at`,
			[
				organization.id,
				organization.projectId,
				organization.environmentId,
				organization.name,
				organization.slug,
				organization.status,
				organization.externalId ?? null,
				organization.createdAt,
				organization.updatedAt,
			],
		);
	}

	await deleteIds(client, tables.environments, environments.deletedIds);
	await deleteIds(client, tables.projects, projects.deletedIds);
}

export class PgStoreV2Shadow implements StoreV2MigrationControl {
	readonly tables: StoreV2TableNames;

	constructor(
		private readonly pool: pg.Pool,
		private readonly snapshotTable: string,
		prefix: string,
	) {
		this.tables = storeV2TableNames(prefix);
	}

	async plan(): Promise<StoreV2Plan> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
			const { snapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
			);
			const meta = await readMeta(client, this.tables);
			const plan = planStoreV2Snapshot(snapshot, revision, phaseFromMeta(meta));
			await client.query("COMMIT");
			return plan;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	async status(): Promise<StoreV2Status> {
		return this.readStatus();
	}

	async loadSnapshot(): Promise<{
		snapshot: DataStoreSnapshot;
		storedSnapshot: DataStoreSnapshot;
		revision: number;
		phase: StoreV2Phase;
	}> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
			const { snapshot: storedSnapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
			);
			const meta = await readMeta(client, this.tables);
			const phase = phaseFromMeta(meta);
			if (
				phase === "hybrid" &&
				numberFromMeta(meta.get(META_SNAPSHOT_REVISION)) !== revision
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_REVISION_DIVERGED",
					"Store-v2 revision does not match the management snapshot.",
				);
			}
			const snapshot = phase === "hybrid"
				? { ...cloneSnapshot(storedSnapshot), events: await readStoreV2Events(client, this.tables) }
				: storedSnapshot;
			await client.query("COMMIT");
			return { snapshot, storedSnapshot, revision, phase };
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	async eventsAreAuthoritative(): Promise<boolean> {
		const meta = await readMeta(this.pool, this.tables);
		return phaseFromMeta(meta) === "hybrid";
	}

	async transactionPhase(queryable: Queryable): Promise<StoreV2Phase> {
		return phaseFromMeta(await readMeta(queryable, this.tables));
	}

	async materializeEvents(queryable: Queryable): Promise<AuditEvent[]> {
		return readStoreV2Events(queryable, this.tables);
	}

	async listEventsPage(
		input: Parameters<StoreV2EventReader["listPage"]>[0],
	): Promise<{ events: AuditEvent[]; hasMore: boolean }> {
		if (!(await this.eventsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_EVENTS_NOT_AUTHORITATIVE",
				"Store-v2 events are not relational-authoritative.",
			);
		}
		return listStoreV2EventsPage(this.pool, this.tables, input);
	}

	async verify(): Promise<StoreV2Status> {
		return this.readStatus();
	}

	private async readStatus(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
			const status = await buildStatus(client, this.tables, this.snapshotTable);
			await client.query("COMMIT");
			return status;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	async apply(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const { snapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
				true,
			);
			const existingTables = await existingStoreV2Tables(client, this.tables);
			const existingMeta = await readMeta(client, this.tables);
			const existingPhase = phaseFromMeta(existingMeta);
			if (existingTables.length > 0 && existingPhase === "absent") {
				throw new StoreV2MigrationError(
					"STORE_V2_SCHEMA_COLLISION",
					"Store-v2 target tables already exist without Clearance ownership metadata.",
				);
			}
			const existingVersion = numberFromMeta(
				existingMeta.get(META_SCHEMA_VERSION),
			);
			if (
				(existingPhase !== "absent" || existingVersion !== null) &&
				existingVersion !== STORE_V2_SCHEMA_VERSION
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_SCHEMA_VERSION_INVALID",
					"The existing store-v2 schema version is incompatible with this release.",
				);
			}
			const plan = planStoreV2Snapshot(
				snapshot,
				revision,
				existingPhase,
			);
			if (!plan.canApply) {
				throw new StoreV2MigrationError(
					"STORE_V2_PREFLIGHT_FAILED",
					`Store-v2 preflight found ${plan.blockerCount} blocker(s).`,
					plan.blockers,
				);
			}

			for (const statement of storeV2SchemaStatements(this.tables)) {
				await client.query(statement);
			}
			if (existingPhase === "hybrid") {
				const status = await buildStatus(client, this.tables, this.snapshotTable);
				await client.query("COMMIT");
				return status;
			}
			await replaceAll(client, this.tables, snapshot, revision);
			await writeMeta(
				client,
				this.tables,
				META_SCHEMA_VERSION,
				STORE_V2_SCHEMA_VERSION,
			);
			await writeMeta(client, this.tables, META_PHASE, "shadow");
			await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, revision);
			await writeMeta(
				client,
				this.tables,
				META_COLLECTIONS,
				STORE_V2_COLLECTIONS,
			);
			await writeMeta(client, this.tables, META_ENABLED_AT, new Date().toISOString());

			const status = await buildStatus(client, this.tables, this.snapshotTable);
			if (!status.consistent) {
				throw new StoreV2MigrationError(
					"STORE_V2_BACKFILL_DIVERGED",
					"Store-v2 backfill verification diverged from the authoritative snapshot.",
				);
			}
			await client.query("COMMIT");
			return status;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	async disable(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await readSnapshot(client, this.snapshotTable, true);
			const meta = await readMeta(client, this.tables);
			if (phaseFromMeta(meta) === "hybrid") {
				throw new StoreV2MigrationError(
					"STORE_V2_EVENTS_ROLLBACK_REQUIRED",
					"Roll back authoritative events before disabling store-v2.",
				);
			}
			if (phaseFromMeta(meta) !== "absent") {
				await writeMeta(client, this.tables, META_PHASE, "disabled");
			}
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		return this.readStatus();
	}

	async cutoverEvents(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const { snapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
				true,
			);
			const meta = await readMeta(client, this.tables);
			if (phaseFromMeta(meta) !== "shadow") {
				throw new StoreV2MigrationError(
					"STORE_V2_EVENTS_CUTOVER_PHASE_INVALID",
					"Event cutover requires an active verified shadow.",
				);
			}
			const status = await buildStatus(client, this.tables, this.snapshotTable);
			if (!status.consistent) {
				throw new StoreV2MigrationError(
					"STORE_V2_DIVERGENCE",
					"Store-v2 shadow data diverged before event cutover.",
				);
			}
			const nextRevision = revision + 1;
			await client.query(
				`UPDATE ${this.snapshotTable}
				 SET data = $1::jsonb, revision = $2, updated_at = now()
				 WHERE id = 1`,
				[JSON.stringify({ ...snapshot, events: [] }), nextRevision],
			);
			await writeMeta(client, this.tables, META_PHASE, "hybrid");
			await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, nextRevision);
			await writeMeta(client, this.tables, META_AUTHORITATIVE_COLLECTIONS, ["events"]);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		return this.readStatus();
	}

	async rollbackEvents(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const { snapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
				true,
			);
			const meta = await readMeta(client, this.tables);
			if (phaseFromMeta(meta) !== "hybrid") {
				throw new StoreV2MigrationError(
					"STORE_V2_EVENTS_ROLLBACK_PHASE_INVALID",
					"Event rollback requires relational-authoritative events.",
				);
			}
			const events = await readStoreV2Events(client, this.tables);
			const nextRevision = revision + 1;
			await client.query(
				`UPDATE ${this.snapshotTable}
				 SET data = $1::jsonb, revision = $2, updated_at = now()
				 WHERE id = 1`,
				[JSON.stringify({ ...snapshot, events }), nextRevision],
			);
			await writeMeta(client, this.tables, META_PHASE, "shadow");
			await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, nextRevision);
			await writeMeta(client, this.tables, META_AUTHORITATIVE_COLLECTIONS, []);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		return this.readStatus();
	}

	async syncTransaction(
		client: pg.PoolClient,
		before: DataStoreSnapshot,
		after: DataStoreSnapshot,
		revision: number,
		appendedEvents?: readonly AuditEvent[],
	): Promise<StoreV2SyncResult> {
		const meta = await readMeta(client, this.tables);
		const phase = phaseFromMeta(meta);
		if (phase !== "shadow" && phase !== "hybrid") {
			return { phase, persistedSnapshot: after };
		}
		if (
			numberFromMeta(meta.get(META_SCHEMA_VERSION)) !== STORE_V2_SCHEMA_VERSION
		) {
			throw new StoreV2MigrationError(
				"STORE_V2_SCHEMA_VERSION_INVALID",
				"The active store-v2 shadow schema version is invalid.",
			);
		}
		const relationalRevision = numberFromMeta(meta.get(META_SNAPSHOT_REVISION));
		if (relationalRevision !== revision - 1) {
			throw new StoreV2MigrationError(
				"STORE_V2_REVISION_DIVERGED",
				"Store-v2 shadow revision does not match the authoritative pre-mutation revision; reconcile before writing.",
			);
		}
		await syncDiff(client, this.tables, before, after);
		let eventDelta: StoreV2EventDelta | undefined;
		let persistedSnapshot = after;
		if (phase === "shadow") {
			await replaceStoreV2Events(client, this.tables, after.events, revision);
		} else {
			let appended: AuditEvent[];
			if (appendedEvents !== undefined) {
				appended = [...appendedEvents];
				if (new Set(appended.map((event) => event.id)).size !== appended.length) {
					throw new StoreV2MigrationError(
						"STORE_V2_EVENTS_HISTORY_MUTATION",
						"Authoritative event mutations cannot contain duplicate appended ids.",
					);
				}
			} else {
				const prependedCount = after.events.length - before.events.length;
				let canonicalPrepend = prependedCount >= 0;
				for (let index = 0; canonicalPrepend && index < before.events.length; index++) {
					canonicalPrepend =
						after.events[prependedCount + index]?.id === before.events[index]?.id;
				}
				if (canonicalPrepend) {
					appended = after.events.slice(0, prependedCount);
					if (new Set(appended.map((event) => event.id)).size !== appended.length) {
						throw new StoreV2MigrationError(
							"STORE_V2_EVENTS_HISTORY_MUTATION",
							"Authoritative event mutations cannot contain duplicate appended ids.",
						);
					}
				} else {
					const beforeById = new Map(
						before.events.map((event) => [event.id, stableJson(event)]),
					);
					const afterById = new Map(
						after.events.map((event) => [event.id, stableJson(event)]),
					);
					if (afterById.size !== after.events.length) {
						throw new StoreV2MigrationError(
							"STORE_V2_EVENTS_HISTORY_MUTATION",
							"Authoritative event mutations cannot contain duplicate historical ids.",
						);
					}
					for (const event of before.events) {
						if (afterById.get(event.id) !== beforeById.get(event.id)) {
							throw new StoreV2MigrationError(
								"STORE_V2_EVENTS_HISTORY_MUTATION",
								"Authoritative event history is append-only.",
							);
						}
					}
					appended = after.events.filter((event) => !beforeById.has(event.id));
				}
			}
			eventDelta = await appendStoreV2Events(
				client,
				this.tables,
				appended,
				revision,
			);
			persistedSnapshot = { ...after, events: [] };
		}
		await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, revision);
		return { phase, persistedSnapshot, ...(eventDelta ? { eventDelta } : {}) };
	}
}
