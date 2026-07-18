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
	type StoreV2PrincipalReader,
	type StoreV2Status,
} from "./types.js";
import {
	STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY,
	STORE_V2_PRINCIPAL_AUTHORITY_VERSION,
	STORE_V2_PRINCIPAL_AUTHORITY_VERSION_META_KEY,
	STORE_V2_PRINCIPAL_REVISION_META_KEY,
	STORE_V2_PRINCIPAL_STATE_META_KEY,
	STORE_V2_SCHEMA_VERSION,
	canonicalStoreV2AuthoritySet,
	parseStoreV2MetadataInteger,
	parseStoreV2AuthoritySet,
	storeV2PrincipalProjectionGuardStatements,
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
import {
	findActiveStoreV2PrincipalByEmail,
	findActiveStoreV2PrincipalByExternalId,
	getStoreV2PrincipalById,
	listStoreV2PrincipalsPage,
	mapStoreV2PrincipalRow,
	advanceStoreV2PrincipalState,
	readStoreV2PrincipalState,
	readStoreV2PrincipalRevision,
	readStoreV2Principals,
	writeStoreV2PrincipalState,
	type StoreV2PrincipalRow,
} from "./store-v2-principals.js";
import {
	STORE_V2_TOPOLOGY_AUTHORITY_VERSION,
	STORE_V2_TOPOLOGY_AUTHORITY_VERSION_META_KEY,
	STORE_V2_TOPOLOGY_STATE_META_KEY,
	advanceStoreV2TopologyState,
	readStoreV2TopologyState,
	storeV2TopologyIsAuthoritative,
	writeStoreV2TopologyState,
	type StoreV2TopologyState,
} from "./store-v2-topology.js";

const MAX_DIFFERING_IDS = 20;
const META_SCHEMA_VERSION = "store_v2_schema_version";
const META_PHASE = "store_v2_phase";
const META_SNAPSHOT_REVISION = "store_v2_snapshot_revision";
const META_COLLECTIONS = "store_v2_collections";
const META_ENABLED_AT = "store_v2_enabled_at";
const META_AUTHORITATIVE_COLLECTIONS =
	STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY;

type StoreV2Resource = Project | Environment | Principal | Organization | AuditEvent;
type Queryable = pg.Pool | pg.PoolClient;

export interface StoreV2SyncResult {
	phase: StoreV2Phase;
	persistedSnapshot: DataStoreSnapshot;
	authoritativeCollections: StoreV2Collection[];
	principalRevision: number | null;
	topologyState?: StoreV2TopologyState | null;
	eventDelta?: StoreV2EventDelta;
}

export interface StoreV2LoadResult {
	snapshot: DataStoreSnapshot;
	storedSnapshot: DataStoreSnapshot;
	principalCount: number;
	revision: number;
	phase: StoreV2Phase;
	authoritativeCollections: StoreV2Collection[];
	principalRevision: number | null;
	topologyState: StoreV2TopologyState | null;
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
	addDuplicateBlockers(
		blockers,
		"principals",
		"STORE_V2_DUPLICATE_ACTIVE_PRINCIPAL_EXTERNAL_ID",
		snapshot.principals,
		(principal) =>
			principal.status === "deleted" || principal.externalId === undefined
				? null
				: `${principal.projectId}\u0000${principal.environmentId}\u0000${principal.externalId}`,
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

function authoritativeCollectionsFromMeta(
	meta: Map<string, unknown>,
	phase: StoreV2Phase,
): StoreV2Collection[] {
	if (phase !== "hybrid") return [];
	try {
		const collections = parseStoreV2AuthoritySet(
			meta.get(META_AUTHORITATIVE_COLLECTIONS),
		);
		if (collections.length === 0 || !collections.includes("events")) {
			throw new Error("STORE_V2_AUTHORITY_SET_INVALID");
		}
		return collections;
	} catch {
		throw new StoreV2MigrationError(
			"STORE_V2_AUTHORITY_SET_INVALID",
			"Store-v2 authoritative collection metadata is invalid.",
		);
	}
}

const numberFromMeta = parseStoreV2MetadataInteger;

function incrementStoreV2Revision(value: number): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new StoreV2MigrationError(
			"STORE_V2_REVISION_INVALID",
			"The store-v2 revision is invalid.",
		);
	}
	if (value === Number.MAX_SAFE_INTEGER) {
		throw new StoreV2MigrationError(
			"STORE_V2_REVISION_EXHAUSTED",
			"The store-v2 revision capacity is exhausted.",
		);
	}
	return value + 1;
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
	const revision = parseStoreV2MetadataInteger(row.revision);
	if (revision === null) {
		throw new StoreV2MigrationError(
			"STORE_V2_SNAPSHOT_REVISION_INVALID",
			"The management snapshot revision is invalid.",
		);
	}
	return {
		snapshot: normalizeSnapshot(cloneSnapshot(row.data)),
		revision,
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
	const principals = await readStoreV2Principals(queryable, tables);
	const organizations = await queryable.query<OrganizationRow>(
		`SELECT * FROM ${tables.organizations}`,
	);
	const events = await readStoreV2Events(queryable, tables);
	return {
		projects: projects.rows.map(mapProject),
		environments: environments.rows.map(mapEnvironment),
		principals,
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
	const authoritativeCollections = authoritativeCollectionsFromMeta(meta, phase);
	const relational =
		phase === "absent" ? null : await relationalCollections(queryable, tables);
	let materialized = snapshot;
	if (relational && authoritativeCollections.length > 0) {
		materialized = {
			...snapshot,
			...(authoritativeCollections.includes("events")
				? { events: relational.events as AuditEvent[] }
				: {}),
			...(authoritativeCollections.includes("principals")
				? { principals: relational.principals as Principal[] }
				: {}),
				...(( ["projects", "environments", "organizations"] as StoreV2Collection[])
					.every((collection) => authoritativeCollections.includes(collection))
					? {
						projects: relational.projects as Project[],
						environments: relational.environments as Environment[],
						organizations: relational.organizations as Organization[],
					}
					: {}),
		};
	}
	const selected = selectedCollections(materialized);
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
	const principalState = phase === "absent"
		? null
		: await readStoreV2PrincipalState(queryable, tables);
	const principalRevision = principalState?.revision ?? null;
	const topologyState = phase === "absent"
		? null
		: await readStoreV2TopologyState(queryable, tables);
	const topologyRevision = topologyState?.revision ?? null;
	const topologyStateConsistent =
		phase === "absent" ||
		(topologyState !== null &&
			topologyState.projectCount === (relational?.projects.length ?? 0) &&
			topologyState.environmentCount ===
				(relational?.environments.length ?? 0) &&
			topologyState.organizationCount ===
				(relational?.organizations.length ?? 0));
	const principalStateConsistent =
		phase === "absent" ||
		(principalState !== null &&
			principalState.count === (relational?.principals.length ?? 0));
	const authoritativeProjectionsEmpty = authoritativeCollections.every(
		(collection) =>
			(collection !== "events" || snapshot.events.length === 0) &&
			(collection !== "principals" || snapshot.principals.length === 0) &&
			(collection !== "projects" || snapshot.projects.length === 0) &&
			(collection !== "environments" || snapshot.environments.length === 0) &&
			(collection !== "organizations" || snapshot.organizations.length === 0),
	);

	return {
		schemaVersion,
		phase,
		snapshotRevision: revision,
		relationalRevision,
		principalRevision,
		topologyRevision,
		consistent:
			phase !== "absent" &&
			schemaVersion === STORE_V2_SCHEMA_VERSION &&
			relationalRevision === revision &&
			principalRevision !== null &&
			principalStateConsistent &&
			topologyStateConsistent &&
			STORE_V2_COLLECTIONS.every(
				(collection) => collections[collection].consistent,
			) && authoritativeProjectionsEmpty,
		authoritativeCollections,
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
	authoritativeCollections: readonly StoreV2Collection[] = [],
): Promise<void> {
	const principalsAuthoritative = authoritativeCollections.includes("principals");
	const topologyAuthoritative = [
		"projects",
		"environments",
		"organizations",
	].every((collection) =>
		authoritativeCollections.includes(collection as StoreV2Collection),
	);
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
	if (principalsAuthoritative && reparentedEnvironmentIds.length > 0) {
		throw new StoreV2MigrationError(
			"STORE_V2_PRINCIPAL_ENVIRONMENT_REPARENT_REQUIRES_TYPED_MUTATION",
			"Environment reparenting requires a typed relational principal mutation while principals are authoritative.",
		);
	}
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

	if (!principalsAuthoritative) {
		await deleteIds(client, tables.principals, principals.deletedIds);
	}
	if (!topologyAuthoritative) await deleteIds(client, tables.organizations, organizations.deletedIds);
	await neutralizeUniqueValues(client, tables, {
		projectIds: topologyAuthoritative ? [] : [
			...new Set([
				...projects.upserted.map((project) => project.id),
				...projects.deletedIds,
			]),
		],
		principalIds: principalsAuthoritative
			? []
			: principals.upserted.map((principal) => principal.id),
		organizationIds: topologyAuthoritative ? [] : organizations.upserted.map(
			(organization) => organization.id,
		),
	});

	if (!topologyAuthoritative) for (const project of projects.upserted) {
		await client.query(
			`INSERT INTO ${tables.projects} (id, name, slug, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (id) DO UPDATE SET
			 name = EXCLUDED.name, slug = EXCLUDED.slug,
			 created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at`,
			[project.id, project.name, project.slug, project.createdAt, project.updatedAt],
		);
	}
	if (!topologyAuthoritative) for (const environment of environments.upserted) {
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
	if (!principalsAuthoritative) {
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
	}
	if (!topologyAuthoritative) for (const organization of organizations.upserted) {
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

	if (!topologyAuthoritative) {
		await deleteIds(client, tables.environments, environments.deletedIds);
		await deleteIds(client, tables.projects, projects.deletedIds);
	}
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

	async loadSnapshot(_cache?: {
		principalRevision: number | null;
		principalCount: number;
	}): Promise<StoreV2LoadResult> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
			const { snapshot: storedSnapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
			);
			const meta = await readMeta(client, this.tables);
			const phase = phaseFromMeta(meta);
			const authoritativeCollections = authoritativeCollectionsFromMeta(meta, phase);
			if (
				phase === "hybrid" &&
				numberFromMeta(meta.get(META_SNAPSHOT_REVISION)) !== revision
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_REVISION_DIVERGED",
					"Store-v2 revision does not match the management snapshot.",
				);
			}
			const principalState = phase === "absent"
				? null
				: await readStoreV2PrincipalState(client, this.tables);
			const principalRevision = principalState?.revision ?? null;
			if (phase !== "absent" && principalRevision === null) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPAL_REVISION_INVALID",
					"Store-v2 principal revision metadata is missing or invalid.",
				);
			}
			const topologyState = phase === "absent"
				? null
				: await readStoreV2TopologyState(client, this.tables);
			if (phase !== "absent" && !topologyState) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_STATE_INVALID",
					"Store-v2 topology state metadata is missing or invalid.",
				);
			}
			let snapshot = storedSnapshot;
			let principalCount = storedSnapshot.principals.length;
			if (authoritativeCollections.length > 0) {
				if (authoritativeCollections.includes("principals")) {
					if (!principalState) {
						throw new StoreV2MigrationError(
							"STORE_V2_PRINCIPAL_STATE_INVALID",
							"Store-v2 principal state metadata is missing or invalid.",
						);
					}
					principalCount = principalState.count;
				}
					snapshot = {
						...cloneSnapshot(storedSnapshot),
					...(authoritativeCollections.includes("events")
						? { events: await readStoreV2Events(client, this.tables) }
						: {}),
						...(authoritativeCollections.includes("principals")
							? { principals: [] }
							: {}),
						...(( ["projects", "environments", "organizations"] as StoreV2Collection[])
							.every((collection) => authoritativeCollections.includes(collection))
							? { projects: [], environments: [], organizations: [] }
							: {}),
					};
			}
			await client.query("COMMIT");
			return {
					snapshot,
					storedSnapshot,
					principalCount,
				revision,
				phase,
				authoritativeCollections,
				principalRevision,
				topologyState,
			};
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	async eventsAreAuthoritative(): Promise<boolean> {
		const meta = await readMeta(this.pool, this.tables);
		const phase = phaseFromMeta(meta);
		return authoritativeCollectionsFromMeta(meta, phase).includes("events");
	}

	async principalsAreAuthoritative(): Promise<boolean> {
		const meta = await readMeta(this.pool, this.tables);
		const phase = phaseFromMeta(meta);
		return authoritativeCollectionsFromMeta(meta, phase).includes("principals");
	}

	async topologyIsAuthoritative(): Promise<boolean> {
		return storeV2TopologyIsAuthoritative(this.pool, this.tables);
	}


	async transactionPhase(queryable: Queryable): Promise<StoreV2Phase> {
		return phaseFromMeta(await readMeta(queryable, this.tables));
	}

	async lockPrincipalAuthority(client: pg.PoolClient): Promise<void> {
		await client.query(
			"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
			[`clearance:store-v2:principals:${this.snapshotTable}`],
		);
	}

	async lockPrincipalAuthorityShared(client: pg.PoolClient): Promise<void> {
		await client.query(
			"SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))",
			[`clearance:store-v2:principals:${this.snapshotTable}`],
		);
	}

	async transactionAuthoritativeCollections(
		queryable: Queryable,
	): Promise<StoreV2Collection[]> {
		const meta = await readMeta(queryable, this.tables);
		return authoritativeCollectionsFromMeta(meta, phaseFromMeta(meta));
	}

	async materializeEvents(queryable: Queryable): Promise<AuditEvent[]> {
		return readStoreV2Events(queryable, this.tables);
	}

	async countPrincipals(queryable: Queryable): Promise<number> {
		const result = await queryable.query<{ count: string }>(
			`SELECT count(*)::text AS count FROM ${this.tables.principals}`,
		);
		const count = parseStoreV2MetadataInteger(result.rows[0]?.count);
		if (count === null) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPAL_COUNT_INVALID",
				"Store-v2 principal count is invalid.",
			);
		}
		return count;
	}

	async principalRevision(queryable: Queryable): Promise<number | null> {
		return readStoreV2PrincipalRevision(queryable, this.tables);
	}

	async principalState(queryable: Queryable) {
		return readStoreV2PrincipalState(queryable, this.tables);
	}

	async getPrincipalById(
		input: Parameters<StoreV2PrincipalReader["getById"]>[0],
	): Promise<Principal | null> {
		if (!(await this.principalsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
				"Store-v2 principals are not relational-authoritative.",
			);
		}
		return getStoreV2PrincipalById(this.pool, this.tables, input);
	}

	async findActivePrincipalByEmail(
		input: Parameters<StoreV2PrincipalReader["findActiveByEmail"]>[0],
	): Promise<Principal | null> {
		if (!(await this.principalsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
				"Store-v2 principals are not relational-authoritative.",
			);
		}
		return findActiveStoreV2PrincipalByEmail(this.pool, this.tables, input);
	}

	async findActivePrincipalByExternalId(
		input: Parameters<StoreV2PrincipalReader["findActiveByExternalId"]>[0],
	): Promise<Principal | null> {
		if (!(await this.principalsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
				"Store-v2 principals are not relational-authoritative.",
			);
		}
		return findActiveStoreV2PrincipalByExternalId(this.pool, this.tables, input);
	}

	async listPrincipalsPage(
		input: Parameters<StoreV2PrincipalReader["listPage"]>[0],
	): Promise<{ principals: Principal[]; hasMore: boolean }> {
		if (!(await this.principalsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
				"Store-v2 principals are not relational-authoritative.",
			);
		}
		return listStoreV2PrincipalsPage(this.pool, this.tables, input);
	}

	async listActivePrincipalSessionsPage(
		input: Parameters<NonNullable<StoreV2PrincipalReader["listActiveSessionsPage"]>>[0],
	): Promise<Awaited<ReturnType<NonNullable<StoreV2PrincipalReader["listActiveSessionsPage"]>>>> {
		if (!(await this.principalsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
				"Store-v2 principals are not relational-authoritative.",
			);
		}
		if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 1_000) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPAL_PAGE_LIMIT_INVALID",
				"Session page limit must be an integer between 1 and 1000.",
			);
		}
		const params: unknown[] = [input.scope.projectId, input.scope.environmentId];
		let keyset = "";
		if (input.cursor) {
			const timestamp = new Date(input.cursor.createdAt);
			if (!Number.isFinite(timestamp.getTime()) || !input.cursor.id) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPAL_CURSOR_INVALID",
					"The session page cursor is invalid.",
				);
			}
			params.push(input.cursor.createdAt, input.cursor.id);
			keyset = `AND (s.created_at, s.id) < ($3::timestamptz, $4)`;
		}
		params.push(input.limit + 1);
		const result = await this.pool.query<{
			session_id: string;
			created_at: Date | string;
			created_at_raw: string;
			expires_at: Date | string | null;
			ip_address: string | null;
			user_agent: string | null;
			id: string;
			project_id: string;
			environment_id: string;
			email: string;
			name: string;
			status: Principal["status"];
			external_id: string | null;
			principal_created_at: Date | string;
			principal_updated_at: Date | string;
		}>(
			`WITH snapshot_sessions AS (
			   SELECT item.value
			   FROM ${this.snapshotTable} snapshot,
			        LATERAL jsonb_array_elements(snapshot.data->'sessions') item(value)
			   WHERE snapshot.id = 1 AND item.value->>'status' = 'active'
			 ), session_rows AS (
			   SELECT runtime.id, runtime."userId" AS user_id,
			          runtime."createdAt" AS created_at,
			          runtime."createdAt"::text AS created_at_raw,
			          runtime."expiresAt" AS expires_at,
			          runtime."ipAddress" AS ip_address,
			          runtime."userAgent" AS user_agent
			   FROM session runtime
			   WHERE runtime."expiresAt" > now()
			   UNION ALL
			   SELECT value->>'id', value->>'principalId',
			          (value->>'createdAt')::timestamptz, value->>'createdAt',
			          NULL::timestamptz, NULL::text, NULL::text
			   FROM snapshot_sessions
			   WHERE NOT EXISTS (
			     SELECT 1 FROM session runtime WHERE runtime.id = value->>'id'
			   )
			 )
			 SELECT s.id AS session_id, s.created_at, s.created_at_raw, s.expires_at,
			        s.ip_address, s.user_agent,
			        p.id, p.project_id, p.environment_id, p.email, p.name, p.status,
			        p.external_id, p.created_at AS principal_created_at,
			        p.updated_at AS principal_updated_at
			 FROM session_rows s
			 JOIN ${this.tables.principals} p ON p.id = s.user_id
			 WHERE p.project_id = $1 AND p.environment_id = $2
			   AND p.status <> 'deleted' ${keyset}
			 ORDER BY s.created_at DESC, s.id DESC
			 LIMIT $${params.length}`,
			params,
		);
		return {
			sessions: result.rows.slice(0, input.limit).map((row) => ({
				id: row.session_id,
				principal: {
					id: row.id,
					projectId: row.project_id,
					environmentId: row.environment_id,
					email: row.email,
					name: row.name,
					status: row.status,
					...(row.external_id === null ? {} : { externalId: row.external_id }),
					createdAt: iso(row.principal_created_at),
					updatedAt: iso(row.principal_updated_at),
				},
				createdAt: iso(row.created_at),
				cursorCreatedAt: row.created_at_raw,
				...(row.expires_at ? { expiresAt: iso(row.expires_at) } : {}),
				...(row.ip_address ? { ipAddress: row.ip_address } : {}),
				...(row.user_agent ? { userAgent: row.user_agent } : {}),
			})),
			hasMore: result.rows.length > input.limit,
		};
	}

	async listPrincipalsForExport(
		input: Parameters<NonNullable<StoreV2PrincipalReader["listForExport"]>>[0],
	): Promise<Awaited<ReturnType<NonNullable<StoreV2PrincipalReader["listForExport"]>>>> {
		if (!(await this.principalsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
				"Store-v2 principals are not relational-authoritative.",
			);
		}
		if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 1_000) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPAL_PAGE_LIMIT_INVALID",
				"Principal export limit must be an integer between 1 and 1000.",
			);
		}
		const params: unknown[] = [input.scope.projectId, input.scope.environmentId];
		let status = "";
		if (input.status) {
			params.push(input.status);
			status = `AND status = $3`;
		}
		params.push(input.limit + 1);
		const result = await this.pool.query<StoreV2PrincipalRow>(
			`SELECT id, project_id, environment_id, email, name, status, external_id,
			        created_at, updated_at
			 FROM ${this.tables.principals}
			 WHERE project_id = $1 AND environment_id = $2
			   AND status <> 'deleted' ${status}
			 ORDER BY lower(email) ASC, id ASC
			 LIMIT $${params.length}`,
			params,
		);
		return {
			principals: result.rows.slice(0, input.limit).map(mapStoreV2PrincipalRow),
			hasMore: result.rows.length > input.limit,
		};
	}

	async countPrincipalsByScope(
		input: Parameters<NonNullable<StoreV2PrincipalReader["countByScope"]>>[0],
	): Promise<{ total: number; active: number }> {
		if (!(await this.principalsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
				"Store-v2 principals are not relational-authoritative.",
			);
		}
		const result = await this.pool.query<{ total: string; active: string }>(
			`SELECT count(*) FILTER (WHERE status <> 'deleted')::text AS total,
			        count(*) FILTER (WHERE status = 'active')::text AS active
			 FROM ${this.tables.principals}
			 WHERE project_id = $1 AND environment_id = $2`,
			[input.scope.projectId, input.scope.environmentId],
		);
		return {
			total: Number(result.rows[0]?.total ?? 0),
			active: Number(result.rows[0]?.active ?? 0),
		};
	}

	async countActivePrincipalSessions(
		input: Parameters<NonNullable<StoreV2PrincipalReader["countActiveSessions"]>>[0],
	): Promise<number> {
		if (!(await this.principalsAreAuthoritative())) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
				"Store-v2 principals are not relational-authoritative.",
			);
		}
		const result = await this.pool.query<{ count: string }>(
			`WITH snapshot_sessions AS (
			   SELECT item.value
			   FROM ${this.snapshotTable} snapshot,
			        LATERAL jsonb_array_elements(snapshot.data->'sessions') item(value)
			   WHERE snapshot.id = 1 AND item.value->>'status' = 'active'
			 ), session_rows AS (
			   SELECT runtime.id, runtime."userId" AS user_id
			   FROM session runtime WHERE runtime."expiresAt" > now()
			   UNION ALL
			   SELECT value->>'id', value->>'principalId'
			   FROM snapshot_sessions
			   WHERE NOT EXISTS (
			     SELECT 1 FROM session runtime WHERE runtime.id = value->>'id'
			   )
			 )
			 SELECT count(*)::text AS count
			 FROM session_rows s
			 JOIN ${this.tables.principals} p ON p.id = s.user_id
			 WHERE p.project_id = $1 AND p.environment_id = $2
			   AND p.status <> 'deleted'`,
			[input.scope.projectId, input.scope.environmentId],
		);
		return Number(result.rows[0]?.count ?? 0);
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
			await this.lockPrincipalAuthority(client);
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
				existingVersion !== 1 &&
				existingVersion !== STORE_V2_SCHEMA_VERSION
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_SCHEMA_VERSION_INVALID",
					"The existing store-v2 schema version is incompatible with this release.",
				);
			}
			const existingPrincipalAuthorityVersion = numberFromMeta(
				existingMeta.get(STORE_V2_PRINCIPAL_AUTHORITY_VERSION_META_KEY),
			);
			if (
				existingPrincipalAuthorityVersion !== null &&
				existingPrincipalAuthorityVersion !== STORE_V2_PRINCIPAL_AUTHORITY_VERSION
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPAL_AUTHORITY_VERSION_INVALID",
					"The existing principal authority capability is incompatible with this release.",
				);
			}
			if (
				existingMeta.has(STORE_V2_PRINCIPAL_REVISION_META_KEY) &&
				numberFromMeta(existingMeta.get(STORE_V2_PRINCIPAL_REVISION_META_KEY)) === null
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPAL_REVISION_INVALID",
					"The existing principal revision marker is invalid.",
				);
			}
			if (
				existingMeta.has(STORE_V2_PRINCIPAL_STATE_META_KEY) &&
				!(await readStoreV2PrincipalState(client, this.tables))
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPAL_STATE_INVALID",
					"The existing principal authority state is invalid.",
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
			for (const statement of storeV2PrincipalProjectionGuardStatements(
				this.tables,
				this.snapshotTable,
			)) {
				await client.query(statement);
			}
			await writeMeta(
				client,
				this.tables,
				META_SCHEMA_VERSION,
				STORE_V2_SCHEMA_VERSION,
			);
			await writeMeta(
				client,
				this.tables,
				STORE_V2_PRINCIPAL_AUTHORITY_VERSION_META_KEY,
				STORE_V2_PRINCIPAL_AUTHORITY_VERSION,
			);
			await writeMeta(
				client,
				this.tables,
				STORE_V2_TOPOLOGY_AUTHORITY_VERSION_META_KEY,
				STORE_V2_TOPOLOGY_AUTHORITY_VERSION,
			);
			const existingAuthorities = existingPhase === "hybrid"
				? authoritativeCollectionsFromMeta(existingMeta, existingPhase)
				: [];
			await writeMeta(
				client,
				this.tables,
				META_AUTHORITATIVE_COLLECTIONS,
				existingAuthorities,
			);
			if (existingPhase === "hybrid") {
				const currentState = await readStoreV2PrincipalState(client, this.tables);
				if (!currentState) {
					const count = await client.query<{ count: string }>(
						`SELECT count(*)::text AS count FROM ${this.tables.principals}`,
					);
					const parsedCount = parseStoreV2MetadataInteger(count.rows[0]?.count);
					if (parsedCount === null) {
						throw new StoreV2MigrationError(
							"STORE_V2_PRINCIPAL_COUNT_INVALID",
							"Store-v2 principal count is invalid.",
						);
					}
					await writeStoreV2PrincipalState(client, this.tables, {
						revision:
							numberFromMeta(
								existingMeta.get(STORE_V2_PRINCIPAL_REVISION_META_KEY),
							) ?? revision,
						count: parsedCount,
					});
				}
				if (!(await readStoreV2TopologyState(client, this.tables))) {
					const counts = await client.query<{ projects: string; environments: string; organizations: string }>(
						`SELECT (SELECT count(*)::text FROM ${this.tables.projects}) projects,
						        (SELECT count(*)::text FROM ${this.tables.environments}) environments,
						        (SELECT count(*)::text FROM ${this.tables.organizations}) organizations`,
					);
					await writeStoreV2TopologyState(client, this.tables, {
						revision,
						projectCount: Number(counts.rows[0]?.projects),
						environmentCount: Number(counts.rows[0]?.environments),
						organizationCount: Number(counts.rows[0]?.organizations),
					});
				}
				const status = await buildStatus(client, this.tables, this.snapshotTable);
				await client.query("COMMIT");
				return status;
			}
			await replaceAll(client, this.tables, snapshot, revision);
			await writeStoreV2PrincipalState(client, this.tables, {
				revision:
					numberFromMeta(existingMeta.get(STORE_V2_PRINCIPAL_REVISION_META_KEY)) ??
					revision,
				count: snapshot.principals.length,
			});
			await writeStoreV2TopologyState(client, this.tables, {
				revision,
				projectCount: snapshot.projects.length,
				environmentCount: snapshot.environments.length,
				organizationCount: snapshot.organizations.length,
			});
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
			await this.lockPrincipalAuthority(client);
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
			await this.lockPrincipalAuthority(client);
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
			const nextRevision = incrementStoreV2Revision(revision);
			await client.query(
				`UPDATE ${this.snapshotTable}
				 SET data = $1::jsonb, revision = $2, updated_at = now()
				 WHERE id = 1`,
				[JSON.stringify({ ...snapshot, events: [] }), nextRevision],
			);
			await writeMeta(client, this.tables, META_PHASE, "hybrid");
			await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, nextRevision);
			await writeMeta(
				client,
				this.tables,
				META_AUTHORITATIVE_COLLECTIONS,
				canonicalStoreV2AuthoritySet(["events"]),
			);
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
			await this.lockPrincipalAuthority(client);
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
			const authoritativeCollections = authoritativeCollectionsFromMeta(
				meta,
				"hybrid",
			);
			if (authoritativeCollections.includes("principals")) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPALS_ROLLBACK_REQUIRED",
					"Roll back relational principal authority before rolling back events.",
				);
			}
			const events = await readStoreV2Events(client, this.tables);
			const nextRevision = incrementStoreV2Revision(revision);
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

	/** Cut over principal authority after relational parity and capability checks. */
	async cutoverPrincipals(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await this.lockPrincipalAuthority(client);
			const { snapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
				true,
			);
			const meta = await readMeta(client, this.tables);
			const phase = phaseFromMeta(meta);
			const authoritativeCollections = authoritativeCollectionsFromMeta(meta, phase);
			if (
				phase !== "hybrid" ||
				!authoritativeCollections.includes("events") ||
				authoritativeCollections.includes("principals")
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPALS_CUTOVER_PHASE_INVALID",
					"Principal cutover requires relational-authoritative events and snapshot-authoritative principals.",
				);
			}
			if (
				numberFromMeta(meta.get(STORE_V2_PRINCIPAL_AUTHORITY_VERSION_META_KEY)) !==
				STORE_V2_PRINCIPAL_AUTHORITY_VERSION
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPAL_AUTHORITY_VERSION_INVALID",
					"Principal authority capability metadata is missing or invalid.",
				);
			}
			const status = await buildStatus(client, this.tables, this.snapshotTable);
			if (!status.consistent || !status.collections.principals.consistent) {
				throw new StoreV2MigrationError(
					"STORE_V2_DIVERGENCE",
					"Store-v2 principals diverged before principal cutover.",
				);
			}
			const principalRevision = await readStoreV2PrincipalRevision(
				client,
				this.tables,
			);
			if (principalRevision === null) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPAL_REVISION_INVALID",
					"Principal authority revision metadata is missing or invalid.",
				);
			}
			const nextRevision = incrementStoreV2Revision(revision);
			await client.query(
				`UPDATE ${this.snapshotTable}
				 SET data = $1::jsonb, revision = $2, updated_at = now()
				 WHERE id = 1`,
				[JSON.stringify({ ...snapshot, principals: [] }), nextRevision],
			);
			await writeMeta(
				client,
				this.tables,
				META_AUTHORITATIVE_COLLECTIONS,
				canonicalStoreV2AuthoritySet([
					...authoritativeCollections,
					"principals",
				]),
			);
			await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, nextRevision);
			await advanceStoreV2PrincipalState(
				client,
				this.tables,
				0,
			);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		return this.readStatus();
	}

	/** Reverse-materialize principals before returning authority to the snapshot. */
	async rollbackPrincipals(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await this.lockPrincipalAuthority(client);
			const { snapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
				true,
			);
			const meta = await readMeta(client, this.tables);
			const phase = phaseFromMeta(meta);
			const authoritativeCollections = authoritativeCollectionsFromMeta(meta, phase);
			if (phase !== "hybrid" || !authoritativeCollections.includes("principals")) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPALS_ROLLBACK_PHASE_INVALID",
					"Principal rollback requires relational-authoritative principals.",
				);
			}
			const principalRevision = await readStoreV2PrincipalRevision(
				client,
				this.tables,
			);
			if (principalRevision === null) {
				throw new StoreV2MigrationError(
					"STORE_V2_PRINCIPAL_REVISION_INVALID",
					"Principal authority revision metadata is missing or invalid.",
				);
			}
			const principals = await readStoreV2Principals(client, this.tables);
			const remainingAuthorities = canonicalStoreV2AuthoritySet(
				authoritativeCollections.filter(
					(collection) => collection !== "principals",
				),
			);
			const nextRevision = incrementStoreV2Revision(revision);
			// Remove authority first inside this transaction so the projection guard
			// permits the paired reverse materialization. Any later failure rolls both back.
			await client.query(
				"SELECT set_config('clearance.principal_authority_rollback', $1, true)",
				[String(STORE_V2_PRINCIPAL_AUTHORITY_VERSION)],
			);
			await writeMeta(
				client,
				this.tables,
				META_AUTHORITATIVE_COLLECTIONS,
				remainingAuthorities,
			);
			await client.query(
				`UPDATE ${this.snapshotTable}
				 SET data = $1::jsonb, revision = $2, updated_at = now()
				 WHERE id = 1`,
				[JSON.stringify({ ...snapshot, principals }), nextRevision],
			);
			const companionEmailTable = `${this.snapshotTable}_principal_email`;
			await client.query(`DELETE FROM ${companionEmailTable}`);
			await client.query(
				`INSERT INTO ${companionEmailTable}
				 (project_id, environment_id, email_lower, principal_id)
				 SELECT project_id, environment_id, lower(email), id
				 FROM ${this.tables.principals}
				 WHERE status <> 'deleted'`,
			);
			await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, nextRevision);
			await advanceStoreV2PrincipalState(
				client,
				this.tables,
				0,
			);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		return this.readStatus();
	}

	/** Move the complete project -> environment -> organization chain to SQL authority. */
	async cutoverTopology(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await this.lockPrincipalAuthority(client);
			const { snapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
				true,
			);
			const meta = await readMeta(client, this.tables);
			const phase = phaseFromMeta(meta);
			const authority = authoritativeCollectionsFromMeta(meta, phase);
			if (
				phase !== "hybrid" ||
				!authority.includes("events") ||
				["projects", "environments", "organizations"].some((collection) =>
					authority.includes(collection as StoreV2Collection),
				)
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_CUTOVER_PHASE_INVALID",
					"Topology cutover requires relational-authoritative events and snapshot-authoritative topology.",
				);
			}
			if (
				numberFromMeta(meta.get(STORE_V2_TOPOLOGY_AUTHORITY_VERSION_META_KEY)) !==
				STORE_V2_TOPOLOGY_AUTHORITY_VERSION
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_AUTHORITY_VERSION_INVALID",
					"Topology authority capability metadata is missing or invalid.",
				);
			}
			const status = await buildStatus(client, this.tables, this.snapshotTable);
			if (
				!status.consistent ||
				!["projects", "environments", "organizations"].every((collection) =>
					status.collections[collection as StoreV2Collection].consistent,
				)
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_DIVERGENCE",
					"Store-v2 topology diverged before cutover.",
				);
			}
			const nextRevision = incrementStoreV2Revision(revision);
			await client.query(
				`UPDATE ${this.snapshotTable}
				 SET data = $1::jsonb, revision = $2, updated_at = now()
				 WHERE id = 1`,
				[
					JSON.stringify({
						...snapshot,
						projects: [],
						environments: [],
						organizations: [],
					}),
					nextRevision,
				],
			);
			await writeMeta(
				client,
				this.tables,
				META_AUTHORITATIVE_COLLECTIONS,
				canonicalStoreV2AuthoritySet([
					...authority,
					"projects",
					"environments",
					"organizations",
				]),
			);
			await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, nextRevision);
			await advanceStoreV2TopologyState(client, this.tables, {
				projectCount: 0,
				environmentCount: 0,
				organizationCount: 0,
			});
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		return this.readStatus();
	}

	/** Reverse-materialize the relational topology before returning authority. */
	async rollbackTopology(): Promise<StoreV2Status> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await this.lockPrincipalAuthority(client);
			const { snapshot, revision } = await readSnapshot(
				client,
				this.snapshotTable,
				true,
			);
			const meta = await readMeta(client, this.tables);
			const phase = phaseFromMeta(meta);
			const authority = authoritativeCollectionsFromMeta(meta, phase);
			if (
				phase !== "hybrid" ||
				!["projects", "environments", "organizations"].every((collection) =>
					authority.includes(collection as StoreV2Collection),
				)
			) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_ROLLBACK_PHASE_INVALID",
					"Topology rollback requires relational topology authority.",
				);
			}
			const status = await buildStatus(client, this.tables, this.snapshotTable);
			if (!status.consistent) {
				throw new StoreV2MigrationError(
					"STORE_V2_DIVERGENCE",
					"Store-v2 topology diverged before rollback.",
				);
			}
			const nextRevision = incrementStoreV2Revision(revision);
			const topology = await relationalCollections(client, this.tables);
			if (!topology) {
				throw new StoreV2MigrationError(
					"STORE_V2_TOPOLOGY_MISSING",
					"Normalized topology rows are unavailable for rollback.",
				);
			}
			await client.query(
				`UPDATE ${this.snapshotTable}
				 SET data = $1::jsonb, revision = $2, updated_at = now()
				 WHERE id = 1`,
				[
					JSON.stringify({
						...snapshot,
						projects: topology.projects,
						environments: topology.environments,
						organizations: topology.organizations,
					}),
					nextRevision,
				],
			);
			await client.query(
				"SELECT set_config('clearance.topology_authority_rollback', $1, true)",
				[String(STORE_V2_TOPOLOGY_AUTHORITY_VERSION)],
			);
			await writeMeta(
				client,
				this.tables,
				META_AUTHORITATIVE_COLLECTIONS,
				canonicalStoreV2AuthoritySet(
					authority.filter(
						(collection) =>
							!["projects", "environments", "organizations"].includes(collection),
					),
				),
			);
			await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, nextRevision);
			await advanceStoreV2TopologyState(client, this.tables, {
				projectCount: 0,
				environmentCount: 0,
				organizationCount: 0,
			});
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
		const authoritativeCollections = authoritativeCollectionsFromMeta(meta, phase);
		let principalState = phase === "absent"
			? null
			: await readStoreV2PrincipalState(client, this.tables);
		let topologyState = phase === "absent"
			? null
			: await readStoreV2TopologyState(client, this.tables);
		if (phase !== "shadow" && phase !== "hybrid") {
			return {
				phase,
				persistedSnapshot: after,
				authoritativeCollections,
				principalRevision: principalState?.revision ?? null,
				topologyState,
			};
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
		if (
			authoritativeCollections.includes("principals") &&
			stableJson(before.principals) !== stableJson(after.principals)
		) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPALS_TYPED_MUTATION_REQUIRED",
				"Generic snapshot mutation cannot change relational-authoritative principals.",
			);
		}
		const topologyAuthoritative = [
			"projects",
			"environments",
			"organizations",
		].every((collection) =>
			authoritativeCollections.includes(collection as StoreV2Collection),
		);
		const topologyChanged =
			stableJson(before.projects) !== stableJson(after.projects) ||
			stableJson(before.environments) !== stableJson(after.environments) ||
			stableJson(before.organizations) !== stableJson(after.organizations);
		if (topologyAuthoritative && topologyChanged) {
			throw new StoreV2MigrationError(
				"STORE_V2_TOPOLOGY_TYPED_MUTATION_REQUIRED",
				"Generic snapshot mutation cannot change relational-authoritative topology.",
			);
		}
		await syncDiff(
			client,
			this.tables,
			before,
			after,
			authoritativeCollections,
		);
		if (
			!authoritativeCollections.includes("principals") &&
			stableJson(before.principals) !== stableJson(after.principals)
		) {
			principalState = await advanceStoreV2PrincipalState(
				client,
				this.tables,
				after.principals.length - before.principals.length,
			);
		} else {
			principalState = await readStoreV2PrincipalState(client, this.tables);
		}
		if (!principalState) {
			throw new StoreV2MigrationError(
				"STORE_V2_PRINCIPAL_STATE_INVALID",
				"Principal authority state metadata is missing or invalid.",
			);
		}
		if (!topologyAuthoritative && topologyChanged) {
			topologyState = await advanceStoreV2TopologyState(client, this.tables, {
				projectCount: after.projects.length - before.projects.length,
				environmentCount:
					after.environments.length - before.environments.length,
				organizationCount:
					after.organizations.length - before.organizations.length,
			});
		} else {
			topologyState = await readStoreV2TopologyState(client, this.tables);
		}
		if (!topologyState) {
			throw new StoreV2MigrationError(
				"STORE_V2_TOPOLOGY_STATE_INVALID",
				"Topology authority state metadata is missing or invalid.",
			);
		}
		let eventDelta: StoreV2EventDelta | undefined;
		let persistedSnapshot = after;
		if (!authoritativeCollections.includes("events")) {
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
		if (authoritativeCollections.includes("principals")) {
			persistedSnapshot = { ...persistedSnapshot, principals: [] };
		}
		if (topologyAuthoritative) {
			persistedSnapshot = {
				...persistedSnapshot,
				projects: [],
				environments: [],
				organizations: [],
			};
		}
		await writeMeta(client, this.tables, META_SNAPSHOT_REVISION, revision);
		return {
			phase,
			persistedSnapshot,
			authoritativeCollections,
			principalRevision: principalState.revision,
			topologyState,
			...(eventDelta ? { eventDelta } : {}),
		};
	}
}
