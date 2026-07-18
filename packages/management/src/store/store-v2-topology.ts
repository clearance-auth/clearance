import type pg from "pg";
import type { PageCursorKey } from "../services/pagination.js";
import type { ResourceScope } from "../services/scope.js";
import type { Environment, Organization, Project } from "../types/resources.js";
import type {
	StoreV2Collection,
	StoreV2TopologyRepository,
} from "./types.js";
import {
	STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY,
	parseStoreV2AuthoritySet,
	parseStoreV2MetadataInteger,
	type StoreV2TableNames,
} from "./store-v2-schema.js";

type Queryable = pg.Pool | pg.PoolClient;

type ProjectRow = {
	id: string;
	name: string;
	slug: string;
	created_at: Date | string;
	updated_at: Date | string;
};

type EnvironmentRow = ProjectRow & {
	project_id: string;
	kind: Environment["kind"];
};

type OrganizationRow = ProjectRow & {
	project_id: string;
	environment_id: string;
	status: Organization["status"];
	external_id: string | null;
};

export type StoreV2TopologyState = {
	revision: number;
	projectCount: number;
	environmentCount: number;
	organizationCount: number;
};

export type StoreV2TopologyCountDelta = Omit<
	StoreV2TopologyState,
	"revision"
>;

export const STORE_V2_TOPOLOGY_AUTHORITY_VERSION = 1 as const;
export const STORE_V2_TOPOLOGY_AUTHORITY_VERSION_META_KEY =
	"store_v2_topology_authority_version";
export const STORE_V2_TOPOLOGY_STATE_META_KEY = "store_v2_topology_state";

export class StoreV2TopologyAuthorityError extends Error {
	constructor(
		readonly code: string,
		message: string,
	) {
		super(message);
		this.name = "StoreV2TopologyAuthorityError";
	}
}

function iso(value: Date | string): string {
	return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
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
	return { ...mapProject(row), projectId: row.project_id, kind: row.kind };
}

function mapOrganization(row: OrganizationRow): Organization {
	return {
		...mapProject(row),
		projectId: row.project_id,
		environmentId: row.environment_id,
		status: row.status,
		...(row.external_id === null ? {} : { externalId: row.external_id }),
	};
}

function assertLimit(value: number): void {
	if (!Number.isSafeInteger(value) || value < 1 || value > 1_000) {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_TOPOLOGY_PAGE_LIMIT_INVALID",
			"Topology page limit must be an integer between 1 and 1000.",
		);
	}
}

function normalizeCursor(value: PageCursorKey): PageCursorKey {
	const timestamp = new Date(value.createdAt);
	if (
		typeof value.id !== "string" ||
		!value.id ||
		value.id.length > 1_024 ||
		value.id.includes("\0") ||
		!Number.isFinite(timestamp.getTime()) ||
		timestamp.toISOString() !== value.createdAt
	) {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_TOPOLOGY_CURSOR_INVALID",
			"The topology page cursor is invalid.",
		);
	}
	return { createdAt: timestamp.toISOString(), id: value.id };
}

export async function readStoreV2TopologyState(
	queryable: Queryable,
	tables: StoreV2TableNames,
	forUpdate = false,
): Promise<StoreV2TopologyState | null> {
	const result = await queryable.query<{ value: unknown }>(
		`SELECT value FROM ${tables.meta} WHERE key = $1${forUpdate ? " FOR UPDATE" : ""}`,
		[STORE_V2_TOPOLOGY_STATE_META_KEY],
	);
	if (!result.rows[0]) return null;
	const value = result.rows[0].value;
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_TOPOLOGY_STATE_INVALID",
			"Topology authority state metadata is invalid.",
		);
	}
	const raw = value as Record<string, unknown>;
	const state = {
		revision: parseStoreV2MetadataInteger(raw.revision),
		projectCount: parseStoreV2MetadataInteger(raw.projectCount),
		environmentCount: parseStoreV2MetadataInteger(raw.environmentCount),
		organizationCount: parseStoreV2MetadataInteger(raw.organizationCount),
	};
	if (Object.values(state).some((child) => child === null)) {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_TOPOLOGY_STATE_INVALID",
			"Topology authority state metadata is invalid.",
		);
	}
	return state as StoreV2TopologyState;
}

export async function writeStoreV2TopologyState(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	state: StoreV2TopologyState,
): Promise<void> {
	if (Object.values(state).some((value) => parseStoreV2MetadataInteger(value) === null)) {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_TOPOLOGY_STATE_INVALID",
			"Topology authority state metadata is invalid.",
		);
	}
	await client.query(
		`INSERT INTO ${tables.meta} (key, value, updated_at)
		 VALUES ($1, $2::jsonb, now())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		[STORE_V2_TOPOLOGY_STATE_META_KEY, JSON.stringify(state)],
	);
}

export async function advanceStoreV2TopologyState(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	delta: StoreV2TopologyCountDelta,
): Promise<StoreV2TopologyState> {
	const current = await readStoreV2TopologyState(client, tables, true);
	if (!current || current.revision === Number.MAX_SAFE_INTEGER) {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_TOPOLOGY_STATE_INVALID",
			"Topology authority state cannot advance safely.",
		);
	}
	const next = {
		revision: current.revision + 1,
		projectCount: current.projectCount + delta.projectCount,
		environmentCount: current.environmentCount + delta.environmentCount,
		organizationCount: current.organizationCount + delta.organizationCount,
	};
	if (Object.values(next).some((value) => !Number.isSafeInteger(value) || value < 0)) {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_TOPOLOGY_STATE_INVALID",
			"Topology authority state cannot advance safely.",
		);
	}
	await writeStoreV2TopologyState(client, tables, next);
	return next;
}

export async function storeV2TopologyIsAuthoritative(
	queryable: Queryable,
	tables: StoreV2TableNames,
): Promise<boolean> {
	const result = await queryable.query<{ value: unknown }>(
		`SELECT value FROM ${tables.meta} WHERE key = $1`,
		[STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY],
	);
	try {
		const authority = result.rows[0]
			? parseStoreV2AuthoritySet(result.rows[0].value)
			: [];
		return (["projects", "environments", "organizations"] as StoreV2Collection[])
			.every((collection) => authority.includes(collection));
	} catch {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_AUTHORITY_SET_INVALID",
			"Store-v2 authority metadata is invalid.",
		);
	}
}

async function assertAuthority(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
): Promise<void> {
	if (!(await storeV2TopologyIsAuthoritative(client, tables))) {
		throw new StoreV2TopologyAuthorityError(
			"STORE_V2_TOPOLOGY_NOT_AUTHORITATIVE",
			"Topology writes require relational topology authority.",
		);
	}
}

export class PgStoreV2TopologyRepository {
	readonly capability: StoreV2TopologyRepository;
	private active = true;
	private mutated = false;
	private insertedProjects = 0;
	private insertedEnvironments = 0;
	private insertedOrganizations = 0;
	private readonly issued = new Set<Promise<unknown>>();

	constructor(
		private readonly client: pg.PoolClient,
		private readonly tables: StoreV2TableNames,
		private readonly trackIssued = true,
	) {
		this.capability = Object.freeze({
			authoritative: true as const,
			getProjectById: (id: string) => this.getProjectById(id),
			getEnvironment: (input: { projectId: string; id: string }) =>
				this.getEnvironment(input),
			getOrganization: (input: { scope: ResourceScope; id: string }) =>
				this.getOrganization(input),
			listProjectsPage: (input: { limit: number; cursor?: PageCursorKey }) =>
				this.listProjectsPage(input),
			listEnvironmentsPage: (input: {
				projectId: string;
				limit: number;
				cursor?: PageCursorKey;
			}) => this.listEnvironmentsPage(input),
			listOrganizationsPage: (input: {
				scope: ResourceScope;
				limit: number;
				cursor?: PageCursorKey;
				includeArchived?: boolean;
			}) => this.listOrganizationsPage(input),
			upsertProject: (input: Project) => this.upsertProject(input),
			upsertEnvironment: (input: Environment) => this.upsertEnvironment(input),
			upsertOrganization: (input: Organization) => this.upsertOrganization(input),
		});
	}

	revoke(): void {
		this.active = false;
	}

	async settleIssued(): Promise<void> {
		const settled = await Promise.allSettled([...this.issued]);
		this.issued.clear();
		const failed = settled.find(
			(result): result is PromiseRejectedResult => result.status === "rejected",
		);
		if (failed) throw failed.reason;
	}

	async finalizeState(): Promise<StoreV2TopologyState | null> {
		return this.mutated
			? advanceStoreV2TopologyState(this.client, this.tables, {
				projectCount: this.insertedProjects,
				environmentCount: this.insertedEnvironments,
				organizationCount: this.insertedOrganizations,
			})
			: readStoreV2TopologyState(this.client, this.tables);
	}

	/** Whether this capability executed a row-changing topology upsert. */
	hasMutations(): boolean {
		return this.mutated;
	}

	private issue<T>(fn: () => Promise<T>): Promise<T> {
		if (!this.active) {
			return Promise.reject(
				new StoreV2TopologyAuthorityError(
					"STORE_V2_TOPOLOGY_REPOSITORY_REVOKED",
					"The topology transaction capability is no longer active.",
				),
			);
		}
		const pending = Promise.resolve().then(fn);
		if (!this.trackIssued) return pending;
		pending.then(() => undefined, () => undefined);
		this.issued.add(pending);
		return pending;
	}

	getProjectById(id: string): Promise<Project | null> {
		return this.issue(async () => {
			const result = await this.client.query<ProjectRow & { inserted: boolean }>(
				`SELECT id, name, slug, created_at, updated_at
				 FROM ${this.tables.projects} WHERE id = $1`,
				[id],
			);
			return result.rows[0] ? mapProject(result.rows[0]) : null;
		});
	}

	getEnvironment(input: { projectId: string; id: string }): Promise<Environment | null> {
		return this.issue(async () => {
			const result = await this.client.query<EnvironmentRow>(
				`SELECT id, project_id, name, slug, kind, created_at, updated_at
				 FROM ${this.tables.environments}
				 WHERE project_id = $1 AND id = $2`,
				[input.projectId, input.id],
			);
			return result.rows[0] ? mapEnvironment(result.rows[0]) : null;
		});
	}

	getOrganization(input: { scope: ResourceScope; id: string }): Promise<Organization | null> {
		return this.issue(async () => {
			const result = await this.client.query<OrganizationRow>(
				`SELECT id, project_id, environment_id, name, slug, status, external_id,
				        created_at, updated_at
				 FROM ${this.tables.organizations}
				 WHERE project_id = $1 AND environment_id = $2 AND id = $3`,
				[input.scope.projectId, input.scope.environmentId, input.id],
			);
			return result.rows[0] ? mapOrganization(result.rows[0]) : null;
		});
	}

	listProjectsPage(input: {
		limit: number;
		cursor?: PageCursorKey;
	}): Promise<{ projects: Project[]; hasMore: boolean }> {
		return this.issue(async () => {
			assertLimit(input.limit);
			const values: unknown[] = [];
			let where = "";
			if (input.cursor) {
				const key = normalizeCursor(input.cursor);
				values.push(key.createdAt, key.id);
				where = " WHERE (created_at, id) > ($1::timestamptz, $2)";
			}
			values.push(input.limit + 1);
			const result = await this.client.query<ProjectRow & { inserted: boolean }>(
				`SELECT id, name, slug, created_at, updated_at
				 FROM ${this.tables.projects}${where}
				 ORDER BY created_at ASC, id ASC
				 LIMIT $${values.length}`,
				values,
			);
			return {
				projects: result.rows.slice(0, input.limit).map(mapProject),
				hasMore: result.rows.length > input.limit,
			};
		});
	}

	listEnvironmentsPage(input: {
		projectId: string;
		limit: number;
		cursor?: PageCursorKey;
	}): Promise<{ environments: Environment[]; hasMore: boolean }> {
		return this.issue(async () => {
			assertLimit(input.limit);
			const values: unknown[] = [input.projectId];
			let keyset = "";
			if (input.cursor) {
				const key = normalizeCursor(input.cursor);
				values.push(key.createdAt, key.id);
				keyset = " AND (created_at, id) > ($2::timestamptz, $3)";
			}
			values.push(input.limit + 1);
			const result = await this.client.query<EnvironmentRow>(
				`SELECT id, project_id, name, slug, kind, created_at, updated_at
				 FROM ${this.tables.environments}
				 WHERE project_id = $1${keyset}
				 ORDER BY created_at ASC, id ASC
				 LIMIT $${values.length}`,
				values,
			);
			return {
				environments: result.rows.slice(0, input.limit).map(mapEnvironment),
				hasMore: result.rows.length > input.limit,
			};
		});
	}

	listOrganizationsPage(input: {
		scope: ResourceScope;
		limit: number;
		cursor?: PageCursorKey;
		includeArchived?: boolean;
	}): Promise<{ organizations: Organization[]; hasMore: boolean }> {
		return this.issue(async () => {
			assertLimit(input.limit);
			const values: unknown[] = [input.scope.projectId, input.scope.environmentId];
			let conditions = "project_id = $1 AND environment_id = $2";
			if (!input.includeArchived) conditions += " AND status <> 'archived'";
			if (input.cursor) {
				const key = normalizeCursor(input.cursor);
				values.push(key.createdAt, key.id);
				conditions += ` AND (created_at, id) > ($${values.length - 1}::timestamptz, $${values.length})`;
			}
			values.push(input.limit + 1);
			const result = await this.client.query<OrganizationRow>(
				`SELECT id, project_id, environment_id, name, slug, status, external_id,
				        created_at, updated_at
				 FROM ${this.tables.organizations}
				 WHERE ${conditions}
				 ORDER BY created_at ASC, id ASC
				 LIMIT $${values.length}`,
				values,
			);
			return {
				organizations: result.rows.slice(0, input.limit).map(mapOrganization),
				hasMore: result.rows.length > input.limit,
			};
		});
	}

	upsertProject(input: Project): Promise<Project> {
		const value = structuredClone(input);
		return this.issue(async () => {
			await assertAuthority(this.client, this.tables);
			const result = await this.client.query<
				ProjectRow & { inserted: boolean }
			>(
				`INSERT INTO ${this.tables.projects} (id, name, slug, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (id) DO UPDATE SET
				   name = EXCLUDED.name, slug = EXCLUDED.slug,
				   created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
				 WHERE (${this.tables.projects}.name, ${this.tables.projects}.slug,
				        ${this.tables.projects}.created_at, ${this.tables.projects}.updated_at)
				       IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.slug,
				                         EXCLUDED.created_at, EXCLUDED.updated_at)
				 RETURNING id, name, slug, created_at, updated_at, xmax = 0 AS inserted`,
				[value.id, value.name, value.slug, value.createdAt, value.updatedAt],
			);
			if (result.rows[0]) {
				this.mutated = true;
				if (result.rows[0].inserted) this.insertedProjects += 1;
				return mapProject(result.rows[0]);
			}
			return (await this.getProjectById(value.id))!;
		});
	}

	upsertEnvironment(input: Environment): Promise<Environment> {
		const value = structuredClone(input);
		return this.issue(async () => {
			await assertAuthority(this.client, this.tables);
			const result = await this.client.query<
				EnvironmentRow & { inserted: boolean }
			>(
				`INSERT INTO ${this.tables.environments} (id, project_id, name, slug, kind, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7)
				 ON CONFLICT (id) DO UPDATE SET
				   project_id = EXCLUDED.project_id, name = EXCLUDED.name,
				   slug = EXCLUDED.slug, kind = EXCLUDED.kind,
				   created_at = EXCLUDED.created_at, updated_at = EXCLUDED.updated_at
				 WHERE (${this.tables.environments}.project_id, ${this.tables.environments}.name,
				        ${this.tables.environments}.slug, ${this.tables.environments}.kind,
				        ${this.tables.environments}.created_at, ${this.tables.environments}.updated_at)
				       IS DISTINCT FROM (EXCLUDED.project_id, EXCLUDED.name, EXCLUDED.slug,
				                         EXCLUDED.kind, EXCLUDED.created_at, EXCLUDED.updated_at)
				 RETURNING id, project_id, name, slug, kind, created_at, updated_at,
				           xmax = 0 AS inserted`,
				[value.id, value.projectId, value.name, value.slug, value.kind, value.createdAt, value.updatedAt],
			);
			if (result.rows[0]) {
				this.mutated = true;
				if (result.rows[0].inserted) this.insertedEnvironments += 1;
				return mapEnvironment(result.rows[0]);
			}
			return (await this.getEnvironment({ projectId: value.projectId, id: value.id }))!;
		});
	}

	upsertOrganization(input: Organization): Promise<Organization> {
		const value = structuredClone(input);
		return this.issue(async () => {
			await assertAuthority(this.client, this.tables);
			const result = await this.client.query<
				OrganizationRow & { inserted: boolean }
			>(
				`INSERT INTO ${this.tables.organizations}
				 (id, project_id, environment_id, name, slug, status, external_id, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				 ON CONFLICT (id) DO UPDATE SET
				   project_id = EXCLUDED.project_id, environment_id = EXCLUDED.environment_id,
				   name = EXCLUDED.name, slug = EXCLUDED.slug, status = EXCLUDED.status,
				   external_id = EXCLUDED.external_id, created_at = EXCLUDED.created_at,
				   updated_at = EXCLUDED.updated_at
				 WHERE (${this.tables.organizations}.project_id, ${this.tables.organizations}.environment_id,
				        ${this.tables.organizations}.name, ${this.tables.organizations}.slug,
				        ${this.tables.organizations}.status, ${this.tables.organizations}.external_id,
				        ${this.tables.organizations}.created_at, ${this.tables.organizations}.updated_at)
				       IS DISTINCT FROM (EXCLUDED.project_id, EXCLUDED.environment_id,
				                         EXCLUDED.name, EXCLUDED.slug, EXCLUDED.status,
				                         EXCLUDED.external_id, EXCLUDED.created_at, EXCLUDED.updated_at)
				 RETURNING id, project_id, environment_id, name, slug, status, external_id,
				           created_at, updated_at, xmax = 0 AS inserted`,
				[
					value.id,
					value.projectId,
					value.environmentId,
					value.name,
					value.slug,
					value.status,
					value.externalId ?? null,
					value.createdAt,
					value.updatedAt,
				],
			);
			if (result.rows[0]) {
				this.mutated = true;
				if (result.rows[0].inserted) this.insertedOrganizations += 1;
				return mapOrganization(result.rows[0]);
			}
			return (await this.getOrganization({
				scope: {
					projectId: value.projectId,
					environmentId: value.environmentId,
				},
				id: value.id,
			}))!;
		});
	}
}
