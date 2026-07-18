import { existsSync } from "node:fs";
import type {
	ManagementSnapshotReader,
	ManagementStore,
	ManagementUnitOfWork,
	StoreV2TopologyReader,
	StoreV2TopologyRepository,
} from "../store/types.js";
import {
	CLEARANCE_RELEASE_VERSION,
	correlationId,
	newId,
	nowIso,
	STORE_SCHEMA_VERSION,
} from "../store/json-store.js";
import type {
	AuditEvent,
	Environment,
	Organization,
	Principal,
	Project,
	SessionRecord,
} from "../types/resources.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { writeExportArtifact } from "./export-artifact.js";
import {
	decodePageCursor,
	encodePageCursor,
	normalizePageLimit,
	paginateByCreatedAt,
} from "./pagination.js";
import { redactRecord } from "./redact.js";
import {
	assertResourceInScope,
	resolveOperatorScope,
	scopeFilter,
	type ResourceScope,
} from "./scope.js";

function slugify(name: string): string {
	return name
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-|-$/g, "")
		.slice(0, 48);
}

function assertSnapshotPrincipalWriterDisabled(
	store: ManagementUnitOfWork,
	stage: string,
): void {
	const candidate = store as ManagementUnitOfWork &
		Partial<Pick<ManagementStore, "storeV2Principals">>;
	if (candidate.storeV2Principals?.authoritative) {
		throw new ClearanceError({
			code: "STORE_V2_PRINCIPALS_TYPED_MUTATION_REQUIRED",
			message: "Relational principal authority requires the coordinated principal writer.",
			stage,
			status: 409,
			remediation: "Use the management application or auth-coordinated user workflow.",
		});
	}
}

function principalReadView(store: ManagementStore): readonly Principal[] {
	if (store.storeV2Principals?.authoritative) {
		throw new ClearanceError({
			code: "STORE_V2_PRINCIPAL_READER_REQUIRED",
			message: "Relational principal authority requires a bounded reader.",
			stage: "principals.read",
			status: 500,
		});
	}
	return store.snapshot.principals;
}

const PROJECT_NAME_MAX_LENGTH = 120;
const ENVIRONMENT_KINDS: readonly Environment["kind"][] = [
	"development",
	"preview",
	"production",
];

function normalizedProjectName(name: string): string {
	return name.trim().replace(/\s+/g, " ");
}

/** Validate and normalize a project name without mutating the store. */
export function planProjectCreate(
	input: { name: string },
	existingProjects?: Project[],
): Pick<Project, "name" | "slug"> {
	const name = normalizedProjectName(input.name);
	if (!name) {
		throw new ClearanceError({
			code: "PROJECT_NAME_REQUIRED",
			message: "Project name is required.",
			stage: "project.create",
			remediation: "Pass a non-empty --name.",
		});
	}
	if (name.length > PROJECT_NAME_MAX_LENGTH) {
		throw new ClearanceError({
			code: "PROJECT_NAME_TOO_LONG",
			message: `Project name must be ${PROJECT_NAME_MAX_LENGTH} characters or fewer.`,
			stage: "project.create",
			remediation: "Use a shorter project name.",
		});
	}
	const slug = slugify(name);
	if (!slug) {
		throw new ClearanceError({
			code: "PROJECT_SLUG_INVALID",
			message: "Project name must contain at least one letter or number.",
			stage: "project.create",
			remediation: "Use a project name containing letters or numbers.",
		});
	}
	const candidate = { name, slug };
	if (existingProjects) assertProjectUnique(existingProjects, candidate);
	return candidate;
}

function assertProjectUnique(
	projects: Project[],
	candidate: Pick<Project, "name" | "slug">,
): void {
	const name = candidate.name.toLowerCase();
	const slug = candidate.slug.toLowerCase();
	if (
		projects.some(
			(project) =>
				project.name.toLowerCase() === name ||
				project.slug.toLowerCase() === slug,
		)
	) {
		throw new ClearanceError({
			code: "PROJECT_ALREADY_EXISTS",
			message: "A project with this name or slug already exists.",
			stage: "project.create",
			status: 409,
			remediation: "Choose a unique project name.",
		});
	}
}

/** Create an additional project without changing the operator's active scope. */
export function createProject(
	store: ManagementStore,
	input: { name: string; actor?: string; source?: "cli" | "console" | "api" },
): Project {
	const candidate = planProjectCreate(input, store.snapshot.projects);
	const now = nowIso();
	const project: Project = {
		id: newId("proj"),
		...candidate,
		createdAt: now,
		updatedAt: now,
	};
	store.mutate((data) => {
		assertProjectUnique(data.projects, candidate);
		data.projects.push(project);
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "project.create",
			subjectType: "project",
			subjectId: project.id,
			outcome: "success",
			source: input.source ?? "cli",
			projectId: project.id,
			message: "Created project",
		});
	});
	return project;
}

function topologyLifecycleError(
	error: unknown,
	kind: "project" | "environment" | "organization-create" | "organization-update",
	organizationSlug?: string,
): never {
	if (error instanceof ClearanceError) throw error;
	const pg = error as { code?: unknown; constraint?: unknown } | null;
	if (pg?.code === "23505") {
		const constraint = typeof pg.constraint === "string" ? pg.constraint : "";
		if (kind === "project") {
			if (!constraint.endsWith("_projects_name_unique") && !constraint.endsWith("_projects_slug_unique")) throw error;
			throw new ClearanceError({
				code: "PROJECT_ALREADY_EXISTS", message: "A project with this name or slug already exists.",
				stage: "project.create", status: 409, remediation: "Choose a unique project name.",
			});
		}
		if (constraint.endsWith("_organizations_slug_unique")) {
			throw new ClearanceError({
				code: "ORG_SLUG_EXISTS",
				message: `Organization slug ${organizationSlug} already exists in this environment`,
				stage: kind === "organization-create" ? "orgs.create" : "orgs.update",
				status: 409,
			});
		}
		if (kind === "organization-update" || !constraint.endsWith("_organizations_pkey")) throw error;
		throw new ClearanceError({
			code: "ORG_EXISTS", message: "Organization id already exists", stage: "orgs.create", status: 409,
		});
	}
	if (pg?.code === "23503") {
		if (kind === "environment") {
			throw new ClearanceError({ code: "PROJECT_NOT_FOUND", message: "Project not found", stage: "env.create" });
		}
		throw new ClearanceError({
			code: "NOT_INITIALIZED", message: "No project/environment — run clearance init", stage: "orgs.create",
		});
	}
	throw error;
}

function topologyMutationUnavailable(stage: string): never {
	throw new ClearanceError({
		code: "STORE_V2_TOPOLOGY_WRITER_REQUIRED",
		message: "Relational topology authority requires its coordinated writer.",
		stage,
		status: 500,
	});
}

/** Relational-authority-aware project creation for production callers. */
export async function createProjectAuthoritative(
	store: ManagementStore,
	input: { name: string; actor?: string; source?: "cli" | "console" | "api" },
): Promise<Project> {
	if (!store.storeV2Topology?.authoritative) return createProject(store, input);
	if (!store.mutateStoreV2Topology) topologyMutationUnavailable("project.create");
	const candidate = planProjectCreate(input);
	if (await store.storeV2Topology.findProjectConflict(candidate)) {
		throw new ClearanceError({
			code: "PROJECT_ALREADY_EXISTS",
			message: "A project with this name or slug already exists.",
			stage: "project.create",
			status: 409,
			remediation: "Choose a unique project name.",
		});
	}
	const now = nowIso();
	const project: Project = { id: newId("proj"), ...candidate, createdAt: now, updatedAt: now };
	try {
		return await store.mutateStoreV2Topology(async ({ topology, appendAudit }) => {
			if (await topology.findProjectConflict(candidate)) {
				throw new ClearanceError({
					code: "PROJECT_ALREADY_EXISTS", message: "A project with this name or slug already exists.",
					stage: "project.create", status: 409, remediation: "Choose a unique project name.",
				});
			}
			const written = await topology.upsertProject(project);
			appendAudit({
				actor: input.actor ?? "operator", action: "project.create", subjectType: "project",
				subjectId: written.id, outcome: "success", source: input.source ?? "cli",
				projectId: written.id, message: "Created project",
			});
			return written;
		});
	} catch (error) {
		return topologyLifecycleError(error, "project");
	}
}

/** Relational-authority-aware project creation plan for production dry-runs. */
export async function planProjectCreateAuthoritative(
	store: ManagementStore,
	input: { name: string },
): Promise<Pick<Project, "name" | "slug">> {
	const candidate = planProjectCreate(input);
	if (store.storeV2Topology?.authoritative) {
		const conflict = await store.storeV2Topology.findProjectConflict(candidate);
		if (conflict) {
			throw new ClearanceError({
				code: "PROJECT_ALREADY_EXISTS",
				message: "A project with this name or slug already exists.",
				stage: "project.create",
				status: 409,
				remediation: "Choose a unique project name.",
			});
		}
	}
	return candidate;
}

function resolveCreateScope(
	store: ManagementSnapshotReader,
	input: { projectId?: string; environmentId?: string },
): ResourceScope {
	return resolveOperatorScope(store, {
		projectId: input.projectId,
		environmentId: input.environmentId,
	});
}

export function initProject(
	store: ManagementStore,
	input: {
		name: string;
		environment?: string;
		actor?: string;
		source?: "cli" | "console" | "api";
	},
): { project: Project; environment: Environment } {
	const existing = store.snapshot.projects[0];
	if (existing) {
		const env =
			store.snapshot.environments.find((e) => e.projectId === existing.id) ??
			null;
		if (!env) {
			throw new ClearanceError({
				code: "ENV_MISSING",
				message: "Project exists without environment",
				stage: "init",
				remediation: "Run clearance env create",
			});
		}
		return { project: existing, environment: env };
	}

	const candidate = planProjectCreate(input);
	const now = nowIso();
	const project: Project = {
		id: newId("proj"),
		...candidate,
		createdAt: now,
		updatedAt: now,
	};
	const environment: Environment = {
		id: newId("env"),
		projectId: project.id,
		name: input.environment ?? "development",
		slug: slugify(input.environment ?? "development"),
		kind: "development",
		createdAt: now,
		updatedAt: now,
	};

	store.mutate((data) => {
		data.projects.push(project);
		data.environments.push(environment);
		data.meta.initializedAt = now;
		data.meta.config = {
			...data.meta.config,
			projectId: project.id,
			environmentId: environment.id,
		};
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "project.init",
			subjectType: "project",
			subjectId: project.id,
			outcome: "success",
			source: input.source ?? "cli",
			projectId: project.id,
			environmentId: environment.id,
			message: `Initialized project ${project.name}`,
		});
	});

	return { project, environment };
}

function initScopeRequired(): never {
	throw new ClearanceError({
		code: "SCOPE_REQUIRED",
		message:
			"Normalized topology does not have one unambiguous operator project/environment scope.",
		stage: "init",
		status: 403,
		remediation:
			"Set CLEARANCE_PROJECT_ID and CLEARANCE_ENV_ID (or restore the exact meta.config pair) before running clearance init.",
	});
}

function initScopeInvalid(): never {
	throw new ClearanceError({
		code: "SCOPE_INVALID",
		message: "Configured operator scope does not match normalized topology.",
		stage: "init",
		status: 403,
		remediation:
			"Align meta.config projectId/environmentId (or CLEARANCE_PROJECT_ID/CLEARANCE_ENV_ID) with an existing project/environment pair.",
	});
}

/**
 * Resolve an existing normalized operator pair without selecting arbitrary
 * rows. `null` means topology is empty and may be initialized by the caller.
 */
async function resolveExistingTopologyInitScope(
	topology: StoreV2TopologyReader,
	config: Record<string, string>,
): Promise<{ project: Project; environment: Environment } | null> {
	const projectId = config.projectId?.trim();
	const environmentId = config.environmentId?.trim();
	if (projectId || environmentId) {
		if (!projectId || !environmentId) initScopeRequired();
		const project = await topology.getProjectById(projectId);
		const environment = project
			? await topology.getEnvironment({ projectId, id: environmentId })
			: null;
		if (!project || !environment) initScopeInvalid();
		return { project, environment };
	}

	const projects = await topology.listProjectsPage({ limit: 2 });
	if (projects.projects.length === 0) return null;
	if (projects.hasMore || projects.projects.length !== 1) initScopeRequired();
	const project = projects.projects[0]!;
	const environments = await topology.listEnvironmentsPage({
		projectId: project.id,
		limit: 2,
	});
	if (environments.hasMore || environments.environments.length !== 1) {
		initScopeRequired();
	}
	return { project, environment: environments.environments[0]! };
}

async function lockExistingTopologyInitScope(
	topology: StoreV2TopologyRepository,
	resolved: { project: Project; environment: Environment },
): Promise<{ project: Project; environment: Environment }> {
	const project = await topology.lockProject({ id: resolved.project.id });
	const environment = project
		? await topology.lockEnvironment({
			projectId: project.id,
			id: resolved.environment.id,
		})
		: null;
	if (!project || !environment) initScopeInvalid();
	return { project, environment };
}

/**
 * Initialize topology plus snapshot-only operator metadata in one transaction
 * after relational topology cutover. The synchronous helper remains the JSON
 * compatibility contract.
 */
export async function initProjectAuthoritative(
	store: ManagementStore,
	input: {
		name: string;
		environment?: string;
		actor?: string;
		source?: "cli" | "console" | "api";
	},
): Promise<{ project: Project; environment: Environment }> {
	if (!store.storeV2Topology?.authoritative) return initProject(store, input);
	const reader = store.storeV2Topology;
	const existing = await resolveExistingTopologyInitScope(
		reader,
		store.snapshot.meta.config,
	);
	if (existing) {
		if (
			store.snapshot.meta.config.projectId === existing.project.id &&
			store.snapshot.meta.config.environmentId === existing.environment.id
		) {
			return existing;
		}
		if (!store.mutateCoordinated) topologyMutationUnavailable("init");
		return store.mutateCoordinated(async ({ data, topology }) => {
			if (!topology) topologyMutationUnavailable("init");
			const resolved = await resolveExistingTopologyInitScope(
				topology,
				data.meta.config,
			);
			if (!resolved) initScopeInvalid();
			const locked = await lockExistingTopologyInitScope(topology, resolved);
			if (
				data.meta.config.projectId !== locked.project.id ||
				data.meta.config.environmentId !== locked.environment.id
			) {
				data.meta.config = {
					...data.meta.config,
					projectId: locked.project.id,
					environmentId: locked.environment.id,
				};
			}
			return locked;
		});
	}
	if (!store.mutateCoordinated) topologyMutationUnavailable("init");
	const candidate = planProjectCreate(input);
	const now = nowIso();
	const project: Project = { id: newId("proj"), ...candidate, createdAt: now, updatedAt: now };
	const environment: Environment = {
		id: newId("env"), projectId: project.id, name: input.environment ?? "development",
		slug: slugify(input.environment ?? "development"), kind: "development", createdAt: now, updatedAt: now,
	};
	try {
		return await store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
			if (!topology) topologyMutationUnavailable("init");
			const existing = await resolveExistingTopologyInitScope(
				topology,
				data.meta.config,
			);
			if (existing) {
				const locked = await lockExistingTopologyInitScope(topology, existing);
				if (
					data.meta.config.projectId !== locked.project.id ||
					data.meta.config.environmentId !== locked.environment.id
				) {
					data.meta.config = {
						...data.meta.config,
						projectId: locked.project.id,
						environmentId: locked.environment.id,
					};
				}
				return locked;
			}
			if (await topology.findProjectConflict(candidate)) {
				throw new ClearanceError({ code: "PROJECT_ALREADY_EXISTS", message: "A project with this name or slug already exists.", stage: "project.create", status: 409, remediation: "Choose a unique project name." });
			}
			await topology.upsertProject(project);
			await topology.upsertEnvironment(environment);
			data.meta.initializedAt = now;
			data.meta.config = { ...data.meta.config, projectId: project.id, environmentId: environment.id };
			appendAudit({
				actor: input.actor ?? "operator", action: "project.init", subjectType: "project",
				subjectId: project.id, outcome: "success", source: input.source ?? "cli",
				projectId: project.id, environmentId: environment.id,
				message: `Initialized project ${project.name}`,
			});
			return { project, environment };
		});
	} catch (error) {
		return topologyLifecycleError(error, "project");
	}
}

export function listProjects(store: ManagementStore): Project[] {
	return store.snapshot.projects;
}

/** Scope-safe authority-aware project point lookup. */
export async function inspectProjectAuthoritative(
	store: ManagementStore,
	id: string,
	scope: ResourceScope,
): Promise<Project> {
	const project = store.storeV2Topology?.authoritative
		? id === scope.projectId
			? await store.storeV2Topology.getProjectById(id)
			: null
		: store.snapshot.projects.find(
			(candidate) => candidate.id === id && candidate.id === scope.projectId,
		) ?? null;
	if (!project) {
		throw new ClearanceError({
			code: "PROJECT_NOT_FOUND",
			message: "Project not found",
			stage: "projects.inspect",
			status: 404,
		});
	}
	return project;
}

export function createEnvironment(
	store: ManagementStore,
	input: {
		projectId: string;
		name: string;
		kind?: Environment["kind"];
		actor?: string;
	},
): Environment {
	const candidate = planEnvironmentCreate(store, input);
	const now = nowIso();
	const environment: Environment = {
		id: newId("env"),
		...candidate,
		createdAt: now,
		updatedAt: now,
	};
	store.mutate((data) => {
		data.environments.push(environment);
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "env.create",
			subjectType: "environment",
			subjectId: environment.id,
			outcome: "success",
			source: "cli",
			projectId: candidate.projectId,
			environmentId: environment.id,
			message: `Created environment ${environment.name}`,
		});
	});
	return environment;
}

/** Relational-authority-aware environment creation for production callers. */
export async function createEnvironmentAuthoritative(
	store: ManagementStore,
	input: { projectId: string; name: string; kind?: Environment["kind"]; actor?: string; source?: AuditEvent["source"] },
): Promise<Environment> {
	if (!store.storeV2Topology?.authoritative) return createEnvironment(store, input);
	if (!store.mutateStoreV2Topology) topologyMutationUnavailable("env.create");
	const project = await store.storeV2Topology.getProjectById(input.projectId);
	if (!project) {
		throw new ClearanceError({ code: "PROJECT_NOT_FOUND", message: `Project ${input.projectId} not found`, stage: "env.create" });
	}
	const candidate = planEnvironmentCreateFromProject(project, input);
	const now = nowIso();
	const environment: Environment = { id: newId("env"), ...candidate, createdAt: now, updatedAt: now };
	try {
		return await store.mutateStoreV2Topology(async ({ topology, appendAudit }) => {
			if (!(await topology.lockProject({ id: input.projectId }))) {
				throw new ClearanceError({ code: "PROJECT_NOT_FOUND", message: `Project ${input.projectId} not found`, stage: "env.create" });
			}
			const written = await topology.upsertEnvironment(environment);
			appendAudit({
				actor: input.actor ?? "operator", action: "env.create", subjectType: "environment",
				subjectId: written.id, outcome: "success", source: input.source ?? "cli",
				projectId: written.projectId, environmentId: written.id, message: `Created environment ${written.name}`,
			});
			return written;
		});
	} catch (error) {
		return topologyLifecycleError(error, "environment");
	}
}

/** Validate an environment creation request without mutating the store. */
export function planEnvironmentCreate(
	store: ManagementStore,
	input: {
		projectId?: string;
		name: string;
		kind?: Environment["kind"];
	},
): Pick<Environment, "projectId" | "name" | "slug" | "kind"> {
	const project = store.snapshot.projects.find((p) => p.id === input.projectId);
	if (!project) {
		throw new ClearanceError({
			code: "PROJECT_NOT_FOUND",
			message: `Project ${input.projectId} not found`,
			stage: "env.create",
		});
	}
	return planEnvironmentCreateFromProject(project, input);
}

/** Relational-authority-aware environment creation plan for production dry-runs. */
export async function planEnvironmentCreateAuthoritative(
	store: ManagementStore,
	input: { projectId?: string; name: string; kind?: Environment["kind"] },
): Promise<Pick<Environment, "projectId" | "name" | "slug" | "kind">> {
	if (!store.storeV2Topology?.authoritative) return planEnvironmentCreate(store, input);
	const project = input.projectId
		? await store.storeV2Topology.getProjectById(input.projectId)
		: null;
	if (!project) {
		throw new ClearanceError({
			code: "PROJECT_NOT_FOUND",
			message: `Project ${input.projectId} not found`,
			stage: "env.create",
		});
	}
	return planEnvironmentCreateFromProject(project, input);
}

function planEnvironmentCreateFromProject(
	project: Project,
	input: { projectId?: string; name: string; kind?: Environment["kind"] },
): Pick<Environment, "projectId" | "name" | "slug" | "kind"> {
	const kind = input.kind ?? "development";
	if (!ENVIRONMENT_KINDS.includes(kind)) {
		throw new ClearanceError({
			code: "ENV_KIND_INVALID",
			message: "Environment kind must be development, preview, or production.",
			stage: "env.create",
			remediation: "Pass --kind development, preview, or production.",
		});
	}
	return {
		projectId: project.id,
		name: input.name,
		slug: slugify(input.name),
		kind,
	};
}

/**
 * List environments for the operator's project (project-scoped).
 * Environment rows are not dual-scoped; projectId must match principal project.
 */
export function listEnvironments(
	store: ManagementStore,
	filter?: { scope?: ResourceScope },
): Environment[] {
	const projectId =
		filter?.scope?.projectId ?? resolveOperatorScope(store).projectId;
	return store.snapshot.environments
		.filter((e) => e.projectId === projectId)
		.slice()
		.sort((a, b) => {
			if (a.createdAt !== b.createdAt) {
				return a.createdAt < b.createdAt ? -1 : 1;
			}
			return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
		});
}

export const ENVIRONMENTS_LIST_DEFAULT_PAGE_LIMIT = 100;
export const ENVIRONMENTS_LIST_MAX_PAGE_LIMIT = 1000;

/**
 * Authority-aware bounded environment listing. The legacy synchronous list is
 * retained for JSON-backed callers; relational topology never reads its empty
 * post-cutover snapshot projection.
 */
export async function listEnvironmentsPageAuthoritative(
	store: ManagementStore,
	opts?: { scope?: ResourceScope; limit?: number; cursor?: string },
): Promise<{ environments: Environment[]; nextCursor: string | null }> {
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const limit = normalizePageLimit(opts?.limit, {
		stage: "envs.list",
		code: "ENVIRONMENTS_LIST_LIMIT_INVALID",
		defaultValue: ENVIRONMENTS_LIST_DEFAULT_PAGE_LIMIT,
		maximum: ENVIRONMENTS_LIST_MAX_PAGE_LIMIT,
	});
	const cursor = decodePageCursor(opts?.cursor, "environments", "envs.list");
	if (!store.storeV2Topology?.authoritative) {
		const page = paginateByCreatedAt(listEnvironments(store, { scope }), {
			surface: "environments",
			order: "asc",
			limit,
			cursor,
		});
		return { environments: page.items, nextCursor: page.nextCursor };
	}
	const page = await store.storeV2Topology.listEnvironmentsPage({
		projectId: scope.projectId,
		limit,
		...(cursor ? { cursor } : {}),
	});
	const last = page.environments[page.environments.length - 1];
	return {
		environments: page.environments,
		nextCursor:
			page.hasMore && last
				? encodePageCursor("environments", {
					createdAt: last.createdAt,
					id: last.id,
				})
				: null,
	};
}

function findEnvironmentInProject(
	store: ManagementStore,
	idOrSlug: string,
	projectId: string,
	stage: string,
): Environment {
	const key = idOrSlug?.trim();
	if (!key) {
		throw new ClearanceError({
			code: "ENV_ID_REQUIRED",
			message: "Environment id or slug is required",
			stage,
			status: 400,
		});
	}
	const env = store.snapshot.environments.find(
		(e) =>
			e.projectId === projectId && (e.id === key || e.slug === key || e.name === key),
	);
	if (!env) {
		throw new ClearanceError({
			code: "ENV_NOT_FOUND",
			message: "Environment not found",
			stage,
			status: 404,
			remediation:
				"Pass an environment id/slug that belongs to the operator project",
		});
	}
	return env;
}

async function findEnvironmentInProjectAuthoritative(
	store: ManagementStore,
	idOrSlug: string,
	projectId: string,
	stage: string,
): Promise<Environment> {
	if (!store.storeV2Topology?.authoritative) {
		return findEnvironmentInProject(store, idOrSlug, projectId, stage);
	}
	const key = idOrSlug?.trim();
	if (!key) {
		throw new ClearanceError({
			code: "ENV_ID_REQUIRED",
			message: "Environment id or slug is required",
			stage,
			status: 400,
		});
	}
	const environment = await store.storeV2Topology.findEnvironmentByKey({
		projectId,
		key,
	});
	if (!environment) {
		throw new ClearanceError({
			code: "ENV_NOT_FOUND",
			message: "Environment not found",
			stage,
			status: 404,
			remediation:
				"Pass an environment id/slug that belongs to the operator project",
		});
	}
	return environment;
}

export type EnvironmentLocalStatus = {
	/** Whether this environment is the operator's active principal environment */
	active: boolean;
	storeBackend: ManagementStore["backend"];
	storePathPresent: boolean;
	schemaVersion: number;
	expectedSchemaVersion: number;
	releaseVersion: string;
	initialized: boolean;
	/** Configuration presence flags only — never secret values */
	config: {
		hasClearanceSecret: boolean;
		hasDatabaseUrl: boolean;
		hasOperatorToken: boolean;
		hasCredentialKey: boolean;
		nodeEnv: string;
		operatorProjectIdConfigured: boolean;
		operatorEnvironmentIdConfigured: boolean;
	};
	resourceCounts: {
		principals: number;
		organizations: number;
		/** Null when relational topology makes organization membership unavailable. */
		memberships: number | null;
		/** Null when relational topology makes organization connections unavailable. */
		identityConnections: number | null;
		/** Null when relational topology makes organization connections unavailable. */
		directoryConnections: number | null;
		roles: number;
		sessions: number;
		/** Null when the authoritative event projection is relational. */
		events: number | null;
	};
};

export type EnvironmentInspectResult = {
	environment: Environment;
	project: Project | null;
	scope: ResourceScope;
	local: EnvironmentLocalStatus;
	correlationId: string;
};

/**
 * Inspect a canonical environment plus truthful local status (no secrets).
 * Default id is the operator principal environment. Cross-project ids fail closed.
 */
function inspectEnvironmentSnapshot(
	store: ManagementStore,
	id?: string,
	opts?: { scope?: ResourceScope },
	allowRelationalPlaceholder = false,
): EnvironmentInspectResult {
	if (store.storeV2Principals?.authoritative && !allowRelationalPlaceholder) {
		throw new ClearanceError({
			code: "STORE_V2_PRINCIPAL_COUNT_READER_REQUIRED",
			message: "Relational environment inspection requires bounded counts.",
			stage: "env.inspect",
			status: 500,
		});
	}
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const key = id?.trim() || scope.environmentId;
	const environment = findEnvironmentInProject(
		store,
		key,
		scope.projectId,
		"env.inspect",
	);
	// Fail closed for environments outside the operator project (already enforced).
	// Active flag tells whether this is the principal environment vs another project env.
	const project =
		store.snapshot.projects.find((p) => p.id === environment.projectId) ?? null;

	const principals = (store.storeV2Principals?.authoritative
		? []
		: principalReadView(store)).filter(
		(p) =>
			p.projectId === environment.projectId &&
			p.environmentId === environment.id &&
			p.status !== "deleted",
	);
	const organizations = store.snapshot.organizations.filter(
		(o) =>
			o.projectId === environment.projectId &&
			o.environmentId === environment.id &&
			o.status !== "archived",
	);
	const orgIds = new Set(organizations.map((o) => o.id));
	const memberships = store.snapshot.memberships.filter(
		(m) => orgIds.has(m.organizationId) && m.status === "active",
	);
	const identityConnections = store.snapshot.identityConnections.filter((c) =>
		orgIds.has(c.organizationId),
	);
	const directoryConnections = store.snapshot.directoryConnections.filter((c) =>
		orgIds.has(c.organizationId),
	);
	const roles = store.snapshot.roles.filter(
		(r) =>
			r.projectId === environment.projectId &&
			r.environmentId === environment.id,
	);
	const sessions = store.snapshot.sessions.filter(
		(s) => s.environmentId === environment.id && s.status === "active",
	);
	const events = store.snapshot.events.filter(
		(e) =>
			e.projectId === environment.projectId &&
			e.environmentId === environment.id,
	);

	const local: EnvironmentLocalStatus = {
		active: environment.id === scope.environmentId,
		storeBackend: store.backend,
		storePathPresent: existsSync(store.path),
		schemaVersion: store.snapshot.meta.schemaVersion,
		expectedSchemaVersion: STORE_SCHEMA_VERSION,
		releaseVersion: store.snapshot.releaseVersion ?? CLEARANCE_RELEASE_VERSION,
		initialized: Boolean(store.snapshot.meta.initializedAt),
		config: {
			hasClearanceSecret: Boolean(process.env.CLEARANCE_SECRET?.trim()),
			hasDatabaseUrl: Boolean(process.env.DATABASE_URL?.trim()),
			hasOperatorToken: Boolean(process.env.CLEARANCE_OPERATOR_TOKEN?.trim()),
			hasCredentialKey: Boolean(process.env.CLEARANCE_CREDENTIAL_KEY?.trim()),
			nodeEnv: process.env.NODE_ENV ?? "development",
			operatorProjectIdConfigured: Boolean(
				process.env.CLEARANCE_PROJECT_ID?.trim() ||
					store.snapshot.meta.config.projectId,
			),
			operatorEnvironmentIdConfigured: Boolean(
				process.env.CLEARANCE_ENV_ID?.trim() ||
					store.snapshot.meta.config.environmentId,
			),
		},
		resourceCounts: {
			principals: principals.length,
			organizations: organizations.length,
			memberships: memberships.length,
			identityConnections: identityConnections.length,
			directoryConnections: directoryConnections.length,
			roles: roles.length,
			sessions: sessions.length,
			events: events.length,
		},
	};

	return {
		environment,
		project,
		scope,
		local,
		correlationId: correlationId(),
	};
}

export function inspectEnvironment(
	store: ManagementStore,
	id?: string,
	opts?: { scope?: ResourceScope },
): EnvironmentInspectResult {
	return inspectEnvironmentSnapshot(store, id, opts);
}

export async function inspectEnvironmentAuthoritative(
	store: ManagementStore,
	id?: string,
	opts?: { scope?: ResourceScope },
): Promise<EnvironmentInspectResult> {
	const topologyAuthoritative = store.storeV2Topology?.authoritative === true;
	const principalsAuthoritative = store.storeV2Principals?.authoritative === true;
	const eventsAuthoritative = store.storeV2Events?.authoritative === true;
	if (!topologyAuthoritative && !principalsAuthoritative && !eventsAuthoritative) {
		return inspectEnvironment(store, id, opts);
	}
	const operatorScope = opts?.scope ?? resolveOperatorScope(store);
	const key = id?.trim() || operatorScope.environmentId;
	const environment = topologyAuthoritative
		? await store.storeV2Topology!.getEnvironment({
			projectId: operatorScope.projectId,
			id: key,
		})
		: findEnvironmentInProject(store, key, operatorScope.projectId, "env.inspect");
	if (!environment) {
		throw new ClearanceError({
			code: "ENV_NOT_FOUND",
			message: "Environment not found",
			stage: "env.inspect",
			status: 404,
			remediation:
				"Pass an environment id that belongs to the operator project",
		});
	}
	const scope = {
		projectId: environment.projectId,
		environmentId: environment.id,
	};
	const project = topologyAuthoritative
		? await store.storeV2Topology!.getProjectById(environment.projectId)
		: store.snapshot.projects.find((candidate) => candidate.id === environment.projectId) ?? null;
	const snapshotOrganizations = topologyAuthoritative
		? []
		: store.snapshot.organizations.filter(
			(candidate) =>
				candidate.projectId === scope.projectId &&
				candidate.environmentId === scope.environmentId &&
				candidate.status !== "archived",
		);
	const [principalCounts, activeSessions, organizationCount] = await Promise.all([
		principalsAuthoritative
			? (() => {
				const countReader = store.storeV2Principals?.countByScope;
				if (!countReader) {
					throw new ClearanceError({
						code: "STORE_V2_PRINCIPAL_COUNT_READER_REQUIRED",
						message: "Relational principal count reader is unavailable",
						stage: "env.inspect",
						status: 500,
					});
				}
				return countReader({ scope });
			})()
			: Promise.resolve({
				total: principalReadView(store).filter(
					(principal) =>
						principal.projectId === scope.projectId &&
						principal.environmentId === scope.environmentId &&
						principal.status !== "deleted",
				).length,
				active: 0,
			}),
		principalsAuthoritative
			? store.storeV2Principals?.countActiveSessions?.({ scope }) ?? Promise.resolve(0)
			: Promise.resolve(
				store.snapshot.sessions.filter(
					(session) =>
						session.environmentId === scope.environmentId &&
						session.status === "active",
				).length,
			),
		topologyAuthoritative
			? store.storeV2Topology!.countOrganizations({ scope })
			: Promise.resolve(snapshotOrganizations.length),
	]);
	const auxiliaryOrganizationCounts = topologyAuthoritative
		? {
			memberships: null,
			identityConnections: null,
			directoryConnections: null,
		}
		: (() => {
			const orgIds = new Set(
				snapshotOrganizations.map((organization) => organization.id),
			);
			return {
				memberships: store.snapshot.memberships.filter(
					(membership) =>
						orgIds.has(membership.organizationId) && membership.status === "active",
				).length,
				identityConnections: store.snapshot.identityConnections.filter((connection) =>
					orgIds.has(connection.organizationId),
				).length,
				directoryConnections: store.snapshot.directoryConnections.filter((connection) =>
					orgIds.has(connection.organizationId),
				).length,
			};
		})();
	return {
		environment,
		project,
		scope: operatorScope,
		local: {
			active: environment.id === operatorScope.environmentId,
			storeBackend: store.backend,
			storePathPresent: existsSync(store.path),
			schemaVersion: store.snapshot.meta.schemaVersion,
			expectedSchemaVersion: STORE_SCHEMA_VERSION,
			releaseVersion: store.snapshot.releaseVersion ?? CLEARANCE_RELEASE_VERSION,
			initialized: Boolean(store.snapshot.meta.initializedAt),
			config: {
				hasClearanceSecret: Boolean(process.env.CLEARANCE_SECRET?.trim()),
				hasDatabaseUrl: Boolean(process.env.DATABASE_URL?.trim()),
				hasOperatorToken: Boolean(process.env.CLEARANCE_OPERATOR_TOKEN?.trim()),
				hasCredentialKey: Boolean(process.env.CLEARANCE_CREDENTIAL_KEY?.trim()),
				nodeEnv: process.env.NODE_ENV ?? "development",
				operatorProjectIdConfigured: Boolean(
					process.env.CLEARANCE_PROJECT_ID?.trim() ||
						store.snapshot.meta.config.projectId,
				),
				operatorEnvironmentIdConfigured: Boolean(
					process.env.CLEARANCE_ENV_ID?.trim() ||
						store.snapshot.meta.config.environmentId,
				),
			},
			resourceCounts: {
				principals: principalCounts.total,
				organizations: organizationCount,
				...auxiliaryOrganizationCounts,
				roles: store.snapshot.roles.filter(
					(role) =>
						role.projectId === scope.projectId &&
						role.environmentId === scope.environmentId,
				).length,
				sessions: activeSessions,
				events: eventsAuthoritative
					? null
					: store.snapshot.events.filter(
						(event) =>
							event.projectId === scope.projectId &&
							event.environmentId === scope.environmentId,
					).length,
			},
		},
		correlationId: correlationId(),
	};
}

export type EnvironmentPromoteBlocker = {
	code: string;
	message: string;
	remediation: string;
};

export type EnvironmentPromotePlanStep = {
	name: string;
	status: "planned" | "blocked" | "skipped" | "done";
	detail?: string;
};

export type EnvironmentPromoteResult = {
	dryRun: boolean;
	applied: boolean;
	blocked: boolean;
	idempotent: boolean;
	wouldChange: boolean;
	source: Environment;
	target: Environment;
	scope: ResourceScope;
	plan: {
		action: "env.promote";
		description: string;
		resourceCounts: EnvironmentLocalStatus["resourceCounts"];
		steps: EnvironmentPromotePlanStep[];
	};
	blockers: EnvironmentPromoteBlocker[];
	correlationId: string;
	auditAction?: "env.promote";
};

export type EnvironmentPromoteInput = {
	/** Target environment id or slug (required) */
	to: string;
	/** Source environment id or slug; defaults to operator principal environment */
	from?: string;
	/** Preview only — default when confirm is not true */
	dryRun?: boolean;
	/** Required for a confirmed attempt (CLI --yes). Never invents deploy apply. */
	confirm?: boolean;
	scope?: ResourceScope;
	actor?: string;
	source?: "cli" | "console" | "api" | "system";
};

function assertPromotionTarget(input: EnvironmentPromoteInput, stage: string): string {
	const target = input.to?.trim();
	if (!target) {
		throw new ClearanceError({
			code: "ENV_PROMOTE_TARGET_REQUIRED",
			message: "Promotion target environment is required",
			stage,
			status: 400,
			remediation: "Pass --to <environment-id-or-slug>",
		});
	}
	return target;
}

function assertPromotionSource(
	source: Environment,
	scope: ResourceScope,
	stage: string,
): void {
	if (source.id !== scope.environmentId) {
		throw new ClearanceError({
			code: "ENV_NOT_FOUND",
			message: "Environment not found",
			stage,
			status: 404,
			remediation:
				"Promotion source must be the operator principal environment",
		});
	}
}

/**
 * Plan (and optionally attempt) environment promotion.
 *
 * Grounded in existing Environment + scoped resource counts only. The snapshot
 * has no Deployment resource, so mutating apply always surfaces an explicit
 * structured blocker rather than inventing deployment state. Dry-run and
 * confirmed apply both validate inputs, return the same plan shape, and audit
 * confirmed attempts (including blocked/idempotent outcomes).
 */
export function promoteEnvironment(
	store: ManagementStore,
	input: EnvironmentPromoteInput,
): EnvironmentPromoteResult {
	const scope = input.scope ?? resolveOperatorScope(store);
	const stage = "env.promote";
	const toKey = assertPromotionTarget(input, stage);
	const source = findEnvironmentInProject(
		store,
		input.from?.trim() || scope.environmentId,
		scope.projectId,
		stage,
	);
	assertPromotionSource(source, scope, stage);
	const target = findEnvironmentInProject(store, toKey, scope.projectId, stage);
	const inspected = inspectEnvironment(store, source.id, { scope });
	return promotionResult(
		store,
		input,
		scope,
		source,
		target,
		inspected.local.resourceCounts,
	);
}

/**
 * Authority-aware environment promotion planning. Relational topology resolves
 * source and target through scoped indexed reads; JSON-backed stores retain the
 * synchronous snapshot implementation above.
 */
export async function promoteEnvironmentAuthoritative(
	store: ManagementStore,
	input: EnvironmentPromoteInput,
): Promise<EnvironmentPromoteResult> {
	if (!store.storeV2Topology?.authoritative) {
		return promoteEnvironment(store, input);
	}
	const scope = input.scope ?? resolveOperatorScope(store);
	const stage = "env.promote";
	const toKey = assertPromotionTarget(input, stage);
	const source = await findEnvironmentInProjectAuthoritative(
		store,
		input.from?.trim() || scope.environmentId,
		scope.projectId,
		stage,
	);
	assertPromotionSource(source, scope, stage);
	const target = await findEnvironmentInProjectAuthoritative(
		store,
		toKey,
		scope.projectId,
		stage,
	);
	const inspected = await inspectEnvironmentAuthoritative(store, source.id, { scope });
	return promotionResult(
		store,
		input,
		scope,
		source,
		target,
		inspected.local.resourceCounts,
	);
}

function promotionResult(
	store: ManagementStore,
	input: EnvironmentPromoteInput,
	scope: ResourceScope,
	source: Environment,
	target: Environment,
	resourceCounts: EnvironmentLocalStatus["resourceCounts"],
): EnvironmentPromoteResult {
	const dryRun = input.dryRun === true || input.confirm !== true;
	const corr = correlationId();
	const same = source.id === target.id;
	const blockers: EnvironmentPromoteBlocker[] = [];
	if (!same) {
		blockers.push({
			code: "ENV_PROMOTE_DEPLOYMENT_UNSUPPORTED",
			message:
				"Environment promotion cannot be applied: the management data model has no Deployment resource to represent or roll back a config/runtime promotion",
			remediation:
				"Use dry-run/plan for validated promotion planning. Apply is blocked until a deployment resource and promote pipeline exist — do not invent deployment state",
		});
	}

	const steps: EnvironmentPromotePlanStep[] = [
		{
			name: "validate-source-target",
			status: "done",
			detail: `source=${source.slug} target=${target.slug} project=${scope.projectId}`,
		},
		{
			name: "inventory-scoped-resources",
			status: "done",
			detail: `principals=${resourceCounts.principals} organizations=${resourceCounts.organizations}`,
		},
		same
			? {
					name: "apply-promotion",
					status: "skipped",
					detail: "Source and target are identical — nothing to promote",
				}
			: {
					name: "apply-promotion",
					status: "blocked",
					detail: blockers[0]?.message,
				},
	];

	const plan = {
		action: "env.promote" as const,
		description: same
			? `No-op: source and target are both ${source.slug}`
			: `Promote configuration/resources from ${source.slug} (${source.kind}) to ${target.slug} (${target.kind})`,
		resourceCounts,
		steps,
	};

	const result: EnvironmentPromoteResult = {
		dryRun,
		applied: false,
		blocked: !same,
		idempotent: same,
		wouldChange: false,
		source,
		target,
		scope,
		plan,
		blockers,
		correlationId: corr,
	};

	// Confirmed attempts are audited even when blocked (evidence of operator intent).
	// Dry-run never mutates or audits.
	if (!dryRun) {
		store.mutate((data) => {
			appendAuditEvent(data, {
				actor: input.actor ?? "operator",
				action: "env.promote",
				subjectType: "environment",
				subjectId: target.id,
				outcome: same ? "success" : "failure",
				source: (input.source as "cli") ?? "cli",
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				correlationId: corr,
				message: same
					? `Environment promote no-op (already ${source.slug})`
					: `Environment promote blocked: deployment model unavailable (${source.slug} → ${target.slug})`,
				metadata: {
					sourceId: source.id,
					targetId: target.id,
					sourceSlug: source.slug,
					targetSlug: target.slug,
					blocked: !same,
					idempotent: same,
					blockerCodes: blockers.map((b) => b.code),
					resourceCounts,
				},
			});
		});
		result.auditAction = "env.promote";
	}

	return result;
}

export function createUser(
	store: ManagementUnitOfWork,
	input: {
		email: string;
		name: string;
		/** Optional stable id (e.g. Clearance runtime user id) */
		id?: string;
		projectId?: string;
		environmentId?: string;
		externalId?: string;
		actor?: string;
		source?: AuditEvent["source"] | "import";
	},
): Principal {
	assertSnapshotPrincipalWriterDisabled(store, "users.create");
	const scope = resolveCreateScope(store, input);
	const email = input.email.toLowerCase();
	const principalId = input.id?.trim() || newId("user");
	const now = nowIso();

	const principal: Principal = {
		id: principalId,
		projectId: scope.projectId,
		environmentId: scope.environmentId,
		email,
		name: input.name,
		status: "active",
		externalId: input.externalId,
		createdAt: now,
		updatedAt: now,
	};

	// Validation + insert + audit are one mutate so Postgres FOR UPDATE + uniqueness
	// tables commit exactly one resource and exactly one audit event under races.
	store.mutate((data) => {
		const projectId =
			input.projectId ??
			data.meta.config.projectId ??
			data.projects[0]?.id ??
			scope.projectId;
		const environmentId =
			input.environmentId ??
			data.meta.config.environmentId ??
			data.environments[0]?.id ??
			scope.environmentId;
		if (!projectId || !environmentId) {
			throw new ClearanceError({
				code: "NOT_INITIALIZED",
				message: "No project/environment — run clearance init",
				stage: "users.create",
				remediation: "Run: clearance init --name my-app",
			});
		}

		const existingEmail = data.principals.find(
			(p) =>
				p.email.toLowerCase() === email &&
				p.projectId === projectId &&
				p.environmentId === environmentId &&
				p.status !== "deleted",
		);
		if (existingEmail) {
			throw new ClearanceError({
				code: "USER_EXISTS",
				message: `User ${input.email} already exists`,
				stage: "users.create",
				status: 409,
			});
		}

		if (data.principals.some((p) => p.id === principalId)) {
			throw new ClearanceError({
				code: "USER_EXISTS",
				message: `User id ${principalId} already exists`,
				stage: "users.create",
				status: 409,
			});
		}

		principal.projectId = projectId;
		principal.environmentId = environmentId;
		data.principals.push(principal);
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "users.create",
			subjectType: "principal",
			subjectId: principal.id,
			outcome: "success",
			source: (input.source as "cli") ?? "cli",
			projectId,
			environmentId,
			message: `Created user ${principal.email}`,
		});
	});

	return principal;
}

export function listUsers(
	store: ManagementStore,
	filter?: {
		environmentId?: string;
		projectId?: string;
		status?: string;
		/** When true (default for scoped callers), require full scope filter */
		scope?: ResourceScope;
	},
): Principal[] {
	const inScope = filter?.scope ? scopeFilter(filter.scope) : null;
	return principalReadView(store).filter((p) => {
		if (p.status === "deleted") return false;
		if (inScope && !inScope(p)) return false;
		if (filter?.projectId && p.projectId !== filter.projectId) return false;
		if (filter?.environmentId && p.environmentId !== filter.environmentId) {
			return false;
		}
		if (filter?.status && p.status !== filter.status) return false;
		return true;
	});
}

export const USERS_LIST_DEFAULT_PAGE_LIMIT = 100;
export const USERS_LIST_MAX_PAGE_LIMIT = 1000;

/**
 * Cursor-paginated users listing (FOLLOW.md P2.3.1), shared by CLI and API.
 * Ordering: createdAt ascending, then id ascending (documented keyset — see
 * pagination.ts for why keyset beats index cursors on the snapshot arrays).
 * Callers that need the full unpaginated legacy behavior keep using listUsers.
 */
export function listUsersPage(
	store: ManagementStore,
	opts?: {
		scope?: ResourceScope;
		status?: string;
		limit?: number;
		/** Opaque cursor from a previous page's nextCursor (fail-closed). */
		cursor?: string;
	},
): { users: Principal[]; nextCursor: string | null } {
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const limit = normalizePageLimit(opts?.limit, {
		stage: "users.list",
		code: "USERS_LIST_LIMIT_INVALID",
		defaultValue: USERS_LIST_DEFAULT_PAGE_LIMIT,
		maximum: USERS_LIST_MAX_PAGE_LIMIT,
	});
	const cursor = decodePageCursor(opts?.cursor, "users", "users.list");
	const all = listUsers(store, {
		scope,
		...(opts?.status ? { status: opts.status } : {}),
	});
	const page = paginateByCreatedAt(all, {
		surface: "users",
		order: "asc",
		limit,
		cursor,
	});
	return { users: page.items, nextCursor: page.nextCursor };
}

/**
 * Authority-aware bounded user listing. Relational authority never falls back
 * to the snapshot projection, which is intentionally empty after cutover.
 */
export async function listUsersPageAuthoritative(
	store: ManagementStore,
	opts?: {
		scope?: ResourceScope;
		status?: Principal["status"];
		limit?: number;
		cursor?: string;
	},
): Promise<{ users: Principal[]; nextCursor: string | null }> {
	if (!store.storeV2Principals?.authoritative) {
		return listUsersPage(store, opts);
	}
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const limit = normalizePageLimit(opts?.limit, {
		stage: "users.list",
		code: "USERS_LIST_LIMIT_INVALID",
		defaultValue: USERS_LIST_DEFAULT_PAGE_LIMIT,
		maximum: USERS_LIST_MAX_PAGE_LIMIT,
	});
	const cursor = decodePageCursor(opts?.cursor, "users", "users.list");
	const page = await store.storeV2Principals.listPage({
		scope,
		limit,
		...(cursor ? { cursor } : {}),
		...(opts?.status ? { status: opts.status } : {}),
	});
	const last = page.principals[page.principals.length - 1];
	return {
		users: page.principals,
		nextCursor:
			page.hasMore && last
				? encodePageCursor("users", { createdAt: last.createdAt, id: last.id })
				: null,
	};
}

/** Scope-safe authority-aware point lookup. */
export async function inspectUserAuthoritative(
	store: ManagementStore,
	id: string,
	scope?: ResourceScope,
): Promise<Principal> {
	if (!store.storeV2Principals?.authoritative) {
		return inspectUser(store, id, scope);
	}
	const resolvedScope = scope ?? resolveOperatorScope(store);
	const user = await store.storeV2Principals.getById({
		scope: resolvedScope,
		id,
	});
	if (!user) {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage: "users.inspect",
			status: 404,
		});
	}
	return user;
}

/**
 * Lookup by id. When scope is provided, cross-scope ids fail closed as NOT_FOUND
 * without revealing that the foreign resource exists.
 */
export function inspectUser(
	store: ManagementStore,
	id: string,
	scope?: ResourceScope,
): Principal {
	const user = principalReadView(store).find((p) => p.id === id);
	if (!user || user.status === "deleted") {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: `User not found`,
			stage: "users.inspect",
			status: 404,
		});
	}
	if (scope) {
		assertResourceInScope(user, scope, {
			code: "USER_NOT_FOUND",
			stage: "users.inspect",
			label: "User",
		});
	}
	return user;
}

/** Fail-closed status validation shared by management + runtime lifecycle paths. */
export function parseUserStatusInput(
	status: unknown,
	stage = "users.update",
): "active" | "disabled" | undefined {
	if (status === undefined || status === null) return undefined;
	if (status === "active" || status === "disabled") return status;
	throw new ClearanceError({
		code: "USER_STATUS_INVALID",
		message: "Invalid status; use active or disabled",
		stage,
		status: 400,
		remediation: "Pass status=active or status=disabled (use delete for soft-delete)",
	});
}

/**
 * Update name, email, and/or status for a principal (management snapshot).
 * Soft-deleted users are fail-closed as NOT_FOUND. Status may be active|disabled
 * (not deleted — use deleteUser). Cross-scope ids fail closed as NOT_FOUND.
 * With DATABASE_URL prefer updateUserInAuth for runtime parity.
 */
export function updateUser(
	store: ManagementUnitOfWork,
	id: string,
	input: {
		name?: string;
		email?: string;
		/** Re-enable or set disabled without soft-delete. */
		status?: "active" | "disabled" | string;
		actor?: string;
		source?: AuditEvent["source"] | "import";
		scope?: ResourceScope;
	},
): Principal {
	assertSnapshotPrincipalWriterDisabled(store, "users.update");
	const hasName = input.name !== undefined;
	const hasEmail = input.email !== undefined;
	// Validate status before any mutation (fail closed; never ignore invalid).
	const status = parseUserStatusInput(input.status, "users.update");
	const hasStatus = status !== undefined;
	if (!hasName && !hasEmail && !hasStatus) {
		throw new ClearanceError({
			code: "USER_UPDATE_EMPTY",
			message: "At least one of name, email, or status is required",
			stage: "users.update",
			status: 400,
			remediation: "Pass --name, --email, and/or --status",
		});
	}
	if (hasName && !String(input.name).trim()) {
		throw new ClearanceError({
			code: "USER_NAME_REQUIRED",
			message: "Name must not be empty",
			stage: "users.update",
			status: 400,
		});
	}
	if (hasEmail && !String(input.email).trim()) {
		throw new ClearanceError({
			code: "USER_EMAIL_REQUIRED",
			message: "Email must not be empty",
			stage: "users.update",
			status: 400,
		});
	}

	const email = hasEmail ? String(input.email).toLowerCase().trim() : undefined;
	const name = hasName ? String(input.name).trim() : undefined;
	const now = nowIso();
	// Always bind mutations to operator scope (explicit or principal-derived).
	const scope = input.scope ?? resolveOperatorScope(store);
	let updated: Principal | undefined;

	store.mutate((data) => {
		const user = data.principals.find((p) => p.id === id);
		if (!user || user.status === "deleted") {
			throw new ClearanceError({
				code: "USER_NOT_FOUND",
				message: "User not found",
				stage: "users.update",
				status: 404,
			});
		}
		assertResourceInScope(user, scope, {
			code: "USER_NOT_FOUND",
			stage: "users.update",
			label: "User",
		});

		if (email && email !== user.email.toLowerCase()) {
			const conflict = data.principals.find(
				(p) =>
					p.id !== user.id &&
					p.email.toLowerCase() === email &&
					p.projectId === user.projectId &&
					p.environmentId === user.environmentId &&
					p.status !== "deleted",
			);
			if (conflict) {
				throw new ClearanceError({
					code: "USER_EXISTS",
					message: `User ${email} already exists`,
					stage: "users.update",
					status: 409,
				});
			}
			user.email = email;
		}
		if (name !== undefined) user.name = name;
		if (status !== undefined) user.status = status;
		user.updatedAt = now;

		updated = { ...user };
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "users.update",
			subjectType: "principal",
			subjectId: user.id,
			outcome: "success",
			source: (input.source as "cli") ?? "cli",
			projectId: user.projectId,
			environmentId: user.environmentId,
			message: `Updated user ${user.email}`,
			metadata: {
				fields: [
					...(hasName ? ["name"] : []),
					...(hasEmail ? ["email"] : []),
					...(hasStatus ? ["status"] : []),
				],
			},
		});
	});

	if (!updated) {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage: "users.update",
			status: 404,
		});
	}
	return updated;
}

/**
 * Disable a principal (status=disabled). Soft-deleted and cross-scope ids fail
 * closed as NOT_FOUND. Active management sessions for the user are revoked in
 * the same audited mutation.
 */
export function disableUser(
	store: ManagementUnitOfWork,
	id: string,
	input?: {
		actor?: string;
		source?: AuditEvent["source"] | "import";
		scope?: ResourceScope;
	},
): Principal {
	assertSnapshotPrincipalWriterDisabled(store, "users.disable");
	const now = nowIso();
	const scope = input?.scope ?? resolveOperatorScope(store);
	let updated: Principal | undefined;

	store.mutate((data) => {
		const user = data.principals.find((p) => p.id === id);
		if (!user || user.status === "deleted") {
			throw new ClearanceError({
				code: "USER_NOT_FOUND",
				message: "User not found",
				stage: "users.disable",
				status: 404,
			});
		}
		assertResourceInScope(user, scope, {
			code: "USER_NOT_FOUND",
			stage: "users.disable",
			label: "User",
		});

		let revokedSessions = 0;
		for (const session of data.sessions) {
			if (session.principalId === user.id && session.status === "active") {
				session.status = "revoked";
				session.revokedAt = now;
				revokedSessions += 1;
			}
		}

		const alreadyDisabled = user.status === "disabled";
		if (!alreadyDisabled) {
			user.status = "disabled";
			user.updatedAt = now;
		}

		updated = { ...user };
		// Idempotent re-disable with no remaining sessions is a no-op (no audit).
		if (!alreadyDisabled || revokedSessions > 0) {
			appendAuditEvent(data, {
				actor: input?.actor ?? "operator",
				action: "users.disable",
				subjectType: "principal",
				subjectId: user.id,
				outcome: "success",
				source: (input?.source as "cli") ?? "cli",
				projectId: user.projectId,
				environmentId: user.environmentId,
				message: `Disabled user ${user.email}`,
				metadata: { revokedSessions, idempotent: alreadyDisabled },
			});
		}
	});

	if (!updated) {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage: "users.disable",
			status: 404,
		});
	}
	return updated;
}

/**
 * Soft-delete a principal (status=deleted). Removed from list/inspect thereafter.
 * Cross-scope ids fail closed as NOT_FOUND. Active sessions are revoked atomically.
 */
export function deleteUser(
	store: ManagementUnitOfWork,
	id: string,
	input?: {
		actor?: string;
		source?: AuditEvent["source"] | "import";
		scope?: ResourceScope;
	},
): Principal {
	assertSnapshotPrincipalWriterDisabled(store, "users.delete");
	const now = nowIso();
	const scope = input?.scope ?? resolveOperatorScope(store);
	let deleted: Principal | undefined;

	store.mutate((data) => {
		const user = data.principals.find((p) => p.id === id);
		if (!user || user.status === "deleted") {
			throw new ClearanceError({
				code: "USER_NOT_FOUND",
				message: "User not found",
				stage: "users.delete",
				status: 404,
			});
		}
		assertResourceInScope(user, scope, {
			code: "USER_NOT_FOUND",
			stage: "users.delete",
			label: "User",
		});

		user.status = "deleted";
		user.updatedAt = now;

		let revokedSessions = 0;
		for (const session of data.sessions) {
			if (session.principalId === user.id && session.status === "active") {
				session.status = "revoked";
				session.revokedAt = now;
				revokedSessions += 1;
			}
		}

		// Soft-remove memberships so deleted users do not retain active roles
		for (const membership of data.memberships) {
			if (
				membership.principalId === user.id &&
				membership.status === "active"
			) {
				membership.status = "removed";
				membership.updatedAt = now;
			}
		}

		deleted = { ...user };
		appendAuditEvent(data, {
			actor: input?.actor ?? "operator",
			action: "users.delete",
			subjectType: "principal",
			subjectId: user.id,
			outcome: "success",
			source: (input?.source as "cli") ?? "cli",
			projectId: user.projectId,
			environmentId: user.environmentId,
			message: `Deleted user ${user.email}`,
			metadata: { revokedSessions },
		});
	});

	if (!deleted) {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage: "users.delete",
			status: 404,
		});
	}
	return deleted;
}

export function createOrganization(
	store: ManagementUnitOfWork,
	input: {
		name: string;
		slug?: string;
		id?: string;
		projectId?: string;
		environmentId?: string;
		externalId?: string;
		actor?: string;
		source?: AuditEvent["source"] | "import";
	},
): Organization {
	const scope = resolveCreateScope(store, input);
	const slug = input.slug ?? slugify(input.name);
	const orgId = input.id?.trim() || newId("org");
	const now = nowIso();

	const org: Organization = {
		id: orgId,
		projectId: scope.projectId,
		environmentId: scope.environmentId,
		name: input.name,
		slug,
		status: "active",
		externalId: input.externalId,
		createdAt: now,
		updatedAt: now,
	};

	store.mutate((data) => {
		const projectId =
			input.projectId ??
			data.meta.config.projectId ??
			data.projects[0]?.id ??
			scope.projectId;
		const environmentId =
			input.environmentId ??
			data.meta.config.environmentId ??
			data.environments[0]?.id ??
			scope.environmentId;
		if (!projectId || !environmentId) {
			throw new ClearanceError({
				code: "NOT_INITIALIZED",
				message: "No project/environment — run clearance init",
				stage: "orgs.create",
			});
		}

		const existingSlug = data.organizations.find(
			(o) =>
				o.slug === slug &&
				o.projectId === projectId &&
				o.environmentId === environmentId &&
				o.status !== "archived",
		);
		if (existingSlug) {
			throw new ClearanceError({
				code: "ORG_SLUG_EXISTS",
				message: `Organization slug ${slug} already exists in this environment`,
				stage: "orgs.create",
				status: 409,
			});
		}

		if (data.organizations.some((o) => o.id === orgId)) {
			throw new ClearanceError({
				code: "ORG_EXISTS",
				message: `Organization id ${orgId} already exists`,
				stage: "orgs.create",
				status: 409,
			});
		}

		org.projectId = projectId;
		org.environmentId = environmentId;
		data.organizations.push(org);
		appendAuditEvent(data, {
			actor: input.actor ?? "operator",
			action: "orgs.create",
			subjectType: "organization",
			subjectId: org.id,
			outcome: "success",
			source: (input.source as "cli") ?? "cli",
			projectId,
			environmentId,
			organizationId: org.id,
			message: `Created organization ${org.name}`,
		});
	});

	return org;
}

async function requireTopologyScope(
	store: ManagementStore,
	scope: ResourceScope,
	stage: string,
): Promise<void> {
	const environment = await store.storeV2Topology!.getEnvironment({
		projectId: scope.projectId,
		id: scope.environmentId,
	});
	if (!environment) {
		throw new ClearanceError({
			code: "NOT_INITIALIZED",
			message: "No project/environment — run clearance init",
			stage,
		});
	}
}

async function lockTopologyScope(
	topology: StoreV2TopologyRepository,
	scope: ResourceScope,
	stage: string,
): Promise<void> {
	const project = await topology.lockProject({ id: scope.projectId });
	const environment = project
		? await topology.lockEnvironment({
			projectId: project.id,
			id: scope.environmentId,
		})
		: null;
	if (!project || !environment) {
		throw new ClearanceError({
			code: "NOT_INITIALIZED",
			message: "No project/environment — run clearance init",
			stage,
		});
	}
}

/** Relational-authority-aware management-only organization creation. */
export async function createOrganizationAuthoritative(
	store: ManagementStore,
	input: {
		name: string;
		slug?: string;
		id?: string;
		projectId?: string;
		environmentId?: string;
		externalId?: string;
		actor?: string;
		source?: AuditEvent["source"] | "import";
	},
): Promise<Organization> {
	if (!store.storeV2Topology?.authoritative) return createOrganization(store, input);
	if (!store.mutateStoreV2Topology) topologyMutationUnavailable("orgs.create");
	const scope = resolveCreateScope(store, input);
	await requireTopologyScope(store, scope, "orgs.create");
	const slug = input.slug ?? slugify(input.name);
	const id = input.id?.trim() || newId("org");
	if (await store.storeV2Topology.organizationIdExists(id)) {
		throw new ClearanceError({
			code: "ORG_EXISTS", message: `Organization id ${id} already exists`, stage: "orgs.create", status: 409,
		});
	}
	if (await store.storeV2Topology.getOrganizationBySlug({ scope, slug })) {
		throw new ClearanceError({
			code: "ORG_SLUG_EXISTS",
			message: `Organization slug ${slug} already exists in this environment`,
			stage: "orgs.create",
			status: 409,
		});
	}
	const now = nowIso();
	const organization: Organization = {
		id, projectId: scope.projectId, environmentId: scope.environmentId,
		name: input.name, slug, status: "active", externalId: input.externalId,
		createdAt: now, updatedAt: now,
	};
	try {
		return await store.mutateStoreV2Topology(async ({ topology, appendAudit }) => {
			await lockTopologyScope(topology, scope, "orgs.create");
			if (await topology.organizationIdExists(id)) {
				throw new ClearanceError({ code: "ORG_EXISTS", message: `Organization id ${id} already exists`, stage: "orgs.create", status: 409 });
			}
			if (await topology.getOrganizationBySlug({ scope, slug })) {
				throw new ClearanceError({ code: "ORG_SLUG_EXISTS", message: `Organization slug ${slug} already exists in this environment`, stage: "orgs.create", status: 409 });
			}
			const written = await topology.upsertOrganization(organization);
			appendAudit({
				actor: input.actor ?? "operator", action: "orgs.create", subjectType: "organization",
				subjectId: written.id, outcome: "success", source: (input.source as AuditEvent["source"]) ?? "cli",
				projectId: written.projectId, environmentId: written.environmentId, organizationId: written.id,
				message: `Created organization ${written.name}`,
			});
			return written;
		});
	} catch (error) {
		return topologyLifecycleError(error, "organization-create", slug);
	}
}

export function listOrganizations(
	store: ManagementStore,
	filter?: {
		environmentId?: string;
		projectId?: string;
		scope?: ResourceScope;
	},
): Organization[] {
	const inScope = filter?.scope ? scopeFilter(filter.scope) : null;
	return store.snapshot.organizations.filter((o) => {
		if (o.status === "archived") return false;
		if (inScope && !inScope(o)) return false;
		if (filter?.environmentId && o.environmentId !== filter.environmentId) {
			return false;
		}
		if (filter?.projectId && o.projectId !== filter.projectId) return false;
		return true;
	});
}

export const ORGS_LIST_DEFAULT_PAGE_LIMIT = 100;
export const ORGS_LIST_MAX_PAGE_LIMIT = 1000;

/**
 * Cursor-paginated organizations listing (FOLLOW.md P2.3.1).
 * Ordering: createdAt ascending, then id ascending (documented keyset).
 */
export function listOrganizationsPage(
	store: ManagementStore,
	opts?: {
		scope?: ResourceScope;
		limit?: number;
		/** Opaque cursor from a previous page's nextCursor (fail-closed). */
		cursor?: string;
	},
): { organizations: Organization[]; nextCursor: string | null } {
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const limit = normalizePageLimit(opts?.limit, {
		stage: "orgs.list",
		code: "ORGS_LIST_LIMIT_INVALID",
		defaultValue: ORGS_LIST_DEFAULT_PAGE_LIMIT,
		maximum: ORGS_LIST_MAX_PAGE_LIMIT,
	});
	const cursor = decodePageCursor(opts?.cursor, "organizations", "orgs.list");
	const all = listOrganizations(store, { scope });
	const page = paginateByCreatedAt(all, {
		surface: "organizations",
		order: "asc",
		limit,
		cursor,
	});
	return { organizations: page.items, nextCursor: page.nextCursor };
}

/** Authority-aware bounded active-organization listing. */
export async function listOrganizationsPageAuthoritative(
	store: ManagementStore,
	opts?: {
		scope?: ResourceScope;
		limit?: number;
		cursor?: string;
	},
): Promise<{ organizations: Organization[]; nextCursor: string | null }> {
	if (!store.storeV2Topology?.authoritative) {
		return listOrganizationsPage(store, opts);
	}
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const limit = normalizePageLimit(opts?.limit, {
		stage: "orgs.list",
		code: "ORGS_LIST_LIMIT_INVALID",
		defaultValue: ORGS_LIST_DEFAULT_PAGE_LIMIT,
		maximum: ORGS_LIST_MAX_PAGE_LIMIT,
	});
	const cursor = decodePageCursor(opts?.cursor, "organizations", "orgs.list");
	const page = await store.storeV2Topology.listOrganizationsPage({
		scope,
		limit,
		...(cursor ? { cursor } : {}),
	});
	const last = page.organizations[page.organizations.length - 1];
	return {
		organizations: page.organizations,
		nextCursor:
			page.hasMore && last
				? encodePageCursor("organizations", {
					createdAt: last.createdAt,
					id: last.id,
				})
				: null,
	};
}

export function inspectOrganization(
	store: ManagementStore,
	id: string,
	scope?: ResourceScope,
): Organization {
	const org = store.snapshot.organizations.find((o) => o.id === id);
	if (!org || org.status === "archived") {
		throw new ClearanceError({
			code: "ORG_NOT_FOUND",
			message: `Organization not found`,
			stage: "orgs.inspect",
			status: 404,
		});
	}
	if (scope) {
		assertResourceInScope(org, scope, {
			code: "ORG_NOT_FOUND",
			stage: "orgs.inspect",
			label: "Organization",
		});
	}
	return org;
}

/** Scope-safe authority-aware active-organization point lookup. */
export async function inspectOrganizationAuthoritative(
	store: ManagementStore,
	id: string,
	scope?: ResourceScope,
): Promise<Organization> {
	if (!store.storeV2Topology?.authoritative) {
		return inspectOrganization(store, id, scope);
	}
	const resolvedScope = scope ?? resolveOperatorScope(store);
	const organization = await store.storeV2Topology.getOrganization({
		scope: resolvedScope,
		id,
	});
	if (!organization || organization.status === "archived") {
		throw new ClearanceError({
			code: "ORG_NOT_FOUND",
			message: "Organization not found",
			stage: "orgs.inspect",
			status: 404,
		});
	}
	return organization;
}

const ORG_SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * Update legitimate mutable organization fields: name and/or slug.
 * Status is not mutable here — use archiveOrganization. Soft-archived and
 * cross-scope ids fail closed as ORG_NOT_FOUND. Idempotent when values match.
 * Audits only when at least one field actually changes.
 */
export function updateOrganization(
	store: ManagementUnitOfWork,
	id: string,
	input: {
		name?: string;
		slug?: string;
		actor?: string;
		source?: AuditEvent["source"] | "import";
		scope?: ResourceScope;
	},
): Organization {
	const hasName = input.name !== undefined;
	const hasSlug = input.slug !== undefined;
	if (!hasName && !hasSlug) {
		throw new ClearanceError({
			code: "ORG_UPDATE_EMPTY",
			message: "At least one of name or slug is required",
			stage: "orgs.update",
			status: 400,
			remediation: "Pass --name and/or --slug",
		});
	}
	if (hasName && !String(input.name).trim()) {
		throw new ClearanceError({
			code: "ORG_NAME_REQUIRED",
			message: "Name must not be empty",
			stage: "orgs.update",
			status: 400,
		});
	}
	let nextSlug: string | undefined;
	if (hasSlug) {
		nextSlug = String(input.slug).trim().toLowerCase();
		if (!nextSlug || !ORG_SLUG_RE.test(nextSlug) || nextSlug.length > 48) {
			throw new ClearanceError({
				code: "ORG_SLUG_INVALID",
				message:
					"Slug must be 1–48 chars of lowercase alphanumeric segments separated by single hyphens",
				stage: "orgs.update",
				status: 400,
				remediation: "Use a slug like acme-corp (lowercase, hyphens only)",
			});
		}
	}
	const nextName = hasName ? String(input.name).trim() : undefined;
	const scope = input.scope ?? resolveOperatorScope(store);
	const now = nowIso();
	let updated: Organization | undefined;

	store.mutate((data) => {
		const org = data.organizations.find((o) => o.id === id);
		if (!org || org.status === "archived") {
			throw new ClearanceError({
				code: "ORG_NOT_FOUND",
				message: "Organization not found",
				stage: "orgs.update",
				status: 404,
			});
		}
		assertResourceInScope(org, scope, {
			code: "ORG_NOT_FOUND",
			stage: "orgs.update",
			label: "Organization",
		});

		const before = { name: org.name, slug: org.slug };
		const fields: string[] = [];

		if (nextSlug && nextSlug !== org.slug) {
			const conflict = data.organizations.find(
				(o) =>
					o.id !== org.id &&
					o.slug === nextSlug &&
					o.projectId === org.projectId &&
					o.environmentId === org.environmentId &&
					o.status !== "archived",
			);
			if (conflict) {
				throw new ClearanceError({
					code: "ORG_SLUG_EXISTS",
					message: `Organization slug ${nextSlug} already exists in this environment`,
					stage: "orgs.update",
					status: 409,
				});
			}
			org.slug = nextSlug;
			fields.push("slug");
		}
		if (nextName !== undefined && nextName !== org.name) {
			org.name = nextName;
			fields.push("name");
		}

		// Idempotent: only touch updatedAt + audit when a field actually changes.
		if (fields.length > 0) {
			org.updatedAt = now;
			appendAuditEvent(data, {
				actor: input.actor ?? "operator",
				action: "orgs.update",
				subjectType: "organization",
				subjectId: org.id,
				outcome: "success",
				source: (input.source as "cli") ?? "cli",
				projectId: org.projectId,
				environmentId: org.environmentId,
				organizationId: org.id,
				message: `Updated organization ${org.name}`,
				metadata: {
					fields,
					before,
					after: { name: org.name, slug: org.slug },
				},
			});
		}

		updated = { ...org };
	});

	if (!updated) {
		throw new ClearanceError({
			code: "ORG_NOT_FOUND",
			message: "Organization not found",
			stage: "orgs.update",
			status: 404,
		});
	}
	return updated;
}

/** Relational-authority-aware management-only organization update. */
export async function updateOrganizationAuthoritative(
	store: ManagementStore,
	id: string,
	input: {
		name?: string;
		slug?: string;
		actor?: string;
		source?: AuditEvent["source"] | "import";
		scope?: ResourceScope;
	},
): Promise<Organization> {
	if (!store.storeV2Topology?.authoritative) return updateOrganization(store, id, input);
	if (!store.mutateStoreV2Topology) topologyMutationUnavailable("orgs.update");
	const hasName = input.name !== undefined;
	const hasSlug = input.slug !== undefined;
	if (!hasName && !hasSlug) {
		throw new ClearanceError({ code: "ORG_UPDATE_EMPTY", message: "At least one of name or slug is required", stage: "orgs.update", status: 400, remediation: "Pass --name and/or --slug" });
	}
	if (hasName && !String(input.name).trim()) {
		throw new ClearanceError({ code: "ORG_NAME_REQUIRED", message: "Name must not be empty", stage: "orgs.update", status: 400 });
	}
	let nextSlug: string | undefined;
	if (hasSlug) {
		nextSlug = String(input.slug).trim().toLowerCase();
		if (!nextSlug || !ORG_SLUG_RE.test(nextSlug) || nextSlug.length > 48) {
			throw new ClearanceError({ code: "ORG_SLUG_INVALID", message: "Slug must be 1–48 chars of lowercase alphanumeric segments separated by single hyphens", stage: "orgs.update", status: 400, remediation: "Use a slug like acme-corp (lowercase, hyphens only)" });
		}
	}
	const scope = input.scope ?? resolveOperatorScope(store);
	const nextName = hasName ? String(input.name).trim() : undefined;
	const current = await store.storeV2Topology.getOrganization({ scope, id });
	if (!current || current.status === "archived") {
		throw new ClearanceError({ code: "ORG_NOT_FOUND", message: "Organization not found", stage: "orgs.update", status: 404 });
	}
	if (nextSlug && nextSlug !== current.slug) {
		const conflict = await store.storeV2Topology.getOrganizationBySlug({
			scope,
			slug: nextSlug,
		});
		if (conflict && conflict.id !== current.id) {
			throw new ClearanceError({
				code: "ORG_SLUG_EXISTS",
				message: `Organization slug ${nextSlug} already exists in this environment`,
				stage: "orgs.update",
				status: 409,
			});
		}
	}
	const now = nowIso();
	try {
		return await store.mutateStoreV2Topology(async ({ topology, appendAudit }) => {
			await lockTopologyScope(topology, scope, "orgs.update");
			const organization = await topology.lockOrganization({ scope, id });
			if (!organization || organization.status === "archived") {
				throw new ClearanceError({ code: "ORG_NOT_FOUND", message: "Organization not found", stage: "orgs.update", status: 404 });
			}
			const fields: string[] = [];
			const before = { name: organization.name, slug: organization.slug };
			const updated = { ...organization };
			if (nextSlug && nextSlug !== updated.slug) {
				const conflict = await topology.getOrganizationBySlug({ scope, slug: nextSlug });
				if (conflict && conflict.id !== updated.id) {
					throw new ClearanceError({ code: "ORG_SLUG_EXISTS", message: `Organization slug ${nextSlug} already exists in this environment`, stage: "orgs.update", status: 409 });
				}
				updated.slug = nextSlug;
				fields.push("slug");
			}
			if (nextName !== undefined && nextName !== updated.name) { updated.name = nextName; fields.push("name"); }
			if (fields.length === 0) return updated;
			updated.updatedAt = now;
			const written = await topology.upsertOrganization(updated);
			appendAudit({
				actor: input.actor ?? "operator", action: "orgs.update", subjectType: "organization",
				subjectId: written.id, outcome: "success", source: (input.source as AuditEvent["source"]) ?? "cli",
				projectId: written.projectId, environmentId: written.environmentId, organizationId: written.id,
				message: `Updated organization ${written.name}`,
				metadata: { fields, before, after: { name: written.name, slug: written.slug } },
			});
			return written;
		});
	} catch (error) {
		return topologyLifecycleError(error, "organization-update", nextSlug);
	}
}

export type ArchiveOrganizationResult = {
	organization: Organization;
	dryRun: boolean;
	idempotent: boolean;
	wouldChange: boolean;
};

/**
 * Archive an organization (status=archived). Requires confirm=true for mutation
 * (CLI --yes). Dry-run previews without audit. Idempotent re-archive succeeds
 * without a second audit when already archived. Membership list/add/update/remove
 * and org inspect remain fail-closed for archived orgs (recovery via audit + row).
 */
export function archiveOrganization(
	store: ManagementUnitOfWork,
	id: string,
	input?: {
		dryRun?: boolean;
		/** Required for mutation. CLI maps --yes → confirm=true. */
		confirm?: boolean;
		actor?: string;
		source?: AuditEvent["source"] | "import";
		scope?: ResourceScope;
	},
): ArchiveOrganizationResult {
	const scope = input?.scope ?? resolveOperatorScope(store);
	const dryRun = input?.dryRun === true || input?.confirm !== true;
	const orgId = id?.trim();
	if (!orgId) {
		throw new ClearanceError({
			code: "ORG_ID_REQUIRED",
			message: "Organization id is required",
			stage: "orgs.archive",
			status: 400,
		});
	}

	// Locate including already-archived for idempotent re-archive under scope.
	const existing = store.snapshot.organizations.find((o) => o.id === orgId);
	if (!existing) {
		throw new ClearanceError({
			code: "ORG_NOT_FOUND",
			message: "Organization not found",
			stage: "orgs.archive",
			status: 404,
		});
	}
	assertResourceInScope(existing, scope, {
		code: "ORG_NOT_FOUND",
		stage: "orgs.archive",
		label: "Organization",
	});

	const alreadyArchived = existing.status === "archived";
	if (dryRun) {
		return {
			organization: { ...existing },
			dryRun: true,
			idempotent: alreadyArchived,
			wouldChange: !alreadyArchived,
		};
	}

	const now = nowIso();
	let result: ArchiveOrganizationResult | undefined;

	store.mutate((data) => {
		const org = data.organizations.find((o) => o.id === orgId);
		if (!org) {
			throw new ClearanceError({
				code: "ORG_NOT_FOUND",
				message: "Organization not found",
				stage: "orgs.archive",
				status: 404,
			});
		}
		assertResourceInScope(org, scope, {
			code: "ORG_NOT_FOUND",
			stage: "orgs.archive",
			label: "Organization",
		});

		const wasArchived = org.status === "archived";
		if (!wasArchived) {
			org.status = "archived";
			org.updatedAt = now;
			appendAuditEvent(data, {
				actor: input?.actor ?? "operator",
				action: "orgs.archive",
				subjectType: "organization",
				subjectId: org.id,
				outcome: "success",
				source: (input?.source as "cli") ?? "cli",
				projectId: org.projectId,
				environmentId: org.environmentId,
				organizationId: org.id,
				message: `Archived organization ${org.name}`,
				metadata: { idempotent: false },
			});
		}

		result = {
			organization: { ...org },
			dryRun: false,
			idempotent: wasArchived,
			wouldChange: !wasArchived,
		};
	});

	if (!result) {
		throw new ClearanceError({
			code: "ORG_NOT_FOUND",
			message: "Organization not found",
			stage: "orgs.archive",
			status: 404,
		});
	}
	return result;
}

/** Relational-authority-aware management-only organization archive. */
export async function archiveOrganizationAuthoritative(
	store: ManagementStore,
	id: string,
	input?: {
		dryRun?: boolean;
		confirm?: boolean;
		actor?: string;
		source?: AuditEvent["source"] | "import";
		scope?: ResourceScope;
	},
): Promise<ArchiveOrganizationResult> {
	if (!store.storeV2Topology?.authoritative) return archiveOrganization(store, id, input);
	const scope = input?.scope ?? resolveOperatorScope(store);
	const orgId = id?.trim();
	if (!orgId) throw new ClearanceError({ code: "ORG_ID_REQUIRED", message: "Organization id is required", stage: "orgs.archive", status: 400 });
	const dryRun = input?.dryRun === true || input?.confirm !== true;
	const existing = await store.storeV2Topology.getOrganization({ scope, id: orgId });
	if (!existing) throw new ClearanceError({ code: "ORG_NOT_FOUND", message: "Organization not found", stage: "orgs.archive", status: 404 });
	const alreadyArchived = existing.status === "archived";
	if (dryRun) return { organization: existing, dryRun: true, idempotent: alreadyArchived, wouldChange: !alreadyArchived };
	if (!store.mutateStoreV2Topology) topologyMutationUnavailable("orgs.archive");
	return await store.mutateStoreV2Topology(async ({ topology, appendAudit }) => {
		await lockTopologyScope(topology, scope, "orgs.archive");
		const organization = await topology.lockOrganization({ scope, id: orgId });
		if (!organization || organization.status === "archived") throw new ClearanceError({ code: "ORG_NOT_FOUND", message: "Organization not found", stage: "orgs.archive", status: 404 });
		const written = await topology.upsertOrganization({ ...organization, status: "archived", updatedAt: nowIso() });
		appendAudit({
			actor: input?.actor ?? "operator", action: "orgs.archive", subjectType: "organization",
			subjectId: written.id, outcome: "success", source: (input?.source as AuditEvent["source"]) ?? "cli",
			projectId: written.projectId, environmentId: written.environmentId, organizationId: written.id,
			message: `Archived organization ${written.name}`, metadata: { idempotent: false },
		});
		return { organization: written, dryRun: false, idempotent: false, wouldChange: true };
	});
}

// --- Users export (bounded, scoped, redacted, deterministic) ---

export const USERS_EXPORT_DEFAULT_LIMIT = 100;
export const USERS_EXPORT_MAX_LIMIT = 1000;
export const USERS_EXPORT_FORMATS = ["json", "jsonl"] as const;
export type UsersExportFormat = (typeof USERS_EXPORT_FORMATS)[number];

export type UsersExportOptions = {
	limit?: number;
	/** Filter by principal status (active|disabled). Deleted never exported. */
	status?: "active" | "disabled" | string;
	format?: UsersExportFormat | string;
	/** Absolute or relative path; when set, artifact is written atomically (CLI only) */
	outputPath?: string;
	force?: boolean;
	scope?: ResourceScope;
	actor?: string;
	source?: "cli" | "console" | "api" | "system";
	skipAudit?: boolean;
};

export type UsersExportEnvelope = {
	schemaVersion: 1;
	kind: "users.export";
	exportedAt: string;
	format: UsersExportFormat;
	scope: ResourceScope;
	limit: number;
	count: number;
	truncated: boolean;
	filters: {
		status?: "active" | "disabled";
	};
	users: Principal[];
	outputPath?: string;
	correlationId: string;
};

export function normalizeUsersExportLimit(limit: number | undefined): number {
	const value = limit ?? USERS_EXPORT_DEFAULT_LIMIT;
	if (!Number.isInteger(value) || value < 1 || value > USERS_EXPORT_MAX_LIMIT) {
		throw new ClearanceError({
			code: "USERS_EXPORT_LIMIT_INVALID",
			message: `Export limit must be an integer between 1 and ${USERS_EXPORT_MAX_LIMIT}`,
			stage: "users.export",
			status: 400,
			remediation: `Pass --limit with an integer from 1 through ${USERS_EXPORT_MAX_LIMIT}`,
		});
	}
	return value;
}

export function normalizeUsersExportFormat(
	format: string | undefined,
): UsersExportFormat {
	const value = (format ?? "json").toLowerCase();
	if (!(USERS_EXPORT_FORMATS as readonly string[]).includes(value)) {
		throw new ClearanceError({
			code: "USERS_EXPORT_FORMAT_INVALID",
			message: `Unsupported export format "${format}"`,
			stage: "users.export",
			status: 400,
			remediation: `Use one of: ${USERS_EXPORT_FORMATS.join(", ")}`,
		});
	}
	return value as UsersExportFormat;
}

export function normalizeUsersExportStatus(
	status: string | undefined,
): "active" | "disabled" | undefined {
	if (status === undefined || status === null || status === "") return undefined;
	if (status === "active" || status === "disabled") return status;
	throw new ClearanceError({
		code: "USERS_EXPORT_STATUS_INVALID",
		message: "Export status filter must be active or disabled",
		stage: "users.export",
		status: 400,
		remediation: "Pass --status active|disabled (deleted users are never exported)",
	});
}

/** Stable sort: email asc, then id asc. */
export function sortUsersDeterministic(users: Principal[]): Principal[] {
	return [...users].sort((a, b) => {
		const ea = a.email.toLowerCase();
		const eb = b.email.toLowerCase();
		if (ea !== eb) return ea < eb ? -1 : 1;
		if (a.id === b.id) return 0;
		return a.id < b.id ? -1 : 1;
	});
}

/** Public export view of a principal — no write-only secrets (none stored). */
export function sanitizePrincipalForExport(user: Principal): Principal {
	const base: Principal = {
		id: user.id,
		projectId: user.projectId,
		environmentId: user.environmentId,
		email: user.email,
		name: user.name,
		status: user.status,
		createdAt: user.createdAt,
		updatedAt: user.updatedAt,
	};
	if (user.externalId !== undefined) {
		// Defense-in-depth: treat externalId as opaque and redact secret-shaped values
		const redacted = redactRecord({ externalId: user.externalId });
		const ext = redacted?.externalId;
		if (typeof ext === "string") {
			base.externalId = ext;
		}
	}
	return base;
}

export function selectUsersForExport(
	store: ManagementStore,
	filter: {
		limit: number;
		status?: "active" | "disabled";
		scope: ResourceScope;
	},
): { users: Principal[]; truncated: boolean } {
	let users = principalReadView(store).filter(
		(p) =>
			p.status !== "deleted" &&
			p.projectId === filter.scope.projectId &&
			p.environmentId === filter.scope.environmentId,
	);
	if (filter.status) {
		users = users.filter((p) => p.status === filter.status);
	}
	const ordered = sortUsersDeterministic(users).map(sanitizePrincipalForExport);
	const truncated = ordered.length > filter.limit;
	return {
		users: ordered.slice(0, filter.limit),
		truncated,
	};
}

function serializeUsersExportBody(
	envelope: UsersExportEnvelope,
	format: UsersExportFormat,
): string {
	if (format === "jsonl") {
		if (envelope.users.length === 0) return "";
		return `${envelope.users.map((u) => JSON.stringify(u)).join("\n")}\n`;
	}
	return `${JSON.stringify(envelope, null, 2)}\n`;
}

/**
 * Export principals: scoped, bounded, redacted, deterministic.
 * Optional file write is atomic and refuse-overwrite by default (CLI).
 * Audit never persists local filesystem paths — only wroteFile boolean.
 */
export function exportUsers(
	store: ManagementStore,
	opts: UsersExportOptions = {},
): UsersExportEnvelope {
	const scope = opts.scope ?? resolveOperatorScope(store);
	const limit = normalizeUsersExportLimit(opts.limit);
	const format = normalizeUsersExportFormat(opts.format);
	const status = normalizeUsersExportStatus(
		opts.status as string | undefined,
	);
	const corr = correlationId();

	const { users, truncated } = selectUsersForExport(store, {
		limit,
		status,
		scope,
	});

	const envelope: UsersExportEnvelope = {
		schemaVersion: 1,
		kind: "users.export",
		exportedAt: nowIso(),
		format,
		scope,
		limit,
		count: users.length,
		truncated,
		filters: {
			...(status ? { status } : {}),
		},
		users,
		correlationId: corr,
	};

	if (opts.outputPath) {
		const body = serializeUsersExportBody(envelope, format);
		const written = writeExportArtifact(
			opts.outputPath,
			body,
			Boolean(opts.force),
			{
				stage: "users.export",
				existsCode: "USERS_EXPORT_EXISTS",
				writeFailedCode: "USERS_EXPORT_WRITE_FAILED",
			},
		);
		envelope.outputPath = written;
	}

	if (!opts.skipAudit) {
		store.mutate((data) => {
			appendAuditEvent(data, {
				actor: opts.actor ?? "operator",
				action: "users.export",
				subjectType: "user_export",
				outcome: "success",
				source: opts.source ?? "cli",
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				correlationId: corr,
				message: `Exported ${users.length} user(s)`,
				metadata: {
					count: users.length,
					limit,
					truncated,
					format,
					wroteFile: Boolean(envelope.outputPath),
					filters: envelope.filters,
				},
			});
		});
	}

	return envelope;
}

/** Bounded authority-aware export backed by the relational email-order index. */
export async function exportUsersAuthoritative(
	store: ManagementStore,
	opts: UsersExportOptions = {},
): Promise<UsersExportEnvelope> {
	if (!store.storeV2Principals?.authoritative) return exportUsers(store, opts);
	const reader = store.storeV2Principals.listForExport;
	if (!reader) {
		throw new ClearanceError({
			code: "STORE_V2_PRINCIPAL_EXPORT_READER_REQUIRED",
			message: "Relational principal export reader is unavailable",
			stage: "users.export",
			status: 500,
		});
	}
	const scope = opts.scope ?? resolveOperatorScope(store);
	const limit = normalizeUsersExportLimit(opts.limit);
	const format = normalizeUsersExportFormat(opts.format);
	const status = normalizeUsersExportStatus(opts.status as string | undefined);
	const corr = correlationId();
	const selected = await reader({
		scope,
		limit,
		...(status ? { status } : {}),
	});
	const users = selected.principals.map(sanitizePrincipalForExport);
	const envelope: UsersExportEnvelope = {
		schemaVersion: 1,
		kind: "users.export",
		exportedAt: nowIso(),
		format,
		scope,
		limit,
		count: users.length,
		truncated: selected.hasMore,
		filters: { ...(status ? { status } : {}) },
		users,
		correlationId: corr,
	};
	if (opts.outputPath) {
		const written = writeExportArtifact(
			opts.outputPath,
			serializeUsersExportBody(envelope, format),
			Boolean(opts.force),
			{
				stage: "users.export",
				existsCode: "USERS_EXPORT_EXISTS",
				writeFailedCode: "USERS_EXPORT_WRITE_FAILED",
			},
		);
		envelope.outputPath = written;
	}
	if (!opts.skipAudit) {
		store.mutate((data) => {
			appendAuditEvent(data, {
				actor: opts.actor ?? "operator",
				action: "users.export",
				subjectType: "user_export",
				outcome: "success",
				source: opts.source ?? "cli",
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				correlationId: corr,
				message: `Exported ${users.length} user(s)`,
				metadata: {
					count: users.length,
					limit,
					truncated: selected.hasMore,
					format,
					wroteFile: Boolean(envelope.outputPath),
					filters: envelope.filters,
				},
			});
		});
	}
	return envelope;
}

// Membership lifecycle lives in members.ts (role validation + owner invariants).
// Re-exported from index for a single public surface.
export {
	addMember,
	updateMember,
	removeMember,
	listMembers,
	inspectMembership,
	findActiveMembership,
	resolveMembershipId,
	assertOwnerInvariant,
} from "./members.js";

export function listEvents(
	store: ManagementStore,
	filter?: {
		limit?: number;
		organizationId?: string;
		action?: string;
		scope?: ResourceScope;
	},
) {
	let events = store.snapshot.events;
	if (filter?.scope) {
		events = events.filter(
			(e) =>
				(!e.projectId || e.projectId === filter.scope!.projectId) &&
				(!e.environmentId || e.environmentId === filter.scope!.environmentId),
		);
	}
	if (filter?.organizationId) {
		events = events.filter((e) => e.organizationId === filter.organizationId);
	}
	if (filter?.action) {
		events = events.filter((e) => e.action === filter.action);
	}
	return events.slice(0, filter?.limit ?? 50);
}

export const EVENTS_LIST_DEFAULT_PAGE_LIMIT = 50;
export const EVENTS_LIST_MAX_PAGE_LIMIT = 1000;

/**
 * Cursor-paginated audit events listing (FOLLOW.md P2.3.1).
 * Ordering: createdAt descending, then id descending (newest first — matches
 * the deterministic export order in events.ts). Keyset cursors survive the
 * prepend-heavy events array where index cursors would duplicate rows.
 */
export function listEventsPage(
	store: ManagementStore,
	filter?: {
		limit?: number;
		organizationId?: string;
		action?: string;
		scope?: ResourceScope;
		/** Opaque cursor from a previous page's nextCursor (fail-closed). */
		cursor?: string;
	},
): { events: AuditEvent[]; nextCursor: string | null } {
	const limit = normalizePageLimit(filter?.limit, {
		stage: "events.list",
		code: "EVENTS_LIST_OPTION_INVALID",
		defaultValue: EVENTS_LIST_DEFAULT_PAGE_LIMIT,
		maximum: EVENTS_LIST_MAX_PAGE_LIMIT,
	});
	const cursor = decodePageCursor(filter?.cursor, "events", "events.list");
	// Reuse the exact legacy filter semantics (scope/org/action), unbounded.
	const all = listEvents(store, {
		limit: Number.MAX_SAFE_INTEGER,
		...(filter?.organizationId ? { organizationId: filter.organizationId } : {}),
		...(filter?.action ? { action: filter.action } : {}),
		...(filter?.scope ? { scope: filter.scope } : {}),
	});
	const page = paginateByCreatedAt(all, {
		surface: "events",
		order: "desc",
		limit,
		cursor,
	});
	return { events: page.items, nextCursor: page.nextCursor };
}

export function createSession(
	store: ManagementStore,
	input: { principalId: string; environmentId: string; scope?: ResourceScope },
): SessionRecord {
	const principal = inspectUser(store, input.principalId, input.scope);
	return createSessionForPrincipal(store, principal, input);
}

function createSessionForPrincipal(
	store: ManagementUnitOfWork,
	principal: Principal,
	input: { principalId: string; environmentId: string; scope?: ResourceScope },
): SessionRecord {
	if (input.scope && principal.environmentId !== input.environmentId) {
		throw new ClearanceError({
			code: "USER_NOT_FOUND",
			message: "User not found",
			stage: "sessions.create",
			status: 404,
		});
	}
	const now = nowIso();
	const session: SessionRecord = {
		id: newId("sess"),
		principalId: principal.id,
		environmentId: input.environmentId,
		status: "active",
		createdAt: now,
	};
	store.mutate((data) => {
		data.sessions.push(session);
		appendAuditEvent(data, {
			actor: principal.email,
			action: "sessions.create",
			subjectType: "session",
			subjectId: session.id,
			outcome: "success",
			source: "system",
			projectId: principal.projectId,
			environmentId: input.environmentId,
			message: `Session created for ${principal.email}`,
		});
	});
	return session;
}

/** Transaction-bound session seed for normalized principal authority. */
export async function createSessionAuthoritative(
	store: ManagementStore,
	input: { principalId: string; environmentId: string; scope?: ResourceScope },
): Promise<SessionRecord> {
	if (!store.storeV2Principals?.authoritative) return createSession(store, input);
	if (!input.scope || typeof store.mutateCoordinated !== "function") {
		throw new ClearanceError({
			code: "STORE_V2_PRINCIPAL_MUTATION_REQUIRED",
			message: "Relational session creation requires scoped coordinated storage.",
			stage: "sessions.create",
			status: 500,
		});
	}
	return store.mutateCoordinated(async ({ data, principals }) => {
		const principal = await principals?.getById({
			scope: input.scope!,
			id: input.principalId,
		});
		if (!principal) {
			throw new ClearanceError({
				code: "USER_NOT_FOUND",
				message: "User not found",
				stage: "sessions.create",
				status: 404,
			});
		}
		const draft: ManagementUnitOfWork = {
			get snapshot() {
				return data;
			},
			mutate(mutator) {
				mutator(data);
				return data;
			},
		};
		return createSessionForPrincipal(draft, principal, input);
	});
}

export function overviewStats(store: ManagementStore, scope?: ResourceScope) {
	const users = listUsers(store, scope ? { scope } : undefined);
	const orgs = listOrganizations(store, scope ? { scope } : undefined);
	const events = listEvents(store, {
		limit: 10,
		...(scope ? { scope } : {}),
	});
	const activeSessions = store.snapshot.sessions.filter((s) => {
		if (s.status !== "active") return false;
		if (!scope) return true;
		const p = principalReadView(store).find((x) => x.id === s.principalId);
		return p
			? p.projectId === scope.projectId && p.environmentId === scope.environmentId
			: false;
	});
	return {
		totalUsers: users.length,
		activeUsers: users.filter((u) => u.status === "active").length,
		organizations: orgs.length,
		activeSessions: activeSessions.length,
		recentEvents: events,
		releaseVersion: store.snapshot.releaseVersion,
		schemaVersion: store.snapshot.meta.schemaVersion,
		resourceCounts: store.resourceCounts(),
	};
}

export type AuthoritativeOverviewStats = Omit<
	ReturnType<typeof overviewStats>,
	"resourceCounts"
> & {
	/** Only authority-unavailable resources are nullable. */
	resourceCounts: Record<string, number | null>;
};

export async function overviewStatsAuthoritative(
	store: ManagementStore,
	scope?: ResourceScope,
): Promise<AuthoritativeOverviewStats> {
	const principalsAuthoritative = store.storeV2Principals?.authoritative === true;
	const topologyAuthoritative = store.storeV2Topology?.authoritative === true;
	const eventsAuthoritative = store.storeV2Events?.authoritative === true;
	if (!principalsAuthoritative && !topologyAuthoritative && !eventsAuthoritative) {
		return overviewStats(store, scope);
	}
	const resolvedScope = scope ?? resolveOperatorScope(store);
	const principalCounts = principalsAuthoritative
		? (() => {
			const countReader = store.storeV2Principals?.countByScope;
			if (!countReader) {
				throw new ClearanceError({
					code: "STORE_V2_PRINCIPAL_COUNT_READER_REQUIRED",
					message: "Relational principal count reader is unavailable",
					stage: "overview",
					status: 500,
				});
			}
			return countReader({ scope: resolvedScope });
		})()
		: Promise.resolve((() => {
			const users = listUsers(store, { scope: resolvedScope });
			return {
				total: users.length,
				active: users.filter((user) => user.status === "active").length,
			};
		})());
	const activeSessions = principalsAuthoritative
		? store.storeV2Principals?.countActiveSessions?.({ scope: resolvedScope }) ??
			Promise.resolve(0)
		: Promise.resolve(store.snapshot.sessions.filter((session) => {
			if (session.status !== "active") return false;
			const principal = principalReadView(store).find(
				(candidate) => candidate.id === session.principalId,
			);
			return principal
				? principal.projectId === resolvedScope.projectId &&
					principal.environmentId === resolvedScope.environmentId
				: false;
		}).length);
	const organizationCount = topologyAuthoritative
		? store.storeV2Topology!.countOrganizations({ scope: resolvedScope })
		: Promise.resolve(listOrganizations(store, { scope: resolvedScope }).length);
	const [counts, sessions, organizations] = await Promise.all([
		principalCounts,
		activeSessions,
		organizationCount,
	]);
	const recentEvents = eventsAuthoritative
		? (await store.storeV2Events.listPage({
				scope: resolvedScope,
				limit: 10,
			})).events
		: listEvents(store, { limit: 10, scope: resolvedScope });
	const resourceCounts = store.resourceCounts();
	return {
		totalUsers: counts.total,
		activeUsers: counts.active,
		organizations,
		activeSessions: sessions,
		recentEvents,
		releaseVersion: store.snapshot.releaseVersion,
		schemaVersion: store.snapshot.meta.schemaVersion,
		resourceCounts: {
			...resourceCounts,
			principals: counts.total,
			sessions,
			events: eventsAuthoritative ? null : resourceCounts.events,
		},
	};
}

// re-export for callers that used recordEvent from core path historically
export { recordEvent };
