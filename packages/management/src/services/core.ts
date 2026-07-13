import { existsSync } from "node:fs";
import type { ManagementStore } from "../store/types.js";
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

function resolveCreateScope(
	store: ManagementStore,
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

export function listProjects(store: ManagementStore): Project[] {
	return store.snapshot.projects;
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

/** Validate an environment creation request without mutating the store. */
export function planEnvironmentCreate(
	store: ManagementStore,
	input: {
		projectId?: string;
		name: string;
		kind?: Environment["kind"];
	},
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
	const project = store.snapshot.projects.find((p) => p.id === input.projectId);
	if (!project) {
		throw new ClearanceError({
			code: "PROJECT_NOT_FOUND",
			message: `Project ${input.projectId} not found`,
			stage: "env.create",
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
		memberships: number;
		identityConnections: number;
		directoryConnections: number;
		roles: number;
		sessions: number;
		events: number;
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
export function inspectEnvironment(
	store: ManagementStore,
	id?: string,
	opts?: { scope?: ResourceScope },
): EnvironmentInspectResult {
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

	const principals = store.snapshot.principals.filter(
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
	input: {
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
	},
): EnvironmentPromoteResult {
	const scope = input.scope ?? resolveOperatorScope(store);
	const dryRun = input.dryRun === true || input.confirm !== true;
	const corr = correlationId();
	const stage = "env.promote";

	const toKey = input.to?.trim();
	if (!toKey) {
		throw new ClearanceError({
			code: "ENV_PROMOTE_TARGET_REQUIRED",
			message: "Promotion target environment is required",
			stage,
			status: 400,
			remediation: "Pass --to <environment-id-or-slug>",
		});
	}

	const source = findEnvironmentInProject(
		store,
		input.from?.trim() || scope.environmentId,
		scope.projectId,
		stage,
	);
	// Source must be the principal environment (exact environment scope for mutations)
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

	const target = findEnvironmentInProject(store, toKey, scope.projectId, stage);

	const inspected = inspectEnvironment(store, source.id, { scope });
	const resourceCounts = inspected.local.resourceCounts;

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
	store: ManagementStore,
	input: {
		email: string;
		name: string;
		/** Optional stable id (e.g. Clearance runtime user id) */
		id?: string;
		projectId?: string;
		environmentId?: string;
		externalId?: string;
		actor?: string;
		source?: "cli" | "console" | "api" | "import" | "scim";
	},
): Principal {
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
	return store.snapshot.principals.filter((p) => {
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
 * Lookup by id. When scope is provided, cross-scope ids fail closed as NOT_FOUND
 * without revealing that the foreign resource exists.
 */
export function inspectUser(
	store: ManagementStore,
	id: string,
	scope?: ResourceScope,
): Principal {
	const user = store.snapshot.principals.find((p) => p.id === id);
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
	store: ManagementStore,
	id: string,
	input: {
		name?: string;
		email?: string;
		/** Re-enable or set disabled without soft-delete. */
		status?: "active" | "disabled" | string;
		actor?: string;
		source?: "cli" | "console" | "api" | "import" | "scim" | "system";
		scope?: ResourceScope;
	},
): Principal {
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
	store: ManagementStore,
	id: string,
	input?: {
		actor?: string;
		source?: "cli" | "console" | "api" | "import" | "scim" | "system";
		scope?: ResourceScope;
	},
): Principal {
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
	store: ManagementStore,
	id: string,
	input?: {
		actor?: string;
		source?: "cli" | "console" | "api" | "import" | "scim" | "system";
		scope?: ResourceScope;
	},
): Principal {
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
	store: ManagementStore,
	input: {
		name: string;
		slug?: string;
		id?: string;
		projectId?: string;
		environmentId?: string;
		externalId?: string;
		actor?: string;
		source?: "cli" | "console" | "api" | "import";
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

const ORG_SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/**
 * Update legitimate mutable organization fields: name and/or slug.
 * Status is not mutable here — use archiveOrganization. Soft-archived and
 * cross-scope ids fail closed as ORG_NOT_FOUND. Idempotent when values match.
 * Audits only when at least one field actually changes.
 */
export function updateOrganization(
	store: ManagementStore,
	id: string,
	input: {
		name?: string;
		slug?: string;
		actor?: string;
		source?: "cli" | "console" | "api" | "import" | "system";
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
	store: ManagementStore,
	id: string,
	input?: {
		dryRun?: boolean;
		/** Required for mutation. CLI maps --yes → confirm=true. */
		confirm?: boolean;
		actor?: string;
		source?: "cli" | "console" | "api" | "import" | "system";
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
	let users = store.snapshot.principals.filter(
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
		const p = store.snapshot.principals.find((x) => x.id === s.principalId);
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

// re-export for callers that used recordEvent from core path historically
export { recordEvent };
