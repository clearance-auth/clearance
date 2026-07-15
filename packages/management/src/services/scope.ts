/**
 * Principal-derived project/environment scope for the management plane.
 *
 * Authority is never taken from client request headers. Scope is resolved from
 * server-side operator configuration and the store's initialized project/env.
 * Client headers may only match principal scope (optional consistency check);
 * they may never broaden or select a different scope.
 */
import type { ManagementSnapshotReader } from "../store/types.js";
import { ClearanceError } from "./errors.js";

export type ResourceScope = {
	projectId: string;
	environmentId: string;
};

export type ScopedResource = {
	projectId: string;
	environmentId: string;
};

/**
 * Resolve the authenticated operator's scope from server configuration + store.
 * Order:
 * 1. Explicit opts (tests / internal callers)
 * 2. CLEARANCE_PROJECT_ID + CLEARANCE_ENV_ID (secure server-side mapping)
 * 3. store.meta.config after init
 * 4. Sole project/environment pair in the store (local single-project profile)
 *
 * Rejects when scope cannot be determined — never invents foreign scope.
 */
export function resolveOperatorScope(
	store: ManagementSnapshotReader,
	opts?: Partial<ResourceScope>,
): ResourceScope {
	const projectId =
		opts?.projectId?.trim() ||
		process.env.CLEARANCE_PROJECT_ID?.trim() ||
		store.snapshot.meta.config.projectId ||
		(store.snapshot.projects.length === 1
			? store.snapshot.projects[0]?.id
			: undefined);

	const environmentId =
		opts?.environmentId?.trim() ||
		process.env.CLEARANCE_ENV_ID?.trim() ||
		store.snapshot.meta.config.environmentId ||
		(store.snapshot.environments.length === 1
			? store.snapshot.environments[0]?.id
			: undefined);

	if (!projectId || !environmentId) {
		throw new ClearanceError({
			code: "SCOPE_REQUIRED",
			message:
				"Operator principal has no project/environment scope. Initialize a project or set CLEARANCE_PROJECT_ID and CLEARANCE_ENV_ID.",
			stage: "scope.resolve",
			status: 403,
			remediation:
				"Run clearance init, or set CLEARANCE_PROJECT_ID and CLEARANCE_ENV_ID to the operator's authorized scope",
		});
	}

	// Env overrides must refer to resources that exist once the store is initialized
	const hasProjects = store.snapshot.projects.length > 0;
	if (hasProjects) {
		const projectOk = store.snapshot.projects.some((p) => p.id === projectId);
		const envOk = store.snapshot.environments.some(
			(e) => e.id === environmentId && e.projectId === projectId,
		);
		if (!projectOk || !envOk) {
			throw new ClearanceError({
				code: "SCOPE_INVALID",
				message: "Configured operator scope does not match store project/environment",
				stage: "scope.resolve",
				status: 403,
				remediation:
					"Align CLEARANCE_PROJECT_ID / CLEARANCE_ENV_ID with the initialized project, or re-init",
			});
		}
	}

	return { projectId, environmentId };
}

/**
 * Optional client header consistency check. Headers never select scope —
 * if present they must equal the principal-derived scope.
 */
export function assertClientScopeHeaders(
	principal: ResourceScope,
	headerProject?: string | null,
	headerEnv?: string | null,
): void {
	if (headerProject && headerProject !== principal.projectId) {
		throw new ClearanceError({
			code: "SCOPE_PROJECT",
			message: "Project scope header does not match operator principal scope",
			stage: "scope.headers",
			status: 403,
			remediation: "Omit scope headers or send the operator's authorized project id",
		});
	}
	if (headerEnv && headerEnv !== principal.environmentId) {
		throw new ClearanceError({
			code: "SCOPE_ENVIRONMENT",
			message: "Environment scope header does not match operator principal scope",
			stage: "scope.headers",
			status: 403,
			remediation:
				"Omit scope headers or send the operator's authorized environment id",
		});
	}
}

/**
 * Fail closed for cross-scope resource access — same error as missing so
 * foreign resources are not revealed.
 */
export function assertResourceInScope(
	resource: ScopedResource | null | undefined,
	scope: ResourceScope,
	opts: { code: string; stage: string; label?: string },
): asserts resource is ScopedResource {
	if (
		!resource ||
		resource.projectId !== scope.projectId ||
		resource.environmentId !== scope.environmentId
	) {
		throw new ClearanceError({
			code: opts.code,
			message: `${opts.label ?? "Resource"} not found`,
			stage: opts.stage,
			status: 404,
		});
	}
}

export function scopeFilter(
	scope: ResourceScope,
): (r: ScopedResource) => boolean {
	return (r) =>
		r.projectId === scope.projectId && r.environmentId === scope.environmentId;
}
