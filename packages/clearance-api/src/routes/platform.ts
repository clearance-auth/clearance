import {
	ClearanceError,
	ENVIRONMENT_OPERATIONS,
	PROJECT_OPERATIONS,
	SYSTEM_OPERATIONS,
	createEnvironment,
	createProject,
	initProject,
	inspectEnvironmentAuthoritative,
	inspectProjectAuthoritative,
	listEnvironmentsPageAuthoritative,
	overviewStatsAuthoritative,
	planEnvironmentCreate,
	planProjectCreate,
	promoteEnvironment,
	runDoctor,
	type ManagementStore,
	type ResourceScope,
} from "@clearance/management";
import { Hono } from "hono";
import type { Context } from "hono";
import { requestActor, requestPrincipal } from "../request-auth.js";
import type { ScopedRouteDependencies } from "./shared.js";

export interface PlatformRouteDependencies extends ScopedRouteDependencies {
	principalScope(store: ManagementStore, context: Context): ResourceScope;
}

export function registerPlatformRoutes({
	storeForRequest,
	principalScope,
	scopeForRequest,
	handleError,
}: PlatformRouteDependencies) {
	return new Hono()
		.get("/v1/whoami", async (c) => {
			try {
				const store = await storeForRequest();
				const scope = principalScope(store, c);
				const principal = requestPrincipal(c);
				return c.json({
					operator: principal.kind === "api_key"
						? { id: principal.id, type: "api_key", authenticated: true, scopes: principal.scopes }
						: { id: "operator", type: "operator", authenticated: true },
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					storeBackend: store.backend,
				});
			} catch (error) {
				return handleError(c, error);
			}
		})
		.get(SYSTEM_OPERATIONS.doctor.http.path, async (c) => {
			const store = await storeForRequest();
			return c.json(await runDoctor(store));
		})
		.get(SYSTEM_OPERATIONS.dev.http.path, (c) =>
			c.json({
				commands: [
					"clearance init --name my-app",
					"pnpm stack:smoke",
					"pnpm stack:up",
					"pnpm --filter @clearance/sample-b2b dev",
					"pnpm --filter @clearance/api dev",
					"pnpm --filter @clearance/console dev",
				],
			}),
		)
		.post(SYSTEM_OPERATIONS.init.http.path, async (c) => {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({}));
			const result = initProject(store, {
				name: (body as { name?: string }).name ?? "clearance-app",
				environment: (body as { environment?: string }).environment,
				source: "api",
			});
			await store.ready();
			return c.json(result);
		})
		.get(SYSTEM_OPERATIONS.overview.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				return c.json(await overviewStatsAuthoritative(store, scope));
			} catch (error) {
				return handleError(c, error);
			}
		})
		.get(PROJECT_OPERATIONS.list.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				return c.json({
					projects: [await inspectProjectAuthoritative(store, scope.projectId, scope)],
					scope,
				});
			} catch (error) {
				return handleError(c, error);
			}
		})
		.get(PROJECT_OPERATIONS.inspect.http.currentPath, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const project = await inspectProjectAuthoritative(store, scope.projectId, scope);
				return c.json({ project, overview: await overviewStatsAuthoritative(store, scope), scope });
			} catch (error) {
				return handleError(c, error);
			}
		})
		.get(PROJECT_OPERATIONS.inspect.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const project = await inspectProjectAuthoritative(store, c.req.param("id"), scope);
				return c.json({ project, overview: await overviewStatsAuthoritative(store, scope), scope });
			} catch (error) {
				return handleError(c, error);
			}
		})
		.post(PROJECT_OPERATIONS.create.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const body = await c.req.json();
				if (body.dryRun === true) {
					return c.json({
						dryRun: true,
						project: planProjectCreate({ name: body.name }, store.snapshot.projects),
					});
				}
				const project = createProject(store, { name: body.name, actor: requestActor(c), source: "api" });
				await store.ready();
				return c.json({ project }, 201);
			} catch (error) {
				return handleError(c, error);
			}
		})
		.get(ENVIRONMENT_OPERATIONS.list.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const limitRaw = c.req.query("limit");
				const cursor = c.req.query("cursor");
				const page = await listEnvironmentsPageAuthoritative(store, {
					scope,
					...(limitRaw !== undefined ? { limit: Number(limitRaw) } : {}),
					...(cursor !== undefined ? { cursor } : {}),
				});
				const includeNextCursor =
					limitRaw !== undefined || cursor !== undefined || page.nextCursor !== null;
				return c.json({
					environments: page.environments,
					...(includeNextCursor ? { nextCursor: page.nextCursor } : {}),
					scope,
				});
			} catch (error) {
				return handleError(c, error);
			}
		})
		.get(ENVIRONMENT_OPERATIONS.inspect.http.currentPath, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				return c.json(await inspectEnvironmentAuthoritative(store, undefined, { scope }));
			} catch (error) {
				return handleError(c, error);
			}
		})
		.post(ENVIRONMENT_OPERATIONS.create.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const body = await c.req.json();
				const projectId = body.projectId ?? scope.projectId;
				if (projectId !== scope.projectId) {
					throw new ClearanceError({
						code: "SCOPE_MISMATCH",
						message: "Environment project is outside the operator scope.",
						stage: "env.create",
						status: 404,
					});
				}
				if (body.dryRun === true) {
					return c.json({
						dryRun: true,
						environment: planEnvironmentCreate(store, {
							projectId,
							name: body.name,
							kind: body.kind,
						}),
						scope,
					});
				}
				const environment = createEnvironment(store, {
					projectId,
					name: body.name,
					kind: body.kind,
					actor: requestActor(c),
				});
				await store.ready();
				return c.json({ environment, scope }, 201);
			} catch (error) {
				return handleError(c, error);
			}
		})
		.get(ENVIRONMENT_OPERATIONS.inspect.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const result = await inspectEnvironmentAuthoritative(store, c.req.param("id"), { scope });
				return c.json(result);
			} catch (error) {
				return handleError(c, error);
			}
		})
		.post(ENVIRONMENT_OPERATIONS.promote.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const body = await c.req.json().catch(() => ({}));
				const to =
					body && typeof body === "object" && typeof (body as { to?: unknown }).to === "string"
						? (body as { to: string }).to
						: "";
				const from =
					body &&
					typeof body === "object" &&
					typeof (body as { from?: unknown }).from === "string"
						? (body as { from: string }).from
						: undefined;
				const dryRun =
					body && typeof body === "object" && "dryRun" in body
						? (body as { dryRun?: unknown }).dryRun
						: undefined;
				const confirm =
					body && typeof body === "object" && "confirm" in body
						? (body as { confirm?: unknown }).confirm
						: undefined;
				if (dryRun !== undefined && typeof dryRun !== "boolean") {
					throw new ClearanceError({
						code: "ENV_PROMOTE_INPUT_INVALID",
						message: "dryRun must be a JSON boolean",
						stage: "env.promote",
						status: 400,
					});
				}
				if (confirm !== undefined && typeof confirm !== "boolean") {
					throw new ClearanceError({
						code: "ENV_PROMOTE_INPUT_INVALID",
						message: "confirm must be a JSON boolean",
						stage: "env.promote",
						status: 400,
					});
				}
				const result = promoteEnvironment(store, {
					to,
					...(from ? { from } : {}),
					...(dryRun !== undefined ? { dryRun } : {}),
					...(confirm !== undefined ? { confirm } : {}),
					scope,
					actor: requestActor(c),
					source: "api",
				});
				if (!result.dryRun) {
					await store.ready();
				}
				return c.json(result);
			} catch (error) {
				return handleError(c, error);
			}
		});
}
