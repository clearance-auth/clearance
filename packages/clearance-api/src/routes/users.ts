import {
	ClearanceError,
	USER_OPERATIONS,
	exportUsers,
	inspectUser,
	listUsers,
	listUsersPage,
} from "@clearance/management";
import { Hono } from "hono";
import {
	apiOperationContext,
	type ApplicationRouteDependencies,
} from "./shared.js";

export interface UserRouteDependencies extends ApplicationRouteDependencies {}

export function registerUserRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
	applicationFor,
}: UserRouteDependencies) {
	const routes = new Hono();

	/**
	 * List users. Without limit/cursor this is the legacy unpaginated contract.
	 * With ?limit= and/or ?cursor= it is keyset-paginated (createdAt+id asc,
	 * opaque fail-closed cursor) and the response carries nextCursor.
	 */
	routes.get(USER_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const limitRaw = c.req.query("limit");
			const cursor = c.req.query("cursor");
			if (limitRaw !== undefined || cursor !== undefined) {
				const page = listUsersPage(store, {
					scope,
					...(limitRaw !== undefined ? { limit: Number(limitRaw) } : {}),
					...(cursor !== undefined ? { cursor } : {}),
				});
				return c.json({ users: page.users, nextCursor: page.nextCursor, scope });
			}
			const users = listUsers(store, { scope });
			return c.json({ users, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(USER_OPERATIONS.inspect.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			// Cross-scope ids fail closed as USER_NOT_FOUND
			const user = inspectUser(store, c.req.param("id"), scope);
			return c.json({ user, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(USER_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			const result = await applicationFor(store).users.create(
				apiOperationContext(scope),
				{
					email: body.email,
					name: body.name,
					password: body.password,
					dryRun: body.dryRun,
				},
			);
			if (result.dryRun) {
				return c.json({ ...result, scope });
			}
			return c.json(
				{
					user: result.user,
					...(result.passwordSetup
						? {
								passwordSetupToken: result.passwordSetup.token,
								passwordSetupExpiresAt: result.passwordSetup.expiresAt,
							}
						: {}),
				},
				201,
			);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.patch(USER_OPERATIONS.update.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			const result = await applicationFor(store).users.update(
				apiOperationContext(scope),
				{
					id: c.req.param("id"),
					name: body.name,
					email: body.email,
					status: "status" in body ? body.status : undefined,
					dryRun: body.dryRun,
				},
			);
			return result.dryRun
				? c.json({ ...result, scope })
				: c.json({ user: result.user, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(USER_OPERATIONS.disable.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			const result = await applicationFor(store).users.disable(
				apiOperationContext(scope),
				{ id: c.req.param("id"), dryRun: body.dryRun },
			);
			return result.dryRun
				? c.json({ ...result, scope })
				: c.json({ user: result.user, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.delete(USER_OPERATIONS.delete.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const user = await applicationFor(store).users.delete(
				apiOperationContext(scope),
				c.req.param("id"),
			);
			return c.json({ user, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	/**
	 * Export scoped users (bounded, redacted, deterministic).
	 * File paths are CLI-only; API returns the envelope in the response body.
	 * Arbitrary filesystem output paths are never accepted.
	 */
	routes.post(USER_OPERATIONS.export.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (
				body &&
				typeof body === "object" &&
				("outputPath" in body || "path" in body || "output" in body)
			) {
				throw new ClearanceError({
					code: "USERS_EXPORT_PATH_FORBIDDEN",
					message:
						"API user export does not accept filesystem output paths; the envelope is returned in the response body",
					stage: "users.export",
					status: 400,
					remediation:
						"Omit outputPath/path/output from the request, or use the CLI: clearance users export --output <path>",
				});
			}
			const limit =
				body && typeof body === "object" && "limit" in body
					? Number((body as { limit?: unknown }).limit)
					: undefined;
			const format =
				body &&
				typeof body === "object" &&
				typeof (body as { format?: unknown }).format === "string"
					? (body as { format: string }).format
					: "json";
			const status =
				body &&
				typeof body === "object" &&
				typeof (body as { status?: unknown }).status === "string"
					? (body as { status: string }).status
					: undefined;
			const envelope = exportUsers(store, {
				scope,
				format,
				limit,
				...(status ? { status } : {}),
				actor: "api",
				source: "api",
			});
			await store.ready();
			return c.json(envelope);
		} catch (e) {
			return handleError(c, e);
		}
	});

	return routes;
}
