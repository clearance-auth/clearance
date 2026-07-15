import {
	API_KEY_OPERATIONS,
	ClearanceError,
	ROLE_OPERATIONS,
	SESSION_OPERATIONS,
	createApiKey,
	createRole,
	inspectApiKey,
	listApiKeys,
	listRoles,
	normalizeAndValidateApiKeyScopes,
	revokeApiKey,
	rotateApiKey,
	updateRole,
	validateApiKeyName,
	validateRole,
} from "@clearance/management";
import { Hono } from "hono";
import {
	apiOperationContext,
	type ApplicationRouteDependencies,
} from "./shared.js";

export interface AccessRouteDependencies extends ApplicationRouteDependencies {}

export function registerAccessRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
	applicationFor,
}: AccessRouteDependencies) {
	const routes = new Hono();

	// --- API keys ---

	routes.get(API_KEY_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json({ apiKeys: listApiKeys(store, { scope, includeRevoked: c.req.query("includeRevoked") === "true" }), scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(API_KEY_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			if (body.dryRun === true) {
				const name = validateApiKeyName(body.name, "keys.create");
				const scopes = normalizeAndValidateApiKeyScopes(body.scopes, "keys.create");
				return c.json({ dryRun: true, apiKey: { name, scopes }, secretGenerated: false, scope });
			}
			const result = await createApiKey(store, { name: body.name, scopes: body.scopes, scope, actor: "api", source: "api" });
			await store.ready();
			return c.json({ ...result, scope }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(API_KEY_OPERATIONS.rotate.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				const apiKey = inspectApiKey(store, c.req.param("id"), { scope });
				if (apiKey.status === "revoked") throw new ClearanceError({ code: "API_KEY_REVOKED", message: "Revoked API keys cannot be rotated", stage: "keys.rotate", status: 409 });
				return c.json({ dryRun: true, apiKey, secretGenerated: false, scope });
			}
			const result = await rotateApiKey(store, c.req.param("id"), apiOperationContext(scope));
			await store.ready();
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(API_KEY_OPERATIONS.revoke.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				const apiKey = inspectApiKey(store, c.req.param("id"), { scope });
				return c.json({ dryRun: true, apiKey, wouldChange: apiKey.status === "active", scope });
			}
			const result = await revokeApiKey(store, c.req.param("id"), apiOperationContext(scope));
			await store.ready();
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	// --- Sessions (principal-derived scope; never expose tokens) ---

	/**
	 * List sessions, keyset-paginated (createdAt+id desc, newest first). limit
	 * keeps the shipped SESSION_LIMIT_INVALID validation as the page size;
	 * nextCursor walks older sessions. Runtime and JSON paths share the same
	 * documented ordering and opaque cursor format.
	 */
	routes.get(SESSION_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const limitRaw = c.req.query("limit");
			const cursor = c.req.query("cursor");
			const limit = Number(limitRaw ?? 100);
			const page = await applicationFor(store).sessions.list(
				apiOperationContext(scope),
				{ limit, ...(cursor !== undefined ? { cursor } : {}) },
			);
			return c.json({
				sessions: page.sessions,
				nextCursor: page.nextCursor,
				scope,
			});
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SESSION_OPERATIONS.revoke.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				const session = await applicationFor(store).sessions.inspect(
					apiOperationContext(scope),
					c.req.param("id"),
				);
				return c.json({ dryRun: true, session, wouldChange: session.status === "active", scope });
			}
			const result = await applicationFor(store).sessions.revoke(
				apiOperationContext(scope),
				c.req.param("id"),
			);
			return c.json({ ...result, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	// --- Roles (principal-derived scope; client headers never authority) ---

	routes.get(ROLE_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const roles = listRoles(store, { scope });
			return c.json({ roles, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(ROLE_OPERATIONS.validate.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			const result = validateRole(store, {
				name: (body as { name?: unknown }).name,
				slug: (body as { slug?: unknown }).slug,
				permissions: (body as { permissions?: unknown }).permissions,
				scope,
			});
			return c.json(result);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(ROLE_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json();
			if (body.dryRun === true) {
				return c.json({ dryRun: true, validation: validateRole(store, { name: body.name, slug: body.slug, permissions: body.permissions, scope }), scope });
			}
			const role = await createRole(store, {
				name: body.name,
				slug: body.slug,
				description: body.description,
				permissions: body.permissions,
				scope,
				actor: "api",
				source: "api",
			});
			await store.ready();
			return c.json({ role, scope }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.patch(ROLE_OPERATIONS.update.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const body = await c.req.json().catch(() => ({}));
			if (body.dryRun === true) {
				return c.json({ dryRun: true, id: c.req.param("id"), validation: validateRole(store, { name: body.name, permissions: body.permissions, scope }), scope });
			}
			const role = await updateRole(store, c.req.param("id"), {
				name: body.name,
				description: body.description,
				permissions: body.permissions,
				scope,
				actor: "api",
				source: "api",
			});
			await store.ready();
			return c.json({ role, scope });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get("/v1/settings", async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json({
				config: store.snapshot.meta.config,
				schemaVersion: store.snapshot.meta.schemaVersion,
				releaseVersion: store.snapshot.releaseVersion,
				resourceCounts: store.resourceCounts(),
				storeBackend: store.backend,
				scope,
				/** Principal scope is server-configured; headers are not authority. */
				tokenBoundary: "principal-derived-scope",
				telemetry: { remoteSinks: [], default: "disabled" },
				auth: { mode: "bearer-operator" },
			});
		} catch (e) {
			return handleError(c, e);
		}
	});

	return routes;
}
