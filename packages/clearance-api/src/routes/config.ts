import {
	ClearanceError,
	CONFIG_OPERATIONS,
	diffConfig,
	publicConfig,
	setConfig,
	validateConfig,
} from "@clearance/management";
import { Hono } from "hono";
import type { ScopedRouteDependencies } from "./shared.js";

export interface ConfigRouteDependencies extends ScopedRouteDependencies {}

export function registerConfigRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
}: ConfigRouteDependencies) {
	return new Hono()
		.get(CONFIG_OPERATIONS.get.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				return c.json({ ...publicConfig(store.snapshot.meta.config, c.req.query("key")), scope });
			} catch (error) {
				return handleError(c, error);
			}
		})
		.patch(CONFIG_OPERATIONS.set.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const request = await c.req.json();
				if (!request || typeof request !== "object" || Array.isArray(request) || typeof request.value !== "string") {
					throw new ClearanceError({
						code: "CONFIG_VALUE_INVALID",
						message: "Config values must be JSON strings.",
						stage: "config.set",
						status: 400,
						remediation: "Send an object with a string value field.",
					});
				}
				const key = c.req.param("key");
				const value = request.value;
				const candidate = { ...store.snapshot.meta.config, [key]: value };
				validateConfig(store, candidate);
				if (request.dryRun === true) {
					return c.json({
						dryRun: true,
						changed: store.snapshot.meta.config[key] !== value,
						key,
						...publicConfig(candidate),
						scope,
					});
				}
				const result = setConfig(store, key, value);
				if (result.changed) await store.ready();
				return c.json({ ok: true, changed: result.changed, key, ...publicConfig(result.config), scope });
			} catch (error) {
				return handleError(c, error);
			}
		})
		.post(CONFIG_OPERATIONS.validate.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const request = await c.req.json().catch(() => ({}));
				const candidate = request.config ?? store.snapshot.meta.config;
				validateConfig(store, candidate);
				return c.json({
					ok: true,
					source: request.config === undefined ? "current" : "candidate",
					...publicConfig(candidate),
					scope,
				});
			} catch (error) {
				return handleError(c, error);
			}
		})
		.post(CONFIG_OPERATIONS.diff.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const request = await c.req.json();
				validateConfig(store, request.config);
				return c.json({ ...diffConfig(store.snapshot.meta.config, request.config), scope });
			} catch (error) {
				return handleError(c, error);
			}
		});
}
