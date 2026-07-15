import {
	EVENT_OPERATIONS,
	exportEvents,
	inspectEvent,
	listEventsPage,
	replayDiagnosticTrace,
} from "@clearance/management";
import { Hono } from "hono";
import type { ScopedRouteDependencies } from "./shared.js";

export interface EventRouteDependencies extends ScopedRouteDependencies {}

export function registerEventRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
}: EventRouteDependencies) {
	return new Hono()
		.get(EVENT_OPERATIONS.list.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const limitRaw = c.req.query("limit");
				const cursor = c.req.query("cursor");
				const action = c.req.query("action");
				const organizationId = c.req.query("organizationId");
				const page = listEventsPage(store, {
					scope,
					...(limitRaw !== undefined ? { limit: Number(limitRaw) } : {}),
					...(cursor !== undefined ? { cursor } : {}),
					...(action !== undefined ? { action } : {}),
					...(organizationId !== undefined ? { organizationId } : {}),
				});
				return c.json({ events: page.events, nextCursor: page.nextCursor, scope });
			} catch (error) {
				return handleError(c, error);
			}
		})
		.get(EVENT_OPERATIONS.inspect.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const result = inspectEvent(store, c.req.param("id"), { scope });
				return c.json(result);
			} catch (error) {
				return handleError(c, error);
			}
		})
		.post(EVENT_OPERATIONS.export.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const body = await c.req.json().catch(() => ({}));
				const limit =
					body && typeof body === "object" && "limit" in body
						? Number((body as { limit?: unknown }).limit)
						: undefined;
				const format =
					body && typeof body === "object" && typeof (body as { format?: unknown }).format === "string"
						? (body as { format: string }).format
						: "json";
				const action =
					body && typeof body === "object" && typeof (body as { action?: unknown }).action === "string"
						? (body as { action: string }).action
						: undefined;
				const organizationId =
					body &&
					typeof body === "object" &&
					typeof (body as { organizationId?: unknown }).organizationId === "string"
						? (body as { organizationId: string }).organizationId
						: undefined;
				const before =
					body &&
					typeof body === "object" &&
					typeof (body as { before?: unknown }).before === "string"
						? (body as { before: string }).before
						: undefined;
				const envelope = exportEvents(store, {
					scope,
					format,
					limit,
					...(action ? { action } : {}),
					...(organizationId ? { organizationId } : {}),
					...(before ? { before } : {}),
					actor: "api",
					source: "api",
				});
				await store.ready();
				return c.json(envelope);
			} catch (error) {
				return handleError(c, error);
			}
		})
		.post(EVENT_OPERATIONS.replay.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const body = await c.req.json().catch(() => ({}));
				const id =
					body && typeof body === "object" && typeof (body as { id?: unknown }).id === "string"
						? (body as { id: string }).id
						: "";
				const bodyDryRun =
					body && typeof body === "object" && (body as { dryRun?: unknown }).dryRun === true;
				const confirm =
					body && typeof body === "object" && (body as { confirm?: unknown }).confirm === true;
				const dryRun = bodyDryRun || !confirm;
				const result = replayDiagnosticTrace(store, id, {
					scope,
					dryRun,
					confirm: confirm && !bodyDryRun,
					actor: "api",
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
