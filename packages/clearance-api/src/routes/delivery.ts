import {
	ClearanceError,
	controlDeliveryJob,
	DELIVERY_OPERATIONS,
	getDeliveryQuotaForManagement,
	getDeliveryReadinessForManagement,
	inspectDeliveryJobForManagement,
	listDeliveryJobsForManagement,
} from "@clearance/management";
import { Hono, type Context } from "hono";
import { apiOperationContext, type ScopedRouteDependencies } from "./shared.js";

type DeliveryState = "queued" | "leased" | "retry" | "delivered" | "dead" | "cancelled";

function requestError(
	code: string,
	message: string,
	remediation: string,
): ClearanceError {
	return new ClearanceError({
		code,
		message,
		stage: "api.request",
		status: 400,
		remediation,
	});
}

async function mutationBody(c: Context): Promise<Record<string, unknown>> {
	const raw = await c.req.text();
	if (raw.trim() === "") return {};
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw requestError(
			"API_JSON_INVALID",
			"Request body must be valid JSON.",
			"Send an empty body for a preview or a JSON object with confirm: true to execute.",
		);
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw requestError(
			"API_BODY_INVALID",
			"Request body must be a JSON object.",
			"Send an empty body for a preview or a JSON object with confirm: true to execute.",
		);
	}
	const body = parsed as Record<string, unknown>;
	for (const field of ["dryRun", "confirm"] as const) {
		if (Object.hasOwn(body, field) && typeof body[field] !== "boolean") {
			throw requestError(
				"API_BOOLEAN_INVALID",
				`${field} must be a JSON boolean.`,
				`Send ${field} as true or false without quotes.`,
			);
		}
	}
	if (
		Object.hasOwn(body, "maxAttempts") &&
		(typeof body.maxAttempts !== "number" || !Number.isSafeInteger(body.maxAttempts))
	) {
		throw requestError(
			"API_NUMBER_INVALID",
			"maxAttempts must be a JSON integer.",
			"Send maxAttempts as an integer without quotes.",
		);
	}
	return body;
}

export function registerDeliveryRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
}: ScopedRouteDependencies) {
	const routes = new Hono();

	routes.get(DELIVERY_OPERATIONS.list.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			const limit = c.req.query("limit");
			const cursor = c.req.query("cursor");
			const states = c.req.queries("state") ?? [];
			const channel = c.req.query("channel");
			const kind = c.req.query("kind");
			return c.json(await listDeliveryJobsForManagement(store, {
				...scope,
				...(limit === undefined ? {} : { limit: Number(limit) }),
				...(cursor === undefined ? {} : { cursor }),
				...(states.length === 0 ? {} : { states: states as DeliveryState[] }),
				...(channel === undefined ? {} : { channel: channel as "email" | "webhook" }),
				...(kind === undefined ? {} : { kind }),
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.get(DELIVERY_OPERATIONS.inspect.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(await inspectDeliveryJobForManagement(store, {
				...scope,
				jobId: c.req.param("id"),
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.get(DELIVERY_OPERATIONS.readiness.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const staleAfterMs = c.req.query("staleAfterMs");
			return c.json(await getDeliveryReadinessForManagement(store, {
				...(staleAfterMs === undefined ? {} : { staleAfterMs: Number(staleAfterMs) }),
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.get(DELIVERY_OPERATIONS.quotas.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const scope = scopeForRequest(store, c);
			return c.json(await getDeliveryQuotaForManagement(store, scope));
		} catch (error) {
			return handleError(c, error);
		}
	});

	for (const [action, operation] of [
		["cancel", DELIVERY_OPERATIONS.cancel],
		["retry", DELIVERY_OPERATIONS.retry],
		["replay", DELIVERY_OPERATIONS.replay],
	] as const) {
		routes.post(operation.http.path, async (c) => {
			try {
				const store = await storeForRequest();
				const scope = scopeForRequest(store, c);
				const body = await mutationBody(c);
				const context = apiOperationContext(scope, c);
				const result = await controlDeliveryJob(store, {
					...context.scope,
					actor: context.actor,
					source: context.source,
					correlationId: context.correlationId,
					jobId: c.req.param("id"),
					action,
					dryRun: body.dryRun === true,
					confirm: body.confirm === true,
					...(action === "replay" && body.maxAttempts !== undefined
						? { maxAttempts: body.maxAttempts as number }
						: {}),
				});
				if (!result.dryRun) await store.ready();
				return c.json(result);
			} catch (error) {
				return handleError(c, error);
			}
		});
	}

	return routes;
}
