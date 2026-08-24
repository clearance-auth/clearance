import {
	ClearanceError,
	createWebhookEndpointForManagement,
	deleteWebhookEndpointForManagement,
	inspectWebhookEndpointForManagement,
	listWebhookEndpointsForManagement,
	rotateWebhookEndpointForManagement,
	testWebhookEndpointForManagement,
	updateWebhookEndpointForManagement,
	WEBHOOK_ENDPOINT_OPERATIONS,
	type WebhookEndpointStatus,
} from "@clearance/management";
import { Hono, type Context } from "hono";
import { apiOperationContext, type ScopedRouteDependencies } from "./shared.js";

type MutableWebhookEndpointStatus = Exclude<WebhookEndpointStatus, "deleted">;
type WebhookEventKind = "organization.updated";

function requestError(code: string, message: string, remediation: string): ClearanceError {
	return new ClearanceError({
		code,
		message,
		stage: "api.request",
		status: 400,
		remediation,
	});
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function objectBody(c: Context, allowed: readonly string[]): Promise<Record<string, unknown>> {
	const raw = await c.req.text();
	if (raw.trim() === "") {
		throw requestError(
			"API_BODY_REQUIRED",
			"Request body must be a JSON object.",
			"Send the required webhook endpoint fields as JSON.",
		);
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw requestError(
			"API_JSON_INVALID",
			"Request body must be valid JSON.",
			"Send a JSON object using the documented webhook endpoint fields.",
		);
	}
	if (!isRecord(parsed)) {
		throw requestError(
			"API_BODY_INVALID",
			"Request body must be a JSON object.",
			"Send a JSON object using the documented webhook endpoint fields.",
		);
	}
	const unknown = Object.keys(parsed).filter((field) => !allowed.includes(field));
	if (unknown.length > 0) {
		throw requestError(
			"API_FIELD_UNKNOWN",
			`Unknown request field: ${unknown[0]}.`,
			"Remove fields that are not part of the webhook endpoint contract.",
		);
	}
	return parsed;
}

function textField(
	body: Readonly<Record<string, unknown>>,
	field: string,
	maximum: number,
	required: true,
): string;
function textField(
	body: Readonly<Record<string, unknown>>,
	field: string,
	maximum: number,
	required?: false,
): string | undefined;
function textField(
	body: Readonly<Record<string, unknown>>,
	field: string,
	maximum: number,
	required = false,
): string | undefined {
	const value = body[field];
	if (value === undefined && !required) return undefined;
	if (typeof value !== "string" || value.trim() === "" || value.length > maximum ||
		/[\u0000-\u001f\u007f]/.test(value)) {
		throw requestError(
			"API_TEXT_INVALID",
			`${field} must be a non-empty string of at most ${maximum} characters.`,
			`Send a valid ${field} value.`,
		);
	}
	return value;
}

function expectedVersion(body: Readonly<Record<string, unknown>>): number {
	const value = body.expectedVersion;
	if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
		throw requestError(
			"API_VERSION_INVALID",
			"expectedVersion must be a positive JSON integer.",
			"Inspect the endpoint and send its current resourceVersion.",
		);
	}
	return value;
}

function booleanField(
	body: Readonly<Record<string, unknown>>,
	field: "dryRun" | "confirm",
): boolean | undefined {
	const value = body[field];
	if (value === undefined) return undefined;
	if (typeof value !== "boolean") {
		throw requestError(
			"API_BOOLEAN_INVALID",
			`${field} must be a JSON boolean.`,
			`Send ${field} as true or false without quotes.`,
		);
	}
	return value;
}

function eventKinds(body: Readonly<Record<string, unknown>>): WebhookEventKind[] | undefined {
	const value = body.eventKinds;
	if (value === undefined) return undefined;
	if (!Array.isArray(value) || value.length !== 1 || value[0] !== "organization.updated") {
		throw requestError(
			"API_EVENT_KINDS_INVALID",
			"eventKinds must be [\"organization.updated\"].",
			"Send the currently supported webhook event kind exactly once.",
		);
	}
	return ["organization.updated"];
}

function mutableStatus(body: Readonly<Record<string, unknown>>): MutableWebhookEndpointStatus | undefined {
	const value = body.status;
	if (value === undefined) return undefined;
	if (value !== "active" && value !== "disabled") {
		throw requestError(
			"API_STATUS_INVALID",
			"status must be active or disabled.",
			"Use the delete operation to remove an endpoint.",
		);
	}
	return value;
}

function strictQuery(c: Context, allowed: readonly string[]): void {
	const unknown = Object.keys(c.req.query()).filter((field) => !allowed.includes(field));
	if (unknown.length > 0) {
		throw requestError(
			"API_QUERY_UNKNOWN",
			`Unknown query parameter: ${unknown[0]}.`,
			"Remove query parameters that are not part of the webhook endpoint contract.",
		);
	}
}

function listLimit(c: Context): number | undefined {
	const raw = c.req.query("limit");
	if (raw === undefined) return undefined;
	if (!/^[1-9][0-9]*$/.test(raw)) {
		throw requestError("API_LIMIT_INVALID", "limit must be an integer from 1 to 200.", "Send a valid limit.");
	}
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value > 200) {
		throw requestError("API_LIMIT_INVALID", "limit must be an integer from 1 to 200.", "Send a valid limit.");
	}
	return value;
}

function listStatuses(c: Context): WebhookEndpointStatus[] | undefined {
	const values = c.req.queries("status");
	if (!values || values.length === 0) return undefined;
	const result: WebhookEndpointStatus[] = [];
	for (const value of values) {
		if (value !== "active" && value !== "disabled" && value !== "deleted") {
			throw requestError(
				"API_STATUS_INVALID",
				"status must be active, disabled, or deleted.",
				"Repeat status only with supported endpoint states.",
			);
		}
		if (!result.includes(value)) result.push(value);
	}
	return result;
}

function listEventKind(c: Context): WebhookEventKind | undefined {
	const value = c.req.query("eventKind");
	if (value === undefined) return undefined;
	if (value !== "organization.updated") {
		throw requestError(
			"API_EVENT_KIND_INVALID",
			"eventKind must be organization.updated.",
			"Send the currently supported webhook event kind.",
		);
	}
	return value;
}

function endpointId(c: Context): string {
	const value = c.req.param("id");
	if (typeof value !== "string" || value.length < 1 || value.length > 4_096 ||
		/[\u0000-\u001f\u007f]/.test(value)) {
		throw requestError("API_ENDPOINT_ID_INVALID", "Webhook endpoint id is invalid.", "Send a valid endpoint id.");
	}
	return value;
}

export function registerWebhookEndpointRoutes({
	storeForRequest,
	scopeForRequest,
	handleError,
}: ScopedRouteDependencies) {
	const routes = new Hono();

	routes.get(WEBHOOK_ENDPOINT_OPERATIONS.list.http.path, async (c) => {
		try {
			strictQuery(c, ["limit", "cursor", "status", "eventKind"]);
			const store = await storeForRequest();
			const requestScope = scopeForRequest(store, c);
			const cursor = c.req.query("cursor");
			if (cursor !== undefined && (cursor.length < 1 || cursor.length > 8_192)) {
				throw requestError("API_CURSOR_INVALID", "cursor is invalid.", "Send nextCursor from a prior response.");
			}
			const limit = listLimit(c);
			const statuses = listStatuses(c);
			const requestedEventKind = listEventKind(c);
			return c.json(await listWebhookEndpointsForManagement(store, {
				...requestScope,
				...(limit === undefined ? {} : { limit }),
				...(cursor === undefined ? {} : { cursor }),
				...(statuses === undefined ? {} : { statuses }),
				...(requestedEventKind === undefined ? {} : { eventKind: requestedEventKind }),
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.get(WEBHOOK_ENDPOINT_OPERATIONS.inspect.http.path, async (c) => {
		try {
			strictQuery(c, []);
			const store = await storeForRequest();
			return c.json(await inspectWebhookEndpointForManagement(store, {
				...scopeForRequest(store, c),
				endpointId: endpointId(c),
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(WEBHOOK_ENDPOINT_OPERATIONS.create.http.path, async (c) => {
		try {
			strictQuery(c, []);
			const body = await objectBody(c, ["name", "url", "eventKinds"]);
			const store = await storeForRequest();
			const context = apiOperationContext(scopeForRequest(store, c), c);
			const result = await createWebhookEndpointForManagement(store, {
				...context.scope,
				actor: context.actor,
				source: context.source,
				correlationId: context.correlationId,
				name: textField(body, "name", 128, true),
				url: textField(body, "url", 8_192, true),
				...(eventKinds(body) === undefined ? {} : { eventKinds: eventKinds(body) }),
			});
			return c.json(result, 201);
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.patch(WEBHOOK_ENDPOINT_OPERATIONS.update.http.path, async (c) => {
		try {
			strictQuery(c, []);
			const body = await objectBody(c, ["expectedVersion", "name", "url", "eventKinds", "status"]);
			const store = await storeForRequest();
			const context = apiOperationContext(scopeForRequest(store, c), c);
			const name = textField(body, "name", 128);
			const url = textField(body, "url", 8_192);
			const kinds = eventKinds(body);
			const status = mutableStatus(body);
			return c.json(await updateWebhookEndpointForManagement(store, {
				...context.scope,
				actor: context.actor,
				source: context.source,
				correlationId: context.correlationId,
				endpointId: endpointId(c),
				expectedVersion: expectedVersion(body),
				...(name === undefined ? {} : { name }),
				...(url === undefined ? {} : { url }),
				...(kinds === undefined ? {} : { eventKinds: kinds }),
				...(status === undefined ? {} : { status }),
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	for (const [operation, execute] of [
		[WEBHOOK_ENDPOINT_OPERATIONS.rotate, rotateWebhookEndpointForManagement],
		[WEBHOOK_ENDPOINT_OPERATIONS.delete, deleteWebhookEndpointForManagement],
		[WEBHOOK_ENDPOINT_OPERATIONS.test, testWebhookEndpointForManagement],
	] as const) {
		routes.on(operation.http.method, operation.http.path, async (c) => {
			try {
				strictQuery(c, []);
				const body = await objectBody(c, ["expectedVersion", "dryRun", "confirm"]);
				const store = await storeForRequest();
				const context = apiOperationContext(scopeForRequest(store, c), c);
				return c.json(await execute(store, {
					...context.scope,
					actor: context.actor,
					source: context.source,
					correlationId: context.correlationId,
					endpointId: endpointId(c),
					expectedVersion: expectedVersion(body),
					dryRun: booleanField(body, "dryRun") === true,
					confirm: booleanField(body, "confirm") === true,
				}));
			} catch (error) {
				return handleError(c, error);
			}
		});
	}

	return routes;
}
