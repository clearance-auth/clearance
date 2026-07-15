import {
	DELIVERY_OPERATIONS,
	resolveOperationPath,
	WEBHOOK_ENDPOINT_OPERATIONS,
} from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	previewConfirmation,
	requireRemoteMutation,
} from "./shared.js";

type DeliveryCommandPath = CliPathOf<typeof DELIVERY_OPERATIONS>;
type WebhookEndpointCommandPath = CliPathOf<typeof WEBHOOK_ENDPOINT_OPERATIONS>;
type DeliveryState = "queued" | "leased" | "retry" | "delivered" | "dead" | "cancelled";

const DELIVERY_STATES = new Set<DeliveryState>([
	"queued",
	"leased",
	"retry",
	"delivered",
	"dead",
	"cancelled",
]);

function boundedInteger(
	value: unknown,
	name: string,
	minimum: number,
	maximum: number,
): number | undefined {
	if (value === undefined) return undefined;
	const parsed = Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
		throw error(
			"DELIVERY_OPTION_INVALID",
			`--${name} must be an integer from ${minimum} to ${maximum}.`,
			`Pass a valid --${name} value.`,
		);
	}
	return parsed;
}

function stateFilters(value: unknown): DeliveryState[] {
	if (value === undefined) return [];
	const states = Array.isArray(value) ? value : [value];
	if (
		states.length > DELIVERY_STATES.size ||
		states.some((state) => typeof state !== "string" || !DELIVERY_STATES.has(state as DeliveryState))
	) {
		throw error(
			"DELIVERY_OPTION_INVALID",
			"--state must name queued, leased, retry, delivered, dead, or cancelled.",
			"Repeat --state only with supported delivery states.",
		);
	}
	return [...new Set(states as DeliveryState[])];
}

function listPath(opts: Readonly<Record<string, unknown>>): `/v1/${string}` {
	const params = new URLSearchParams();
	const limit = boundedInteger(opts.limit, "limit", 1, 200);
	if (limit !== undefined) params.set("limit", String(limit));
	if (typeof opts.cursor === "string" && opts.cursor !== "") params.set("cursor", opts.cursor);
	for (const state of stateFilters(opts.state)) params.append("state", state);
	if (opts.channel !== undefined) {
		if (opts.channel !== "email" && opts.channel !== "webhook") {
			throw error(
				"DELIVERY_OPTION_INVALID",
				"--channel must be email or webhook.",
				"Pass --channel email or --channel webhook.",
			);
		}
		params.set("channel", opts.channel);
	}
	if (typeof opts.kind === "string" && opts.kind !== "") params.set("kind", opts.kind);
	return `${DELIVERY_OPERATIONS.list.http.path}${params.size ? `?${params}` : ""}` as `/v1/${string}`;
}

function endpointStatuses(value: unknown): Array<"active" | "disabled" | "deleted"> {
	if (value === undefined) return [];
	const values = Array.isArray(value) ? value : [value];
	const result: Array<"active" | "disabled" | "deleted"> = [];
	for (const status of values) {
		if (status !== "active" && status !== "disabled" && status !== "deleted") {
			throw error(
				"WEBHOOK_ENDPOINT_OPTION_INVALID",
				"--status must be active, disabled, or deleted.",
				"Repeat --status only with supported endpoint states.",
			);
		}
		if (!result.includes(status)) result.push(status);
	}
	return result;
}

function endpointEventKinds(value: unknown): "organization.updated"[] | undefined {
	if (value === undefined || Array.isArray(value) && value.length === 0) return undefined;
	const values = Array.isArray(value) ? value : [value];
	if (values.length !== 1 || values[0] !== "organization.updated") {
		throw error(
			"WEBHOOK_ENDPOINT_OPTION_INVALID",
			"--event-kind must be organization.updated and may be supplied once.",
			"Pass --event-kind organization.updated or omit the option.",
		);
	}
	return ["organization.updated"];
}

function endpointText(
	value: unknown,
	name: string,
	maximum: number,
	required = false,
): string | undefined {
	if (value === undefined && !required) return undefined;
	if (typeof value !== "string" || value.trim() === "" || value.length > maximum ||
		/[\u0000-\u001f\u007f]/.test(value)) {
		throw error(
			"WEBHOOK_ENDPOINT_OPTION_INVALID",
			`--${name} must be a non-empty string of at most ${maximum} characters.`,
			`Pass a valid --${name} value.`,
		);
	}
	return value;
}

function endpointVersion(value: unknown): number {
	const version = boundedInteger(value, "expected-version", 1, Number.MAX_SAFE_INTEGER);
	if (version === undefined) {
		throw error(
			"WEBHOOK_ENDPOINT_OPTION_INVALID",
			"--expected-version is required.",
			"Inspect the endpoint and pass its current resourceVersion.",
		);
	}
	return version;
}

function endpointIdentifier(value: unknown): string {
	if (typeof value !== "string" || value.length < 1 || value.length > 4_096 ||
		/[\u0000-\u001f\u007f]/.test(value)) {
		throw error(
			"WEBHOOK_ENDPOINT_OPTION_INVALID",
			"Webhook endpoint id argument is invalid.",
			"Pass a valid endpoint id from delivery endpoints list.",
		);
	}
	return value;
}

function endpointListPath(opts: Readonly<Record<string, unknown>>): `/v1/${string}` {
	const params = new URLSearchParams();
	const limit = boundedInteger(opts.limit, "limit", 1, 200);
	if (limit !== undefined) params.set("limit", String(limit));
	const cursor = endpointText(opts.cursor, "cursor", 8_192);
	if (cursor !== undefined) params.set("cursor", cursor);
	for (const status of endpointStatuses(opts.status)) params.append("status", status);
	const kinds = endpointEventKinds(opts.eventKind);
	if (kinds?.[0]) params.set("eventKind", kinds[0]);
	return params.size === 0
		? WEBHOOK_ENDPOINT_OPERATIONS.list.http.path
		: `${WEBHOOK_ENDPOINT_OPERATIONS.list.http.path}?${params}`;
}

export async function dispatchDeliveryCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<DeliveryCommandPath | WebhookEndpointCommandPath>): Promise<unknown> {
	const id = firstStringArgument(args);
	switch (path) {
		case DELIVERY_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: DELIVERY_OPERATIONS.list.http.method,
				path: listPath(opts),
			});
		case DELIVERY_OPERATIONS.inspect.cliPath:
			return requestManagementApi(session, {
				method: DELIVERY_OPERATIONS.inspect.http.method,
				path: resolveOperationPath(DELIVERY_OPERATIONS.inspect, { id }),
			});
		case DELIVERY_OPERATIONS.readiness.cliPath: {
			const staleAfterMs = boundedInteger(
				opts.staleAfterMs,
				"stale-after-ms",
				1_000,
				86_400_000,
			);
			const params = new URLSearchParams();
			if (staleAfterMs !== undefined) params.set("staleAfterMs", String(staleAfterMs));
			return requestManagementApi(session, {
				method: DELIVERY_OPERATIONS.readiness.http.method,
				path: `${DELIVERY_OPERATIONS.readiness.http.path}${params.size ? `?${params}` : ""}` as `/v1/${string}`,
			});
		}
		case DELIVERY_OPERATIONS.quotas.cliPath:
			return requestManagementApi(session, {
				method: DELIVERY_OPERATIONS.quotas.http.method,
				path: DELIVERY_OPERATIONS.quotas.http.path,
			});
		case DELIVERY_OPERATIONS.cancel.cliPath:
			return requestManagementApi(session, {
				method: DELIVERY_OPERATIONS.cancel.http.method,
				path: resolveOperationPath(DELIVERY_OPERATIONS.cancel, { id }),
				body: previewConfirmation(global),
			});
		case DELIVERY_OPERATIONS.retry.cliPath:
			return requestManagementApi(session, {
				method: DELIVERY_OPERATIONS.retry.http.method,
				path: resolveOperationPath(DELIVERY_OPERATIONS.retry, { id }),
				body: previewConfirmation(global),
			});
		case DELIVERY_OPERATIONS.replay.cliPath:
			return requestManagementApi(session, {
				method: DELIVERY_OPERATIONS.replay.http.method,
				path: resolveOperationPath(DELIVERY_OPERATIONS.replay, { id }),
				body: body({
					maxAttempts: boundedInteger(opts.maxAttempts, "max-attempts", 1, 100),
					...previewConfirmation(global),
				}),
			});
		case WEBHOOK_ENDPOINT_OPERATIONS.list.cliPath:
			return requestManagementApi(session, {
				method: WEBHOOK_ENDPOINT_OPERATIONS.list.http.method,
				path: endpointListPath(opts),
			});
		case WEBHOOK_ENDPOINT_OPERATIONS.inspect.cliPath:
			return requestManagementApi(session, {
				method: WEBHOOK_ENDPOINT_OPERATIONS.inspect.http.method,
				path: resolveOperationPath(WEBHOOK_ENDPOINT_OPERATIONS.inspect, {
					id: endpointIdentifier(id),
				}),
			});
		case WEBHOOK_ENDPOINT_OPERATIONS.create.cliPath:
			requireRemoteMutation(global, path);
			return requestManagementApi(session, {
				method: WEBHOOK_ENDPOINT_OPERATIONS.create.http.method,
				path: WEBHOOK_ENDPOINT_OPERATIONS.create.http.path,
				body: body({
					name: endpointText(opts.name, "name", 128, true),
					url: endpointText(opts.url, "url", 8_192, true),
					eventKinds: endpointEventKinds(opts.eventKind),
				}),
			});
		case WEBHOOK_ENDPOINT_OPERATIONS.update.cliPath: {
			requireRemoteMutation(global, path);
			const name = endpointText(opts.name, "name", 128);
			const url = endpointText(opts.url, "url", 8_192);
			const kinds = endpointEventKinds(opts.eventKind);
			const status = opts.status;
			if (status !== undefined && status !== "active" && status !== "disabled") {
				throw error(
					"WEBHOOK_ENDPOINT_OPTION_INVALID",
					"--status must be active or disabled.",
					"Use delivery endpoints delete to remove an endpoint.",
				);
			}
			if (name === undefined && url === undefined && kinds === undefined && status === undefined) {
				throw error(
					"WEBHOOK_ENDPOINT_OPTION_INVALID",
					"Endpoint update requires at least one mutable field.",
					"Pass --name, --url, --event-kind, or --status.",
				);
			}
			return requestManagementApi(session, {
				method: WEBHOOK_ENDPOINT_OPERATIONS.update.http.method,
				path: resolveOperationPath(WEBHOOK_ENDPOINT_OPERATIONS.update, {
					id: endpointIdentifier(id),
				}),
				body: body({
					expectedVersion: endpointVersion(opts.expectedVersion),
					name,
					url,
					eventKinds: kinds,
					status,
				}),
			});
		}
		case WEBHOOK_ENDPOINT_OPERATIONS.rotate.cliPath:
		case WEBHOOK_ENDPOINT_OPERATIONS.delete.cliPath:
		case WEBHOOK_ENDPOINT_OPERATIONS.test.cliPath: {
			const operation = path === WEBHOOK_ENDPOINT_OPERATIONS.rotate.cliPath
				? WEBHOOK_ENDPOINT_OPERATIONS.rotate
				: path === WEBHOOK_ENDPOINT_OPERATIONS.delete.cliPath
					? WEBHOOK_ENDPOINT_OPERATIONS.delete
					: WEBHOOK_ENDPOINT_OPERATIONS.test;
			return requestManagementApi(session, {
				method: operation.http.method,
				path: resolveOperationPath(operation, { id: endpointIdentifier(id) }),
				body: body({
					expectedVersion: endpointVersion(opts.expectedVersion),
					...previewConfirmation(global),
				}),
			});
		}
	}
}
