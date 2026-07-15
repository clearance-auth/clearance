import { DELIVERY_OPERATIONS, resolveOperationPath } from "@clearance/management";
import { requestManagementApi } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	previewConfirmation,
} from "./shared.js";

type DeliveryCommandPath = CliPathOf<typeof DELIVERY_OPERATIONS>;
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

export async function dispatchDeliveryCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<DeliveryCommandPath>): Promise<unknown> {
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
	}
}
