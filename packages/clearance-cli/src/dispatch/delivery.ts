import {
	DELIVERY_OPERATIONS,
	WEBHOOK_ENDPOINT_OPERATIONS,
} from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	managementCallOptions,
	requireConfirmation,
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

function deliveryChannel(value: unknown): "email" | "webhook" | undefined {
	if (value === undefined) return undefined;
	if (value === "email" || value === "webhook") return value;
	throw error(
		"DELIVERY_OPTION_INVALID",
		"--channel must be email or webhook.",
		"Pass --channel email or --channel webhook.",
	);
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
			return callManagementOperation(session, "delivery.jobs.list", body({
				limit: boundedInteger(opts.limit, "limit", 1, 200),
				cursor: typeof opts.cursor === "string" && opts.cursor !== "" ? opts.cursor : undefined,
				states: stateFilters(opts.state),
				channel: deliveryChannel(opts.channel),
				kind: typeof opts.kind === "string" && opts.kind !== "" ? opts.kind : undefined,
			}) as {
				limit?: number;
				cursor?: string;
				states?: DeliveryState[];
				channel?: "email" | "webhook";
				kind?: string;
			});
		case DELIVERY_OPERATIONS.inspect.cliPath:
			return callManagementOperation(session, "delivery.jobs.inspect", { id });
		case DELIVERY_OPERATIONS.readiness.cliPath: {
			const staleAfterMs = boundedInteger(
				opts.staleAfterMs,
				"stale-after-ms",
				1_000,
				86_400_000,
			);
			return callManagementOperation(session, "delivery.readiness", body({ staleAfterMs }));
		}
		case DELIVERY_OPERATIONS.quotas.cliPath:
			return callManagementOperation(session, "delivery.quotas.get", {});
		case DELIVERY_OPERATIONS.cancel.cliPath:
			requireConfirmation(global, "DELIVERY_CANCEL_CONFIRMATION_REQUIRED", "Delivery cancellation");
			return callManagementOperation(session, "delivery.jobs.cancel", {
				id,
				dryRun: Boolean(global.dryRun),
			}, managementCallOptions(global));
		case DELIVERY_OPERATIONS.retry.cliPath:
			requireConfirmation(global, "DELIVERY_RETRY_CONFIRMATION_REQUIRED", "Delivery retry");
			return callManagementOperation(session, "delivery.jobs.retry", {
				id,
				dryRun: Boolean(global.dryRun),
			}, managementCallOptions(global));
		case DELIVERY_OPERATIONS.replay.cliPath:
			requireConfirmation(global, "DELIVERY_REPLAY_CONFIRMATION_REQUIRED", "Delivery replay");
			return callManagementOperation(
				session,
				"delivery.jobs.replay",
				body({
					id,
					maxAttempts: boundedInteger(opts.maxAttempts, "max-attempts", 1, 100),
					dryRun: Boolean(global.dryRun),
				}) as { id: string; maxAttempts?: number; dryRun?: boolean },
				managementCallOptions(global),
			);
		case WEBHOOK_ENDPOINT_OPERATIONS.list.cliPath:
			return callManagementOperation(
				session,
				"delivery.webhook_endpoints.list",
				body({
					limit: boundedInteger(opts.limit, "limit", 1, 200),
					cursor: endpointText(opts.cursor, "cursor", 8_192),
					statuses: endpointStatuses(opts.status),
					eventKind: endpointEventKinds(opts.eventKind)?.[0],
				}) as {
					limit?: number;
					cursor?: string;
					statuses?: Array<"active" | "disabled" | "deleted">;
					eventKind?: "organization.updated";
				},
			);
		case WEBHOOK_ENDPOINT_OPERATIONS.inspect.cliPath:
			return callManagementOperation(session, "delivery.webhook_endpoints.inspect", {
				id: endpointIdentifier(id),
			});
		case WEBHOOK_ENDPOINT_OPERATIONS.create.cliPath:
			requireRemoteMutation(global, path);
			return callManagementOperation(
				session,
				"delivery.webhook_endpoints.create",
				body({
					name: endpointText(opts.name, "name", 128, true),
					url: endpointText(opts.url, "url", 8_192, true),
					eventKinds: endpointEventKinds(opts.eventKind),
				}) as { name: string; url: string; eventKinds?: "organization.updated"[] },
			);
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
			return callManagementOperation(
				session,
				"delivery.webhook_endpoints.update",
				body({
					id: endpointIdentifier(id),
					expectedVersion: endpointVersion(opts.expectedVersion),
					name,
					url,
					eventKinds: kinds,
					status,
				}) as {
					id: string;
					expectedVersion: number;
					name?: string;
					url?: string;
					eventKinds?: "organization.updated"[];
					status?: "active" | "disabled";
				},
			);
		}
		case WEBHOOK_ENDPOINT_OPERATIONS.rotate.cliPath:
		case WEBHOOK_ENDPOINT_OPERATIONS.delete.cliPath:
		case WEBHOOK_ENDPOINT_OPERATIONS.test.cliPath: {
			const operationId = path === WEBHOOK_ENDPOINT_OPERATIONS.rotate.cliPath
				? "delivery.webhook_endpoints.rotate"
				: path === WEBHOOK_ENDPOINT_OPERATIONS.delete.cliPath
					? "delivery.webhook_endpoints.delete"
					: "delivery.webhook_endpoints.test";
			requireConfirmation(
				global,
				"WEBHOOK_ENDPOINT_CONFIRMATION_REQUIRED",
				`Webhook endpoint ${path.split(" ").at(-1) ?? "mutation"}`,
			);
			const input = {
				id: endpointIdentifier(id),
				expectedVersion: endpointVersion(opts.expectedVersion),
				dryRun: Boolean(global.dryRun),
			};
			if (operationId === "delivery.webhook_endpoints.rotate") {
				return callManagementOperation(session, operationId, input, managementCallOptions(global));
			}
			if (operationId === "delivery.webhook_endpoints.delete") {
				return callManagementOperation(session, operationId, input, managementCallOptions(global));
			}
			return callManagementOperation(session, operationId, input, managementCallOptions(global));
		}
	}
}
