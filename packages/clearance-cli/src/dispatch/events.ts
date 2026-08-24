import { EVENT_OPERATIONS } from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import { CliExitError } from "../output.js";
import { writeRemoteExport } from "./export-artifact.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	managementCallOptions,
} from "./shared.js";

export const EVENTS_TAIL_MIN_POLL_INTERVAL_MS = 100;
export const EVENTS_TAIL_MAX_POLL_INTERVAL_MS = 60_000;

type EventCommandPath = CliPathOf<typeof EVENT_OPERATIONS>;

type RemoteAuditEvent = {
	id: string;
	createdAt: string;
	action: string;
	actor: string;
	outcome: string;
};

function emitTailEvent(json: boolean, event: RemoteAuditEvent): void {
	process.stdout.write(json
		? `${JSON.stringify(event)}\n`
		: `${event.createdAt} ${event.action} actor=${event.actor} outcome=${event.outcome} id=${event.id}\n`);
}

function integerOption(
	value: unknown,
	fallback: number,
	minimum: number,
	maximum: number,
	name: string,
	code = "CLI_OPTION_INVALID",
): number {
	const parsed = value === undefined ? fallback : Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
		throw error(code, `${name} must be an integer from ${minimum} to ${maximum}.`, `Pass a valid --${name} value.`);
	}
	return parsed;
}

export async function dispatchEventCommand({
	session,
	path,
	args,
	opts,
	global,
}: DispatchInput<EventCommandPath>): Promise<unknown> {
	const rawId = firstStringArgument(args);
	switch (path) {
		case EVENT_OPERATIONS.list.cliPath:
			return callManagementOperation(session, "events.list", body({
					limit: opts.limit === undefined ? undefined : Number(opts.limit),
					cursor: opts.cursor,
					action: opts.action,
					organizationId: opts.org,
				}));
		case EVENT_OPERATIONS.tail.cliPath: {
			const limit = integerOption(opts.limit, 20, 1, 1000, "limit", "EVENTS_TAIL_OPTION_INVALID");
			// These controls govern the local polling lifecycle and never belong to
			// the generated one-request events.tail transport contract.
			const pollInterval = integerOption(
				opts.pollInterval,
				1000,
				EVENTS_TAIL_MIN_POLL_INTERVAL_MS,
				EVENTS_TAIL_MAX_POLL_INTERVAL_MS,
				"poll-interval",
				"EVENTS_TAIL_OPTION_INVALID",
			);
			const maxEvents = integerOption(
				opts.maxEvents,
				0,
				0,
				Number.MAX_SAFE_INTEGER,
				"max-events",
				"EVENTS_TAIL_OPTION_INVALID",
			);
			const seen = new Set<string>();
			let emitted = 0;
			const poll = async () => {
				const response = await callManagementOperation(session, "events.tail", body({
					limit,
					action: opts.action,
					organizationId: opts.org,
				}));
				const fresh = (response.events as RemoteAuditEvent[]).filter((event) => !seen.has(event.id)).reverse();
				for (const event of fresh) {
					seen.add(event.id);
					if (maxEvents !== 0 && emitted >= maxEvents) break;
					emitTailEvent(Boolean(global.json), event);
					emitted += 1;
				}
			};
			await poll();
			if (opts.once || (maxEvents !== 0 && emitted >= maxEvents)) throw new CliExitError(0);
			while (maxEvents === 0 || emitted < maxEvents) {
				await new Promise((resolveDelay) => setTimeout(resolveDelay, pollInterval));
				await poll();
			}
			throw new CliExitError(0);
		}
		case EVENT_OPERATIONS.inspect.cliPath:
			return callManagementOperation(session, "events.inspect", { id: rawId });
		case EVENT_OPERATIONS.export.cliPath: {
			const envelope = await callManagementOperation(session, "events.export", body({
					format: opts.format,
					limit: opts.limit === undefined ? undefined : Number(opts.limit),
					action: opts.action,
					organizationId: opts.org,
					before: opts.before,
				}) as {
					format?: "json" | "jsonl";
					limit?: number;
					action?: string;
					organizationId?: string;
					before?: string;
				});
			return writeRemoteExport(envelope, opts, "events");
		}
		case EVENT_OPERATIONS.replay.cliPath:
			return callManagementOperation(session, "events.replay", {
				id: String(args[0]),
				dryRun: global.dryRun || !global.yes,
			}, managementCallOptions(global));
	}
}
