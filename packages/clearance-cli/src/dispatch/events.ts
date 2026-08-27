import { EVENT_OPERATIONS } from "@clearance/management";
import { callManagementOperation } from "../api-client.js";
import { selectOutputFormat, successEnvelope } from "../output.js";
import { evaluateJsonQuery } from "../json-query.js";
import { sanitizeTerminalText } from "../terminal-sanitize.js";
import { writeRemoteExport } from "./export-artifact.js";
import {
	body,
	type CliPathOf,
	type DispatchInput,
	error,
	firstStringArgument,
	managementCallOptions,
	requireConfirmation,
} from "./shared.js";

export const EVENTS_TAIL_MIN_POLL_INTERVAL_MS = 100;
export const EVENTS_TAIL_MAX_POLL_INTERVAL_MS = 60_000;
export const EVENTS_TAIL_STREAM_ID = "events.tail" as const;

export type EventTailStopReason = "once" | "max-events" | "cancelled";

/**
 * Tagged completion returned after the dispatcher has already emitted a stream.
 * Command hosts use the tag to avoid printing the ordinary one-result envelope.
 */
export interface EventStreamResult {
	readonly eventStreamResult: true;
	readonly stream: typeof EVENTS_TAIL_STREAM_ID;
	readonly emitted: number;
	readonly stopped: EventTailStopReason;
}

export function isEventStreamResult(value: unknown): value is EventStreamResult {
	if (value === null || typeof value !== "object") return false;
	const candidate = value as Partial<EventStreamResult>;
	return candidate.eventStreamResult === true &&
		candidate.stream === EVENTS_TAIL_STREAM_ID &&
		typeof candidate.emitted === "number" &&
		Number.isSafeInteger(candidate.emitted) &&
		candidate.emitted >= 0 &&
		(candidate.stopped === "once" || candidate.stopped === "max-events" || candidate.stopped === "cancelled");
}

/** Streaming commands cannot run inside a renderer that owns stdout, such as the TUI. */
export function isStreamingEventCommandPath(path: string): boolean {
	return path === EVENT_OPERATIONS.tail.cliPath;
}

type EventCommandPath = CliPathOf<typeof EVENT_OPERATIONS>;

type RemoteAuditEvent = {
	id: string;
	createdAt: string;
	action: string;
	actor: string;
	outcome: string;
};

function terminalField(value: unknown): string {
	return sanitizeTerminalText(value, { preserveNewlines: false, preserveTabs: false });
}

function emitTailEvent(global: DispatchInput<string>["global"], event: RemoteAuditEvent): void {
	const format = selectOutputFormat(global);
	if (format === "quiet") return;
	if (format === "json" || format === "jsonl") {
		// Tail is a stream: every machine event is exactly one JSON Lines record,
		// even when the caller selected `json`. Explicit output formats use the
		// normal envelope; legacy --json continues to expose the raw event.
		const envelope = successEnvelope(event, { meta: { stream: EVENTS_TAIL_STREAM_ID } });
		const legacyJson = global.json === true && global.format === undefined && global.output === undefined && !global.jq;
		let selected: unknown = legacyJson ? event : envelope;
		if (global.jq) {
			try {
				selected = evaluateJsonQuery(envelope, global.jq);
			} catch (cause) {
				throw error(
					"CLI_JQ_INVALID",
					cause instanceof Error ? cause.message : String(cause),
					"Use selectors such as .data, .data.items[], or .data.items[0].id.",
				);
			}
		}
		process.stdout.write(`${JSON.stringify(selected)}\n`);
		return;
	}
	process.stdout.write(
		`${terminalField(event.createdAt)} ${terminalField(event.action)} actor=${terminalField(event.actor)} outcome=${terminalField(event.outcome)} id=${terminalField(event.id)}\n`,
	);
}

function streamResult(emitted: number, stopped: EventTailStopReason): EventStreamResult {
	return Object.freeze({
		eventStreamResult: true as const,
		stream: EVENTS_TAIL_STREAM_ID,
		emitted,
		stopped,
	});
}

function waitForPoll(milliseconds: number, signal?: AbortSignal): Promise<boolean> {
	if (signal?.aborted) return Promise.resolve(false);
	return new Promise<boolean>((resolveWait) => {
		let settled = false;
		const finish = (completed: boolean) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			signal?.removeEventListener("abort", abort);
			resolveWait(completed);
		};
		const abort = () => finish(false);
		const timer = setTimeout(() => finish(true), milliseconds);
		signal?.addEventListener("abort", abort, { once: true });
	});
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
			const poll = async (): Promise<boolean> => {
				if (global.signal?.aborted) return false;
				let response;
				try {
					response = await callManagementOperation(session, "events.tail", body({
						limit,
						action: opts.action,
						organizationId: opts.org,
					}), managementCallOptions(global));
				} catch (cause) {
					// A caller-requested abort is normal stream completion. Transport and
					// server failures still retain their typed error behavior.
					if (global.signal?.aborted) return false;
					throw cause;
				}
				const fresh = (response.events as RemoteAuditEvent[]).filter((event) => !seen.has(event.id)).reverse();
				for (const event of fresh) {
					seen.add(event.id);
					if (maxEvents !== 0 && emitted >= maxEvents) break;
					emitTailEvent(global, event);
					emitted += 1;
				}
				return !global.signal?.aborted;
			};
			if (!await poll()) return streamResult(emitted, "cancelled");
			if (opts.once) return streamResult(emitted, "once");
			if (maxEvents !== 0 && emitted >= maxEvents) return streamResult(emitted, "max-events");
			while (maxEvents === 0 || emitted < maxEvents) {
				if (!await waitForPoll(pollInterval, global.signal)) return streamResult(emitted, "cancelled");
				if (!await poll()) return streamResult(emitted, "cancelled");
			}
			return streamResult(emitted, "max-events");
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
			requireConfirmation(global, "EVENT_REPLAY_CONFIRMATION_REQUIRED", "Event replay");
			return callManagementOperation(session, "events.replay", {
				id: String(args[0]),
				dryRun: Boolean(global.dryRun),
			}, managementCallOptions(global));
	}
}
