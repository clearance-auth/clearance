/**
 * Audit event export and diagnostic-trace replay.
 *
 * Export is bounded, scope-safe, secret-redacted, and deterministic.
 * Replay only re-records repository-defined diagnostic traces via the shared
 * SCIM trace/replay service. Arbitrary audit mutations are never replayable.
 */
import type { ManagementStore } from "../store/types.js";
import { correlationId, nowIso } from "../store/json-store.js";
import type { AuditEvent, DiagnosticTrace } from "../types/resources.js";
import { appendAuditEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import { writeExportArtifact } from "./export-artifact.js";
import { redactRecord } from "./redact.js";
import {
	decodePageCursor,
	encodePageCursor,
	normalizePageLimit,
	type PageCursorKey,
} from "./pagination.js";
import {
	inspectScimTrace,
	inspectScimTraceAuthoritative,
	replayScimTrace,
	replayScimTraceAuthoritative,
	type ScimActorSource,
} from "./scim.js";
import {
	resolveOperatorScope,
	resolveOperatorScopeAuthoritative,
	type ResourceScope,
} from "./scope.js";

export const EVENTS_EXPORT_DEFAULT_LIMIT = 100;
export const EVENTS_EXPORT_MAX_LIMIT = 1000;
export const EVENTS_TAIL_DEFAULT_LIMIT = 20;
export const EVENTS_TAIL_MAX_LIMIT = 1000;
const EVENTS_LIST_DEFAULT_PAGE_LIMIT = 50;
const EVENTS_LIST_MAX_PAGE_LIMIT = 1000;
export const EVENTS_EXPORT_FORMATS = ["json", "jsonl"] as const;
export type EventsExportFormat = (typeof EVENTS_EXPORT_FORMATS)[number];

export type EventsTailFilter = {
	organizationId?: string;
	action?: string;
	scope?: ResourceScope;
};

/**
 * Tail cursor state is intentionally local to one CLI invocation. It records
 * every event visible at startup so a later poll never backfills old history.
 */
export type EventsTailCursor = {
	readonly scope: ResourceScope;
	readonly organizationId?: string;
	readonly action?: string;
	readonly seenIds: Set<string>;
};

/**
 * Subsystems with a defined safe diagnostic re-record path.
 * Only SCIM has a repository replay service today (no domain state mutation).
 */
export const REPLAYABLE_TRACE_SUBSYSTEMS = ["scim"] as const;
export type ReplayableTraceSubsystem =
	(typeof REPLAYABLE_TRACE_SUBSYSTEMS)[number];

export type EventsExportOptions = {
	limit?: number;
	organizationId?: string;
	action?: string;
	/**
	 * Export only events created strictly BEFORE this ISO-8601 timestamp.
	 * Archival bound (see audit.ts header): schedule exports with --before so
	 * events are captured before the retention cap prunes them.
	 */
	before?: string;
	/** json (envelope) or jsonl (one event object per line) */
	format?: EventsExportFormat | string;
	/** Absolute or relative path; when set, artifact is written atomically */
	outputPath?: string;
	/** Allow replacing an existing file at outputPath */
	force?: boolean;
	scope?: ResourceScope;
	actor?: string;
	source?: AuditEvent["source"];
	/** When true, skip privileged-read audit (tests / nested callers) */
	skipAudit?: boolean;
};

export type EventsExportEnvelope = {
	schemaVersion: 1;
	kind: "events.export";
	exportedAt: string;
	format: EventsExportFormat;
	scope: ResourceScope;
	limit: number;
	count: number;
	truncated: boolean;
	filters: {
		organizationId?: string;
		action?: string;
		before?: string;
	};
	events: AuditEvent[];
	outputPath?: string;
	correlationId: string;
};

export type EventInspectResult = {
	event?: AuditEvent;
	trace?: DiagnosticTrace;
	scope: ResourceScope;
	replayable: boolean;
	replayBlocker?: string;
};

export type ReplayDiagnosticOptions = {
	/** Preview only — default safe path when confirm is not true */
	dryRun?: boolean;
	/**
	 * Required for mutating apply. CLI maps --yes → confirm=true.
	 * When confirm is not true, the service always dry-runs.
	 */
	confirm?: boolean;
	scope?: ResourceScope;
	actor?: string;
	source?: AuditEvent["source"];
};

export type ReplayDiagnosticResult = {
	dryRun: boolean;
	idempotent: boolean;
	wouldChange: boolean;
	replayable: true;
	original: DiagnosticTrace;
	trace: DiagnosticTrace;
	scope: ResourceScope;
	auditAction?: "events.replay" | "scim.replay";
};

function eventInScope(event: AuditEvent, scope: ResourceScope): boolean {
	return (
		event.projectId === scope.projectId &&
		event.environmentId === scope.environmentId
	);
}

function traceInScope(trace: DiagnosticTrace, scope: ResourceScope): boolean {
	return (
		trace.projectId === scope.projectId &&
		trace.environmentId === scope.environmentId
	);
}

export function normalizeEventsExportLimit(limit: number | undefined): number {
	const value = limit ?? EVENTS_EXPORT_DEFAULT_LIMIT;
	if (!Number.isInteger(value) || value < 1 || value > EVENTS_EXPORT_MAX_LIMIT) {
		throw new ClearanceError({
			code: "EVENTS_EXPORT_LIMIT_INVALID",
			message: `Export limit must be an integer between 1 and ${EVENTS_EXPORT_MAX_LIMIT}`,
			stage: "events.export",
			status: 400,
			remediation: `Pass --limit with an integer from 1 through ${EVENTS_EXPORT_MAX_LIMIT}`,
		});
	}
	return value;
}

export function normalizeEventsTailLimit(limit: number | undefined): number {
	const value = limit ?? EVENTS_TAIL_DEFAULT_LIMIT;
	if (!Number.isInteger(value) || value < 1 || value > EVENTS_TAIL_MAX_LIMIT) {
		throw new ClearanceError({
			code: "EVENTS_TAIL_LIMIT_INVALID",
			message: `Tail limit must be an integer between 1 and ${EVENTS_TAIL_MAX_LIMIT}`,
			stage: "events.tail",
			status: 400,
			remediation: `Pass --limit with an integer from 1 through ${EVENTS_TAIL_MAX_LIMIT}`,
		});
	}
	return value;
}

/** Fail-closed --before parsing: ISO-8601, normalized for lexical compare. */
export function normalizeEventsExportBefore(
	before: string | undefined,
): string | undefined {
	if (before === undefined || before === null || before === "") return undefined;
	const parsed = Date.parse(before);
	if (Number.isNaN(parsed)) {
		throw new ClearanceError({
			code: "EVENTS_EXPORT_BEFORE_INVALID",
			message: `--before must be an ISO-8601 timestamp (got "${before}")`,
			stage: "events.export",
			status: 400,
			remediation: "Pass --before as an ISO timestamp, e.g. 2026-07-01T00:00:00Z",
		});
	}
	return new Date(parsed).toISOString();
}

export function normalizeEventsExportFormat(
	format: string | undefined,
): EventsExportFormat {
	const value = (format ?? "json").toLowerCase();
	if (!(EVENTS_EXPORT_FORMATS as readonly string[]).includes(value)) {
		throw new ClearanceError({
			code: "EVENTS_EXPORT_FORMAT_INVALID",
			message: `Unsupported export format "${format}"`,
			stage: "events.export",
			status: 400,
			remediation: `Use one of: ${EVENTS_EXPORT_FORMATS.join(", ")}`,
		});
	}
	return value as EventsExportFormat;
}

/** Stable sort: newest first, then id descending for total order. */
export function sortEventsDeterministic(events: AuditEvent[]): AuditEvent[] {
	return [...events].sort((a, b) => {
		if (a.createdAt !== b.createdAt) {
			return a.createdAt < b.createdAt ? 1 : -1;
		}
		if (a.id === b.id) return 0;
		return a.id < b.id ? 1 : -1;
	});
}

/** Defense-in-depth redaction of an already-stored audit event. */
export function sanitizeAuditEvent(event: AuditEvent): AuditEvent {
	return {
		...event,
		metadata: redactRecord(event.metadata as Record<string, unknown> | undefined),
	};
}

export function selectEventsForExport(
	store: ManagementStore,
	filter: {
		limit: number;
		organizationId?: string;
		action?: string;
		/** Normalized ISO bound — only events with createdAt strictly before */
		before?: string;
		scope: ResourceScope;
	},
): { events: AuditEvent[]; truncated: boolean } {
	let events = store.snapshot.events.filter((e) => eventInScope(e, filter.scope));
	if (filter.organizationId) {
		events = events.filter((e) => e.organizationId === filter.organizationId);
	}
	if (filter.action) {
		events = events.filter((e) => e.action === filter.action);
	}
	if (filter.before) {
		const bound = filter.before;
		events = events.filter((e) => e.createdAt < bound);
	}
	const ordered = sortEventsDeterministic(events).map(sanitizeAuditEvent);
	const truncated = ordered.length > filter.limit;
	return {
		events: ordered.slice(0, filter.limit),
		truncated,
	};
}

type OperationalEventsFilter = {
	limit?: number;
	organizationId?: string;
	action?: string;
	scope?: ResourceScope;
	cursor?: string;
	before?: string;
};

type EventSourcePage = { events: AuditEvent[]; hasMore: boolean };

function eventSortDescending(left: AuditEvent, right: AuditEvent): number {
	if (left.createdAt !== right.createdAt) {
		return left.createdAt < right.createdAt ? 1 : -1;
	}
	return left.id === right.id ? 0 : left.id < right.id ? 1 : -1;
}

function mergeEventPages(
	pages: readonly EventSourcePage[],
	limit: number,
): EventSourcePage {
	const ids = new Set<string>();
	const merged = pages
		.flatMap((page) => page.events)
		.sort(eventSortDescending)
		.filter((event) => {
			if (ids.has(event.id)) return false;
			ids.add(event.id);
			return true;
		});
	return {
		events: merged.slice(0, limit).map(sanitizeAuditEvent),
		hasMore: merged.length > limit || pages.some((page) => page.hasMore),
	};
}

function snapshotEventPage(
	store: ManagementStore,
	input: {
		scope: ResourceScope;
		limit: number;
		cursor?: PageCursorKey;
		action?: string;
		organizationId?: string;
		before?: string;
	},
): EventSourcePage {
	let events = store.snapshot.events.filter(
		(event) =>
			(!event.projectId || event.projectId === input.scope.projectId) &&
			(!event.environmentId || event.environmentId === input.scope.environmentId),
	);
	if (input.organizationId) {
		events = events.filter((event) => event.organizationId === input.organizationId);
	}
	if (input.action) events = events.filter((event) => event.action === input.action);
	if (input.before) events = events.filter((event) => event.createdAt < input.before!);
	if (input.cursor) {
		events = events.filter(
			(event) =>
				event.createdAt < input.cursor!.createdAt ||
				(event.createdAt === input.cursor!.createdAt && event.id < input.cursor!.id),
		);
	}
	const ordered = events.sort(eventSortDescending);
	return {
		events: ordered.slice(0, input.limit),
		hasMore: ordered.length > input.limit,
	};
}

async function managementEventPage(
	store: ManagementStore,
	input: {
		scope: ResourceScope;
		limit: number;
		cursor?: PageCursorKey;
		action?: string;
		organizationId?: string;
		before?: string;
	},
): Promise<EventSourcePage> {
	if (store.storeV2Events?.authoritative) {
		return store.storeV2Events.listPage(input);
	}
	return snapshotEventPage(store, input);
}

async function operationalEventPage(
	store: ManagementStore,
	input: {
		scope: ResourceScope;
		limit: number;
		cursor?: PageCursorKey;
		action?: string;
		organizationId?: string;
		before?: string;
	},
): Promise<EventSourcePage> {
	const management = managementEventPage(store, input);
	const runtime = store.runtimeAuditEvents
		? store.runtimeAuditEvents.listPage(input)
		: Promise.resolve<EventSourcePage>({ events: [], hasMore: false });
	return mergeEventPages(await Promise.all([management, runtime]), input.limit);
}

/**
 * Database-aware list reader for operational transports. The legacy sync
 * reader remains available to local JSON callers; Postgres callers merge two
 * independently bounded sources and retain the existing opaque cursor.
 */
export async function listEventsPageOperational(
	store: ManagementStore,
	filter: OperationalEventsFilter = {},
): Promise<{ events: AuditEvent[]; nextCursor: string | null }> {
	const limit = normalizePageLimit(filter.limit, {
		stage: "events.list",
		code: "EVENTS_LIST_OPTION_INVALID",
		defaultValue: EVENTS_LIST_DEFAULT_PAGE_LIMIT,
		maximum: EVENTS_LIST_MAX_PAGE_LIMIT,
	});
	const cursor = decodePageCursor(filter.cursor, "events", "events.list");
	const scope = filter.scope ?? resolveOperatorScope(store);
	const page = await operationalEventPage(store, {
		scope,
		limit,
		...(cursor ? { cursor } : {}),
		...(filter.action ? { action: filter.action } : {}),
		...(filter.organizationId ? { organizationId: filter.organizationId } : {}),
	});
	const last = page.events[page.events.length - 1];
	return {
		events: page.events,
		nextCursor: page.hasMore && last ? encodePageCursor("events", last) : null,
	};
}

function selectTailCandidates(
	store: ManagementStore,
	filter: Required<Pick<EventsTailFilter, "scope">> & EventsTailFilter,
): AuditEvent[] {
	// Use the export selector so tail shares its scope, action/org filtering,
	// deterministic ordering, and defense-in-depth redaction behavior.
	return selectEventsForExport(store, {
		limit: Number.MAX_SAFE_INTEGER,
		organizationId: filter.organizationId,
		action: filter.action,
		scope: filter.scope,
	}).events;
}

/**
 * Select the newest N matching events, then emit that initial history oldest
 * first. All currently visible ids become the cursor baseline; later polls
 * therefore only emit events that appeared after tailing began.
 */
export function beginEventsTail(
	store: ManagementStore,
	filter: EventsTailFilter & { limit?: number } = {},
): { cursor: EventsTailCursor; events: AuditEvent[] } {
	const scope = filter.scope ?? resolveOperatorScope(store);
	const limit = normalizeEventsTailLimit(filter.limit);
	const candidates = selectTailCandidates(store, { ...filter, scope });
	const uniqueIds = new Set<string>();
	const uniqueNewestFirst = candidates.filter((event) => {
		if (uniqueIds.has(event.id)) return false;
		uniqueIds.add(event.id);
		return true;
	});
	const cursor: EventsTailCursor = {
		scope,
		...(filter.organizationId ? { organizationId: filter.organizationId } : {}),
		...(filter.action ? { action: filter.action } : {}),
		seenIds: new Set(uniqueNewestFirst.map((event) => event.id)),
	};
	return {
		cursor,
		events: uniqueNewestFirst.slice(0, limit).reverse(),
	};
}

/**
 * Return newly observed scoped events in chronological order. Callers refresh
 * their store before every poll; this works for both shared Postgres and a
 * JsonStore modified by another process.
 */
export function pollEventsTail(
	store: ManagementStore,
	cursor: EventsTailCursor,
): AuditEvent[] {
	const candidates = selectTailCandidates(store, cursor);
	const newNewestFirst: AuditEvent[] = [];
	for (const event of candidates) {
		if (cursor.seenIds.has(event.id)) continue;
		cursor.seenIds.add(event.id);
		newNewestFirst.push(event);
	}
	return newNewestFirst.reverse();
}

function serializeExportBody(
	envelope: EventsExportEnvelope,
	format: EventsExportFormat,
): string {
	if (format === "jsonl") {
		if (envelope.events.length === 0) {
			return "";
		}
		return `${envelope.events.map((e) => JSON.stringify(e)).join("\n")}\n`;
	}
	return `${JSON.stringify(envelope, null, 2)}\n`;
}

/**
 * Export audit events: scoped, bounded, redacted, deterministic.
 * Optional file write is atomic and refuse-overwrite by default.
 */
export function exportEvents(
	store: ManagementStore,
	opts: EventsExportOptions = {},
): EventsExportEnvelope {
	const scope = opts.scope ?? resolveOperatorScope(store);
	const limit = normalizeEventsExportLimit(opts.limit);
	const format = normalizeEventsExportFormat(opts.format);
	const before = normalizeEventsExportBefore(opts.before);
	const corr = correlationId();

	const { events, truncated } = selectEventsForExport(store, {
		limit,
		organizationId: opts.organizationId,
		action: opts.action,
		...(before ? { before } : {}),
		scope,
	});

	const envelope: EventsExportEnvelope = {
		schemaVersion: 1,
		kind: "events.export",
		exportedAt: nowIso(),
		format,
		scope,
		limit,
		count: events.length,
		truncated,
		filters: {
			...(opts.organizationId ? { organizationId: opts.organizationId } : {}),
			...(opts.action ? { action: opts.action } : {}),
			...(before ? { before } : {}),
		},
		events,
		correlationId: corr,
	};

	if (opts.outputPath) {
		const body = serializeExportBody(envelope, format);
		const written = writeExportArtifact({ outputPath: opts.outputPath, body, force: Boolean(opts.force) });
		envelope.outputPath = written;
	}

	if (!opts.skipAudit) {
		store.mutate((data) => {
			appendAuditEvent(data, {
				actor: opts.actor ?? "operator",
				action: "events.export",
				subjectType: "audit_export",
				outcome: "success",
				source: opts.source ?? "cli",
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				correlationId: corr,
				message: `Exported ${events.length} audit event(s)`,
				metadata: {
					count: events.length,
					limit,
					truncated,
					format,
					wroteFile: Boolean(envelope.outputPath),
					filters: envelope.filters,
				},
			});
		});
	}

	return envelope;
}

/**
 * Database-aware export. It reads at most limit + 1 rows from each authority
 * so truncation is accurate without materializing a runtime audit history.
 */
export async function exportEventsOperational(
	store: ManagementStore,
	opts: EventsExportOptions = {},
): Promise<EventsExportEnvelope> {
	const scope = opts.scope ?? resolveOperatorScope(store);
	const limit = normalizeEventsExportLimit(opts.limit);
	const format = normalizeEventsExportFormat(opts.format);
	const before = normalizeEventsExportBefore(opts.before);
	const corr = correlationId();
	const page = await operationalEventPage(store, {
		scope,
		limit,
		...(opts.organizationId ? { organizationId: opts.organizationId } : {}),
		...(opts.action ? { action: opts.action } : {}),
		...(before ? { before } : {}),
	});

	const envelope: EventsExportEnvelope = {
		schemaVersion: 1,
		kind: "events.export",
		exportedAt: nowIso(),
		format,
		scope,
		limit,
		count: page.events.length,
		truncated: page.hasMore,
		filters: {
			...(opts.organizationId ? { organizationId: opts.organizationId } : {}),
			...(opts.action ? { action: opts.action } : {}),
			...(before ? { before } : {}),
		},
		events: page.events,
		correlationId: corr,
	};

	if (opts.outputPath) {
		const body = serializeExportBody(envelope, format);
		const written = writeExportArtifact({ outputPath: opts.outputPath, body, force: Boolean(opts.force) });
		envelope.outputPath = written;
	}

	if (!opts.skipAudit) {
		store.mutate((data) => {
			appendAuditEvent(data, {
				actor: opts.actor ?? "operator",
				action: "events.export",
				subjectType: "audit_export",
				outcome: "success",
				source: opts.source ?? "cli",
				projectId: scope.projectId,
				environmentId: scope.environmentId,
				correlationId: corr,
				message: `Exported ${page.events.length} audit event(s)`,
				metadata: {
					count: page.events.length,
					limit,
					truncated: page.hasMore,
					format,
					wroteFile: Boolean(envelope.outputPath),
					filters: envelope.filters,
				},
			});
		});
	}

	return envelope;
}

export function isReplayableTraceSubsystem(
	subsystem: DiagnosticTrace["subsystem"],
): subsystem is ReplayableTraceSubsystem {
	return (REPLAYABLE_TRACE_SUBSYSTEMS as readonly string[]).includes(subsystem);
}

function findTrace(
	store: ManagementStore,
	id: string,
): DiagnosticTrace | undefined {
	const key = id?.trim();
	if (!key) return undefined;
	return store.snapshot.traces.find(
		(t) => t.id === key || t.correlationId === key,
	);
}

/**
 * Locate a prior SCIM replay of the same original via audit metadata.
 * Used for idempotent events.replay apply.
 */
function findExistingScimReplay(
	store: ManagementStore,
	originalId: string,
	scope: ResourceScope,
): DiagnosticTrace | undefined {
	const audit = store.snapshot.events.find(
		(e) =>
			(e.action === "scim.replay" || e.action === "events.replay") &&
			eventInScope(e, scope) &&
			e.metadata &&
			(e.metadata as { originalId?: string }).originalId === originalId &&
			typeof e.subjectId === "string",
	);
	if (!audit?.subjectId) return undefined;
	try {
		return inspectScimTrace(store, audit.subjectId, { scope });
	} catch {
		return undefined;
	}
}

async function findExistingScimReplayAuthoritative(
	store: ManagementStore,
	originalId: string,
	scope: ResourceScope,
): Promise<DiagnosticTrace | undefined> {
	const audit = store.snapshot.events.find(
		(event) =>
			(event.action === "scim.replay" || event.action === "events.replay") &&
			eventInScope(event, scope) &&
			event.metadata &&
			(event.metadata as { originalId?: string }).originalId === originalId &&
			typeof event.subjectId === "string",
	);
	if (!audit?.subjectId) return undefined;
	try {
		return await inspectScimTraceAuthoritative(store, audit.subjectId, { scope });
	} catch {
		return undefined;
	}
}

function traceNotFound(id: string, stage: string): ClearanceError {
	return new ClearanceError({
		code: "TRACE_NOT_FOUND",
		message: "Diagnostic trace not found",
		stage,
		status: 404,
		remediation:
			"Pass a SCIM diagnostic trace id from scim test (not an audit event id)",
	});
}

async function recordIdempotentReplayAuditAuthoritative(
	store: ManagementStore,
	input: {
		original: DiagnosticTrace;
		existing: DiagnosticTrace;
		scope: ResourceScope;
		opts: ReplayDiagnosticOptions;
	},
): Promise<void> {
	if (!store.storeV2Topology?.authoritative) {
		store.mutate((data) => {
			appendAuditEvent(data, replayIdempotentAuditInput(input));
		});
		return;
	}
	if (!store.mutateCoordinated) {
		throw new ClearanceError({
			code: "STORE_V2_TOPOLOGY_TRANSACTION_REQUIRED",
			message: "Relational topology authority requires a coordinated transaction",
			stage: "events.replay",
			status: 500,
		});
	}
	await store.mutateCoordinated(async ({ data, topology, appendAudit }) => {
		const original = data.traces.find((trace) => trace.id === input.original.id);
		const existing = data.traces.find((trace) => trace.id === input.existing.id);
		if (!original || original.subsystem !== "scim" || !existing) {
			throw traceNotFound(input.original.id, "events.replay");
		}
		if (original.connectionId) {
			const connection = data.scimConnections.find(
				(candidate) => candidate.id === original.connectionId,
			);
			const organization = connection && topology ? await topology.lockOrganization({
				scope: input.scope,
				id: connection.organizationId,
			}) : null;
			if (!organization || organization.status === "archived") {
				throw traceNotFound(input.original.id, "events.replay");
			}
		} else if (original.organizationId) {
			const organization = topology ? await topology.lockOrganization({
				scope: input.scope,
				id: original.organizationId,
			}) : null;
			if (!organization || organization.status === "archived") {
				throw traceNotFound(input.original.id, "events.replay");
			}
		} else if (
			original.projectId !== input.scope.projectId ||
			original.environmentId !== input.scope.environmentId
		) {
			throw traceNotFound(input.original.id, "events.replay");
		}
		appendAudit(replayIdempotentAuditInput(input));
	});
}

function replayIdempotentAuditInput(input: {
	original: DiagnosticTrace;
	existing: DiagnosticTrace;
	scope: ResourceScope;
	opts: ReplayDiagnosticOptions;
}) {
	return {
		actor: input.opts.actor ?? "operator",
		action: "events.replay" as const,
		subjectType: "diagnostic_trace",
		subjectId: input.existing.id,
		outcome: "success" as const,
		source: input.opts.source ?? "cli",
		projectId: input.scope.projectId,
		environmentId: input.scope.environmentId,
		organizationId: input.original.organizationId,
		message: `Replay already recorded for diagnostic trace ${input.original.id}`,
		metadata: {
			originalId: input.original.id,
			idempotent: true,
			subsystem: "scim",
		},
	};
}

/**
 * Inspect an audit event and/or diagnostic trace by id / correlation id.
 * Fail closed for wrong-scope resources (same as missing).
 */
export function inspectEvent(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope },
): EventInspectResult {
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const key = id?.trim();
	if (!key) {
		throw new ClearanceError({
			code: "EVENT_ID_REQUIRED",
			message: "Event or trace id is required",
			stage: "events.inspect",
			status: 400,
			remediation: "Pass a stable event id or diagnostic trace id",
		});
	}

	const rawEvent = store.snapshot.events.find((e) => e.id === key);
	const event =
		rawEvent && eventInScope(rawEvent, scope)
			? sanitizeAuditEvent(rawEvent)
			: undefined;

	let trace: DiagnosticTrace | undefined;
	const rawTrace = findTrace(store, key);
	if (rawTrace) {
		if (rawTrace.subsystem === "scim") {
			try {
				trace = inspectScimTrace(store, rawTrace.id, { scope });
			} catch {
				// Wrong scope / missing → omit (fail closed later if no event either)
				trace = undefined;
			}
		} else if (traceInScope(rawTrace, scope)) {
			trace = rawTrace;
		}
	}

	if (!event && !trace) {
		throw new ClearanceError({
			code: "EVENT_NOT_FOUND",
			message: "Event or diagnostic trace not found",
			stage: "events.inspect",
			status: 404,
			remediation: "Verify the id and that it belongs to the active project/environment",
		});
	}

	let replayable = false;
	let replayBlocker: string | undefined;
	if (trace) {
		if (trace.stage.endsWith(".replay")) {
			replayBlocker =
				"Trace is already a replay artifact; pass the original diagnostic trace id";
		} else if (trace.subsystem === "scim") {
			replayable = true;
		} else if (trace.subsystem === "sso") {
			replayBlocker =
				"SSO diagnostic traces have no repository-defined mutating replay service; only SCIM re-record is supported";
		} else {
			replayBlocker = `Subsystem "${trace.subsystem}" is not replayable (only scim diagnostic re-record)`;
		}
	} else if (event) {
		replayBlocker =
			"Audit events are not replayable; only SCIM diagnostic traces can be re-recorded";
	}

	return { event, trace, scope, replayable, replayBlocker };
}

/**
 * Inspect runtime-owned events before falling back to the legacy audit/trace
 * reader. Runtime audit rows are never replayable; traces retain their
 * existing replay behavior and error contract.
 */
export async function inspectEventOperational(
	store: ManagementStore,
	id: string,
	opts?: { scope?: ResourceScope },
): Promise<EventInspectResult> {
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const key = id.trim();
	const runtime = key
		? await store.runtimeAuditEvents?.getById({ scope, id: key })
		: undefined;
	if (runtime) {
		return {
			event: sanitizeAuditEvent(runtime),
			scope,
			replayable: false,
			replayBlocker:
				"Audit events are not replayable; only SCIM diagnostic traces can be re-recorded",
		};
	}
	return inspectEvent(store, id, { scope });
}

/**
 * Replay a diagnostic trace via the shared SCIM replay service.
 *
 * - Defaults to dry-run when dryRun is true or confirm is not set.
 * - Mutating apply requires confirm=true (CLI --yes) and only works for SCIM.
 * - Idempotent: a prior scim.replay/events.replay of the same original returns
 *   the existing artifact without writing another.
 * - Never re-executes directory mutations or arbitrary audit actions.
 */
export function replayDiagnosticTrace(
	store: ManagementStore,
	id: string,
	opts: ReplayDiagnosticOptions = {},
): ReplayDiagnosticResult {
	const scope = opts.scope ?? resolveOperatorScope(store);
	const dryRun = opts.dryRun === true || opts.confirm !== true;
	const stage = "events.replay";

	const inspected = inspectEvent(store, id, { scope });
	const original = inspected.trace;
	if (!original) {
		throw new ClearanceError({
			code: "TRACE_NOT_FOUND",
			message: "Diagnostic trace not found",
			stage,
			status: 404,
			remediation:
				"Pass a SCIM diagnostic trace id from scim test (not an audit event id)",
		});
	}
	if (!inspected.replayable) {
		throw new ClearanceError({
			code: "EVENT_NOT_REPLAYABLE",
			message: inspected.replayBlocker ?? "Trace is not replayable",
			stage,
			status: 400,
			remediation:
				"Only original SCIM diagnostic traces can be re-recorded; audit mutations and other subsystems cannot be replayed",
		});
	}

	// Ensure SCIM scope rules (connection/org) — fail closed as TRACE_NOT_FOUND
	const scimOriginal = inspectScimTrace(store, original.id, { scope });

	const existing = findExistingScimReplay(store, scimOriginal.id, scope);
	if (existing) {
		if (!dryRun) {
			// Record idempotent audit evidence through a lightweight events.replay note
			store.mutate((data) => {
				appendAuditEvent(data, {
					actor: opts.actor ?? "operator",
					action: "events.replay",
					subjectType: "diagnostic_trace",
					subjectId: existing.id,
					outcome: "success",
					source: opts.source ?? "cli",
					projectId: scope.projectId,
					environmentId: scope.environmentId,
					organizationId: scimOriginal.organizationId,
					message: `Replay already recorded for diagnostic trace ${scimOriginal.id}`,
					metadata: {
						originalId: scimOriginal.id,
						idempotent: true,
						subsystem: "scim",
					},
				});
			});
		}
		return {
			dryRun,
			idempotent: true,
			wouldChange: false,
			replayable: true,
			original: scimOriginal,
			trace: existing,
			scope,
			...(dryRun ? {} : { auditAction: "events.replay" as const }),
		};
	}

	if (dryRun) {
		const preview: DiagnosticTrace = {
			...scimOriginal,
			id: "tr_preview",
			correlationId: "corr_replay_preview",
			createdAt: nowIso(),
			stage: `${scimOriginal.stage.replace(/\.replay$/, "")}.replay`,
		};
		return {
			dryRun: true,
			idempotent: false,
			wouldChange: true,
			replayable: true,
			original: scimOriginal,
			trace: preview,
			scope,
		};
	}

	// Mutating apply — real SCIM diagnostic re-record service
	const source = (opts.source ?? "cli") as ScimActorSource;
	const replay = replayScimTrace(store, scimOriginal.id, {
		actor: opts.actor ?? "operator",
		source,
		scope,
	});

	return {
		dryRun: false,
		idempotent: false,
		wouldChange: true,
		replayable: true,
		original: scimOriginal,
		trace: replay,
		scope,
		auditAction: "scim.replay",
	};
}

/**
 * Production replay path. It retains the synchronous JSON fallback, while
 * Postgres topology cutover resolves every SCIM organization boundary through
 * bounded normalized reads and rechecks that boundary in the write unit.
 */
export async function replayDiagnosticTraceOperational(
	store: ManagementStore,
	id: string,
	opts: ReplayDiagnosticOptions = {},
): Promise<ReplayDiagnosticResult> {
	if (!store.storeV2Topology?.authoritative) {
		return replayDiagnosticTrace(store, id, opts);
	}
	const scope = opts.scope ?? await resolveOperatorScopeAuthoritative(store);
	const dryRun = opts.dryRun === true || opts.confirm !== true;
	const stage = "events.replay";
	const rawTrace = findTrace(store, id);
	if (!rawTrace) throw traceNotFound(id, stage);
	if (rawTrace.subsystem !== "scim") {
		if (!traceInScope(rawTrace, scope)) throw traceNotFound(id, stage);
		throw new ClearanceError({
			code: "EVENT_NOT_REPLAYABLE",
			message: rawTrace.stage.endsWith(".replay")
				? "Trace is already a replay artifact; pass the original diagnostic trace id"
				: `Subsystem "${rawTrace.subsystem}" is not replayable (only scim diagnostic re-record)`,
			stage,
			status: 400,
			remediation:
				"Only original SCIM diagnostic traces can be re-recorded; audit mutations and other subsystems cannot be replayed",
		});
	}
	const original = await inspectScimTraceAuthoritative(store, rawTrace.id, { scope });
	if (original.stage.endsWith(".replay")) {
		throw new ClearanceError({
			code: "EVENT_NOT_REPLAYABLE",
			message: "Trace is already a replay artifact; pass the original diagnostic trace id",
			stage,
			status: 400,
			remediation:
				"Only original SCIM diagnostic traces can be re-recorded; audit mutations and other subsystems cannot be replayed",
		});
	}

	const existing = await findExistingScimReplayAuthoritative(store, original.id, scope);
	if (existing) {
		if (!dryRun) {
			await recordIdempotentReplayAuditAuthoritative(store, {
				original,
				existing,
				scope,
				opts,
			});
		}
		return {
			dryRun,
			idempotent: true,
			wouldChange: false,
			replayable: true,
			original,
			trace: existing,
			scope,
			...(dryRun ? {} : { auditAction: "events.replay" as const }),
		};
	}

	if (dryRun) {
		return {
			dryRun: true,
			idempotent: false,
			wouldChange: true,
			replayable: true,
			original,
			trace: {
				...original,
				id: "tr_preview",
				correlationId: "corr_replay_preview",
				createdAt: nowIso(),
				stage: `${original.stage.replace(/\.replay$/, "")}.replay`,
			},
			scope,
		};
	}

	const trace = await replayScimTraceAuthoritative(store, original.id, {
		actor: opts.actor ?? "operator",
		source: (opts.source ?? "cli") as ScimActorSource,
		scope,
	});
	return {
		dryRun: false,
		idempotent: false,
		wouldChange: true,
		replayable: true,
		original,
		trace,
		scope,
		auditAction: "scim.replay",
	};
}
