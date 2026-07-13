/**
 * Audit event construction, append, and retention (FOLLOW.md P2.3.4).
 *
 * Retention: the snapshot keeps at most CLEARANCE_AUDIT_MAX_EVENTS events
 * (default 5000, validated fail-closed), newest first. When the cap forces
 * truncation, a single `system.audit.pruned` marker event is recorded with
 * the dropped count and the createdAt of the oldest dropped event, so
 * operators can see that history was lost instead of it vanishing silently.
 * The marker is inserted only after room is made below the cap, so pruning
 * can never recurse.
 *
 * Archival: pruned events are gone from the snapshot. To keep an append-only
 * archive, export on a schedule BEFORE events age out, bounding each run with
 * --before so archives don't overlap:
 *
 *   clearance events export --output audit-$(date +%F).json --before <iso-ts>
 *
 * (--before exports only events created strictly before the timestamp.)
 * True append-only archival storage belongs to store-v2.
 */
import type { ManagementStore } from "../store/types.js";
import { correlationId, newId, nowIso } from "../store/json-store.js";
import type { AuditEvent, DataStoreSnapshot } from "../types/resources.js";
import { ClearanceError } from "./errors.js";
import { redactRecord } from "./redact.js";

export const AUDIT_MAX_EVENTS_DEFAULT = 5000;
export const AUDIT_MAX_EVENTS_MIN = 10;
export const AUDIT_MAX_EVENTS_MAX = 1_000_000;
export const AUDIT_PRUNED_ACTION = "system.audit.pruned";

/**
 * Resolve the audit retention cap. CLEARANCE_AUDIT_MAX_EVENTS overrides the
 * default; garbage values fail closed (mutations refuse to run) rather than
 * silently falling back to a cap the operator did not configure.
 */
/**
 * Memoized by raw env value: retention runs on every audit append, so the
 * parse/validate work must not repeat per write. Validation behavior is
 * unchanged (a malformed value still fails closed on every write — audit
 * retention silently misconfigured would be worse).
 */
let auditMaxCacheRaw: string | undefined | symbol = Symbol("unset");
let auditMaxCacheValue = AUDIT_MAX_EVENTS_DEFAULT;

export function auditMaxEvents(
	env: Record<string, string | undefined> = process.env,
): number {
	const raw = env.CLEARANCE_AUDIT_MAX_EVENTS;
	if (env === process.env && raw === auditMaxCacheRaw) return auditMaxCacheValue;
	const value = computeAuditMaxEvents(raw);
	if (env === process.env) {
		auditMaxCacheRaw = raw;
		auditMaxCacheValue = value;
	}
	return value;
}

function computeAuditMaxEvents(raw: string | undefined): number {
	if (raw === undefined || raw.trim() === "") return AUDIT_MAX_EVENTS_DEFAULT;
	const value = Number(raw);
	if (
		!Number.isInteger(value) ||
		value < AUDIT_MAX_EVENTS_MIN ||
		value > AUDIT_MAX_EVENTS_MAX
	) {
		throw new ClearanceError({
			code: "AUDIT_MAX_EVENTS_INVALID",
			message: `CLEARANCE_AUDIT_MAX_EVENTS must be an integer between ${AUDIT_MAX_EVENTS_MIN} and ${AUDIT_MAX_EVENTS_MAX}`,
			stage: "audit.retention",
			status: 500,
			remediation:
				"Unset CLEARANCE_AUDIT_MAX_EVENTS or set a valid integer cap (default 5000)",
		});
	}
	return value;
}

export type AuditEventInput = Omit<
	AuditEvent,
	"id" | "createdAt" | "correlationId"
> & {
	correlationId?: string;
};

/** Build a redacted audit event (no secrets/tokens in metadata). */
export function buildAuditEvent(input: AuditEventInput): AuditEvent {
	return {
		id: newId("evt"),
		correlationId: input.correlationId ?? correlationId(),
		projectId: input.projectId,
		environmentId: input.environmentId,
		organizationId: input.organizationId,
		actor: input.actor,
		action: input.action,
		subjectType: input.subjectType,
		subjectId: input.subjectId,
		outcome: input.outcome,
		source: input.source,
		message: input.message,
		// Never persist secrets/tokens in audit metadata
		metadata: redactRecord(
			input.metadata as Record<string, unknown> | undefined,
		),
		createdAt: nowIso(),
	};
}

/**
 * Enforce the retention cap on a snapshot draft (events are newest-first).
 * Truncation maintains exactly ONE rolling system.audit.pruned marker with a
 * cumulative droppedCount. A per-prune marker is itself an event that
 * re-overflows the cap, so the naive version reached ~50% marker density at
 * steady state and halved effective retention (adversarial finding M3).
 * Prior markers are extracted (counts carried forward), overflow real events
 * drop from the tail, and one cumulative marker is reinserted at the head —
 * never re-triggering itself (no recursion, no cap overshoot).
 */
export function enforceAuditRetention(data: DataStoreSnapshot): void {
	const max = auditMaxEvents();
	if (data.events.length <= max) return;
	let carriedDropped = 0;
	let carriedOldest: string | null = null;
	const real: typeof data.events = [];
	for (const e of data.events) {
		if (e.action === AUDIT_PRUNED_ACTION && e.actor === "system") {
			const meta = e.metadata as
				| { droppedCount?: number; oldestDroppedCreatedAt?: string | null }
				| undefined;
			carriedDropped += Number(meta?.droppedCount ?? 0) || 0;
			const prev = meta?.oldestDroppedCreatedAt ?? null;
			if (prev && (!carriedOldest || prev < carriedOldest)) carriedOldest = prev;
			continue;
		}
		real.push(e);
	}
	const keep = max - 1; // reserve one slot for the rolling marker
	const dropped = real.slice(keep);
	if (real.length > keep) real.length = keep;
	const oldestDroppedNow = dropped[dropped.length - 1]?.createdAt ?? null;
	const oldest =
		[oldestDroppedNow, carriedOldest]
			.filter((v): v is string => Boolean(v))
			.sort()[0] ?? null;
	const totalDropped = carriedDropped + dropped.length;
	const marker = buildAuditEvent({
		actor: "system",
		action: AUDIT_PRUNED_ACTION,
		subjectType: "audit_log",
		outcome: "success",
		source: "system",
		message: `Pruned ${totalDropped} audit event(s) beyond retention cap ${max} (cumulative)`,
		metadata: {
			droppedCount: totalDropped,
			oldestDroppedCreatedAt: oldest,
			cap: max,
		},
	});
	data.events.length = 0;
	data.events.push(marker, ...real);
}

/**
 * Append an audit event onto a snapshot draft. Use inside the same store.mutate
 * as the resource mutation so Postgres commits validation+write+audit atomically.
 */
export function appendAuditEvent(
	data: DataStoreSnapshot,
	input: AuditEventInput,
): AuditEvent {
	const event = buildAuditEvent(input);
	data.events.unshift(event);
	enforceAuditRetention(data);
	return event;
}

export function recordEvent(
	store: ManagementStore,
	input: AuditEventInput,
): AuditEvent {
	const event = buildAuditEvent(input);
	store.mutate((data) => {
		data.events.unshift(event);
		enforceAuditRetention(data);
	});
	return event;
}
