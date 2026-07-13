/**
 * Opaque keyset cursor pagination over snapshot arrays (FOLLOW.md P2.3.1).
 *
 * Ordering contract (stable, documented — shared by CLI and API):
 * - users, organizations: createdAt ascending, then id ascending
 * - events, sessions:     createdAt descending, then id descending (newest first)
 *
 * Design choice: KEYSET (createdAt + id), not index/offset. The snapshot's
 * events array is prepend-heavy (unshift) and users/orgs grow by append; an
 * index cursor would re-serve or skip rows whenever a concurrent writer
 * inserts between pages. A (createdAt, id) keyset is a strict total order, so
 * following nextCursor to exhaustion yields no duplicates and no omissions
 * for rows that existed when the walk began.
 *
 * The cursor is base64url(JSON {v:1, s:<surface>, k:[createdAt, id]}) of the
 * LAST item on the returned page. It is opaque to callers and validated
 * fail-closed: garbage, truncated, or cross-surface cursors raise a
 * structured CURSOR_INVALID error rather than silently returning page one.
 */
import { Buffer } from "node:buffer";
import { ClearanceError } from "./errors.js";

export type PageSurface = "users" | "organizations" | "events" | "sessions";
export type PageOrder = "asc" | "desc";

export type PageCursorKey = {
	createdAt: string;
	id: string;
};

type CursorPayload = {
	v: 1;
	s: PageSurface;
	k: [string, string];
};

const PAGE_SURFACES: readonly PageSurface[] = [
	"users",
	"organizations",
	"events",
	"sessions",
];

export function encodePageCursor(
	surface: PageSurface,
	key: PageCursorKey,
): string {
	const payload: CursorPayload = { v: 1, s: surface, k: [key.createdAt, key.id] };
	return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

function cursorInvalid(surface: PageSurface, stage: string): ClearanceError {
	return new ClearanceError({
		code: "CURSOR_INVALID",
		message: `Invalid pagination cursor for ${surface}`,
		stage,
		status: 400,
		remediation:
			"Pass the opaque nextCursor value returned by the previous page, or omit cursor for the first page",
	});
}

/**
 * Decode + validate an opaque cursor. Fail-closed: anything that is not a
 * well-formed cursor for this surface throws CURSOR_INVALID (garbage base64,
 * non-JSON, wrong shape, wrong version, or a cursor minted for another
 * surface). Returns undefined when no cursor was supplied.
 */
export function decodePageCursor(
	raw: string | undefined | null,
	surface: PageSurface,
	stage: string,
): PageCursorKey | undefined {
	if (raw === undefined || raw === null || raw === "") return undefined;
	if (typeof raw !== "string" || raw.length > 2048) {
		throw cursorInvalid(surface, stage);
	}
	// Node's base64url decoder is lenient; round-trip to reject smuggled junk
	// that would decode to different bytes than it re-encodes to.
	let parsed: unknown;
	try {
		parsed = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
	} catch {
		throw cursorInvalid(surface, stage);
	}
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw cursorInvalid(surface, stage);
	}
	const payload = parsed as Partial<CursorPayload>;
	if (payload.v !== 1) throw cursorInvalid(surface, stage);
	if (!PAGE_SURFACES.includes(payload.s as PageSurface)) {
		throw cursorInvalid(surface, stage);
	}
	if (payload.s !== surface) throw cursorInvalid(surface, stage);
	if (
		!Array.isArray(payload.k) ||
		payload.k.length !== 2 ||
		typeof payload.k[0] !== "string" ||
		typeof payload.k[1] !== "string" ||
		!payload.k[0] ||
		!payload.k[1]
	) {
		throw cursorInvalid(surface, stage);
	}
	return { createdAt: payload.k[0], id: payload.k[1] };
}

/** Strict total order on (createdAt, id) — ISO-8601 strings compare lexically. */
function compareKey(a: PageCursorKey, b: PageCursorKey): number {
	if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? -1 : 1;
	if (a.id === b.id) return 0;
	return a.id < b.id ? -1 : 1;
}

export type ResourcePage<T> = {
	items: T[];
	/** Opaque cursor for the next page; null when this page is the last. */
	nextCursor: string | null;
};

/**
 * Keyset-paginate an already-filtered snapshot array. Items are sorted into
 * the documented order for the surface, the page starts strictly after the
 * cursor key (when present), and nextCursor is emitted only when more items
 * remain.
 */
export function paginateByCreatedAt<T extends { id: string; createdAt: string }>(
	items: T[],
	opts: {
		surface: PageSurface;
		order: PageOrder;
		limit: number;
		cursor?: PageCursorKey;
	},
): ResourcePage<T> {
	const sorted = [...items].sort((a, b) =>
		opts.order === "asc" ? compareKey(a, b) : compareKey(b, a),
	);
	let begin = 0;
	if (opts.cursor) {
		const cursor = opts.cursor;
		const idx = sorted.findIndex((item) =>
			opts.order === "asc"
				? compareKey(item, cursor) > 0
				: compareKey(item, cursor) < 0,
		);
		begin = idx === -1 ? sorted.length : idx;
	}
	const page = sorted.slice(begin, begin + opts.limit);
	const hasMore = begin + opts.limit < sorted.length;
	const last = page[page.length - 1];
	return {
		items: page,
		nextCursor: hasMore && last ? encodePageCursor(opts.surface, last) : null,
	};
}

/**
 * Fail-closed page-size validation shared by paginated list services.
 * NaN / non-integers / out-of-range values raise the caller's stable code.
 */
export function normalizePageLimit(
	limit: number | undefined,
	spec: {
		stage: string;
		code: string;
		defaultValue: number;
		maximum: number;
	},
): number {
	const value = limit ?? spec.defaultValue;
	if (!Number.isInteger(value) || value < 1 || value > spec.maximum) {
		throw new ClearanceError({
			code: spec.code,
			message: `List limit must be an integer between 1 and ${spec.maximum}`,
			stage: spec.stage,
			status: 400,
			remediation: `Pass limit as an integer from 1 through ${spec.maximum}`,
		});
	}
	return value;
}
