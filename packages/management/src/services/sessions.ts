/**
 * Operator session list / revoke on the management plane.
 *
 * JSON/local: management snapshot sessions only.
 * Postgres runtime path lives in auth-bridge (listSessionsInAuth / revokeSessionInAuth)
 * and never returns raw session tokens or token prefixes.
 *
 * Scope is always principal-derived (projectId + environmentId). Request headers
 * are never authority — callers pass the already-resolved ResourceScope.
 */
import type {
	ManagementSnapshotReader,
	ManagementUnitOfWork,
} from "../store/types.js";
import type { AuditEvent, SessionRecord } from "../types/resources.js";
import { appendAuditEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";
import {
	decodePageCursor,
	normalizePageLimit,
	paginateByCreatedAt,
} from "./pagination.js";
import {
	assertResourceInScope,
	resolveOperatorScope,
	type ResourceScope,
} from "./scope.js";
import { nowIso } from "../store/json-store.js";

/** Safe operator-facing session view — never includes token material. */
export type SessionView = {
	id: string;
	principalId: string;
	projectId: string;
	environmentId: string;
	status: "active" | "revoked";
	createdAt: string;
	expiresAt?: string;
	revokedAt?: string;
	ipAddress?: string;
	userAgent?: string;
};

export type SessionSource = AuditEvent["source"];

export type RevokeSessionResult = {
	session: SessionView;
	/** True when session was already revoked / absent under authorized contract */
	idempotent: boolean;
};

export function normalizeSessionLimit(limit: number | undefined): number {
	const value = limit ?? 100;
	if (!Number.isInteger(value) || value < 1 || value > 500) {
		throw new ClearanceError({
			code: "SESSION_LIMIT_INVALID",
			message: "Session limit must be an integer between 1 and 500",
			stage: "sessions.list",
			status: 400,
			remediation: "Pass --limit with an integer from 1 through 500",
		});
	}
	return value;
}

const SENSITIVE_SESSION_KEYS = /token|secret|password|authorization|bearer|cookie/i;

/**
 * Strip any credential-like fields from a session-shaped object before return.
 * Defense in depth: list/revoke must never surface raw tokens.
 */
export function sanitizeSessionView(
	input: Record<string, unknown>,
): SessionView {
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(input)) {
		if (SENSITIVE_SESSION_KEYS.test(k)) continue;
		out[k] = v;
	}
	return {
		id: String(out.id ?? ""),
		principalId: String(out.principalId ?? ""),
		projectId: String(out.projectId ?? ""),
		environmentId: String(out.environmentId ?? ""),
		status: out.status === "revoked" ? "revoked" : "active",
		createdAt: String(out.createdAt ?? ""),
		...(typeof out.expiresAt === "string" ? { expiresAt: out.expiresAt } : {}),
		...(typeof out.revokedAt === "string" ? { revokedAt: out.revokedAt } : {}),
		...(typeof out.ipAddress === "string" && out.ipAddress
			? { ipAddress: out.ipAddress }
			: {}),
		...(typeof out.userAgent === "string" && out.userAgent
			? { userAgent: out.userAgent }
			: {}),
	};
}

function principalForSession(
	store: ManagementSnapshotReader,
	principalId: string,
	scope: ResourceScope,
	stage: string,
) {
	const principal = store.snapshot.principals.find((p) => p.id === principalId);
	if (!principal || principal.status === "deleted") {
		throw new ClearanceError({
			code: "SESSION_NOT_FOUND",
			message: "Session not found",
			stage,
			status: 404,
		});
	}
	assertResourceInScope(principal, scope, {
		code: "SESSION_NOT_FOUND",
		stage,
		label: "Session",
	});
	return principal;
}

export function toSessionView(
	session: SessionRecord,
	projectId: string,
	extra?: Partial<SessionView>,
): SessionView {
	return sanitizeSessionView({
		id: session.id,
		principalId: session.principalId,
		projectId,
		environmentId: session.environmentId,
		status: session.status,
		createdAt: session.createdAt,
		...(session.revokedAt ? { revokedAt: session.revokedAt } : {}),
		...extra,
	});
}

/**
 * List management-snapshot sessions under principal-derived scope.
 * Defaults to active only. Does not audit (list is not privileged-write).
 */
export function listSessions(
	store: ManagementSnapshotReader,
	opts?: {
		scope?: ResourceScope;
		/** When true, include revoked tombstones */
		includeRevoked?: boolean;
		limit?: number;
	},
): SessionView[] {
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const includeRevoked = opts?.includeRevoked === true;
	const limit = normalizeSessionLimit(opts?.limit);
	const views = selectSessionViews(store, scope, includeRevoked);
	// Newest first, then apply limit
	views.sort((a, b) => (a.createdAt < b.createdAt ? 1 : a.createdAt > b.createdAt ? -1 : 0));
	return views.slice(0, limit);
}

/** Shared scoped selection for listSessions / listSessionsPage (unbounded). */
function selectSessionViews(
	store: ManagementSnapshotReader,
	scope: ResourceScope,
	includeRevoked: boolean,
): SessionView[] {
	const principals = new Map(
		store.snapshot.principals
			.filter(
				(p) =>
					p.projectId === scope.projectId &&
					p.environmentId === scope.environmentId &&
					p.status !== "deleted",
			)
			.map((p) => [p.id, p]),
	);

	const views: SessionView[] = [];
	for (const session of store.snapshot.sessions) {
		if (!includeRevoked && session.status !== "active") continue;
		const principal = principals.get(session.principalId);
		if (!principal) continue;
		// Session environment must match principal scope environment
		if (session.environmentId !== scope.environmentId) continue;
		views.push(toSessionView(session, principal.projectId));
	}
	return views;
}

/**
 * Cursor-paginated management-snapshot sessions (FOLLOW.md P2.3.1).
 * Ordering: createdAt descending, then id descending (newest first; the id
 * tiebreak makes the keyset a strict total order — see pagination.ts).
 * Postgres runtime sessions paginate via listSessionsPageInAuth (auth-bridge).
 */
export function listSessionsPage(
	store: ManagementSnapshotReader,
	opts?: {
		scope?: ResourceScope;
		/** When true, include revoked tombstones */
		includeRevoked?: boolean;
		limit?: number;
		/** Opaque cursor from a previous page's nextCursor (fail-closed). */
		cursor?: string;
	},
): { sessions: SessionView[]; nextCursor: string | null } {
	const scope = opts?.scope ?? resolveOperatorScope(store);
	// Keep the shipped SESSION_LIMIT_INVALID contract for page size.
	const limit = normalizeSessionLimit(opts?.limit);
	const cursor = decodePageCursor(opts?.cursor, "sessions", "sessions.list");
	// Same selection semantics as listSessions, unbounded.
	const all = selectSessionViews(store, scope, opts?.includeRevoked === true);
	const page = paginateByCreatedAt(all, {
		surface: "sessions",
		order: "desc",
		limit,
		cursor,
	});
	return { sessions: page.items, nextCursor: page.nextCursor };
}

/** Load one safe session view under scope without changing state. */
export function inspectSession(
	store: ManagementSnapshotReader,
	id: string,
	opts?: { scope?: ResourceScope },
): SessionView {
	const scope = opts?.scope ?? resolveOperatorScope(store);
	const sessionId = id?.trim();
	const session = store.snapshot.sessions.find((candidate) => candidate.id === sessionId);
	if (!session) {
		throw new ClearanceError({
			code: "SESSION_NOT_FOUND",
			message: "Session not found",
			stage: "sessions.inspect",
			status: 404,
		});
	}
	const principal = principalForSession(
		store,
		session.principalId,
		scope,
		"sessions.inspect",
	);
	if (session.environmentId !== scope.environmentId) {
		throw new ClearanceError({
			code: "SESSION_NOT_FOUND",
			message: "Session not found",
			stage: "sessions.inspect",
			status: 404,
		});
	}
	return toSessionView(session, principal.projectId);
}

/**
 * Revoke a management-snapshot session by stable id.
 * Idempotent: already-revoked under scope returns success with idempotent=true.
 * Missing or cross-scope fails closed as SESSION_NOT_FOUND.
 * Always writes an audit event (including idempotent re-revoke).
 */
export function revokeSession(
	store: ManagementUnitOfWork,
	id: string,
	input?: {
		actor?: string;
		source?: SessionSource;
		scope?: ResourceScope;
	},
): RevokeSessionResult {
	const scope = input?.scope ?? resolveOperatorScope(store);
	const now = nowIso();
	const sessionId = id?.trim();
	if (!sessionId) {
		throw new ClearanceError({
			code: "SESSION_ID_REQUIRED",
			message: "Session id is required",
			stage: "sessions.revoke",
			status: 400,
		});
	}

	let result: RevokeSessionResult | undefined;

	store.mutate((data) => {
		const session = data.sessions.find((s) => s.id === sessionId);
		if (!session) {
			throw new ClearanceError({
				code: "SESSION_NOT_FOUND",
				message: "Session not found",
				stage: "sessions.revoke",
				status: 404,
			});
		}

		const principal = data.principals.find((p) => p.id === session.principalId);
		if (!principal || principal.status === "deleted") {
			throw new ClearanceError({
				code: "SESSION_NOT_FOUND",
				message: "Session not found",
				stage: "sessions.revoke",
				status: 404,
			});
		}
		assertResourceInScope(principal, scope, {
			code: "SESSION_NOT_FOUND",
			stage: "sessions.revoke",
			label: "Session",
		});
		if (session.environmentId !== scope.environmentId) {
			throw new ClearanceError({
				code: "SESSION_NOT_FOUND",
				message: "Session not found",
				stage: "sessions.revoke",
				status: 404,
			});
		}

		const alreadyRevoked = session.status === "revoked";
		if (!alreadyRevoked) {
			session.status = "revoked";
			session.revokedAt = now;
		}

		const view = toSessionView(session, principal.projectId);
		appendAuditEvent(data, {
			actor: input?.actor ?? "operator",
			action: "sessions.revoke",
			subjectType: "session",
			subjectId: session.id,
			outcome: "success",
			source: (input?.source as "cli") ?? "cli",
			projectId: principal.projectId,
			environmentId: principal.environmentId,
			message: alreadyRevoked
				? `Session ${session.id} already revoked`
				: `Revoked session ${session.id}`,
			metadata: {
				principalId: principal.id,
				idempotent: alreadyRevoked,
			},
		});

		result = { session: view, idempotent: alreadyRevoked };
	});

	if (!result) {
		throw new ClearanceError({
			code: "SESSION_NOT_FOUND",
			message: "Session not found",
			stage: "sessions.revoke",
			status: 404,
		});
	}
	return result;
}

/** Test/helper: ensure principal exists in scope (re-export pattern). */
export function assertSessionPrincipalInScope(
	store: ManagementSnapshotReader,
	principalId: string,
	scope?: ResourceScope,
): void {
	const resolved = scope ?? resolveOperatorScope(store);
	principalForSession(store, principalId, resolved, "sessions.scope");
}
