/**
 * Idempotency-Key storage for /v1/* mutating API routes (FOLLOW.md P2.3.2).
 *
 * Keys are scoped per route+method ("POST /v1/users") and fingerprint the
 * request body, so replaying the same key with the same payload returns the
 * original response, while the same key with a DIFFERENT payload is a
 * structured 409 conflict.
 *
 * Storage backends:
 * - Postgres (PgStore): a dedicated companion table
 *   (<snapshot_table>_idempotency) with an expires_at TTL and opportunistic
 *   cleanup — deliberately NOT the JSONB snapshot, which would inflate every
 *   subsequent write and make TTL expiry itself a snapshot mutation.
 * - JSON store: an in-memory Map with the same TTL semantics. This is
 *   process-local by design — the JSON backend is the single-process local
 *   dev profile, so replay protection across process restarts is not
 *   promised there (documented limitation; Postgres is the durable path).
 */
import { createHash } from "node:crypto";
import type { ManagementStore } from "../store/types.js";
import { ClearanceError } from "./errors.js";

export const IDEMPOTENCY_DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h

export type IdempotencyRecord = {
	/** Route+method scope, e.g. "POST /v1/users" */
	scopeKey: string;
	/** Client-supplied Idempotency-Key header value */
	key: string;
	/** sha256 of scopeKey + raw request body — detects key reuse conflicts */
	fingerprint: string;
	status: number;
	contentType: string;
	body: string;
};

export interface IdempotencyBackend {
	readonly kind: "postgres" | "memory";
	get(scopeKey: string, key: string): Promise<IdempotencyRecord | null>;
	put(record: IdempotencyRecord): Promise<void>;
}

/**
 * Resolve the replay TTL. CLEARANCE_IDEMPOTENCY_TTL_MS overrides the 24h
 * default (fail-closed on garbage — an unparseable TTL must not silently
 * become "keys never expire" or "keys never match").
 */
export function resolveIdempotencyTtlMs(
	env: Record<string, string | undefined> = process.env,
): number {
	const raw = env.CLEARANCE_IDEMPOTENCY_TTL_MS;
	if (raw === undefined || raw.trim() === "") return IDEMPOTENCY_DEFAULT_TTL_MS;
	const value = Number(raw);
	if (!Number.isInteger(value) || value < 1 || value > 30 * 24 * 60 * 60 * 1000) {
		throw new ClearanceError({
			code: "IDEMPOTENCY_TTL_INVALID",
			message:
				"CLEARANCE_IDEMPOTENCY_TTL_MS must be an integer between 1 and 2592000000 (30 days)",
			stage: "api.idempotency",
			status: 500,
			remediation: "Unset CLEARANCE_IDEMPOTENCY_TTL_MS or set a valid duration in milliseconds",
		});
	}
	return value;
}

const IDEMPOTENCY_KEY_RE = /^[\x21-\x7e]{1,200}$/;

/** Fail-closed Idempotency-Key header validation (visible ASCII, 1–200 chars). */
export function assertIdempotencyKeyValid(key: string): void {
	if (!IDEMPOTENCY_KEY_RE.test(key)) {
		throw new ClearanceError({
			code: "IDEMPOTENCY_KEY_INVALID",
			message: "Idempotency-Key must be 1-200 visible ASCII characters",
			stage: "api.idempotency",
			status: 400,
			remediation: "Send a unique opaque token (e.g. a UUID) as the Idempotency-Key header",
		});
	}
}

/** Deterministic request fingerprint: same route+method+body ⇒ same digest. */
export function fingerprintIdempotentRequest(
	scopeKey: string,
	rawBody: string,
): string {
	return createHash("sha256").update(`${scopeKey}\n${rawBody}`).digest("hex");
}

/** Structured 409 for Idempotency-Key reuse with a different payload. */
export function idempotencyConflictError(scopeKey: string): ClearanceError {
	return new ClearanceError({
		code: "IDEMPOTENCY_KEY_CONFLICT",
		message: `Idempotency-Key was already used for ${scopeKey} with a different request payload`,
		stage: "api.idempotency",
		status: 409,
		remediation:
			"Use a fresh Idempotency-Key for a different payload, or resend the original payload to replay the stored response",
	});
}

type PgIdempotencyCapable = {
	getIdempotencyRecord(
		scopeKey: string,
		key: string,
	): Promise<{
		fingerprint: string;
		status: number;
		contentType: string;
		body: string;
	} | null>;
	putIdempotencyRecord(record: {
		scopeKey: string;
		key: string;
		fingerprint: string;
		status: number;
		contentType: string;
		body: string;
		ttlMs: number;
	}): Promise<void>;
};

function hasPgIdempotency(
	store: ManagementStore,
): store is ManagementStore & PgIdempotencyCapable {
	return (
		store.backend === "postgres" &&
		typeof (store as Partial<PgIdempotencyCapable>).getIdempotencyRecord ===
			"function" &&
		typeof (store as Partial<PgIdempotencyCapable>).putIdempotencyRecord ===
			"function"
	);
}

type MemoryEntry = IdempotencyRecord & { expiresAt: number };

class MemoryIdempotencyBackend implements IdempotencyBackend {
	readonly kind = "memory" as const;
	private entries = new Map<string, MemoryEntry>();

	constructor(
		private ttlMs: number,
		private now: () => number = Date.now,
	) {}

	private mapKey(scopeKey: string, key: string): string {
		return `${scopeKey}\n${key}`;
	}

	async get(scopeKey: string, key: string): Promise<IdempotencyRecord | null> {
		const entry = this.entries.get(this.mapKey(scopeKey, key));
		if (!entry) return null;
		if (entry.expiresAt <= this.now()) {
			this.entries.delete(this.mapKey(scopeKey, key));
			return null;
		}
		const { expiresAt: _e, ...record } = entry;
		return record;
	}

	async put(record: IdempotencyRecord): Promise<void> {
		// Opportunistic sweep — same policy as the Postgres companion table.
		const now = this.now();
		for (const [k, entry] of this.entries) {
			if (entry.expiresAt <= now) this.entries.delete(k);
		}
		const mapKey = this.mapKey(record.scopeKey, record.key);
		if (this.entries.has(mapKey)) return; // first responder wins
		this.entries.set(mapKey, { ...record, expiresAt: now + this.ttlMs });
	}
}

class PgIdempotencyBackend implements IdempotencyBackend {
	readonly kind = "postgres" as const;

	constructor(
		private store: ManagementStore & PgIdempotencyCapable,
		private ttlMs: number,
	) {}

	async get(scopeKey: string, key: string): Promise<IdempotencyRecord | null> {
		const row = await this.store.getIdempotencyRecord(scopeKey, key);
		if (!row) return null;
		return { scopeKey, key, ...row };
	}

	async put(record: IdempotencyRecord): Promise<void> {
		await this.store.putIdempotencyRecord({ ...record, ttlMs: this.ttlMs });
	}
}

/**
 * Pick the idempotency backend for a management store: the Postgres companion
 * table when the store is PgStore, otherwise the process-local in-memory map.
 */
export function createIdempotencyBackend(
	store: ManagementStore,
	opts?: { ttlMs?: number; now?: () => number },
): IdempotencyBackend {
	const ttlMs = opts?.ttlMs ?? resolveIdempotencyTtlMs();
	if (hasPgIdempotency(store)) {
		return new PgIdempotencyBackend(store, ttlMs);
	}
	return new MemoryIdempotencyBackend(ttlMs, opts?.now);
}
