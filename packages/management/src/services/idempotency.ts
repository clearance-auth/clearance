/** Durable operation-key fencing for mutating management API requests. */
import { createHash } from "node:crypto";
import type { ManagementStore } from "../store/types.js";
import { ClearanceError } from "./errors.js";

export const IDEMPOTENCY_DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
// Long enough that a healthy request cannot be reclaimed while a durable
// create/rotate is still committing; failed requests release immediately.
export const IDEMPOTENCY_DEFAULT_LEASE_MS = 5 * 60 * 1000;

export type IdempotencyRecord = {
	scopeKey: string; key: string; fingerprint: string; status: number; contentType: string; body: string;
};
export type IdempotencyClaim =
	| { state: "claimed"; generation: number }
	| { state: "pending"; generation: number }
	| { state: "completed"; record: IdempotencyRecord }
	| { state: "conflict" };

export interface IdempotencyBackend {
	readonly kind: "postgres" | "memory";
	claim(input: { scopeKey: string; key: string; fingerprint: string; leaseMs?: number }): Promise<IdempotencyClaim>;
	renew(input: { scopeKey: string; key: string; fingerprint: string; generation: number; leaseMs?: number }): Promise<boolean>;
	complete(input: IdempotencyRecord & { generation: number }): Promise<boolean>;
	fail(input: { scopeKey: string; key: string; fingerprint: string; generation: number }): Promise<void>;
	/** Legacy inspection helpers retained for management-store callers. */
	get(scopeKey: string, key: string): Promise<IdempotencyRecord | null>;
	put(record: IdempotencyRecord): Promise<void>;
}

export function resolveIdempotencyTtlMs(env: Record<string, string | undefined> = process.env): number {
	const raw = env.CLEARANCE_IDEMPOTENCY_TTL_MS;
	if (raw === undefined || raw.trim() === "") return IDEMPOTENCY_DEFAULT_TTL_MS;
	const value = Number(raw);
	if (!Number.isInteger(value) || value < 1 || value > 30 * 24 * 60 * 60 * 1000) throw new ClearanceError({ code: "IDEMPOTENCY_TTL_INVALID", message: "CLEARANCE_IDEMPOTENCY_TTL_MS must be an integer between 1 and 2592000000 (30 days)", stage: "api.idempotency", status: 500, remediation: "Unset CLEARANCE_IDEMPOTENCY_TTL_MS or set a valid duration in milliseconds" });
	return value;
}
const IDEMPOTENCY_KEY_RE = /^[\x21-\x7e]{1,200}$/;
export function assertIdempotencyKeyValid(key: string): void {
	if (!IDEMPOTENCY_KEY_RE.test(key)) throw new ClearanceError({ code: "IDEMPOTENCY_KEY_INVALID", message: "Operation-Key must be 1-200 visible ASCII characters", stage: "api.idempotency", status: 400, remediation: "Send a unique opaque token (e.g. a UUID) as the Operation-Key header" });
}
export function fingerprintIdempotentRequest(scopeKey: string, rawBody: string): string { return createHash("sha256").update(`${scopeKey}\n${rawBody}`).digest("hex"); }
export function idempotencyConflictError(scopeKey: string): ClearanceError { return new ClearanceError({ code: "IDEMPOTENCY_KEY_CONFLICT", message: `Operation-Key was already used for ${scopeKey} with a different request payload`, stage: "api.idempotency", status: 409, remediation: "Use a fresh Operation-Key for a different payload, or resend the original payload to replay the stored response" }); }

type PgIdempotencyCapable = {
	claimIdempotencyRecord(input: { scopeKey: string; key: string; fingerprint: string; ttlMs: number; leaseMs: number }): Promise<IdempotencyClaim>;
	renewIdempotencyRecord(input: { scopeKey: string; key: string; fingerprint: string; generation: number; ttlMs: number; leaseMs: number }): Promise<boolean>;
	completeIdempotencyRecord(input: IdempotencyRecord & { generation: number; ttlMs: number }): Promise<boolean>;
	failIdempotencyRecord(input: { scopeKey: string; key: string; fingerprint: string; generation: number }): Promise<void>;
	getIdempotencyRecord(scopeKey: string, key: string): Promise<IdempotencyRecord | null>;
	putIdempotencyRecord(record: IdempotencyRecord & { ttlMs: number }): Promise<void>;
};
function hasPgIdempotency(store: ManagementStore): store is ManagementStore & PgIdempotencyCapable { return store.backend === "postgres" && typeof (store as Partial<PgIdempotencyCapable>).claimIdempotencyRecord === "function"; }

type MemoryEntry = IdempotencyRecord & { state: "pending" | "completed" | "failed"; generation: number; expiresAt: number; leaseExpiresAt: number };
class MemoryIdempotencyBackend implements IdempotencyBackend {
	readonly kind = "memory" as const; private entries = new Map<string, MemoryEntry>();
	constructor(private ttlMs: number, private now: () => number = Date.now) {}
	private mapKey(scopeKey: string, key: string): string { return `${scopeKey}\n${key}`; }
	private sweep(): void { const now = this.now(); for (const [key, entry] of this.entries) if (entry.expiresAt <= now) this.entries.delete(key); }
	async claim(input: { scopeKey: string; key: string; fingerprint: string; leaseMs?: number }): Promise<IdempotencyClaim> {
		this.sweep(); const key = this.mapKey(input.scopeKey, input.key); const now = this.now(); const existing = this.entries.get(key);
		if (!existing) { const generation = 1; const leaseMs = input.leaseMs ?? IDEMPOTENCY_DEFAULT_LEASE_MS; this.entries.set(key, { ...input, status: 0, contentType: "", body: "", state: "pending", generation, expiresAt: now + Math.max(this.ttlMs, leaseMs), leaseExpiresAt: now + leaseMs }); return { state: "claimed", generation }; }
		if (existing.fingerprint !== input.fingerprint) return { state: "conflict" };
		if (existing.state === "completed") return { state: "completed", record: { scopeKey: existing.scopeKey, key: existing.key, fingerprint: existing.fingerprint, status: existing.status, contentType: existing.contentType, body: existing.body } };
		if (existing.state === "failed" || existing.leaseExpiresAt <= now) { existing.state = "pending"; existing.generation += 1; existing.leaseExpiresAt = now + (input.leaseMs ?? IDEMPOTENCY_DEFAULT_LEASE_MS); return { state: "claimed", generation: existing.generation }; }
		return { state: "pending", generation: existing.generation };
	}
	async complete(input: IdempotencyRecord & { generation: number }): Promise<boolean> { const entry = this.entries.get(this.mapKey(input.scopeKey, input.key)); const now = this.now(); if (!entry || entry.state !== "pending" || entry.generation !== input.generation || entry.fingerprint !== input.fingerprint || entry.leaseExpiresAt <= now) return false; Object.assign(entry, input, { state: "completed", leaseExpiresAt: 0, expiresAt: now + this.ttlMs }); return true; }
	async renew(input: { scopeKey: string; key: string; fingerprint: string; generation: number; leaseMs?: number }): Promise<boolean> { const entry = this.entries.get(this.mapKey(input.scopeKey, input.key)); const now = this.now(); if (!entry || entry.state !== "pending" || entry.generation !== input.generation || entry.fingerprint !== input.fingerprint || entry.leaseExpiresAt <= now) return false; const leaseMs = input.leaseMs ?? IDEMPOTENCY_DEFAULT_LEASE_MS; entry.leaseExpiresAt = now + leaseMs; entry.expiresAt = now + Math.max(this.ttlMs, leaseMs); return true; }
	async fail(input: { scopeKey: string; key: string; fingerprint: string; generation: number }): Promise<void> { const entry = this.entries.get(this.mapKey(input.scopeKey, input.key)); if (entry?.state === "pending" && entry.generation === input.generation && entry.fingerprint === input.fingerprint) { entry.state = "failed"; entry.leaseExpiresAt = 0; } }
	async get(scopeKey: string, key: string): Promise<IdempotencyRecord | null> { this.sweep(); const entry = this.entries.get(this.mapKey(scopeKey, key)); return entry?.state === "completed" ? { scopeKey, key, fingerprint: entry.fingerprint, status: entry.status, contentType: entry.contentType, body: entry.body } : null; }
	async put(record: IdempotencyRecord): Promise<void> { const claimed = await this.claim(record); if (claimed.state === "claimed") await this.complete({ ...record, generation: claimed.generation }); }
}
class PgIdempotencyBackend implements IdempotencyBackend {
	readonly kind = "postgres" as const; constructor(private store: ManagementStore & PgIdempotencyCapable, private ttlMs: number) {}
	claim(input: { scopeKey: string; key: string; fingerprint: string; leaseMs?: number }): Promise<IdempotencyClaim> { return this.store.claimIdempotencyRecord({ ...input, ttlMs: this.ttlMs, leaseMs: input.leaseMs ?? IDEMPOTENCY_DEFAULT_LEASE_MS }); }
	renew(input: { scopeKey: string; key: string; fingerprint: string; generation: number; leaseMs?: number }): Promise<boolean> { return this.store.renewIdempotencyRecord({ ...input, ttlMs: this.ttlMs, leaseMs: input.leaseMs ?? IDEMPOTENCY_DEFAULT_LEASE_MS }); }
	complete(input: IdempotencyRecord & { generation: number }): Promise<boolean> { return this.store.completeIdempotencyRecord({ ...input, ttlMs: this.ttlMs }); }
	fail(input: { scopeKey: string; key: string; fingerprint: string; generation: number }): Promise<void> { return this.store.failIdempotencyRecord(input); }
	get(scopeKey: string, key: string): Promise<IdempotencyRecord | null> { return this.store.getIdempotencyRecord(scopeKey, key); }
	put(record: IdempotencyRecord): Promise<void> { return this.store.putIdempotencyRecord({ ...record, ttlMs: this.ttlMs }); }
}
export function createIdempotencyBackend(store: ManagementStore, opts?: { ttlMs?: number; now?: () => number }): IdempotencyBackend { const ttlMs = opts?.ttlMs ?? resolveIdempotencyTtlMs(); return hasPgIdempotency(store) ? new PgIdempotencyBackend(store, ttlMs) : new MemoryIdempotencyBackend(ttlMs, opts?.now); }
