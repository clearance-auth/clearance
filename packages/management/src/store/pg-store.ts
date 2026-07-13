/**
 * Postgres-backed management store.
 *
 * Single-row JSONB snapshot with revision + row-lock semantics.
 * Mutations are queued and transactionally replayed against the latest locked
 * row so concurrent CLI/API processes do not lose each other's writes.
 *
 * Database-enforced uniqueness (same transaction as snapshot + audit):
 * - principal email unique per (project_id, environment_id)
 * - organization slug unique per (project_id, environment_id)
 *
 * Call refresh() on long-lived readers before serving requests.
 */
import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import pg from "pg";
import type { DataStoreSnapshot } from "../types/resources.js";
import {
	CLEARANCE_RELEASE_VERSION,
	emptySnapshot,
	normalizeSnapshot,
	STORE_SCHEMA_VERSION,
} from "./json-store.js";
import type { ManagementStore } from "./types.js";

const SNAPSHOT_TABLE = "clearance_management_snapshot";

function safeTableName(value: string): string {
	if (!/^[a-z_][a-z0-9_]*$/i.test(value)) {
		throw new Error(`Invalid Postgres snapshot table name: ${value}`);
	}
	return value;
}

function cloneSnapshot(data: DataStoreSnapshot): DataStoreSnapshot {
	return JSON.parse(JSON.stringify(data)) as DataStoreSnapshot;
}

export class PgStore implements ManagementStore {
	readonly backend = "postgres" as const;
	readonly path: string;
	private data: DataStoreSnapshot;
	private revision = 0;
	private pool: pg.Pool;
	private table: string;
	private emailUniqueTable: string;
	private slugUniqueTable: string;
	private idempotencyTable: string;
	private pending: Promise<void> = Promise.resolve();
	/** Set when a queued write fails; rethrown from ready() so the chain never rejects. */
	private writeError: unknown = null;
	private initialized = false;

	constructor(
		databaseUrl: string,
		opts?: { backupDir?: string; tableName?: string },
	) {
		this.path = resolve(opts?.backupDir ?? process.cwd(), ".clearance", "pg");
		this.pool = new pg.Pool({ connectionString: databaseUrl });
		this.table = safeTableName(opts?.tableName ?? SNAPSHOT_TABLE);
		// Companion uniqueness tables share the snapshot table prefix for test isolation
		this.emailUniqueTable = safeTableName(`${this.table}_principal_email`);
		this.slugUniqueTable = safeTableName(`${this.table}_organization_slug`);
		this.idempotencyTable = safeTableName(`${this.table}_idempotency`);
		this.data = emptySnapshot();
	}

	/** Ensure schema + load snapshot. Call before first use. */
	async init(): Promise<this> {
		if (this.initialized) return this;
		await this.pool.query(`
			CREATE TABLE IF NOT EXISTS ${this.table} (
				id integer PRIMARY KEY CHECK (id = 1),
				data jsonb NOT NULL,
				revision bigint NOT NULL DEFAULT 0,
				updated_at timestamptz NOT NULL DEFAULT now()
			)
		`);
		// Existing installs created before revision column
		await this.pool.query(`
			ALTER TABLE ${this.table}
			ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 0
		`);

		// Database-enforced uniqueness within project/environment scope
		await this.pool.query(`
			CREATE TABLE IF NOT EXISTS ${this.emailUniqueTable} (
				project_id text NOT NULL,
				environment_id text NOT NULL,
				email_lower text NOT NULL,
				principal_id text NOT NULL,
				PRIMARY KEY (project_id, environment_id, email_lower)
			)
		`);
		await this.pool.query(`
			CREATE TABLE IF NOT EXISTS ${this.slugUniqueTable} (
				project_id text NOT NULL,
				environment_id text NOT NULL,
				slug text NOT NULL,
				organization_id text NOT NULL,
				PRIMARY KEY (project_id, environment_id, slug)
			)
		`);

		// Idempotency-Key replay records (FOLLOW.md P2.3.2). Deliberately a
		// companion table, NOT part of the JSONB snapshot: storing keys in the
		// snapshot would inflate every subsequent write of any kind and make TTL
		// expiry itself a snapshot mutation.
		await this.pool.query(`
			CREATE TABLE IF NOT EXISTS ${this.idempotencyTable} (
				scope_key text NOT NULL,
				key text NOT NULL,
				fingerprint text NOT NULL,
				status integer NOT NULL,
				content_type text NOT NULL,
				body text NOT NULL,
				created_at timestamptz NOT NULL DEFAULT now(),
				expires_at timestamptz NOT NULL,
				PRIMARY KEY (scope_key, key)
			)
		`);

		const result = await this.pool.query<{
			data: DataStoreSnapshot;
			revision: string | number;
		}>(`SELECT data, revision FROM ${this.table} WHERE id = 1`);
		if (result.rows[0]?.data) {
			this.data = normalizeSnapshot(result.rows[0].data);
			this.revision = Number(result.rows[0].revision ?? 0);
		} else {
			this.data = emptySnapshot({
				storeBackend: "postgres",
			});
			await this.persistLocked(this.data, 0);
			this.revision = 1;
		}
		this.initialized = true;
		return this;
	}

	load(): DataStoreSnapshot {
		return this.data;
	}

	get snapshot(): DataStoreSnapshot {
		return this.data;
	}

	/** Monotonic revision of the last known durable snapshot (test/debug). */
	get currentRevision(): number {
		return this.revision;
	}

	save(): void {
		this.queueWrite((data) => data);
	}

	async ready(): Promise<void> {
		await this.pending;
		if (this.writeError) {
			const err = this.writeError;
			this.writeError = null;
			throw err;
		}
	}

	/**
	 * Pull latest durable snapshot if another process advanced the revision.
	 * Safe to call on every API request; no-op when revision is current.
	 */
	async refresh(): Promise<void> {
		await this.ready();
		const result = await this.pool.query<{
			data: DataStoreSnapshot;
			revision: string | number;
		}>(`SELECT data, revision FROM ${this.table} WHERE id = 1`);
		if (!result.rows[0]) return;
		const rev = Number(result.rows[0].revision ?? 0);
		if (rev !== this.revision) {
			this.data = normalizeSnapshot(result.rows[0].data);
			this.revision = rev;
		}
	}

	replace(snapshot: DataStoreSnapshot): void {
		const next = cloneSnapshot(snapshot);
		this.queueWrite(() => next);
	}

	mutate(fn: (data: DataStoreSnapshot) => void): DataStoreSnapshot {
		this.queueWrite(fn);
		// Snapshot may lag until ready(); callers that built objects outside the
		// mutator still return those objects. Await ready() before reading snapshot.
		return this.data;
	}

	mutateDurable<T>(fn: (data: DataStoreSnapshot) => T): Promise<T> {
		return new Promise<T>((resolvePromise, rejectPromise) => {
			this.pending = this.pending.then(async () => {
				try {
					resolvePromise(await this.transactMutation(fn));
				} catch (error) {
					rejectPromise(error);
				}
			});
		});
	}

	/**
	 * Single Postgres transaction: lock management snapshot, run caller SQL
	 * (runtime user/session/account tables) + snapshot mutator, enforce
	 * uniqueness indexes, commit. Full ROLLBACK on any throw — never returns
	 * success when runtime and management diverge.
	 */
	mutateCoordinated<T>(
		fn: (ctx: {
			data: DataStoreSnapshot;
			query: (
				sql: string,
				params?: unknown[],
			) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
		}) => Promise<T> | T,
	): Promise<T> {
		return new Promise<T>((resolvePromise, rejectPromise) => {
			this.pending = this.pending.then(async () => {
				try {
					resolvePromise(await this.transactCoordinated(fn));
				} catch (error) {
					rejectPromise(error);
				}
			});
		});
	}

	checksum(): string {
		return createHash("sha256").update(JSON.stringify(this.data)).digest("hex");
	}

	resourceCounts(): Record<string, number> {
		const d = this.data;
		return {
			projects: d.projects.length,
			environments: d.environments.length,
			principals: d.principals.length,
			organizations: d.organizations.length,
			memberships: d.memberships.length,
			identityConnections: d.identityConnections.length,
			directoryConnections: d.directoryConnections.length,
			roles: (d.roles ?? []).length,
			events: d.events.length,
			traces: d.traces.length,
			migrations: d.migrations.length,
			sessions: d.sessions.filter((s) => s.status === "active").length,
			apiKeys: (d.apiKeys ?? []).length,
		};
	}

	async destroy(): Promise<void> {
		await this.ready().catch(() => undefined);
		await this.pool.end();
	}

	/**
	 * Read a stored Idempotency-Key replay record. Expired rows are treated as
	 * absent (TTL is enforced on read as well as by opportunistic cleanup).
	 */
	async getIdempotencyRecord(
		scopeKey: string,
		key: string,
	): Promise<{
		fingerprint: string;
		status: number;
		contentType: string;
		body: string;
	} | null> {
		const r = await this.pool.query<{
			fingerprint: string;
			status: number;
			content_type: string;
			body: string;
		}>(
			`SELECT fingerprint, status, content_type, body
       FROM ${this.idempotencyTable}
       WHERE scope_key = $1 AND key = $2 AND expires_at > now()`,
			[scopeKey, key],
		);
		const row = r.rows[0];
		if (!row) return null;
		return {
			fingerprint: row.fingerprint,
			status: Number(row.status),
			contentType: row.content_type,
			body: row.body,
		};
	}

	/**
	 * Store an Idempotency-Key replay record with a TTL. Opportunistically
	 * deletes expired rows first (the table stays small; expiry never touches
	 * the snapshot). ON CONFLICT DO NOTHING: the first committed responder wins
	 * under a same-key race.
	 */
	async putIdempotencyRecord(record: {
		scopeKey: string;
		key: string;
		fingerprint: string;
		status: number;
		contentType: string;
		body: string;
		ttlMs: number;
	}): Promise<void> {
		await this.pool.query(
			`DELETE FROM ${this.idempotencyTable} WHERE expires_at <= now()`,
		);
		await this.pool.query(
			`INSERT INTO ${this.idempotencyTable}
         (scope_key, key, fingerprint, status, content_type, body, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7::double precision / 1000))
       ON CONFLICT (scope_key, key) DO NOTHING`,
			[
				record.scopeKey,
				record.key,
				record.fingerprint,
				record.status,
				record.contentType,
				record.body,
				record.ttlMs,
			],
		);
	}

	/**
	 * Enqueue a mutation that will be transactionally replayed against the
	 * row-locked latest snapshot (not applied only to a stale process-local copy).
	 * The chain never rejects (errors are stashed and rethrown from ready()) so
	 * concurrent writers cannot strand later ops or emit unhandledRejection.
	 */
	private queueWrite(fn: (data: DataStoreSnapshot) => DataStoreSnapshot | void): void {
		this.pending = this.pending.then(async () => {
			try {
				await this.transactReplay(fn);
			} catch (e) {
				// Preserve the first unobserved failure until ready() reports it. A later
				// successful queued write must never erase evidence of a failed mutation.
				this.writeError ??= e;
			}
		});
	}

	private async transactReplay(
		fn: (data: DataStoreSnapshot) => DataStoreSnapshot | void,
	): Promise<void> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const result = await client.query<{
				data: DataStoreSnapshot;
				revision: string | number;
			}>(
				`SELECT data, revision FROM ${this.table} WHERE id = 1 FOR UPDATE`,
			);

			let base: DataStoreSnapshot;
			let rev: number;
			if (result.rows[0]?.data) {
				base = cloneSnapshot(result.rows[0].data);
				rev = Number(result.rows[0].revision ?? 0);
			} else {
				base = emptySnapshot({ storeBackend: "postgres" });
				rev = 0;
			}

			// Apply on draft — if fn throws (e.g. USER_EXISTS), full ROLLBACK
			const applied = fn(base);
			const next = applied === undefined ? base : applied;
			const newRevision = rev + 1;

			// Enforce uniqueness indexes from the committed snapshot draft
			await this.syncUniqueness(client, next);

			await client.query(
				`INSERT INTO ${this.table} (id, data, revision, updated_at)
         VALUES (1, $1::jsonb, $2, now())
         ON CONFLICT (id) DO UPDATE
         SET data = EXCLUDED.data,
             revision = EXCLUDED.revision,
             updated_at = now()`,
				[JSON.stringify(next), newRevision],
			);
			await client.query("COMMIT");
			this.data = next;
			this.revision = newRevision;
		} catch (e) {
			try {
				await client.query("ROLLBACK");
			} catch {
				/* ignore rollback errors */
			}
			throw e;
		} finally {
			client.release();
		}
	}

	private async transactMutation<T>(
		fn: (data: DataStoreSnapshot) => T,
	): Promise<T> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const result = await client.query<{
				data: DataStoreSnapshot;
				revision: string | number;
			}>(`SELECT data, revision FROM ${this.table} WHERE id = 1 FOR UPDATE`);
			const base = result.rows[0]?.data
				? cloneSnapshot(result.rows[0].data)
				: emptySnapshot({ storeBackend: "postgres" });
			const revision = Number(result.rows[0]?.revision ?? 0) + 1;
			const value = fn(base);
			await this.syncUniqueness(client, base);
			await client.query(
				`INSERT INTO ${this.table} (id, data, revision, updated_at)
         VALUES (1, $1::jsonb, $2, now())
         ON CONFLICT (id) DO UPDATE
         SET data = EXCLUDED.data,
             revision = EXCLUDED.revision,
             updated_at = now()`,
				[JSON.stringify(base), revision],
			);
			await client.query("COMMIT");
			this.data = base;
			this.revision = revision;
			return value;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	private async transactCoordinated<T>(
		fn: (ctx: {
			data: DataStoreSnapshot;
			query: (
				sql: string,
				params?: unknown[],
			) => Promise<{ rows: Record<string, unknown>[]; rowCount: number | null }>;
		}) => Promise<T> | T,
	): Promise<T> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const result = await client.query<{
				data: DataStoreSnapshot;
				revision: string | number;
			}>(`SELECT data, revision FROM ${this.table} WHERE id = 1 FOR UPDATE`);
			const base = result.rows[0]?.data
				? cloneSnapshot(result.rows[0].data)
				: emptySnapshot({ storeBackend: "postgres" });
			const revision = Number(result.rows[0]?.revision ?? 0) + 1;

			const query = async (sql: string, params?: unknown[]) => {
				const r = await client.query(sql, params);
				return {
					rows: r.rows as Record<string, unknown>[],
					rowCount: r.rowCount,
				};
			};

			const value = await fn({ data: base, query });

			await this.syncUniqueness(client, base);
			await client.query(
				`INSERT INTO ${this.table} (id, data, revision, updated_at)
         VALUES (1, $1::jsonb, $2, now())
         ON CONFLICT (id) DO UPDATE
         SET data = EXCLUDED.data,
             revision = EXCLUDED.revision,
             updated_at = now()`,
				[JSON.stringify(base), revision],
			);
			await client.query("COMMIT");
			this.data = base;
			this.revision = revision;
			return value;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	/**
	 * Rebuild uniqueness tables from snapshot inside the open transaction.
	 * Primary keys enforce same-email / same-slug within project+environment.
	 * Concurrent writers serialize on snapshot FOR UPDATE; app checks catch
	 * duplicates first, and these constraints fail closed as a second layer.
	 */
	private async syncUniqueness(
		client: pg.PoolClient,
		snapshot: DataStoreSnapshot,
	): Promise<void> {
		await client.query(`DELETE FROM ${this.emailUniqueTable}`);
		await client.query(`DELETE FROM ${this.slugUniqueTable}`);

		for (const p of snapshot.principals) {
			if (p.status === "deleted") continue;
			await client.query(
				`INSERT INTO ${this.emailUniqueTable}
         (project_id, environment_id, email_lower, principal_id)
         VALUES ($1, $2, $3, $4)`,
				[
					p.projectId,
					p.environmentId,
					p.email.toLowerCase(),
					p.id,
				],
			);
		}

		for (const o of snapshot.organizations) {
			if (o.status === "archived") continue;
			await client.query(
				`INSERT INTO ${this.slugUniqueTable}
         (project_id, environment_id, slug, organization_id)
         VALUES ($1, $2, $3, $4)`,
				[o.projectId, o.environmentId, o.slug, o.id],
			);
		}
	}

	/** Initial insert path used only from init when the row is missing. */
	private async persistLocked(
		data: DataStoreSnapshot,
		fromRevision: number,
	): Promise<void> {
		const newRevision = fromRevision + 1;
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(
				`INSERT INTO ${this.table} (id, data, revision, updated_at)
         VALUES (1, $1::jsonb, $2, now())
         ON CONFLICT (id) DO UPDATE
         SET data = EXCLUDED.data,
             revision = EXCLUDED.revision,
             updated_at = now()`,
				[JSON.stringify(data), newRevision],
			);
			await this.syncUniqueness(client, data);
			await client.query("COMMIT");
			this.data = data;
			this.revision = newRevision;
		} catch (e) {
			try {
				await client.query("ROLLBACK");
			} catch {
				/* ignore */
			}
			throw e;
		} finally {
			client.release();
		}
	}
}

export async function createPgStore(
	databaseUrl: string,
	opts?: { backupDir?: string; tableName?: string },
): Promise<PgStore> {
	const store = new PgStore(databaseUrl, opts);
	await store.init();
	return store;
}

export function pgStoreId(): string {
	return `pg_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
}

export { CLEARANCE_RELEASE_VERSION, STORE_SCHEMA_VERSION };
