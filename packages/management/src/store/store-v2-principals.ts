import type pg from "pg";
import type { PageCursorKey } from "../services/pagination.js";
import type { ResourceScope } from "../services/scope.js";
import type { Principal } from "../types/resources.js";
import type { StoreV2PrincipalRepository } from "./types.js";
import {
	STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY,
	STORE_V2_PRINCIPAL_REVISION_META_KEY,
	STORE_V2_PRINCIPAL_STATE_META_KEY,
	parseStoreV2MetadataInteger,
	parseStoreV2AuthoritySet,
	storeV2PrincipalEmailUniqueIndex,
	storeV2PrincipalExternalIdUniqueIndex,
	type StoreV2TableNames,
} from "./store-v2-schema.js";

type Queryable = pg.Pool | pg.PoolClient;

export interface StoreV2PrincipalRow {
	id: string;
	project_id: string;
	environment_id: string;
	email: string;
	name: string;
	status: Principal["status"];
	external_id: string | null;
	created_at: Date | string;
	updated_at: Date | string;
}

export interface StoreV2PrincipalPageInput {
	scope: ResourceScope;
	limit: number;
	cursor?: PageCursorKey;
	includeDeleted?: boolean;
	status?: Principal["status"];
}

export interface StoreV2PrincipalState {
	revision: number;
	count: number;
}

export class StoreV2PrincipalAuthorityError extends Error {
	readonly code: string;

	constructor(code: string, message: string) {
		super(message);
		this.name = "StoreV2PrincipalAuthorityError";
		this.code = code;
	}
}

export class StoreV2PrincipalConflictError extends StoreV2PrincipalAuthorityError {
	constructor() {
		super(
			"STORE_V2_PRINCIPAL_CONFLICT",
			"The principal changed after it was read; reload and retry.",
		);
		this.name = "StoreV2PrincipalConflictError";
	}
}

type PgErrorShape = { code?: unknown; constraint?: unknown };

export function translateStoreV2PrincipalError(
	error: unknown,
	tables?: StoreV2TableNames,
): Error {
	if (error instanceof StoreV2PrincipalAuthorityError) return error;
	const pgError = error as PgErrorShape;
	if (pgError.code === "23505") {
		const emailConstraint =
			Boolean(tables) &&
			typeof pgError.constraint === "string" &&
			pgError.constraint === storeV2PrincipalEmailUniqueIndex(tables!);
		const externalIdConstraint =
			Boolean(tables) &&
			typeof pgError.constraint === "string" &&
			pgError.constraint === storeV2PrincipalExternalIdUniqueIndex(tables!);
		return new StoreV2PrincipalAuthorityError(
			emailConstraint
				? "STORE_V2_PRINCIPAL_EMAIL_CONFLICT"
				: externalIdConstraint
					? "STORE_V2_PRINCIPAL_EXTERNAL_ID_CONFLICT"
				: "STORE_V2_PRINCIPAL_ID_CONFLICT",
			emailConstraint
				? "An active principal already uses that email in this scope."
				: externalIdConstraint
					? "An active principal already uses that external identifier in this scope."
				: "A principal with that identifier already exists.",
		);
	}
	if (pgError.code === "23503") {
		return new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_SCOPE_INVALID",
			"The principal project or environment scope is invalid.",
		);
	}
	if (
		pgError.code === "23514" ||
		pgError.code === "23502" ||
		pgError.code === "22007"
	) {
		return new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_DATA_INVALID",
			"The principal data is invalid.",
		);
	}
	if (typeof pgError.code === "string") {
		return new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_WRITE_FAILED",
			"The principal operation failed.",
		);
	}
	return new StoreV2PrincipalAuthorityError(
		"STORE_V2_PRINCIPAL_WRITE_FAILED",
		"The principal operation failed.",
	);
}

function iso(value: Date | string): string {
	return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

/** Return an OCC token guaranteed to advance beyond the token that was read. */
export function advancingPrincipalUpdatedAt(
	candidate: string,
	expectedUpdatedAt: string,
): string {
	const candidateTime = new Date(candidate).getTime();
	const expectedTime = new Date(expectedUpdatedAt).getTime();
	if (!Number.isFinite(candidateTime) || !Number.isFinite(expectedTime)) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_DATA_INVALID",
			"The principal update timestamp is invalid.",
		);
	}
	if (candidateTime > expectedTime) return new Date(candidateTime).toISOString();
	if (expectedTime >= 8_640_000_000_000_000) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_REVISION_EXHAUSTED",
			"The principal update timestamp cannot advance.",
		);
	}
	return new Date(expectedTime + 1).toISOString();
}

export function mapStoreV2PrincipalRow(row: StoreV2PrincipalRow): Principal {
	return {
		id: row.id,
		projectId: row.project_id,
		environmentId: row.environment_id,
		email: row.email,
		name: row.name,
		status: row.status,
		...(row.external_id === null ? {} : { externalId: row.external_id }),
		createdAt: iso(row.created_at),
		updatedAt: iso(row.updated_at),
	};
}

function parseStoreV2PrincipalState(
	value: unknown,
): StoreV2PrincipalState | null {
	if (typeof value !== "object" || value === null || Array.isArray(value)) {
		return null;
	}
	const state = value as Record<string, unknown>;
	const revision = parseStoreV2MetadataInteger(state.revision);
	const count = parseStoreV2MetadataInteger(state.count);
	return revision === null || count === null ? null : { revision, count };
}

export async function readStoreV2PrincipalState(
	queryable: Queryable,
	tables: StoreV2TableNames,
	options: { forUpdate?: boolean } = {},
): Promise<StoreV2PrincipalState | null> {
	const result = await queryable.query<{ value: unknown }>(
		`SELECT value FROM ${tables.meta} WHERE key = $1${
			options.forUpdate ? " FOR UPDATE" : ""
		}`,
		[STORE_V2_PRINCIPAL_STATE_META_KEY],
	);
	if (!result.rows[0]) return null;
	const state = parseStoreV2PrincipalState(result.rows[0].value);
	if (!state) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_STATE_INVALID",
			"Principal authority state metadata is invalid.",
		);
	}
	return state;
}

export async function writeStoreV2PrincipalState(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	state: StoreV2PrincipalState,
): Promise<void> {
	if (
		parseStoreV2MetadataInteger(state.revision) === null ||
		parseStoreV2MetadataInteger(state.count) === null
	) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_STATE_INVALID",
			"Principal authority state metadata is invalid.",
		);
	}
	await client.query(
		`INSERT INTO ${tables.meta} (key, value, updated_at)
		 VALUES ($1, $2::jsonb, now()), ($3, $4::jsonb, now())
		 ON CONFLICT (key) DO UPDATE
		 SET value = EXCLUDED.value, updated_at = now()`,
		[
			STORE_V2_PRINCIPAL_STATE_META_KEY,
			JSON.stringify(state),
			STORE_V2_PRINCIPAL_REVISION_META_KEY,
			JSON.stringify(state.revision),
		],
	);
}

export async function advanceStoreV2PrincipalState(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
	countDelta: number,
): Promise<StoreV2PrincipalState> {
	if (!Number.isSafeInteger(countDelta)) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_STATE_INVALID",
			"Principal authority count delta is invalid.",
		);
	}
	const current = await readStoreV2PrincipalState(client, tables, {
		forUpdate: true,
	});
	if (!current) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_STATE_INVALID",
			"Principal authority state metadata is missing.",
		);
	}
	const next: StoreV2PrincipalState = {
		revision: current.revision + 1,
		count: current.count + countDelta,
	};
	if (
		!Number.isSafeInteger(next.revision) ||
		!Number.isSafeInteger(next.count) ||
		next.count < 0
	) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_STATE_INVALID",
			"Principal authority state cannot advance safely.",
		);
	}
	await writeStoreV2PrincipalState(client, tables, next);
	return next;
}

export async function readStoreV2PrincipalRevision(
	queryable: Queryable,
	tables: StoreV2TableNames,
): Promise<number | null> {
	return (await readStoreV2PrincipalState(queryable, tables))?.revision ?? null;
}

export function normalizeStoreV2PrincipalCursor(
	cursor: PageCursorKey,
): PageCursorKey {
	if (
		typeof cursor.createdAt !== "string" ||
		!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(
			cursor.createdAt,
		) ||
		typeof cursor.id !== "string" ||
		!cursor.id ||
		cursor.id.length > 1_024 ||
		cursor.id.includes("\0")
	) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_CURSOR_INVALID",
			"The principal page cursor is invalid.",
		);
	}
	const timestamp = new Date(cursor.createdAt);
	if (
		!Number.isFinite(timestamp.getTime()) ||
		timestamp.toISOString() !== cursor.createdAt
	) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_CURSOR_INVALID",
			"The principal page cursor is invalid.",
		);
	}
	return { createdAt: timestamp.toISOString(), id: cursor.id };
}

export async function storeV2PrincipalsAreAuthoritative(
	queryable: Queryable,
	tables: StoreV2TableNames,
): Promise<boolean> {
	const result = await queryable.query<{ value: unknown }>(
		`SELECT value FROM ${tables.meta} WHERE key = $1`,
		[STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY],
	);
	if (!result.rows[0]) return false;
	try {
		return parseStoreV2AuthoritySet(result.rows[0].value).includes("principals");
	} catch {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_AUTHORITY_SET_INVALID",
			"Store-v2 authority metadata is invalid.",
		);
	}
}

export async function readStoreV2Principals(
	queryable: Queryable,
	tables: StoreV2TableNames,
): Promise<Principal[]> {
	const result = await queryable.query<StoreV2PrincipalRow>(
		 `SELECT id, project_id, environment_id, email, name, status, external_id,
		        created_at, updated_at
		 FROM ${tables.principals}
		 ORDER BY created_at ASC, id ASC`,
	);
	return result.rows.map(mapStoreV2PrincipalRow);
}

export async function getStoreV2PrincipalById(
	queryable: Queryable,
	tables: StoreV2TableNames,
	input: { scope: ResourceScope; id: string; includeDeleted?: boolean },
): Promise<Principal | null> {
	const result = await queryable.query<StoreV2PrincipalRow>(
		`SELECT id, project_id, environment_id, email, name, status, external_id,
		        created_at, updated_at
		 FROM ${tables.principals}
		 WHERE project_id = $1 AND environment_id = $2 AND id = $3
		   ${input.includeDeleted ? "" : "AND status <> 'deleted'"}`,
		[input.scope.projectId, input.scope.environmentId, input.id],
	);
	return result.rows[0] ? mapStoreV2PrincipalRow(result.rows[0]) : null;
}

export async function findActiveStoreV2PrincipalByEmail(
	queryable: Queryable,
	tables: StoreV2TableNames,
	input: { scope: ResourceScope; email: string },
): Promise<Principal | null> {
	const result = await queryable.query<StoreV2PrincipalRow>(
		`SELECT id, project_id, environment_id, email, name, status, external_id,
		        created_at, updated_at
		 FROM ${tables.principals}
		 WHERE project_id = $1 AND environment_id = $2
		   AND lower(email) = lower($3) AND status <> 'deleted'`,
		[input.scope.projectId, input.scope.environmentId, input.email],
	);
	return result.rows[0] ? mapStoreV2PrincipalRow(result.rows[0]) : null;
}

export async function findActiveStoreV2PrincipalByExternalId(
	queryable: Queryable,
	tables: StoreV2TableNames,
	input: { scope: ResourceScope; externalId: string },
): Promise<Principal | null> {
	const result = await queryable.query<StoreV2PrincipalRow>(
		`SELECT id, project_id, environment_id, email, name, status, external_id,
		        created_at, updated_at
		 FROM ${tables.principals}
		 WHERE project_id = $1 AND environment_id = $2
		   AND external_id = $3 AND status <> 'deleted'`,
		[input.scope.projectId, input.scope.environmentId, input.externalId],
	);
	return result.rows[0] ? mapStoreV2PrincipalRow(result.rows[0]) : null;
}

export async function listStoreV2PrincipalsPage(
	queryable: Queryable,
	tables: StoreV2TableNames,
	input: StoreV2PrincipalPageInput,
): Promise<{ principals: Principal[]; hasMore: boolean }> {
	if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 1_000) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_PAGE_LIMIT_INVALID",
			"Principal page limit must be an integer between 1 and 1000.",
		);
	}
	const params: unknown[] = [
		input.scope.projectId,
		input.scope.environmentId,
	];
	const conditions = ["project_id = $1", "environment_id = $2"];
	if (!input.includeDeleted) conditions.push("status <> 'deleted'");
	if (input.status) {
		params.push(input.status);
		conditions.push(`status = $${params.length}`);
	}
	if (input.cursor) {
		const cursor = normalizeStoreV2PrincipalCursor(input.cursor);
		params.push(cursor.createdAt, cursor.id);
		conditions.push(
			`(created_at, id) > ($${params.length - 1}::timestamptz, $${params.length})`,
		);
	}
	params.push(input.limit + 1);
	const result = await queryable.query<StoreV2PrincipalRow>(
		`SELECT id, project_id, environment_id, email, name, status, external_id,
		        created_at, updated_at
		 FROM ${tables.principals}
		 WHERE ${conditions.join(" AND ")}
		 ORDER BY created_at ASC, id ASC
		 LIMIT $${params.length}`,
		params,
	);
	return {
		principals: result.rows.slice(0, input.limit).map(mapStoreV2PrincipalRow),
		hasMore: result.rows.length > input.limit,
	};
}

async function assertPrincipalAuthority(
	client: pg.PoolClient,
	tables: StoreV2TableNames,
): Promise<void> {
	if (!(await storeV2PrincipalsAreAuthoritative(client, tables))) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPALS_NOT_AUTHORITATIVE",
			"Principal writes require relational principal authority.",
		);
	}
}

const PRINCIPAL_REPOSITORY_CONTROLLERS = new WeakMap<
	StoreV2PrincipalRepository,
	PgStoreV2PrincipalRepository
>();

export class PgStoreV2PrincipalRepository {
	readonly capability: StoreV2PrincipalRepository;
	private active = true;
	private readonly issued = new Set<Promise<unknown>>();
	private inserted = 0;
	private removed = 0;
	private mutated = false;
	private finalizedState: StoreV2PrincipalState | undefined;
	private readonly upserted = new Map<string, Principal>();

	constructor(
		private readonly client: pg.PoolClient,
		private readonly tables: StoreV2TableNames,
	) {
		const capability: StoreV2PrincipalRepository = {
			authoritative: true as const,
			getById: (input) => this.getById(input),
			findActiveByEmail: (input) => this.findActiveByEmail(input),
			findActiveByExternalId: (input) => this.findActiveByExternalId(input),
			listPage: (input) => this.listPage(input),
			insert: (principal) => this.insert(principal),
			update: (principal, input) => this.update(principal, input),
			disable: (input) => this.disable(input),
			delete: (input) => this.delete(input),
		};
		this.capability = Object.freeze(capability);
		PRINCIPAL_REPOSITORY_CONTROLLERS.set(this.capability, this);
	}

	revoke(): void {
		this.active = false;
	}

	async settleIssued(): Promise<void> {
		const settled = await Promise.allSettled([...this.issued]);
		this.issued.clear();
		const failed = settled.find(
			(result): result is PromiseRejectedResult => result.status === "rejected",
		);
		if (failed) throw failed.reason;
	}

	countDelta(): number {
		return this.inserted - this.removed;
	}

	async finalizeState(): Promise<StoreV2PrincipalState> {
		if (this.finalizedState) return this.finalizedState;
		const state = this.mutated
			? await advanceStoreV2PrincipalState(
					this.client,
					this.tables,
					this.countDelta(),
				)
			: await readStoreV2PrincipalState(this.client, this.tables);
		if (!state) {
			throw new StoreV2PrincipalAuthorityError(
				"STORE_V2_PRINCIPAL_STATE_INVALID",
				"Principal authority state metadata is missing.",
			);
		}
		this.finalizedState = state;
		return state;
	}

	delta(): { upserted: Principal[] } {
		return {
			upserted: [...this.upserted.values()].map((principal) =>
				structuredClone(principal),
			),
		};
	}

	private issue<T>(operation: () => Promise<T>): Promise<T> {
		if (!this.active) {
			return Promise.reject(
				new StoreV2PrincipalAuthorityError(
					"STORE_V2_PRINCIPAL_REPOSITORY_REVOKED",
					"The principal transaction capability is no longer active.",
				),
			);
		}
		const pending = Promise.resolve()
			.then(operation)
			.catch((error: unknown) => {
				throw translateStoreV2PrincipalError(error, this.tables);
			});
		pending.then(
			() => undefined,
			() => undefined,
		);
		this.issued.add(pending);
		return pending;
	}

	private record(principal: Principal): Principal {
		const stored = structuredClone(principal);
		this.upserted.set(stored.id, stored);
		return structuredClone(stored);
	}

	getById(input: {
		scope: ResourceScope;
		id: string;
		includeDeleted?: boolean;
	}): Promise<Principal | null> {
		const captured = structuredClone(input);
		return this.issue(() =>
			getStoreV2PrincipalById(this.client, this.tables, captured),
		);
	}

	findActiveByEmail(input: {
		scope: ResourceScope;
		email: string;
	}): Promise<Principal | null> {
		const captured = structuredClone(input);
		return this.issue(() =>
			findActiveStoreV2PrincipalByEmail(this.client, this.tables, captured),
		);
	}

	findActiveByExternalId(input: {
		scope: ResourceScope;
		externalId: string;
	}): Promise<Principal | null> {
		const captured = structuredClone(input);
		return this.issue(() =>
			findActiveStoreV2PrincipalByExternalId(this.client, this.tables, captured),
		);
	}

	listPage(input: StoreV2PrincipalPageInput): Promise<{
		principals: Principal[];
		hasMore: boolean;
	}> {
		const captured = structuredClone(input);
		return this.issue(() =>
			listStoreV2PrincipalsPage(this.client, this.tables, captured),
		);
	}

	insert(principal: Principal): Promise<Principal> {
		const captured = structuredClone(principal);
		return this.issue(async () => {
			await assertPrincipalAuthority(this.client, this.tables);
			const result = await this.client.query<StoreV2PrincipalRow>(
			`INSERT INTO ${this.tables.principals}
			 (id, project_id, environment_id, email, name, status, external_id,
			  created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			 RETURNING id, project_id, environment_id, email, name, status,
			           external_id, created_at, updated_at`,
			[
				captured.id,
				captured.projectId,
				captured.environmentId,
				captured.email,
				captured.name,
				captured.status,
				captured.externalId ?? null,
				captured.createdAt,
				captured.updatedAt,
			],
			);
			this.inserted += 1;
			this.mutated = true;
			return this.record(mapStoreV2PrincipalRow(result.rows[0]!));
		});
	}

	update(
		principal: Principal,
		input: { expectedUpdatedAt: string },
	): Promise<Principal | null> {
		const captured = structuredClone(principal);
		const expected = structuredClone(input);
		captured.updatedAt = advancingPrincipalUpdatedAt(
			captured.updatedAt,
			expected.expectedUpdatedAt,
		);
		return this.issue(async () => {
			await assertPrincipalAuthority(this.client, this.tables);
			const result = await this.client.query<StoreV2PrincipalRow>(
			`UPDATE ${this.tables.principals}
			 SET email = $4, name = $5, status = $6, external_id = $7,
			     updated_at = $8
			 WHERE id = $1 AND project_id = $2 AND environment_id = $3
			   AND updated_at = $9::timestamptz
			 RETURNING id, project_id, environment_id, email, name, status,
			           external_id, created_at, updated_at`,
			[
				captured.id,
				captured.projectId,
				captured.environmentId,
				captured.email,
				captured.name,
				captured.status,
				captured.externalId ?? null,
				captured.updatedAt,
				expected.expectedUpdatedAt,
			],
			);
			if (!result.rows[0]) {
				const existing = await getStoreV2PrincipalById(this.client, this.tables, {
				scope: {
					projectId: captured.projectId,
					environmentId: captured.environmentId,
				},
				id: captured.id,
				includeDeleted: true,
				});
				if (existing) throw new StoreV2PrincipalConflictError();
				return null;
			}
			this.mutated = true;
			return this.record(mapStoreV2PrincipalRow(result.rows[0]));
		});
	}

	disable(input: {
		scope: ResourceScope;
		id: string;
		updatedAt: string;
		expectedUpdatedAt: string;
	}): Promise<Principal | null> {
		return this.setLifecycleStatus(input, "disabled");
	}

	delete(input: {
		scope: ResourceScope;
		id: string;
		updatedAt: string;
		expectedUpdatedAt: string;
	}): Promise<Principal | null> {
		return this.setLifecycleStatus(input, "deleted");
	}

	hardDeleteImportedPrincipal(principal: Principal): Promise<boolean> {
		const captured = structuredClone(principal);
		return this.issue(async () => {
			await assertPrincipalAuthority(this.client, this.tables);
			const result = await this.client.query(
				`DELETE FROM ${this.tables.principals}
				 WHERE id = $1 AND project_id = $2 AND environment_id = $3
				   AND email = $4 AND name = $5 AND status = $6
				   AND external_id IS NOT DISTINCT FROM $7
				   AND created_at = $8::timestamptz
				   AND updated_at = $9::timestamptz`,
				[
					captured.id,
					captured.projectId,
					captured.environmentId,
					captured.email,
					captured.name,
					captured.status,
					captured.externalId ?? null,
					captured.createdAt,
					captured.updatedAt,
				],
			);
			if (result.rowCount !== 1) return false;
			this.removed += 1;
			this.mutated = true;
			this.upserted.delete(captured.id);
			return true;
		});
	}

	private setLifecycleStatus(
		input: {
			scope: ResourceScope;
			id: string;
			updatedAt: string;
			expectedUpdatedAt: string;
		},
		status: "disabled" | "deleted",
	): Promise<Principal | null> {
		const captured = structuredClone(input);
		captured.updatedAt = advancingPrincipalUpdatedAt(
			captured.updatedAt,
			captured.expectedUpdatedAt,
		);
		return this.issue(async () => {
			await assertPrincipalAuthority(this.client, this.tables);
			const result = await this.client.query<StoreV2PrincipalRow>(
			`UPDATE ${this.tables.principals}
			 SET status = $4, updated_at = $5
			 WHERE id = $1 AND project_id = $2 AND environment_id = $3
			   AND updated_at = $6::timestamptz
			   ${status === "disabled" ? "AND status <> 'deleted'" : ""}
			 RETURNING id, project_id, environment_id, email, name, status,
			           external_id, created_at, updated_at`,
			[
				captured.id,
				captured.scope.projectId,
				captured.scope.environmentId,
				status,
				captured.updatedAt,
				captured.expectedUpdatedAt,
			],
			);
			if (!result.rows[0]) {
				const existing = await getStoreV2PrincipalById(this.client, this.tables, {
				scope: captured.scope,
				id: captured.id,
				includeDeleted: true,
				});
				if (existing) throw new StoreV2PrincipalConflictError();
				return null;
			}
			this.mutated = true;
			return this.record(mapStoreV2PrincipalRow(result.rows[0]));
		});
	}
}

/**
 * Internal migration rollback seam. The public repository surface cannot issue
 * physical deletion, and this exact checkpoint is matched in the DELETE itself.
 */
export function hardDeleteImportedPrincipalForRollback(
	repository: StoreV2PrincipalRepository,
	checkpoint: Principal,
): Promise<boolean> {
	const controller = PRINCIPAL_REPOSITORY_CONTROLLERS.get(repository);
	if (!controller) {
		throw new StoreV2PrincipalAuthorityError(
			"STORE_V2_PRINCIPAL_ROLLBACK_CAPABILITY_INVALID",
			"Physical principal deletion requires the internal Postgres migration rollback capability.",
		);
	}
	return controller.hardDeleteImportedPrincipal(structuredClone(checkpoint));
}
