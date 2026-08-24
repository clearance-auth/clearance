import { createHash } from "node:crypto";
import type pg from "pg";

export const CREDENTIAL_AUTHORITY_FENCE_ID = "credential-authority";
export const CREDENTIAL_AUTHORITY_PROTOCOL_VERSION = 1;

export type CredentialAuthorityGeneration = "legacy-v1" | "digest-v1";
export type CredentialAuthorityPhase =
	| "legacy-open"
	| "draining"
	| "migrating"
	| "digest-live";

export type CredentialAuthorityRuntimeIdentity = {
	generation: CredentialAuthorityGeneration;
	deploymentId: string;
	instanceId: string;
};

export type CredentialAuthorityFenceStatus = {
	protocolVersion: number;
	phase: CredentialAuthorityPhase;
	generation: CredentialAuthorityGeneration;
	drainId: string | null;
	bridgeDeploymentId: string | null;
	expectedRuntimeCount: number | null;
	revision: number;
	drainStartedAt: Date | null;
	drainedAt: Date | null;
	publishedAt: Date | null;
	activeRuntimeLeases: number;
};

type FenceRow = Omit<CredentialAuthorityFenceStatus, "activeRuntimeLeases">;

const lockNamespace = ":clearance:credential-authority:v1";

function identityHash(value: string): string {
	return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function runtimeApplicationName(
	identity: CredentialAuthorityRuntimeIdentity,
): string {
	return [
		"clearance-ca-v1",
		identityHash(identity.deploymentId),
		identityHash(identity.instanceId),
		identity.generation,
	].join(":");
}

function requiredIdentityValue(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized) throw new Error(`${label} is required`);
	if (normalized.length > 200) throw new Error(`${label} is too long`);
	return normalized;
}

function positiveInteger(value: number, label: string): number {
	if (!Number.isSafeInteger(value) || value < 1 || value > 10_000) {
		throw new Error(`${label} must be an integer between 1 and 10000`);
	}
	return value;
}

function mapFenceRow(row: Record<string, unknown>): FenceRow {
	const phase = row.phase;
	const generation = row.generation;
	if (
		phase !== "legacy-open" &&
		phase !== "draining" &&
		phase !== "migrating" &&
		phase !== "digest-live"
	) {
		throw new Error("Credential authority fence has an invalid phase");
	}
	if (generation !== "legacy-v1" && generation !== "digest-v1") {
		throw new Error("Credential authority fence has an invalid generation");
	}
	return {
		protocolVersion: Number(row.protocolVersion),
		phase,
		generation,
		drainId: typeof row.drainId === "string" ? row.drainId : null,
		bridgeDeploymentId:
			typeof row.bridgeDeploymentId === "string"
				? row.bridgeDeploymentId
				: null,
		expectedRuntimeCount:
			row.expectedRuntimeCount === null ||
			row.expectedRuntimeCount === undefined
				? null
				: Number(row.expectedRuntimeCount),
		revision: Number(row.revision),
		drainStartedAt:
			row.drainStartedAt instanceof Date ? row.drainStartedAt : null,
		drainedAt: row.drainedAt instanceof Date ? row.drainedAt : null,
		publishedAt: row.publishedAt instanceof Date ? row.publishedAt : null,
	};
}

async function readFence(client: pg.PoolClient): Promise<FenceRow> {
	const result = await client.query(
		`SELECT "protocolVersion", phase, generation, "drainId",
		        "bridgeDeploymentId", "expectedRuntimeCount", revision,
		        "drainStartedAt", "drainedAt", "publishedAt"
		 FROM "credentialAuthorityFence" WHERE id = $1`,
		[CREDENTIAL_AUTHORITY_FENCE_ID],
	);
	if (result.rows.length !== 1) {
		throw new Error("Credential authority fence singleton is missing");
	}
	const row = mapFenceRow(result.rows[0] as Record<string, unknown>);
	if (row.protocolVersion !== CREDENTIAL_AUTHORITY_PROTOCOL_VERSION) {
		throw new Error(
			`Unsupported credential authority fence protocol ${row.protocolVersion}`,
		);
	}
	return row;
}

async function countRuntimeLeases(
	client: pg.PoolClient | pg.Pool,
): Promise<number> {
	const result = await client.query<{ count: string }>(
		`SELECT count(*)::text AS count
		 FROM pg_locks
		 WHERE locktype = 'advisory'
		   AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		   AND classid = hashtext(current_database())::oid
		   AND objid = hashtext(current_schema() || $1)::oid
		   AND objsubid = 2
		   AND mode = 'ShareLock'
		   AND granted`,
		[lockNamespace],
	);
	return Number(result.rows[0]?.count ?? 0);
}

async function listRuntimeLeaseApplications(
	client: pg.PoolClient | pg.Pool,
): Promise<string[]> {
	const result = await client.query<{ application_name: string }>(
		`SELECT activity.application_name
		 FROM pg_locks AS lock_record
		 JOIN pg_stat_activity AS activity
		   ON activity.pid = lock_record.pid
		 WHERE lock_record.locktype = 'advisory'
		   AND lock_record.database = (SELECT oid FROM pg_database WHERE datname = current_database())
		   AND lock_record.classid = hashtext(current_database())::oid
		   AND lock_record.objid = hashtext(current_schema() || $1)::oid
		   AND lock_record.objsubid = 2
		   AND lock_record.mode = 'ShareLock'
		   AND lock_record.granted
		 ORDER BY activity.application_name`,
		[lockNamespace],
	);
	return result.rows.map((row) => row.application_name);
}

async function acquireRuntimeLock(client: pg.PoolClient): Promise<void> {
	const result = await client.query<{ acquired: boolean }>(
		`SELECT pg_try_advisory_lock_shared(
			hashtext(current_database()),
			hashtext(current_schema() || $1)
		) AS acquired`,
		[lockNamespace],
	);
	if (result.rows[0]?.acquired !== true) {
		throw new Error("Credential authority migration is in progress");
	}
}

async function releaseRuntimeLock(client: pg.PoolClient): Promise<void> {
	await client
		.query(
			`SELECT pg_advisory_unlock_shared(
				hashtext(current_database()),
				hashtext(current_schema() || $1)
			)`,
			[lockNamespace],
		)
		.catch(() => undefined);
}

async function tryAcquireMigrationLock(
	client: pg.PoolClient,
): Promise<boolean> {
	const result = await client.query<{ acquired: boolean }>(
		`SELECT pg_try_advisory_lock(
			hashtext(current_database()),
			hashtext(current_schema() || $1)
		) AS acquired`,
		[lockNamespace],
	);
	return result.rows[0]?.acquired === true;
}

async function releaseMigrationLock(client: pg.PoolClient): Promise<void> {
	await client
		.query(
			`SELECT pg_advisory_unlock(
				hashtext(current_database()),
				hashtext(current_schema() || $1)
			)`,
			[lockNamespace],
		)
		.catch(() => undefined);
}

async function ownsMigrationLock(client: pg.PoolClient): Promise<boolean> {
	const result = await client.query<{ owned: boolean }>(
		`SELECT EXISTS (
			SELECT 1
			FROM pg_locks
			WHERE locktype = 'advisory'
			  AND pid = pg_backend_pid()
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
			  AND classid = hashtext(current_database())::oid
			  AND objid = hashtext(current_schema() || $1)::oid
			  AND objsubid = 2
			  AND mode = 'ExclusiveLock'
			  AND granted
		) AS owned`,
		[lockNamespace],
	);
	return result.rows[0]?.owned === true;
}

function wait(delayMs: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function validateFenceCatalog(client: pg.PoolClient): Promise<void> {
	const expectedColumns = new Map<string, { type: string; nullable: boolean }>([
		["id", { type: "text", nullable: false }],
		["protocolVersion", { type: "int4", nullable: false }],
		["phase", { type: "text", nullable: false }],
		["generation", { type: "text", nullable: false }],
		["drainId", { type: "text", nullable: true }],
		["bridgeDeploymentId", { type: "text", nullable: true }],
		["expectedRuntimeCount", { type: "int4", nullable: true }],
		["revision", { type: "int8", nullable: false }],
		["drainStartedAt", { type: "timestamptz", nullable: true }],
		["drainedAt", { type: "timestamptz", nullable: true }],
		["publishedAt", { type: "timestamptz", nullable: true }],
		["createdAt", { type: "timestamptz", nullable: false }],
		["updatedAt", { type: "timestamptz", nullable: false }],
	]);
	const columns = await client.query<{
		column_name: string;
		udt_name: string;
		is_nullable: "YES" | "NO";
	}>(
		`SELECT column_name, udt_name, is_nullable
		 FROM information_schema.columns
		 WHERE table_schema = current_schema()
		   AND table_name = 'credentialAuthorityFence'`,
	);
	if (columns.rows.length !== expectedColumns.size) {
		throw new Error("Credential authority fence schema has unexpected columns");
	}
	for (const column of columns.rows) {
		const expected = expectedColumns.get(column.column_name);
		if (
			!expected ||
			column.udt_name !== expected.type ||
			(column.is_nullable === "YES") !== expected.nullable
		) {
			throw new Error(
				`Credential authority fence column ${column.column_name} has an incompatible type or nullability`,
			);
		}
	}

	const normalize = (value: string) => value.replace(/\s+/g, " ").trim();
	const expectedChecks = new Map<string, string>([
		[
			"credentialAuthorityFence_id_v1",
			"CHECK (id = 'credential-authority'::text)",
		],
		["credentialAuthorityFence_protocol_v1", 'CHECK ("protocolVersion" = 1)'],
		[
			"credentialAuthorityFence_phase_v1",
			"CHECK (phase = ANY (ARRAY['legacy-open'::text, 'draining'::text, 'migrating'::text, 'digest-live'::text]))",
		],
		[
			"credentialAuthorityFence_generation_v1",
			"CHECK (generation = ANY (ARRAY['legacy-v1'::text, 'digest-v1'::text]))",
		],
		[
			"credentialAuthorityFence_state_v1",
			"CHECK ((phase = ANY (ARRAY['legacy-open'::text, 'draining'::text, 'migrating'::text])) AND generation = 'legacy-v1'::text OR phase = 'digest-live'::text AND generation = 'digest-v1'::text)",
		],
		[
			"credentialAuthorityFence_expected_v1",
			'CHECK ("expectedRuntimeCount" IS NULL OR "expectedRuntimeCount" > 0)',
		],
	]);
	const constraints = await client.query<{
		name: string;
		type: string;
		validated: boolean;
		definition: string;
	}>(
		`SELECT constraint_record.conname AS name,
		        constraint_record.contype AS type,
		        constraint_record.convalidated AS validated,
		        pg_get_constraintdef(constraint_record.oid, true) AS definition
		 FROM pg_constraint AS constraint_record
		 JOIN pg_class AS table_record
		   ON table_record.oid = constraint_record.conrelid
		 JOIN pg_namespace AS namespace_record
		   ON namespace_record.oid = table_record.relnamespace
		 WHERE namespace_record.nspname = current_schema()
		   AND table_record.relname = 'credentialAuthorityFence'`,
	);
	if (constraints.rows.length !== expectedChecks.size + 1) {
		throw new Error("Credential authority fence constraints are incomplete");
	}
	const primary = constraints.rows.find(
		(constraint) => constraint.type === "p",
	);
	if (!primary || normalize(primary.definition) !== "PRIMARY KEY (id)") {
		throw new Error("Credential authority fence primary key is incompatible");
	}
	for (const [name, definition] of expectedChecks) {
		const actual = constraints.rows.find(
			(constraint) => constraint.name === name,
		);
		if (
			!actual ||
			actual.type !== "c" ||
			actual.validated !== true ||
			normalize(actual.definition) !== definition
		) {
			throw new Error(
				`Credential authority fence constraint ${name} is incompatible`,
			);
		}
	}
}

export async function bootstrapCredentialAuthorityFence(
	pool: pg.Pool,
): Promise<void> {
	const client = await pool.connect();
	try {
		await client.query("BEGIN");
		await client.query(
			`SELECT pg_advisory_xact_lock(
				hashtext(current_database()),
				hashtext(current_schema() || ':clearance:credential-authority:bootstrap:v1')
			)`,
		);
		await client.query(`
			CREATE TABLE IF NOT EXISTS "credentialAuthorityFence" (
				id text PRIMARY KEY,
				"protocolVersion" integer NOT NULL,
				phase text NOT NULL,
				generation text NOT NULL,
				"drainId" text,
				"bridgeDeploymentId" text,
				"expectedRuntimeCount" integer,
				revision bigint NOT NULL DEFAULT 0,
				"drainStartedAt" timestamptz,
				"drainedAt" timestamptz,
				"publishedAt" timestamptz,
				"createdAt" timestamptz NOT NULL DEFAULT now(),
				"updatedAt" timestamptz NOT NULL DEFAULT now(),
				CONSTRAINT "credentialAuthorityFence_id_v1"
					CHECK (id = 'credential-authority'),
				CONSTRAINT "credentialAuthorityFence_protocol_v1"
					CHECK ("protocolVersion" = 1),
				CONSTRAINT "credentialAuthorityFence_phase_v1"
					CHECK (phase IN ('legacy-open', 'draining', 'migrating', 'digest-live')),
				CONSTRAINT "credentialAuthorityFence_generation_v1"
					CHECK (generation IN ('legacy-v1', 'digest-v1')),
				CONSTRAINT "credentialAuthorityFence_state_v1"
					CHECK (
						(phase IN ('legacy-open', 'draining', 'migrating') AND generation = 'legacy-v1')
						OR (phase = 'digest-live' AND generation = 'digest-v1')
					),
				CONSTRAINT "credentialAuthorityFence_expected_v1"
					CHECK ("expectedRuntimeCount" IS NULL OR "expectedRuntimeCount" > 0)
			)
		`);
		await client.query(
			`INSERT INTO "credentialAuthorityFence"
				(id, "protocolVersion", phase, generation, revision)
			 VALUES ($1, 1, 'legacy-open', 'legacy-v1', 0)
			 ON CONFLICT (id) DO NOTHING`,
			[CREDENTIAL_AUTHORITY_FENCE_ID],
		);
		await validateFenceCatalog(client);
		await readFence(client);
		await client.query("COMMIT");
	} catch (error) {
		await client.query("ROLLBACK").catch(() => undefined);
		throw error;
	} finally {
		client.release();
	}
}

export class PostgresCredentialAuthorityFence {
	private lease: pg.PoolClient | null = null;
	private migrationLease: pg.PoolClient | null = null;
	private leaseValid = false;
	private leaseErrorListener: ((error: Error) => void) | null = null;
	private bootstrapPromise: Promise<void> | null = null;
	private leaseOperations: Promise<void> = Promise.resolve();
	private closing = false;

	constructor(
		private readonly pool: pg.Pool,
		private readonly identity: CredentialAuthorityRuntimeIdentity,
	) {}

	private bootstrap(): Promise<void> {
		this.bootstrapPromise ??= bootstrapCredentialAuthorityFence(this.pool);
		return this.bootstrapPromise;
	}

	async status(): Promise<CredentialAuthorityFenceStatus> {
		await this.bootstrap();
		const client = await this.pool.connect();
		try {
			return {
				...(await readFence(client)),
				activeRuntimeLeases: await countRuntimeLeases(client),
			};
		} finally {
			client.release();
		}
	}

	async arm(input: {
		deploymentId: string;
		expectedRuntimeCount: number;
	}): Promise<CredentialAuthorityFenceStatus> {
		await this.bootstrap();
		const deploymentId = requiredIdentityValue(
			input.deploymentId,
			"deploymentId",
		);
		const expectedRuntimeCount = positiveInteger(
			input.expectedRuntimeCount,
			"expectedRuntimeCount",
		);
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const row = await client.query(
				`SELECT "protocolVersion", phase, generation, "drainId",
				        "bridgeDeploymentId", "expectedRuntimeCount", revision,
				        "drainStartedAt", "drainedAt", "publishedAt"
				 FROM "credentialAuthorityFence" WHERE id = $1 FOR UPDATE`,
				[CREDENTIAL_AUTHORITY_FENCE_ID],
			);
			const current = mapFenceRow(row.rows[0] as Record<string, unknown>);
			if (
				current.phase !== "legacy-open" ||
				current.generation !== "legacy-v1"
			) {
				throw new Error(
					`Credential authority fence cannot be armed from ${current.phase}/${current.generation}`,
				);
			}
			const leases = await countRuntimeLeases(client);
			if (leases !== expectedRuntimeCount) {
				throw new Error(
					`Expected ${expectedRuntimeCount} bridge runtime leases, found ${leases}`,
				);
			}
			const applications = await listRuntimeLeaseApplications(client);
			const deploymentHash = identityHash(deploymentId);
			const expectedPrefix = `clearance-ca-v1:${deploymentHash}:`;
			if (
				applications.length !== expectedRuntimeCount ||
				new Set(applications).size !== applications.length ||
				applications.some(
					(application) =>
						!application.startsWith(expectedPrefix) ||
						!application.endsWith(":legacy-v1"),
				)
			) {
				throw new Error(
					"Credential authority bridge leases do not belong to unique instances in the requested deployment cohort",
				);
			}
			await client.query(
				`UPDATE "credentialAuthorityFence"
				 SET "bridgeDeploymentId" = $2,
				     "expectedRuntimeCount" = $3,
				     revision = revision + 1,
				     "updatedAt" = now()
				 WHERE id = $1`,
				[CREDENTIAL_AUTHORITY_FENCE_ID, deploymentId, expectedRuntimeCount],
			);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		return this.status();
	}

	async beginDrain(input: {
		deploymentId: string;
		drainId: string;
	}): Promise<CredentialAuthorityFenceStatus> {
		await this.bootstrap();
		const deploymentId = requiredIdentityValue(
			input.deploymentId,
			"deploymentId",
		);
		const drainId = requiredIdentityValue(input.drainId, "drainId");
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			const row = await client.query(
				`SELECT "protocolVersion", phase, generation, "drainId",
				        "bridgeDeploymentId", "expectedRuntimeCount", revision,
				        "drainStartedAt", "drainedAt", "publishedAt"
				 FROM "credentialAuthorityFence" WHERE id = $1 FOR UPDATE`,
				[CREDENTIAL_AUTHORITY_FENCE_ID],
			);
			const current = mapFenceRow(row.rows[0] as Record<string, unknown>);
			if (
				current.phase === "draining" &&
				current.drainId === drainId &&
				current.bridgeDeploymentId === deploymentId
			) {
				await client.query("COMMIT");
				return this.status();
			}
			if (
				current.phase !== "legacy-open" ||
				current.generation !== "legacy-v1"
			) {
				throw new Error(
					`Credential authority drain cannot begin from ${current.phase}/${current.generation}`,
				);
			}
			if (
				current.bridgeDeploymentId !== deploymentId ||
				current.expectedRuntimeCount === null
			) {
				throw new Error("Credential authority bridge deployment is not armed");
			}
			const leases = await countRuntimeLeases(client);
			if (leases !== current.expectedRuntimeCount) {
				throw new Error(
					`Expected ${current.expectedRuntimeCount} bridge runtime leases, found ${leases}`,
				);
			}
			await client.query(
				`UPDATE "credentialAuthorityFence"
				 SET phase = 'draining',
				     "drainId" = $2,
				     "drainStartedAt" = now(),
				     revision = revision + 1,
				     "updatedAt" = now()
				 WHERE id = $1`,
				[CREDENTIAL_AUTHORITY_FENCE_ID, drainId],
			);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
		return this.status();
	}

	private async ensureRuntimeLease(): Promise<pg.PoolClient> {
		await this.bootstrap();
		if (this.lease && this.leaseValid) return this.lease;
		const client = await this.pool.connect();
		let valid = true;
		const invalidate = () => {
			valid = false;
			this.leaseValid = false;
		};
		client.on("error", invalidate);
		try {
			await client.query("SELECT set_config('application_name', $1, false)", [
				runtimeApplicationName(this.identity),
			]);
			await acquireRuntimeLock(client);
			if (!valid)
				throw new Error("Credential authority runtime lease was lost");
			this.lease = client;
			this.leaseValid = true;
			this.leaseErrorListener = invalidate;
			return client;
		} catch (error) {
			client.removeListener("error", invalidate);
			client.release();
			throw error;
		}
	}

	private async assertRuntimeServingNow(): Promise<void> {
		if (this.closing) {
			throw new Error("Credential authority runtime is closing");
		}
		requiredIdentityValue(
			this.identity.deploymentId,
			"credentialAuthority.deploymentId",
		);
		requiredIdentityValue(
			this.identity.instanceId,
			"credentialAuthority.instanceId",
		);
		const client = await this.ensureRuntimeLease();
		try {
			const state = await readFence(client);
			if (this.identity.generation === "legacy-v1") {
				if (
					state.phase !== "legacy-open" ||
					state.generation !== "legacy-v1" ||
					(state.bridgeDeploymentId !== null &&
						state.bridgeDeploymentId !== this.identity.deploymentId)
				) {
					throw new Error(
						`Legacy runtime ${this.identity.instanceId} is fenced by ${state.phase}/${state.generation}`,
					);
				}
				return;
			}
			if (state.phase !== "digest-live" || state.generation !== "digest-v1") {
				throw new Error(
					`Digest runtime ${this.identity.instanceId} cannot serve before digest publication`,
				);
			}
		} catch (error) {
			await this.releaseRuntimeLeaseNow();
			throw error;
		}
	}

	async assertRuntimeServing(): Promise<void> {
		const operation = this.leaseOperations.then(
			() => this.assertRuntimeServingNow(),
			() => this.assertRuntimeServingNow(),
		);
		this.leaseOperations = operation.then(
			() => undefined,
			() => undefined,
		);
		return operation;
	}

	async withExclusiveMigrationLease<T>(input: {
		drainId: string;
		allowUnarmedLegacyOpen: boolean;
		timeoutMs?: number;
		run: (client: pg.PoolClient) => Promise<T>;
	}): Promise<T> {
		await this.bootstrap();
		if (this.lease) {
			throw new Error(
				"This process already holds a runtime credential lease and cannot migrate",
			);
		}
		const drainId = requiredIdentityValue(input.drainId, "drainId");
		const timeoutMs = input.timeoutMs ?? 180_000;
		if (
			!Number.isSafeInteger(timeoutMs) ||
			timeoutMs < 1_000 ||
			timeoutMs > 600_000
		) {
			throw new Error(
				"migration lease timeout must be between 1000 and 600000 ms",
			);
		}
		const client = await this.pool.connect();
		let connectionHealthy = true;
		const invalidateConnection = () => {
			connectionHealthy = false;
		};
		client.on("error", invalidateConnection);
		let locked = false;
		try {
			const deadline = Date.now() + timeoutMs;
			while (!(locked = await tryAcquireMigrationLock(client))) {
				if (Date.now() >= deadline) {
					throw new Error(
						"Timed out waiting for credential-capable runtimes to drain",
					);
				}
				await wait(100);
			}
			await client.query("BEGIN");
			await validateFenceCatalog(client);
			const current = await readFence(client);
			const resumable =
				current.phase === "migrating" && current.drainId === drainId;
			const drained =
				current.phase === "draining" && current.drainId === drainId;
			const fresh =
				input.allowUnarmedLegacyOpen &&
				current.phase === "legacy-open" &&
				current.bridgeDeploymentId === null;
			if (!resumable && !drained && !fresh) {
				throw new Error(
					`Credential migration drain ${drainId} is not authorized from ${current.phase}`,
				);
			}
			if (!resumable) {
				await client.query(
					`UPDATE "credentialAuthorityFence"
					 SET phase = 'migrating',
					     "drainId" = $2,
					     "drainedAt" = now(),
					     revision = revision + 1,
					     "updatedAt" = now()
					 WHERE id = $1`,
					[CREDENTIAL_AUTHORITY_FENCE_ID, drainId],
				);
			}
			await client.query("COMMIT");
			await client.query(
				`SELECT set_config('clearance.credential_authority_drain_id', $1, false)`,
				[drainId],
			);
			this.migrationLease = client;

			const result = await input.run(client);

			if (!(await ownsMigrationLock(client))) {
				throw new Error(
					"Credential authority migration lease was lost before publication",
				);
			}
			await client.query("BEGIN");
			await validateFenceCatalog(client);
			const publishing = await readFence(client);
			if (publishing.phase !== "migrating" || publishing.drainId !== drainId) {
				throw new Error("Credential authority fence changed during migration");
			}
			await client.query(
				`UPDATE "credentialAuthorityFence"
				 SET phase = 'digest-live',
				     generation = 'digest-v1',
				     "publishedAt" = now(),
				     revision = revision + 1,
				     "updatedAt" = now()
				 WHERE id = $1`,
				[CREDENTIAL_AUTHORITY_FENCE_ID],
			);
			await client.query("COMMIT");
			return result;
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			if (this.migrationLease === client) this.migrationLease = null;
			await client
				.query("RESET clearance.credential_authority_drain_id")
				.catch(() => undefined);
			if (locked) await releaseMigrationLock(client);
			client.removeListener("error", invalidateConnection);
			client.release(connectionHealthy ? undefined : true);
		}
	}

	private async releaseRuntimeLeaseNow(): Promise<void> {
		const client = this.lease;
		const listener = this.leaseErrorListener;
		const connectionHealthy = this.leaseValid;
		this.lease = null;
		this.leaseValid = false;
		this.leaseErrorListener = null;
		if (!client) return;
		if (connectionHealthy) await releaseRuntimeLock(client);
		if (listener) client.removeListener("error", listener);
		client.release(connectionHealthy ? undefined : true);
	}

	async releaseRuntimeLease(): Promise<void> {
		await this.leaseOperations;
		await this.releaseRuntimeLeaseNow();
	}

	async close(): Promise<void> {
		this.closing = true;
		await this.releaseRuntimeLease();
	}
}
