import type { ClearanceOptions } from "@clearance/core";
import type { DBFieldAttribute, DBFieldType } from "@clearance/core/db";
import { getAuthTables } from "@clearance/core/db";
import {
	initGetFieldName,
	initGetModelName,
} from "@clearance/core/db/adapter";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { createLogger } from "@clearance/core/env";
import type { KyselyDatabaseType } from "@clearance/kysely-adapter";
import {
	createKyselyAdapter,
	kyselyAdapter,
} from "@clearance/kysely-adapter";
import type {
	AlterTableColumnAlteringBuilder,
	ColumnDataType,
	CreateIndexBuilder,
	CreateTableBuilder,
	Kysely,
	RawBuilder,
	TableMetadata,
} from "kysely";
import { sql } from "kysely";
import { getSchema } from "./get-schema";
import {
	assertSecurityMigrationComplete,
	assertSessionCredentialMigrationComplete,
	migrateLegacySessionCredentials,
	OAUTH_TOKEN_MIGRATION_ID,
	recordSecurityMigrationComplete,
	SESSION_CREDENTIAL_MIGRATION_ID,
} from "./session-credential-migration";
import { readInternalCredentialAuthority } from "../internal/credential-authority";

const postgresMap = {
	string: ["character varying", "varchar", "text", "uuid"],
	number: [
		"int4",
		"int8",
		"integer",
		"bigint",
		"smallint",
		"numeric",
		"real",
		"double precision",
	],
	boolean: ["bool", "boolean"],
	date: ["timestamptz", "timestamp", "date"],
	json: ["json", "jsonb"],
};
const mysqlMap = {
	string: ["varchar", "text", "uuid"],
	number: [
		"integer",
		"int",
		"bigint",
		"smallint",
		"decimal",
		"float",
		"double",
	],
	boolean: ["boolean", "tinyint"],
	date: ["timestamp", "datetime", "date"],
	json: ["json"],
};

const sqliteMap = {
	string: ["TEXT"],
	number: ["INTEGER", "REAL", "BIGINT"],
	boolean: ["INTEGER", "BOOLEAN"], // 0 or 1
	date: ["DATE", "INTEGER"],
	json: ["TEXT"],
};

const mssqlMap = {
	string: ["varchar", "nvarchar", "uniqueidentifier"],
	number: ["int", "bigint", "smallint", "decimal", "float", "double"],
	boolean: ["bit", "smallint"],
	date: ["datetime2", "date", "datetime"],
	json: ["varchar", "nvarchar"],
};

const map = {
	postgres: postgresMap,
	mysql: mysqlMap,
	sqlite: sqliteMap,
	mssql: mssqlMap,
};

export function assertCredentialAuthorityMigrationEngineSupported(
	dbType: KyselyDatabaseType,
): void {
	if (dbType === "mssql") {
		throw new Error(
			"SQL Server credential-authority migrations are disabled until the writer seals pass canonical live-engine proof; no migration changes were applied",
		);
	}
}

export function matchType(
	columnDataType: string,
	fieldType: DBFieldType,
	dbType: KyselyDatabaseType,
) {
	function normalize(type: string) {
		return type.toLowerCase().split("(")[0]!.trim();
	}
	if (fieldType === "string[]" || fieldType === "number[]") {
		return columnDataType.toLowerCase().includes("json");
	}
	const types = map[dbType]!;
	const expected = Array.isArray(fieldType)
		? types["string"].map((t) => t.toLowerCase())
		: types[fieldType]!.map((t) => t.toLowerCase());
	return expected.includes(normalize(columnDataType));
}

/**
 * Get the current PostgreSQL schema (search_path) for the database connection
 * Returns the first schema in the search_path, defaulting to 'public' if not found
 */
async function getPostgresSchema(db: Kysely<unknown>): Promise<string> {
	try {
		const result = await sql<{
			search_path?: string;
			searchPath?: string;
		}>`SHOW search_path`.execute(db);
		const searchPath =
			result.rows[0]?.search_path ?? result.rows[0]?.searchPath;
		if (searchPath) {
			// search_path can be a comma-separated list like "$user, public" or '"$user", public'
			// Supabase may return escaped format like '"\$user", public'
			// We want the first non-variable schema
			const schemas = searchPath
				.split(",")
				.map((s) => s.trim())
				// Remove quotes and filter out variables like $user
				.map((s) => s.replace(/^["']|["']$/g, ""))
				// Filter out variable references like $user, \$user (escaped)
				.filter((s) => !s.startsWith("$") && !s.startsWith("\\$"));
			return schemas[0] || "public";
		}
	} catch {
		// If query fails, fall back to public schema
	}
	return "public";
}

async function assertPinnedPostgresCredentialMigration(
	db: Kysely<unknown>,
	drainId: string,
): Promise<void> {
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
	const columns = await sql<{
		columnName: string;
		type: string;
		nullable: "YES" | "NO";
	}>`
		SELECT column_name AS "columnName", udt_name AS type, is_nullable AS nullable
		FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name = 'credentialAuthorityFence'
	`.execute(db);
	if (columns.rows.length !== expectedColumns.size) {
		throw new Error("Credential authority fence schema has unexpected columns");
	}
	for (const column of columns.rows) {
		const expected = expectedColumns.get(column.columnName);
		if (
			!expected ||
			column.type !== expected.type ||
			(column.nullable === "YES") !== expected.nullable
		) {
			throw new Error(
				`Credential authority fence column ${column.columnName} is incompatible`,
			);
		}
	}

	const expectedChecks = new Map<string, string>([
		["credentialAuthorityFence_id_v1", "CHECK (id = 'credential-authority'::text)"],
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
	const constraints = await sql<{
		name: string;
		type: string;
		validated: boolean;
		definition: string;
	}>`
		SELECT constraint_record.conname AS name,
		       constraint_record.contype AS type,
		       constraint_record.convalidated AS validated,
		       pg_get_constraintdef(constraint_record.oid, true) AS definition
		FROM pg_constraint AS constraint_record
		JOIN pg_class AS table_record
		  ON table_record.oid = constraint_record.conrelid
		JOIN pg_namespace AS namespace_record
		  ON namespace_record.oid = table_record.relnamespace
		WHERE namespace_record.nspname = current_schema()
		  AND table_record.relname = 'credentialAuthorityFence'
	`.execute(db);
	if (constraints.rows.length !== expectedChecks.size + 1) {
		throw new Error("Credential authority fence constraints are incomplete");
	}
	const primary = constraints.rows.find((constraint) => constraint.type === "p");
	if (
		!primary ||
		primary.validated !== true ||
		primary.definition.replace(/\s+/g, " ").trim() !== "PRIMARY KEY (id)"
	) {
		throw new Error("Credential authority fence primary key is incompatible");
	}
	for (const [name, definition] of expectedChecks) {
		const constraint = constraints.rows.find((candidate) => candidate.name === name);
		if (
			!constraint ||
			constraint.type !== "c" ||
			constraint.validated !== true ||
			constraint.definition.replace(/\s+/g, " ").trim() !== definition
		) {
			throw new Error(`Credential authority fence constraint ${name} is incompatible`);
		}
	}

	const admission = await sql<{
		protocolVersion: number;
		phase: string;
		generation: string;
		fenceDrainId: string | null;
		drainedAt: Date | null;
		publishedAt: Date | null;
		ownedExclusiveLocks: number | string;
		allExclusiveLocks: number | string;
		sharedLocks: number | string;
		sessionDrainId: string | null;
	}>`
		SELECT fence."protocolVersion" AS "protocolVersion",
		       fence.phase,
		       fence.generation,
		       fence."drainId" AS "fenceDrainId",
		       fence."drainedAt" AS "drainedAt",
		       fence."publishedAt" AS "publishedAt",
		       current_setting('clearance.credential_authority_drain_id', true) AS "sessionDrainId",
		       (SELECT count(*) FROM pg_locks
		         WHERE locktype = 'advisory'
		           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		           AND classid = hashtext(current_database())::oid
		           AND objid = hashtext(current_schema() || ':clearance:credential-authority:v1')::oid
		           AND objsubid = 2 AND mode = 'ExclusiveLock' AND granted
		           AND pid = pg_backend_pid()) AS "ownedExclusiveLocks",
		       (SELECT count(*) FROM pg_locks
		         WHERE locktype = 'advisory'
		           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		           AND classid = hashtext(current_database())::oid
		           AND objid = hashtext(current_schema() || ':clearance:credential-authority:v1')::oid
		           AND objsubid = 2 AND mode = 'ExclusiveLock' AND granted) AS "allExclusiveLocks",
		       (SELECT count(*) FROM pg_locks
		         WHERE locktype = 'advisory'
		           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		           AND classid = hashtext(current_database())::oid
		           AND objid = hashtext(current_schema() || ':clearance:credential-authority:v1')::oid
		           AND objsubid = 2 AND mode = 'ShareLock' AND granted) AS "sharedLocks"
		FROM "credentialAuthorityFence" AS fence
		WHERE fence.tableoid = to_regclass(format('%I.%I', current_schema(), 'credentialAuthorityFence'))
		  AND fence.id = 'credential-authority'
	`.execute(db);
	const state = admission.rows[0];
	if (
		admission.rows.length !== 1 ||
		state?.protocolVersion !== 1 ||
		state.phase !== "migrating" ||
		state.generation !== "legacy-v1" ||
		state.fenceDrainId !== drainId ||
		state.sessionDrainId !== drainId ||
		state.drainedAt === null ||
		state.publishedAt !== null ||
		Number(state.ownedExclusiveLocks) !== 1 ||
		Number(state.allExclusiveLocks) !== 1 ||
		Number(state.sharedLocks) !== 0
	) {
		throw new Error(
			"Credential authority migration requires the exact drain-bound PostgreSQL fence session",
		);
	}
}

type InternalMigrationOptions = {
	skipPostgresLock?: boolean | undefined;
	ambientPostgresTransaction?: boolean | undefined;
	schemaOnly?: boolean | undefined;
	newCredentialAuthority?: boolean | undefined;
	postgresWriterSealsInstalled?: boolean | undefined;
	credentialMigrationDrainId?: string | undefined;
};

async function getMigrationsInternal(
	config: ClearanceOptions,
	internal?: InternalMigrationOptions,
) {
	const credentialMigrationDrainId =
		internal?.credentialMigrationDrainId ??
		readInternalCredentialAuthority(config)?.migrationDrainId;
	const clearanceSchema = getSchema(config);
	const logger = createLogger(config.logger);

	let { kysely: db, databaseType: dbType } = await createKyselyAdapter(config);

	if (!dbType) {
		logger.warn(
			"Could not determine database type, defaulting to sqlite. Please provide a type in the database options to avoid this.",
		);
		dbType = "sqlite";
	}

	if (!db) {
		logger.error(
			"Only kysely adapter is supported for migrations. You can use `generate` command to generate the schema, if you're using a different adapter.",
		);
		process.exit(1);
	}
	const configuredDatabase =
		config.database && "db" in config.database
			? config.database.db
			: config.database;
	const isD1Database = Boolean(
		configuredDatabase &&
			typeof configuredDatabase === "object" &&
		"batch" in configuredDatabase &&
		"exec" in configuredDatabase &&
		"prepare" in configuredDatabase,
	);

	// For PostgreSQL, detect and log the current schema being used
	let currentSchema = "public";
	if (dbType === "postgres") {
		currentSchema = await getPostgresSchema(db);
		logger.debug(
			`PostgreSQL migration: Using schema '${currentSchema}' (from search_path)`,
		);

		// Verify the schema exists
		try {
			const schemaCheck = await sql<{
				schema_name?: string;
				schemaName?: string;
			}>`
				SELECT schema_name
				FROM information_schema.schemata
				WHERE schema_name = ${currentSchema}
			`.execute(db);

			const schemaExists =
				schemaCheck.rows[0]?.schema_name ?? schemaCheck.rows[0]?.schemaName;
			if (!schemaExists) {
				logger.warn(
					`Schema '${currentSchema}' does not exist. Tables will be inspected from available schemas. Consider creating the schema first or checking your database configuration.`,
				);
			}
		} catch (error) {
			logger.debug(
				`Could not verify schema existence: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}

	let allTableMetadata: TableMetadata[] | undefined;
	for (let attempt = 1; attempt <= 5; attempt++) {
		try {
			allTableMetadata = await db.introspection.getTables();
			break;
		} catch (error) {
			const postgresCode =
				typeof error === "object" && error !== null && "code" in error
					? (error as { code?: unknown }).code
					: undefined;
			if (dbType !== "postgres" || postgresCode !== "42P01" || attempt === 5) {
				throw error;
			}
			logger.debug(
				`PostgreSQL schema changed during introspection; retrying (${attempt}/5)`,
			);
		}
	}
	if (!allTableMetadata) {
		throw new Error("Database introspection returned no table metadata");
	}

	// For PostgreSQL, filter tables to only those in the target schema
	let tableMetadata = allTableMetadata;
	if (dbType === "postgres") {
		// Get tables with their schema information
		try {
			const tablesInSchema = await sql<{
				table_name?: string;
				tableName?: string;
			}>`
				SELECT table_name
				FROM information_schema.tables
				WHERE table_schema = ${currentSchema}
				AND table_type = 'BASE TABLE'
			`.execute(db);

			const tableNamesInSchema = new Set(
				tablesInSchema.rows.map((row) => row.table_name ?? row.tableName),
			);

			// Filter to only tables that exist in the target schema
			tableMetadata = allTableMetadata.filter(
				(table) =>
					table.schema === currentSchema && tableNamesInSchema.has(table.name),
			);

			logger.debug(
				`Found ${tableMetadata.length} table(s) in schema '${currentSchema}': ${tableMetadata.map((t) => t.name).join(", ") || "(none)"}`,
			);
		} catch (error) {
			logger.warn(
				`Could not filter tables by schema. Using all discovered tables. Error: ${error instanceof Error ? error.message : String(error)}`,
			);
			// Fall back to using all tables if schema filtering fails
		}
	}
	const toBeCreated: {
		table: string;
		fields: Record<string, DBFieldAttribute>;
		order: number;
	}[] = [];
	const toBeAdded: {
		table: string;
		fields: Record<string, DBFieldAttribute>;
		order: number;
	}[] = [];

	for (const [key, value] of Object.entries(clearanceSchema)) {
		if (value.disableMigrations) {
			continue;
		}
		const table = tableMetadata.find((t) => t.name === key);
		if (!table) {
			const tIndex = toBeCreated.findIndex((t) => t.table === key);
			const tableData = {
				table: key,
				fields: value.fields,
				order: value.order || Infinity,
			};

			const insertIndex = toBeCreated.findIndex(
				(t) => (t.order || Infinity) > tableData.order,
			);

			if (insertIndex === -1) {
				if (tIndex === -1) {
					toBeCreated.push(tableData);
				} else {
					toBeCreated[tIndex]!.fields = {
						...toBeCreated[tIndex]!.fields,
						...value.fields,
					};
				}
			} else {
				toBeCreated.splice(insertIndex, 0, tableData);
			}
			continue;
		}
		const toBeAddedFields: Record<string, DBFieldAttribute> = {};
		for (const [fieldName, field] of Object.entries(value.fields)) {
			const column = table.columns.find((c) => c.name === fieldName);
			if (!column) {
				toBeAddedFields[fieldName] = field;
				continue;
			}

			if (matchType(column.dataType, field.type, dbType)) {
				continue;
			} else {
				logger.warn(
					`Field ${fieldName} in table ${key} has a different type in the database. Expected ${field.type} but got ${column.dataType}.`,
				);
			}
		}
		if (Object.keys(toBeAddedFields).length > 0) {
			toBeAdded.push({
				table: key,
				fields: toBeAddedFields,
				order: value.order || Infinity,
			});
		}
	}

	const migrations: (
		| AlterTableColumnAlteringBuilder
		| CreateTableBuilder<string, string>
		| CreateIndexBuilder
	)[] = [];

	const useUUIDs = config.advanced?.database?.generateId === "uuid";
	const useNumberId = config.advanced?.database?.generateId === "serial";

	function getType(field: DBFieldAttribute, fieldName: string) {
		const type = field.type;
		const provider = dbType || "sqlite";
		type StringOnlyUnion<T> = T extends string ? T : never;
		const typeMap: Record<
			StringOnlyUnion<DBFieldType> | "id" | "foreignKeyId",
			Record<KyselyDatabaseType, ColumnDataType | RawBuilder<unknown>>
		> = {
			string: {
				sqlite: "text",
				postgres: "text",
				mysql: field.unique
					? "varchar(255)"
					: field.references
						? "varchar(36)"
						: field.sortable
							? "varchar(255)"
							: field.index
								? "varchar(255)"
								: "text",
				mssql:
					field.unique || field.sortable
						? "varchar(255)"
						: field.references
							? "varchar(36)"
							: // mssql deprecated `text`, and the alternative is `varchar(max)`.
								// Kysely type interface doesn't support `text`, so we set this to `varchar(8000)` as
								// that's the max length for `varchar`
								"varchar(8000)",
			},
			boolean: {
				sqlite: "integer",
				postgres: "boolean",
				mysql: "boolean",
				mssql: "smallint",
			},
			number: {
				sqlite: field.bigint ? "bigint" : "integer",
				postgres: field.bigint ? "bigint" : "integer",
				mysql: field.bigint ? "bigint" : "integer",
				mssql: field.bigint ? "bigint" : "integer",
			},
			date: {
				sqlite: "date",
				postgres: "timestamptz",
				mysql: "timestamp(3)",
				mssql: sql`datetime2(3)`,
			},
			json: {
				sqlite: "text",
				postgres: "jsonb",
				mysql: "json",
				mssql: "varchar(8000)",
			},
			id: {
				postgres: useNumberId
					? sql`integer GENERATED BY DEFAULT AS IDENTITY`
					: useUUIDs
						? "uuid"
						: "text",
				mysql: useNumberId
					? "integer"
					: useUUIDs
						? "varchar(36)"
						: "varchar(36)",
				mssql: useNumberId
					? "integer"
					: useUUIDs
						? "varchar(36)"
						: "varchar(36)",
				sqlite: useNumberId ? "integer" : "text",
			},
			foreignKeyId: {
				postgres: useNumberId ? "integer" : useUUIDs ? "uuid" : "text",
				mysql: useNumberId
					? "integer"
					: useUUIDs
						? "varchar(36)"
						: "varchar(36)",
				mssql: useNumberId
					? "integer"
					: useUUIDs
						? "varchar(36)" /* Should be using `UNIQUEIDENTIFIER` but Kysely doesn't support it */
						: "varchar(36)",
				sqlite: useNumberId ? "integer" : "text",
			},
			"string[]": {
				sqlite: "text",
				postgres: "jsonb",
				mysql: "json",
				mssql: "varchar(8000)",
			},
			"number[]": {
				sqlite: "text",
				postgres: "jsonb",
				mysql: "json",
				mssql: "varchar(8000)",
			},
		} as const;
		if (fieldName === "id" || field.references?.field === "id") {
			if (fieldName === "id") {
				return typeMap.id[provider];
			}
			return typeMap.foreignKeyId[provider];
		}
		if (Array.isArray(type)) {
			return "text";
		}
		if (!(type in typeMap)) {
			throw new Error(
				`Unsupported field type '${String(type)}' for field '${fieldName}'. Allowed types are: string, number, boolean, date, string[], number[]. If you need to store structured data, store it as a JSON string (type: "string") or split it into primitive fields. See https://github.com/clearance-auth/clearance`,
			);
		}
		return typeMap[type][provider];
	}
	const getModelName = initGetModelName({
		schema: getAuthTables(config),
		usePlural: false,
	});
	const getFieldName = initGetFieldName({
		schema: getAuthTables(config),
		usePlural: false,
	});

	// Helper function to safely resolve model and field names, falling back to
	// user-supplied strings for external tables not in the Clearance schema
	function getReferencePath(model: string, field: string): string {
		try {
			const modelName = getModelName(model);
			const fieldName = getFieldName({ model, field });
			return `${modelName}.${fieldName}`;
		} catch {
			// If resolution fails (external table), fall back to user-supplied references
			return `${model}.${field}`;
		}
	}

	// Indexes are collected separately and appended last to ensure all
	// referenced columns/tables exist before any CREATE INDEX executes.
	const deferredIndexes: CreateIndexBuilder[] = [];

	if (toBeAdded.length) {
		for (const table of toBeAdded) {
			for (const [fieldName, field] of Object.entries(table.fields)) {
				const type = getType(field, fieldName);
				const builder = db.schema.alterTable(table.table);

				if (field.index) {
					const indexName = `${table.table}_${fieldName}_${field.unique ? "uidx" : "idx"}`;
					const indexBuilder = db.schema
						.createIndex(indexName)
						.on(table.table)
						.columns([fieldName]);
					deferredIndexes.push(
						field.unique ? indexBuilder.unique() : indexBuilder,
					);
				}

				const built = builder.addColumn(fieldName, type, (col) => {
					col = field.required !== false ? col.notNull() : col;
					if (field.references) {
						col = col
							.references(
								getReferencePath(
									field.references.model,
									field.references.field,
								),
							)
							.onDelete(field.references.onDelete || "cascade");
					}
					if (field.unique) {
						col = col.unique();
					}
					if (
						field.type === "date" &&
						typeof field.defaultValue === "function" &&
						(dbType === "postgres" || dbType === "mysql" || dbType === "mssql")
					) {
						if (dbType === "mysql") {
							col = col.defaultTo(sql`CURRENT_TIMESTAMP(3)`);
						} else {
							col = col.defaultTo(sql`CURRENT_TIMESTAMP`);
						}
					}
					return col;
				});
				migrations.push(built);
			}
		}
	}

	if (toBeCreated.length) {
		for (const table of toBeCreated) {
			const idType = getType({ type: useNumberId ? "number" : "string" }, "id");
			let dbT = db.schema
				.createTable(table.table)
				.addColumn("id", idType, (col) => {
					if (useNumberId) {
						if (dbType === "postgres") {
							// Identity column is already specified in the type via sql template tag
							return col.primaryKey().notNull();
						} else if (dbType === "sqlite") {
							return col.primaryKey().notNull();
						} else if (dbType === "mssql") {
							return col.identity().primaryKey().notNull();
						}
						return col.autoIncrement().primaryKey().notNull();
					}
					if (useUUIDs) {
						if (dbType === "postgres") {
							return col
								.primaryKey()
								.defaultTo(sql`pg_catalog.gen_random_uuid()`)
								.notNull();
						}
						return col.primaryKey().notNull();
					}
					return col.primaryKey().notNull();
				});

			for (const [fieldName, field] of Object.entries(table.fields)) {
				const type = getType(field, fieldName);
				dbT = dbT.addColumn(fieldName, type, (col) => {
					col = field.required !== false ? col.notNull() : col;
					if (field.references) {
						col = col
							.references(
								getReferencePath(
									field.references.model,
									field.references.field,
								),
							)
							.onDelete(field.references.onDelete || "cascade");
					}

					if (field.unique) {
						col = col.unique();
					}
					if (
						field.type === "date" &&
						typeof field.defaultValue === "function" &&
						(dbType === "postgres" || dbType === "mysql" || dbType === "mssql")
					) {
						if (dbType === "mysql") {
							col = col.defaultTo(sql`CURRENT_TIMESTAMP(3)`);
						} else {
							col = col.defaultTo(sql`CURRENT_TIMESTAMP`);
						}
					}
					return col;
				});

				if (field.index) {
					const builder = db.schema
						.createIndex(
							`${table.table}_${fieldName}_${field.unique ? "uidx" : "idx"}`,
						)
						.on(table.table)
						.columns([fieldName]);
					deferredIndexes.push(field.unique ? builder.unique() : builder);
				}
			}
			migrations.push(dbT);
		}
	}

	for (const index of deferredIndexes) {
		migrations.push(index);
	}

	const quotePostgresIdentifier = (identifier: string) =>
		`"${identifier.replaceAll('"', '""')}"`;

	async function sealPostgresCredentialColumns(
		mode: "install" | "validate",
	): Promise<void> {
		if (dbType !== "postgres") return;
		const tables = getAuthTables(config);
		const seals: {
			table: string;
			column: string;
			constraint: string;
			prefix: string;
		}[] = [];
		const session = tables.session;
		if (session) {
			seals.push({
				table: session.modelName,
				column: session.fields.token?.fieldName ?? "token",
				constraint: "clearance_session_credential_authority_v1",
				prefix: "clr_sid_",
			});
		}
		const oauth = tables.oauthAccessToken;
		if (oauth) {
			seals.push(
				{
					table: oauth.modelName,
					column: oauth.fields.accessToken?.fieldName ?? "accessToken",
					constraint: "clearance_oauth_access_authority_v1",
					prefix: "clr_oauth_ref_",
				},
				{
					table: oauth.modelName,
					column: oauth.fields.refreshToken?.fieldName ?? "refreshToken",
					constraint: "clearance_oauth_refresh_authority_v1",
					prefix: "clr_oauth_ref_",
				},
			);
		}
		if (seals.length === 0) return;

		const seal = async (trx: Kysely<any>) => {
			await sql`SELECT pg_advisory_xact_lock(hashtext('clearance:credential-authority:v1'))`.execute(
				trx,
			);
			for (const seal of seals) {
				const table = `${quotePostgresIdentifier(currentSchema)}.${quotePostgresIdentifier(seal.table)}`;
				const column = quotePostgresIdentifier(seal.column);
				const constraint = quotePostgresIdentifier(seal.constraint);
				if (mode === "install") {
					// Install before backfill. NOT VALID still enforces every new write,
					// so a legacy runtime cannot create fresh replayable authority while
					// existing legacy rows remain eligible for migration.
					await sql
						.raw(`ALTER TABLE ${table} DROP CONSTRAINT IF EXISTS ${constraint}`)
						.execute(trx);
					await sql
						.raw(
							`ALTER TABLE ${table} ADD CONSTRAINT ${constraint} CHECK (${column} IS NULL OR left(${column}, ${seal.prefix.length}) = '${seal.prefix}') NOT VALID`,
						)
						.execute(trx);
				} else {
					// Never drop the installed writer fence during final verification.
					await sql
						.raw(`ALTER TABLE ${table} VALIDATE CONSTRAINT ${constraint}`)
						.execute(trx);
				}
				const verified = await sql<{
					kind: string;
					validated: boolean;
					definition: string;
				}>`
					SELECT constraint_record.contype AS kind,
					       constraint_record.convalidated AS validated,
					       pg_get_constraintdef(constraint_record.oid) AS definition
					FROM pg_constraint constraint_record
					JOIN pg_class table_record
					  ON table_record.oid = constraint_record.conrelid
					JOIN pg_namespace namespace_record
					  ON namespace_record.oid = table_record.relnamespace
					WHERE namespace_record.nspname = ${currentSchema}
					  AND table_record.relname = ${seal.table}
					  AND constraint_record.conname = ${seal.constraint}
				`.execute(trx);
				const definition = verified.rows[0]?.definition
					?.toLowerCase()
					.replaceAll('"', "")
					.replace(/\s+/g, "")
					.replaceAll("(", "")
					.replaceAll(")", "");
				const columnName = seal.column.toLowerCase();
				if (
					verified.rows.length !== 1 ||
					verified.rows[0]?.kind !== "c" ||
					(mode === "validate" && verified.rows[0]?.validated !== true) ||
					!definition?.includes(`${columnName}isnull`) ||
					!definition.includes(`left${columnName},${seal.prefix.length}`) ||
					!definition.includes(seal.prefix.toLowerCase())
				) {
					throw new Error(
						`Credential writer seal verification failed for ${seal.table}.${seal.column}`,
					);
				}
			}
		};
		if (internal?.ambientPostgresTransaction) {
			await seal(db!);
			return;
		}
		await db!.transaction().execute(seal);
	}

	async function sealNonPostgresCredentialColumns(): Promise<void> {
		if (dbType === "postgres") return;
		const tables = getAuthTables(config);
		const seals: Array<{
			table: string;
			column: string;
			constraint: string;
			prefix: string;
		}> = [];
		if (tables.session) {
			seals.push({
				table: tables.session.modelName,
				column: tables.session.fields.token?.fieldName ?? "token",
				constraint: "clearance_session_credential_authority_v1",
				prefix: "clr_sid_",
			});
		}
		if (tables.oauthAccessToken) {
			seals.push(
				{
					table: tables.oauthAccessToken.modelName,
					column:
						tables.oauthAccessToken.fields.accessToken?.fieldName ??
						"accessToken",
					constraint: "clearance_oauth_access_authority_v1",
					prefix: "clr_oauth_ref_",
				},
				{
					table: tables.oauthAccessToken.modelName,
					column:
						tables.oauthAccessToken.fields.refreshToken?.fieldName ??
						"refreshToken",
					constraint: "clearance_oauth_refresh_authority_v1",
					prefix: "clr_oauth_ref_",
				},
			);
		}
		let isMariaDb = false;
		if (dbType === "mysql" && seals.length > 0) {
			const versionResult = await sql<{ version?: string }>`
				SELECT VERSION() AS version
			`.execute(db!);
			const version = versionResult.rows[0]?.version ?? "";
			const parsed = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
			isMariaDb = /mariadb/i.test(version);
			const minimum = isMariaDb ? [10, 2, 1] : [8, 0, 16];
			const actual = parsed
				? [Number(parsed[1]), Number(parsed[2]), Number(parsed[3])]
				: [];
			let supportsEnforcedChecks = actual.length === minimum.length;
			for (let index = 0; supportsEnforcedChecks && index < minimum.length; index++) {
				if (actual[index] === minimum[index]) continue;
				supportsEnforcedChecks = actual[index]! > minimum[index]!;
				break;
			}
			if (!supportsEnforcedChecks) {
				throw new Error(
					`Credential writer seals require enforced CHECK constraints; MySQL 8.0.16+ or MariaDB 10.2.1+ is required (detected ${version || "unknown"})`,
				);
			}
		}
		for (const seal of seals) {
			if (dbType === "sqlite") {
				const table = `"${seal.table.replaceAll('"', '""')}"`;
				const column = `"${seal.column.replaceAll('"', '""')}"`;
				for (const operation of ["insert", "update"] as const) {
					const triggerName = `${seal.constraint}_${operation}`;
					const trigger = `"${triggerName.replaceAll('"', '""')}"`;
					const existing = await sql<{
						table_name?: string;
						tableName?: string;
					}>`
						SELECT tbl_name AS table_name
						FROM sqlite_master
						WHERE type = 'trigger' AND name = ${triggerName}
					`.execute(db!);
					const existingTable =
						existing.rows[0]?.table_name ?? existing.rows[0]?.tableName;
					if (existingTable && existingTable !== seal.table) {
						throw new Error(
							`Credential writer seal ${triggerName} belongs to unexpected table ${existingTable}`,
						);
					}
					await sql.raw(`DROP TRIGGER IF EXISTS ${trigger}`).execute(db!);
					const definition =
						`CREATE TRIGGER ${trigger} BEFORE ${operation.toUpperCase()} ON ${table} ` +
						`FOR EACH ROW WHEN NEW.${column} IS NOT NULL AND substr(NEW.${column}, 1, ${seal.prefix.length}) <> '${seal.prefix}' ` +
						"BEGIN SELECT RAISE(ABORT, 'Clearance credential authority rejects replayable bearer storage'); END";
					await sql
						.raw(definition)
						.execute(db!);
					const verified = await sql<{
						definition?: string;
						table_name?: string;
						tableName?: string;
					}>`
						SELECT sql AS definition, tbl_name AS table_name
						FROM sqlite_master
						WHERE type = 'trigger' AND name = ${triggerName}
					`.execute(db!);
					const installed = verified.rows[0];
					const normalize = (value: string) =>
						value.replace(/\s+/g, " ").trim().replace(/;$/, "").toLowerCase();
					if (
						verified.rows.length !== 1 ||
						(installed?.table_name ?? installed?.tableName) !== seal.table ||
						typeof installed?.definition !== "string" ||
						normalize(installed.definition) !== normalize(definition)
					) {
						throw new Error(
							`Credential writer seal verification failed for ${seal.table}.${seal.column}`,
						);
					}
				}
				const invalid = await sql
					.raw<{ present: number }>(
						`SELECT 1 AS present FROM ${table} WHERE ${column} IS NOT NULL AND substr(${column}, 1, ${seal.prefix.length}) <> '${seal.prefix}' LIMIT 1`,
					)
					.execute(db!);
				if (invalid.rows[0]) {
					throw new Error(
						`Credential writer seal found replayable material in ${seal.table}.${seal.column}`,
					);
				}
				continue;
			}
			if (dbType === "mysql") {
				const quote = (value: string) =>
					`\`${value.replaceAll("`", "``")}\``;
				const expression =
					`${quote(seal.column)} IS NULL OR ` +
					`BINARY LEFT(${quote(seal.column)}, ${seal.prefix.length}) = BINARY '${seal.prefix}'`;
				const existing = await sql<{ kind: string }>`
					SELECT constraint_type AS kind FROM information_schema.table_constraints
					WHERE constraint_schema = database()
					  AND table_name = ${seal.table}
					  AND constraint_name = ${seal.constraint}
				`.execute(db!);
				if (
					existing.rows[0] &&
					existing.rows[0].kind.toUpperCase() !== "CHECK"
				) {
					throw new Error(
						`Credential writer seal ${seal.constraint} has unexpected type ${existing.rows[0].kind}`,
					);
				}
				if (existing.rows[0]) {
					await sql
						.raw(
							`ALTER TABLE ${quote(seal.table)} DROP ${isMariaDb ? "CONSTRAINT" : "CHECK"} ${quote(seal.constraint)}`,
						)
						.execute(db!);
				}
				await sql
					.raw(
						`ALTER TABLE ${quote(seal.table)} ADD CONSTRAINT ${quote(seal.constraint)} CHECK (${expression})`,
					)
					.execute(db!);
				const verified = await sql<{ kind: string; definition: string }>`
					SELECT table_constraint.constraint_type AS kind,
					       check_constraint.check_clause AS definition
					FROM information_schema.table_constraints AS table_constraint
					JOIN information_schema.check_constraints AS check_constraint
					  ON check_constraint.constraint_schema = table_constraint.constraint_schema
					 AND check_constraint.constraint_name = table_constraint.constraint_name
					WHERE table_constraint.constraint_schema = database()
					  AND table_constraint.table_name = ${seal.table}
					  AND table_constraint.constraint_name = ${seal.constraint}
				`.execute(db!);
				const normalizedDefinition = verified.rows[0]?.definition
					?.replaceAll("`", "")
					.replace(/\s+/g, " ")
					.toLowerCase();
				const compactDefinition = normalizedDefinition?.replace(/\s+/g, "");
				if (
					verified.rows.length !== 1 ||
					verified.rows[0]?.kind.toUpperCase() !== "CHECK" ||
					!compactDefinition?.includes(`${seal.column.toLowerCase()}isnull`) ||
					!compactDefinition.includes(
						`left(${seal.column.toLowerCase()},${seal.prefix.length})`,
					) ||
					!compactDefinition.includes("charsetbinary") ||
					!compactDefinition.includes(seal.prefix.toLowerCase())
				) {
					throw new Error(
						`Credential writer seal verification failed for ${seal.table}.${seal.column}: ${normalizedDefinition ?? "missing definition"}`,
					);
				}
				const table = quote(seal.table);
				const column = quote(seal.column);
				const invalid = await sql
					.raw<{ present: number }>(
						`SELECT 1 AS present FROM ${table} WHERE ${column} IS NOT NULL AND BINARY LEFT(${column}, ${seal.prefix.length}) <> BINARY '${seal.prefix}' LIMIT 1`,
					)
					.execute(db!);
				if (invalid.rows[0]) {
					throw new Error(
						`Credential writer seal found replayable material in ${seal.table}.${seal.column}`,
					);
				}
				continue;
			}
			if (dbType === "mssql") {
				const mssqlExpression = () =>
					`${quote(seal.column)} IS NULL OR ` +
					`LEFT(${quote(seal.column)}, ${seal.prefix.length}) COLLATE Latin1_General_100_BIN2 = ` +
					`'${seal.prefix}' COLLATE Latin1_General_100_BIN2`;
				const quote = (value: string) => `[${value.replace(/]/g, "]]")}]`;
				const existing = await sql<{ kind: string }>`
					SELECT constraint_record.type AS kind
					FROM sys.objects AS constraint_record
					JOIN sys.tables AS table_record
					  ON table_record.object_id = constraint_record.parent_object_id
					JOIN sys.schemas AS schema_record
					  ON schema_record.schema_id = table_record.schema_id
					WHERE schema_record.name = schema_name()
					  AND table_record.name = ${seal.table}
					  AND constraint_record.name = ${seal.constraint}
				`.execute(db!);
				if (existing.rows[0] && existing.rows[0].kind !== "C") {
					throw new Error(
						`Credential writer seal ${seal.constraint} has unexpected type ${existing.rows[0].kind}`,
					);
				}
				if (existing.rows[0]) {
					await sql
						.raw(
							`ALTER TABLE ${quote(seal.table)} DROP CONSTRAINT ${quote(seal.constraint)}`,
						)
						.execute(db!);
				}
				await sql
					.raw(
						`ALTER TABLE ${quote(seal.table)} WITH CHECK ADD CONSTRAINT ${quote(seal.constraint)} CHECK (${mssqlExpression()})`,
					)
					.execute(db!);
				await sql
					.raw(
						`ALTER TABLE ${quote(seal.table)} WITH CHECK CHECK CONSTRAINT ${quote(seal.constraint)}`,
					)
					.execute(db!);
				const verified = await sql<{
					definition: string;
					disabled: boolean | number;
					untrusted: boolean | number;
				}>`
					SELECT constraint_record.definition,
					       constraint_record.is_disabled AS disabled,
					       constraint_record.is_not_trusted AS untrusted
					FROM sys.check_constraints AS constraint_record
					JOIN sys.tables AS table_record
					  ON table_record.object_id = constraint_record.parent_object_id
					JOIN sys.schemas AS schema_record
					  ON schema_record.schema_id = table_record.schema_id
					WHERE schema_record.name = schema_name()
					  AND table_record.name = ${seal.table}
					  AND constraint_record.name = ${seal.constraint}
				`.execute(db!);
				const normalizedDefinition = verified.rows[0]?.definition
					?.replace(/[\[\]]/g, "")
					.replace(/\s+/g, " ")
					.toLowerCase();
				const canonicalBinaryComparison =
					`left(${seal.column}, ${seal.prefix.length}) collate latin1_general_100_bin2 = '${seal.prefix}' collate latin1_general_100_bin2`.toLowerCase();
				if (
					verified.rows.length !== 1 ||
					!normalizedDefinition?.includes(canonicalBinaryComparison) ||
					Boolean(verified.rows[0]?.disabled) ||
					Boolean(verified.rows[0]?.untrusted)
				) {
					throw new Error(
						`Credential writer seal verification failed for ${seal.table}.${seal.column}`,
					);
				}
			}
		}
	}

	async function runMigrations() {
		assertCredentialAuthorityMigrationEngineSupported(dbType!);
		if (isD1Database) {
			throw new Error(
				"Cloudflare D1 credential-authority migrations and writer-seal verification require an atomic batch implementation and are refused before applying schema changes",
			);
		}
		await assertLegacyCredentialAuthorityDrained();
		if (dbType === "postgres" && !internal?.skipPostgresLock) {
			await db!.transaction().execute(async (transaction) => {
				await sql`
					SELECT pg_advisory_xact_lock(
						hashtext('clearance:runtime-migrations:' || current_schema())
					)
				`.execute(transaction);
				const refreshed = await getMigrationsInternal(
					{
						...config,
						database: {
							db: transaction,
							type: "postgres",
							transaction: false,
						},
					},
					{
							skipPostgresLock: true,
							ambientPostgresTransaction: true,
							schemaOnly: true,
							credentialMigrationDrainId,
						},
				);
				await refreshed.runMigrations();
			});
			await sealPostgresCredentialColumns("install");
			const refreshed = await getMigrationsInternal(config, {
					skipPostgresLock: true,
					newCredentialAuthority: legacyAuthorityMigrationIds.length === 0,
					postgresWriterSealsInstalled: true,
					credentialMigrationDrainId,
				});
			await refreshed.runMigrations();
			return;
		}
		for (const migration of migrations) {
			await migration.execute();
		}
		if (internal?.schemaOnly) return;
		const migrationAdapter = kyselyAdapter(db!, {
			type: dbType!,
			transaction: !internal?.ambientPostgresTransaction,
		})(config);
		if (
			dbType === "postgres" &&
			!internal?.postgresWriterSealsInstalled
		) {
			await sealPostgresCredentialColumns("install");
		}
		await migrateLegacySessionCredentials(migrationAdapter, config);
		const migratesOAuth = Boolean(
			config.plugins?.some(
				(plugin) => plugin.id === "oidc-provider" || plugin.id === "mcp",
			),
		);
		if (migratesOAuth) {
			const { migrateOAuthTokenSecrets } = await import(
				"../plugins/oidc-provider"
			);
			await migrateOAuthTokenSecrets(
				migrationAdapter,
				"oauthAccessToken",
				config,
			);
		}
		await sealPostgresCredentialColumns("validate");
		await sealNonPostgresCredentialColumns();
		await assertLegacyCredentialAuthorityDrained();
		await runWithTransaction(migrationAdapter, async () => {
			const markerAdapter = await getCurrentAdapter(migrationAdapter);
			await recordSecurityMigrationComplete(
				markerAdapter,
				SESSION_CREDENTIAL_MIGRATION_ID,
				config,
			);
			if (migratesOAuth) {
				await recordSecurityMigrationComplete(
					markerAdapter,
					OAUTH_TOKEN_MIGRATION_ID,
					config,
				);
			}
		});
	}
	async function compileMigrations() {
		const tables = getAuthTables(config);
		const securityTables = new Set([
			tables.sessionCredential?.modelName,
			tables.securityMigration?.modelName,
			tables.oauthAccessToken?.modelName,
		]);
		const hasPendingSecurityDDL = [...toBeCreated, ...toBeAdded].some(
			(migration) => securityTables.has(migration.table),
		);
		if (hasPendingSecurityDDL || pendingSecurityMigrations.length > 0) {
			throw new Error(
				`Credential security migrations require executable migration; run schema migrate before generating SQL (${pendingSecurityMigrations.join(", ") || "security schema"})`,
			);
		}
		const compiled = migrations.map((m) => m.compile().sql);
		return `${compiled.join(";\n\n")};`;
	}
	const pendingSecurityMigrations: string[] = [];
	const tables = getAuthTables(config);
	const securityTables = new Set([
		tables.sessionCredential?.modelName,
		tables.securityMigration?.modelName,
		tables.oauthAccessToken?.modelName,
	]);
	const hasPendingSecurityDDL = [...toBeCreated, ...toBeAdded].some(
		(migration) => securityTables.has(migration.table),
	);
	const migratesOAuth = Boolean(
		config.plugins?.some(
			(plugin) => plugin.id === "oidc-provider" || plugin.id === "mcp",
		),
	);
	if (hasPendingSecurityDDL) {
		pendingSecurityMigrations.push(SESSION_CREDENTIAL_MIGRATION_ID);
		if (migratesOAuth) pendingSecurityMigrations.push(OAUTH_TOKEN_MIGRATION_ID);
	} else {
		const migrationAdapter = kyselyAdapter(db!, {
			type: dbType!,
			transaction: false,
		})(config);
		try {
			await assertSessionCredentialMigrationComplete(migrationAdapter, config);
		} catch {
			pendingSecurityMigrations.push(SESSION_CREDENTIAL_MIGRATION_ID);
		}
		if (migratesOAuth) {
			try {
				await assertSecurityMigrationComplete(
					migrationAdapter,
					OAUTH_TOKEN_MIGRATION_ID,
				);
			} catch {
				pendingSecurityMigrations.push(OAUTH_TOKEN_MIGRATION_ID);
			}
		}
	}
	const legacyAuthorityMigrationIds = pendingSecurityMigrations.filter(
		(migrationId) => {
			if (migrationId === SESSION_CREDENTIAL_MIGRATION_ID) {
				return Boolean(
					tables.session &&
						!toBeCreated.some(
							(candidate) => candidate.table === tables.session!.modelName,
						),
				);
			}
			if (migrationId === OAUTH_TOKEN_MIGRATION_ID) {
				return Boolean(
					tables.oauthAccessToken &&
						!toBeCreated.some(
							(candidate) =>
								candidate.table === tables.oauthAccessToken!.modelName,
						),
				);
			}
			return false;
		},
	);
	async function assertLegacyCredentialAuthorityDrained(): Promise<void> {
		if (internal?.newCredentialAuthority) return;
		if (legacyAuthorityMigrationIds.length === 0) return;
			if (dbType === "postgres") {
				const drainId = credentialMigrationDrainId;
			if (!drainId) {
				throw new Error(
					`Existing PostgreSQL credential migration ${legacyAuthorityMigrationIds.join(", ")} is reserved for createClearanceAuth(...).migrate() with an armed durable drain`,
				);
			}
			await assertPinnedPostgresCredentialMigration(db!, drainId);
			return;
		}
		throw new Error(
			`Existing credential migration ${legacyAuthorityMigrationIds.join(", ")} is refused without a database-native product drain fence`,
		);
	}
	return {
		toBeCreated,
		toBeAdded,
		pendingSecurityMigrations,
		runMigrations,
		compileMigrations,
	};
}

export async function getMigrations(config: ClearanceOptions) {
	return getMigrationsInternal(config);
}
