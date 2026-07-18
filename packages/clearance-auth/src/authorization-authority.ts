import pg from "pg";

const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;
const MIGRATION_ID = "authorization-authority-v1";
const DEFAULT_PREFIX = "clearance";

type QueryResult<Row extends Record<string, unknown>> = Promise<{
	rows: Row[];
	rowCount: number | null;
}>;

type Queryable = {
	query<Row extends Record<string, unknown>>(
		text: string,
		values?: readonly unknown[],
	): QueryResult<Row>;
};

export type AuthorizationAuthorityTransaction = {
	rawTransactionQuery<Row extends Record<string, unknown>>(
		text: string,
		values?: readonly unknown[],
	): QueryResult<Row>;
};

export type AuthorizationAuthorityIdentity = Readonly<{
	projectId: string;
	environmentId: string;
}>;

export type PostgresAuthorizationAuthorityOptions = AuthorizationAuthorityIdentity &
	Readonly<{
		schema?: string;
		prefix?: string;
	}>;

export type AuthorizationSubject = Readonly<{
	kind: "principal" | "service_account";
	id: string;
}>;

export type AuthorizationAuthorityReadInput = Readonly<{
	organizationId: string;
	subject: AuthorizationSubject;
	transaction?: AuthorizationAuthorityTransaction | Queryable;
}>;

export type AuthorizationAuthorityReadResult = Readonly<{
	projectId: string;
	environmentId: string;
	organizationId: string;
	subject: AuthorizationSubject;
	roleIds: readonly string[];
	actions: readonly string[];
	revision: string;
}>;

export type AuthorizationAuthorityMigrationPlan = Readonly<{
	pendingTables: number;
	pendingFields: number;
	pendingSecurityMigrations: readonly string[];
	compileSql(): Promise<string>;
	apply(): Promise<void>;
}>;

export class PostgresAuthorizationAuthorityError extends Error {
	readonly code: string;

	constructor(message: string, options?: ErrorOptions & { code?: string }) {
		super(message, options);
		this.name = "PostgresAuthorizationAuthorityError";
		this.code = options?.code ?? "AUTHORIZATION_AUTHORITY_UNAVAILABLE";
	}
}

type Names = Readonly<{
	actions: string;
	roles: string;
	roleActions: string;
	assignments: string;
	serviceAccounts: string;
	credentials: string;
	revisions: string;
}>;

type ExpectedColumn = Readonly<{
	name: string;
	dataType: string;
	nullable: boolean;
	default?: "now" | "false";
}>;

type ExpectedConstraint = Readonly<{
	name: string;
	type: "p" | "u" | "f" | "c";
	definitionIncludes?: readonly string[];
}>;

type ExpectedIndex = Readonly<{ name: string; definitionIncludes: readonly string[] }>;

type TableRow = { table_name: string; relkind: string; persistence: string };
type ColumnRow = {
	table_name: string;
	column_name: string;
	data_type: string;
	is_nullable: "YES" | "NO";
	column_default: string | null;
};
type ConstraintRow = {
	table_name: string;
	constraint_name: string;
	constraint_type: "p" | "u" | "f" | "c";
	validated: boolean;
	definition: string;
};
type IndexRow = { table_name: string; index_name: string; definition: string };
type TriggerRow = { table_name: string; trigger_name: string; definition: string };
type FunctionRow = { function_name: string; definition: string };

function error(message: string, cause?: unknown, code?: string): PostgresAuthorizationAuthorityError {
	return new PostgresAuthorizationAuthorityError(message, {
		...(cause === undefined ? {} : { cause }),
		...(code === undefined ? {} : { code }),
	});
}

function scopeString(value: unknown, label: string): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 255 ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	}
	return value;
}

function identifier(value: unknown, label: string, maxLength: number): string {
	if (typeof value !== "string" || !/^[a-z_][a-z0-9_]*$/.test(value) || value.length > maxLength) {
		throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	}
	return value;
}

function quoted(value: string): string {
	return `"${value.replaceAll('"', '""')}"`;
}

function qualified(schema: string, table: string): string {
	return `${quoted(schema)}.${quoted(table)}`;
}

function namesFor(prefix: string): Names {
	return Object.freeze({
		actions: `${prefix}_authz_actions`,
		roles: `${prefix}_authz_roles`,
		roleActions: `${prefix}_authz_role_actions`,
		assignments: `${prefix}_authz_subject_role_assignments`,
		serviceAccounts: `${prefix}_authz_service_accounts`,
		credentials: `${prefix}_authz_service_account_credentials`,
		revisions: `${prefix}_authz_revisions`,
	});
}

function shortName(names: Names, suffix: string): string {
	const prefix = names.actions.slice(0, -"_authz_actions".length);
	const result = `${prefix}_az_${suffix}`;
	if (result.length > 63) throw error("Authorization identifier is too long", undefined, "AUTHORIZATION_INPUT_INVALID");
	return result;
}

function normalize(value: string): string {
	return value.replaceAll('"', "").replace(/\s+/g, " ").trim().toLowerCase();
}

function columns(): Readonly<Record<keyof Names, readonly ExpectedColumn[]>> {
	const scope = [
		{ name: "projectId", dataType: "text", nullable: false },
		{ name: "environmentId", dataType: "text", nullable: false },
	] as const;
	const created = { name: "createdAt", dataType: "timestamp with time zone", nullable: false, default: "now" } as const;
	return {
		actions: [...scope, { name: "actionId", dataType: "text", nullable: false }, { name: "actionName", dataType: "text", nullable: false }, { name: "description", dataType: "text", nullable: true }, created],
		roles: [...scope, { name: "roleId", dataType: "text", nullable: false }, { name: "organizationId", dataType: "text", nullable: true }, { name: "slug", dataType: "text", nullable: false }, { name: "name", dataType: "text", nullable: false }, { name: "description", dataType: "text", nullable: true }, { name: "builtIn", dataType: "boolean", nullable: false, default: "false" }, { name: "status", dataType: "text", nullable: false }, created, { name: "updatedAt", dataType: "timestamp with time zone", nullable: false, default: "now" }],
		roleActions: [...scope, { name: "roleId", dataType: "text", nullable: false }, { name: "actionId", dataType: "text", nullable: false }, created],
		assignments: [...scope, { name: "organizationId", dataType: "text", nullable: false }, { name: "subjectKind", dataType: "text", nullable: false }, { name: "subjectId", dataType: "text", nullable: false }, { name: "roleId", dataType: "text", nullable: false }, created],
		serviceAccounts: [...scope, { name: "organizationId", dataType: "text", nullable: false }, { name: "serviceAccountId", dataType: "text", nullable: false }, { name: "name", dataType: "text", nullable: false }, { name: "status", dataType: "text", nullable: false }, created, { name: "updatedAt", dataType: "timestamp with time zone", nullable: false, default: "now" }],
		credentials: [...scope, { name: "organizationId", dataType: "text", nullable: false }, { name: "credentialId", dataType: "text", nullable: false }, { name: "serviceAccountId", dataType: "text", nullable: false }, { name: "credentialDigest", dataType: "text", nullable: false }, { name: "credentialPrefix", dataType: "text", nullable: false }, { name: "credentialFingerprint", dataType: "text", nullable: false }, { name: "status", dataType: "text", nullable: false }, { name: "expiresAt", dataType: "timestamp with time zone", nullable: true }, { name: "replacedCredentialId", dataType: "text", nullable: true }, { name: "version", dataType: "integer", nullable: false }, created, { name: "revokedAt", dataType: "timestamp with time zone", nullable: true }, { name: "updatedAt", dataType: "timestamp with time zone", nullable: false, default: "now" }],
		revisions: [...scope, { name: "organizationId", dataType: "text", nullable: false }, { name: "revision", dataType: "bigint", nullable: false }, { name: "updatedAt", dataType: "timestamp with time zone", nullable: false, default: "now" }],
	};
}

function constraints(names: Names): Readonly<Record<keyof Names, readonly ExpectedConstraint[]>> {
	const c = (suffix: string) => shortName(names, suffix);
	const fk = (suffix: string, include: string): ExpectedConstraint => ({ name: c(suffix), type: "f", definitionIncludes: [include] });
	return {
		actions: [{ name: c("actions_pk"), type: "p" }, { name: c("actions_name_uq"), type: "u" }, { name: c("actions_name_ck"), type: "c", definitionIncludes: ["actionname = lower", "actionname ~"] }],
		roles: [
			{ name: c("roles_pk"), type: "p" },
			{ name: c("roles_status_ck"), type: "c", definitionIncludes: ["status = any", "active", "disabled", "archived"] },
			{ name: c("roles_slug_ck"), type: "c", definitionIncludes: ["slug = lower", "slug ~"] },
			{ name: c("roles_name_ck"), type: "c", definitionIncludes: ["name <> ''"] },
		],
		roleActions: [
			{ name: c("role_actions_pk"), type: "p" },
			fk("role_actions_role_fk", names.roles),
			fk("role_actions_action_fk", names.actions),
		],
		assignments: [
			{ name: c("assignments_pk"), type: "p" },
			{ name: c("assignments_subject_ck"), type: "c", definitionIncludes: ["subjectkind = any", "principal", "service_account"] },
			fk("assignments_role_fk", names.roles),
		],
		serviceAccounts: [
			{ name: c("service_accounts_pk"), type: "p" },
			{ name: c("service_accounts_status_ck"), type: "c", definitionIncludes: ["status = any", "active", "disabled"] },
			{ name: c("service_accounts_name_ck"), type: "c", definitionIncludes: ["name <> ''"] },
		],
		credentials: [
			{ name: c("credentials_pk"), type: "p" },
			{ name: c("credentials_digest_uq"), type: "u" },
			{ name: c("credentials_status_ck"), type: "c", definitionIncludes: ["status = any", "active", "revoked"] },
			{ name: c("credentials_version_ck"), type: "c", definitionIncludes: ["version > 0"] },
			{ name: c("credentials_secret_ck"), type: "c", definitionIncludes: ["credentialdigest <> ''", "credentialprefix ~", "credentialfingerprint ~"] },
			{ name: c("credentials_expiry_ck"), type: "c", definitionIncludes: ["expiresat is null", "expiresat > createdat"] },
			{ name: c("credentials_replacement_ck"), type: "c", definitionIncludes: ["replacedcredentialid is null", "replacedcredentialid <> credentialid"] },
			fk("credentials_account_fk", names.serviceAccounts),
			fk("credentials_replacement_fk", names.credentials),
		],
		revisions: [
			{ name: c("revisions_pk"), type: "p" },
			{ name: c("revisions_positive_ck"), type: "c", definitionIncludes: ["revision > 0"] },
		],
	};
}

function indexes(names: Names): Readonly<Record<keyof Names, readonly ExpectedIndex[]>> {
	const c = (suffix: string) => shortName(names, suffix);
	return {
		actions: [],
		roles: [{ name: c("roles_scope_org_slug_uq"), definitionIncludes: ["unique index", "projectid", "environmentid", "coalesce", "organizationid", "slug"] }],
		roleActions: [],
		assignments: [{ name: c("assignments_subject_idx"), definitionIncludes: ["projectid", "environmentid", "organizationid", "subjectkind", "subjectid"] }],
		serviceAccounts: [{ name: c("service_accounts_scope_name_uq"), definitionIncludes: ["unique index", "projectid", "environmentid", "organizationid", "name"] }],
		credentials: [
			{ name: c("credentials_account_idx"), definitionIncludes: ["projectid", "environmentid", "organizationid", "serviceaccountid"] },
			{ name: c("credentials_account_version_uq"), definitionIncludes: ["unique index", "projectid", "environmentid", "organizationid", "serviceaccountid", "version"] },
		],
		revisions: [],
	};
}

type ExpectedTrigger = Readonly<{
	table: keyof Names;
	name: string;
	definitionIncludes: readonly string[];
}>;

type ExpectedFunction = Readonly<{
	name: string;
	definitionIncludes: readonly string[];
}>;

function authorizationGuardFunctionName(names: Names): string {
	return shortName(names, "role_scope_guard_fn");
}

function authorizationTriggers(names: Names): readonly ExpectedTrigger[] {
	const c = (suffix: string) => shortName(names, suffix);
	const guard = authorizationGuardFunctionName(names);
	return [
		{
			table: "assignments",
			name: c("assignments_role_scope_trg"),
			definitionIncludes: ["constraint trigger", "after insert or update", names.assignments, `.${guard}()`],
		},
		{
			table: "roles",
			name: c("roles_scope_change_trg"),
			definitionIncludes: ["constraint trigger", "after update of", "organizationid", names.roles, `.${guard}()`],
		},
	];
}

function authorizationGuardFunctions(names: Names): readonly ExpectedFunction[] {
	return [{
		name: authorizationGuardFunctionName(names),
		definitionIncludes: ["returns trigger", "role scope mismatch", "new.organizationid", "organizationid"],
	}];
}

function createSql(schema: string, names: Names): string {
	const t = (name: string) => qualified(schema, name);
	const c = (suffix: string) => quoted(shortName(names, suffix));
	const f = (suffix: string) => qualified(schema, suffix);
	return [
		`CREATE TABLE IF NOT EXISTS ${t(names.actions)} (
			"projectId" text NOT NULL, "environmentId" text NOT NULL, "actionId" text NOT NULL, "actionName" text NOT NULL, description text,
			"createdAt" timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT ${c("actions_pk")} PRIMARY KEY ("projectId", "environmentId", "actionId"),
			CONSTRAINT ${c("actions_name_uq")} UNIQUE ("projectId", "environmentId", "actionName"),
			CONSTRAINT ${c("actions_name_ck")} CHECK ("actionName" = lower("actionName") AND "actionName" ~ '^[a-z][a-z0-9._:-]{0,127}$')
		)`,
		`CREATE TABLE IF NOT EXISTS ${t(names.roles)} (
			"projectId" text NOT NULL, "environmentId" text NOT NULL, "roleId" text NOT NULL,
			"organizationId" text, slug text NOT NULL, name text NOT NULL, description text, "builtIn" boolean NOT NULL DEFAULT false,
			status text NOT NULL, "createdAt" timestamptz NOT NULL DEFAULT now(),
			"updatedAt" timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT ${c("roles_pk")} PRIMARY KEY ("projectId", "environmentId", "roleId"),
			CONSTRAINT ${c("roles_status_ck")} CHECK (status IN ('active', 'disabled', 'archived')),
			CONSTRAINT ${c("roles_slug_ck")} CHECK (slug = lower(slug) AND slug ~ '^[a-z][a-z0-9_-]{0,127}$'),
			CONSTRAINT ${c("roles_name_ck")} CHECK (name <> '')
		)`,
		`CREATE TABLE IF NOT EXISTS ${t(names.roleActions)} (
			"projectId" text NOT NULL, "environmentId" text NOT NULL, "roleId" text NOT NULL, "actionId" text NOT NULL,
			"createdAt" timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT ${c("role_actions_pk")} PRIMARY KEY ("projectId", "environmentId", "roleId", "actionId"),
			CONSTRAINT ${c("role_actions_role_fk")} FOREIGN KEY ("projectId", "environmentId", "roleId") REFERENCES ${t(names.roles)} ("projectId", "environmentId", "roleId") ON DELETE CASCADE,
			CONSTRAINT ${c("role_actions_action_fk")} FOREIGN KEY ("projectId", "environmentId", "actionId") REFERENCES ${t(names.actions)} ("projectId", "environmentId", "actionId") ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS ${t(names.assignments)} (
			"projectId" text NOT NULL, "environmentId" text NOT NULL, "organizationId" text NOT NULL,
			"subjectKind" text NOT NULL, "subjectId" text NOT NULL, "roleId" text NOT NULL,
			"createdAt" timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT ${c("assignments_pk")} PRIMARY KEY ("projectId", "environmentId", "organizationId", "subjectKind", "subjectId", "roleId"),
			CONSTRAINT ${c("assignments_subject_ck")} CHECK ("subjectKind" IN ('principal', 'service_account')),
			CONSTRAINT ${c("assignments_role_fk")} FOREIGN KEY ("projectId", "environmentId", "roleId") REFERENCES ${t(names.roles)} ("projectId", "environmentId", "roleId") ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS ${t(names.serviceAccounts)} (
			"projectId" text NOT NULL, "environmentId" text NOT NULL, "organizationId" text NOT NULL,
			"serviceAccountId" text NOT NULL, name text NOT NULL, status text NOT NULL,
			"createdAt" timestamptz NOT NULL DEFAULT now(), "updatedAt" timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT ${c("service_accounts_pk")} PRIMARY KEY ("projectId", "environmentId", "organizationId", "serviceAccountId"),
			CONSTRAINT ${c("service_accounts_status_ck")} CHECK (status IN ('active', 'disabled')),
			CONSTRAINT ${c("service_accounts_name_ck")} CHECK (name <> '')
		)`,
		`CREATE TABLE IF NOT EXISTS ${t(names.credentials)} (
			"projectId" text NOT NULL, "environmentId" text NOT NULL, "organizationId" text NOT NULL,
			"credentialId" text NOT NULL, "serviceAccountId" text NOT NULL, "credentialDigest" text NOT NULL,
			"credentialPrefix" text NOT NULL, "credentialFingerprint" text NOT NULL, status text NOT NULL,
			"expiresAt" timestamptz, "replacedCredentialId" text, version integer NOT NULL,
			"createdAt" timestamptz NOT NULL DEFAULT now(), "revokedAt" timestamptz, "updatedAt" timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT ${c("credentials_pk")} PRIMARY KEY ("projectId", "environmentId", "organizationId", "credentialId"),
			CONSTRAINT ${c("credentials_digest_uq")} UNIQUE ("credentialDigest"),
			CONSTRAINT ${c("credentials_status_ck")} CHECK (status IN ('active', 'revoked')),
			CONSTRAINT ${c("credentials_version_ck")} CHECK (version > 0),
			CONSTRAINT ${c("credentials_secret_ck")} CHECK ("credentialDigest" <> '' AND "credentialPrefix" ~ '^[A-Za-z0-9_-]{1,32}$' AND "credentialFingerprint" ~ '^[A-Za-z0-9_-]{6,128}$'),
			CONSTRAINT ${c("credentials_expiry_ck")} CHECK ("expiresAt" IS NULL OR "expiresAt" > "createdAt"),
			CONSTRAINT ${c("credentials_replacement_ck")} CHECK ("replacedCredentialId" IS NULL OR "replacedCredentialId" <> "credentialId"),
			CONSTRAINT ${c("credentials_account_fk")} FOREIGN KEY ("projectId", "environmentId", "organizationId", "serviceAccountId") REFERENCES ${t(names.serviceAccounts)} ("projectId", "environmentId", "organizationId", "serviceAccountId") ON DELETE CASCADE,
			CONSTRAINT ${c("credentials_replacement_fk")} FOREIGN KEY ("projectId", "environmentId", "organizationId", "replacedCredentialId") REFERENCES ${t(names.credentials)} ("projectId", "environmentId", "organizationId", "credentialId") ON DELETE RESTRICT
		)`,
		`CREATE TABLE IF NOT EXISTS ${t(names.revisions)} (
			"projectId" text NOT NULL, "environmentId" text NOT NULL, "organizationId" text NOT NULL,
			revision bigint NOT NULL, "updatedAt" timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT ${c("revisions_pk")} PRIMARY KEY ("projectId", "environmentId", "organizationId"),
			CONSTRAINT ${c("revisions_positive_ck")} CHECK (revision > 0)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${c("roles_scope_org_slug_uq")} ON ${t(names.roles)} ("projectId", "environmentId", COALESCE("organizationId", ''), slug)`,
		`CREATE INDEX IF NOT EXISTS ${c("assignments_subject_idx")} ON ${t(names.assignments)} ("projectId", "environmentId", "organizationId", "subjectKind", "subjectId")`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${c("service_accounts_scope_name_uq")} ON ${t(names.serviceAccounts)} ("projectId", "environmentId", "organizationId", name)`,
		`CREATE INDEX IF NOT EXISTS ${c("credentials_account_idx")} ON ${t(names.credentials)} ("projectId", "environmentId", "organizationId", "serviceAccountId")`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${c("credentials_account_version_uq")} ON ${t(names.credentials)} ("projectId", "environmentId", "organizationId", "serviceAccountId", version)`,
		`CREATE FUNCTION ${f(authorizationGuardFunctionName(names))}()
		RETURNS trigger
		LANGUAGE plpgsql
		AS $$
		DECLARE
			role_organization_id text;
		BEGIN
			IF TG_TABLE_NAME = '${names.assignments}' THEN
				SELECT r."organizationId" INTO role_organization_id
				FROM ${t(names.roles)} r
				WHERE r."projectId" = NEW."projectId" AND r."environmentId" = NEW."environmentId" AND r."roleId" = NEW."roleId";
				IF NOT FOUND THEN
					RAISE EXCEPTION 'authorization role was not found' USING ERRCODE = '23503';
				END IF;
				IF role_organization_id IS NOT NULL AND role_organization_id <> NEW."organizationId" THEN
					RAISE EXCEPTION 'authorization role scope mismatch' USING ERRCODE = '23514';
				END IF;
			ELSIF TG_TABLE_NAME = '${names.roles}' THEN
				IF NEW."organizationId" IS NOT NULL AND EXISTS (
					SELECT 1 FROM ${t(names.assignments)} a
					WHERE a."projectId" = NEW."projectId" AND a."environmentId" = NEW."environmentId" AND a."roleId" = NEW."roleId" AND a."organizationId" <> NEW."organizationId"
				) THEN
					RAISE EXCEPTION 'authorization role scope mismatch' USING ERRCODE = '23514';
				END IF;
			END IF;
			RETURN NEW;
		END;
		$$`,
		`CREATE CONSTRAINT TRIGGER ${c("assignments_role_scope_trg")}
		AFTER INSERT OR UPDATE OF "organizationId", "roleId" ON ${t(names.assignments)}
		DEFERRABLE INITIALLY IMMEDIATE
		FOR EACH ROW EXECUTE FUNCTION ${f(authorizationGuardFunctionName(names))}()`,
		`CREATE CONSTRAINT TRIGGER ${c("roles_scope_change_trg")}
		AFTER UPDATE OF "organizationId" ON ${t(names.roles)}
		DEFERRABLE INITIALLY IMMEDIATE
		FOR EACH ROW EXECUTE FUNCTION ${f(authorizationGuardFunctionName(names))}()`,
	].join(";\n");
}

function canonicalRevision(value: unknown): string {
	if (typeof value !== "string" || !/^[1-9]\d*$/.test(value)) {
		throw error("Authorization revision is invalid", undefined, "AUTHORIZATION_REVISION_INVALID");
	}
	try {
		const parsed = BigInt(value);
		if (parsed <= 0n || parsed > POSTGRES_BIGINT_MAX) throw new Error("out of range");
	} catch (cause) {
		throw error("Authorization revision is invalid", cause, "AUTHORIZATION_REVISION_INVALID");
	}
	return value;
}

function assertColumns(table: string, actual: readonly ColumnRow[], expected: readonly ExpectedColumn[]): void {
	const rows = actual.filter((row) => row.table_name === table);
	if (rows.length !== expected.length) throw error(`Authorization table ${table} has incompatible columns`);
	for (const column of expected) {
		const found = rows.find((row) => row.column_name === column.name);
		const expectedDefault = column.default === "now" ? "now()" : column.default === "false" ? "false" : null;
		if (!found || found.data_type !== column.dataType || (found.is_nullable === "YES") !== column.nullable || found.column_default !== expectedDefault) {
			throw error(`Authorization table ${table} has incompatible column ${column.name}`);
		}
	}
}

function assertConstraints(table: string, actual: readonly ConstraintRow[], expected: readonly ExpectedConstraint[]): void {
	const rows = actual.filter((row) => row.table_name === table);
	if (rows.length !== expected.length) throw error(`Authorization table ${table} has incompatible constraints`);
	for (const constraint of expected) {
		const found = rows.find((row) => row.constraint_name === constraint.name);
		if (!found || found.constraint_type !== constraint.type || !found.validated) throw error(`Authorization table ${table} has incompatible constraint ${constraint.name}`);
		const definition = normalize(found.definition);
		if (constraint.definitionIncludes?.some((part) => !definition.includes(normalize(part)))) {
			throw error(`Authorization table ${table} has incompatible constraint ${constraint.name}`);
		}
	}
}

function assertIndexes(table: string, actual: readonly IndexRow[], expected: readonly ExpectedIndex[]): void {
	const rows = actual.filter((row) => row.table_name === table);
	if (rows.length !== expected.length) throw error(`Authorization table ${table} has incompatible indexes`);
	for (const index of expected) {
		const found = rows.find((row) => row.index_name === index.name);
		if (!found || index.definitionIncludes.some((part) => !normalize(found.definition).includes(normalize(part)))) {
			throw error(`Authorization table ${table} has incompatible index ${index.name}`);
		}
	}
}

function assertTriggers(actual: readonly TriggerRow[], names: Names, expected: readonly ExpectedTrigger[]): void {
	if (actual.length !== expected.length) throw error("Authorization triggers are incompatible");
	for (const trigger of expected) {
		const found = actual.find((row) => row.table_name === names[trigger.table] && row.trigger_name === trigger.name);
		if (!found || trigger.definitionIncludes.some((part) => !normalize(found.definition).includes(normalize(part)))) {
			throw error(`Authorization trigger ${trigger.name} is incompatible`);
		}
	}
}

function assertFunctions(actual: readonly FunctionRow[], expected: readonly ExpectedFunction[]): void {
	if (actual.length !== expected.length) throw error("Authorization guard functions are incompatible");
	for (const functionDefinition of expected) {
		const found = actual.find((row) => row.function_name === functionDefinition.name);
		if (!found || functionDefinition.definitionIncludes.some((part) => !normalize(found.definition).includes(normalize(part)))) {
			throw error(`Authorization guard function ${functionDefinition.name} is incompatible`);
		}
	}
}

async function inspectCatalog(queryable: Queryable, schema: string, names: Names): Promise<boolean> {
	const tableNames = Object.values(names);
	const tables = await queryable.query<TableRow>(`SELECT c.relname AS table_name, c.relkind, c.relpersistence AS persistence FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = ANY($2::text[])`, [schema, tableNames]);
	if (tables.rows.length === 0) return false;
	if (tables.rows.length !== tableNames.length || tables.rows.some((row) => row.relkind !== "r" || row.persistence !== "p")) throw error("PostgreSQL authorization authority is partially installed or incompatible");
	const actualColumns = await queryable.query<ColumnRow>(`SELECT table_name, column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = ANY($2::text[]) ORDER BY table_name, ordinal_position`, [schema, tableNames]);
	const actualConstraints = await queryable.query<ConstraintRow>(`SELECT c.relname AS table_name, con.conname AS constraint_name, con.contype AS constraint_type, con.convalidated AS validated, pg_get_constraintdef(con.oid, true) AS definition FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = ANY($2::text[]) AND con.contype = ANY(ARRAY['p', 'u', 'f', 'c']::"char"[]) ORDER BY c.relname, con.conname`, [schema, tableNames]);
	const actualIndexes = await queryable.query<IndexRow>(`SELECT c.relname AS table_name, i.relname AS index_name, pg_get_indexdef(i.oid) AS definition FROM pg_index x JOIN pg_class c ON c.oid = x.indrelid JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_constraint con ON con.conindid = i.oid WHERE n.nspname = $1 AND c.relname = ANY($2::text[]) AND con.oid IS NULL ORDER BY c.relname, i.relname`, [schema, tableNames]);
	const actualTriggers = await queryable.query<TriggerRow>(`SELECT c.relname AS table_name, tg.tgname AS trigger_name, pg_get_triggerdef(tg.oid, true) AS definition FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = ANY($2::text[]) AND NOT tg.tgisinternal ORDER BY c.relname, tg.tgname`, [schema, tableNames]);
	const guard = authorizationGuardFunctionName(names);
	const actualFunctions = await queryable.query<FunctionRow>(`SELECT p.proname AS function_name, pg_get_functiondef(p.oid) AS definition FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1 AND p.proname = $2 AND p.pronargs = 0`, [schema, guard]);
	const expectedColumns = columns(); const expectedConstraints = constraints(names); const expectedIndexes = indexes(names);
	for (const key of Object.keys(names) as (keyof Names)[]) {
		assertColumns(names[key], actualColumns.rows, expectedColumns[key]);
		assertConstraints(names[key], actualConstraints.rows, expectedConstraints[key]);
		assertIndexes(names[key], actualIndexes.rows, expectedIndexes[key]);
	}
	assertTriggers(actualTriggers.rows, names, authorizationTriggers(names));
	assertFunctions(actualFunctions.rows, authorizationGuardFunctions(names));
	return true;
}

function transactionQueryable(value: AuthorizationAuthorityTransaction | Queryable): Queryable {
	if ("rawTransactionQuery" in value) return { query: value.rawTransactionQuery.bind(value) };
	if (typeof value.query === "function") return value;
	throw error("Authorization transaction is invalid", undefined, "AUTHORIZATION_INPUT_INVALID");
}

type ReadRow = { revision: unknown; subject_valid: unknown; role_ids: unknown; actions: unknown };

function decodeSortedStrings(value: unknown, field: string): readonly string[] {
	if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || entry.length === 0)) throw error(`Authorization ${field} is invalid`);
	const sorted = [...value].sort((left, right) => left.localeCompare(right));
	if (sorted.some((value, index) => index > 0 && value === sorted[index - 1])) throw error(`Authorization ${field} is invalid`);
	return Object.freeze(sorted);
}

export class PostgresAuthorizationAuthority {
	readonly identity: AuthorizationAuthorityIdentity;
	readonly schema: string;
	readonly prefix: string;
	readonly #database: Pick<pg.Pool, "query" | "connect">;
	readonly #names: Names;

	constructor(database: Pick<pg.Pool, "query" | "connect">, options: PostgresAuthorizationAuthorityOptions) {
		if (!database || typeof database.query !== "function" || typeof database.connect !== "function") throw error("PostgreSQL authorization database is invalid", undefined, "AUTHORIZATION_INPUT_INVALID");
		this.identity = Object.freeze({ projectId: scopeString(options.projectId, "projectId"), environmentId: scopeString(options.environmentId, "environmentId") });
		this.schema = identifier(options.schema ?? "public", "schema", 63);
		this.prefix = identifier(options.prefix ?? DEFAULT_PREFIX, "prefix", 24);
		this.#database = database;
		this.#names = namesFor(this.prefix);
	}

	async planMigration(): Promise<AuthorizationAuthorityMigrationPlan> {
		const installed = await inspectCatalog(this.#database, this.schema, this.#names);
		const fieldCount = Object.values(columns()).reduce((total, table) => total + table.length, 0);
		const sql = installed ? "" : createSql(this.schema, this.#names);
		return Object.freeze({
			pendingTables: installed ? 0 : Object.keys(this.#names).length,
			pendingFields: installed ? 0 : fieldCount,
			pendingSecurityMigrations: installed ? Object.freeze([]) : Object.freeze([MIGRATION_ID]),
			compileSql: async () => sql,
			apply: async () => {
				const client = await this.#database.connect();
				try {
					await client.query("BEGIN");
					await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`${this.schema}:${this.prefix}:${MIGRATION_ID}`]);
					const alreadyInstalled = await inspectCatalog(client, this.schema, this.#names);
					if (!alreadyInstalled) await client.query(createSql(this.schema, this.#names));
					await inspectCatalog(client, this.schema, this.#names);
					await client.query("COMMIT");
				} catch (cause) {
					try { await client.query("ROLLBACK"); } catch { /* preserve original failure */ }
					throw cause;
				} finally { client.release(); }
			},
		});
	}

	async readEffective(input: AuthorizationAuthorityReadInput): Promise<AuthorizationAuthorityReadResult> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		if (!input.subject || (input.subject.kind !== "principal" && input.subject.kind !== "service_account")) throw error("Authorization subject is invalid", undefined, "AUTHORIZATION_INPUT_INVALID");
		const subject = Object.freeze({ kind: input.subject.kind, id: scopeString(input.subject.id, "subject.id") });
		const queryable = input.transaction ? transactionQueryable(input.transaction) : this.#database;
		const t = (name: string) => qualified(this.schema, name);
		const row = await queryable.query<ReadRow>(`WITH revision_row AS (
			SELECT revision::text AS revision FROM ${t(this.#names.revisions)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3
		), effective_roles AS (
			SELECT DISTINCT r."roleId" FROM ${t(this.#names.assignments)} a
			JOIN ${t(this.#names.roles)} r ON r."projectId" = a."projectId" AND r."environmentId" = a."environmentId" AND r."roleId" = a."roleId"
			WHERE a."projectId" = $1 AND a."environmentId" = $2 AND a."organizationId" = $3 AND a."subjectKind" = $4 AND a."subjectId" = $5
			AND r.status = 'active' AND (r."organizationId" IS NULL OR r."organizationId" = a."organizationId")
		), effective_actions AS (
			SELECT DISTINCT ac."actionName" FROM effective_roles er JOIN ${t(this.#names.roleActions)} ra ON ra."projectId" = $1 AND ra."environmentId" = $2 AND ra."roleId" = er."roleId"
			JOIN ${t(this.#names.actions)} ac ON ac."projectId" = ra."projectId" AND ac."environmentId" = ra."environmentId" AND ac."actionId" = ra."actionId"
		)
		SELECT (SELECT revision FROM revision_row) AS revision,
			CASE WHEN $4 = 'principal' THEN true ELSE EXISTS (SELECT 1 FROM ${t(this.#names.serviceAccounts)} sa WHERE sa."projectId" = $1 AND sa."environmentId" = $2 AND sa."organizationId" = $3 AND sa."serviceAccountId" = $5 AND sa.status = 'active') END AS subject_valid,
			COALESCE((SELECT array_agg("roleId" ORDER BY "roleId") FROM effective_roles), ARRAY[]::text[]) AS role_ids,
			COALESCE((SELECT array_agg("actionName" ORDER BY "actionName") FROM effective_actions), ARRAY[]::text[]) AS actions`, [this.identity.projectId, this.identity.environmentId, organizationId, subject.kind, subject.id]);
		if (row.rows.length !== 1) throw error("Authorization read is unavailable");
		const result = row.rows[0]!;
		if (result.revision === null || result.revision === undefined) throw error("Authorization revision was not found", undefined, "AUTHORIZATION_REVISION_NOT_FOUND");
		const revision = canonicalRevision(result.revision);
		if (result.subject_valid !== true) throw error("Authorization subject was not found", undefined, "AUTHORIZATION_SUBJECT_NOT_FOUND");
		return Object.freeze({ projectId: this.identity.projectId, environmentId: this.identity.environmentId, organizationId, subject, roleIds: decodeSortedStrings(result.role_ids, "roles"), actions: decodeSortedStrings(result.actions, "actions"), revision });
	}
}
