import type {
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyIdentity,
	RuntimeAuthenticationPolicyOverride,
	RuntimeAuthenticationPolicyReader,
	RuntimeAuthenticationPolicyReaderInput,
	RuntimeAuthenticationPolicyReaderResult,
} from "../../core/src/types/authentication-policy.js";
import {
	applyRuntimeAuthenticationPolicyOverride,
	normalizeRuntimeAuthenticationPolicy,
	normalizeRuntimeAuthenticationPolicyOverride,
} from "../../runtime/src/internal/authentication-policy.js";
import pg from "pg";

const POLICY_TABLE = "authenticationPolicy";
const OVERRIDE_TABLE = "authenticationPolicyOrganizationOverride";
const MIGRATION_ID = "authentication-policy-authority-v1";
const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;

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

export type AuthenticationPolicyAuthorityMigrationPlan = {
	pendingTables: number;
	pendingFields: number;
	pendingSecurityMigrations: readonly string[];
	compileSql(): Promise<string>;
	apply(): Promise<void>;
};

export class PostgresAuthenticationPolicyAuthorityError extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "PostgresAuthenticationPolicyAuthorityError";
	}
}

type ExpectedColumn = Readonly<{
	name: string;
	dataType: string;
	nullable: boolean;
	defaultKind?: "now" | "false";
}>;

type ExpectedConstraint = Readonly<{
	name: string;
	type: "p" | "f" | "c";
	definition: string;
}>;

const POLICY_COLUMNS: readonly ExpectedColumn[] = [
	{ name: "projectId", dataType: "text", nullable: false },
	{ name: "environmentId", dataType: "text", nullable: false },
	{ name: "revision", dataType: "bigint", nullable: false },
	{ name: "passwordLockoutEnabled", dataType: "boolean", nullable: false },
	{ name: "passwordLockoutMaxFailedAttempts", dataType: "integer", nullable: false },
	{ name: "passwordLockoutDurationSeconds", dataType: "integer", nullable: false },
	{ name: "factorLockoutEnabled", dataType: "boolean", nullable: false },
	{ name: "factorLockoutMaxFailedAttempts", dataType: "integer", nullable: false },
	{ name: "factorLockoutDurationSeconds", dataType: "integer", nullable: false },
	{ name: "minimumAssurance", dataType: "text", nullable: false },
	{ name: "allowedFactorTotp", dataType: "boolean", nullable: false },
	{ name: "allowedFactorPasskey", dataType: "boolean", nullable: false },
	{ name: "trustedDeviceEnabled", dataType: "boolean", nullable: false },
	{ name: "trustedDeviceMaxAgeSeconds", dataType: "integer", nullable: false },
	{ name: "assuranceMaxAgeSeconds", dataType: "integer", nullable: true },
	{ name: "createdAt", dataType: "timestamp with time zone", nullable: false, defaultKind: "now" },
	{ name: "updatedAt", dataType: "timestamp with time zone", nullable: false, defaultKind: "now" },
] as const;

const OVERRIDE_COLUMNS: readonly ExpectedColumn[] = [
	{ name: "projectId", dataType: "text", nullable: false },
	{ name: "environmentId", dataType: "text", nullable: false },
	{ name: "organizationId", dataType: "text", nullable: false },
	{ name: "revision", dataType: "bigint", nullable: false },
	{ name: "passwordLockoutEnabled", dataType: "boolean", nullable: true },
	{ name: "passwordLockoutMaxFailedAttempts", dataType: "integer", nullable: true },
	{ name: "passwordLockoutDurationSeconds", dataType: "integer", nullable: true },
	{ name: "factorLockoutEnabled", dataType: "boolean", nullable: true },
	{ name: "factorLockoutMaxFailedAttempts", dataType: "integer", nullable: true },
	{ name: "factorLockoutDurationSeconds", dataType: "integer", nullable: true },
	{ name: "minimumAssurance", dataType: "text", nullable: true },
	{ name: "allowedFactorTotp", dataType: "boolean", nullable: true },
	{ name: "allowedFactorPasskey", dataType: "boolean", nullable: true },
	{ name: "trustedDeviceEnabled", dataType: "boolean", nullable: true },
	{ name: "trustedDeviceMaxAgeSeconds", dataType: "integer", nullable: true },
	{ name: "assuranceMaxAgeSecondsSet", dataType: "boolean", nullable: false, defaultKind: "false" },
	{ name: "assuranceMaxAgeSeconds", dataType: "integer", nullable: true },
	{ name: "createdAt", dataType: "timestamp with time zone", nullable: false, defaultKind: "now" },
	{ name: "updatedAt", dataType: "timestamp with time zone", nullable: false, defaultKind: "now" },
] as const;

const POLICY_CONSTRAINTS: readonly ExpectedConstraint[] = [
	{ name: "auth_policy_pkey", type: "p", definition: 'PRIMARY KEY ("projectId", "environmentId")' },
	{ name: "auth_policy_revision_ck", type: "c", definition: "CHECK (revision > 0)" },
	{ name: "auth_policy_password_lockout_ck", type: "c", definition: 'CHECK ("passwordLockoutMaxFailedAttempts" >= 3 AND "passwordLockoutMaxFailedAttempts" <= 100 AND "passwordLockoutDurationSeconds" >= 30 AND "passwordLockoutDurationSeconds" <= 86400)' },
	{ name: "auth_policy_factor_lockout_ck", type: "c", definition: 'CHECK ("factorLockoutMaxFailedAttempts" >= 3 AND "factorLockoutMaxFailedAttempts" <= 100 AND "factorLockoutDurationSeconds" >= 30 AND "factorLockoutDurationSeconds" <= 86400)' },
	{ name: "auth_policy_minimum_assurance_ck", type: "c", definition: 'CHECK ("minimumAssurance" = ANY (ARRAY[\'single_factor\'::text, \'multi_factor\'::text, \'phishing_resistant\'::text]))' },
	{ name: "auth_policy_trusted_device_ck", type: "c", definition: 'CHECK ("trustedDeviceMaxAgeSeconds" >= CASE WHEN "trustedDeviceEnabled" THEN 60 ELSE 0 END AND "trustedDeviceMaxAgeSeconds" <= 2592000)' },
	{ name: "auth_policy_assurance_max_age_ck", type: "c", definition: 'CHECK ("assuranceMaxAgeSeconds" IS NULL OR "assuranceMaxAgeSeconds" >= 60 AND "assuranceMaxAgeSeconds" <= 2592000)' },
	{ name: "auth_policy_cross_fields_ck", type: "c", definition: 'CHECK (("minimumAssurance" = \'single_factor\'::text OR "allowedFactorTotp" OR "allowedFactorPasskey") AND ("minimumAssurance" <> \'phishing_resistant\'::text OR "allowedFactorPasskey" AND NOT "trustedDeviceEnabled"))' },
] as const;

const OVERRIDE_CONSTRAINTS: readonly ExpectedConstraint[] = [
	{ name: "auth_policy_org_override_pkey", type: "p", definition: 'PRIMARY KEY ("projectId", "environmentId", "organizationId")' },
	{ name: "auth_policy_org_override_revision_ck", type: "c", definition: "CHECK (revision > 0)" },
	{ name: "auth_policy_org_override_password_ck", type: "c", definition: 'CHECK (("passwordLockoutMaxFailedAttempts" IS NULL OR "passwordLockoutMaxFailedAttempts" >= 3 AND "passwordLockoutMaxFailedAttempts" <= 100) AND ("passwordLockoutDurationSeconds" IS NULL OR "passwordLockoutDurationSeconds" >= 30 AND "passwordLockoutDurationSeconds" <= 86400))' },
	{ name: "auth_policy_org_override_factor_ck", type: "c", definition: 'CHECK (("factorLockoutMaxFailedAttempts" IS NULL OR "factorLockoutMaxFailedAttempts" >= 3 AND "factorLockoutMaxFailedAttempts" <= 100) AND ("factorLockoutDurationSeconds" IS NULL OR "factorLockoutDurationSeconds" >= 30 AND "factorLockoutDurationSeconds" <= 86400))' },
	{ name: "auth_policy_org_override_assurance_ck", type: "c", definition: 'CHECK ("minimumAssurance" IS NULL OR ("minimumAssurance" = ANY (ARRAY[\'single_factor\'::text, \'multi_factor\'::text, \'phishing_resistant\'::text])))' },
	{ name: "auth_policy_org_override_trusted_ck", type: "c", definition: 'CHECK ("trustedDeviceMaxAgeSeconds" IS NULL OR "trustedDeviceMaxAgeSeconds" >= CASE WHEN "trustedDeviceEnabled" IS TRUE THEN 60 ELSE 0 END AND "trustedDeviceMaxAgeSeconds" <= 2592000)' },
	{ name: "auth_policy_org_override_max_age_ck", type: "c", definition: 'CHECK (NOT "assuranceMaxAgeSecondsSet" AND "assuranceMaxAgeSeconds" IS NULL OR "assuranceMaxAgeSecondsSet" AND ("assuranceMaxAgeSeconds" IS NULL OR "assuranceMaxAgeSeconds" >= 60 AND "assuranceMaxAgeSeconds" <= 2592000))' },
	{ name: "auth_policy_org_override_cross_ck", type: "c", definition: 'CHECK (("minimumAssurance" IS DISTINCT FROM \'multi_factor\'::text AND "minimumAssurance" IS DISTINCT FROM \'phishing_resistant\'::text OR "allowedFactorTotp" IS DISTINCT FROM false OR "allowedFactorPasskey" IS DISTINCT FROM false) AND ("minimumAssurance" IS DISTINCT FROM \'phishing_resistant\'::text OR "allowedFactorPasskey" IS DISTINCT FROM false AND "trustedDeviceEnabled" IS DISTINCT FROM true))' },
	{ name: "auth_policy_org_override_policy_fk", type: "f", definition: 'FOREIGN KEY ("projectId", "environmentId") REFERENCES "authenticationPolicy"("projectId", "environmentId") ON DELETE CASCADE' },
	{ name: "auth_policy_org_override_org_fk", type: "f", definition: 'FOREIGN KEY ("organizationId") REFERENCES organization(id) ON DELETE CASCADE' },
] as const;

const EXPECTED_TABLE_CATALOG_JSON = JSON.stringify([
	{ tableName: POLICY_TABLE, relkind: "r", persistence: "p" },
	{ tableName: OVERRIDE_TABLE, relkind: "r", persistence: "p" },
]);

const EXPECTED_COLUMN_CATALOG_JSON = JSON.stringify(
	[
		...POLICY_COLUMNS.map((column, ordinal) => ({
			tableName: POLICY_TABLE,
			ordinal: ordinal + 1,
			columnName: column.name,
			dataType: column.dataType,
			nullable: column.nullable,
			defaultValue:
				column.defaultKind === "now"
					? "now()"
					: column.defaultKind === "false"
						? "false"
						: null,
		})),
		...OVERRIDE_COLUMNS.map((column, ordinal) => ({
			tableName: OVERRIDE_TABLE,
			ordinal: ordinal + 1,
			columnName: column.name,
			dataType: column.dataType,
			nullable: column.nullable,
			defaultValue:
				column.defaultKind === "now"
					? "now()"
					: column.defaultKind === "false"
						? "false"
						: null,
		})),
	],
);

const EXPECTED_CONSTRAINT_CATALOG_JSON = JSON.stringify(
	[
		...POLICY_CONSTRAINTS.map((constraint) => ({
			tableName: POLICY_TABLE,
			constraintName: constraint.name,
			constraintType: constraint.type,
			validated: true,
			definition: normalizeDefinition(constraint.definition),
		})).sort((left, right) =>
			left.constraintName < right.constraintName
				? -1
				: left.constraintName > right.constraintName
					? 1
					: 0,
		),
		...OVERRIDE_CONSTRAINTS.map((constraint) => ({
			tableName: OVERRIDE_TABLE,
			constraintName: constraint.name,
			constraintType: constraint.type,
			validated: true,
			definition: normalizeDefinition(constraint.definition),
		})).sort((left, right) =>
			left.constraintName < right.constraintName
				? -1
				: left.constraintName > right.constraintName
					? 1
					: 0,
		),
	],
);

const CREATE_POLICY_SQL = `CREATE TABLE "${POLICY_TABLE}" (
	"projectId" text NOT NULL,
	"environmentId" text NOT NULL,
	revision bigint NOT NULL,
	"passwordLockoutEnabled" boolean NOT NULL,
	"passwordLockoutMaxFailedAttempts" integer NOT NULL,
	"passwordLockoutDurationSeconds" integer NOT NULL,
	"factorLockoutEnabled" boolean NOT NULL,
	"factorLockoutMaxFailedAttempts" integer NOT NULL,
	"factorLockoutDurationSeconds" integer NOT NULL,
	"minimumAssurance" text NOT NULL,
	"allowedFactorTotp" boolean NOT NULL,
	"allowedFactorPasskey" boolean NOT NULL,
	"trustedDeviceEnabled" boolean NOT NULL,
	"trustedDeviceMaxAgeSeconds" integer NOT NULL,
	"assuranceMaxAgeSeconds" integer,
	"createdAt" timestamptz NOT NULL DEFAULT now(),
	"updatedAt" timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT auth_policy_pkey PRIMARY KEY ("projectId", "environmentId"),
	CONSTRAINT auth_policy_revision_ck CHECK (revision > 0),
	CONSTRAINT auth_policy_password_lockout_ck CHECK (
		"passwordLockoutMaxFailedAttempts" BETWEEN 3 AND 100
		AND "passwordLockoutDurationSeconds" BETWEEN 30 AND 86400
	),
	CONSTRAINT auth_policy_factor_lockout_ck CHECK (
		"factorLockoutMaxFailedAttempts" BETWEEN 3 AND 100
		AND "factorLockoutDurationSeconds" BETWEEN 30 AND 86400
	),
	CONSTRAINT auth_policy_minimum_assurance_ck CHECK (
		"minimumAssurance" IN ('single_factor', 'multi_factor', 'phishing_resistant')
	),
	CONSTRAINT auth_policy_trusted_device_ck CHECK (
		"trustedDeviceMaxAgeSeconds" BETWEEN
			(CASE WHEN "trustedDeviceEnabled" THEN 60 ELSE 0 END) AND 2592000
	),
	CONSTRAINT auth_policy_assurance_max_age_ck CHECK (
		"assuranceMaxAgeSeconds" IS NULL
		OR "assuranceMaxAgeSeconds" BETWEEN 60 AND 2592000
	),
	CONSTRAINT auth_policy_cross_fields_ck CHECK (
		("minimumAssurance" = 'single_factor' OR "allowedFactorTotp" OR "allowedFactorPasskey")
		AND (
			"minimumAssurance" <> 'phishing_resistant'
			OR ("allowedFactorPasskey" AND NOT "trustedDeviceEnabled")
		)
	)
)`;

const CREATE_OVERRIDE_SQL = `CREATE TABLE "${OVERRIDE_TABLE}" (
	"projectId" text NOT NULL,
	"environmentId" text NOT NULL,
	"organizationId" text NOT NULL,
	revision bigint NOT NULL,
	"passwordLockoutEnabled" boolean,
	"passwordLockoutMaxFailedAttempts" integer,
	"passwordLockoutDurationSeconds" integer,
	"factorLockoutEnabled" boolean,
	"factorLockoutMaxFailedAttempts" integer,
	"factorLockoutDurationSeconds" integer,
	"minimumAssurance" text,
	"allowedFactorTotp" boolean,
	"allowedFactorPasskey" boolean,
	"trustedDeviceEnabled" boolean,
	"trustedDeviceMaxAgeSeconds" integer,
	"assuranceMaxAgeSecondsSet" boolean NOT NULL DEFAULT false,
	"assuranceMaxAgeSeconds" integer,
	"createdAt" timestamptz NOT NULL DEFAULT now(),
	"updatedAt" timestamptz NOT NULL DEFAULT now(),
	CONSTRAINT auth_policy_org_override_pkey PRIMARY KEY (
		"projectId", "environmentId", "organizationId"
	),
	CONSTRAINT auth_policy_org_override_revision_ck CHECK (revision > 0),
	CONSTRAINT auth_policy_org_override_password_ck CHECK (
		("passwordLockoutMaxFailedAttempts" IS NULL OR "passwordLockoutMaxFailedAttempts" BETWEEN 3 AND 100)
		AND ("passwordLockoutDurationSeconds" IS NULL OR "passwordLockoutDurationSeconds" BETWEEN 30 AND 86400)
	),
	CONSTRAINT auth_policy_org_override_factor_ck CHECK (
		("factorLockoutMaxFailedAttempts" IS NULL OR "factorLockoutMaxFailedAttempts" BETWEEN 3 AND 100)
		AND ("factorLockoutDurationSeconds" IS NULL OR "factorLockoutDurationSeconds" BETWEEN 30 AND 86400)
	),
	CONSTRAINT auth_policy_org_override_assurance_ck CHECK (
		"minimumAssurance" IS NULL
		OR "minimumAssurance" IN ('single_factor', 'multi_factor', 'phishing_resistant')
	),
	CONSTRAINT auth_policy_org_override_trusted_ck CHECK (
		"trustedDeviceMaxAgeSeconds" IS NULL
		OR "trustedDeviceMaxAgeSeconds" BETWEEN
			(CASE WHEN "trustedDeviceEnabled" IS TRUE THEN 60 ELSE 0 END) AND 2592000
	),
	CONSTRAINT auth_policy_org_override_max_age_ck CHECK (
		(NOT "assuranceMaxAgeSecondsSet" AND "assuranceMaxAgeSeconds" IS NULL)
		OR (
			"assuranceMaxAgeSecondsSet"
			AND ("assuranceMaxAgeSeconds" IS NULL OR "assuranceMaxAgeSeconds" BETWEEN 60 AND 2592000)
		)
	),
	CONSTRAINT auth_policy_org_override_cross_ck CHECK (
		(
			"minimumAssurance" IS DISTINCT FROM 'multi_factor'
			AND "minimumAssurance" IS DISTINCT FROM 'phishing_resistant'
			OR "allowedFactorTotp" IS DISTINCT FROM false
			OR "allowedFactorPasskey" IS DISTINCT FROM false
		)
		AND (
			"minimumAssurance" IS DISTINCT FROM 'phishing_resistant'
			OR (
				"allowedFactorPasskey" IS DISTINCT FROM false
				AND "trustedDeviceEnabled" IS DISTINCT FROM true
			)
		)
	),
	CONSTRAINT auth_policy_org_override_policy_fk FOREIGN KEY ("projectId", "environmentId")
		REFERENCES "${POLICY_TABLE}" ("projectId", "environmentId") ON DELETE CASCADE,
	CONSTRAINT auth_policy_org_override_org_fk FOREIGN KEY ("organizationId")
		REFERENCES organization (id) ON DELETE CASCADE
)`;

type CatalogState = Readonly<{
	policyExists: boolean;
	overrideExists: boolean;
	scopeExists: boolean;
	scopeRevision?: string;
	scopePolicy?: RuntimeAuthenticationPolicy;
}>;

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
	constraint_type: "p" | "f" | "c";
	validated: boolean;
	definition: string;
};

type TableRow = {
	table_name: string;
	relkind: string;
	persistence: string;
};

type PolicyRow = {
	revision: unknown;
	passwordLockoutEnabled: unknown;
	passwordLockoutMaxFailedAttempts: unknown;
	passwordLockoutDurationSeconds: unknown;
	factorLockoutEnabled: unknown;
	factorLockoutMaxFailedAttempts: unknown;
	factorLockoutDurationSeconds: unknown;
	minimumAssurance: unknown;
	allowedFactorTotp: unknown;
	allowedFactorPasskey: unknown;
	trustedDeviceEnabled: unknown;
	trustedDeviceMaxAgeSeconds: unknown;
	assuranceMaxAgeSeconds: unknown;
};

type ReaderRow = PolicyRow & {
	projectId: unknown;
	environmentId: unknown;
	subjectId: unknown;
	organizationId: unknown;
	overrideRevision: unknown;
	overridePasswordLockoutEnabled: unknown;
	overridePasswordLockoutMaxFailedAttempts: unknown;
	overridePasswordLockoutDurationSeconds: unknown;
	overrideFactorLockoutEnabled: unknown;
	overrideFactorLockoutMaxFailedAttempts: unknown;
	overrideFactorLockoutDurationSeconds: unknown;
	overrideMinimumAssurance: unknown;
	overrideAllowedFactorTotp: unknown;
	overrideAllowedFactorPasskey: unknown;
	overrideTrustedDeviceEnabled: unknown;
	overrideTrustedDeviceMaxAgeSeconds: unknown;
	overrideAssuranceMaxAgeSecondsSet: unknown;
	overrideAssuranceMaxAgeSeconds: unknown;
};

function authorityError(message: string, cause?: unknown): PostgresAuthenticationPolicyAuthorityError {
	return new PostgresAuthenticationPolicyAuthorityError(message, cause === undefined ? undefined : { cause });
}

function identifier(value: unknown, label: string): string {
	if (
		typeof value !== "string" ||
		value.length === 0 ||
		value.length > 1_024 ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		throw authorityError(`${label} is invalid`);
	}
	return value;
}

function canonicalRevision(value: unknown): string {
	const text = typeof value === "bigint" ? value.toString() : value;
	if (typeof text !== "string" || !/^[1-9]\d*$/.test(text)) {
		throw authorityError("Authentication policy revision is invalid");
	}
	let parsed: bigint;
	try {
		parsed = BigInt(text);
	} catch (error) {
		throw authorityError("Authentication policy revision is invalid", error);
	}
	if (parsed <= 0n || parsed > POSTGRES_BIGINT_MAX) {
		throw authorityError("Authentication policy revision is invalid");
	}
	return text;
}

function normalizeDefinition(value: string): string {
	return value.replace(/\s+/g, " ").trim();
}

function defaultMatches(actual: string | null, kind: ExpectedColumn["defaultKind"]): boolean {
	if (!kind) return actual === null;
	if (kind === "now") return actual === "now()";
	return actual === "false";
}

function assertColumns(
	table: string,
	actualRows: readonly ColumnRow[],
	expected: readonly ExpectedColumn[],
): void {
	const actual = actualRows.filter((row) => row.table_name === table);
	if (actual.length !== expected.length) {
		throw authorityError(`PostgreSQL authentication-policy table ${table} has incompatible columns`);
	}
	for (const column of expected) {
		const found = actual.find((row) => row.column_name === column.name);
		if (
			!found ||
			found.data_type !== column.dataType ||
			(found.is_nullable === "YES") !== column.nullable ||
			!defaultMatches(found.column_default, column.defaultKind)
		) {
			throw authorityError(`PostgreSQL authentication-policy table ${table} has incompatible column ${column.name}`);
		}
	}
}

function assertConstraints(
	table: string,
	actualRows: readonly ConstraintRow[],
	expected: readonly ExpectedConstraint[],
): void {
	const actual = actualRows.filter((row) => row.table_name === table);
	if (actual.length !== expected.length) {
		throw authorityError(`PostgreSQL authentication-policy table ${table} has incompatible constraints`);
	}
	for (const constraint of expected) {
		const found = actual.find((row) => row.constraint_name === constraint.name);
		if (
			!found ||
			found.constraint_type !== constraint.type ||
			found.validated !== true ||
			normalizeDefinition(found.definition) !== normalizeDefinition(constraint.definition)
		) {
			throw authorityError(
				`PostgreSQL authentication-policy table ${table} has incompatible constraint ${constraint.name}: ${found?.definition ?? "missing"}`,
			);
		}
	}
}

function decodeEnvironmentPolicy(row: PolicyRow): RuntimeAuthenticationPolicy {
	return normalizeRuntimeAuthenticationPolicy({
		passwordLockout: {
			enabled: row.passwordLockoutEnabled,
			maxFailedAttempts: row.passwordLockoutMaxFailedAttempts,
			durationSeconds: row.passwordLockoutDurationSeconds,
		},
		factorLockout: {
			enabled: row.factorLockoutEnabled,
			maxFailedAttempts: row.factorLockoutMaxFailedAttempts,
			durationSeconds: row.factorLockoutDurationSeconds,
		},
		minimumAssurance: row.minimumAssurance,
		allowedFactors: {
			totp: row.allowedFactorTotp,
			passkey: row.allowedFactorPasskey,
		},
		trustedDevice: {
			enabled: row.trustedDeviceEnabled,
			maxAgeSeconds: row.trustedDeviceMaxAgeSeconds,
		},
		assuranceMaxAgeSeconds: row.assuranceMaxAgeSeconds,
	});
}

function setIfPresent(
	target: Record<string, unknown>,
	key: string,
	value: unknown,
): void {
	if (value !== null && value !== undefined) target[key] = value;
}

function decodeOverride(row: ReaderRow): RuntimeAuthenticationPolicyOverride | null {
	if (row.overrideRevision === null || row.overrideRevision === undefined) return null;
	const passwordLockout: Record<string, unknown> = {};
	setIfPresent(passwordLockout, "enabled", row.overridePasswordLockoutEnabled);
	setIfPresent(passwordLockout, "maxFailedAttempts", row.overridePasswordLockoutMaxFailedAttempts);
	setIfPresent(passwordLockout, "durationSeconds", row.overridePasswordLockoutDurationSeconds);
	const factorLockout: Record<string, unknown> = {};
	setIfPresent(factorLockout, "enabled", row.overrideFactorLockoutEnabled);
	setIfPresent(factorLockout, "maxFailedAttempts", row.overrideFactorLockoutMaxFailedAttempts);
	setIfPresent(factorLockout, "durationSeconds", row.overrideFactorLockoutDurationSeconds);
	const allowedFactors: Record<string, unknown> = {};
	setIfPresent(allowedFactors, "totp", row.overrideAllowedFactorTotp);
	setIfPresent(allowedFactors, "passkey", row.overrideAllowedFactorPasskey);
	const trustedDevice: Record<string, unknown> = {};
	setIfPresent(trustedDevice, "enabled", row.overrideTrustedDeviceEnabled);
	setIfPresent(trustedDevice, "maxAgeSeconds", row.overrideTrustedDeviceMaxAgeSeconds);
	const override: Record<string, unknown> = {};
	if (Object.keys(passwordLockout).length > 0) override.passwordLockout = passwordLockout;
	if (Object.keys(factorLockout).length > 0) override.factorLockout = factorLockout;
	setIfPresent(override, "minimumAssurance", row.overrideMinimumAssurance);
	if (Object.keys(allowedFactors).length > 0) override.allowedFactors = allowedFactors;
	if (Object.keys(trustedDevice).length > 0) override.trustedDevice = trustedDevice;
	if (row.overrideAssuranceMaxAgeSecondsSet === true) {
		override.assuranceMaxAgeSeconds = row.overrideAssuranceMaxAgeSeconds;
	} else if (row.overrideAssuranceMaxAgeSecondsSet !== false) {
		throw authorityError("Authentication policy override is invalid");
	}
	return normalizeRuntimeAuthenticationPolicyOverride(override);
}

function sqlLiteral(value: string): string {
	return `'${value.replaceAll("'", "''")}'`;
}

function nullableIntegerLiteral(value: number | null): string {
	return value === null ? "NULL" : String(value);
}

function seedSql(identity: RuntimeAuthenticationPolicyIdentity, policy: RuntimeAuthenticationPolicy): string {
	return `INSERT INTO "${POLICY_TABLE}" (
	"projectId", "environmentId", revision,
	"passwordLockoutEnabled", "passwordLockoutMaxFailedAttempts", "passwordLockoutDurationSeconds",
	"factorLockoutEnabled", "factorLockoutMaxFailedAttempts", "factorLockoutDurationSeconds",
	"minimumAssurance", "allowedFactorTotp", "allowedFactorPasskey",
	"trustedDeviceEnabled", "trustedDeviceMaxAgeSeconds", "assuranceMaxAgeSeconds"
) VALUES (
	${sqlLiteral(identity.projectId)}, ${sqlLiteral(identity.environmentId)}, 1,
	${policy.passwordLockout.enabled}, ${policy.passwordLockout.maxFailedAttempts}, ${policy.passwordLockout.durationSeconds},
	${policy.factorLockout.enabled}, ${policy.factorLockout.maxFailedAttempts}, ${policy.factorLockout.durationSeconds},
	${sqlLiteral(policy.minimumAssurance)}, ${policy.allowedFactors.totp}, ${policy.allowedFactors.passkey},
	${policy.trustedDevice.enabled}, ${policy.trustedDevice.maxAgeSeconds}, ${nullableIntegerLiteral(policy.assuranceMaxAgeSeconds)}
) ON CONFLICT ("projectId", "environmentId") DO NOTHING`;
}

function samePolicy(left: RuntimeAuthenticationPolicy, right: RuntimeAuthenticationPolicy): boolean {
	return JSON.stringify(left) === JSON.stringify(right);
}

async function inspectCatalog(
	queryable: Queryable,
	identity: RuntimeAuthenticationPolicyIdentity,
): Promise<CatalogState> {
	const tables = await queryable.query<TableRow>(
		`SELECT c.relname AS table_name,
		        c.relkind,
		        c.relpersistence AS persistence
		 FROM pg_class c
		 JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = current_schema()
		   AND c.relname = ANY($1::text[])`,
		[[POLICY_TABLE, OVERRIDE_TABLE]],
	);
	const incompatibleTable = tables.rows.find(
		(row) => row.relkind !== "r" || row.persistence !== "p",
	);
	if (incompatibleTable) {
		throw authorityError(
			`PostgreSQL authentication-policy authority ${incompatibleTable.table_name} must be an ordinary permanent table`,
		);
	}
	const policyExists = tables.rows.some((row) => row.table_name === POLICY_TABLE);
	const overrideExists = tables.rows.some((row) => row.table_name === OVERRIDE_TABLE);
	if (!policyExists && overrideExists) {
		throw authorityError("PostgreSQL authentication-policy authority is partially installed");
	}
	if (!policyExists) return { policyExists: false, overrideExists: false, scopeExists: false };

	const columns = await queryable.query<ColumnRow>(
		`SELECT table_name, column_name, data_type, is_nullable, column_default
		 FROM information_schema.columns
		 WHERE table_schema = current_schema()
		   AND table_name = ANY($1::text[])
		 ORDER BY table_name, ordinal_position`,
		[[POLICY_TABLE, OVERRIDE_TABLE]],
	);
	assertColumns(POLICY_TABLE, columns.rows, POLICY_COLUMNS);
	if (overrideExists) assertColumns(OVERRIDE_TABLE, columns.rows, OVERRIDE_COLUMNS);

	const constraints = await queryable.query<ConstraintRow>(
		`SELECT table_class.relname AS table_name,
		        constraint_row.conname AS constraint_name,
		        constraint_row.contype AS constraint_type,
		        constraint_row.convalidated AS validated,
		        pg_get_constraintdef(constraint_row.oid, true) AS definition
		 FROM pg_constraint constraint_row
		 JOIN pg_class table_class ON table_class.oid = constraint_row.conrelid
		 JOIN pg_namespace n ON n.oid = table_class.relnamespace
		 WHERE n.nspname = current_schema()
		   AND table_class.relname = ANY($1::text[])
		 ORDER BY table_class.relname, constraint_row.conname`,
		[[POLICY_TABLE, OVERRIDE_TABLE]],
	);
	assertConstraints(POLICY_TABLE, constraints.rows, POLICY_CONSTRAINTS);
	if (overrideExists) assertConstraints(OVERRIDE_TABLE, constraints.rows, OVERRIDE_CONSTRAINTS);

	const scope = await queryable.query<PolicyRow>(
		`SELECT revision::text AS revision,
		        "passwordLockoutEnabled", "passwordLockoutMaxFailedAttempts", "passwordLockoutDurationSeconds",
		        "factorLockoutEnabled", "factorLockoutMaxFailedAttempts", "factorLockoutDurationSeconds",
		        "minimumAssurance", "allowedFactorTotp", "allowedFactorPasskey",
		        "trustedDeviceEnabled", "trustedDeviceMaxAgeSeconds", "assuranceMaxAgeSeconds"
		 FROM "${POLICY_TABLE}"
		 WHERE "projectId" = $1 AND "environmentId" = $2`,
		[identity.projectId, identity.environmentId],
	);
	if (scope.rows.length > 1) {
		throw authorityError("PostgreSQL authentication-policy scope is not unique");
	}
	const row = scope.rows[0];
	if (!row) return { policyExists, overrideExists, scopeExists: false };
	return {
		policyExists,
		overrideExists,
		scopeExists: true,
		scopeRevision: canonicalRevision(row.revision),
		scopePolicy: decodeEnvironmentPolicy(row),
	};
}

const READ_SQL = `WITH catalog_tables AS (
	SELECT COALESCE(
		jsonb_agg(
			jsonb_build_object(
				'tableName', relation.relname,
				'relkind', relation.relkind::text,
				'persistence', relation.relpersistence::text
			)
			ORDER BY CASE relation.relname
				WHEN '${POLICY_TABLE}' THEN 0
				ELSE 1
			END
		),
		'[]'::jsonb
	) AS value
	FROM pg_class relation
	JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
	WHERE namespace.nspname = current_schema()
		AND relation.relname IN ('${POLICY_TABLE}', '${OVERRIDE_TABLE}')
), catalog_columns AS (
	SELECT COALESCE(
		jsonb_agg(
			jsonb_build_object(
				'tableName', columns.table_name,
				'ordinal', columns.ordinal_position,
				'columnName', columns.column_name,
				'dataType', columns.data_type,
				'nullable', columns.is_nullable = 'YES',
				'defaultValue', columns.column_default
			)
			ORDER BY CASE columns.table_name
				WHEN '${POLICY_TABLE}' THEN 0
				ELSE 1
			END, columns.ordinal_position
		),
		'[]'::jsonb
	) AS value
	FROM information_schema.columns columns
	WHERE columns.table_schema = current_schema()
		AND columns.table_name IN ('${POLICY_TABLE}', '${OVERRIDE_TABLE}')
), catalog_constraints AS (
	SELECT COALESCE(
		jsonb_agg(
			jsonb_build_object(
				'tableName', relation.relname,
				'constraintName', constraint_row.conname,
				'constraintType', constraint_row.contype::text,
				'validated', constraint_row.convalidated,
				'definition', btrim(regexp_replace(
					pg_get_constraintdef(constraint_row.oid, true),
					'[[:space:]]+',
					' ',
					'g'
				))
			)
			ORDER BY CASE relation.relname
				WHEN '${POLICY_TABLE}' THEN 0
				ELSE 1
			END, constraint_row.conname COLLATE "C"
		),
		'[]'::jsonb
	) AS value
	FROM pg_constraint constraint_row
	JOIN pg_class relation ON relation.oid = constraint_row.conrelid
	JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
	WHERE namespace.nspname = current_schema()
		AND relation.relname IN ('${POLICY_TABLE}', '${OVERRIDE_TABLE}')
), catalog_ready AS (
	SELECT 1
	FROM catalog_tables tables,
		catalog_columns columns,
		catalog_constraints constraints
	WHERE tables.value = $6::jsonb
		AND columns.value = $7::jsonb
		AND constraints.value = $8::jsonb
), requested_subject AS (
	SELECT id
	FROM "user"
	WHERE id = $3
), requested_organization AS (
	SELECT $4::text AS id
	WHERE $4::text IS NULL
	   OR (
		EXISTS (SELECT 1 FROM organization WHERE id = $4)
		AND EXISTS (
			SELECT 1 FROM member
			WHERE "organizationId" = $4 AND "userId" = $3
		)
	   )
)
SELECT policy."projectId" AS "projectId",
	policy."environmentId" AS "environmentId",
	requested_subject.id AS "subjectId",
	requested_organization.id AS "organizationId",
	policy.revision::text AS revision,
	policy."passwordLockoutEnabled", policy."passwordLockoutMaxFailedAttempts", policy."passwordLockoutDurationSeconds",
	policy."factorLockoutEnabled", policy."factorLockoutMaxFailedAttempts", policy."factorLockoutDurationSeconds",
	policy."minimumAssurance", policy."allowedFactorTotp", policy."allowedFactorPasskey",
	policy."trustedDeviceEnabled", policy."trustedDeviceMaxAgeSeconds", policy."assuranceMaxAgeSeconds",
	override.revision::text AS "overrideRevision",
	override."passwordLockoutEnabled" AS "overridePasswordLockoutEnabled",
	override."passwordLockoutMaxFailedAttempts" AS "overridePasswordLockoutMaxFailedAttempts",
	override."passwordLockoutDurationSeconds" AS "overridePasswordLockoutDurationSeconds",
	override."factorLockoutEnabled" AS "overrideFactorLockoutEnabled",
	override."factorLockoutMaxFailedAttempts" AS "overrideFactorLockoutMaxFailedAttempts",
	override."factorLockoutDurationSeconds" AS "overrideFactorLockoutDurationSeconds",
	override."minimumAssurance" AS "overrideMinimumAssurance",
	override."allowedFactorTotp" AS "overrideAllowedFactorTotp",
	override."allowedFactorPasskey" AS "overrideAllowedFactorPasskey",
	override."trustedDeviceEnabled" AS "overrideTrustedDeviceEnabled",
	override."trustedDeviceMaxAgeSeconds" AS "overrideTrustedDeviceMaxAgeSeconds",
	override."assuranceMaxAgeSecondsSet" AS "overrideAssuranceMaxAgeSecondsSet",
	override."assuranceMaxAgeSeconds" AS "overrideAssuranceMaxAgeSeconds"
FROM "${POLICY_TABLE}" policy
JOIN catalog_ready ON true
JOIN requested_subject ON true
JOIN requested_organization ON true
LEFT JOIN "${OVERRIDE_TABLE}" override
	ON $4::text IS NOT NULL
	AND override."projectId" = policy."projectId"
	AND override."environmentId" = policy."environmentId"
	AND override."organizationId" = $4
WHERE policy."projectId" = $1
	AND policy."environmentId" = $2
	AND ($5::bigint IS NULL OR policy.revision >= $5::bigint)`;

export class PostgresAuthenticationPolicyAuthority implements RuntimeAuthenticationPolicyReader {
	readonly identity: RuntimeAuthenticationPolicyIdentity;
	readonly initialPolicy: RuntimeAuthenticationPolicy;

	constructor(
		private readonly pool: pg.Pool,
		identityInput: RuntimeAuthenticationPolicyIdentity,
		seed: RuntimeAuthenticationPolicy,
	) {
		this.identity = Object.freeze({
			projectId: identifier(identityInput.projectId, "Authentication policy projectId"),
			environmentId: identifier(identityInput.environmentId, "Authentication policy environmentId"),
		});
		this.initialPolicy = normalizeRuntimeAuthenticationPolicy(seed);
	}

	async plan(): Promise<AuthenticationPolicyAuthorityMigrationPlan> {
		const state = await inspectCatalog(this.pool, this.identity);
		const pendingTables = Number(!state.policyExists) + Number(!state.overrideExists);
		const pendingFields =
			(state.policyExists ? 0 : POLICY_COLUMNS.length) +
			(state.overrideExists ? 0 : OVERRIDE_COLUMNS.length);
		const pending = pendingTables > 0 || !state.scopeExists;
		const statements = [
			...(state.policyExists ? [] : [CREATE_POLICY_SQL]),
			...(state.overrideExists ? [] : [CREATE_OVERRIDE_SQL]),
			...(state.scopeExists ? [] : [seedSql(this.identity, this.initialPolicy)]),
		];
		return {
			pendingTables,
			pendingFields,
			pendingSecurityMigrations: pending ? [MIGRATION_ID] : [],
			compileSql: async () => statements.map((statement) => `${statement};`).join("\n"),
			apply: () => this.applyMigration(),
		};
	}

	private async applyMigration(): Promise<void> {
		const client = await this.pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(
				"SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':clearance:authentication-policy-authority:v1', 0))",
			);
			const before = await inspectCatalog(client, this.identity);
			if (!before.policyExists) await client.query(CREATE_POLICY_SQL);
			if (!before.overrideExists) await client.query(CREATE_OVERRIDE_SQL);
			if (!before.scopeExists) {
				await client.query(seedSql(this.identity, this.initialPolicy));
			}
			const after = await inspectCatalog(client, this.identity);
			if (!after.policyExists || !after.overrideExists || !after.scopeExists) {
				throw authorityError("PostgreSQL authentication-policy authority verification failed");
			}
			if (
				!before.scopeExists &&
				(after.scopeRevision !== "1" ||
					!after.scopePolicy ||
					!samePolicy(after.scopePolicy, this.initialPolicy))
			) {
				throw authorityError("PostgreSQL authentication-policy seed verification failed");
			}
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			if (error instanceof PostgresAuthenticationPolicyAuthorityError) throw error;
			throw authorityError("PostgreSQL authentication-policy migration failed", error);
		} finally {
			client.release();
		}
	}

	async readForSubject(
		input: RuntimeAuthenticationPolicyReaderInput,
	): Promise<RuntimeAuthenticationPolicyReaderResult> {
		const subjectId = identifier(input.subjectId, "Authentication policy subjectId");
		const organizationId = input.organizationId === undefined
			? undefined
			: identifier(input.organizationId, "Authentication policy organizationId");
		const minimumRevision = input.minimumRevision === undefined
			? null
			: canonicalRevision(input.minimumRevision);
		let query: <Row extends Record<string, unknown>>(
			text: string,
			values?: readonly unknown[],
		) => QueryResult<Row>;
		if (input.transaction !== undefined) {
			if (typeof input.transaction.rawTransactionQuery !== "function") {
				throw authorityError("Ambient PostgreSQL authentication-policy transaction is unavailable");
			}
			query = input.transaction.rawTransactionQuery.bind(input.transaction);
		} else {
			query = this.pool.query.bind(this.pool) as typeof query;
		}

		let result: { rows: ReaderRow[]; rowCount: number | null };
		try {
			result = await query<ReaderRow>(READ_SQL, [
				this.identity.projectId,
				this.identity.environmentId,
				subjectId,
				organizationId ?? null,
				minimumRevision,
				EXPECTED_TABLE_CATALOG_JSON,
				EXPECTED_COLUMN_CATALOG_JSON,
				EXPECTED_CONSTRAINT_CATALOG_JSON,
			]);
		} catch (error) {
			if (error instanceof PostgresAuthenticationPolicyAuthorityError) throw error;
			throw authorityError("PostgreSQL authentication-policy read failed", error);
		}
		if (result.rows.length !== 1) {
			throw authorityError("PostgreSQL authentication-policy authority returned no exact subject scope");
		}
		const row = result.rows[0]!;
		if (
			row.projectId !== this.identity.projectId ||
			row.environmentId !== this.identity.environmentId ||
			row.subjectId !== subjectId ||
			row.organizationId !== (organizationId ?? null)
		) {
			throw authorityError("PostgreSQL authentication-policy authority returned a mismatched scope");
		}
		const revision = canonicalRevision(row.revision);
		const environment = decodeEnvironmentPolicy(row);
		const overridePolicy = decodeOverride(row);
		const overrideRevision = overridePolicy
			? canonicalRevision(row.overrideRevision)
			: null;
		if (overrideRevision && BigInt(overrideRevision) > BigInt(revision)) {
			throw authorityError("Authentication policy override revision exceeds environment revision");
		}
		const effective = applyRuntimeAuthenticationPolicyOverride(
			environment,
			overridePolicy ?? {},
		);
		return Object.freeze({
			scope: this.identity,
			subjectId,
			revision,
			environment,
			organizationMembership: organizationId
				? Object.freeze({ subjectId, organizationId })
				: null,
			organizationOverride: organizationId && overridePolicy && overrideRevision
				? Object.freeze({
						scope: this.identity,
						organizationId,
						revision: overrideRevision,
						policy: overridePolicy,
					})
				: null,
			effective,
		});
	}
}
