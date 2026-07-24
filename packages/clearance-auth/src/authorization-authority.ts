import { createHash, randomBytes, randomUUID } from "node:crypto";
import pg from "pg";

const POSTGRES_BIGINT_MAX = 9_223_372_036_854_775_807n;
const MAX_EFFECTIVE_ACTIONS = 256;
const MIGRATION_ID = "authorization-authority-v2";
const DEFAULT_PREFIX = "clearance";
const SERVICE_ACCOUNT_CREDENTIAL_PREFIX = "clr_sac_v1";
const SERVICE_ACCOUNT_CREDENTIAL_SECRET_BYTES = 32;
const ROLLBACK_FENCE_FUNCTION_SOURCE = `
	DECLARE
		argument_index integer := 0;
		fence_kind text;
		reference_column text;
		condition_column text;
		condition_value text;
		reference_id text;
		row_data jsonb := to_jsonb(NEW);
	BEGIN
		WHILE argument_index < TG_NARGS LOOP
			fence_kind := TG_ARGV[argument_index];
			reference_column := TG_ARGV[argument_index + 1];
			condition_column := TG_ARGV[argument_index + 2];
			condition_value := TG_ARGV[argument_index + 3];
			reference_id := row_data ->> reference_column;
			IF reference_id IS NOT NULL AND (
				condition_column = '' OR row_data ->> condition_column = condition_value
			) THEN
				PERFORM pg_advisory_xact_lock(hashtextextended(
					'clearance-import-rollback:v1:' || fence_kind || ':' || reference_id,
					0
				));
				IF EXISTS (
					SELECT 1 FROM "public"."clearance_import_rollback_tombstones"
					WHERE kind = fence_kind AND resource_id = reference_id
				) THEN
					RAISE EXCEPTION 'Clearance rollback-fenced resource cannot be referenced'
						USING ERRCODE = '23503';
				END IF;
			END IF;
			argument_index := argument_index + 4;
		END LOOP;
		RETURN NEW;
	END
`;
const SERVICE_ACCOUNT_CREDENTIAL_DIGEST_DOMAIN = "clearance:service-account-credential:v1:";
const BUILT_IN_ROLE_DEFINITIONS = Object.freeze([
	Object.freeze({
		roleId: "role_builtin_owner",
		slug: "owner",
		name: "Owner",
		description: "Full organization control including delete and access-control management",
		actions: Object.freeze(["ac:create", "ac:delete", "ac:read", "ac:update", "invitation:cancel", "invitation:create", "member:create", "member:delete", "member:update", "organization:delete", "organization:update", "team:create", "team:delete", "team:update"]),
	}),
	Object.freeze({
		roleId: "role_builtin_admin",
		slug: "admin",
		name: "Admin",
		description: "Manage members, invitations, teams, and access control (no organization delete)",
		actions: Object.freeze(["ac:create", "ac:delete", "ac:read", "ac:update", "invitation:cancel", "invitation:create", "member:create", "member:delete", "member:update", "organization:update", "team:create", "team:delete", "team:update"]),
	}),
	Object.freeze({
		roleId: "role_builtin_member",
		slug: "member",
		name: "Member",
		description: "Baseline organization membership with read access to roles",
		actions: Object.freeze(["ac:read"]),
	}),
]);

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

/**
 * Server-owned identity for the runtime organization authority. This is kept
 * out of product configuration: callers either inject the exact table they
 * own or reconciliation is unavailable.
 */
export type AuthorizationRuntimeOrganizationAuthority = Readonly<{
	schema: string;
	table: string;
	/**
	 * Optional exact normalized-management organization authority. When present,
	 * an active row protects its authorization state even if the runtime product
	 * organization row does not exist. This identity is server-owned and never
	 * comes from product configuration.
	 */
	management?: Readonly<{
		schema: string;
		table: string;
	}>;
}>;

export type AuthorizationSubject = Readonly<{
	kind: "principal" | "service_account";
	id: string;
}>;

export type AuthorizationAuthorityReadInput = Readonly<{
	organizationId: string;
	subject: AuthorizationSubject;
	transaction?: AuthorizationAuthorityTransaction;
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

export type AuthorizationAuthorityRole = Readonly<{
	roleId: string;
	organizationId: string | null;
	slug: string;
	name: string;
	description: string | null;
	builtIn: boolean;
	status: "active" | "disabled" | "archived";
	actions: readonly string[];
}>;

export type AuthorizationAuthorityRoleInput = Omit<AuthorizationAuthorityRole, "actions">;

export type AuthorizationAuthorityRevision = Readonly<{
	organizationId: string;
	revision: string;
	initialized: boolean;
}>;

export type AuthorizationAuthorityAffectedRevision = Readonly<{
	organizationId: string;
	previousRevision: string;
	revision: string;
}>;

/** Redacted result of terminalizing an organization's authorization authority. */
export type AuthorizationAuthorityArchiveOrganizationResult = Readonly<{
	organizationId: string;
	previousRevision: string;
	revision: string;
	archived: boolean;
	removedAssignments: number;
	disabledServiceAccounts: number;
	revokedCredentials: number;
}>;

export type AuthorizationAuthorityArchiveOrganizationInput = Readonly<{
	organizationId: string;
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationAuthorityReconciliationResult = Readonly<{
	terminalizedOrganizations: number;
	/** Bounded redacted identifiers for durable migration/audit evidence. */
	terminalizedOrganizationIds: readonly string[];
	removedAssignments: number;
	disabledServiceAccounts: number;
	revokedCredentials: number;
}>;

export type AuthorizationAuthorityUpsertRoleInput = Readonly<{
	role: AuthorizationAuthorityRoleInput;
	actions: readonly string[];
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationAuthorityUpsertRoleResult = Readonly<{
	changed: boolean;
	affectedOrganizations: readonly AuthorizationAuthorityAffectedRevision[];
}>;

export type AuthorizationAuthorityReplaceSubjectRolesInput = Readonly<{
	organizationId: string;
	subject: AuthorizationSubject;
	roleIds: readonly string[];
	expectedRevision?: string;
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationAuthorityReplaceSubjectRolesResult = Readonly<{
	changed: boolean;
	previousRevision: string;
	revision: string;
	roleIds: readonly string[];
}>;

export type AuthorizationAuthorityListRolesInput = Readonly<{
	organizationId?: string;
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationAuthorityAssignment = Readonly<{
	organizationId: string;
	subject: AuthorizationSubject;
	roleId: string;
}>;

export type AuthorizationServiceAccount = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	name: string;
	status: "active" | "disabled";
}>;

export type AuthorizationServiceAccountMutation = Readonly<{
	serviceAccount: AuthorizationServiceAccount;
	previousRevision: string;
	revision: string;
}>;

export type AuthorizationServiceAccountCredential = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	credentialId: string;
	credentialPrefix: string;
	credentialFingerprint: string;
	expiresAt: Date | null;
	version: number;
}>;

export type AuthorizationServiceAccountCredentialMutation = Readonly<{
	credential: AuthorizationServiceAccountCredential;
	secret: string;
	previousRevision: string;
	revision: string;
}>;

export type AuthorizationCreateServiceAccountInput = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	name: string;
	roleIds: readonly string[];
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationListServiceAccountsInput = Readonly<{
	organizationId: string;
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationSetServiceAccountStatusInput = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	status: "active" | "disabled";
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationCreateServiceAccountCredentialInput = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	credentialId?: string;
	expiresAt?: Date;
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationRotateServiceAccountCredentialInput = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	credentialId: string;
	expiresAt?: Date;
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationRevokeServiceAccountCredentialInput = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	credentialId: string;
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationAuthenticateServiceAccountCredentialInput = Readonly<{
	secret: string;
	transaction?: AuthorizationAuthorityTransaction;
}>;

export type AuthorizationAuthenticateServiceAccountCredentialResult = Readonly<{
	projectId: string;
	environmentId: string;
	organizationId: string;
	subject: Readonly<{ kind: "service_account"; id: string }>;
	credential: AuthorizationServiceAccountCredential;
	roleIds: readonly string[];
	actions: readonly string[];
	revision: string;
}>;

export type AuthorizationAuthorityListSubjectAssignmentsInput = Readonly<{
	organizationId: string;
	subject?: AuthorizationSubject;
	transaction?: AuthorizationAuthorityTransaction;
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
type TriggerRow = {
	table_name: string;
	trigger_name: string;
	definition: string;
	enabled: boolean;
	function_schema: string;
	function_name: string;
	function_identity: string;
	function_source: string;
	function_language: string;
	function_return_type: string;
	function_argument_count: number;
	function_security_definer: boolean;
};
type RollbackFenceTableRow = {
	relkind: string;
	persistence: string;
	column_count: number;
	has_kind: boolean;
	has_resource_id: boolean;
	has_tombstoned_at: boolean;
	has_primary_key: boolean;
};
type FunctionRow = { function_name: string; definition: string };

function error(message: string, cause?: unknown, code?: string): PostgresAuthorizationAuthorityError {
	return new PostgresAuthorizationAuthorityError(message, {
		...(cause === undefined ? {} : { cause }),
		...(code === undefined ? {} : { code }),
	});
}

function postgresErrorCode(value: unknown): string | undefined {
	if (!value || typeof value !== "object" || !("code" in value)) return undefined;
	return typeof value.code === "string" ? value.code : undefined;
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

function canonicalStringCompare(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
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
		revisions: [...scope, { name: "organizationId", dataType: "text", nullable: false }, { name: "revision", dataType: "bigint", nullable: false }, { name: "terminal", dataType: "boolean", nullable: false, default: "false" }, { name: "updatedAt", dataType: "timestamp with time zone", nullable: false, default: "now" }],
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
		assignments: [
			{ name: c("assignments_subject_idx"), definitionIncludes: ["projectid", "environmentid", "organizationid", "subjectkind", "subjectid"] },
			{ name: c("assignments_principal_subject_idx"), definitionIncludes: ["projectid", "environmentid", "subjectkind", "subjectid"] },
		],
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
			definitionIncludes: ["constraint trigger", "after insert or update", names.assignments, `${guard}()`],
		},
		{
			table: "roles",
			name: c("roles_scope_change_trg"),
			definitionIncludes: ["constraint trigger", "after update of", "organizationid", names.roles, `${guard}()`],
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
			revision bigint NOT NULL, terminal boolean NOT NULL DEFAULT false, "updatedAt" timestamptz NOT NULL DEFAULT now(),
			CONSTRAINT ${c("revisions_pk")} PRIMARY KEY ("projectId", "environmentId", "organizationId"),
			CONSTRAINT ${c("revisions_positive_ck")} CHECK (revision > 0)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${c("roles_scope_org_slug_uq")} ON ${t(names.roles)} ("projectId", "environmentId", COALESCE("organizationId", ''), slug)`,
		`CREATE INDEX IF NOT EXISTS ${c("assignments_subject_idx")} ON ${t(names.assignments)} ("projectId", "environmentId", "organizationId", "subjectKind", "subjectId")`,
		`CREATE INDEX IF NOT EXISTS ${c("assignments_principal_subject_idx")} ON ${t(names.assignments)} ("projectId", "environmentId", "subjectKind", "subjectId")`,
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

function terminalizationMigrationSql(schema: string, names: Names): string {
	return `ALTER TABLE ${qualified(schema, names.revisions)} ADD COLUMN IF NOT EXISTS terminal boolean NOT NULL DEFAULT false`;
}

function principalSubjectIndexMigrationSql(schema: string, names: Names): string {
	return `CREATE INDEX IF NOT EXISTS ${quoted(shortName(names, "assignments_principal_subject_idx"))} ON ${qualified(schema, names.assignments)} ("projectId", "environmentId", "subjectKind", "subjectId")`;
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
	const rollbackFences = actual.filter((row) => row.trigger_name === "clearance_import_rollback_guard_v1");
	if (rollbackFences.length > 1) throw error("Authorization rollback fence trigger is incompatible");
	if (rollbackFences.length === 1) {
		const [rollbackFence] = rollbackFences;
		const definition = normalize(rollbackFence.definition);
		const expectedArguments = "('organization', 'organizationId', '', '', 'principal', 'subjectId', 'subjectKind', 'principal')";
		if (
			rollbackFence.table_name !== names.assignments ||
			!rollbackFence.enabled ||
			rollbackFence.function_schema !== "public" ||
			rollbackFence.function_name !== "clearance_import_rollback_guard_v1" ||
			rollbackFence.function_identity !== "public.clearance_import_rollback_guard_v1()" ||
			rollbackFence.function_language !== "plpgsql" ||
			rollbackFence.function_return_type !== "trigger" ||
			rollbackFence.function_argument_count !== 0 ||
			rollbackFence.function_security_definer !== false ||
			!definition.includes(normalize("before insert or update")) ||
			!definition.includes(normalize("for each row")) ||
			!definition.includes(normalize(expectedArguments)) ||
			normalize(rollbackFence.function_source) !== normalize(ROLLBACK_FENCE_FUNCTION_SOURCE)
		) {
			throw error("Authorization rollback fence trigger is incompatible");
		}
	}
	const authorityTriggers = actual.filter((row) => row.trigger_name !== "clearance_import_rollback_guard_v1");
	if (authorityTriggers.length !== expected.length) throw error("Authorization triggers are incompatible");
	for (const trigger of expected) {
		const found = authorityTriggers.find((row) => row.table_name === names[trigger.table] && row.trigger_name === trigger.name);
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

type CatalogInspection = Readonly<{
	installed: boolean;
	terminalizationPending: boolean;
	principalSubjectIndexPending: boolean;
}>;

async function inspectCatalog(queryable: Queryable, schema: string, names: Names): Promise<CatalogInspection> {
	const tableNames = Object.values(names);
	const tables = await queryable.query<TableRow>(`SELECT c.relname AS table_name, c.relkind, c.relpersistence AS persistence FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = ANY($2::text[])`, [schema, tableNames]);
	if (tables.rows.length === 0) return Object.freeze({ installed: false, terminalizationPending: false, principalSubjectIndexPending: false });
	if (tables.rows.length !== tableNames.length || tables.rows.some((row) => row.relkind !== "r" || row.persistence !== "p")) throw error("PostgreSQL authorization authority is partially installed or incompatible");
	const actualColumns = await queryable.query<ColumnRow>(`SELECT table_name, column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = $1 AND table_name = ANY($2::text[]) ORDER BY table_name, ordinal_position`, [schema, tableNames]);
	const actualConstraints = await queryable.query<ConstraintRow>(`SELECT c.relname AS table_name, con.conname AS constraint_name, con.contype AS constraint_type, con.convalidated AS validated, pg_get_constraintdef(con.oid, true) AS definition FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = ANY($2::text[]) AND con.contype = ANY(ARRAY['p', 'u', 'f', 'c']::"char"[]) ORDER BY c.relname, con.conname`, [schema, tableNames]);
	const actualIndexes = await queryable.query<IndexRow>(`SELECT c.relname AS table_name, i.relname AS index_name, pg_get_indexdef(i.oid) AS definition FROM pg_index x JOIN pg_class c ON c.oid = x.indrelid JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_constraint con ON con.conindid = i.oid WHERE n.nspname = $1 AND c.relname = ANY($2::text[]) AND con.oid IS NULL ORDER BY c.relname, i.relname`, [schema, tableNames]);
	const actualTriggers = await queryable.query<TriggerRow>(`SELECT c.relname AS table_name, tg.tgname AS trigger_name, pg_get_triggerdef(tg.oid, true) AS definition, tg.tgenabled = 'O' AS enabled, function_namespace.nspname AS function_schema, function_record.proname AS function_name, format('%I.%I(%s)', function_namespace.nspname, function_record.proname, pg_get_function_identity_arguments(function_record.oid)) AS function_identity, function_record.prosrc AS function_source, language_record.lanname AS function_language, return_type.typname AS function_return_type, function_record.pronargs AS function_argument_count, function_record.prosecdef AS function_security_definer FROM pg_trigger tg JOIN pg_class c ON c.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_proc function_record ON function_record.oid = tg.tgfoid JOIN pg_namespace function_namespace ON function_namespace.oid = function_record.pronamespace JOIN pg_language language_record ON language_record.oid = function_record.prolang JOIN pg_type return_type ON return_type.oid = function_record.prorettype WHERE n.nspname = $1 AND c.relname = ANY($2::text[]) AND NOT tg.tgisinternal ORDER BY c.relname, tg.tgname`, [schema, tableNames]);
	const rollbackFencePresent = actualTriggers.rows.some((row) => row.trigger_name === "clearance_import_rollback_guard_v1");
	if (rollbackFencePresent) {
		const rollbackFenceTable = await queryable.query<RollbackFenceTableRow>(`SELECT c.relkind, c.relpersistence AS persistence, (SELECT count(*)::int FROM pg_attribute attribute_record WHERE attribute_record.attrelid = c.oid AND attribute_record.attnum > 0 AND NOT attribute_record.attisdropped) AS column_count, EXISTS (SELECT 1 FROM pg_attribute attribute_record WHERE attribute_record.attrelid = c.oid AND attribute_record.attname = 'kind' AND attribute_record.atttypid = 'text'::regtype AND attribute_record.attnotnull) AS has_kind, EXISTS (SELECT 1 FROM pg_attribute attribute_record WHERE attribute_record.attrelid = c.oid AND attribute_record.attname = 'resource_id' AND attribute_record.atttypid = 'text'::regtype AND attribute_record.attnotnull) AS has_resource_id, EXISTS (SELECT 1 FROM pg_attribute attribute_record WHERE attribute_record.attrelid = c.oid AND attribute_record.attname = 'tombstoned_at' AND attribute_record.atttypid = 'timestamp with time zone'::regtype AND attribute_record.attnotnull) AS has_tombstoned_at, EXISTS (SELECT 1 FROM pg_constraint constraint_record WHERE constraint_record.conrelid = c.oid AND constraint_record.contype = 'p' AND pg_get_constraintdef(constraint_record.oid, true) = 'PRIMARY KEY (kind, resource_id)') AS has_primary_key FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relname = $2`, ["public", "clearance_import_rollback_tombstones"]);
		const tableRecord = rollbackFenceTable.rows[0];
		if (
			rollbackFenceTable.rows.length !== 1 ||
			tableRecord?.relkind !== "r" ||
			tableRecord.persistence !== "p" ||
			tableRecord.column_count !== 3 ||
			!tableRecord.has_kind ||
			!tableRecord.has_resource_id ||
			!tableRecord.has_tombstoned_at ||
			!tableRecord.has_primary_key
		) {
			throw error("Authorization rollback fence table is incompatible");
		}
	}
	const guard = authorizationGuardFunctionName(names);
	const actualFunctions = await queryable.query<FunctionRow>(`SELECT p.proname AS function_name, pg_get_functiondef(p.oid) AS definition FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = $1 AND p.proname = $2 AND p.pronargs = 0`, [schema, guard]);
	const expectedColumns = columns(); const expectedConstraints = constraints(names); const expectedIndexes = indexes(names);
	const terminalizationPending = !actualColumns.rows.some((row) => row.table_name === names.revisions && row.column_name === "terminal");
	const principalSubjectIndex = shortName(names, "assignments_principal_subject_idx");
	const principalSubjectIndexPending = !actualIndexes.rows.some((row) => row.table_name === names.assignments && row.index_name === principalSubjectIndex);
	const compatibleColumns = terminalizationPending
		? Object.freeze({ ...expectedColumns, revisions: expectedColumns.revisions.filter((column) => column.name !== "terminal") })
		: expectedColumns;
	const compatibleIndexes = principalSubjectIndexPending
		? Object.freeze({ ...expectedIndexes, assignments: expectedIndexes.assignments.filter((index) => index.name !== principalSubjectIndex) })
		: expectedIndexes;
	for (const key of Object.keys(names) as (keyof Names)[]) {
		assertColumns(names[key], actualColumns.rows, compatibleColumns[key]);
		assertConstraints(names[key], actualConstraints.rows, expectedConstraints[key]);
		assertIndexes(names[key], actualIndexes.rows, compatibleIndexes[key]);
	}
	assertTriggers(actualTriggers.rows, names, authorizationTriggers(names));
	assertFunctions(actualFunctions.rows, authorizationGuardFunctions(names));
	return Object.freeze({ installed: true, terminalizationPending, principalSubjectIndexPending });
}

function transactionQueryable(value: AuthorizationAuthorityTransaction): Queryable {
	if (value && typeof value.rawTransactionQuery === "function") return { query: value.rawTransactionQuery.bind(value) };
	throw error("Authorization transaction is invalid", undefined, "AUTHORIZATION_INPUT_INVALID");
}

type ReadRow = { revision: unknown; subject_valid: unknown; role_ids: unknown; actions: unknown };

function decodeSortedStrings(value: unknown, field: string): readonly string[] {
	if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || entry.length === 0)) throw error(`Authorization ${field} is invalid`);
	const sorted = [...value].sort(canonicalStringCompare);
	if (sorted.some((value, index) => index > 0 && value === sorted[index - 1])) throw error(`Authorization ${field} is invalid`);
	return Object.freeze(sorted);
}

function sortedUnique(values: readonly unknown[], label: string, validate: (value: unknown, label: string) => string): readonly string[] {
	if (!Array.isArray(values)) throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	const result = values.map((value) => validate(value, label)).sort(canonicalStringCompare);
	if (result.some((value, index) => index > 0 && value === result[index - 1])) throw error(`${label} contains duplicates`, undefined, "AUTHORIZATION_INPUT_INVALID");
	return Object.freeze(result);
}

function sortedDistinct(values: readonly unknown[], label: string, validate: (value: unknown, label: string) => string): readonly string[] {
	return Object.freeze([...new Set(values.map((value) => validate(value, label)))].sort(canonicalStringCompare));
}

function canonicalActionName(value: unknown, label: string): string {
	const action = scopeString(value, label);
	if (!/^[a-z][a-z0-9._:-]{0,127}$/.test(action)) throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	return action;
}

function roleId(value: unknown, label: string): string {
	return scopeString(value, label);
}

function roleSlug(value: unknown, label: string): string {
	const slug = scopeString(value, label);
	if (!/^[a-z][a-z0-9_-]{0,127}$/.test(slug)) throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	return slug;
}

function roleName(value: unknown, label: string): string {
	const name = scopeString(value, label);
	if (name.length > 255) throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	return name;
}

function serviceAccountStatus(value: unknown, label: string): AuthorizationServiceAccount["status"] {
	if (value === "active" || value === "disabled") return value;
	throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
}

function credentialId(value: unknown, label: string): string {
	return scopeString(value, label);
}

function optionalCredentialExpiry(value: unknown, label: string): Date | null {
	if (value === undefined || value === null) return null;
	if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
		throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	}
	if (value.getTime() <= Date.now()) throw error(`${label} must be in the future`, undefined, "AUTHORIZATION_INPUT_INVALID");
	return new Date(value.getTime());
}

function storedCredentialExpiry(value: unknown): Date | null {
	if (value === null || value === undefined) return null;
	if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw error("Stored credential expiry is invalid");
	return new Date(value.getTime());
}

function credentialVersion(value: unknown): number {
	const parsed = typeof value === "number" ? value : Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 1) throw error("Stored credential version is invalid");
	return parsed;
}

function nextCredentialVersion(value: unknown): number {
	const parsed = typeof value === "number" ? value : Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed >= 2_147_483_647) {
		throw error("Service account credential version overflow", undefined, "AUTHORIZATION_CREDENTIAL_VERSION_OVERFLOW");
	}
	return parsed + 1;
}

function serviceAccountCredentialSecret(): string {
	return `${SERVICE_ACCOUNT_CREDENTIAL_PREFIX}_${randomBytes(SERVICE_ACCOUNT_CREDENTIAL_SECRET_BYTES).toString("base64url")}`;
}

function credentialSecretDigest(secret: string): string {
	return `v1:${createHash("sha256").update(`${SERVICE_ACCOUNT_CREDENTIAL_DIGEST_DOMAIN}${secret}`, "utf8").digest("hex")}`;
}

function credentialSecretFingerprint(secret: string): string {
	return createHash("sha256").update(`${SERVICE_ACCOUNT_CREDENTIAL_DIGEST_DOMAIN}${secret}`, "utf8").digest("base64url").slice(0, 22);
}

function assertCredentialSecret(value: unknown): string {
	if (typeof value !== "string" || !new RegExp(`^${SERVICE_ACCOUNT_CREDENTIAL_PREFIX}_[A-Za-z0-9_-]{43}$`).test(value)) {
		throw error("Service account credential is invalid", undefined, "AUTHORIZATION_CREDENTIAL_INVALID");
	}
	return value;
}

function roleDescription(value: unknown, label: string): string | null {
	if (value === null) return null;
	const description = scopeString(value, label);
	if (description.length > 4_096) throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	return description;
}

function roleStatus(value: unknown, label: string): AuthorizationAuthorityRole["status"] {
	if (value === "active" || value === "disabled" || value === "archived") return value;
	throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
}

function authorizationSubject(value: unknown, label: string): AuthorizationSubject {
	if (!value || typeof value !== "object") throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	const candidate = value as { kind?: unknown; id?: unknown };
	if (candidate.kind !== "principal" && candidate.kind !== "service_account") throw error(`${label}.kind is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	return Object.freeze({ kind: candidate.kind, id: scopeString(candidate.id, `${label}.id`) });
}

function authorizationRole(value: unknown, actions: readonly string[], label: string): AuthorizationAuthorityRole {
	if (!value || typeof value !== "object") throw error(`${label} is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	const candidate = value as Record<string, unknown>;
	const organizationId = candidate.organizationId === null ? null : scopeString(candidate.organizationId, `${label}.organizationId`);
	if (typeof candidate.builtIn !== "boolean") throw error(`${label}.builtIn is invalid`, undefined, "AUTHORIZATION_INPUT_INVALID");
	return Object.freeze({
		roleId: roleId(candidate.roleId, `${label}.roleId`),
		organizationId,
		slug: roleSlug(candidate.slug, `${label}.slug`),
		name: roleName(candidate.name, `${label}.name`),
		description: roleDescription(candidate.description, `${label}.description`),
		builtIn: candidate.builtIn,
		status: roleStatus(candidate.status, `${label}.status`),
		actions,
	});
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
	return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isReservedBuiltInRole(role: AuthorizationAuthorityRole): boolean {
	return BUILT_IN_ROLE_DEFINITIONS.some((definition) => definition.roleId === role.roleId || definition.slug === role.slug);
}

type RevisionRow = { revision: unknown; terminal: unknown };
type RoleRow = {
	role_id: unknown;
	organization_id: unknown;
	slug: unknown;
	name: unknown;
	description: unknown;
	built_in: unknown;
	status: unknown;
};
type RoleListRow = RoleRow & { actions: unknown };
type AssignmentRow = { organization_id: unknown; subject_kind: unknown; subject_id: unknown; role_id: unknown };
type ServiceAccountRow = { organization_id: unknown; service_account_id: unknown; name: unknown; status: unknown };
type CredentialRow = {
	organization_id: unknown;
	service_account_id: unknown;
	credential_id: unknown;
	credential_digest: unknown;
	credential_prefix: unknown;
	credential_fingerprint: unknown;
	expires_at: unknown;
	version: unknown;
};
type CredentialAuthenticationRow = CredentialRow & { revision: unknown; role_ids: unknown; actions: unknown };

export class PostgresAuthorizationAuthority {
	readonly identity: AuthorizationAuthorityIdentity;
	readonly schema: string;
	readonly prefix: string;
	readonly #database: Pick<pg.Pool, "query" | "connect">;
	readonly #names: Names;
	readonly #runtimeOrganizationAuthority: AuthorizationRuntimeOrganizationAuthority | undefined;

	constructor(
		database: Pick<pg.Pool, "query" | "connect">,
		options: PostgresAuthorizationAuthorityOptions,
		runtimeOrganizationAuthority?: AuthorizationRuntimeOrganizationAuthority,
	) {
		if (!database || typeof database.query !== "function" || typeof database.connect !== "function") throw error("PostgreSQL authorization database is invalid", undefined, "AUTHORIZATION_INPUT_INVALID");
		this.identity = Object.freeze({ projectId: scopeString(options.projectId, "projectId"), environmentId: scopeString(options.environmentId, "environmentId") });
		this.schema = identifier(options.schema ?? "public", "schema", 63);
		this.prefix = identifier(options.prefix ?? DEFAULT_PREFIX, "prefix", 24);
		this.#database = database;
		this.#names = namesFor(this.prefix);
		this.#runtimeOrganizationAuthority = runtimeOrganizationAuthority === undefined
			? undefined
			: Object.freeze({
				schema: identifier(runtimeOrganizationAuthority.schema, "runtime organization schema", 63),
				table: identifier(runtimeOrganizationAuthority.table, "runtime organization table", 63),
				...(runtimeOrganizationAuthority.management === undefined
					? {}
					: {
						management: Object.freeze({
							schema: identifier(runtimeOrganizationAuthority.management.schema, "management organization schema", 63),
							table: identifier(runtimeOrganizationAuthority.management.table, "management organization table", 63),
						}),
					}),
			});
	}

	async planMigration(): Promise<AuthorizationAuthorityMigrationPlan> {
		const inspection = await inspectCatalog(this.#database, this.schema, this.#names);
		const fieldCount = Object.values(columns()).reduce((total, table) => total + table.length, 0);
		const sql = !inspection.installed
			? createSql(this.schema, this.#names)
			: [
				...(inspection.terminalizationPending ? [terminalizationMigrationSql(this.schema, this.#names)] : []),
				...(inspection.principalSubjectIndexPending ? [principalSubjectIndexMigrationSql(this.schema, this.#names)] : []),
			].join(";\n");
		return Object.freeze({
			pendingTables: inspection.installed ? 0 : Object.keys(this.#names).length,
			pendingFields: inspection.installed ? (inspection.terminalizationPending ? 1 : 0) : fieldCount,
			pendingSecurityMigrations: sql === "" ? Object.freeze([]) : Object.freeze([MIGRATION_ID]),
			compileSql: async () => sql,
			apply: async () => {
				const client = await this.#database.connect();
				try {
					await client.query("BEGIN");
					await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`${this.schema}:${this.prefix}:${MIGRATION_ID}`]);
					const current = await inspectCatalog(client, this.schema, this.#names);
					if (!current.installed) await client.query(createSql(this.schema, this.#names));
					else {
						if (current.terminalizationPending) await client.query(terminalizationMigrationSql(this.schema, this.#names));
						if (current.principalSubjectIndexPending) await client.query(principalSubjectIndexMigrationSql(this.schema, this.#names));
					}
					const verified = await inspectCatalog(client, this.schema, this.#names);
					if (!verified.installed || verified.terminalizationPending || verified.principalSubjectIndexPending) {
						throw error("PostgreSQL authorization authority terminalization migration is incomplete");
					}
					await this.#seedBuiltInRoles(client);
					await client.query("COMMIT");
				} catch (cause) {
					try { await client.query("ROLLBACK"); } catch { /* preserve original failure */ }
					throw cause;
				} finally { client.release(); }
			},
		});
	}

	#table(name: string): string {
		return qualified(this.schema, name);
	}

	async acquireMutationLock(
		transaction: AuthorizationAuthorityTransaction,
	): Promise<void> {
		const queryable = transactionQueryable(transaction);
		await queryable.query(
			"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
			[`${this.schema}:${this.prefix}:authorization-mutation-v1`],
		);
	}

	async #withMutation<T>(transaction: AuthorizationAuthorityTransaction | undefined, operation: (queryable: Queryable) => Promise<T>): Promise<T> {
		if (transaction) {
			const queryable = transactionQueryable(transaction);
			await this.acquireMutationLock(transaction);
			return operation(queryable);
		}
		const client = await this.#database.connect();
		try {
			await client.query("BEGIN");
			await this.acquireMutationLock({
				rawTransactionQuery: <Row extends Record<string, unknown>>(
					text: string,
					values?: readonly unknown[],
				) => client.query<Row>(text, values ? [...values] : undefined),
			});
			const result = await operation(client);
			await client.query("COMMIT");
			return result;
		} catch (cause) {
			try { await client.query("ROLLBACK"); } catch { /* preserve original failure */ }
			throw cause;
		} finally {
			client.release();
		}
	}

	async #ensureRevision(queryable: Queryable, organizationId: string): Promise<AuthorizationAuthorityRevision> {
		const table = this.#table(this.#names.revisions);
		const inserted = await queryable.query<RevisionRow>(`INSERT INTO ${table} ("projectId", "environmentId", "organizationId", revision) VALUES ($1, $2, $3, 1) ON CONFLICT ("projectId", "environmentId", "organizationId") DO NOTHING RETURNING revision::text AS revision, terminal`, [this.identity.projectId, this.identity.environmentId, organizationId]);
		if (inserted.rows.length === 1) return Object.freeze({ organizationId, revision: canonicalRevision(inserted.rows[0]!.revision), initialized: true });
		const existing = await queryable.query<RevisionRow>(`SELECT revision::text AS revision, terminal FROM ${table} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, organizationId]);
		if (existing.rows.length !== 1) throw error("Authorization revision is unavailable");
		if (existing.rows[0]!.terminal !== false) throw error("Organization authorization is archived", undefined, "AUTHORIZATION_ORGANIZATION_ARCHIVED");
		return Object.freeze({ organizationId, revision: canonicalRevision(existing.rows[0]!.revision), initialized: false });
	}

	async #requireRevision(queryable: Queryable, organizationId: string): Promise<string> {
		const rows = await queryable.query<RevisionRow>(`SELECT revision::text AS revision, terminal FROM ${this.#table(this.#names.revisions)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, organizationId]);
		if (rows.rows.length !== 1) throw error("Authorization revision was not found", undefined, "AUTHORIZATION_REVISION_NOT_FOUND");
		return canonicalRevision(rows.rows[0]!.revision);
	}

	async #requireActiveOrganization(queryable: Queryable, organizationId: string): Promise<string> {
		const rows = await queryable.query<RevisionRow>(`SELECT revision::text AS revision, terminal FROM ${this.#table(this.#names.revisions)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, organizationId]);
		if (rows.rows.length !== 1) throw error("Authorization revision was not found", undefined, "AUTHORIZATION_REVISION_NOT_FOUND");
		if (rows.rows[0]!.terminal !== false) {
			throw error("Organization authorization is archived", undefined, "AUTHORIZATION_ORGANIZATION_ARCHIVED");
		}
		return canonicalRevision(rows.rows[0]!.revision);
	}

	async #advanceAffectedRevisions(queryable: Queryable, organizationIds: readonly string[]): Promise<readonly AuthorizationAuthorityAffectedRevision[]> {
		const affected: AuthorizationAuthorityAffectedRevision[] = [];
		for (const organizationId of organizationIds) {
			const revision = await this.#ensureRevision(queryable, organizationId);
			if (revision.initialized) {
				affected.push(Object.freeze({ organizationId, previousRevision: "0", revision: revision.revision }));
				continue;
			}
			if (BigInt(revision.revision) >= POSTGRES_BIGINT_MAX) throw error("Authorization revision overflow", undefined, "AUTHORIZATION_REVISION_OVERFLOW");
			const updated = await queryable.query<RevisionRow>(`UPDATE ${this.#table(this.#names.revisions)} SET revision = revision + 1, "updatedAt" = now() WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 RETURNING revision::text AS revision`, [this.identity.projectId, this.identity.environmentId, organizationId]);
			if (updated.rows.length !== 1) throw error("Authorization revision is unavailable");
			affected.push(Object.freeze({ organizationId, previousRevision: revision.revision, revision: canonicalRevision(updated.rows[0]!.revision) }));
		}
		return Object.freeze(affected);
	}

	async #seedBuiltInRoles(queryable: Queryable): Promise<boolean> {
		const roles = this.#table(this.#names.roles);
		const actions = this.#table(this.#names.actions);
		const roleActions = this.#table(this.#names.roleActions);
		const roleIds = BUILT_IN_ROLE_DEFINITIONS.map((definition) => definition.roleId);
		const slugs = BUILT_IN_ROLE_DEFINITIONS.map((definition) => definition.slug);
		const actionNames = Object.freeze([...new Set(BUILT_IN_ROLE_DEFINITIONS.flatMap((definition) => definition.actions))].sort(canonicalStringCompare));
		const roleRows = await queryable.query<RoleRow>(`SELECT "roleId" AS role_id, "organizationId" AS organization_id, slug, name, description, "builtIn" AS built_in, status FROM ${roles} WHERE "projectId" = $1 AND "environmentId" = $2 AND "roleId" = ANY($3::text[]) FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, roleIds]);
		const slugRows = await queryable.query<{ role_id: unknown; slug: unknown }>(`SELECT "roleId" AS role_id, slug FROM ${roles} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" IS NULL AND slug = ANY($3::text[]) FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, slugs]);
		const actionRows = await queryable.query<{ action_id: unknown; action_name: unknown }>(`SELECT "actionId" AS action_id, "actionName" AS action_name FROM ${actions} WHERE "projectId" = $1 AND "environmentId" = $2 AND "actionName" = ANY($3::text[]) FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, actionNames]);
		for (const row of actionRows.rows) {
			const actionName = canonicalActionName(row.action_name, "stored built-in action");
			if (roleId(row.action_id, "stored built-in actionId") !== actionName) throw error("Built-in action catalog drift was detected", undefined, "AUTHORIZATION_BUILT_IN_ROLE_DRIFT");
		}
		const rolesById = new Map(roleRows.rows.map((row) => [roleId(row.role_id, "stored built-in roleId"), row]));
		for (const row of slugRows.rows) {
			const slug = roleSlug(row.slug, "stored built-in role slug");
			const definition = BUILT_IN_ROLE_DEFINITIONS.find((candidate) => candidate.slug === slug);
			if (!definition || roleId(row.role_id, "stored built-in roleId") !== definition.roleId) throw error("Built-in role collision was detected", undefined, "AUTHORIZATION_BUILT_IN_ROLE_DRIFT");
		}
		const missing: typeof BUILT_IN_ROLE_DEFINITIONS[number][] = [];
		for (const definition of BUILT_IN_ROLE_DEFINITIONS) {
			const row = rolesById.get(definition.roleId);
			if (!row) {
				missing.push(definition);
				continue;
			}
			const storedActions = await queryable.query<{ actions: unknown }>(`SELECT COALESCE(array_agg(a."actionName" ORDER BY a."actionName"), ARRAY[]::text[]) AS actions FROM ${roleActions} ra JOIN ${actions} a ON a."projectId" = ra."projectId" AND a."environmentId" = ra."environmentId" AND a."actionId" = ra."actionId" WHERE ra."projectId" = $1 AND ra."environmentId" = $2 AND ra."roleId" = $3`, [this.identity.projectId, this.identity.environmentId, definition.roleId]);
			const stored = authorizationRole({ roleId: row.role_id, organizationId: row.organization_id, slug: row.slug, name: row.name, description: row.description, builtIn: row.built_in, status: row.status }, decodeSortedStrings(storedActions.rows[0]?.actions, "stored built-in actions").map((action) => canonicalActionName(action, "stored built-in action")), "stored built-in role");
			const expected = authorizationRole({ ...definition, organizationId: null, builtIn: true, status: "active" }, definition.actions, "canonical built-in role");
			if (stored.roleId !== expected.roleId || stored.organizationId !== expected.organizationId || stored.slug !== expected.slug || stored.name !== expected.name || stored.description !== expected.description || stored.builtIn !== expected.builtIn || stored.status !== expected.status || !sameStrings(stored.actions, expected.actions)) {
				throw error("Built-in role drift was detected", undefined, "AUTHORIZATION_BUILT_IN_ROLE_DRIFT");
			}
		}
		if (missing.length === 0) return false;
		await queryable.query(`INSERT INTO ${actions} ("projectId", "environmentId", "actionId", "actionName") SELECT $1, $2, action_name, action_name FROM unnest($3::text[]) AS requested(action_name) ON CONFLICT ("projectId", "environmentId", "actionName") DO NOTHING`, [this.identity.projectId, this.identity.environmentId, actionNames]);
		for (const definition of missing) {
			await queryable.query(`INSERT INTO ${roles} ("projectId", "environmentId", "roleId", "organizationId", slug, name, description, "builtIn", status) VALUES ($1, $2, $3, NULL, $4, $5, $6, true, 'active')`, [this.identity.projectId, this.identity.environmentId, definition.roleId, definition.slug, definition.name, definition.description]);
			await queryable.query(`INSERT INTO ${roleActions} ("projectId", "environmentId", "roleId", "actionId") SELECT $1, $2, $3, a."actionId" FROM ${actions} a WHERE a."projectId" = $1 AND a."environmentId" = $2 AND a."actionName" = ANY($4::text[])`, [this.identity.projectId, this.identity.environmentId, definition.roleId, definition.actions]);
		}
		return true;
	}

	async initializeOrganization(input: Readonly<{ organizationId: string; transaction?: AuthorizationAuthorityTransaction }>): Promise<AuthorizationAuthorityRevision> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		return this.#withMutation(input.transaction, async (queryable) => {
			await this.#seedBuiltInRoles(queryable);
			return this.#ensureRevision(queryable, organizationId);
		});
	}

	/**
	 * Irreversibly terminalizes this scope's authorization state for an organization.
	 * It is intentionally transaction-capable so topology archival can share the
	 * same commit boundary. No restore operation exists in this authority.
	 */
	async archiveOrganization(input: AuthorizationAuthorityArchiveOrganizationInput): Promise<AuthorizationAuthorityArchiveOrganizationResult> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		return this.#withMutation(input.transaction, async (queryable) => {
			const revisions = this.#table(this.#names.revisions);
			const inserted = await queryable.query<RevisionRow>(`INSERT INTO ${revisions} ("projectId", "environmentId", "organizationId", revision, terminal) VALUES ($1, $2, $3, 1, true) ON CONFLICT ("projectId", "environmentId", "organizationId") DO NOTHING RETURNING revision::text AS revision, terminal`, [this.identity.projectId, this.identity.environmentId, organizationId]);
			const current = inserted.rows[0] ?? (await queryable.query<RevisionRow>(`SELECT revision::text AS revision, terminal FROM ${revisions} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, organizationId])).rows[0];
			if (!current) throw error("Authorization terminalization is unavailable");
			const previousRevision = inserted.rows.length === 1 ? "0" : canonicalRevision(current.revision);
			let revision = canonicalRevision(current.revision);
			if (current.terminal === false) {
				if (BigInt(revision) >= POSTGRES_BIGINT_MAX) throw error("Authorization revision overflow", undefined, "AUTHORIZATION_REVISION_OVERFLOW");
				const advanced = await queryable.query<RevisionRow>(`UPDATE ${revisions} SET terminal = true, revision = revision + 1, "updatedAt" = now() WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND terminal = false RETURNING revision::text AS revision, terminal`, [this.identity.projectId, this.identity.environmentId, organizationId]);
				if (advanced.rows.length !== 1 || advanced.rows[0]!.terminal !== true) throw error("Authorization terminalization is unavailable");
				revision = canonicalRevision(advanced.rows[0]!.revision);
			} else if (current.terminal !== true) {
				throw error("Authorization terminal state is invalid");
			}
			const assignments = await queryable.query(`DELETE FROM ${this.#table(this.#names.assignments)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3`, [this.identity.projectId, this.identity.environmentId, organizationId]);
			const disabled = await queryable.query(`UPDATE ${this.#table(this.#names.serviceAccounts)} SET status = 'disabled', "updatedAt" = now() WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND status = 'active'`, [this.identity.projectId, this.identity.environmentId, organizationId]);
			const revoked = await queryable.query(`UPDATE ${this.#table(this.#names.credentials)} SET status = 'revoked', "revokedAt" = now(), "updatedAt" = now() WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND status = 'active'`, [this.identity.projectId, this.identity.environmentId, organizationId]);
			return Object.freeze({
				organizationId,
				previousRevision,
				revision,
				archived: true,
				removedAssignments: assignments.rowCount ?? 0,
				disabledServiceAccounts: disabled.rowCount ?? 0,
				revokedCredentials: revoked.rowCount ?? 0,
			});
		});
	}

	/**
	 * Terminalizes only live authorization rows that are absent from every exact
	 * injected organization authority. A runtime product row or a scoped active
	 * normalized-management row is sufficient to keep an organization live. The
	 * operation is set-based, idempotent, and deliberately unavailable without
	 * both server-owned identities: runtime absence alone is never archival proof.
	 */
	async reconcileRuntimeOrganizations(input?: Readonly<{
		management: Readonly<{ schema: string; table: string }>;
		transaction?: AuthorizationAuthorityTransaction;
	}>): Promise<AuthorizationAuthorityReconciliationResult> {
		const runtime = this.#runtimeOrganizationAuthority;
		const configuredManagement = input?.management ?? runtime?.management;
		const management = configuredManagement === undefined
			? undefined
			: Object.freeze({
				schema: identifier(configuredManagement.schema, "management organization schema", 63),
				table: identifier(configuredManagement.table, "management organization table", 63),
			});
		if (!runtime || !management) throw error("Organization authorities are not configured", undefined, "AUTHORIZATION_RUNTIME_ORGANIZATION_UNAVAILABLE");
		return this.#withMutation(input?.transaction, async (queryable) => {
			const runtimeTable = qualified(runtime.schema, runtime.table);
			const managementTable = qualified(management.schema, management.table);
			const catalog = await queryable.query<{ authority: unknown; exists: unknown; id_type: unknown; status_type: unknown; project_type: unknown; environment_type: unknown }>(`SELECT authority, to_regclass(qualified_name) IS NOT NULL AS exists,
				(SELECT data_type FROM information_schema.columns WHERE table_schema = schema_name AND table_name = table_name_input AND column_name = 'id') AS id_type,
				(SELECT data_type FROM information_schema.columns WHERE table_schema = schema_name AND table_name = table_name_input AND column_name = 'status') AS status_type,
				(SELECT data_type FROM information_schema.columns WHERE table_schema = schema_name AND table_name = table_name_input AND column_name = 'project_id') AS project_type,
				(SELECT data_type FROM information_schema.columns WHERE table_schema = schema_name AND table_name = table_name_input AND column_name = 'environment_id') AS environment_type
				FROM (VALUES
					('runtime'::text, $1::text, $2::text, $3::text),
					('management'::text, $4::text, $5::text, $6::text)
				) AS authority_rows(authority, qualified_name, schema_name, table_name_input)`, [
				`${runtime.schema}.${runtime.table}`, runtime.schema, runtime.table,
				`${management.schema}.${management.table}`, management.schema, management.table,
			]);
			const runtimeCatalog = catalog.rows.find((row) => row.authority === "runtime");
			const managementCatalog = catalog.rows.find((row) => row.authority === "management");
			if (
				catalog.rows.length !== 2 ||
				runtimeCatalog?.exists !== true || runtimeCatalog.id_type !== "text" ||
				managementCatalog?.exists !== true || managementCatalog.id_type !== "text" ||
				managementCatalog.status_type !== "text" || managementCatalog.project_type !== "text" || managementCatalog.environment_type !== "text"
			) {
				throw error("Organization authorities are unavailable", undefined, "AUTHORIZATION_RUNTIME_ORGANIZATION_UNAVAILABLE");
			}
			const revisions = this.#table(this.#names.revisions);
			const managementActive = `EXISTS (SELECT 1 FROM ${managementTable} management_org WHERE management_org.id = revision."organizationId" AND management_org.project_id = revision."projectId" AND management_org.environment_id = revision."environmentId" AND management_org.status = 'active')`;
			const managementArchived = `EXISTS (SELECT 1 FROM ${managementTable} management_org WHERE management_org.id = revision."organizationId" AND management_org.project_id = revision."projectId" AND management_org.environment_id = revision."environmentId" AND management_org.status = 'archived')`;
			// A normalized tombstone is authoritative over stale runtime state. In
			// its absence, an extant runtime row still protects legacy live orgs.
			const missingAuthority = `NOT (${managementActive}) AND ((${managementArchived}) OR NOT EXISTS (SELECT 1 FROM ${runtimeTable} runtime_org WHERE runtime_org.id = revision."organizationId"))`;
			const overflow = await queryable.query<{ organization_id: unknown }>(`SELECT "organizationId" AS organization_id FROM ${revisions} revision WHERE revision."projectId" = $1 AND revision."environmentId" = $2 AND revision.terminal = false AND revision.revision >= $3::bigint AND ${missingAuthority} LIMIT 1 FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, POSTGRES_BIGINT_MAX.toString()]);
			if (overflow.rows.length > 0) throw error("Authorization revision overflow", undefined, "AUTHORIZATION_REVISION_OVERFLOW");
			const terminalized = await queryable.query<{ count: unknown; organization_ids: unknown }>(`WITH orphaned AS (
				SELECT revision."organizationId" FROM ${revisions} revision
				WHERE revision."projectId" = $1 AND revision."environmentId" = $2 AND revision.terminal = false
				AND ${missingAuthority}
			), updated AS (
				UPDATE ${revisions} revision SET terminal = true, revision = revision.revision + 1, "updatedAt" = now()
				FROM orphaned WHERE revision."projectId" = $1 AND revision."environmentId" = $2
				AND revision."organizationId" = orphaned."organizationId" AND revision.terminal = false
				RETURNING revision."organizationId" AS organization_id
			) SELECT count(*)::int AS count, COALESCE((array_agg(organization_id ORDER BY organization_id))[1:100], ARRAY[]::text[]) AS organization_ids FROM updated`, [this.identity.projectId, this.identity.environmentId]);
			const assignments = await queryable.query(`DELETE FROM ${this.#table(this.#names.assignments)} assignment
				USING ${revisions} revision
				WHERE assignment."projectId" = $1 AND assignment."environmentId" = $2
				AND revision."projectId" = assignment."projectId" AND revision."environmentId" = assignment."environmentId"
				AND revision."organizationId" = assignment."organizationId" AND revision.terminal = true`, [this.identity.projectId, this.identity.environmentId]);
			const disabled = await queryable.query(`UPDATE ${this.#table(this.#names.serviceAccounts)} account SET status = 'disabled', "updatedAt" = now()
				WHERE account."projectId" = $1 AND account."environmentId" = $2 AND account.status = 'active'
				AND EXISTS (SELECT 1 FROM ${revisions} revision WHERE revision."projectId" = $1 AND revision."environmentId" = $2 AND revision."organizationId" = account."organizationId" AND revision.terminal = true)`, [this.identity.projectId, this.identity.environmentId]);
			const revoked = await queryable.query(`UPDATE ${this.#table(this.#names.credentials)} credential SET status = 'revoked', "revokedAt" = now(), "updatedAt" = now()
				WHERE credential."projectId" = $1 AND credential."environmentId" = $2 AND credential.status = 'active'
				AND EXISTS (SELECT 1 FROM ${revisions} revision WHERE revision."projectId" = $1 AND revision."environmentId" = $2 AND revision."organizationId" = credential."organizationId" AND revision.terminal = true)`, [this.identity.projectId, this.identity.environmentId]);
			const terminalizedRow = terminalized.rows[0];
			const terminalizedIds = Array.isArray(terminalizedRow?.organization_ids)
				? terminalizedRow.organization_ids.filter((id): id is string => typeof id === "string")
				: [];
			return Object.freeze({ terminalizedOrganizations: Number(terminalizedRow?.count ?? 0), terminalizedOrganizationIds: Object.freeze(terminalizedIds), removedAssignments: assignments.rowCount ?? 0, disabledServiceAccounts: disabled.rowCount ?? 0, revokedCredentials: revoked.rowCount ?? 0 });
		});
	}

	async #assertAssignedSubjectActionLimit(queryable: Queryable, role: AuthorizationAuthorityRole, assignments: readonly AssignmentRow[]): Promise<void> {
		if (role.status !== "active" || assignments.length === 0) return;
		const roles = this.#table(this.#names.roles);
		const roleActions = this.#table(this.#names.roleActions);
		const actions = this.#table(this.#names.actions);
		const assignmentsTable = this.#table(this.#names.assignments);
		for (const assignment of assignments) {
			const organizationId = scopeString(assignment.organization_id, "stored assignment organizationId");
			const subject = authorizationSubject({ kind: assignment.subject_kind, id: assignment.subject_id }, "stored assignment subject");
			const otherActions = await queryable.query<{ action_name: unknown }>(`SELECT DISTINCT ac."actionName" AS action_name FROM ${assignmentsTable} a JOIN ${roles} r ON r."projectId" = a."projectId" AND r."environmentId" = a."environmentId" AND r."roleId" = a."roleId" JOIN ${roleActions} ra ON ra."projectId" = r."projectId" AND ra."environmentId" = r."environmentId" AND ra."roleId" = r."roleId" JOIN ${actions} ac ON ac."projectId" = ra."projectId" AND ac."environmentId" = ra."environmentId" AND ac."actionId" = ra."actionId" WHERE a."projectId" = $1 AND a."environmentId" = $2 AND a."organizationId" = $3 AND a."subjectKind" = $4 AND a."subjectId" = $5 AND a."roleId" <> $6 AND r.status = 'active' AND (r."organizationId" IS NULL OR r."organizationId" = a."organizationId")`, [this.identity.projectId, this.identity.environmentId, organizationId, subject.kind, subject.id, role.roleId]);
			const effectiveActions = new Set(role.actions);
			for (const row of otherActions.rows) effectiveActions.add(canonicalActionName(row.action_name, "stored action"));
			if (effectiveActions.size > MAX_EFFECTIVE_ACTIONS) throw error("Authorization action limit was exceeded", undefined, "AUTHORIZATION_ACTION_LIMIT_EXCEEDED");
		}
	}

	#serviceAccountFromRow(row: ServiceAccountRow): AuthorizationServiceAccount {
		return Object.freeze({
			organizationId: scopeString(row.organization_id, "stored service account organizationId"),
			serviceAccountId: scopeString(row.service_account_id, "stored service accountId"),
			name: roleName(row.name, "stored service account name"),
			status: serviceAccountStatus(row.status, "stored service account status"),
		});
	}

	#credentialFromRow(row: CredentialRow): AuthorizationServiceAccountCredential {
		const prefix = scopeString(row.credential_prefix, "stored credential prefix");
		const fingerprint = scopeString(row.credential_fingerprint, "stored credential fingerprint");
		if (!/^[A-Za-z0-9_-]{1,32}$/.test(prefix) || !/^[A-Za-z0-9_-]{6,128}$/.test(fingerprint)) {
			throw error("Stored credential is invalid");
		}
		return Object.freeze({
			organizationId: scopeString(row.organization_id, "stored credential organizationId"),
			serviceAccountId: scopeString(row.service_account_id, "stored credential serviceAccountId"),
			credentialId: credentialId(row.credential_id, "stored credentialId"),
			credentialPrefix: prefix,
			credentialFingerprint: fingerprint,
			expiresAt: storedCredentialExpiry(row.expires_at),
			version: credentialVersion(row.version),
		});
	}

	async #requireServiceAccount(queryable: Queryable, organizationId: string, serviceAccountId: string, active: boolean): Promise<AuthorizationServiceAccount> {
		await this.#requireActiveOrganization(queryable, organizationId);
		const rows = await queryable.query<ServiceAccountRow>(`SELECT "organizationId" AS organization_id, "serviceAccountId" AS service_account_id, name, status FROM ${this.#table(this.#names.serviceAccounts)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4 FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId]);
		if (rows.rows.length !== 1) throw error("Service account was not found", undefined, "AUTHORIZATION_SERVICE_ACCOUNT_NOT_FOUND");
		const account = this.#serviceAccountFromRow(rows.rows[0]!);
		if (active && account.status !== "active") throw error("Service account is disabled", undefined, "AUTHORIZATION_SERVICE_ACCOUNT_DISABLED");
		return account;
	}

	async #validateServiceAccountRoleIds(queryable: Queryable, organizationId: string, roleIds: readonly string[]): Promise<void> {
		if (roleIds.length === 0) return;
		const roles = this.#table(this.#names.roles);
		const requestedRoles = await queryable.query<RoleRow>(`SELECT "roleId" AS role_id, "organizationId" AS organization_id, slug, name, description, "builtIn" AS built_in, status FROM ${roles} WHERE "projectId" = $1 AND "environmentId" = $2 AND "roleId" = ANY($3::text[]) FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, roleIds]);
		if (requestedRoles.rows.length !== roleIds.length) throw error("Authorization role was not found", undefined, "AUTHORIZATION_ROLE_NOT_FOUND");
		for (const row of requestedRoles.rows) {
			const role = authorizationRole({ roleId: row.role_id, organizationId: row.organization_id, slug: row.slug, name: row.name, description: row.description, builtIn: row.built_in, status: row.status }, Object.freeze([]), "stored role");
			if (role.status !== "active") throw error("Authorization role is inactive", undefined, "AUTHORIZATION_ROLE_INACTIVE");
			if (role.organizationId !== null && role.organizationId !== organizationId) throw error("Authorization role scope mismatch", undefined, "AUTHORIZATION_ROLE_SCOPE_MISMATCH");
		}
		const requestedActions = await queryable.query<{ action_name: unknown }>(`SELECT DISTINCT a."actionName" AS action_name FROM ${this.#table(this.#names.roleActions)} ra JOIN ${this.#table(this.#names.actions)} a ON a."projectId" = ra."projectId" AND a."environmentId" = ra."environmentId" AND a."actionId" = ra."actionId" WHERE ra."projectId" = $1 AND ra."environmentId" = $2 AND ra."roleId" = ANY($3::text[])`, [this.identity.projectId, this.identity.environmentId, roleIds]);
		if (new Set(requestedActions.rows.map((row) => canonicalActionName(row.action_name, "stored requested action"))).size > MAX_EFFECTIVE_ACTIONS) {
			throw error("Authorization action limit was exceeded", undefined, "AUTHORIZATION_ACTION_LIMIT_EXCEEDED");
		}
	}

	async #insertServiceAccountCredential(queryable: Queryable, input: Readonly<{ organizationId: string; serviceAccountId: string; credentialId: string; expiresAt: Date | null; version: number; replacedCredentialId: string | null }>): Promise<AuthorizationServiceAccountCredentialMutation["credential"] & { readonly secret: string }> {
		const secret = serviceAccountCredentialSecret();
		const digest = credentialSecretDigest(secret);
		let row: { rows: CredentialRow[]; rowCount: number | null };
		try {
			row = await queryable.query<CredentialRow>(`INSERT INTO ${this.#table(this.#names.credentials)} ("projectId", "environmentId", "organizationId", "credentialId", "serviceAccountId", "credentialDigest", "credentialPrefix", "credentialFingerprint", status, "expiresAt", "replacedCredentialId", version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10, $11) RETURNING "organizationId" AS organization_id, "serviceAccountId" AS service_account_id, "credentialId" AS credential_id, "credentialDigest" AS credential_digest, "credentialPrefix" AS credential_prefix, "credentialFingerprint" AS credential_fingerprint, "expiresAt" AS expires_at, version`, [this.identity.projectId, this.identity.environmentId, input.organizationId, input.credentialId, input.serviceAccountId, digest, SERVICE_ACCOUNT_CREDENTIAL_PREFIX, credentialSecretFingerprint(secret), input.expiresAt, input.replacedCredentialId, input.version]);
		} catch (cause) {
			if (postgresErrorCode(cause) === "23505") {
				throw error("Service account credential is unavailable", undefined, "AUTHORIZATION_CREDENTIAL_COLLISION");
			}
			throw cause;
		}
		if (row.rows.length !== 1) throw error("Service account credential is unavailable");
		return Object.freeze({ ...this.#credentialFromRow(row.rows[0]!), secret });
	}

	async upsertRole(input: AuthorizationAuthorityUpsertRoleInput): Promise<AuthorizationAuthorityUpsertRoleResult> {
		const actions = sortedUnique(input.actions, "actions", canonicalActionName);
		const role = authorizationRole(input.role, actions, "role");
		if (role.builtIn || isReservedBuiltInRole(role)) throw error("Built-in roles are initialized by the authorization authority", undefined, "AUTHORIZATION_ROLE_IMMUTABLE");
		return this.#withMutation(input.transaction, async (queryable) => {
			if (actions.length > MAX_EFFECTIVE_ACTIONS) throw error("Authorization action limit was exceeded", undefined, "AUTHORIZATION_ACTION_LIMIT_EXCEEDED");
			if (role.organizationId !== null) await this.#requireActiveOrganization(queryable, role.organizationId);
			const roles = this.#table(this.#names.roles);
			const roleActions = this.#table(this.#names.roleActions);
			const actionsTable = this.#table(this.#names.actions);
			const assignments = this.#table(this.#names.assignments);
			const currentRows = await queryable.query<RoleRow>(`SELECT "roleId" AS role_id, "organizationId" AS organization_id, slug, name, description, "builtIn" AS built_in, status FROM ${roles} WHERE "projectId" = $1 AND "environmentId" = $2 AND "roleId" = $3 FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, role.roleId]);
			if (currentRows.rows.length > 1) throw error("Authorization role is unavailable");
			const currentActions = currentRows.rows.length === 0
				? Object.freeze([]) as readonly string[]
				: decodeSortedStrings((await queryable.query<{ actions: unknown }>(`SELECT COALESCE(array_agg(a."actionName" ORDER BY a."actionName"), ARRAY[]::text[]) AS actions FROM ${roleActions} ra JOIN ${actionsTable} a ON a."projectId" = ra."projectId" AND a."environmentId" = ra."environmentId" AND a."actionId" = ra."actionId" WHERE ra."projectId" = $1 AND ra."environmentId" = $2 AND ra."roleId" = $3`, [this.identity.projectId, this.identity.environmentId, role.roleId])).rows[0]?.actions, "role actions").map((action) => canonicalActionName(action, "role action"));
			const current = currentRows.rows.length === 0 ? undefined : authorizationRole({
				roleId: currentRows.rows[0]!.role_id,
				organizationId: currentRows.rows[0]!.organization_id,
				slug: currentRows.rows[0]!.slug,
				name: currentRows.rows[0]!.name,
				description: currentRows.rows[0]!.description,
				builtIn: currentRows.rows[0]!.built_in,
				status: currentRows.rows[0]!.status,
			}, currentActions, "stored role");
			if (current?.organizationId !== null && current?.organizationId !== undefined) {
				await this.#requireActiveOrganization(queryable, current.organizationId);
			}
			const unchanged = current !== undefined && current.roleId === role.roleId && current.organizationId === role.organizationId && current.slug === role.slug && current.name === role.name && current.description === role.description && current.builtIn === role.builtIn && current.status === role.status && sameStrings(current.actions, role.actions);
			if (current && (current.builtIn !== role.builtIn || current.builtIn) && !unchanged) {
				throw error("Built-in roles are immutable", undefined, "AUTHORIZATION_ROLE_IMMUTABLE");
			}
			if (unchanged) return Object.freeze({ changed: false, affectedOrganizations: Object.freeze([]) });
			const collision = await queryable.query<{ role_id: unknown }>(`SELECT "roleId" AS role_id FROM ${roles} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" IS NOT DISTINCT FROM $3 AND slug = $4 AND "roleId" <> $5 LIMIT 1`, [this.identity.projectId, this.identity.environmentId, role.organizationId, role.slug, role.roleId]);
			if (collision.rows.length !== 0) throw error("Authorization role slug already exists", undefined, "AUTHORIZATION_ROLE_COLLISION");
			const assignmentRows = await queryable.query<AssignmentRow>(`SELECT DISTINCT "organizationId" AS organization_id, "subjectKind" AS subject_kind, "subjectId" AS subject_id FROM ${assignments} WHERE "projectId" = $1 AND "environmentId" = $2 AND "roleId" = $3 ORDER BY "organizationId", "subjectKind", "subjectId"`, [this.identity.projectId, this.identity.environmentId, role.roleId]);
			await this.#assertAssignedSubjectActionLimit(queryable, role, assignmentRows.rows);
			const affectedOrganizations = sortedDistinct([
				...assignmentRows.rows.map((row) => row.organization_id),
				...(current?.organizationId === null || current === undefined ? [] : [current.organizationId]),
				...(role.organizationId === null ? [] : [role.organizationId]),
			], "affected organizationId", scopeString);
			if (current) {
				await queryable.query(`UPDATE ${roles} SET "organizationId" = $4, slug = $5, name = $6, description = $7, "builtIn" = $8, status = $9, "updatedAt" = now() WHERE "projectId" = $1 AND "environmentId" = $2 AND "roleId" = $3`, [this.identity.projectId, this.identity.environmentId, role.roleId, role.organizationId, role.slug, role.name, role.description, role.builtIn, role.status]);
			} else {
				await queryable.query(`INSERT INTO ${roles} ("projectId", "environmentId", "roleId", "organizationId", slug, name, description, "builtIn", status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, [this.identity.projectId, this.identity.environmentId, role.roleId, role.organizationId, role.slug, role.name, role.description, role.builtIn, role.status]);
			}
			if (role.actions.length > 0) {
				await queryable.query(`INSERT INTO ${actionsTable} ("projectId", "environmentId", "actionId", "actionName") SELECT $1, $2, action_name, action_name FROM unnest($3::text[]) AS requested(action_name) ON CONFLICT ("projectId", "environmentId", "actionName") DO NOTHING`, [this.identity.projectId, this.identity.environmentId, role.actions]);
			}
			await queryable.query(`DELETE FROM ${roleActions} WHERE "projectId" = $1 AND "environmentId" = $2 AND "roleId" = $3`, [this.identity.projectId, this.identity.environmentId, role.roleId]);
			if (role.actions.length > 0) {
				await queryable.query(`INSERT INTO ${roleActions} ("projectId", "environmentId", "roleId", "actionId") SELECT $1, $2, $3, a."actionId" FROM ${actionsTable} a WHERE a."projectId" = $1 AND a."environmentId" = $2 AND a."actionName" = ANY($4::text[])`, [this.identity.projectId, this.identity.environmentId, role.roleId, role.actions]);
			}
			return Object.freeze({ changed: true, affectedOrganizations: await this.#advanceAffectedRevisions(queryable, affectedOrganizations) });
		});
	}

	async replaceSubjectRoles(input: AuthorizationAuthorityReplaceSubjectRolesInput): Promise<AuthorizationAuthorityReplaceSubjectRolesResult> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		const subject = authorizationSubject(input.subject, "subject");
		const roleIds = sortedUnique(input.roleIds, "roleIds", roleId);
		const expectedRevision = input.expectedRevision === undefined ? undefined : canonicalRevision(input.expectedRevision);
		return this.#withMutation(input.transaction, async (queryable) => {
			const revision = await this.#requireActiveOrganization(queryable, organizationId);
			if (expectedRevision !== undefined && expectedRevision !== revision) throw error("Authorization revision is stale", undefined, "AUTHORIZATION_REVISION_STALE");
			const roles = this.#table(this.#names.roles);
			const assignments = this.#table(this.#names.assignments);
			if (subject.kind === "service_account") {
				const account = await queryable.query<{ service_account_id: unknown }>(`SELECT "serviceAccountId" AS service_account_id FROM ${this.#table(this.#names.serviceAccounts)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4 AND status = 'active'`, [this.identity.projectId, this.identity.environmentId, organizationId, subject.id]);
				if (account.rows.length !== 1) throw error("Authorization subject was not found", undefined, "AUTHORIZATION_SUBJECT_NOT_FOUND");
			}
			if (roleIds.length > 0) {
				const requestedRoles = await queryable.query<RoleRow>(`SELECT "roleId" AS role_id, "organizationId" AS organization_id, slug, name, description, "builtIn" AS built_in, status FROM ${roles} WHERE "projectId" = $1 AND "environmentId" = $2 AND "roleId" = ANY($3::text[]) FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, roleIds]);
				if (requestedRoles.rows.length !== roleIds.length) throw error("Authorization role was not found", undefined, "AUTHORIZATION_ROLE_NOT_FOUND");
				for (const row of requestedRoles.rows) {
					const role = authorizationRole({ roleId: row.role_id, organizationId: row.organization_id, slug: row.slug, name: row.name, description: row.description, builtIn: row.built_in, status: row.status }, Object.freeze([]), "stored role");
					if (role.status !== "active") throw error("Authorization role is inactive", undefined, "AUTHORIZATION_ROLE_INACTIVE");
					if (role.organizationId !== null && role.organizationId !== organizationId) throw error("Authorization role scope mismatch", undefined, "AUTHORIZATION_ROLE_SCOPE_MISMATCH");
				}
				const requestedActions = await queryable.query<{ action_name: unknown }>(`SELECT DISTINCT a."actionName" AS action_name FROM ${this.#table(this.#names.roleActions)} ra JOIN ${this.#table(this.#names.actions)} a ON a."projectId" = ra."projectId" AND a."environmentId" = ra."environmentId" AND a."actionId" = ra."actionId" WHERE ra."projectId" = $1 AND ra."environmentId" = $2 AND ra."roleId" = ANY($3::text[])`, [this.identity.projectId, this.identity.environmentId, roleIds]);
				const effectiveActions = new Set(requestedActions.rows.map((row) => canonicalActionName(row.action_name, "stored requested action")));
				if (effectiveActions.size > MAX_EFFECTIVE_ACTIONS) throw error("Authorization action limit was exceeded", undefined, "AUTHORIZATION_ACTION_LIMIT_EXCEEDED");
			}
			const currentRows = await queryable.query<{ role_id: unknown }>(`SELECT "roleId" AS role_id FROM ${assignments} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "subjectKind" = $4 AND "subjectId" = $5 ORDER BY "roleId" FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, organizationId, subject.kind, subject.id]);
			const currentRoleIds = Object.freeze(currentRows.rows.map((row) => roleId(row.role_id, "stored assignment roleId")).sort(canonicalStringCompare));
			if (subject.kind === "principal") {
				const owners = await queryable.query<{ subject_id: unknown; role_id: unknown }>(`SELECT a."subjectId" AS subject_id, a."roleId" AS role_id FROM ${assignments} a JOIN ${roles} r ON r."projectId" = a."projectId" AND r."environmentId" = a."environmentId" AND r."roleId" = a."roleId" WHERE a."projectId" = $1 AND a."environmentId" = $2 AND a."organizationId" = $3 AND a."subjectKind" = 'principal' AND r."builtIn" = true AND r.slug = 'owner' AND r.status = 'active' AND (r."organizationId" IS NULL OR r."organizationId" = a."organizationId") FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, organizationId]);
				if (owners.rows.length > 0) {
					const currentOwnerCountOutsideSubject = owners.rows.filter((row) => scopeString(row.subject_id, "stored owner subjectId") !== subject.id).length;
					const ownerRoleIds = new Set(owners.rows.map((row) => roleId(row.role_id, "stored owner roleId")));
					const replacementOwnerCount = roleIds.filter((roleId) => ownerRoleIds.has(roleId)).length;
					if (currentOwnerCountOutsideSubject + replacementOwnerCount === 0) throw error("The final active owner assignment is protected", undefined, "AUTHORIZATION_LAST_OWNER_PROTECTED");
				}
			}
			if (sameStrings(currentRoleIds, roleIds)) return Object.freeze({ changed: false, previousRevision: revision, revision, roleIds });
			await queryable.query(`DELETE FROM ${assignments} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "subjectKind" = $4 AND "subjectId" = $5`, [this.identity.projectId, this.identity.environmentId, organizationId, subject.kind, subject.id]);
			if (roleIds.length > 0) {
				await queryable.query(`INSERT INTO ${assignments} ("projectId", "environmentId", "organizationId", "subjectKind", "subjectId", "roleId") SELECT $1, $2, $3, $4, $5, role_id FROM unnest($6::text[]) AS requested(role_id)`, [this.identity.projectId, this.identity.environmentId, organizationId, subject.kind, subject.id, roleIds]);
			}
			const affected = await this.#advanceAffectedRevisions(queryable, Object.freeze([organizationId]));
			const advanced = affected[0]!;
			return Object.freeze({ changed: true, previousRevision: advanced.previousRevision, revision: advanced.revision, roleIds });
		});
	}

	async createServiceAccount(input: AuthorizationCreateServiceAccountInput): Promise<AuthorizationServiceAccountMutation> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		const serviceAccountId = scopeString(input.serviceAccountId, "serviceAccountId");
		const name = roleName(input.name, "name");
		const roleIds = sortedUnique(input.roleIds, "roleIds", roleId);
		return this.#withMutation(input.transaction, async (queryable) => {
			await this.#requireActiveOrganization(queryable, organizationId);
			await this.#validateServiceAccountRoleIds(queryable, organizationId, roleIds);
			const inserted = await queryable.query<ServiceAccountRow>(`INSERT INTO ${this.#table(this.#names.serviceAccounts)} ("projectId", "environmentId", "organizationId", "serviceAccountId", name, status) VALUES ($1, $2, $3, $4, $5, 'active') RETURNING "organizationId" AS organization_id, "serviceAccountId" AS service_account_id, name, status`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId, name]);
			if (inserted.rows.length !== 1) throw error("Service account is unavailable");
			if (roleIds.length > 0) {
				await queryable.query(`INSERT INTO ${this.#table(this.#names.assignments)} ("projectId", "environmentId", "organizationId", "subjectKind", "subjectId", "roleId") SELECT $1, $2, $3, 'service_account', $4, role_id FROM unnest($5::text[]) AS requested(role_id)`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId, roleIds]);
			}
			const advanced = (await this.#advanceAffectedRevisions(queryable, Object.freeze([organizationId])))[0]!;
			return Object.freeze({ serviceAccount: this.#serviceAccountFromRow(inserted.rows[0]!), previousRevision: advanced.previousRevision, revision: advanced.revision });
		});
	}

	async listServiceAccounts(input: AuthorizationListServiceAccountsInput): Promise<readonly AuthorizationServiceAccount[]> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		const queryable = input.transaction ? transactionQueryable(input.transaction) : this.#database;
		await this.#requireActiveOrganization(queryable, organizationId);
		const rows = await queryable.query<ServiceAccountRow>(`SELECT "organizationId" AS organization_id, "serviceAccountId" AS service_account_id, name, status FROM ${this.#table(this.#names.serviceAccounts)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 ORDER BY name, "serviceAccountId"`, [this.identity.projectId, this.identity.environmentId, organizationId]);
		return Object.freeze(rows.rows.map((row) => this.#serviceAccountFromRow(row)));
	}

	async setServiceAccountStatus(input: AuthorizationSetServiceAccountStatusInput): Promise<AuthorizationServiceAccountMutation> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		const serviceAccountId = scopeString(input.serviceAccountId, "serviceAccountId");
		const status = serviceAccountStatus(input.status, "status");
		return this.#withMutation(input.transaction, async (queryable) => {
			const account = await this.#requireServiceAccount(queryable, organizationId, serviceAccountId, false);
			if (account.status === status) {
				const revision = await this.#requireRevision(queryable, organizationId);
				return Object.freeze({ serviceAccount: account, previousRevision: revision, revision });
			}
			const updated = await queryable.query<ServiceAccountRow>(`UPDATE ${this.#table(this.#names.serviceAccounts)} SET status = $5, "updatedAt" = now() WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4 RETURNING "organizationId" AS organization_id, "serviceAccountId" AS service_account_id, name, status`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId, status]);
			if (updated.rows.length !== 1) throw error("Service account is unavailable");
			const advanced = (await this.#advanceAffectedRevisions(queryable, Object.freeze([organizationId])))[0]!;
			return Object.freeze({ serviceAccount: this.#serviceAccountFromRow(updated.rows[0]!), previousRevision: advanced.previousRevision, revision: advanced.revision });
		});
	}

	async createServiceAccountCredential(input: AuthorizationCreateServiceAccountCredentialInput): Promise<AuthorizationServiceAccountCredentialMutation> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		const serviceAccountId = scopeString(input.serviceAccountId, "serviceAccountId");
		const expiresAt = optionalCredentialExpiry(input.expiresAt, "expiresAt");
		const requestedCredentialId = input.credentialId === undefined ? `credential_${randomUUID()}` : credentialId(input.credentialId, "credentialId");
		return this.#withMutation(input.transaction, async (queryable) => {
			await this.#requireServiceAccount(queryable, organizationId, serviceAccountId, true);
			const versionRows = await queryable.query<{ version: unknown }>(`SELECT COALESCE(max(version), 0)::text AS version FROM ${this.#table(this.#names.credentials)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId]);
			const version = nextCredentialVersion(versionRows.rows[0]?.version ?? 0);
			const created = await this.#insertServiceAccountCredential(queryable, { organizationId, serviceAccountId, credentialId: requestedCredentialId, expiresAt, version, replacedCredentialId: null });
			const advanced = (await this.#advanceAffectedRevisions(queryable, Object.freeze([organizationId])))[0]!;
			const { secret, ...credential } = created;
			return Object.freeze({ credential: Object.freeze(credential), secret, previousRevision: advanced.previousRevision, revision: advanced.revision });
		});
	}

	async rotateServiceAccountCredential(input: AuthorizationRotateServiceAccountCredentialInput): Promise<AuthorizationServiceAccountCredentialMutation> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		const serviceAccountId = scopeString(input.serviceAccountId, "serviceAccountId");
		const oldCredentialId = credentialId(input.credentialId, "credentialId");
		const expiresAt = optionalCredentialExpiry(input.expiresAt, "expiresAt");
		return this.#withMutation(input.transaction, async (queryable) => {
			await this.#requireServiceAccount(queryable, organizationId, serviceAccountId, true);
			const oldRows = await queryable.query<CredentialRow>(`SELECT "organizationId" AS organization_id, "serviceAccountId" AS service_account_id, "credentialId" AS credential_id, "credentialDigest" AS credential_digest, "credentialPrefix" AS credential_prefix, "credentialFingerprint" AS credential_fingerprint, "expiresAt" AS expires_at, version FROM ${this.#table(this.#names.credentials)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4 AND "credentialId" = $5 AND status = 'active' AND ("expiresAt" IS NULL OR "expiresAt" > clock_timestamp()) FOR UPDATE`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId, oldCredentialId]);
			if (oldRows.rows.length !== 1) throw error("Service account credential is invalid", undefined, "AUTHORIZATION_CREDENTIAL_INVALID");
			this.#credentialFromRow(oldRows.rows[0]!);
			const versionRows = await queryable.query<{ version: unknown }>(`SELECT COALESCE(max(version), 0)::text AS version FROM ${this.#table(this.#names.credentials)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId]);
			const created = await this.#insertServiceAccountCredential(queryable, { organizationId, serviceAccountId, credentialId: `credential_${randomUUID()}`, expiresAt, version: nextCredentialVersion(versionRows.rows[0]?.version ?? 0), replacedCredentialId: oldCredentialId });
			const revoked = await queryable.query(`UPDATE ${this.#table(this.#names.credentials)} SET status = 'revoked', "revokedAt" = now(), "updatedAt" = now() WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4 AND "credentialId" = $5 AND status = 'active'`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId, oldCredentialId]);
			if (revoked.rowCount !== 1) throw error("Service account credential is unavailable");
			const advanced = (await this.#advanceAffectedRevisions(queryable, Object.freeze([organizationId])))[0]!;
			const { secret, ...credential } = created;
			return Object.freeze({ credential: Object.freeze(credential), secret, previousRevision: advanced.previousRevision, revision: advanced.revision });
		});
	}

	async revokeServiceAccountCredential(input: AuthorizationRevokeServiceAccountCredentialInput): Promise<AuthorizationAuthorityAffectedRevision> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		const serviceAccountId = scopeString(input.serviceAccountId, "serviceAccountId");
		const revokedCredentialId = credentialId(input.credentialId, "credentialId");
		return this.#withMutation(input.transaction, async (queryable) => {
			await this.#requireServiceAccount(queryable, organizationId, serviceAccountId, false);
			const revoked = await queryable.query(`UPDATE ${this.#table(this.#names.credentials)} SET status = 'revoked', "revokedAt" = now(), "updatedAt" = now() WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND "serviceAccountId" = $4 AND "credentialId" = $5 AND status = 'active'`, [this.identity.projectId, this.identity.environmentId, organizationId, serviceAccountId, revokedCredentialId]);
			if (revoked.rowCount !== 1) throw error("Service account credential is invalid", undefined, "AUTHORIZATION_CREDENTIAL_INVALID");
			return (await this.#advanceAffectedRevisions(queryable, Object.freeze([organizationId])))[0]!;
		});
	}

	async authenticateServiceAccountCredential(input: AuthorizationAuthenticateServiceAccountCredentialInput): Promise<AuthorizationAuthenticateServiceAccountCredentialResult> {
		const secret = assertCredentialSecret(input.secret);
		const digest = credentialSecretDigest(secret);
		const queryable = input.transaction ? transactionQueryable(input.transaction) : this.#database;
		const t = (name: string) => this.#table(name);
		const rows = await queryable.query<CredentialAuthenticationRow>(`WITH credential AS (
			SELECT c."organizationId", c."serviceAccountId", c."credentialId", c."credentialDigest", c."credentialPrefix", c."credentialFingerprint", c."expiresAt", c.version
			FROM ${t(this.#names.credentials)} c JOIN ${t(this.#names.serviceAccounts)} sa ON sa."projectId" = c."projectId" AND sa."environmentId" = c."environmentId" AND sa."organizationId" = c."organizationId" AND sa."serviceAccountId" = c."serviceAccountId"
			WHERE c."credentialDigest" = $1 AND c."projectId" = $2 AND c."environmentId" = $3 AND c.status = 'active' AND (c."expiresAt" IS NULL OR c."expiresAt" > clock_timestamp()) AND sa.status = 'active'
		), effective_roles AS (
			SELECT DISTINCT r."roleId" FROM credential c JOIN ${t(this.#names.assignments)} a ON a."projectId" = $2 AND a."environmentId" = $3 AND a."organizationId" = c."organizationId" AND a."subjectKind" = 'service_account' AND a."subjectId" = c."serviceAccountId"
			JOIN ${t(this.#names.roles)} r ON r."projectId" = a."projectId" AND r."environmentId" = a."environmentId" AND r."roleId" = a."roleId"
			WHERE r.status = 'active' AND (r."organizationId" IS NULL OR r."organizationId" = a."organizationId")
		), effective_actions AS (
			SELECT DISTINCT ac."actionName" FROM effective_roles er JOIN ${t(this.#names.roleActions)} ra ON ra."projectId" = $2 AND ra."environmentId" = $3 AND ra."roleId" = er."roleId"
			JOIN ${t(this.#names.actions)} ac ON ac."projectId" = ra."projectId" AND ac."environmentId" = ra."environmentId" AND ac."actionId" = ra."actionId"
		)
		SELECT c."organizationId" AS organization_id, c."serviceAccountId" AS service_account_id, c."credentialId" AS credential_id, c."credentialDigest" AS credential_digest, c."credentialPrefix" AS credential_prefix, c."credentialFingerprint" AS credential_fingerprint, c."expiresAt" AS expires_at, c.version,
			r.revision::text AS revision, COALESCE((SELECT array_agg("roleId" ORDER BY "roleId") FROM effective_roles), ARRAY[]::text[]) AS role_ids, COALESCE((SELECT array_agg("actionName" ORDER BY "actionName") FROM effective_actions), ARRAY[]::text[]) AS actions
		FROM credential c JOIN ${t(this.#names.revisions)} r ON r."projectId" = $2 AND r."environmentId" = $3 AND r."organizationId" = c."organizationId" AND r.terminal = false`, [digest, this.identity.projectId, this.identity.environmentId]);
		if (rows.rows.length !== 1) throw error("Service account credential is invalid", undefined, "AUTHORIZATION_CREDENTIAL_INVALID");
		const row = rows.rows[0]!;
		const actions = decodeSortedStrings(row.actions, "actions").map((action) => canonicalActionName(action, "stored action"));
		if (actions.length > MAX_EFFECTIVE_ACTIONS) throw error("Authorization action limit was exceeded", undefined, "AUTHORIZATION_ACTION_LIMIT_EXCEEDED");
		const credential = this.#credentialFromRow(row);
		return Object.freeze({ projectId: this.identity.projectId, environmentId: this.identity.environmentId, organizationId: credential.organizationId, subject: Object.freeze({ kind: "service_account", id: credential.serviceAccountId }), credential, roleIds: decodeSortedStrings(row.role_ids, "roles"), actions: Object.freeze(actions), revision: canonicalRevision(row.revision) });
	}

	async listRoles(input: AuthorizationAuthorityListRolesInput): Promise<readonly AuthorizationAuthorityRole[]> {
		const organizationId = input.organizationId === undefined
			? undefined
			: scopeString(input.organizationId, "organizationId");
		const queryable = input.transaction ? transactionQueryable(input.transaction) : this.#database;
		if (organizationId !== undefined) await this.#requireActiveOrganization(queryable, organizationId);
		const roles = this.#table(this.#names.roles);
		const rows = await queryable.query<RoleListRow>(`SELECT r."roleId" AS role_id, r."organizationId" AS organization_id, r.slug, r.name, r.description, r."builtIn" AS built_in, r.status, COALESCE(array_agg(a."actionName" ORDER BY a."actionName") FILTER (WHERE a."actionName" IS NOT NULL), ARRAY[]::text[]) AS actions FROM ${roles} r LEFT JOIN ${this.#table(this.#names.roleActions)} ra ON ra."projectId" = r."projectId" AND ra."environmentId" = r."environmentId" AND ra."roleId" = r."roleId" LEFT JOIN ${this.#table(this.#names.actions)} a ON a."projectId" = ra."projectId" AND a."environmentId" = ra."environmentId" AND a."actionId" = ra."actionId" WHERE r."projectId" = $1 AND r."environmentId" = $2 AND ($3::text IS NULL OR r."organizationId" IS NULL OR r."organizationId" = $3) GROUP BY r."projectId", r."environmentId", r."roleId", r."organizationId", r.slug, r.name, r.description, r."builtIn", r.status ORDER BY r.slug, r."roleId"`, [this.identity.projectId, this.identity.environmentId, organizationId ?? null]);
		return Object.freeze(rows.rows.map((row) => authorizationRole({ roleId: row.role_id, organizationId: row.organization_id, slug: row.slug, name: row.name, description: row.description, builtIn: row.built_in, status: row.status }, decodeSortedStrings(row.actions, "role actions").map((action) => canonicalActionName(action, "stored action")), "stored role")));
	}

	async listSubjectAssignments(input: AuthorizationAuthorityListSubjectAssignmentsInput): Promise<readonly AuthorizationAuthorityAssignment[]> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		const subject = input.subject === undefined ? undefined : authorizationSubject(input.subject, "subject");
		const queryable = input.transaction ? transactionQueryable(input.transaction) : this.#database;
		await this.#requireActiveOrganization(queryable, organizationId);
		const rows = await queryable.query<AssignmentRow>(`SELECT "organizationId" AS organization_id, "subjectKind" AS subject_kind, "subjectId" AS subject_id, "roleId" AS role_id FROM ${this.#table(this.#names.assignments)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3 AND ($4::text IS NULL OR ("subjectKind" = $4 AND "subjectId" = $5)) ORDER BY "subjectKind", "subjectId", "roleId"`, [this.identity.projectId, this.identity.environmentId, organizationId, subject?.kind ?? null, subject?.id ?? null]);
		return Object.freeze(rows.rows.map((row) => Object.freeze({ organizationId: scopeString(row.organization_id, "stored assignment organizationId"), subject: authorizationSubject({ kind: row.subject_kind, id: row.subject_id }, "stored assignment subject"), roleId: roleId(row.role_id, "stored assignment roleId") })));
	}

	async readEffective(input: AuthorizationAuthorityReadInput): Promise<AuthorizationAuthorityReadResult> {
		const organizationId = scopeString(input.organizationId, "organizationId");
		if (!input.subject || (input.subject.kind !== "principal" && input.subject.kind !== "service_account")) throw error("Authorization subject is invalid", undefined, "AUTHORIZATION_INPUT_INVALID");
		const subject = Object.freeze({ kind: input.subject.kind, id: scopeString(input.subject.id, "subject.id") });
		const queryable = input.transaction ? transactionQueryable(input.transaction) : this.#database;
		const t = (name: string) => qualified(this.schema, name);
		const row = await queryable.query<ReadRow & { terminal: unknown }>(`WITH revision_row AS (
			SELECT revision::text AS revision, terminal FROM ${t(this.#names.revisions)} WHERE "projectId" = $1 AND "environmentId" = $2 AND "organizationId" = $3
		), effective_roles AS (
			SELECT DISTINCT r."roleId" FROM ${t(this.#names.assignments)} a
			JOIN ${t(this.#names.roles)} r ON r."projectId" = a."projectId" AND r."environmentId" = a."environmentId" AND r."roleId" = a."roleId"
			WHERE a."projectId" = $1 AND a."environmentId" = $2 AND a."organizationId" = $3 AND a."subjectKind" = $4 AND a."subjectId" = $5
			AND r.status = 'active' AND (r."organizationId" IS NULL OR r."organizationId" = a."organizationId")
		), effective_actions AS (
			SELECT DISTINCT ac."actionName" FROM effective_roles er JOIN ${t(this.#names.roleActions)} ra ON ra."projectId" = $1 AND ra."environmentId" = $2 AND ra."roleId" = er."roleId"
			JOIN ${t(this.#names.actions)} ac ON ac."projectId" = ra."projectId" AND ac."environmentId" = ra."environmentId" AND ac."actionId" = ra."actionId"
		)
		SELECT (SELECT revision FROM revision_row) AS revision, (SELECT terminal FROM revision_row) AS terminal,
			CASE WHEN $4 = 'principal' THEN true ELSE EXISTS (SELECT 1 FROM ${t(this.#names.serviceAccounts)} sa WHERE sa."projectId" = $1 AND sa."environmentId" = $2 AND sa."organizationId" = $3 AND sa."serviceAccountId" = $5 AND sa.status = 'active') END AS subject_valid,
			COALESCE((SELECT array_agg("roleId" ORDER BY "roleId") FROM effective_roles), ARRAY[]::text[]) AS role_ids,
			COALESCE((SELECT array_agg("actionName" ORDER BY "actionName") FROM effective_actions), ARRAY[]::text[]) AS actions`, [this.identity.projectId, this.identity.environmentId, organizationId, subject.kind, subject.id]);
		if (row.rows.length !== 1) throw error("Authorization read is unavailable");
		const result = row.rows[0]!;
		if (result.revision === null || result.revision === undefined) throw error("Authorization revision was not found", undefined, "AUTHORIZATION_REVISION_NOT_FOUND");
		if (result.terminal !== false) throw error("Organization authorization is archived", undefined, "AUTHORIZATION_ORGANIZATION_ARCHIVED");
		const revision = canonicalRevision(result.revision);
		if (result.subject_valid !== true) throw error("Authorization subject was not found", undefined, "AUTHORIZATION_SUBJECT_NOT_FOUND");
		return Object.freeze({ projectId: this.identity.projectId, environmentId: this.identity.environmentId, organizationId, subject, roleIds: decodeSortedStrings(result.role_ids, "roles"), actions: decodeSortedStrings(result.actions, "actions"), revision });
	}
}
