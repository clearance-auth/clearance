import { createHash } from "node:crypto";

export const STORE_V2_SCHEMA_VERSION = 1 as const;

export interface StoreV2TableNames {
	meta: string;
	projects: string;
	environments: string;
	principals: string;
	organizations: string;
	events: string;
}

const IDENTIFIER = /^[a-z_][a-z0-9_]*$/i;
const POSTGRES_IDENTIFIER_MAX = 63;

function safeIdentifier(value: string): string {
	if (!IDENTIFIER.test(value) || value.length > POSTGRES_IDENTIFIER_MAX) {
		throw new Error(`Invalid store-v2 Postgres identifier: ${value}`);
	}
	return value;
}

function derivedIdentifier(value: string): string {
	if (value.length <= POSTGRES_IDENTIFIER_MAX) return safeIdentifier(value);
	const digest = createHash("sha256").update(value, "utf8").digest("hex").slice(0, 12);
	return safeIdentifier(
		`${value.slice(0, POSTGRES_IDENTIFIER_MAX - digest.length - 1)}_${digest}`,
	);
}

export function storeV2TableNames(prefix: string): StoreV2TableNames {
	const safePrefix = safeIdentifier(prefix);
	return {
		meta: safeIdentifier(`${safePrefix}meta`),
		projects: safeIdentifier(`${safePrefix}projects`),
		environments: safeIdentifier(`${safePrefix}environments`),
		principals: safeIdentifier(`${safePrefix}principals`),
		organizations: safeIdentifier(`${safePrefix}organizations`),
		events: safeIdentifier(`${safePrefix}events`),
	};
}

export function storeV2SchemaStatements(
	tables: StoreV2TableNames,
): string[] {
	const projectNameIndex = derivedIdentifier(`${tables.projects}_name_unique`);
	const projectSlugIndex = derivedIdentifier(`${tables.projects}_slug_unique`);
	const environmentCursorIndex = derivedIdentifier(
		`${tables.environments}_cursor`,
	);
	const principalEmailIndex = derivedIdentifier(
		`${tables.principals}_email_unique`,
	);
	const principalCursorIndex = derivedIdentifier(`${tables.principals}_cursor`);
	const organizationSlugIndex = derivedIdentifier(
		`${tables.organizations}_slug_unique`,
	);
	const organizationCursorIndex = derivedIdentifier(
		`${tables.organizations}_cursor`,
	);
	const eventCursorIndex = derivedIdentifier(`${tables.events}_cursor`);
	const eventScopeCursorIndex = derivedIdentifier(`${tables.events}_scope_cursor`);
	const eventOrganizationCursorIndex = derivedIdentifier(
		`${tables.events}_organization_cursor`,
	);
	const eventActionCursorIndex = derivedIdentifier(`${tables.events}_action_cursor`);

	return [
		`CREATE TABLE IF NOT EXISTS ${tables.meta} (
			key text PRIMARY KEY,
			value jsonb NOT NULL,
			updated_at timestamptz NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS ${tables.projects} (
			id text PRIMARY KEY,
			name text NOT NULL,
			slug text NOT NULL,
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${projectNameIndex}
			ON ${tables.projects} (lower(name))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${projectSlugIndex}
			ON ${tables.projects} (lower(slug))`,
		`CREATE TABLE IF NOT EXISTS ${tables.environments} (
			id text PRIMARY KEY,
			project_id text NOT NULL REFERENCES ${tables.projects}(id) ON DELETE RESTRICT,
			name text NOT NULL,
			slug text NOT NULL,
			kind text NOT NULL CHECK (kind IN ('development', 'preview', 'production')),
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL,
			UNIQUE (project_id, id)
		)`,
		`CREATE INDEX IF NOT EXISTS ${environmentCursorIndex}
			ON ${tables.environments} (project_id, created_at DESC, id DESC)`,
		`CREATE TABLE IF NOT EXISTS ${tables.principals} (
			id text PRIMARY KEY,
			project_id text NOT NULL,
			environment_id text NOT NULL,
			email text NOT NULL,
			name text NOT NULL,
			status text NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
			external_id text,
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL,
			FOREIGN KEY (project_id, environment_id)
				REFERENCES ${tables.environments}(project_id, id) ON DELETE RESTRICT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${principalEmailIndex}
			ON ${tables.principals} (project_id, environment_id, lower(email))
			WHERE status <> 'deleted'`,
		`CREATE INDEX IF NOT EXISTS ${principalCursorIndex}
			ON ${tables.principals}
				(project_id, environment_id, created_at DESC, id DESC)`,
		`CREATE TABLE IF NOT EXISTS ${tables.organizations} (
			id text PRIMARY KEY,
			project_id text NOT NULL,
			environment_id text NOT NULL,
			name text NOT NULL,
			slug text NOT NULL,
			status text NOT NULL CHECK (status IN ('active', 'archived')),
			external_id text,
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL,
			FOREIGN KEY (project_id, environment_id)
				REFERENCES ${tables.environments}(project_id, id) ON DELETE RESTRICT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${organizationSlugIndex}
			ON ${tables.organizations} (project_id, environment_id, slug)
			WHERE status <> 'archived'`,
		`CREATE INDEX IF NOT EXISTS ${organizationCursorIndex}
			ON ${tables.organizations}
				(project_id, environment_id, created_at DESC, id DESC)`,
		`CREATE TABLE IF NOT EXISTS ${tables.events} (
			id text PRIMARY KEY,
			correlation_id text NOT NULL,
			project_id text,
			environment_id text,
			organization_id text,
			actor text NOT NULL,
			action text NOT NULL,
			subject_type text NOT NULL,
			subject_id text,
			outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'pending')),
			source text NOT NULL CHECK (source IN ('cli', 'console', 'api', 'system', 'migration', 'sso', 'scim')),
			message text NOT NULL,
			metadata jsonb,
			created_at timestamptz NOT NULL,
			committed_revision bigint NOT NULL,
			retention_marker boolean NOT NULL DEFAULT false,
			visible boolean NOT NULL DEFAULT true
		)`,
		`CREATE INDEX IF NOT EXISTS ${eventCursorIndex}
			ON ${tables.events} (created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS ${eventScopeCursorIndex}
			ON ${tables.events}
				(project_id, environment_id, created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS ${eventOrganizationCursorIndex}
			ON ${tables.events} (organization_id, created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS ${eventActionCursorIndex}
			ON ${tables.events} (action, created_at DESC, id DESC)`,
	];
}
