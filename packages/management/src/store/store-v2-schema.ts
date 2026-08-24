import { createHash } from "node:crypto";
import {
	STORE_V2_COLLECTIONS,
	type StoreV2Collection,
} from "./types.js";

export const STORE_V2_SCHEMA_VERSION = 2 as const;
export const STORE_V2_PRINCIPAL_AUTHORITY_VERSION = 1 as const;
export const STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY =
	"store_v2_authoritative_collections";
export const STORE_V2_PRINCIPAL_AUTHORITY_VERSION_META_KEY =
	"store_v2_principal_authority_version";
export const STORE_V2_PRINCIPAL_REVISION_META_KEY =
	"store_v2_principal_revision";
export const STORE_V2_PRINCIPAL_STATE_META_KEY =
	"store_v2_principal_state";
export const STORE_V2_TOPOLOGY_AUTHORITY_VERSION_META_KEY =
	"store_v2_topology_authority_version";

/** Strict parser shared by every store-v2 revision/version metadata read. */
export function parseStoreV2MetadataInteger(value: unknown): number | null {
	if (typeof value === "number") {
		return Number.isSafeInteger(value) && value >= 0 ? value : null;
	}
	if (typeof value !== "string" || !/^(0|[1-9]\d*)$/.test(value)) return null;
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

const STORE_V2_AUTHORITY_ORDER: readonly StoreV2Collection[] = [
	"events",
	"principals",
	"projects",
	"environments",
	"organizations",
];

export function canonicalStoreV2AuthoritySet(
	collections: readonly StoreV2Collection[],
): StoreV2Collection[] {
	const selected = new Set(collections);
	return STORE_V2_AUTHORITY_ORDER.filter((collection) => selected.has(collection));
}

export function parseStoreV2AuthoritySet(value: unknown): StoreV2Collection[] {
	if (!Array.isArray(value)) {
		throw new Error("STORE_V2_AUTHORITY_SET_INVALID");
	}
	const valid = new Set<string>(STORE_V2_COLLECTIONS);
	const collections: StoreV2Collection[] = [];
	for (const collection of value) {
		if (typeof collection !== "string" || !valid.has(collection)) {
			throw new Error("STORE_V2_AUTHORITY_SET_INVALID");
		}
		if (collections.includes(collection as StoreV2Collection)) {
			throw new Error("STORE_V2_AUTHORITY_SET_INVALID");
		}
		collections.push(collection as StoreV2Collection);
	}
	return canonicalStoreV2AuthoritySet(collections);
}

export interface StoreV2TableNames {
	meta: string;
	projects: string;
	environments: string;
	principals: string;
	organizations: string;
	events: string;
	productPresentations: string;
	productAuthDomains: string;
	productEmailSenders: string;
	productEmailTemplates: string;
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

export function storeV2PrincipalEmailUniqueIndex(
	tables: StoreV2TableNames,
): string {
	return derivedIdentifier(`${tables.principals}_email_unique`);
}

export function storeV2PrincipalExternalIdUniqueIndex(
	tables: StoreV2TableNames,
): string {
	return derivedIdentifier(`${tables.principals}_external_id_unique`);
}

export function storeV2PrincipalProjectionGuardStatements(
	tables: StoreV2TableNames,
	snapshotTable: string,
): string[] {
	const safeSnapshotTable = safeIdentifier(snapshotTable);
	const functionName = derivedIdentifier(`${safeSnapshotTable}_v2_principal_guard_fn`);
	const triggerName = derivedIdentifier(`${safeSnapshotTable}_v2_principal_guard`);
	const authorityFunctionName = derivedIdentifier(`${safeSnapshotTable}_v2_authority_guard_fn`);
	const authorityTriggerName = derivedIdentifier(`${safeSnapshotTable}_v2_authority_guard`);
	return [
		`CREATE OR REPLACE FUNCTION ${functionName}() RETURNS trigger AS $$
		DECLARE authority_set jsonb;
		BEGIN
			SELECT value INTO authority_set
			FROM ${tables.meta}
			WHERE key = '${STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY}';
			IF authority_set IS NULL OR jsonb_typeof(authority_set) <> 'array'
			THEN
				RAISE EXCEPTION USING
					ERRCODE = '23514',
					MESSAGE = 'STORE_V2_AUTHORITY_SET_INVALID';
			END IF;
			IF EXISTS (
					SELECT 1 FROM jsonb_array_elements_text(authority_set) AS item(value)
					WHERE item.value NOT IN ('events', 'principals', 'projects', 'environments', 'organizations')
				)
				OR jsonb_array_length(authority_set) <> (
					SELECT count(DISTINCT item.value)
					FROM jsonb_array_elements_text(authority_set) AS item(value)
				)
			THEN
				RAISE EXCEPTION USING
					ERRCODE = '23514',
					MESSAGE = 'STORE_V2_AUTHORITY_SET_INVALID';
			END IF;
			IF authority_set ? 'principals'
				AND (
					jsonb_typeof(NEW.data->'principals') IS DISTINCT FROM 'array'
					OR jsonb_array_length(NEW.data->'principals') > 0
				)
			THEN
				RAISE EXCEPTION USING
					ERRCODE = '23514',
					MESSAGE = 'STORE_V2_PRINCIPAL_PROJECTION_FORBIDDEN';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS ${triggerName} ON ${safeSnapshotTable}`,
		`CREATE TRIGGER ${triggerName}
			BEFORE INSERT OR UPDATE OF data ON ${safeSnapshotTable}
			FOR EACH ROW EXECUTE FUNCTION ${functionName}()`,
		`CREATE OR REPLACE FUNCTION ${authorityFunctionName}() RETURNS trigger AS $$
		BEGIN
			IF OLD.key = '${STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY}'
				AND OLD.value ? 'principals'
				AND NOT (NEW.value ? 'principals')
				AND current_setting('clearance.principal_authority_rollback', true)
					IS DISTINCT FROM '${STORE_V2_PRINCIPAL_AUTHORITY_VERSION}'
			THEN
				RAISE EXCEPTION USING
					ERRCODE = '23514',
					MESSAGE = 'STORE_V2_PRINCIPAL_AUTHORITY_ROLLBACK_CAPABILITY_REQUIRED';
			END IF;
			IF OLD.key = '${STORE_V2_AUTHORITATIVE_COLLECTIONS_META_KEY}'
				AND (OLD.value ? 'projects' OR OLD.value ? 'environments' OR OLD.value ? 'organizations')
				AND NOT (NEW.value ? 'projects' AND NEW.value ? 'environments' AND NEW.value ? 'organizations')
				AND current_setting('clearance.topology_authority_rollback', true)
					IS DISTINCT FROM '1'
			THEN
				RAISE EXCEPTION USING
					ERRCODE = '23514',
					MESSAGE = 'STORE_V2_TOPOLOGY_AUTHORITY_ROLLBACK_CAPABILITY_REQUIRED';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`,
		`DROP TRIGGER IF EXISTS ${authorityTriggerName} ON ${tables.meta}`,
		`CREATE TRIGGER ${authorityTriggerName}
			BEFORE UPDATE OF value ON ${tables.meta}
			FOR EACH ROW EXECUTE FUNCTION ${authorityFunctionName}()`,
	];
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
		productPresentations: derivedIdentifier(`${safePrefix}product_presentations`),
		productAuthDomains: derivedIdentifier(`${safePrefix}product_auth_domains`),
		productEmailSenders: derivedIdentifier(`${safePrefix}product_email_senders`),
		productEmailTemplates: derivedIdentifier(`${safePrefix}product_email_templates`),
	};
}

export function storeV2SchemaStatements(
	tables: StoreV2TableNames,
): string[] {
	const projectNameIndex = derivedIdentifier(`${tables.projects}_name_unique`);
	const projectSlugIndex = derivedIdentifier(`${tables.projects}_slug_unique`);
	const projectCursorIndex = derivedIdentifier(`${tables.projects}_cursor`);
	const environmentCursorIndex = derivedIdentifier(
		`${tables.environments}_cursor`,
	);
	const environmentNameIndex = derivedIdentifier(
		`${tables.environments}_project_name`,
	);
	const environmentSlugIndex = derivedIdentifier(
		`${tables.environments}_project_slug`,
	);
	const principalEmailIndex = storeV2PrincipalEmailUniqueIndex(tables);
	const principalExternalIdIndex = storeV2PrincipalExternalIdUniqueIndex(tables);
	const principalCursorIndex = derivedIdentifier(`${tables.principals}_cursor`);
	const organizationSlugIndex = derivedIdentifier(
		`${tables.organizations}_slug_unique`,
	);
	const organizationExternalIdIndex = derivedIdentifier(
		`${tables.organizations}_external_id`,
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
	const activeAuthDomainIndex = derivedIdentifier(
		`${tables.productAuthDomains}_active_scope`,
	);
	const claimedAuthDomainIndex = derivedIdentifier(
		`${tables.productAuthDomains}_claimed_hostname`,
	);
	const legacyOwnedAuthDomainIndex = derivedIdentifier(
		`${tables.productAuthDomains}_owned_hostname`,
	);

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
			created_at timestamptz(3) NOT NULL,
			updated_at timestamptz(3) NOT NULL
		)`,
		`ALTER TABLE ${tables.projects}
			ALTER COLUMN created_at TYPE timestamptz(3)
				USING date_trunc('milliseconds', created_at),
			ALTER COLUMN updated_at TYPE timestamptz(3)
				USING date_trunc('milliseconds', updated_at)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${projectNameIndex}
			ON ${tables.projects} (lower(name))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${projectSlugIndex}
			ON ${tables.projects} (lower(slug))`,
		`CREATE INDEX IF NOT EXISTS ${projectCursorIndex}
			ON ${tables.projects} (created_at ASC, id ASC)`,
		`CREATE TABLE IF NOT EXISTS ${tables.environments} (
			id text PRIMARY KEY,
			project_id text NOT NULL REFERENCES ${tables.projects}(id) ON DELETE RESTRICT,
			name text NOT NULL,
			slug text NOT NULL,
			kind text NOT NULL CHECK (kind IN ('development', 'preview', 'production')),
			created_at timestamptz(3) NOT NULL,
			updated_at timestamptz(3) NOT NULL,
			UNIQUE (project_id, id)
		)`,
		`ALTER TABLE ${tables.environments}
			ALTER COLUMN created_at TYPE timestamptz(3)
				USING date_trunc('milliseconds', created_at),
			ALTER COLUMN updated_at TYPE timestamptz(3)
				USING date_trunc('milliseconds', updated_at)`,
		`CREATE INDEX IF NOT EXISTS ${environmentCursorIndex}
			ON ${tables.environments} (project_id, created_at DESC, id DESC)`,
		`CREATE INDEX IF NOT EXISTS ${environmentNameIndex}
			ON ${tables.environments} (project_id, name)`,
		`CREATE INDEX IF NOT EXISTS ${environmentSlugIndex}
			ON ${tables.environments} (project_id, slug)`,
		`CREATE TABLE IF NOT EXISTS ${tables.principals} (
			id text PRIMARY KEY,
			project_id text NOT NULL,
			environment_id text NOT NULL,
			email text NOT NULL,
			name text NOT NULL,
			status text NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
			external_id text,
			created_at timestamptz(3) NOT NULL,
			updated_at timestamptz(3) NOT NULL,
			FOREIGN KEY (project_id, environment_id)
				REFERENCES ${tables.environments}(project_id, id) ON DELETE RESTRICT
		)`,
		`ALTER TABLE ${tables.principals}
			ALTER COLUMN created_at TYPE timestamptz(3)
				USING date_trunc('milliseconds', created_at),
			ALTER COLUMN updated_at TYPE timestamptz(3)
				USING date_trunc('milliseconds', updated_at)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${principalEmailIndex}
			ON ${tables.principals} (project_id, environment_id, lower(email))
			WHERE status <> 'deleted'`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${principalExternalIdIndex}
			ON ${tables.principals} (project_id, environment_id, external_id)
			WHERE status <> 'deleted' AND external_id IS NOT NULL`,
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
			created_at timestamptz(3) NOT NULL,
			updated_at timestamptz(3) NOT NULL,
			FOREIGN KEY (project_id, environment_id)
				REFERENCES ${tables.environments}(project_id, id) ON DELETE RESTRICT
		)`,
		`ALTER TABLE ${tables.organizations}
			ALTER COLUMN created_at TYPE timestamptz(3)
				USING date_trunc('milliseconds', created_at),
			ALTER COLUMN updated_at TYPE timestamptz(3)
				USING date_trunc('milliseconds', updated_at)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${organizationSlugIndex}
			ON ${tables.organizations} (project_id, environment_id, slug)
			WHERE status <> 'archived'`,
		`CREATE INDEX IF NOT EXISTS ${organizationExternalIdIndex}
			ON ${tables.organizations} (project_id, environment_id, external_id)
			WHERE status <> 'archived' AND external_id IS NOT NULL`,
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
			source text NOT NULL CHECK (source IN ('cli', 'console', 'api', 'system', 'migration', 'import', 'sso', 'scim')),
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
		`CREATE TABLE IF NOT EXISTS ${tables.productPresentations} (
			project_id text NOT NULL,
			environment_id text NOT NULL,
			product_label text NOT NULL,
			home_label text NOT NULL,
			accent_color text NOT NULL CHECK (accent_color ~ '^#[0-9a-f]{6}$'),
			logo_url text,
			version bigint NOT NULL CHECK (version > 0),
			updated_at timestamptz(3) NOT NULL,
			PRIMARY KEY (project_id, environment_id),
			FOREIGN KEY (project_id, environment_id)
				REFERENCES ${tables.environments}(project_id, id) ON DELETE RESTRICT
		)`,
		`ALTER TABLE ${tables.productPresentations} ADD COLUMN IF NOT EXISTS logo_url text`,
		`CREATE TABLE IF NOT EXISTS ${tables.productAuthDomains} (
			project_id text NOT NULL,
			environment_id text NOT NULL,
			origin text NOT NULL,
			hostname text NOT NULL,
			dns_name text NOT NULL,
			challenge_digest bytea NOT NULL CHECK (octet_length(challenge_digest) = 32),
			state text NOT NULL CHECK (state IN ('pending', 'verified', 'active', 'disabled')),
			version bigint NOT NULL CHECK (version > 0),
			verified_at timestamptz(3),
			updated_at timestamptz(3) NOT NULL,
			PRIMARY KEY (project_id, environment_id, origin),
			FOREIGN KEY (project_id, environment_id)
				REFERENCES ${tables.environments}(project_id, id) ON DELETE RESTRICT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${activeAuthDomainIndex}
			ON ${tables.productAuthDomains} (project_id, environment_id)
			WHERE state = 'active'`,
		`DROP INDEX IF EXISTS ${legacyOwnedAuthDomainIndex}`,
		`CREATE UNIQUE INDEX IF NOT EXISTS ${claimedAuthDomainIndex}
			ON ${tables.productAuthDomains} (hostname)
			WHERE state <> 'disabled'`,
		`CREATE TABLE IF NOT EXISTS ${tables.productEmailSenders} (
			project_id text NOT NULL,
			environment_id text NOT NULL,
			display_name text NOT NULL,
			address text NOT NULL,
			domain text NOT NULL,
			version bigint NOT NULL CHECK (version > 0),
			updated_at timestamptz(3) NOT NULL,
			PRIMARY KEY (project_id, environment_id),
			CHECK (position('@' IN address) > 1),
			CHECK (domain = lower(domain)),
			FOREIGN KEY (project_id, environment_id)
				REFERENCES ${tables.environments}(project_id, id) ON DELETE RESTRICT
		)`,
		`CREATE TABLE IF NOT EXISTS ${tables.productEmailTemplates} (
			project_id text NOT NULL,
			environment_id text NOT NULL,
			kind text NOT NULL CHECK (kind IN ('verification', 'password-reset', 'invitation', 'email-change')),
			subject text NOT NULL,
			plain_text text NOT NULL DEFAULT '',
			html text NOT NULL DEFAULT '',
			variables jsonb NOT NULL CHECK (jsonb_typeof(variables) = 'array'),
			version bigint NOT NULL CHECK (version > 0),
			content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
			updated_at timestamptz(3) NOT NULL,
			PRIMARY KEY (project_id, environment_id, kind),
			FOREIGN KEY (project_id, environment_id)
				REFERENCES ${tables.environments}(project_id, id) ON DELETE RESTRICT
		)`,
		`ALTER TABLE ${tables.productEmailTemplates} ADD COLUMN IF NOT EXISTS plain_text text NOT NULL DEFAULT ''`,
		`ALTER TABLE ${tables.productEmailTemplates} ADD COLUMN IF NOT EXISTS html text NOT NULL DEFAULT ''`,
	];
}
