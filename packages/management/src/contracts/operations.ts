import type {
	AuditEvent,
	BackupRecord,
	CustomRole,
	DoctorCheck,
	Environment,
	Membership,
	MigrationPlan,
	Organization,
	Principal,
	Project,
	ReadinessReport,
} from "../types/resources.js";
import type { ApiKeyView, CreatedApiKey } from "../services/api-keys.js";
import type {
	EventInspectResult,
	EventsExportEnvelope,
	EventsExportFormat,
	ReplayDiagnosticResult,
} from "../services/events.js";
import type { ResourceScope } from "../services/scope.js";
import type { ArchiveOrganizationResult } from "../services/core.js";
import type {
	EnvironmentInspectResult,
	EnvironmentPromoteResult,
	overviewStats,
} from "../services/core.js";
import type {
	MemberImportPlan,
	MemberImportResult,
} from "../services/members-import.js";
import type { validateRole } from "../services/roles.js";
import type {
	PublicDirectoryConnection,
	PublicIdentityConnection,
} from "../services/redact.js";
import type { RevokeSessionResult, SessionView } from "../services/sessions.js";
import type { ConfigRecord, diffConfig, publicConfig } from "../services/config.js";
import type { MigrationPreview, verifyMigration } from "../services/migration.js";
import type {
	applyUpgrade,
	planUpgrade,
	rollbackUpgrade,
	verifyUpgrade,
} from "../services/upgrade.js";
import type {
	getRuntimeSchemaStatus,
	migrateRuntimeSchema,
	planRuntimeSchema,
} from "../services/runtime-schema.js";
import type { restoreBackup, upgradeCheck } from "../services/backup.js";
import type {
	restorePostgresBackup,
	upgradeCheckWithDb,
} from "../services/backup-pg.js";
import type { createSetupLink } from "../services/setup-links.js";
import type { testSsoConnection } from "../services/sso.js";
import type { testSsoConnectionReal } from "../services/sso-real.js";
import type { testScimConnection } from "../services/scim.js";
import type { testScimConnectionReal } from "../services/scim-real.js";
import type {
	testScimConnectionLive,
	testSsoConnectionLive,
} from "../services/live-conformance.js";

export type OperationConfirmation =
	| "none"
	| "client-required"
	| "client-required-when-live"
	| "server-required";
export type OperationMethod = "GET" | "POST" | "PATCH" | "DELETE";

export interface ManagementOperationTypes {
	"system.init": {
		input: { name?: string; environment?: string };
		output: { project: Project; environment: Environment };
	};
	"system.doctor": {
		input: Record<string, never>;
		output: { checks: DoctorCheck[]; ok: boolean; releaseVersion: string };
	};
	"system.dev": {
		input: Record<string, never>;
		output: { commands: string[] };
	};
	"system.overview": {
		input: Record<string, never>;
		output: ReturnType<typeof overviewStats>;
	};
	"projects.list": {
		input: Record<string, never>;
		output: { projects: Project[]; scope: ResourceScope };
	};
	"projects.inspect": {
		input: { id?: string };
		output: { project: Project; overview: ReturnType<typeof overviewStats>; scope: ResourceScope };
	};
	"projects.create": {
		input: { name: string; dryRun?: boolean };
		output:
			| { project: Project }
			| { dryRun: true; project: Pick<Project, "name" | "slug"> };
	};
	"environments.list": {
		input: Record<string, never>;
		output: { environments: Environment[]; scope: ResourceScope };
	};
	"environments.inspect": {
		input: { id?: string };
		output: EnvironmentInspectResult;
	};
	"environments.create": {
		input: { name: string; projectId?: string; kind?: Environment["kind"]; dryRun?: boolean };
		output:
			| { environment: Environment; scope: ResourceScope }
			| {
					dryRun: true;
					environment: Pick<Environment, "projectId" | "name" | "slug" | "kind">;
					scope: ResourceScope;
			  };
	};
	"environments.promote": {
		input: { to: string; from?: string; dryRun?: boolean; confirm?: boolean };
		output: EnvironmentPromoteResult;
	};
	"events.list": {
		input: { limit?: number; cursor?: string; action?: string; organizationId?: string };
		output: { events: AuditEvent[]; nextCursor: string | null; scope: ResourceScope };
	};
	"events.tail": {
		input: { limit?: number; action?: string; organizationId?: string; pollInterval?: number; maxEvents?: number; once?: boolean };
		output: { events: AuditEvent[]; nextCursor: string | null; scope: ResourceScope };
	};
	"events.inspect": {
		input: { id: string };
		output: EventInspectResult;
	};
	"events.export": {
		input: { format?: EventsExportFormat; limit?: number; action?: string; organizationId?: string; before?: string };
		output: EventsExportEnvelope;
	};
	"events.replay": {
		input: { id: string; dryRun?: boolean; confirm?: boolean };
		output: ReplayDiagnosticResult;
	};
	"keys.list": {
		input: { includeRevoked?: boolean };
		output: { apiKeys: ApiKeyView[]; scope: ResourceScope };
	};
	"keys.create": {
		input: { name: string; scopes?: string[]; dryRun?: boolean };
		output:
			| (CreatedApiKey & { scope: ResourceScope })
			| { dryRun: true; apiKey: { name: string; scopes: string[] }; secretGenerated: false; scope: ResourceScope };
	};
	"keys.rotate": {
		input: { id: string; dryRun?: boolean };
		output:
			| (CreatedApiKey & { revokedKey: ApiKeyView; scope: ResourceScope })
			| { dryRun: true; apiKey: ApiKeyView; secretGenerated: false; scope: ResourceScope };
	};
	"keys.revoke": {
		input: { id: string; dryRun?: boolean };
		output:
			| { apiKey: ApiKeyView; idempotent: boolean; scope: ResourceScope }
			| { dryRun: true; apiKey: ApiKeyView; wouldChange: boolean; scope: ResourceScope };
	};
	"sessions.list": {
		input: { limit?: number; cursor?: string };
		output: { sessions: SessionView[]; nextCursor: string | null; scope: ResourceScope };
	};
	"sessions.revoke": {
		input: { id: string; dryRun?: boolean };
		output:
			| (RevokeSessionResult & { scope: ResourceScope })
			| { dryRun: true; session: SessionView; wouldChange: boolean; scope: ResourceScope };
	};
	"roles.list": {
		input: Record<string, never>;
		output: { roles: CustomRole[]; scope: ResourceScope };
	};
	"roles.validate": {
		input: { name?: string; slug?: string; permissions?: string[] };
		output: ReturnType<typeof validateRole>;
	};
	"roles.create": {
		input: { name: string; slug?: string; description?: string; permissions: string[]; dryRun?: boolean };
		output:
			| { role: CustomRole; scope: ResourceScope }
			| { dryRun: true; validation: ReturnType<typeof validateRole>; scope: ResourceScope };
	};
	"roles.update": {
		input: { id: string; name?: string; description?: string; permissions?: string[]; dryRun?: boolean };
		output:
			| { role: CustomRole; scope: ResourceScope }
			| { dryRun: true; id: string; validation: ReturnType<typeof validateRole>; scope: ResourceScope };
	};
	"sso.list": {
		input: { organizationId?: string };
		output: { connections: PublicIdentityConnection[]; scope: ResourceScope };
	};
	"sso.create": {
		input: {
			organizationId: string;
			provider: string;
			protocol?: "oidc" | "saml";
			issuer?: string;
			audience?: string;
			domain?: string;
			samlEntryPoint?: string;
			samlCertificate?: string;
		};
		output: { connection: PublicIdentityConnection };
	};
	"sso.configure": {
		input: { id: string; issuer?: string; audience?: string; domain?: string; domains?: string[]; dryRun?: boolean };
		output:
			| { connection: PublicIdentityConnection; scope: ResourceScope }
			| { dryRun: true; connection: PublicIdentityConnection; proposed: { issuer?: string; audience?: string; domains?: string[] }; scope: ResourceScope };
	};
	"sso.test": {
		input: { id: string; fixture?: string; live?: boolean };
		output:
			| Awaited<ReturnType<typeof testSsoConnection>>
			| Awaited<ReturnType<typeof testSsoConnectionReal>>
			| Awaited<ReturnType<typeof testSsoConnectionLive>>;
	};
	"sso.setupLink.create": {
		input: { organizationId: string };
		output: ReturnType<typeof createSetupLink> & { scope: ResourceScope };
	};
	"sso.rotate": {
		input: { id: string; dryRun?: boolean };
		output:
			| { connection: PublicIdentityConnection; scope: ResourceScope }
			| { dryRun: true; connection: PublicIdentityConnection; wouldChange: true; scope: ResourceScope };
	};
	"sso.disable": {
		input: { id: string; dryRun?: boolean };
		output:
			| { connection: PublicIdentityConnection; idempotent: boolean; runtimeRemoved?: boolean; scope: ResourceScope }
			| { dryRun: true; connection: PublicIdentityConnection; wouldChange: boolean; scope: ResourceScope };
	};
	"scim.list": {
		input: { organizationId?: string };
		output: { connections: PublicDirectoryConnection[]; scope: ResourceScope };
	};
	"scim.create": {
		input: { organizationId: string; provider: string; endpoint?: string };
		output: { connection: PublicDirectoryConnection & { bearerTokenOnce?: string } };
	};
	"scim.test": {
		input: { id: string; fixture?: string; live?: boolean; dryRun?: boolean };
		output:
			| Awaited<ReturnType<typeof testScimConnection>>
			| Awaited<ReturnType<typeof testScimConnectionReal>>
			| Awaited<ReturnType<typeof testScimConnectionLive>>;
	};
	"scim.setupLink.create": {
		input: { organizationId: string };
		output: ReturnType<typeof createSetupLink> & { scope: ResourceScope };
	};
	"scim.rotate": {
		input: { id: string; dryRun?: boolean };
		output:
			| { connection: PublicDirectoryConnection; scope: ResourceScope }
			| { dryRun: true; connection: PublicDirectoryConnection; wouldChange: true; scope: ResourceScope };
	};
	"scim.disable": {
		input: { id: string; dryRun?: boolean };
		output:
			| { connection: PublicDirectoryConnection; idempotent: boolean; runtimeRemoved?: boolean; scope: ResourceScope }
			| { dryRun: true; connection: PublicDirectoryConnection; wouldChange: boolean; scope: ResourceScope };
	};
	"scim.replay": {
		input: { traceId: string; dryRun?: boolean; confirm?: boolean };
		output: ReplayDiagnosticResult;
	};
	"readiness.check": {
		input: { organizationId: string };
		output: { report: ReadinessReport };
	};
	"readiness.report": {
		input: { organizationId: string };
		output: { report: ReadinessReport };
	};
	"config.get": {
		input: { key?: string };
		output: ReturnType<typeof publicConfig> & { scope: ResourceScope };
	};
	"config.set": {
		input: { key: string; value: string; dryRun?: boolean };
		output:
			| ({ ok: true; changed: boolean; key: string; scope: ResourceScope } & ReturnType<typeof publicConfig>)
			| ({ dryRun: true; changed: boolean; key: string; scope: ResourceScope } & ReturnType<typeof publicConfig>);
	};
	"config.validate": {
		input: { config?: ConfigRecord };
		output: { ok: true; source: "current" | "candidate"; scope: ResourceScope } & ReturnType<typeof publicConfig>;
	};
	"config.diff": {
		input: { config: ConfigRecord };
		output: ReturnType<typeof diffConfig> & { scope: ResourceScope };
	};
	"imports.legacy": {
		input: { fixture: string; dryRun?: boolean; confirm?: boolean };
		output:
			| { schemaVersion: "v1"; dryRun: true; source: "legacy"; preview: MigrationPreview; storeBackend: string }
			| {
					schemaVersion: "v1";
					dryRun: false;
					source: "legacy";
					migration: MigrationPlan;
					preview: MigrationPreview;
					verification: Omit<ReturnType<typeof verifyMigration>, "plan">;
					storeBackend: string;
			  };
	};
	"migrations.plan": {
		input: { source: "legacy"; fixture: string };
		output: { plan: MigrationPlan };
	};
	"migrations.run": {
		input: { id: string; fixture: string; dryRun?: boolean };
		output: { plan: MigrationPlan };
	};
	"migrations.verify": {
		input: { id: string; fixture: string };
		output: ReturnType<typeof verifyMigration>;
	};
	"migrations.rollback": {
		input: { id: string; fixture: string; confirm?: boolean };
		output: { plan: MigrationPlan };
	};
	"migrations.status": {
		input: { id: string };
		output: { plan: MigrationPlan };
	};
	"backups.create": {
		input: Record<string, never>;
		output: { backup: BackupRecord };
	};
	"backups.verify": {
		input: { id: string };
		output: { backup: BackupRecord };
	};
	"backups.restore": {
		input: { id: string; target?: string; confirm?: boolean };
		output:
			| Awaited<ReturnType<typeof restoreBackup>>
			| Awaited<ReturnType<typeof restorePostgresBackup>>;
	};
	"upgrades.check": {
		input: Record<string, never>;
		output:
			| Awaited<ReturnType<typeof upgradeCheck>>
			| Awaited<ReturnType<typeof upgradeCheckWithDb>>;
	};
	"upgrades.plan": {
		input: { target: string; dir: string; current?: string; dryRun?: boolean };
		output: Awaited<ReturnType<typeof planUpgrade>>;
	};
	"upgrades.apply": {
		input: { plan: string; dir: string; dryRun?: boolean; confirm?: boolean };
		output: Awaited<ReturnType<typeof applyUpgrade>>;
	};
	"upgrades.verify": {
		input: { plan: string; dir: string; healthUrl?: string; dryRun?: boolean };
		output: Awaited<ReturnType<typeof verifyUpgrade>>;
	};
	"upgrades.rollback": {
		input: {
			plan: string;
			dir: string;
			dryRun?: boolean;
			confirm?: boolean;
			restoreActive?: boolean;
			activeDatabaseConfirmation?: string;
			backupDir?: string;
		};
		output: Awaited<ReturnType<typeof rollbackUpgrade>>;
	};
	"schema.status": {
		input: Record<string, never>;
		output: {
			management: { schemaVersion: number; releaseVersion: string; initializedAt?: string };
			runtime: Awaited<ReturnType<typeof getRuntimeSchemaStatus>>;
		};
	};
	"schema.generate": {
		input: Record<string, never>;
		output: { kind: "schema.generate" } & Awaited<ReturnType<typeof planRuntimeSchema>>;
	};
	"schema.migrate": {
		input: { dryRun?: boolean; confirm?: boolean };
		output: Awaited<ReturnType<typeof migrateRuntimeSchema>>;
	};
	"users.list": {
		input: { limit?: number; cursor?: string };
		output: { users: Principal[]; nextCursor?: string | null; scope: ResourceScope };
	};
	"users.inspect": {
		input: { id: string };
		output: { user: Principal; scope: ResourceScope };
	};
	"users.create": {
		input: { email: string; name: string; password?: string; dryRun?: boolean };
		output:
			| { dryRun: true; email: string; name: string; scope: ResourceScope }
			| { user: Principal; passwordSetupToken?: string; passwordSetupExpiresAt?: string };
	};
	"users.update": {
		input: { id: string; email?: string; name?: string; status?: string; dryRun?: boolean };
		output: { user: Principal } | { dryRun: true; id: string };
	};
	"users.disable": {
		input: { id: string; dryRun?: boolean };
		output: { user: Principal } | { dryRun: true; id: string };
	};
	"users.delete": {
		input: { id: string };
		output: { user: Principal; scope: ResourceScope };
	};
	"users.export": {
		input: { format?: "json" | "jsonl"; limit?: number; status?: string };
		output: { users: Principal[]; scope: ResourceScope };
	};
	"organizations.list": {
		input: { limit?: number; cursor?: string };
		output: { organizations: Organization[]; nextCursor?: string | null; scope: ResourceScope };
	};
	"organizations.inspect": {
		input: { id: string };
		output: { organization: Organization; scope: ResourceScope };
	};
	"organizations.create": {
		input: { name: string; slug?: string; ownerUserId?: string };
		output: { organization: Organization };
	};
	"organizations.update": {
		input: { id: string; name?: string; slug?: string; dryRun?: boolean };
		output:
			| { organization: Organization; scope: ResourceScope }
			| { dryRun: true; id: string; name?: string; slug?: string; scope: ResourceScope };
	};
	"organizations.archive": {
		input: { id: string; dryRun?: boolean; confirm?: boolean };
		output: ArchiveOrganizationResult & { scope: ResourceScope };
	};
	"organizations.members.list": {
		input: { organizationId: string };
		output: { members: Membership[]; scope: ResourceScope };
	};
	"organizations.members.add": {
		input: { organizationId: string; principalId: string; role?: string; dryRun?: boolean };
		output:
			| { membership: Membership; scope: ResourceScope }
			| { dryRun: true; organizationId: string; principalId: string; role: string; scope: ResourceScope };
	};
	"organizations.members.update": {
		input: { organizationId: string; membershipId: string; role: string; dryRun?: boolean };
		output:
			| { membership: Membership; scope: ResourceScope }
			| { dryRun: true; organizationId: string; membershipId: string; role: string; scope: ResourceScope };
	};
	"organizations.members.remove": {
		input: { organizationId: string; membershipId: string; dryRun?: boolean };
		output:
			| { membership: Membership; scope: ResourceScope }
			| { dryRun: true; organizationId: string; membershipId: string; membership: Membership; scope: ResourceScope };
	};
	"organizations.members.import": {
		input: { organizationId: string; content: string; format: "json" | "csv"; dryRun?: boolean; confirm?: boolean };
		output:
			| ({ dryRun: true; scope: ResourceScope } & MemberImportPlan)
			| (MemberImportResult & { scope: ResourceScope });
	};
}

export type ManagementOperationId = keyof ManagementOperationTypes;
export type OperationInput<Id extends ManagementOperationId> =
	ManagementOperationTypes[Id]["input"];
export type OperationOutput<Id extends ManagementOperationId> =
	ManagementOperationTypes[Id]["output"];

export interface ManagementOperation<Id extends ManagementOperationId> {
	readonly id: Id;
	readonly cliPath: string;
	readonly http: {
		readonly method: OperationMethod;
		readonly path: `/v1/${string}`;
	};
	readonly mutation: boolean;
	readonly supportsDryRun: boolean;
	readonly confirmation: OperationConfirmation;
}

function defineOperation<
	const Operation extends ManagementOperation<ManagementOperationId>,
>(operation: Operation): Operation {
	return Object.freeze({
		...operation,
		http: Object.freeze(operation.http),
	}) as Operation;
}

export const SYSTEM_OPERATIONS = Object.freeze({
	init: defineOperation({
		id: "system.init",
		cliPath: "init",
		http: { method: "POST", path: "/v1/init" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	doctor: defineOperation({
		id: "system.doctor",
		cliPath: "doctor",
		http: { method: "GET", path: "/v1/doctor" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	dev: defineOperation({
		id: "system.dev",
		cliPath: "dev",
		http: { method: "GET", path: "/v1/dev" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	overview: defineOperation({
		id: "system.overview",
		cliPath: "overview",
		http: { method: "GET", path: "/v1/overview" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
});

export const PROJECT_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "projects.list",
		cliPath: "project list",
		http: { method: "GET", path: "/v1/projects" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	inspect: defineOperation({
		id: "projects.inspect",
		cliPath: "project inspect",
		http: {
			method: "GET",
			path: "/v1/projects/:id",
			currentPath: "/v1/projects/current",
		},
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "projects.create",
		cliPath: "project create",
		http: { method: "POST", path: "/v1/projects" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
});

export const ENVIRONMENT_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "environments.list",
		cliPath: "env list",
		http: { method: "GET", path: "/v1/environments" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	inspect: defineOperation({
		id: "environments.inspect",
		cliPath: "env inspect",
		http: {
			method: "GET",
			path: "/v1/environments/:id",
			currentPath: "/v1/environments/current",
		},
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "environments.create",
		cliPath: "env create",
		http: { method: "POST", path: "/v1/environments" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	promote: defineOperation({
		id: "environments.promote",
		cliPath: "env promote",
		http: { method: "POST", path: "/v1/environments/promote" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const EVENT_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "events.list",
		cliPath: "events list",
		http: { method: "GET", path: "/v1/events" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	tail: defineOperation({
		id: "events.tail",
		cliPath: "events tail",
		http: { method: "GET", path: "/v1/events" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	inspect: defineOperation({
		id: "events.inspect",
		cliPath: "events inspect",
		http: { method: "GET", path: "/v1/events/:id" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	export: defineOperation({
		id: "events.export",
		cliPath: "events export",
		http: { method: "POST", path: "/v1/events/export" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	replay: defineOperation({
		id: "events.replay",
		cliPath: "events replay",
		http: { method: "POST", path: "/v1/events/replay" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const API_KEY_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "keys.list",
		cliPath: "keys list",
		http: { method: "GET", path: "/v1/keys" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "keys.create",
		cliPath: "keys create",
		http: { method: "POST", path: "/v1/keys" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	rotate: defineOperation({
		id: "keys.rotate",
		cliPath: "keys rotate",
		http: { method: "POST", path: "/v1/keys/:id/rotate" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
	revoke: defineOperation({
		id: "keys.revoke",
		cliPath: "keys revoke",
		http: { method: "POST", path: "/v1/keys/:id/revoke" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
});

export const SESSION_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "sessions.list",
		cliPath: "sessions list",
		http: { method: "GET", path: "/v1/sessions" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	revoke: defineOperation({
		id: "sessions.revoke",
		cliPath: "sessions revoke",
		http: { method: "POST", path: "/v1/sessions/:id/revoke" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
});

export const ROLE_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "roles.list",
		cliPath: "roles list",
		http: { method: "GET", path: "/v1/roles" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	validate: defineOperation({
		id: "roles.validate",
		cliPath: "roles validate",
		http: { method: "POST", path: "/v1/roles/validate" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "roles.create",
		cliPath: "roles create",
		http: { method: "POST", path: "/v1/roles" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	update: defineOperation({
		id: "roles.update",
		cliPath: "roles update",
		http: { method: "PATCH", path: "/v1/roles/:id" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
});

export const SSO_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "sso.list",
		cliPath: "sso list",
		http: { method: "GET", path: "/v1/sso" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "sso.create",
		cliPath: "sso create",
		http: { method: "POST", path: "/v1/sso" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	configure: defineOperation({
		id: "sso.configure",
		cliPath: "sso configure",
		http: { method: "PATCH", path: "/v1/sso/:id" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	test: defineOperation({
		id: "sso.test",
		cliPath: "sso test",
		http: { method: "POST", path: "/v1/sso/:id/test" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "client-required-when-live",
	}),
	setupLink: defineOperation({
		id: "sso.setupLink.create",
		cliPath: "sso setup-link",
		http: { method: "POST", path: "/v1/sso/setup-links" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	rotate: defineOperation({
		id: "sso.rotate",
		cliPath: "sso rotate",
		http: { method: "POST", path: "/v1/sso/:id/rotate" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
	disable: defineOperation({
		id: "sso.disable",
		cliPath: "sso disable",
		http: { method: "POST", path: "/v1/sso/:id/disable" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
});

export const SCIM_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "scim.list",
		cliPath: "scim list",
		http: { method: "GET", path: "/v1/scim" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "scim.create",
		cliPath: "scim create",
		http: { method: "POST", path: "/v1/scim" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	test: defineOperation({
		id: "scim.test",
		cliPath: "scim test",
		http: { method: "POST", path: "/v1/scim/:id/test" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required-when-live",
	}),
	setupLink: defineOperation({
		id: "scim.setupLink.create",
		cliPath: "scim setup-link",
		http: { method: "POST", path: "/v1/scim/setup-links" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	rotate: defineOperation({
		id: "scim.rotate",
		cliPath: "scim rotate",
		http: { method: "POST", path: "/v1/scim/:id/rotate" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
	disable: defineOperation({
		id: "scim.disable",
		cliPath: "scim disable",
		http: { method: "POST", path: "/v1/scim/:id/disable" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
	replay: defineOperation({
		id: "scim.replay",
		cliPath: "scim replay",
		http: { method: "POST", path: "/v1/scim/traces/:traceId/replay" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const READINESS_OPERATIONS = Object.freeze({
	check: defineOperation({
		id: "readiness.check",
		cliPath: "readiness check",
		http: { method: "POST", path: "/v1/readiness/check" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	report: defineOperation({
		id: "readiness.report",
		cliPath: "readiness report",
		http: { method: "GET", path: "/v1/readiness/:orgId" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
});

export const CONFIG_OPERATIONS = Object.freeze({
	get: defineOperation({
		id: "config.get",
		cliPath: "config get",
		http: { method: "GET", path: "/v1/config" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	set: defineOperation({
		id: "config.set",
		cliPath: "config set",
		http: { method: "PATCH", path: "/v1/config/:key" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	validate: defineOperation({
		id: "config.validate",
		cliPath: "config validate",
		http: { method: "POST", path: "/v1/config/validate" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	diff: defineOperation({
		id: "config.diff",
		cliPath: "config diff",
		http: { method: "POST", path: "/v1/config/diff" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
});

export const IMPORT_OPERATIONS = Object.freeze({
	legacy: defineOperation({
		id: "imports.legacy",
		cliPath: "import legacy",
		http: { method: "POST", path: "/v1/import/legacy" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const MIGRATION_OPERATIONS = Object.freeze({
	plan: defineOperation({
		id: "migrations.plan",
		cliPath: "migration plan",
		http: { method: "POST", path: "/v1/migrations/plan" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	run: defineOperation({
		id: "migrations.run",
		cliPath: "migration run",
		http: { method: "POST", path: "/v1/migrations/:id/run" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	verify: defineOperation({
		id: "migrations.verify",
		cliPath: "migration verify",
		http: { method: "POST", path: "/v1/migrations/:id/verify" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	rollback: defineOperation({
		id: "migrations.rollback",
		cliPath: "migration rollback",
		http: { method: "POST", path: "/v1/migrations/:id/rollback" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
	status: defineOperation({
		id: "migrations.status",
		cliPath: "migration status",
		http: { method: "GET", path: "/v1/migrations/:id" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
});

export const BACKUP_OPERATIONS = Object.freeze({
	create: defineOperation({
		id: "backups.create",
		cliPath: "backup create",
		http: { method: "POST", path: "/v1/backups" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	verify: defineOperation({
		id: "backups.verify",
		cliPath: "backup verify",
		http: { method: "POST", path: "/v1/backups/:id/verify" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	restore: defineOperation({
		id: "backups.restore",
		cliPath: "backup restore",
		http: { method: "POST", path: "/v1/backups/:id/restore" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
});

export const UPGRADE_OPERATIONS = Object.freeze({
	check: defineOperation({
		id: "upgrades.check",
		cliPath: "upgrade check",
		http: { method: "GET", path: "/v1/upgrades/check" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	plan: defineOperation({
		id: "upgrades.plan",
		cliPath: "upgrade plan",
		http: { method: "POST", path: "/v1/upgrades/plan" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	apply: defineOperation({
		id: "upgrades.apply",
		cliPath: "upgrade apply",
		http: { method: "POST", path: "/v1/upgrades/apply" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
	verify: defineOperation({
		id: "upgrades.verify",
		cliPath: "upgrade verify",
		http: { method: "POST", path: "/v1/upgrades/verify" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	rollback: defineOperation({
		id: "upgrades.rollback",
		cliPath: "upgrade rollback",
		http: { method: "POST", path: "/v1/upgrades/rollback" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const SCHEMA_OPERATIONS = Object.freeze({
	status: defineOperation({
		id: "schema.status",
		cliPath: "schema status",
		http: { method: "GET", path: "/v1/schema/status" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	generate: defineOperation({
		id: "schema.generate",
		cliPath: "schema generate",
		http: { method: "POST", path: "/v1/schema/generate" },
		mutation: false,
		supportsDryRun: true,
		confirmation: "none",
	}),
	migrate: defineOperation({
		id: "schema.migrate",
		cliPath: "schema migrate",
		http: { method: "POST", path: "/v1/schema/migrate" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const USER_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "users.list",
		cliPath: "users list",
		http: { method: "GET", path: "/v1/users" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	inspect: defineOperation({
		id: "users.inspect",
		cliPath: "users inspect",
		http: { method: "GET", path: "/v1/users/:id" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "users.create",
		cliPath: "users create",
		http: { method: "POST", path: "/v1/users" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	update: defineOperation({
		id: "users.update",
		cliPath: "users update",
		http: { method: "PATCH", path: "/v1/users/:id" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	disable: defineOperation({
		id: "users.disable",
		cliPath: "users disable",
		http: { method: "POST", path: "/v1/users/:id/disable" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	delete: defineOperation({
		id: "users.delete",
		cliPath: "users delete",
		http: { method: "DELETE", path: "/v1/users/:id" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "client-required",
	}),
	export: defineOperation({
		id: "users.export",
		cliPath: "users export",
		http: { method: "POST", path: "/v1/users/export" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
});

export const ORGANIZATION_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "organizations.list",
		cliPath: "orgs list",
		http: { method: "GET", path: "/v1/organizations" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	inspect: defineOperation({
		id: "organizations.inspect",
		cliPath: "orgs inspect",
		http: { method: "GET", path: "/v1/organizations/:id" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "organizations.create",
		cliPath: "orgs create",
		http: { method: "POST", path: "/v1/organizations" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	update: defineOperation({
		id: "organizations.update",
		cliPath: "orgs update",
		http: { method: "PATCH", path: "/v1/organizations/:id" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	archive: defineOperation({
		id: "organizations.archive",
		cliPath: "orgs archive",
		http: { method: "POST", path: "/v1/organizations/:id/archive" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const MEMBER_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "organizations.members.list",
		cliPath: "orgs members list",
		http: { method: "GET", path: "/v1/organizations/:id/members" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	add: defineOperation({
		id: "organizations.members.add",
		cliPath: "orgs members add",
		http: { method: "POST", path: "/v1/organizations/:id/members" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	update: defineOperation({
		id: "organizations.members.update",
		cliPath: "orgs members update",
		http: { method: "PATCH", path: "/v1/organizations/:id/members/:memberId" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	remove: defineOperation({
		id: "organizations.members.remove",
		cliPath: "orgs members remove",
		http: { method: "DELETE", path: "/v1/organizations/:id/members/:memberId" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
	import: defineOperation({
		id: "organizations.members.import",
		cliPath: "orgs members import",
		http: { method: "POST", path: "/v1/organizations/:id/members/import" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const MANAGEMENT_OPERATIONS = Object.freeze([
	...Object.values(SYSTEM_OPERATIONS),
	...Object.values(PROJECT_OPERATIONS),
	...Object.values(ENVIRONMENT_OPERATIONS),
	...Object.values(EVENT_OPERATIONS),
	...Object.values(API_KEY_OPERATIONS),
	...Object.values(SESSION_OPERATIONS),
	...Object.values(ROLE_OPERATIONS),
	...Object.values(SSO_OPERATIONS),
	...Object.values(SCIM_OPERATIONS),
	...Object.values(READINESS_OPERATIONS),
	...Object.values(CONFIG_OPERATIONS),
	...Object.values(IMPORT_OPERATIONS),
	...Object.values(MIGRATION_OPERATIONS),
	...Object.values(BACKUP_OPERATIONS),
	...Object.values(UPGRADE_OPERATIONS),
	...Object.values(SCHEMA_OPERATIONS),
	...Object.values(USER_OPERATIONS),
	...Object.values(ORGANIZATION_OPERATIONS),
	...Object.values(MEMBER_OPERATIONS),
]);

export function resolveOperationPath<Id extends ManagementOperationId>(
	operation: ManagementOperation<Id>,
	params: Record<string, string>,
): `/v1/${string}` {
	return operation.http.path.replace(/:([A-Za-z][A-Za-z0-9]*)/g, (_, name: string) => {
		const value = params[name];
		if (!value) throw new Error(`Missing path parameter ${name} for ${operation.id}`);
		return encodeURIComponent(value);
	}) as `/v1/${string}`;
}
