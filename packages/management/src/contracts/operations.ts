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
import type {
	ArchiveOrganizationResult,
	AuthoritativeOverviewStats,
	EnvironmentInspectResult,
	EnvironmentPromoteResult,
	UsersExportEnvelope,
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
	getCredentialAuthorityStatus,
	getRuntimeSchemaStatus,
	planRuntimeSchema,
} from "../services/runtime-schema.js";
import type {
	StoreV2CommandEnvelope,
} from "../services/store-v2.js";
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
import type {
	DeliveryControlResult,
	ScopedDeliveryJob,
	ScopedDeliveryJobPage,
} from "../services/delivery-control.js";
import type {
	ScopedWebhookEndpoint,
	ScopedWebhookEndpointPage,
	WebhookEndpointDeletionResult,
	WebhookEndpointControlResult,
	WebhookEndpointCreateResult,
	WebhookEndpointMutationPreview,
	WebhookEndpointUpdateResult,
} from "../services/webhook-endpoints.js";
import type {
	AuthenticationPolicyApplyControlResult,
	AuthenticationPolicyApplyInput,
	AuthenticationPolicyGetResult,
	AuthenticationPolicyPlanInput,
	AuthenticationPolicyPlanResult,
	AuthenticationUnlockControlResult,
	AuthenticationUnlockInput,
} from "../services/authentication-policy.js";
import type {
	KeyManagementApplyControlResult,
	KeyManagementApplyInput,
	KeyManagementPlanResult,
	KeyManagementStatusResult,
} from "../services/key-management.js";
import type {
	DeliveryControlAction,
	DeliveryControlPreview,
	DeliveryJobState,
	DeliveryQuotaStatus,
	DeliveryReadinessSummary,
	EnqueuedDelivery,
	PublicDeliveryJob,
	PublicWebhookEndpoint,
	WebhookEndpointStatus,
	WebhookEventKind,
} from "@clearance/delivery";

export type OperationConfirmation =
	| "none"
	| "client-required"
	| "client-required-when-live"
	| "server-required";
export type OperationMethod = "GET" | "POST" | "PATCH" | "DELETE";

/** A normalized authorization subject, safe to expose through management APIs. */
export type AuthorizationSubject =
	| { kind: "principal"; id: string }
	| { kind: "service_account"; id: string };

/** A paired optional filter: callers either identify a subject completely or do not filter. */
export type AuthorizationAssignmentFilter =
	| { subjectKind: AuthorizationSubject["kind"]; subjectId: string }
	| { subjectKind?: never; subjectId?: never };

export interface AuthorizationEffectiveView {
	organizationId: string;
	subject: AuthorizationSubject;
	roleIds: string[];
	actions: string[];
	revision: string;
}

export interface AuthorizationAssignmentView {
	organizationId: string;
	subject: AuthorizationSubject;
	roleId: string;
}

export interface AuthorizationAssignmentSetView {
	organizationId: string;
	subject: AuthorizationSubject;
	roleIds: string[];
}

export interface ServiceAccountView {
	organizationId: string;
	serviceAccountId: string;
	name: string;
	status: "active" | "disabled";
}

export interface ServiceAccountCredentialView {
	organizationId: string;
	serviceAccountId: string;
	credentialId: string;
	credentialPrefix: string;
	credentialFingerprint: string;
	expiresAt: string | null;
	version: number;
}

export type ManagementJsonPrimitive = string | number | boolean | null;
export type ManagementJsonValue =
	| ManagementJsonPrimitive
	| ManagementJsonValue[]
	| { [key: string]: ManagementJsonValue };

/**
 * The service layer may use Dates, readonly collections, or opaque metadata
 * internally. Management operations describe the JSON representation that
 * actually crosses the HTTP boundary.
 */
export type ManagementJsonWire<Value> =
	unknown extends Value
		? ManagementJsonValue
		: Value extends Date
			? string
			: Value extends ManagementJsonPrimitive | undefined
				? Value
				: Value extends ManagementJsonValue
					? Value
				: Value extends readonly unknown[]
					? { -readonly [Key in keyof Value]: ManagementJsonWire<Value[Key]> }
					: Value extends object
						? { -readonly [Key in keyof Value]: ManagementJsonWire<Value[Key]> }
						: never;

type PublicSsoIdentityConnection = Omit<PublicIdentityConnection, "protocol"> & {
	protocol: "saml" | "oidc";
};

type WithPublicConnection<Value, Connection> =
	Value extends { connection: unknown }
		? Omit<Value, "connection"> & { connection: Connection }
		: Value;

type PublicScimTestResult<Value> =
	Value extends { connection: unknown; proposed: unknown }
		? Omit<Value, "connection" | "proposed"> & {
				connection: PublicDirectoryConnection;
				proposed: Array<{
					action: "deprovision" | "upsert";
					email: string;
				}>;
		  }
		: WithPublicConnection<Value, PublicDirectoryConnection>;

type SetupLinkWire =
	| (ReturnType<typeof createSetupLink> & { scope: ResourceScope })
	| (Omit<ReturnType<typeof createSetupLink>, "token" | "url"> & {
			scope: ResourceScope;
			oneTimeSecretsOmitted: ["token", "url"];
	  });

type DeliveryControlWire<Action extends DeliveryControlAction> =
	Omit<DeliveryControlResult, "operation" | "preview" | "result"> & {
		operation: `delivery.jobs.${Action}`;
		preview: Omit<DeliveryControlPreview, "action"> & { action: Action };
		result?: Action extends "replay" ? EnqueuedDelivery : PublicDeliveryJob;
	};

type WebhookEndpointCreateWire =
	| WebhookEndpointCreateResult
	| (Omit<WebhookEndpointCreateResult, "signingSecret"> & {
			secretAlreadyIssued: true;
			oneTimeSecretsOmitted: ["signingSecret"];
	  });

type WebhookEndpointControlBase<Action extends "rotate" | "delete" | "test"> =
	Omit<WebhookEndpointControlResult, "operation" | "preview" | "result"> & {
		operation: `delivery.webhook_endpoints.${Action}`;
		preview: Extract<WebhookEndpointMutationPreview, { action: Action }>;
	};

type WebhookEndpointRotateWire =
	| (WebhookEndpointControlBase<"rotate"> & { dryRun: true })
	| (WebhookEndpointControlBase<"rotate"> & {
			dryRun: false;
			result: { endpoint: PublicWebhookEndpoint; signingSecret: string };
	  })
	| (WebhookEndpointControlBase<"rotate"> & {
			dryRun: false;
			result: { endpoint: PublicWebhookEndpoint };
			secretAlreadyIssued: true;
			oneTimeSecretsOmitted: ["result.signingSecret"];
	  });

type WebhookEndpointDeleteWire = WebhookEndpointControlBase<"delete"> & {
	result?: WebhookEndpointDeletionResult;
};

type WebhookEndpointTestWire = WebhookEndpointControlBase<"test"> & {
	result?: { endpoint: PublicWebhookEndpoint; delivery: EnqueuedDelivery };
};

type CredentialAuthorityStatusWire =
	Omit<Awaited<ReturnType<typeof getCredentialAuthorityStatus>>, "protocolVersion"> & {
		protocolVersion: 1;
	};

type StoreV2StatusWire<Operation extends StoreV2CommandEnvelope["operation"]> =
	Omit<StoreV2CommandEnvelope, "operation" | "dryRun" | "status" | "plan"> & {
		operation: Operation;
		dryRun: false;
		status: NonNullable<StoreV2CommandEnvelope["status"]>;
	};

type StoreV2PlanWire<Operation extends StoreV2CommandEnvelope["operation"]> =
	Omit<StoreV2CommandEnvelope, "operation" | "dryRun" | "status" | "plan"> & {
		operation: Operation;
		dryRun: true;
		plan: NonNullable<StoreV2CommandEnvelope["plan"]>;
	};

type UpgradePlanSummaryWire = {
	id: string;
	targetVersion: string;
	status: string;
};

type UpgradePlanWire =
	| {
			schemaVersion: "v1";
			operation: "upgrade.plan";
			dryRun: true;
			plan: {
				targetVersion: string;
				currentVersion: string | null;
				directory: string;
				createsArtifacts: false;
			};
	  }
	| {
			schemaVersion: "v1";
			operation: "upgrade.plan";
			dryRun: false;
			plan: UpgradePlanSummaryWire & {
				path: string;
				currentVersion: string;
			};
	  };

type UpgradeApplyWire =
	| {
			schemaVersion: "v1";
			operation: "upgrade.apply";
			dryRun: true;
			plan: UpgradePlanSummaryWire & {
				path: string;
				currentVersion: string;
			};
			wouldRun: ["preflight", "verified_backup", "version_hook"];
	  }
	| {
			schemaVersion: "v1";
			operation: "upgrade.apply";
			dryRun: false;
			plan: UpgradePlanSummaryWire & {
				backupId: string | null;
				rollbackReference: ManagementJsonValue;
			};
	  };

type UpgradeVerifyWire =
	| {
			schemaVersion: "v1";
			operation: "upgrade.verify";
			dryRun: true;
			plan: UpgradePlanSummaryWire;
			wouldRun: Array<
				"backup_reference_check" | "apply_marker_check" | "health_url_check"
			>;
	  }
	| {
			schemaVersion: "v1";
			operation: "upgrade.verify";
			plan: UpgradePlanSummaryWire & {
				updatedAt: string | null;
				backupId: string | null;
			};
	  };

type UpgradeRollbackWire =
	| {
			schemaVersion: "v1";
			operation: "upgrade.rollback";
			dryRun: true;
			mode: "isolated_verify_only";
			activeDatabaseUntouched: true;
			wouldModifyActiveDatabase: false;
			plan: UpgradePlanSummaryWire;
			wouldRun: [
				"backup_checksum_check",
				"isolated_restore",
				"reconciliation",
				"rollback_receipt",
			];
	  }
	| {
			schemaVersion: "v1";
			operation: "upgrade.rollback";
			dryRun: true;
			mode: "active_database_restore";
			activeDatabaseUntouched: true;
			wouldModifyActiveDatabase: true;
			plan: UpgradePlanSummaryWire;
			wouldRun: [
				"advisory_lock",
				"safety_backup",
				"staging_restore",
				"database_swap",
				"live_verification",
				"rollback_receipt",
			];
	  }
	| {
			schemaVersion: "v1";
			operation: "upgrade.rollback";
			dryRun: false;
			mode: "isolated_verify_only" | "active_database_restore";
			activeDatabaseUntouched: boolean;
			plan: UpgradePlanSummaryWire;
			rollbackReceipt: string;
			receipt: Record<string, ManagementJsonValue>;
	  };

type RuntimeSchemaMigrateWire =
	| {
			kind: "schema.migrate";
			dryRun: true;
			pendingTables: number;
			pendingFields: number;
			pendingSecurityMigrations: string[];
	  }
	| {
			kind: "schema.migrate";
			dryRun: false;
			appliedTables: number;
			appliedFields: number;
	  };

type MemberImportWireResult = Omit<MemberImportResult, "results"> & {
	results: Array<
		| {
				row: number;
				principalId: string;
				status: "success" | "idempotent";
		  }
		| {
				row: number;
				principalId: string;
				status: "failure";
				error: { code: string; stage: string; retryable: boolean };
		  }
	>;
};

export interface ManagementOperationServiceTypes {
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
		output: AuthoritativeOverviewStats;
	};
	"projects.list": {
		input: Record<string, never>;
		output: { projects: Project[]; scope: ResourceScope };
	};
	"projects.inspect": {
		input: { id?: string };
		output: { project: Project; overview: AuthoritativeOverviewStats; scope: ResourceScope };
	};
	"projects.create": {
		input: { name: string; dryRun?: boolean };
		output:
			| { project: Project }
			| { dryRun: true; project: Pick<Project, "name" | "slug"> };
	};
	"environments.list": {
		input: { limit?: number; cursor?: string };
		output: { environments: Environment[]; nextCursor?: string | null; scope: ResourceScope };
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
		/** One ordinary events-list poll; the CLI owns tail lifecycle controls. */
		input: { limit?: number; action?: string; organizationId?: string };
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
		input: { name: string; scopes?: string[]; expiresAt?: string; dryRun?: boolean };
		output:
			| (CreatedApiKey & { scope: ResourceScope })
			| { dryRun: true; apiKey: { name: string; scopes: string[]; expiresAt?: string }; secretGenerated: false; scope: ResourceScope };
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
		output: { connections: PublicSsoIdentityConnection[]; scope: ResourceScope };
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
		output: { connection: PublicSsoIdentityConnection };
	};
	"sso.configure": {
		input: { id: string; issuer?: string; audience?: string; domain?: string; domains?: string[]; dryRun?: boolean };
		output:
			| { connection: PublicSsoIdentityConnection; scope: ResourceScope }
			| { dryRun: true; connection: PublicSsoIdentityConnection; proposed: { issuer?: string; audience?: string; domains?: string[] }; scope: ResourceScope };
	};
	"sso.test": {
		input: { id: string; fixture?: string; live?: boolean };
		output:
			| WithPublicConnection<Awaited<ReturnType<typeof testSsoConnection>>, PublicSsoIdentityConnection>
			| WithPublicConnection<Awaited<ReturnType<typeof testSsoConnectionReal>>, PublicSsoIdentityConnection>
			| WithPublicConnection<Awaited<ReturnType<typeof testSsoConnectionLive>>, PublicSsoIdentityConnection>;
	};
	"sso.setupLink.create": {
		input: { organizationId: string };
		output: SetupLinkWire;
	};
	"sso.rotate": {
		input: { id: string; dryRun?: boolean };
		output:
			| { connection: PublicSsoIdentityConnection; scope: ResourceScope }
			| { dryRun: true; connection: PublicSsoIdentityConnection; wouldChange: true; scope: ResourceScope };
	};
	"sso.disable": {
		input: { id: string; dryRun?: boolean };
		output:
			| { connection: PublicSsoIdentityConnection; idempotent: boolean; runtimeRemoved?: boolean; scope: ResourceScope }
			| { dryRun: true; connection: PublicSsoIdentityConnection; wouldChange: boolean; scope: ResourceScope };
	};
	"scim.list": {
		input: { organizationId?: string };
		output: { connections: PublicDirectoryConnection[]; scope: ResourceScope };
	};
	"scim.create": {
		input: { organizationId: string; provider: string; endpoint?: string };
		output:
			| { connection: PublicDirectoryConnection & { bearerTokenOnce: string } }
			| {
					connection: PublicDirectoryConnection;
					oneTimeSecretsOmitted: ["connection.bearerTokenOnce"];
			  };
	};
	"scim.test": {
		input: {
			id: string;
			fixture?: string;
		live?: boolean;
		dryRun?: boolean;
		users?: Array<{ userName: string; displayName?: string; active?: boolean }>;
			/** Closed, server-executed runtime conformance scenario. */
			scenario?: "users" | "group-lifecycle";
		};
		output:
			| PublicScimTestResult<Awaited<ReturnType<typeof testScimConnection>>>
			| PublicScimTestResult<Awaited<ReturnType<typeof testScimConnectionReal>>>
			| PublicScimTestResult<Awaited<ReturnType<typeof testScimConnectionLive>>>;
	};
	"scim.setupLink.create": {
		input: { organizationId: string };
		output: SetupLinkWire;
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
	"delivery.jobs.list": {
		input: {
			limit?: number;
			cursor?: string;
			states?: DeliveryJobState[];
			channel?: "email" | "webhook";
			kind?: string;
		};
		output: ScopedDeliveryJobPage;
	};
	"delivery.jobs.inspect": {
		input: { id: string };
		output: ScopedDeliveryJob;
	};
	"delivery.readiness": {
		input: { staleAfterMs?: number };
		output: DeliveryReadinessSummary;
	};
	"delivery.quotas.get": {
		input: Record<string, never>;
		output: DeliveryQuotaStatus;
	};
	"delivery.jobs.cancel": {
		input: { id: string; dryRun?: boolean; confirm?: boolean };
		output: DeliveryControlWire<"cancel">;
	};
	"delivery.jobs.retry": {
		input: { id: string; dryRun?: boolean; confirm?: boolean };
		output: DeliveryControlWire<"retry">;
	};
	"delivery.jobs.replay": {
		input: { id: string; maxAttempts?: number; dryRun?: boolean; confirm?: boolean };
		output: DeliveryControlWire<"replay">;
	};
	"delivery.webhook_endpoints.list": {
		input: {
			limit?: number;
			cursor?: string;
			statuses?: WebhookEndpointStatus[];
			eventKind?: WebhookEventKind;
		};
		output: ScopedWebhookEndpointPage;
	};
	"delivery.webhook_endpoints.inspect": {
		input: { id: string };
		output: ScopedWebhookEndpoint;
	};
	"delivery.webhook_endpoints.create": {
		input: { name: string; url: string; eventKinds?: WebhookEventKind[] };
		output: WebhookEndpointCreateWire;
	};
	"delivery.webhook_endpoints.update": {
		input: {
			id: string;
			expectedVersion: number;
			name?: string;
			url?: string;
			eventKinds?: WebhookEventKind[];
			status?: "active" | "disabled";
		};
		output: WebhookEndpointUpdateResult;
	};
	"delivery.webhook_endpoints.rotate": {
		input: { id: string; expectedVersion: number; dryRun?: boolean; confirm?: boolean };
		output: WebhookEndpointRotateWire;
	};
	"delivery.webhook_endpoints.delete": {
		input: { id: string; expectedVersion: number; dryRun?: boolean; confirm?: boolean };
		output: WebhookEndpointDeleteWire;
	};
	"delivery.webhook_endpoints.test": {
		input: { id: string; expectedVersion: number; dryRun?: boolean; confirm?: boolean };
		output: WebhookEndpointTestWire;
	};
	"authentication_policy.get": {
		input: { organizationId?: string };
		output: AuthenticationPolicyGetResult;
	};
	"authentication_policy.plan": {
		input: AuthenticationPolicyPlanInput;
		output: AuthenticationPolicyPlanResult;
	};
	"authentication_policy.apply": {
		input: AuthenticationPolicyApplyInput & { dryRun?: boolean; confirm?: boolean };
		output: AuthenticationPolicyApplyControlResult;
	};
	"authentication_policy.unlock": {
		input: AuthenticationUnlockInput & { dryRun?: boolean; confirm?: boolean };
		output: AuthenticationUnlockControlResult;
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
		input: {
			id: string;
			/** Isolated Postgres database name; JSON-store restore destinations are server-managed. */
			target?: `clearance_restore_${string}`;
			confirm?: boolean;
		};
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
		output: UpgradePlanWire;
	};
	"upgrades.apply": {
		input: { plan: string; dir: string; dryRun?: boolean; confirm?: boolean };
		output: UpgradeApplyWire;
	};
	"upgrades.verify": {
		input: { plan: string; dir: string; healthUrl?: string; dryRun?: boolean };
		output: UpgradeVerifyWire;
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
		output: UpgradeRollbackWire;
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
		output: RuntimeSchemaMigrateWire;
	};
	"schema.credential-authority.status": {
		input: Record<string, never>;
		output: CredentialAuthorityStatusWire;
	};
	"schema.credential-authority.arm": {
		input: {
			deploymentId: string;
			expectedRuntimeCount: number;
			confirm?: boolean;
		};
		output: CredentialAuthorityStatusWire;
	};
	"schema.credential-authority.drain": {
		input: { deploymentId: string; drainId: string; confirm?: boolean };
		output: CredentialAuthorityStatusWire;
	};
	"key_management.status": {
		input: Record<string, never>;
		output: KeyManagementStatusResult;
	};
	"key_management.plan": {
		input: Record<string, never>;
		output: KeyManagementPlanResult;
	};
	"key_management.apply": {
		input: KeyManagementApplyInput & { dryRun?: boolean; confirm?: boolean };
		output: KeyManagementApplyControlResult;
	};
	"schema.store-v2.status": {
		input: Record<string, never>;
		output: StoreV2StatusWire<"schema.store-v2.status">;
	};
	"schema.store-v2.plan": {
		input: Record<string, never>;
		output: StoreV2PlanWire<"schema.store-v2.plan">;
	};
	"schema.store-v2.apply": {
		input: { dryRun?: boolean; confirm?: boolean };
		output:
			| StoreV2PlanWire<"schema.store-v2.apply">
			| StoreV2StatusWire<"schema.store-v2.apply">;
	};
	"schema.store-v2.verify": {
		input: Record<string, never>;
		output: StoreV2StatusWire<"schema.store-v2.verify">;
	};
	"schema.store-v2.rollback": {
		input: { confirm?: boolean };
		output: StoreV2StatusWire<"schema.store-v2.rollback">;
	};
	"schema.store-v2.events.cutover": {
		input: { confirm?: boolean };
		output: StoreV2StatusWire<"schema.store-v2.events.cutover">;
	};
	"schema.store-v2.events.rollback": {
		input: { confirm?: boolean };
		output: StoreV2StatusWire<"schema.store-v2.events.rollback">;
	};
	"schema.store-v2.principals.cutover": {
		input: { confirm?: boolean };
		output: StoreV2StatusWire<"schema.store-v2.principals.cutover">;
	};
	"schema.store-v2.principals.rollback": {
		input: { confirm?: boolean };
		output: StoreV2StatusWire<"schema.store-v2.principals.rollback">;
	};
	"schema.store-v2.topology.cutover": {
		input: { confirm?: boolean };
		output: StoreV2StatusWire<"schema.store-v2.topology.cutover">;
	};
	"schema.store-v2.topology.rollback": {
		input: { confirm?: boolean };
		output: StoreV2StatusWire<"schema.store-v2.topology.rollback">;
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
		output:
			| { user: Principal; scope: ResourceScope }
			| {
					dryRun: true;
					id: string;
					email?: string;
					name?: string;
					status?: "active" | "disabled";
					scope: ResourceScope;
			  };
	};
	"users.disable": {
		input: { id: string; dryRun?: boolean };
		output:
			| { user: Principal; scope: ResourceScope }
			| { dryRun: true; user: Principal; scope: ResourceScope };
	};
	"users.delete": {
		input: { id: string };
		output: { user: Principal; scope: ResourceScope };
	};
	"users.export": {
		input: { format?: "json" | "jsonl"; limit?: number; status?: string };
		output: Omit<UsersExportEnvelope, "outputPath">;
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
			| (MemberImportWireResult & { scope: ResourceScope });
	};
	"authorization.effective.inspect": {
		input: {
			organizationId: string;
			subjectKind: AuthorizationSubject["kind"];
			subjectId: string;
		};
		output: { effective: AuthorizationEffectiveView; scope: ResourceScope };
	};
	"authorization.assignments.list": {
		input: { organizationId: string } & AuthorizationAssignmentFilter;
		output: { assignments: AuthorizationAssignmentView[]; scope: ResourceScope };
	};
	"authorization.assignments.replace": {
		input: {
			organizationId: string;
			subjectKind: AuthorizationSubject["kind"];
			subjectId: string;
			/** Sorted role IDs. */
			roleIds: string[];
			expectedRevision?: string;
			dryRun?: boolean;
			confirm?: boolean;
		};
		output:
			| {
					assignment: AuthorizationAssignmentSetView;
					changed: boolean;
					previousRevision: string;
					revision: string;
					scope: ResourceScope;
			  }
			| {
					dryRun: true;
					assignment: AuthorizationAssignmentSetView;
					wouldChange: boolean;
					currentRevision: string;
					scope: ResourceScope;
			  };
	};
	"authorization.reconcile": {
		input: {
			organizationId: string;
			dryRun?: boolean;
			confirm?: boolean;
		};
		output:
			| {
					organizationId: string;
					initialized: boolean;
					rolesChanged: number;
					assignmentsChanged: number;
					revision: string;
					scope: ResourceScope;
			  }
			| {
					dryRun: true;
					organizationId: string;
					initialized: boolean;
					rolesChanged: number;
					assignmentsChanged: number;
					scope: ResourceScope;
			  };
	};
	"service-accounts.list": {
		input: { organizationId: string };
		output: { serviceAccounts: ServiceAccountView[]; scope: ResourceScope };
	};
	"service-accounts.inspect": {
		input: { organizationId: string; accountId: string };
		output: {
			serviceAccount: ServiceAccountView;
			assignments: AuthorizationAssignmentView[];
			scope: ResourceScope;
		};
	};
	"service-accounts.create": {
		input: { organizationId: string; name: string; roleIds: string[]; dryRun?: boolean };
		output:
			| { serviceAccount: ServiceAccountView; previousRevision: string; revision: string; scope: ResourceScope }
			| {
					dryRun: true;
					serviceAccount: Pick<ServiceAccountView, "organizationId" | "name"> & { status: "active" };
					roleIds: string[];
					scope: ResourceScope;
			  };
	};
	"service-accounts.disable": {
		input: { organizationId: string; accountId: string; status: "disabled"; dryRun?: boolean };
		output:
			| { serviceAccount: ServiceAccountView; previousRevision: string; revision: string; scope: ResourceScope }
			| { dryRun: true; serviceAccount: ServiceAccountView; wouldChange: boolean; currentRevision: string; scope: ResourceScope };
	};
	"service-accounts.enable": {
		input: { organizationId: string; accountId: string; status: "active"; dryRun?: boolean };
		output:
			| { serviceAccount: ServiceAccountView; previousRevision: string; revision: string; scope: ResourceScope }
			| { dryRun: true; serviceAccount: ServiceAccountView; wouldChange: boolean; currentRevision: string; scope: ResourceScope };
	};
	"service-accounts.credentials.create": {
		input: { organizationId: string; accountId: string; expiresAt?: string; dryRun?: boolean };
		output:
			| { credential: ServiceAccountCredentialView; secret: string; previousRevision: string; revision: string; scope: ResourceScope }
			| { dryRun: true; organizationId: string; serviceAccountId: string; expiresAt: string | null; secretGenerated: false; scope: ResourceScope };
	};
	"service-accounts.credentials.rotate": {
		input: { organizationId: string; accountId: string; credentialId: string; expiresAt?: string; dryRun?: boolean };
		output:
			| {
					credential: ServiceAccountCredentialView;
					secret: string;
					previousRevision: string;
					revision: string;
					scope: ResourceScope;
			  }
			| {
					dryRun: true;
					organizationId: string;
					serviceAccountId: string;
					credentialId: string;
					expiresAt: string | null;
					secretGenerated: false;
					scope: ResourceScope;
			  };
	};
	"service-accounts.credentials.revoke": {
		input: { organizationId: string; accountId: string; credentialId: string; dryRun?: boolean };
		output:
			| {
					organizationId: string;
					serviceAccountId: string;
					credentialId: string;
					previousRevision: string;
					revision: string;
					scope: ResourceScope;
			  }
			| {
					dryRun: true;
					organizationId: string;
					serviceAccountId: string;
					credentialId: string;
					wouldChange: boolean;
					scope: ResourceScope;
			  };
	};
}

export type ManagementOperationTypes = {
	[Id in keyof ManagementOperationServiceTypes]: {
		input: ManagementOperationServiceTypes[Id]["input"];
		output: ManagementJsonWire<ManagementOperationServiceTypes[Id]["output"]>;
	};
};

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

export const AUTHORIZATION_OPERATIONS = Object.freeze({
	effectiveInspect: defineOperation({
		id: "authorization.effective.inspect",
		cliPath: "orgs authorization effective",
		http: { method: "GET", path: "/v1/organizations/:id/authorization/effective/:subjectKind/:subjectId" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	assignmentsList: defineOperation({
		id: "authorization.assignments.list",
		cliPath: "orgs authorization assignments list",
		http: { method: "GET", path: "/v1/organizations/:id/authorization/assignments" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	assignmentsReplace: defineOperation({
		id: "authorization.assignments.replace",
		cliPath: "orgs authorization assignments replace",
		http: { method: "PATCH", path: "/v1/organizations/:id/authorization/assignments/:subjectKind/:subjectId" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
	reconcile: defineOperation({
		id: "authorization.reconcile",
		cliPath: "orgs authorization reconcile",
		http: { method: "POST", path: "/v1/organizations/:id/authorization/reconcile" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const SERVICE_ACCOUNT_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "service-accounts.list",
		cliPath: "orgs service-accounts list",
		http: { method: "GET", path: "/v1/organizations/:id/service-accounts" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	inspect: defineOperation({
		id: "service-accounts.inspect",
		cliPath: "orgs service-accounts inspect",
		http: { method: "GET", path: "/v1/organizations/:id/service-accounts/:accountId" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "service-accounts.create",
		cliPath: "orgs service-accounts create",
		http: { method: "POST", path: "/v1/organizations/:id/service-accounts" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	disable: defineOperation({
		id: "service-accounts.disable",
		cliPath: "orgs service-accounts disable",
		http: { method: "PATCH", path: "/v1/organizations/:id/service-accounts/:accountId/status" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
	enable: defineOperation({
		id: "service-accounts.enable",
		cliPath: "orgs service-accounts enable",
		http: { method: "PATCH", path: "/v1/organizations/:id/service-accounts/:accountId/status" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	credentialCreate: defineOperation({
		id: "service-accounts.credentials.create",
		cliPath: "orgs service-accounts credentials create",
		http: { method: "POST", path: "/v1/organizations/:id/service-accounts/:accountId/credentials" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "none",
	}),
	credentialRotate: defineOperation({
		id: "service-accounts.credentials.rotate",
		cliPath: "orgs service-accounts credentials rotate",
		http: { method: "POST", path: "/v1/organizations/:id/service-accounts/:accountId/credentials/:credentialId/rotate" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
	}),
	credentialRevoke: defineOperation({
		id: "service-accounts.credentials.revoke",
		cliPath: "orgs service-accounts credentials revoke",
		http: { method: "POST", path: "/v1/organizations/:id/service-accounts/:accountId/credentials/:credentialId/revoke" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "client-required",
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

export const DELIVERY_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "delivery.jobs.list",
		cliPath: "delivery list",
		http: { method: "GET", path: "/v1/delivery/jobs" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	inspect: defineOperation({
		id: "delivery.jobs.inspect",
		cliPath: "delivery inspect",
		http: { method: "GET", path: "/v1/delivery/jobs/:id" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	readiness: defineOperation({
		id: "delivery.readiness",
		cliPath: "delivery readiness",
		http: { method: "GET", path: "/v1/delivery/readiness" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	quotas: defineOperation({
		id: "delivery.quotas.get",
		cliPath: "delivery quotas",
		http: { method: "GET", path: "/v1/delivery/quotas" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	cancel: defineOperation({
		id: "delivery.jobs.cancel",
		cliPath: "delivery cancel",
		http: { method: "POST", path: "/v1/delivery/jobs/:id/cancel" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
	retry: defineOperation({
		id: "delivery.jobs.retry",
		cliPath: "delivery retry",
		http: { method: "POST", path: "/v1/delivery/jobs/:id/retry" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
	replay: defineOperation({
		id: "delivery.jobs.replay",
		cliPath: "delivery replay",
		http: { method: "POST", path: "/v1/delivery/jobs/:id/replay" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const WEBHOOK_ENDPOINT_OPERATIONS = Object.freeze({
	list: defineOperation({
		id: "delivery.webhook_endpoints.list",
		cliPath: "delivery endpoints list",
		http: { method: "GET", path: "/v1/delivery/webhook-endpoints" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	inspect: defineOperation({
		id: "delivery.webhook_endpoints.inspect",
		cliPath: "delivery endpoints inspect",
		http: { method: "GET", path: "/v1/delivery/webhook-endpoints/:id" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	create: defineOperation({
		id: "delivery.webhook_endpoints.create",
		cliPath: "delivery endpoints create",
		http: { method: "POST", path: "/v1/delivery/webhook-endpoints" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	update: defineOperation({
		id: "delivery.webhook_endpoints.update",
		cliPath: "delivery endpoints update",
		http: { method: "PATCH", path: "/v1/delivery/webhook-endpoints/:id" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "none",
	}),
	rotate: defineOperation({
		id: "delivery.webhook_endpoints.rotate",
		cliPath: "delivery endpoints rotate",
		http: { method: "POST", path: "/v1/delivery/webhook-endpoints/:id/rotate" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
	delete: defineOperation({
		id: "delivery.webhook_endpoints.delete",
		cliPath: "delivery endpoints delete",
		http: { method: "DELETE", path: "/v1/delivery/webhook-endpoints/:id" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
	test: defineOperation({
		id: "delivery.webhook_endpoints.test",
		cliPath: "delivery endpoints test",
		http: { method: "POST", path: "/v1/delivery/webhook-endpoints/:id/test" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
});

export const AUTHENTICATION_POLICY_OPERATIONS = Object.freeze({
	get: defineOperation({
		id: "authentication_policy.get",
		cliPath: "auth-policy get",
		http: { method: "GET", path: "/v1/authentication-policy" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	plan: defineOperation({
		id: "authentication_policy.plan",
		cliPath: "auth-policy plan",
		http: { method: "POST", path: "/v1/authentication-policy/plan" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	apply: defineOperation({
		id: "authentication_policy.apply",
		cliPath: "auth-policy apply",
		http: { method: "PATCH", path: "/v1/authentication-policy" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
	unlock: defineOperation({
		id: "authentication_policy.unlock",
		cliPath: "auth-policy unlock",
		http: { method: "POST", path: "/v1/authentication-policy/unlock" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
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
		supportsDryRun: false,
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
	credentialAuthorityStatus: defineOperation({
		id: "schema.credential-authority.status",
		cliPath: "schema credential-authority status",
		http: { method: "GET", path: "/v1/schema/credential-authority" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	credentialAuthorityArm: defineOperation({
		id: "schema.credential-authority.arm",
		cliPath: "schema credential-authority arm",
		http: { method: "POST", path: "/v1/schema/credential-authority/arm" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
	credentialAuthorityDrain: defineOperation({
		id: "schema.credential-authority.drain",
		cliPath: "schema credential-authority drain",
		http: { method: "POST", path: "/v1/schema/credential-authority/drain" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
});

export const STORE_V2_OPERATIONS = Object.freeze({
	status: defineOperation({
		id: "schema.store-v2.status",
		cliPath: "schema store-v2 status",
		http: { method: "GET", path: "/v1/schema/store-v2" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	plan: defineOperation({
		id: "schema.store-v2.plan",
		cliPath: "schema store-v2 plan",
		http: { method: "GET", path: "/v1/schema/store-v2/plan" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	apply: defineOperation({
		id: "schema.store-v2.apply",
		cliPath: "schema store-v2 apply",
		http: { method: "POST", path: "/v1/schema/store-v2/apply" },
		mutation: true,
		supportsDryRun: true,
		confirmation: "server-required",
	}),
	verify: defineOperation({
		id: "schema.store-v2.verify",
		cliPath: "schema store-v2 verify",
		http: { method: "GET", path: "/v1/schema/store-v2/verify" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	rollback: defineOperation({
		id: "schema.store-v2.rollback",
		cliPath: "schema store-v2 rollback",
		http: { method: "POST", path: "/v1/schema/store-v2/rollback" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
	eventsCutover: defineOperation({
		id: "schema.store-v2.events.cutover",
		cliPath: "schema store-v2 events cutover",
		http: { method: "POST", path: "/v1/schema/store-v2/events/cutover" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
	eventsRollback: defineOperation({
		id: "schema.store-v2.events.rollback",
		cliPath: "schema store-v2 events rollback",
		http: { method: "POST", path: "/v1/schema/store-v2/events/rollback" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
	principalsCutover: defineOperation({
		id: "schema.store-v2.principals.cutover",
		cliPath: "schema store-v2 principals cutover",
		http: { method: "POST", path: "/v1/schema/store-v2/principals/cutover" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
	principalsRollback: defineOperation({
		id: "schema.store-v2.principals.rollback",
		cliPath: "schema store-v2 principals rollback",
		http: { method: "POST", path: "/v1/schema/store-v2/principals/rollback" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
	topologyCutover: defineOperation({
		id: "schema.store-v2.topology.cutover",
		cliPath: "schema store-v2 topology cutover",
		http: { method: "POST", path: "/v1/schema/store-v2/topology/cutover" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
	topologyRollback: defineOperation({
		id: "schema.store-v2.topology.rollback",
		cliPath: "schema store-v2 topology rollback",
		http: { method: "POST", path: "/v1/schema/store-v2/topology/rollback" },
		mutation: true,
		supportsDryRun: false,
		confirmation: "server-required",
	}),
});

export const KEY_MANAGEMENT_OPERATIONS = Object.freeze({
	status: defineOperation({
		id: "key_management.status",
		cliPath: "key-management status",
		http: { method: "GET", path: "/v1/key-management/status" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	plan: defineOperation({
		id: "key_management.plan",
		cliPath: "key-management plan",
		http: { method: "POST", path: "/v1/key-management/plan" },
		mutation: false,
		supportsDryRun: false,
		confirmation: "none",
	}),
	apply: defineOperation({
		id: "key_management.apply",
		cliPath: "key-management apply",
		http: { method: "POST", path: "/v1/key-management/apply" },
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
	...Object.values(AUTHORIZATION_OPERATIONS),
	...Object.values(SERVICE_ACCOUNT_OPERATIONS),
	...Object.values(SSO_OPERATIONS),
	...Object.values(SCIM_OPERATIONS),
	...Object.values(READINESS_OPERATIONS),
	...Object.values(DELIVERY_OPERATIONS),
	...Object.values(WEBHOOK_ENDPOINT_OPERATIONS),
	...Object.values(AUTHENTICATION_POLICY_OPERATIONS),
	...Object.values(CONFIG_OPERATIONS),
	...Object.values(IMPORT_OPERATIONS),
	...Object.values(MIGRATION_OPERATIONS),
	...Object.values(BACKUP_OPERATIONS),
	...Object.values(UPGRADE_OPERATIONS),
	...Object.values(SCHEMA_OPERATIONS),
	...Object.values(STORE_V2_OPERATIONS),
	...Object.values(KEY_MANAGEMENT_OPERATIONS),
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
