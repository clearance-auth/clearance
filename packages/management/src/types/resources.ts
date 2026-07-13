export type ResourceId = string;

export interface Project {
	id: ResourceId;
	name: string;
	slug: string;
	createdAt: string;
	updatedAt: string;
}

export interface Environment {
	id: ResourceId;
	projectId: ResourceId;
	name: string;
	slug: string;
	kind: "development" | "preview" | "production";
	createdAt: string;
	updatedAt: string;
}

export interface Principal {
	id: ResourceId;
	projectId: ResourceId;
	environmentId: ResourceId;
	email: string;
	name: string;
	status: "active" | "disabled" | "deleted";
	externalId?: string;
	createdAt: string;
	updatedAt: string;
}

export interface Organization {
	id: ResourceId;
	projectId: ResourceId;
	environmentId: ResourceId;
	name: string;
	slug: string;
	status: "active" | "archived";
	externalId?: string;
	createdAt: string;
	updatedAt: string;
}

export interface Membership {
	id: ResourceId;
	organizationId: ResourceId;
	principalId: ResourceId;
	role: string;
	status: "active" | "invited" | "removed";
	source: "manual" | "scim" | "sso" | "import";
	createdAt: string;
	updatedAt: string;
}

/**
 * Authorization role definition (project/environment scoped).
 * Built-in roles are virtual system definitions; custom roles are persisted.
 * Optional organizationId binds a custom role to one organization.
 * Optional status defaults to active when omitted (legacy snapshots).
 */
export interface CustomRole {
	id: ResourceId;
	projectId: ResourceId;
	environmentId: ResourceId;
	name: string;
	/** Lowercase unique key within project+environment */
	slug: string;
	description?: string;
	/** Normalized, deduplicated, stably ordered permission strings (resource:action) */
	permissions: string[];
	kind: "built_in" | "custom";
	/** When set, role may only be assigned within this organization */
	organizationId?: ResourceId;
	/** active (default) | disabled | archived — only active roles are assignable */
	status?: "active" | "disabled" | "archived";
	createdAt: string;
	updatedAt: string;
}

export type IdentityProtocol = "saml" | "oidc" | "password" | "passkey" | "social";

export interface IdentityConnection {
	id: ResourceId;
	organizationId: ResourceId;
	protocol: IdentityProtocol;
	provider: string;
	status: "draft" | "testing" | "active" | "disabled";
	domains: string[];
	issuer?: string;
	audience?: string;
	metadataUrl?: string;
	clientId?: string;
	/** Write-only secret fingerprint after create */
	clientSecretFingerprint?: string;
	/**
	 * Versioned AEAD envelope for client secret. Write-only — never expose on
	 * public/domain list responses (use publicIdentityConnection).
	 */
	clientSecretEncrypted?: string;
	/** Key id used for clientSecretEncrypted (rotation metadata). */
	clientSecretKeyId?: string;
	/** Public IdP SAML endpoint and signing certificate used by the runtime. */
	samlEntryPoint?: string;
	samlCertificate?: string;
	samlCertificateFingerprint?: string;
	certificateFingerprint?: string;
	attributeMapping: Record<string, string>;
	createdAt: string;
	updatedAt: string;
}

export interface DirectoryConnection {
	id: ResourceId;
	organizationId: ResourceId;
	provider: string;
	status: "draft" | "testing" | "active" | "disabled";
	endpoint: string;
	bearerTokenFingerprint?: string;
	/**
	 * Versioned AEAD envelope for SCIM bearer. Write-only — strip from public responses.
	 */
	bearerTokenEncrypted?: string;
	bearerTokenKeyId?: string;
	deprovisioningPolicy: "disable" | "delete" | "suspend";
	createdAt: string;
	updatedAt: string;
}

/**
 * Persisted setup capability: digest only (never raw token).
 * Single-use, scoped to project/environment/organization + action.
 *
 * Completion state machine (durable fields only):
 * - available: useCount < maxUses, !redeemedAt, !revokedAt, no active reservation
 * - reserved: reservedAt + reservationId + reservationExpiresAt (in-progress lease)
 * - redeemed: useCount >= maxUses and redeemedAt set (terminal; never reopen)
 * - revoked: revokedAt set
 *
 * Raw capability tokens are never stored. Reservation ids are opaque leases,
 * not the customer token.
 */
export interface SetupCapability {
	id: ResourceId;
	/** SHA-256 hex digest of the capability token */
	digest: string;
	kind: "sso" | "scim";
	action: "setup";
	resourceType: "organization";
	resourceId: ResourceId;
	organizationId: ResourceId;
	projectId: ResourceId;
	environmentId: ResourceId;
	expiresAt: string;
	maxUses: number;
	useCount: number;
	revokedAt?: string;
	redeemedAt?: string;
	/**
	 * In-progress completion lease. Bound with reservationExpiresAt so a crashed
	 * holder does not permanently burn the capability. Cleared on commit/release.
	 */
	reservedAt?: string;
	/**
	 * Opaque lease / setup-attempt id. Derived from the capability digest so the
	 * same attempt identity is reused after lease expiry (durable provision
	 * reconcile). Never the raw capability token.
	 */
	reservationId?: string;
	/** When the reservation lease ends and another attempt may re-reserve. */
	reservationExpiresAt?: string;
	createdAt: string;
}

export interface AuditEvent {
	id: ResourceId;
	correlationId: string;
	projectId?: ResourceId;
	environmentId?: ResourceId;
	organizationId?: ResourceId;
	actor: string;
	action: string;
	subjectType: string;
	subjectId?: string;
	outcome: "success" | "failure" | "pending";
	source: "cli" | "console" | "api" | "system" | "migration" | "sso" | "scim";
	message: string;
	metadata?: Record<string, unknown>;
	createdAt: string;
}

export type ConformanceMode = "simulation" | "live";

export interface DiagnosticTrace {
	id: ResourceId;
	correlationId: string;
	projectId?: ResourceId;
	environmentId?: ResourceId;
	organizationId?: ResourceId;
	connectionId?: ResourceId;
	subsystem: "sso" | "scim" | "email" | "webhook" | "session" | "migration" | "deploy" | "doctor";
	stage: string;
	outcome: "pass" | "fail" | "warn";
	/**
	 * simulation = fixture/lab path (not live IdP/directory conformance)
	 * live = exercised against a real external system
	 */
	mode?: ConformanceMode;
	cause?: string;
	causeConfidence?: number;
	owner?: "customer" | "application" | "clearance";
	remediation?: string;
	redactedRequest?: Record<string, unknown>;
	redactedResponse?: Record<string, unknown>;
	checks?: Array<{ name: string; pass: boolean; detail?: string }>;
	createdAt: string;
}

export interface ReadinessCheck {
	id: string;
	name: string;
	status: "pass" | "fail" | "warn" | "skip";
	detail: string;
	fingerprint?: string;
	/** When true, a pass does not imply live production conformance */
	simulation?: boolean;
}

export interface ReadinessReport {
	id: ResourceId;
	organizationId: ResourceId;
	generatedAt: string;
	checks: ReadinessCheck[];
	overall: "ready" | "blocked" | "attention";
	/** Explicit: overall ready never means live IdP/SCIM certification from synthetic checks */
	conformance: {
		mode: ConformanceMode;
		liveCertified: false | true;
		note: string;
	};
	remainingCustomerActions: string[];
	signature: string;
}

export interface MigrationPlan {
	id: ResourceId;
	source: "legacy";
	/** Immutable operator scope that owns this migration plan. */
	readonly projectId: ResourceId;
	readonly environmentId: ResourceId;
	status: "planned" | "running" | "verified" | "rolled_back" | "failed";
	counts: Record<string, number>;
	/** Stable fixture identity and last durable import checkpoint for safe resume/audit. */
	fixtureChecksum: string;
	checkpoint: {
		phase: "planned" | "dry_run" | "imported" | "verified" | "failed" | "rolled_back";
		source: "legacy";
		fixtureChecksum: string;
		counts: Record<string, number>;
		wouldCreate: Record<string, number>;
		idempotent: Record<string, number>;
	};
	createdResourceIds?: {
		users: ResourceId[];
		organizations: ResourceId[];
		memberships: ResourceId[];
	};
	/** Exact runtime rows created by the coordinated Postgres importer. */
	createdRuntimeResourceIds?: {
		users: ResourceId[];
		organizations: ResourceId[];
		memberships: ResourceId[];
	};
	/** Identity and relationship fields that must still match before exact rollback. */
	rollbackResourceState?: {
		management: {
			users: Array<{
				id: ResourceId;
				projectId: ResourceId;
				environmentId: ResourceId;
				email: string;
				name: string;
				status: Principal["status"];
				externalId?: string;
				updatedAt: string;
			}>;
			organizations: Array<{
				id: ResourceId;
				projectId: ResourceId;
				environmentId: ResourceId;
				name: string;
				slug: string;
				status: Organization["status"];
				externalId?: string;
				updatedAt: string;
			}>;
			memberships: Array<{
				id: ResourceId;
				organizationId: ResourceId;
				principalId: ResourceId;
				role: string;
				status: Membership["status"];
				source: Membership["source"];
				updatedAt: string;
			}>;
		};
		runtime: {
			users: Array<{
				id: ResourceId;
				email: string;
				name: string;
				emailVerified: boolean;
				image: string | null;
				banned: boolean;
				banReason: string | null;
				updatedAt: string;
			}>;
			organizations: Array<{
				id: ResourceId;
				name: string;
				slug: string;
				logo: string | null;
				metadata: string | null;
			}>;
			memberships: Array<{ id: ResourceId; organizationId: ResourceId; principalId: ResourceId; role: string }>;
		};
	};
	steps: Array<{
		name: string;
		status: "pending" | "done" | "failed" | "skipped";
		detail?: string;
	}>;
	createdAt: string;
	updatedAt: string;
}

export interface BackupRecord {
	id: ResourceId;
	path: string;
	createdAt: string;
	checksum: string;
	resourceCounts: Record<string, number>;
	verified: boolean;
}

export interface SessionRecord {
	id: ResourceId;
	principalId: ResourceId;
	environmentId: ResourceId;
	status: "active" | "revoked";
	createdAt: string;
	revokedAt?: string;
}

/** Digest-only API key record. The raw secret is returned once at creation only. */
export interface ApiKey {
	id: ResourceId;
	projectId: ResourceId;
	environmentId: ResourceId;
	name: string;
	/** Normalized, sorted authorization scopes. */
	scopes: string[];
	/** SHA-256 hex digest of the raw API key; never expose in public views. */
	digest: string;
	/** Safe non-secret identifier derived from the key material. */
	prefix: string;
	/** Short digest fingerprint for operator correlation. */
	fingerprint: string;
	status: "active" | "revoked";
	createdAt: string;
	updatedAt: string;
	revokedAt?: string;
	replacedById?: string;
}

export interface DoctorCheck {
	id: string;
	name: string;
	status: "pass" | "fail" | "warn";
	detail: string;
	remediation?: string;
}

export interface DataStoreSnapshot {
	version: number;
	releaseVersion: string;
	projects: Project[];
	environments: Environment[];
	principals: Principal[];
	organizations: Organization[];
	memberships: Membership[];
	identityConnections: IdentityConnection[];
	directoryConnections: DirectoryConnection[];
	/** Custom (operator-defined) roles only — built-ins are virtual */
	roles: CustomRole[];
	events: AuditEvent[];
	traces: DiagnosticTrace[];
	readinessReports: ReadinessReport[];
	migrations: MigrationPlan[];
	backups: BackupRecord[];
	sessions: SessionRecord[];
	/** API-key digests only; raw secrets are never snapshotted. */
	apiKeys: ApiKey[];
	/** Capability digests for SSO/SCIM setup links (no raw tokens) */
	setupLinks: SetupCapability[];
	meta: {
		initializedAt?: string;
		schemaVersion: number;
		config: Record<string, string>;
	};
}
