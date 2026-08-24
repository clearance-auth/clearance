import type {
	KeyProviderReadiness,
	KeyProviderRegistry,
	KeyPurpose,
	KeySigningProvider,
} from "@clearance/key-management";

export type SocialProviderConfig = {
	clientId: string;
	clientSecret: string;
	[key: string]: unknown;
};

export type ClearanceAuthenticationSecurityOptions = {
	passwordLockout?: {
		enabled?: boolean;
		maxFailedAttempts?: number;
		durationSeconds?: number;
	};
	twoFactor?: {
		enabled?: boolean;
		issuer?: string;
		maxFailedAttempts?: number;
		lockoutSeconds?: number;
		trustDeviceMaxAgeSeconds?: number;
	};
	breachedPassword?: {
		/** Defaults to enabled in strict/production mode. */
		enabled?: boolean;
		customMessage?: string;
		timeoutMs?: number;
	};
	asymmetricAccessTokens?: {
		enabled?: boolean;
		issuer?: string;
		audience?: string | string[];
		rotationIntervalSeconds?: number;
		gracePeriodSeconds?: number;
	};
};

/** Product-supported options forwarded directly to the runtime passkey plugin. */
export type ClearancePasskeyOptions = {
	/** Exact WebAuthn relying-party domain. Defaults from the static `baseURL`. */
	rpID?: string;
	/** Human-readable relying-party name shown by authenticators. */
	rpName?: string;
	/** Additional exact ceremony origins, validated by the runtime. */
	origin?: string[];
	authenticatorSelection?: {
		authenticatorAttachment?: "platform" | "cross-platform";
	};
	/** Per-plugin rate limit for all `/passkey/*` endpoints. */
	rateLimit?: {
		window?: number;
		max?: number;
	};
};

export type ClearanceRuntimeUser = {
	id: string;
	email: string;
	name: string;
	createdAt: Date;
	updatedAt: Date;
	emailVerified: boolean;
	image?: string | null;
};

export type ClearanceRuntimeOrganization = {
	id: string;
	name: string;
	slug: string;
	logo?: string | null;
	metadata?: Record<string, unknown> | null;
	createdAt: Date;
};

export type ClearanceRuntimeSession = {
	id: string;
	/** @deprecated Stable, non-secret compatibility alias for `id`. */
	token: string;
	userId: string;
	expiresAt: Date;
	createdAt: Date;
	updatedAt: Date;
	ipAddress?: string | null;
	userAgent?: string | null;
};

export type ClearanceRuntimeSessionResponse = {
	session: ClearanceRuntimeSession;
	user: ClearanceRuntimeUser;
};

export type TenantProductSsoConnection = Readonly<{
	id: string;
	organizationId: string;
	protocol: "saml" | "oidc";
	provider: string;
	status: "draft" | "testing" | "active" | "disabled";
	domains: readonly string[];
	issuer?: string;
	audience?: string;
	metadataUrl?: string;
	clientId?: string;
	clientSecretFingerprint?: string;
	hasClientSecret: boolean;
	samlEntryPoint?: string;
	samlCertificateFingerprint?: string;
	attributeMapping: Readonly<Record<string, string>>;
	createdAt: string;
	updatedAt: string;
}>;

export type TenantProductScimConnection = Readonly<{
	id: string;
	organizationId: string;
	provider: string;
	status: "draft" | "testing" | "active" | "disabled";
	endpoint: string;
	bearerTokenFingerprint?: string;
	hasBearerToken: boolean;
	deprovisioningPolicy: "disable" | "delete" | "suspend";
	createdAt: string;
	updatedAt: string;
}>;

export type TenantProductAuditEvent = Readonly<{
	id: string;
	correlationId: string;
	organizationId: string;
	actor: string;
	action: string;
	subjectType?: string;
	subjectId?: string;
	outcome: "success" | "failure" | "pending";
	source:
		| "cli"
		| "console"
		| "api"
		| "system"
		| "migration"
		| "sso"
		| "scim";
	message: string;
	metadata: Readonly<Record<string, unknown>>;
	createdAt: string;
}>;

export type TenantProductReadiness = Readonly<{
	id: string;
	organizationId: string;
	generatedAt: string;
	overall: "ready" | "blocked" | "attention";
	conformance: Readonly<{
		mode: "simulation" | "live";
		liveCertified: boolean;
		note: string;
	}>;
	checks: readonly Readonly<{
		id: string;
		name: string;
		status: "pass" | "fail" | "warn" | "skip";
		detail: string;
		fingerprint?: string;
		simulation?: boolean;
	}>[];
	remainingCustomerActions: readonly string[];
	reportDigest: string;
	/** Exact enterprise configuration fingerprint evaluated by this response. */
	stateFingerprint?: string;
	/** A stored report is never silently treated as current after a mutation. */
	state?: "current" | "stale" | "not_run";
}>;

/**
 * Server-only bridge for tenant enterprise administration. Implementations own
 * product scope, management storage, normalized transaction authorization, and
 * secret handling. Browser callers can supply only organization-scoped domain
 * inputs through the authenticated tenant endpoints.
 */
export type TenantProductAdministrationFacade = Readonly<{
	listAudit(input: {
		organizationId: string;
		actorId: string;
		limit?: number;
		cursor?: string;
		action?: string;
	}): Promise<Readonly<{
		events: readonly TenantProductAuditEvent[];
		nextCursor: string | null;
	}>>;
	listSso(input: {
		organizationId: string;
		actorId: string;
	}): Promise<readonly TenantProductSsoConnection[]>;
	inspectSso(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
	}): Promise<TenantProductSsoConnection>;
	createSso(input: {
		organizationId: string;
		actorId: string;
		protocol: "saml" | "oidc";
		provider: string;
		issuer: string;
		domain: string;
		audience?: string;
		clientId?: string;
		clientSecret?: string;
		samlEntryPoint?: string;
		samlCertificate?: string;
	}): Promise<TenantProductSsoConnection>;
	testSso(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
		mode?: "simulation" | "live";
	}): Promise<Readonly<{
		connection: TenantProductSsoConnection;
		pass: boolean;
		mode: "simulation" | "live";
		liveCertified: boolean;
		evidence?: string;
		authorizationUrl?: string;
	}>>;
	configureSso(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
		issuer?: string;
		audience?: string;
		domain?: string;
		clientId?: string;
		samlEntryPoint?: string;
		samlCertificate?: string;
	}): Promise<TenantProductSsoConnection>;
	replaceSsoSecret(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
		operationId: string;
		newClientSecret?: string;
		newSamlEntryPoint?: string;
		newSamlCertificate?: string;
	}): Promise<TenantProductSsoConnection>;
	disableSso(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
	}): Promise<Readonly<{
		connection: TenantProductSsoConnection;
		idempotent: boolean;
		runtimeRemoved: boolean;
	}>>;
	listScim(input: {
		organizationId: string;
		actorId: string;
	}): Promise<readonly TenantProductScimConnection[]>;
	inspectScim(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
	}): Promise<TenantProductScimConnection>;
	createScim(input: {
		organizationId: string;
		actorId: string;
		operationId: string;
		provider: string;
		endpoint?: string;
	}): Promise<Readonly<{
		connection: TenantProductScimConnection;
		bearerTokenOnce: string;
	}>>;
	testScim(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
		mode?: "simulation" | "live";
		scenario?: "users" | "group-lifecycle";
	}): Promise<Readonly<{
		connection: TenantProductScimConnection;
		pass: boolean;
		mode: "simulation" | "live";
		liveCertified: boolean;
		evidence?: string;
		groupLifecycle?: Readonly<{
			group: Readonly<{ id: string; status: "deleted" }>;
			counts: Readonly<{
				usersCreated: number;
				membersCreated: number;
				membersAfterPatch: number;
			}>;
		}>;
	}>>;
	configureScim(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
		endpoint?: string;
		deprovisioningPolicy?: "disable" | "delete" | "suspend";
	}): Promise<TenantProductScimConnection>;
	rotateScim(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
		operationId: string;
	}): Promise<Readonly<{
		connection: TenantProductScimConnection;
		bearerTokenOnce?: string;
		replayed: boolean;
	}>>;
	disableScim(input: {
		organizationId: string;
		actorId: string;
		connectionId: string;
	}): Promise<Readonly<{
		connection: TenantProductScimConnection;
		idempotent: boolean;
		runtimeRemoved: boolean;
	}>>;
	readiness(input: {
		organizationId: string;
		actorId: string;
	}): Promise<TenantProductReadiness>;
}>;

export type ClearancePublicPasskey = {
	id: string;
	name?: string | null;
	deviceType: "singleDevice" | "multiDevice";
	backedUp: boolean;
	transports?: Array<
		| "ble"
		| "cable"
		| "hybrid"
		| "internal"
		| "nfc"
		| "smart-card"
		| "usb"
	>;
	createdAt: Date;
	updatedAt: Date;
};

export type ClearancePasskeyRegistrationResponse = {
	id: string;
	rawId: string;
	type: "public-key";
	authenticatorAttachment?: "platform" | "cross-platform";
	clientExtensionResults: Record<string, unknown>;
	response: {
		clientDataJSON: string;
		attestationObject: string;
		authenticatorData?: string;
		transports?: ClearancePublicPasskey["transports"];
		publicKeyAlgorithm?: number;
		publicKey?: string;
	};
};

export type ClearancePasskeyAuthenticationResponse = {
	id: string;
	rawId: string;
	type: "public-key";
	authenticatorAttachment?: "platform" | "cross-platform";
	clientExtensionResults: Record<string, unknown>;
	response: {
		clientDataJSON: string;
		authenticatorData: string;
		signature: string;
		userHandle?: string;
	};
};

export type ClearancePasskeyRegistrationOptions = {
	challenge: string;
	rp: { id: string; name: string };
	user: { id: string; name: string; displayName: string };
	pubKeyCredParams: Array<{ alg: number; type: "public-key" }>;
	timeout: number;
	excludeCredentials?: Array<{
		id: string;
		type: "public-key";
		transports?: ClearancePublicPasskey["transports"];
	}>;
	authenticatorSelection: {
		authenticatorAttachment?: "platform" | "cross-platform";
		residentKey: "required";
		requireResidentKey: true;
		userVerification: "required";
	};
	attestation: "none";
	extensions?: Record<string, unknown>;
};

export type ClearancePasskeyAuthenticationOptions = {
	challenge: string;
	rpId: string;
	timeout: number;
	allowCredentials?: never;
	userVerification: "required";
	extensions?: Record<string, unknown>;
};

export type ClearancePasskeyDeletionCredential = {
	id: string;
	type: "public-key";
	transports?: ClearancePublicPasskey["transports"];
};

export type ClearancePasskeyDeletionOptions = {
	challenge: string;
	rpId: string;
	timeout: number;
	allowCredentials: [
		ClearancePasskeyDeletionCredential,
		...ClearancePasskeyDeletionCredential[],
	];
	userVerification: "required";
	extensions?: Record<string, unknown>;
};

export type ClearancePasskeyDeletionProof =
	| { type: "password"; password: string }
	| { type: "totp"; code: string }
	| { type: "recovery-code"; code: string }
	| { type: "passkey"; response: ClearancePasskeyAuthenticationResponse };

export type ClearanceTwoFactorRuntimeUser = ClearanceRuntimeUser & {
	twoFactorEnabled: boolean;
};

export type ClearanceTwoFactorEnrollment = {
	totpURI: string;
	backupCodes: string[];
};

export type ClearanceTwoFactorVerification = {
	token?: string;
	user: ClearanceTwoFactorRuntimeUser;
};

export type ClearanceJwtPayload = Record<string, unknown> & {
	sub?: string;
	iss?: string;
	aud?: string | string[];
	iat?: number;
	exp?: number;
	sid?: string;
	session_family?: string;
	session_generation?: number;
};

export type ClearanceJsonWebKey = Record<string, unknown> & {
	kid: string;
	kty: string;
	alg: string;
	use?: string;
	crv?: string;
	x?: string;
	y?: string;
	n?: string;
	e?: string;
};

export type ClearanceJsonWebKeySet = {
	keys: ClearanceJsonWebKey[];
};

interface ClearanceProductEndpoint<Input, Output> {
	(input: Input & { asResponse: true }): Promise<Response>;
	(input: Input & { returnHeaders: true; returnStatus: true }): Promise<{
		headers: Headers;
		status: number;
		response: Output;
	}>;
	(input: Input & { returnHeaders: true; returnStatus: false }): Promise<{
		headers: Headers;
		response: Output;
	}>;
	(input: Input & { returnHeaders: false; returnStatus: true }): Promise<{
		status: number;
		response: Output;
	}>;
	(
		input: Input & { returnHeaders: false; returnStatus: false },
	): Promise<Output>;
	(input: Input & { returnHeaders: true }): Promise<{
		headers: Headers;
		response: Output;
	}>;
	(input: Input & { returnStatus: true }): Promise<{
		status: number;
		response: Output;
	}>;
	(input: Input): Promise<Output>;
}

export type CreateClearanceAuthOptions<
	Security extends ClearanceAuthenticationSecurityOptions | undefined =
		ClearanceAuthenticationSecurityOptions,
	Passkeys extends false | ClearancePasskeyOptions | undefined =
		| false
		| ClearancePasskeyOptions
		| undefined,
> = {
	baseURL: string;
	secret: string;
	databaseUrl: string;
	enableSso?: boolean;
	enableScim?: boolean;
	trustedOrigins?: string[];
	rateLimitEnabled?: boolean;
	strictSecrets?: boolean;
	onUserCreated?: (user: ClearanceRuntimeUser) => void | Promise<void>;
	socialProviders?: Record<string, SocialProviderConfig>;
	/** Product-guarded runtime extensions such as OIDC Provider and MCP. */
	plugins?: ClearancePlugin[];
	authenticationSecurity?: Security;
	/**
	 * Immutable product scope for the managed PostgreSQL authentication-policy
	 * authority. Omit to keep the runtime policy-unmanaged.
	 */
	authenticationPolicy?: {
		projectId: string;
		environmentId: string;
	};
	/**
	 * Purpose-separated credential and signing-key protection. Required in
	 * production/strict mode. Development derives isolated encryption and
	 * signing keys.
	 */
	keyManagement?: {
		projectId: string;
		environmentId: string;
		registry: KeyProviderRegistry;
		/** ES256 software or cloud signer used for five-minute access tokens. */
		signingProvider: KeySigningProvider;
	};
	/**
	 * Append-only PostgreSQL security audit outbox. When omitted, a scope is
	 * derived only from one unambiguous managed product scope.
	 */
	runtimeAudit?:
		| false
		| {
				projectId: string;
				environmentId: string;
				schema?: string;
				prefix?: string;
		  };
	/**
	 * Normalized PostgreSQL roles, actions, subject assignments, service accounts,
	 * credentials, and organization authorization revisions.
	 */
	authorization?: {
		projectId: string;
		environmentId: string;
		schema?: string;
		prefix?: string;
	};
	/** Enabled by default. Set to `false` to omit the passkey server surface. */
	passkeys?: Passkeys;
	credentialAuthority?: {
		/** Runtime generation admitted by the durable database fence. */
		generation: "legacy-v1" | "digest-v1";
		/** Immutable rollout identity shared by every replica in one deployment. */
		deploymentId: string;
		/** Unique process or pod identity for diagnostics and fail-closed errors. */
		instanceId: string;
		/** Required by the one-shot migrator when upgrading existing authority. */
		migrationDrainId?: string;
		/** Maximum wait for all shared runtime leases to leave. */
		migrationLeaseTimeoutMs?: number;
	};
	durableDelivery?: {
		projectId: string;
		environmentId: string;
		/** Build the application page URL a recipient clicks to accept an invitation. */
		invitationUrl: (invitationId: string) => string;
		keyring: {
			currentKeyId: string;
			keys: Record<string, string>;
			currentFingerprintKeyId: string;
			fingerprintKeys: Record<string, string>;
			sourceDedupeKey: string;
		};
		schema?: string;
		prefix?: string;
		/** Required when upgrading non-empty delivery schema v1/v2; migrate before rotating this key. */
		legacyFingerprintKeyId?: string;
	};
};

export type ClearanceRuntimeMigrationPlan = {
	pendingTables: number;
	pendingFields: number;
	pendingSecurityMigrations: readonly string[];
	compileSql(): Promise<string>;
	apply(): Promise<void>;
};

export type ClearanceRuntimeMigrationResult = {
	appliedTables: number;
	appliedFields: number;
};

export type ClearanceAuthenticationAssuranceLevel =
	| "single_factor"
	| "multi_factor"
	| "phishing_resistant";

export type ClearanceAuthenticationPolicy = Readonly<{
	passwordLockout: Readonly<{
		enabled: boolean;
		maxFailedAttempts: number;
		durationSeconds: number;
	}>;
	factorLockout: Readonly<{
		enabled: boolean;
		maxFailedAttempts: number;
		durationSeconds: number;
	}>;
	minimumAssurance: ClearanceAuthenticationAssuranceLevel;
	allowedFactors: Readonly<{ totp: boolean; passkey: boolean }>;
	trustedDevice: Readonly<{ enabled: boolean; maxAgeSeconds: number }>;
	assuranceMaxAgeSeconds: number | null;
}>;

export type ClearanceAuthenticationPolicyOverride = Readonly<{
	passwordLockout?: Readonly<{
		enabled?: boolean;
		maxFailedAttempts?: number;
		durationSeconds?: number;
	}>;
	factorLockout?: Readonly<{
		enabled?: boolean;
		maxFailedAttempts?: number;
		durationSeconds?: number;
	}>;
	minimumAssurance?: ClearanceAuthenticationAssuranceLevel;
	allowedFactors?: Readonly<{ totp?: boolean; passkey?: boolean }>;
	trustedDevice?: Readonly<{ enabled?: boolean; maxAgeSeconds?: number }>;
	assuranceMaxAgeSeconds?: number | null;
}>;

/**
 * A caller-owned PostgreSQL transaction. Management facades use this narrow
 * structural shape so they can share an already-open transaction without
 * exposing a pool client or connection details.
 */
export type ClearanceTransactionQuery = Readonly<{
	rawTransactionQuery<Row extends Record<string, unknown> = Record<string, unknown>>(
		text: string,
		values?: readonly unknown[],
	): Promise<{ rows: Row[]; rowCount: number | null }>;
}>;

export type ClearanceAuthenticationPolicyTransaction = ClearanceTransactionQuery;

export type ClearanceAuthorizationSubject = Readonly<{
	kind: "principal" | "service_account";
	id: string;
}>;

export type ClearanceAuthorizationReadResult = Readonly<{
	projectId: string;
	environmentId: string;
	organizationId: string;
	subject: ClearanceAuthorizationSubject;
	roleIds: readonly string[];
	actions: readonly string[];
	revision: string;
}>;

export type ClearanceAuthorizationRole = Readonly<{
	roleId: string;
	organizationId: string | null;
	slug: string;
	name: string;
	description: string | null;
	builtIn: boolean;
	status: "active" | "disabled" | "archived";
	actions: readonly string[];
}>;

export type ClearanceAuthorizationAssignment = Readonly<{
	organizationId: string;
	subject: ClearanceAuthorizationSubject;
	roleId: string;
}>;

export type ClearanceAuthorizationAffectedRevision = Readonly<{
	organizationId: string;
	previousRevision: string;
	revision: string;
}>;

/** Redacted audit result from irreversible authorization terminalization. */
export type ClearanceAuthorizationArchiveOrganizationResult = Readonly<{
	organizationId: string;
	previousRevision: string;
	revision: string;
	archived: boolean;
	removedAssignments: number;
	disabledServiceAccounts: number;
	revokedCredentials: number;
}>;

export type ClearanceAuthorizationServiceAccount = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	name: string;
	status: "active" | "disabled";
}>;

export type ClearanceAuthorizationServiceAccountMutation = Readonly<{
	serviceAccount: ClearanceAuthorizationServiceAccount;
	previousRevision: string;
	revision: string;
}>;

export type ClearanceAuthorizationServiceAccountCredential = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	credentialId: string;
	credentialPrefix: string;
	credentialFingerprint: string;
	expiresAt: Date | null;
	version: number;
}>;

export type ClearanceAuthorizationServiceAccountCredentialMutation = Readonly<{
	credential: ClearanceAuthorizationServiceAccountCredential;
	secret: string;
	previousRevision: string;
	revision: string;
	/** Internal replay signal; tenant HTTP responses intentionally omit it. */
	replayed: boolean;
}>;

export type ClearanceAuthorizationServiceAccountAuthentication = Readonly<{
	projectId: string;
	environmentId: string;
	organizationId: string;
	subject: Readonly<{ kind: "service_account"; id: string }>;
	credential: ClearanceAuthorizationServiceAccountCredential;
	roleIds: readonly string[];
	actions: readonly string[];
	revision: string;
}>;

export type ClearanceAuthorizationFacade = Readonly<{
	readonly scope: Readonly<{ projectId: string; environmentId: string }>;
	/** Internal lifecycle sequencing primitive for an existing transaction. */
	acquireMutationLock(transaction: ClearanceTransactionQuery): Promise<void>;
	/** Package-internal startup reconciliation; callers supply only server-owned table identities. */
	reconcileRuntimeOrganizations(input: Readonly<{
		management: Readonly<{ schema: string; table: string }>;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<Readonly<{
		terminalizedOrganizations: number;
		terminalizedOrganizationIds: readonly string[];
		removedAssignments: number;
		disabledServiceAccounts: number;
		revokedCredentials: number;
	}>>;
	readEffective(input: Readonly<{
		organizationId: string;
		subject: ClearanceAuthorizationSubject;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<ClearanceAuthorizationReadResult>;
	initializeOrganization(input: Readonly<{
		organizationId: string;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<Readonly<{
		organizationId: string;
		revision: string;
		initialized: boolean;
	}>>;
	archiveOrganization(input: Readonly<{
		organizationId: string;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<ClearanceAuthorizationArchiveOrganizationResult>;
	upsertRole(input: Readonly<{
		role: Omit<ClearanceAuthorizationRole, "actions">;
		actions: readonly string[];
		transaction?: ClearanceTransactionQuery;
	}>): Promise<Readonly<{
		changed: boolean;
		affectedOrganizations: readonly ClearanceAuthorizationAffectedRevision[];
	}>>;
	replaceSubjectRoles(input: Readonly<{
		organizationId: string;
		subject: ClearanceAuthorizationSubject;
		roleIds: readonly string[];
		expectedRevision?: string;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<Readonly<{
		changed: boolean;
		previousRevision: string;
		revision: string;
		roleIds: readonly string[];
	}>>;
	listRoles(input: Readonly<{
		organizationId?: string;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<readonly ClearanceAuthorizationRole[]>;
	listSubjectAssignments(input: Readonly<{
		organizationId: string;
		subject?: ClearanceAuthorizationSubject;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<readonly ClearanceAuthorizationAssignment[]>;
	createServiceAccount(input: Readonly<{
		organizationId: string;
		serviceAccountId: string;
		name: string;
		roleIds: readonly string[];
		transaction?: ClearanceTransactionQuery;
	}>): Promise<ClearanceAuthorizationServiceAccountMutation>;
	listServiceAccounts(input: Readonly<{
		organizationId: string;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<readonly ClearanceAuthorizationServiceAccount[]>;
	setServiceAccountStatus(input: Readonly<{
		organizationId: string;
		serviceAccountId: string;
		status: "active" | "disabled";
		transaction?: ClearanceTransactionQuery;
	}>): Promise<ClearanceAuthorizationServiceAccountMutation>;
	createServiceAccountCredential(input: Readonly<{
		organizationId: string;
		actorId: string;
		operationId: string;
		serviceAccountId: string;
		credentialId?: string;
		expiresAt?: Date;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<ClearanceAuthorizationServiceAccountCredentialMutation>;
	rotateServiceAccountCredential(input: Readonly<{
		organizationId: string;
		actorId: string;
		operationId: string;
		serviceAccountId: string;
		credentialId: string;
		expiresAt?: Date;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<ClearanceAuthorizationServiceAccountCredentialMutation>;
	revokeServiceAccountCredential(input: Readonly<{
		organizationId: string;
		serviceAccountId: string;
		credentialId: string;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<ClearanceAuthorizationAffectedRevision>;
	authenticateServiceAccountCredential(input: Readonly<{
		secret: string;
		transaction?: ClearanceTransactionQuery;
	}>): Promise<ClearanceAuthorizationServiceAccountAuthentication>;
}>;

export type ClearanceKeyManagementMigrationCounts = Readonly<{
	oidcClientSecrets: number;
	scimTokens: number;
	jwks: number;
	total: number;
}>;

export type ClearanceKeyManagementStatus = Readonly<{
	schemaVersion: "v1";
	scope: Readonly<{ projectId: string; environmentId: string }>;
	ready: boolean;
	encryption: Readonly<{
		ready: boolean;
		purposes: Readonly<Record<KeyPurpose, KeyProviderReadiness>>;
	}>;
	signing: Readonly<{
		ready: boolean;
		readiness: KeyProviderReadiness;
		algorithm: "ES256";
		currentIdentity: string;
		retainedIdentities: readonly string[];
		gracePeriodSeconds: number;
	}>;
	schema: Readonly<{ setup: "ready" | "pending" }>;
	migration: Readonly<{
		complete: boolean;
		pending: ClearanceKeyManagementMigrationCounts;
		migrated: ClearanceKeyManagementMigrationCounts;
	}>;
}>;

export type ClearanceKeyManagementMigrationPlan = Readonly<{
	schemaVersion: "v1";
	scope: Readonly<{ projectId: string; environmentId: string }>;
	phase: "setup" | "batch" | "complete";
	maxBatchSize: Readonly<{ perDomain: 5; total: 15 }>;
	pending: ClearanceKeyManagementMigrationCounts;
	nextBatch: ClearanceKeyManagementMigrationCounts;
	planId: string;
}>;

export type ClearanceKeyManagementMigrationResult = Readonly<{
	applied: ClearanceKeyManagementMigrationCounts;
	changed: number;
	previousPlanId: string;
	nextPlanId: string;
	remainingPlan: ClearanceKeyManagementMigrationPlan;
	status: ClearanceKeyManagementStatus;
	complete: boolean;
}>;

export type ClearanceKeyManagementFacade = Readonly<{
	readonly scope: Readonly<{ projectId: string; environmentId: string }>;
	resourceId(
		purpose: KeyPurpose,
		identity: Readonly<Record<string, string | null>>,
	): string;
	sealText(
		purpose: KeyPurpose,
		resourceId: string,
		plaintext: string,
	): Promise<string>;
	openText(
		purpose: KeyPurpose,
		resourceId: string,
		envelope: string,
	): Promise<string>;
	readiness(): Promise<Readonly<{
		ready: boolean;
		purposes: Readonly<Record<KeyPurpose, KeyProviderReadiness>>;
	}>>;
	status(): Promise<ClearanceKeyManagementStatus>;
	planMigration(): Promise<ClearanceKeyManagementMigrationPlan>;
	applyMigration(input: {
		expectedPlanId: string;
		transaction: ClearanceTransactionQuery;
	}): Promise<ClearanceKeyManagementMigrationResult>;
}>;

export type ClearanceAuthenticationPolicyGetResult = Readonly<{
	schemaVersion: "v1";
	scope: Readonly<{ projectId: string; environmentId: string }>;
	revision: string;
	environment: ClearanceAuthenticationPolicy;
	organizationOverride: Readonly<{
		organizationId: string;
		revision: string;
		policy: ClearanceAuthenticationPolicyOverride;
	}> | null;
	effective: ClearanceAuthenticationPolicy;
}>;

export type ClearanceAuthenticationPolicyPlanResult = Readonly<{
	schemaVersion: "v1";
	scope: Readonly<{ projectId: string; environmentId: string }>;
	target:
		| Readonly<{ kind: "environment" }>
		| Readonly<{ kind: "organization"; organizationId: string }>;
	expectedRevision: string;
	candidateRevision: string;
	wouldChange: boolean;
	current: Readonly<{
		revision: string;
		policy: ClearanceAuthenticationPolicy | ClearanceAuthenticationPolicyOverride | null;
		effective: ClearanceAuthenticationPolicy;
	}>;
	candidate: Readonly<{
		revision: string;
		policy: ClearanceAuthenticationPolicy | ClearanceAuthenticationPolicyOverride | null;
		effective: ClearanceAuthenticationPolicy;
	}>;
}>;

export type ClearanceAuthenticationPolicyApplyResult =
	ClearanceAuthenticationPolicyPlanResult &
		Readonly<{
			changed: boolean;
			previousRevision: string;
			revision: string;
		}>;

export type ClearanceAuthenticationUnlockKind = "password" | "factor" | "all";

export type ClearanceAuthenticationUnlockAuthorityCounts = Readonly<{
	matchedRows: number;
	failedAttemptRows: number;
	reservationRows: number;
	lockedRows: number;
	wouldChangeRows: number;
}>;

export type ClearanceAuthenticationUnlockPreview = Readonly<{
	schemaVersion: "v1";
	userId: string;
	kind: ClearanceAuthenticationUnlockKind;
	password: ClearanceAuthenticationUnlockAuthorityCounts;
	factor: ClearanceAuthenticationUnlockAuthorityCounts;
	wouldChange: boolean;
}>;

export type ClearanceAuthenticationUnlockResult =
	ClearanceAuthenticationUnlockPreview & Readonly<{ changed: boolean }>;

export type ClearanceAuthenticationPolicyFacade = Readonly<{
	/** Immutable authority scope for fail-fast management scope comparison. */
	scope: Readonly<{ projectId: string; environmentId: string }>;
	get(input?: {
		organizationId?: string;
		transaction?: ClearanceAuthenticationPolicyTransaction;
	}): Promise<ClearanceAuthenticationPolicyGetResult>;
	plan(input: ClearanceAuthenticationPolicyCandidateInput & {
		transaction?: ClearanceAuthenticationPolicyTransaction;
	}): Promise<ClearanceAuthenticationPolicyPlanResult>;
	apply(input: ClearanceAuthenticationPolicyCandidateInput & {
		expectedRevision: string;
		transaction?: ClearanceAuthenticationPolicyTransaction;
	}): Promise<ClearanceAuthenticationPolicyApplyResult>;
	planUnlock(input: {
		userId: string;
		kind: ClearanceAuthenticationUnlockKind;
		transaction?: ClearanceAuthenticationPolicyTransaction;
	}): Promise<ClearanceAuthenticationUnlockPreview>;
	unlock(input: {
		userId: string;
		kind: ClearanceAuthenticationUnlockKind;
		transaction?: ClearanceAuthenticationPolicyTransaction;
	}): Promise<ClearanceAuthenticationUnlockResult>;
}>;

export type ClearanceAuthenticationPolicyCandidateInput =
	| Readonly<{
			organizationId?: never;
			policy: ClearanceAuthenticationPolicy;
	  }>
	| Readonly<{
			organizationId: string;
			policy: ClearanceAuthenticationPolicyOverride | null;
	  }>;

export interface ClearanceAuthRuntime {
	handler(request: Request): Promise<Response>;
	readonly api: Readonly<Record<string, (...args: any[]) => Promise<any>>>;
	readonly $context: Promise<unknown>;
}

type ClearanceBaseProductApi = {
	signInEmail(input: Record<string, unknown>): Promise<unknown>;
	getSession(input: {
		headers?: HeadersInit;
		query?: { disableCookieCache?: boolean; disableRefresh?: boolean };
	}): Promise<ClearanceRuntimeSessionResponse | null>;
	resetPassword(input: Record<string, unknown>): Promise<unknown>;
	signUpEmail(input: {
		body: { email: string; password: string; name: string };
	}): Promise<{ token: string; user: ClearanceRuntimeUser }>;
	listOrganizations(input: {
		headers: Headers;
	}): Promise<ClearanceRuntimeOrganization[]>;
	createOrganization(input: {
		body: {
			name: string;
			slug: string;
			logo?: string | null;
			metadata?: Record<string, unknown>;
			keepCurrentActiveOrganization?: boolean;
		};
		headers: Headers;
	}): Promise<ClearanceRuntimeOrganization>;
};

type ClearanceTwoFactorProductApi = {
	enableTwoFactor: ClearanceProductEndpoint<
		{
			body: { password: string; issuer?: string; currentCode?: string };
			headers: HeadersInit;
		},
		ClearanceTwoFactorEnrollment
	>;
	getTOTPURI: ClearanceProductEndpoint<
		{
			body: { password: string };
			headers: HeadersInit;
		},
		{ totpURI: string }
	>;
	verifyTOTP: ClearanceProductEndpoint<
		{
			body: { code: string; trustDevice?: boolean };
			headers: HeadersInit;
		},
		ClearanceTwoFactorVerification
	>;
	disableTwoFactor: ClearanceProductEndpoint<
		{
			body:
				| { password: string; currentCode: string; recoveryCode?: never }
				| { password: string; currentCode?: never; recoveryCode: string };
			headers: HeadersInit;
		},
		{ status: true }
	>;
	generateBackupCodes: ClearanceProductEndpoint<
		{
			body:
				| { password: string; currentCode: string; recoveryCode?: never }
				| { password: string; currentCode?: never; recoveryCode: string };
			headers: HeadersInit;
		},
		{ status: true; backupCodes: string[] }
	>;
	verifyBackupCode: ClearanceProductEndpoint<
		{
			body: {
				code: string;
				disableSession?: boolean;
				trustDevice?: boolean;
			};
			headers: HeadersInit;
		},
		ClearanceTwoFactorVerification
	>;
};

type ClearanceJwtProductApi = {
	getToken: ClearanceProductEndpoint<
		{
			headers: HeadersInit;
		},
		{ token: string }
	>;
	getJwks(): Promise<ClearanceJsonWebKeySet>;
	verifyJWT: ClearanceProductEndpoint<
		{
			body: { token: string; issuer?: string };
		},
		{ payload: ClearanceJwtPayload | null }
	>;
};

type ClearancePasskeyProductApi = {
	generatePasskeyRegistrationOptions: ClearanceProductEndpoint<
		{
			body?: {
				authenticatorAttachment?: "platform" | "cross-platform";
			};
			headers: HeadersInit;
		},
		ClearancePasskeyRegistrationOptions
	>;
	verifyPasskeyRegistration: ClearanceProductEndpoint<
		{
			body: {
				response: ClearancePasskeyRegistrationResponse;
				name?: string;
			};
			headers: HeadersInit;
		},
		ClearancePublicPasskey
	>;
	generatePasskeyAuthenticationOptions: ClearanceProductEndpoint<
		{ headers: HeadersInit },
		ClearancePasskeyAuthenticationOptions
	>;
	verifyPasskeyAuthentication: ClearanceProductEndpoint<
		{
			body: { response: ClearancePasskeyAuthenticationResponse };
			headers: HeadersInit;
		},
		ClearanceRuntimeSessionResponse
	>;
	generatePasskeyDeletionOptions: ClearanceProductEndpoint<
		{ body: { id: string }; headers: HeadersInit },
		ClearancePasskeyDeletionOptions
	>;
	deletePasskey: ClearanceProductEndpoint<
		{
			body: { id: string; proof: ClearancePasskeyDeletionProof };
			headers: HeadersInit;
		},
		{ status: true }
	>;
	listPasskeys: ClearanceProductEndpoint<
		{ headers: HeadersInit },
		ClearancePublicPasskey[]
	>;
	updatePasskey: ClearanceProductEndpoint<
		{ body: { id: string; name: string }; headers: HeadersInit },
		ClearancePublicPasskey
	>;
};

type ClearanceAuthenticationSecurityApi<
	Security extends ClearanceAuthenticationSecurityOptions | undefined,
> = (Security extends undefined
	? ClearanceTwoFactorProductApi
	: "twoFactor" extends keyof Security
		? Security extends { twoFactor: { enabled: false } }
			? Record<never, never>
			: Security extends { twoFactor: { enabled: true } }
				? ClearanceTwoFactorProductApi
				: Partial<ClearanceTwoFactorProductApi>
		: ClearanceTwoFactorProductApi) &
	(Security extends undefined
		? ClearanceJwtProductApi
		: "asymmetricAccessTokens" extends keyof Security
			? Security extends { asymmetricAccessTokens: { enabled: false } }
				? Record<never, never>
				: Security extends { asymmetricAccessTokens: { enabled: true } }
					? ClearanceJwtProductApi
					: Partial<ClearanceJwtProductApi>
			: ClearanceJwtProductApi);

type ClearancePasskeyApi<
	Passkeys extends false | ClearancePasskeyOptions | undefined,
> = [Passkeys] extends [false]
	? Record<never, never>
	: false extends Passkeys
		? Partial<ClearancePasskeyProductApi>
		: ClearancePasskeyProductApi;

export type ClearanceProductAuthRuntime<
	Security extends ClearanceAuthenticationSecurityOptions | undefined =
		undefined,
	Passkeys extends false | ClearancePasskeyOptions | undefined = undefined,
> = Omit<ClearanceAuthRuntime, "api"> & {
	readonly api: ClearanceBaseProductApi &
		ClearanceAuthenticationSecurityApi<Security> &
		ClearancePasskeyApi<Passkeys>;
};

export interface ClearanceQueryResult<
	Row extends Record<string, unknown> = Record<string, unknown>,
> {
	rows: Row[];
	rowCount: number | null;
}

export interface ClearanceDatabasePool {
	query<Row extends Record<string, unknown> = Record<string, unknown>>(
		text: string,
		values?: readonly unknown[],
	): Promise<ClearanceQueryResult<Row>>;
	end(): Promise<void>;
}

export type ClearanceAuthBundle<
	Security extends ClearanceAuthenticationSecurityOptions | undefined =
		undefined,
	Passkeys extends false | ClearancePasskeyOptions | undefined = undefined,
> = {
	auth: ClearanceProductAuthRuntime<Security, Passkeys>;
	pool: ClearanceDatabasePool;
	db: unknown;
	plugins: {
		organization: true;
		sso: boolean;
		scim: boolean;
		twoFactor: boolean;
		breachedPassword: boolean;
		asymmetricAccessTokens: boolean;
		passkeys: boolean;
	};
	rateLimitEnabled: boolean;
	credentialAuthority: {
		status(): Promise<{
			protocolVersion: number;
			phase: "legacy-open" | "draining" | "migrating" | "digest-live";
			generation: "legacy-v1" | "digest-v1";
			drainId: string | null;
			bridgeDeploymentId: string | null;
			expectedRuntimeCount: number | null;
			revision: number;
			drainStartedAt: Date | null;
			drainedAt: Date | null;
			publishedAt: Date | null;
			activeRuntimeLeases: number;
		}>;
		arm(input: {
			deploymentId: string;
			expectedRuntimeCount: number;
		}): Promise<unknown>;
		beginDrain(input: {
			deploymentId: string;
			drainId: string;
		}): Promise<unknown>;
		assertRuntimeServing(): Promise<void>;
	};
	passwordSetup: {
		/** Issue the stock single-use password-reset ceremony for an operator-created user. */
		create(input: {
			userId: string;
			token: string;
			expiresAt: Date;
		}): Promise<void>;
	};
	/** Present only when createClearanceAuth received authenticationPolicy scope. */
	authenticationPolicy?: ClearanceAuthenticationPolicyFacade;
	/** Present only when createClearanceAuth received authorization scope. */
	authorization?: ClearanceAuthorizationFacade;
	keyManagement: ClearanceKeyManagementFacade;
	prepareCredentialAuthorityRuntime(): Promise<void>;
	planMigrations(): Promise<ClearanceRuntimeMigrationPlan>;
	migrate(input?: { drainId?: string }): Promise<ClearanceRuntimeMigrationResult>;
	destroy(): Promise<void>;
};

export interface ClearancePlugin {
	id: string;
	readonly endpoints?: Readonly<Record<string, unknown>>;
	readonly options?: unknown;
}

export declare function oidcProvider(options: {
	loginPage: string;
	consentPage?: string;
	useJWTPlugin?: boolean;
	[key: string]: unknown;
}): ClearancePlugin;

export declare function mcp(options: {
	loginPage: string;
	resource?: string;
	[key: string]: unknown;
}): ClearancePlugin;

export type ClearanceMigrationSet = {
	toBeCreated: ReadonlyArray<{
		table: string;
		fields: Record<string, unknown>;
		order: number;
	}>;
	toBeAdded: ReadonlyArray<{
		table: string;
		fields: Record<string, unknown>;
		order: number;
	}>;
	pendingSecurityMigrations: readonly string[];
	runMigrations(): Promise<void>;
	compileMigrations(): Promise<string>;
};

export declare const CLEARANCE_AUTH_VERSION: string;
export declare const RUNTIME_BASELINE: Readonly<{
	package: "@clearance/runtime";
	version: "1.6.23";
}>;
export declare const DEFAULT_TELEMETRY_ENDPOINT: string | undefined;

export declare function encryptRuntimeCredential(
	plaintext: string,
	secret: string,
): Promise<string>;
export declare function decryptRuntimeCredential(
	ciphertext: string,
	secret: string,
): Promise<string>;
export declare function socialProvidersFromEnvironment(
	env?: Record<string, string | undefined>,
): Record<string, SocialProviderConfig>;
export declare function createClearanceAuth<
	const Security extends ClearanceAuthenticationSecurityOptions | undefined =
		undefined,
	const Passkeys extends false | ClearancePasskeyOptions | undefined = undefined,
>(
	options: CreateClearanceAuthOptions<Security, Passkeys>,
): ClearanceAuthBundle<Security, Passkeys>;
export declare function withClearanceDefaults<
	T extends Record<string, unknown>,
>(options: T): T & { telemetry: { enabled: false } };

export declare function clearance<Options extends Record<string, unknown>>(
	options: Options,
): ClearanceAuthRuntime;
export declare function organization(
	options?: Record<string, unknown>,
): ClearancePlugin;
export declare function sso(options?: Record<string, unknown>): ClearancePlugin;
export declare function scim(
	options?: Record<string, unknown>,
): ClearancePlugin;
export declare function getMigrations(
	options: Record<string, unknown>,
): Promise<ClearanceMigrationSet>;

export {
	FORBIDDEN_DEFAULT_SECRETS,
	MINIMUM_SECRET_LENGTH,
	isForbiddenDefaultSecret,
} from "./secret-policy.js";
export { fromNodeHeaders, toNodeHandler } from "./node.js";
