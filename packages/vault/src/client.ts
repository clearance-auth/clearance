import type { VaultEndpointConfig } from "./origins";
import {
	createVaultTransport,
	type VaultRequestOptions,
} from "./transport";
import {
	parseAssignment,
	parseAuthPost,
	parseCredentialMutation,
	parseAuditList,
	parseEffectiveAuthorization,
	parseEnterpriseReadiness,
	parseScimConnection,
	parseScimMutation,
	parseScimRotation,
	parseScimTest,
	parseSSOConnection,
	parseSsoCreate,
	parseSsoMutation,
	parseSSOTest,
	parseInvitation,
	parseList,
	parseOrganization,
	parsePasskey,
	parseRole,
	parseServiceAccount,
	parseSession,
	parseSessionState,
	parseStatus,
	record,
} from "./validation";
import {
	parseDeletionOptions,
	parseAuthenticationOptions,
	parseRegistrationOptions,
	type VaultAuthenticationResponse,
	type VaultAuthenticationOptions,
	type VaultDeletionOptions,
	type VaultRegistrationOptions,
	type VaultRegistrationResponse,
} from "./webauthn";

export type VaultUser = Readonly<{
	id: string;
	email: string;
	name?: string | null;
	image?: string | null;
	twoFactorEnabled?: boolean;
}>;

export type VaultSession = Readonly<{
	id: string;
	userId: string;
	activeOrganizationId?: string | null;
	expiresAt?: string | Date;
	ipAddress?: string | null;
	userAgent?: string | null;
}>;

export type VaultSessionState = Readonly<{
	user: VaultUser;
	session: VaultSession;
}>;

export type VaultTwoFactorMethod = "totp" | "otp" | "backup_code";

export type VaultAuthenticationResult =
	| Readonly<{ kind: "authenticated"; session: VaultSessionState }>
	| Readonly<{
			kind: "two_factor_required";
			methods: readonly VaultTwoFactorMethod[];
	  }>
	| Readonly<{ kind: "verification_required"; user: VaultUser }>;

export type VaultOrganization = Readonly<{
	id: string;
	name: string;
	slug?: string;
	logo?: string | null;
}>;

export type VaultOrganizationCreateInput = Readonly<{
	name: string;
	slug: string;
}>;

export type VaultInvitation = Readonly<{
	id: string;
	email: string;
	status: string;
	role?: string;
	organizationId?: string;
	organizationName?: string;
	expiresAt?: string | Date;
}>;

export type VaultPasskey = Readonly<{
	id: string;
	name?: string | null;
	createdAt?: string | Date;
	deviceType?: string;
	backedUp?: boolean;
}>;

export type VaultClientConfig = VaultEndpointConfig;

export type VaultPasskeyDeletionProof =
	| Readonly<{ type: "password"; password: string }>
	| Readonly<{ type: "totp"; code: string }>
	| Readonly<{ type: "recovery-code"; code: string }>
	| Readonly<{ type: "passkey"; response: VaultAuthenticationResponse }>;

export type VaultFactorStepUp =
	| Readonly<{ currentCode: string; recoveryCode?: never }>
	| Readonly<{ currentCode?: never; recoveryCode: string }>;

export type VaultAuthorizationSubject = Readonly<{
	kind: "principal" | "service_account";
	id: string;
}>;

export type VaultAuthorizationRole = Readonly<{
	roleId: string;
	organizationId: string | null;
	slug: string;
	name: string;
	description: string | null;
	builtIn: boolean;
	status: "active" | "disabled" | "archived";
	actions: readonly string[];
}>;

export type VaultAuthorizationAssignment = Readonly<{
	organizationId: string;
	subject: VaultAuthorizationSubject;
	roleId: string;
}>;

export type VaultEffectiveAuthorization = Readonly<{
	projectId: string;
	environmentId: string;
	organizationId: string;
	subject: VaultAuthorizationSubject;
	roleIds: readonly string[];
	actions: readonly string[];
	revision: string;
}>;

export type VaultServiceAccount = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	name: string;
	status: "active" | "disabled";
}>;

export type VaultServiceAccountCredential = Readonly<{
	organizationId: string;
	serviceAccountId: string;
	credentialId: string;
	credentialPrefix: string;
	credentialFingerprint: string;
	expiresAt: string | null;
	version: number;
}>;

export type VaultSSOProvider = Readonly<{
	providerId: string;
	type: "saml" | "oidc";
	issuer: string;
	domain: string;
	organizationId: string | null;
	domainVerified: boolean;
}>;

export type VaultSCIMConnection = Readonly<{
	id: string;
	providerId: string;
	organizationId: string | null;
}>;

export type VaultCredentialMutation = Readonly<{
	credential: VaultServiceAccountCredential;
	secret: string;
	previousRevision: string;
	revision: string;
}>;

export type VaultAuditEvent = Readonly<{
	id: string;
	correlationId: string;
	action: string;
	outcome: "success" | "failure" | "pending";
	source: "cli" | "console" | "api" | "system" | "migration" | "sso" | "scim";
	message: string;
	createdAt: string;
}>;

export type VaultAuditPage = Readonly<{
	events: readonly VaultAuditEvent[];
	nextCursor: string | null;
}>;

export type VaultSsoConnection = Readonly<{
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

export type VaultScimConnection = Readonly<{
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

export type VaultMutationPreview = Readonly<{ dryRun: true; confirm: false }>;
export type VaultMutationConfirmation = Readonly<{
	dryRun: false;
	confirm: true;
}>;

type VaultSsoCreateBaseInput =
	| Readonly<{
		protocol: "oidc";
		provider: string;
		issuer: string;
		domain: string;
		audience?: string;
		clientId: string;
	}>
	| Readonly<{
		protocol: "saml";
		provider: string;
		issuer: string;
		domain: string;
		audience?: string;
		samlEntryPoint: string;
	}>;

/** Preview payloads deliberately omit credentials and certificates. */
export type VaultSsoCreatePreviewInput = VaultSsoCreateBaseInput & VaultMutationPreview;

export type VaultSsoCreateLiveInput =
	| (Extract<VaultSsoCreateBaseInput, Readonly<{ protocol: "oidc" }>> &
		Readonly<{ clientSecret: string }> & VaultMutationConfirmation)
	| (Extract<VaultSsoCreateBaseInput, Readonly<{ protocol: "saml" }>> &
		Readonly<{ samlCertificate: string }> & VaultMutationConfirmation);

/** @deprecated Prefer the preview or live discriminated input type. */
export type VaultSsoCreateInput = VaultSsoCreatePreviewInput | VaultSsoCreateLiveInput;

export type VaultSsoCreatePreview = Readonly<{
	preview: true;
	proposed:
		| Readonly<{
				organizationId: string;
				protocol: "oidc";
				provider: string;
				issuer: string;
				domain: string;
				audience: string | null;
				clientId: string;
				hasClientSecret: true;
		  }>
		| Readonly<{
				organizationId: string;
				protocol: "saml";
				provider: string;
				issuer: string;
				domain: string;
				audience: string | null;
				samlEntryPoint: string;
				hasSamlCertificate: true;
		  }>;
	wouldChange: boolean;
}>;

export type VaultSsoMutationPreview = Readonly<{
	preview: true;
	connection: VaultSsoConnection;
	wouldChange: boolean;
}>;

export type VaultScimCreatePreview = Readonly<{
	preview: true;
	proposed: Readonly<{
		organizationId: string;
		provider: string;
		endpoint: string | null;
		bearerTokenGenerated: false;
	}>;
	wouldChange: boolean;
}>;

export type VaultScimMutationPreview = Readonly<{
	preview: true;
	connection: VaultScimConnection;
	wouldChange: boolean;
}>;

export type VaultScimSecretMutation = Readonly<{
	connection: VaultScimConnection;
	bearerTokenOnce: string;
}>;

export type VaultScimRotation = Readonly<{
	connection: VaultScimConnection;
	replayed: boolean;
	bearerTokenOnce?: string;
}>;

export type VaultConnectionDisableResult<TConnection> = Readonly<{
	connection: TConnection;
	idempotent: boolean;
	runtimeRemoved: boolean;
}>;

export type VaultSsoTestResult = Readonly<{
	connection: VaultSsoConnection;
	pass: boolean;
	evidence?: string;
	mode?: "simulation" | "live";
	liveCertified: boolean;
}>;

export type VaultScimTestResult = Readonly<{
	connection: VaultScimConnection;
	pass: boolean;
	evidence?: string;
	mode?: "simulation" | "live";
	liveCertified: boolean;
	scenario?: "users" | "group-lifecycle";
	groupLifecycle?: Readonly<{
		group: Readonly<{ id: string; status: "deleted" }>;
		counts: Readonly<{
			usersCreated: number;
			membersCreated: number;
			membersAfterPatch: number;
		}>;
	}>;
}>;

export type VaultReadiness = Readonly<{
	state: "ready" | "not_run" | "stale" | "blocked";
	overall: "ready" | "blocked" | "attention";
	generatedAt: string;
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
		simulation?: boolean;
	}>[];
	remainingCustomerActions: readonly string[];
}>;

export type VaultConfirmedMutation =
	| Readonly<{ dryRun: true; confirm: false }>
	| Readonly<{ dryRun: false; confirm: true }>;

export type VaultAuthClient = Readonly<{
	getSession(options?: VaultRequestOptions): Promise<VaultSessionState | null>;
	signIn(
		input: Readonly<{ email: string; password: string; rememberMe?: boolean }>,
		options?: VaultRequestOptions,
	): Promise<VaultAuthenticationResult>;
	signUp(
		input: Readonly<{
			name: string;
			email: string;
			password: string;
			rememberMe?: boolean;
		}>,
		options?: VaultRequestOptions,
	): Promise<VaultAuthenticationResult>;
	sendTwoFactorOTP(options?: VaultRequestOptions): Promise<void>;
	completeTwoFactor(
		input: Readonly<{
			method: VaultTwoFactorMethod;
			code: string;
			trustDevice?: boolean;
		}>,
		options?: VaultRequestOptions,
	): Promise<VaultSessionState>;
	signOut(options?: VaultRequestOptions): Promise<unknown>;
	requestPasswordReset(
		input: Readonly<{ email: string; redirectTo?: string }>,
		options?: VaultRequestOptions,
	): Promise<Readonly<{ status: boolean; message?: string }>>;
	resetPassword(
		input: Readonly<{ token: string; newPassword: string }>,
		options?: VaultRequestOptions,
	): Promise<Readonly<{ status: boolean }>>;
	changePassword(
		input: Readonly<{
			currentPassword: string;
			newPassword: string;
			revokeOtherSessions?: boolean;
		}>,
		options?: VaultRequestOptions,
	): Promise<unknown>;
	listSessions(options?: VaultRequestOptions): Promise<readonly VaultSession[]>;
	revokeOtherSessions(options?: VaultRequestOptions): Promise<unknown>;
	listPasskeys(options?: VaultRequestOptions): Promise<readonly VaultPasskey[]>;
	beginPasskeyRegistration(
		input?: Readonly<{
			authenticatorAttachment?: "platform" | "cross-platform";
		}>,
		options?: VaultRequestOptions,
	): Promise<VaultRegistrationOptions>;
	finishPasskeyRegistration(
		input: Readonly<{ response: VaultRegistrationResponse; name?: string }>,
		options?: VaultRequestOptions,
	): Promise<VaultPasskey>;
	beginPasskeyAuthentication(options?: VaultRequestOptions): Promise<VaultAuthenticationOptions>;
	finishPasskeyAuthentication(input: Readonly<{ response: VaultAuthenticationResponse }>, options?: VaultRequestOptions): Promise<VaultSessionState>;
	beginPasskeyDeletion(
		input: Readonly<{ id: string }>,
		options?: VaultRequestOptions,
	): Promise<VaultDeletionOptions>;
	deletePasskey(
		input: Readonly<{
			id: string;
			proof: VaultPasskeyDeletionProof;
		}>,
		options?: VaultRequestOptions,
	): Promise<VaultSessionState>;
	enableTwoFactor(
		input: Readonly<{ password: string; currentCode?: string }>,
		options?: VaultRequestOptions,
	): Promise<
		Readonly<{
			totpURI: string;
			backupCodes: readonly string[];
			session: VaultSessionState;
		}>
	>;
	verifyTwoFactor(
		input: Readonly<{ code: string; trustDevice?: boolean }>,
		options?: VaultRequestOptions,
	): Promise<VaultSessionState>;
	disableTwoFactor(
		input: Readonly<{ password: string }> & VaultFactorStepUp,
		options?: VaultRequestOptions,
	): Promise<VaultSessionState>;
	generateBackupCodes(
		input: Readonly<{ password: string }> & VaultFactorStepUp,
		options?: VaultRequestOptions,
	): Promise<
		Readonly<{ backupCodes: readonly string[]; session: VaultSessionState }>
	>;
	createOrganization(
		input: VaultOrganizationCreateInput,
		options?: VaultRequestOptions,
	): Promise<VaultOrganization>;
	listOrganizations(options?: VaultRequestOptions): Promise<readonly VaultOrganization[]>;
	setActiveOrganization(
		organizationId: string,
		options?: VaultRequestOptions,
	): Promise<VaultOrganization | null>;
	listUserInvitations(
		options?: VaultRequestOptions,
	): Promise<readonly VaultInvitation[]>;
	listOrganizationInvitations(
		organizationId: string,
		options?: VaultRequestOptions,
	): Promise<readonly VaultInvitation[]>;
	inviteMember(
		input: Readonly<{
			organizationId: string;
			email: string;
			role: string | readonly string[];
		}>,
		options?: VaultRequestOptions,
	): Promise<VaultInvitation>;
	cancelInvitation(
		invitationId: string,
		options?: VaultRequestOptions,
	): Promise<unknown>;
	acceptInvitation(
		invitationId: string,
		options?: VaultRequestOptions,
	): Promise<unknown>;
	rejectInvitation(
		invitationId: string,
		options?: VaultRequestOptions,
	): Promise<unknown>;
}>;

export type VaultTenantClient = Readonly<{
	listAudit(
		organizationId: string,
		input?: Readonly<{ cursor?: string; limit?: number; action?: string }>,
		options?: VaultRequestOptions,
	): Promise<VaultAuditPage>;
	listSso(
		organizationId: string,
		options?: VaultRequestOptions,
	): Promise<readonly VaultSsoConnection[]>;
	inspectSso(
		organizationId: string,
		connectionId: string,
		options?: VaultRequestOptions,
	): Promise<VaultSsoConnection>;
	createSso(
		organizationId: string,
		input: VaultSsoCreatePreviewInput,
		options?: VaultRequestOptions,
	): Promise<VaultSsoCreatePreview>;
	createSso(
		organizationId: string,
		input: VaultSsoCreateLiveInput,
		options?: VaultRequestOptions,
	): Promise<VaultSsoConnection>;
	testSso(
		organizationId: string,
		connectionId: string,
		input: VaultMutationPreview,
		options?: VaultRequestOptions,
	): Promise<VaultSsoMutationPreview>;
	testSso(
		organizationId: string,
		connectionId: string,
		input: VaultMutationConfirmation,
		options?: VaultRequestOptions,
	): Promise<VaultSsoTestResult>;
	disableSso(
		organizationId: string,
		connectionId: string,
		input: VaultMutationPreview,
		options?: VaultRequestOptions,
	): Promise<VaultSsoMutationPreview>;
	disableSso(
		organizationId: string,
		connectionId: string,
		input: VaultMutationConfirmation,
		options?: VaultRequestOptions,
	): Promise<VaultConnectionDisableResult<VaultSsoConnection>>;
	replaceSsoSecret(
		organizationId: string,
		connectionId: string,
		input: VaultMutationPreview,
		options?: VaultRequestOptions,
	): Promise<VaultSsoMutationPreview>;
	replaceSsoSecret(
		organizationId: string,
		connectionId: string,
		input: Readonly<{ newClientSecret: string; operationId: string }> & VaultMutationConfirmation,
		options?: VaultRequestOptions,
	): Promise<VaultSsoConnection>;
	listScim(
		organizationId: string,
		options?: VaultRequestOptions,
	): Promise<readonly VaultScimConnection[]>;
	inspectScim(
		organizationId: string,
		connectionId: string,
		options?: VaultRequestOptions,
	): Promise<VaultScimConnection>;
	createScim(
		organizationId: string,
		input: Readonly<{ provider: string; endpoint?: string }> & VaultMutationPreview,
		options?: VaultRequestOptions,
	): Promise<VaultScimCreatePreview>;
	createScim(
		organizationId: string,
		input: Readonly<{ provider: string; endpoint?: string; operationId: string }> & VaultMutationConfirmation,
		options?: VaultRequestOptions,
	): Promise<VaultScimSecretMutation>;
	testScim(
		organizationId: string,
		connectionId: string,
		input: VaultMutationPreview,
		options?: VaultRequestOptions,
	): Promise<VaultScimMutationPreview>;
	testScim(
		organizationId: string,
		connectionId: string,
		input: VaultMutationConfirmation,
		options?: VaultRequestOptions,
	): Promise<VaultScimTestResult>;
	disableScim(
		organizationId: string,
		connectionId: string,
		input: VaultMutationPreview,
		options?: VaultRequestOptions,
	): Promise<VaultScimMutationPreview>;
	disableScim(
		organizationId: string,
		connectionId: string,
		input: VaultMutationConfirmation,
		options?: VaultRequestOptions,
	): Promise<VaultConnectionDisableResult<VaultScimConnection>>;
	rotateScim(
		organizationId: string,
		connectionId: string,
		input: VaultMutationPreview,
		options?: VaultRequestOptions,
	): Promise<VaultScimMutationPreview>;
	rotateScim(
		organizationId: string,
		connectionId: string,
		input: Readonly<{ operationId: string }> & VaultMutationConfirmation,
		options?: VaultRequestOptions,
	): Promise<VaultScimRotation>;
	getReadiness(
		organizationId: string,
		options?: VaultRequestOptions,
	): Promise<VaultReadiness>;
	listRoles(
		organizationId: string,
		options?: VaultRequestOptions,
	): Promise<readonly VaultAuthorizationRole[]>;
	getEffectiveAuthorization(
		organizationId: string,
		subject: VaultAuthorizationSubject,
		options?: VaultRequestOptions,
	): Promise<VaultEffectiveAuthorization>;
	listAssignments(
		organizationId: string,
		subject?: VaultAuthorizationSubject,
		options?: VaultRequestOptions,
	): Promise<readonly VaultAuthorizationAssignment[]>;
	replaceAssignments(
		organizationId: string,
		input: Readonly<{
			subject: VaultAuthorizationSubject;
			roleIds: readonly string[];
			expectedRevision?: string;
		}> &
			VaultConfirmedMutation,
		options?: VaultRequestOptions,
	): Promise<
		| Readonly<{
				preview: true;
				assignment: Readonly<{
					organizationId: string;
					subject: VaultAuthorizationSubject;
					roleIds: readonly string[];
				}>;
				wouldChange: boolean;
				currentRevision: string;
		  }>
		| Readonly<{
				assignment: Readonly<{
					organizationId: string;
					subject: VaultAuthorizationSubject;
					roleIds: readonly string[];
				}>;
				changed: boolean;
				previousRevision: string;
				revision: string;
		  }>
	>;
	listServiceAccounts(
		organizationId: string,
		options?: VaultRequestOptions,
	): Promise<readonly VaultServiceAccount[]>;
	inspectServiceAccount(
		organizationId: string,
		serviceAccountId: string,
		options?: VaultRequestOptions,
	): Promise<
		Readonly<{
			serviceAccount: VaultServiceAccount;
			assignments: readonly VaultAuthorizationAssignment[];
		}>
	>;
	createServiceAccount(
		organizationId: string,
		input: Readonly<{
			name: string;
			roleIds: readonly string[];
			dryRun: true;
		}>,
		options?: VaultRequestOptions,
	): Promise<
		Readonly<{
			preview: true;
			serviceAccount: Readonly<{
				organizationId: string;
				name: string;
				status: "active";
			}>;
			roleIds: readonly string[];
		}>
	>;
	createServiceAccount(
		organizationId: string,
		input: Readonly<{
			name: string;
			roleIds: readonly string[];
			dryRun: false;
		}>,
		options?: VaultRequestOptions,
	): Promise<
		Readonly<{
			serviceAccount: VaultServiceAccount;
			previousRevision: string;
			revision: string;
		}>
	>;
	enableServiceAccount(
		organizationId: string,
		serviceAccountId: string,
		input: Readonly<{ dryRun: boolean }>,
		options?: VaultRequestOptions,
	): Promise<unknown>;
	disableServiceAccount(
		organizationId: string,
		serviceAccountId: string,
		input: VaultConfirmedMutation,
		options?: VaultRequestOptions,
	): Promise<unknown>;
	createCredential(
		organizationId: string,
		serviceAccountId: string,
		input: Readonly<{ expiresAt?: string; dryRun: true }>,
		options?: VaultRequestOptions,
	): Promise<unknown>;
	createCredential(
		organizationId: string,
		serviceAccountId: string,
		input: Readonly<{ expiresAt?: string; dryRun: false; operationId: string }>,
		options?: VaultRequestOptions,
	): Promise<VaultCredentialMutation>;
	rotateCredential(
		organizationId: string,
		serviceAccountId: string,
		credentialId: string,
		input: Readonly<{ expiresAt?: string; dryRun: true; confirm: false }>,
		options?: VaultRequestOptions,
	): Promise<unknown>;
	rotateCredential(
		organizationId: string,
		serviceAccountId: string,
		credentialId: string,
		input: Readonly<{ expiresAt?: string; dryRun: false; confirm: true; operationId: string }>,
		options?: VaultRequestOptions,
	): Promise<VaultCredentialMutation>;
	revokeCredential(
		organizationId: string,
		serviceAccountId: string,
		credentialId: string,
		input: VaultConfirmedMutation,
		options?: VaultRequestOptions,
	): Promise<unknown>;
}>;

function identifier(value: string, label: string): string {
	if (
		typeof value !== "string" ||
		value.length < 1 ||
		value.length > 1_024 ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		throw new TypeError(`${label} is invalid`);
	}
	return value;
}

function responseIdentifier(value: unknown, label: string): string {
	if (typeof value !== "string") {
		throw new TypeError(`Vault received an invalid ${label} response`);
	}
	return identifier(value, label);
}

function pathIdentifier(value: string, label: string): string {
	return encodeURIComponent(identifier(value, label));
}

function boundedText(value: unknown, label: string, maximum: number): string {
	if (
		typeof value !== "string" ||
		value.length < 1 ||
		value.length > maximum ||
		value.trim() !== value ||
		value.includes("\0")
	) {
		throw new TypeError(`${label} is invalid`);
	}
	return value;
}

function organizationName(value: unknown): string {
	if (
		typeof value !== "string" ||
		value.length < 1 ||
		value.length > 256 ||
		value.trim() !== value ||
		/[\u0000-\u001f\u007f]/.test(value)
	) {
		throw new TypeError("organization name is invalid");
	}
	return value;
}

function organizationSlug(value: unknown): string {
	if (
		typeof value !== "string" ||
		value.length < 1 ||
		value.length > 48 ||
		!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value)
	) {
		throw new TypeError("organization slug is invalid");
	}
	return value;
}

function operationId(value: unknown): string {
	if (
		typeof value !== "string" ||
		!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
	) {
		throw new TypeError("operationId must be a canonical UUID");
	}
	return value;
}

function confirmedMutation(input: Readonly<{ dryRun: boolean; confirm: boolean }>) {
	if (input.dryRun === true && input.confirm === false) {
		return Object.freeze({ dryRun: true as const, confirm: false as const });
	}
	if (input.dryRun === false && input.confirm === true) {
		return Object.freeze({ dryRun: false as const, confirm: true as const });
	}
	throw new TypeError("Vault mutation confirmation is invalid");
}

export type VaultClient = Readonly<{
	auth: VaultAuthClient;
	tenant: VaultTenantClient;
}>;

export function createVaultClient(config: VaultClientConfig = {}): VaultClient {
	const transport = createVaultTransport(config);
	const readSession = async (
		options?: VaultRequestOptions,
	): Promise<VaultSessionState | null> =>
		parseSessionState(await transport.auth<unknown>("/get-session", options));
	const authenticationResult = async (
		value: unknown,
		options?: VaultRequestOptions,
	): Promise<VaultAuthenticationResult> => {
		const parsed = parseAuthPost(value);
		if (parsed.kind === "two_factor") {
			return Object.freeze({
				kind: "two_factor_required",
				methods: parsed.methods,
			});
		}
		if (parsed.kind === "verification") {
			return Object.freeze({
				kind: "verification_required",
				user: parsed.user,
			});
		}
		const session = await readSession(options);
		if (!session) {
			throw new TypeError(
				"Vault could not confirm the authenticated browser session",
			);
		}
		return Object.freeze({ kind: "authenticated", session });
	};
	const auth: VaultAuthClient = Object.freeze({
		async getSession(options) {
			return readSession(options);
		},
		async signIn(input, options) {
			const value = await transport.auth<unknown>("/sign-in/email", {
				method: "POST",
				body: input,
				...options,
			});
			return authenticationResult(value, options);
		},
		async signUp(input, options) {
			const value = await transport.auth<unknown>("/sign-up/email", {
				method: "POST",
				body: input,
				...options,
			});
			return authenticationResult(value, options);
		},
		async sendTwoFactorOTP(options) {
			const value = await transport.auth<unknown>("/two-factor/send-otp", {
				method: "POST",
				body: {},
				...options,
			});
			parseStatus(value, "two-factor OTP");
		},
		async completeTwoFactor(input, options) {
			const path =
				input.method === "totp"
					? "/two-factor/verify-totp"
					: input.method === "otp"
						? "/two-factor/verify-otp"
						: "/two-factor/verify-backup-code";
			await transport.auth<unknown>(path, {
				method: "POST",
				body: {
					code: input.code,
					...(input.trustDevice !== undefined
						? { trustDevice: input.trustDevice }
						: {}),
				},
				...options,
			});
			const session = await readSession(options);
			if (!session) {
				throw new TypeError(
					"Vault could not confirm the two-factor browser session",
				);
			}
			return session;
		},
		signOut: (options) =>
			transport.auth("/sign-out", { method: "POST", ...options }),
		async requestPasswordReset(input, options) {
			const value = await transport.auth<unknown>("/request-password-reset", {
				method: "POST",
				body: input,
				...options,
			});
			const result = record(value, "password reset request");
			if (result.status !== true) {
				throw new TypeError(
					"Vault received an invalid password reset request response",
				);
			}
			return Object.freeze({ status: true });
		},
		async resetPassword(input, options) {
			const value = await transport.auth<unknown>("/reset-password", {
				method: "POST",
				body: input,
				...options,
			});
			parseStatus(value, "password reset");
			return Object.freeze({ status: true });
		},
		changePassword: (input, options) =>
			transport.auth("/change-password", {
				method: "POST",
				body: input,
				...options,
			}),
		async listSessions(options) {
			const value = await transport.auth<unknown>("/list-sessions", options);
			return parseList(value, ["sessions"], "session list", parseSession);
		},
		revokeOtherSessions: (options) =>
			transport.auth("/revoke-other-sessions", {
				method: "POST",
				...options,
			}),
		async listPasskeys(options) {
			const value = await transport.auth<unknown>("/passkey/list", options);
			return parseList(value, ["passkeys"], "passkey list", parsePasskey);
		},
		async beginPasskeyRegistration(input = {}, options) {
			const value = await transport.auth<unknown>(
				"/passkey/generate-registration-options",
				{
				method: "POST",
				body: input,
				...options,
				},
			);
			return parseRegistrationOptions(value);
		},
		async finishPasskeyRegistration(input, options) {
			const value = await transport.auth<unknown>(
				"/passkey/verify-registration",
				{
				method: "POST",
				body: input,
				...options,
				},
			);
			return parsePasskey(value);
		},
		async beginPasskeyAuthentication(options) {
			const value = await transport.auth<unknown>("/passkey/generate-authentication-options", { method: "POST", ...options });
			return parseAuthenticationOptions(value);
		},
		async finishPasskeyAuthentication(input, options) {
			await transport.auth<unknown>("/passkey/verify-authentication", { method: "POST", body: input, ...options });
			const session = await readSession(options);
			if (!session) throw new TypeError("Vault could not confirm the passkey browser session");
			return session;
		},
		async beginPasskeyDeletion(input, options) {
			const value = await transport.auth<unknown>(
				"/passkey/generate-deletion-options",
				{
					method: "POST",
					body: { id: identifier(input.id, "passkey id") },
					...options,
				},
			);
			return parseDeletionOptions(value);
		},
		async deletePasskey(input, options) {
			await transport.auth<unknown>("/passkey/delete", {
				method: "POST",
				body: input,
				...options,
			});
			const session = await readSession(options);
			if (!session) {
				throw new TypeError("Vault could not confirm the passkey deletion session");
			}
			return session;
		},
		async enableTwoFactor(input, options) {
			const value = await transport.auth<unknown>("/two-factor/enable", {
				method: "POST",
				body: input,
				...options,
			});
			const result = record(value, "two-factor enrollment");
			const session = await readSession(options);
			if (!session) {
				throw new TypeError("Vault could not confirm the two-factor enrollment session");
			}
			return Object.freeze({
				totpURI: responseIdentifier(result.totpURI, "totpURI"),
				backupCodes: parseList(
					result.backupCodes,
					[],
					"recovery code list",
					(item) => responseIdentifier(item, "recovery code"),
				),
				session,
			});
		},
		async verifyTwoFactor(input, options) {
			await transport.auth("/two-factor/verify-totp", {
				method: "POST",
				body: input,
				...options,
			});
			const session = await readSession(options);
			if (!session) {
				throw new TypeError(
					"Vault could not confirm the two-factor browser session",
				);
			}
			return session;
		},
		async disableTwoFactor(input, options) {
			await transport.auth("/two-factor/disable", {
				method: "POST",
				body: input,
				...options,
			});
			const session = await readSession(options);
			if (!session) {
				throw new TypeError(
					"Vault could not confirm the two-factor browser session",
				);
			}
			return session;
		},
		async generateBackupCodes(input, options) {
			const value = await transport.auth<unknown>(
				"/two-factor/generate-backup-codes",
				{
				method: "POST",
				body: input,
				...options,
				},
			);
			const result = record(value, "recovery code");
			const session = await readSession(options);
			if (!session) {
				throw new TypeError("Vault could not confirm the recovery code session");
			}
			return Object.freeze({
				backupCodes: parseList(
					result.backupCodes,
					[],
					"recovery code list",
					(item) => responseIdentifier(item, "recovery code"),
				),
				session,
			});
		},
		async createOrganization(input, options) {
			const value = await transport.auth<unknown>("/organization/create", {
				method: "POST",
				body: {
					name: organizationName(input.name),
					slug: organizationSlug(input.slug),
				},
				...options,
			});
			return parseOrganization(value);
		},
		async listOrganizations(options) {
			const value = await transport.auth<unknown>("/organization/list", options);
			return parseList(
				value,
				["organizations"],
				"organization list",
				parseOrganization,
			);
		},
		async setActiveOrganization(organizationId, options) {
			const value = await transport.auth<unknown>("/organization/set-active", {
				method: "POST",
				body: { organizationId: identifier(organizationId, "organizationId") },
				...options,
			});
			return value === null ? null : parseOrganization(value);
		},
		async listUserInvitations(options) {
			const value = await transport.auth<unknown>(
				"/organization/list-user-invitations",
				options,
			);
			return parseList(
				value,
				["invitations"],
				"invitation list",
				parseInvitation,
			);
		},
		async listOrganizationInvitations(organizationId, options) {
			const query = new URLSearchParams({
				organizationId: identifier(organizationId, "organizationId"),
			});
			const value = await transport.auth<unknown>(
				`/organization/list-invitations?${query}` as `/${string}`,
				options,
			);
			return parseList(
				value,
				["invitations"],
				"invitation list",
				parseInvitation,
			);
		},
		async inviteMember(input, options) {
			const value = await transport.auth<unknown>("/organization/invite-member", {
				method: "POST",
				body: input,
				...options,
			});
			return parseInvitation(value);
		},
		cancelInvitation: (invitationId, options) =>
			transport.auth("/organization/cancel-invitation", {
				method: "POST",
				body: { invitationId: identifier(invitationId, "invitationId") },
				...options,
			}),
		acceptInvitation: (invitationId, options) =>
			transport.auth("/organization/accept-invitation", {
				method: "POST",
				body: { invitationId: identifier(invitationId, "invitationId") },
				...options,
			}),
		rejectInvitation: (invitationId, options) =>
			transport.auth("/organization/reject-invitation", {
				method: "POST",
				body: { invitationId: identifier(invitationId, "invitationId") },
				...options,
			}),
	});
	const organizationPath = (organizationId: string) =>
		`/v1/organizations/${pathIdentifier(organizationId, "organizationId")}` as const;
	const accountPath = (organizationId: string, serviceAccountId: string) =>
		`${organizationPath(organizationId)}/service-accounts/${pathIdentifier(serviceAccountId, "serviceAccountId")}` as const;
	const credentialPath = (
		organizationId: string,
		serviceAccountId: string,
		credentialId: string,
	) =>
		`${accountPath(organizationId, serviceAccountId)}/credentials/${pathIdentifier(credentialId, "credentialId")}` as const;
	const credentialMutation = async (
		path: `/${string}`,
		body: unknown,
		options: VaultRequestOptions | undefined,
	): Promise<VaultCredentialMutation> => {
		const value = await transport.tenant<unknown>(path, {
			method: "POST",
			body,
			...options,
		});
		// This closed copy is returned directly and is never retained by the client.
		return parseCredentialMutation(value);
	};
	const tenantImplementation = {
		async listAudit(
			organizationId: string,
			input: Readonly<{ cursor?: string; limit?: number; action?: string }> = {},
			options?: VaultRequestOptions,
		) {
			const query = new URLSearchParams();
			if (input.cursor !== undefined) {
				query.set("cursor", boundedText(input.cursor, "audit cursor", 4_096));
			}
			if (input.limit !== undefined) {
				if (!Number.isInteger(input.limit) || input.limit < 1 || input.limit > 100) {
					throw new TypeError("audit limit is invalid");
				}
				query.set("limit", String(input.limit));
			}
			if (input.action !== undefined) {
				query.set("action", boundedText(input.action, "audit action", 256));
			}
			const suffix = query.size > 0 ? `?${query}` : "";
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/audit${suffix}` as `/${string}`,
				options,
			);
			return parseAuditList(value);
		},
		async listSso(organizationId: string, options?: VaultRequestOptions) {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/sso`,
				options,
			);
			return parseList(value, ["connections"], "SSO connection list", parseSSOConnection);
		},
		inspectSso: (
			organizationId: string,
			connectionId: string,
			options?: VaultRequestOptions,
		) =>
			transport
				.tenant<unknown>(
					`${organizationPath(organizationId)}/enterprise/sso/${pathIdentifier(connectionId, "connectionId")}`,
					options,
				)
				.then((value) => parseSSOConnection(record(value, "SSO inspection").connection)),
		createSso: async (
			organizationId: string,
			input: (VaultSsoCreatePreviewInput | VaultSsoCreateLiveInput),
			options?: VaultRequestOptions,
		) => {
			const confirmation = confirmedMutation(input);
			const base = {
				protocol: input.protocol,
				provider: boundedText(input.provider, "SSO provider", 128),
				issuer: boundedText(input.issuer, "SSO issuer", 2_048),
				domain: boundedText(input.domain, "SSO domain", 253),
				...(input.audience === undefined
					? {}
					: { audience: boundedText(input.audience, "SSO audience", 512) }),
				...confirmation,
			};
			const body = input.protocol === "oidc"
				? {
					...base,
					clientId: boundedText(input.clientId, "SSO client ID", 512),
					...(input.dryRun
						? {}
						: { clientSecret: boundedText(input.clientSecret, "SSO client secret", 16_384) }),
				}
				: {
					...base,
					samlEntryPoint: boundedText(input.samlEntryPoint, "SAML entry point", 2_048),
					...(input.dryRun
						? {}
						: { samlCertificate: boundedText(input.samlCertificate, "SAML certificate", 65_536) }),
				};
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/sso`,
				{ method: "POST", body, ...options },
			);
			return parseSsoCreate(value);
		},
		testSso: async (
			organizationId: string,
			connectionId: string,
			input: Readonly<{ dryRun: boolean; confirm: boolean }>,
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/sso/${pathIdentifier(connectionId, "connectionId")}/test`,
				{ method: "POST", body: confirmedMutation(input), ...options },
			);
			return input.dryRun ? parseSsoMutation(value) : parseSSOTest(value);
		},
		disableSso: async (
			organizationId: string,
			connectionId: string,
			input: Readonly<{ dryRun: boolean; confirm: boolean }>,
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/sso/${pathIdentifier(connectionId, "connectionId")}/disable`,
				{ method: "POST", body: confirmedMutation(input), ...options },
			);
			return parseSsoMutation(value);
		},
		replaceSsoSecret: async (
			organizationId: string,
			connectionId: string,
			input: (VaultMutationPreview | (Readonly<{ newClientSecret: string; operationId: string }> & VaultMutationConfirmation)),
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/sso/${pathIdentifier(connectionId, "connectionId")}/replace-secret`,
				{
					method: "POST",
					body: {
						...(input.dryRun
							? {}
							: {
								newClientSecret: boundedText(input.newClientSecret, "SSO client secret", 16_384),
								operationId: operationId(input.operationId),
							}),
						...confirmedMutation(input),
					},
					...options,
				},
			);
			return parseSsoMutation(value);
		},
		async listScim(organizationId: string, options?: VaultRequestOptions) {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/scim`,
				options,
			);
			return parseList(value, ["connections"], "SCIM connection list", parseScimConnection);
		},
		inspectScim: (
			organizationId: string,
			connectionId: string,
			options?: VaultRequestOptions,
		) =>
			transport
				.tenant<unknown>(
					`${organizationPath(organizationId)}/enterprise/scim/${pathIdentifier(connectionId, "connectionId")}`,
					options,
				)
				.then((value) => parseScimConnection(record(value, "SCIM inspection").connection)),
		createScim: async (
			organizationId: string,
			input: Readonly<{ provider: string; endpoint?: string; dryRun: boolean; confirm: boolean; operationId?: string }>,
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/scim`,
				{
					method: "POST",
					body: {
						provider: boundedText(input.provider, "SCIM provider", 128),
						...(input.endpoint === undefined ? {} : { endpoint: boundedText(input.endpoint, "SCIM endpoint", 2_048) }),
						...(input.dryRun ? {} : { operationId: operationId(input.operationId) }),
						...confirmedMutation(input),
					},
					...options,
				},
			);
			return parseScimMutation(value);
		},
		testScim: async (
			organizationId: string,
			connectionId: string,
			input: Readonly<{ dryRun: boolean; confirm: boolean }>,
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/scim/${pathIdentifier(connectionId, "connectionId")}/test`,
				{ method: "POST", body: confirmedMutation(input), ...options },
			);
			return input.dryRun ? parseScimMutation(value) : parseScimTest(value);
		},
		disableScim: async (
			organizationId: string,
			connectionId: string,
			input: Readonly<{ dryRun: boolean; confirm: boolean }>,
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/scim/${pathIdentifier(connectionId, "connectionId")}/disable`,
				{ method: "POST", body: confirmedMutation(input), ...options },
			);
			return parseScimMutation(value);
		},
		rotateScim: async (
			organizationId: string,
			connectionId: string,
			input: VaultMutationPreview | (Readonly<{ operationId: string }> & VaultMutationConfirmation),
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/enterprise/scim/${pathIdentifier(connectionId, "connectionId")}/rotate`,
				{
					method: "POST",
					body: {
						...confirmedMutation(input),
						...(input.dryRun ? {} : { operationId: operationId(input.operationId) }),
					},
					...options,
				},
			);
			return input.dryRun ? parseScimMutation(value) : parseScimRotation(value);
		},
		getReadiness: async (organizationId: string, options?: VaultRequestOptions) =>
			parseEnterpriseReadiness(
				await transport.tenant<unknown>(
					`${organizationPath(organizationId)}/enterprise/readiness`,
					options,
				),
			),
		async listRoles(
			organizationId: string,
			options?: VaultRequestOptions,
		) {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/authorization/roles`,
				options,
			);
			return parseList(value, ["roles"], "authorization role list", parseRole);
		},
		getEffectiveAuthorization: (
			organizationId: string,
			subject: VaultAuthorizationSubject,
			options?: VaultRequestOptions,
		) =>
			transport
				.tenant<unknown>(
					`${organizationPath(organizationId)}/authorization/effective`,
					{ method: "POST", body: { subject }, ...options },
				)
				.then(parseEffectiveAuthorization),
		async listAssignments(
			organizationId: string,
			subject?: VaultAuthorizationSubject,
			options?: VaultRequestOptions,
		) {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/authorization/assignments/list`,
				{
					method: "POST",
					body: subject ? { subject } : {},
					...options,
				},
			);
			return parseList(
				value,
				["assignments"],
				"authorization assignment list",
				parseAssignment,
			);
		},
		replaceAssignments: async (
			organizationId: string,
			input: Readonly<{
				subject: VaultAuthorizationSubject;
				roleIds: readonly string[];
				expectedRevision?: string;
				dryRun: boolean;
				confirm: boolean;
			}>,
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/authorization/assignments/replace`,
				{ method: "POST", body: input, ...options },
			);
			const result = record(value, "authorization replacement");
			const assignment = record(
				result.assignment,
				"authorization replacement",
			);
			const parsedAssignment = Object.freeze({
				organizationId: responseIdentifier(
					assignment.organizationId,
					"organizationId",
				),
				subject: (() => {
					const parsed = record(
						assignment.subject,
						"authorization replacement",
					);
					if (
						parsed.kind !== "principal" &&
						parsed.kind !== "service_account"
					) {
						throw new TypeError(
							"Vault received an invalid authorization replacement response",
						);
					}
					return Object.freeze({
						kind: parsed.kind,
						id: responseIdentifier(parsed.id, "subject.id"),
					});
				})(),
				roleIds: parseList(
					assignment.roleIds,
					[],
					"authorization role ID list",
					(item) => responseIdentifier(item, "roleId"),
				),
			});
			if (result.preview === true) {
				if (
					typeof result.wouldChange !== "boolean" ||
					typeof result.currentRevision !== "string"
				) {
					throw new TypeError(
						"Vault received an invalid authorization replacement response",
					);
				}
				return Object.freeze({
					preview: true as const,
					assignment: parsedAssignment,
					wouldChange: result.wouldChange,
					currentRevision: result.currentRevision,
				});
			}
			if (
				typeof result.changed !== "boolean" ||
				typeof result.previousRevision !== "string" ||
				typeof result.revision !== "string"
			) {
				throw new TypeError(
					"Vault received an invalid authorization replacement response",
				);
			}
			return Object.freeze({
				assignment: parsedAssignment,
				changed: result.changed,
				previousRevision: result.previousRevision,
				revision: result.revision,
			});
		},
		async listServiceAccounts(
			organizationId: string,
			options?: VaultRequestOptions,
		) {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/service-accounts`,
				options,
			);
			return parseList(
				value,
				["serviceAccounts"],
				"service account list",
				parseServiceAccount,
			);
		},
		inspectServiceAccount: (
			organizationId: string,
			serviceAccountId: string,
			options?: VaultRequestOptions,
		) =>
			transport
				.tenant<unknown>(
					accountPath(organizationId, serviceAccountId),
					options,
				)
				.then((value) => {
					const input = record(value, "service account inspection");
					return Object.freeze({
						serviceAccount: parseServiceAccount(input.serviceAccount),
						assignments: parseList(
							input.assignments,
							[],
							"authorization assignment list",
							parseAssignment,
						),
					});
				}),
		createServiceAccount: async (
			organizationId: string,
			input: Readonly<{
				name: string;
				roleIds: readonly string[];
				dryRun: boolean;
			}>,
			options?: VaultRequestOptions,
		) => {
			const value = await transport.tenant<unknown>(
				`${organizationPath(organizationId)}/service-accounts`,
				{ method: "POST", body: input, ...options },
			);
			const result = record(value, "service account creation");
			if (input.dryRun) {
				const preview = record(
					result.serviceAccount,
					"service account creation",
				);
				if (preview.status !== "active") {
					throw new TypeError(
						"Vault received an invalid service account creation response",
					);
				}
				return Object.freeze({
					preview: true as const,
					serviceAccount: Object.freeze({
						organizationId: responseIdentifier(
							preview.organizationId,
							"organizationId",
						),
						name: responseIdentifier(preview.name, "name"),
						status: "active" as const,
					}),
					roleIds: parseList(
						result.roleIds,
						[],
						"authorization role ID list",
						(item) => responseIdentifier(item, "roleId"),
					),
				});
			}
			if (
				typeof result.previousRevision !== "string" ||
				typeof result.revision !== "string"
			) {
				throw new TypeError(
					"Vault received an invalid service account creation response",
				);
			}
			return Object.freeze({
				serviceAccount: parseServiceAccount(result.serviceAccount),
				previousRevision: result.previousRevision,
				revision: result.revision,
			});
		},
		enableServiceAccount: (
			organizationId: string,
			serviceAccountId: string,
			input: Readonly<{ dryRun: boolean }>,
			options?: VaultRequestOptions,
		) =>
			transport.tenant(`${accountPath(organizationId, serviceAccountId)}/enable`, {
				method: "POST",
				body: input,
				...options,
			}),
		disableServiceAccount: (
			organizationId: string,
			serviceAccountId: string,
			input: Readonly<{ dryRun: boolean; confirm: boolean }>,
			options?: VaultRequestOptions,
		) =>
			transport.tenant(
				`${accountPath(organizationId, serviceAccountId)}/disable`,
				{ method: "POST", body: input, ...options },
			),
		createCredential: async (
			organizationId: string,
			serviceAccountId: string,
			input: Readonly<{ expiresAt?: string; dryRun: boolean; operationId?: string }>,
			options?: VaultRequestOptions,
		): Promise<unknown> => {
			const path =
				`${accountPath(organizationId, serviceAccountId)}/credentials` as const;
			if (input.dryRun) {
				return transport.tenant(path, {
					method: "POST",
					body: {
						...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt }),
						dryRun: true,
					},
					...options,
				});
			}
			return credentialMutation(path, { ...input, operationId: operationId(input.operationId) }, options);
		},
		rotateCredential: async (
			organizationId: string,
			serviceAccountId: string,
			credentialId: string,
			input: Readonly<{
				expiresAt?: string;
				dryRun: boolean;
				confirm: boolean;
				operationId?: string;
			}>,
			options?: VaultRequestOptions,
		): Promise<unknown> => {
			const path =
				`${credentialPath(organizationId, serviceAccountId, credentialId)}/rotate` as const;
			if (input.dryRun) {
				return transport.tenant(path, {
					method: "POST",
					body: {
						...(input.expiresAt === undefined ? {} : { expiresAt: input.expiresAt }),
						dryRun: true,
						confirm: false,
					},
					...options,
				});
			}
			return credentialMutation(path, { ...input, operationId: operationId(input.operationId) }, options);
		},
		revokeCredential: (
			organizationId: string,
			serviceAccountId: string,
			credentialId: string,
			input: Readonly<{ dryRun: boolean; confirm: boolean }>,
			options?: VaultRequestOptions,
		) =>
			transport.tenant(
				`${credentialPath(organizationId, serviceAccountId, credentialId)}/revoke`,
				{ method: "POST", body: input, ...options },
			),
	};
	const tenant = Object.freeze(tenantImplementation) as VaultTenantClient;
	return Object.freeze({ auth, tenant });
}
