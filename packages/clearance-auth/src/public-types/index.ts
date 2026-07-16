export type SocialProviderConfig = {
	clientId: string;
	clientSecret: string;
	[key: string]: unknown;
};

export type ClearanceAuthenticationSecurityOptions = {
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

export type ClearanceProductAuthRuntime<
	Security extends ClearanceAuthenticationSecurityOptions | undefined =
		undefined,
> = Omit<ClearanceAuthRuntime, "api"> & {
	readonly api: ClearanceBaseProductApi &
		ClearanceAuthenticationSecurityApi<Security>;
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
> = {
	auth: ClearanceProductAuthRuntime<Security>;
	pool: ClearanceDatabasePool;
	db: unknown;
	plugins: {
		organization: true;
		sso: boolean;
		scim: boolean;
		twoFactor: boolean;
		breachedPassword: boolean;
		asymmetricAccessTokens: boolean;
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
>(options: CreateClearanceAuthOptions<Security>): ClearanceAuthBundle<Security>;
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
