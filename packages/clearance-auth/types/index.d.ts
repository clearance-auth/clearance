export type SocialProviderConfig = {
	clientId: string;
	clientSecret: string;
	[key: string]: unknown;
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

export type CreateClearanceAuthOptions = {
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
};

export type ClearanceRuntimeMigrationPlan = {
	pendingTables: number;
	pendingFields: number;
	compileSql: () => Promise<string>;
	apply: () => Promise<void>;
};

export type ClearanceRuntimeMigrationResult = {
	appliedTables: number;
	appliedFields: number;
};

export interface ClearanceAuthRuntime {
	handler(request: Request): Promise<Response>;
	api: Record<string, (...args: any[]) => Promise<any>>;
	[key: string]: unknown;
}

export interface ClearanceQueryResult<Row extends Record<string, unknown> = any> {
	rows: Row[];
	rowCount: number | null;
}

export interface ClearanceDatabasePool {
	query<Row extends Record<string, unknown> = any>(
		text: string,
		values?: readonly unknown[],
	): Promise<ClearanceQueryResult<Row>>;
	end(): Promise<void>;
}

export type ClearanceAuthBundle = {
	auth: ClearanceAuthRuntime;
	pool: ClearanceDatabasePool;
	db: unknown;
	plugins: { organization: true; sso: boolean; scim: boolean };
	rateLimitEnabled: boolean;
	planMigrations(): Promise<ClearanceRuntimeMigrationPlan>;
	migrate(): Promise<ClearanceRuntimeMigrationResult>;
	destroy(): Promise<void>;
};

export const CLEARANCE_AUTH_VERSION: string;
export const RUNTIME_BASELINE: Readonly<{
	package: "@clearance/runtime";
	version: "1.6.23";
}>;
export const DEFAULT_TELEMETRY_ENDPOINT: undefined;

export function isForbiddenDefaultSecret(secret: string): boolean;
export function encryptRuntimeCredential(
	plaintext: string,
	secret: string,
): Promise<string>;
export function decryptRuntimeCredential(
	ciphertext: string,
	secret: string,
): Promise<string>;
export function socialProvidersFromEnvironment(
	env?: Record<string, string | undefined>,
): Record<string, SocialProviderConfig>;
export function createClearanceAuth(
	options: CreateClearanceAuthOptions,
): ClearanceAuthBundle;
export function withClearanceDefaults<T extends Record<string, unknown>>(
	options: T,
): T & { telemetry: { enabled: false } };

export function clearance<Options extends Record<string, unknown>>(
	options: Options,
): ClearanceAuthRuntime;
export function organization(options?: Record<string, unknown>): unknown;
export function sso(options?: Record<string, unknown>): unknown;
export function scim(options?: Record<string, unknown>): unknown;
export function getMigrations(options: unknown): Promise<unknown>;

export { fromNodeHeaders, toNodeHandler } from "./node.js";
