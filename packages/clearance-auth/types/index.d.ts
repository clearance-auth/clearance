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
export type ClearanceRuntimeOrganization = {
    id: string;
    name: string;
    slug: string;
    logo?: string | null;
    metadata?: Record<string, unknown> | null;
    createdAt: Date;
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
export interface ClearanceProductAuthRuntime extends ClearanceAuthRuntime {
    readonly api: ClearanceAuthRuntime["api"] & {
        signUpEmail(input: {
            body: {
                email: string;
                password: string;
                name: string;
            };
        }): Promise<{
            user: ClearanceRuntimeUser;
        }>;
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
}
export interface ClearanceQueryResult<Row extends Record<string, unknown> = Record<string, unknown>> {
    rows: Row[];
    rowCount: number | null;
}
export interface ClearanceDatabasePool {
    query<Row extends Record<string, unknown> = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<ClearanceQueryResult<Row>>;
    end(): Promise<void>;
}
export type ClearanceAuthBundle = {
    auth: ClearanceProductAuthRuntime;
    pool: ClearanceDatabasePool;
    db: unknown;
    plugins: {
        organization: true;
        sso: boolean;
        scim: boolean;
    };
    rateLimitEnabled: boolean;
    planMigrations(): Promise<ClearanceRuntimeMigrationPlan>;
    migrate(): Promise<ClearanceRuntimeMigrationResult>;
    destroy(): Promise<void>;
};
export interface ClearancePlugin {
    id: string;
    readonly endpoints?: Readonly<Record<string, unknown>>;
    readonly options?: unknown;
}
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
    runMigrations(): Promise<void>;
    compileMigrations(): Promise<string>;
};
export declare const CLEARANCE_AUTH_VERSION: string;
export declare const RUNTIME_BASELINE: Readonly<{
    package: "@clearance/runtime";
    version: "1.6.23";
}>;
export declare const DEFAULT_TELEMETRY_ENDPOINT: string | undefined;
export declare function encryptRuntimeCredential(plaintext: string, secret: string): Promise<string>;
export declare function decryptRuntimeCredential(ciphertext: string, secret: string): Promise<string>;
export declare function socialProvidersFromEnvironment(env?: Record<string, string | undefined>): Record<string, SocialProviderConfig>;
export declare function createClearanceAuth(options: CreateClearanceAuthOptions): ClearanceAuthBundle;
export declare function withClearanceDefaults<T extends Record<string, unknown>>(options: T): T & {
    telemetry: {
        enabled: false;
    };
};
export declare function clearance<Options extends Record<string, unknown>>(options: Options): ClearanceAuthRuntime;
export declare function organization(options?: Record<string, unknown>): ClearancePlugin;
export declare function sso(options?: Record<string, unknown>): ClearancePlugin;
export declare function scim(options?: Record<string, unknown>): ClearancePlugin;
export declare function getMigrations(options: Record<string, unknown>): Promise<ClearanceMigrationSet>;
export { FORBIDDEN_DEFAULT_SECRETS, MINIMUM_SECRET_LENGTH, isForbiddenDefaultSecret, } from "./secret-policy.js";
export { fromNodeHeaders, toNodeHandler } from "./node.js";
