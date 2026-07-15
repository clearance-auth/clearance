export type ClearanceClientError = {
	code?: string;
	message?: string;
	status: number;
	statusText: string;
	[key: string]: unknown;
};

export type ClearanceClientResponse<Data> =
	{ data: Data; error: null } | { data: null; error: ClearanceClientError };

export type ClearanceClientFetchOptions = {
	headers?: HeadersInit;
	signal?: AbortSignal | null;
	[key: string]: unknown;
};

export type ClearanceTwoFactorClientUser = {
	id: string;
	email: string;
	name: string;
	emailVerified: boolean;
	image?: string | null;
	createdAt: Date;
	updatedAt: Date;
	twoFactorEnabled: boolean;
};

export type ClearanceTwoFactorEnrollment = {
	totpURI: string;
	backupCodes: string[];
};

export type ClearanceTwoFactorVerification = {
	token?: string;
	user: ClearanceTwoFactorClientUser;
};

export type ClearanceJsonWebKey = {
	kid: string;
	kty: string;
	alg: string;
	use?: string;
	crv?: string;
	x?: string;
	y?: string;
	n?: string;
	e?: string;
	[key: string]: unknown;
};

export type ClearanceJsonWebKeySet = {
	keys: ClearanceJsonWebKey[];
};

export interface ClearanceTwoFactorClientApi {
	readonly twoFactor: {
		enable(input: {
			password: string;
			issuer?: string;
			currentCode?: string;
			fetchOptions?: ClearanceClientFetchOptions;
		}): Promise<ClearanceClientResponse<ClearanceTwoFactorEnrollment>>;
		getTotpUri(input: {
			password: string;
			fetchOptions?: ClearanceClientFetchOptions;
		}): Promise<ClearanceClientResponse<{ totpURI: string }>>;
		verifyTotp(input: {
			code: string;
			trustDevice?: boolean;
			fetchOptions?: ClearanceClientFetchOptions;
		}): Promise<ClearanceClientResponse<ClearanceTwoFactorVerification>>;
		disable(
			input:
				| {
						password: string;
						currentCode: string;
						recoveryCode?: never;
						fetchOptions?: ClearanceClientFetchOptions;
				  }
				| {
						password: string;
						currentCode?: never;
						recoveryCode: string;
						fetchOptions?: ClearanceClientFetchOptions;
				  },
		): Promise<ClearanceClientResponse<{ status: true }>>;
		generateBackupCodes(
			input:
				| {
						password: string;
						currentCode: string;
						recoveryCode?: never;
						fetchOptions?: ClearanceClientFetchOptions;
				  }
				| {
						password: string;
						currentCode?: never;
						recoveryCode: string;
						fetchOptions?: ClearanceClientFetchOptions;
				  },
		): Promise<
			ClearanceClientResponse<{ status: true; backupCodes: string[] }>
		>;
		verifyBackupCode(input: {
			code: string;
			disableSession?: boolean;
			trustDevice?: boolean;
			fetchOptions?: ClearanceClientFetchOptions;
		}): Promise<ClearanceClientResponse<ClearanceTwoFactorVerification>>;
	};
}

export interface ClearanceJwtClientApi {
	token(input?: {
		fetchOptions?: ClearanceClientFetchOptions;
	}): Promise<ClearanceClientResponse<{ token: string }>>;
	jwks(
		fetchOptions?: ClearanceClientFetchOptions,
	): Promise<ClearanceClientResponse<ClearanceJsonWebKeySet>>;
}

export type ClearanceAuthClient = Readonly<Record<string, unknown>> &
	ClearanceTwoFactorClientApi &
	ClearanceJwtClientApi;

export type ClearanceBaseAuthClient = Readonly<Record<string, unknown>>;

export interface ClearanceClientPlugin {
	id: string;
	version?: string;
	pathMethods?: Record<string, "POST" | "GET">;
	$ERROR_CODES?: Record<string, { code: string; message: string }>;
}

export interface ClearanceTwoFactorClientPlugin extends ClearanceClientPlugin {
	readonly id: "two-factor";
	readonly $clearanceProductApi?: "two-factor";
}

export interface ClearanceJwtClientPlugin extends ClearanceClientPlugin {
	readonly id: "clearance-client";
	readonly $clearanceProductApi?: "jwt";
}

export type ClearanceAuthClientOptions = {
	baseURL?: string;
	basePath?: string;
	disableDefaultFetchPlugins?: boolean;
	fetchOptions?: ClearanceClientFetchOptions;
	plugins?: ClearanceClientPlugin[];
};

type ClearancePluginUnion<Options> = Options extends {
	plugins: Array<infer Plugin>;
}
	? Plugin
	: never;

type ClearanceAuthClientFor<Options> =
	Extract<
		ClearancePluginUnion<Options>,
		ClearanceTwoFactorClientPlugin
	> extends never
		? Extract<
				ClearancePluginUnion<Options>,
				ClearanceJwtClientPlugin
			> extends never
			? ClearanceBaseAuthClient
			: ClearanceBaseAuthClient & ClearanceJwtClientApi
		: Extract<
					ClearancePluginUnion<Options>,
					ClearanceJwtClientPlugin
			  > extends never
			? ClearanceBaseAuthClient & ClearanceTwoFactorClientApi
			: ClearanceAuthClient;

export declare function createAuthClient<
	const Plugins extends ClearanceClientPlugin[],
>(
	options: Omit<ClearanceAuthClientOptions, "plugins"> & { plugins: Plugins },
): ClearanceAuthClientFor<{ plugins: Plugins }>;
export declare function createAuthClient<
	Options extends ClearanceAuthClientOptions = ClearanceAuthClientOptions,
>(options?: Options): ClearanceBaseAuthClient;

export declare function organizationClient(options?: {
	teams?: { enabled: boolean };
}): ClearanceClientPlugin;

export declare function twoFactorClient(options?: {
	twoFactorPage?: string;
	onTwoFactorRedirect?: (context: {
		twoFactorMethods?: string[];
	}) => void | Promise<void>;
}): ClearanceTwoFactorClientPlugin;

export declare function jwtClient(options?: {
	jwks?: { jwksPath?: string };
}): ClearanceJwtClientPlugin;
