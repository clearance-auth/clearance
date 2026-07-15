export type ClearanceAuthClient = Readonly<Record<string, unknown>>;

export interface ClearanceClientPlugin {
	id: string;
	version?: string;
	pathMethods?: Record<string, "POST" | "GET">;
	$ERROR_CODES?: Record<string, { code: string; message: string }>;
}

export type ClearanceAuthClientOptions = {
	baseURL?: string;
	basePath?: string;
	disableDefaultFetchPlugins?: boolean;
	plugins?: ClearanceClientPlugin[];
};

export declare function createAuthClient<
	Options extends ClearanceAuthClientOptions = ClearanceAuthClientOptions,
>(options?: Options): ClearanceAuthClient;

export declare function organizationClient(
	options?: { teams?: { enabled: boolean } },
): ClearanceClientPlugin;
