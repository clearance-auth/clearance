export interface ClearanceAuthClient {
	[key: string]: unknown;
}

export function createAuthClient<
	Options extends Record<string, unknown> = Record<string, never>,
>(options?: Options): ClearanceAuthClient;

export function organizationClient(
	options?: Record<string, unknown>,
): unknown;
