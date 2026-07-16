import type { ClearanceClientPlugin } from "@clearance/core";
import type { JSONWebKeySet } from "jose";
import { generateCredentialOperationKey } from "../../utils/operation-key";
import { PACKAGE_VERSION } from "../../version";
import type { jwt } from "./index";

type TokenRequest = {
	fetchOptions?: any;
};

function tokenRequestHeaders(headersInit?: HeadersInit): Headers {
	const headers = new Headers(headersInit);
	if (!headers.has("idempotency-key")) {
		headers.set("idempotency-key", generateCredentialOperationKey());
	}
	return headers;
}

interface JwtClientOptions {
	jwks?: {
		/**
		 * The path of the endpoint exposing the JWKS.
		 * Must match the server configuration.
		 *
		 * @default /jwks
		 */
		jwksPath?: string;
	};
}

export const jwtClient = (options?: JwtClientOptions) => {
	const jwksPath = options?.jwks?.jwksPath ?? "/jwks";

	return {
		id: "clearance-client",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof jwt>,
		pathMethods: {
			[jwksPath]: "GET",
			"/token": "POST",
		},
		getActions: ($fetch) => ({
			token: async (request?: TokenRequest) => {
				const fetchOptions = request?.fetchOptions;
				let useLegacyGet = false;
				const onResponse = fetchOptions?.onResponse;
				const rotated = await $fetch<{ token: string }>("/token", {
					...fetchOptions,
					method: "POST",
					headers: tokenRequestHeaders(fetchOptions?.headers),
					onResponse(context: any) {
						useLegacyGet =
							context.response.headers.get("clearance-jwt-token-mode") ===
							"legacy-get";
						return onResponse?.(context);
					},
				});
				if (!useLegacyGet) {
					return rotated;
				}
				return await $fetch<{ token: string }>("/token", {
					...fetchOptions,
					method: "GET",
				});
			},
			jwks: async (fetchOptions?: any) => {
				return await $fetch<JSONWebKeySet>(jwksPath, {
					method: "GET",
					...fetchOptions,
				});
			},
		}),
	} satisfies ClearanceClientPlugin;
};

export type * from "./types";
