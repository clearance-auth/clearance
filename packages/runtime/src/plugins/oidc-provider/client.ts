import type { ClearanceClientPlugin } from "@clearance/core";
import { PACKAGE_VERSION } from "../../version";
import type { oidcProvider } from ".";

/**
 * @deprecated Use `@clearance/oauth-provider` instead. This plugin will be removed in the next major version.
 * @see https://github.com/clearance-auth/clearance
 */
export const oidcClient = () => {
	return {
		id: "oidc-client",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof oidcProvider>,
	} satisfies ClearanceClientPlugin;
};

export type OidcClientPlugin = ReturnType<typeof oidcClient>;

export type * from "./types";
