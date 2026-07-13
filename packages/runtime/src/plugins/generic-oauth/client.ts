import type { ClearanceClientPlugin } from "@clearance/core";
import { PACKAGE_VERSION } from "../../version";
import type { genericOAuth } from ".";
import { GENERIC_OAUTH_ERROR_CODES } from "./error-codes";

export const genericOAuthClient = () => {
	return {
		id: "generic-oauth-client",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof genericOAuth>,
		$ERROR_CODES: GENERIC_OAUTH_ERROR_CODES,
	} satisfies ClearanceClientPlugin;
};

export * from "./error-codes";
export type {
	BaseOAuthProviderOptions,
	GenericOAuthConfig,
	GenericOAuthOptions,
} from "./index";
export type * from "./providers";
