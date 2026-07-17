import type { ClearancePlugin } from "@clearance/core";
import { mergeSchema } from "../../db/schema";
import { PACKAGE_VERSION } from "../../version";
import { PASSKEY_ERROR_CODES } from "./error-codes";
import {
	generatePasskeyAuthenticationOptions,
	generatePasskeyDeletionOptions,
	generatePasskeyRegistrationOptions,
	generatePasskeyRemediationAuthenticationOptions,
	generatePasskeyRemediationRegistrationOptions,
	listPasskeys,
	deletePasskey,
	updatePasskey,
	verifyPasskeyAuthentication,
	verifyPasskeyRemediationAuthentication,
	verifyPasskeyRemediationRegistration,
	verifyPasskeyRegistration,
} from "./routes";
import { schema } from "./schema";
import type { PasskeyOptions } from "./types";

export * from "./error-codes";

declare module "@clearance/core" {
	interface ClearancePluginRegistry<AuthOptions, Options> {
		passkey: {
			creator: typeof passkey;
		};
	}
}

/**
 * WebAuthn ceremony core for discoverable (usernameless) registration and
 * authentication backed by `@simplewebauthn/server`.
 */
export const passkey = <O extends PasskeyOptions>(options?: O) => {
	return {
		id: "passkey",
		version: PACKAGE_VERSION,
		endpoints: {
			generatePasskeyRegistrationOptions:
				generatePasskeyRegistrationOptions(options),
			verifyPasskeyRegistration: verifyPasskeyRegistration(options),
			generatePasskeyRemediationRegistrationOptions:
				generatePasskeyRemediationRegistrationOptions(options),
			generatePasskeyRemediationAuthenticationOptions:
				generatePasskeyRemediationAuthenticationOptions(options),
			verifyPasskeyRemediationRegistration:
				verifyPasskeyRemediationRegistration(options),
			verifyPasskeyRemediationAuthentication:
				verifyPasskeyRemediationAuthentication(options),
			generatePasskeyAuthenticationOptions:
				generatePasskeyAuthenticationOptions(options),
			verifyPasskeyAuthentication: verifyPasskeyAuthentication(options),
			generatePasskeyDeletionOptions:
				generatePasskeyDeletionOptions(options),
			deletePasskey: deletePasskey(options),
			listPasskeys,
			updatePasskey,
		},
		schema: mergeSchema(schema, options?.schema),
		rateLimit: [
			{
				pathMatcher: (path: string) => path.startsWith("/passkey/"),
				window: options?.rateLimit?.window ?? 60,
				max: options?.rateLimit?.max ?? 10,
			},
		],
		$ERROR_CODES: PASSKEY_ERROR_CODES,
		options,
	} satisfies ClearancePlugin;
};

export type {
	Passkey,
	PasskeyDeletionProof,
	PasskeyOptions,
	PublicPasskey,
} from "./types";
