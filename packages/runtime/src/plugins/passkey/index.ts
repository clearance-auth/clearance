import type { ClearancePlugin } from "@clearance/core";
import { mergeSchema } from "../../db/schema";
import { PACKAGE_VERSION } from "../../version";
import { PASSKEY_ERROR_CODES } from "./error-codes";
import {
	generatePasskeyAuthenticationOptions,
	generatePasskeyRegistrationOptions,
	listPasskeys,
	updatePasskey,
	verifyPasskeyAuthentication,
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
 *
 * This slice intentionally does not include credential deletion/revocation,
 * last-factor recovery safety, or session-generation invalidation; those
 * ship in a separate destructive-lifecycle slice.
 */
export const passkey = <O extends PasskeyOptions>(options?: O) => {
	return {
		id: "passkey",
		version: PACKAGE_VERSION,
		endpoints: {
			generatePasskeyRegistrationOptions:
				generatePasskeyRegistrationOptions(options),
			verifyPasskeyRegistration: verifyPasskeyRegistration(options),
			generatePasskeyAuthenticationOptions:
				generatePasskeyAuthenticationOptions(options),
			verifyPasskeyAuthentication: verifyPasskeyAuthentication(options),
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

export type { Passkey, PasskeyOptions, PublicPasskey } from "./types";
