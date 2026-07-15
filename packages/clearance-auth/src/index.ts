/** @clearance/auth — Clearance product entry for the authentication runtime. */
export { clearance } from "@clearance/runtime";
export { organization } from "@clearance/runtime/plugins";
export { getMigrations } from "@clearance/runtime/db/migration";
export { sso } from "@clearance/sso";
export { scim } from "@clearance/scim";

export {
	createClearanceAuth,
	CLEARANCE_AUTH_VERSION,
	RUNTIME_BASELINE,
	encryptRuntimeCredential,
	decryptRuntimeCredential,
	socialProvidersFromEnvironment,
	type CreateClearanceAuthOptions,
	type ClearanceAuthBundle,
	type ClearanceRuntimeMigrationPlan,
	type ClearanceRuntimeMigrationResult,
	type ClearanceRuntimeUser,
} from "./create-auth.js";
export {
	FORBIDDEN_DEFAULT_SECRETS,
	MINIMUM_SECRET_LENGTH,
	isForbiddenDefaultSecret,
} from "./secret-policy.js";

export { toNodeHandler, fromNodeHeaders } from "@clearance/runtime/node";

/** Clearance product defaults layered on auth options. */
export function withClearanceDefaults<T extends Record<string, unknown>>(
	options: T,
): T & { telemetry: { enabled: false } } {
	return {
		...options,
		telemetry: { enabled: false },
	};
}

export const DEFAULT_TELEMETRY_ENDPOINT: string | undefined = undefined;
