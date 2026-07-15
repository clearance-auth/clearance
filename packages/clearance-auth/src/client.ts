import { createAuthClient as runtimeCreateAuthClient } from "@clearance/runtime/client";

export * from "@clearance/runtime/client";
export {
	jwtClient,
	organizationClient,
	twoFactorClient,
} from "@clearance/runtime/client/plugins";

export const createAuthClient =
	runtimeCreateAuthClient as typeof import("./public-types/client.js").createAuthClient;
