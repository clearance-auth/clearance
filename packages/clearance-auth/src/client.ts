import { createAuthClient as runtimeCreateAuthClient } from "../../runtime/src/client/index.js";

export * from "../../runtime/src/client/index.js";
export {
	jwtClient,
	organizationClient,
	twoFactorClient,
} from "../../runtime/src/client/plugins/index.js";

export const createAuthClient =
	runtimeCreateAuthClient as typeof import("./public-types/client.js").createAuthClient;
