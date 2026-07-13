import type { ClearanceClientPlugin } from "@clearance/core";
import { PACKAGE_VERSION } from "../../version";
import type { multiSession } from ".";
import { MULTI_SESSION_ERROR_CODES } from "./error-codes";

export * from "./error-codes";

export const multiSessionClient = () => {
	return {
		id: "multi-session",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof multiSession>,
		atomListeners: [
			{
				matcher(path) {
					return path === "/multi-session/set-active";
				},
				signal: "$sessionSignal",
			},
		],
		$ERROR_CODES: MULTI_SESSION_ERROR_CODES,
	} satisfies ClearanceClientPlugin;
};

export type { MultiSessionConfig } from "./index";
