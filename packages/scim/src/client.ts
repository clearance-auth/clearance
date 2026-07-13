import type { ClearanceClientPlugin } from "@clearance/runtime/client";
import type { scim } from "./index";
import { PACKAGE_VERSION } from "./version";

export const scimClient = () => {
	return {
		id: "scim-client",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as ReturnType<typeof scim>,
	} satisfies ClearanceClientPlugin;
};
