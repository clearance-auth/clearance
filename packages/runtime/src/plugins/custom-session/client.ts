import type { Auth } from "@clearance/runtime";
import { InferServerPlugin } from "../../client/plugins";
import type { ClearanceOptions } from "../../types";

export const customSessionClient = <
	A extends
		| Auth
		| {
				options: ClearanceOptions;
		  },
>() => {
	return InferServerPlugin<A, "custom-session">();
};
