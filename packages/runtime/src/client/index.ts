import type {
	ClearanceClientPlugin,
	ClearanceOptions,
	ClearancePlugin,
} from "@clearance/core";
import { PACKAGE_VERSION } from "../version";

export * from "./broadcast-channel";
export * from "./equality";
export {
	type FocusListener,
	type FocusManager,
	kFocusManager,
} from "./focus-manager";
export {
	kOnlineManager,
	type OnlineListener,
	type OnlineManager,
} from "./online-manager";
export * from "./parser";
export * from "./query";
export * from "./session-refresh";
export * from "./types";
export * from "./vanilla";

export const InferPlugin = <T extends ClearancePlugin>() => {
	return {
		id: "infer-server-plugin",
		version: PACKAGE_VERSION,
		$InferServerPlugin: {} as T,
	} satisfies ClearanceClientPlugin;
};

export function InferAuth<O extends { options: ClearanceOptions }>() {
	return {} as O["options"];
}

//#region Necessary re-exports
export type * from "@clearance/core/db";
export type { DBPrimitive } from "@clearance/core/db";
export type * from "@better-fetch/fetch";
export type * from "nanostores";
export type * from "../plugins/access";
export type * from "../plugins/organization";
export type * from "../types/helper";
export type { UnionToIntersection } from "../types/helper";
export type * from "./path-to-object";
//#endregion
