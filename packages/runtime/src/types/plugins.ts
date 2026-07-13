import type {
	AuthContext,
	ClearanceOptions,
	ClearancePlugin,
} from "@clearance/core";

import type { ClearancePluginDBSchema } from "@clearance/core/db";
import type {
	ExtractPluginField,
	InferPluginFieldFromTuple,
	UnionToIntersection,
} from "./helper";

export type InferOptionSchema<S extends ClearancePluginDBSchema> =
	S extends Record<string, { fields: infer Fields }>
		? {
				[K in keyof S]?: {
					modelName?: string | undefined;
					fields?:
						| {
								[P in keyof Fields]?: string;
						  }
						| undefined;
				};
			}
		: never;

export type InferPluginErrorCodes<O extends ClearanceOptions> =
	O["plugins"] extends readonly [unknown, ...unknown[]]
		? InferPluginFieldFromTuple<O["plugins"], "$ERROR_CODES">
		: O["plugins"] extends Array<infer P>
			? UnionToIntersection<ExtractPluginField<P, "$ERROR_CODES">>
			: {};

export type InferPluginIDs<O extends ClearanceOptions> =
	O["plugins"] extends Array<infer P>
		? UnionToIntersection<P extends ClearancePlugin ? P["id"] : never>
		: never;

type ExtractInitContext<P extends ClearancePlugin> = P["init"] extends (
	...args: any[]
) => infer R
	? Awaited<R> extends { context?: infer C }
		? C extends Record<string, any>
			? Omit<C, keyof AuthContext>
			: {}
		: {}
	: {};

export type InferPluginContext<O extends ClearanceOptions> =
	O["plugins"] extends Array<infer P>
		? UnionToIntersection<
				P extends ClearancePlugin ? ExtractInitContext<P> : {}
			>
		: {};
