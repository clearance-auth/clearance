import type { ClearanceOptions } from "@clearance/core";
import type {
	InferDBFieldsFromOptionsInput,
	InferDBFieldsFromPluginsInput,
} from "@clearance/core/db";
import type {
	ExtractPluginField,
	InferPluginFieldFromTuple,
	UnionToIntersection,
} from "./helper";

export type AdditionalUserFieldsInput<Options extends ClearanceOptions> =
	InferDBFieldsFromPluginsInput<"user", Options["plugins"]> &
		InferDBFieldsFromOptionsInput<Options["user"]>;

export type AdditionalSessionFieldsInput<Options extends ClearanceOptions> =
	InferDBFieldsFromPluginsInput<"session", Options["plugins"]> &
		InferDBFieldsFromOptionsInput<Options["session"]>;

export type InferPluginTypes<O extends ClearanceOptions> =
	O["plugins"] extends readonly [unknown, ...unknown[]]
		? InferPluginFieldFromTuple<O["plugins"], "$Infer">
		: O["plugins"] extends Array<infer P>
			? UnionToIntersection<ExtractPluginField<P, "$Infer">>
			: {};

export type {
	Account,
	RateLimit,
	Session,
	User,
	Verification,
} from "@clearance/core/db";
