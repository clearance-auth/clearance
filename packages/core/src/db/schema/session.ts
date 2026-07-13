import * as z from "zod";
import type { ClearanceOptions, Prettify } from "../../types";
import type {
	InferDBFieldsFromOptions,
	InferDBFieldsFromPlugins,
} from "../type";
import { coreSchema } from "./shared";

export const sessionSchema = coreSchema.extend({
	userId: z.coerce.string(),
	expiresAt: z.date(),
	token: z.string(),
	ipAddress: z.string().nullish(),
	userAgent: z.string().nullish(),
});

export type BaseSession = z.infer<typeof sessionSchema>;

/**
 * Session schema type used by clearance, note that it's possible that session could have additional fields
 */
export type Session<
	DBOptions extends ClearanceOptions["session"] = ClearanceOptions["session"],
	Plugins extends ClearanceOptions["plugins"] = ClearanceOptions["plugins"],
> = Prettify<
	z.infer<typeof sessionSchema> &
		InferDBFieldsFromOptions<DBOptions> &
		InferDBFieldsFromPlugins<"session", Plugins>
>;
