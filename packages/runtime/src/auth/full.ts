import type { ClearanceOptions } from "@clearance/core";
import { init } from "../context/init";
import type { Auth } from "../types";
import { createClearance } from "./base";

/**
 * Clearance initializer for full mode (with Kysely)
 *
 * @example
 * ```ts
 * import { clearance } from "@clearance/runtime";
 *
 * const auth = clearance({
 * 	database: new PostgresDialect({ connection: process.env.DATABASE_URL }),
 * });
 * ```
 *
 * For minimal mode (without Kysely), import from `clearance/minimal` instead
 * @example
 * ```ts
 * import { clearance } from "@clearance/runtime/minimal";
 *
 * const auth = clearance({
 *	  database: drizzleAdapter(db, { provider: "pg" }),
 * });
 */
export const clearance = <Options extends ClearanceOptions>(
	options: Options & {},
): Auth<Options> => {
	return createClearance(options, init);
};
