import type { ClearanceOptions } from "@clearance/core";
import { initMinimal } from "../context/init-minimal";
import type { Auth } from "../types";
import { createClearance } from "./base";

export type { ClearanceOptions };

/**
 * Clearance initializer for minimal mode (without Kysely)
 */
export const clearance = <Options extends ClearanceOptions>(
	options: Options & {},
): Auth<Options> => {
	return createClearance(options, initMinimal);
};
