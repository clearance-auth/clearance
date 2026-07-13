import type { User } from "@clearance/runtime/types";
import { expect } from "vitest";
import { createTestSuite } from "../create-test-suite";
import { getNormalTestSuiteTests } from "./basic";

export const numberIdTestSuite = createTestSuite(
	"number-id",
	{
		defaultClearanceOptions: {
			advanced: {
				database: {
					generateId: "serial",
				},
			},
		},
		alwaysMigrate: true,
		prefixTests: "number-id",
	},
	(helpers) => {
		const { "create - should use generateId if provided": _, ...normalTests } =
			getNormalTestSuiteTests({ ...helpers });

		return {
			"init - tests": async () => {
				const opts = helpers.getClearanceOptions();
				expect(opts.advanced?.database?.generateId === "serial").toBe(true);
			},
			"create - should return a number id": async () => {
				const user = await helpers.generate("user");
				const res = await helpers.adapter.create<User>({
					model: "user",
					data: user,
					forceAllowId: true,
				});
				expect(res).toHaveProperty("id");
				expect(typeof res.id).toBe("string");
				expect(Number(res.id)).toBeGreaterThan(0);
			},
			...normalTests,
		};
	},
);
