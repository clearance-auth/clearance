import { describe, expect, it } from "vitest";
import { POLICY_CONFIG_OPERATION_SCHEMAS } from "./policy-config.js";

describe("policy config schemas", () => {
	it("rejects own prototype-sensitive config keys before record parsing", () => {
		for (const key of ["__proto__", "constructor", "prototype"]) {
			const config = Object.create(null) as Record<string, string>;
			Object.defineProperty(config, key, { enumerable: true, value: "unsafe" });
			expect(POLICY_CONFIG_OPERATION_SCHEMAS["config.validate"].input.safeParse({ config }).success)
				.toBe(false);
			expect(POLICY_CONFIG_OPERATION_SCHEMAS["config.diff"].input.safeParse({ config }).success)
				.toBe(false);
		}

		expect(POLICY_CONFIG_OPERATION_SCHEMAS["config.validate"].input.safeParse({
			config: { region: "ap-southeast-1" },
		}).success).toBe(true);
		const nullPrototypeConfig = Object.assign(Object.create(null), { region: "ap-southeast-1" });
		expect(POLICY_CONFIG_OPERATION_SCHEMAS["config.diff"].input.safeParse({
			config: nullPrototypeConfig,
		}).success).toBe(true);
	});
});
