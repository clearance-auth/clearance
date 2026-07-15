import { describe, expect, it } from "vitest";
import {
	MINIMUM_SECRET_LENGTH,
	isForbiddenDefaultSecret,
} from "./secret-policy.js";

describe("secret policy", () => {
	it.each([
		null,
		undefined,
		"",
		" short ",
		"CLEARANCE-SECRET",
		"prefix-change-me-long-enough",
		"prefix-dev-secret-long-enough",
	])("rejects known weak value %s", (secret) => {
		expect(isForbiddenDefaultSecret(secret)).toBe(true);
	});

	it("accepts a strong random-looking value", () => {
		expect(MINIMUM_SECRET_LENGTH).toBe(16);
		expect(isForbiddenDefaultSecret("nF9vQ2mL8xT4sR7pK3wZ6cY1")).toBe(false);
	});
});
