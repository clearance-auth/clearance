import { describe, expect, it } from "vitest";
import { matchType } from "./get-migration";

describe("matchType", () => {
	it("accepts PostgreSQL int8 as a numeric column", () => {
		expect(matchType("int8", "number", "postgres")).toBe(true);
	});
});
