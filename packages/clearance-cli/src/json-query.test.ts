import { describe, expect, it } from "vitest";
import { evaluateJsonQuery } from "./json-query.js";

describe("built-in JSON query", () => {
	it("returns JSON null for absent object fields and array indexes", () => {
		expect(evaluateJsonQuery({ items: ["first"] }, ".missing")).toBeNull();
		expect(evaluateJsonQuery({ items: ["first"] }, ".items[2]")).toBeNull();
	});
});
