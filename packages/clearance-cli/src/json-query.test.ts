import { describe, expect, it } from "vitest";
import { evaluateJsonQuery, validateJsonQuery } from "./json-query.js";

describe("built-in JSON query", () => {
	it("returns JSON null for absent object fields and array indexes", () => {
		expect(evaluateJsonQuery({ items: ["first"] }, ".missing")).toBeNull();
		expect(evaluateJsonQuery({ items: ["first"] }, ".items[2]")).toBeNull();
	});

	it("validates syntax independently and makes valid selectors total", () => {
		expect(validateJsonQuery(".data.items[0].id")).toEqual(["data", "items", "[0]", "id"]);
		expect(() => validateJsonQuery(".data[")).toThrow("Unsupported --jq expression");
		expect(evaluateJsonQuery({ data: null }, ".data.items[0].id")).toBeNull();
		expect(evaluateJsonQuery({ data: null }, ".data.items[]")).toEqual([]);
	});
});
