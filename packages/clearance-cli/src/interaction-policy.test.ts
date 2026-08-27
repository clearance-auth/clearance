import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { canInteract, interactionEligibility } from "./interaction-policy.js";

function terminal(): PassThrough & { isTTY: boolean } {
	const stream = new PassThrough() as PassThrough & { isTTY: boolean };
	stream.isTTY = true;
	return stream;
}

function eligibleInput() {
	return { stdin: terminal(), stdout: terminal(), stderr: terminal(), env: {} };
}

describe("interaction eligibility", () => {
	it("requires all three standard streams to be TTYs", () => {
		for (const stream of ["stdin", "stdout", "stderr"] as const) {
			const input = eligibleInput();
			input[stream].isTTY = false;
			expect(interactionEligibility(input)).toEqual({ eligible: false, reason: `${stream}-not-tty` });
		}
	});

	it("rejects automation and machine output modes", () => {
		expect(canInteract({ ...eligibleInput(), env: { CLEARANCE_NONINTERACTIVE: "1" } })).toBe(false);
		expect(canInteract({ ...eligibleInput(), env: { CI: "true" } })).toBe(false);
		expect(canInteract({ ...eligibleInput(), noInput: true })).toBe(false);
		expect(canInteract({ ...eligibleInput(), json: true })).toBe(false);
		expect(canInteract({ ...eligibleInput(), machineOutput: true })).toBe(false);
	});

	it("allows human interaction only when all gates are clear", () => {
		expect(interactionEligibility(eligibleInput())).toEqual({ eligible: true });
	});
});
