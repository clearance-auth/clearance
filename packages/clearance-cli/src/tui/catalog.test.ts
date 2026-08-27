import { describe, expect, it } from "vitest";
import { MANAGEMENT_OPERATIONS } from "@clearance/management";
import { actionsFor, WORKFLOW_ACTIONS, WORKFLOW_AREAS } from "./catalog.js";

describe("workflow catalog", () => {
	it("covers every top-level workflow area", () => {
		for (const area of WORKFLOW_AREAS) expect(actionsFor(area).length).toBeGreaterThan(0);
	});

	it("maps every action to an inspectable Clearance command", () => {
		for (const action of WORKFLOW_ACTIONS) {
			const invocation = action.invocation({});
			expect(invocation.path).toBe(action.path);
			expect(invocation.command).toMatch(/^clearance(?: --yes)? /);
		}
	});

	it("keeps every TUI action in safety parity with its canonical operation", () => {
		for (const action of WORKFLOW_ACTIONS) {
			const operation = MANAGEMENT_OPERATIONS.find((candidate) => candidate.cliPath === action.path);
			expect(operation, action.path).toBeDefined();
			expect(action.mutation, action.path).toBe(operation?.mutation);
			expect(action.confirmation, action.path).toBe(operation?.confirmation);
			expect(action.supportsDryRun, action.path).toBe(operation?.supportsDryRun);
			expect(action.risk, action.path).toBe(!operation?.mutation ? "read" : operation.confirmation === "none" ? "mutation" : "destructive");
		}
	});

	it("builds shell-safe commands and dispatcher input from fields", () => {
		const create = WORKFLOW_ACTIONS.find((action) => action.id === "users-create");
		const invocation = create?.invocation({ email: "ada@example.com", name: "Ada Lovelace" });
		expect(invocation).toEqual({
			path: "users create",
			args: [],
			opts: { email: "ada@example.com", name: "Ada Lovelace" },
			global: {},
			command: "clearance users create --email ada@example.com --name 'Ada Lovelace'",
		});
	});

	it("uses one invocation for inherited target and safety context", () => {
		const action = WORKFLOW_ACTIONS.find((candidate) => candidate.id === "users-delete");
		expect(action?.invocation({ id: "usr_1" }, { profile: "prod east", apiUrl: "https://auth.example", dryRun: false })).toEqual({
			path: "users delete",
			args: ["usr_1"],
			opts: {},
			global: { profile: "prod east", apiUrl: "https://auth.example", dryRun: false, yes: true },
			command: "clearance --profile 'prod east' --api-url https://auth.example --yes users delete usr_1",
		});
	});

	it("searches labels, descriptions, and exact paths within one area", () => {
		expect(actionsFor("Events & delivery", "delivery retry").map((action) => action.id)).toContain("delivery-retry");
		expect(actionsFor("Overview", "delivery retry")).toEqual([]);
	});
});
