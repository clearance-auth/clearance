import { Command } from "commander";
import { describe, expect, it, vi } from "vitest";
import {
	DELIVERY_OPERATIONS,
	WEBHOOK_ENDPOINT_OPERATIONS,
} from "../../management/src/contracts/operations.js";
import { registerDeliveryCommands } from "./delivery-command.js";

function deliveryProgram(action: (command: Command) => void): Command {
	const program = new Command("clearance");
	program.exitOverride();
	registerDeliveryCommands(program, function (this: Command) {
		action(this);
	});
	return program;
}

describe("delivery command parser", () => {
	it("registers one leaf for every delivery operation contract", () => {
		const program = deliveryProgram(() => undefined);
		const delivery = program.commands.find((command) => command.name() === "delivery");
		expect(delivery).toBeDefined();
		expect(delivery?.commands.filter((command) => command.name() !== "endpoints")
			.map((command) => `delivery ${command.name()}`)).toEqual(
			Object.values(DELIVERY_OPERATIONS).map((operation) => operation.cliPath),
		);
		const endpoints = delivery?.commands.find((command) => command.name() === "endpoints");
		expect(endpoints?.commands.map((command) => `delivery endpoints ${command.name()}`))
			.toEqual(Object.values(WEBHOOK_ENDPOINT_OPERATIONS).map((operation) => operation.cliPath));
	});

	it("parses webhook endpoint create and versioned controls", async () => {
		const create = vi.fn();
		await deliveryProgram((command) => create(command.processedArgs, command.opts())).parseAsync([
			"node", "clearance", "delivery", "endpoints", "create",
			"--name", "Audit sink", "--url", "https://hooks.example.test/events",
			"--event-kind", "organization.updated",
		]);
		expect(create).toHaveBeenCalledWith([], {
			name: "Audit sink",
			url: "https://hooks.example.test/events",
			eventKind: ["organization.updated"],
		});

		const rotate = vi.fn();
		await deliveryProgram((command) => rotate(command.processedArgs, command.opts())).parseAsync([
			"node", "clearance", "delivery", "endpoints", "rotate", "endpoint_1",
			"--expected-version", "4",
		]);
		expect(rotate).toHaveBeenCalledWith(["endpoint_1"], { expectedVersion: "4" });
	});

	it("parses repeatable list filters without interaction", async () => {
		const action = vi.fn();
		const program = deliveryProgram((command) => action(command.processedArgs, command.opts()));
		await program.parseAsync([
			"node",
			"clearance",
			"delivery",
			"list",
			"--limit",
			"25",
			"--cursor",
			"next_page",
			"--state",
			"retry",
			"--state",
			"dead",
			"--channel",
			"webhook",
			"--kind",
			"organization.updated",
		]);
		expect(action).toHaveBeenCalledWith([], {
			limit: "25",
			cursor: "next_page",
			state: ["retry", "dead"],
			channel: "webhook",
			kind: "organization.updated",
		});
	});

	it("parses readiness and replay controls", async () => {
		const readiness = vi.fn();
		await deliveryProgram((command) => readiness(command.opts())).parseAsync([
			"node", "clearance", "delivery", "readiness", "--stale-after-ms", "45000",
		]);
		expect(readiness).toHaveBeenCalledWith({ staleAfterMs: "45000" });

		const replay = vi.fn();
		await deliveryProgram((command) => replay(command.processedArgs, command.opts())).parseAsync([
			"node", "clearance", "delivery", "replay", "job_1", "--max-attempts", "12",
		]);
		expect(replay).toHaveBeenCalledWith(["job_1"], { maxAttempts: "12" });
	});
});
