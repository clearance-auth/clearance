import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";
import { interactionEligibility, type InteractionPolicyInput } from "./interaction-policy.js";

export interface InteractiveIo {
	input: Readable & { isTTY?: boolean };
	output: Writable & { isTTY?: boolean };
	error: Writable & { isTTY?: boolean };
}

export interface GuidedInteractionOptions extends InteractionPolicyInput {
	io?: InteractiveIo;
	commandName?: string;
}

export type GuidedInteractionResult =
	| { status: "completed"; command: string }
	| { status: "cancelled" }
	| { status: "unavailable"; reason: string };

type Workflow = "login" | "whoami" | "init" | "users" | "orgs" | "events";

function shellQuote(value: string): string {
	return `'${value.replace(/'/g, "'\"'\"'")}'`;
}

function writeLine(error: Writable, value = ""): void {
	error.write(`${value}\n`);
}

function isCancelled(answer: string): boolean {
	return ["q", "quit", "cancel", "exit"].includes(answer.trim().toLowerCase());
}

async function ask(question: string, io: InteractiveIo): Promise<string | null> {
	const readline = createInterface({ input: io.input, output: io.error, terminal: true });
	let cancelled = false;
	readline.on("SIGINT", () => {
		cancelled = true;
		readline.close();
	});
	try {
		const answer = await readline.question(question);
		return cancelled ? null : answer.trim();
	} catch {
		return null;
	} finally {
		readline.close();
	}
}

async function askRequired(question: string, fallback: string | undefined, io: InteractiveIo): Promise<string | null> {
	const answer = await ask(question, io);
	if (answer === null || isCancelled(answer)) return null;
	return answer || fallback || null;
}

function commandFor(workflow: Workflow, commandName: string, values: Record<string, string>): string {
	switch (workflow) {
		case "login":
			return `${commandName} --profile ${shellQuote(values.profile)} login --url ${shellQuote(values.url)}`;
		case "whoami":
			return `${commandName} --profile ${shellQuote(values.profile)} whoami`;
		case "init":
			return `${commandName} init --name ${shellQuote(values.name)} --environment ${shellQuote(values.environment)}`;
		case "users":
			return `${commandName} users list`;
		case "orgs":
			return `${commandName} orgs list`;
		case "events":
			return `${commandName} events list`;
	}
}

/**
 * Offer a small set of existing CLI workflows and print the selected command.
 * It intentionally does not execute the command: the user retains a visible,
 * copyable command and every guided capability remains available to automation.
 */
export async function runGuidedInteraction(options: GuidedInteractionOptions = {}): Promise<GuidedInteractionResult> {
	const io = options.io ?? { input: process.stdin, output: process.stdout, error: process.stderr };
	const eligibility = interactionEligibility({ ...options, stdin: io.input, stdout: io.output, stderr: io.error });
	if (!eligibility.eligible) return { status: "unavailable", reason: eligibility.reason! };

	const commandName = options.commandName ?? "clearance";
	writeLine(io.error, "Clearance guided setup");
	writeLine(io.error, "Choose a workflow. Enter q at any prompt to cancel.");
	writeLine(io.error, "  1. Connect an API profile");
	writeLine(io.error, "  2. Check an API profile");
	writeLine(io.error, "  3. Initialize a project");
	writeLine(io.error, "  4. List users");
	writeLine(io.error, "  5. List organizations");
	writeLine(io.error, "  6. List audit events");

	const choice = await ask("Workflow [1-6, q]: ", io);
	if (choice === null || isCancelled(choice)) return { status: "cancelled" };
	const workflows: Record<string, Workflow> = {
		"1": "login", "2": "whoami", "3": "init", "4": "users", "5": "orgs", "6": "events",
	};
	const workflow = workflows[choice];
	if (!workflow) {
		writeLine(io.error, "No workflow selected. Run clearance --help to browse all commands.");
		return { status: "cancelled" };
	}

	const values: Record<string, string> = {};
	if (workflow === "login" || workflow === "whoami") {
		const profile = await askRequired("Profile [default]: ", "default", io);
		if (!profile) return { status: "cancelled" };
		values.profile = profile;
	}
	if (workflow === "login") {
		const url = await askRequired("API URL [http://localhost:3000]: ", "http://localhost:3000", io);
		if (!url) return { status: "cancelled" };
		values.url = url;
		writeLine(io.error, "Set CLEARANCE_OPERATOR_TOKEN before running the command.");
	}
	if (workflow === "init") {
		const name = await askRequired("Project name [clearance-app]: ", "clearance-app", io);
		if (!name) return { status: "cancelled" };
		const environment = await askRequired("Environment [development]: ", "development", io);
		if (!environment) return { status: "cancelled" };
		values.name = name;
		values.environment = environment;
	}

	const command = commandFor(workflow, commandName, values);
	writeLine(io.error);
	writeLine(io.error, "Run:");
	writeLine(io.error, `  ${command}`);
	return { status: "completed", command };
}
