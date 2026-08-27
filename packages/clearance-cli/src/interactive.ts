import { createInterface } from "node:readline/promises";
import { basename } from "node:path";
import { Writable, type Readable } from "node:stream";
import { DEFAULT_CLEARANCE_API_ORIGIN } from "./cli-defaults.js";
import { interactionEligibility, type InteractionPolicyInput } from "./interaction-policy.js";
import { sanitizeTerminalText } from "./terminal-sanitize.js";

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

export interface FirstRunConnection {
	readonly apiUrl: string;
	readonly profile: string;
	readonly token: string;
}

export interface FirstRunVerification {
	readonly summary: string;
	readonly principal?: string;
	readonly projectId?: string;
	readonly environmentId?: string;
}

export interface FirstRunActionResult {
	readonly summary: string;
	readonly state?: "installed" | "unchanged" | "conflict" | "newer";
}

export interface FirstRunPreview extends FirstRunActionResult {
	readonly command: string;
}

export interface ExistingVerifiedProfile {
	readonly apiUrl: string;
	readonly profile: string;
	readonly verification: FirstRunVerification;
}

/**
 * Side effects are injected so the flow can be tested and so the CLI entrypoint
 * remains the authority for authentication, profile storage, and installers.
 */
export interface FirstRunCallbacks {
	/** Return the selected profile only after its saved credential verifies. */
	resumeProfile?(): Promise<ExistingVerifiedProfile | null>;
	verifyConnection(connection: Readonly<FirstRunConnection>): Promise<FirstRunVerification>;
	saveProfile(connection: Readonly<FirstRunConnection>): Promise<void>;
	installCompletion?(shell: "bash" | "zsh" | "fish"): Promise<FirstRunActionResult>;
	installSkill?(): Promise<FirstRunActionResult>;
	previewFirstOperation(context: { apiUrl: string; profile: string }): Promise<FirstRunPreview>;
	runFirstOperation?(context: { apiUrl: string; profile: string }): Promise<FirstRunActionResult>;
}

export interface FirstRunOptions extends InteractionPolicyInput {
	readonly callbacks: FirstRunCallbacks;
	readonly io?: InteractiveIo;
	readonly commandName?: string;
	readonly defaultApiUrl?: string;
	readonly defaultProfile?: string;
	readonly shell?: string;
	readonly readSecret?: (prompt: string, io: InteractiveIo) => Promise<string | null>;
}

export interface FirstRunResult {
	readonly status: "completed" | "cancelled" | "unavailable";
	readonly reason?: string;
	readonly apiUrl?: string;
	readonly profile?: string;
	readonly verification?: FirstRunVerification;
	readonly completion: "installed" | "unchanged" | "conflict" | "newer" | "skipped" | "unavailable";
	readonly skill: "installed" | "unchanged" | "conflict" | "newer" | "skipped" | "unavailable";
	readonly firstOperation: "executed" | "previewed" | "skipped";
	readonly command?: string;
}

function shellQuote(value: string): string {
	return `'${value.replace(/'/g, "'\"'\"'")}'`;
}

function writeLine(error: Writable, value = ""): void {
	error.write(`${sanitizeTerminalText(value, { preserveNewlines: false, preserveTabs: true })}\n`);
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
		const answer = await readline.question(sanitizeTerminalText(question, { preserveNewlines: false }));
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

async function askYesNo(question: string, fallback: boolean, io: InteractiveIo): Promise<boolean | null> {
	for (;;) {
		const answer = await ask(question, io);
		if (answer === null || isCancelled(answer)) return null;
		if (!answer) return fallback;
		if (["y", "yes"].includes(answer.toLowerCase())) return true;
		if (["n", "no"].includes(answer.toLowerCase())) return false;
		writeLine(io.error, "Enter yes or no.");
	}
}

/**
 * Read a secret with readline terminal handling enabled while discarding its
 * echo stream. The prompt is visible; the token and its length are not.
 */
export async function readMaskedSecret(prompt: string, io: InteractiveIo): Promise<string | null> {
	writeLine(io.error, prompt);
	const muted = new Writable({
		write(_chunk, _encoding, callback) {
			callback();
		},
	}) as Writable & { isTTY?: boolean };
	muted.isTTY = true;
	const readline = createInterface({ input: io.input, output: muted, terminal: true });
	let cancelled = false;
	readline.on("SIGINT", () => {
		cancelled = true;
		readline.close();
	});
	try {
		const answer = await readline.question("");
		writeLine(io.error);
		return cancelled || answer.length === 0 ? null : answer;
	} catch {
		writeLine(io.error);
		return null;
	} finally {
		readline.close();
	}
}

function supportedShell(value: string | undefined): "bash" | "zsh" | "fish" | undefined {
	const name = basename(value?.trim() ?? "");
	return name === "bash" || name === "zsh" || name === "fish" ? name : undefined;
}

function unavailableFirstRun(reason: string): FirstRunResult {
	return {
		status: "unavailable",
		reason,
		completion: "unavailable",
		skill: "unavailable",
		firstOperation: "skipped",
	};
}

function cancelledFirstRun(): FirstRunResult {
	return { status: "cancelled", completion: "skipped", skill: "skipped", firstOperation: "skipped" };
}

/**
 * Complete first-run setup: verify before saving, offer owned installers, then
 * preview and optionally execute one read operation. Tokens are never returned
 * or written to either output stream.
 */
export async function runFirstRunExperience(options: FirstRunOptions): Promise<FirstRunResult> {
	const io = options.io ?? { input: process.stdin, output: process.stdout, error: process.stderr };
	const eligibility = interactionEligibility({ ...options, stdin: io.input, stdout: io.output, stderr: io.error });
	if (!eligibility.eligible) return unavailableFirstRun(eligibility.reason!);

	const existing = await options.callbacks.resumeProfile?.();
	if (existing) {
		const preview = await options.callbacks.previewFirstOperation(existing);
		writeLine(io.error, "Clearance");
		writeLine(io.error, `Connected profile: ${existing.profile}`);
		writeLine(io.error, `Verified: ${existing.verification.summary}`);
		writeLine(io.error);
		writeLine(io.error, "Continue:");
		writeLine(io.error, `  ${preview.command}`);
		writeLine(io.error, `  ${options.commandName ?? "clearance"} doctor`);
		writeLine(io.error, `  ${options.commandName ?? "clearance"} tui`);
		return {
			status: "completed",
			apiUrl: existing.apiUrl,
			profile: existing.profile,
			verification: existing.verification,
			completion: "unavailable",
			skill: "unavailable",
			firstOperation: "previewed",
			command: preview.command,
		};
	}

	writeLine(io.error, "Welcome to Clearance");
	writeLine(io.error, "Connect a profile, verify it, and run your first operation. Enter q to cancel.");
	const profile = await askRequired(
		`Profile [${options.defaultProfile ?? "default"}]: `,
		options.defaultProfile ?? "default",
		io,
	);
	if (!profile) return cancelledFirstRun();
	const defaultApiUrl = options.defaultApiUrl ?? DEFAULT_CLEARANCE_API_ORIGIN;
	const apiUrl = await askRequired(`Management API [${defaultApiUrl}]: `, defaultApiUrl, io);
	if (!apiUrl) return cancelledFirstRun();
	const token = await (options.readSecret ?? readMaskedSecret)("Operator token (input hidden):", io);
	if (!token) return cancelledFirstRun();

	writeLine(io.error, "Verifying connection...");
	const connection = { apiUrl, profile, token };
	const verification = await options.callbacks.verifyConnection(connection);
	await options.callbacks.saveProfile(connection);
	writeLine(io.error, `Connected: ${verification.summary}`);
	writeLine(io.error, `Saved profile: ${profile}`);

	let completion: FirstRunResult["completion"] = "unavailable";
	const shell = supportedShell(options.shell ?? process.env.SHELL);
	if (shell && options.callbacks.installCompletion) {
		const install = await askYesNo(`Install ${shell} completion? [Y/n]: `, true, io);
		if (install === null) return {
			status: "cancelled", apiUrl, profile, verification, completion, skill: "unavailable",
			firstOperation: "skipped",
		};
		if (install) {
			const result = await options.callbacks.installCompletion(shell);
			completion = result.state ?? "installed";
			writeLine(io.error, result.summary);
		} else completion = "skipped";
	}

	let skill: FirstRunResult["skill"] = "unavailable";
	if (options.callbacks.installSkill) {
		const install = await askYesNo("Install the Clearance agent skill? [Y/n]: ", true, io);
		if (install === null) return {
			status: "cancelled", apiUrl, profile, verification, completion, skill,
			firstOperation: "skipped",
		};
		if (install) {
			const result = await options.callbacks.installSkill();
			skill = result.state ?? "installed";
			writeLine(io.error, result.summary);
		} else skill = "skipped";
	}

	const preview = await options.callbacks.previewFirstOperation({ apiUrl, profile });
	writeLine(io.error);
	writeLine(io.error, `First operation: ${preview.summary}`);
	writeLine(io.error, `  ${preview.command}`);
	let firstOperation: FirstRunResult["firstOperation"] = "previewed";
	if (options.callbacks.runFirstOperation) {
		const run = await askYesNo("Run it now? [Y/n]: ", true, io);
		if (run === null) {
			return {
				status: "cancelled", apiUrl, profile, verification, completion, skill,
				firstOperation, command: preview.command,
			};
		}
		if (run) {
			const result = await options.callbacks.runFirstOperation({ apiUrl, profile });
			firstOperation = "executed";
			writeLine(io.error, result.summary);
		}
	}

	return {
		status: "completed",
		apiUrl,
		profile,
		verification,
		completion,
		skill,
		firstOperation,
		command: preview.command,
	};
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
		const url = await askRequired(
			`API URL [${DEFAULT_CLEARANCE_API_ORIGIN}]: `,
			DEFAULT_CLEARANCE_API_ORIGIN,
			io,
		);
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
