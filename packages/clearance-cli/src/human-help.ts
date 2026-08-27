import { sanitizeTerminalText } from "./terminal-sanitize.js";
import { terminalWidth, wrapTerminalText } from "./terminal-width.js";
import { CLI_EXIT_CODE } from "./output-exit-codes.js";

export interface HumanHelpTopic {
	readonly id: string;
	readonly group: "Getting started" | "Operate accounts" | "Configure workflows" | "Local tooling" | "Safety";
	readonly title: string;
	readonly summary: string;
	readonly examples: readonly string[];
}

export class HumanHelpTopicError extends Error {
	readonly code = "CLI_HELP_TOPIC_NOT_FOUND";
	constructor(topic: string) {
		super(`Unknown help topic: ${safeTopic(topic)}`);
		this.name = "HumanHelpTopicError";
	}
}

const EXIT_CODE_SUMMARY = [
	`${CLI_EXIT_CODE.success} success`,
	`${CLI_EXIT_CODE.checkFailed} check failed`,
	`${CLI_EXIT_CODE.invalidInput} invalid input`,
	`${CLI_EXIT_CODE.notFound} not found`,
	`${CLI_EXIT_CODE.unavailable} unavailable`,
	`${CLI_EXIT_CODE.internal} internal`,
	`${CLI_EXIT_CODE.conflict} conflict`,
	`${CLI_EXIT_CODE.temporaryFailure} temporary failure`,
	`${CLI_EXIT_CODE.authentication} authentication`,
	`${CLI_EXIT_CODE.permission} permission`,
].join("; ") + ".";

function safeTopic(value: string): string {
	return value.replace(/[^a-z0-9-]/giu, "").slice(0, 64) || "unknown";
}

export const HUMAN_HELP_TOPICS: readonly HumanHelpTopic[] = Object.freeze([
	{ id: "getting-started", group: "Getting started", title: "Get started", summary: "Connect a profile, verify local setup, then inspect available commands.", examples: ["clearance login --profile development", "clearance doctor", "clearance commands"] },
	{ id: "profiles", group: "Getting started", title: "Profiles", summary: "Keep API origins and credentials in named local profiles.", examples: ["clearance login --profile staging", "clearance --profile staging whoami"] },
	{ id: "users", group: "Operate accounts", title: "Users and organizations", summary: "Inspect and manage users, organizations, memberships, and access.", examples: ["clearance users list", "clearance orgs list"] },
	{ id: "output", group: "Configure workflows", title: "Machine-readable output", summary: "Use JSON, JSONL, quiet output, or jq for automation.", examples: ["clearance users list --output-format json", "clearance events tail --jsonl"] },
	{ id: "environment", group: "Configure workflows", title: "Environment", summary: "Override the origin deliberately and use environment credentials only for scoped automation.", examples: ["clearance --api-url http://localhost:13200 doctor", "CLEARANCE_PROFILE=staging clearance whoami"] },
	{ id: "tui", group: "Local tooling", title: "TUI", summary: "Open the guided terminal interface after connecting a profile.", examples: ["clearance --profile development tui"] },
	{ id: "completion", group: "Local tooling", title: "Shell completion", summary: "Generate completion source or install an owned completion file for your current shell.", examples: ["clearance completion zsh", "clearance completion install zsh"] },
	{ id: "safety", group: "Safety", title: "Safe operation", summary: "Review mutation commands, use dry runs where available, and never place credentials in shell history.", examples: ["clearance skill install --dry-run", "clearance logout --profile staging"] },
	{ id: "exit-codes", group: "Safety", title: "Exit codes", summary: EXIT_CODE_SUMMARY, examples: ["clearance doctor; echo $?", "clearance commands --output-format json"] },
]);

export function listHumanHelpTopics(): readonly HumanHelpTopic[] {
	return HUMAN_HELP_TOPICS;
}

export function findHumanHelpTopic(topic: string): HumanHelpTopic {
	const normalized = safeTopic(topic);
	const result = HUMAN_HELP_TOPICS.find((candidate) => candidate.id === normalized);
	if (!result) throw new HumanHelpTopicError(topic);
	return result;
}

function wrap(text: string, width: number): string[] {
	return wrapTerminalText(sanitizeTerminalText(text), width);
}

/** Render stable, curated help without coupling to Commander or terminal APIs. */
export function renderHumanHelp(topic?: string, width: (() => number) | number = 80): string {
	const columns = Math.max(40, typeof width === "function" ? width() : width);
	if (!topic) {
		const groups = new Map<string, HumanHelpTopic[]>();
		for (const item of HUMAN_HELP_TOPICS) groups.set(item.group, [...(groups.get(item.group) ?? []), item]);
		return [...groups.entries()].flatMap(([group, items]) => [
			sanitizeTerminalText(group),
			...items.flatMap((item) => {
				const id = sanitizeTerminalText(item.id, { preserveNewlines: false, preserveTabs: false });
				const prefix = `  ${id}${" ".repeat(Math.max(1, 18 - terminalWidth(id)))}`;
				const summary = wrap(item.summary, Math.max(1, columns - terminalWidth(prefix)));
				return summary.map((line, index) => `${index === 0 ? prefix : " ".repeat(terminalWidth(prefix))}${line}`);
			}),
		]).join("\n");
	}
	const item = findHumanHelpTopic(topic);
	return [
		sanitizeTerminalText(item.title),
		...wrap(item.summary, columns),
		"Examples:",
		...item.examples.flatMap((example) => wrap(example, Math.max(1, columns - 2)).map((line) => `  ${line}`)),
	].join("\n");
}
