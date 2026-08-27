#!/usr/bin/env node
import { Command, CommanderError } from "commander";
import { readFileSync } from "node:fs";
import { lstat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import {
	ClearanceError,
	EVENTS_EXPORT_MAX_LIMIT,
	EVENTS_TAIL_MAX_LIMIT,
	USERS_EXPORT_MAX_LIMIT,
	MANAGEMENT_OPERATIONS,
	closeAuthBundle,
	migrateRuntimeSchemaLocally,
} from "@clearance/management";
import {
	CLI_EXIT_CODE,
	CliExitError,
	fail,
	parseOutputFormat,
	printResult,
	selectOutputFormat,
	validateOutputSelector,
	type GlobalOpts,
	type OutputFormat,
} from "./output.js";
import {
	deleteSavedCredential,
	credentialDirectory,
	environmentToken,
	fetchWhoami,
	normalizeApiUrl,
	normalizeProfile,
	readSavedCredential,
	readTokenFromStdin,
	validateAndSaveCredential,
	verifyOperatorCredential,
	writeSavedCredential,
} from "./operator-auth.js";
import { resolveApiSession } from "./api-client.js";
import { registerDeliveryCommands } from "./delivery-command.js";
import { registerAuthenticationPolicyCommands } from "./authentication-policy-command.js";
import { registerKeyManagementCommands } from "./key-management-command.js";
import { registerProductPresentationCommands } from "./product-presentation-command.js";
import {
	commandPath,
	dispatchRemoteCommand,
	EVENTS_TAIL_MAX_POLL_INTERVAL_MS,
	EVENTS_TAIL_MIN_POLL_INTERVAL_MS,
} from "./remote-dispatch.js";
import {
	buildCommandSpecDocument,
	compareCommanderParity,
	type CommandSpecRecord,
	type SupplementalCommandSpec,
} from "./command-spec.js";
import { buildExperienceManifest } from "./experience-manifest.js";
import { clearanceCommandFromArgv, OperationRunner, type OperationRunResult } from "./operation-runner.js";
import { defaultExecutionReceiptPath, FileExecutionReceiptStore } from "./execution-receipt.js";
import { renderCompletion, type CompletionShell } from "./completion.js";
import {
	completionInstallationPath,
	inspectCompletionInstallation,
	installCompletion,
} from "./completion-installer.js";
import { installClearanceAgentSkill, inspectClearanceAgentSkill } from "./agent-skill.js";
import { runFirstRunExperience } from "./interactive.js";
import { interactionEligibility } from "./interaction-policy.js";
import { listHumanHelpTopics, renderHumanHelp } from "./human-help.js";
import { renderHumanPresentation, type HumanField, type HumanTableColumn } from "./human-presentation.js";
import { renderLocalDoctor, runLocalDoctor, type LocalFeatureInspection } from "./local-doctor.js";
import { createRemoteWorkflowExecutor, parseTuiDeepLink, runTerminalUi } from "./tui/index.js";
import { isEventStreamResult } from "./dispatch/events.js";
import { readPasswordPrompt } from "./password-prompt.js";

const MAX_STDIN_PASSWORD_BYTES = 4_096;
const operationRunner = (() => {
	try {
		return new OperationRunner({
			receiptStore: new FileExecutionReceiptStore(defaultExecutionReceiptPath()),
		});
	} catch (cause) {
		return new OperationRunner({
			receiptStore: { async save() { throw cause; } },
		});
	}
})();

type LocalMutationInput<Prepared, Result> = {
	readonly operation: Readonly<LocalMutationContract>;
	readonly global: Readonly<GlobalOpts>;
	readonly target?: {
		readonly resource?: string;
		readonly principal?: string;
		readonly environment?: string;
		readonly apiOrigin?: string;
	};
	readonly reconciliationCommands?: readonly string[];
	prepare(redact: (value: string) => void): Prepared | Promise<Prepared>;
	mutate(prepared: Prepared, signal?: AbortSignal): Result | Promise<Result>;
};

type LocalMutationContract = {
	readonly id: string;
	readonly path: string;
	readonly supportsDryRun: boolean;
};

const LOCAL_MUTATION_CONTRACTS = Object.freeze({
	login: Object.freeze({ id: "authentication.login", path: "login", supportsDryRun: false }),
	logout: Object.freeze({ id: "authentication.logout", path: "logout", supportsDryRun: false }),
	completionInstall: Object.freeze({ id: "local.completion.install", path: "completion install", supportsDryRun: true }),
	skillInstall: Object.freeze({ id: "local.skill.install", path: "skill install", supportsDryRun: true }),
	schemaMigrate: Object.freeze({
		id: "schema.migrate.local",
		path: "schema migrate",
		supportsDryRun: MANAGEMENT_OPERATIONS.find((operation) => operation.cliPath === "schema migrate")?.supportsDryRun === true,
	}),
} satisfies Record<string, LocalMutationContract>);

async function runLocalMutation<Prepared, Result>(
	input: Readonly<LocalMutationInput<Prepared, Result>>,
) {
	return operationRunner.run({
		operation: {
			id: input.operation.id,
			path: input.operation.path,
			mutation: true,
			confirmation: "none",
		},
		command: clearanceCommandFromArgv(process.argv),
		target: input.target,
		dryRun: input.global.dryRun,
		confirmed: true,
		signal: input.global.signal,
		reconciliationCommands: input.reconciliationCommands,
		execute: async ({ signal, markDispatched, redact }) => {
			if (input.global.dryRun && !input.operation.supportsDryRun) {
				throw new ClearanceError({
					code: "CLI_LOCAL_DRY_RUN_UNSUPPORTED",
					message: `${input.operation.path} does not support --dry-run.`,
					stage: "cli.dispatch",
					status: 400,
					remediation: "Run the command without --dry-run when you are ready to change local state.",
				});
			}
			const prepared = await input.prepare(redact);
			markDispatched();
			return { data: await input.mutate(prepared, signal) };
		},
	});
}

function localMutationPresentation<Result>(
	path: string,
	run: OperationRunResult<Result>,
) {
	return operationHumanPresentation(path, true, run.data, run.receipt, {
		status: run.receiptPersistence,
		...(run.receiptPersistencePath ? { path: run.receiptPersistencePath } : {}),
		...(run.receiptPersistenceError ? { error: run.receiptPersistenceError } : {}),
	});
}

function failLocalMutation(
	run: OperationRunResult<unknown>,
	global: Readonly<GlobalOpts>,
): never {
	fail(run.cause, global, {
		receipt: run.receipt,
		receiptPersistence: run.receiptPersistence,
		...(run.receiptPersistencePath ? { receiptPersistencePath: run.receiptPersistencePath } : {}),
		...(run.receiptPersistenceError ? { receiptPersistenceError: run.receiptPersistenceError } : {}),
	});
}

const VERSION = (
	JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
		version: string;
	}
).version;

function globals(cmd: Command): GlobalOpts {
	const opts = cmd.optsWithGlobals() as GlobalOpts & Record<string, unknown>;
	return {
		json: Boolean(opts.json),
		jsonl: Boolean(opts.jsonl),
		quiet: Boolean(opts.quiet),
		jq: typeof opts.jq === "string" ? opts.jq : undefined,
		output: opts.outputFormat as OutputFormat | undefined,
		inferredFormat: process.stdout.isTTY ? undefined : "json",
		noInput: opts.input === false,
		yes: Boolean(opts.yes),
		dryRun: Boolean(opts.dryRun),
		profile: opts.profile as string | undefined,
		apiUrl: opts.apiUrl as string | undefined,
	};
}

function humanCommandListing(commands: readonly CommandSpecRecord[]): string {
	const lines = commands.map((command) => {
		const description = command.description?.trim();
		return description ? `  ${command.path}\n    ${description}` : `  ${command.path}`;
	});
	return ["Available Clearance commands:", ...lines, "", "Run clearance <command> --help for command details."].join("\n");
}

function supportedCompletionShell(value: unknown): value is CompletionShell {
	return typeof value === "string" && (["bash", "zsh", "fish"] as const).includes(value as CompletionShell);
}

function detectedCompletionShell(): CompletionShell | undefined {
	const shell = basename(process.env.SHELL?.trim() ?? "");
	return supportedCompletionShell(shell) ? shell : undefined;
}

function shellWord(value: string): string {
	return /^[a-zA-Z0-9_./:@%+=,-]+$/u.test(value)
		? value
		: `'${value.replaceAll("'", "'\"'\"'")}'`;
}

function rawJsonCommand(): string {
	return ["clearance", ...process.argv.slice(2), "--output-format", "json"].map(shellWord).join(" ");
}

function record(value: unknown): Readonly<Record<string, unknown>> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value)
		? value as Readonly<Record<string, unknown>>
		: undefined;
}

function listResult(data: unknown): {
	name: string;
	rows: readonly Readonly<Record<string, unknown>>[];
	fields: readonly HumanField[];
} | undefined {
	const source = record(data);
	const entry = Array.isArray(data)
		? ["results", data] as const
		: Object.entries(source ?? {}).find(([, value]) => Array.isArray(value));
	if (!entry) return undefined;
	const [name, values] = entry as readonly [string, readonly unknown[]];
	return {
		name,
		rows: values.map((value) => record(value) ?? { value }),
		fields: Object.entries(source ?? {})
			.filter(([key]) => key !== name)
			.map(([key, value]) => ({
				label: key.replace(/([a-z0-9])([A-Z])/gu, "$1 $2").replace(/^./u, (character) => character.toUpperCase()),
				value,
				group: /cursor|page|count|total|truncated/iu.test(key) ? "Page" : "Context",
			})),
	};
}

function tableColumns(rows: readonly Readonly<Record<string, unknown>>[]): readonly HumanTableColumn[] {
	const keys = [...new Set(rows.flatMap((row) => Object.keys(row).filter((key) => {
		const value = row[key];
		return value === null || value === undefined || typeof value !== "object";
	})))];
	const priority = ["id", "name", "email", "status", "type", "role", "createdAt", "updatedAt"];
	keys.sort((left, right) => {
		const leftIndex = priority.indexOf(left);
		const rightIndex = priority.indexOf(right);
		return (leftIndex < 0 ? priority.length : leftIndex) - (rightIndex < 0 ? priority.length : rightIndex)
			|| left.localeCompare(right);
	});
	return keys.slice(0, 5).map((key) => ({
		key,
		label: key.replace(/([a-z0-9])([A-Z])/gu, "$1 $2").replace(/^./u, (character) => character.toUpperCase()),
		minWidth: key === "id" ? 12 : 8,
		maxWidth: key === "email" ? 36 : key === "id" ? 28 : 24,
	}));
}

function resultFields(data: unknown, group = "Result"): readonly HumanField[] {
	const source = record(data);
	if (!source) return [{ label: "Value", value: data, group }];
	return Object.entries(source).slice(0, 16).map(([key, value]) => ({
		label: key.replace(/([a-z0-9])([A-Z])/gu, "$1 $2").replace(/^./u, (character) => character.toUpperCase()),
		value,
		group,
	}));
}

function operationHumanPresentation(
	path: string,
	mutation: boolean,
	data: unknown,
	receipt: {
		readonly receiptId: string;
		readonly outcome: string;
		readonly commitState: string;
		readonly requestId: string | null;
		readonly reconciliationCommands: readonly string[];
	},
	receiptPersistence: {
		readonly status: "saved" | "not-configured" | "failed";
		readonly path?: string;
		readonly error?: string;
	},
): {
	human: string;
	summary: string;
	next: readonly string[];
	meta: { receipt: typeof receipt; receiptPersistence: typeof receiptPersistence };
} {
	const width = process.stdout.columns ?? 80;
	const displayPath = path.replaceAll("-", " ").replace(/^./u, (character) => character.toUpperCase());
	if (mutation) {
		const fields: HumanField[] = [
			{ label: "Operation", value: path, group: "Receipt" },
			{ label: "Outcome", value: receipt.outcome, group: "Receipt" },
			{ label: "Commit state", value: receipt.commitState, group: "Receipt" },
			{ label: "Receipt ID", value: receipt.receiptId, group: "Receipt" },
			...(receipt.requestId ? [{ label: "Request ID", value: receipt.requestId, group: "Receipt" }] : []),
			{
				label: "Journal",
				value: receiptPersistence.status === "saved"
					? `saved${receiptPersistence.path ? ` at ${receiptPersistence.path}` : ""}`
					: receiptPersistence.error ?? receiptPersistence.status,
				group: "Receipt",
			},
			...resultFields(data),
		];
		const summary = `${displayPath} ${receipt.outcome}.`;
		return {
			human: renderHumanPresentation({
				kind: "mutation",
				title: summary,
				receipt: fields,
				next: receipt.reconciliationCommands,
			}, { width }),
			summary,
			next: receipt.reconciliationCommands,
			meta: { receipt, receiptPersistence },
		};
	}
	const list = listResult(data);
	if (list) {
		const summary = `${list.rows.length} ${list.name}.`;
		return {
			human: renderHumanPresentation({
				kind: "list",
				title: displayPath,
				columns: tableColumns(list.rows),
				rows: list.rows,
				fields: list.fields,
				empty: `No ${list.name} found.`,
				summary,
				rawJsonCommand: rawJsonCommand(),
			}, { width }),
			summary,
			next: [],
			meta: { receipt, receiptPersistence },
		};
	}
	const summary = `${displayPath} completed.`;
	return {
		human: renderHumanPresentation({
			kind: "detail",
			title: displayPath,
			fields: resultFields(data, "Details"),
			summary,
			rawJsonCommand: rawJsonCommand(),
		}, { width }),
		summary,
		next: [],
		meta: { receipt, receiptPersistence },
	};
}

async function inspectLocalConfig(): Promise<{ state: "ready" | "absent" | "unsafe"; detail?: string }> {
	const path = credentialDirectory(process.env);
	try {
		const stat = await lstat(path);
		if (stat.isSymbolicLink() || !stat.isDirectory() || (stat.mode & 0o777) !== 0o700) {
			return { state: "unsafe", detail: `${path} must be a regular directory with mode 0700.` };
		}
		return { state: "ready", detail: path };
	} catch (cause) {
		if ((cause as NodeJS.ErrnoException).code === "ENOENT") return { state: "absent", detail: path };
		return { state: "unsafe", detail: `${path} could not be inspected.` };
	}
}

function featureInspection(
	inspection: { exists: boolean; owned: boolean; path: string },
): LocalFeatureInspection {
	if (!inspection.exists) return { state: "missing", detail: inspection.path };
	return inspection.owned
		? { state: "installed", detail: inspection.path }
		: { state: "conflict", detail: inspection.path };
}

async function inspectLocalProfile(profile: string): Promise<{
	state: "configured" | "absent" | "unsafe";
	apiOrigin?: string;
}> {
	try {
		const saved = await readSavedCredential(process.env, profile);
		return saved ? { state: "configured", apiOrigin: saved.apiUrl } : { state: "absent" };
	} catch {
		return { state: "unsafe" };
	}
}

function localSetupError(code: string, message: string, remediation: string, status = 409): ClearanceError {
	return new ClearanceError({ code, message, stage: "cli.local-setup", status, remediation });
}

function passwordInputError(code: string, message: string, remediation: string): ClearanceError {
	return new ClearanceError({ code, message, stage: "cli.password-input", status: 400, remediation });
}

function passwordFromInput(input: string): string {
	const password = input.replace(/\r?\n$/, "");
	if (Buffer.byteLength(password, "utf8") > MAX_STDIN_PASSWORD_BYTES) {
		throw passwordInputError(
			"USER_CREATE_PASSWORD_TOO_LARGE",
			"Initial password input exceeds the 4096-byte limit.",
			"Provide a shorter password.",
		);
	}
	if (password.length === 0) {
		throw passwordInputError(
			"USER_CREATE_PASSWORD_EMPTY",
			"Initial password input cannot be empty.",
			"Provide a non-empty password, or omit password options to issue a setup token.",
		);
	}
	return password;
}

async function readPasswordFromStdin(): Promise<string> {
	if (process.stdin.isTTY) {
		throw passwordInputError(
			"USER_CREATE_PASSWORD_STDIN_TTY",
			"--password-stdin requires piped standard input.",
			"Pipe the password to standard input, or use --password-prompt in an interactive terminal.",
		);
	}
	let input = "";
	for await (const chunk of process.stdin) {
		input += typeof chunk === "string" ? chunk : chunk.toString("utf8");
		if (Buffer.byteLength(input, "utf8") > MAX_STDIN_PASSWORD_BYTES + 2) {
			throw passwordInputError(
				"USER_CREATE_PASSWORD_TOO_LARGE",
				"Initial password input exceeds the 4096-byte limit.",
				"Provide a shorter password.",
			);
		}
	}
	return passwordFromInput(input);
}

async function readPasswordFromPrompt(): Promise<string> {
	const eligibility = interactionEligibility();
	if (!eligibility.eligible || typeof process.stdin.setRawMode !== "function") {
		throw passwordInputError(
			"USER_CREATE_PASSWORD_PROMPT_TTY_REQUIRED",
			`--password-prompt requires an interactive terminal (${eligibility.reason ?? "raw-mode-unavailable"}).`,
			"Use --password-stdin with piped input, or omit password options to issue a setup token.",
		);
	}

	return readPasswordPrompt(process.stdin, process.stderr);
}

interface NumericOptionConstraint {
	readonly key: string;
	readonly flag: string;
	readonly minimum: number;
	readonly maximum: number;
}

const NUMERIC_OPTION_CONSTRAINTS: Readonly<Record<string, readonly NumericOptionConstraint[]>> = {
	"users list": [{ key: "limit", flag: "limit", minimum: 1, maximum: 1_000 }],
	"users export": [{ key: "limit", flag: "limit", minimum: 1, maximum: USERS_EXPORT_MAX_LIMIT }],
	"orgs list": [{ key: "limit", flag: "limit", minimum: 1, maximum: 1_000 }],
	"events list": [{ key: "limit", flag: "limit", minimum: 1, maximum: 1_000 }],
	"events tail": [
		{ key: "limit", flag: "limit", minimum: 1, maximum: EVENTS_TAIL_MAX_LIMIT },
		{ key: "pollInterval", flag: "poll-interval", minimum: EVENTS_TAIL_MIN_POLL_INTERVAL_MS, maximum: EVENTS_TAIL_MAX_POLL_INTERVAL_MS },
		{ key: "maxEvents", flag: "max-events", minimum: 0, maximum: Number.MAX_SAFE_INTEGER },
	],
	"events export": [{ key: "limit", flag: "limit", minimum: 1, maximum: EVENTS_EXPORT_MAX_LIMIT }],
	"sessions list": [{ key: "limit", flag: "limit", minimum: 1, maximum: 500 }],
	"delivery list": [{ key: "limit", flag: "limit", minimum: 1, maximum: 200 }],
	"delivery readiness": [{ key: "staleAfterMs", flag: "stale-after-ms", minimum: 1_000, maximum: 86_400_000 }],
	"delivery replay": [{ key: "maxAttempts", flag: "max-attempts", minimum: 1, maximum: 100 }],
	"delivery endpoints list": [{ key: "limit", flag: "limit", minimum: 1, maximum: 200 }],
	"delivery endpoints update": [{ key: "expectedVersion", flag: "expected-version", minimum: 1, maximum: Number.MAX_SAFE_INTEGER }],
	"delivery endpoints rotate": [{ key: "expectedVersion", flag: "expected-version", minimum: 1, maximum: Number.MAX_SAFE_INTEGER }],
	"delivery endpoints delete": [{ key: "expectedVersion", flag: "expected-version", minimum: 1, maximum: Number.MAX_SAFE_INTEGER }],
	"delivery endpoints test": [{ key: "expectedVersion", flag: "expected-version", minimum: 1, maximum: Number.MAX_SAFE_INTEGER }],
	"auth-policy apply": [{ key: "expectedRevision", flag: "expected-revision", minimum: 1, maximum: Number.MAX_SAFE_INTEGER }],
	"orgs authorization assignments replace": [{ key: "expectedRevision", flag: "expected-revision", minimum: 1, maximum: Number.MAX_SAFE_INTEGER }],
	"product presentation apply": [{ key: "expectedVersion", flag: "expected-version", minimum: 0, maximum: Number.MAX_SAFE_INTEGER }],
	"product domains reissue": [{ key: "expectedVersion", flag: "expected-version", minimum: 0, maximum: Number.MAX_SAFE_INTEGER }],
	"product domains activate": [{ key: "expectedVersion", flag: "expected-version", minimum: 0, maximum: Number.MAX_SAFE_INTEGER }],
	"product domains disable": [{ key: "expectedVersion", flag: "expected-version", minimum: 0, maximum: Number.MAX_SAFE_INTEGER }],
	"product sender apply": [{ key: "expectedVersion", flag: "expected-version", minimum: 0, maximum: Number.MAX_SAFE_INTEGER }],
	"product sender readiness": [{ key: "staleAfterMs", flag: "stale-after-ms", minimum: 1, maximum: Number.MAX_SAFE_INTEGER }],
	"product templates apply": [{ key: "expectedVersion", flag: "expected-version", minimum: 0, maximum: Number.MAX_SAFE_INTEGER }],
	"schema credential-authority arm": [{ key: "expectedRuntimes", flag: "expected-runtimes", minimum: 1, maximum: 10_000 }],
};

const FORMAT_OPTION_CHOICES: Readonly<Record<string, readonly string[]>> = {
	"users export": ["json", "jsonl"],
	"events export": ["json", "jsonl"],
	"orgs members import": ["json", "csv"],
};

function cliUsage(message: string, remediation: string): ClearanceError {
	return new ClearanceError({ code: "CLI_USAGE", message, stage: "cli.usage", status: 400, remediation });
}

function normalizeRemoteInputs(path: string, values: Record<string, unknown>): Record<string, unknown> {
	const normalized = { ...values };
	for (const constraint of NUMERIC_OPTION_CONSTRAINTS[path] ?? []) {
		const value = normalized[constraint.key];
		if (value === undefined) continue;
		const canonical = typeof value === "number"
			? Number.isSafeInteger(value)
			: typeof value === "string" && /^(0|[1-9]\d*)$/u.test(value);
		const parsed = canonical ? Number(value) : Number.NaN;
		if (!Number.isSafeInteger(parsed) || parsed < constraint.minimum || parsed > constraint.maximum) {
			throw cliUsage(
				`--${constraint.flag} must be an integer from ${constraint.minimum} to ${constraint.maximum}.`,
				`Pass a valid --${constraint.flag} value.`,
			);
		}
		normalized[constraint.key] = parsed;
	}
	const formatChoices = FORMAT_OPTION_CHOICES[path];
	if (formatChoices && normalized.format !== undefined && !formatChoices.includes(String(normalized.format))) {
		throw cliUsage(
			`--format must be one of: ${formatChoices.join(", ")}.`,
			`Pass --format ${formatChoices[0]}.`,
		);
	}
	return normalized;
}

async function remoteCommandOptions(command: Command, global: GlobalOpts): Promise<Record<string, unknown>> {
	const opts = command.opts() as Record<string, unknown>;
	const path = commandPath(command);
	if (path !== "users create") return normalizeRemoteInputs(path, opts);
	const passwordStdin = opts.passwordStdin === true;
	const passwordPrompt = opts.passwordPrompt === true;
	if (passwordStdin && passwordPrompt) {
		throw passwordInputError(
			"USER_CREATE_PASSWORD_SOURCE_CONFLICT",
			"Use only one initial password input mode.",
			"Choose either --password-stdin or --password-prompt, or omit both to issue a setup token.",
		);
	}
	delete opts.passwordStdin;
	delete opts.passwordPrompt;
	if (passwordStdin) opts.password = await readPasswordFromStdin();
	if (passwordPrompt) {
		const eligibility = interactionEligibility({
			noInput: global.noInput,
			json: global.json,
			machineOutput: global.jsonl || global.quiet || Boolean(global.jq) || global.output !== undefined,
		});
		if (!eligibility.eligible) {
			throw passwordInputError(
				"USER_CREATE_PASSWORD_PROMPT_NONINTERACTIVE",
				`--password-prompt requires interactive input (${eligibility.reason}).`,
				"Use --password-stdin for CI, or omit password options to issue a setup token.",
			);
		}
		opts.password = await readPasswordFromPrompt();
	}
	return normalizeRemoteInputs(path, opts);
}

function groupCommandAction(this: Command): void {
	const g = globals(this);
	if (selectOutputFormat(g) === "human") {
		process.stdout.write(`${this.helpInformation()}\n`);
		return;
	}
	const path = commandPath(this);
	throw cliUsage(
		`A subcommand is required for ${path}.`,
		`Run clearance ${path} --help to list available subcommands.`,
	);
}

function configureGroupActions(command: Command): void {
	for (const child of command.commands) {
		configureGroupActions(child);
		// `completion` intentionally keeps its shorthand action (`completion zsh`).
		// Every other group is navigation-only and should own a useful bare action
		// instead of Commander's internal `(outputHelp)` error.
		if (child.commands.length > 0 && commandPath(child) !== "completion") {
			child.action(groupCommandAction);
		}
	}
}

/**
 * Execute one operational command through the authenticated management API.
 * Commander binds `this` to the leaf command, preserving each command's own
 * arguments and options while keeping workflow execution in one place.
 */
async function remoteCommandAction(this: Command): Promise<void> {
	const g = globals(this);
	const path = commandPath(this);
	const operation = MANAGEMENT_OPERATIONS.find((candidate) => candidate.cliPath === path);
	let target: { principal?: string; apiOrigin?: string } = {
		...(g.profile ? { principal: g.profile } : {}),
		...(g.apiUrl ? { apiOrigin: g.apiUrl } : {}),
	};
	try {
		validateOutputSelector(g);
		if (!operation) throw new Error(`No canonical operation exists for ${path}.`);
		const opts = await remoteCommandOptions(this, g);
		const session = await resolveApiSession({
			profile: g.profile,
			apiUrl: g.apiUrl,
		});
		if (!session) {
			throw new ClearanceError({
				code: "CLI_LOGIN_REQUIRED",
				message: "An authenticated Clearance API profile is required.",
				stage: "cli.dispatch",
				status: 401,
				remediation:
					"Run clearance login --profile <name> for the intended API origin.",
			});
		}
		target = {
			principal: session.credentialSource === "saved" ? session.profile : "environment",
			apiOrigin: session.apiUrl,
		};
		const run = await operationRunner.run({
			operation: {
				id: operation.id,
				path,
				mutation: operation.mutation,
				confirmation: operation.confirmation,
			},
			command: clearanceCommandFromArgv(process.argv),
			target,
			dryRun: g.dryRun,
			live: opts.live === true,
			confirmed: g.yes,
			signal: g.signal,
			secretValues: typeof opts.password === "string" ? [opts.password] : [],
			execute: async ({ signal, markDispatched }) => {
				if (g.dryRun && !operation.supportsDryRun) {
					throw new ClearanceError({
						code: "CLI_REMOTE_DRY_RUN_UNSUPPORTED",
						message: `${path} does not expose a server-side dry-run contract.`,
						stage: "cli.dispatch",
						status: 400,
						remediation: "Review the target, then run the command without --dry-run.",
					});
				}
				let transportStarted = false;
				const dispatchSession = {
					...session,
					operationObserver: {
						onDispatch() {
							if (!transportStarted) {
								transportStarted = true;
								markDispatched();
							}
						},
						onMetadata(metadata: { requestId?: string; idempotencyKey?: string }) {
							markDispatched(metadata);
						},
					},
				};
				const data = await dispatchRemoteCommand({
					session: dispatchSession,
					path,
					args: this.processedArgs,
					opts,
					global: { ...g, signal },
				});
				return { data };
			},
		});
		if (run.cause !== undefined) {
			fail(run.cause, g, {
				receipt: run.receipt,
				receiptPersistence: run.receiptPersistence,
				...(run.receiptPersistenceError ? { receiptPersistenceError: run.receiptPersistenceError } : {}),
				...(run.receiptPersistencePath ? { receiptPersistencePath: run.receiptPersistencePath } : {}),
			});
		}
		if (!isEventStreamResult(run.data)) {
			printResult(g, run.data, operationHumanPresentation(
				path,
				operation.mutation,
				run.data,
				run.receipt,
				{
					status: run.receiptPersistence,
					...(run.receiptPersistencePath ? { path: run.receiptPersistencePath } : {}),
					...(run.receiptPersistenceError ? { error: run.receiptPersistenceError } : {}),
				},
			));
		}
		if (
			path === "doctor" &&
			run.data !== null &&
			typeof run.data === "object" &&
			(run.data as { ok?: unknown }).ok === false
		) {
			throw new CliExitError(2);
		}
	} catch (cause) {
		if (cause instanceof CliExitError) throw cause;
		if (operation?.mutation) {
			const failed = await operationRunner.run({
				operation: {
					id: operation.id,
					path,
					mutation: true,
					confirmation: "none",
				},
				command: clearanceCommandFromArgv(process.argv),
				target,
				dryRun: g.dryRun,
				confirmed: true,
				secretValues: [],
				execute: async () => { throw cause; },
			});
			fail(cause, g, {
				receipt: failed.receipt,
				receiptPersistence: failed.receiptPersistence,
				...(failed.receiptPersistenceError ? { receiptPersistenceError: failed.receiptPersistenceError } : {}),
				...(failed.receiptPersistencePath ? { receiptPersistencePath: failed.receiptPersistencePath } : {}),
			});
		}
		fail(cause, g);
	}
}

async function schemaMigrateAction(this: Command): Promise<void> {
	const opts = this.opts() as Record<string, unknown>;
	if (opts.local !== true) {
		await remoteCommandAction.call(this);
		return;
	}
	const g = globals(this);
	try {
		const run = await runLocalMutation({
			operation: LOCAL_MUTATION_CONTRACTS.schemaMigrate,
			global: g,
			target: { resource: "runtime-schema", environment: "local" },
			reconciliationCommands: ["clearance schema status"],
			prepare: () => {
				if (g.profile || g.apiUrl) {
					throw new ClearanceError({
						code: "SCHEMA_LOCAL_MIGRATION_REMOTE_FLAGS_INVALID",
						message: "Local schema migration cannot use an API profile or URL.",
						stage: "schema.migrate.local",
						remediation: "Remove --profile and --api-url from the one-shot migration command.",
					});
				}
				if (!g.dryRun && !g.yes) {
					throw new ClearanceError({
						code: "SCHEMA_MIGRATE_CONFIRMATION_REQUIRED",
						message: "Local schema migration requires explicit confirmation.",
						stage: "schema.migrate.local",
						remediation: "Review --dry-run, then pass --local --yes.",
					});
				}
				if (!g.dryRun && (typeof opts.drainId !== "string" || opts.drainId.trim().length === 0)) {
					throw new ClearanceError({
						code: "SCHEMA_MIGRATE_DRAIN_ID_REQUIRED",
						message: "Local schema migration requires the exact armed drain ID.",
						stage: "schema.migrate.local",
						remediation: "Pass --local --drain-id <id> --yes from the one-shot migrator.",
					});
				}
				return {
					dryRun: Boolean(g.dryRun),
					drainId: typeof opts.drainId === "string" ? opts.drainId : undefined,
				};
			},
			mutate: (migration) => migrateRuntimeSchemaLocally(migration),
		});
		if (run.cause !== undefined) failLocalMutation(run, g);
		printResult(g, run.data, localMutationPresentation("schema migrate", run));
	} catch (cause) {
		if (cause instanceof CliExitError) throw cause;
		fail(cause, g);
	} finally {
		await closeAuthBundle().catch(() => undefined);
	}
}

async function main() {
	const program = new Command("clearance");
	program.exitOverride((cause) => {
		if (cause.code === "commander.helpDisplayed" || cause.code === "commander.version") {
			throw new CliExitError(0);
		}
		throw new ClearanceError({
			code: "CLI_USAGE",
			message: cause.message,
			stage: "cli.usage",
			status: 400,
			remediation: "Run clearance --help to see valid commands and options.",
		});
	});
	// Commander otherwise writes a diagnostic before exitOverride can route it
	// through the stable human or machine error protocol.
	program.configureOutput({ writeErr: () => undefined });
	program.addHelpCommand(false);
	program
		.version(VERSION)
		.description("Clearance CLI — open-source auth operations")
		.option("--json", "Deprecated raw JSON compatibility output", false)
		.option("--jsonl", "Stable compact JSON Lines output", false)
		.option("--quiet", "Suppress successful output", false)
		.option("--jq <expression>", "Select machine output with the built-in jq subset")
		.option("--output-format <format>", "Output format: human, json, jsonl, or quiet", parseOutputFormat)
		.option("--no-input", "Disable prompts (CI/agents)")
		.option("--yes", "Confirm destructive actions", false)
		.option("--dry-run", "Preview mutations", false)
		.option("--profile <name>", "Saved API profile")
		.option("--api-url <url>", "Clearance management API origin override");
	program.hook("preAction", (_command, actionCommand) => {
		validateOutputSelector(globals(actionCommand));
	});

	program.action(async () => {
		const g = globals(program);
		const result = await runFirstRunExperience({
			json: g.json,
			machineOutput: Boolean(g.jsonl || g.quiet || g.jq || g.output === "json" || g.output === "jsonl" || g.output === "quiet"),
			noInput: g.noInput,
			callbacks: {
				resumeProfile: async () => {
					const profile = normalizeProfile(g.profile, process.env);
					const saved = await readSavedCredential(process.env, profile);
					if (!saved) return null;
					try {
						const whoami = await verifyOperatorCredential(saved.apiUrl, saved.token);
						return {
							apiUrl: saved.apiUrl,
							profile,
							verification: {
								summary: `operator ${whoami.projectId}/${whoami.environmentId} at ${saved.apiUrl}`,
								principal: "operator",
								projectId: whoami.projectId,
								environmentId: whoami.environmentId,
							},
						};
					} catch {
						return null;
					}
				},
				verifyConnection: async ({ apiUrl, token }) => {
					const normalizedUrl = normalizeApiUrl(apiUrl, {});
					const whoami = await verifyOperatorCredential(normalizedUrl, token);
					return {
						summary: `operator ${whoami.projectId}/${whoami.environmentId} at ${normalizedUrl}`,
						principal: "operator",
						projectId: whoami.projectId,
						environmentId: whoami.environmentId,
					};
				},
				saveProfile: async ({ apiUrl, profile, token }) => {
					await writeSavedCredential(
						{ apiUrl: normalizeApiUrl(apiUrl, {}), token },
						process.env,
						normalizeProfile(profile, process.env),
					);
				},
				installCompletion: async (shell) => {
					const document = buildCommandSpecDocument({ program, supplementalCommands });
					const installed = await installCompletion({
						shell,
						content: renderCompletion(shell, document, program.options),
					});
					return {
						summary: `Shell completion ${installed.action}: ${installed.projected.path}`,
						state: installed.action === "refreshed" ? "installed" : installed.action,
					};
				},
				installSkill: async () => {
					const installed = await installClearanceAgentSkill({
						directory: join(homedir(), ".agents", "skills"),
					});
					return {
						summary: `Agent skill ${installed.action}: ${installed.projected.path}`,
						state: installed.action === "refreshed" ? "installed" : installed.action,
					};
				},
				previewFirstOperation: async ({ profile }) => ({
					summary: "List users from the connected environment",
					command: `clearance --profile ${shellWord(normalizeProfile(profile, process.env))} users list`,
				}),
				runFirstOperation: async ({ profile }) => {
					const selectedProfile = normalizeProfile(profile, process.env);
					const saved = await readSavedCredential(process.env, selectedProfile);
					if (!saved) {
						throw localSetupError(
							"CLI_PROFILE_NOT_SAVED",
							`Profile ${selectedProfile} was not available after setup.`,
							"Run clearance login, then clearance users list.",
							70,
						);
					}
					const data = await dispatchRemoteCommand({
						session: {
							apiUrl: saved.apiUrl,
							token: saved.token,
							profile: selectedProfile,
							credentialSource: "saved",
						},
						path: "users list",
						args: [],
						opts: {},
						global: { signal: g.signal },
					});
					const listed = listResult(data);
					return { summary: listed ? `Setup complete. Found ${listed.rows.length} ${listed.name}.` : "Setup complete. First operation succeeded." };
				},
			},
		});
		if (result.status === "unavailable") {
			const document = buildCommandSpecDocument({ program, supplementalCommands });
			const parity = compareCommanderParity(program, { supplementalCommands });
			printResult(g, { ...document, experience: buildExperienceManifest(document), parity }, {
				human: humanCommandListing(document.commands),
				summary: "Clearance command discovery",
				next: ["clearance commands", "clearance --help"],
			});
		}
	});

	program
		.command("init")
		.description("Initialize a Clearance project and development environment")
		.option("--name <name>", "Project name", "clearance-app")
		.option("--environment <name>", "Environment name", "development")
		.action(remoteCommandAction);

	program
		.command("doctor")
		.description("Check local setup and unauthenticated API reachability")
		.option("--remote", "Run the authenticated server-side doctor instead", false)
		.action(async function (this: Command, options: { remote?: boolean }) {
			if (options.remote) {
				await remoteCommandAction.call(this);
				return;
			}
			const g = globals(this);
			const shell = detectedCompletionShell();
			const skillDirectory = join(homedir(), ".agents", "skills");
			const result = await runLocalDoctor({
				profile: normalizeProfile(g.profile, process.env),
				apiOrigin: normalizeApiUrl(g.apiUrl, process.env),
			}, {
				cliVersion: () => VERSION,
				inspectConfig: inspectLocalConfig,
				inspectProfile: inspectLocalProfile,
				inspectSkill: async () => featureInspection(await inspectClearanceAgentSkill(skillDirectory)),
				inspectCompletion: async () => shell
					? featureInspection(await inspectCompletionInstallation(completionInstallationPath(shell)))
					: { state: "unavailable", detail: "Set SHELL to bash, zsh, or fish." },
				fetch: globalThis.fetch,
			});
			const next = result.checks.flatMap((check) => check.status === "pass" ? [] : (
				check.id === "profile" ? ["clearance login --profile <name>"]
					: check.id === "completion" && shell ? [`clearance completion install ${shell}`]
						: check.id === "skill" ? ["clearance skill install"] : []
			));
			printResult(g, result, {
				human: [
					renderLocalDoctor(result),
					...(next.length > 0 ? [["Next:", ...next.map((command) => `  - ${command}`)].join("\n")] : []),
				].join("\n\n"),
				summary: result.ok ? "Local setup is healthy." : "Local setup needs attention.",
				next,
			});
			if (!result.ok) throw new CliExitError(2);
		});

	program
		.command("dev")
		.description("Show verified local development startup paths")
		.action(remoteCommandAction);

	// project
	const project = program.command("project").description("Project resources");
	project
		.command("list")
		.action(remoteCommandAction);
	project
		.command("inspect")
		.argument("[id]")
		.action(remoteCommandAction);
	project
		.command("create")
		.requiredOption("--name <name>")
		.action(remoteCommandAction);

	// env
	const env = program.command("env").description("Environments");
	env
		.command("list")
		.action(remoteCommandAction);
	env
		.command("inspect")
		.description("Inspect environment and API configuration status (no secrets)")
		.argument("[id]", "Environment id/slug (defaults to operator principal env)")
		.action(remoteCommandAction);
	env
		.command("create")
		.requiredOption("--name <name>")
		.option("--project-id <id>")
		.option("--kind <kind>", "development|preview|production", "development")
		.action(remoteCommandAction);
	env
		.command("promote")
		.description(
			"Plan environment promotion (validated plan/dry-run; apply blocked without Deployment resource)",
		)
		.requiredOption("--to <id>", "Target environment id or slug")
		.option("--from <id>", "Source environment id/slug (defaults to principal env)")
		.action(remoteCommandAction);

	// users
	const users = program.command("users").description("Users / principals");
	users
		.command("list")
		.option("--limit <n>", "Page size (enables keyset cursor pagination)")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(remoteCommandAction);
	users
		.command("inspect")
		.argument("<id>")
		.action(remoteCommandAction);
	users
		.command("create")
		.requiredOption("--email <email>")
		.requiredOption("--name <name>")
		.option("--password-stdin", "Read an initial password from piped standard input (maximum 4096 bytes)", false)
		.option("--password-prompt", "Prompt for an initial password without terminal echo (TTY only)", false)
		.action(remoteCommandAction);
	users
		.command("update")
		.argument("<id>")
		.option("--name <name>", "Display name")
		.option("--email <email>", "Primary email")
		.option("--status <status>", "active|disabled")
		.action(remoteCommandAction);
	users
		.command("disable")
		.argument("<id>")
		.action(remoteCommandAction);
	users
		.command("delete")
		.argument("<id>")
		.action(remoteCommandAction);
	users
		.command("export")
		.description("Export scoped users (bounded, redacted, deterministic)")
		.requiredOption(
			"--output <path>",
			"Output file path (required; refuse overwrite unless --force)",
		)
		.option("--format <fmt>", "json|jsonl", "json")
		.option("--limit <n>", `Max records (1-${USERS_EXPORT_MAX_LIMIT})`, "100")
		.option("--status <status>", "Filter active|disabled")
		.option("--force", "Overwrite existing output file", false)
		.action(remoteCommandAction);

	// orgs — same canonical management ops as API
	const orgs = program.command("orgs").description("Organizations");
	orgs
		.command("list")
		.option("--limit <n>", "Page size (enables keyset cursor pagination)")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(remoteCommandAction);
	orgs
		.command("inspect")
		.argument("<id>")
		.action(remoteCommandAction);
	orgs
		.command("create")
		.requiredOption("--name <name>")
		.option("--slug <slug>")
		.option("--owner-user <id>", "Runtime owner user id (defaults to first active principal)")
		.action(remoteCommandAction);
	orgs
		.command("update")
		.argument("<id>")
		.option("--name <name>", "Display name")
		.option("--slug <slug>", "URL slug (lowercase)")
		.action(remoteCommandAction);
	orgs
		.command("archive")
		.argument("<id>")
		.description("Archive an organization (requires --yes; supports --dry-run)")
		.action(remoteCommandAction);

	const members = orgs.command("members").description("Organization members");
	members
		.command("import")
		.requiredOption("--org <id>")
		.requiredOption("--file <path>")
		.option("--format <format>", "json|csv (defaults from file extension)")
		.action(remoteCommandAction);
	members
		.command("list")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);
	members
		.command("add")
		.requiredOption("--org <id>")
		.requiredOption("--user <id>")
		.option("--role <role>", "Role slug (default: member)", "member")
		.action(remoteCommandAction);
	members
		.command("update")
		.requiredOption("--org <id>")
		.option("--user <id>", "User id of the member")
		.option("--member <id>", "Membership id")
		.requiredOption("--role <role>", "New role slug")
		.action(remoteCommandAction);
	members
		.command("remove")
		.requiredOption("--org <id>")
		.option("--user <id>", "User id of the member")
		.option("--member <id>", "Membership id")
		.action(remoteCommandAction);

	const authorization = orgs
		.command("authorization")
		.description("Normalized organization authorization");
	const authorizationEffective = authorization
		.command("effective")
		.description("Inspect a subject's effective organization authorization");
	authorizationEffective
		.requiredOption("--org <id>", "Organization id")
		.requiredOption("--subject <id>", "User or service-account id")
		.requiredOption("--subject-kind <kind>", "principal|service_account")
		.action(remoteCommandAction);
	const authorizationAssignments = authorization
		.command("assignments")
		.description("Inspect or replace normalized role assignments");
	authorizationAssignments
		.command("list")
		.requiredOption("--org <id>", "Organization id")
		.option("--subject <id>", "Optional principal or service-account id")
		.option("--subject-kind <kind>", "principal|service_account; requires --subject")
		.action(remoteCommandAction);
	authorizationAssignments
		.command("replace")
		.requiredOption("--org <id>", "Organization id")
		.requiredOption("--subject <id>", "User or service-account id")
		.requiredOption("--subject-kind <kind>", "principal|service_account")
		.option("--role <id>", "Role id; repeat for each assigned role", (value, previous: string[] = []) => [...previous, value], [])
		.option("--expected-revision <revision>", "Require this current authorization revision")
		.action(remoteCommandAction);
	authorization
		.command("reconcile")
		.description("Preview organization authorization reconciliation; pass --yes to apply")
		.requiredOption("--org <id>", "Organization id")
		.action(remoteCommandAction);

	const serviceAccounts = orgs
		.command("service-accounts")
		.description("Organization service accounts and credentials");
	serviceAccounts
		.command("list")
		.requiredOption("--org <id>", "Organization id")
		.action(remoteCommandAction);
	serviceAccounts
		.command("inspect")
		.argument("<accountId>", "Service-account id")
		.requiredOption("--org <id>", "Organization id")
		.action(remoteCommandAction);
	serviceAccounts
		.command("create")
		.requiredOption("--org <id>", "Organization id")
		.requiredOption("--name <name>", "Human-readable service-account name")
		.option("--role <id>", "Role id; repeat for each assignment", (value, previous: string[] = []) => [...previous, value], [])
		.action(remoteCommandAction);
	serviceAccounts
		.command("disable")
		.argument("<accountId>", "Service-account id")
		.requiredOption("--org <id>", "Organization id")
		.action(remoteCommandAction);
	serviceAccounts
		.command("enable")
		.argument("<accountId>", "Service-account id")
		.requiredOption("--org <id>", "Organization id")
		.action(remoteCommandAction);
	const serviceAccountCredentials = serviceAccounts
		.command("credentials")
		.description("Service-account credential lifecycle");
	serviceAccountCredentials
		.command("create")
		.argument("<accountId>", "Service-account id")
		.requiredOption("--org <id>", "Organization id")
		.option("--expires-at <iso-timestamp>", "Optional absolute ISO-8601 expiry")
		.option("--operation-id <uuid>", "Stable UUID for live retry recovery")
		.action(remoteCommandAction);
	serviceAccountCredentials
		.command("rotate")
		.argument("<accountId>", "Service-account id")
		.argument("<credentialId>", "Credential id")
		.requiredOption("--org <id>", "Organization id")
		.option("--expires-at <iso-timestamp>", "Optional absolute ISO-8601 expiry")
		.option("--operation-id <uuid>", "Stable UUID for live retry recovery")
		.action(remoteCommandAction);
	serviceAccountCredentials
		.command("revoke")
		.argument("<accountId>", "Service-account id")
		.argument("<credentialId>", "Credential id")
		.requiredOption("--org <id>", "Organization id")
		.action(remoteCommandAction);

	// events — list / tail / inspect / export / replay (shared management services)
	const events = program.command("events").description("Audit events");
	events
		.command("list")
		.option("--limit <n>", "50")
		.option("--action <action>", "Filter by action")
		.option("--org <id>", "Filter by organization id")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(remoteCommandAction);
	events
		.command("tail")
		.description("Stream scoped audit events by polling the management API")
		.option("--limit <n>", `Initial history (1-${EVENTS_TAIL_MAX_LIMIT})`, "20")
		.option("--poll-interval <milliseconds>", `Refresh interval (${EVENTS_TAIL_MIN_POLL_INTERVAL_MS}-${EVENTS_TAIL_MAX_POLL_INTERVAL_MS}ms)`, "1000")
		.option("--max-events <n>", "Exit after N events; 0 means unlimited", "0")
		.option("--once", "Emit initial history and exit", false)
		.option("--action <action>", "Filter by action")
		.option("--org <id>", "Filter by organization id")
		.action(remoteCommandAction);
	events
		.command("inspect")
		.argument("<id>", "Event id or diagnostic trace id")
		.action(remoteCommandAction);
	events
		.command("export")
		.description("Export scoped audit events (bounded, redacted, deterministic)")
		.requiredOption("--output <path>", "Output file path (required; refuse overwrite unless --force)")
		.option("--format <fmt>", "json|jsonl", "json")
		.option("--limit <n>", `Max records (1-${EVENTS_EXPORT_MAX_LIMIT})`, "100")
		.option("--action <action>", "Filter by action")
		.option("--org <id>", "Filter by organization id")
		.option(
			"--before <iso-timestamp>",
			"Export only events created strictly before this ISO-8601 timestamp (archival bound)",
		)
		.option("--force", "Overwrite existing output file", false)
		.action(remoteCommandAction);
	events
		.command("replay")
		.description(
			"Re-record a SCIM diagnostic trace (default dry-run; --yes to apply)",
		)
		.argument("<id>", "SCIM diagnostic trace id")
		.action(remoteCommandAction);

	registerDeliveryCommands(program, remoteCommandAction);
	registerAuthenticationPolicyCommands(program, remoteCommandAction);
	registerProductPresentationCommands(program, remoteCommandAction);
	registerKeyManagementCommands(program, remoteCommandAction);

	// keys — digest-only project/environment scoped API-key lifecycle
	const keys = program.command("keys").description("Project and environment API keys");
	keys.command("list").option("--include-revoked", "Include revoked keys", false).action(remoteCommandAction);
	keys.command("create").requiredOption("--name <name>", "Human-readable key name")
			.option("--scope <scope>", "Repeatable resource:action scope", (value, previous: string[] = []) => [...previous, value], [])
			.option("--expires-at <iso-timestamp>", "Optional absolute ISO-8601 expiry")
			.action(remoteCommandAction);
	keys.command("rotate").argument("<id>", "API key id").action(remoteCommandAction);
	keys.command("revoke").argument("<id>", "API key id").action(remoteCommandAction);

	// sessions — list / revoke under principal-derived scope
	const sessions = program.command("sessions").description("Auth sessions");
	sessions
		.command("list")
		.option("--limit <n>", "Max sessions to return (page size)", "100")
		.option("--cursor <cursor>", "Opaque cursor from a previous page's nextCursor")
		.action(remoteCommandAction);
	sessions
		.command("revoke")
		.argument("<id>", "Stable session id")
		.action(remoteCommandAction);

	// roles — canonical project/environment-scoped role services shared with API/console
	const roles = program.command("roles").description("Custom access-control roles");
	roles
		.command("list")
		.action(remoteCommandAction);
	roles
		.command("validate")
		.option("--name <name>")
		.option("--slug <slug>")
		.option("--permission <permission...>", "One or more resource:action permissions")
		.action(remoteCommandAction);
	roles
		.command("create")
		.requiredOption("--name <name>")
		.option("--slug <slug>")
		.option("--description <description>")
		.requiredOption("--permission <permission...>", "One or more resource:action permissions")
		.action(remoteCommandAction);
	roles
		.command("update")
		.argument("<id>")
		.option("--name <name>")
		.option("--description <description>")
		.option("--permission <permission...>", "Replacement resource:action permissions")
		.action(remoteCommandAction);

	// sso
	const sso = program.command("sso").description("Enterprise SSO connections");
	sso
		.command("create")
		.requiredOption("--org <id>")
		.requiredOption("--provider <name>")
		.option("--protocol <protocol>", "Identity protocol: oidc|saml", "oidc")
			.requiredOption("--issuer <url>")
			.option("--audience <aud>")
			.option("--domain <domain>")
			.option("--entry-point <url>", "SAML identity provider SSO URL")
			.option("--certificate <path>", "SAML identity provider signing certificate PEM")
			.action(remoteCommandAction);
	sso
		.command("configure")
		.argument("<id>")
		.option("--issuer <url>")
		.option("--audience <aud>")
		.option("--domain <domain>")
		.action(remoteCommandAction);
	sso
		.command("test")
		.argument("<id>")
		.option("--fixture <name>", "ok|wrong-issuer|wrong-audience|malformed|expired|clock-skew|replay")
		.option(
			"--live",
			"Probe the REAL configured issuer (read-only discovery/JWKS conformance). Requires --yes, HTTPS, non-loopback.",
			false,
		)
		.action(remoteCommandAction);
	sso
		.command("list")
		.option("--org <id>")
		.action(remoteCommandAction);
	sso
		.command("setup-link")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);
	sso
		.command("rotate")
		.description("Rotate SSO client-secret credential envelope under the current key")
		.argument("<id>", "SSO connection id")
		.action(remoteCommandAction);
	sso
		.command("disable")
		.description("Disable an SSO connection")
		.argument("<id>", "SSO connection id")
		.action(remoteCommandAction);

	// scim
	const scim = program.command("scim").description("SCIM directory connections");
	scim
		.command("create")
		.requiredOption("--org <id>")
		.requiredOption("--provider <name>")
		.option(
			"--endpoint <url>",
			"External SCIM base URL (required for live conformance probes)",
		)
		.action(remoteCommandAction);
	scim
		.command("test")
		.argument("<id>")
		.option("--apply", "Apply instead of dry-run", false)
		.option("--fixture <name>", "ok|malformed|unauthorized")
		.option("--scenario <name>", "users|group-lifecycle", "users")
		.option(
			"--live",
			"Probe the REAL configured SCIM endpoint (read-only GETs). Requires --yes, HTTPS, non-loopback.",
			false,
		)
		.action(remoteCommandAction);
	scim
		.command("list")
		.option("--org <id>")
		.action(remoteCommandAction);
	scim
		.command("setup-link")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);
	scim
		.command("rotate")
		.description("Rotate SCIM bearer credential envelope under the current key")
		.argument("<id>", "SCIM connection id")
		.action(remoteCommandAction);
	scim
		.command("disable")
		.description("Disable a SCIM directory connection")
		.argument("<id>", "SCIM connection id")
		.action(remoteCommandAction);
	scim
		.command("replay")
		.description(
			"Re-record a SCIM diagnostic trace (default dry-run; --yes to apply)",
		)
		.argument("<traceId>", "SCIM diagnostic trace id")
		.action(remoteCommandAction);

	// readiness
	const readiness = program.command("readiness").description("Enterprise readiness");
	readiness
		.command("check")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);
	readiness
		.command("report")
		.requiredOption("--org <id>")
		.action(remoteCommandAction);

	// migration
	const imports = program.command("import").description("Import supported auth exports");
	imports
		.command("legacy")
		.description("Preview or import a validated legacy export")
		.requiredOption("--file <path>", "Local legacy JSON export")
		.action(remoteCommandAction);

	const migration = program.command("migration").description("Tenant migration");
	migration
		.command("plan")
		.requiredOption("--source <source>", "legacy")
		.requiredOption("--fixture <path>")
		.action(remoteCommandAction);
	migration
		.command("apply")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(remoteCommandAction);
	migration
		.command("verify")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(remoteCommandAction);
	migration
		.command("rollback")
		.requiredOption("--id <planId>")
		.requiredOption("--fixture <path>")
		.action(remoteCommandAction);
	migration
		.command("status")
		.requiredOption("--id <planId>")
		.action(remoteCommandAction);

	// backup
	const backup = program.command("backup").description("Backup and restore");
	backup
		.command("create")
		.action(remoteCommandAction);
	backup
		.command("verify")
		.requiredOption("--id <backupId>")
		.action(remoteCommandAction);
	backup
		.command("restore")
		.requiredOption("--id <backupId>")
		.option("--target <database>", "Optional isolated Postgres database name beginning clearance_restore_; file targets are server-managed")
		.action(remoteCommandAction);

	// upgrade
	const upgrade = program.command("upgrade").description("Upgrade tooling");
	upgrade
		.command("check")
		.action(remoteCommandAction);
	upgrade
		.command("plan")
		.requiredOption("--target <version>", "Target release version")
		.option("--current <version>", "Current release version override")
		.action(remoteCommandAction);
	upgrade
		.command("apply")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.action(remoteCommandAction);
	upgrade
		.command("verify")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.action(remoteCommandAction);
	upgrade
		.command("rollback")
		.description("Verify a rollback in isolation, or explicitly restore the active database")
		.requiredOption("--plan <id-or-path>", "Plan ID or plan path")
		.option("--restore-active", "Restore the rollback backup into the active database", false)
		.option("--confirm <token>", "Exact RESTORE_ACTIVE:<plan-id>:<database> confirmation")
		.action(remoteCommandAction);

	// schema
	const schema = program.command("schema").description("Management and runtime schema lifecycle");
	schema
		.command("status")
		.action(remoteCommandAction);
	schema
		.command("generate")
		.description("Compile pending Clearance Postgres SQL without applying it")
		.option("--output <path>", "Output SQL file path (required)")
		.option("--force", "Overwrite an existing output artifact", false)
		.action(remoteCommandAction);
	schema
		.command("migrate")
		.description("Apply pending Clearance migrations and lifecycle compatibility ensures")
		.option("--local", "Run directly against DATABASE_URL after API replicas drain", false)
		.option("--drain-id <id>", "Exact armed credential-authority drain id")
		.action(schemaMigrateAction);
	const credentialAuthority = schema
		.command("credential-authority")
		.description("Durable credential-generation cutover fence");
	credentialAuthority
		.command("status")
		.description("Show durable phase, generation, and active runtime leases")
		.action(remoteCommandAction);
	credentialAuthority
		.command("arm")
		.requiredOption("--deployment-id <id>", "Immutable candidate deployment id")
		.requiredOption("--expected-runtimes <count>", "Exact bridge runtime lease count")
		.action(remoteCommandAction);
	credentialAuthority
		.command("drain")
		.requiredOption("--deployment-id <id>", "Armed candidate deployment id")
		.requiredOption("--drain-id <id>", "Unique cutover drain id")
		.action(remoteCommandAction);
	const storeV2 = schema
		.command("store-v2")
		.description("Normalized management-store migration");
	storeV2.command("status").description("Show store-v2 phase and parity").action(remoteCommandAction);
	storeV2.command("plan").description("Preflight the store-v2 backfill").action(remoteCommandAction);
	storeV2.command("apply").description("Backfill and enable verified dual-write").action(remoteCommandAction);
	storeV2.command("verify").description("Fail unless snapshot and relational data match").action(remoteCommandAction);
	storeV2.command("rollback").description("Disable dual-write while retaining relational data").action(remoteCommandAction);
	const storeV2Events = storeV2.command("events").description("Relational audit-event authority");
	storeV2Events.command("cutover").description("Make relational audit events authoritative").action(remoteCommandAction);
	storeV2Events.command("rollback").description("Return audit-event authority to the snapshot").action(remoteCommandAction);
	const storeV2Principals = storeV2.command("principals").description("Relational principal authority");
	storeV2Principals.command("cutover").description("Make normalized principals authoritative").action(remoteCommandAction);
	storeV2Principals.command("rollback").description("Reverse-materialize principals into the snapshot").action(remoteCommandAction);
	const storeV2Topology = storeV2.command("topology").description("Relational topology authority");
	storeV2Topology.command("cutover").description("Make normalized topology authoritative").action(remoteCommandAction);
	storeV2Topology.command("rollback").description("Reverse-materialize topology into the snapshot").action(remoteCommandAction);

	// config
	const config = program.command("config").description("Config");
	config
		.command("get")
		.argument("[key]")
		.action(remoteCommandAction);
	config
		.command("set")
		.argument("<key>")
		.argument("<value>")
		.action(remoteCommandAction);
	config
		.command("validate")
		.option("--file <json-file>", "Candidate config JSON file")
		.action(remoteCommandAction);
	config
		.command("diff")
		.requiredOption("--file <json-file>", "Candidate config JSON file")
		.action(remoteCommandAction);

	// overview for console parity
	program
		.command("overview")
		.description("Dashboard overview stats")
		.action(remoteCommandAction);

	program
		.command("login")
		.description("Validate and save an operator credential for API-backed commands")
		.option("--url <url>", "Clearance API URL")
		.option("--token-stdin", "Read an operator token from standard input", false)
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const run = await runLocalMutation({
					operation: LOCAL_MUTATION_CONTRACTS.login,
					global: g,
					target: {
						principal: g.profile ?? "default",
						...(typeof opts.url === "string" ? { apiOrigin: opts.url } : {}),
					},
					reconciliationCommands: ["clearance whoami"],
					prepare: async (redact) => {
						const profile = normalizeProfile(g.profile);
						const apiUrl = normalizeApiUrl(opts.url);
						const token = opts.tokenStdin ? await readTokenFromStdin() : environmentToken();
						if (!token) {
							throw new ClearanceError({
								code: "CLI_TOKEN_REQUIRED",
								message: "An operator token is required for login.",
								stage: "operator-auth.login",
								remediation: "Set CLEARANCE_OPERATOR_TOKEN or CLEARANCE_API_TOKEN, or pass --token-stdin.",
							});
						}
						redact(token);
						return { profile, apiUrl, token };
					},
					mutate: async ({ profile, apiUrl, token }) => {
						const whoami = await validateAndSaveCredential(apiUrl, token, process.env, profile);
						return {
							authenticated: true,
							credentialSaved: true,
							credentialSource: opts.tokenStdin ? "stdin" : "environment",
							profile,
							apiUrl,
							whoami,
						};
					},
				});
				if (run.cause !== undefined) failLocalMutation(run, g);
				printResult(g, run.data, localMutationPresentation("login", run));
			} catch (e) {
				if (e instanceof CliExitError) throw e;
				fail(e, g);
			}
		});

	program
		.command("logout")
		.description("Remove the saved operator credential")
		.action(async (_, cmd) => {
			const g = globals(cmd);
			try {
				const run = await runLocalMutation({
					operation: LOCAL_MUTATION_CONTRACTS.logout,
					global: g,
					target: { principal: g.profile ?? "default" },
					reconciliationCommands: [],
					prepare: () => normalizeProfile(g.profile),
					mutate: async (profile) => {
						const credentialRemoved = await deleteSavedCredential(process.env, profile);
						const environmentCredentialPresent = Boolean(environmentToken());
						return {
							credentialRemoved,
							idempotent: !credentialRemoved,
							environmentCredentialPresent,
							credentialSource: environmentCredentialPresent ? "environment" : "none",
							profile,
						};
					},
				});
				if (run.cause !== undefined) failLocalMutation(run, g);
				printResult(g, run.data, localMutationPresentation("logout", run));
			} catch (e) {
				if (e instanceof CliExitError) throw e;
				fail(e, g);
			}
		});

	program
		.command("whoami")
		.description("Verify the current operator credential and scope")
		.option("--url <url>", "Clearance API URL override")
		.action(async (opts, cmd) => {
			const g = globals(cmd);
			try {
				const session = await resolveApiSession({
					...(environmentToken() ? {} : { profile: g.profile }),
					apiUrl: opts.url ?? g.apiUrl,
				});
				if (session) {
					const whoami = await fetchWhoami(session.apiUrl, session.token);
					const via = session.credentialSource === "saved" ? session.profile : "environment";
					const principal = whoami.operator.type === "api_key"
						? `api-key ${whoami.operator.id}`
						: "operator";
					printResult(g, {
						authenticated: true,
						credentialSource: session.credentialSource,
						...(session.credentialSource === "saved" ? { profile: session.profile } : {}),
						apiUrl: session.apiUrl,
						...whoami,
					}, `${principal} ${whoami.projectId}/${whoami.environmentId} via ${via} (${session.apiUrl})`);
					return;
				}
				throw new ClearanceError({
					code: "CLI_LOGIN_REQUIRED",
					message: "No authenticated Clearance API profile is configured.",
					stage: "cli.auth",
					status: 401,
					remediation: "Run clearance login --profile <name> for the intended API origin.",
				});
			} catch (e) {
				fail(e, g);
			}
			});

	const supplementalCommands = [
		{ path: "login", executionClass: "authentication", mutation: true, confirmation: "none", supportsDryRun: LOCAL_MUTATION_CONTRACTS.login.supportsDryRun, agentNotes: ["Writes a validated credential to a named local profile."] },
		{ path: "logout", executionClass: "authentication", mutation: true, confirmation: "none", supportsDryRun: LOCAL_MUTATION_CONTRACTS.logout.supportsDryRun, agentNotes: ["Removes only the selected saved profile credential."] },
		{ path: "whoami", executionClass: "authentication", mutation: false, confirmation: "none", supportsDryRun: false },
		{ path: "commands", executionClass: "discovery", mutation: false, confirmation: "none", supportsDryRun: false },
		{ path: "help", executionClass: "discovery", mutation: false, confirmation: "none", supportsDryRun: false },
		{ path: "completion generate", executionClass: "discovery", mutation: false, confirmation: "none", supportsDryRun: false },
		{ path: "completion status", executionClass: "local", mutation: false, confirmation: "none", supportsDryRun: false },
		{ path: "completion install", executionClass: "local", mutation: true, confirmation: "none", supportsDryRun: LOCAL_MUTATION_CONTRACTS.completionInstall.supportsDryRun, agentNotes: ["Refuses to overwrite unowned or newer completion content."] },
		{ path: "skill status", executionClass: "local", mutation: false, confirmation: "none", supportsDryRun: false },
		{ path: "skill install", executionClass: "local", mutation: true, confirmation: "none", supportsDryRun: LOCAL_MUTATION_CONTRACTS.skillInstall.supportsDryRun, agentNotes: ["Refuses to overwrite unowned skill content."] },
		{ path: "tui", executionClass: "interactive", mutation: false, confirmation: "none", supportsDryRun: false, agentNotes: ["Requires an interactive terminal; every action displays its CLI equivalent."] },
	] satisfies readonly SupplementalCommandSpec[];

	program
		.command("help [topic]")
		.description("Browse curated operator help by task")
		.action((topic: string | undefined, _options, command: Command) => {
			const topics = listHumanHelpTopics();
			const selected = topic ? topics.find((item) => item.id === topic) : undefined;
			if (topic && !selected) {
				throw new ClearanceError({
					code: "CLI_HELP_TOPIC_NOT_FOUND",
					message: `Unknown help topic: ${topic}`,
					stage: "cli.help",
					status: 400,
					remediation: "Run clearance help to list curated topics.",
				});
			}
			printResult(globals(command), selected ?? { topics }, {
				human: renderHumanHelp(topic, process.stdout.columns ?? 80),
				summary: topic ? `Clearance help: ${topic}` : `${topics.length} curated help topics.`,
				next: topic ? [] : topics.map((item) => `clearance help ${item.id}`),
			});
		});

	program
		.command("commands")
		.description("Describe the complete CLI surface for humans and agents")
		.action((_, command) => {
			const document = buildCommandSpecDocument({ program, supplementalCommands });
			const parity = compareCommanderParity(program, { supplementalCommands });
			printResult(globals(command), { ...document, experience: buildExperienceManifest(document), parity }, {
				human: humanCommandListing(document.commands),
				summary: `${document.commands.length} commands; contract parity ${parity.matches ? "verified" : "failed"}.`,
				next: ["clearance completion zsh", "clearance skill install --dry-run"],
			});
		});

	const completion = program
		.command("completion")
		.description("Generate, inspect, or safely install shell completion")
		.argument("[shell]", "Compatibility shorthand for completion generate <shell>")
		.action((shell: string | undefined) => {
			if (!supportedCompletionShell(shell)) {
				throw new ClearanceError({
					code: "CLI_USAGE",
					message: "Choose bash, zsh, or fish.",
					stage: "cli.usage",
					status: 400,
					remediation: "Run clearance completion generate zsh or clearance completion zsh.",
				});
			}
			const document = buildCommandSpecDocument({ program, supplementalCommands });
			process.stdout.write(`${renderCompletion(shell, document, program.options)}\n`);
		});
	completion
		.command("generate")
		.description("Generate completion source on standard output")
		.argument("<shell>", "bash, zsh, or fish")
		.action((shell: string) => {
			if (!supportedCompletionShell(shell)) {
				throw localSetupError("CLI_COMPLETION_SHELL_INVALID", "Unsupported completion shell.", "Choose bash, zsh, or fish.", 400);
			}
			const document = buildCommandSpecDocument({ program, supplementalCommands });
			process.stdout.write(`${renderCompletion(shell, document, program.options)}\n`);
		});
	completion
		.command("status")
		.description("Inspect completion ownership without writing")
		.argument("<shell>", "bash, zsh, or fish")
		.option("--path <path>", "Exact completion file path override")
		.action(async (shell: string, options: { path?: string }, command: Command) => {
			if (!supportedCompletionShell(shell)) {
				throw localSetupError("CLI_COMPLETION_SHELL_INVALID", "Unsupported completion shell.", "Choose bash, zsh, or fish.", 400);
			}
			const inspection = await inspectCompletionInstallation(completionInstallationPath(shell, { path: options.path }));
			printResult(globals(command), inspection, {
				summary: inspection.exists
					? `Shell completion ${inspection.owned ? "is managed by Clearance" : "has an ownership conflict"}: ${inspection.path}`
					: `Shell completion is not installed: ${inspection.path}`,
				next: inspection.exists ? [] : [`clearance completion install ${shell}`],
			});
			if (inspection.exists && !inspection.owned) throw new CliExitError(CLI_EXIT_CODE.conflict);
			if (!inspection.exists) throw new CliExitError(CLI_EXIT_CODE.checkFailed);
		});
	completion
		.command("install")
		.description("Install completion without overwriting unowned content")
		.argument("<shell>", "bash, zsh, or fish")
		.option("--path <path>", "Exact completion file path override")
		.action(async (shell: string, options: { path?: string }, command: Command) => {
			const g = globals(command);
			const run = await runLocalMutation({
				operation: LOCAL_MUTATION_CONTRACTS.completionInstall,
				global: g,
				target: { resource: options.path ?? `completion:${shell}`, environment: "local" },
				reconciliationCommands: [`clearance completion status ${shell}`],
				prepare: () => {
					if (!supportedCompletionShell(shell)) {
						throw localSetupError("CLI_COMPLETION_SHELL_INVALID", "Unsupported completion shell.", "Choose bash, zsh, or fish.", 400);
					}
					const document = buildCommandSpecDocument({ program, supplementalCommands });
					return { shell, content: renderCompletion(shell, document, program.options) };
				},
				mutate: ({ shell: selectedShell, content }) => installCompletion({
					shell: selectedShell,
					content,
					path: options.path,
					dryRun: g.dryRun,
				}),
			});
			if (run.cause !== undefined) failLocalMutation(run, g);
			const result = run.data!;
			const presentation = localMutationPresentation("completion install", run);
			printResult(g, result, {
				...presentation,
				summary: `Shell completion ${result.action}: ${result.projected.path}`,
				notice: result.activation,
				next: result.action === "conflict"
					? ["Move or rename the unowned completion file, then retry."]
					: [],
			});
			if (result.action === "conflict") throw new CliExitError(CLI_EXIT_CODE.conflict);
		});

	const skill = program.command("skill").description("Manage the bundled Clearance agent skill");
	skill.command("status")
		.option("--directory <path>", "Agent skills root directory", join(homedir(), ".agents", "skills"))
		.action(async (options, command) => {
			printResult(globals(command), await inspectClearanceAgentSkill(String(options.directory)));
		});
	skill.command("install")
		.option("--directory <path>", "Agent skills root directory", join(homedir(), ".agents", "skills"))
		.action(async (options, command) => {
			const g = globals(command);
			const directory = String(options.directory);
			const run = await runLocalMutation({
				operation: LOCAL_MUTATION_CONTRACTS.skillInstall,
				global: g,
				target: { resource: directory, environment: "local" },
				reconciliationCommands: ["clearance skill status"],
				prepare: () => undefined,
				mutate: () => installClearanceAgentSkill({ directory, dryRun: g.dryRun }),
			});
			if (run.cause !== undefined) failLocalMutation(run, g);
			const result = run.data!;
			const presentation = localMutationPresentation("skill install", run);
			printResult(g, result, {
				...presentation,
				summary: `Clearance agent skill ${result.action}: ${result.projected.path}`,
				next: result.action === "conflict" ? ["Move or rename the unowned destination, then retry."] : [],
			});
			if (result.action === "conflict") throw new CliExitError(CLI_EXIT_CODE.conflict);
		});

	program.command("tui")
		.description("Open the interactive Clearance operations workspace")
		.option("--user <id>", "Open a user")
		.option("--organization <id>", "Open an organization")
		.option("--event <id>", "Open an audit event")
		.option("--delivery <id>", "Open a delivery")
		.option("--sso <id>", "Open an SSO connection")
		.option("--scim <id>", "Open a SCIM connection")
		.option("--open <target...>", "Open <resource> <id> (user, organization, event, delivery, sso, or scim)")
		.action(async (tuiOptions, command) => {
			const g = globals(command);
			const eligibility = interactionEligibility({
				noInput: g.noInput,
				json: g.json,
				machineOutput: Boolean(g.jsonl || g.quiet || g.jq || g.output === "json" || g.output === "jsonl" || g.output === "quiet"),
			});
			if (!eligibility.eligible) {
				throw new ClearanceError({
					code: "CLI_INTERACTIVE_REQUIRED",
					message: `The TUI requires an interactive terminal (${eligibility.reason}).`,
					stage: "cli.tui",
					remediation: "Run clearance tui in a terminal, or use clearance commands --output-format json for automation.",
				});
			}
			const session = await resolveApiSession({ profile: g.profile, apiUrl: g.apiUrl });
			if (!session) {
				throw new ClearanceError({
					code: "CLI_LOGIN_REQUIRED",
					message: "An authenticated Clearance API profile is required.",
					stage: "cli.tui",
					status: 401,
					remediation: "Run clearance login --profile <name>, then clearance --profile <name> tui.",
				});
			}
			const deepLinkArgs = ["tui"];
			for (const flag of ["user", "organization", "event", "delivery", "sso", "scim"] as const) {
				if (typeof tuiOptions[flag] === "string") deepLinkArgs.push(`--${flag}`, tuiOptions[flag]);
			}
			if (Array.isArray(tuiOptions.open)) deepLinkArgs.push("--open", ...tuiOptions.open.map(String));
			const document = buildCommandSpecDocument({ program, supplementalCommands });
			await runTerminalUi({
				executor: createRemoteWorkflowExecutor(session, g),
				manifest: buildExperienceManifest(document),
				initialTarget: parseTuiDeepLink(deepLinkArgs),
			});
		});

	configureGroupActions(program);

	try {
		await program.parseAsync();
	} catch (cause) {
		if (cause instanceof CommanderError) {
			fail(new ClearanceError({
				code: "CLI_USAGE",
				message: cause.message,
				stage: "cli.usage",
				status: 400,
				remediation: "Run clearance --help to see valid commands and options.",
			}), globals(program));
		}
		fail(cause, globals(program));
	}
}

main().catch((err) => {
	if (err instanceof CliExitError) {
		process.exitCode = err.exitCode;
		return;
	}
	console.error(err);
	process.exitCode = 1;
});
