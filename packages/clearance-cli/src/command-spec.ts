import { MANAGEMENT_OPERATIONS } from "@clearance/management";
import type {
	ManagementOperation,
	ManagementOperationId,
	OperationConfirmation,
} from "@clearance/management";
import { Command } from "commander";

/** Increment only when the serialized command record contract changes. */
export const COMMAND_SPEC_VERSION = 2 as const;

export type CommandValueType = "boolean" | "string" | "number" | "string-array";
export type CommandInputKind = "value" | "file" | "secret" | "secret-file";
export type CommandRetrySafety = "safe" | "reconcile-before-retry" | "not-declared";
export type CommandIdempotency = "none" | "automatic-operation-key" | "not-declared";

export interface CommandResultSpec {
	readonly protocol: "clearance.cli.output";
	readonly protocolVersion: 1;
	readonly shape: "management-operation-output" | "command-defined";
	readonly operationId?: ManagementOperationId;
}

export type CommandExecutionClass =
	| "management-api"
	| "local"
	| "authentication"
	| "interactive"
	| "discovery";

export interface CommandSpecRecord {
	readonly specVersion: typeof COMMAND_SPEC_VERSION;
	readonly path: string;
	readonly description?: string;
	readonly executionClass: CommandExecutionClass;
	readonly operationId?: ManagementOperationId;
	readonly mutation: boolean;
	readonly confirmation: OperationConfirmation;
	readonly supportsDryRun: boolean;
	readonly idempotency: CommandIdempotency;
	readonly retrySafety: CommandRetrySafety;
	readonly result: CommandResultSpec;
	readonly agentNotes: readonly string[];
	readonly usage?: string;
	readonly arguments: readonly CommandArgumentSpec[];
	readonly options: readonly CommandOptionSpec[];
}

export interface CommandArgumentSpec {
	readonly name: string;
	readonly description?: string;
	readonly required: boolean;
	readonly variadic: boolean;
	readonly defaultValue?: unknown;
	readonly valueType: CommandValueType;
	readonly choices: readonly string[];
	readonly inputKind: CommandInputKind;
}

export interface CommandOptionSpec {
	readonly flags: string;
	readonly description?: string;
	readonly required: boolean;
	readonly optional: boolean;
	readonly variadic: boolean;
	readonly defaultValue?: unknown;
	readonly valueType: CommandValueType;
	readonly choices: readonly string[];
	readonly inputKind: CommandInputKind;
}

/**
 * Non-management commands must declare their safety behavior explicitly. This
 * prevents local or interactive commands from being presented to an agent as
 * harmless simply because they have no management operation descriptor.
 */
export interface SupplementalCommandSpec {
	readonly path: string;
	readonly description?: string;
	readonly executionClass: Exclude<CommandExecutionClass, "management-api">;
	readonly mutation: boolean;
	readonly confirmation: OperationConfirmation;
	readonly supportsDryRun: boolean;
	readonly agentNotes?: readonly string[];
}

export interface CommandSpecDocument {
	readonly specVersion: typeof COMMAND_SPEC_VERSION;
	readonly globalOptions: readonly CommandOptionSpec[];
	readonly commands: readonly CommandSpecRecord[];
}

export interface CommanderLeaf {
	readonly path: string;
	readonly description?: string;
	readonly usage: string;
	readonly arguments: readonly CommandArgumentSpec[];
	readonly options: readonly CommandOptionSpec[];
}

type CanonicalOperation = Pick<
	ManagementOperation<ManagementOperationId>,
	"id" | "cliPath" | "http" | "mutation" | "confirmation" | "supportsDryRun"
>;

export interface BuildCommandSpecOptions {
	readonly program?: Command;
	readonly operations?: readonly CanonicalOperation[];
	readonly supplementalCommands?: readonly SupplementalCommandSpec[];
}

export interface CommandPathDrift {
	readonly parentPath: string;
	readonly canonicalPath: string;
	readonly registeredPath: string;
}

export interface CommandParityReport {
	readonly matches: boolean;
	readonly registeredPaths: readonly string[];
	readonly canonicalPaths: readonly string[];
	readonly supplementalPaths: readonly string[];
	readonly missingCanonicalPaths: readonly string[];
	readonly missingSupplementalPaths: readonly string[];
	readonly unexpectedRegisteredPaths: readonly string[];
	readonly pathDrifts: readonly CommandPathDrift[];
}

function normalizePath(path: string): string {
	return path.trim().split(/\s+/u).filter(Boolean).join(" ");
}

function optionalDescription(description: string | undefined): string | undefined {
	const normalized = description?.trim();
	return normalized ? normalized : undefined;
}

function inputKind(name: string): CommandInputKind {
	const normalized = name.toLowerCase().replace(/[<>\[\]]/gu, "");
	const secret = /(^|[-_])(password|secret|token|private[-_]?key|api[-_]?key)([-_]|$)/u.test(normalized);
	const file = /(^|[-_])(file|fixture|policy|config)([-_]|$)/u.test(normalized);
	if (secret && file) return "secret-file";
	if (secret) return "secret";
	return file ? "file" : "value";
}

function valueType(value: {
	readonly required?: boolean;
	readonly optional?: boolean;
	readonly variadic: boolean;
	readonly defaultValue?: unknown;
}): CommandValueType {
	if (value.variadic) return "string-array";
	if (typeof value.defaultValue === "number") return "number";
	if (value.required === false && value.optional === false) return "boolean";
	return "string";
}

function resultForOperation(operationId?: ManagementOperationId): CommandResultSpec {
	return Object.freeze({
		protocol: "clearance.cli.output",
		protocolVersion: 1,
		shape: operationId ? "management-operation-output" : "command-defined",
		...(operationId ? { operationId } : {}),
	});
}

function notesForOperation(operation: CanonicalOperation): readonly string[] {
	const notes: string[] = [
		`Canonical management operation: ${operation.id}.`,
	];
	if (operation.supportsDryRun) {
		notes.push("Use --dry-run to preview the mutation when appropriate.");
	}
	switch (operation.confirmation) {
		case "client-required":
			notes.push("Live execution requires explicit client confirmation.");
			break;
		case "client-required-when-live":
			notes.push("Explicit client confirmation is required unless this is a dry run.");
			break;
		case "server-required":
			notes.push("The server enforces explicit confirmation for live execution.");
			break;
	}
	return Object.freeze(notes);
}

export function collectCommanderLeaves(program: Command): readonly CommanderLeaf[] {
	const leaves: CommanderLeaf[] = [];

	function visit(command: Command, parents: readonly string[]): void {
		for (const child of command.commands) {
			const pathSegments = [...parents, child.name()];
			if (child.commands.length > 0) {
				visit(child, pathSegments);
				continue;
			}
			leaves.push(Object.freeze({
				path: normalizePath(pathSegments.join(" ")),
				description: optionalDescription(child.description()),
				usage: child.usage(),
				arguments: Object.freeze(child.registeredArguments.map((argument) => Object.freeze({
					name: argument.name(),
					description: optionalDescription(argument.description),
					required: argument.required,
					variadic: argument.variadic,
					valueType: valueType(argument),
					choices: Object.freeze([...(argument.argChoices ?? [])]),
					inputKind: inputKind(argument.name()),
					...(argument.defaultValue === undefined ? {} : { defaultValue: argument.defaultValue as unknown }),
				}))),
				options: Object.freeze(child.options.map((option) => Object.freeze({
					flags: option.flags,
					description: optionalDescription(option.description),
					required: option.required,
					optional: option.optional,
					variadic: option.variadic,
					valueType: valueType(option),
					choices: Object.freeze([...(option.argChoices ?? [])]),
					inputKind: inputKind(option.long ?? option.flags),
					...(option.defaultValue === undefined ? {} : { defaultValue: option.defaultValue as unknown }),
				}))),
			}));
		}
	}

	visit(program, []);
	return Object.freeze(leaves.sort((left, right) => left.path.localeCompare(right.path)));
}

export function buildCommandSpecDocument(
	options: BuildCommandSpecOptions = {},
): CommandSpecDocument {
	const operations = options.operations ?? MANAGEMENT_OPERATIONS;
	const supplementalCommands = options.supplementalCommands ?? [];
	const commanderLeaves = options.program ? collectCommanderLeaves(options.program) : [];
	const commanderDescriptions = new Map(
		commanderLeaves.map((leaf) => [leaf.path, leaf.description]),
	);
	const commanderDetails = new Map(commanderLeaves.map((leaf) => [leaf.path, leaf]));
	const records = new Map<string, CommandSpecRecord>();

	for (const operation of operations) {
		const path = normalizePath(operation.cliPath);
		const details = commanderDetails.get(path);
		if (records.has(path)) throw new Error(`Duplicate canonical command path: ${path}`);
		records.set(path, Object.freeze({
			specVersion: COMMAND_SPEC_VERSION,
			path,
			description: commanderDescriptions.get(path),
			executionClass: "management-api",
			operationId: operation.id,
			mutation: operation.mutation,
			confirmation: operation.confirmation,
			supportsDryRun: operation.supportsDryRun,
			idempotency: operation.mutation ? "automatic-operation-key" : "none",
			retrySafety: operation.mutation ? "reconcile-before-retry" : "safe",
			result: resultForOperation(operation.id),
			agentNotes: notesForOperation(operation),
			usage: details?.usage,
			arguments: details?.arguments ?? [],
			options: details?.options ?? [],
		}));
	}

	for (const supplemental of supplementalCommands) {
		const path = normalizePath(supplemental.path);
		const details = commanderDetails.get(path);
		if (!path) throw new Error("Supplemental command path cannot be empty.");
		if (records.has(path)) throw new Error(`Duplicate command spec path: ${path}`);
		records.set(path, Object.freeze({
			specVersion: COMMAND_SPEC_VERSION,
			path,
			description: optionalDescription(
				supplemental.description ?? commanderDescriptions.get(path),
			),
			executionClass: supplemental.executionClass,
			mutation: supplemental.mutation,
			confirmation: supplemental.confirmation,
			supportsDryRun: supplemental.supportsDryRun,
			idempotency: supplemental.mutation ? "not-declared" : "none",
			retrySafety: supplemental.mutation ? "not-declared" : "safe",
			result: resultForOperation(),
			agentNotes: Object.freeze([...(supplemental.agentNotes ?? [])]),
			usage: details?.usage,
			arguments: details?.arguments ?? [],
			options: details?.options ?? [],
		}));
	}

	return Object.freeze({
		specVersion: COMMAND_SPEC_VERSION,
		globalOptions: Object.freeze((options.program?.options ?? []).map((option) => Object.freeze({
			flags: option.flags,
			description: optionalDescription(option.description),
			required: option.required,
			optional: option.optional,
			variadic: option.variadic,
			valueType: valueType(option),
			choices: Object.freeze([...(option.argChoices ?? [])]),
			inputKind: inputKind(option.long ?? option.flags),
			...(option.defaultValue === undefined ? {} : { defaultValue: option.defaultValue as unknown }),
		}))),
		commands: Object.freeze(
			[...records.values()].sort((left, right) => left.path.localeCompare(right.path)),
		),
	});
}

function parentPath(path: string): string {
	const segments = path.split(" ");
	return segments.slice(0, -1).join(" ");
}

export function compareCommanderParity(
	program: Command,
	options: Omit<BuildCommandSpecOptions, "program"> = {},
): CommandParityReport {
	const registeredPaths = collectCommanderLeaves(program).map((leaf) => leaf.path);
	const canonicalPaths = (options.operations ?? MANAGEMENT_OPERATIONS)
		.map((operation) => normalizePath(operation.cliPath));
	const supplementalPaths = (options.supplementalCommands ?? [])
		.map((command) => normalizePath(command.path));
	const registered = new Set(registeredPaths);
	const expected = new Set([...canonicalPaths, ...supplementalPaths]);
	const missingCanonicalPaths = canonicalPaths.filter((path) => !registered.has(path)).sort();
	const missingSupplementalPaths = supplementalPaths.filter((path) => !registered.has(path)).sort();
	const unexpectedRegisteredPaths = registeredPaths.filter((path) => !expected.has(path)).sort();
	const pathDrifts: CommandPathDrift[] = [];
	const affectedParents = new Set(missingCanonicalPaths.map(parentPath));

	for (const parent of affectedParents) {
		const missing = missingCanonicalPaths.filter((path) => parentPath(path) === parent);
		const unexpected = unexpectedRegisteredPaths.filter((path) => parentPath(path) === parent);
		if (missing.length === 1 && unexpected.length === 1) {
			pathDrifts.push(Object.freeze({
				parentPath: parent,
				canonicalPath: missing[0]!,
				registeredPath: unexpected[0]!,
			}));
		}
	}

	return Object.freeze({
		matches:
			missingCanonicalPaths.length === 0 &&
			missingSupplementalPaths.length === 0 &&
			unexpectedRegisteredPaths.length === 0,
		registeredPaths: Object.freeze([...registeredPaths].sort()),
		canonicalPaths: Object.freeze([...canonicalPaths].sort()),
		supplementalPaths: Object.freeze([...supplementalPaths].sort()),
		missingCanonicalPaths: Object.freeze(missingCanonicalPaths),
		missingSupplementalPaths: Object.freeze(missingSupplementalPaths),
		unexpectedRegisteredPaths: Object.freeze(unexpectedRegisteredPaths),
		pathDrifts: Object.freeze(pathDrifts),
	});
}
