import { ClearanceError, isClearanceError } from "@clearance/management";
import {
	CLI_EXIT_CODE,
	exitCodeForClearanceError,
	type CliExitCode,
} from "./output-exit-codes.js";
import {
	selectOutputFormat,
	type OutputFormat,
	type OutputFormatOptions,
} from "./output-format.js";
import { renderHumanError, renderHumanSuccess } from "./output-human.js";
import { evaluateJsonQuery, validateJsonQuery } from "./json-query.js";

export { CLI_EXIT_CODE, exitCodeForClearanceError } from "./output-exit-codes.js";
export {
	OUTPUT_FORMATS,
	isOutputFormat,
	parseOutputFormat,
	selectOutputFormat,
} from "./output-format.js";
export { renderHumanData, renderHumanError, renderHumanSuccess } from "./output-human.js";
export type { CliExitCode } from "./output-exit-codes.js";
export type { OutputFormat, OutputFormatOptions } from "./output-format.js";

export interface GlobalOpts extends OutputFormatOptions {
	noInput?: boolean;
	yes?: boolean;
	dryRun?: boolean;
	profile?: string;
	apiUrl?: string;
	/** Cancellation propagated by interactive or embedding callers. */
	signal?: AbortSignal;
}

/** Increment only when the serialized machine envelope changes. */
export const OUTPUT_PROTOCOL_VERSION = 1 as const;
export const OUTPUT_PROTOCOL = "clearance.cli.output" as const;

export interface NextAction {
	readonly action: "run-command" | "follow-up";
	readonly command: string | null;
	readonly description: string | null;
	readonly mutation: boolean | null;
	readonly confirmationRequired: boolean | null;
}

export interface OutputMeta {
	readonly [key: string]: unknown;
}

export interface SuccessEnvelope<T = unknown> {
	readonly protocol: typeof OUTPUT_PROTOCOL;
	readonly protocolVersion: typeof OUTPUT_PROTOCOL_VERSION;
	readonly ok: true;
	readonly data: T;
	readonly summary: string | null;
	readonly notice: string | null;
	readonly next: readonly string[];
	readonly actions: readonly NextAction[];
	readonly meta: Readonly<OutputMeta>;
}

export interface ErrorDetail {
	readonly code: string;
	readonly message: string;
	readonly stage: string;
	readonly retryable: boolean;
	readonly remediation: string | null;
}

export interface ErrorEnvelope {
	readonly protocol: typeof OUTPUT_PROTOCOL;
	readonly protocolVersion: typeof OUTPUT_PROTOCOL_VERSION;
	readonly ok: false;
	readonly error: ErrorDetail;
	readonly actions: readonly NextAction[];
	readonly meta: Readonly<OutputMeta>;
}

export type OutputEnvelope<T = unknown> = SuccessEnvelope<T> | ErrorEnvelope;

export interface ResultPresentation {
	/** Exact text used for human output and the machine-readable summary. */
	readonly human?: string;
	readonly summary?: string | null;
	readonly notice?: string | null;
	readonly next?: readonly string[];
	readonly actions?: readonly NextAction[];
	readonly meta?: Readonly<OutputMeta>;
}

function actionFromLegacyStep(step: string): NextAction {
	const normalized = step.trim();
	const isCommand = normalized === "clearance" || normalized.startsWith("clearance ");
	return Object.freeze({
		action: isCommand ? "run-command" : "follow-up",
		command: isCommand ? normalized : null,
		description: isCommand ? null : normalized,
		mutation: null,
		confirmationRequired: null,
	});
}

export class CliExitError extends Error {
	readonly exitCode: CliExitCode;

	constructor(exitCode: CliExitCode = CLI_EXIT_CODE.failure) {
		super("CLI command failed");
		this.name = "CliExitError";
		this.exitCode = exitCode;
	}
}

export function successEnvelope<T>(
	data: T,
	presentation: string | Readonly<ResultPresentation> = {},
): SuccessEnvelope<T> {
	const normalized = typeof presentation === "string"
		? { human: presentation, summary: presentation }
		: presentation;
	return {
		protocol: OUTPUT_PROTOCOL,
		protocolVersion: OUTPUT_PROTOCOL_VERSION,
		ok: true,
		data,
		summary: normalized.summary ?? normalized.human ?? null,
		notice: normalized.notice ?? null,
		next: normalized.next ? [...normalized.next] : [],
		actions: normalized.actions
			? normalized.actions.map((action) => Object.freeze({ ...action }))
			: (normalized.next ?? []).map(actionFromLegacyStep),
		meta: normalized.meta ? { ...normalized.meta } : {},
	};
}

export function errorEnvelope(err: unknown, meta: Readonly<OutputMeta> = {}): ErrorEnvelope {
	if (isClearanceError(err)) {
		return {
			protocol: OUTPUT_PROTOCOL,
			protocolVersion: OUTPUT_PROTOCOL_VERSION,
			ok: false,
			error: {
				code: err.code,
				message: err.message,
				stage: err.stage,
				retryable: err.retryable,
				remediation: err.remediation,
			},
			actions: err.remediation ? [actionFromLegacyStep(err.remediation)] : [],
			meta: { ...meta },
		};
	}
	return {
		protocol: OUTPUT_PROTOCOL,
		protocolVersion: OUTPUT_PROTOCOL_VERSION,
		ok: false,
		error: {
			code: "INTERNAL",
			message: err instanceof Error ? err.message : String(err),
			stage: "unknown",
			retryable: false,
			remediation: null,
		},
		actions: [],
		meta: { ...meta },
	};
}

function writeMachineEnvelope(format: Extract<OutputFormat, "json" | "jsonl">, value: OutputEnvelope): void {
	const serialized = format === "jsonl" ? JSON.stringify(value) : JSON.stringify(value, null, 2);
	process.stdout.write(`${serialized}\n`);
}

export function printResult(
	opts: Readonly<GlobalOpts>,
	data: unknown,
	presentation: string | Readonly<ResultPresentation> = {},
): void {
	const format = selectOutputFormat(opts);
	if (format === "quiet") return;
	const envelope = successEnvelope(data, presentation);
	// `--json` predates the output envelope and remains the raw command result
	// for scripts that consume it. The explicit --output-format json contract is
	// the enveloped protocol. Selectors always operate on the envelope.
	const legacyJson = opts.json === true && opts.format === undefined && opts.output === undefined && !opts.jq;
	let selected: unknown = envelope;
	if (opts.jq) {
		try {
			selected = evaluateJsonQuery(envelope, opts.jq);
		} catch (cause) {
			throw new ClearanceError({
				code: "CLI_JQ_INVALID",
				message: cause instanceof Error ? cause.message : String(cause),
				stage: "cli.output",
				status: 400,
				remediation: "Use selectors such as .data, .data.items[], or .data.items[0].id.",
			});
		}
	}
	if (format === "json" || format === "jsonl") {
		const value = legacyJson ? data : selected;
		const serialized = format === "jsonl" ? JSON.stringify(value) : JSON.stringify(value, null, 2);
		process.stdout.write(`${serialized}\n`);
		return;
	}
	const normalized = typeof presentation === "string" ? { human: presentation } : presentation;
	const rendered = normalized.human ?? renderHumanSuccess(envelope);
	process.stdout.write(`${rendered}\n`);
}

/** Fail a malformed selector before an action can cross a mutation boundary. */
export function validateOutputSelector(opts: Readonly<GlobalOpts>): void {
	if (!opts.jq) return;
	try {
		validateJsonQuery(opts.jq);
	} catch (cause) {
		throw new ClearanceError({
			code: "CLI_JQ_INVALID",
			message: cause instanceof Error ? cause.message : String(cause),
			stage: "cli.output",
			status: 400,
			remediation: "Use selectors such as .data, .data.items[], or .data.items[0].id.",
		});
	}
}

export function fail(err: unknown, opts: GlobalOpts, meta: Readonly<OutputMeta> = {}): never {
	// A CliExitError means fail() already emitted a structured document and is
	// unwinding. Re-throw untouched so a catch block that funnels back into
	// fail() can never emit a second JSON document on stdout (--json contract:
	// exactly one document per invocation).
	if (err instanceof CliExitError) {
		throw err;
	}
	const envelope = errorEnvelope(err, meta);
	const format = selectOutputFormat(opts);
	if (format === "json" || format === "jsonl") writeMachineEnvelope(format, envelope);
	else process.stderr.write(`${renderHumanError(envelope.error)}\n`);
	throw new CliExitError(
		isClearanceError(err) ? exitCodeForClearanceError(err) : CLI_EXIT_CODE.internal,
	);
}

export function exitCodeFromDoctor(ok: boolean): CliExitCode {
	return ok ? CLI_EXIT_CODE.success : CLI_EXIT_CODE.checkFailed;
}

export function asClearanceError(err: unknown): ClearanceError | null {
	return isClearanceError(err) ? err : null;
}
