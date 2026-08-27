import { randomUUID } from "node:crypto";
import { ClearanceError, isClearanceError, type OperationConfirmation } from "@clearance/management";
import {
	EXECUTION_RECEIPT_VERSION,
	type ExecutionReceipt,
	type ExecutionReceiptStore,
	type OperationCommitState,
	type OperationOutcome,
	type OperationTarget,
	type ReceiptError,
} from "./execution-receipt.js";

const SECRET_OPTION = /(--(?:[a-z0-9]+[-_])*(?:password|secret|token|private[-_]?key|api[-_]?key)(?:[-_]file)?)(=|\s+)(?:"[^"]*"|'[^']*'|\S+)/giu;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f]/gu;

export interface OperationRunnerDescriptor {
	readonly id: string;
	readonly path: string;
	readonly mutation: boolean;
	readonly confirmation: OperationConfirmation;
}

export interface OperationDispatchMetadata {
	readonly dispatchedAt?: string;
	readonly requestId?: string;
	readonly idempotencyKey?: string;
}

export interface OperationExecution<T> extends OperationDispatchMetadata {
	readonly data: T;
}

export interface OperationExecutionContext {
	readonly signal?: AbortSignal;
	/** Call at the transport boundary, then again to enrich it with response metadata. */
	markDispatched(metadata?: Readonly<OperationDispatchMetadata>): void;
	/** Register a late-bound secret before it can appear in an error or receipt. */
	redact(value: string): void;
}

export interface RunOperationInput<T> {
	readonly operation: Readonly<OperationRunnerDescriptor>;
	readonly command: string;
	readonly target?: Readonly<OperationTarget>;
	readonly dryRun?: boolean;
	/** True only when a conditionally guarded operation is requesting its live mode. */
	readonly live?: boolean;
	readonly confirmed?: boolean;
	readonly signal?: AbortSignal;
	readonly secretValues?: readonly string[];
	readonly reconciliationCommands?: readonly string[];
	execute(context: OperationExecutionContext): Promise<OperationExecution<T>>;
}

/** Build the stable command recorded in receipts without leaking the Node launcher path. */
export function clearanceCommandFromArgv(argv: readonly string[]): string {
	const shellWord = (value: string): string => /^[a-zA-Z0-9_./:@%+=,-]+$/u.test(value)
		? value
		: `'${value.replaceAll("'", "'\"'\"'")}'`;
	return safeCommand(["clearance", ...argv.slice(2)].map(shellWord).join(" "), []);
}

export interface OperationRunResult<T> {
	readonly operationRunner: true;
	readonly data?: T;
	/** Original failure for callers that must preserve typed exit behavior. Never serialize this field. */
	readonly cause?: unknown;
	readonly receipt: ExecutionReceipt;
	readonly receiptPersistence: "saved" | "not-configured" | "failed";
	readonly receiptPersistencePath?: string;
	readonly receiptPersistenceError?: string;
}

export interface OperationRunnerOptions {
	readonly receiptStore?: ExecutionReceiptStore;
	readonly now?: () => Date;
	readonly createReceiptId?: () => string;
}

function safeCommand(command: string, secretValues: readonly string[]): string {
	let safe = command.replace(CONTROL_CHARACTERS, "�").replace(
		SECRET_OPTION,
		(_match, option: string, separator: string) => `${option}${separator}[REDACTED]`,
	);
	for (const secret of secretValues) {
		if (secret) safe = safe.replaceAll(secret, "[REDACTED]");
	}
	return safe;
}

function safeText(value: string, secretValues: readonly string[]): string {
	let safe = value.replace(CONTROL_CHARACTERS, "�");
	for (const secret of secretValues) {
		if (secret) safe = safe.replaceAll(secret, "[REDACTED]");
	}
	return safe;
}

function receiptError(cause: unknown, secretValues: readonly string[]): ReceiptError {
	if (isClearanceError(cause)) {
		return Object.freeze({
			code: cause.code,
			message: safeText(cause.message, secretValues),
			stage: cause.stage,
			retryable: cause.retryable,
			remediation: safeText(cause.remediation, secretValues),
		});
	}
	return Object.freeze({
		code: cause instanceof DOMException && cause.name === "AbortError" ? "ABORTED" : "INTERNAL",
		message: safeText(cause instanceof Error ? cause.message : String(cause), secretValues),
		stage: "operation.runner",
		retryable: false,
		remediation: null,
	});
}

function definitiveRejection(cause: unknown): boolean {
	return isClearanceError(cause) && !cause.retryable && cause.status >= 400 && cause.status < 500;
}

function knownPreDispatchFailure(cause: unknown): boolean {
	return isClearanceError(cause) && (
		cause.stage === "cli.dispatch" ||
		cause.stage === "cli.output" ||
		cause.stage === "management-client.input" ||
		cause.stage === "management-client.config" ||
		cause.stage === "management-client.idempotency"
	);
}

function commitState(
	outcome: OperationOutcome,
	mutation: boolean,
	dryRun: boolean,
	dispatched: boolean,
): OperationCommitState {
	if (!mutation || dryRun) return "not-applicable";
	if (outcome === "succeeded") return "committed";
	if (outcome === "rejected") return dispatched ? "not-committed" : "not-dispatched";
	if (outcome === "failed_before_dispatch") return "not-dispatched";
	return "unknown";
}

export class OperationRunner {
	readonly #store?: ExecutionReceiptStore;
	readonly #now: () => Date;
	readonly #createReceiptId: () => string;

	constructor(options: Readonly<OperationRunnerOptions> = {}) {
		this.#store = options.receiptStore;
		this.#now = options.now ?? (() => new Date());
		this.#createReceiptId = options.createReceiptId ?? randomUUID;
	}

	async run<T>(input: Readonly<RunOperationInput<T>>): Promise<OperationRunResult<T>> {
		const startedAt = this.#now().toISOString();
		const dryRun = input.dryRun === true;
		let dispatchedAt: string | null = null;
		let requestId: string | null = null;
		let idempotencyKey: string | null = null;
		let data: T | undefined;
		let outcome: OperationOutcome = "failed_before_dispatch";
		let failure: ReceiptError | null = null;
		let failureCause: unknown;
		const secretValues = [...(input.secretValues ?? [])];

		const confirmationRequired = input.operation.mutation && !dryRun && (
			input.operation.confirmation === "client-required" ||
			input.operation.confirmation === "server-required" ||
			(input.operation.confirmation === "client-required-when-live" && input.live === true)
		);
		if (confirmationRequired && input.confirmed !== true) {
			outcome = "rejected";
			failureCause = new ClearanceError({
				code: "CLI_CONFIRMATION_REQUIRED",
				message: `${input.operation.path} requires explicit confirmation for live execution.`,
				stage: "operation.runner",
				status: 400,
				remediation: "Review the target, then pass --yes to confirm live execution.",
			});
			failure = receiptError(failureCause, secretValues);
		} else if (input.signal?.aborted) {
			outcome = "failed_before_dispatch";
			failureCause = input.signal.reason ?? new DOMException("Aborted", "AbortError");
			failure = receiptError(failureCause, secretValues);
		} else {
			if (input.operation.mutation && !dryRun && this.#store?.prepare) {
				try {
					await this.#store.prepare();
				} catch (cause) {
					outcome = "failed_before_dispatch";
					failureCause = cause;
					failure = receiptError(cause, secretValues);
				}
			}
			try {
				if (failureCause === undefined) {
					const execution = await input.execute({
						signal: input.signal,
						redact: (value) => { if (value) secretValues.push(value); },
						markDispatched: (metadata = {}) => {
							dispatchedAt ??= metadata.dispatchedAt ?? this.#now().toISOString();
							requestId = metadata.requestId ?? requestId;
							idempotencyKey = metadata.idempotencyKey ?? idempotencyKey;
						},
					});
					data = execution.data;
					dispatchedAt ??= execution.dispatchedAt ?? startedAt;
					requestId = execution.requestId ?? requestId;
					idempotencyKey = execution.idempotencyKey ?? idempotencyKey;
					outcome = "succeeded";
				}
			} catch (cause) {
				failureCause = cause;
				failure = receiptError(cause, secretValues);
				const failedBeforeDispatch = dispatchedAt === null || knownPreDispatchFailure(cause);
				if (failedBeforeDispatch) {
					dispatchedAt = null;
					requestId = null;
					idempotencyKey = null;
				}
				outcome = failedBeforeDispatch
					? "failed_before_dispatch"
					: definitiveRejection(cause) ? "rejected" : "indeterminate";
			}
		}

		const receipt: ExecutionReceipt = Object.freeze({
			receiptVersion: EXECUTION_RECEIPT_VERSION,
			receiptId: this.#createReceiptId(),
			operationId: input.operation.id,
			path: input.operation.path,
			mutation: input.operation.mutation,
			dryRun,
			target: Object.freeze({ ...(input.target ?? {}) }),
			command: safeCommand(input.command, secretValues),
			startedAt,
			dispatchedAt,
			completedAt: this.#now().toISOString(),
			requestId,
			idempotencyKey,
			outcome,
			commitState: commitState(outcome, input.operation.mutation, dryRun, dispatchedAt !== null),
			reconciliationCommands: Object.freeze([...(input.reconciliationCommands ?? (
				input.operation.mutation
					? ["clearance events list --limit 20 --output-format json"]
					: []
			))]),
			error: failure,
		});

		const result = {
			operationRunner: true as const,
			data,
			...(failureCause === undefined ? {} : { cause: failureCause }),
			receipt,
		};
		if (!this.#store) return { ...result, receiptPersistence: "not-configured" };
		try {
			await this.#store.save(receipt);
			return {
				...result,
				receiptPersistence: "saved",
				...(this.#store.path ? { receiptPersistencePath: this.#store.path } : {}),
			};
		} catch (cause) {
			return {
				...result,
				receiptPersistence: "failed",
				...(this.#store.path ? { receiptPersistencePath: this.#store.path } : {}),
				receiptPersistenceError: cause instanceof Error ? cause.message : String(cause),
			};
		}
	}
}
