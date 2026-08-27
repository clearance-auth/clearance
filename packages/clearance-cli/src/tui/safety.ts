import {
	EXECUTION_RECEIPT_VERSION,
	defaultExecutionReceiptPath,
	FileExecutionReceiptStore,
	type ExecutionReceipt,
	type ExecutionReceiptStore,
	type OperationCommitState,
} from "../execution-receipt.js";
import type {
	OperationOutcome,
	OperationReceipt,
	OperationReceiptJournal,
	OperationRunnerResult,
	RevealedSecret,
	WorkflowAction,
	WorkflowField,
	WorkflowInvocation,
} from "./types.js";

export const SECRET_MASK = "••••••";

const SECRET_KEY_PATTERN = /(?:^|_)(?:access_token|refresh_token|api_key|signing_key|token|secret|password|passphrase|private_key|client_secret|credential|authorization)(?:$|_)/u;
const OUTCOMES = new Set<OperationOutcome>(["succeeded", "rejected", "failed_before_dispatch", "indeterminate"]);

function normalizedKey(value: string): string {
	return value
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.replace(/[^A-Za-z0-9]+/g, "_")
		.toLowerCase();
}

export function isSecretField(field: WorkflowField): boolean {
	return field.secret === true || SECRET_KEY_PATTERN.test(normalizedKey(field.key));
}

export class EphemeralSecretVault {
	readonly #values = new Map<string, string>();

	append(key: string, value: string): void {
		this.#values.set(key, `${this.#values.get(key) ?? ""}${value}`);
	}

	backspace(key: string): void {
		const points = Array.from(this.#values.get(key) ?? "");
		points.pop();
		if (points.length) this.#values.set(key, points.join(""));
		else this.#values.delete(key);
	}

	has(key: string): boolean {
		return Boolean(this.#values.get(key));
	}

	materialize(values: Readonly<Record<string, string>>): Record<string, string> {
		const result = { ...values };
		for (const [key, value] of this.#values) result[key] = value;
		return result;
	}

	take(): ReadonlyMap<string, string> {
		const snapshot = new Map(this.#values);
		this.clear();
		return snapshot;
	}

	clear(): void {
		this.#values.clear();
	}
}

function shellQuote(value: string): string {
	if (/^[A-Za-z0-9_./:@,+-]+$/u.test(value)) return value;
	return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function replaceAllLiteral(value: string, needle: string, replacement: string): string {
	return needle ? value.split(needle).join(replacement) : value;
}

export function redactInvocationCommand(
	invocation: WorkflowInvocation,
	secrets: ReadonlyMap<string, string>,
): WorkflowInvocation {
	let command = invocation.command;
	const values = [...secrets.values()].filter(Boolean).sort((left, right) => right.length - left.length);
	for (const value of values) {
		command = replaceAllLiteral(command, shellQuote(value), "<redacted>");
		command = replaceAllLiteral(command, value, "<redacted>");
	}
	command = command.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu, "?");
	return { ...invocation, command };
}

type Redaction = { data: unknown; revealed: RevealedSecret[] };

export function redactSecretValues(value: unknown): Redaction {
	const revealed: RevealedSecret[] = [];
	const seen = new WeakSet<object>();
	const visit = (candidate: unknown, path: string): unknown => {
		if (Array.isArray(candidate)) {
			if (seen.has(candidate)) return "[Circular]";
			seen.add(candidate);
			return candidate.map((item, index) => visit(item, `${path}[${index}]`));
		}
		if (!candidate || typeof candidate !== "object") return candidate;
		if (seen.has(candidate)) return "[Circular]";
		seen.add(candidate);
		const result: Record<string, unknown> = {};
		for (const [key, child] of Object.entries(candidate)) {
			const childPath = path ? `${path}.${key}` : key;
			if (SECRET_KEY_PATTERN.test(normalizedKey(key)) && (typeof child === "string" || typeof child === "number")) {
				revealed.push({ path: childPath, value: String(child) });
				result[key] = "<redacted: revealed once>";
			} else result[key] = visit(child, childPath);
		}
		return result;
	};
	return { data: visit(value, ""), revealed };
}

export function isOperationRunnerResult(value: unknown): value is OperationRunnerResult {
	if (!value || typeof value !== "object") return false;
	const candidate = value as Partial<OperationRunnerResult>;
	return candidate.operationRunner === true && candidate.receipt?.receiptVersion === EXECUTION_RECEIPT_VERSION && OUTCOMES.has(candidate.receipt.outcome);
}

export function normalizeOperationRunnerResult(value: unknown): OperationRunnerResult | undefined {
	if (!value || typeof value !== "object") return undefined;
	const candidate = value as {
		operationRunner?: unknown;
		data?: unknown;
		receipt?: {
			receiptVersion?: unknown;
			outcome?: unknown;
			requestId?: unknown;
			reconciliationCommands?: unknown;
			error?: unknown;
		};
	};
	const receipt = candidate.receipt;
	if (!receipt || receipt.receiptVersion !== EXECUTION_RECEIPT_VERSION) return undefined;
	if (!OUTCOMES.has(receipt.outcome as OperationOutcome)) return undefined;
	return {
		operationRunner: true,
		data: candidate.data,
		// Compatibility accepts earlier partial v1 projections for presentation,
		// while real runner results retain the complete canonical receipt verbatim.
		receipt: receipt as ExecutionReceipt,
		receiptPersistence: typeof (candidate as { receiptPersistence?: unknown }).receiptPersistence === "string"
			? (candidate as OperationRunnerResult).receiptPersistence
			: "not-configured",
		...((candidate as { receiptPersistencePath?: unknown }).receiptPersistencePath && typeof (candidate as { receiptPersistencePath?: unknown }).receiptPersistencePath === "string"
			? { receiptPersistencePath: (candidate as { receiptPersistencePath: string }).receiptPersistencePath }
			: {}),
		...((candidate as { receiptPersistenceError?: unknown }).receiptPersistenceError && typeof (candidate as { receiptPersistenceError?: unknown }).receiptPersistenceError === "string"
			? { receiptPersistenceError: (candidate as { receiptPersistenceError: string }).receiptPersistenceError }
			: {}),
	} as OperationRunnerResult;
}

export function operationFailureDetails(cause: unknown, synchronous = false): {
	outcome: OperationOutcome;
	requestId?: string;
	reconciliationCommands?: readonly string[];
} {
	if (!cause || typeof cause !== "object") return { outcome: synchronous ? "failed_before_dispatch" : "indeterminate" };
	const value = cause as {
		outcome?: unknown;
		dispatchState?: unknown;
		status?: unknown;
		requestId?: unknown;
		reconciliationCommands?: unknown;
		receipt?: Partial<{ outcome: unknown; requestId: unknown; reconciliationCommands: unknown }>;
	};
	const explicitOutcome = value.receipt?.outcome ?? value.outcome;
	const outcome = OUTCOMES.has(explicitOutcome as OperationOutcome)
		? explicitOutcome as OperationOutcome
		: synchronous || value.dispatchState === "not_dispatched" || value.dispatchState === "before_dispatch"
			? "failed_before_dispatch"
			: typeof value.status === "number" && value.status >= 400 && value.status < 500
				? "rejected"
				: "indeterminate";
	const requestId = typeof (value.receipt?.requestId ?? value.requestId) === "string"
		? String(value.receipt?.requestId ?? value.requestId)
		: undefined;
	const commands = value.receipt?.reconciliationCommands ?? value.reconciliationCommands;
	return {
		outcome,
		requestId,
		reconciliationCommands: Array.isArray(commands) && commands.every((command) => typeof command === "string")
			? commands
			: undefined,
	};
}

function commandPrefix(invocation: WorkflowInvocation): string[] {
	const result = ["clearance"];
	if (invocation.global.profile) result.push("--profile", shellQuote(invocation.global.profile));
	if (invocation.global.apiUrl) result.push("--api-url", shellQuote(invocation.global.apiUrl));
	return result;
}

export function reconciliationCommands(action: WorkflowAction, invocation: WorkflowInvocation): readonly string[] {
	const prefix = commandPrefix(invocation);
	const command = (...parts: Array<string | undefined>): string => [...prefix, ...parts.filter((part): part is string => Boolean(part)).map(shellQuote)].join(" ");
	const option = (key: string): string | undefined => typeof invocation.opts[key] === "string" ? invocation.opts[key] : undefined;
	if (action.path === "users create") return [command("users", "list")];
	if (["users update", "users disable", "users delete"].includes(action.path)) return [command("users", "inspect", invocation.args[0])];
	if (action.path === "orgs create") return [command("orgs", "list")];
	if (["orgs update", "orgs archive"].includes(action.path)) return [command("orgs", "inspect", invocation.args[0])];
	if (action.path.startsWith("orgs members ")) return [command("orgs", "members", "list", "--org", option("org"))];
	if (action.path === "config set") return [command("config", "get", invocation.args[0])];
	if (action.path.startsWith("delivery ")) return [command("delivery", "list")];
	return [command("events", "list", "--limit", "20")];
}

export function defaultReceiptJournalPath(env: NodeJS.ProcessEnv = process.env): string {
	return defaultExecutionReceiptPath(env);
}

function legacyCommitState(receipt: OperationReceipt): OperationCommitState {
	if (receipt.outcome === "succeeded") return "committed";
	if (receipt.outcome === "rejected") return receipt.dispatchedAt === undefined ? "not-dispatched" : "not-committed";
	if (receipt.outcome === "failed_before_dispatch") return "not-dispatched";
	return "unknown";
}

function canonicalReceiptFromLegacy(receipt: OperationReceipt): ExecutionReceipt {
	const startedAt = new Date(receipt.createdAt).toISOString();
	const dispatchedAt = receipt.dispatchedAt === undefined ? null : new Date(receipt.dispatchedAt).toISOString();
	return Object.freeze({
		receiptVersion: EXECUTION_RECEIPT_VERSION,
		receiptId: receipt.id,
		operationId: receipt.operationId,
		path: receipt.path,
		mutation: true,
		dryRun: /(?:^|\s)--dry-run(?:\s|$)/u.test(receipt.command),
		target: Object.freeze({
			principal: receipt.target.profile,
			apiOrigin: receipt.target.apiUrl,
			environment: receipt.target.environmentId ?? receipt.target.projectId,
		}),
		command: receipt.command,
		startedAt,
		dispatchedAt,
		completedAt: new Date(receipt.completedAt ?? receipt.createdAt).toISOString(),
		requestId: receipt.requestId ?? null,
		idempotencyKey: receipt.idempotencyKey ?? null,
		outcome: receipt.outcome ?? "indeterminate",
		commitState: legacyCommitState(receipt),
		reconciliationCommands: Object.freeze([...receipt.reconciliationCommands]),
		error: receipt.error ? Object.freeze({
			code: "TUI_NONCANONICAL_EXECUTION",
			message: "The TUI operation settled outside the canonical operation runner.",
			stage: "tui.lifecycle",
			retryable: receipt.outcome === "indeterminate",
			remediation: null,
		}) : null,
	});
}

/**
 * Resolve append-only lifecycle revisions. A receipt ID is the correlation key
 * and the last durable revision is authoritative, including a definitive
 * runner settlement that supersedes an earlier detached indeterminate record.
 */
export function collapseExecutionReceiptLifecycles(
	receipts: readonly ExecutionReceipt[],
): readonly ExecutionReceipt[] {
	const latest = new Map<string, ExecutionReceipt>();
	for (const receipt of receipts) {
		if (latest.has(receipt.receiptId)) latest.delete(receipt.receiptId);
		latest.set(receipt.receiptId, receipt);
	}
	return Object.freeze([...latest.values()]);
}

/**
 * Coordinates TUI durability with the canonical receipt store. Lifecycle
 * checkpoints only preflight the journal; settled fallback records use the
 * versioned ExecutionReceipt schema, and canonical runner saves are not
 * duplicated by the controller's compatibility lifecycle callback.
 */
export class FileOperationReceiptJournal implements OperationReceiptJournal, ExecutionReceiptStore {
	readonly path: string;
	readonly #store: FileExecutionReceiptStore;
	readonly #canonicalSettled = new Set<string>();
	#tail: Promise<void> = Promise.resolve();

	constructor(path = defaultReceiptJournalPath()) {
		this.#store = new FileExecutionReceiptStore(path);
		this.path = this.#store.path;
	}

	prepare(): Promise<void> {
		return this.#enqueue(() => this.#store.prepare());
	}

	async save(receipt: ExecutionReceipt): Promise<void> {
		await this.#enqueue(async () => {
			await this.#store.save(receipt);
			this.#canonicalSettled.add(receipt.receiptId);
		});
	}

	async record(receipt: OperationReceipt): Promise<void> {
		await this.#enqueue(async () => {
			if (receipt.phase !== "settled") {
				await this.#store.prepare();
				return;
			}
			if (this.#canonicalSettled.has(receipt.id)) return;
			await this.#store.save(canonicalReceiptFromLegacy(receipt));
		});
	}

	#enqueue(write: () => Promise<void>): Promise<void> {
		const queued = this.#tail.catch(() => {}).then(write);
		this.#tail = queued.then(() => {}, () => {});
		return queued;
	}
}
