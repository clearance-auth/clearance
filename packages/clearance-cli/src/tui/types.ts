import type { GlobalOpts } from "../output.js";
import type { OperationConfirmation } from "@clearance/management";
import type {
	ExecutionReceipt,
	OperationOutcome as CanonicalOperationOutcome,
} from "../execution-receipt.js";
import type { OperationRunResult } from "../operation-runner.js";
import type { OperationDispatchMetadata } from "../operation-runner.js";

export type WorkflowArea =
	| "Overview"
	| "People"
	| "Security"
	| "Operations";
export type ActionRisk = "read" | "mutation" | "destructive";
export type OperationOutcome = CanonicalOperationOutcome;
export type MutationPhase = "editing" | "preview" | "confirmed" | "dispatching" | "settled";

export type WorkflowField = {
	readonly key: string;
	readonly label: string;
	readonly required?: boolean;
	readonly placeholder?: string;
	readonly argument?: boolean;
	readonly flag?: string;
	/** Commander variadic options are entered as comma-separated values and retained as arrays. */
	readonly repeatable?: boolean;
	/** Secret values remain in an ephemeral vault and are never copied into TUI state or command receipts. */
	readonly secret?: boolean;
};

export type WorkflowInvocation = {
	readonly path: string;
	readonly args: readonly string[];
	readonly opts: Readonly<Record<string, string | boolean | readonly string[]>>;
	readonly global: Readonly<GlobalOpts>;
	readonly command: string;
};

export type WorkflowAction = {
	readonly id: string;
	readonly area: WorkflowArea;
	readonly label: string;
	readonly description: string;
	readonly path: string;
	readonly risk: ActionRisk;
	readonly mutation: boolean;
	readonly confirmation: OperationConfirmation;
	readonly supportsDryRun: boolean;
	readonly fields: readonly WorkflowField[];
	invocation(values: Readonly<Record<string, string>>, global?: Readonly<GlobalOpts>): WorkflowInvocation;
};

export type VerifiedStartupIdentity = {
	readonly verified: true;
	readonly verifiedAt: number;
	readonly apiUrl: string;
	readonly credentialSource: "environment" | "saved";
	readonly profile: string;
	readonly projectId: string;
	readonly environmentId: string;
	readonly operatorId: string;
	readonly operatorType: "operator" | "api_key";
};

export type WorkflowExecutionContext = {
	readonly signal: AbortSignal;
	readonly lane: string;
	readonly generation: number;
	readonly mutation: boolean;
	/** Stable canonical identity allocated before the mutation durability gate. */
	readonly lifecycle?: OperationLifecycleIdentity;
	/** Publish transport metadata into the same lifecycle before settlement. */
	readonly updateReceiptMetadata?: (metadata: Readonly<OperationDispatchMetadata>) => void;
};

export type OperationLifecycleIdentity = {
	readonly receiptId: string;
	readonly operationId: string;
	readonly path: string;
	readonly startedAt: string;
	readonly target: Readonly<import("../execution-receipt.js").OperationTarget>;
};

/** The TUI consumes the exact same versioned receipt emitted by the CLI runner. */
export type OperationRunnerReceipt = ExecutionReceipt;

export type OperationReceiptError = {
	readonly code: string;
	readonly message: string;
	readonly remediation?: string;
};

export type OperationRunnerResult = OperationRunResult<unknown>;

export type WorkflowExecutor = ((
	invocation: WorkflowInvocation,
	context: WorkflowExecutionContext,
) => Promise<unknown>) & {
	readonly global?: Readonly<GlobalOpts>;
	readonly verifyIdentity?: (signal: AbortSignal) => Promise<VerifiedStartupIdentity>;
	/** Shared canonical receipt coordinator used by the runner and TUI lifecycle. */
	readonly receiptJournal?: OperationReceiptJournal;
};

export type OperationReceipt = {
	readonly id: string;
	/** Canonical runner identity. Every durable revision for this lifecycle shares it. */
	readonly operationId: string;
	readonly path: string;
	readonly actionId: string;
	readonly risk: ActionRisk;
	readonly command: string;
	readonly target: {
		readonly profile: string;
		readonly apiUrl: string;
		readonly projectId?: string;
		readonly environmentId?: string;
	};
	readonly phase: "confirmed" | "dispatching" | "settled";
	readonly createdAt: number;
	readonly dispatchedAt?: number;
	readonly completedAt?: number;
	readonly requestId?: string;
	readonly idempotencyKey?: string;
	readonly outcome?: OperationOutcome;
	readonly error?: OperationReceiptError;
	readonly reconciliationRequired: boolean;
	readonly reconciliationCommands: readonly string[];
	readonly detached?: boolean;
};

export interface OperationReceiptJournal {
	/** Compatibility lifecycle hook. Durable records are canonical ExecutionReceipts. */
	record(receipt: OperationReceipt): Promise<void>;
}

export type MutationState = {
	readonly actionId: string;
	readonly phase: MutationPhase;
	readonly receiptId?: string;
	/** Retained independently of presentation loading state for safe detachment. */
	readonly generation?: number;
	readonly outcome?: OperationOutcome;
	readonly reconciliationRequired: boolean;
	readonly reconciliationCommands: readonly string[];
};

export type RevealedSecret = {
	readonly path: string;
	readonly value: string;
};

export type ViewSnapshot = {
	readonly data?: unknown;
	readonly error?: string;
	readonly updatedAt?: number;
};

export type TuiMode = "browse" | "search" | "form" | "preview" | "help";
export type WorkspaceFocus = "actions" | "resources";

export type TuiState = {
	mode: TuiMode;
	areaIndex: number;
	selection: number;
	search: string;
	formValues: Record<string, string>;
	formIndex: number;
	loading?: { actionId: string; generation: number; mutation: boolean };
	resultOffset: number;
	confirmationInput: string;
	notice?: string;
	snapshots: Record<string, ViewSnapshot>;
	identity?: VerifiedStartupIdentity;
	mutation?: MutationState;
	receipts: OperationReceipt[];
	workspace: import("./workspace.js").ResourceWorkspaceState;
	workspaceFocus: WorkspaceFocus;
	workspaceActions: readonly import("./workspace.js").SelectedRowAction[];
	feedback: import("./feedback.js").FeedbackState;
	refresh: import("./live.js").PollingRefreshState;
	preferences: import("./preferences.js").TuiPreferences;
	quit: boolean;
};

export interface TuiInput {
	isTTY?: boolean;
	setRawMode?(mode: boolean): void;
	resume(): void;
	pause(): void;
	on(event: "data", listener: (data: Buffer | string) => void): this;
	off(event: "data", listener: (data: Buffer | string) => void): this;
}

export interface TuiOutput {
	isTTY?: boolean;
	columns?: number;
	rows?: number;
	write(text: string): unknown;
	on?(event: "resize", listener: () => void): this;
	off?(event: "resize", listener: () => void): this;
}

export type TuiIO = { readonly input: TuiInput; readonly output: TuiOutput };

export interface TuiProcessSignals {
	on(event: "SIGINT" | "SIGTERM", listener: () => void): this;
	off(event: "SIGINT" | "SIGTERM", listener: () => void): this;
}
