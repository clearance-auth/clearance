import type { GlobalOpts } from "../output.js";
import type { OperationConfirmation } from "@clearance/management";

export type WorkflowArea = "Overview" | "Users & organizations" | "Events & delivery" | "Configuration & enterprise";
export type ActionRisk = "read" | "mutation" | "destructive";

export type WorkflowField = {
	readonly key: string;
	readonly label: string;
	readonly required?: boolean;
	readonly placeholder?: string;
	readonly argument?: boolean;
	readonly flag?: string;
};

export type WorkflowInvocation = {
	readonly path: string;
	readonly args: readonly string[];
	readonly opts: Readonly<Record<string, string | boolean>>;
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

export type WorkflowExecutor = ((
	invocation: WorkflowInvocation,
	context: { readonly signal: AbortSignal; readonly lane: string; readonly generation: number },
) => Promise<unknown>) & { readonly global?: Readonly<GlobalOpts> };

export type ViewSnapshot = {
	readonly data?: unknown;
	readonly error?: string;
	readonly updatedAt?: number;
};

export type TuiMode = "browse" | "search" | "form" | "preview" | "help";

export type TuiState = {
	mode: TuiMode;
	areaIndex: number;
	selection: number;
	search: string;
	formValues: Record<string, string>;
	formIndex: number;
	loading?: { actionId: string; generation: number };
	resultOffset: number;
	confirmationInput: string;
	notice?: string;
	snapshots: Record<string, ViewSnapshot>;
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
