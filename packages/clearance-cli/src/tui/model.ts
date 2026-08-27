import { actionsFor, WORKFLOW_ACTIONS, WORKFLOW_AREAS } from "./catalog.js";
import { MANAGEMENT_OPERATIONS } from "@clearance/management";
import type { GlobalOpts } from "../output.js";
import { sanitizeTerminalText } from "../terminal-sanitize.js";
import { closeModal, dismissNotice, initialFeedbackState, pushToast, showModal, upsertNotice } from "./feedback.js";
import { initialPollingRefreshState, markPollingRefreshFailed, markPollingRefreshStarted, markPollingRefreshSucceeded, setVisiblePanel } from "./live.js";
import { DEFAULT_TUI_PREFERENCES, type TuiPreferences } from "./preferences.js";
import {
	EphemeralSecretVault,
	isSecretField,
	normalizeOperationRunnerResult,
	operationFailureDetails,
	reconciliationCommands,
	redactInvocationCommand,
	redactSecretValues,
	SECRET_MASK,
} from "./safety.js";
import type {
	OperationOutcome,
	OperationReceipt,
	OperationReceiptError,
	OperationReceiptJournal,
	RevealedSecret,
	TuiState,
	VerifiedStartupIdentity,
	WorkflowAction,
	WorkflowExecutor,
	WorkflowInvocation,
} from "./types.js";
import {
	activateWorkspaceSection,
	advanceWorkspaceCursor,
	initialResourceWorkspace,
	normalizeWorkspaceSection,
	resourcePageFrom,
	retreatWorkspaceCursor,
	scrollWorkspaceDetail,
	selectWorkspaceAction,
	selectWorkspaceRow,
	setWorkspaceMode,
	updateWorkspacePage,
	WORKSPACE_SECTIONS,
	type WorkspaceSectionAdapter,
} from "./workspace.js";
import type { TuiDeepLinkTarget } from "./deep-link.js";

type ActiveRequest = { generation: number; controller: AbortController; mutation: boolean };

export class RequestLanes {
	readonly #active = new Map<string, ActiveRequest>();
	readonly #generations = new Map<string, number>();

	start(lane: string, mutation = false): { generation: number; signal: AbortSignal } {
		this.cancel(lane);
		const generation = (this.#generations.get(lane) ?? 0) + 1;
		const controller = new AbortController();
		this.#generations.set(lane, generation);
		this.#active.set(lane, { generation, controller, mutation });
		return { generation, signal: controller.signal };
	}

	isCurrent(lane: string, generation: number): boolean {
		return this.#active.get(lane)?.generation === generation;
	}

	finish(lane: string, generation: number): void {
		if (this.isCurrent(lane, generation)) this.#active.delete(lane);
	}

	cancel(lane: string): void {
		const request = this.#active.get(lane);
		if (!request) return;
		request.controller.abort(new Error("Request cancelled"));
		this.#active.delete(lane);
	}

	detach(lane: string, generation: number): void {
		this.finish(lane, generation);
	}

	cancelAll(): void {
		for (const lane of [...this.#active.keys()]) this.cancel(lane);
	}

	cancelReads(): void {
		for (const [lane, request] of [...this.#active.entries()]) {
			if (!request.mutation) this.cancel(lane);
		}
	}
}

export function initialTuiState(options: { readonly preferences?: TuiPreferences; readonly target?: TuiDeepLinkTarget } = {}): TuiState {
	const savedSection = options.preferences?.sectionId ? normalizeWorkspaceSection(options.preferences.sectionId) : undefined;
	const initialSection = options.target?.sectionId ?? savedSection ?? "overview";
	const sectionIndex = WORKSPACE_SECTIONS.findIndex((section) => section.id === initialSection);
	let workspace = initialResourceWorkspace(initialSection);
	if (options.target) {
		workspace = updateWorkspacePage(workspace, options.target.sectionId, resourcePageFrom([{ id: options.target.id, kind: options.target.resource }], options.target.resource));
		workspace = setWorkspaceMode(workspace, options.target.sectionId, "detail");
	}
	return {
		mode: "browse",
		areaIndex: Math.max(0, sectionIndex),
		selection: 0,
		search: "",
		formValues: {},
		formIndex: 0,
		resultOffset: 0,
		confirmationInput: "",
		snapshots: {},
		receipts: [],
		workspace,
		workspaceFocus: options.target ? "resources" : "actions",
		workspaceActions: [],
		feedback: initialFeedbackState(),
		refresh: setVisiblePanel(initialPollingRefreshState(), initialSection),
		preferences: options.preferences ?? DEFAULT_TUI_PREFERENCES,
		quit: false,
	};
}

function describeError(cause: unknown): string {
	if (cause && typeof cause === "object") {
		const value = cause as { code?: unknown; message?: unknown; remediation?: unknown };
		const prefix = typeof value.code === "string" ? `[${value.code}] ` : "";
		const message = typeof value.message === "string" ? value.message : String(cause);
		const remediation = typeof value.remediation === "string" ? `\nNext: ${value.remediation}` : "";
		return sanitizeTerminalText(`${prefix}${message}${remediation}`);
	}
	return sanitizeTerminalText(cause instanceof Error ? cause.message : String(cause));
}

function receiptError(cause: unknown): OperationReceiptError | undefined {
	if (!cause || typeof cause !== "object") return undefined;
	const value = cause as { code?: unknown; message?: unknown; remediation?: unknown };
	if (typeof value.code !== "string" || typeof value.message !== "string") return undefined;
	return {
		code: value.code,
		message: value.message,
		remediation: typeof value.remediation === "string" ? value.remediation : undefined,
	};
}

function isEscape(key: string): boolean {
	return key === "\u001b";
}

function isBackspace(key: string): boolean {
	return key === "\u007f" || key === "\b";
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
	if (signal.aborted) return Promise.reject(signal.reason);
	return new Promise<T>((resolve, reject) => {
		const aborted = () => reject(signal.reason);
		signal.addEventListener("abort", aborted, { once: true });
		promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", aborted));
	});
}

export type TuiControllerSafetyOptions = {
	readonly identity?: VerifiedStartupIdentity;
	readonly receiptJournal?: OperationReceiptJournal;
	readonly revealSecret?: (secret: RevealedSecret) => void | Promise<void>;
	readonly now?: () => number;
	readonly createReceiptId?: () => string;
	readonly actions?: readonly WorkflowAction[];
	readonly adapters?: readonly WorkspaceSectionAdapter[];
	readonly preferences?: TuiPreferences;
	readonly initialTarget?: TuiDeepLinkTarget;
};

export class TuiController {
	readonly state: TuiState;
	readonly #executor: WorkflowExecutor;
	readonly #lanes = new RequestLanes();
	readonly #pending = new Set<Promise<void>>();
	readonly #onChange: () => void;
	readonly #global: Readonly<GlobalOpts>;
	readonly #secrets = new EphemeralSecretVault();
	readonly #journal?: OperationReceiptJournal;
	readonly #revealSecret?: (secret: RevealedSecret) => void | Promise<void>;
	readonly #now: () => number;
	readonly #createReceiptId: () => string;
	readonly #actions: readonly WorkflowAction[];
	readonly #adapters: readonly WorkspaceSectionAdapter[];
	#deepLinkTarget?: TuiDeepLinkTarget;
	#receiptSequence = 0;
	#journalTail: Promise<void> = Promise.resolve();

	constructor(
		executor: WorkflowExecutor,
		onChange: () => void = () => {},
		state: TuiState | undefined = undefined,
		global = executor.global ?? {},
		safety: TuiControllerSafetyOptions = {},
	) {
		this.#executor = executor;
		this.#onChange = onChange;
		this.state = state ?? initialTuiState({ preferences: safety.preferences, target: safety.initialTarget });
		this.#global = global;
		this.#journal = safety.receiptJournal;
		this.#revealSecret = safety.revealSecret;
		this.#now = safety.now ?? Date.now;
		this.#createReceiptId = safety.createReceiptId ?? (() => `op_${this.#now().toString(36)}_${(++this.#receiptSequence).toString(36)}`);
		this.#actions = safety.actions ?? WORKFLOW_ACTIONS;
		this.#adapters = safety.adapters ?? [];
		this.#deepLinkTarget = safety.initialTarget;
		if (safety.identity) this.state.identity = safety.identity;
		this.updateWorkspaceActions();
		if (safety.initialTarget) queueMicrotask(() => this.openDeepLink(safety.initialTarget!));
	}

	get area() {
		return WORKFLOW_AREAS[this.state.areaIndex] ?? WORKFLOW_AREAS[0];
	}

	get visibleActions(): readonly WorkflowAction[] {
		if (this.#actions === WORKFLOW_ACTIONS) return actionsFor(this.area, this.state.search);
		const query = this.state.search.trim().toLowerCase();
		return this.#actions.filter((action) => action.area === this.area && (!query || `${action.label} ${action.description} ${action.path}`.toLowerCase().includes(query)));
	}

	get selectedAction(): WorkflowAction | undefined {
		return this.visibleActions[this.state.selection];
	}

	handleKey(key: string): void {
		if (key === "\u0003") {
			this.quit();
			return;
		}
		if (this.state.feedback.modal) {
			this.state.feedback = closeModal(this.state.feedback);
			if (key.toLowerCase() === "r") this.refreshWorkspace();
			else this.changed();
			return;
		}
		if (this.state.mode === "help") {
			this.state.mode = "browse";
			this.changed();
			return;
		}
		if (this.state.mode === "search") {
			this.handleSearchKey(key);
			return;
		}
		if (this.state.mode === "form") {
			this.handleFormKey(key);
			return;
		}
		if (this.state.mode === "preview") {
			this.handlePreviewKey(key);
			return;
		}
		this.handleBrowseKey(key);
	}

	async waitForIdle(): Promise<void> {
		while (this.#pending.size) await Promise.all([...this.#pending]);
	}

	refreshVisibleWorkspace(): void {
		if (this.state.workspaceFocus !== "resources" || this.state.loading || this.state.mode !== "browse" || this.activeMutation()) return;
		this.refreshWorkspace(true);
	}

	quit(): boolean {
		if (this.activeMutation()) {
			this.state.notice = "A mutation is dispatching. Quit is blocked until its outcome is known; send SIGTERM only to detach with reconciliation required.";
			this.changed();
			return false;
		}
		this.#lanes.cancelAll();
		this.#secrets.clear();
		this.state.quit = true;
		this.changed();
		return true;
	}

	async detachAndQuit(signal: "SIGINT" | "SIGTERM"): Promise<void> {
		const active = this.activeMutation();
		if (!active) {
			this.quit();
			return;
		}
		if (active.generation !== undefined) this.#lanes.detach(active.actionId, active.generation);
		const receipt = this.receipt(active.receiptId);
		let detachedReceipt: OperationReceipt | undefined;
		if (receipt) {
			const settled: OperationReceipt = {
				...receipt,
				phase: "settled",
				completedAt: this.#now(),
				outcome: "indeterminate",
				reconciliationRequired: true,
				detached: true,
			};
			this.replaceReceipt(settled);
			this.state.mutation = {
				actionId: settled.actionId,
				phase: "settled",
				receiptId: settled.id,
				outcome: "indeterminate",
				reconciliationRequired: true,
				reconciliationCommands: settled.reconciliationCommands,
			};
			detachedReceipt = settled;
		}
		this.state.loading = undefined;
		this.state.notice = `${signal} detached from an in-flight mutation. Its outcome is indeterminate; reconcile before retrying.`;
		this.state.quit = true;
		this.changed();
		if (!detachedReceipt) return;
		try {
			await this.persistReceipt(detachedReceipt);
		} catch (cause) {
			this.state.notice = `${signal} detached from an in-flight mutation. Its outcome is indeterminate and the receipt update could not be persisted: ${describeError(cause)} Reconcile before retrying.`;
			this.changed();
		}
	}

	private activeMutation(): { receiptId: string; actionId: string; generation?: number } | undefined {
		if (!this.state.mutation?.receiptId) return undefined;
		if (this.state.mutation.phase !== "confirmed" && this.state.mutation.phase !== "dispatching") return undefined;
		return {
			receiptId: this.state.mutation.receiptId,
			actionId: this.state.mutation.actionId,
			generation: this.state.mutation.generation,
		};
	}

	private handleBrowseKey(key: string): void {
		if (key === "q") {
			this.quit();
			return;
		}
		if (key === "?") {
			this.state.mode = "help";
			this.changed();
			return;
		}
		if (key === "/") {
			this.state.mode = "search";
			this.changed();
			return;
		}
		if (key === "\t" && this.currentWorkspace().page.rows.length) {
			this.state.workspaceFocus = this.state.workspaceFocus === "actions" ? "resources" : "actions";
			this.changed();
			return;
		}
		if (key === "c" && (this.activeMutation() || this.state.loading)) {
			if (this.activeMutation()) {
				this.state.notice = "This mutation may already be running and cannot be cancelled safely. Wait for its receipt, then reconcile if required.";
				this.changed();
				return;
			}
			const loading = this.state.loading;
			if (!loading) return;
			this.#lanes.cancel(loading.actionId);
			this.state.loading = undefined;
			this.state.notice = "Stopped waiting locally. The read was aborted; the last good result remains available.";
			this.changed();
			return;
		}
		if (key === "v" && (this.state.workspaceFocus === "resources" || this.selectedAction && this.state.snapshots[this.selectedAction.id]?.data !== undefined)) {
			this.state.preferences = { ...this.state.preferences, rawJson: !this.state.preferences.rawJson };
			this.changed();
			return;
		}
		if (this.state.workspaceFocus === "resources") {
			if (key === "a") {
				if (this.state.workspaceActions.length) {
					this.state.workspace = setWorkspaceMode(this.state.workspace, this.state.workspace.sectionId, "actions");
					this.state.workspace = selectWorkspaceAction(this.state.workspace, this.state.workspace.sectionId, 0, this.state.workspaceActions.length);
				} else this.state.workspaceFocus = "actions";
				this.changed();
				return;
			}
			if (key === "r") return this.refreshWorkspace();
			if (key === "n" || key === "\u001b[6~") return this.changeWorkspacePage(1);
			if (key === "p" || key === "\u001b[5~") return this.changeWorkspacePage(-1);
			if (key === "[") return this.scrollWorkspace(-5);
			if (key === "]") return this.scrollWorkspace(5);
			if (key === "\u001b[A" || key === "k") {
				if (this.currentWorkspace().mode === "actions") return this.moveWorkspaceAction(-1);
				return this.moveWorkspaceSelection(-1);
			}
			if (key === "\u001b[B" || key === "j") {
				if (this.currentWorkspace().mode === "actions") return this.moveWorkspaceAction(1);
				return this.moveWorkspaceSelection(1);
			}
			if (key === "\r" || key === "\n") {
				if (this.currentWorkspace().mode === "actions") return this.openWorkspaceAction();
				this.state.workspace = setWorkspaceMode(this.state.workspace, this.state.workspace.sectionId, "detail");
				this.changed();
				return;
			}
			if (isEscape(key)) {
				if (this.currentWorkspace().mode === "actions") this.state.workspace = setWorkspaceMode(this.state.workspace, this.state.workspace.sectionId, "detail");
				else if (this.currentWorkspace().mode === "detail" || this.currentWorkspace().mode === "raw") this.state.workspace = setWorkspaceMode(this.state.workspace, this.state.workspace.sectionId, "list");
				else this.state.workspaceFocus = "actions";
				this.changed();
				return;
			}
		}
		if (key === "[") return this.scrollResult(-5);
		if (key === "]") return this.scrollResult(5);
		if (key === "\u001b[D" || key === "h") return this.moveArea(-1);
		if (key === "\u001b[C" || key === "l") return this.moveArea(1);
		if (key === "\u001b[A" || key === "k") return this.moveSelection(-1);
		if (key === "\u001b[B" || key === "j") return this.moveSelection(1);
		if (isEscape(key)) {
			if (this.state.search) {
				this.state.search = "";
				this.state.selection = 0;
				this.changed();
			}
			return;
		}
		if (key === "\r" || key === "\n" || key === "r") this.openSelected();
	}

	private handleSearchKey(key: string): void {
		if (isEscape(key)) {
			this.state.search = "";
			this.state.selection = 0;
			this.state.mode = "browse";
			this.changed();
			return;
		}
		if (key === "\r" || key === "\n") {
			this.state.mode = "browse";
			this.changed();
			return;
		}
		if (isBackspace(key)) this.state.search = Array.from(this.state.search).slice(0, -1).join("");
		else if (isPrintableKey(key)) this.state.search += key;
		this.state.selection = 0;
		this.changed();
	}

	private handleFormKey(key: string): void {
		const action = this.actionByForm();
		const field = action?.fields[this.state.formIndex];
		if (!action || !field || isEscape(key)) {
			this.#secrets.clear();
			this.state.formValues = {};
			this.state.mode = "browse";
			this.state.mutation = undefined;
			this.state.notice = isEscape(key) ? "Action cancelled before dispatch." : undefined;
			this.changed();
			return;
		}
		const current = this.state.formValues[field.key] ?? "";
		if (key === "\r" || key === "\n") {
			if (field.required && !this.fieldHasValue(field)) {
				this.state.notice = `${field.label} is required.`;
				this.changed();
				return;
			}
			if (this.state.formIndex < action.fields.length - 1) {
				this.state.formIndex += 1;
				this.state.notice = undefined;
				this.changed();
				return;
			}
			const missing = action.fields.find((candidate) => candidate.required && !this.fieldHasValue(candidate));
			if (missing) {
				this.state.formIndex = action.fields.indexOf(missing);
				this.state.notice = `${missing.label} is required.`;
				this.changed();
				return;
			}
			if (action.risk === "read") this.execute(action);
			else {
				this.state.mode = "preview";
				this.state.mutation = {
					actionId: action.id,
					phase: "preview",
					reconciliationRequired: false,
					reconciliationCommands: [],
				};
				this.state.notice = undefined;
				this.changed();
			}
			return;
		}
		if (key === "\t") {
			this.state.formIndex = (this.state.formIndex + 1) % action.fields.length;
			this.changed();
			return;
		}
		if (isSecretField(field)) {
			if (isBackspace(key)) this.#secrets.backspace(field.key);
			else if (isPrintableKey(key)) this.#secrets.append(field.key, key);
			if (this.#secrets.has(field.key)) this.state.formValues[field.key] = SECRET_MASK;
			else delete this.state.formValues[field.key];
		} else if (isBackspace(key)) this.state.formValues[field.key] = Array.from(current).slice(0, -1).join("");
		else if (isPrintableKey(key)) this.state.formValues[field.key] = current + key;
		this.state.notice = undefined;
		this.changed();
	}

	private fieldHasValue(field: WorkflowAction["fields"][number]): boolean {
		return isSecretField(field) ? this.#secrets.has(field.key) : Boolean(this.state.formValues[field.key]?.trim());
	}

	private handlePreviewKey(key: string): void {
		const action = this.actionByForm();
		if (isEscape(key) || (key === "n" && action?.risk !== "destructive")) {
			this.#secrets.clear();
			this.state.formValues = {};
			this.state.mode = "browse";
			this.state.mutation = undefined;
			this.state.confirmationInput = "";
			this.state.notice = "Mutation cancelled before dispatch.";
			this.changed();
			return;
		}
		if (!action) return;
		if (this.#global.dryRun && !action.supportsDryRun) {
			this.state.notice = `${action.path} has no server-side dry-run contract. Press Escape to cancel; this dry-run session will not dispatch it live.`;
			this.changed();
			return;
		}
		if (action.risk === "destructive" && !this.#global.dryRun) {
			if (key === "\u0004" && action.supportsDryRun && !this.state.confirmationInput) {
				this.confirmAndExecute(action, true);
				return;
			}
			if (key === "\r" || key === "\n") {
				if (this.state.confirmationInput === action.id) this.confirmAndExecute(action);
				else {
					this.state.notice = `Type ${action.id} exactly to confirm.`;
					this.changed();
				}
				return;
			}
			if (isBackspace(key)) this.state.confirmationInput = Array.from(this.state.confirmationInput).slice(0, -1).join("");
			else if (isPrintableKey(key)) this.state.confirmationInput += key;
			this.state.notice = undefined;
			this.changed();
			return;
		}
		if (key.toLowerCase() === "d" && action.supportsDryRun) {
			this.confirmAndExecute(action, true);
			return;
		}
		if (key.toLowerCase() === "y") this.confirmAndExecute(action);
	}

	private confirmAndExecute(action: WorkflowAction, forceDryRun = false): void {
		this.state.mutation = {
			actionId: action.id,
			phase: "confirmed",
			reconciliationRequired: false,
			reconciliationCommands: [],
		};
		this.changed();
		this.execute(action, forceDryRun);
	}

	private actionByForm(): WorkflowAction | undefined {
		const id = this.state.formValues.__action;
		return this.#actions.find((candidate) => candidate.id === id);
	}

	private openSelected(selected: WorkflowAction | undefined = this.selectedAction): void {
		if (this.activeMutation()) {
			this.state.notice = "Wait for the active mutation receipt before starting another operation.";
			this.changed();
			return;
		}
		const action = selected;
		if (!action) return;
		this.#secrets.clear();
		this.state.formValues = {
			__action: action.id,
			...(this.currentWorkspace().page.cursor && action.fields.some((field) => field.key === "cursor") ? { cursor: this.currentWorkspace().page.cursor } : {}),
		};
		this.state.formIndex = 0;
		this.state.confirmationInput = "";
		this.state.notice = undefined;
		this.state.mutation = action.mutation
			? {
				actionId: action.id,
				phase: action.fields.length ? "editing" : "preview",
				reconciliationRequired: false,
				reconciliationCommands: [],
			}
			: undefined;
		if (action.fields.length) this.state.mode = "form";
		else if (action.risk !== "read") this.state.mode = "preview";
		else this.execute(action);
		this.changed();
	}

	private execute(action: WorkflowAction, forceDryRun = false, automatic = false): void {
		const activeMutation = this.activeMutation();
		if (activeMutation) {
			// Mutation state is authoritative. Reads and a second mutation may not
			// replace its loading indicator or receipt lifecycle.
			if (action.mutation) {
				this.state.notice = "Wait for the active mutation receipt before starting another mutation.";
				this.changed();
			}
			return;
		}
		const rawValues = this.#secrets.materialize(this.state.formValues);
		const secretValues = this.#secrets.take();
		let invocation: WorkflowInvocation;
		try {
			invocation = action.invocation(rawValues, forceDryRun ? { ...this.#global, dryRun: true, yes: false } : this.#global);
			invocation = redactInvocationCommand(invocation, secretValues);
		} catch (cause) {
			this.state.mode = "browse";
			this.state.notice = `Mutation failed before dispatch: ${describeError(cause)}`;
			this.state.mutation = action.mutation
				? { actionId: action.id, phase: "settled", outcome: "failed_before_dispatch", reconciliationRequired: false, reconciliationCommands: [] }
				: undefined;
			this.changed();
			return;
		}

		for (const field of action.fields) if (isSecretField(field)) delete this.state.formValues[field.key];
		if (action.mutation) {
			this.#lanes.cancelReads();
			if (this.state.loading && !this.state.loading.mutation) this.state.loading = undefined;
		}
		const request = this.#lanes.start(action.id, action.mutation);
		const reconcile = action.mutation ? reconciliationCommands(action, invocation) : [];
		let receipt: OperationReceipt | undefined;
		if (action.mutation) {
			const operation = MANAGEMENT_OPERATIONS.find((candidate) => candidate.cliPath === action.path);
			if (!operation) {
				this.#lanes.finish(action.id, request.generation);
				this.state.mode = "browse";
				this.state.loading = undefined;
				this.state.mutation = {
					actionId: action.id,
					phase: "settled",
					outcome: "failed_before_dispatch",
					reconciliationRequired: false,
					reconciliationCommands: [],
				};
				this.state.notice = `Mutation failed before dispatch: no canonical operation exists for ${action.path}.`;
				this.changed();
				return;
			}
			receipt = {
				id: this.#createReceiptId(),
				operationId: operation.id,
				path: operation.cliPath,
				actionId: action.id,
				risk: action.risk,
				command: invocation.command,
				target: {
					profile: this.state.identity?.credentialSource === "environment"
						? "environment"
						: this.state.identity?.profile ?? this.#global.profile ?? "default",
					apiUrl: this.state.identity?.apiUrl ?? this.#global.apiUrl ?? "saved/default target",
					projectId: this.state.identity?.projectId,
					environmentId: this.state.identity?.environmentId,
				},
				phase: "confirmed",
				createdAt: this.#now(),
				reconciliationRequired: false,
				reconciliationCommands: reconcile,
			};
			this.state.receipts.push(receipt);
			this.state.mutation = {
				actionId: action.id,
				phase: "confirmed",
				receiptId: receipt.id,
				generation: request.generation,
				reconciliationRequired: false,
				reconciliationCommands: reconcile,
			};
		}
		this.state.mode = "browse";
		this.state.loading = { actionId: action.id, generation: request.generation, mutation: action.mutation };
		this.state.resultOffset = 0;
		this.state.confirmationInput = "";
		if (!automatic) this.state.notice = action.mutation ? `Confirmed ${invocation.command}; writing receipt before dispatch.` : `Running ${invocation.command}`;
		this.changed();

		const pending = this.runExecution(action, invocation, request, receipt, automatic);
		this.#pending.add(pending);
		void pending.finally(() => this.#pending.delete(pending));
	}

	private async runExecution(
		action: WorkflowAction,
		invocation: WorkflowInvocation,
		request: { generation: number; signal: AbortSignal },
		receipt: OperationReceipt | undefined,
		automatic: boolean,
	): Promise<void> {
		let currentReceipt = receipt;
		try {
			if (currentReceipt) {
				try {
					await this.persistReceipt(currentReceipt);
				} catch (cause) {
					if (!this.#lanes.isCurrent(action.id, request.generation)) return;
					await this.settleMutation(currentReceipt, "failed_before_dispatch", cause);
					return;
				}
				if (!this.#lanes.isCurrent(action.id, request.generation)) return;
				currentReceipt = {
					...currentReceipt,
					phase: "dispatching",
					dispatchedAt: this.#now(),
				};
				this.replaceReceipt(currentReceipt);
				this.state.mutation = {
					actionId: action.id,
					phase: "dispatching",
					receiptId: currentReceipt.id,
					generation: request.generation,
					reconciliationRequired: false,
					reconciliationCommands: currentReceipt.reconciliationCommands,
				};
				this.state.notice = `Dispatching ${invocation.command}`;
				this.changed();
				try {
					await this.persistReceipt(currentReceipt);
				} catch (cause) {
					if (!this.#lanes.isCurrent(action.id, request.generation)) return;
					await this.settleMutation(currentReceipt, "failed_before_dispatch", cause);
					return;
				}
				if (!this.#lanes.isCurrent(action.id, request.generation)) return;
			}

			let execution: Promise<unknown>;
			try {
				execution = this.#executor(invocation, {
					signal: request.signal,
					lane: action.id,
					generation: request.generation,
					mutation: action.mutation,
					...(currentReceipt ? {
						lifecycle: {
							receiptId: currentReceipt.id,
							operationId: currentReceipt.operationId,
							path: currentReceipt.path,
							startedAt: new Date(currentReceipt.createdAt).toISOString(),
							target: {
								principal: currentReceipt.target.profile,
								apiOrigin: currentReceipt.target.apiUrl,
								environment: currentReceipt.target.environmentId ?? currentReceipt.target.projectId,
							},
						},
						updateReceiptMetadata: (metadata) => this.updateReceiptMetadata(currentReceipt!.id, metadata),
					} : {}),
				});
			} catch (cause) {
				if (currentReceipt) await this.settleMutation(currentReceipt, "failed_before_dispatch", cause);
				else this.recordReadFailure(action, cause);
				return;
			}
			const result = await abortable(execution, request.signal);
			if (!this.#lanes.isCurrent(action.id, request.generation)) return;
			const runner = normalizeOperationRunnerResult(result);
			const data = runner ? runner.data : result;
			const redacted = redactSecretValues(data);
			let revealFailed = redacted.revealed.length > 0 && !this.#revealSecret;
			for (const secret of redacted.revealed) {
				try {
					if (this.#revealSecret) await this.#revealSecret(secret);
				} catch {
					revealFailed = true;
				}
			}
			const outcome = runner?.receipt.outcome ?? "succeeded";
			if (outcome === "succeeded") {
				this.state.snapshots[action.id] = { data: redacted.data, updatedAt: this.#now() };
				const productNotice = this.recordProductSuccess(action, redacted.data, invocation, automatic);
				if (!automatic) this.state.notice = revealFailed
					? "Operation succeeded, but a one-time secret could not be displayed. Rotate or reissue it before continuing."
					: redacted.revealed.length
						? "Operation succeeded. One-time secrets were revealed once and were not retained."
						: productNotice ?? `Completed ${invocation.command}`;
			} else {
				const previous = this.state.snapshots[action.id];
				const failure = runner?.receipt.error;
				this.state.snapshots[action.id] = { ...previous, error: failure ? describeError(failure) : `Operation ${outcome}.`, updatedAt: previous?.updatedAt };
				this.state.notice = action.mutation
					? `${outcomeNotice(outcome)}${failure ? ` ${describeError(failure)}` : ""}`
					: "Read failed. The last good result was preserved; retry when the target is reachable.";
			}
			if (currentReceipt) {
				await this.settleMutation(
					currentReceipt,
					outcome,
					runner?.receipt.error,
					runner?.receipt.requestId ?? undefined,
					runner?.receipt.reconciliationCommands,
					runner?.receipt.idempotencyKey ?? undefined,
				);
			}
		} catch (cause) {
			if (!this.#lanes.isCurrent(action.id, request.generation)) return;
			if (currentReceipt) {
				const details = operationFailureDetails(cause);
				await this.settleMutation(currentReceipt, details.outcome, cause, details.requestId, details.reconciliationCommands);
			} else this.recordReadFailure(action, cause);
		} finally {
			if (this.#lanes.isCurrent(action.id, request.generation)) {
				this.#lanes.finish(action.id, request.generation);
				if (this.state.loading?.actionId === action.id && this.state.loading.generation === request.generation) this.state.loading = undefined;
				this.changed();
			}
		}
	}

	private recordReadFailure(action: WorkflowAction, cause: unknown): void {
		const previous = this.state.snapshots[action.id];
		this.state.snapshots[action.id] = { ...previous, error: describeError(cause), updatedAt: previous?.updatedAt };
		this.state.notice = "Request failed. The last good result was preserved.";
		const offline = cause && typeof cause === "object" && "code" in cause && String(cause.code).includes("UNREACHABLE");
		this.state.refresh = markPollingRefreshFailed(this.state.refresh, { unreachable: Boolean(offline), now: this.#now() });
		this.state.feedback = upsertNotice(this.state.feedback, { id: `error:${action.id}`, message: this.state.notice, severity: "error", command: action.invocation({}, this.#global).command });
		this.state.feedback = showModal(this.state.feedback, {
			id: `error:${action.id}`,
			title: "Refresh failed",
			message: describeError(cause),
			severity: "error",
			actions: [{ id: "retry", label: "Retry", primary: true }, { id: "close", label: "Keep last result" }],
		});
	}

	private async settleMutation(
		receipt: OperationReceipt,
		outcome: OperationOutcome,
		cause?: unknown,
		requestId?: string,
		commands?: readonly string[],
		idempotencyKey?: string,
	): Promise<void> {
		if (this.receipt(receipt.id)?.detached) return;
		const reconciliationRequired = outcome === "indeterminate";
		const failure = receiptError(cause);
		const settled: OperationReceipt = {
			...receipt,
			phase: "settled",
			completedAt: this.#now(),
			outcome,
			requestId,
			idempotencyKey,
			error: failure,
			reconciliationRequired,
			reconciliationCommands: commands?.length ? commands : receipt.reconciliationCommands,
		};
		this.replaceReceipt(settled);
		this.state.mutation = {
			actionId: settled.actionId,
			phase: "settled",
			receiptId: settled.id,
			outcome,
			reconciliationRequired,
			reconciliationCommands: settled.reconciliationCommands,
		};
		if (cause) {
			const previous = this.state.snapshots[settled.actionId];
			this.state.snapshots[settled.actionId] = { ...previous, error: describeError(cause), updatedAt: previous?.updatedAt };
			this.state.notice = `${outcomeNotice(outcome)} ${describeError(cause)}`;
		}
		try {
			await this.persistReceipt(settled);
		} catch (journalCause) {
			this.state.notice = `${this.state.notice ?? outcomeNotice(outcome)} Receipt persistence failed: ${describeError(journalCause)}`;
		}
		this.changed();
	}

	private updateReceiptMetadata(
		receiptId: string,
		metadata: Readonly<{ dispatchedAt?: string; requestId?: string; idempotencyKey?: string }>,
	): void {
		const current = this.receipt(receiptId);
		if (!current || current.detached) return;
		const dispatchedAt = metadata.dispatchedAt === undefined ? current.dispatchedAt : Date.parse(metadata.dispatchedAt);
		this.replaceReceipt({
			...current,
			...(Number.isFinite(dispatchedAt) ? { dispatchedAt } : {}),
			...(metadata.requestId ? { requestId: metadata.requestId } : {}),
			...(metadata.idempotencyKey ? { idempotencyKey: metadata.idempotencyKey } : {}),
		});
	}

	private receipt(id: string): OperationReceipt | undefined {
		return this.state.receipts.find((candidate) => candidate.id === id);
	}

	private replaceReceipt(receipt: OperationReceipt): void {
		const index = this.state.receipts.findIndex((candidate) => candidate.id === receipt.id);
		if (index === -1) this.state.receipts.push(receipt);
		else this.state.receipts[index] = receipt;
	}

	private async persistReceipt(receipt: OperationReceipt): Promise<void> {
		const write = this.#journalTail
			.catch(() => {})
			.then(() => this.#journal?.record(receipt));
		this.#journalTail = write.then(() => {}, () => {});
		await write;
	}

	private moveArea(delta: number): void {
		this.state.areaIndex = (this.state.areaIndex + delta + WORKFLOW_AREAS.length) % WORKFLOW_AREAS.length;
		this.state.selection = 0;
		this.state.resultOffset = 0;
		this.state.notice = undefined;
		const section = WORKSPACE_SECTIONS[this.state.areaIndex]?.id ?? "overview";
		this.state.workspace = activateWorkspaceSection(this.state.workspace, section);
		this.state.preferences = { ...this.state.preferences, sectionId: section };
		this.state.refresh = setVisiblePanel(this.state.refresh, section);
		this.updateWorkspaceActions();
		this.changed();
	}

	private scrollResult(delta: number): void {
		this.state.resultOffset = Math.max(0, this.state.resultOffset + delta);
		this.changed();
	}

	private moveSelection(delta: number): void {
		const count = this.visibleActions.length;
		if (!count) return;
		this.state.selection = (this.state.selection + delta + count) % count;
		this.state.resultOffset = 0;
		this.state.notice = undefined;
		this.changed();
	}

	private currentWorkspace() {
		return this.state.workspace.sections[this.state.workspace.sectionId];
	}

	private moveWorkspaceSelection(delta: number): void {
		const current = this.currentWorkspace();
		if (!current.page.rows.length) return;
		const index = (current.selectedIndex + delta + current.page.rows.length) % current.page.rows.length;
		this.state.workspace = selectWorkspaceRow(this.state.workspace, this.state.workspace.sectionId, index);
		this.updateWorkspaceActions();
		this.changed();
	}

	private moveWorkspaceAction(delta: number): void {
		const current = this.currentWorkspace();
		this.state.workspace = selectWorkspaceAction(this.state.workspace, this.state.workspace.sectionId, current.actionIndex + delta, this.state.workspaceActions.length);
		this.changed();
	}

	private scrollWorkspace(delta: number): void {
		this.state.workspace = scrollWorkspaceDetail(this.state.workspace, this.state.workspace.sectionId, delta);
		this.changed();
	}

	private changeWorkspacePage(delta: -1 | 1): void {
		const before = this.currentWorkspace();
		const next = delta > 0
			? advanceWorkspaceCursor(this.state.workspace, this.state.workspace.sectionId)
			: retreatWorkspaceCursor(this.state.workspace, this.state.workspace.sectionId);
		if (next === this.state.workspace) {
			this.state.notice = delta > 0 ? "No next page is available." : "Already on the first page.";
			this.changed();
			return;
		}
		this.state.workspace = next;
		this.state.notice = undefined;
		this.refreshWorkspace(false);
		if (before.page.rows.length) this.changed();
	}

	private openWorkspaceAction(): void {
		if (this.activeMutation()) {
			this.state.notice = "Wait for the active mutation receipt before starting another operation.";
			this.changed();
			return;
		}
		const selected = this.state.workspaceActions[this.currentWorkspace().actionIndex];
		if (!selected) return;
		const action = this.#actions.find((candidate) => candidate.id === selected.actionId);
		if (!action) return;
		this.#secrets.clear();
		const values: Record<string, string> = { __action: action.id };
		let argumentIndex = 0;
		for (const field of action.fields) {
			if (field.argument) {
				const value = selected.invocation.args[argumentIndex++];
				if (value !== undefined) values[field.key] = value;
			} else {
				const value = selected.invocation.opts[field.key];
					if (Array.isArray(value)) values[field.key] = value.join(", ");
					else if (typeof value === "string") values[field.key] = value;
				else if (typeof value === "boolean") values[field.key] = String(value);
			}
		}
		this.state.formValues = values;
		this.state.confirmationInput = "";
		this.state.notice = undefined;
		if (action.risk === "read") this.execute(action);
		else {
			const firstEditable = action.fields.findIndex((field) => !values[field.key]);
			if (firstEditable >= 0) {
				this.state.formIndex = firstEditable;
				this.state.mode = "form";
				this.state.mutation = { actionId: action.id, phase: "editing", reconciliationRequired: false, reconciliationCommands: [] };
			} else {
				this.state.mode = "preview";
				this.state.mutation = { actionId: action.id, phase: "preview", reconciliationRequired: false, reconciliationCommands: [] };
			}
			this.changed();
		}
	}

	private openDeepLink(target: TuiDeepLinkTarget): void {
		if (this.activeMutation()) return;
		const inspectPaths: Readonly<Record<TuiDeepLinkTarget["resource"], string>> = {
			user: "users inspect",
			organization: "orgs inspect",
			event: "events inspect",
			delivery: "delivery inspect",
			sso: "sso inspect",
			scim: "scim inspect",
		};
		const fallbackPaths: Readonly<Partial<Record<TuiDeepLinkTarget["resource"], string>>> = {
			sso: "sso list",
			scim: "scim list",
		};
		const action = this.#actions.find((candidate) => candidate.path === inspectPaths[target.resource])
			?? this.#actions.find((candidate) => candidate.path === fallbackPaths[target.resource]);
		if (!action) {
			this.state.notice = `No inspect workflow is available for ${target.resource} ${target.id}.`;
			this.changed();
			return;
		}
		const idField = action.fields.find((field) => field.argument) ?? action.fields.find((field) => field.key === "id");
		this.state.formValues = { __action: action.id, ...(idField ? { [idField.key]: target.id } : {}) };
		if (action.risk === "read") this.execute(action);
		else {
			this.#deepLinkTarget = undefined;
			this.state.mode = "preview";
			this.state.mutation = { actionId: action.id, phase: "preview", reconciliationRequired: false, reconciliationCommands: [] };
			this.state.notice = `No read-only inspect operation exists for ${target.resource}; review the exact verification command before dispatch.`;
			this.changed();
		}
	}

	private updateWorkspaceActions(): void {
		const sectionId = this.state.workspace.sectionId;
		const current = this.state.workspace.sections[sectionId];
		const row = current.page.rows[current.selectedIndex];
		const adapter = this.#adapters.find((candidate) => candidate.definition.id === sectionId);
		this.state.workspaceActions = row && adapter ? adapter.rowActions(row, this.#actions, this.#global) : [];
	}

	private refreshWorkspace(automatic = false): void {
		const sectionId = this.state.workspace.sectionId;
		const preferred: Readonly<Record<string, string>> = {
			overview: "overview",
			people: "users list",
			security: "events list",
			operations: "readiness report",
		};
		const action = this.#actions.find((candidate) => candidate.path === preferred[sectionId]) ?? this.visibleActions.find((candidate) => candidate.risk === "read" && !candidate.fields.some((field) => field.required));
		if (!action) {
			this.state.notice = "This section needs a target before it can refresh.";
			this.changed();
			return;
		}
		if (automatic && action.fields.some((field) => field.required)) return;
		this.state.formValues = {
			__action: action.id,
			...(this.currentWorkspace().page.cursor && action.fields.some((field) => field.key === "cursor") ? { cursor: this.currentWorkspace().page.cursor } : {}),
		};
		if (action.fields.some((field) => field.required)) this.openSelected(action);
		else {
			this.state.refresh = markPollingRefreshStarted(this.state.refresh, this.#now());
			this.execute(action, false, automatic);
		}
	}

	private recordProductSuccess(action: WorkflowAction, data: unknown, invocation: WorkflowInvocation, automatic: boolean): string | undefined {
		const section = WORKSPACE_SECTIONS.find((candidate) => candidate.label === action.area);
		if (!section) return undefined;
		let productNotice: string | undefined;
		if (/(?:^| )list$/u.test(action.path) || action.path === "overview") {
			const adapter = this.#adapters.find((candidate) => candidate.definition.id === section.id);
			const root = action.path.split(" ")[0];
			const kind = root === "users" ? "user" : root === "orgs" ? "organization" : root === "events" ? "event" : root;
			const page = adapter?.resourcePage(data, kind) ?? resourcePageFrom(data, kind || section.resourceKinds[0]);
			this.state.workspace = updateWorkspacePage(this.state.workspace, section.id, page);
			this.state.workspace = activateWorkspaceSection(this.state.workspace, section.id);
			this.state.workspaceFocus = page.rows.length ? "resources" : "actions";
			if (this.#deepLinkTarget?.sectionId === section.id) {
				const index = page.rows.findIndex((row) => row.id === this.#deepLinkTarget?.id);
				if (index >= 0) {
					this.state.workspace = selectWorkspaceRow(this.state.workspace, section.id, index);
					this.state.workspace = setWorkspaceMode(this.state.workspace, section.id, "detail");
				} else productNotice = `${this.#deepLinkTarget.resource} ${this.#deepLinkTarget.id} was not found in the returned resources.`;
				this.#deepLinkTarget = undefined;
			}
			this.updateWorkspaceActions();
		} else if (/(?:^| )inspect$/u.test(action.path)) {
			const root = action.path.split(" ")[0];
			const kind = root === "users" ? "user" : root === "orgs" ? "organization" : root === "events" ? "event" : root;
			let page = resourcePageFrom(data, kind);
			const requestedId = invocation.args[0] ?? (typeof invocation.opts.id === "string" ? invocation.opts.id : undefined);
			const current = this.state.workspace.sections[section.id];
			const inspected = page.rows[0];
			if (!inspected) {
				productNotice = "The result has no stable resource identity, so it remains in the action result instead of creating a synthetic workspace row.";
				this.#deepLinkTarget = undefined;
			} else if (requestedId && current.page.rows.some((row) => row.id === requestedId)) {
				page = {
					...current.page,
					rows: current.page.rows.map((row) => row.id === requestedId ? inspected : row),
				};
			}
			if (inspected) {
				this.state.workspace = updateWorkspacePage(this.state.workspace, section.id, page);
				this.state.workspace = activateWorkspaceSection(this.state.workspace, section.id);
				this.state.workspace = setWorkspaceMode(this.state.workspace, section.id, "detail");
				this.state.workspaceFocus = "resources";
				this.#deepLinkTarget = undefined;
				this.updateWorkspaceActions();
			}
		}
		if (!automatic) this.state.feedback = pushToast(this.state.feedback, { id: `success:${action.id}`, message: `${action.label} completed.`, severity: "success" }, this.#now());
		this.state.feedback = dismissNotice(this.state.feedback, `error:${action.id}`);
		this.state.refresh = markPollingRefreshSucceeded(this.state.refresh, this.#now());
		return productNotice;
	}

	private changed(): void {
		this.#onChange();
	}
}

function outcomeNotice(outcome: OperationOutcome): string {
	switch (outcome) {
		case "succeeded": return "Mutation succeeded and its receipt was recorded.";
		case "rejected": return "Mutation was rejected; no retry is needed until the request is corrected.";
		case "failed_before_dispatch": return "Mutation failed before dispatch; it is safe to correct the problem and retry.";
		case "indeterminate": return "Mutation outcome is indeterminate. Run the receipt's reconciliation command before retrying.";
	}
}

function isPrintableKey(key: string): boolean {
	return Array.from(key).length === 1 && !/[\u0000-\u001f\u007f-\u009f]/u.test(key);
}
