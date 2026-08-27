import { actionsFor, WORKFLOW_ACTIONS, WORKFLOW_AREAS } from "./catalog.js";
import type { GlobalOpts } from "../output.js";
import type { TuiState, WorkflowAction, WorkflowExecutor } from "./types.js";

type ActiveRequest = { generation: number; controller: AbortController };

export class RequestLanes {
	readonly #active = new Map<string, ActiveRequest>();
	readonly #generations = new Map<string, number>();

	start(lane: string): { generation: number; signal: AbortSignal } {
		this.cancel(lane);
		const generation = (this.#generations.get(lane) ?? 0) + 1;
		const controller = new AbortController();
		this.#generations.set(lane, generation);
		this.#active.set(lane, { generation, controller });
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

	cancelAll(): void {
		for (const lane of [...this.#active.keys()]) this.cancel(lane);
	}
}

export function initialTuiState(): TuiState {
	return {
		mode: "browse",
		areaIndex: 0,
		selection: 0,
		search: "",
		formValues: {},
		formIndex: 0,
		resultOffset: 0,
		confirmationInput: "",
		snapshots: {},
		quit: false,
	};
}

function describeError(cause: unknown): string {
	if (cause && typeof cause === "object") {
		const value = cause as { code?: unknown; message?: unknown; remediation?: unknown };
		const prefix = typeof value.code === "string" ? `[${value.code}] ` : "";
		const message = typeof value.message === "string" ? value.message : String(cause);
		const remediation = typeof value.remediation === "string" ? `\nNext: ${value.remediation}` : "";
		return `${prefix}${message}${remediation}`;
	}
	return cause instanceof Error ? cause.message : String(cause);
}

function isEscape(key: string): boolean {
	return key === "\u001b";
}

function isBackspace(key: string): boolean {
	return key === "\u007f" || key === "\b";
}

export class TuiController {
	readonly state: TuiState;
	readonly #executor: WorkflowExecutor;
	readonly #lanes = new RequestLanes();
	readonly #pending = new Set<Promise<void>>();
	readonly #onChange: () => void;
	readonly #global: Readonly<GlobalOpts>;

	constructor(executor: WorkflowExecutor, onChange: () => void = () => {}, state = initialTuiState(), global = executor.global ?? {}) {
		this.#executor = executor;
		this.#onChange = onChange;
		this.state = state;
		this.#global = global;
	}

	get area() {
		return WORKFLOW_AREAS[this.state.areaIndex] ?? WORKFLOW_AREAS[0];
	}

	get visibleActions(): readonly WorkflowAction[] {
		return actionsFor(this.area, this.state.search);
	}

	get selectedAction(): WorkflowAction | undefined {
		return this.visibleActions[this.state.selection];
	}

	handleKey(key: string): void {
		if (key === "\u0003") {
			this.quit();
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
		await Promise.all([...this.#pending]);
	}

	quit(): void {
		this.#lanes.cancelAll();
		this.state.quit = true;
		this.changed();
	}

	private handleBrowseKey(key: string): void {
		if (key === "q") return this.quit();
		if (key === "?") {
			this.state.mode = "help";
			return this.changed();
		}
		if (key === "/") {
			this.state.mode = "search";
			return this.changed();
		}
		if (key === "c" && this.state.loading) {
			const running = WORKFLOW_ACTIONS.find((action) => action.id === this.state.loading?.actionId);
			if (running?.mutation) {
				this.state.notice = "This mutation may already be running and cannot be cancelled safely. Wait for its result, then inspect the resource to reconcile.";
				return this.changed();
			}
			this.#lanes.cancel(this.state.loading.actionId);
			this.state.loading = undefined;
			this.state.notice = "Stopped waiting locally. The remote outcome is unknown; re-run this read to reconcile.";
			return this.changed();
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
			return this.changed();
		}
		if (key === "\r" || key === "\n") {
			this.state.mode = "browse";
			return this.changed();
		}
		if (isBackspace(key)) this.state.search = this.state.search.slice(0, -1);
		else if (isPrintableKey(key)) this.state.search += key;
		this.state.selection = 0;
		this.changed();
	}

	private handleFormKey(key: string): void {
		const action = this.actionByForm();
		const field = action?.fields[this.state.formIndex];
		if (!action || !field || isEscape(key)) {
			this.state.mode = "browse";
			this.state.notice = isEscape(key) ? "Action cancelled." : undefined;
			return this.changed();
		}
		const current = this.state.formValues[field.key] ?? "";
		if (key === "\r" || key === "\n") {
			if (field.required && !current.trim()) {
				this.state.notice = `${field.label} is required.`;
				return this.changed();
			}
			if (this.state.formIndex < action.fields.length - 1) {
				this.state.formIndex += 1;
				this.state.notice = undefined;
				return this.changed();
			}
			const missing = action.fields.find((candidate) => candidate.required && !this.state.formValues[candidate.key]?.trim());
			if (missing) {
				this.state.formIndex = action.fields.indexOf(missing);
				this.state.notice = `${missing.label} is required.`;
				return this.changed();
			}
			if (action.risk === "read") this.execute(action);
			else {
				this.state.mode = "preview";
				this.state.notice = undefined;
				this.changed();
			}
			return;
		}
		if (key === "\t") {
			this.state.formIndex = (this.state.formIndex + 1) % action.fields.length;
			return this.changed();
		}
		if (isBackspace(key)) this.state.formValues[field.key] = current.slice(0, -1);
		else if (isPrintableKey(key)) this.state.formValues[field.key] = current + key;
		this.state.notice = undefined;
		this.changed();
	}

	private handlePreviewKey(key: string): void {
		const action = this.actionByForm();
		if (isEscape(key) || (key === "n" && action?.risk !== "destructive")) {
			this.state.mode = "browse";
			this.state.confirmationInput = "";
			this.state.notice = "Mutation cancelled before dispatch.";
			return this.changed();
		}
		if (!action) return;
		if (key.toLowerCase() === "d" && action.supportsDryRun) {
			this.execute(action, true);
			return;
		}
		if (action.risk === "destructive" && !this.#global.dryRun) {
			if (key === "\r" || key === "\n") {
				if (this.state.confirmationInput === action.id) this.execute(action);
				else {
					this.state.notice = `Type ${action.id} exactly to confirm.`;
					this.changed();
				}
				return;
			}
			if (isBackspace(key)) this.state.confirmationInput = this.state.confirmationInput.slice(0, -1);
			else if (isPrintableKey(key)) this.state.confirmationInput += key;
			this.state.notice = undefined;
			this.changed();
			return;
		}
		if (key.toLowerCase() === "y") {
			this.execute(action);
		}
	}

	private actionByForm(): WorkflowAction | undefined {
		const id = this.state.formValues.__action;
		return WORKFLOW_ACTIONS.find((candidate) => candidate.id === id);
	}

	private openSelected(): void {
		const action = this.selectedAction;
		if (!action) return;
		this.state.formValues = { __action: action.id };
		this.state.formIndex = 0;
		this.state.confirmationInput = "";
		this.state.notice = undefined;
		if (action.fields.length) this.state.mode = "form";
		else if (action.risk !== "read") this.state.mode = "preview";
		else this.execute(action);
		this.changed();
	}

	private execute(action: WorkflowAction, forceDryRun = false): void {
		const invocation = action.invocation(this.state.formValues, forceDryRun ? { ...this.#global, dryRun: true, yes: false } : this.#global);
		const request = this.#lanes.start(action.id);
		this.state.mode = "browse";
		this.state.loading = { actionId: action.id, generation: request.generation };
		this.state.resultOffset = 0;
		this.state.confirmationInput = "";
		this.state.notice = `Running ${invocation.command}`;
		this.changed();
		const pending = this.#executor(invocation, {
			signal: request.signal,
			lane: action.id,
			generation: request.generation,
		}).then((data) => {
			if (!this.#lanes.isCurrent(action.id, request.generation)) return;
			this.state.snapshots[action.id] = { data, updatedAt: Date.now() };
			this.state.notice = `Completed ${invocation.command}`;
		}).catch((cause) => {
			if (!this.#lanes.isCurrent(action.id, request.generation)) return;
			const previous = this.state.snapshots[action.id];
			this.state.snapshots[action.id] = { ...previous, error: describeError(cause), updatedAt: previous?.updatedAt };
			this.state.notice = "Request failed. The last good result was preserved.";
		}).finally(() => {
			if (this.#lanes.isCurrent(action.id, request.generation)) {
				this.#lanes.finish(action.id, request.generation);
				if (this.state.loading?.actionId === action.id && this.state.loading.generation === request.generation) {
					this.state.loading = undefined;
				}
				this.changed();
			}
		});
		this.#pending.add(pending);
		void pending.finally(() => this.#pending.delete(pending));
	}

	private moveArea(delta: number): void {
		this.state.areaIndex = (this.state.areaIndex + delta + WORKFLOW_AREAS.length) % WORKFLOW_AREAS.length;
		this.state.selection = 0;
		this.state.resultOffset = 0;
		this.state.notice = undefined;
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

	private changed(): void {
		this.#onChange();
	}
}

function isPrintableKey(key: string): boolean {
	return key.length === 1 && !/[\u0000-\u001f\u007f-\u009f]/u.test(key);
}
