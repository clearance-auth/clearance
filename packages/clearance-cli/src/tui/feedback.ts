export type FeedbackSeverity = "info" | "success" | "warning" | "error";

export interface Toast {
	readonly id: string;
	readonly message: string;
	readonly severity: FeedbackSeverity;
	readonly createdAt: number;
	readonly expiresAt: number;
}

export interface BlockingModal {
	readonly id: string;
	readonly title: string;
	readonly message: string;
	readonly severity: FeedbackSeverity;
	readonly actions: readonly { readonly id: string; readonly label: string; readonly primary?: boolean }[];
}

export interface PersistentNotice {
	readonly id: string;
	readonly message: string;
	readonly severity: Exclude<FeedbackSeverity, "success">;
	readonly command?: string;
}

export interface FeedbackState {
	readonly toasts: readonly Toast[];
	readonly notices: readonly PersistentNotice[];
	readonly modal?: BlockingModal;
}

export function initialFeedbackState(): FeedbackState {
	return Object.freeze({ toasts: [], notices: [] });
}

export function pushToast(
	state: FeedbackState,
	toast: Omit<Toast, "createdAt" | "expiresAt"> & { readonly durationMs?: number },
	now = Date.now(),
): FeedbackState {
	const duration = Math.min(30_000, Math.max(1_000, toast.durationMs ?? 4_000));
	return Object.freeze({
		...state,
		toasts: Object.freeze([
			...state.toasts.filter((candidate) => candidate.id !== toast.id && candidate.expiresAt > now),
			Object.freeze({ id: toast.id, message: toast.message, severity: toast.severity, createdAt: now, expiresAt: now + duration }),
		]),
	});
}

export function expireToasts(state: FeedbackState, now = Date.now()): FeedbackState {
	return Object.freeze({ ...state, toasts: Object.freeze(state.toasts.filter((toast) => toast.expiresAt > now)) });
}

export function upsertNotice(state: FeedbackState, notice: PersistentNotice): FeedbackState {
	return Object.freeze({
		...state,
		notices: Object.freeze([...state.notices.filter((candidate) => candidate.id !== notice.id), Object.freeze(notice)]),
	});
}

export function dismissNotice(state: FeedbackState, id: string): FeedbackState {
	return Object.freeze({ ...state, notices: Object.freeze(state.notices.filter((notice) => notice.id !== id)) });
}

export function showModal(state: FeedbackState, modal: BlockingModal): FeedbackState {
	return Object.freeze({ ...state, modal: Object.freeze(modal) });
}

export function closeModal(state: FeedbackState, id?: string): FeedbackState {
	if (id && state.modal?.id !== id) return state;
	const { modal: _modal, ...rest } = state;
	return Object.freeze(rest);
}

export type HelpContext =
	| "navigation"
	| "action-list"
	| "resource-list"
	| "resource-detail"
	| "form"
	| "preview"
	| "modal"
	| "raw";

export interface HelpBinding {
	readonly keys: string;
	readonly label: string;
}

const HELP_BINDINGS: Readonly<Record<HelpContext, readonly HelpBinding[]>> = Object.freeze({
	navigation: Object.freeze([{ keys: "←/→", label: "section" }, { keys: "/", label: "search" }, { keys: "?", label: "help" }]),
	"action-list": Object.freeze([{ keys: "↑/↓", label: "select" }, { keys: "Enter", label: "open" }, { keys: "?", label: "help" }]),
	"resource-list": Object.freeze([{ keys: "↑/↓", label: "select" }, { keys: "Enter", label: "inspect" }, { keys: "?", label: "help" }]),
	"resource-detail": Object.freeze([{ keys: "Esc", label: "list" }, { keys: "a", label: "actions" }, { keys: "?", label: "help" }]),
	form: Object.freeze([{ keys: "Tab", label: "next field" }, { keys: "Enter", label: "review" }, { keys: "Esc", label: "cancel" }]),
	preview: Object.freeze([{ keys: "y", label: "dispatch" }, { keys: "d", label: "dry run" }, { keys: "Esc", label: "cancel" }]),
	modal: Object.freeze([{ keys: "←/→", label: "action" }, { keys: "Enter", label: "choose" }, { keys: "Esc", label: "close" }]),
	raw: Object.freeze([{ keys: "v", label: "structured view" }, { keys: "[/]", label: "scroll" }, { keys: "Esc", label: "back" }]),
});

export function contextualHelp(context: HelpContext, width = 120): readonly HelpBinding[] {
	const bindings = HELP_BINDINGS[context];
	let used = 0;
	return bindings.filter((binding) => {
		const next = binding.keys.length + binding.label.length + 3;
		if (used + next > Math.max(16, width)) return false;
		used += next;
		return true;
	});
}

export function renderHelpBindings(bindings: readonly HelpBinding[]): string {
	return bindings.map((binding) => `${binding.keys} ${binding.label}`).join(" • ");
}
