/** The TUI refreshes the visible workspace with an interval poller. It has no push connection. */
export type PollingRefreshStatus = "polling" | "refreshing" | "offline";

export interface PollingRefreshState {
	readonly status: PollingRefreshStatus;
	readonly visiblePanel?: string;
	readonly lastAttemptAt?: number;
	readonly lastSuccessfulAt?: number;
	readonly staleSince?: number;
}

export function initialPollingRefreshState(): PollingRefreshState {
	return Object.freeze({ status: "polling" });
}

export function setVisiblePanel(state: PollingRefreshState, panel?: string): PollingRefreshState {
	return Object.freeze({ ...state, visiblePanel: panel });
}

export function markPollingRefreshStarted(state: PollingRefreshState, now = Date.now()): PollingRefreshState {
	return Object.freeze({ ...state, status: "refreshing", lastAttemptAt: now });
}

export function markPollingRefreshSucceeded(state: PollingRefreshState, now = Date.now()): PollingRefreshState {
	return Object.freeze({
		...state,
		status: "polling",
		lastAttemptAt: state.lastAttemptAt ?? now,
		lastSuccessfulAt: now,
		staleSince: undefined,
	});
}

export function markPollingRefreshFailed(
	state: PollingRefreshState,
	options: { readonly unreachable: boolean; readonly now?: number },
): PollingRefreshState {
	const now = options.now ?? Date.now();
	return Object.freeze({
		...state,
		status: options.unreachable ? "offline" : "polling",
		lastAttemptAt: state.lastAttemptAt ?? now,
		...(options.unreachable ? { staleSince: state.staleSince ?? now } : {}),
	});
}
