import type { ObservabilityHandle } from "./bootstrap";

export type ObservabilitySignal = "SIGINT" | "SIGTERM";
type ObservabilityShutdownEvent = ObservabilitySignal | "beforeExit";

export interface ObservabilityShutdownTarget {
	once(event: ObservabilityShutdownEvent, listener: () => void): void;
	removeListener(event: ObservabilityShutdownEvent, listener: () => void): void;
	terminate(signal: ObservabilitySignal): void;
}

function processTarget(): ObservabilityShutdownTarget {
	return {
		once: (event, listener) => {
			process.once(event, listener);
		},
		removeListener: (event, listener) => {
			process.removeListener(event, listener);
		},
		terminate: (signal) => {
			try {
				// Re-send only after removing our listeners. Node then applies its
				// normal signal termination and conventional exit status.
				process.kill(process.pid, signal);
			} catch {
				process.exitCode = signal === "SIGINT" ? 130 : 143;
			}
		},
	};
}

/** Installs one shared bounded flush for natural and signal-driven shutdown. */
export function installObservabilityShutdownHandlers(
	handle: ObservabilityHandle,
	target: ObservabilityShutdownTarget = processTarget(),
): () => void {
	let shutdown: Promise<void> | undefined;
	let terminatingSignal: ObservabilitySignal | undefined;

	const shutdownOnce = () => {
		shutdown ??= handle.shutdown().then(
			() => undefined,
			() => undefined,
		);
		return shutdown;
	};
	const beforeExit = () => {
		void shutdownOnce();
	};
	const terminateAfterShutdown = (signal: ObservabilitySignal) => {
		if (terminatingSignal) return;
		terminatingSignal = signal;
		void shutdownOnce().finally(() => {
			uninstall();
			target.terminate(signal);
		});
	};
	const onSigint = () => terminateAfterShutdown("SIGINT");
	const onSigterm = () => terminateAfterShutdown("SIGTERM");
	const uninstall = () => {
		target.removeListener("beforeExit", beforeExit);
		target.removeListener("SIGINT", onSigint);
		target.removeListener("SIGTERM", onSigterm);
	};

	target.once("beforeExit", beforeExit);
	target.once("SIGINT", onSigint);
	target.once("SIGTERM", onSigterm);
	return uninstall;
}
