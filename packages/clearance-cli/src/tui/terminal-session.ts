import type { TuiIO, TuiProcessSignals } from "./types.js";

const ENTER_TERMINAL = "\u001b[?1049h\u001b[?25l";
const RESTORE_TERMINAL = "\u001b[?25h\u001b[0m\u001b[?1049l";

/** Owns raw mode and the alternate screen, restoring every resource exactly once. */
export class TerminalSession {
	readonly #io: TuiIO;
	#entered = false;
	#restored = false;
	#raw = false;
	#restoreErrors: unknown[] = [];

	constructor(io: TuiIO) {
		this.#io = io;
	}

	get restoreErrors(): readonly unknown[] {
		return this.#restoreErrors;
	}

	enter(): void {
		if (this.#entered && !this.#restored) return;
		if (this.#restored) throw new Error("A restored terminal session cannot be entered again.");
		this.#entered = true;
		try {
			this.#io.output.write(ENTER_TERMINAL);
			this.#raw = true;
			this.#io.input.setRawMode?.(true);
			this.#io.input.resume();
		} catch (cause) {
			this.restore();
			throw cause;
		}
	}

	restore(): void {
		if (this.#restored || !this.#entered) return;
		this.#restored = true;
		if (this.#raw) {
			try {
				this.#io.input.setRawMode?.(false);
			} catch (cause) {
				this.#restoreErrors.push(cause);
			}
			this.#raw = false;
		}
		try {
			this.#io.input.pause();
		} catch (cause) {
			this.#restoreErrors.push(cause);
		}
		try {
			this.#io.output.write(RESTORE_TERMINAL);
		} catch (cause) {
			this.#restoreErrors.push(cause);
		}
	}
}

export function attachTerminalSignals(
	signals: TuiProcessSignals,
	handler: (signal: "SIGINT" | "SIGTERM") => void,
): () => void {
	const onSigint = () => handler("SIGINT");
	const onSigterm = () => handler("SIGTERM");
	signals.on("SIGINT", onSigint);
	signals.on("SIGTERM", onSigterm);
	let attached = true;
	return () => {
		if (!attached) return;
		attached = false;
		signals.off("SIGINT", onSigint);
		signals.off("SIGTERM", onSigterm);
	};
}
