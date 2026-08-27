import { ClearanceError } from "@clearance/management";

const MAX_PASSWORD_BYTES = 4_096;

export interface PasswordPromptInput {
	readonly isTTY?: boolean;
	readonly isRaw?: boolean;
	readonly readableFlowing?: boolean | null;
	isPaused(): boolean;
	setRawMode(mode: boolean): unknown;
	resume(): unknown;
	pause(): unknown;
	on(event: "data", listener: (chunk: Buffer | string) => void): unknown;
	on(event: "end" | "close", listener: () => void): unknown;
	on(event: "error", listener: (cause: Error) => void): unknown;
	off(event: "data", listener: (chunk: Buffer | string) => void): unknown;
	off(event: "end" | "close", listener: () => void): unknown;
	off(event: "error", listener: (cause: Error) => void): unknown;
}

export interface PasswordPromptOutput {
	write(value: string): unknown;
}

function inputError(code: string, message: string, remediation: string): ClearanceError {
	return new ClearanceError({
		code,
		message,
		stage: "cli.password-input",
		status: 400,
		remediation,
	});
}

function passwordFromInput(input: string): string {
	if (Buffer.byteLength(input, "utf8") > MAX_PASSWORD_BYTES) {
		throw inputError(
			"USER_CREATE_PASSWORD_TOO_LARGE",
			"Initial password input exceeds the 4096-byte limit.",
			"Provide a shorter password.",
		);
	}
	if (input.length === 0) {
		throw inputError(
			"USER_CREATE_PASSWORD_EMPTY",
			"Initial password input cannot be empty.",
			"Provide a non-empty password, or omit password options to issue a setup token.",
		);
	}
	return input;
}

/** Read a secret without echo and restore the caller's exact terminal ownership state. */
export function readPasswordPrompt(
	input: PasswordPromptInput,
	output: PasswordPromptOutput,
): Promise<string> {
	if (!input.isTTY || typeof input.setRawMode !== "function") {
		return Promise.reject(inputError(
			"USER_CREATE_PASSWORD_PROMPT_TTY_REQUIRED",
			"--password-prompt requires an interactive terminal.",
			"Use --password-stdin with piped input, or omit password options to issue a setup token.",
		));
	}

	const initialRaw = input.isRaw === true;
	const initialPaused = input.isPaused();
	const initialFlowing = input.readableFlowing;
	return new Promise<string>((resolve, reject) => {
		let value = "";
		let settled = false;
		let rawModeChanged = false;

		const restore = () => {
			input.off("data", onData);
			input.off("end", onEnd);
			input.off("close", onEnd);
			input.off("error", onError);
			if (rawModeChanged) {
				try { input.setRawMode(initialRaw); } catch { /* terminal is already unavailable */ }
			}
			if (initialFlowing === true && !initialPaused) input.resume();
			else input.pause();
			output.write("\n");
		};
		const finish = (result: { value: string } | { error: unknown }) => {
			if (settled) return;
			settled = true;
			restore();
			if ("error" in result) reject(result.error);
			else resolve(result.value);
		};
		const cancelled = () => inputError(
			"USER_CREATE_PASSWORD_PROMPT_CANCELLED",
			"Initial password prompt was cancelled.",
			"Retry with --password-prompt, --password-stdin, or omit password options to issue a setup token.",
		);
		function onEnd() { finish({ error: cancelled() }); }
		function onError() {
			finish({ error: inputError(
				"USER_CREATE_PASSWORD_PROMPT_FAILED",
				"Initial password could not be read from the terminal.",
				"Retry in a terminal, or use --password-stdin with piped input.",
			) });
		}
		function onData(chunk: Buffer | string) {
			for (const character of typeof chunk === "string" ? chunk : chunk.toString("utf8")) {
				if (character === "\r" || character === "\n") {
					try { finish({ value: passwordFromInput(value) }); }
					catch (cause) { finish({ error: cause }); }
					return;
				}
				if (character === "\u0003" || character === "\u0004") {
					finish({ error: cancelled() });
					return;
				}
				if (character === "\u007f" || character === "\b") {
					value = [...value].slice(0, -1).join("");
					continue;
				}
				if (character >= " ") value += character;
				if (Buffer.byteLength(value, "utf8") > MAX_PASSWORD_BYTES) {
					finish({ error: inputError(
						"USER_CREATE_PASSWORD_TOO_LARGE",
						"Initial password input exceeds the 4096-byte limit.",
						"Provide a shorter password.",
					) });
					return;
				}
			}
		}

		try {
			input.setRawMode(true);
			rawModeChanged = true;
			input.on("data", onData);
			input.on("end", onEnd);
			input.on("close", onEnd);
			input.on("error", onError);
			input.resume();
			output.write("Initial password: ");
		} catch {
			finish({ error: inputError(
				"USER_CREATE_PASSWORD_PROMPT_FAILED",
				"Initial password prompt could not take control of the terminal.",
				"Retry in a terminal, or use --password-stdin with piped input.",
			) });
		}
	});
}
