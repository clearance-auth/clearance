import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { readPasswordPrompt, type PasswordPromptInput } from "./password-prompt.js";

function terminalInput(initialRaw = false): PassThrough & PasswordPromptInput {
	const input = new PassThrough() as PassThrough & PasswordPromptInput;
	Object.defineProperties(input, {
		isTTY: { value: true, configurable: true },
		isRaw: { value: initialRaw, writable: true, configurable: true },
		setRawMode: {
			value: vi.fn((mode: boolean) => { input.isRaw = mode; return input; }),
			configurable: true,
		},
	});
	return input;
}

describe("password prompt terminal lifecycle", () => {
	it("restores raw and paused state after a completed prompt", async () => {
		const input = terminalInput();
		input.pause();
		const output = { write: vi.fn() };
		const pending = readPasswordPrompt(input, output);
		input.write("sëcret\r");
		await expect(pending).resolves.toBe("sëcret");
		expect(input.setRawMode).toHaveBeenNthCalledWith(1, true);
		expect(input.setRawMode).toHaveBeenLastCalledWith(false);
		expect(input.isPaused()).toBe(true);
		expect(output.write).toHaveBeenCalledWith("\n");
	});

	it("settles and restores the terminal when input closes without Enter", async () => {
		const input = terminalInput(true);
		const output = { write: vi.fn() };
		const pending = readPasswordPrompt(input, output);
		input.end();
		await expect(pending).rejects.toMatchObject({ code: "USER_CREATE_PASSWORD_PROMPT_CANCELLED" });
		expect(input.setRawMode).toHaveBeenLastCalledWith(true);
		expect(input.isPaused()).toBe(true);
	});
});
