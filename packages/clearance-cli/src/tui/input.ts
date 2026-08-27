import { StringDecoder } from "node:string_decoder";

const ESC = "\u001b";

function terminalSequenceEnd(value: string, start: number): number {
	for (let index = start; index < value.length; index += 1) {
		const code = value.charCodeAt(index);
		if (code >= 0x40 && code <= 0x7e) return index;
	}
	return -1;
}

function stringTerminator(value: string, start: number): number {
	for (let index = start; index < value.length; index += 1) {
		if (value[index] === "\u0007") return index + 1;
		if (value[index] === ESC && value[index + 1] === "\\") return index + 2;
	}
	return -1;
}

/** Stateful decoder so split escape and UTF-8 sequences cannot leak bytes into form input. */
export class TerminalInputDecoder {
	readonly #text = new StringDecoder("utf8");
	#buffer = "";

	get hasPendingInput(): boolean {
		return this.#buffer.length > 0;
	}

	push(data: Buffer | string): string[] {
		this.#buffer += this.#text.write(typeof data === "string" ? Buffer.from(data, "utf8") : data);
		return this.drain(false);
	}

	flush(): string[] {
		this.#buffer += this.#text.end();
		return this.drain(true);
	}

	reset(): void {
		this.#buffer = "";
		this.#text.end();
	}

	private drain(final: boolean): string[] {
		const keys: string[] = [];
		let index = 0;
		while (index < this.#buffer.length) {
			if (this.#buffer[index] !== ESC) {
				const point = this.#buffer.codePointAt(index);
				if (point === undefined) break;
				const key = String.fromCodePoint(point);
				keys.push(key);
				index += key.length;
				continue;
			}

			if (index + 1 >= this.#buffer.length) {
				if (final) {
					keys.push(ESC);
					index += 1;
				}
				break;
			}

			const introducer = this.#buffer[index + 1];
			if (introducer === "[") {
				const end = terminalSequenceEnd(this.#buffer, index + 2);
				if (end === -1) {
					if (final) index = this.#buffer.length;
					break;
				}
				const finalByte = this.#buffer[end];
				if (finalByte === "A" || finalByte === "B" || finalByte === "C" || finalByte === "D") keys.push(`${ESC}[${finalByte}`);
				index = end + 1;
				continue;
			}

			if (introducer === "O") {
				const end = terminalSequenceEnd(this.#buffer, index + 2);
				if (end === -1) {
					if (final) index = this.#buffer.length;
					break;
				}
				const finalByte = this.#buffer[end];
				if (finalByte === "A" || finalByte === "B" || finalByte === "C" || finalByte === "D") keys.push(`${ESC}[${finalByte}`);
				index = end + 1;
				continue;
			}

			if (introducer === "]" || introducer === "P" || introducer === "X" || introducer === "^" || introducer === "_") {
				const end = stringTerminator(this.#buffer, index + 2);
				if (end === -1) {
					if (final) index = this.#buffer.length;
					break;
				}
				index = end;
				continue;
			}

			// Unknown two-byte, intermediate, and Alt escape sequences are swallowed atomically.
			let end = index + 1;
			while (end < this.#buffer.length) {
				const code = this.#buffer.charCodeAt(end);
				if (code >= 0x30 && code <= 0x7e) {
					end += 1;
					break;
				}
				if (code < 0x20 || code > 0x2f) break;
				end += 1;
			}
			if (end > this.#buffer.length || (end === this.#buffer.length && this.#buffer.charCodeAt(end - 1) < 0x30)) {
				if (final) index = this.#buffer.length;
				break;
			}
			index = Math.max(end, index + 2);
		}

		this.#buffer = this.#buffer.slice(index);
		return keys;
	}
}

export function decodeInput(data: Buffer | string): string[] {
	const decoder = new TerminalInputDecoder();
	return [...decoder.push(data), ...decoder.flush()];
}
