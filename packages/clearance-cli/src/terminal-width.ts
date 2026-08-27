import { sanitizeTerminalText } from "./terminal-sanitize.js";

const segmenter = typeof Intl.Segmenter === "function"
	? new Intl.Segmenter(undefined, { granularity: "grapheme" })
	: undefined;

function graphemes(value: string): string[] {
	return segmenter ? Array.from(segmenter.segment(value), ({ segment }) => segment) : Array.from(value);
}

function codePointWidth(codePoint: number): number {
	// Combining marks, joiners, and variation selectors occupy no cells on
	// their own. The ranges cover Unicode combining blocks and common scripts.
	if ((codePoint >= 0x300 && codePoint <= 0x36f) || (codePoint >= 0x483 && codePoint <= 0x489)
		|| (codePoint >= 0x591 && codePoint <= 0x5bd) || (codePoint >= 0x5bf && codePoint <= 0x5bf)
		|| (codePoint >= 0x5c1 && codePoint <= 0x5c2) || (codePoint >= 0x5c4 && codePoint <= 0x5c5)
		|| (codePoint >= 0x610 && codePoint <= 0x61a) || (codePoint >= 0x64b && codePoint <= 0x65f)
		|| (codePoint >= 0x670 && codePoint <= 0x670) || (codePoint >= 0x6d6 && codePoint <= 0x6ed)
		|| (codePoint >= 0x730 && codePoint <= 0x74a) || (codePoint >= 0x7a6 && codePoint <= 0x7b0)
		|| (codePoint >= 0x7eb && codePoint <= 0x7f3) || (codePoint >= 0x7fd && codePoint <= 0x7fd)
		|| (codePoint >= 0x816 && codePoint <= 0x819) || (codePoint >= 0x81b && codePoint <= 0x823)
		|| (codePoint >= 0x825 && codePoint <= 0x827) || (codePoint >= 0x829 && codePoint <= 0x82d)
		|| (codePoint >= 0x859 && codePoint <= 0x85b) || (codePoint >= 0x8d3 && codePoint <= 0x903)
		|| (codePoint >= 0x93a && codePoint <= 0x93c) || (codePoint >= 0x93e && codePoint <= 0x94f)
		|| (codePoint >= 0x951 && codePoint <= 0x957) || (codePoint >= 0x1ab0 && codePoint <= 0x1aff)
		|| (codePoint >= 0x1dc0 && codePoint <= 0x1dff) || (codePoint >= 0x20d0 && codePoint <= 0x20ff)
		|| (codePoint >= 0xfe00 && codePoint <= 0xfe0f) || (codePoint >= 0xfe20 && codePoint <= 0xfe2f)
		|| (codePoint >= 0xe0100 && codePoint <= 0xe01ef) || codePoint === 0x200d) return 0;
	if ((codePoint >= 0x1100 && codePoint <= 0x115f) || (codePoint >= 0x2329 && codePoint <= 0x232a)
		|| (codePoint >= 0x2e80 && codePoint <= 0xa4cf && codePoint !== 0x303f)
		|| (codePoint >= 0xac00 && codePoint <= 0xd7a3) || (codePoint >= 0xf900 && codePoint <= 0xfaff)
		|| (codePoint >= 0xfe10 && codePoint <= 0xfe19) || (codePoint >= 0xfe30 && codePoint <= 0xfe6f)
		|| (codePoint >= 0xff00 && codePoint <= 0xff60) || (codePoint >= 0xffe0 && codePoint <= 0xffe6)
		|| (codePoint >= 0x1f000 && codePoint <= 0x1faff) || (codePoint >= 0x20000 && codePoint <= 0x3fffd)) return 2;
	return 1;
}

/** Terminal cell width for sanitized text, calculated by grapheme cluster. */
export function terminalWidth(value: unknown): number {
	return Math.max(0, ...sanitizeTerminalText(value).split("\n").map((line) =>
		graphemes(line.replaceAll("\t", "    ")).reduce((total, grapheme) => {
			const width = Math.max(0, ...Array.from(grapheme, (character) => codePointWidth(character.codePointAt(0)!)));
			return total + width;
		}, 0)));
}

/** Truncate without splitting a grapheme cluster. */
export function truncateTerminalText(value: unknown, maxWidth: number, ellipsis = "…"): string {
	if (maxWidth <= 0) return "";
	const text = sanitizeTerminalText(value, { preserveNewlines: false, preserveTabs: false });
	if (terminalWidth(text) <= maxWidth) return text;
	const marker = sanitizeTerminalText(ellipsis, { preserveNewlines: false, preserveTabs: false });
	const markerWidth = terminalWidth(marker);
	if (markerWidth >= maxWidth) return graphemes(marker).filter((part) => terminalWidth(part) <= maxWidth).slice(0, 1).join("");
	let output = "";
	let used = 0;
	for (const part of graphemes(text)) {
		const width = terminalWidth(part);
		if (used + width + markerWidth > maxWidth) break;
		output += part;
		used += width;
	}
	return `${output}${marker}`;
}

/** Wrap sanitized text to terminal cells without splitting grapheme clusters. */
export function wrapTerminalText(value: unknown, maxWidth: number): string[] {
	if (maxWidth <= 0) return [];
	const lines: string[] = [];
	const pushChunked = (word: string): string => {
		let line = "";
		let used = 0;
		for (const part of graphemes(word)) {
			const width = terminalWidth(part);
			if (used > 0 && used + width > maxWidth) {
				lines.push(line);
				line = "";
				used = 0;
			}
			if (width > maxWidth) continue;
			line += part;
			used += width;
		}
		return line;
	};
	for (const sourceLine of sanitizeTerminalText(value).split("\n")) {
		const words = sourceLine.replaceAll("\t", "    ").trim().split(/\s+/u).filter(Boolean);
		if (words.length === 0) {
			lines.push("");
			continue;
		}
		let line = "";
		for (const word of words) {
			const separator = line ? " " : "";
			if (terminalWidth(line) + terminalWidth(separator) + terminalWidth(word) <= maxWidth) {
				line += `${separator}${word}`;
				continue;
			}
			if (line) {
				lines.push(line);
				line = "";
			}
			line = terminalWidth(word) <= maxWidth ? word : pushChunked(word);
		}
		if (line || words.length > 0) lines.push(line);
	}
	return lines;
}
