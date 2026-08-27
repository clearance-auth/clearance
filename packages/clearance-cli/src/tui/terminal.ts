import { sanitizeTerminalText } from "../terminal-sanitize.js";
import { terminalWidth, truncateTerminalText, wrapTerminalText } from "../terminal-width.js";

const SGR_SEQUENCE = /\u001b\[[0-9;]*m/gu;

export type TerminalTheme = "dark" | "light";

export interface TerminalAppearance {
	readonly color: boolean;
	readonly theme: TerminalTheme;
}

function graphemes(value: string): readonly string[] {
	const Segmenter = Intl.Segmenter;
	if (!Segmenter) return Array.from(value);
	return [...new Segmenter(undefined, { granularity: "grapheme" }).segment(value)]
		.map((part) => part.segment);
}

/** Returns display cells, not UTF-16 code units. */
export function cellWidth(value: string): number {
	return terminalWidth(value);
}

export function truncateCells(value: string, width: number, ellipsis = "…"): string {
	return truncateTerminalText(value, width, ellipsis);
}

export function padCells(value: string, width: number): string {
	const clipped = truncateCells(value, width);
	return clipped + " ".repeat(Math.max(0, width - cellWidth(clipped)));
}

/** Preserves renderer-owned SGR styles while discarding all other escape sequences. */
export function truncateStyledCells(value: string, width: number): string {
	if (width <= 0) return "";
	const tokens = value.split(/(\u001b\[[0-9;]*m)/gu);
	let output = "";
	let used = 0;
	let styled = false;
	for (const token of tokens) {
		if (!token) continue;
		if (SGR_SEQUENCE.test(token)) {
			output += token;
			styled = token !== "\u001b[0m";
			SGR_SEQUENCE.lastIndex = 0;
			continue;
		}
		for (const grapheme of graphemes(sanitizeTerminalText(token))) {
			const next = terminalWidth(grapheme);
			if (used + next > width) return output + (styled ? "\u001b[0m" : "");
			output += grapheme;
			used += next;
		}
	}
	return output;
}

export function padStyledCells(value: string, width: number): string {
	const clipped = truncateStyledCells(value, width);
	return clipped + " ".repeat(Math.max(0, width - cellWidth(clipped)));
}

export function wrapCells(value: unknown, width: number, limit = Number.POSITIVE_INFINITY): readonly string[] {
	return width <= 0 || limit <= 0 ? [] : wrapTerminalText(value, width).slice(0, limit);
}

export { sanitizeTerminalText };

export function resolveTerminalAppearance(input: {
	readonly requestedColor?: boolean;
	readonly requestedTheme?: "auto" | TerminalTheme;
	readonly env?: Readonly<Record<string, string | undefined>>;
	readonly isTTY?: boolean;
} = {}): TerminalAppearance {
	const env = input.env ?? process.env;
	const color = env.NO_COLOR !== undefined
		? false
		: input.requestedColor ?? (input.isTTY !== false && env.TERM !== "dumb");
	const theme = input.requestedTheme === "light" || input.requestedTheme === "dark"
		? input.requestedTheme
		: env.COLORFGBG?.split(";").at(-1) && Number(env.COLORFGBG.split(";").at(-1)) >= 8 ? "light" : "dark";
	return { color, theme };
}
