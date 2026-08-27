import { sanitizeTerminalText } from "./terminal-sanitize.js";

export interface HumanSuccessContent {
	data: unknown;
	summary: string | null;
	notice: string | null;
	next: readonly string[];
}

function oneLine(value: unknown): string {
	return sanitizeTerminalText(value, { preserveNewlines: true, preserveTabs: true })
		.replace(/[\n\t]+/gu, " ")
		.replace(/ {2,}/gu, " ")
		.trim();
}

function label(key: string): string {
	return oneLine(key)
		.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
		.replace(/[_-]+/g, " ")
		.replace(/^./, (character) => character.toUpperCase());
}

function scalar(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string") return oneLine(value);
	if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") {
		return String(value);
	}
	try {
		return oneLine(JSON.stringify(value));
	} catch {
		return "[unrenderable value]";
	}
}

function renderArray(values: readonly unknown[], indent: string): string[] {
	if (values.length === 0) return [`${indent}[]`];
	return values.flatMap((value) => {
		if (value !== null && typeof value === "object") {
			const nested = renderHumanData(value, `${indent}  `);
			const [first = "", ...rest] = nested.split("\n");
			return [`${indent}- ${first.trimStart()}`, ...rest];
		}
		return [`${indent}- ${scalar(value)}`];
	});
}

/** Render arbitrary command data without changing or filtering its shape. */
export function renderHumanData(data: unknown, indent = ""): string {
	const safeIndent = sanitizeTerminalText(indent, { preserveNewlines: false, preserveTabs: false });
	if (Array.isArray(data)) return renderArray(data, safeIndent).join("\n");
	if (data !== null && typeof data === "object") {
		const entries = Object.entries(data as Record<string, unknown>);
		if (entries.length === 0) return `${safeIndent}{}`;
		return entries.flatMap(([key, value]) => {
			if (Array.isArray(value)) {
				return [`${safeIndent}${label(key)}:`, ...renderArray(value, `${safeIndent}  `)];
			}
			if (value !== null && typeof value === "object") {
				return [`${safeIndent}${label(key)}:`, renderHumanData(value, `${safeIndent}  `)];
			}
			return [`${safeIndent}${label(key)}: ${scalar(value)}`];
		}).join("\n");
	}
	return `${safeIndent}${scalar(data)}`;
}

export function renderHumanSuccess(content: Readonly<HumanSuccessContent>): string {
	const sections: string[] = [];
	if (content.summary) sections.push(oneLine(content.summary));
	else sections.push(renderHumanData(content.data));
	if (content.notice) sections.push(`Notice: ${oneLine(content.notice)}`);
	if (content.next.length > 0) {
		sections.push(["Next:", ...content.next.map((step) => `  - ${oneLine(step)}`)].join("\n"));
	}
	return sections.join("\n\n");
}

export function renderHumanError(error: {
	code: string;
	message: string;
	stage: string;
	remediation: string | null;
}): string {
	const lines = [`Error [${oneLine(error.code)}] stage=${oneLine(error.stage)}: ${oneLine(error.message)}`];
	if (error.remediation) lines.push(`Remediation: ${oneLine(error.remediation)}`);
	return lines.join("\n");
}
