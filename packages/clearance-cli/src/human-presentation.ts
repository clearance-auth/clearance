import { sanitizeTerminalText } from "./terminal-sanitize.js";
import { terminalWidth, truncateTerminalText, wrapTerminalText } from "./terminal-width.js";

export type HumanOperationKind = "list" | "detail" | "mutation";
export interface HumanField { readonly label: string; readonly value: unknown; readonly group?: string; }
export interface HumanTableColumn { readonly key: string; readonly label: string; readonly minWidth?: number; readonly maxWidth?: number; }
export interface HumanListPresentation {
	readonly kind: "list";
	readonly title: string;
	readonly columns: readonly HumanTableColumn[];
	readonly rows: readonly Readonly<Record<string, unknown>>[];
	/** Non-row fields from the response envelope, including pagination state. */
	readonly fields?: readonly HumanField[];
	readonly empty?: string;
	readonly summary?: string;
	readonly next?: readonly string[];
	readonly rawJsonCommand?: string;
}
export interface HumanDetailPresentation {
	readonly kind: "detail";
	readonly title: string;
	readonly fields: readonly HumanField[];
	readonly summary?: string;
	readonly next?: readonly string[];
	readonly rawJsonCommand?: string;
}
export interface HumanMutationPresentation {
	readonly kind: "mutation";
	readonly title: string;
	readonly receipt: readonly HumanField[];
	readonly summary?: string;
	readonly next?: readonly string[];
	readonly rawJsonCommand?: string;
}
export type HumanPresentation = HumanListPresentation | HumanDetailPresentation | HumanMutationPresentation;

export interface HumanPresentationOptions { readonly width?: number; }

function clean(value: unknown): string {
	if (value === null) return "null";
	if (value === undefined) return "";
	if (typeof value === "string") return sanitizeTerminalText(value);
	if (typeof value === "object") return "[structured value]";
	return sanitizeTerminalText(String(value));
}

function oneLine(value: unknown): string { return clean(value).replace(/\s+/gu, " ").trim(); }
function heading(value: string): string { return oneLine(value); }

function fieldLabel(value: string): string {
	return oneLine(value)
		.replace(/([a-z0-9])([A-Z])/gu, "$1 $2")
		.replace(/[_-]+/gu, " ")
		.replace(/^./u, (character) => character.toUpperCase());
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function flattenedFields(
	field: HumanField,
	seen: WeakSet<object> = new WeakSet(),
	depth = 0,
): HumanField[] {
	const { value } = field;
	if (value === null || typeof value !== "object") return [field];
	if (seen.has(value)) return [{ ...field, value: "[circular value]" }];
	if (depth >= 5) return [{ ...field, value: "[nested value]" }];
	seen.add(value);
	try {
		if (Array.isArray(value)) {
			if (value.length === 0) return [{ ...field, value: "None" }];
			if (value.every((item) => item === null || typeof item !== "object")) {
				return [{ ...field, value: value.map(oneLine).join(", ") }];
			}
			return value.flatMap((item, index) => flattenedFields({
				...field,
				label: `${field.label} ${index + 1}`,
				value: item,
			}, seen, depth + 1));
		}
		if (isRecord(value)) {
			const entries = Object.entries(value);
			if (entries.length === 0) return [{ ...field, value: "None" }];
			return entries.flatMap(([key, nested]) => flattenedFields({
				...field,
				label: `${field.label} / ${fieldLabel(key)}`,
				value: nested,
			}, seen, depth + 1));
		}
		return [{ ...field, value: String(value) }];
	} finally {
		seen.delete(value);
	}
}

function fieldLines(fields: readonly HumanField[], width: number): string[] {
	const groups = new Map<string, HumanField[]>();
	for (const field of fields.flatMap((entry) => flattenedFields(entry))) {
		const group = oneLine(field.group ?? "Details");
		groups.set(group, [...(groups.get(group) ?? []), field]);
	}
	const output: string[] = [];
	for (const [group, entries] of groups) {
		if (output.length > 0) output.push("");
		output.push(group);
		const labelWidth = Math.min(24, Math.max(...entries.map((field) => terminalWidth(oneLine(field.label)))));
		for (const field of entries) {
			const label = oneLine(field.label);
			const prefix = `${label}${" ".repeat(Math.max(0, labelWidth - terminalWidth(label)))}  `;
			const values = wrapTerminalText(clean(field.value), Math.max(1, width - terminalWidth(prefix)));
			output.push(`${prefix}${values[0] ?? ""}`);
			for (const continuation of values.slice(1)) output.push(`${" ".repeat(terminalWidth(prefix))}${continuation}`);
		}
	}
	return output;
}

/** Render a terminal-safe, width-aware table. Narrow terminals use labeled rows. */
export function renderResponsiveTable(columns: readonly HumanTableColumn[], rows: readonly Readonly<Record<string, unknown>>[], width = 80): string {
	const safeWidth = Math.max(20, Math.min(500, width));
	const labels = columns.map((column) => oneLine(column.label));
	const minimums = columns.map((column, index) => Math.max(3, column.minWidth ?? terminalWidth(labels[index])));
	const separatorWidth = Math.max(0, columns.length - 1) * 3;
	if (columns.length === 0 || rows.length === 0) return "";
	if (minimums.reduce((sum, value) => sum + value, 0) + separatorWidth > safeWidth) {
		return rows.flatMap((row, rowIndex) => [
			...(rowIndex > 0 ? ["─".repeat(safeWidth)] : []),
			...columns.flatMap((column) => {
				const prefix = `${oneLine(column.label)}: `;
				const lines = wrapTerminalText(oneLine(row[column.key]), Math.max(1, safeWidth - terminalWidth(prefix)));
				return lines.map((line, index) => `${index === 0 ? prefix : " ".repeat(terminalWidth(prefix))}${line}`);
			}),
		]).join("\n");
	}
	const desired = columns.map((column, index) => Math.min(
		column.maxWidth ?? safeWidth,
		Math.max(minimums[index], terminalWidth(labels[index]), ...rows.map((row) => terminalWidth(oneLine(row[column.key])))),
	));
	const widths = [...minimums];
	let remaining = safeWidth - separatorWidth - widths.reduce((sum, value) => sum + value, 0);
	while (remaining > 0 && widths.some((value, index) => value < desired[index])) {
		for (let index = 0; index < widths.length && remaining > 0; index += 1) {
			if (widths[index] < desired[index]) { widths[index]++; remaining--; }
		}
	}
	const format = (values: readonly string[]) => values.map((value, index) => {
		const clipped = truncateTerminalText(value, widths[index]);
		return `${clipped}${" ".repeat(Math.max(0, widths[index] - terminalWidth(clipped)))}`;
	}).join(" │ ").trimEnd();
	return [format(labels), format(widths.map((column) => "─".repeat(column))), ...rows.map((row) => format(columns.map((column) => oneLine(row[column.key]))))].join("\n");
}

/** Present list, detail, and mutation results as a consistent human CLI receipt. */
export function renderHumanPresentation(presentation: HumanPresentation, options: HumanPresentationOptions = {}): string {
	const width = Math.max(20, Math.min(500, options.width ?? 80));
	const sections: string[] = [heading(presentation.title)];
	if (presentation.summary) sections.push(...wrapTerminalText(clean(presentation.summary), width));
	if (presentation.kind === "list") {
		sections.push(presentation.rows.length === 0
			? clean(presentation.empty ?? "No results found.")
			: renderResponsiveTable(presentation.columns, presentation.rows, width));
		if (presentation.fields && presentation.fields.length > 0) {
			sections.push(fieldLines(presentation.fields, width).join("\n"));
		}
	} else {
		sections.push(fieldLines(presentation.kind === "mutation" ? presentation.receipt : presentation.fields, width).join("\n"));
	}
	if (presentation.next && presentation.next.length > 0) {
		sections.push("Next:\n" + presentation.next.flatMap((item) => {
			const lines = wrapTerminalText(oneLine(item), Math.max(1, width - 4));
			return lines.map((line, index) => `${index === 0 ? "  - " : "    "}${line}`);
		}).join("\n"));
	}
	if (presentation.rawJsonCommand) {
		const lines = wrapTerminalText(oneLine(presentation.rawJsonCommand), Math.max(1, width - 10));
		sections.push(lines.map((line, index) => `${index === 0 ? "Raw JSON: " : "          "}${line}`).join("\n"));
	}
	return sections.filter((section) => section.length > 0).join("\n\n");
}
