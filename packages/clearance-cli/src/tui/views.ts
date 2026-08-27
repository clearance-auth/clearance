import { cellWidth, padCells, sanitizeTerminalText, truncateCells, wrapCells } from "./terminal.js";

export type StructuredView =
	| { readonly kind: "empty"; readonly message: string }
	| { readonly kind: "list"; readonly rows: readonly Readonly<Record<string, unknown>>[]; readonly columns: readonly string[] }
	| { readonly kind: "detail"; readonly groups: readonly DetailGroup[] }
	| { readonly kind: "diff"; readonly entries: readonly DiffEntry[] }
	| { readonly kind: "raw"; readonly value: unknown };

export interface DetailGroup {
	readonly label: string;
	readonly fields: readonly { readonly label: string; readonly value: unknown }[];
}

export interface DiffEntry {
	readonly path: string;
	readonly before?: unknown;
	readonly after?: unknown;
	readonly state: "added" | "removed" | "changed" | "unchanged";
}

const PREFERRED_COLUMNS = ["id", "name", "displayName", "email", "status", "state", "action", "createdAt"] as const;
const IDENTITY_FIELDS = new Set(["id", "name", "displayName", "email", "slug", "type", "kind"]);
const STATUS_FIELDS = new Set(["status", "state", "phase", "enabled", "active", "verified"]);
const METADATA_FIELDS = new Set(["createdAt", "updatedAt", "timestamp", "requestId", "traceId"]);

function record(value: unknown): Readonly<Record<string, unknown>> | undefined {
	return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Readonly<Record<string, unknown>> : undefined;
}

function rowsFrom(value: unknown): readonly Readonly<Record<string, unknown>>[] | undefined {
	if (Array.isArray(value)) return value.map((item) => record(item) ?? Object.freeze({ value: item }));
	const container = record(value);
	for (const key of [
		"items", "data", "results", "users", "organizations", "members", "memberships", "events", "deliveries", "jobs", "endpoints",
		"connections", "sessions", "roles", "apiKeys", "serviceAccounts", "projects", "environments", "domains", "templates", "backups",
	]) {
		if (Array.isArray(container?.[key])) return (container[key] as unknown[]).map((item) => record(item) ?? Object.freeze({ value: item }));
	}
	return undefined;
}

function humanLabel(key: string): string {
	return sanitizeTerminalText(key).replace(/([a-z0-9])([A-Z])/gu, "$1 $2").replace(/[_-]+/gu, " ").replace(/^./u, (letter) => letter.toUpperCase());
}

function scalar(value: unknown): string {
	if (value === null) return "null";
	if (value === undefined) return "—";
	if (typeof value === "string") return sanitizeTerminalText(value);
	if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return String(value);
	try { return sanitizeTerminalText(JSON.stringify(value)); } catch { return sanitizeTerminalText(String(value)); }
}

function chooseColumns(rows: readonly Readonly<Record<string, unknown>>[]): readonly string[] {
	const keys = new Set(rows.flatMap((row) => Object.keys(row)));
	const selected = PREFERRED_COLUMNS.filter((column) => keys.has(column)).slice(0, 4);
	if (selected.length) return selected;
	return [...keys].slice(0, 4);
}

function flattenDiff(before: unknown, after: unknown, prefix = ""): readonly DiffEntry[] {
	const left = record(before);
	const right = record(after);
	if (left || right) {
		const keys = [...new Set([...Object.keys(left ?? {}), ...Object.keys(right ?? {})])].sort();
		return keys.flatMap((key) => flattenDiff(left?.[key], right?.[key], prefix ? `${prefix}.${key}` : key));
	}
	const equal = JSON.stringify(before) === JSON.stringify(after);
	return [Object.freeze({
		path: prefix || "value",
		...(before !== undefined ? { before } : {}),
		...(after !== undefined ? { after } : {}),
		state: equal ? "unchanged" : before === undefined ? "added" : after === undefined ? "removed" : "changed",
	})];
}

export function structuredViewFor(value: unknown, options: { readonly raw?: boolean; readonly resultShape?: string } = {}): StructuredView {
	if (options.raw) return Object.freeze({ kind: "raw", value });
	if (value === undefined || value === null) return Object.freeze({ kind: "empty", message: "No result yet." });
	const container = record(value);
	if (options.resultShape === "diff" || (container && "before" in container && "after" in container)) {
		return Object.freeze({ kind: "diff", entries: Object.freeze(flattenDiff(container?.before, container?.after).filter((entry) => entry.state !== "unchanged")) });
	}
	const rows = rowsFrom(value);
	if (rows) {
		if (!rows.length) return Object.freeze({ kind: "empty", message: "No resources match this view." });
		return Object.freeze({ kind: "list", rows: Object.freeze(rows), columns: Object.freeze(chooseColumns(rows)) });
	}
	if (container) {
		const groups = [
			{ label: "Identity", include: (key: string) => IDENTITY_FIELDS.has(key) },
			{ label: "Status", include: (key: string) => STATUS_FIELDS.has(key) },
			{ label: "Metadata", include: (key: string) => METADATA_FIELDS.has(key) },
			{ label: "Details", include: (key: string) => !IDENTITY_FIELDS.has(key) && !STATUS_FIELDS.has(key) && !METADATA_FIELDS.has(key) },
		].map((group) => Object.freeze({
			label: group.label,
			fields: Object.freeze(Object.entries(container).filter(([key]) => group.include(key)).map(([key, fieldValue]) => Object.freeze({ label: humanLabel(key), value: fieldValue }))),
		})).filter((group) => group.fields.length);
		return Object.freeze({ kind: "detail", groups: Object.freeze(groups) });
	}
	return Object.freeze({ kind: "detail", groups: Object.freeze([{ label: "Result", fields: Object.freeze([{ label: "Value", value }]) }]) });
}

function renderTable(view: Extract<StructuredView, { kind: "list" }>, width: number): readonly string[] {
	const gutter = 3 * Math.max(0, view.columns.length - 1);
	const available = Math.max(view.columns.length * 4, width - gutter);
	const natural = view.columns.map((column) => Math.max(cellWidth(humanLabel(column)), ...view.rows.slice(0, 100).map((row) => cellWidth(scalar(row[column])))));
	const widthPerColumn = Math.max(4, Math.floor(available / Math.max(1, view.columns.length)));
	const widths = natural.map((columnWidth) => Math.min(columnWidth, widthPerColumn));
	const renderRow = (values: readonly string[]) => values.map((value, index) => padCells(value, widths[index] ?? 4)).join(" │ ");
	return Object.freeze([
		renderRow(view.columns.map(humanLabel)),
		widths.map((columnWidth) => "─".repeat(columnWidth)).join("─┼─"),
		...view.rows.map((row) => renderRow(view.columns.map((column) => scalar(row[column])))),
	]);
}

export function renderStructuredView(
	view: StructuredView,
	options: { readonly width?: number; readonly height?: number; readonly command?: string } = {},
): readonly string[] {
	const width = Math.max(16, options.width ?? 80);
	const height = Math.max(1, options.height ?? 20);
	const output: string[] = [];
	if (options.command) output.push(`CLI  ${truncateCells(options.command, Math.max(1, width - 5))}`, "");
	if (view.kind === "empty") output.push(view.message);
	if (view.kind === "list") output.push(...renderTable(view, width));
	if (view.kind === "detail") {
		for (const group of view.groups) {
			if (output.length) output.push("");
			output.push(group.label);
			const labelWidth = Math.min(24, Math.max(6, ...group.fields.map((field) => cellWidth(field.label))));
			for (const field of group.fields) {
				const prefix = `${padCells(field.label, labelWidth)}  `;
				const wrapped = wrapCells(scalar(field.value), Math.max(4, width - cellWidth(prefix)), height);
				output.push(`${prefix}${wrapped[0] ?? ""}`);
				for (const continuation of wrapped.slice(1)) output.push(`${" ".repeat(cellWidth(prefix))}${continuation}`);
			}
		}
	}
	if (view.kind === "diff") {
		if (!view.entries.length) output.push("No changes.");
		for (const entry of view.entries) {
			const path = sanitizeTerminalText(entry.path);
			if (entry.state === "added") output.push(`+ ${path}: ${scalar(entry.after)}`);
			else if (entry.state === "removed") output.push(`- ${path}: ${scalar(entry.before)}`);
			else if (entry.state === "changed") output.push(`~ ${path}: ${scalar(entry.before)} → ${scalar(entry.after)}`);
		}
	}
	if (view.kind === "raw") {
		let encoded: string;
		try { encoded = JSON.stringify(view.value, null, 2) ?? "null"; } catch { encoded = String(view.value); }
		output.push(...sanitizeTerminalText(encoded).split("\n"));
	}
	return Object.freeze(output.slice(0, height).map((row) => truncateCells(row, width)));
}
