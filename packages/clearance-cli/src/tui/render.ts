import { WORKFLOW_AREAS } from "./catalog.js";
import type { GlobalOpts } from "../output.js";
import type { TuiState, WorkflowAction, WorkflowField } from "./types.js";
import { contextualHelp, renderHelpBindings } from "./feedback.js";
import { cellWidth, padStyledCells, resolveTerminalAppearance, sanitizeTerminalText, wrapCells } from "./terminal.js";
import { renderStructuredView, structuredViewFor } from "./views.js";

function clip(value: string, width: number): string {
	return padStyledCells(value, width);
}

function lines(value: string, width: number, limit = 20): string[] {
	return [...wrapCells(value, width, limit)];
}

function quote(value: string): string {
	if (/^[A-Za-z0-9_./:@,+-]+$/.test(value)) return value;
	return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function template(action: WorkflowAction, global: Readonly<GlobalOpts> = {}): string {
	const parts = ["clearance"];
	if (global.profile) parts.push("--profile", quote(global.profile));
	if (global.apiUrl) parts.push("--api-url", quote(global.apiUrl));
	if (global.dryRun) parts.push("--dry-run");
	if (global.yes || (action.confirmation !== "none" && !global.dryRun)) parts.push("--yes");
	parts.push(...action.path.split(" "));
	for (const field of action.fields) {
		const value = field.required ? `<${field.key}>` : `[${field.key}]`;
		parts.push(field.argument ? value : `${field.flag ?? `--${field.key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}`} ${value}`);
	}
	return parts.join(" ");
}

function fieldLine(field: WorkflowField, value: string, active: boolean): string {
	const marker = active ? "›" : " ";
	const required = field.required ? " *" : "";
	const repeatable = field.repeatable ? " (comma-separated)" : "";
	return `${marker} ${field.label}${repeatable}${required}: ${sanitizeTerminalText(value || `(${field.placeholder ?? "optional"})`)}`;
}

function areaTabs(
	areaIndex: number,
	width: number,
	style: { readonly active: (value: string) => string; readonly inactive: (value: string) => string },
): readonly string[] {
	const tokens = WORKFLOW_AREAS.map((area, index) => {
		return index === areaIndex ? style.active(`[ ${area} ]`) : style.inactive(`  ${area}  `);
	});
	const rows: string[] = [];
	let row = "";
	for (const token of tokens) {
		if (row && cellWidth(`${row} ${token}`) > width) {
			rows.push(row);
			row = token;
		} else row = row ? `${row} ${token}` : token;
	}
	if (row) rows.push(row);
	return rows;
}

export function renderTui(state: TuiState, actions: readonly WorkflowAction[], options: {
	readonly width?: number;
	readonly height?: number;
	readonly color?: boolean;
	readonly theme?: "auto" | "dark" | "light";
	readonly rawResult?: boolean;
	readonly title?: string;
	readonly global?: Readonly<GlobalOpts>;
} = {}): string {
	const width = Math.max(32, options.width ?? 100);
	const height = Math.max(12, options.height ?? 32);
	const appearance = resolveTerminalAppearance({ requestedColor: options.color, requestedTheme: options.theme, isTTY: true });
	const useColor = appearance.color;
	const paint = (code: number, value: string) => useColor ? `\u001b[${code}m${value}\u001b[0m` : value;
	const dim = (value: string) => paint(2, value);
	const strong = (value: string) => paint(1, value);
	const cyan = (value: string) => paint(appearance.theme === "light" ? 34 : 36, value);
	const yellow = (value: string) => paint(appearance.theme === "light" ? 35 : 33, value);
	const red = (value: string) => paint(31, value);
	const selected = actions[state.selection];
	const output: string[] = [];

	output.push(strong(sanitizeTerminalText(options.title ?? "Clearance")));
	const verified = state.identity;
	const pollSeconds = Math.max(1, Math.round(state.preferences.refreshIntervalMs / 1_000));
	if (state.refresh.status === "refreshing") output.push(dim("Refreshing…"));
	else if (state.refresh.status === "offline") output.push(red(`Offline • showing saved data • retrying in ${pollSeconds}s`));
	if (options.global?.dryRun) output.push(yellow("Dry run"));
	output.push(...areaTabs(state.areaIndex, width, { active: cyan, inactive: dim }));
	if (state.feedback.modal) {
		const modal = state.feedback.modal;
		output.push(red(strong(sanitizeTerminalText(modal.title))), "", ...lines(sanitizeTerminalText(modal.message), width, Math.max(2, height - 10)));
		output.push("", modal.actions.map((action) => action.primary ? `[ ${action.label} ]` : action.label).join("   "));
		output.push("", dim("r retry • any other key keeps the last good result"));
		return clipFrame(output, width, height);
	}

	if (state.mode === "help") {
		output.push("", strong("Help"), "");
		const profile = verified?.profile ?? options.global?.profile ?? "default";
		const endpoint = verified?.apiUrl ?? options.global?.apiUrl ?? "saved default";
		output.push(strong("Connection"));
		output.push(`Profile       ${sanitizeTerminalText(profile)}`);
		output.push(`Endpoint      ${sanitizeTerminalText(endpoint)}`);
		if (verified) {
			output.push(`Environment   ${sanitizeTerminalText(verified.environmentId)}`);
			output.push(`Project       ${sanitizeTerminalText(verified.projectId)}`);
			output.push("Status        verified");
		} else output.push(`Status        ${state.refresh.status}`);
		const rowAction = state.workspaceActions[state.workspace.sections[state.workspace.sectionId].actionIndex];
		const disclosedCommand = state.workspaceFocus === "resources" && rowAction
			? rowAction.command
			: selected ? template(selected, options.global) : undefined;
		if (disclosedCommand) output.push("", strong("Selected workflow"), ...lines(sanitizeTerminalText(disclosedCommand), width).map(cyan));
		output.push("", strong("Keys"));
		output.push("Workspace", renderHelpBindings(contextualHelp("navigation", width)), "", "Workflow actions", renderHelpBindings(contextualHelp("action-list", width)));
		output.push("", "Selected resource", renderHelpBindings(contextualHelp("resource-list", width)));
		output.push("", "Result views", renderHelpBindings(contextualHelp(options.rawResult ? "raw" : "resource-detail", width)));
		output.push("", yellow("Press any key to close help."));
		return clipFrame(output, width, height);
	}

	if (state.mode === "form" && selected) {
		const actionId = state.formValues.__action;
		const action = actions.find((candidate) => candidate.id === actionId) ?? selected;
		output.push(strong(action.label), action.description, "");
		output.push(...action.fields.map((field, index) => fieldLine(field, state.formValues[field.key] ?? "", index === state.formIndex)));
		output.push("", dim("Type a value • Enter next • Tab skip • Escape cancel"));
		if (state.notice) output.push("", yellow(state.notice));
		return clipFrame(output, width, height);
	}

	if (state.mode === "preview") {
		const actionId = state.formValues.__action;
		const action = actions.find((candidate) => candidate.id === actionId);
		if (action) {
			const invocation = action.invocation(state.formValues, options.global);
			output.push(action.risk === "destructive" ? red(strong("Destructive action")) : yellow(strong("Mutation preview")));
			if (verified) {
				const verifiedCredential = verified.credentialSource === "environment"
					? "credential environment token"
					: `profile ${sanitizeTerminalText(verified.profile)}`;
				output.push(dim(`Verified target: ${verifiedCredential} • project ${sanitizeTerminalText(verified.projectId)} • environment ${sanitizeTerminalText(verified.environmentId)} • API ${sanitizeTerminalText(verified.apiUrl)}`));
			}
			output.push("", action.label, action.description, "", strong("Exact command"), cyan(sanitizeTerminalText(invocation.command)));
			output.push("", dim("No request has been sent."));
			if (options.global?.dryRun && !action.supportsDryRun) {
				output.push("", red("Dry run unavailable for this operation."), dim("Press Escape to cancel. Leave dry-run mode only after reviewing the exact live command."));
			} else if (action.supportsDryRun) output.push(cyan(action.risk === "destructive"
				? "Press Ctrl+D to run a safe dry run."
				: "Press d to run a safe dry run."));
			if (options.global?.dryRun && !action.supportsDryRun) {
				// The unavailable state above intentionally exposes no dispatch key.
			} else if (action.risk === "destructive" && !options.global?.dryRun) {
				output.push("", yellow(`Type ${action.id}, then press Enter to run live:`), sanitizeTerminalText(state.confirmationInput) || dim("(confirmation required)"), dim("Escape cancels before dispatch."));
			} else output.push("", yellow(options.global?.dryRun ? "Press y to dispatch this dry run, n or Escape to cancel." : "Press y to dispatch live, n or Escape to cancel."));
		}
		return clipFrame(output, width, height);
	}

	const leftWidth = Math.min(38, Math.floor(width * 0.4));
	const rightWidth = width - leftWidth - 3;
	const bodyRows = Math.max(4, height - output.length - 2);
	const listRows: string[] = [];
	const detailRows: string[] = [];
	const workspace = state.workspace.sections[state.workspace.sectionId];
	if (state.workspaceFocus === "resources" && workspace.page.rows.length) {
		const listCapacity = Math.max(1, bodyRows - 1);
		const listStart = Math.min(
			Math.max(0, workspace.selectedIndex - Math.floor(listCapacity / 2)),
			Math.max(0, workspace.page.rows.length - listCapacity),
		);
		const listEnd = Math.min(workspace.page.rows.length, listStart + listCapacity);
		const total = workspace.page.total ?? workspace.page.rows.length;
		const paging = `${workspace.cursorHistory.length + 1}${workspace.page.nextCursor ? "+" : ""}`;
		listRows.push(strong(`Resources ${listStart + 1}-${listEnd}/${total}  page ${paging}`));
		for (let index = listStart; index < listEnd; index += 1) {
			const row = workspace.page.rows[index]!;
			const marker = index === workspace.selectedIndex ? cyan("›") : " ";
			listRows.push(`${marker} ${sanitizeTerminalText(row.label)}${row.status ? dim(`  ${sanitizeTerminalText(row.status)}`) : ""}`);
		}
		const row = workspace.page.rows[workspace.selectedIndex];
		if (row) {
			detailRows.push(strong(sanitizeTerminalText(row.label)), dim(sanitizeTerminalText(row.kind)));
			detailRows.push("", ...renderStructuredView(structuredViewFor(row.data, { raw: state.preferences.rawJson }), { width: rightWidth, height: 2_000 }));
			if (state.workspaceActions.length) {
				detailRows.push("", strong(workspace.mode === "actions" ? "Choose an action" : "Selected-row actions"));
				for (let index = 0; index < state.workspaceActions.length; index += 1) {
					const action = state.workspaceActions[index]!;
					const marker = workspace.mode === "actions" && workspace.actionIndex === index ? cyan("›") : " ";
					detailRows.push(`${marker} ${action.label}`);
				}
			}
			detailRows.push("", dim(workspace.mode === "actions"
				? "↑/↓ choose • Enter run/open • Esc back"
				: `${state.preferences.rawJson ? "v structured" : "v raw JSON"} • a actions • ? help`));
		}
	} else {
		if (state.mode === "search" || state.search) listRows.push(cyan(`/ ${sanitizeTerminalText(state.search)}${state.mode === "search" ? "▌" : ""}`), "");
		for (let index = 0; index < actions.length; index += 1) {
			const marker = index === state.selection ? cyan("›") : " ";
			listRows.push(`${marker} ${actions[index].label}`);
		}
		if (!actions.length) listRows.push(dim("No matching workflows"));

		if (selected) {
			detailRows.push(selected.description);
			const snapshot = state.snapshots[selected.id];
			const resultLines = snapshot?.data === undefined ? [] : [...renderStructuredView(structuredViewFor(snapshot.data, { raw: options.rawResult ?? state.preferences.rawJson }), {
				width: rightWidth,
				height: 2_000,
			})];
			if (resultLines.length) detailRows.push("", strong("Result"));
			const visibleResultLines = resultLines.slice(state.resultOffset, state.resultOffset + Math.max(5, height - 15));
			detailRows.push(...visibleResultLines);
			if (resultLines.length > visibleResultLines.length) detailRows.push(dim(`Result lines ${state.resultOffset + 1}-${state.resultOffset + visibleResultLines.length} of ${resultLines.length} • [ / ] scroll`));
			if (snapshot?.data !== undefined) detailRows.push("", dim((options.rawResult ?? state.preferences.rawJson) ? "v structured view" : "v raw JSON"));
			if (snapshot?.error) detailRows.push("", red("Latest error"), ...lines(sanitizeTerminalText(snapshot.error), rightWidth, 4).map(red));
			if (!snapshot?.data && !snapshot?.error) detailRows.push("", dim("Enter open • ? details"));
		}
	}

	const detailOffset = Math.min(workspace.scrollOffset, Math.max(0, detailRows.length - bodyRows));
	const visibleDetailRows = state.workspaceFocus === "resources"
		? detailRows.slice(detailOffset, detailOffset + bodyRows)
		: detailRows;
	for (let index = 0; index < bodyRows; index += 1) {
		output.push(`${clip(listRows[index] ?? "", leftWidth)} │ ${clip(visibleDetailRows[index] ?? "", rightWidth)}`);
	}
	output.push(dim("─".repeat(width)));
	if (state.loading) {
		const loadingAction = actions.find((action) => action.id === state.loading?.actionId);
		output.push(yellow(loadingAction?.mutation
			? `◌ Running ${state.loading.actionId} • mutation cancellation disabled`
			: `◌ Loading ${state.loading.actionId} • c stops waiting locally`));
	}
	else if (state.notice) output.push(lines(sanitizeTerminalText(state.notice), width, 1)[0]);
	else if (state.feedback.toasts.length) output.push(cyan(sanitizeTerminalText(state.feedback.toasts.at(-1)?.message ?? "")));
	else if (state.feedback.notices.length) output.push(yellow(sanitizeTerminalText(state.feedback.notices.at(-1)?.message ?? "")));
	else output.push(dim(renderHelpBindings(contextualHelp(state.workspaceFocus === "resources" ? "resource-detail" : selected ? "action-list" : "navigation", width))));
	return clipFrame(output, width, height);
}

function clipFrame(rows: readonly string[], width: number, height: number): string {
	return rows.slice(0, height).map((row) => clip(row, width)).join("\n");
}
