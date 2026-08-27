import { WORKFLOW_AREAS } from "./catalog.js";
import type { GlobalOpts } from "../output.js";
import type { TuiState, WorkflowAction, WorkflowField } from "./types.js";

const ESCAPE_PATTERN = /\u001b\[[0-9;]*m/g;

function clip(value: string, width: number): string {
	if (width <= 0) return "";
	const plain = value.replace(ESCAPE_PATTERN, "");
	if (plain.length <= width) return value + " ".repeat(width - plain.length);
	return plain.slice(0, Math.max(0, width - 1)) + "…";
}

function lines(value: string, width: number, limit = 20): string[] {
	const output: string[] = [];
	const safeValue = value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/gu, "�");
	for (const paragraph of safeValue.split("\n")) {
		let remaining = paragraph;
		while (remaining.length > width && output.length < limit) {
			let boundary = remaining.lastIndexOf(" ", width);
			if (boundary < Math.floor(width / 2)) boundary = width;
			output.push(remaining.slice(0, boundary));
			remaining = remaining.slice(boundary).trimStart();
		}
		if (output.length < limit) output.push(remaining);
	}
	return output.slice(0, limit);
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

function resultText(value: unknown): string {
	if (value === undefined) return "No result yet. Press Enter to run this workflow.";
	try {
		return JSON.stringify(value, null, 2);
	} catch {
		return String(value);
	}
}

function fieldLine(field: WorkflowField, value: string, active: boolean): string {
	const marker = active ? "›" : " ";
	const required = field.required ? " *" : "";
	return `${marker} ${field.label}${required}: ${value || `(${field.placeholder ?? "optional"})`}`;
}

export function renderTui(state: TuiState, actions: readonly WorkflowAction[], options: {
	readonly width?: number;
	readonly height?: number;
	readonly color?: boolean;
	readonly title?: string;
	readonly global?: Readonly<GlobalOpts>;
} = {}): string {
	const width = Math.max(32, options.width ?? 100);
	const height = Math.max(12, options.height ?? 32);
	const useColor = options.color !== false;
	const paint = (code: number, value: string) => useColor ? `\u001b[${code}m${value}\u001b[0m` : value;
	const dim = (value: string) => paint(2, value);
	const strong = (value: string) => paint(1, value);
	const cyan = (value: string) => paint(36, value);
	const yellow = (value: string) => paint(33, value);
	const red = (value: string) => paint(31, value);
	const selected = actions[state.selection];
	const output: string[] = [];

	output.push(strong(options.title ?? "Clearance workflows"));
	const target = options.global?.apiUrl ? `API ${options.global.apiUrl}` : "API saved/default target";
	const profile = options.global?.profile ? `profile ${options.global.profile}` : "default profile";
	output.push(dim(`Target: ${profile} • ${target}${options.global?.dryRun ? " • DRY RUN" : ""}`));
	output.push(WORKFLOW_AREAS.map((area, index) => index === state.areaIndex ? cyan(`[ ${area} ]`) : dim(`  ${area}  `)).join(" "));
	output.push(dim("─".repeat(width)));

	if (state.mode === "help") {
		output.push(strong("Keyboard help"), "");
		output.push("↑/↓ or j/k  Select workflow", "←/→ or h/l  Change area", "/             Search this area");
		output.push("Enter or r    Run/open workflow", "[ / ]         Scroll result", "c             Stop waiting for reads", "Escape        Back/cancel", "q             Quit");
		output.push("", dim("Every workflow shows and dispatches the equivalent Clearance CLI command."));
		output.push("", yellow("Press any key to close help."));
		return clipFrame(output, width, height);
	}

	if (state.mode === "form" && selected) {
		const actionId = state.formValues.__action;
		const action = actions.find((candidate) => candidate.id === actionId) ?? selected;
		output.push(strong(action.label), action.description, "", dim(`CLI  ${template(action, options.global)}`), "");
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
			output.push("", action.label, action.description, "", strong("Exact command"), cyan(invocation.command));
			output.push("", dim("No request has been sent."));
			if (action.supportsDryRun) output.push(cyan("Press d to run a safe dry run."));
			if (action.risk === "destructive" && !options.global?.dryRun) {
				output.push("", yellow(`Type ${action.id}, then press Enter to run live:`), state.confirmationInput || dim("(confirmation required)"), dim("Escape cancels before dispatch."));
			} else output.push("", yellow(options.global?.dryRun ? "Press y to dispatch this dry run, n or Escape to cancel." : "Press y to dispatch live, n or Escape to cancel."));
		}
		return clipFrame(output, width, height);
	}

	const leftWidth = Math.min(38, Math.floor(width * 0.4));
	const rightWidth = width - leftWidth - 3;
	const listRows: string[] = [];
	const detailRows: string[] = [];
	if (state.mode === "search" || state.search) listRows.push(cyan(`/ ${state.search}${state.mode === "search" ? "▌" : ""}`), "");
	for (let index = 0; index < actions.length; index += 1) {
		const marker = index === state.selection ? cyan("›") : " ";
		const risk = actions[index].risk === "destructive" ? " !" : actions[index].risk === "mutation" ? " +" : "";
		listRows.push(`${marker} ${actions[index].label}${risk}`);
	}
	if (!actions.length) listRows.push(dim("No matching workflows"));

	if (selected) {
		detailRows.push(strong(selected.label), selected.description, "", strong("Exact CLI command"));
		detailRows.push(...lines(template(selected, options.global), rightWidth).map(cyan));
		const snapshot = state.snapshots[selected.id];
		detailRows.push("", strong("Last good result"));
		const resultLines = lines(resultText(snapshot?.data), rightWidth, 2_000);
		const visibleResultLines = resultLines.slice(state.resultOffset, state.resultOffset + Math.max(5, height - 15));
		detailRows.push(...visibleResultLines);
		if (resultLines.length > visibleResultLines.length) detailRows.push(dim(`Result lines ${state.resultOffset + 1}-${state.resultOffset + visibleResultLines.length} of ${resultLines.length} • [ / ] scroll`));
		if (snapshot?.error) detailRows.push("", red("Latest error"), ...lines(snapshot.error, rightWidth, 4).map(red));
	}

	const bodyRows = Math.max(4, height - 6);
	for (let index = 0; index < bodyRows; index += 1) {
		output.push(`${clip(listRows[index] ?? "", leftWidth)} │ ${clip(detailRows[index] ?? "", rightWidth)}`);
	}
	output.push(dim("─".repeat(width)));
	if (state.loading) {
		const loadingAction = actions.find((action) => action.id === state.loading?.actionId);
		output.push(yellow(loadingAction?.mutation
			? `◌ Running ${state.loading.actionId} • mutation cancellation disabled`
			: `◌ Loading ${state.loading.actionId} • c stops waiting locally`));
	}
	else if (state.notice) output.push(lines(state.notice, width, 1)[0]);
	else output.push(dim("Enter run • / search • ? help • q quit"));
	return clipFrame(output, width, height);
}

function clipFrame(rows: readonly string[], width: number, height: number): string {
	return rows.slice(0, height).map((row) => clip(row, width)).join("\n");
}
