import { ClearanceError } from "@clearance/management";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { ApiSession } from "../api-client.js";
import type { GlobalOpts } from "../output.js";

export interface DispatchInput<Path extends string> {
	session: ApiSession;
	path: Path;
	args: readonly unknown[];
	opts: Readonly<Record<string, unknown>>;
	global: Readonly<GlobalOpts>;
}

export type CliPathOf<Operations extends Record<string, { readonly cliPath: string }>> =
	Operations[keyof Operations]["cliPath"];

export function firstStringArgument(args: readonly unknown[]): string {
	return typeof args[0] === "string" ? args[0] : "";
}

export function error(code: string, message: string, remediation: string): ClearanceError {
	return new ClearanceError({ code, message, stage: "cli.dispatch", remediation });
}

export function query(path: string, values: Record<string, unknown>): `/v1/${string}` {
	const params = new URLSearchParams();
	for (const [key, value] of Object.entries(values)) {
		if (value !== undefined && value !== false && value !== "") params.set(key, String(value));
	}
	return `${path}${params.size ? `?${params}` : ""}` as `/v1/${string}`;
}

export function body(values: Record<string, unknown>): Record<string, unknown> {
	return Object.fromEntries(Object.entries(values).filter(([, value]) => value !== undefined));
}

export function previewConfirmation(global: Readonly<GlobalOpts>): {
	dryRun: boolean | undefined;
	confirm: boolean | undefined;
} {
	return {
		dryRun: global.dryRun || !global.yes,
		confirm: global.yes && !global.dryRun,
	};
}

export function localFile(path: unknown, code: string, label: string): string {
	try {
		return readFileSync(resolve(String(path)), "utf8");
	} catch {
		throw error(code, `${label} could not be read.`, "Provide a readable local file and retry.");
	}
}

export function requireRemoteMutation(global: Readonly<GlobalOpts>, path: string): void {
	if (global.dryRun) {
		throw error(
			"CLI_REMOTE_DRY_RUN_UNSUPPORTED",
			`${path} does not yet expose a server-side dry-run contract.`,
			"Use the command without --dry-run after reviewing the target.",
		);
	}
}

export function requireConfirmation(
	global: Readonly<GlobalOpts>,
	code: string,
	label: string,
): void {
	if (!global.yes && !global.dryRun) {
		throw error(code, `${label} requires --yes.`, "Review the target, then pass --yes to confirm.");
	}
}
