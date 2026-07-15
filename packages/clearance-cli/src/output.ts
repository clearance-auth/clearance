import { ClearanceError, isClearanceError } from "@clearance/management";

export interface GlobalOpts {
	json?: boolean;
	noInput?: boolean;
	yes?: boolean;
	dryRun?: boolean;
	profile?: string;
	apiUrl?: string;
}

export class CliExitError extends Error {
	readonly exitCode: number;

	constructor(exitCode = 1) {
		super("CLI command failed");
		this.name = "CliExitError";
		this.exitCode = exitCode;
	}
}

export function printResult(opts: GlobalOpts, data: unknown, human?: string): void {
	if (opts.json) {
		process.stdout.write(`${JSON.stringify(data, null, 2)}\n`);
		return;
	}
	if (human) {
		process.stdout.write(`${human}\n`);
		return;
	}
	process.stdout.write(`${JSON.stringify(data, null, 2)}\n`);
}

export function fail(err: unknown, opts: GlobalOpts): never {
	// A CliExitError means fail() already emitted a structured document and is
	// unwinding. Re-throw untouched so a catch block that funnels back into
	// fail() can never emit a second JSON document on stdout (--json contract:
	// exactly one document per invocation).
	if (err instanceof CliExitError) {
		throw err;
	}
	if (isClearanceError(err)) {
		if (opts.json) {
			process.stdout.write(`${JSON.stringify(err.toJSON(), null, 2)}\n`);
		} else {
			process.stderr.write(
				`Error [${err.code}] stage=${err.stage}: ${err.message}\nRemediation: ${err.remediation}\n`,
			);
		}
		throw new CliExitError(1);
	}
	const message = err instanceof Error ? err.message : String(err);
	if (opts.json) {
		process.stdout.write(
			`${JSON.stringify({ error: { code: "INTERNAL", message, stage: "unknown", retryable: false } }, null, 2)}\n`,
		);
	} else {
		process.stderr.write(`Error: ${message}\n`);
	}
	throw new CliExitError(1);
}

export function exitCodeFromDoctor(ok: boolean): number {
	return ok ? 0 : 2;
}

export function asClearanceError(err: unknown): ClearanceError | null {
	return isClearanceError(err) ? err : null;
}
