import { constants } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { credentialDirectory } from "./operator-auth.js";

export const EXECUTION_RECEIPT_VERSION = 1 as const;

export type OperationOutcome =
	| "succeeded"
	| "rejected"
	| "failed_before_dispatch"
	| "indeterminate";

export type OperationCommitState =
	| "not-applicable"
	| "not-dispatched"
	| "not-committed"
	| "committed"
	| "unknown";

export interface OperationTarget {
	readonly resource?: string;
	readonly principal?: string;
	readonly environment?: string;
	readonly apiOrigin?: string;
}

export interface ReceiptError {
	readonly code: string;
	readonly message: string;
	readonly stage: string;
	readonly retryable: boolean;
	readonly remediation: string | null;
}

export interface ExecutionReceipt {
	readonly receiptVersion: typeof EXECUTION_RECEIPT_VERSION;
	readonly receiptId: string;
	readonly operationId: string;
	readonly path: string;
	readonly mutation: boolean;
	readonly dryRun: boolean;
	readonly target: Readonly<OperationTarget>;
	/** A control-free command with declared and recognizable secret values redacted. */
	readonly command: string;
	readonly startedAt: string;
	readonly dispatchedAt: string | null;
	readonly completedAt: string;
	readonly requestId: string | null;
	readonly idempotencyKey: string | null;
	readonly outcome: OperationOutcome;
	readonly commitState: OperationCommitState;
	readonly reconciliationCommands: readonly string[];
	readonly error: ReceiptError | null;
}

export interface ExecutionReceiptStore {
	readonly path?: string;
	/** Verify that the durable journal is writable before a mutation can dispatch. */
	prepare?(): Promise<void>;
	save(receipt: ExecutionReceipt): Promise<void>;
}

type ReceiptEnvironment = Partial<Pick<
	NodeJS.ProcessEnv,
	"CLEARANCE_RECEIPT_PATH" | "CLEARANCE_CLI_CONFIG_DIR" | "XDG_CONFIG_HOME" | "HOME"
>>;

/** Resolve the durable receipt journal, with an explicit absolute-path override. */
export function defaultExecutionReceiptPath(env: ReceiptEnvironment = process.env): string {
	const explicit = env.CLEARANCE_RECEIPT_PATH?.trim();
	if (explicit) {
		if (!isAbsolute(explicit)) throw new TypeError("CLEARANCE_RECEIPT_PATH must be absolute.");
		return explicit;
	}
	return join(credentialDirectory(env), "operation-receipts.jsonl");
}

function mode(value: number): number {
	return value & 0o777;
}

/** Append-only NDJSON persistence in a private directory and regular 0600 file. */
export class FileExecutionReceiptStore implements ExecutionReceiptStore {
	readonly path: string;

	constructor(path: string) {
		if (!isAbsolute(path)) throw new TypeError("Receipt store path must be absolute.");
		this.path = path;
	}

	async #openStore() {
		const directory = dirname(this.path);
		try {
			const parent = await lstat(directory);
			if (parent.isSymbolicLink() || !parent.isDirectory() || mode(parent.mode) !== 0o700) {
				throw new TypeError("Receipt store parent must be a private 0700 directory.");
			}
		} catch (cause) {
			if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
			await mkdir(directory, { recursive: true, mode: 0o700 });
			const parent = await lstat(directory);
			if (parent.isSymbolicLink() || !parent.isDirectory() || mode(parent.mode) !== 0o700) {
				throw new TypeError("Receipt store parent could not be secured.");
			}
		}
		const handle = await open(
			this.path,
			constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW,
			0o600,
		);
		try {
			const file = await handle.stat();
			if (!file.isFile() || mode(file.mode) !== 0o600) {
				throw new TypeError("Receipt store must be a regular 0600 file.");
			}
			return handle;
		} catch (cause) {
			await handle.close();
			throw cause;
		}
	}

	async prepare(): Promise<void> {
		const handle = await this.#openStore();
		try {
			await handle.datasync();
		} finally {
			await handle.close();
		}
	}

	async save(receipt: ExecutionReceipt): Promise<void> {
		const handle = await this.#openStore();
		try {
			await handle.writeFile(`${JSON.stringify(receipt)}\n`, { encoding: "utf8" });
			await handle.datasync();
		} finally {
			await handle.close();
		}
	}
}
