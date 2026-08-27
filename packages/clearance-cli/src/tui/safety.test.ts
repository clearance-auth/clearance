import { describe, expect, it } from "vitest";
import { chmodSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	EphemeralSecretVault,
	FileOperationReceiptJournal,
	collapseExecutionReceiptLifecycles,
	normalizeOperationRunnerResult,
	operationFailureDetails,
	redactInvocationCommand,
	redactSecretValues,
} from "./safety.js";

describe("TUI operation safety", () => {
	it("keeps form secrets ephemeral and redacts exact command values", () => {
		const vault = new EphemeralSecretVault();
		vault.append("clientSecret", "s3cr");
		vault.append("clientSecret", "et ' value");
		const materialized = vault.materialize({ clientSecret: "••••••", name: "demo" });
		expect(materialized.clientSecret).toBe("s3cret ' value");
		const secrets = vault.take();
		expect(vault.has("clientSecret")).toBe(false);
		const invocation = redactInvocationCommand({
			path: "example create",
			args: [],
			opts: { clientSecret: materialized.clientSecret },
			global: {},
			command: `clearance example create --client-secret 's3cret '"'"' value'`,
		}, secrets);
		expect(invocation.command).toBe("clearance example create --client-secret <redacted>");
	});

	it("redacts nested one-time secrets while returning reveal-once hooks", () => {
		const result = redactSecretValues({ id: "key_1", credentials: { accessToken: "once", api_key: "key-secret" } });
		expect(result.data).toEqual({
			id: "key_1",
			credentials: { accessToken: "<redacted: revealed once>", api_key: "<redacted: revealed once>" },
		});
		expect(result.revealed).toEqual([
			{ path: "credentials.accessToken", value: "once" },
			{ path: "credentials.api_key", value: "key-secret" },
		]);
		expect(JSON.stringify(result.data)).not.toContain("key-secret");
	});

	it("normalizes the shared OperationRunner receipt contract", () => {
		expect(normalizeOperationRunnerResult({
			data: { id: "usr_1" },
			receipt: {
				receiptVersion: 1,
				outcome: "indeterminate",
				requestId: "req_1",
				reconciliationCommands: ["clearance users inspect usr_1"],
				error: {
					code: "CLI_API_UNREACHABLE",
					message: "The API stopped responding.",
					remediation: "Inspect the user before retrying.",
				},
			},
		})).toMatchObject({
			operationRunner: true,
			data: { id: "usr_1" },
			receipt: {
				receiptVersion: 1,
				outcome: "indeterminate",
				requestId: "req_1",
				reconciliationCommands: ["clearance users inspect usr_1"],
				error: {
					code: "CLI_API_UNREACHABLE",
					message: "The API stopped responding.",
					remediation: "Inspect the user before retrying.",
				},
			},
		});
	});

	it("fails closed on ambiguous post-dispatch errors", () => {
		expect(operationFailureDetails(Object.assign(new Error("invalid"), { status: 422 })).outcome).toBe("rejected");
		expect(operationFailureDetails(Object.assign(new Error("offline"), { dispatchState: "before_dispatch" })).outcome).toBe("failed_before_dispatch");
		expect(operationFailureDetails(new Error("offline")).outcome).toBe("indeterminate");
	});

	it("writes only canonical receipts when runner and TUI lifecycle share a journal", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-tui-receipts-"));
		chmodSync(directory, 0o700);
		const path = join(directory, "operation-receipts.jsonl");
		const journal = new FileOperationReceiptJournal(path);
		const command = "clearance users create --email ada@example.com --name Ada";
		const canonical = {
			receiptVersion: 1,
			receiptId: "receipt_canonical",
			operationId: "users.create",
			path: "users create",
			mutation: true,
			dryRun: false,
			target: { principal: "production", apiOrigin: "https://api.clearance.test" },
			command,
			startedAt: "2026-08-27T10:00:00.000Z",
			dispatchedAt: "2026-08-27T10:00:01.000Z",
			completedAt: "2026-08-27T10:00:02.000Z",
			requestId: "req_1",
			idempotencyKey: "operation-key-1",
			outcome: "succeeded",
			commitState: "committed",
			reconciliationCommands: ["clearance users list"],
			error: null,
		} as const;

		await journal.prepare();
		await journal.save(canonical);
		await journal.record({
			id: "receipt_canonical",
			operationId: "users.create",
			path: "users create",
			actionId: "users-create",
			risk: "mutation",
			command,
			target: { profile: "production", apiUrl: "https://api.clearance.test" },
			phase: "settled",
			createdAt: Date.parse(canonical.startedAt),
			dispatchedAt: Date.parse(canonical.dispatchedAt),
			completedAt: Date.parse(canonical.completedAt),
			requestId: "req_1",
			outcome: "succeeded",
			reconciliationRequired: false,
			reconciliationCommands: ["clearance users list"],
		});

		const records = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
		expect(records).toEqual([canonical]);
		expect(records[0]).toMatchObject({
			receiptVersion: 1,
			requestId: "req_1",
			idempotencyKey: "operation-key-1",
			commitState: "committed",
		});
		expect(records[0]).not.toHaveProperty("phase");
	});

	it("correlates a detached indeterminate revision with its later canonical settlement", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-tui-detach-race-"));
		chmodSync(directory, 0o700);
		const path = join(directory, "operation-receipts.jsonl");
		const journal = new FileOperationReceiptJournal(path);
		const lifecycle = {
			id: "receipt_lifecycle_1",
			operationId: "users.create",
			path: "users create",
			actionId: "users-create",
			risk: "mutation" as const,
			command: "clearance users create --email ada@example.com --name Ada",
			target: { profile: "production", apiUrl: "https://api.clearance.test", projectId: "proj_1", environmentId: "env_1" },
			phase: "settled" as const,
			createdAt: Date.parse("2026-08-27T10:00:00.000Z"),
			dispatchedAt: Date.parse("2026-08-27T10:00:01.000Z"),
			completedAt: Date.parse("2026-08-27T10:00:02.000Z"),
			requestId: "req_1",
			idempotencyKey: "operation-key-1",
			outcome: "indeterminate" as const,
			reconciliationRequired: true,
			reconciliationCommands: ["clearance users list"],
			detached: true,
		};
		await journal.record(lifecycle);

		const definitive = {
			receiptVersion: 1 as const,
			receiptId: lifecycle.id,
			operationId: lifecycle.operationId,
			path: lifecycle.path,
			mutation: true,
			dryRun: false,
			target: { principal: "production", apiOrigin: "https://api.clearance.test", environment: "env_1" },
			command: lifecycle.command,
			startedAt: "2026-08-27T10:00:00.000Z",
			dispatchedAt: "2026-08-27T10:00:01.000Z",
			completedAt: "2026-08-27T10:00:03.000Z",
			requestId: "req_1",
			idempotencyKey: "operation-key-1",
			outcome: "succeeded" as const,
			commitState: "committed" as const,
			reconciliationCommands: ["clearance users list"],
			error: null,
		};
		await journal.save(definitive);
		await journal.record({ ...lifecycle, outcome: "succeeded", reconciliationRequired: false, detached: false });

		const records = readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.parse(line));
		expect(records).toHaveLength(2);
		expect(records.map((receipt) => receipt.receiptId)).toEqual([lifecycle.id, lifecycle.id]);
		expect(records[0]).toMatchObject({
			operationId: "users.create",
			path: "users create",
			requestId: "req_1",
			idempotencyKey: "operation-key-1",
			outcome: "indeterminate",
		});
		expect(collapseExecutionReceiptLifecycles(records)).toEqual([definitive]);
	});
});
