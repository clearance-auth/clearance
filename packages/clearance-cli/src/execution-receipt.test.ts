import { chmodSync, mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	defaultExecutionReceiptPath,
	FileExecutionReceiptStore,
	type ExecutionReceipt,
} from "./execution-receipt.js";

const receipt: ExecutionReceipt = {
	receiptVersion: 1,
	receiptId: "receipt_1",
	operationId: "organizations.archive",
	path: "orgs archive",
	mutation: true,
	dryRun: false,
	target: { resource: "org_1", apiOrigin: "https://api.clearance.test" },
	command: "clearance orgs archive org_1 --token [REDACTED] --yes",
	startedAt: "2026-08-27T10:00:00.000Z",
	dispatchedAt: "2026-08-27T10:00:01.000Z",
	completedAt: "2026-08-27T10:00:02.000Z",
	requestId: "request_1",
	idempotencyKey: "operation-key-1",
	outcome: "succeeded",
	commitState: "committed",
	reconciliationCommands: ["clearance orgs inspect org_1 --output-format json"],
	error: null,
};

describe("execution receipt persistence", () => {
	it("uses the private CLI config directory by default and supports an explicit absolute path", () => {
		expect(defaultExecutionReceiptPath({
			CLEARANCE_CLI_CONFIG_DIR: "/private/clearance-config",
		} as NodeJS.ProcessEnv)).toBe("/private/clearance-config/operation-receipts.jsonl");
		expect(defaultExecutionReceiptPath({
			CLEARANCE_RECEIPT_PATH: "/private/audit/clearance.ndjson",
		} as NodeJS.ProcessEnv)).toBe("/private/audit/clearance.ndjson");
		expect(() => defaultExecutionReceiptPath({
			CLEARANCE_RECEIPT_PATH: "relative/receipt.ndjson",
		} as NodeJS.ProcessEnv)).toThrow("must be absolute");
	});

	it("appends durable receipts to a regular 0600 file without secret values", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-receipts-"));
		chmodSync(directory, 0o700);
		const path = join(directory, "operations.ndjson");
		const store = new FileExecutionReceiptStore(path);

		await store.save(receipt);
		await store.save({ ...receipt, receiptId: "receipt_2" });

		expect(statSync(path).mode & 0o777).toBe(0o600);
		const contents = readFileSync(path, "utf8");
		expect(contents.trim().split("\n")).toHaveLength(2);
		expect(contents).toContain("[REDACTED]");
		expect(contents).not.toContain("visible-secret");
	});

	it("refuses receipt persistence through a non-private directory", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-unsafe-receipts-"));
		chmodSync(directory, 0o755);
		await expect(new FileExecutionReceiptStore(join(directory, "operations.ndjson")).save(receipt))
			.rejects.toThrow("private 0700 directory");
	});
});
