import { ClearanceError } from "@clearance/management";
import { describe, expect, it, vi } from "vitest";
import { clearanceCommandFromArgv, OperationRunner } from "./operation-runner.js";

const guardedMutation = {
	id: "organizations.archive",
	path: "orgs archive",
	mutation: true,
	confirmation: "server-required",
} as const;

function clock(): () => Date {
	let tick = 0;
	return () => new Date(Date.UTC(2026, 7, 27, 10, 0, tick++));
}

function runner(store?: { save: (receipt: unknown) => Promise<void> }): OperationRunner {
	return new OperationRunner({
		now: clock(),
		createReceiptId: () => "receipt_1",
		receiptStore: store,
	});
}

describe("operation runner", () => {
	it("fails closed before execution and emits a rejected receipt", async () => {
		const execute = vi.fn();
		const result = await runner().run({
			operation: guardedMutation,
			command: "clearance orgs archive org_1",
			execute,
		});

		expect(execute).not.toHaveBeenCalled();
		expect(result.operationRunner).toBe(true);
		expect(result.cause).toBeInstanceOf(ClearanceError);
		expect(result.receipt).toMatchObject({
			outcome: "rejected",
			commitState: "not-dispatched",
			dispatchedAt: null,
			error: {
				code: "CLI_CONFIRMATION_REQUIRED",
				remediation: "Review the target, then pass --yes to confirm live execution.",
			},
		});
	});

	it("guards conditionally live operations only when live mode is requested", async () => {
		const operation = { ...guardedMutation, confirmation: "client-required-when-live" } as const;
		const previewExecute = vi.fn(async () => ({ data: { mode: "fixture" } }));
		const preview = await runner().run({
			operation,
			command: "clearance sso test sso_1 --fixture okta",
			execute: previewExecute,
		});
		expect(previewExecute).toHaveBeenCalledOnce();
		expect(preview.receipt.outcome).toBe("succeeded");

		const liveExecute = vi.fn();
		const live = await runner().run({
			operation,
			command: "clearance sso test sso_1 --live",
			live: true,
			execute: liveExecute,
		});
		expect(liveExecute).not.toHaveBeenCalled();
		expect(live.receipt).toMatchObject({
			outcome: "rejected",
			commitState: "not-dispatched",
			error: { code: "CLI_CONFIRMATION_REQUIRED" },
		});
	});

	it("records canonical clearance commands rather than launcher paths", () => {
		expect(clearanceCommandFromArgv([
			"/opt/homebrew/bin/node",
			"/workspace/packages/clearance-cli/src/index.ts",
			"users",
			"list",
			"--filter",
			"Acme West",
		])).toBe("clearance users list --filter 'Acme West'");
	});

	it("records success metadata and redacts secrets from a persisted receipt", async () => {
		const save = vi.fn(async () => undefined);
		const result = await runner({ save }).run({
			operation: guardedMutation,
			command: "clearance orgs archive org_1 --token visible-token --yes",
			secretValues: ["visible-token"],
			confirmed: true,
			target: { resource: "org_1", environment: "production" },
			reconciliationCommands: ["clearance orgs inspect org_1 --output-format json"],
			execute: async ({ markDispatched }) => {
				markDispatched({ idempotencyKey: "operation-key-1" });
				return { data: { archived: true }, requestId: "request_1" };
			},
		});

		expect(result.data).toEqual({ archived: true });
		expect(result.receiptPersistence).toBe("saved");
		expect(result.receipt).toMatchObject({
			outcome: "succeeded",
			commitState: "committed",
			requestId: "request_1",
			idempotencyKey: "operation-key-1",
			command: "clearance orgs archive org_1 --token [REDACTED] --yes",
		});
		expect(save).toHaveBeenCalledWith(result.receipt);
		expect(JSON.stringify(result.receipt)).not.toContain("visible-token");
	});

	it("distinguishes pre-dispatch failure, definitive rejection, and uncertainty", async () => {
		const preDispatch = await runner().run({
			operation: guardedMutation,
			command: "clearance orgs archive org_1 --yes",
			confirmed: true,
			secretValues: ["sensitive-value"],
			execute: async () => { throw new Error("input sensitive-value invalid"); },
		});
			expect(preDispatch.receipt).toMatchObject({
			outcome: "failed_before_dispatch",
			commitState: "not-dispatched",
		});
		expect(preDispatch.receipt.error?.message).toBe("input [REDACTED] invalid");

		const rejected = await runner().run({
			operation: guardedMutation,
			command: "clearance orgs archive org_1 --yes",
			confirmed: true,
			execute: async ({ markDispatched }) => {
				markDispatched({ requestId: "request_conflict" });
				throw new ClearanceError({
					code: "CONFLICT",
					message: "Revision sensitive-value changed.",
					stage: "api",
					status: 409,
					remediation: "Inspect sensitive-value before retrying.",
				});
			},
			secretValues: ["sensitive-value"],
		});
		expect(rejected.receipt).toMatchObject({
			outcome: "rejected",
			commitState: "not-committed",
			requestId: "request_conflict",
			error: {
				code: "CONFLICT",
				message: "Revision [REDACTED] changed.",
				remediation: "Inspect [REDACTED] before retrying.",
			},
		});

		const indeterminate = await runner().run({
			operation: guardedMutation,
			command: "clearance orgs archive org_1 --yes",
			confirmed: true,
			execute: async ({ markDispatched }) => {
				markDispatched({ idempotencyKey: "operation-key-2" });
				throw new Error("connection lost");
			},
		});
		expect(indeterminate.receipt).toMatchObject({
			outcome: "indeterminate",
			commitState: "unknown",
			idempotencyKey: "operation-key-2",
			reconciliationCommands: ["clearance events list --limit 20 --output-format json"],
		});
	});

	it("reclassifies generated-client local validation before the transport boundary", async () => {
		const result = await runner().run({
			operation: guardedMutation,
			command: "clearance orgs archive '' --yes",
			confirmed: true,
			execute: async ({ markDispatched }) => {
				// The API adapter marks conservatively before calling the generated client.
				markDispatched({ idempotencyKey: "generated-but-unsent" });
				throw new ClearanceError({
					code: "MANAGEMENT_PROTOCOL_ERROR",
					message: "organizations.archive input did not match its schema.",
					stage: "management-client.input",
					status: 0,
					remediation: "Correct the local input.",
				});
			},
		});

		expect(result.receipt).toMatchObject({
			outcome: "failed_before_dispatch",
			commitState: "not-dispatched",
			dispatchedAt: null,
			idempotencyKey: null,
		});
	});

	it("enriches the first dispatch boundary with actual response metadata", async () => {
		const result = await runner().run({
			operation: guardedMutation,
			command: "clearance orgs archive org_1 --yes",
			confirmed: true,
			execute: async ({ markDispatched }) => {
				markDispatched();
				markDispatched({ requestId: "request_actual", idempotencyKey: "key_actual" });
				return { data: { archived: true } };
			},
		});

		expect(result.receipt).toMatchObject({
			requestId: "request_actual",
			idempotencyKey: "key_actual",
			outcome: "succeeded",
		});
	});

	it("reports receipt persistence failure without hiding the operation result", async () => {
		const result = await runner({ save: async () => { throw new Error("disk full"); } }).run({
			operation: { ...guardedMutation, mutation: false, confirmation: "none" },
			command: "clearance orgs inspect org_1",
			execute: async ({ markDispatched }) => {
				markDispatched();
				return { data: { id: "org_1" } };
			},
		});

		expect(result.data).toEqual({ id: "org_1" });
		expect(result.receipt.outcome).toBe("succeeded");
		expect(result.receiptPersistence).toBe("failed");
		expect(result.receiptPersistenceError).toBe("disk full");
	});

	it("fails a live mutation before execution when durable receipt preparation fails", async () => {
		const execute = vi.fn(async () => ({ data: { archived: true } }));
		const result = await new OperationRunner({
			now: clock(),
			createReceiptId: () => "receipt_prepare_failure",
			receiptStore: {
				async prepare() { throw new Error("journal unavailable"); },
				async save() { throw new Error("journal unavailable"); },
			},
		}).run({
			operation: guardedMutation,
			command: "clearance orgs archive org_1 --yes",
			confirmed: true,
			execute,
		});

		expect(execute).not.toHaveBeenCalled();
		expect(result.receipt).toMatchObject({
			outcome: "failed_before_dispatch",
			commitState: "not-dispatched",
			dispatchedAt: null,
			error: { message: "journal unavailable" },
		});
		expect(result.receiptPersistence).toBe("failed");
	});
});
