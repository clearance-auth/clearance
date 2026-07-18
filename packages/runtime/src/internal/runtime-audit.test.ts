import type { DBAdapter, DBTransactionAdapter } from "@clearance/core/db/adapter";
import { runWithTransaction } from "@clearance/core/context";
import { describe, expect, it, vi } from "vitest";
import {
	appendInternalRuntimeAudit,
	attachCapturedInternalRuntimeAudit,
	attachInternalRuntimeAudit,
	classifyRuntimeInteractiveAuthenticationRoute,
	getRuntimeAuditRequestContext,
	InvalidRuntimeAuditError,
	readInternalRuntimeAudit,
	runWithRuntimeAuditRequestContext,
	RuntimeAuditTransactionRequiredError,
	type InternalRuntimeAuditDraft,
} from "./runtime-audit";

const request = {
	correlationId: "request-1",
	operationId: "session.create",
	route: "/sign-in/email",
	method: "POST",
	clientIp: "203.0.113.10",
	userAgent: "Clearance runtime audit proof",
} as const;

function draft(
	override: Partial<InternalRuntimeAuditDraft> = {},
): InternalRuntimeAuditDraft {
	return {
		actor: "user_1",
		action: "session.create",
		subjectType: "session",
		subjectId: "session_1",
		outcome: "success",
		source: "system",
		organizationId: null,
		message: "Session created",
		metadata: { factor: "password" },
		request,
		...override,
	};
}

describe("runtime audit authority", () => {
	it("classifies direct and callback login terminals from one contract", () => {
		expect(classifyRuntimeInteractiveAuthenticationRoute("/sign-in/email")).toBe(
			"password",
		);
		expect(classifyRuntimeInteractiveAuthenticationRoute("/sign-in/social")).toBe(
			"federated",
		);
		expect(
			classifyRuntimeInteractiveAuthenticationRoute("/sign-in/anonymous"),
		).toBe("anonymous");
		expect(
			classifyRuntimeInteractiveAuthenticationRoute("/callback/:id"),
		).toBe("federated");
		expect(
			classifyRuntimeInteractiveAuthenticationRoute(
				"/oauth2/callback/:providerId",
			),
		).toBe("federated");
		expect(
			classifyRuntimeInteractiveAuthenticationRoute("/sso/saml2/sp/acs/provider"),
		).toBe("sso");
		expect(classifyRuntimeInteractiveAuthenticationRoute("/sign-in/magic-link"))
			.toBeNull();
	});

	it("normalizes one request context and appends through the active transaction binding", async () => {
		let received: InternalRuntimeAuditDraft | undefined;
		const append = vi.fn(
			async (
				_transaction: DBTransactionAdapter,
				candidate: InternalRuntimeAuditDraft,
			) => {
				received = candidate;
			},
		);
		const transaction = {
			rawTransactionQuery: vi.fn(),
			options: {},
		} as unknown as DBTransactionAdapter;
		const adapter = {
			transaction: async (callback: (trx: DBTransactionAdapter) => Promise<void>) =>
				callback(transaction),
		} as unknown as DBAdapter;
		attachInternalRuntimeAudit(adapter, {
			identity: { projectId: "project_1", environmentId: "environment_1" },
			append,
		});
		const binding = readInternalRuntimeAudit(adapter)!;
		attachCapturedInternalRuntimeAudit(transaction.options!, binding);

		await runWithRuntimeAuditRequestContext(request, async () => {
			expect(await getRuntimeAuditRequestContext()).toEqual(request);
			await runWithTransaction(adapter, async () => {
				await appendInternalRuntimeAudit(transaction, draft());
			});
		});

		expect(readInternalRuntimeAudit(transaction)).toBe(binding);
		expect(append).toHaveBeenCalledOnce();
		expect(append).toHaveBeenCalledWith(transaction, {
			...draft(),
			metadata: { factor: "password" },
		});
		expect(Object.isFrozen(received!.metadata)).toBe(true);
	});

	it("rejects a swapped binding, non-transaction adapter, and unsafe metadata", async () => {
		const target = {};
		attachInternalRuntimeAudit(target, {
			identity: { projectId: "project_1", environmentId: "environment_1" },
			append: async () => {},
		});
		const other = {};
		attachInternalRuntimeAudit(other, {
			identity: { projectId: "project_1", environmentId: "environment_2" },
			append: async () => {},
		});
		await expect(
			appendInternalRuntimeAudit(target, draft()),
		).rejects.toBeInstanceOf(RuntimeAuditTransactionRequiredError);
		expect(() =>
			attachCapturedInternalRuntimeAudit(target, readInternalRuntimeAudit(other)!),
		).toThrow(InvalidRuntimeAuditError);

		const transaction = {
			rawTransactionQuery: vi.fn(),
			options: {},
		} as unknown as DBTransactionAdapter;
		attachCapturedInternalRuntimeAudit(
			transaction.options!,
			readInternalRuntimeAudit(target)!,
		);
		const adapter = {
			transaction: async (callback: (trx: DBTransactionAdapter) => Promise<void>) =>
				callback(transaction),
		} as unknown as DBAdapter;
		await runWithTransaction(adapter, async () => {
			await expect(
				appendInternalRuntimeAudit(
					transaction,
					draft({ metadata: { authorization: "Bearer forbidden" } }),
				),
			).rejects.toBeInstanceOf(InvalidRuntimeAuditError);
		});
	});
});
