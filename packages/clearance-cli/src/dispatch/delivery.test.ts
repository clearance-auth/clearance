import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@clearance/management", async (importOriginal) => {
	const original = await importOriginal<typeof import("@clearance/management")>();
	const source = await import("../../../management/src/contracts/operations.ts");
	return {
		...original,
		DELIVERY_OPERATIONS: source.DELIVERY_OPERATIONS,
		WEBHOOK_ENDPOINT_OPERATIONS: source.WEBHOOK_ENDPOINT_OPERATIONS,
	};
});

import type { ApiSession } from "../api-client.js";
import { dispatchDeliveryCommand } from "./delivery.js";

const session: ApiSession = {
	apiUrl: "https://api.clearance.test",
	token: "operator-token-for-delivery-tests",
	profile: "test",
	credentialSource: "saved",
};

afterEach(() => vi.unstubAllGlobals());

function jsonResponse(): Response {
	return new Response(JSON.stringify({ ok: true }), { status: 200 });
}

describe("delivery remote dispatch", () => {
	it("uses the exact scoped read paths, methods, and list query shape", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return jsonResponse();
		}));

		await dispatchDeliveryCommand({
			session,
			path: "delivery list",
			args: [],
			opts: {
				limit: "25",
				cursor: "next/page",
				state: ["retry", "dead"],
				channel: "webhook",
				kind: "organization.updated",
			},
			global: {},
		});
		await dispatchDeliveryCommand({
			session,
			path: "delivery inspect",
			args: ["job /1"],
			opts: {},
			global: {},
		});
		await dispatchDeliveryCommand({
			session,
			path: "delivery readiness",
			args: [],
			opts: { staleAfterMs: "45000" },
			global: {},
		});
		await dispatchDeliveryCommand({
			session,
			path: "delivery quotas",
			args: [],
			opts: {},
			global: {},
		});

		expect(calls.map(([url, init]) => [url, init.method])).toEqual([
			[
				"https://api.clearance.test/v1/delivery/jobs?limit=25&cursor=next%2Fpage&state=retry&state=dead&channel=webhook&kind=organization.updated",
				"GET",
			],
			["https://api.clearance.test/v1/delivery/jobs/job%20%2F1", "GET"],
			["https://api.clearance.test/v1/delivery/readiness?staleAfterMs=45000", "GET"],
			["https://api.clearance.test/v1/delivery/quotas", "GET"],
		]);
	});

	it("previews mutations by default and executes only with --yes", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return jsonResponse();
		}));

		await dispatchDeliveryCommand({
			session,
			path: "delivery cancel",
			args: ["job_1"],
			opts: {},
			global: {},
		});
		await dispatchDeliveryCommand({
			session,
			path: "delivery retry",
			args: ["job_2"],
			opts: {},
			global: { yes: true },
		});
		await dispatchDeliveryCommand({
			session,
			path: "delivery replay",
			args: ["job_3"],
			opts: { maxAttempts: "12" },
			global: { yes: true, dryRun: true },
		});

		expect(calls.map(([url, init]) => ({
			url,
			method: init.method,
			body: JSON.parse(String(init.body)),
		}))).toEqual([
			{
				url: "https://api.clearance.test/v1/delivery/jobs/job_1/cancel",
				method: "POST",
				body: { dryRun: true },
			},
			{
				url: "https://api.clearance.test/v1/delivery/jobs/job_2/retry",
				method: "POST",
				body: { dryRun: false, confirm: true },
			},
			{
				url: "https://api.clearance.test/v1/delivery/jobs/job_3/replay",
				method: "POST",
				body: { maxAttempts: 12, dryRun: true, confirm: false },
			},
		]);
	});

	it("uses exact webhook endpoint routes and preview confirmation", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return jsonResponse();
		}));

		await dispatchDeliveryCommand({
			session,
			path: "delivery endpoints list",
			args: [],
			opts: { limit: "10", status: ["active", "disabled"], eventKind: "organization.updated" },
			global: {},
		});
		await dispatchDeliveryCommand({
			session,
			path: "delivery endpoints create",
			args: [],
			opts: { name: "Audit sink", url: "https://hooks.example.test/events" },
			global: {},
		});
		await dispatchDeliveryCommand({
			session,
			path: "delivery endpoints rotate",
			args: ["endpoint /1"],
			opts: { expectedVersion: "3" },
			global: { yes: true },
		});

		expect(calls.map(([url, init]) => ({
			url,
			method: init.method,
			body: init.body === undefined ? undefined : JSON.parse(String(init.body)),
		}))).toEqual([
			{
				url: "https://api.clearance.test/v1/delivery/webhook-endpoints?limit=10&status=active&status=disabled&eventKind=organization.updated",
				method: "GET",
				body: undefined,
			},
			{
				url: "https://api.clearance.test/v1/delivery/webhook-endpoints",
				method: "POST",
				body: { name: "Audit sink", url: "https://hooks.example.test/events" },
			},
			{
				url: "https://api.clearance.test/v1/delivery/webhook-endpoints/endpoint%20%2F1/rotate",
				method: "POST",
				body: { expectedVersion: 3, dryRun: false, confirm: true },
			},
		]);
	});

	it.each([
		["delivery list", { limit: "0" }],
		["delivery list", { state: ["unknown"] }],
		["delivery list", { channel: "sms" }],
		["delivery readiness", { staleAfterMs: "999" }],
		["delivery replay", { maxAttempts: "101" }],
	] as const)("rejects invalid options for %s before network I/O", async (path, opts) => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		await expect(dispatchDeliveryCommand({
			session,
			path,
			args: ["job_1"],
			opts,
			global: {},
		})).rejects.toMatchObject({ code: "DELIVERY_OPTION_INVALID" });
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects unsupported endpoint create dry-runs before network I/O", async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		await expect(dispatchDeliveryCommand({
			session,
			path: "delivery endpoints create",
			args: [],
			opts: { name: "Audit sink", url: "https://hooks.example.test/events" },
			global: { dryRun: true },
		})).rejects.toMatchObject({ code: "CLI_REMOTE_DRY_RUN_UNSUPPORTED" });
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("preserves structured API errors and exit metadata", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
			error: {
				code: "DELIVERY_JOB_NOT_FOUND",
				message: "Delivery job not found.",
				stage: "delivery.inspect",
				remediation: "Verify the scoped job id.",
				retryable: false,
			},
		}), { status: 404 })));

		await expect(dispatchDeliveryCommand({
			session,
			path: "delivery inspect",
			args: ["job_missing"],
			opts: {},
			global: { json: true, noInput: true },
		})).rejects.toMatchObject({
			code: "DELIVERY_JOB_NOT_FOUND",
			stage: "delivery.inspect",
			remediation: "Verify the scoped job id.",
			retryable: false,
			status: 404,
		});
	});
});
