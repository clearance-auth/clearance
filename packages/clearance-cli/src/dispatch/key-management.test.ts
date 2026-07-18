import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@clearance/management", async (importOriginal) => {
	const original = await importOriginal<typeof import("@clearance/management")>();
	const source = await import("../../../management/src/contracts/operations.ts");
	return {
		...original,
		KEY_MANAGEMENT_OPERATIONS: source.KEY_MANAGEMENT_OPERATIONS,
	};
});

import type { ApiSession } from "../api-client.js";
import { dispatchKeyManagementCommand } from "./key-management.js";

const session: ApiSession = {
	apiUrl: "https://api.clearance.test",
	token: "operator-token-for-key-management-tests",
	profile: "test",
	credentialSource: "saved",
};

const planId = "a".repeat(64);

afterEach(() => vi.unstubAllGlobals());

function jsonResponse(): Response {
	return new Response(JSON.stringify({ ok: true }), { status: 200 });
}

describe("key-management remote dispatch", () => {
	it("uses the exact status and plan methods, paths, and body", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return jsonResponse();
		}));

		await dispatchKeyManagementCommand({
			session,
			path: "key-management status",
			args: [],
			opts: {},
			global: {},
		});
		await dispatchKeyManagementCommand({
			session,
			path: "key-management plan",
			args: [],
			opts: {},
			global: {},
		});

		expect(calls.map(([url, init]) => ({
			url,
			method: init.method,
			body: init.body === undefined ? undefined : JSON.parse(String(init.body)),
		}))).toEqual([
			{
				url: "https://api.clearance.test/v1/key-management/status",
				method: "GET",
				body: undefined,
			},
			{
				url: "https://api.clearance.test/v1/key-management/plan",
				method: "POST",
				body: {},
			},
		]);
	});

	it("previews apply by default, executes with --yes, and gives --dry-run precedence", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return jsonResponse();
		}));

		for (const global of [{}, { yes: true }, { yes: true, dryRun: true }]) {
			await dispatchKeyManagementCommand({
				session,
				path: "key-management apply",
				args: [],
				opts: { expectedPlan: planId },
				global,
			});
		}

		expect(calls.map(([url, init]) => ({
			url,
			method: init.method,
			body: JSON.parse(String(init.body)),
		}))).toEqual([
			{
				url: "https://api.clearance.test/v1/key-management/apply",
				method: "POST",
				body: { expectedPlanId: planId, dryRun: true },
			},
			{
				url: "https://api.clearance.test/v1/key-management/apply",
				method: "POST",
				body: { expectedPlanId: planId, dryRun: false, confirm: true },
			},
			{
				url: "https://api.clearance.test/v1/key-management/apply",
				method: "POST",
				body: { expectedPlanId: planId, dryRun: true, confirm: false },
			},
		]);
	});

	it("rejects malformed expected-plan values before requesting the API", async () => {
		const fetch = vi.fn();
		vi.stubGlobal("fetch", fetch);

		await expect(dispatchKeyManagementCommand({
			session,
			path: "key-management apply",
			args: [],
			opts: { expectedPlan: "A".repeat(64) },
			global: {},
		})).rejects.toMatchObject({
			code: "KEY_MANAGEMENT_OPTION_INVALID",
			remediation: "Run key-management plan, then retry with its plan ID.",
		});
		expect(fetch).not.toHaveBeenCalled();
	});
});
