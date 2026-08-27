import { afterEach, describe, expect, it, vi } from "vitest";
import {
	callManagementOperation,
	resolveApiSession,
	type ApiSession,
} from "./api-client.js";
import { environmentToken, readSavedCredential } from "./operator-auth.js";

vi.mock("./operator-auth.js", async (importOriginal) => {
	const original = await importOriginal<typeof import("./operator-auth.js")>();
	return {
		...original,
		environmentToken: vi.fn(),
		readSavedCredential: vi.fn(),
	};
});

const session: ApiSession = {
	apiUrl: "https://api.clearance.test",
	token: "operator-token-for-api-client-tests",
	profile: "production",
	credentialSource: "saved",
};

afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
	vi.clearAllMocks();
});

describe("management API client contract", () => {
	it("fails closed when an explicit profile is combined with an unscoped environment token", async () => {
		vi.mocked(environmentToken).mockReturnValue("environment-operator-token");
		await expect(resolveApiSession({ profile: "production" })).rejects.toMatchObject({
			code: "CLI_PROFILE_ENV_TOKEN_CONFLICT",
		});
		expect(readSavedCredential).not.toHaveBeenCalled();
	});

	it("requires an explicit API origin for an environment token", async () => {
		vi.mocked(environmentToken).mockReturnValue("environment-operator-token");
		const previous = process.env.CLEARANCE_API_URL;
		delete process.env.CLEARANCE_API_URL;
		try {
			await expect(resolveApiSession()).rejects.toMatchObject({ code: "CLI_ENV_TOKEN_API_URL_REQUIRED" });
		} finally {
			if (previous === undefined) delete process.env.CLEARANCE_API_URL;
			else process.env.CLEARANCE_API_URL = previous;
		}
	});

	it("binds an environment token to the explicit API origin", async () => {
		vi.mocked(environmentToken).mockReturnValue("environment-operator-token");
		await expect(resolveApiSession({ apiUrl: "https://api.clearance.test" })).resolves.toMatchObject({
			apiUrl: "https://api.clearance.test",
			credentialSource: "environment",
		});
	});

	it("does not send a saved profile token to a caller-supplied mismatched origin", async () => {
		vi.mocked(environmentToken).mockReturnValue(undefined);
		vi.mocked(readSavedCredential).mockResolvedValue({
			version: 1,
			apiUrl: "https://production.clearance.test",
			token: "saved-production-operator-token",
		});
		await expect(resolveApiSession({
			profile: "production",
			apiUrl: "https://attacker.clearance.test",
		})).rejects.toMatchObject({ code: "CLI_CREDENTIAL_ORIGIN_MISMATCH" });
	});

	it("uses a saved profile only at its bound API origin", async () => {
		vi.mocked(environmentToken).mockReturnValue(undefined);
		vi.mocked(readSavedCredential).mockResolvedValue({
			version: 1,
			apiUrl: "https://production.clearance.test",
			token: "saved-production-operator-token",
		});
		await expect(resolveApiSession({
			profile: "production",
			apiUrl: "https://production.clearance.test/",
		})).resolves.toMatchObject({
			apiUrl: "https://production.clearance.test",
			profile: "production",
			credentialSource: "saved",
		});
	});

	it("uses generated transport and unwraps typed management response data", async () => {
		const onDispatch = vi.fn();
		const onMetadata = vi.fn();
		const observedSession: ApiSession = {
			...session,
			operationObserver: { onDispatch, onMetadata },
		};
		const fetchMock = vi.fn(async () => new Response(JSON.stringify({
			users: [],
			nextCursor: null,
			scope: { projectId: "prj_1", environmentId: "env_1" },
		}), { status: 200, headers: { "x-request-id": "req_actual" } }));
		vi.stubGlobal("fetch", fetchMock);
		await expect(callManagementOperation(observedSession, "users.list", { limit: 10 })).resolves.toEqual({
			users: [],
			nextCursor: null,
			scope: { projectId: "prj_1", environmentId: "env_1" },
		});
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://api.clearance.test/v1/users?limit=10");
		expect(new Headers(init.headers).get("authorization")).toBe(`Bearer ${session.token}`);
		expect(new Headers(init.headers).has("x-clearance-project-id")).toBe(false);
		expect(new Headers(init.headers).has("x-clearance-environment-id")).toBe(false);
		expect(onDispatch).toHaveBeenCalledOnce();
		expect(onMetadata).toHaveBeenCalledWith({ requestId: "req_actual" });
	});

	it("preserves response request and idempotency metadata for mutation receipts", async () => {
		const onMetadata = vi.fn();
		vi.stubGlobal("fetch", vi.fn(async () => Response.json({
			dryRun: true,
			project: { name: "Preview", slug: "preview" },
		}, { headers: { "x-request-id": "req_mutation" } })));

		await callManagementOperation({
			...session,
			operationObserver: { onDispatch: vi.fn(), onMetadata },
		}, "projects.create", { name: "Preview", dryRun: true }, {
			idempotencyKey: "operation-key-actual",
		});

		expect(onMetadata).toHaveBeenCalledWith({
			requestId: "req_mutation",
			idempotencyKey: "operation-key-actual",
		});
	});

	it("labels generated-client input validation as pre-transport", async () => {
		const fetchMock = vi.fn();
		const onDispatch = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		await expect(callManagementOperation({
			...session,
			operationObserver: { onDispatch, onMetadata: vi.fn() },
		}, "users.create", {} as never)).rejects.toMatchObject({
			code: "MANAGEMENT_PROTOCOL_ERROR",
			stage: "management-client.input",
			status: 0,
		});
		expect(onDispatch).toHaveBeenCalledOnce();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("delegates mutation JSON and idempotency authority to the generated transport", async () => {
		const fetchMock = vi.fn(async () => Response.json({
			dryRun: true,
			project: { name: "Preview", slug: "preview" },
		}));
		vi.stubGlobal("fetch", fetchMock);
		await callManagementOperation(
			session,
			"projects.create",
			{ name: "Preview", dryRun: true },
			{ idempotencyKey: "cli-test-idempotency-key" },
		);
		const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		const headers = new Headers(init.headers);
		expect(headers.get("authorization")).toBe(`Bearer ${session.token}`);
		expect(headers.get("content-type")).toBe("application/json");
		expect(headers.get("operation-key")).toBe("cli-test-idempotency-key");
		expect(JSON.parse(String(init.body))).toEqual({ name: "Preview", dryRun: true });
	});

	it("maps generated API failures to the CLI error shape without losing remote detail", async () => {
		const onMetadata = vi.fn();
		vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: {
			code: "SCOPE_MISMATCH",
			message: "Resource is outside the principal scope.",
			stage: "users.list",
			remediation: "Select the intended environment.",
			retryable: false,
		} }), { status: 404, headers: { "x-request-id": "req_rejected" } })));
		await expect(callManagementOperation({
			...session,
			operationObserver: { onDispatch: vi.fn(), onMetadata },
		}, "users.list", {})).rejects.toMatchObject({
			code: "SCOPE_MISMATCH",
			stage: "users.list",
			remediation: "Select the intended environment.",
			status: 404,
		});
		expect(onMetadata).toHaveBeenCalledWith({ requestId: "req_rejected" });
	});

	it("maps generated transport aborts to the CLI unreachable contract", async () => {
		const controller = new AbortController();
		vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
			await new Promise<void>((_resolve, reject) => {
				if (init.signal?.aborted) {
					reject(new DOMException("Aborted", "AbortError"));
					return;
				}
				init.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
			});
			throw new Error("unreachable");
		}));
		const pending = callManagementOperation(session, "users.list", {}, { signal: controller.signal });
		controller.abort();
		await expect(pending).rejects.toMatchObject({
			code: "CLI_API_UNREACHABLE",
		});
	});

	it("enforces the CLI's 15-second transport deadline", async () => {
		vi.useFakeTimers();
		vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => {
			await new Promise<void>((_resolve, reject) => {
				init.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
			});
			throw new Error("unreachable");
		}));
		const pending = callManagementOperation(session, "users.list", {});
		const rejection = expect(pending).rejects.toMatchObject({ code: "CLI_API_TIMEOUT" });
		await vi.advanceTimersByTimeAsync(15_000);
		await rejection;
	});
});
