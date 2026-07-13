import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveApiSession, requestManagementApi, type ApiSession } from "./api-client.js";
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

	it("routes reads through the versioned API with bearer auth and no caller-controlled scope", async () => {
		const fetchMock = vi.fn(async () => new Response(JSON.stringify({ users: [] }), { status: 200 }));
		vi.stubGlobal("fetch", fetchMock);
		await requestManagementApi(session, { path: "/v1/users" });
		const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(url).toBe("https://api.clearance.test/v1/users");
		expect(init.method).toBe("GET");
		expect(init.headers).toMatchObject({ authorization: `Bearer ${session.token}` });
		expect(init.headers).not.toHaveProperty("x-clearance-project-id");
		expect(init.headers).not.toHaveProperty("x-clearance-environment-id");
	});

	it("sends mutations with JSON and a unique idempotency contract", async () => {
		const fetchMock = vi.fn(async () => new Response(JSON.stringify({ user: { id: "usr_1" } }), { status: 201 }));
		vi.stubGlobal("fetch", fetchMock);
		await requestManagementApi(session, {
			method: "POST",
			path: "/v1/users",
			body: { email: "beta@example.com", name: "Beta" },
			idempotencyKey: "cli-test-idempotency-key",
		});
		const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
		expect(init.headers).toMatchObject({
			authorization: `Bearer ${session.token}`,
			"content-type": "application/json",
			"idempotency-key": "cli-test-idempotency-key",
		});
		expect(JSON.parse(String(init.body))).toEqual({ email: "beta@example.com", name: "Beta" });
	});

	it("preserves structured API errors without reflecting the credential", async () => {
		vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
			error: { code: "SCOPE_MISMATCH", message: "Resource is outside the principal scope.", stage: "users.list", retryable: false },
		}), { status: 404 })));
		await expect(requestManagementApi(session, { path: "/v1/users" })).rejects.toMatchObject({
			code: "SCOPE_MISMATCH",
			stage: "users.list",
		});
	});
});
