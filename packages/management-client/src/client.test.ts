import { describe, expect, it } from "vitest";
import * as z from "zod";
import {
	createBrowserManagementClient,
	createOrganizationMemberResource,
	createServerManagementClient,
	defineOperation,
	defineOperationRegistry,
	ManagementApiError,
	ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
	ORGANIZATION_MEMBER_REMOVE,
} from "./index.js";

function response(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
	return new Response(body === undefined ? undefined : JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...headers },
	});
}

const removeId = ORGANIZATION_MEMBER_REMOVE.id;

describe("generated management client contract", () => {
	it("uses same-origin BFF cookies and CSRF without permitting browser bearer credentials", async () => {
		let url = "";
		let request: RequestInit | undefined;
		const client = createBrowserManagementClient({
			baseUrl: "/api",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			csrfToken: "csrf-token",
			fetch: async (receivedUrl, init) => {
				url = receivedUrl;
				request = init;
				return response({ organizationId: "org/a", memberId: "member b", removed: true }, 200, {
					"x-request-id": "req_browser",
				});
			},
			createIdempotencyKey: () => "browser-retry-key",
		});
		const members = createOrganizationMemberResource(client);
		const result = await members.remove({ id: "org/a", memberId: "member b", dryRun: true });
		expect(url).toBe("/api/v1/organizations/org%2Fa/members/member%20b");
		expect(request?.credentials).toBe("include");
		expect(new Headers(request?.headers).get("x-csrf-token")).toBe("csrf-token");
		expect(new Headers(request?.headers).get("authorization")).toBeNull();
		expect(request?.body).toBe(JSON.stringify({ dryRun: true }));
		expect(result).toMatchObject({ requestId: "req_browser", idempotencyKey: "browser-retry-key" });
		expect(() => createBrowserManagementClient({
			baseUrl: "/api",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			bearerToken: "forbidden",
		} as never)).toThrow("cannot accept bearer tokens");
	});

	it("fails closed before transport for omitted confirmation and non-schema body fields", async () => {
		let calls = 0;
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			bearerToken: "operator-token",
			fetch: async () => {
				calls += 1;
				return response({ organizationId: "org_1", memberId: "mem_1", removed: true });
			},
		});
		await expect(client.call(removeId, { id: "org_1", memberId: "mem_1" }))
			.rejects.toMatchObject({ code: "MANAGEMENT_CLIENT_CONFIRMATION_REQUIRED" });
		await expect(client.call(removeId, { id: "org_1", memberId: "mem_1", dryRun: true, extra: true } as never, { confirm: true }))
			.rejects.toMatchObject({ code: "MANAGEMENT_PROTOCOL_ERROR" });
		expect(calls).toBe(0);
	});

	it("rejects malformed successful output while retaining protocol identifiers", async () => {
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			bearerToken: "operator-token",
			createIdempotencyKey: () => "retry-key-456",
			fetch: async () => response({ removed: "not-a-boolean" }, 200, { "x-request-id": "req_bad_output" }),
		});
		await expect(client.call(removeId, { id: "org_1", memberId: "mem_1" }, { confirm: true })).rejects.toMatchObject<Partial<ManagementApiError>>({
			code: "MANAGEMENT_PROTOCOL_ERROR",
			requestId: "req_bad_output",
			idempotencyKey: "retry-key-456",
		});
	});

	it("treats non-JSON successful responses as protocol errors and derives idempotency from mutation", async () => {
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			bearerToken: "operator-token",
			fetch: async () => new Response("not json", { status: 200, headers: { "x-request-id": "req_non_json" } }),
		});
		await expect(client.call(removeId, { id: "org_1", memberId: "mem_1" }, { confirm: true }))
			.rejects.toMatchObject({ code: "MANAGEMENT_PROTOCOL_ERROR", requestId: "req_non_json" });
		const diagnostic = defineOperation({
			id: "system.doctor",
			http: { method: "GET", path: "/v1/doctor" },
			mutation: true,
			supportsDryRun: false,
			confirmation: "none",
			schemas: {
				input: z.object({}).strict(),
				output: z.object({ ok: z.boolean() }).strict(),
			},
			transport: { path: [], query: [], body: [] },
		});
		let sentHeaders: Headers | undefined;
		const diagnosticClient = createServerManagementClient({
			baseUrl: "https://api.example.test",
			bearerToken: "operator-token",
			registry: defineOperationRegistry({ [diagnostic.id]: diagnostic }),
			createIdempotencyKey: () => "doctor-key",
			fetch: async (_url, init) => {
				sentHeaders = new Headers(init.headers);
				return response({ ok: true });
			},
		});
		await diagnosticClient.call(diagnostic.id, {});
		expect(sentHeaders?.get("idempotency-key")).toBe("doctor-key");
	});

	it("retains structured API errors and idempotency replay metadata", async () => {
		let sentKey: string | null = null;
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			bearerToken: "operator-token",
			createIdempotencyKey: () => "retry-key-789",
			fetch: async (_url, init) => {
				sentKey = new Headers(init.headers).get("idempotency-key");
				return response({
					error: { code: "IDEMPOTENCY_KEY_CONFLICT", message: "Already used", stage: "api.idempotency", retryable: false },
				}, 409, { "x-request-id": "req_error" });
			},
		});
		await expect(client.call(removeId, { id: "org_1", memberId: "mem_1" }, { confirm: true })).rejects.toMatchObject<Partial<ManagementApiError>>({
			code: "IDEMPOTENCY_KEY_CONFLICT",
			status: 409,
			requestId: "req_error",
			idempotencyKey: "retry-key-789",
		});
		expect(sentKey).toBe("retry-key-789");
	});

	it("derives conditional confirmation only from validated semantic live input", async () => {
		const operation = defineOperation({
			id: "sso.test",
			http: { method: "POST", path: "/v1/sso/:id/test" },
			mutation: true,
			supportsDryRun: true,
			confirmation: "client-required-when-live",
			confirmationWhen: { inputKey: "live", equals: true },
			schemas: {
				input: z.object({ id: z.string().min(1), live: z.boolean().default(false), dryRun: z.boolean().optional() }).strict(),
				output: z.object({ ok: z.boolean() }).strict(),
			},
			transport: { path: ["id"], query: [], body: ["live", "dryRun"] },
		});
		let calls = 0;
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: defineOperationRegistry({ [operation.id]: operation }),
			bearerToken: "operator-token",
			fetch: async () => {
				calls += 1;
				return response({ ok: true });
			},
		});
		await client.call(operation.id, { id: "sso_1", live: false });
		await expect(client.call(operation.id, { id: "sso_1", live: true }))
			.rejects.toMatchObject({ code: "MANAGEMENT_CLIENT_CONFIRMATION_REQUIRED" });
		await client.call(operation.id, { id: "sso_1", live: true }, { confirm: true });
		await client.call(operation.id, { id: "sso_1", live: true, dryRun: true });
		expect(calls).toBe(3);
	});

	it("preserves server-required preview confirmation as false", async () => {
		const operation = defineOperation({
			id: "events.replay",
			http: { method: "POST", path: "/v1/events/:id/replay" },
			mutation: true,
			supportsDryRun: true,
			confirmation: "server-required",
			schemas: {
				input: z.object({ id: z.string().min(1), dryRun: z.boolean().optional() }).strict(),
				output: z.object({ ok: z.boolean() }).strict(),
			},
			transport: { path: ["id"], query: [], body: ["dryRun"] },
		});
		const bodies: string[] = [];
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: defineOperationRegistry({ [operation.id]: operation }),
			bearerToken: "operator-token",
			fetch: async (_url, init) => {
				bodies.push(String(init.body));
				return response({ ok: true });
			},
		});
		await client.call(operation.id, { id: "event_1", dryRun: true });
		await client.call(operation.id, { id: "event_1", dryRun: true }, { confirm: true });
		await expect(client.call(operation.id, { id: "event_1", dryRun: false }))
			.rejects.toMatchObject({ code: "MANAGEMENT_CLIENT_CONFIRMATION_REQUIRED" });
		await client.call(operation.id, { id: "event_1", dryRun: false }, { confirm: true });
		expect(bodies).toEqual([
			JSON.stringify({ dryRun: true, confirm: false }),
			JSON.stringify({ dryRun: true, confirm: false }),
			JSON.stringify({ dryRun: false, confirm: true }),
		]);
	});

	it("selects currentPath only when its validated semantic path key is absent", async () => {
		const operation = defineOperation({
			id: "projects.inspect",
			http: { method: "GET", path: "/v1/projects/:id", currentPath: "/v1/projects/current" },
			mutation: false,
			supportsDryRun: false,
			confirmation: "none",
			schemas: {
				input: z.object({ id: z.string().min(1).optional() }).strict(),
				output: z.object({ id: z.string() }).strict(),
			},
			transport: { path: ["id"], query: [], body: [] },
		});
		const urls: string[] = [];
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: defineOperationRegistry({ [operation.id]: operation }),
			bearerToken: "operator-token",
			fetch: async (url) => {
				urls.push(url);
				return response({ id: "project" });
			},
		});
		await client.call(operation.id, {});
		await client.call(operation.id, { id: "project/a" });
		expect(urls).toEqual([
			"https://api.example.test/v1/projects/current",
			"https://api.example.test/v1/projects/project%2Fa",
		]);
	});

	it("rejects malformed descriptors and protected custom headers before transport", () => {
		expect(() => createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: { [removeId]: { ...ORGANIZATION_MEMBER_REMOVE, mutation: "yes" } } as never,
			bearerToken: "operator-token",
		})).toThrow("mutation and supportsDryRun must be booleans");
		for (const protectedName of ["Authorization", "IDEMPOTENCY-KEY", "Accept", "CONTENT-TYPE"]) {
			expect(() => createServerManagementClient({
				baseUrl: "https://api.example.test",
				registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
				bearerToken: "operator-token",
				headers: { [protectedName]: "attacker-controlled" },
			})).toThrow("transport-protected");
		}
		expect(() => createBrowserManagementClient({
			baseUrl: "/api",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			csrfHeader: "Accept",
			csrfToken: "authoritative",
		})).toThrow("protected transport authority");
	});

	it("rejects contradictory dry-run descriptors and unexpected descriptor keys", () => {
		expect(() => createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: { [removeId]: { ...ORGANIZATION_MEMBER_REMOVE, supportsDryRun: false } },
			bearerToken: "operator-token",
		})).toThrow("supportsDryRun must exactly match");
		for (const operation of [
			{ ...ORGANIZATION_MEMBER_REMOVE, unexpected: true },
			{ ...ORGANIZATION_MEMBER_REMOVE, http: { ...ORGANIZATION_MEMBER_REMOVE.http, unexpected: true } },
			{ ...ORGANIZATION_MEMBER_REMOVE, schemas: { ...ORGANIZATION_MEMBER_REMOVE.schemas, unexpected: true } },
			{ ...ORGANIZATION_MEMBER_REMOVE, transport: { ...ORGANIZATION_MEMBER_REMOVE.transport, unexpected: true } },
		]) {
			expect(() => createServerManagementClient({
				baseUrl: "https://api.example.test",
				registry: { [removeId]: operation } as never,
				bearerToken: "operator-token",
			})).toThrow("unexpected key");
		}
		const liveOperation = defineOperation({
			id: "sso.test",
			http: { method: "POST", path: "/v1/sso/:id/test" },
			mutation: true,
			supportsDryRun: false,
			confirmation: "client-required-when-live",
			confirmationWhen: { inputKey: "live", equals: true, unexpected: true },
			schemas: {
				input: z.object({ id: z.string(), live: z.boolean() }).strict(),
				output: z.object({ ok: z.boolean() }).strict(),
			},
			transport: { path: ["id"], query: [], body: ["live"] },
		});
		expect(() => createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: { [liveOperation.id]: liveOperation } as never,
			bearerToken: "operator-token",
		})).toThrow("confirmationWhen contains unexpected key");
		expect(() => createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: {
				[removeId]: {
					...ORGANIZATION_MEMBER_REMOVE,
					http: { ...ORGANIZATION_MEMBER_REMOVE.http, currentPath: "/v1/organizations/current" },
				},
			} as never,
			bearerToken: "operator-token",
		})).toThrow("currentPath requires one optional semantic path key");
	});

	it("rejects noncanonical API paths and server-required GET bodies", () => {
		for (const path of [
			"/v1/foo/../bar",
			"/v1/foo/%2Fbar",
			"/v1/foo/%5cbar",
			"/v1/foo/%2e%2e/bar",
			"/v1/foo/%zz",
		]) {
			expect(() => createServerManagementClient({
				baseUrl: "https://api.example.test",
				registry: { [removeId]: { ...ORGANIZATION_MEMBER_REMOVE, http: { ...ORGANIZATION_MEMBER_REMOVE.http, path } } } as never,
				bearerToken: "operator-token",
			})).toThrow("valid method and /v1 path");
		}
		const getWithConfirmation = defineOperation({
			id: "system.confirmed",
			http: { method: "GET", path: "/v1/confirmed" },
			mutation: true,
			supportsDryRun: false,
			confirmation: "server-required",
			schemas: { input: z.object({}).strict(), output: z.object({ ok: z.boolean() }).strict() },
			transport: { path: [], query: [], body: [] },
		});
		expect(() => createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: { [getWithConfirmation.id]: getWithConfirmation },
			bearerToken: "operator-token",
		})).toThrow("cannot project or synthesize a request body");
	});

	it("rejects ambiguous omitted live conditions", () => {
		for (const liveSchema of [z.boolean().optional(), z.boolean().default(true)]) {
			const operation = defineOperation({
				id: "sso.test",
				http: { method: "POST", path: "/v1/sso/:id/test" },
				mutation: true,
				supportsDryRun: false,
				confirmation: "client-required-when-live",
				confirmationWhen: { inputKey: "live", equals: true },
				schemas: {
					input: z.object({ id: z.string(), live: liveSchema }).strict(),
					output: z.object({ ok: z.boolean() }).strict(),
				},
				transport: { path: ["id"], query: [], body: ["live"] },
			});
			expect(() => createServerManagementClient({
				baseUrl: "https://api.example.test",
				registry: { [operation.id]: operation },
				bearerToken: "operator-token",
			})).toThrow("explicit non-live semantic value");
		}
	});

	it("rejects invalid generated or supplied mutation keys and non-scalar query entries", async () => {
		let calls = 0;
		for (const generated of ["", 0, null]) {
			const client = createServerManagementClient({
				baseUrl: "https://api.example.test",
				registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
				bearerToken: "operator-token",
				createIdempotencyKey: (() => generated) as never,
				fetch: async () => {
					calls += 1;
					return response({ organizationId: "org", memberId: "member", removed: false });
				},
			});
			await expect(client.call(removeId, { id: "org", memberId: "member", dryRun: true }))
				.rejects.toMatchObject({ code: "MANAGEMENT_CLIENT_IDEMPOTENCY_INVALID" });
		}
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			bearerToken: "operator-token",
			fetch: async () => {
				calls += 1;
				return response({ organizationId: "org", memberId: "member", removed: false });
			},
		});
		for (const idempotencyKey of ["", null, false]) {
			await expect(client.call(removeId, { id: "org", memberId: "member", dryRun: true }, { idempotencyKey } as never))
				.rejects.toMatchObject({ code: "MANAGEMENT_CLIENT_IDEMPOTENCY_INVALID" });
		}

		const queryOperation = defineOperation({
			id: "events.list",
			http: { method: "GET", path: "/v1/events" },
			mutation: false,
			supportsDryRun: false,
			confirmation: "none",
			schemas: {
				input: z.object({ filters: z.array(z.unknown()) }).strict(),
				output: z.object({ ok: z.boolean() }).strict(),
			},
			transport: { path: [], query: ["filters"], body: [] },
		});
		const queryClient = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: { [queryOperation.id]: queryOperation },
			bearerToken: "operator-token",
			fetch: async () => {
				calls += 1;
				return response({ ok: true });
			},
		});
		for (const filters of [[{}], [null], [Number.POSITIVE_INFINITY]]) {
			await expect(queryClient.call(queryOperation.id, { filters }))
				.rejects.toMatchObject({ code: "MANAGEMENT_PROTOCOL_ERROR" });
		}
		expect(calls).toBe(0);
	});

	it("rejects operation names inherited from Object.prototype", () => {
		const client = createServerManagementClient({
			baseUrl: "https://api.example.test",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			bearerToken: "operator-token",
		});
		expect(() => client.call("toString" as never, {} as never)).toThrow("Unknown operation id toString");
	});

	it("rejects unsafe base URLs while retaining explicit loopback HTTP development", () => {
		for (const baseUrl of [
			"http://example.com",
			"https://user:secret@example.com",
			"https://example.com/api?tenant=other",
			"https://example.com/api#fragment",
			"https://example.com/%zz",
			"https://shared.example/clearance/../billing",
			"https://shared.example/clearance/%2e%2e/billing",
			"https://shared.example/clearance/%2Fbilling",
			"https://shared.example/clearance/%5Cbilling",
			"https://shared.example/clearance//billing",
			"https://shared.example/clearance/",
			"https://",
		]) {
			expect(() => createServerManagementClient({
				baseUrl,
				registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
				bearerToken: "operator-token",
			})).toThrowError(ManagementApiError);
		}
		for (const baseUrl of ["http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000"]) {
			expect(() => createServerManagementClient({
				baseUrl,
				registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
				bearerToken: "operator-token",
			})).not.toThrow();
		}
		expect(() => createServerManagementClient({
			baseUrl: "https://shared.example/clearance",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			bearerToken: "operator-token",
		})).not.toThrow();
		for (const baseUrl of ["//", "//evil.example/api", "/api?tenant=other", "https://user:secret@example.com", "http://example.com/api"]) {
			expect(() => createBrowserManagementClient({
				baseUrl,
				registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
			})).toThrowError(ManagementApiError);
		}
		expect(() => createBrowserManagementClient({
			baseUrl: "http://localhost:3000/api",
			registry: ORGANIZATION_MEMBER_FIXTURE_OPERATIONS,
		})).not.toThrow();
	});
});
