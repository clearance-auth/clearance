import { afterEach, describe, expect, it, vi } from "vitest";

// The CLI suite resolves workspace dependencies from their last built dist.
// Supply the source-change registry additions here so transport tests remain
// build-free; management's contract suite owns the canonical definitions.
vi.mock("@clearance/management", async (importOriginal) => {
	const original = await importOriginal<typeof import("@clearance/management")>();
	const source = await import("../../management/src/contracts/operations.ts");
	return {
		...original,
		DELIVERY_OPERATIONS: source.DELIVERY_OPERATIONS,
		WEBHOOK_ENDPOINT_OPERATIONS: source.WEBHOOK_ENDPOINT_OPERATIONS,
		STORE_V2_OPERATIONS: source.STORE_V2_OPERATIONS,
		SCHEMA_OPERATIONS: source.SCHEMA_OPERATIONS,
		AUTHENTICATION_POLICY_OPERATIONS: source.AUTHENTICATION_POLICY_OPERATIONS,
		AUTHORIZATION_OPERATIONS: source.AUTHORIZATION_OPERATIONS,
		PRODUCT_DOMAIN_OPERATIONS: source.PRODUCT_DOMAIN_OPERATIONS,
		PRODUCT_PRESENTATION_OPERATIONS: source.PRODUCT_PRESENTATION_OPERATIONS,
		PRODUCT_SENDER_OPERATIONS: source.PRODUCT_SENDER_OPERATIONS,
		PRODUCT_TEMPLATE_OPERATIONS: source.PRODUCT_TEMPLATE_OPERATIONS,
		MANAGEMENT_OPERATIONS: source.MANAGEMENT_OPERATIONS,
		SERVICE_ACCOUNT_OPERATIONS: source.SERVICE_ACCOUNT_OPERATIONS,
	};
});

// These are descriptor-projection tests. Keep the generated input/path/query/body
// authority real while leaving response-schema conformance to management-client.
vi.mock("@clearance/management-client", async (importOriginal) => {
	const original = await importOriginal<typeof import("@clearance/management-client")>();
	const source = await import("../../management-client/src/generated/registry.ts");
	const client = await import("../../management-client/src/client.ts");
	const errors = await import("../../management-client/src/error.ts");
	const permissiveOutput = { safeParse: (data: unknown) => ({ success: true, data }) };
	return {
		...original,
		...client,
		...errors,
		MANAGEMENT_OPERATION_REGISTRY: Object.fromEntries(
			Object.entries(source.MANAGEMENT_OPERATION_REGISTRY).map(([id, operation]) => [
				id,
				{ ...operation, schemas: { ...operation.schemas, output: permissiveOutput } },
			]),
		),
	};
});
import { dispatchRemoteCommand } from "./remote-dispatch.js";
import type { ApiSession } from "./api-client.js";

const productSenderFixture = new URL("./__fixtures__/product-sender.json", import.meta.url).pathname;
const session: ApiSession = { apiUrl: "https://api.clearance.test", token: "operator-token-for-dispatch-tests", profile: "test", credentialSource: "saved" };

afterEach(() => vi.unstubAllGlobals());

describe("CLI transport parity", () => {
	it("preserves optional-id and replay apply semantics", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ ok: true }), { status: 200 });
		}));
		await dispatchRemoteCommand({ session: session, path: "project inspect", args: [], opts: {}, global: {} });
		await dispatchRemoteCommand({ session: session, path: "env inspect", args: [], opts: {}, global: {} });
		await dispatchRemoteCommand({ session: session, path: "scim replay", args: ["trace_1"], opts: {}, global: { yes: true } });
		expect(calls[0]?.[0]).toBe("https://api.clearance.test/v1/projects/current");
		expect(calls[1]?.[0]).toBe("https://api.clearance.test/v1/environments/current");
		expect(calls[2]?.[0]).toBe("https://api.clearance.test/v1/scim/traces/trace_1/replay");
		expect(JSON.parse(String(calls[2]?.[1].body))).toEqual({ dryRun: false, confirm: true });
	});

	it("routes the complete product domain and sender surface through canonical metadata", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ ok: true }), { status: 200 });
		}));
		await dispatchRemoteCommand({ session: session, path: "product domains reissue", args: [], opts: { origin: "https://auth.example.test", expectedVersion: "4" }, global: {} });
		await dispatchRemoteCommand({ session: session, path: "product domains activate", args: [], opts: { origin: "https://auth.example.test", expectedVersion: "5" }, global: { yes: true } });
		await dispatchRemoteCommand({ session: session, path: "product sender get", args: [], opts: {}, global: {} });
		await dispatchRemoteCommand({ session: session, path: "product sender plan", args: [], opts: { file: productSenderFixture }, global: {} });
		await dispatchRemoteCommand({ session: session, path: "product sender apply", args: [], opts: { file: productSenderFixture, expectedVersion: "2" }, global: { yes: true } });
		expect(calls.map(([url, init]) => [url, init.method, init.body ? JSON.parse(String(init.body)) : undefined])).toEqual([
			["https://api.clearance.test/v1/product-presentation/domains/reissue", "POST", { origin: "https://auth.example.test", expectedVersion: 4 }],
			["https://api.clearance.test/v1/product-presentation/domains/activate", "POST", { origin: "https://auth.example.test", expectedVersion: 5, dryRun: false, confirm: true }],
			["https://api.clearance.test/v1/product-presentation/sender", "GET", undefined],
			["https://api.clearance.test/v1/product-presentation/sender/plan", "POST", { displayName: "Clearance", address: "security@auth.example.test" }],
			["https://api.clearance.test/v1/product-presentation/sender", "PATCH", { displayName: "Clearance", address: "security@auth.example.test", expectedVersion: 2, dryRun: false, confirm: true }],
		]);
	});

	it("routes supported previews to the API without requiring --yes", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ dryRun: true }), { status: 200 });
		}));
		await dispatchRemoteCommand({ session: session, path: "project create", args: [], opts: { name: "Preview" }, global: { dryRun: true } });
		await dispatchRemoteCommand({ session: session, path: "keys rotate", args: ["key_1"], opts: {}, global: { dryRun: true } });
		await dispatchRemoteCommand({ session: session, path: "sso rotate", args: ["sso_1"], opts: {}, global: { dryRun: true } });
		await dispatchRemoteCommand({ session: session, path: "scim rotate", args: ["scim_1"], opts: {}, global: { dryRun: true } });
		for (const [, init] of calls) expect(JSON.parse(String(init.body)).dryRun).toBe(true);
	});

	it("forwards API-key expiry through the CLI transport", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ apiKey: { id: "key_1" } }), { status: 201 });
		}));
		await dispatchRemoteCommand({ session: session, path: "keys create", args: [], opts: { name: "automation", scope: ["users:read"], expiresAt: "2030-01-01T00:00:00Z" }, global: {} });
		expect(JSON.parse(String(calls[0]?.[1].body))).toEqual({
			name: "automation",
			scopes: ["users:read"],
			expiresAt: "2030-01-01T00:00:00Z",
		});
	});

	it("dispatches normalized authorization and service-account lifecycle operations exactly", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ ok: true }), { status: 200 });
		}));

		await dispatchRemoteCommand({ session: session, path: "orgs authorization effective", args: [], opts: {
			org: "org_1", subject: "user_1", subjectKind: "principal",
		}, global: {} });
		await dispatchRemoteCommand({ session: session, path: "orgs authorization assignments replace", args: [], opts: {
			org: "org_1", subject: "user_1", subjectKind: "principal", role: ["role_b", "role_a", "role_b"], expectedRevision: "7",
		}, global: { yes: true, dryRun: false } });
		await expect(dispatchRemoteCommand({ session: session, path: "orgs authorization assignments replace", args: [], opts: {
			org: "org_1", subject: "user_1", subjectKind: "principal", role: [], expectedRevision: "07",
		}, global: { dryRun: false } })).rejects.toMatchObject({ code: "AUTHORIZATION_OPTION_INVALID" });
		await expect(dispatchRemoteCommand({ session: session, path: "orgs service-accounts disable", args: ["svc_1"], opts: { org: "org_1" }, global: {} }))
			.rejects.toMatchObject({ code: "SERVICE_ACCOUNT_DISABLE_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "orgs service-accounts disable", args: ["svc_1"], opts: { org: "org_1" }, global: { yes: true, dryRun: false } });
		await dispatchRemoteCommand({ session: session, path: "orgs service-accounts credentials create", args: ["svc_1"], opts: {
			org: "org_1", expiresAt: "2030-01-01T00:00:00Z", operationId: "11111111-1111-4111-8111-111111111111",
		}, global: { dryRun: false } });
		await dispatchRemoteCommand({ session: session, path: "orgs service-accounts credentials rotate", args: ["svc_1", "cred_1"], opts: {
			org: "org_1", expiresAt: "2031-01-01T00:00:00Z",
		}, global: { yes: true, dryRun: false } });
		await dispatchRemoteCommand({ session: session, path: "orgs service-accounts credentials revoke", args: ["svc_1", "cred_1"], opts: { org: "org_1" }, global: { dryRun: true } });

		expect(calls.map(([url]) => url)).toEqual([
			"https://api.clearance.test/v1/organizations/org_1/authorization/effective/principal/user_1",
			"https://api.clearance.test/v1/organizations/org_1/authorization/assignments/principal/user_1",
			"https://api.clearance.test/v1/organizations/org_1/service-accounts/svc_1/status",
			"https://api.clearance.test/v1/organizations/org_1/service-accounts/svc_1/credentials",
			"https://api.clearance.test/v1/organizations/org_1/service-accounts/svc_1/credentials/cred_1/rotate",
			"https://api.clearance.test/v1/organizations/org_1/service-accounts/svc_1/credentials/cred_1/revoke",
		]);
		expect(JSON.parse(String(calls[1]?.[1].body))).toEqual({
			roleIds: ["role_a", "role_b"], expectedRevision: "7", dryRun: false, confirm: true,
		});
		expect(JSON.parse(String(calls[2]?.[1].body))).toEqual({ status: "disabled", dryRun: false });
		expect(JSON.parse(String(calls[3]?.[1].body))).toEqual({
			expiresAt: "2030-01-01T00:00:00Z", dryRun: false,
			operationId: "11111111-1111-4111-8111-111111111111",
		});
		expect(JSON.parse(String(calls[4]?.[1].body))).toEqual({
			expiresAt: "2031-01-01T00:00:00Z", dryRun: false,
			operationId: expect.stringMatching(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i),
		});
		expect(JSON.parse(String(calls[5]?.[1].body))).toEqual({ dryRun: true });
	});

	it("omits credential operation IDs from dry-run previews", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ dryRun: true }), { status: 200 });
		}));

		await dispatchRemoteCommand({ session: session, path: "orgs service-accounts credentials create", args: ["svc_1"], opts: { org: "org_1" }, global: { dryRun: true } });
		expect(JSON.parse(String(calls[0]?.[1].body))).toEqual({ dryRun: true });
		await expect(dispatchRemoteCommand({ session: session, path: "orgs service-accounts credentials create", args: ["svc_1"], opts: { org: "org_1", operationId: "11111111-1111-4111-8111-111111111111" }, global: { dryRun: true } })).rejects.toMatchObject({ code: "SERVICE_ACCOUNT_CREDENTIAL_OPERATION_ID_DRY_RUN_INVALID" });
		await expect(dispatchRemoteCommand({ session: session, path: "orgs service-accounts credentials rotate", args: ["svc_1", "cred_1"], opts: { org: "org_1", operationId: "not-a-uuid" }, global: { yes: true, dryRun: false } })).rejects.toMatchObject({ code: "SERVICE_ACCOUNT_CREDENTIAL_OPERATION_ID_INVALID" });
	});

	it("routes store-v2 reads and gates apply, rollback, event, principal, and topology authority", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ schemaVersion: "v1" }), { status: 200 });
		}));

		await dispatchRemoteCommand({ session: session, path: "schema store-v2 status", args: [], opts: {}, global: {} });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 plan", args: [], opts: {}, global: {} });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 verify", args: [], opts: {}, global: {} });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema store-v2 apply", args: [], opts: {}, global: {} }),
		).rejects.toMatchObject({ code: "STORE_V2_APPLY_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 apply", args: [], opts: {}, global: { dryRun: true } });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema store-v2 rollback", args: [], opts: {}, global: {} }),
		).rejects.toMatchObject({ code: "STORE_V2_ROLLBACK_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 rollback", args: [], opts: {}, global: { yes: true } });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema store-v2 principals cutover", args: [], opts: {}, global: {} }),
		).rejects.toMatchObject({ code: "STORE_V2_PRINCIPALS_CUTOVER_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 principals cutover", args: [], opts: {}, global: { yes: true } });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema store-v2 principals rollback", args: [], opts: {}, global: {} }),
		).rejects.toMatchObject({ code: "STORE_V2_PRINCIPALS_ROLLBACK_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 principals rollback", args: [], opts: {}, global: { yes: true } });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema store-v2 topology cutover", args: [], opts: {}, global: {} }),
		).rejects.toMatchObject({ code: "STORE_V2_TOPOLOGY_CUTOVER_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 topology cutover", args: [], opts: {}, global: { yes: true } });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema store-v2 topology rollback", args: [], opts: {}, global: {} }),
		).rejects.toMatchObject({ code: "STORE_V2_TOPOLOGY_ROLLBACK_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 topology rollback", args: [], opts: {}, global: { yes: true } });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema store-v2 events cutover", args: [], opts: {}, global: {} }),
		).rejects.toMatchObject({ code: "STORE_V2_EVENTS_CUTOVER_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 events cutover", args: [], opts: {}, global: { yes: true } });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema store-v2 events rollback", args: [], opts: {}, global: {} }),
		).rejects.toMatchObject({ code: "STORE_V2_EVENTS_ROLLBACK_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand({ session: session, path: "schema store-v2 events rollback", args: [], opts: {}, global: { yes: true } });

		expect(calls.map(([url]) => url)).toEqual([
			"https://api.clearance.test/v1/schema/store-v2",
			"https://api.clearance.test/v1/schema/store-v2/plan",
			"https://api.clearance.test/v1/schema/store-v2/verify",
			"https://api.clearance.test/v1/schema/store-v2/apply",
			"https://api.clearance.test/v1/schema/store-v2/rollback",
			"https://api.clearance.test/v1/schema/store-v2/principals/cutover",
			"https://api.clearance.test/v1/schema/store-v2/principals/rollback",
			"https://api.clearance.test/v1/schema/store-v2/topology/cutover",
			"https://api.clearance.test/v1/schema/store-v2/topology/rollback",
			"https://api.clearance.test/v1/schema/store-v2/events/cutover",
			"https://api.clearance.test/v1/schema/store-v2/events/rollback",
		]);
		expect(JSON.parse(String(calls[3]?.[1].body))).toEqual({ dryRun: true, confirm: false });
		expect(JSON.parse(String(calls[4]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[5]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[6]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[7]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[8]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[9]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[10]?.[1].body))).toEqual({ confirm: true });
	});

	it("routes credential-authority status, arm, and drain with exact confirmation payloads", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ phase: "legacy-open" }), { status: 200 });
		}));

		await dispatchRemoteCommand({ session: session, path: "schema credential-authority status", args: [], opts: {}, global: {} });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema credential-authority arm", args: [], opts: { deploymentId: "candidate-v03", expectedRuntimes: "2" }, global: {} }),
		).rejects.toMatchObject({
			code: "CREDENTIAL_AUTHORITY_ARM_CONFIRMATION_REQUIRED",
		});
		await dispatchRemoteCommand({ session: session, path: "schema credential-authority arm", args: [], opts: { deploymentId: "candidate-v03", expectedRuntimes: "2" }, global: { yes: true } });
		await expect(
			dispatchRemoteCommand({ session: session, path: "schema credential-authority drain", args: [], opts: { deploymentId: "candidate-v03", drainId: "drain-v03" }, global: {} }),
		).rejects.toMatchObject({
			code: "CREDENTIAL_AUTHORITY_DRAIN_CONFIRMATION_REQUIRED",
		});
		await dispatchRemoteCommand({ session: session, path: "schema credential-authority drain", args: [], opts: { deploymentId: "candidate-v03", drainId: "drain-v03" }, global: { yes: true } });

		expect(calls.map(([url]) => url)).toEqual([
			"https://api.clearance.test/v1/schema/credential-authority",
			"https://api.clearance.test/v1/schema/credential-authority/arm",
			"https://api.clearance.test/v1/schema/credential-authority/drain",
		]);
		expect(JSON.parse(String(calls[1]?.[1].body))).toEqual({
			deploymentId: "candidate-v03",
			expectedRuntimeCount: 2,
			confirm: true,
		});
		expect(JSON.parse(String(calls[2]?.[1].body))).toEqual({
			deploymentId: "candidate-v03",
			drainId: "drain-v03",
			confirm: true,
		});
	});

	it("lets global dry-run override SCIM apply and rejects unsupported SSO test previews", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ dryRun: true }), { status: 200 });
		}));
		await dispatchRemoteCommand({ session: session, path: "scim test", args: ["scim_1"], opts: { apply: true }, global: { dryRun: true } });
		expect(JSON.parse(String(calls[0]?.[1].body)).dryRun).toBe(true);
		expect(JSON.parse(String(calls[0]?.[1].body)).scenario).toBe("users");
		await expect(
			dispatchRemoteCommand({ session: session, path: "sso test", args: ["sso_1"], opts: { fixture: "ok" }, global: { dryRun: true } }),
		).rejects.toMatchObject({ code: "CLI_REMOTE_DRY_RUN_UNSUPPORTED" });
		expect(calls).toHaveLength(1);
	});

	it("forwards only the closed group-lifecycle SCIM scenario", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ dryRun: true }), { status: 200 });
		}));
		await dispatchRemoteCommand({ session: session, path: "scim test", args: ["scim_1"], opts: { scenario: "group-lifecycle" }, global: {} });
		expect(JSON.parse(String(calls[0]?.[1].body))).toMatchObject({
			dryRun: true,
			scenario: "group-lifecycle",
		});
	});

	it("refuses the bundled group lifecycle under live conformance mode", async () => {
		await expect(
			dispatchRemoteCommand({ session: session, path: "scim test", args: ["scim_1"], opts: { live: true, scenario: "group-lifecycle" }, global: { yes: true } }),
		).rejects.toMatchObject({ code: "SCIM_SCENARIO_LIVE_CONFLICT" });
	});

	it("uses server-managed backup storage and rejects host paths", async () => {
		const fetchMock = vi.fn(async () =>
			new Response(JSON.stringify({ backup: { id: "bak_1" } }), { status: 201 }),
		);
		vi.stubGlobal("fetch", fetchMock);
		await expect(
			dispatchRemoteCommand({ session: session, path: "backup create", args: [], opts: { dir: "/host/backups" }, global: {} }),
		).rejects.toMatchObject({ code: "BACKUP_DIRECTORY_SERVER_MANAGED" });
		expect(fetchMock).not.toHaveBeenCalled();

		await dispatchRemoteCommand({ session: session, path: "backup create", args: [], opts: {}, global: {} });
		expect(fetchMock).toHaveBeenCalledOnce();
		expect(fetchMock.mock.calls[0]?.[0]).toBe("https://api.clearance.test/v1/backups");
		expect(fetchMock.mock.calls[0]?.[1]?.body).toBeUndefined();
	});

	it.each(["sso test", "scim test"])("rejects %s --live with --dry-run before issuing a request", async (path) => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		await expect(dispatchRemoteCommand({ session: session, path: path, args: ["connection_1"], opts: { live: true }, global: {
			dryRun: true,
			yes: true,
		} })).rejects.toMatchObject({
			code: path === "sso test" ? "SSO_LIVE_CONFIRM_REQUIRED" : "SCIM_LIVE_CONFIRM_REQUIRED",
		});
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it.each(["sso test", "scim test"])("requires --yes for %s --live", async (path) => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		await expect(dispatchRemoteCommand({ session: session, path: path, args: ["connection_1"], opts: { live: true }, global: {} })).rejects.toMatchObject({
			code: path === "sso test" ? "SSO_LIVE_CONFIRM_REQUIRED" : "SCIM_LIVE_CONFIRM_REQUIRED",
		});
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
