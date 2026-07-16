import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
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
		MANAGEMENT_OPERATIONS: source.MANAGEMENT_OPERATIONS,
	};
});
import {
	classifyCommandPath,
	dispatchRemoteCommand,
} from "./remote-dispatch.js";
import type { ApiSession } from "./api-client.js";

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const entry = join(packageRoot, "dist", "index.js");
const session: ApiSession = { apiUrl: "https://api.clearance.test", token: "operator-token-for-dispatch-tests", profile: "test", credentialSource: "saved" };

afterEach(() => vi.unstubAllGlobals());

function children(path: string[]): string[] {
	const help = execFileSync(process.execPath, [entry, ...path, "--help"], {
		encoding: "utf8",
	});
	const commands = help.split("\n").slice(help.split("\n").findIndex((line) => line === "Commands:") + 1);
	const names: string[] = [];
	for (const line of commands) {
		if (!line.trim()) break;
		const match = line.match(/^  ([a-z][a-z0-9-]*)(?:\s|$)/);
		if (match?.[1] && match[1] !== "help") names.push(match[1]);
	}
	return names;
}

function leafCommands(path: string[] = []): string[] {
	const found: string[] = [];
	for (const child of children(path)) {
		const next = [...path, child];
		const nested = children(next);
		if (nested.length === 0) found.push(next.join(" "));
		else found.push(...leafCommands(next));
	}
	return found;
}

describe("CLI transport parity", () => {
	it("classifies every leaf command as API-backed or authentication-only", () => {
		const leaves = leafCommands();
		const unavailable = leaves.filter((path) => classifyCommandPath(path) === "unavailable");
		expect(unavailable).toEqual([]);
		expect(leaves.length).toBeGreaterThan(50);
		expect(leaves.filter((path) => classifyCommandPath(path) === "remote-api").length)
			.toBe(leaves.length - 3);
	});

	it("preserves optional-id and replay apply semantics", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ ok: true }), { status: 200 });
		}));
		await dispatchRemoteCommand(session, "project inspect", [], {}, {});
		await dispatchRemoteCommand(session, "env inspect", [], {}, {});
		await dispatchRemoteCommand(session, "scim replay", ["trace_1"], {}, { yes: true });
		expect(calls[0]?.[0]).toBe("https://api.clearance.test/v1/projects/current");
		expect(calls[1]?.[0]).toBe("https://api.clearance.test/v1/environments/current");
		expect(calls[2]?.[0]).toBe("https://api.clearance.test/v1/scim/traces/trace_1/replay");
		expect(JSON.parse(String(calls[2]?.[1].body))).toEqual({ dryRun: false, confirm: true });
	});

	it("routes supported previews to the API without requiring --yes", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ dryRun: true }), { status: 200 });
		}));
		await dispatchRemoteCommand(session, "project create", [], { name: "Preview" }, { dryRun: true });
		await dispatchRemoteCommand(session, "keys rotate", ["key_1"], {}, { dryRun: true });
		await dispatchRemoteCommand(session, "sso rotate", ["sso_1"], {}, { dryRun: true });
		await dispatchRemoteCommand(session, "scim rotate", ["scim_1"], {}, { dryRun: true });
		for (const [, init] of calls) expect(JSON.parse(String(init.body)).dryRun).toBe(true);
	});

	it("forwards API-key expiry through the CLI transport", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ apiKey: { id: "key_1" } }), { status: 201 });
		}));
		await dispatchRemoteCommand(
			session,
			"keys create",
			[],
			{ name: "automation", scope: ["users:read"], expiresAt: "2030-01-01T00:00:00Z" },
			{},
		);
		expect(JSON.parse(String(calls[0]?.[1].body))).toEqual({
			name: "automation",
			scopes: ["users:read"],
			expiresAt: "2030-01-01T00:00:00Z",
		});
	});

	it("routes store-v2 reads and gates apply, rollback, event, and principal authority", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ schemaVersion: "v1" }), { status: 200 });
		}));

		await dispatchRemoteCommand(session, "schema store-v2 status", [], {}, {});
		await dispatchRemoteCommand(session, "schema store-v2 plan", [], {}, {});
		await dispatchRemoteCommand(session, "schema store-v2 verify", [], {}, {});
		await expect(
			dispatchRemoteCommand(session, "schema store-v2 apply", [], {}, {}),
		).rejects.toMatchObject({ code: "STORE_V2_APPLY_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand(
			session,
			"schema store-v2 apply",
			[],
			{},
			{ dryRun: true },
		);
		await expect(
			dispatchRemoteCommand(session, "schema store-v2 rollback", [], {}, {}),
		).rejects.toMatchObject({ code: "STORE_V2_ROLLBACK_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand(
			session,
			"schema store-v2 rollback",
			[],
			{},
			{ yes: true },
		);
		await expect(
			dispatchRemoteCommand(session, "schema store-v2 principals cutover", [], {}, {}),
		).rejects.toMatchObject({ code: "STORE_V2_PRINCIPALS_CUTOVER_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand(
			session,
			"schema store-v2 principals cutover",
			[],
			{},
			{ yes: true },
		);
		await expect(
			dispatchRemoteCommand(session, "schema store-v2 principals rollback", [], {}, {}),
		).rejects.toMatchObject({ code: "STORE_V2_PRINCIPALS_ROLLBACK_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand(
			session,
			"schema store-v2 principals rollback",
			[],
			{},
			{ yes: true },
		);
		await expect(
			dispatchRemoteCommand(session, "schema store-v2 events cutover", [], {}, {}),
		).rejects.toMatchObject({ code: "STORE_V2_EVENTS_CUTOVER_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand(
			session,
			"schema store-v2 events cutover",
			[],
			{},
			{ yes: true },
		);
		await expect(
			dispatchRemoteCommand(session, "schema store-v2 events rollback", [], {}, {}),
		).rejects.toMatchObject({ code: "STORE_V2_EVENTS_ROLLBACK_CONFIRMATION_REQUIRED" });
		await dispatchRemoteCommand(
			session,
			"schema store-v2 events rollback",
			[],
			{},
			{ yes: true },
		);

		expect(calls.map(([url]) => url)).toEqual([
			"https://api.clearance.test/v1/schema/store-v2",
			"https://api.clearance.test/v1/schema/store-v2/plan",
			"https://api.clearance.test/v1/schema/store-v2/verify",
			"https://api.clearance.test/v1/schema/store-v2/apply",
			"https://api.clearance.test/v1/schema/store-v2/rollback",
			"https://api.clearance.test/v1/schema/store-v2/principals/cutover",
			"https://api.clearance.test/v1/schema/store-v2/principals/rollback",
			"https://api.clearance.test/v1/schema/store-v2/events/cutover",
			"https://api.clearance.test/v1/schema/store-v2/events/rollback",
		]);
		expect(JSON.parse(String(calls[3]?.[1].body))).toEqual({ dryRun: true });
		expect(JSON.parse(String(calls[4]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[5]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[6]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[7]?.[1].body))).toEqual({ confirm: true });
		expect(JSON.parse(String(calls[8]?.[1].body))).toEqual({ confirm: true });
	});

	it("routes credential-authority status, arm, and drain with exact confirmation payloads", async () => {
		const calls: Array<[string, RequestInit]> = [];
		vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
			calls.push([url, init]);
			return new Response(JSON.stringify({ phase: "legacy-open" }), { status: 200 });
		}));

		await dispatchRemoteCommand(
			session,
			"schema credential-authority status",
			[],
			{},
			{},
		);
		await expect(
			dispatchRemoteCommand(
				session,
				"schema credential-authority arm",
				[],
				{ deploymentId: "candidate-v03", expectedRuntimes: "2" },
				{},
			),
		).rejects.toMatchObject({
			code: "CREDENTIAL_AUTHORITY_ARM_CONFIRMATION_REQUIRED",
		});
		await dispatchRemoteCommand(
			session,
			"schema credential-authority arm",
			[],
			{ deploymentId: "candidate-v03", expectedRuntimes: "2" },
			{ yes: true },
		);
		await expect(
			dispatchRemoteCommand(
				session,
				"schema credential-authority drain",
				[],
				{ deploymentId: "candidate-v03", drainId: "drain-v03" },
				{},
			),
		).rejects.toMatchObject({
			code: "CREDENTIAL_AUTHORITY_DRAIN_CONFIRMATION_REQUIRED",
		});
		await dispatchRemoteCommand(
			session,
			"schema credential-authority drain",
			[],
			{ deploymentId: "candidate-v03", drainId: "drain-v03" },
			{ yes: true },
		);

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
		await dispatchRemoteCommand(session, "scim test", ["scim_1"], { apply: true }, { dryRun: true });
		expect(JSON.parse(String(calls[0]?.[1].body)).dryRun).toBe(true);
		await expect(
			dispatchRemoteCommand(session, "sso test", ["sso_1"], { fixture: "ok" }, { dryRun: true }),
		).rejects.toMatchObject({ code: "CLI_REMOTE_DRY_RUN_UNSUPPORTED" });
		expect(calls).toHaveLength(1);
	});

	it("uses server-managed backup storage and rejects host paths", async () => {
		const fetchMock = vi.fn(async () =>
			new Response(JSON.stringify({ backup: { id: "bak_1" } }), { status: 201 }),
		);
		vi.stubGlobal("fetch", fetchMock);
		await expect(
			dispatchRemoteCommand(session, "backup create", [], { dir: "/host/backups" }, {}),
		).rejects.toMatchObject({ code: "BACKUP_DIRECTORY_SERVER_MANAGED" });
		expect(fetchMock).not.toHaveBeenCalled();

		await dispatchRemoteCommand(session, "backup create", [], {}, {});
		expect(fetchMock).toHaveBeenCalledOnce();
		expect(fetchMock.mock.calls[0]?.[0]).toBe("https://api.clearance.test/v1/backups");
		expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({});
	});

	it.each(["sso test", "scim test"])("rejects %s --live with --dry-run before issuing a request", async (path) => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		await expect(dispatchRemoteCommand(session, path, ["connection_1"], { live: true }, {
			dryRun: true,
			yes: true,
		})).rejects.toMatchObject({
			code: path === "sso test" ? "SSO_LIVE_CONFIRM_REQUIRED" : "SCIM_LIVE_CONFIRM_REQUIRED",
		});
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it.each(["sso test", "scim test"])("requires --yes for %s --live", async (path) => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);
		await expect(dispatchRemoteCommand(session, path, ["connection_1"], { live: true }, {})).rejects.toMatchObject({
			code: path === "sso test" ? "SSO_LIVE_CONFIRM_REQUIRED" : "SCIM_LIVE_CONFIRM_REQUIRED",
		});
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
