import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
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
