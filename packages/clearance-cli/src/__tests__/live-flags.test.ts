/**
 * CLI arming rules for live SSO/SCIM conformance (FOLLOW.md P2.1):
 * --live conflicts with --fixture, and requires --yes. Runs the built binary.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { authenticatedApiEnv, stopAuthenticatedApiServers } from "./api-test-server.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const entry = join(root, "dist", "index.js");
const dirs: string[] = [];

function run(args: string[], dataPath: string): { stdout: string; status: number } {
	try {
		const stdout = execFileSync(
			process.execPath,
			[entry, ...args, "--json", "--no-input"],
			{
				encoding: "utf8",
				env: {
					...process.env,
					DATABASE_URL: "",
					...authenticatedApiEnv(dataPath),
					CLEARANCE_SECRET: "unit-test-secret-value-not-default!!",
					CLEARANCE_BASE_URL: "http://localhost:3000",
					CLEARANCE_CREDENTIAL_KEY: "unit-test-credential-key-material-32b!!",
					CLEARANCE_CREDENTIAL_KEY_ID: "k1",
					NODE_ENV: "development",
				},
			},
		);
		return { stdout, status: 0 };
	} catch (err: unknown) {
		const e = err as { stdout?: string; status?: number };
		return { stdout: e.stdout ?? "", status: e.status ?? 1 };
	}
}

afterAll(() => {
	stopAuthenticatedApiServers();
	for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function seededStore(): { data: string; ssoId: string; scimId: string } {
	const dir = mkdtempSync(join(tmpdir(), "clr-live-flags-"));
	dirs.push(dir);
	const data = join(dir, "d.json");
	run(["init", "--name", "LiveFlags"], data);
	const org = JSON.parse(run(["orgs", "create", "--name", "Acme"], data).stdout);
	const sso = JSON.parse(
		run(
			[
				"sso", "create", "--org", org.organization.id, "--provider", "okta",
				"--protocol", "oidc", "--issuer", "https://idp.example.com",
				"--audience", "clearance-sp",
			],
			data,
		).stdout,
	);
	const scim = JSON.parse(
		run(
			[
				"scim", "create", "--org", org.organization.id, "--provider", "okta",
				"--endpoint", "https://scim.example.com/scim/v2",
			],
			data,
		).stdout,
	);
	return { data, ssoId: sso.connection.id, scimId: scim.connection.id };
}

describe("live conformance CLI arming", () => {
	it("sso test --live --fixture is a structured conflict", () => {
		const { data, ssoId } = seededStore();
		const res = run(["sso", "test", ssoId, "--live", "--fixture", "ok", "--yes"], data);
		expect(res.status).toBe(1);
		expect(JSON.parse(res.stdout).error.code).toBe("SSO_TEST_MODE_CONFLICT");
	});
	it("sso test --live without --yes is refused with remediation", () => {
		const { data, ssoId } = seededStore();
		const res = run(["sso", "test", ssoId, "--live"], data);
		expect(res.status).toBe(1);
		const doc = JSON.parse(res.stdout);
		expect(doc.error.code).toBe("SSO_LIVE_CONFIRM_REQUIRED");
		expect(doc.error.remediation).toMatch(/--yes/);
	});
	it("scim test --live --fixture is a structured conflict", () => {
		const { data, scimId } = seededStore();
		const res = run(["scim", "test", scimId, "--live", "--fixture", "ok", "--yes"], data);
		expect(res.status).toBe(1);
		expect(JSON.parse(res.stdout).error.code).toBe("SCIM_TEST_MODE_CONFLICT");
	});
	it("scim test --live without --yes is refused", () => {
		const { data, scimId } = seededStore();
		const res = run(["scim", "test", scimId, "--live"], data);
		expect(res.status).toBe(1);
		expect(JSON.parse(res.stdout).error.code).toBe("SCIM_LIVE_CONFIRM_REQUIRED");
	});
	it("armed live probe reaches the endpoint guard (no network beyond refusal)", () => {
		const { data, ssoId } = seededStore();
		// Issuer is non-loopback HTTPS, so arming succeeds and the probe runs;
		// example.com is not an OIDC issuer, so the result is a live FAIL trace
		// (never an unhandled error, never a simulation label).
		const res = run(["sso", "test", ssoId, "--live", "--yes"], data);
		const doc = JSON.parse(res.stdout);
		expect(doc.mode).toBe("live");
		expect(doc.pass).toBe(false);
		expect(doc.trace.mode).toBe("live");
	}, 30_000);
});
