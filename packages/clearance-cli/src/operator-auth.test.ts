import { chmodSync, existsSync, lstatSync, mkdtempSync, renameSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	credentialDirectory,
	credentialPath,
	deleteSavedCredential,
	environmentToken,
	fetchWhoami,
	normalizeApiUrl,
	readSavedCredential,
	validateAndSaveCredential,
	writeSavedCredential,
} from "./operator-auth.js";

const TOKEN = "operator-token-for-cli-tests-123456";
const dirs: string[] = [];

function testEnv(): NodeJS.ProcessEnv {
	const dir = mkdtempSync(join(tmpdir(), "clearance-cli-auth-"));
	dirs.push(dir);
	return { CLEARANCE_CLI_CONFIG_DIR: join(dir, "credentials") };
}

function whoamiResponse(): Response {
	return new Response(
		JSON.stringify({
			operator: { id: "operator", type: "operator", authenticated: true },
			projectId: "proj_cli_test",
			environmentId: "env_cli_test",
			storeBackend: "json",
		}),
		{ status: 200, headers: { "content-type": "application/json" } },
	);
}

afterEach(() => {
	vi.unstubAllGlobals();
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("Clearance CLI operator credentials", () => {
	it("validates live whoami before atomically saving a 0600 credential under a 0700 directory", async () => {
		const env = testEnv();
		vi.stubGlobal("fetch", vi.fn(async () => whoamiResponse()));

		const whoami = await validateAndSaveCredential("http://localhost:3200", TOKEN, env);
		const directory = credentialDirectory(env);
		const path = credentialPath(env);
		expect(whoami).toMatchObject({ projectId: "proj_cli_test", environmentId: "env_cli_test" });
		expect(lstatSync(directory).mode & 0o777).toBe(0o700);
		expect(lstatSync(path).mode & 0o777).toBe(0o600);
		expect(await readSavedCredential(env)).toEqual({ version: 1, apiUrl: "http://localhost:3200", token: TOKEN });
	});

	it("does not persist a credential when validation is unauthorized or unreachable, without leaking the token", async () => {
		const env = testEnv();
		vi.stubGlobal("fetch", vi.fn(async () => new Response("", { status: 401 })));
		await expect(validateAndSaveCredential("http://localhost:3200", TOKEN, env)).rejects.toMatchObject({
			code: "CLI_AUTH_UNAUTHORIZED",
		});
		expect(existsSync(credentialPath(env))).toBe(false);

		vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network unavailable"); }));
		try {
			await fetchWhoami("http://localhost:3200", TOKEN);
		} catch (cause) {
			expect(cause).toMatchObject({ code: "CLI_API_UNREACHABLE" });
			expect(String(cause)).not.toContain(TOKEN);
		}
	});

	it("rejects insecure remote HTTP and unsafe credential files without following symlinks", async () => {
		const env = testEnv();
		expect(() => normalizeApiUrl("http://api.example.test", env)).toThrow(/HTTPS/);
		expect(normalizeApiUrl("http://127.0.0.1:3200", env)).toBe("http://127.0.0.1:3200");
		await writeSavedCredential({ apiUrl: "http://localhost:3200", token: TOKEN }, env);
		chmodSync(credentialPath(env), 0o644);
		await expect(readSavedCredential(env)).rejects.toMatchObject({ code: "CLI_CREDENTIAL_FILE_UNSAFE" });

		chmodSync(credentialPath(env), 0o600);
		unlinkSync(credentialPath(env));
		const target = join(credentialDirectory(env), "other.json");
		symlinkSync(target, credentialPath(env));
		await expect(writeSavedCredential({ apiUrl: "http://localhost:3200", token: TOKEN }, env)).rejects.toMatchObject({
			code: "CLI_CREDENTIAL_FILE_UNSAFE",
		});
	});

	it("uses explicit, XDG, and home configuration resolution and rejects unsafe directories or schemas", async () => {
		const env = testEnv();
		expect(credentialDirectory(env)).toBe(env.CLEARANCE_CLI_CONFIG_DIR);
		expect(credentialDirectory({ XDG_CONFIG_HOME: "/tmp/xdg-clearance" })).toBe("/tmp/xdg-clearance/clearance");
		expect(credentialDirectory({ HOME: "/tmp/home-clearance" })).toBe("/tmp/home-clearance/.config/clearance");
		await writeSavedCredential({ apiUrl: "http://localhost:3200", token: TOKEN }, env);
		chmodSync(credentialDirectory(env), 0o755);
		await expect(readSavedCredential(env)).rejects.toMatchObject({ code: "CLI_CREDENTIAL_DIRECTORY_UNSAFE" });

		chmodSync(credentialDirectory(env), 0o700);
		writeFileSync(credentialPath(env), JSON.stringify({ version: 1, apiUrl: "http://localhost:3200", token: TOKEN, extra: true }), { mode: 0o600 });
		chmodSync(credentialPath(env), 0o600);
		await expect(readSavedCredential(env)).rejects.toMatchObject({ code: "CLI_CREDENTIAL_INVALID" });
	});

	it("makes logout idempotent and gives environment credentials precedence", async () => {
		const env = testEnv();
		await writeSavedCredential({ apiUrl: "http://localhost:3200", token: TOKEN }, env);
		expect(await deleteSavedCredential(env)).toBe(true);
		expect(await deleteSavedCredential(env)).toBe(false);
		expect(environmentToken({ CLEARANCE_OPERATOR_TOKEN: "operator-first", CLEARANCE_API_TOKEN: "api-second" })).toBe("operator-first");
		expect(environmentToken({ CLEARANCE_API_TOKEN: "api-only" })).toBe("api-only");
	});

	it("rejects tokens outside the API length contract and refuses symlinks on read", async () => {
		const env = testEnv();
		await expect(writeSavedCredential({ apiUrl: "http://localhost:3200", token: "too-short" }, env)).rejects.toMatchObject({
			code: "CLI_TOKEN_INVALID",
		});

		await writeSavedCredential({ apiUrl: "http://localhost:3200", token: TOKEN }, env);
		const target = join(credentialDirectory(env), "credential-target.json");
		renameSync(credentialPath(env), target);
		symlinkSync(target, credentialPath(env));
		await expect(readSavedCredential(env)).rejects.toMatchObject({ code: "CLI_CREDENTIAL_IO" });
	});
});
