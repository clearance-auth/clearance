import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const script = join(root, "scripts/verify-release-version.mjs");
const dirs: string[] = [];
const required = [
	"packages/clearance-auth/package.json",
	"packages/management/package.json",
	"packages/clearance-cli/package.json",
	"packages/clearance-api/package.json",
	"packages/clearance-console/package.json",
	"apps/sample-b2b/package.json",
	"deploy/helm/clearance/Chart.yaml",
	"deploy/helm/clearance/values.yaml",
	"deploy/terraform/variables.tf",
	"packages/clearance-auth/src/create-auth.ts",
	"packages/management/src/store/json-store.ts",
	"packages/clearance-api/src/server.ts",
];

afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("release version consistency", () => {
	it("accepts the current release and rejects drift in a release-bearing surface", () => {
		expect(execFileSync(process.execPath, [script, "0.1.0"], { encoding: "utf8" })).toContain("RELEASE_VERSION_OK");
		const fixture = mkdtempSync(join(tmpdir(), "clearance-release-version-"));
		dirs.push(fixture);
		for (const relative of required) {
			mkdirSync(dirname(join(fixture, relative)), { recursive: true });
			cpSync(join(root, relative), join(fixture, relative));
		}
		const api = join(fixture, "packages/clearance-api/src/server.ts");
		writeFileSync(api, readFileSync(api, "utf8").replace('version: "0.1.0",', 'version: "9.9.9",'));
		expect(() => execFileSync(process.execPath, [script, "0.1.0"], {
			encoding: "utf8",
			env: { ...process.env, CLEARANCE_RELEASE_ROOT: fixture },
			stdio: "pipe",
		})).toThrow();
	});
});
