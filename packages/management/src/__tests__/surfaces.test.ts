import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { MANAGEMENT_SURFACES, consoleRoutesFromContract } from "../contracts/surfaces.js";

const here = dirname(fileURLToPath(import.meta.url));
const consoleAppJs = join(
	here,
	"..",
	"..",
	"..",
	"clearance-console",
	"public",
	"app.js",
);

describe("management surface contracts", () => {
	it("includes readiness with API and CLI contracts", () => {
		const readiness = MANAGEMENT_SURFACES.find((s) => s.id === "readiness");
		expect(readiness).toBeTruthy();
		expect(readiness!.apiPath).toContain("/v1/readiness");
		expect(readiness!.cliCommand).toContain("readiness");
		expect(readiness!.consoleRoute).toBe("readiness");
	});

	it("every consoleRoute is declared in console app.js routes", () => {
		const src = readFileSync(consoleAppJs, "utf8");
		// Match route keys inside `const routes = { ... }`
		const routesBlock = src.match(/const routes\s*=\s*\{([\s\S]*?)\n\};/);
		expect(routesBlock).toBeTruthy();
		const block = routesBlock![1];
		const declared = new Set(
			[...block.matchAll(/^ {2}(?:"([a-zA-Z0-9_-]+)"|([a-zA-Z0-9_-]+))\s*:/gm)].map(
				(m) => m[1] || m[2],
			),
		);
		for (const route of consoleRoutesFromContract()) {
			expect(declared.has(route), `console missing routes.${route}`).toBe(true);
		}
	});

	it("registers every shipped management console route", () => {
		const src = readFileSync(consoleAppJs, "utf8");
		const routesBlock = src.match(/const routes\s*=\s*\{([\s\S]*?)\n\};/);
		expect(routesBlock).toBeTruthy();
		const declared = new Set(
			[...routesBlock![1].matchAll(/^ {2}(?:"([a-zA-Z0-9_-]+)"|([a-zA-Z0-9_-]+))\s*:/gm)].map(
				(m) => m[1] || m[2],
			),
		);
		const registered = new Set(consoleRoutesFromContract());
		for (const route of declared) {
			expect(
				registered.has(route),
				`management console route ${route} is missing from MANAGEMENT_SURFACES`,
			).toBe(true);
		}
	});

	it("registers normalized authorization and service-account operations", () => {
		const ids = new Set(MANAGEMENT_SURFACES.map((surface) => surface.id));
		for (const id of [
			"roles.list",
			"roles.validate",
			"roles.create",
			"roles.update",
			"authorization.effective.inspect",
			"authorization.assignments.list",
			"authorization.assignments.replace",
			"authorization.reconcile",
			"service-accounts.list",
			"service-accounts.inspect",
			"service-accounts.create",
			"service-accounts.disable",
			"service-accounts.enable",
			"service-accounts.credentials.create",
			"service-accounts.credentials.rotate",
			"service-accounts.credentials.revoke",
		]) {
			expect(ids.has(id), `missing MANAGEMENT_SURFACES entry ${id}`).toBe(true);
		}
	});
});
