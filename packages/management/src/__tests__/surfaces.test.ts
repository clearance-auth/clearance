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
			[...block.matchAll(/^\s*([a-zA-Z0-9_]+)\s*:/gm)].map((m) => m[1]),
		);
		for (const route of consoleRoutesFromContract()) {
			expect(declared.has(route), `console missing routes.${route}`).toBe(true);
		}
	});
});
