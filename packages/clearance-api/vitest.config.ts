import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
	test: {
		include: ["src/**/*.test.ts"],
	},
	// Resolve workspace package to TypeScript source so tests exercise this
	// change set without a package build step.
	resolve: {
		alias: {
			"@clearance/management": resolve(here, "../management/src/index.ts"),
		},
	},
});
