import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
	test: { include: ["src/**/*.test.ts"] },
	resolve: {
		alias: {
			"@clearance/management": resolve(
				here,
				"../../packages/management/src/index.ts",
			),
			"@clearance/auth": resolve(
				here,
				"../../packages/clearance-auth/src/index.ts",
			),
		},
	},
});
