import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
	test: {
		include: ["src/**/*.test.ts"],
		// Serial for Postgres suites that share DATABASE_URL / tables
		fileParallelism: false,
	},
	// Exercise TypeScript sources for workspace packages without a build step
	resolve: {
		alias: [
			{
				find: "@clearance/auth/secret-policy",
				replacement: resolve(here, "../clearance-auth/src/secret-policy.ts"),
			},
			{
				find: "@clearance/auth",
				replacement: resolve(here, "../clearance-auth/src/index.ts"),
			},
		],
	},
});
