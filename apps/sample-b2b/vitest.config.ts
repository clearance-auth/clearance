import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
	test: { include: ["src/**/*.test.ts"] },
	resolve: {
		alias: [
			{
				find: "@clearance/auth/secret-policy",
				replacement: resolve(
					here,
					"../../packages/clearance-auth/src/secret-policy.ts",
				),
			},
			{
				find: "@clearance/management",
				replacement: resolve(here, "../../packages/management/src/index.ts"),
			},
			{
				find: "@clearance/auth",
				replacement: resolve(here, "../../packages/clearance-auth/src/index.ts"),
			},
		],
	},
});
