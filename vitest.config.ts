import { defineConfig } from "vitest/config";

/**
 * Root Vitest workspace for Clearance product packages.
 * Inherited runtime packages keep local vitest configs and are run via
 * `pnpm test:runtime` filters; this config is for product-layer projects.
 */
export default defineConfig({
	test: {
		projects: [
			"./packages/management",
			"./packages/clearance-auth",
			"./packages/clearance-cli",
			"./packages/clearance-api",
			"./apps/sample-b2b",
		],
	},
});
