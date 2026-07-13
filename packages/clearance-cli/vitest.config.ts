import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["src/**/*.test.ts"],
		// Every test in this package spawns the built CLI binary (node startup
		// ~1-2s per invocation, several invocations per test). Under full-gate
		// load the vitest 5s default is marginal and flaked on a fresh-clone
		// run; the budget below is per-test headroom, not expected runtime.
		testTimeout: 120_000,
	},
});
