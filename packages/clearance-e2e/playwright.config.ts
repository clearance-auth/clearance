import { defineConfig } from "@playwright/test";

/**
 * Rendered-browser acceptance for the compose stack (FOLLOW.md P2.5).
 * Target URLs and operator credentials come from the environment —
 * scripts/compose-smoke.sh exports its per-run randomized ports before
 * invoking this suite. Chromium only, by design: this is a gate, not a
 * browser-compatibility matrix.
 */
export default defineConfig({
	testDir: "./tests",
	timeout: 30_000,
	retries: 0,
	workers: 1,
	forbidOnly: true,
	reporter: [["list"]],
	use: {
		browserName: "chromium",
		screenshot: "only-on-failure",
	},
});
