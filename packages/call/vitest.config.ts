import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["packages/call/src/**/*.test.ts"],
	},
});
