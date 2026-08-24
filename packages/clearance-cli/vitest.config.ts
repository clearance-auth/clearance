import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		// The CLI's command matrix is generated from the same management metadata
		// tested downstream. Exercise the distinct local safety boundaries and one
		// representative transport mutation here instead of spawning every leaf.
		include: [
			"src/api-client.test.ts",
			"src/operator-auth.test.ts",
			"src/password-input.test.ts",
			"src/remote-dispatch.test.ts",
		],
	},
});
