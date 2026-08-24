import { defineProject } from "vitest/config";

const corePublicEgress = new URL("../core/src/utils/public-egress.ts", import.meta.url).pathname;

export default defineProject({
	resolve: {
		alias: {
			"@clearance/core/utils/public-egress": corePublicEgress,
		},
	},
	test: {
		clearMocks: true,
		restoreMocks: true,
		testTimeout: 10_000,
	},
});
