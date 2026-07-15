import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: { alias: { "@clearance/delivery": fileURLToPath(new URL("../delivery/src/index.ts", import.meta.url)) } },
	test: { testTimeout: 20_000, hookTimeout: 20_000 },
});
