import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		conditions: ["dev-source"],
		alias: [
			{ find: /^@clearance\/core$/, replacement: new URL("../core/src/index.ts", import.meta.url).pathname },
			{ find: /^@clearance\/core\/(.+)$/, replacement: `${new URL("../core/src/", import.meta.url).pathname}$1` },
			{ find: /^@clearance\/kysely-adapter$/, replacement: new URL("../kysely-adapter/src/index.ts", import.meta.url).pathname },
			{ find: /^@clearance\/runtime$/, replacement: new URL("../runtime/src/index.ts", import.meta.url).pathname },
			{ find: /^@clearance\/runtime\/crypto$/, replacement: new URL("../runtime/src/crypto/index.ts", import.meta.url).pathname },
			{ find: /^@clearance\/runtime\/plugins$/, replacement: new URL("../runtime/src/plugins/index.ts", import.meta.url).pathname },
			{ find: /^@clearance\/runtime\/db\/migration$/, replacement: new URL("../runtime/src/db/get-migration.ts", import.meta.url).pathname },
			{ find: /^@clearance\/delivery$/, replacement: new URL("../delivery/src/index.ts", import.meta.url).pathname },
			{ find: /^@clearance\/delivery-worker$/, replacement: new URL("../delivery-worker/src/index.ts", import.meta.url).pathname },
		],
	},
	test: {
		include: ["src/**/*.test.ts"],
		server: { deps: { inline: [/^@clearance\//] } },
	},
});
