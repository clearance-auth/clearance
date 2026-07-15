import { defineConfig } from "tsdown";

export default defineConfig({
	entry: ["src/index.ts", "src/client.ts", "src/node.ts", "src/secret-policy.ts"],
	format: "esm",
	platform: "node",
	target: "es2022",
	dts: false,
	clean: true,
	treeshake: true,
	deps: {
		// Clearance carries audited fork changes in these workspace-only packages.
		// Keeping them out of production dependencies forces the published runtime
		// and declarations to contain the reviewed code instead of resolving npm's
		// same-version Clearance packages at install time.
		onlyBundle: false,
	},
});
