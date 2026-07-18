import { defineConfig } from "tsdown";

export default defineConfig({
	entry: ["src/index.ts", "src/preload.ts", "src/register.ts"],
	format: "esm",
	platform: "node",
	target: "node20",
	dts: true,
	clean: true,
	treeshake: true,
});
