import { defineConfig } from "vite";

export default defineConfig({
	root: import.meta.dirname,
	resolve: {
		conditions: ["dev-source"],
	},
});
