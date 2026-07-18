import { defineConfig } from "tsdown";

export default defineConfig({ entry: ["src/index.ts", "src/cli.ts", "src/bin.ts"], format: ["esm"], dts: true, clean: true });
