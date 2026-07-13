import { defineConfig } from "tsdown";

export default defineConfig({
	dts: { build: true, incremental: true },
	format: ["esm"],
	entry: [
		"./src/index.ts",
		"./src/base32.ts",
		"./src/base64.ts",
		"./src/binary.ts",
		"./src/hash.ts",
		"./src/hex.ts",
		"./src/hmac.ts",
		"./src/otp.ts",
		"./src/password.ts",
		"./src/password.node.ts",
		"./src/random.ts",
	],
	unbundle: true,
	treeshake: true,
	clean: true,
});
