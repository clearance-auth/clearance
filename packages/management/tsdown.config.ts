import { defineConfig } from "tsdown";

export default defineConfig({
	entry: ["src/index.ts"],
	format: "esm",
	platform: "node",
	target: "es2022",
	dts: true,
	clean: true,
	treeshake: true,
	deps: {
		// SSO and SCIM validators are Clearance fork inputs. Bundle them so npm
		// cannot substitute same-version upstream packages in production.
		onlyAllowBundle: false,
	},
});
