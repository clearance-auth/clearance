import { describe, expect, it } from "vitest";
import {
	CLEARANCE_AUTH_VERSION,
	RUNTIME_BASELINE,
	createClearanceAuth,
	withClearanceDefaults,
} from "./index.js";

describe("@clearance/auth runtime wrapper", () => {
	it("exports real clearance factory (not constants-only stub)", async () => {
		const mod = await import("@clearance/runtime");
		expect(typeof mod.clearance).toBe("function");
		expect(typeof createClearanceAuth).toBe("function");
		expect(CLEARANCE_AUTH_VERSION).toMatch(/^\d+\.\d+\.\d+/);
		expect(RUNTIME_BASELINE).toEqual({
			package: "@clearance/runtime",
			version: "1.6.23",
		});
	});

	it("forces telemetry off via withClearanceDefaults", () => {
		const result = withClearanceDefaults({
			baseURL: "http://localhost:3000",
			telemetry: { enabled: true },
		});
		expect(result.telemetry.enabled).toBe(false);
	});

	it("createClearanceAuth builds an instance with handler and api", () => {
		// Uses DATABASE_URL if set; otherwise in-memory is not supported —
		// construction still returns handler object when postgres URL is placeholder.
		// Skip live DB if not available.
		const url =
			process.env.DATABASE_URL ??
			"postgres://clearance:clearance@127.0.0.1:5434/clearance";
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "development";
		try {
			const bundle = createClearanceAuth({
				baseURL: "http://localhost:3300",
				secret: "unit-test-secret-value-not-default!!",
				databaseUrl: url,
				enableSso: true,
				enableScim: true,
			});
			expect(typeof bundle.auth.handler).toBe("function");
			expect(bundle.auth.api).toBeTruthy();
			expect(bundle.plugins.sso).toBe(true);
			expect(bundle.plugins.scim).toBe(true);
			expect(bundle.plugins.organization).toBe(true);
			expect(bundle.rateLimitEnabled).toBe(true);
			// do not migrate here if DB down
			void bundle.destroy();
		} finally {
			process.env.NODE_ENV = prev;
		}
	});

	it("enforces production-safe SAML and SCIM defaults", async () => {
		const bundle = createClearanceAuth({
			baseURL: "http://localhost:3300",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl: "postgres://clearance:clearance@127.0.0.1:5434/clearance",
		});
		try {
			const plugins = bundle.auth.options.plugins ?? [];
			const ssoPlugin = plugins.find((plugin) => plugin.id === "sso");
			const scimPlugin = plugins.find((plugin) => plugin.id === "scim");
			const ssoOptions = ssoPlugin?.options as
				| {
						saml?: {
							allowIdpInitiated?: boolean;
							enableInResponseToValidation?: boolean;
							requireTimestamps?: boolean;
						};
				  }
				| undefined;
			const scimOptions = scimPlugin?.options as
				| {
						canGenerateToken?: (input: {
							organizationId?: string;
						}) => boolean | Promise<boolean>;
						providerOwnership?: { enabled?: boolean };
						requiredRole?: string[];
				  }
				| undefined;

			expect(ssoOptions?.saml).toMatchObject({
				enableInResponseToValidation: true,
				allowIdpInitiated: false,
				requireTimestamps: true,
			});
			expect(scimOptions?.providerOwnership?.enabled).toBe(true);
			expect(scimOptions?.requiredRole).toEqual(["admin", "owner"]);
			expect(
				await scimOptions?.canGenerateToken?.({ organizationId: undefined }),
			).toBe(false);
			expect(
				await scimOptions?.canGenerateToken?.({ organizationId: "org_1" }),
			).toBe(true);
		} finally {
			await bundle.destroy();
		}
	});

	it("production refuses default secrets", () => {
		const prev = process.env.NODE_ENV;
		process.env.NODE_ENV = "production";
		try {
			expect(() =>
				createClearanceAuth({
					baseURL: "http://localhost:3300",
					secret: "dev-secret-change-me-please-32chars!!",
					databaseUrl: "postgres://clearance:clearance@127.0.0.1:5434/clearance",
				}),
			).toThrow(/refuses default/i);
		} finally {
			process.env.NODE_ENV = prev;
		}
	});
});
