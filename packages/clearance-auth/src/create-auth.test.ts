import { describe, expect, it } from "vitest";
import {
	CLEARANCE_AUTH_VERSION,
	RUNTIME_BASELINE,
	createClearanceAuth,
	withClearanceDefaults,
} from "./index.js";

const databaseUrl =
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const durableKeyring = {
	currentKeyId: "current",
	keys: { current: Buffer.alloc(32, 1).toString("base64") },
	fingerprintKey: Buffer.alloc(32, 2).toString("base64"),
};

function durableDelivery(invitationUrl: (invitationId: string) => string) {
	return {
		projectId: "project-test",
		environmentId: "environment-test",
		invitationUrl,
		keyring: durableKeyring,
	};
}

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

	it("enables adapter transactions only for durable delivery", async () => {
		const legacy = createClearanceAuth({
			baseURL: "http://localhost:3300",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
			enableSso: false,
			enableScim: false,
		});
		const durable = createClearanceAuth({
			baseURL: "http://localhost:3300",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
			enableSso: false,
			enableScim: false,
			durableDelivery: durableDelivery(
				(id) => `http://localhost:3300/invitations/${id}`,
			),
		});
		try {
			const legacyDatabase = (
				legacy.auth as unknown as {
					options: { database: Record<string, unknown> };
				}
			).options.database;
			const durableDatabase = (
				durable.auth as unknown as {
					options: { database: Record<string, unknown> };
				}
			).options.database;
			expect(legacyDatabase).not.toHaveProperty("transaction");
			expect(durableDatabase).toHaveProperty("transaction", true);
		} finally {
			await Promise.all([legacy.destroy(), durable.destroy()]);
		}
	});

	it("requires HTTPS durable delivery URLs in strict mode", async () => {
		expect(() =>
			createClearanceAuth({
				baseURL: "http://example.test/api/auth",
				secret: "unit-test-secret-value-not-default!!",
				databaseUrl,
				strictSecrets: true,
				enableSso: false,
				enableScim: false,
				durableDelivery: durableDelivery(
					(id) => `https://example.test/invitations/${id}`,
				),
			}),
		).toThrow(/baseURL must use HTTPS/i);

		const strictBundle = createClearanceAuth({
			baseURL: "https://example.test/api/auth",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
			strictSecrets: true,
			enableSso: false,
			enableScim: false,
			durableDelivery: durableDelivery(
				(id) => `http://example.test/invitations/${id}`,
			),
		});
		try {
			const strictDelivery = (
				strictBundle.auth as unknown as {
					options: {
						durableDelivery: { createInvitationUrl(id: string): string };
					};
				}
			).options.durableDelivery;
			expect(() => strictDelivery.createInvitationUrl("invitation-1")).toThrow(
				/durableDelivery\.invitationUrl must use HTTPS/i,
			);
		} finally {
			await strictBundle.destroy();
		}
	});

	it("allows loopback HTTP durable delivery URLs outside strict mode", async () => {
		expect(() =>
			createClearanceAuth({
				baseURL: "http://example.test/api/auth",
				secret: "unit-test-secret-value-not-default!!",
				databaseUrl,
				enableSso: false,
				enableScim: false,
				durableDelivery: durableDelivery(
					(id) => `https://example.test/invitations/${id}`,
				),
			}),
		).toThrow(/HTTP only on a loopback host/i);

		const bundle = createClearanceAuth({
			baseURL: "http://localhost:3300/api/auth",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
			enableSso: false,
			enableScim: false,
			durableDelivery: durableDelivery(
				(id) => `http://localhost:3300/invitations/${id}`,
			),
		});
		try {
			const runtimeDelivery = (
				bundle.auth as unknown as {
					options: {
						durableDelivery: { createInvitationUrl(id: string): string };
					};
				}
			).options.durableDelivery;
			expect(runtimeDelivery.createInvitationUrl("invitation-1")).toBe(
				"http://localhost:3300/invitations/invitation-1",
			);
		} finally {
			await bundle.destroy();
		}
	});
});
