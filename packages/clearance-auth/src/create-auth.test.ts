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
	currentFingerprintKeyId: "fingerprint-current",
	fingerprintKeys: { "fingerprint-current": Buffer.alloc(32, 2).toString("base64") },
	sourceDedupeKey: Buffer.alloc(32, 3).toString("base64"),
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
			expect(bundle.plugins.twoFactor).toBe(true);
			expect(bundle.plugins.breachedPassword).toBe(false);
			expect(bundle.plugins.asymmetricAccessTokens).toBe(true);
			expect(bundle.rateLimitEnabled).toBe(true);
			// do not migrate here if DB down
			void bundle.destroy();
		} finally {
			process.env.NODE_ENV = prev;
		}
	});

	it("installs encrypted two-factor, bounded HIBP, and rotating EdDSA defaults", async () => {
		const bundle = createClearanceAuth({
			baseURL: "http://localhost:3300",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
			authenticationSecurity: {
				passwordLockout: {
					maxFailedAttempts: 6,
					durationSeconds: 480,
				},
				twoFactor: {
					issuer: "Clearance Test",
					maxFailedAttempts: 7,
					lockoutSeconds: 600,
				},
				breachedPassword: { enabled: true, timeoutMs: 1_250 },
				asymmetricAccessTokens: {
					rotationIntervalSeconds: 3_600,
					gracePeriodSeconds: 7_200,
				},
			},
		});
		try {
			const options = (bundle.auth as unknown as {
				options: {
					plugins: Array<{ id: string; options?: Record<string, unknown> }>;
					account?: { encryptOAuthTokens?: boolean };
					emailAndPassword?: {
						accountLockout?: {
							enabled?: boolean;
							maxFailedAttempts?: number;
							durationSeconds?: number;
						};
					};
				};
			}).options;
			const twoFactor = options.plugins.find((plugin) => plugin.id === "two-factor");
			const breached = options.plugins.find(
				(plugin) => plugin.id === "have-i-been-pwned",
			);
			const accessTokens = options.plugins.find((plugin) => plugin.id === "jwt");
			expect(options.emailAndPassword?.accountLockout).toEqual({
				enabled: true,
				maxFailedAttempts: 6,
				durationSeconds: 480,
			});
			expect(twoFactor?.options).toMatchObject({
				issuer: "Clearance Test",
			backupCodeOptions: { storeBackupCodes: "hashed" },
				accountLockout: {
					enabled: true,
					maxFailedAttempts: 7,
					durationSeconds: 600,
				},
			});
			expect(breached?.options).toMatchObject({ enabled: true, timeoutMs: 1_250 });
			expect(accessTokens?.options).toMatchObject({
				jwks: {
					keyPairConfig: { alg: "EdDSA", crv: "Ed25519" },
					rotationInterval: 3_600,
					gracePeriod: 7_200,
				},
				jwt: {
					issuer: "http://localhost:3300",
					audience: "http://localhost:3300",
					expirationTime: "5m",
				},
			});
			expect(options.account?.encryptOAuthTokens).toBe(true);
		} finally {
			await bundle.destroy();
		}
	});

	it("enables breached-password defense in strict mode and bounds key overlap", async () => {
		const strict = createClearanceAuth({
			baseURL: "https://auth.example.test",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
			strictSecrets: true,
		});
		try {
			expect(strict.plugins.breachedPassword).toBe(true);
		} finally {
			await strict.destroy();
		}
		expect(() =>
			createClearanceAuth({
				baseURL: "http://localhost:3300",
				secret: "unit-test-secret-value-not-default!!",
				databaseUrl,
				authenticationSecurity: {
					asymmetricAccessTokens: {
						rotationIntervalSeconds: 3_600,
						gracePeriodSeconds: 86_401,
					},
				},
			}),
		).toThrow(/gracePeriodSeconds must be an integer between 300 and 86400/);
		expect(() =>
			createClearanceAuth({
				baseURL: "http://localhost:3300",
				secret: "unit-test-secret-value-not-default!!",
				databaseUrl,
				authenticationSecurity: {
					passwordLockout: { maxFailedAttempts: 2 },
				},
			}),
		).toThrow(/passwordLockout.maxFailedAttempts must be an integer between 3 and 100/);
		expect(() =>
			createClearanceAuth({
				baseURL: "http://localhost:3300",
				secret: "unit-test-secret-value-not-default!!",
				databaseUrl,
				authenticationSecurity: {
					passwordLockout: { durationSeconds: 86_401 },
				},
			}),
		).toThrow(/passwordLockout.durationSeconds must be an integer between 30 and 86400/);
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

	it("enables adapter transactions for every PostgreSQL runtime", async () => {
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
			expect(legacyDatabase).toHaveProperty("transaction", true);
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
