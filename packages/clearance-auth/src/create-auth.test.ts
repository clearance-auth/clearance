import { generateKeyPairSync, randomUUID } from "node:crypto";
import pg from "pg";
import { describe, expect, it } from "vitest";
import {
	createKeyProviderRegistry,
	createLocalKeyProvider,
	createLocalSigningProvider,
} from "@clearance/key-management";
import {
	CLEARANCE_AUTH_VERSION,
	RUNTIME_BASELINE,
	createClearanceAuth,
	withClearanceDefaults,
} from "./index.js";

const databaseUrl =
	"postgres://clearance:clearance@127.0.0.1:5434/clearance";
const authorizationDatabaseUrl =
	process.env.CLEARANCE_TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? databaseUrl;
const authorizationDatabaseProbe = new pg.Pool({
	connectionString: authorizationDatabaseUrl,
	connectionTimeoutMillis: 500,
});
let authorizationDatabaseAvailable = false;
try {
	await authorizationDatabaseProbe.query("SELECT 1");
	authorizationDatabaseAvailable = true;
} finally {
	await authorizationDatabaseProbe.end().catch(() => {});
}
const durableKeyring = {
	currentKeyId: "current",
	keys: { current: Buffer.alloc(32, 1).toString("base64") },
	currentFingerprintKeyId: "fingerprint-current",
	fingerprintKeys: { "fingerprint-current": Buffer.alloc(32, 2).toString("base64") },
	sourceDedupeKey: Buffer.alloc(32, 3).toString("base64"),
};

function testKeyManagement(
	projectId = "project-test",
	environmentId = "environment-test",
) {
	const signingKey = generateKeyPairSync("ec", {
		namedCurve: "prime256v1",
	}).privateKey.export({ format: "der", type: "pkcs8" });
	return {
		projectId,
		environmentId,
		registry: createKeyProviderRegistry({
			"oidc-client-secret": createLocalKeyProvider({
				providerId: "test-oidc",
				purpose: "oidc-client-secret",
				currentKeyId: "v1",
				keys: { v1: Buffer.alloc(32, 11) },
			}),
			"scim-bearer-token": createLocalKeyProvider({
				providerId: "test-scim",
				purpose: "scim-bearer-token",
				currentKeyId: "v1",
				keys: { v1: Buffer.alloc(32, 12) },
			}),
			"service-account-credential-replay": createLocalKeyProvider({
				providerId: "test-service-account-credential-replay",
				purpose: "service-account-credential-replay",
				currentKeyId: "v1",
				keys: { v1: Buffer.alloc(32, 14) },
			}),
			"access-token-signing-key": createLocalKeyProvider({
				providerId: "test-jwt",
				purpose: "access-token-signing-key",
				currentKeyId: "v1",
				keys: { v1: Buffer.alloc(32, 13) },
			}),
		}),
		signingProvider: createLocalSigningProvider({
			providerId: "test-access-token-signer",
			currentKeyReference: "v1",
			keys: { v1: signingKey },
		}),
	};
}

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

	it("never trusts forwarded proxy headers", async () => {
		const bundle = createClearanceAuth({
			baseURL: "http://localhost:3300",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
		});
		try {
			const options = (bundle.auth as unknown as {
				options: { advanced?: { trustedProxyHeaders?: boolean } };
			}).options;
			expect(options.advanced?.trustedProxyHeaders).toBe(false);
		} finally {
			await bundle.destroy();
		}
	});

	it("installs encrypted two-factor, bounded HIBP, and ES256 signing defaults", async () => {
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
					keyPairConfig: { alg: "ES256" },
					gracePeriod: 7_200,
				},
				jwt: {
					issuer: "http://localhost:3300",
					audience: "http://localhost:3300",
					expirationTime: "5m",
					sign: expect.any(Function),
				},
			});
			expect(options.account?.encryptOAuthTokens).toBe(true);
		} finally {
			await bundle.destroy();
		}
	});

	it("enables breached-password defense in strict mode and bounds key overlap", async () => {
		expect(() =>
			createClearanceAuth({
				baseURL: "https://auth.example.test",
				secret: "unit-test-secret-value-not-default!!",
				databaseUrl,
				strictSecrets: true,
			}),
		).toThrow(/explicit purpose-separated keyManagement providers/);
		const strict = createClearanceAuth({
			baseURL: "https://auth.example.test",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
			strictSecrets: true,
			keyManagement: testKeyManagement(),
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

	it("rejects incompatible managed-policy rollout settings before database use", async () => {
		const common = {
			baseURL: "http://localhost:3300",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl,
			authenticationPolicy: {
				projectId: "project-managed-policy",
				environmentId: "environment-managed-policy",
			},
		} as const;
		expect(() =>
			createClearanceAuth({
				...common,
				credentialAuthority: {
					generation: "legacy-v1",
					deploymentId: "deployment-test",
					instanceId: "instance-test",
				},
			}),
		).toThrow(
			"authenticationPolicy requires credentialAuthority.generation to be digest-v1",
		);
		expect(() =>
			createClearanceAuth({
				...common,
				authenticationSecurity: {
					twoFactor: { trustDeviceMaxAgeSeconds: 31 * 24 * 60 * 60 },
				},
			}),
		).toThrow(
			"authenticationSecurity.twoFactor.trustDeviceMaxAgeSeconds must not exceed 2592000 when authenticationPolicy is enabled",
		);
		expect(() =>
			createClearanceAuth({
				...common,
				authorization: {
					projectId: common.authenticationPolicy.projectId,
					environmentId: common.authenticationPolicy.environmentId,
				},
				authenticationSecurity: {
					asymmetricAccessTokens: { enabled: false },
				},
			}),
		).toThrow(
			"authorization requires asymmetric access tokens for revision-bound action claims",
		);
		const boundary = createClearanceAuth({
			...common,
			authenticationSecurity: {
				twoFactor: { trustDeviceMaxAgeSeconds: 30 * 24 * 60 * 60 },
			},
		});
		await boundary.destroy();
	});

	it.skipIf(!authorizationDatabaseAvailable)("wires the service-account credential replay cipher during authorization bootstrap", async () => {
		const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
		const schema = `auth_replay_${suffix}`;
		const projectId = `project_replay_${suffix}`;
		const environmentId = `environment_replay_${suffix}`;
		const admin = new pg.Pool({ connectionString: authorizationDatabaseUrl });
		await admin.query(`CREATE SCHEMA "${schema}"`);
		const bundle = createClearanceAuth({
			baseURL: "http://localhost:3300",
			secret: "unit-test-secret-value-not-default!!",
			databaseUrl: authorizationDatabaseUrl,
			keyManagement: testKeyManagement(projectId, environmentId),
			authenticationPolicy: { projectId, environmentId },
			authorization: { projectId, environmentId, schema, prefix: "r" },
		});
		try {
			await bundle.migrate();
			const authorization = bundle.authorization;
			expect(authorization).toBeDefined();
			await authorization!.initializeOrganization({ organizationId: "organization_replay" });
			await authorization!.createServiceAccount({
				organizationId: "organization_replay",
				serviceAccountId: "service_account_replay",
				name: "Replay test account",
				roleIds: [],
			});
			const operationId = randomUUID();
			const input = {
				organizationId: "organization_replay",
				actorId: "principal_replay",
				operationId,
				serviceAccountId: "service_account_replay",
			};
			const created = await authorization!.createServiceAccountCredential(input);
			const replayed = await authorization!.createServiceAccountCredential(input);
			expect(created).toMatchObject({
				replayed: false,
				secret: expect.stringMatching(/^clr_sac_v1_/),
			});
			expect(replayed).toEqual({ ...created, replayed: true });
		} finally {
			await bundle.destroy();
			await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
			await admin.end();
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
						storeSCIMToken?: {
							encrypt(token: string, context: {
								providerId: string;
								organizationId?: string;
							}): Promise<string>;
							decrypt(stored: string, context: {
								providerId: string;
								organizationId?: string;
							}): Promise<string>;
						};
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
			const tokenContext = {
				providerId: "provider_1",
				organizationId: "org_1",
			};
			const storedToken = await scimOptions?.storeSCIMToken?.encrypt(
				"base-token",
				tokenContext,
			);
			expect(storedToken).toMatch(/^clr-scim:v1:clrkm\$v1\$/);
			expect(
				await scimOptions?.storeSCIMToken?.decrypt(storedToken!, tokenContext),
			).toBe("base-token");
			await expect(
				scimOptions?.storeSCIMToken?.decrypt(
					"clr-scim:v1:legacy-general-secret-ciphertext",
					tokenContext,
				),
			).rejects.toThrow("Stored SCIM token envelope is invalid");
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
			keyManagement: testKeyManagement(),
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
