import { randomUUID } from "node:crypto";
import {
	clearance,
	APIError,
	type ClearanceOptions,
} from "../../runtime/src/index.js";
import {
	createDeliveryKeyring,
	enqueueDeliveryInExistingTransaction,
	migrateDeliverySchema,
} from "@clearance/delivery";
import {
	symmetricDecrypt,
	symmetricEncrypt,
} from "../../runtime/src/crypto/index.js";
import {
	encodeBackupCodes,
	haveIBeenPwned,
	jwt,
	isOneWayBackupCodeEnvelope,
	organization,
	passkey,
	twoFactor,
	type Jwk,
	type PasskeyOptions,
} from "../../runtime/src/plugins/index.js";
import { getMigrations } from "../../runtime/src/db/get-migration.js";
import { attachInternalCredentialAuthority } from "../../runtime/src/internal/credential-authority.js";
import { sso } from "@clearance/sso";
import { scim } from "@clearance/scim";
import { Kysely, PostgresDialect } from "kysely";
import pg from "pg";
import {
	MINIMUM_SECRET_LENGTH,
	isForbiddenDefaultSecret,
} from "./secret-policy.js";
import {
	PostgresCredentialAuthorityFence,
	bootstrapCredentialAuthorityFence,
} from "./credential-authority-fence.js";
import type {
	ClearanceAuthBundle,
	ClearanceAuthenticationSecurityOptions,
	ClearancePasskeyOptions,
	ClearanceProductAuthRuntime,
	ClearanceRuntimeMigrationPlan,
	ClearanceRuntimeMigrationResult,
	ClearanceRuntimeUser,
	CreateClearanceAuthOptions,
	SocialProviderConfig,
} from "./public-types/index.js";

export const CLEARANCE_AUTH_VERSION = "0.2.1";
export const RUNTIME_BASELINE = {
	package: "@clearance/runtime",
	version: "1.6.23",
} as const;

export type {
	ClearanceAuthBundle,
	ClearanceRuntimeMigrationPlan,
	ClearanceRuntimeMigrationResult,
	ClearanceRuntimeUser,
	CreateClearanceAuthOptions,
	ClearanceAuthenticationSecurityOptions,
	ClearancePasskeyOptions,
	SocialProviderConfig,
} from "./public-types/index.js";

function createLeaseBoundMigrationDatabase(client: pg.PoolClient): Kysely<unknown> {
	// Kysely releases a client after every reserved connection. The migration
	// session must retain the exact pg backend that owns the advisory lease, so
	// expose a single-client pool whose release/end operations are deliberately
	// local no-ops. The fence remains the sole owner of the real client lifetime.
	const leasedClient = {
		query: client.query.bind(client),
		release: () => undefined,
	};
	const leasedPool = {
		connect: async () => leasedClient,
		end: async () => undefined,
		options: {},
	};
	return new Kysely({
		dialect: new PostgresDialect({
			pool: leasedPool as unknown as pg.Pool,
		}),
	});
}

export function socialProvidersFromEnvironment(
	env: Record<string, string | undefined> = process.env,
): Record<string, SocialProviderConfig> {
	const providers: Record<string, SocialProviderConfig> = {};
	if (
		Boolean(env.CLEARANCE_GITHUB_CLIENT_ID) !==
		Boolean(env.CLEARANCE_GITHUB_CLIENT_SECRET)
	) {
		throw new Error(
			"GitHub social login requires both CLEARANCE_GITHUB_CLIENT_ID and CLEARANCE_GITHUB_CLIENT_SECRET",
		);
	}
	if (
		Boolean(env.CLEARANCE_GOOGLE_CLIENT_ID) !==
		Boolean(env.CLEARANCE_GOOGLE_CLIENT_SECRET)
	) {
		throw new Error(
			"Google social login requires both CLEARANCE_GOOGLE_CLIENT_ID and CLEARANCE_GOOGLE_CLIENT_SECRET",
		);
	}
	if (env.CLEARANCE_GITHUB_CLIENT_ID && env.CLEARANCE_GITHUB_CLIENT_SECRET) {
		providers.github = {
			clientId: env.CLEARANCE_GITHUB_CLIENT_ID,
			clientSecret: env.CLEARANCE_GITHUB_CLIENT_SECRET,
		};
	}
	if (env.CLEARANCE_GOOGLE_CLIENT_ID && env.CLEARANCE_GOOGLE_CLIENT_SECRET) {
		providers.google = {
			clientId: env.CLEARANCE_GOOGLE_CLIENT_ID,
			clientSecret: env.CLEARANCE_GOOGLE_CLIENT_SECRET,
		};
	}
	return providers;
}

function boundedSecurityInteger(
	value: number | undefined,
	fallback: number,
	input: { label: string; min: number; max: number },
): number {
	const resolved = value ?? fallback;
	if (
		!Number.isSafeInteger(resolved) ||
		resolved < input.min ||
		resolved > input.max
	) {
		throw new Error(
			`${input.label} must be an integer between ${input.min} and ${input.max}`,
		);
	}
	return resolved;
}

type ResolvedAuthenticationSecurity = {
	twoFactor: {
		enabled: boolean;
		issuer: string;
		maxFailedAttempts: number;
		lockoutSeconds: number;
		trustDeviceMaxAgeSeconds: number;
	};
	breachedPassword: {
		enabled: boolean;
		customMessage?: string;
		timeoutMs: number;
	};
	asymmetricAccessTokens: {
		enabled: boolean;
		issuer: string;
		audience: string | string[];
		rotationIntervalSeconds: number;
		gracePeriodSeconds: number;
	};
};

function resolveAuthenticationSecurity(
	options: CreateClearanceAuthOptions<
		ClearanceAuthenticationSecurityOptions | undefined
	>,
	strict: boolean,
): ResolvedAuthenticationSecurity {
	const input = options.authenticationSecurity;
	const rotationIntervalSeconds = boundedSecurityInteger(
		input?.asymmetricAccessTokens?.rotationIntervalSeconds,
		24 * 60 * 60,
		{
			label:
				"authenticationSecurity.asymmetricAccessTokens.rotationIntervalSeconds",
			min: 300,
			max: 365 * 24 * 60 * 60,
		},
	);
	const gracePeriodSeconds = boundedSecurityInteger(
		input?.asymmetricAccessTokens?.gracePeriodSeconds,
		15 * 60,
		{
			label: "authenticationSecurity.asymmetricAccessTokens.gracePeriodSeconds",
			min: 300,
			max: 24 * 60 * 60,
		},
	);
	return {
		twoFactor: {
			enabled: input?.twoFactor?.enabled !== false,
			issuer: input?.twoFactor?.issuer?.trim() || "Clearance",
			maxFailedAttempts: boundedSecurityInteger(
				input?.twoFactor?.maxFailedAttempts,
				10,
				{
					label: "authenticationSecurity.twoFactor.maxFailedAttempts",
					min: 3,
					max: 100,
				},
			),
			lockoutSeconds: boundedSecurityInteger(
				input?.twoFactor?.lockoutSeconds,
				15 * 60,
				{
					label: "authenticationSecurity.twoFactor.lockoutSeconds",
					min: 30,
					max: 24 * 60 * 60,
				},
			),
			trustDeviceMaxAgeSeconds: boundedSecurityInteger(
				input?.twoFactor?.trustDeviceMaxAgeSeconds,
				30 * 24 * 60 * 60,
				{
					label: "authenticationSecurity.twoFactor.trustDeviceMaxAgeSeconds",
					min: 60,
					max: 365 * 24 * 60 * 60,
				},
			),
		},
		breachedPassword: {
			enabled: input?.breachedPassword?.enabled ?? strict,
			customMessage: input?.breachedPassword?.customMessage,
			timeoutMs: boundedSecurityInteger(
				input?.breachedPassword?.timeoutMs,
				5_000,
				{
					label: "authenticationSecurity.breachedPassword.timeoutMs",
					min: 100,
					max: 30_000,
				},
			),
		},
		asymmetricAccessTokens: {
			enabled: input?.asymmetricAccessTokens?.enabled !== false,
			issuer: input?.asymmetricAccessTokens?.issuer ?? options.baseURL,
			audience: input?.asymmetricAccessTokens?.audience ?? options.baseURL,
			rotationIntervalSeconds,
			gracePeriodSeconds,
		},
	};
}

function postgresJwksAdapter(pool: pg.Pool) {
	const selectColumns = `id, "publicKey", "privateKey", "createdAt", "expiresAt", alg, crv`;
	return {
		async getJwks(): Promise<Jwk[]> {
			const result = await pool.query<Jwk>(
				`SELECT ${selectColumns} FROM jwks ORDER BY "createdAt" DESC`,
			);
			return result.rows;
		},
		async createJwk(data: Omit<Jwk, "id">): Promise<Jwk> {
			const client = await pool.connect();
			try {
				await client.query("BEGIN");
				await client.query(
					`SELECT pg_advisory_xact_lock(
						hashtext(current_database()),
						hashtext(current_schema() || ':clearance:jwks-rotation')
					)`,
				);
				const current = await client.query<Jwk>(
					`SELECT ${selectColumns} FROM jwks
					 WHERE ("expiresAt" IS NULL OR "expiresAt" > now())
					   AND alg = 'EdDSA' AND crv = 'Ed25519'
					 ORDER BY "createdAt" DESC FOR UPDATE`,
				);
				const activeEd25519 = current.rows.find(
					(row) =>
						row.alg === "EdDSA" &&
						isCompatiblePublicJwk(row.publicKey, "EdDSA"),
				);
				if (activeEd25519) {
					await client.query("COMMIT");
					return activeEd25519;
				}

				const inserted = await client.query<Jwk>(
					`INSERT INTO jwks
					 (id, "publicKey", "privateKey", "createdAt", "expiresAt", alg, crv)
					 VALUES ($1, $2, $3, $4, $5, $6, $7)
					 RETURNING ${selectColumns}`,
					[
						randomUUID(),
						data.publicKey,
						data.privateKey,
						data.createdAt,
						data.expiresAt ?? null,
						data.alg ?? null,
						data.crv ?? null,
					],
				);
				await client.query("COMMIT");
				if (!inserted.rows[0]) {
					throw new Error("JWT signing key insert returned no row");
				}
				return inserted.rows[0];
			} catch (error) {
				await client.query("ROLLBACK").catch(() => {});
				throw error;
			} finally {
				client.release();
			}
		},
	};
}

function inferJwkMetadata(publicKey: string): {
	alg: NonNullable<Jwk["alg"]>;
	crv?: NonNullable<Jwk["crv"]>;
} | null {
	let key: { alg?: unknown; crv?: unknown; kty?: unknown };
	try {
		key = JSON.parse(publicKey) as typeof key;
	} catch {
		return null;
	}
	if (
		key.alg === "EdDSA" ||
		key.alg === "ES256" ||
		key.alg === "ES512" ||
		key.alg === "PS256" ||
		key.alg === "RS256"
	) {
		return {
			alg: key.alg,
			...(key.crv === "Ed25519" || key.crv === "P-256" || key.crv === "P-521"
				? { crv: key.crv }
				: {}),
		};
	}
	if (key.kty === "OKP" && key.crv === "Ed25519") {
		return { alg: "EdDSA", crv: "Ed25519" };
	}
	if (key.kty === "EC" && key.crv === "P-256") {
		return { alg: "ES256", crv: "P-256" };
	}
	if (key.kty === "EC" && key.crv === "P-521") {
		return { alg: "ES512", crv: "P-521" };
	}
	return null;
}

function isSupportedJwkAlgorithm(
	value: unknown,
): value is NonNullable<Jwk["alg"]> {
	return (
		value === "EdDSA" ||
		value === "ES256" ||
		value === "ES512" ||
		value === "PS256" ||
		value === "RS256"
	);
}

function isSupportedJwkCurve(value: unknown): value is NonNullable<Jwk["crv"]> {
	return value === "Ed25519" || value === "P-256" || value === "P-521";
}

function isCompatiblePublicJwk(
	publicKey: string,
	alg: NonNullable<Jwk["alg"]>,
): boolean {
	let key: {
		crv?: unknown;
		e?: unknown;
		kty?: unknown;
		n?: unknown;
		x?: unknown;
		y?: unknown;
	};
	try {
		key = JSON.parse(publicKey) as typeof key;
	} catch {
		return false;
	}
	if (alg === "EdDSA") {
		return (
			key.kty === "OKP" && key.crv === "Ed25519" && typeof key.x === "string"
		);
	}
	if (alg === "ES256" || alg === "ES512") {
		return (
			key.kty === "EC" &&
			key.crv === (alg === "ES256" ? "P-256" : "P-521") &&
			typeof key.x === "string" &&
			typeof key.y === "string"
		);
	}
	return (
		key.kty === "RSA" && typeof key.n === "string" && typeof key.e === "string"
	);
}

async function migrateRecoveryCodesToHashes(
	stored: string,
	secret: string,
): Promise<string> {
	if (stored.startsWith("clr-recovery:")) {
		if (!isOneWayBackupCodeEnvelope(stored)) {
			throw new Error("Cannot migrate invalid recovery-code envelope");
		}
		return stored;
	}
	let plaintext: string;
	try {
		plaintext = await decryptRuntimeCredential(stored, secret);
	} catch {
		plaintext = stored;
	}
	const codes = JSON.parse(plaintext) as unknown;
	if (
		!Array.isArray(codes) ||
		codes.some((code) => typeof code !== "string" || code.length === 0)
	) {
		throw new Error("Cannot migrate invalid two-factor recovery-code storage");
	}
	return encodeBackupCodes(codes, secret, { storeBackupCodes: "hashed" });
}

export async function encryptRuntimeCredential(
	plaintext: string,
	secret: string,
): Promise<string> {
	return symmetricEncrypt({ key: secret, data: plaintext });
}

export async function decryptRuntimeCredential(
	ciphertext: string,
	secret: string,
): Promise<string> {
	return symmetricDecrypt({ key: secret, data: ciphertext });
}

function validateDurableDeliveryUrl(
	raw: string,
	label: string,
	requireHttps: boolean,
): URL {
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error(`${label} must be an absolute URL`);
	}
	if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
		throw new Error(`${label} must be an HTTP(S) URL`);
	}
	if (requireHttps && parsed.protocol !== "https:") {
		throw new Error(`${label} must use HTTPS in strict mode`);
	}
	if (
		parsed.protocol === "http:" &&
		!["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname.toLowerCase())
	) {
		throw new Error(`${label} may use HTTP only on a loopback host`);
	}
	return parsed;
}

/**
 * Build a Clearance auth instance on the Clearance runtime.
 * Telemetry is always disabled. Rate limiting is enabled by default.
 * Postgres is the data plane via Kysely.
 * Production (NODE_ENV=production) refuses default/weak secrets.
 */
export function createClearanceAuth<
	const Security extends ClearanceAuthenticationSecurityOptions | undefined =
		undefined,
	const Passkeys extends false | ClearancePasskeyOptions | undefined = undefined,
>(
	options: CreateClearanceAuthOptions<Security, Passkeys>,
): ClearanceAuthBundle<Security, Passkeys> {
	const nodeEnv = process.env.NODE_ENV ?? "development";
	const strict =
		options.strictSecrets === true ||
		nodeEnv === "production" ||
		process.env.CLEARANCE_STRICT_SECRETS === "1";

	if (strict && isForbiddenDefaultSecret(options.secret)) {
		throw new Error(
			"Production refuses default/weak CLEARANCE_SECRET. Set a strong random secret (openssl rand -base64 32).",
		);
	}
	if (!options.secret || options.secret.length < MINIMUM_SECRET_LENGTH) {
		throw new Error("CLEARANCE_SECRET must be at least 16 characters");
	}
	if (!options.databaseUrl) {
		throw new Error("databaseUrl is required for createClearanceAuth");
	}
	if (options.durableDelivery) {
		validateDurableDeliveryUrl(options.baseURL, "baseURL", strict);
	}
	const authenticationSecurity = resolveAuthenticationSecurity(options, strict);
	const passkeyOptions: PasskeyOptions | undefined =
		options.passkeys === false ? undefined : options.passkeys;

	const pool = new pg.Pool({ connectionString: options.databaseUrl });
	const credentialAuthorityGeneration =
		options.credentialAuthority?.generation ?? "digest-v1";
	const credentialAuthority = new PostgresCredentialAuthorityFence(pool, {
		generation: credentialAuthorityGeneration,
		deploymentId:
			options.credentialAuthority?.deploymentId ?? (strict ? "" : "development"),
		instanceId:
			options.credentialAuthority?.instanceId ??
			(strict ? "" : `development-${randomUUID()}`),
	});
	let legacyBridgeCompatibilityPromise: Promise<void> | null = null;
	const assertProductRuntimeServing = async () => {
		await credentialAuthority.assertRuntimeServing();
		if (credentialAuthorityGeneration === "legacy-v1") {
			legacyBridgeCompatibilityPromise ??=
				ensureLegacyBridgeCompatibility().catch((error) => {
					legacyBridgeCompatibilityPromise = null;
					throw error;
				});
			await legacyBridgeCompatibilityPromise;
			await credentialAuthority.assertRuntimeServing();
		}
	};
	const jwksAdapter = postgresJwksAdapter(pool);
	const db = new Kysely({
		dialect: new PostgresDialect({ pool }),
	});
	const deliveryKeyring = options.durableDelivery
		? createDeliveryKeyring(options.durableDelivery.keyring)
		: null;
	const durableDelivery =
		options.durableDelivery && deliveryKeyring
			? {
					createInvitationUrl: (invitationId: string) => {
						const raw = options.durableDelivery!.invitationUrl(invitationId);
						const parsed = validateDurableDeliveryUrl(
							raw,
							"durableDelivery.invitationUrl",
							strict,
						);
						return parsed.toString();
					},
					enqueue: async (
						transaction: {
							rawTransactionQuery?: <
								Row extends Record<string, unknown> = Record<string, unknown>,
							>(
								text: string,
								values?: readonly unknown[],
							) => Promise<{ rows: Row[]; rowCount: number | null }>;
						},
						input: Omit<
							Parameters<typeof enqueueDeliveryInExistingTransaction>[1],
							"projectId" | "environmentId"
						>,
					) => {
						await enqueueDeliveryInExistingTransaction(
							transaction,
							{
								...input,
								projectId: options.durableDelivery!.projectId,
								environmentId: options.durableDelivery!.environmentId,
							},
							deliveryKeyring,
							{
								schema: options.durableDelivery!.schema,
								prefix: options.durableDelivery!.prefix,
							},
						);
					},
				}
			: undefined;
	const database = {
		db,
		type: "postgres" as const,
		transaction: true as const,
	};

	const plugins = [
		organization(),
		...(options.passkeys === false ? [] : [passkey(passkeyOptions)]),
		...(authenticationSecurity.twoFactor.enabled
			? [
					twoFactor({
						issuer: authenticationSecurity.twoFactor.issuer,
						backupCodeOptions: { storeBackupCodes: "hashed" },
						trustDeviceMaxAge:
							authenticationSecurity.twoFactor.trustDeviceMaxAgeSeconds,
						accountLockout: {
							enabled: true,
							maxFailedAttempts:
								authenticationSecurity.twoFactor.maxFailedAttempts,
							durationSeconds: authenticationSecurity.twoFactor.lockoutSeconds,
						},
					}),
				]
			: []),
		haveIBeenPwned({
			enabled: authenticationSecurity.breachedPassword.enabled,
			customPasswordCompromisedMessage:
				authenticationSecurity.breachedPassword.customMessage,
			timeoutMs: authenticationSecurity.breachedPassword.timeoutMs,
		}),
		...(authenticationSecurity.asymmetricAccessTokens.enabled
			? [
					jwt({
						disableSettingJwtHeader: true,
						adapter: jwksAdapter,
						jwks: {
							keyPairConfig: { alg: "EdDSA", crv: "Ed25519" },
							rotationInterval:
								authenticationSecurity.asymmetricAccessTokens
									.rotationIntervalSeconds,
							gracePeriod:
								authenticationSecurity.asymmetricAccessTokens
									.gracePeriodSeconds,
						},
						jwt: {
							issuer: authenticationSecurity.asymmetricAccessTokens.issuer,
							audience: authenticationSecurity.asymmetricAccessTokens.audience,
							expirationTime: "5m",
						},
					}),
				]
			: []),
		...(options.enableSso !== false
			? [
					sso({
						saml: {
							enableInResponseToValidation: true,
							allowIdpInitiated: false,
							requireTimestamps: true,
						},
						storeOIDCClientSecret: {
							encrypt: (secret) =>
								encryptRuntimeCredential(secret, options.secret),
							decrypt: (ciphertext) =>
								decryptRuntimeCredential(ciphertext, options.secret),
						},
					}),
				]
			: []),
		...(options.enableScim !== false
			? [
					scim({
						// Clearance only issues organization-scoped SCIM credentials. The
						// SCIM plugin performs the membership + admin/owner role check before
						// this additional fail-closed gate runs.
						canGenerateToken: ({ organizationId }) => Boolean(organizationId),
						providerOwnership: { enabled: true },
						requiredRole: ["admin", "owner"],
						storeSCIMToken: {
							encrypt: (token) =>
								encryptRuntimeCredential(token, options.secret),
							decrypt: (token) =>
								decryptRuntimeCredential(token, options.secret),
						},
					}),
				]
			: []),
		...((options.plugins ?? []) as NonNullable<ClearanceOptions["plugins"]>),
	];

	const rateLimitEnabled = options.rateLimitEnabled ?? true;
	const rateLimit = {
		enabled: rateLimitEnabled,
		window: 60,
		max: 100,
		storage: "database" as const,
	};
	const onUserCreated = options.onUserCreated;

	/**
	 * Lifecycle field for disable/delete enforcement at session creation.
	 * Management mutations set `banned` (and optional banReason via SQL);
	 * this guard denies sign-in that would open a new session for a banned principal.
	 * Only boolean `banned` is a Clearance additionalField — string banReason is
	 * SQL-only so it never becomes a required signup input.
	 */
	const userAdditionalFields = {
		banned: {
			type: "boolean" as const,
			required: false,
			defaultValue: false,
			input: false,
		},
	};

	const underlyingAuth = clearance(
		attachInternalCredentialAuthority(
			{
		appName: "Clearance",
		baseURL: options.baseURL,
		secret: options.secret,
		database,
		durableDelivery,
		emailVerification: durableDelivery ? { sendOnSignUp: true } : undefined,
		emailAndPassword: {
			enabled: true,
			minPasswordLength: 12,
		},
		account: {
			encryptOAuthTokens: true,
		},
		user: {
			additionalFields: userAdditionalFields,
		},
		socialProviders:
			options.socialProviders as ClearanceOptions["socialProviders"],
		trustedOrigins: options.trustedOrigins ?? [options.baseURL],
		telemetry: { enabled: false },
		rateLimit,
		advanced: {
			cookiePrefix: "clearance",
		},
		// Durable management identity bridge + disable/delete sign-in guard.
		// Failures in onUserCreated must not be swallowed by the caller.
		databaseHookFailureMode: onUserCreated ? "rollback" : "observe",
		databaseHooks: {
			user: onUserCreated
				? {
						create: {
							after: async (user) => {
								await onUserCreated({
									id: user.id,
									email: user.email,
									name: user.name,
									createdAt: user.createdAt,
									updatedAt: user.updatedAt,
									emailVerified: Boolean(user.emailVerified),
									image: user.image,
								});
							},
						},
					}
				: undefined,
			session: {
				create: {
					before: async (session, ctx) => {
						if (!ctx) return;
						const user = await ctx.context.internalAdapter.findUserById(
							session.userId,
						);
						const banned = Boolean(
							(user as { banned?: boolean | null } | null)?.banned,
						);
						if (banned) {
							throw APIError.from("FORBIDDEN", {
								message: "User is disabled and cannot sign in",
								code: "USER_DISABLED",
							});
						}
					},
				},
			},
		},
		plugins,
			},
			{
				generation: credentialAuthorityGeneration,
			},
		),
	);
	const guardedApiFunctions = new Map<PropertyKey, unknown>();
	const guardedApi = new Proxy(underlyingAuth.api, {
		get(target, property, receiver) {
			const value = Reflect.get(target, property, receiver);
			if (typeof value !== "function") return value;
			if (guardedApiFunctions.has(property)) {
				return guardedApiFunctions.get(property);
			}
			const guarded = async (...args: unknown[]) => {
				await assertProductRuntimeServing();
				return Reflect.apply(value, target, args);
			};
			guardedApiFunctions.set(property, guarded);
			return guarded;
		},
	});
	const guardedHandler = async (...args: unknown[]) => {
		try {
			await assertProductRuntimeServing();
		} catch (error) {
			return new Response(
				JSON.stringify({
					code: "CREDENTIAL_AUTHORITY_FENCED",
					message:
						error instanceof Error
							? error.message
							: "Credential authority is unavailable",
				}),
				{
					status: 503,
					headers: { "content-type": "application/json; charset=utf-8" },
				},
			);
		}
		return Reflect.apply(underlyingAuth.handler, underlyingAuth, args);
	};
	const guardRuntimeMethods = <Target extends object>(target: Target): Target => {
		const guardedMethods = new Map<PropertyKey, unknown>();
		return new Proxy(target, {
			get(current, property, receiver) {
				const value = Reflect.get(current, property, receiver);
				if (typeof value !== "function") return value;
				if (guardedMethods.has(property)) return guardedMethods.get(property);
				const guarded = async (...args: unknown[]) => {
					await assertProductRuntimeServing();
					return Reflect.apply(value, current, args);
				};
				guardedMethods.set(property, guarded);
				return guarded;
			},
		});
	};
	const guardedContext = underlyingAuth.$context.then((context) => {
		const guardedAdapter = guardRuntimeMethods(context.adapter);
		const guardedInternalAdapter = guardRuntimeMethods(context.internalAdapter);
		return new Proxy(context, {
			get(current, property, receiver) {
				if (property === "adapter") return guardedAdapter;
				if (property === "internalAdapter") return guardedInternalAdapter;
				if (property === "runMigrations") {
					const runMigrations = Reflect.get(current, property, receiver);
					if (typeof runMigrations !== "function") return runMigrations;
					return async (...args: unknown[]) => {
						await assertProductRuntimeServing();
						return Reflect.apply(runMigrations, current, args);
					};
				}
				return Reflect.get(current, property, receiver);
			},
		});
	});
	const auth = new Proxy(underlyingAuth, {
		get(target, property, receiver) {
			if (property === "api") return guardedApi;
			if (property === "handler") return guardedHandler;
			if (property === "$context") return guardedContext;
			return Reflect.get(target, property, receiver);
		},
	});

	const migrationConfigFor = (
		migrationDatabase = database,
		migrationDrainId?: string,
	) =>
		attachInternalCredentialAuthority(
			{
		database: migrationDatabase,
		secret: options.secret,
		baseURL: options.baseURL,
		emailAndPassword: { enabled: true },
		user: { additionalFields: userAdditionalFields },
		rateLimit,
		plugins,
			},
			{
				generation: credentialAuthorityGeneration,
				...(migrationDrainId ? { migrationDrainId } : {}),
			},
		) as Parameters<typeof getMigrations>[0];

	async function planMigrationsFor(
		migrationDatabase = database,
		migrationDrainId?: string,
	): Promise<ClearanceRuntimeMigrationPlan> {
		const {
			toBeCreated,
			toBeAdded,
			pendingSecurityMigrations,
			runMigrations,
			compileMigrations,
		} =
			await getMigrations(
				migrationConfigFor(migrationDatabase, migrationDrainId),
			);
		return {
			pendingTables: toBeCreated.length,
			pendingFields: [...toBeCreated, ...toBeAdded].reduce(
				(total, migration) => total + Object.keys(migration.fields).length,
				0,
			),
			pendingSecurityMigrations,
			compileSql: compileMigrations,
			apply: runMigrations,
		};
	}

	async function inspectPreFenceCredentialSchema(): Promise<{
		fence: boolean;
		session: boolean;
		oauth: boolean;
	}> {
		const result = await pool.query<{
			fence: boolean;
			session: boolean;
			oauth: boolean;
		}>(`SELECT
			to_regclass(format('%I.%I', current_schema(), 'credentialAuthorityFence')) IS NOT NULL AS fence,
			to_regclass(format('%I.%I', current_schema(), 'session')) IS NOT NULL AS session,
			to_regclass(format('%I.%I', current_schema(), 'oauthAccessToken')) IS NOT NULL AS oauth`);
		return result.rows[0] ?? { fence: false, session: false, oauth: false };
	}

	async function ensureLegacyBridgeCompatibility(): Promise<void> {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(
				`SELECT pg_advisory_xact_lock(
					hashtext(current_database()),
					hashtext(current_schema() || ':clearance:legacy-bridge-prep:v1')
				)`,
			);
			await client.query(`
				ALTER TABLE "user" ADD COLUMN IF NOT EXISTS banned boolean DEFAULT false;
				ALTER TABLE "user" ADD COLUMN IF NOT EXISTS "banReason" text;
				ALTER TABLE "user" ADD COLUMN IF NOT EXISTS "twoFactorEnabled" boolean DEFAULT false;
				ALTER TABLE "user" ADD COLUMN IF NOT EXISTS "twoFactorSessionGeneration" text;
				ALTER TABLE session ADD COLUMN IF NOT EXISTS "twoFactorSessionGeneration" text;

				CREATE TABLE IF NOT EXISTS "twoFactor" (
					id text PRIMARY KEY,
					secret text NOT NULL,
					"backupCodes" text NOT NULL,
					"pendingSecret" text,
					"pendingBackupCodes" text,
					"userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
					verified boolean DEFAULT true,
					"failedVerificationCount" integer DEFAULT 0,
					"activeVerificationReservations" text DEFAULT '[]',
					"lockedUntil" timestamptz,
					"lastUsedTotpCounter" integer DEFAULT -1,
					"trustDeviceGeneration" text
				);
				ALTER TABLE "twoFactor" ADD COLUMN IF NOT EXISTS "pendingSecret" text;
				ALTER TABLE "twoFactor" ADD COLUMN IF NOT EXISTS "pendingBackupCodes" text;
				ALTER TABLE "twoFactor" ADD COLUMN IF NOT EXISTS verified boolean DEFAULT true;
				ALTER TABLE "twoFactor" ADD COLUMN IF NOT EXISTS "failedVerificationCount" integer DEFAULT 0;
				ALTER TABLE "twoFactor" ADD COLUMN IF NOT EXISTS "activeVerificationReservations" text DEFAULT '[]';
				ALTER TABLE "twoFactor" ADD COLUMN IF NOT EXISTS "lockedUntil" timestamptz;
				ALTER TABLE "twoFactor" ADD COLUMN IF NOT EXISTS "lastUsedTotpCounter" integer DEFAULT -1;
				ALTER TABLE "twoFactor" ADD COLUMN IF NOT EXISTS "trustDeviceGeneration" text;
				CREATE INDEX IF NOT EXISTS "twoFactor_secret_idx" ON "twoFactor" (secret);

				CREATE TABLE IF NOT EXISTS jwks (
					id text PRIMARY KEY,
					"publicKey" text NOT NULL,
					"privateKey" text NOT NULL,
					"createdAt" timestamptz NOT NULL,
					"expiresAt" timestamptz,
					alg text,
					crv text
				);
				ALTER TABLE jwks ADD COLUMN IF NOT EXISTS alg text;
				ALTER TABLE jwks ADD COLUMN IF NOT EXISTS crv text
			`);
			const duplicateFactor = await client.query<{ userId: string }>(`
				SELECT "userId" FROM "twoFactor"
				GROUP BY "userId" HAVING count(*) > 1 LIMIT 1
			`);
			if (duplicateFactor.rows[0]) {
				throw new Error(
					`Cannot prepare the credential bridge: duplicate two-factor records exist for user ${duplicateFactor.rows[0].userId}`,
				);
			}
			await client.query(
				`CREATE UNIQUE INDEX IF NOT EXISTS "twoFactor_userId_unique" ON "twoFactor" ("userId")`,
			);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			client.release();
		}
	}

	async function ensureLifecycleCompatibility(): Promise<void> {
		// Fail-closed column ensure for installs that predate lifecycle fields.
		await pool.query(
			`ALTER TABLE "user" ADD COLUMN IF NOT EXISTS banned boolean DEFAULT false`,
		);
		await pool.query(
			`ALTER TABLE "user" ADD COLUMN IF NOT EXISTS "banReason" text`,
		);
		if (options.enableSso !== false) {
			const providers = await pool.query<{
				id: string;
				oidcConfig: string | null;
			}>(
				`select id, "oidcConfig" from "ssoProvider" where "oidcConfig" is not null`,
			);
			for (const provider of providers.rows) {
				const config = JSON.parse(provider.oidcConfig ?? "null") as {
					clientSecret?: string;
				} | null;
				if (
					config?.clientSecret &&
					!config.clientSecret.startsWith("clr-sso:v1:")
				) {
					config.clientSecret = `clr-sso:v1:${await encryptRuntimeCredential(
						config.clientSecret,
						options.secret,
					)}`;
					await pool.query(
						`update "ssoProvider" set "oidcConfig" = $1 where id = $2`,
						[JSON.stringify(config), provider.id],
					);
				}
			}
		}
	}

	async function ensureAuthenticationSecurityCompatibility(): Promise<void> {
		if (authenticationSecurity.twoFactor.enabled) {
			const duplicates = await pool.query<{ userId: string }>(
				`SELECT "userId" FROM "twoFactor"
				 GROUP BY "userId" HAVING count(*) > 1 LIMIT 1`,
			);
			if (duplicates.rows[0]) {
				throw new Error(
					`Cannot enforce one two-factor record per user: duplicate records exist for user ${duplicates.rows[0].userId}`,
				);
			}
			const uniqueUserIndex = await pool.query(
				`SELECT 1 FROM pg_indexes
				 WHERE schemaname=current_schema() AND tablename='twoFactor'
				   AND indexdef ILIKE '%UNIQUE%'
				   AND indexdef ILIKE '%("userId")%' LIMIT 1`,
			);
			if (uniqueUserIndex.rowCount === 0) {
				await pool.query(
					`CREATE UNIQUE INDEX "twoFactor_userId_unique"
					 ON "twoFactor" ("userId")`,
				);
			}
			await pool.query(
				`UPDATE "twoFactor" SET "failedVerificationCount" = 0
				 WHERE "failedVerificationCount" IS NULL`,
			);
			await pool.query(
				`UPDATE "twoFactor" SET "activeVerificationReservations" = '[]'
				 WHERE "activeVerificationReservations" IS NULL`,
			);
			const recoveryRows = await pool.query<{
				id: string;
				backupCodes: string;
				pendingBackupCodes: string | null;
				trustDeviceGeneration: string | null;
			}>(
				`SELECT id, "backupCodes", "pendingBackupCodes", "trustDeviceGeneration"
				 FROM "twoFactor"`,
			);
			for (const row of recoveryRows.rows) {
				const backupCodes = await migrateRecoveryCodesToHashes(
					row.backupCodes,
					options.secret,
				);
				const pendingBackupCodes = row.pendingBackupCodes
					? await migrateRecoveryCodesToHashes(
							row.pendingBackupCodes,
							options.secret,
						)
					: null;
				const trustDeviceGeneration = row.trustDeviceGeneration ?? randomUUID();
				if (
					backupCodes !== row.backupCodes ||
					pendingBackupCodes !== row.pendingBackupCodes ||
					trustDeviceGeneration !== row.trustDeviceGeneration
				) {
					const migrated = await pool.query(
						`UPDATE "twoFactor"
						 SET "backupCodes"=$2, "pendingBackupCodes"=$3,
						     "trustDeviceGeneration"=$4
						 WHERE id=$1 AND "backupCodes"=$5
						   AND "pendingBackupCodes" IS NOT DISTINCT FROM $6
						   AND "trustDeviceGeneration" IS NOT DISTINCT FROM $7`,
						[
							row.id,
							backupCodes,
							pendingBackupCodes,
							trustDeviceGeneration,
							row.backupCodes,
							row.pendingBackupCodes,
							row.trustDeviceGeneration,
						],
					);
					if (migrated.rowCount !== 1) {
						throw new Error(
							"Two-factor recovery state changed during migration; retry migration",
						);
					}
				}
			}
			await pool.query(
				`WITH missing_users AS MATERIALIZED (
					SELECT id, gen_random_uuid()::text AS generation
					FROM "user"
					WHERE "twoFactorSessionGeneration" IS NULL
				), updated_users AS (
					UPDATE "user" AS target
					SET "twoFactorSessionGeneration" = missing_users.generation
					FROM missing_users
					WHERE target.id = missing_users.id
					  AND target."twoFactorSessionGeneration" IS NULL
					RETURNING target.id, target."twoFactorSessionGeneration" AS generation
				)
				UPDATE "session" AS session
				SET "twoFactorSessionGeneration" =
					COALESCE(updated_users.generation, owner."twoFactorSessionGeneration")
				FROM "user" AS owner
				LEFT JOIN updated_users ON updated_users.id = owner.id
				WHERE session."userId" = owner.id
				  AND session."twoFactorSessionGeneration" IS NULL
				  AND COALESCE(
					updated_users.generation,
					owner."twoFactorSessionGeneration"
				  ) IS NOT NULL`,
			);
		}
		if (!authenticationSecurity.asymmetricAccessTokens.enabled) return;
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(
				`SELECT pg_advisory_xact_lock(
					hashtext(current_database()),
					hashtext(current_schema() || ':clearance:jwks-rotation')
				)`,
			);
			const rows = await client.query<{
				id: string;
				publicKey: string;
				expiresAt: Date | null;
				alg: string | null;
				crv: string | null;
			}>(`SELECT id, "publicKey", "expiresAt", alg, crv FROM jwks FOR UPDATE`);
			const now = new Date();
			const retiredBefore = new Date(
				now.getTime() -
					(authenticationSecurity.asymmetricAccessTokens.gracePeriodSeconds +
						1) *
						1000,
			);
			for (const row of rows.rows) {
				const inferred = inferJwkMetadata(row.publicKey);
				const alg =
					inferred?.alg ?? (isSupportedJwkAlgorithm(row.alg) ? row.alg : null);
				const crv =
					inferred?.crv ?? (isSupportedJwkCurve(row.crv) ? row.crv : null);
				const metadataKnown =
					alg !== null && isCompatiblePublicJwk(row.publicKey, alg);
				const persistedAlg = metadataKnown ? alg : null;
				const persistedCrv = metadataKnown ? crv : null;
				const isEd25519SigningKey =
					metadataKnown && alg === "EdDSA" && crv === "Ed25519";
				const retirementCeiling = metadataKnown ? now : retiredBefore;
				const expiresAt =
					isEd25519SigningKey && row.expiresAt !== null
						? row.expiresAt
						: row.expiresAt !== null && row.expiresAt < retirementCeiling
							? row.expiresAt
							: retirementCeiling;
				if (
					row.alg !== persistedAlg ||
					row.crv !== persistedCrv ||
					row.expiresAt?.getTime() !== expiresAt.getTime()
				) {
					await client.query(
						`UPDATE jwks SET alg=$2, crv=$3, "expiresAt"=$4 WHERE id=$1`,
						[row.id, persistedAlg, persistedCrv, expiresAt],
					);
				}
			}
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK").catch(() => {});
			throw error;
		} finally {
			client.release();
		}
	}
	const credentialAuthorityFacade = Object.freeze({
		status: () => credentialAuthority.status(),
		arm: (input: { deploymentId: string; expectedRuntimeCount: number }) =>
			credentialAuthority.arm(input),
		beginDrain: (input: { deploymentId: string; drainId: string }) =>
			credentialAuthority.beginDrain(input),
		assertRuntimeServing: () => assertProductRuntimeServing(),
	});

	return {
		auth: auth as unknown as ClearanceProductAuthRuntime<Security, Passkeys>,
		pool,
		db,
		credentialAuthority: credentialAuthorityFacade,
		plugins: {
			organization: true,
			sso: options.enableSso !== false,
			scim: options.enableScim !== false,
			twoFactor: authenticationSecurity.twoFactor.enabled,
			breachedPassword: authenticationSecurity.breachedPassword.enabled,
			asymmetricAccessTokens:
				authenticationSecurity.asymmetricAccessTokens.enabled,
			passkeys: options.passkeys !== false,
		},
		rateLimitEnabled,
		prepareCredentialAuthorityRuntime: assertProductRuntimeServing,
		planMigrations: () => planMigrationsFor(),
		async migrate(input) {
			const preFenceSchema = await inspectPreFenceCredentialSchema();
			await bootstrapCredentialAuthorityFence(pool);
			const plan = await planMigrationsFor();
			const apply = async () => {
				await plan.apply();
				await ensureAuthenticationSecurityCompatibility();
				await ensureLifecycleCompatibility();
				if (options.durableDelivery) {
					await migrateDeliverySchema(pool, {
						schema: options.durableDelivery.schema,
						prefix: options.durableDelivery.prefix,
						legacyFingerprintKeyId:
							options.durableDelivery.legacyFingerprintKeyId,
					});
				}
			};
			const state = await credentialAuthority.status();
			if (
				state.phase === "digest-live" &&
				plan.pendingSecurityMigrations.length > 0
			) {
				throw new Error(
					`Credential authority markers conflict with the durable digest-live generation: ${plan.pendingSecurityMigrations.join(", ")}`,
				);
			}
			if (state.phase !== "digest-live") {
				const freshDatabase =
					!preFenceSchema.fence &&
					!preFenceSchema.session &&
					!preFenceSchema.oauth;
				// Development/test databases may already contain a fully migrated
				// digest schema from a pre-fence candidate. Production must still arm
				// and drain that deployment before publishing the durable generation.
				const localFenceAdoption = !strict && !preFenceSchema.fence;
				const allowUnarmedLegacyOpen = freshDatabase || localFenceAdoption;
				const drainId =
					input?.drainId ??
					options.credentialAuthority?.migrationDrainId ??
					(allowUnarmedLegacyOpen
						? state.drainId ?? `bootstrap-${randomUUID()}`
						: undefined);
				if (!drainId) {
					throw new Error(
						"Existing credential authority requires an armed drain and credentialAuthority.migrationDrainId",
					);
				}
				await credentialAuthority.withExclusiveMigrationLease({
					drainId,
					allowUnarmedLegacyOpen,
					timeoutMs:
						options.credentialAuthority?.migrationLeaseTimeoutMs,
					run: async (leaseClient) => {
						const leaseDatabase = {
							db: createLeaseBoundMigrationDatabase(leaseClient),
							type: "postgres" as const,
							transaction: true as const,
						};
						try {
							const leasePlan = await planMigrationsFor(
								leaseDatabase,
								drainId,
							);
							await leasePlan.apply();
							await ensureAuthenticationSecurityCompatibility();
							await ensureLifecycleCompatibility();
							if (options.durableDelivery) {
								await migrateDeliverySchema(pool, {
									schema: options.durableDelivery.schema,
									prefix: options.durableDelivery.prefix,
									legacyFingerprintKeyId:
										options.durableDelivery.legacyFingerprintKeyId,
								});
							}
						} finally {
							await leaseDatabase.db.destroy();
						}
					},
				});
			} else {
				await apply();
			}
			return {
				appliedTables: plan.pendingTables,
				appliedFields: plan.pendingFields,
			};
		},
		async destroy() {
			await credentialAuthority.close();
			await pool.end();
		},
	};
}
