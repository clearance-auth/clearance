import { clearance, APIError, type ClearanceOptions } from "@clearance/runtime";
import {
	createDeliveryKeyring,
	enqueueDeliveryInExistingTransaction,
	migrateDeliverySchema,
} from "@clearance/delivery";
import { symmetricDecrypt, symmetricEncrypt } from "@clearance/runtime/crypto";
import { organization } from "@clearance/runtime/plugins";
import { getMigrations } from "@clearance/runtime/db/migration";
import { sso } from "@clearance/sso";
import { scim } from "@clearance/scim";
import { Kysely, PostgresDialect } from "kysely";
import pg from "pg";
import {
	MINIMUM_SECRET_LENGTH,
	isForbiddenDefaultSecret,
} from "./secret-policy.js";
import type {
	ClearanceAuthBundle,
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
	SocialProviderConfig,
} from "./public-types/index.js";

export function socialProvidersFromEnvironment(
	env: Record<string, string | undefined> = process.env,
): Record<string, SocialProviderConfig> {
	const providers: Record<string, SocialProviderConfig> = {};
	if (Boolean(env.CLEARANCE_GITHUB_CLIENT_ID) !== Boolean(env.CLEARANCE_GITHUB_CLIENT_SECRET)) {
		throw new Error(
			"GitHub social login requires both CLEARANCE_GITHUB_CLIENT_ID and CLEARANCE_GITHUB_CLIENT_SECRET",
		);
	}
	if (Boolean(env.CLEARANCE_GOOGLE_CLIENT_ID) !== Boolean(env.CLEARANCE_GOOGLE_CLIENT_SECRET)) {
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
export function createClearanceAuth(
	options: CreateClearanceAuthOptions,
): ClearanceAuthBundle {
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

	const pool = new pg.Pool({ connectionString: options.databaseUrl });
	const db = new Kysely({
		dialect: new PostgresDialect({ pool }),
	});
	const deliveryKeyring = options.durableDelivery
		? createDeliveryKeyring(options.durableDelivery.keyring)
		: null;
	const durableDelivery = options.durableDelivery && deliveryKeyring
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
						rawTransactionQuery?: <Row extends Record<string, unknown> = Record<string, unknown>>(
							text: string,
							values?: readonly unknown[],
						) => Promise<{ rows: Row[]; rowCount: number | null }>;
					},
					input: Omit<Parameters<typeof enqueueDeliveryInExistingTransaction>[1], "projectId" | "environmentId">,
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
		...(durableDelivery ? { transaction: true as const } : {}),
	};

	const plugins = [
		organization(),
		...(options.enableSso !== false
			? [
					sso({
						saml: {
							enableInResponseToValidation: true,
							allowIdpInitiated: false,
							requireTimestamps: true,
						},
						storeOIDCClientSecret: {
							encrypt: (secret) => encryptRuntimeCredential(secret, options.secret),
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

	const auth = clearance({
		appName: "Clearance",
		baseURL: options.baseURL,
		secret: options.secret,
		database,
		durableDelivery,
		emailVerification: durableDelivery
			? { sendOnSignUp: true }
			: undefined,
		emailAndPassword: {
			enabled: true,
			minPasswordLength: 12,
		},
		user: {
			additionalFields: userAdditionalFields,
		},
		socialProviders: options.socialProviders as ClearanceOptions["socialProviders"],
		trustedOrigins: options.trustedOrigins ?? [options.baseURL],
		telemetry: { enabled: false },
		rateLimit,
		advanced: {
			cookiePrefix: "clearance",
		},
		// Durable management identity bridge + disable/delete sign-in guard.
		// Failures in onUserCreated must not be swallowed by the caller.
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
	});

	const migrationConfig = {
		database,
		secret: options.secret,
		baseURL: options.baseURL,
		emailAndPassword: { enabled: true },
		user: { additionalFields: userAdditionalFields },
		rateLimit,
		plugins,
	} as Parameters<typeof getMigrations>[0];

	async function planMigrations(): Promise<ClearanceRuntimeMigrationPlan> {
		const { toBeCreated, toBeAdded, runMigrations, compileMigrations } =
			await getMigrations(migrationConfig);
		return {
			pendingTables: toBeCreated.length,
			pendingFields: [...toBeCreated, ...toBeAdded].reduce(
				(total, migration) => total + Object.keys(migration.fields).length,
				0,
			),
			compileSql: compileMigrations,
			apply: runMigrations,
		};
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
			}>(`select id, "oidcConfig" from "ssoProvider" where "oidcConfig" is not null`);
			for (const provider of providers.rows) {
				const config = JSON.parse(provider.oidcConfig ?? "null") as
					| { clientSecret?: string }
					| null;
				if (config?.clientSecret && !config.clientSecret.startsWith("clr-sso:v1:")) {
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

	return {
		auth,
		pool,
		db,
		plugins: {
			organization: true,
			sso: options.enableSso !== false,
			scim: options.enableScim !== false,
		},
		rateLimitEnabled,
		planMigrations,
		async migrate() {
			const plan = await planMigrations();
			await plan.apply();
			await ensureLifecycleCompatibility();
			if (options.durableDelivery) {
				await migrateDeliverySchema(pool, {
					schema: options.durableDelivery.schema,
					prefix: options.durableDelivery.prefix,
				});
			}
			return {
				appliedTables: plan.pendingTables,
				appliedFields: plan.pendingFields,
			};
		},
		async destroy() {
			await pool.end();
		},
	};
}
