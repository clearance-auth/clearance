import {
	createECDH,
	createHash,
	createPrivateKey,
	hkdfSync,
	randomUUID,
} from "node:crypto";
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
	createKeyProviderRegistry,
	createLocalKeyProvider,
	createLocalSigningProvider,
	parseKeyEnvelope,
	signJwtPayload,
	type KeyProviderRegistry,
	type KeyPurpose,
	type KeySigningProvider,
} from "@clearance/key-management";
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
import { attachInternalAuthenticationPolicy } from "../../runtime/src/internal/authentication-policy.js";
import { attachInternalAuthorizationAuthority } from "../../runtime/src/internal/authorization-authority.js";
import { attachInternalManagedOrganizationLifecycleAuthority } from "../../runtime/src/internal/organization-lifecycle-authority.js";
import { queueAfterTransactionHook } from "../../core/src/context/index.js";
import { attachInternalCredentialAuthority } from "../../runtime/src/internal/credential-authority.js";
import { attachCapturedInternalRuntimeAudit } from "@clearance/runtime/internal/runtime-audit";
import { createInternalVerificationChallengeAuthority } from "../../runtime/src/internal/verification-challenge-context.js";
import { attachSSOInternalVerificationChallengeAuthority } from "../../sso/src/internal/verification-challenge-authority.js";
import { attachSSOKeyManagementWriter } from "../../sso/src/internal/key-management-writer.js";
import { attachSCIMKeyManagementWriter } from "../../scim/src/internal/key-management-writer.js";
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
import { PostgresAuthenticationPolicyAuthority } from "./authentication-policy-authority.js";
import { PostgresAuthorizationAuthority } from "./authorization-authority.js";
import { createRuntimeAuditOutbox } from "./runtime-audit.js";
import { createTenantAdministrationPlugin } from "./tenant-administration.js";
import type {
	ClearanceAuthBundle,
	ClearanceAuthorizationFacade,
	ClearanceAuthorizationAffectedRevision,
	ClearanceAuthorizationAssignment,
	ClearanceAuthorizationReadResult,
	ClearanceAuthorizationRole,
	ClearanceAuthorizationServiceAccount,
	ClearanceAuthorizationServiceAccountAuthentication,
	ClearanceAuthorizationServiceAccountCredential,
	ClearanceAuthorizationServiceAccountCredentialMutation,
	ClearanceAuthorizationServiceAccountMutation,
	ClearanceAuthorizationSubject,
	ClearanceAuthenticationAssuranceLevel,
	ClearanceAuthenticationPolicy,
	ClearanceAuthenticationPolicyApplyResult,
	ClearanceAuthenticationPolicyCandidateInput,
	ClearanceAuthenticationPolicyFacade,
	ClearanceAuthenticationPolicyGetResult,
	ClearanceAuthenticationPolicyOverride,
	ClearanceAuthenticationPolicyPlanResult,
	ClearanceAuthenticationPolicyTransaction,
	ClearanceKeyManagementFacade,
	ClearanceKeyManagementMigrationCounts,
	ClearanceKeyManagementMigrationPlan,
	ClearanceKeyManagementMigrationResult,
	ClearanceKeyManagementStatus,
	ClearanceTransactionQuery,
	ClearanceAuthenticationSecurityOptions,
	ClearanceAuthenticationUnlockAuthorityCounts,
	ClearanceAuthenticationUnlockKind,
	ClearanceAuthenticationUnlockPreview,
	ClearanceAuthenticationUnlockResult,
	ClearancePasskeyOptions,
	ClearanceProductAuthRuntime,
	ClearanceRuntimeMigrationPlan,
	ClearanceRuntimeMigrationResult,
	ClearanceRuntimeUser,
	CreateClearanceAuthOptions,
	SocialProviderConfig,
	TenantProductAdministrationFacade,
	TenantProductAuditEvent,
	TenantProductReadiness,
	TenantProductScimConnection,
	TenantProductSsoConnection,
} from "./public-types/index.js";

export const CLEARANCE_AUTH_VERSION = "0.3.0";
export const RUNTIME_BASELINE = {
	package: "@clearance/runtime",
	version: "1.6.23",
} as const;

const DEVELOPMENT_KEY_MANAGEMENT_SALT = Buffer.from(
	"clearance-development-key-management-v1",
	"utf8",
);
const SCIM_TOKEN_ENVELOPE_PREFIX = "clr-scim:v1:";
const RETIRED_JWK_PRIVATE_KEY = "clr-jwk:retired:v1";
const KEY_MANAGEMENT_MIGRATION_BATCH_SIZE = 5;
const ONE_TIME_SECRET_REPLAY_PURPOSE = "service-account-credential-replay" as const;
const MAX_ONE_TIME_SECRET_REPLAY_PLAINTEXT_BYTES = 16_384;
type KeyManagementMigrationDomain = "oidcClientSecrets" | "scimTokens" | "jwks";
type MigrationSnapshot = Readonly<{
	id: string;
	version: number | null;
	revision: number | null;
	sourceHash: string;
}>;
type KeyManagementMigrationBatch = Readonly<{
	oidcClientSecrets: readonly MigrationSnapshot[];
	scimTokens: readonly MigrationSnapshot[];
	jwks: readonly MigrationSnapshot[];
}>;
type KeyManagementQuery = Pick<ClearanceTransactionQuery, "rawTransactionQuery">;
type KeyManagementTriggerDefinition = Readonly<{
	table: '"ssoProvider"' | '"scimProvider"' | "jwks";
	column: '"oidcConfig"' | '"scimToken"' | '"privateKey"';
	triggerName: string;
	functionName: string;
	body: string;
}>;
const OIDC_KEY_MANAGEMENT_TRIGGER_BODY = `
DECLARE client_secret text; DECLARE migration_bypass boolean;
BEGIN
	IF NEW."oidcConfig" IS NULL THEN RETURN NEW; END IF;
	migration_bypass := current_setting('clearance.key_management_migration', true) = 'v1';
	BEGIN client_secret := (NEW."oidcConfig"::jsonb)->>'clientSecret';
	EXCEPTION WHEN others THEN
		RAISE EXCEPTION 'OIDC configuration must be valid managed JSON' USING ERRCODE = '23514';
	END;
	IF client_secret IS NOT NULL AND client_secret <> '' AND
		left(client_secret, length('clr-sso:v1:clrkm$v1$')) <> 'clr-sso:v1:clrkm$v1$' THEN
		RAISE EXCEPTION 'OIDC client secret must use purpose-separated storage' USING ERRCODE = '23514';
	END IF;
	IF migration_bypass THEN RETURN NEW; END IF;
	IF TG_OP = 'INSERT' OR OLD."oidcConfig" IS NULL THEN
		IF NEW."keyManagementVersion" IS DISTINCT FROM 1 OR NEW."keyManagementRevision" IS DISTINCT FROM 1 THEN
			RAISE EXCEPTION 'OIDC key generation is invalid' USING ERRCODE = '23514';
		END IF;
	ELSIF NEW."oidcConfig" IS DISTINCT FROM OLD."oidcConfig" AND (
		OLD."keyManagementVersion" IS DISTINCT FROM 1 OR NEW."keyManagementVersion" IS DISTINCT FROM 1 OR
		OLD."keyManagementRevision" IS NULL OR NEW."keyManagementRevision" IS DISTINCT FROM OLD."keyManagementRevision" + 1
	) THEN RAISE EXCEPTION 'OIDC key revision did not advance' USING ERRCODE = '23514';
	END IF;
	RETURN NEW;
END`.trim();
const SCIM_KEY_MANAGEMENT_TRIGGER_BODY = `
DECLARE migration_bypass boolean;
BEGIN
	migration_bypass := current_setting('clearance.key_management_migration', true) = 'v1';
	IF left(NEW."scimToken", length('clr-scim:v1:clrkm$v1$')) <> 'clr-scim:v1:clrkm$v1$' THEN
		RAISE EXCEPTION 'SCIM token must use purpose-separated storage' USING ERRCODE = '23514';
	END IF;
	IF migration_bypass THEN RETURN NEW; END IF;
	IF TG_OP = 'INSERT' THEN
		IF NEW."keyManagementVersion" IS DISTINCT FROM 1 OR NEW."keyManagementRevision" IS DISTINCT FROM 1 THEN
			RAISE EXCEPTION 'SCIM key generation is invalid' USING ERRCODE = '23514';
		END IF;
	ELSIF NEW."scimToken" IS DISTINCT FROM OLD."scimToken" AND (
		OLD."keyManagementVersion" IS DISTINCT FROM 1 OR NEW."keyManagementVersion" IS DISTINCT FROM 1 OR
		OLD."keyManagementRevision" IS NULL OR NEW."keyManagementRevision" IS DISTINCT FROM OLD."keyManagementRevision" + 1
	) THEN RAISE EXCEPTION 'SCIM key revision did not advance' USING ERRCODE = '23514';
	END IF;
	RETURN NEW;
END`.trim();
const JWKS_KEY_MANAGEMENT_TRIGGER_BODY = `
DECLARE migration_bypass boolean;
BEGIN
	migration_bypass := current_setting('clearance.key_management_migration', true) = 'v1';
	IF NEW."privateKey" <> 'clr-jwk:retired:v1' AND left(NEW."privateKey", length('clrkm$v1$')) <> 'clrkm$v1$' THEN
		RAISE EXCEPTION 'JWT private key must use purpose-separated storage' USING ERRCODE = '23514';
	END IF;
	IF migration_bypass THEN RETURN NEW; END IF;
	IF TG_OP = 'INSERT' THEN
		IF NEW."keyManagementVersion" IS DISTINCT FROM 1 OR NEW."keyManagementRevision" IS DISTINCT FROM 1 THEN
			RAISE EXCEPTION 'JWT key generation is invalid' USING ERRCODE = '23514';
		END IF;
	ELSIF NEW."privateKey" IS DISTINCT FROM OLD."privateKey" AND (
		OLD."keyManagementVersion" IS DISTINCT FROM 1 OR NEW."keyManagementVersion" IS DISTINCT FROM 1 OR
		OLD."keyManagementRevision" IS NULL OR NEW."keyManagementRevision" IS DISTINCT FROM OLD."keyManagementRevision" + 1
	) THEN RAISE EXCEPTION 'JWT key revision did not advance' USING ERRCODE = '23514';
	END IF;
	RETURN NEW;
END`.trim();
const KEY_MANAGEMENT_TRIGGER_DEFINITIONS: readonly KeyManagementTriggerDefinition[] = [
	{ table: '"ssoProvider"', column: '"oidcConfig"', triggerName: "clearance_require_oidc_key_v1", functionName: "clearance_require_oidc_key_v1", body: OIDC_KEY_MANAGEMENT_TRIGGER_BODY },
	{ table: '"scimProvider"', column: '"scimToken"', triggerName: "clearance_require_scim_key_v1", functionName: "clearance_require_scim_key_v1", body: SCIM_KEY_MANAGEMENT_TRIGGER_BODY },
	{ table: "jwks", column: '"privateKey"', triggerName: "clearance_require_jwt_key_v1", functionName: "clearance_require_jwt_key_v1", body: JWKS_KEY_MANAGEMENT_TRIGGER_BODY },
] as const;
const P256_ORDER = BigInt(
	"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);

function credentialResourceId(
	purpose: KeyPurpose,
	identity: Readonly<Record<string, string | null>>,
): string {
	const canonicalIdentity = JSON.stringify(
		Object.fromEntries(
			Object.entries(identity).sort(([left], [right]) =>
				left.localeCompare(right),
			),
		),
	);
	return `${purpose}:${createHash("sha256").update(canonicalIdentity).digest("hex")}`;
}

function canonicalOneTimeSecretReplayResourceId(
	binding: string,
	scope: Readonly<{ projectId: string; environmentId: string }>,
): string {
	if (
		typeof binding !== "string" ||
		Buffer.byteLength(binding, "utf8") === 0 ||
		Buffer.byteLength(binding, "utf8") > 4_096
	) {
		throw new Error("One-time secret replay binding is invalid");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(binding);
	} catch {
		throw new Error("One-time secret replay binding is invalid");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error("One-time secret replay binding is invalid");
	}
	const candidate = parsed as Record<string, unknown>;
	const keys = [
		"actorId",
		"environmentId",
		"operationId",
		"operationKind",
		"organizationId",
		"projectId",
		"serviceAccountId",
	];
	const canonicalBinding = JSON.stringify({
		projectId: candidate.projectId,
		environmentId: candidate.environmentId,
		organizationId: candidate.organizationId,
		actorId: candidate.actorId,
		serviceAccountId: candidate.serviceAccountId,
		operationId: candidate.operationId,
		operationKind: candidate.operationKind,
	});
	if (
		Object.keys(candidate).sort().join("\u0000") !== keys.join("\u0000") ||
		canonicalBinding !== binding ||
		candidate.projectId !== scope.projectId ||
		candidate.environmentId !== scope.environmentId ||
		candidate.operationKind !== "service_account_credential.create" &&
			candidate.operationKind !== "service_account_credential.rotate" ||
		["organizationId", "actorId", "serviceAccountId", "operationId"].some(
			(key) =>
				typeof candidate[key] !== "string" ||
				candidate[key].length === 0 ||
				candidate[key].length > 255 ||
				candidate[key].trim() !== candidate[key] ||
				candidate[key].includes("\0"),
		)
	) {
		throw new Error("One-time secret replay binding is invalid");
	}
	return credentialResourceId(ONE_TIME_SECRET_REPLAY_PURPOSE, { binding });
}

function canonicalOneTimeSecretReplayPlaintext(plaintext: string): Buffer {
	if (typeof plaintext !== "string") {
		throw new Error("One-time secret replay plaintext is invalid");
	}
	const bytes = Buffer.from(plaintext, "utf8");
	if (bytes.length === 0 || bytes.length > MAX_ONE_TIME_SECRET_REPLAY_PLAINTEXT_BYTES) {
		throw new Error("One-time secret replay plaintext is invalid");
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(plaintext);
	} catch {
		throw new Error("One-time secret replay plaintext is invalid");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || JSON.stringify(parsed) !== plaintext) {
		throw new Error("One-time secret replay plaintext is invalid");
	}
	return bytes;
}

function developmentKeyManagementRegistry(secret: string): KeyProviderRegistry {
	const purposes = [
		"oidc-client-secret",
		"scim-bearer-token",
		ONE_TIME_SECRET_REPLAY_PURPOSE,
		"access-token-signing-key",
	] as const satisfies readonly KeyPurpose[];
	return createKeyProviderRegistry(
		Object.fromEntries(
			purposes.map((purpose) => [
				purpose,
				createLocalKeyProvider({
					providerId: `development-${purpose}`,
					purpose,
					currentKeyId: "development-v1",
					keys: {
						"development-v1": Buffer.from(
							hkdfSync(
								"sha256",
								Buffer.from(secret, "utf8"),
								DEVELOPMENT_KEY_MANAGEMENT_SALT,
								Buffer.from(purpose, "utf8"),
								32,
							),
						),
					},
				}),
			]),
		) as Record<KeyPurpose, ReturnType<typeof createLocalKeyProvider>>,
	);
}

function developmentSigningProvider(secret: string): KeySigningProvider {
	const derived = Buffer.from(
		hkdfSync(
			"sha256",
			Buffer.from(secret, "utf8"),
			DEVELOPMENT_KEY_MANAGEMENT_SALT,
			Buffer.from("access-token-remote-signing-key", "utf8"),
			32,
		),
	);
	const scalar = (BigInt(`0x${derived.toString("hex")}`) % (P256_ORDER - 1n)) + 1n;
	const privateCoordinate = Buffer.from(
		scalar.toString(16).padStart(64, "0"),
		"hex",
	);
	const ecdh = createECDH("prime256v1");
	ecdh.setPrivateKey(privateCoordinate);
	const publicPoint = ecdh.getPublicKey(undefined, "uncompressed");
	const privateKey = createPrivateKey({
		key: {
			kty: "EC",
			crv: "P-256",
			x: publicPoint.subarray(1, 33).toString("base64url"),
			y: publicPoint.subarray(33, 65).toString("base64url"),
			d: privateCoordinate.toString("base64url"),
		},
		format: "jwk",
	});
	return createLocalSigningProvider({
		providerId: "development-access-token-signer",
		currentKeyReference: "development-v1",
		keys: {
			"development-v1": privateKey.export({ format: "der", type: "pkcs8" }),
		},
	});
}

function resolveProductKeyManagement<
	Security extends ClearanceAuthenticationSecurityOptions | undefined,
	Passkeys extends ClearancePasskeyOptions | false | undefined,
>(
	options: CreateClearanceAuthOptions<Security, Passkeys>,
	strict: boolean,
): Readonly<{
	projectId: string;
	environmentId: string;
	registry: KeyProviderRegistry;
	signingProvider: KeySigningProvider;
}> {
	const explicit = options.keyManagement;
	if (strict && !explicit) {
		throw new Error(
			"Production requires explicit purpose-separated keyManagement providers",
		);
	}
	if (strict && !explicit?.signingProvider) {
		throw new Error(
			"Production requires an explicit keyManagement signingProvider",
		);
	}
	const inferredScope =
		options.authenticationPolicy ?? options.durableDelivery ?? options.authorization;
	const projectId = explicit?.projectId ?? inferredScope?.projectId ?? "development";
	const environmentId =
		explicit?.environmentId ?? inferredScope?.environmentId ?? "development";
	if (!projectId.trim() || !environmentId.trim()) {
		throw new Error("keyManagement projectId and environmentId are required");
	}
	for (const scoped of [
		options.authenticationPolicy,
		options.durableDelivery,
		options.authorization,
	]) {
		if (
			scoped &&
			(scoped.projectId !== projectId || scoped.environmentId !== environmentId)
		) {
			throw new Error(
				"keyManagement scope must match every managed product scope",
			);
		}
	}
	const registry = explicit?.registry ?? developmentKeyManagementRegistry(options.secret);
	if (
		!registry ||
		typeof registry.providerFor !== "function" ||
		typeof registry.readiness !== "function"
	) {
		throw new Error("keyManagement registry is invalid");
	}
	const signingProvider =
		explicit?.signingProvider ?? developmentSigningProvider(options.secret);
	if (
		!signingProvider ||
		signingProvider.purpose !== "access-token-signing-key" ||
		signingProvider.algorithm !== "ES256" ||
		typeof signingProvider.sign !== "function" ||
		typeof signingProvider.publicKeys !== "function" ||
		typeof signingProvider.readiness !== "function"
	) {
		throw new Error("keyManagement signingProvider is invalid");
	}
	return Object.freeze({
		projectId,
		environmentId,
		registry,
		signingProvider,
	});
}

function resolveRuntimeAuditScope<
	Security extends ClearanceAuthenticationSecurityOptions | undefined,
	Passkeys extends ClearancePasskeyOptions | false | undefined,
>(
	options: CreateClearanceAuthOptions<Security, Passkeys>,
	strict: boolean,
):
	| Readonly<{ projectId: string; environmentId: string; schema?: string; prefix?: string }>
	| undefined {
	if (options.runtimeAudit === false) return undefined;
	const explicit = options.runtimeAudit;
	const scopes = [
		options.authenticationPolicy,
		options.keyManagement,
		options.durableDelivery,
		options.authorization,
	].filter((scope): scope is { projectId: string; environmentId: string } => Boolean(scope));
	if (explicit) scopes.push(explicit);
	if (scopes.length === 0) return undefined;
	const [first] = scopes;
	if (!first || scopes.some((scope) =>
		scope.projectId !== first.projectId || scope.environmentId !== first.environmentId,
	)) {
		throw new Error("runtimeAudit scope must match every managed product scope");
	}
	if (strict && !first.projectId.trim()) {
		throw new Error("runtimeAudit requires one unambiguous managed product scope");
	}
	return Object.freeze({
		projectId: first.projectId,
		environmentId: first.environmentId,
		...(explicit?.schema === undefined ? {} : { schema: explicit.schema }),
		...(explicit?.prefix === undefined ? {} : { prefix: explicit.prefix }),
	});
}

export type {
	ClearanceAuthBundle,
	ClearanceAuthorizationFacade,
	ClearanceAuthorizationAffectedRevision,
	ClearanceAuthorizationAssignment,
	ClearanceAuthorizationReadResult,
	ClearanceAuthorizationRole,
	ClearanceAuthorizationServiceAccount,
	ClearanceAuthorizationServiceAccountAuthentication,
	ClearanceAuthorizationServiceAccountCredential,
	ClearanceAuthorizationServiceAccountCredentialMutation,
	ClearanceAuthorizationServiceAccountMutation,
	ClearanceAuthorizationSubject,
	ClearanceAuthenticationAssuranceLevel,
	ClearanceAuthenticationPolicy,
	ClearanceAuthenticationPolicyApplyResult,
	ClearanceAuthenticationPolicyCandidateInput,
	ClearanceAuthenticationPolicyFacade,
	ClearanceAuthenticationPolicyGetResult,
	ClearanceAuthenticationPolicyOverride,
	ClearanceAuthenticationPolicyPlanResult,
	ClearanceAuthenticationPolicyTransaction,
	ClearanceKeyManagementFacade,
	ClearanceKeyManagementMigrationCounts,
	ClearanceKeyManagementMigrationPlan,
	ClearanceKeyManagementMigrationResult,
	ClearanceKeyManagementStatus,
	ClearanceTransactionQuery,
	ClearanceRuntimeMigrationPlan,
	ClearanceRuntimeMigrationResult,
	ClearanceRuntimeUser,
	CreateClearanceAuthOptions,
	ClearanceAuthenticationSecurityOptions,
	ClearanceAuthenticationUnlockAuthorityCounts,
	ClearanceAuthenticationUnlockKind,
	ClearanceAuthenticationUnlockPreview,
	ClearanceAuthenticationUnlockResult,
	ClearancePasskeyOptions,
	SocialProviderConfig,
	TenantProductAdministrationFacade,
	TenantProductAuditEvent,
	TenantProductReadiness,
	TenantProductScimConnection,
	TenantProductSsoConnection,
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
	passwordLockout: {
		enabled: boolean;
		maxFailedAttempts: number;
		durationSeconds: number;
	};
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
		passwordLockout: {
			enabled: input?.passwordLockout?.enabled ?? true,
			maxFailedAttempts: boundedSecurityInteger(
				input?.passwordLockout?.maxFailedAttempts,
				10,
				{
					label: "authenticationSecurity.passwordLockout.maxFailedAttempts",
					min: 3,
					max: 100,
				},
			),
			durationSeconds: boundedSecurityInteger(
				input?.passwordLockout?.durationSeconds,
				15 * 60,
				{
					label: "authenticationSecurity.passwordLockout.durationSeconds",
					min: 30,
					max: 24 * 60 * 60,
				},
			),
		},
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

function signingProviderJwksAdapter(
	pool: pg.Pool,
	signingProvider: KeySigningProvider,
	gracePeriodSeconds: number,
) {
	let providerKeysPromise: ReturnType<KeySigningProvider["publicKeys"]> | null =
		null;
	const loadProviderKeys = () => {
		providerKeysPromise ??= signingProvider.publicKeys().catch((error) => {
			providerKeysPromise = null;
			throw error;
		});
		return providerKeysPromise;
	};
	return {
		async getJwks(): Promise<Jwk[]> {
			const [providerKeys, legacyResult] = await Promise.all([
				loadProviderKeys(),
				pool.query<{
					id: string;
					publicKey: string;
					createdAt: Date;
					expiresAt: Date | null;
					alg: Jwk["alg"] | null;
					crv: Jwk["crv"] | null;
				}>(
					`SELECT id, "publicKey", "createdAt", "expiresAt", alg, crv
					 FROM jwks
					 WHERE "expiresAt" IS NULL OR "expiresAt" > $1
					 ORDER BY "createdAt" DESC`,
					[new Date(Date.now() - gracePeriodSeconds * 1_000)],
				),
			]);
			const legacyKeys: Jwk[] = legacyResult.rows.map((key) => ({
				id: key.id,
				publicKey: key.publicKey,
				privateKey: RETIRED_JWK_PRIVATE_KEY,
				createdAt: key.createdAt,
				...(key.expiresAt === null ? {} : { expiresAt: key.expiresAt }),
				...(key.alg === null ? {} : { alg: key.alg }),
				...(key.crv === null ? {} : { crv: key.crv }),
			}));
			const seen = new Set<string>();
			const managed = providerKeys.map((key): Jwk => {
				if (seen.has(key.id)) {
					throw new Error("Signing provider returned duplicate public key ids");
				}
				seen.add(key.id);
				return {
					id: key.id,
					publicKey: JSON.stringify(key.publicJwk),
					privateKey: RETIRED_JWK_PRIVATE_KEY,
					createdAt: new Date(key.createdAt),
					...(key.expiresAt === undefined
						? {}
						: { expiresAt: new Date(key.expiresAt) }),
					alg: "ES256",
					crv: "P-256",
				};
			});
			for (const key of legacyKeys) {
				if (seen.has(key.id)) {
					throw new Error("Signing provider public key id collides with stored JWKS");
				}
				seen.add(key.id);
			}
			return [...managed, ...legacyKeys];
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
export type ClearanceManagementAuthOptions = CreateClearanceAuthOptions &
	Readonly<{
		tenantProductAdministration: TenantProductAdministrationFacade;
		/**
		 * Private server bootstrap for the management projection of a runtime
		 * first-organization create. Product/browser configuration never receives
		 * this capability or chooses its scope.
		 */
		managedOrganizationLifecycle: ManagedOrganizationLifecycleFacade;
	}>;

export type ManagedOrganizationLifecycleFacade = Readonly<{
	finalizeCreatedOrganization(input: Readonly<{
		organization: Readonly<{
			id: string;
			name: string;
			slug: string;
			createdAt: Date;
		}>;
		owner: Readonly<{
			id: string;
			email: string;
			name?: string | null;
			createdAt: Date;
			updatedAt: Date;
		}>;
		ownerMembershipId: string;
		authorizationRevision: string;
		transaction: ClearanceTransactionQuery;
	}>): Promise<void>;
	/** Invoked only after the outer runtime transaction commits. */
	refreshAfterCommit(): Promise<void>;
}>;

export function createClearanceAuth<
	const Security extends ClearanceAuthenticationSecurityOptions | undefined =
		undefined,
	const Passkeys extends false | ClearancePasskeyOptions | undefined = undefined,
>(
	options: CreateClearanceAuthOptions<Security, Passkeys>,
): ClearanceAuthBundle<Security, Passkeys> {
	return createClearanceAuthWithTenantProductAdministration(options, undefined);
}

/**
 * Management-only bootstrap. This symbol is deliberately omitted from the
 * root package entrypoint: public product configuration cannot inject a
 * tenant-administration facade or bypass its transactional guard.
 */
export function createClearanceAuthWithTenantProductAdministration<
	const Security extends ClearanceAuthenticationSecurityOptions | undefined =
		undefined,
	const Passkeys extends false | ClearancePasskeyOptions | undefined = undefined,
>(
	options: CreateClearanceAuthOptions<Security, Passkeys>,
	tenantProductAdministration: TenantProductAdministrationFacade | undefined,
	managedOrganizationLifecycle: ManagedOrganizationLifecycleFacade | undefined =
		undefined,
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
	const keyManagement = resolveProductKeyManagement(options, strict);
	const keyManagementFacade: ClearanceKeyManagementFacade = Object.freeze({
		scope: Object.freeze({
			projectId: keyManagement.projectId,
			environmentId: keyManagement.environmentId,
		}),
		resourceId: credentialResourceId,
		async sealText(
			purpose: KeyPurpose,
			resourceId: string,
			plaintext: string,
		): Promise<string> {
			return keyManagement.registry.providerFor(purpose).seal(
				Buffer.from(plaintext, "utf8"),
				{
					projectId: keyManagement.projectId,
					environmentId: keyManagement.environmentId,
					resourceId,
				},
			);
		},
		async openText(
			purpose: KeyPurpose,
			resourceId: string,
			envelope: string,
		): Promise<string> {
			return Buffer.from(
				await keyManagement.registry.providerFor(purpose).open(envelope, {
					projectId: keyManagement.projectId,
					environmentId: keyManagement.environmentId,
					resourceId,
				}),
			).toString("utf8");
		},
		readiness: () => keyManagement.registry.readiness(),
		status: () => keyManagementStatus(),
		planMigration: () => keyManagementMigrationPlan(),
		applyMigration: (input) => applyKeyManagementMigration(input),
	});
	const oneTimeSecretReplayCipher = Object.freeze({
		async seal(plaintext: string, binding: string): Promise<string> {
			const resourceId = canonicalOneTimeSecretReplayResourceId(
				binding,
				keyManagementFacade.scope,
			);
			const envelope = await keyManagement.registry
				.providerFor(ONE_TIME_SECRET_REPLAY_PURPOSE)
				.seal(canonicalOneTimeSecretReplayPlaintext(plaintext), {
					...keyManagementFacade.scope,
					resourceId,
				});
			const parsed = parseKeyEnvelope(envelope);
			if (
				parsed.purpose !== ONE_TIME_SECRET_REPLAY_PURPOSE ||
				parsed.projectId !== keyManagementFacade.scope.projectId ||
				parsed.environmentId !== keyManagementFacade.scope.environmentId ||
				parsed.resourceId !== resourceId
			) {
				throw new Error("One-time secret replay envelope is invalid");
			}
			return envelope;
		},
		async open(envelope: string, binding: string): Promise<string> {
			const resourceId = canonicalOneTimeSecretReplayResourceId(
				binding,
				keyManagementFacade.scope,
			);
			const parsed = parseKeyEnvelope(envelope);
			if (
				parsed.purpose !== ONE_TIME_SECRET_REPLAY_PURPOSE ||
				parsed.projectId !== keyManagementFacade.scope.projectId ||
				parsed.environmentId !== keyManagementFacade.scope.environmentId ||
				parsed.resourceId !== resourceId
			) {
				throw new Error("One-time secret replay envelope is invalid");
			}
			const bytes = Buffer.from(
				await keyManagement.registry.providerFor(ONE_TIME_SECRET_REPLAY_PURPOSE).open(
					envelope,
					{ ...keyManagementFacade.scope, resourceId },
				),
			);
			const plaintext = bytes.toString("utf8");
			if (!Buffer.from(plaintext, "utf8").equals(bytes)) {
				throw new Error("One-time secret replay plaintext is invalid");
			}
			canonicalOneTimeSecretReplayPlaintext(plaintext);
			return plaintext;
		},
	});
	const openManagedOrLegacyText = async (
		purpose: KeyPurpose,
		resourceId: string,
		ciphertext: string,
	): Promise<string> =>
		ciphertext.startsWith("clrkm$v1$")
			? keyManagementFacade.openText(purpose, resourceId, ciphertext)
			: decryptRuntimeCredential(ciphertext, options.secret);
	const authenticationSecurity = resolveAuthenticationSecurity(options, strict);
	const passkeyOptions: PasskeyOptions | undefined =
		options.passkeys === false ? undefined : options.passkeys;
	const credentialAuthorityGeneration =
		options.credentialAuthority?.generation ?? "digest-v1";
	if (
		options.authenticationPolicy &&
		credentialAuthorityGeneration !== "digest-v1"
	) {
		throw new Error(
			"authenticationPolicy requires credentialAuthority.generation to be digest-v1",
		);
	}
	if (options.authorization && !options.authenticationPolicy) {
		throw new Error(
			"authorization requires authenticationPolicy for revision-bound session claims",
		);
	}
	if (
		options.authorization &&
		!authenticationSecurity.asymmetricAccessTokens.enabled
	) {
		throw new Error(
			"authorization requires asymmetric access tokens for revision-bound action claims",
		);
	}
	if (
		options.authenticationPolicy &&
		authenticationSecurity.twoFactor.trustDeviceMaxAgeSeconds >
			30 * 24 * 60 * 60
	) {
		throw new Error(
			"authenticationSecurity.twoFactor.trustDeviceMaxAgeSeconds must not exceed 2592000 when authenticationPolicy is enabled",
		);
	}

	const pool = new pg.Pool({ connectionString: options.databaseUrl });
	const runtimeAuditScope = resolveRuntimeAuditScope(options, strict);
	const runtimeAuditOutbox = runtimeAuditScope
		? createRuntimeAuditOutbox(pool, runtimeAuditScope)
		: null;
	const authorizationAuthority = options.authorization
		? new PostgresAuthorizationAuthority(pool, {
			...options.authorization,
			oneTimeSecretReplayCipher,
		}, {
			// createClearanceAuth owns the runtime migration and its exact public
			// organization authority; this is intentionally not caller-configurable.
			schema: "public",
			table: "organization",
		})
		: null;
	const authenticationPolicyAuthority = options.authenticationPolicy
		? new PostgresAuthenticationPolicyAuthority(
				pool,
				options.authenticationPolicy,
				{
					passwordLockout: authenticationSecurity.passwordLockout,
					factorLockout: {
						enabled: authenticationSecurity.twoFactor.enabled,
						maxFailedAttempts:
							authenticationSecurity.twoFactor.maxFailedAttempts,
						durationSeconds: authenticationSecurity.twoFactor.lockoutSeconds,
					},
					minimumAssurance: "single_factor",
					allowedFactors: {
						totp: authenticationSecurity.twoFactor.enabled,
						passkey: options.passkeys !== false,
					},
					trustedDevice: {
						enabled: authenticationSecurity.twoFactor.enabled,
						maxAgeSeconds:
							authenticationSecurity.twoFactor.trustDeviceMaxAgeSeconds,
					},
					assuranceMaxAgeSeconds: null,
				},
			)
		: null;
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
	const jwksAdapter = signingProviderJwksAdapter(
		pool,
		keyManagement.signingProvider,
		authenticationSecurity.asymmetricAccessTokens.gracePeriodSeconds,
	);
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
								...(runtimeAuditOutbox
									? { runtimeAudit: runtimeAuditOutbox.auditTable }
									: {}),
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
	const attachProductAuthorities = <Target extends object>(
		target: Target,
		migrationDrainId?: string,
	): Target => {
		attachInternalCredentialAuthority(target, {
			generation: credentialAuthorityGeneration,
			...(migrationDrainId ? { migrationDrainId } : {}),
		});
		if (authenticationPolicyAuthority) {
			attachInternalAuthenticationPolicy(target, {
				identity: authenticationPolicyAuthority.identity,
				reader: authenticationPolicyAuthority,
			});
		}
		if (authorizationAuthority) {
			attachInternalAuthorizationAuthority(target, {
				async readEffectiveAuthorization(input) {
					const effective = await authorizationAuthority.readEffective(input);
					return Object.freeze({
						organizationId: effective.organizationId,
						subject: Object.freeze({
							kind: effective.subject.kind,
							id: effective.subject.id,
						}),
						revision: effective.revision,
						actions: effective.actions,
					});
				},
				async authenticateServiceAccountCredential(secret) {
					const authenticated =
						await authorizationAuthority.authenticateServiceAccountCredential({
							secret,
						});
					return Object.freeze({
						organizationId: authenticated.organizationId,
						subject: Object.freeze({
							kind: "service_account" as const,
							id: authenticated.subject.id,
						}),
						revision: authenticated.revision,
						actions: authenticated.actions,
						expiresAt: authenticated.credential.expiresAt,
					});
				},
				async initializeOrganizationOwner(input) {
					const revision = await authorizationAuthority.initializeOrganization({
						organizationId: input.organizationId,
						transaction: input.transaction,
					});
					const owner = await authorizationAuthority.replaceSubjectRoles({
						organizationId: input.organizationId,
						subject: {
							kind: "principal",
							id: input.ownerPrincipalId,
						},
						roleIds: ["role_builtin_owner"],
						expectedRevision: revision.revision,
						transaction: input.transaction,
					});
					return owner.revision;
				},
			});
		}
		if (managedOrganizationLifecycle) {
			attachInternalManagedOrganizationLifecycleAuthority(target, {
				async finalizeCreatedOrganization(input) {
					await managedOrganizationLifecycle.finalizeCreatedOrganization(input);
					await queueAfterTransactionHook(async () => {
						// The database has committed regardless of a local cache refresh
						// failure. Keep the next ordinary refresh as the recovery path.
						await managedOrganizationLifecycle.refreshAfterCommit().catch(
							() => undefined,
						);
					}, input.transaction);
				},
			});
		}
		if (runtimeAuditOutbox) {
			attachCapturedInternalRuntimeAudit(target, runtimeAuditOutbox.binding);
		}
		return target;
	};

	const plugins = [
		organization(options.enableScim !== false ? {
			// SCIM Groups are the organization team authority. Do not create an
			// unrelated default team for organizations provisioned by management.
			teams: {
				enabled: true,
				defaultTeam: { enabled: false },
				allowRemovingAllTeams: true,
			},
		} : undefined),
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
							keyPairConfig: { alg: "ES256" },
							gracePeriod:
								authenticationSecurity.asymmetricAccessTokens
									.gracePeriodSeconds,
						},
						jwt: {
							issuer: authenticationSecurity.asymmetricAccessTokens.issuer,
							audience: authenticationSecurity.asymmetricAccessTokens.audience,
							expirationTime: "5m",
							sign: (payload) =>
								signJwtPayload(keyManagement.signingProvider, payload),
						},
					}),
				]
			: []),
		...(options.enableSso !== false
			? [
					sso(
						attachSSOInternalVerificationChallengeAuthority(
							{
								saml: {
									enableInResponseToValidation: true,
									allowIdpInitiated: false,
									requireTimestamps: true,
								},
								storeOIDCClientSecret: attachSSOKeyManagementWriter({
									encrypt: (secret: string, providerId: string) =>
										keyManagementFacade.sealText(
											"oidc-client-secret",
											keyManagementFacade.resourceId("oidc-client-secret", {
												providerId,
											}),
											secret,
										),
									decrypt: (ciphertext: string, providerId: string) =>
										openManagedOrLegacyText(
											"oidc-client-secret",
											keyManagementFacade.resourceId("oidc-client-secret", {
												providerId,
											}),
											ciphertext,
										),
								}),
							},
							createInternalVerificationChallengeAuthority(),
						),
					),
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
						storeSCIMToken: attachSCIMKeyManagementWriter({
							encrypt: async (token, context) =>
								`${SCIM_TOKEN_ENVELOPE_PREFIX}${await keyManagementFacade.sealText(
									"scim-bearer-token",
									keyManagementFacade.resourceId("scim-bearer-token", {
										providerId: context.providerId,
										organizationId: context.organizationId ?? null,
									}),
									token,
								)}`,
							decrypt: async (stored, context) => {
								const resourceId = keyManagementFacade.resourceId(
									"scim-bearer-token",
									{
										providerId: context.providerId,
										organizationId: context.organizationId ?? null,
									},
								);
								if (stored.startsWith(SCIM_TOKEN_ENVELOPE_PREFIX)) {
									const envelope = stored.slice(SCIM_TOKEN_ENVELOPE_PREFIX.length);
									if (!envelope.startsWith("clrkm$v1$")) {
										throw new Error("Stored SCIM token envelope is invalid");
									}
									return await keyManagementFacade.openText(
										"scim-bearer-token",
										resourceId,
										envelope,
									);
								}
								return await openManagedOrLegacyText(
									"scim-bearer-token",
									resourceId,
									stored,
								);
							},
						}),
					}),
				]
			: []),
		...(authorizationAuthority && runtimeAuditOutbox
			? [
					createTenantAdministrationPlugin({
						authorization: authorizationAuthority,
						runtimeAudit: runtimeAuditOutbox.binding,
						...(tenantProductAdministration
							? {
									productAdministration:
										tenantProductAdministration,
								}
							: {}),
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
		attachProductAuthorities(
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
			accountLockout: authenticationSecurity.passwordLockout,
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
			trustedProxyHeaders: false,
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
		attachProductAuthorities(
			{
		database: migrationDatabase,
		secret: options.secret,
		baseURL: options.baseURL,
		emailAndPassword: {
			enabled: true,
			accountLockout: authenticationSecurity.passwordLockout,
		},
		user: { additionalFields: userAdditionalFields },
		rateLimit,
		plugins,
			},
			migrationDrainId,
		) as Parameters<typeof getMigrations>[0];

	async function runtimeMigrationPlanFor(
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

	function combineMigrationPlans(
		...plans: readonly (ClearanceRuntimeMigrationPlan | undefined)[]
	): ClearanceRuntimeMigrationPlan {
		const activePlans = plans.filter(
			(plan): plan is ClearanceRuntimeMigrationPlan => plan !== undefined,
		);
		const [first] = activePlans;
		if (!first) throw new Error("At least one migration plan is required");
		if (activePlans.length === 1) return first;
		return {
			pendingTables: activePlans.reduce((total, plan) => total + plan.pendingTables, 0),
			pendingFields: activePlans.reduce((total, plan) => total + plan.pendingFields, 0),
			pendingSecurityMigrations: Object.freeze([
				...new Set(activePlans.flatMap((plan) => plan.pendingSecurityMigrations)),
			]),
			async compileSql() {
				const statements = (await Promise.all(activePlans.map((plan) => plan.compileSql())))
					.filter((statement) => statement.trim().length > 0);
				return statements.join("\n");
			},
			async apply() {
				for (const plan of activePlans) await plan.apply();
			},
		};
	}

	async function planMigrationsFor(
		migrationDatabase = database,
		migrationDrainId?: string,
	): Promise<ClearanceRuntimeMigrationPlan> {
		const [runtimePlan, policyPlan, auditPlan, authorizationPlan] = await Promise.all([
			runtimeMigrationPlanFor(migrationDatabase, migrationDrainId),
			authenticationPolicyAuthority?.planMigration(),
			runtimeAuditOutbox?.planMigration(),
			authorizationAuthority?.planMigration(),
		]);
		return combineMigrationPlans(
			runtimePlan,
			policyPlan,
			auditPlan,
			authorizationPlan,
		);
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
				ALTER TABLE "user" ADD COLUMN IF NOT EXISTS "passkeySessionGeneration" text;
				ALTER TABLE "user" ADD COLUMN IF NOT EXISTS "passkeyUserHandle" text;
				ALTER TABLE session ADD COLUMN IF NOT EXISTS "twoFactorSessionGeneration" text;
				ALTER TABLE session ADD COLUMN IF NOT EXISTS "passkeySessionGeneration" text;
				ALTER TABLE account ADD COLUMN IF NOT EXISTS "failedPasswordAttempts" integer DEFAULT 0;
				ALTER TABLE account ADD COLUMN IF NOT EXISTS "activePasswordAttemptReservations" text DEFAULT '[]';
				ALTER TABLE account ADD COLUMN IF NOT EXISTS "passwordLockedUntil" timestamptz;

				CREATE TABLE IF NOT EXISTS passkey (
					id text PRIMARY KEY,
					"userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
					name text,
					"credentialID" text NOT NULL,
					"publicKey" text NOT NULL,
					"userHandle" text NOT NULL,
					counter integer NOT NULL,
					"deviceType" text NOT NULL,
					"backedUp" boolean NOT NULL,
					transports text,
					aaguid text,
					"createdAt" timestamptz NOT NULL,
					"updatedAt" timestamptz NOT NULL
				);
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS id text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS "userId" text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS name text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS "credentialID" text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS "publicKey" text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS "userHandle" text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS counter integer;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS "deviceType" text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS "backedUp" boolean;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS transports text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS aaguid text;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS "createdAt" timestamptz;
				ALTER TABLE passkey ADD COLUMN IF NOT EXISTS "updatedAt" timestamptz;

				CREATE TABLE IF NOT EXISTS "passkeyChallenge" (
					id text PRIMARY KEY,
					"digestId" text NOT NULL,
					ceremony text NOT NULL,
					"rpID" text NOT NULL,
					origin text NOT NULL,
					"userId" text,
					"userHandle" text,
					"stagedSubjectId" text,
					"targetPasskeyId" text,
					"expiresAt" timestamptz NOT NULL,
					"createdAt" timestamptz NOT NULL,
					"updatedAt" timestamptz NOT NULL
				);
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS id text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "digestId" text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS ceremony text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "rpID" text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS origin text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "userId" text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "userHandle" text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "stagedSubjectId" text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "targetPasskeyId" text;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "expiresAt" timestamptz;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "createdAt" timestamptz;
				ALTER TABLE "passkeyChallenge" ADD COLUMN IF NOT EXISTS "updatedAt" timestamptz;

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
					"keyManagementVersion" integer,
					"keyManagementRevision" integer,
					"createdAt" timestamptz NOT NULL,
					"expiresAt" timestamptz,
					alg text,
					crv text
				);
				ALTER TABLE jwks ADD COLUMN IF NOT EXISTS alg text;
				ALTER TABLE jwks ADD COLUMN IF NOT EXISTS crv text;
				ALTER TABLE jwks ADD COLUMN IF NOT EXISTS "keyManagementVersion" integer;
				ALTER TABLE jwks ADD COLUMN IF NOT EXISTS "keyManagementRevision" integer
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
			const duplicatePasskeyHandle = await client.query<{ handle: string }>(`
				SELECT "passkeyUserHandle" AS handle FROM "user"
				WHERE "passkeyUserHandle" IS NOT NULL
				GROUP BY "passkeyUserHandle" HAVING count(*) > 1 LIMIT 1
			`);
			if (duplicatePasskeyHandle.rows[0]) {
				throw new Error(
					`Cannot prepare the passkey bridge: duplicate user handles exist for ${duplicatePasskeyHandle.rows[0].handle}`,
				);
			}
			const duplicateCredential = await client.query<{ credentialId: string }>(`
				SELECT "credentialID" AS "credentialId" FROM passkey
				WHERE "credentialID" IS NOT NULL
				GROUP BY "credentialID" HAVING count(*) > 1 LIMIT 1
			`);
			if (duplicateCredential.rows[0]) {
				throw new Error(
					`Cannot prepare the passkey bridge: duplicate credential IDs exist for ${duplicateCredential.rows[0].credentialId}`,
				);
			}
			const duplicateChallenge = await client.query<{ digestId: string }>(`
				SELECT "digestId" FROM "passkeyChallenge"
				WHERE "digestId" IS NOT NULL
				GROUP BY "digestId" HAVING count(*) > 1 LIMIT 1
			`);
			if (duplicateChallenge.rows[0]) {
				throw new Error(
					`Cannot prepare the passkey bridge: duplicate challenge digests exist for ${duplicateChallenge.rows[0].digestId}`,
				);
			}
			const orphanedPasskey = await client.query<{ userId: string | null }>(`
				SELECT passkey."userId" FROM passkey
				LEFT JOIN "user" ON "user".id = passkey."userId"
				WHERE passkey."userId" IS NULL OR "user".id IS NULL LIMIT 1
			`);
			if (orphanedPasskey.rows[0]) {
				throw new Error(
					`Cannot prepare the passkey bridge: credential references unavailable user ${orphanedPasskey.rows[0].userId ?? "<null>"}`,
				);
			}
			await client.query(`
				ALTER TABLE passkey ALTER COLUMN id SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN "userId" SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN "credentialID" SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN "publicKey" SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN "userHandle" SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN counter SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN "deviceType" SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN "backedUp" SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN "createdAt" SET NOT NULL;
				ALTER TABLE passkey ALTER COLUMN "updatedAt" SET NOT NULL;
				ALTER TABLE "passkeyChallenge" ALTER COLUMN id SET NOT NULL;
				ALTER TABLE "passkeyChallenge" ALTER COLUMN "digestId" SET NOT NULL;
				ALTER TABLE "passkeyChallenge" ALTER COLUMN ceremony SET NOT NULL;
				ALTER TABLE "passkeyChallenge" ALTER COLUMN "rpID" SET NOT NULL;
				ALTER TABLE "passkeyChallenge" ALTER COLUMN origin SET NOT NULL;
				ALTER TABLE "passkeyChallenge" ALTER COLUMN "expiresAt" SET NOT NULL;
				ALTER TABLE "passkeyChallenge" ALTER COLUMN "createdAt" SET NOT NULL;
				ALTER TABLE "passkeyChallenge" ALTER COLUMN "updatedAt" SET NOT NULL;
				CREATE UNIQUE INDEX IF NOT EXISTS "user_passkeyUserHandle_uidx"
					ON "user" ("passkeyUserHandle");
				CREATE UNIQUE INDEX IF NOT EXISTS "passkey_credentialID_uidx"
					ON passkey ("credentialID");
				CREATE INDEX IF NOT EXISTS "passkey_userId_idx" ON passkey ("userId");
				CREATE UNIQUE INDEX IF NOT EXISTS "passkeyChallenge_digestId_uidx"
					ON "passkeyChallenge" ("digestId");
				CREATE INDEX IF NOT EXISTS "passkeyChallenge_expiresAt_idx"
					ON "passkeyChallenge" ("expiresAt");
				CREATE INDEX IF NOT EXISTS "passkeyChallenge_userId_idx"
					ON "passkeyChallenge" ("userId");
				CREATE INDEX IF NOT EXISTS "passkeyChallenge_stagedSubjectId_idx"
					ON "passkeyChallenge" ("stagedSubjectId");
				DO $bridge$
				BEGIN
					IF NOT EXISTS (
						SELECT 1 FROM pg_constraint
						WHERE conrelid = to_regclass(format('%I.%I', current_schema(), 'passkey'))
						  AND contype = 'p'
					) THEN
						ALTER TABLE passkey ADD CONSTRAINT passkey_pkey PRIMARY KEY (id);
					END IF;
					IF NOT EXISTS (
						SELECT 1 FROM pg_constraint
						WHERE conrelid = to_regclass(format('%I.%I', current_schema(), 'passkeyChallenge'))
						  AND contype = 'p'
					) THEN
						ALTER TABLE "passkeyChallenge"
							ADD CONSTRAINT "passkeyChallenge_pkey" PRIMARY KEY (id);
					END IF;
					IF NOT EXISTS (
						SELECT 1 FROM pg_constraint
						WHERE conrelid = to_regclass(format('%I.%I', current_schema(), 'passkey'))
						  AND conname = 'passkey_userId_fkey'
					) THEN
						ALTER TABLE passkey ADD CONSTRAINT "passkey_userId_fkey"
							FOREIGN KEY ("userId") REFERENCES "user"(id) ON DELETE CASCADE;
					END IF;
				END
				$bridge$;
			`);
			await client.query(
				`CREATE UNIQUE INDEX IF NOT EXISTS "twoFactor_userId_unique" ON "twoFactor" ("userId")`,
			);
			const incompatiblePasskeyColumn = await client.query<{
				tableName: string;
				columnName: string;
			}>(`
				WITH expected("tableName", "columnName", type, nullable) AS (VALUES
					('user', 'passkeySessionGeneration', 'text', 'YES'),
					('user', 'passkeyUserHandle', 'text', 'YES'),
					('session', 'passkeySessionGeneration', 'text', 'YES'),
					('account', 'failedPasswordAttempts', 'int4', 'YES'),
					('account', 'activePasswordAttemptReservations', 'text', 'YES'),
					('account', 'passwordLockedUntil', 'timestamptz', 'YES'),
					('passkey', 'id', 'text', 'NO'),
					('passkey', 'userId', 'text', 'NO'),
					('passkey', 'name', 'text', 'YES'),
					('passkey', 'credentialID', 'text', 'NO'),
					('passkey', 'publicKey', 'text', 'NO'),
					('passkey', 'userHandle', 'text', 'NO'),
					('passkey', 'counter', 'int4', 'NO'),
					('passkey', 'deviceType', 'text', 'NO'),
					('passkey', 'backedUp', 'bool', 'NO'),
					('passkey', 'transports', 'text', 'YES'),
					('passkey', 'aaguid', 'text', 'YES'),
					('passkey', 'createdAt', 'timestamptz', 'NO'),
					('passkey', 'updatedAt', 'timestamptz', 'NO'),
					('passkeyChallenge', 'id', 'text', 'NO'),
					('passkeyChallenge', 'digestId', 'text', 'NO'),
					('passkeyChallenge', 'ceremony', 'text', 'NO'),
					('passkeyChallenge', 'rpID', 'text', 'NO'),
					('passkeyChallenge', 'origin', 'text', 'NO'),
					('passkeyChallenge', 'userId', 'text', 'YES'),
					('passkeyChallenge', 'userHandle', 'text', 'YES'),
					('passkeyChallenge', 'stagedSubjectId', 'text', 'YES'),
					('passkeyChallenge', 'targetPasskeyId', 'text', 'YES'),
					('passkeyChallenge', 'expiresAt', 'timestamptz', 'NO'),
					('passkeyChallenge', 'createdAt', 'timestamptz', 'NO'),
					('passkeyChallenge', 'updatedAt', 'timestamptz', 'NO')
				)
				SELECT expected."tableName", expected."columnName"
				FROM expected
				LEFT JOIN information_schema.columns AS actual
				  ON actual.table_schema = current_schema()
				 AND actual.table_name = expected."tableName"
				 AND actual.column_name = expected."columnName"
				WHERE actual.column_name IS NULL
				   OR actual.udt_name <> expected.type
				   OR actual.is_nullable <> expected.nullable
				LIMIT 1
			`);
			if (incompatiblePasskeyColumn.rows[0]) {
				throw new Error(
					`Cannot prepare the passkey bridge: incompatible column ${incompatiblePasskeyColumn.rows[0].tableName}.${incompatiblePasskeyColumn.rows[0].columnName}`,
				);
			}
			const incompatiblePasswordLockoutDefault = await client.query<{
				columnName: string;
			}>(`
				SELECT column_name AS "columnName"
				FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name = 'account'
				  AND (
				    (column_name = 'failedPasswordAttempts' AND column_default IS DISTINCT FROM '0')
				    OR (column_name = 'activePasswordAttemptReservations' AND column_default IS DISTINCT FROM '''[]''::text')
				    OR (column_name = 'passwordLockedUntil' AND column_default IS NOT NULL)
				  )
				LIMIT 1
			`);
			if (incompatiblePasswordLockoutDefault.rows[0]) {
				throw new Error(
					`Cannot prepare password lockout: incompatible default for account.${incompatiblePasswordLockoutDefault.rows[0].columnName}`,
				);
			}
			const incompatiblePasskeyIndex = await client.query<{ name: string }>(`
				WITH expected(name, "tableName", unique_index, column_name) AS (VALUES
					('user_passkeyUserHandle_uidx', 'user', true, 'passkeyUserHandle'),
					('passkey_credentialID_uidx', 'passkey', true, 'credentialID'),
					('passkey_userId_idx', 'passkey', false, 'userId'),
					('passkeyChallenge_digestId_uidx', 'passkeyChallenge', true, 'digestId'),
					('passkeyChallenge_expiresAt_idx', 'passkeyChallenge', false, 'expiresAt'),
					('passkeyChallenge_userId_idx', 'passkeyChallenge', false, 'userId'),
					('passkeyChallenge_stagedSubjectId_idx', 'passkeyChallenge', false, 'stagedSubjectId')
				), actual AS (
					SELECT index_record.relname AS name,
					       table_record.relname AS "tableName",
					       index_state.indisunique AS unique_index,
					       index_state.indisvalid AS valid_index,
					       index_state.indisready AS ready_index,
					       index_state.indislive AS live_index,
					       COALESCE(
					         (to_jsonb(index_state)->>'indnullsnotdistinct')::boolean,
					         false
					       ) AS nulls_not_distinct,
					       index_state.indpred IS NULL AS unpredicated,
					       index_state.indexprs IS NULL AS no_expressions,
					       index_state.indnkeyatts AS key_attribute_count,
					       index_state.indnatts AS total_attribute_count,
					       array_agg(attribute_record.attname::text ORDER BY index_key.ordinality) AS columns
					FROM pg_index AS index_state
					JOIN pg_class AS table_record ON table_record.oid = index_state.indrelid
					JOIN pg_namespace AS namespace_record ON namespace_record.oid = table_record.relnamespace
					JOIN pg_class AS index_record ON index_record.oid = index_state.indexrelid
					CROSS JOIN LATERAL unnest(index_state.indkey)
					  WITH ORDINALITY AS index_key(attnum, ordinality)
					JOIN pg_attribute AS attribute_record
					  ON attribute_record.attrelid = table_record.oid
					 AND attribute_record.attnum = index_key.attnum
					WHERE namespace_record.nspname = current_schema()
					GROUP BY index_record.relname, table_record.relname,
					         index_state.indisunique, index_state.indisvalid,
					         index_state.indisready, index_state.indislive,
					         COALESCE(
					           (to_jsonb(index_state)->>'indnullsnotdistinct')::boolean,
					           false
					         ),
					         index_state.indpred, index_state.indexprs,
					         index_state.indnkeyatts, index_state.indnatts
				)
				SELECT expected.name FROM expected
				LEFT JOIN actual ON actual.name = expected.name
				WHERE actual.name IS NULL
				   OR actual."tableName" <> expected."tableName"
				   OR actual.unique_index <> expected.unique_index
				   OR actual.valid_index IS NOT TRUE
				   OR actual.ready_index IS NOT TRUE
				   OR actual.live_index IS NOT TRUE
				   OR actual.nulls_not_distinct IS TRUE
				   OR actual.unpredicated IS NOT TRUE
				   OR actual.no_expressions IS NOT TRUE
				   OR actual.key_attribute_count <> 1
				   OR actual.total_attribute_count <> 1
				   OR actual.columns <> ARRAY[expected.column_name]
				LIMIT 1
			`);
			if (incompatiblePasskeyIndex.rows[0]) {
				throw new Error(
					`Cannot prepare the passkey bridge: incompatible index ${incompatiblePasskeyIndex.rows[0].name}`,
				);
			}
			const incompatiblePasskeyConstraint = await client.query<{ name: string }>(`
				WITH expected(name, type, definition) AS (VALUES
					('passkey_pkey', 'p', 'PRIMARY KEY (id)'),
					('passkeyChallenge_pkey', 'p', 'PRIMARY KEY (id)'),
					('passkey_userId_fkey', 'f', 'FOREIGN KEY ("userId") REFERENCES "user"(id) ON DELETE CASCADE')
				), actual AS (
					SELECT constraint_record.conname AS name,
					       constraint_record.contype::text AS type,
					       pg_get_constraintdef(constraint_record.oid, true) AS definition
					FROM pg_constraint AS constraint_record
					JOIN pg_class AS table_record ON table_record.oid = constraint_record.conrelid
					JOIN pg_namespace AS namespace_record ON namespace_record.oid = table_record.relnamespace
					WHERE namespace_record.nspname = current_schema()
				)
				SELECT expected.name FROM expected
				LEFT JOIN actual ON actual.name = expected.name
				WHERE actual.name IS NULL
				   OR actual.type <> expected.type
				   OR actual.definition <> expected.definition
				LIMIT 1
			`);
			if (incompatiblePasskeyConstraint.rows[0]) {
				throw new Error(
					`Cannot prepare the passkey bridge: incompatible constraint ${incompatiblePasskeyConstraint.rows[0].name}`,
				);
			}
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
	}

	async function installKeyManagementTrigger(
		client: { query: ClearanceTransactionQuery["rawTransactionQuery"] },
		definition: KeyManagementTriggerDefinition,
	): Promise<void> {
		await client.query(`
			CREATE OR REPLACE FUNCTION ${definition.functionName}()
			RETURNS trigger LANGUAGE plpgsql AS $function$${definition.body}$function$;
			DROP TRIGGER IF EXISTS ${definition.triggerName} ON ${definition.table};
			CREATE TRIGGER ${definition.triggerName}
				BEFORE INSERT OR UPDATE OF ${definition.column} ON ${definition.table}
				FOR EACH ROW EXECUTE FUNCTION ${definition.functionName}();
		`);
	}

	async function migratePurposeSeparatedCredentialBatch(
		setupOnly: boolean,
		transaction?: KeyManagementQuery,
		approvedBatch?: KeyManagementMigrationBatch,
	): Promise<ClearanceKeyManagementMigrationCounts> {
		let migratedOidcClientSecrets = 0;
		let migratedScimTokens = 0;
		let migratedJwks = 0;
		const ownedClient = transaction ? undefined : await pool.connect();
		const client: { query: ClearanceTransactionQuery["rawTransactionQuery"] } =
			transaction
				? { query: transaction.rawTransactionQuery.bind(transaction) }
				: { query: ownedClient!.query.bind(ownedClient) };
		try {
			if (ownedClient) await client.query("BEGIN");
			await client.query(
				`SELECT pg_advisory_xact_lock(
					hashtext(current_database()),
					hashtext(current_schema() || ':clearance:key-management-migration:v1')
				)`,
			);
			const credentialTables = await client.query<{
				ssoProvider: string | null;
				scimProvider: string | null;
				jwks: string | null;
			}>(`SELECT
				to_regclass(format('%I.%I', current_schema(), 'ssoProvider'))::text AS "ssoProvider",
				to_regclass(format('%I.%I', current_schema(), 'scimProvider'))::text AS "scimProvider",
				to_regclass(format('%I.%I', current_schema(), 'jwks'))::text AS jwks`);
			const tables = credentialTables.rows[0]!;
			if (tables.ssoProvider) {
				await client.query(`ALTER TABLE "ssoProvider"
					ADD COLUMN IF NOT EXISTS "keyManagementVersion" integer,
					ADD COLUMN IF NOT EXISTS "keyManagementRevision" integer`);
			}
			if (tables.scimProvider) {
				await client.query(`ALTER TABLE "scimProvider"
					ADD COLUMN IF NOT EXISTS "keyManagementVersion" integer,
					ADD COLUMN IF NOT EXISTS "keyManagementRevision" integer`);
			}
			if (tables.jwks) {
				await client.query(`ALTER TABLE jwks
					ADD COLUMN IF NOT EXISTS "keyManagementVersion" integer,
					ADD COLUMN IF NOT EXISTS "keyManagementRevision" integer`);
			}
			if (!setupOnly) {
				await client.query(
					`SELECT set_config('clearance.key_management_migration', 'v1', true)`,
				);
			}
			if (!setupOnly && tables.ssoProvider) {
				const providers = await client.query<{
					id: string;
					providerId: string;
					oidcConfig: string;
					keyManagementVersion: number | null;
					keyManagementRevision: number | null;
				}>(`SELECT id, "providerId", "oidcConfig", "keyManagementVersion",
					       "keyManagementRevision"
					FROM "ssoProvider"
					WHERE "oidcConfig" IS NOT NULL
					  AND ("keyManagementVersion" IS DISTINCT FROM 1
					       OR "keyManagementRevision" IS NULL)
					${approvedBatch ? "AND id = ANY($1::text[])" : ""}
					ORDER BY id ${approvedBatch ? "FOR UPDATE" : `LIMIT ${KEY_MANAGEMENT_MIGRATION_BATCH_SIZE} FOR UPDATE SKIP LOCKED`}`,
					approvedBatch
						? [approvedBatch.oidcClientSecrets.map((snapshot) => snapshot.id)]
						: undefined);
				assertApprovedMigrationSnapshots(
					"oidcClientSecrets",
					providers.rows,
					approvedBatch?.oidcClientSecrets,
				);
				for (const provider of providers.rows) {
					let config: { clientSecret?: unknown };
					try {
						config = JSON.parse(provider.oidcConfig) as typeof config;
					} catch {
						throw new Error(
							`Cannot migrate invalid OIDC configuration for provider ${provider.id}`,
						);
					}
					if (typeof config?.clientSecret !== "string" || !config.clientSecret) {
						const updated = await client.query(
							`UPDATE "ssoProvider"
							 SET "keyManagementVersion"=1,
							     "keyManagementRevision"=COALESCE("keyManagementRevision", 0) + 1
							 WHERE id=$1 AND "oidcConfig"=$2
							   AND "keyManagementVersion" IS NOT DISTINCT FROM $3
							   AND "keyManagementRevision" IS NOT DISTINCT FROM $4`,
							[
								provider.id,
								provider.oidcConfig,
								provider.keyManagementVersion,
								provider.keyManagementRevision,
							],
						);
						if (updated.rowCount !== 1) {
							throw new Error(
								`OIDC configuration changed during key migration for provider ${provider.id}`,
							);
						}
						migratedOidcClientSecrets += 1;
						continue;
					}
					const resourceId = keyManagementFacade.resourceId("oidc-client-secret", {
						providerId: provider.providerId,
					});
					const wrapped = config.clientSecret.startsWith("clr-sso:v1:");
					const stored = wrapped
						? config.clientSecret.slice("clr-sso:v1:".length)
						: config.clientSecret;
					let migratedConfig = provider.oidcConfig;
					if (stored.startsWith("clrkm$v1$")) {
						await keyManagementFacade.openText(
							"oidc-client-secret",
							resourceId,
							stored,
						);
					} else {
						const plaintext = wrapped
							? await decryptRuntimeCredential(stored, options.secret)
							: stored;
						config.clientSecret = `clr-sso:v1:${await keyManagementFacade.sealText(
							"oidc-client-secret",
							resourceId,
							plaintext,
						)}`;
						migratedConfig = JSON.stringify(config);
					}
					const updated = await client.query(
						`UPDATE "ssoProvider"
						 SET "oidcConfig"=$2, "keyManagementVersion"=1,
						     "keyManagementRevision"=COALESCE("keyManagementRevision", 0) + 1
						 WHERE id=$1 AND "oidcConfig"=$3
						   AND "keyManagementVersion" IS NOT DISTINCT FROM $4
						   AND "keyManagementRevision" IS NOT DISTINCT FROM $5`,
						[
							provider.id,
							migratedConfig,
							provider.oidcConfig,
							provider.keyManagementVersion,
							provider.keyManagementRevision,
						],
					);
					if (updated.rowCount !== 1) {
						throw new Error(
							`OIDC configuration changed during key migration for provider ${provider.id}`,
						);
					}
					migratedOidcClientSecrets += 1;
				}
			}
			if (!setupOnly && tables.scimProvider) {
				const providers = await client.query<{
					id: string;
					providerId: string;
					organizationId: string | null;
					scimToken: string;
					keyManagementVersion: number | null;
					keyManagementRevision: number | null;
				}>(`SELECT id, "providerId", "organizationId", "scimToken",
					       "keyManagementVersion", "keyManagementRevision"
					FROM "scimProvider"
					WHERE ("keyManagementVersion" IS DISTINCT FROM 1
					   OR "keyManagementRevision" IS NULL)
					${approvedBatch ? "AND id = ANY($1::text[])" : ""}
					ORDER BY id ${approvedBatch ? "FOR UPDATE" : `LIMIT ${KEY_MANAGEMENT_MIGRATION_BATCH_SIZE} FOR UPDATE SKIP LOCKED`}`,
					approvedBatch
						? [approvedBatch.scimTokens.map((snapshot) => snapshot.id)]
						: undefined);
				assertApprovedMigrationSnapshots(
					"scimTokens",
					providers.rows,
					approvedBatch?.scimTokens,
				);
				for (const provider of providers.rows) {
					const resourceId = keyManagementFacade.resourceId("scim-bearer-token", {
						providerId: provider.providerId,
						organizationId: provider.organizationId,
					});
					const wrapped = provider.scimToken.startsWith(
						SCIM_TOKEN_ENVELOPE_PREFIX,
					);
					const stored = wrapped
						? provider.scimToken.slice(SCIM_TOKEN_ENVELOPE_PREFIX.length)
						: provider.scimToken;
					if (wrapped && !stored.startsWith("clrkm$v1$")) {
						throw new Error(
							`Cannot migrate invalid SCIM token envelope for provider ${provider.id}`,
						);
					}
					let migrated: string;
					if (stored.startsWith("clrkm$v1$")) {
						await keyManagementFacade.openText(
							"scim-bearer-token",
							resourceId,
							stored,
						);
						migrated = `${SCIM_TOKEN_ENVELOPE_PREFIX}${stored}`;
					} else {
						const plaintext = await decryptRuntimeCredential(stored, options.secret);
						migrated = `${SCIM_TOKEN_ENVELOPE_PREFIX}${await keyManagementFacade.sealText(
							"scim-bearer-token",
							resourceId,
							plaintext,
						)}`;
					}
					const updated = await client.query(
						`UPDATE "scimProvider"
						 SET "scimToken"=$2, "keyManagementVersion"=1,
						     "keyManagementRevision"=COALESCE("keyManagementRevision", 0) + 1
						 WHERE id=$1 AND "scimToken"=$3
						   AND "keyManagementVersion" IS NOT DISTINCT FROM $4
						   AND "keyManagementRevision" IS NOT DISTINCT FROM $5`,
						[
							provider.id,
							migrated,
							provider.scimToken,
							provider.keyManagementVersion,
							provider.keyManagementRevision,
						],
					);
					if (updated.rowCount !== 1) {
						throw new Error(
							`SCIM token changed during key migration for provider ${provider.id}`,
						);
					}
					migratedScimTokens += 1;
				}
			}
			await client.query(
				`SELECT pg_advisory_xact_lock(
					hashtext(current_database()),
					hashtext(current_schema() || ':clearance:jwks-rotation')
				)`,
			);
			const signingKeys: { rows: Array<{
				id: string;
				publicKey: string;
				privateKey: string;
				expiresAt: Date | null;
				keyManagementVersion: number | null;
				keyManagementRevision: number | null;
			}> } = !setupOnly && tables.jwks
				? await client.query(`SELECT id, "publicKey", "privateKey", "expiresAt",
					       "keyManagementVersion", "keyManagementRevision"
					FROM jwks
					WHERE ("keyManagementVersion" IS DISTINCT FROM 1
					   OR "keyManagementRevision" IS NULL)
					${approvedBatch ? "AND id = ANY($1::text[])" : ""}
					ORDER BY id ${approvedBatch ? "FOR UPDATE" : `LIMIT ${KEY_MANAGEMENT_MIGRATION_BATCH_SIZE} FOR UPDATE SKIP LOCKED`}`,
					approvedBatch
						? [approvedBatch.jwks.map((snapshot) => snapshot.id)]
						: undefined)
				: { rows: [] };
			assertApprovedMigrationSnapshots(
				"jwks",
				signingKeys.rows,
				approvedBatch?.jwks,
			);
			for (const signingKey of signingKeys.rows) {
				let migratedPrivateKey: string;
				if (
					signingKey.privateKey === RETIRED_JWK_PRIVATE_KEY ||
					(signingKey.expiresAt !== null &&
						signingKey.expiresAt.getTime() <= Date.now())
				) {
					migratedPrivateKey = RETIRED_JWK_PRIVATE_KEY;
				} else {
					const resourceId = keyManagementFacade.resourceId(
						"access-token-signing-key",
						{ publicKey: signingKey.publicKey },
					);
					if (signingKey.privateKey.startsWith("clrkm$v1$")) {
						await keyManagementFacade.openText(
							"access-token-signing-key",
							resourceId,
							signingKey.privateKey,
						);
						migratedPrivateKey = signingKey.privateKey;
					} else {
						let legacyCiphertext: unknown;
						try {
							legacyCiphertext = JSON.parse(signingKey.privateKey);
						} catch {
							throw new Error(
								`Cannot migrate invalid JWT private-key storage for key ${signingKey.id}`,
							);
						}
						if (typeof legacyCiphertext !== "string" || !legacyCiphertext) {
							throw new Error(
								`Cannot migrate invalid JWT private-key storage for key ${signingKey.id}`,
							);
						}
						const privateKey = await decryptRuntimeCredential(
							legacyCiphertext,
							options.secret,
						);
						migratedPrivateKey = await keyManagementFacade.sealText(
							"access-token-signing-key",
							resourceId,
							privateKey,
						);
					}
				}
				const updated = await client.query(
					`UPDATE jwks
					 SET "privateKey"=$2, "keyManagementVersion"=1,
					     "keyManagementRevision"=COALESCE("keyManagementRevision", 0) + 1
					 WHERE id=$1 AND "privateKey"=$3 AND "publicKey"=$4
					   AND "keyManagementVersion" IS NOT DISTINCT FROM $5
					   AND "keyManagementRevision" IS NOT DISTINCT FROM $6`,
					[
						signingKey.id,
						migratedPrivateKey,
						signingKey.privateKey,
						signingKey.publicKey,
						signingKey.keyManagementVersion,
						signingKey.keyManagementRevision,
					],
				);
				if (updated.rowCount !== 1) {
					throw new Error(
						`JWT private key changed during key migration for key ${signingKey.id}`,
						);
					}
				migratedJwks += 1;
			}
			if (setupOnly && tables.ssoProvider) {
				await installKeyManagementTrigger(client, KEY_MANAGEMENT_TRIGGER_DEFINITIONS[0]);
			}
			if (setupOnly && tables.scimProvider) {
				await installKeyManagementTrigger(client, KEY_MANAGEMENT_TRIGGER_DEFINITIONS[1]);
			}
			if (setupOnly && tables.jwks) {
				await installKeyManagementTrigger(client, KEY_MANAGEMENT_TRIGGER_DEFINITIONS[2]);
			}
			if (ownedClient) await client.query("COMMIT");
		} catch (error) {
			if (ownedClient) await client.query("ROLLBACK").catch(() => undefined);
			throw error;
		} finally {
			ownedClient?.release();
		}
		return keyManagementMigrationCounts(
			migratedOidcClientSecrets,
			migratedScimTokens,
			migratedJwks,
		);
	}

	type CredentialTables = Readonly<{
		ssoProvider: boolean;
		scimProvider: boolean;
		jwks: boolean;
	}>;
	type KeyManagementMigrationInspection = Readonly<{
		tables: CredentialTables;
		setupReady: boolean;
		pending: ClearanceKeyManagementMigrationCounts;
		migrated: ClearanceKeyManagementMigrationCounts;
		batch: KeyManagementMigrationBatch;
		snapshots: Readonly<Record<KeyManagementMigrationDomain, readonly MigrationSnapshot[]>>;
	}>;

	const zeroKeyManagementMigrationCounts = (): ClearanceKeyManagementMigrationCounts =>
		Object.freeze({ oidcClientSecrets: 0, scimTokens: 0, jwks: 0, total: 0 });
	const keyManagementMigrationCounts = (
		oidcClientSecrets: number,
		scimTokens: number,
		jwks: number,
	): ClearanceKeyManagementMigrationCounts =>
		Object.freeze({
			oidcClientSecrets,
			scimTokens,
			jwks,
			total: oidcClientSecrets + scimTokens + jwks,
		});
	const sourceDigest = (value: string): string =>
		createHash("sha256").update(value, "utf8").digest("hex");
	function configuredKeyManagementWriteAuthority(): Readonly<{
		encryption: readonly Readonly<{ purpose: KeyPurpose; identity: string }>[];
		signing: string;
	}> {
		const encryption = ([
			"oidc-client-secret",
			"scim-bearer-token",
			ONE_TIME_SECRET_REPLAY_PURPOSE,
			"access-token-signing-key",
		] as const).map((purpose) => {
			const provider = keyManagement.registry.providerFor(purpose);
			return Object.freeze({
				purpose,
				identity: sourceDigest(JSON.stringify({
					kind: provider.kind,
					providerId: provider.providerId,
					currentKeyId: provider.currentKeyId,
				})),
			});
		});
		return Object.freeze({
			encryption: Object.freeze(encryption),
			signing: sourceDigest(JSON.stringify({
				kind: keyManagement.signingProvider.kind,
				providerId: keyManagement.signingProvider.providerId,
				currentKeyId: keyManagement.signingProvider.currentKeyId,
			})),
		});
	}
	const nullableNumber = (value: unknown): number | null =>
		typeof value === "number" ? value : null;
	const nullableText = (value: unknown): string | null =>
		typeof value === "string" ? value : null;
	const canonicalSnapshot = (
		domain: KeyManagementMigrationDomain,
		row: Record<string, unknown>,
	): MigrationSnapshot => {
		const id = String(row.id);
		const version = nullableNumber(row.version ?? row.keyManagementVersion);
		const revision = nullableNumber(row.revision ?? row.keyManagementRevision);
		const source = nullableText(row.source) ??
			(domain === "oidcClientSecrets"
				? String(row.oidcConfig)
				: domain === "scimTokens"
					? String(row.scimToken)
					: String(row.privateKey));
		const expiresAt = row.expiresAt instanceof Date
			? row.expiresAt.toISOString()
			: row.expiresAt === null || row.expiresAt === undefined
				? null
				: new Date(String(row.expiresAt)).toISOString();
		const binding = domain === "oidcClientSecrets"
			? { providerId: String(row.providerId), oidcConfig: source }
			: domain === "scimTokens"
				? {
					providerId: String(row.providerId),
					organizationId: nullableText(row.organizationId),
					scimToken: source,
				}
				: {
					publicKey: String(row.publicKey),
					privateKey: source,
					expiresAt,
				};
		return Object.freeze({
			id,
			version,
			revision,
			sourceHash: sourceDigest(JSON.stringify({ id, version, revision, ...binding })),
		});
	};
	const staleKeyManagementPlan = (): Error =>
		Object.assign(new Error("Key management migration plan is stale"), {
			code: "KEY_MANAGEMENT_PLAN_STALE",
		});
	const keyManagementTransactionRequired = (): Error =>
		Object.assign(new Error("Key management migration requires a PostgreSQL transaction"), {
			code: "KEY_MANAGEMENT_TRANSACTION_REQUIRED",
		});
	const keyManagementProviderNotReady = (): Error =>
		Object.assign(new Error("Purpose-separated key providers are not ready"), {
			code: "KEY_MANAGEMENT_PROVIDER_NOT_READY",
		});
	function assertApprovedMigrationSnapshots(
		domain: KeyManagementMigrationDomain,
		rows: readonly Record<string, unknown>[],
		expected: readonly MigrationSnapshot[] | undefined,
	): void {
		if (!expected) return;
		const actual = rows.map((row) => canonicalSnapshot(domain, row));
		if (
			actual.length !== expected.length ||
			actual.some((snapshot, index) =>
				snapshot.id !== expected[index]?.id ||
				snapshot.version !== expected[index]?.version ||
				snapshot.revision !== expected[index]?.revision ||
				snapshot.sourceHash !== expected[index]?.sourceHash,
			)
		) {
			throw staleKeyManagementPlan();
		}
	}

	function keyManagementQuery(
		transaction?: KeyManagementQuery,
	): ClearanceTransactionQuery["rawTransactionQuery"] {
		return transaction
			? transaction.rawTransactionQuery.bind(transaction)
			: pool.query.bind(pool);
	}

	async function inspectKeyManagementMigration(
		transaction?: KeyManagementQuery,
	): Promise<KeyManagementMigrationInspection> {
		const query = keyManagementQuery(transaction);
		const tableResult = await query<{
			ssoProvider: string | null;
			scimProvider: string | null;
			jwks: string | null;
		}>(`SELECT
			to_regclass(format('%I.%I', current_schema(), 'ssoProvider'))::text AS "ssoProvider",
			to_regclass(format('%I.%I', current_schema(), 'scimProvider'))::text AS "scimProvider",
			to_regclass(format('%I.%I', current_schema(), 'jwks'))::text AS jwks`);
		const tables = Object.freeze({
			ssoProvider: Boolean(tableResult.rows[0]?.ssoProvider),
			scimProvider: Boolean(tableResult.rows[0]?.scimProvider),
			jwks: Boolean(tableResult.rows[0]?.jwks),
		});
		const setup = await query<{
			name: string;
			columnsReady: boolean;
			triggerReady: boolean;
		}>(`WITH expected(name, table_name, column_name, trigger_name, function_name, function_body) AS (
			VALUES
				('oidcClientSecrets', 'ssoProvider', 'oidcConfig', 'clearance_require_oidc_key_v1', 'clearance_require_oidc_key_v1', $1::text),
				('scimTokens', 'scimProvider', 'scimToken', 'clearance_require_scim_key_v1', 'clearance_require_scim_key_v1', $2::text),
				('jwks', 'jwks', 'privateKey', 'clearance_require_jwt_key_v1', 'clearance_require_jwt_key_v1', $3::text)
		)
		SELECT expected.name,
			CASE WHEN to_regclass(format('%I.%I', current_schema(), expected.table_name)) IS NULL THEN true
			ELSE (
				SELECT count(*) = 2 AND bool_and(data_type = 'integer' AND udt_name = 'int4')
				FROM information_schema.columns
				WHERE table_schema = current_schema() AND table_name = expected.table_name
				AND column_name IN ('keyManagementVersion', 'keyManagementRevision')
			) END AS "columnsReady",
			CASE WHEN to_regclass(format('%I.%I', current_schema(), expected.table_name)) IS NULL THEN true
			ELSE EXISTS (
				SELECT 1 FROM pg_trigger trigger_record
				JOIN pg_class table_record ON table_record.oid = trigger_record.tgrelid
				JOIN pg_namespace namespace_record ON namespace_record.oid = table_record.relnamespace
				JOIN pg_proc function_record ON function_record.oid = trigger_record.tgfoid
				WHERE namespace_record.nspname = current_schema()
				AND table_record.relname = expected.table_name
				AND trigger_record.tgname = expected.trigger_name
				AND NOT trigger_record.tgisinternal
				AND trigger_record.tgenabled = 'O'
				AND trigger_record.tgtype = 23::smallint
				AND array_length(trigger_record.tgattr::smallint[], 1) = 1
				AND array_to_string(trigger_record.tgattr::smallint[], ',') = (
					SELECT attribute_record.attnum::text FROM pg_attribute attribute_record
					WHERE attribute_record.attrelid = table_record.oid
					AND attribute_record.attname = expected.column_name
					AND NOT attribute_record.attisdropped
				)
				AND function_record.proname = expected.function_name
				AND function_record.pronargs = 0
				AND function_record.prorettype = 'trigger'::regtype
				AND function_record.prosrc = expected.function_body
			) END AS "triggerReady"
		FROM expected`, [
			OIDC_KEY_MANAGEMENT_TRIGGER_BODY,
			SCIM_KEY_MANAGEMENT_TRIGGER_BODY,
			JWKS_KEY_MANAGEMENT_TRIGGER_BODY,
		]);
		const setupReady = setup.rows.every(
			(row) => row.columnsReady && row.triggerReady,
		);

		const readDomain = async (
			domain: KeyManagementMigrationDomain,
		): Promise<Readonly<{ pending: number; migrated: number; snapshots: readonly MigrationSnapshot[] }>> => {
			if (
				(domain === "oidcClientSecrets" && !tables.ssoProvider) ||
				(domain === "scimTokens" && !tables.scimProvider) ||
				(domain === "jwks" && !tables.jwks)
			) return { pending: 0, migrated: 0, snapshots: [] };
			const table = domain === "oidcClientSecrets" ? '"ssoProvider"' : domain === "scimTokens" ? '"scimProvider"' : "jwks";
			const source = domain === "oidcClientSecrets" ? '"oidcConfig"' : domain === "scimTokens" ? '"scimToken"' : '"privateKey"';
			const eligible = domain === "oidcClientSecrets" ? `WHERE ${source} IS NOT NULL` : "";
			const markerReady = setup.rows.find((row) => row.name === domain)?.columnsReady === true;
			const pendingWhere = markerReady
				? `${eligible ? `${eligible} AND` : "WHERE"} ("keyManagementVersion" IS DISTINCT FROM 1 OR "keyManagementRevision" IS NULL)`
				: eligible;
			const migratedWhere = markerReady
				? `${eligible ? `${eligible} AND` : "WHERE"} "keyManagementVersion" = 1 AND "keyManagementRevision" IS NOT NULL`
				: "WHERE false";
			const counts = await query<{ pending: string; migrated: string }>(`SELECT
				(SELECT count(*)::text FROM ${table} ${pendingWhere}) AS pending,
				(SELECT count(*)::text FROM ${table} ${migratedWhere}) AS migrated`);
			const rows = await query<{
				id: string;
				version: number | null;
				revision: number | null;
				source: string;
				providerId?: string;
				organizationId?: string | null;
				publicKey?: string;
				expiresAt?: Date | null;
			}>(`SELECT id, ${markerReady ? '"keyManagementVersion"' : "NULL::integer"} AS version,
				${markerReady ? '"keyManagementRevision"' : "NULL::integer"} AS revision,
				${source} AS source,
				${domain === "oidcClientSecrets" || domain === "scimTokens" ? '"providerId"' : "NULL::text"} AS "providerId",
				${domain === "scimTokens" ? '"organizationId"' : "NULL::text"} AS "organizationId",
				${domain === "jwks" ? '"publicKey"' : "NULL::text"} AS "publicKey",
				${domain === "jwks" ? '"expiresAt"' : "NULL::timestamptz"} AS "expiresAt"
				FROM ${table} ${pendingWhere} ORDER BY id
				LIMIT ${KEY_MANAGEMENT_MIGRATION_BATCH_SIZE}`);
			return Object.freeze({
				pending: Number(counts.rows[0]?.pending ?? 0),
				migrated: Number(counts.rows[0]?.migrated ?? 0),
				snapshots: Object.freeze(rows.rows.map((row) => canonicalSnapshot(domain, row))),
			});
		};
		const oidcClientSecrets = await readDomain("oidcClientSecrets");
		const scimTokens = await readDomain("scimTokens");
		const jwks = await readDomain("jwks");
		return Object.freeze({
			tables,
			setupReady,
			pending: keyManagementMigrationCounts(
				oidcClientSecrets.pending,
				scimTokens.pending,
				jwks.pending,
			),
			migrated: keyManagementMigrationCounts(
				oidcClientSecrets.migrated,
				scimTokens.migrated,
				jwks.migrated,
			),
			batch: Object.freeze({
				oidcClientSecrets: oidcClientSecrets.snapshots,
				scimTokens: scimTokens.snapshots,
				jwks: jwks.snapshots,
			}),
			snapshots: Object.freeze({
				oidcClientSecrets: oidcClientSecrets.snapshots,
				scimTokens: scimTokens.snapshots,
				jwks: jwks.snapshots,
			}),
		});
	}

	function keyManagementMigrationPlanFromInspection(
		inspection: KeyManagementMigrationInspection,
	): ClearanceKeyManagementMigrationPlan {
		const phase = !inspection.setupReady
			? "setup"
			: inspection.pending.total > 0
				? "batch"
				: "complete";
		const nextBatch = keyManagementMigrationCounts(
			inspection.batch.oidcClientSecrets.length,
			inspection.batch.scimTokens.length,
			inspection.batch.jwks.length,
		);
		const planId = sourceDigest(JSON.stringify({
			schemaVersion: "v1",
			scope: keyManagementFacade.scope,
			setupReady: inspection.setupReady,
			tables: inspection.tables,
			pending: inspection.pending,
			migrated: inspection.migrated,
			writeAuthority: configuredKeyManagementWriteAuthority(),
			snapshots: inspection.snapshots,
		}));
		return Object.freeze({
			schemaVersion: "v1",
			scope: keyManagementFacade.scope,
			phase,
			maxBatchSize: Object.freeze({ perDomain: 5, total: 15 }),
			pending: inspection.pending,
			nextBatch,
			planId,
		});
	}

	async function keyManagementMigrationPlan(
		transaction?: KeyManagementQuery,
	): Promise<ClearanceKeyManagementMigrationPlan> {
		return keyManagementMigrationPlanFromInspection(
			await inspectKeyManagementMigration(transaction),
		);
	}

	type KeyManagementReadinessEvidence = Readonly<{
		encryption: Awaited<ReturnType<typeof keyManagementFacade.readiness>>;
		signing: Awaited<ReturnType<typeof keyManagement.signingProvider.readiness>>;
	}>;
	async function keyManagementReadinessEvidence(): Promise<KeyManagementReadinessEvidence> {
		let encryption: Awaited<ReturnType<typeof keyManagementFacade.readiness>>;
		let signing: Awaited<ReturnType<typeof keyManagement.signingProvider.readiness>>;
		try {
			[encryption, signing] = await Promise.all([
				keyManagementFacade.readiness(),
				keyManagement.signingProvider.readiness(),
			]);
		} catch {
			throw keyManagementProviderNotReady();
		}
		return Object.freeze({ encryption, signing });
	}
	function keyManagementStatusFromInspection(
		inspection: KeyManagementMigrationInspection,
		evidence: KeyManagementReadinessEvidence,
	): ClearanceKeyManagementStatus {
		const { encryption, signing: signingReadiness } = evidence;
		const currentIdentity = keyManagement.signingProvider.currentKeyId;
		const retainedIdentities = Object.freeze(
			[...keyManagement.signingProvider.retainedKeyIds]
				.sort(),
		);
		return Object.freeze({
			schemaVersion: "v1",
			scope: keyManagementFacade.scope,
			ready:
				encryption.ready &&
				signingReadiness.ready &&
				inspection.setupReady &&
				inspection.pending.total === 0,
			encryption: Object.freeze({ ready: encryption.ready, purposes: encryption.purposes }),
			signing: Object.freeze({
				ready: signingReadiness.ready,
				readiness: signingReadiness,
				algorithm: "ES256",
				currentIdentity,
				retainedIdentities,
				gracePeriodSeconds: authenticationSecurity.asymmetricAccessTokens.gracePeriodSeconds,
			}),
			schema: Object.freeze({ setup: inspection.setupReady ? "ready" : "pending" }),
			migration: Object.freeze({
				complete: inspection.setupReady && inspection.pending.total === 0,
				pending: inspection.pending,
				migrated: inspection.migrated,
			}),
		});
	}
	async function keyManagementStatus(
		transaction?: KeyManagementQuery,
	): Promise<ClearanceKeyManagementStatus> {
		const [inspection, evidence] = await Promise.all([
			inspectKeyManagementMigration(transaction),
			keyManagementReadinessEvidence(),
		]);
		return keyManagementStatusFromInspection(inspection, evidence);
	}

	async function assertKeyManagementMigrationReady(): Promise<KeyManagementReadinessEvidence> {
		const evidence = await keyManagementReadinessEvidence();
		if (!evidence.encryption.ready || !evidence.signing.ready) {
			throw keyManagementProviderNotReady();
		}
		return evidence;
	}
	async function requireKeyManagementMigrationTransaction(
		transaction: ClearanceTransactionQuery,
	): Promise<void> {
		const before = await transaction.rawTransactionQuery<{ txid: string }>(
			"SELECT txid_current()::text AS txid",
		);
		await transaction.rawTransactionQuery(`SELECT pg_advisory_xact_lock(
			hashtext(current_database()),
			hashtext(current_schema() || ':clearance:key-management-migration:v1')
		)`);
		const after = await transaction.rawTransactionQuery<{ txid: string }>(
			"SELECT txid_current()::text AS txid",
		);
		if (!before.rows[0]?.txid || before.rows[0].txid !== after.rows[0]?.txid) {
			throw keyManagementTransactionRequired();
		}
	}

	async function applyKeyManagementMigration(input: {
		expectedPlanId: string;
		transaction: ClearanceTransactionQuery;
	}): Promise<ClearanceKeyManagementMigrationResult> {
		if (!input.expectedPlanId || typeof input.transaction?.rawTransactionQuery !== "function") {
			throw Object.assign(new Error("Key management migration input is invalid"), {
				code: "KEY_MANAGEMENT_INPUT_INVALID",
			});
		}
		const readinessEvidence = await assertKeyManagementMigrationReady();
		const transaction = input.transaction;
		await requireKeyManagementMigrationTransaction(transaction);
		const inspection = await inspectKeyManagementMigration(transaction);
		const previousPlan = keyManagementMigrationPlanFromInspection(inspection);
		if (previousPlan.planId !== input.expectedPlanId) {
			throw staleKeyManagementPlan();
		}
		let applied = zeroKeyManagementMigrationCounts();
		if (previousPlan.phase === "setup") {
			await migratePurposeSeparatedCredentialBatch(true, transaction);
			if (previousPlan.nextBatch.total > 0) {
				applied = await migratePurposeSeparatedCredentialBatch(
					false,
					transaction,
					inspection.batch,
				);
			}
		} else if (previousPlan.phase === "batch") {
			applied = await migratePurposeSeparatedCredentialBatch(
				false,
				transaction,
				inspection.batch,
			);
		}
		const remainingInspection = await inspectKeyManagementMigration(transaction);
		const remainingPlan = keyManagementMigrationPlanFromInspection(remainingInspection);
		const status = keyManagementStatusFromInspection(
			remainingInspection,
			readinessEvidence,
		);
		return Object.freeze({
			applied,
			changed: applied.total,
			previousPlanId: previousPlan.planId,
			nextPlanId: remainingPlan.planId,
			remainingPlan,
			status,
			complete: remainingPlan.phase === "complete",
		});
	}

	async function ensurePurposeSeparatedCredentialCompatibility(): Promise<void> {
		await assertKeyManagementMigrationReady();
		await migratePurposeSeparatedCredentialBatch(true);
		while ((await migratePurposeSeparatedCredentialBatch(false)).total > 0) {
			// Each transaction advances at most five rows per credential table.
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
	const authenticationPolicyFacade = authenticationPolicyAuthority
		? Object.freeze({
				scope: authenticationPolicyAuthority.identity,
				get: authenticationPolicyAuthority.get.bind(authenticationPolicyAuthority),
				plan: authenticationPolicyAuthority.plan.bind(authenticationPolicyAuthority),
				apply: authenticationPolicyAuthority.apply.bind(authenticationPolicyAuthority),
				planUnlock:
					authenticationPolicyAuthority.planUnlock.bind(authenticationPolicyAuthority),
				unlock: authenticationPolicyAuthority.unlock.bind(authenticationPolicyAuthority),
			})
		: undefined;
	const authorizationFacade: ClearanceAuthorizationFacade | undefined =
		authorizationAuthority
			? Object.freeze({
					scope: authorizationAuthority.identity,
					acquireMutationLock:
						authorizationAuthority.acquireMutationLock.bind(authorizationAuthority),
					reconcileRuntimeOrganizations:
						authorizationAuthority.reconcileRuntimeOrganizations.bind(authorizationAuthority),
					readEffective:
						authorizationAuthority.readEffective.bind(authorizationAuthority),
					initializeOrganization:
						authorizationAuthority.initializeOrganization.bind(authorizationAuthority),
					archiveOrganization:
						authorizationAuthority.archiveOrganization.bind(authorizationAuthority),
					upsertRole:
						authorizationAuthority.upsertRole.bind(authorizationAuthority),
					replaceSubjectRoles:
						authorizationAuthority.replaceSubjectRoles.bind(authorizationAuthority),
					listRoles:
						authorizationAuthority.listRoles.bind(authorizationAuthority),
					listSubjectAssignments:
						authorizationAuthority.listSubjectAssignments.bind(authorizationAuthority),
					createServiceAccount:
						authorizationAuthority.createServiceAccount.bind(authorizationAuthority),
					listServiceAccounts:
						authorizationAuthority.listServiceAccounts.bind(authorizationAuthority),
					setServiceAccountStatus:
						authorizationAuthority.setServiceAccountStatus.bind(authorizationAuthority),
					createServiceAccountCredential:
						authorizationAuthority.createServiceAccountCredential.bind(authorizationAuthority),
					rotateServiceAccountCredential:
						authorizationAuthority.rotateServiceAccountCredential.bind(authorizationAuthority),
					revokeServiceAccountCredential:
						authorizationAuthority.revokeServiceAccountCredential.bind(authorizationAuthority),
					authenticateServiceAccountCredential:
						authorizationAuthority.authenticateServiceAccountCredential.bind(authorizationAuthority),
				})
			: undefined;
	const passwordSetupFacade = Object.freeze({
		async create(input: { userId: string; token: string; expiresAt: Date }) {
			const identifier = `reset-password:${input.token}`;
			const authContext = await auth.$context;
			await createInternalVerificationChallengeAuthority().create(
				authContext.internalAdapter,
				{ purpose: "password-reset", subject: identifier },
				{
					identifier,
					value: input.userId,
					expiresAt: input.expiresAt,
				},
			);
		},
	});

	return {
		auth: auth as unknown as ClearanceProductAuthRuntime<Security, Passkeys>,
		pool,
		db,
		credentialAuthority: credentialAuthorityFacade,
		keyManagement: keyManagementFacade,
		...(authenticationPolicyFacade
			? { authenticationPolicy: authenticationPolicyFacade }
			: {}),
		...(authorizationFacade ? { authorization: authorizationFacade } : {}),
		passwordSetup: passwordSetupFacade,
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
			const [runtimePlan, policyPlan, auditPlan, authorizationPlan] = await Promise.all([
				runtimeMigrationPlanFor(),
				authenticationPolicyAuthority?.planMigration(),
				runtimeAuditOutbox?.planMigration(),
				authorizationAuthority?.planMigration(),
			]);
			const plan = combineMigrationPlans(
				runtimePlan,
				policyPlan,
				auditPlan,
				authorizationPlan,
			);
			const apply = async () => {
				await runtimePlan.apply();
				await ensureAuthenticationSecurityCompatibility();
				await ensureLifecycleCompatibility();
				await ensurePurposeSeparatedCredentialCompatibility();
				await auditPlan?.apply();
				await authorizationPlan?.apply();
				if (options.durableDelivery) {
					await migrateDeliverySchema(pool, {
						schema: options.durableDelivery.schema,
						prefix: options.durableDelivery.prefix,
						legacyFingerprintKeyId:
							options.durableDelivery.legacyFingerprintKeyId,
					});
				}
				await policyPlan?.apply();
			};
			const state = await credentialAuthority.status();
			if (
				state.phase === "digest-live" &&
				runtimePlan.pendingSecurityMigrations.length > 0
			) {
				throw new Error(
					`Credential authority markers conflict with the durable digest-live generation: ${runtimePlan.pendingSecurityMigrations.join(", ")}`,
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
							const leasePlan = await runtimeMigrationPlanFor(
								leaseDatabase,
								drainId,
							);
							await leasePlan.apply();
							await ensureAuthenticationSecurityCompatibility();
							await ensureLifecycleCompatibility();
							await ensurePurposeSeparatedCredentialCompatibility();
							if (runtimeAuditOutbox) {
								await runtimeAuditOutbox.applyMigration(leaseClient);
							}
							await authorizationPlan?.apply();
							if (options.durableDelivery) {
								await migrateDeliverySchema(pool, {
									schema: options.durableDelivery.schema,
									prefix: options.durableDelivery.prefix,
									legacyFingerprintKeyId:
										options.durableDelivery.legacyFingerprintKeyId,
								});
							}
							await policyPlan?.apply();
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
			const settled = await Promise.allSettled([
				credentialAuthority.close(),
				pool.end(),
			]);
			const failures = settled
				.filter(
					(result): result is PromiseRejectedResult =>
						result.status === "rejected",
				)
				.map((result) => result.reason);
			if (failures.length === 1) throw failures[0];
			if (failures.length > 1) {
				throw new AggregateError(failures, "Clearance auth teardown failed");
			}
		},
	};
}

/**
 * Typed server-only bootstrap for the management package. Keeping the tenant
 * facade on this entry point avoids weakening the normal product options while
 * removing bootstrap casts across the package boundary.
 */
export function createClearanceManagementAuth(
	options: ClearanceManagementAuthOptions,
): ClearanceAuthBundle {
	const {
		tenantProductAdministration,
		managedOrganizationLifecycle,
		...publicOptions
	} = options;
	return createClearanceAuthWithTenantProductAdministration(
		publicOptions,
		tenantProductAdministration,
		managedOrganizationLifecycle,
	) as unknown as ClearanceAuthBundle;
}
