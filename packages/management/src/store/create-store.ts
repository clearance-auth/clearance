import { resolve } from "node:path";
import { JsonStore, defaultDataPath } from "./json-store.js";
import {
	createPgStore,
	type PgStore,
	type PgStoreDeliveryOptions,
} from "./pg-store.js";
import type { ManagementStore } from "./types.js";
import {
	DEFAULT_DELIVERY_QUOTA_POLICY,
	deliverySchemaName,
	deliveryTableNames,
	resolveDeliveryKeyring,
	type DeliveryQuotaPolicy,
} from "@clearance/delivery";

export type CreateStoreOptions = {
	/** Explicit file path for JSON backend */
	dataPath?: string;
	/** Force backend; default chooses postgres when DATABASE_URL is set */
	backend?: "json" | "postgres" | "auto";
	databaseUrl?: string;
	/** Optional encrypted outbox capability for coordinated Postgres mutations. */
	delivery?: PgStoreDeliveryOptions;
};

const DELIVERY_KEY_ENV = [
	"CLEARANCE_DELIVERY_KEY_ID",
	"CLEARANCE_DELIVERY_KEYS_JSON",
	"CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID",
	"CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON",
	"CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY",
] as const;

function quotaInteger(
	env: NodeJS.ProcessEnv,
	name: string,
	fallback: number,
	minimum: number,
	maximum: number,
): number {
	const raw = env[name]?.trim();
	if (!raw) return fallback;
	if (!/^[0-9]+$/.test(raw)) {
		throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
	}
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
		throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
	}
	return value;
}

/** Shared API/management producer configuration; absent unless any key signal is present. */
export function deliveryStoreOptionsFromEnvironment(
	env: NodeJS.ProcessEnv = process.env,
): PgStoreDeliveryOptions | undefined {
	if (!DELIVERY_KEY_ENV.some((name) => Boolean(env[name]?.trim()))) return undefined;
	const schema = env.CLEARANCE_DELIVERY_SCHEMA?.trim() || undefined;
	const prefix = env.CLEARANCE_DELIVERY_PREFIX?.trim() || undefined;
	const legacyFingerprintKeyId =
		env.CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID?.trim() || undefined;
	// Validate storage identifiers alongside keys so configuration fails before
	// a connection or mutation is attempted.
	deliverySchemaName(schema ? { schema } : {});
	deliveryTableNames(prefix ? { prefix } : {});
	if (
		legacyFingerprintKeyId !== undefined &&
		!/^[A-Za-z0-9._-]{1,64}$/.test(legacyFingerprintKeyId)
	) {
		throw new Error(
			"CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID must be a valid delivery key id",
		);
	}
	const quota: DeliveryQuotaPolicy = {
		maxActive: quotaInteger(
			env,
			"CLEARANCE_DELIVERY_QUOTA_MAX_ACTIVE",
			DEFAULT_DELIVERY_QUOTA_POLICY.maxActive,
			1,
			10_000_000,
		),
		maxBacklog: quotaInteger(
			env,
			"CLEARANCE_DELIVERY_QUOTA_MAX_BACKLOG",
			DEFAULT_DELIVERY_QUOTA_POLICY.maxBacklog,
			1,
			10_000_000,
		),
		maxEnqueuesPerWindow: quotaInteger(
			env,
			"CLEARANCE_DELIVERY_QUOTA_MAX_ENQUEUES_PER_WINDOW",
			DEFAULT_DELIVERY_QUOTA_POLICY.maxEnqueuesPerWindow,
			1,
			10_000_000,
		),
		windowMs: quotaInteger(
			env,
			"CLEARANCE_DELIVERY_QUOTA_WINDOW_MS",
			DEFAULT_DELIVERY_QUOTA_POLICY.windowMs,
			1_000,
			86_400_000,
		),
	};
	return {
		keyring: resolveDeliveryKeyring(env),
		quota,
		...(schema ? { schema } : {}),
		...(prefix ? { prefix } : {}),
		...(legacyFingerprintKeyId ? { legacyFingerprintKeyId } : {}),
	};
}

/**
 * Open the management store.
 * - DATABASE_URL set → Postgres is the single transactional source of truth
 * - otherwise → local JSON file (developer quick path)
 */
export async function createManagementStore(
	opts: CreateStoreOptions = {},
): Promise<ManagementStore> {
	const rawUrl = opts.databaseUrl ?? process.env.DATABASE_URL;
	const databaseUrl = rawUrl?.trim() ? rawUrl.trim() : undefined;
	const mode = opts.backend ?? "auto";
	const usePostgres =
		mode === "postgres" || (mode === "auto" && Boolean(databaseUrl));

	if (usePostgres) {
		if (!databaseUrl) {
			throw new Error(
				"Postgres management store requires DATABASE_URL (or opts.databaseUrl)",
			);
		}
		return createPgStore(databaseUrl, {
			...(opts.delivery ? { delivery: opts.delivery } : {}),
		});
	}

	const path = opts.dataPath
		? resolve(opts.dataPath)
		: process.env.CLEARANCE_DATA_PATH
			? resolve(process.env.CLEARANCE_DATA_PATH)
			: defaultDataPath();
	return new JsonStore(path);
}

export type { PgStore };
