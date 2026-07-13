import { resolve } from "node:path";
import { JsonStore, defaultDataPath } from "./json-store.js";
import { createPgStore, type PgStore } from "./pg-store.js";
import type { ManagementStore } from "./types.js";

export type CreateStoreOptions = {
	/** Explicit file path for JSON backend */
	dataPath?: string;
	/** Force backend; default chooses postgres when DATABASE_URL is set */
	backend?: "json" | "postgres" | "auto";
	databaseUrl?: string;
};

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
		return createPgStore(databaseUrl);
	}

	const path = opts.dataPath
		? resolve(opts.dataPath)
		: process.env.CLEARANCE_DATA_PATH
			? resolve(process.env.CLEARANCE_DATA_PATH)
			: defaultDataPath();
	return new JsonStore(path);
}

export type { PgStore };
