import type { ClearanceOptions } from "@clearance/core";
import { getAuthTables } from "@clearance/core/db";
import type { DBAdapter } from "@clearance/core/db/adapter";
import { logger } from "@clearance/core/env";
import type { MemoryDB } from "@clearance/memory-adapter";

export async function getBaseAdapter(
	options: ClearanceOptions,
	handleDirectDatabase: (
		options: ClearanceOptions,
	) => Promise<DBAdapter<ClearanceOptions>>,
): Promise<DBAdapter<ClearanceOptions>> {
	let adapter: DBAdapter<ClearanceOptions>;

	if (!options.database) {
		const tables = getAuthTables(options);
		const memoryDB = Object.keys(tables).reduce<MemoryDB>((acc, key) => {
			acc[key] = [];
			return acc;
		}, {});
		const { memoryAdapter } = await import("@clearance/memory-adapter");
		adapter = memoryAdapter(memoryDB)(options);
	} else if (typeof options.database === "function") {
		adapter = options.database(options);
	} else {
		adapter = await handleDirectDatabase(options);
	}

	// patch for 1.3.x to ensure we have a transaction function in the adapter
	if (!adapter.transaction) {
		logger.warn(
			"Adapter does not correctly implement transaction function, patching it automatically. Please update your adapter implementation.",
		);
		adapter.transaction = async (cb) => {
			return cb(adapter);
		};
	}

	return adapter;
}
