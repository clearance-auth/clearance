import type { ClearanceOptions } from "@clearance/core";
import type { DBAdapter } from "@clearance/core/db/adapter";
import { ClearanceError } from "@clearance/core/error";
import { getBaseAdapter } from "./adapter-base";

export async function getAdapter(
	options: ClearanceOptions,
): Promise<DBAdapter<ClearanceOptions>> {
	return getBaseAdapter(options, async (opts) => {
		const { createKyselyAdapter } = await import("../adapters/kysely-adapter");
		const { kysely, databaseType, transaction } =
			await createKyselyAdapter(opts);
		if (!kysely) {
			throw new ClearanceError("Failed to initialize database adapter");
		}
		const { kyselyAdapter } = await import("../adapters/kysely-adapter");
		return kyselyAdapter(kysely, {
			type: databaseType || "sqlite",
			debugLogs:
				opts.database && "debugLogs" in opts.database
					? opts.database.debugLogs
					: false,
			transaction: transaction,
		})(opts);
	});
}
