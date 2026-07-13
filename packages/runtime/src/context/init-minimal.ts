import type { ClearanceOptions } from "@clearance/core";
import { ClearanceError } from "@clearance/core/error";
import { getBaseAdapter } from "../db/adapter-base";
import { createAuthContext } from "./create-context";

export const initMinimal = async (options: ClearanceOptions) => {
	const adapter = await getBaseAdapter(options, async () => {
		throw new ClearanceError(
			"Direct database connection requires Kysely. Please use `clearance` instead of `clearance/minimal`, or provide an adapter (drizzleAdapter, prismaAdapter, etc.)",
		);
	});

	// Without Kysely, we can't detect database type, so always return "unknown"
	const getDatabaseType = (_database: ClearanceOptions["database"]) =>
		"unknown";

	// Use base context creation
	const ctx = await createAuthContext(adapter, options, getDatabaseType);

	// Add runMigrations that throws error (migrations require Kysely)
	ctx.runMigrations = async function () {
		throw new ClearanceError(
			"Migrations are not supported in 'clearance/minimal'. Please use 'clearance' for migration support.",
		);
	};

	return ctx;
};
