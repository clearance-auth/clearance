import {
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../test-utils/test-instance";

const hasPostgres = Boolean(
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
		process.env.CLEARANCE_TEST_DATABASE_URL,
);

describe.skipIf(!hasPostgres)("verification reservation PostgreSQL authority", () => {
	it.each(["serial", "uuid"] as const)(
		"keeps a losing %s reservation transaction usable and rolls winners back",
		async (generateId) => {
			const { auth } = await getTestInstance(
				{
					advanced: { database: { generateId } },
					logger: { level: "error" },
				},
				{ disableTestUser: true, testWith: "postgres" },
			);
			const context = await auth.$context;
			const expiresAt = new Date(Date.now() + 60_000);
			const committed = {
				identifier: `postgres-reservation-committed-${generateId}`,
				value: "opaque-committed-value",
				expiresAt,
			};

			await expect(
				context.internalAdapter.reserveVerificationValue(committed),
			).resolves.toBe(true);
			await expect(
				runWithTransaction(context.adapter, async () => {
					expect(
						await context.internalAdapter.reserveVerificationValue(committed),
					).toBe(false);
					const transaction = await getCurrentAdapter(context.adapter);
					const rows = await transaction.findMany<Record<string, unknown>>({
						model: "securityMigration",
						where: [
							{ field: "state", value: "verification-reservation-v1" },
						],
					});
					expect(rows).toHaveLength(1);
					return "transaction-remained-usable";
				}),
			).resolves.toBe("transaction-remained-usable");

			const rolledBack = {
				identifier: `postgres-reservation-rollback-${generateId}`,
				value: "opaque-rollback-value",
				expiresAt,
			};
			await expect(
				runWithTransaction(context.adapter, async () => {
					expect(
						await context.internalAdapter.reserveVerificationValue(rolledBack),
					).toBe(true);
					throw new Error("roll back reservation winner");
				}),
			).rejects.toThrow("roll back reservation winner");
			await expect(
				context.internalAdapter.reserveVerificationValue(rolledBack),
			).resolves.toBe(true);
		},
	);
});
