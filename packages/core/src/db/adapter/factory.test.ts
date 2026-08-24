import { describe, expect, it, vi } from "vitest";
import { runWithTransaction } from "../../context/transaction";
import type { ClearanceOptions } from "../../types";
import { createAdapterFactory } from "./factory";
import type {
	CleanedWhere,
	CustomAdapter,
	DBAdapter,
	DBTransactionAdapter,
} from "./index";

function createCustomAdapter(overrides: Partial<CustomAdapter>): CustomAdapter {
	return {
		create: async <T extends Record<string, any>>({ data }: { data: T }) =>
			data,
		update: async <T>() => null as T | null,
		updateMany: async () => 0,
		findOne: async <T>() => null as T | null,
		findMany: async <T>() => [] as T[],
		delete: async () => {},
		deleteMany: async () => 0,
		count: async () => 0,
		...overrides,
	};
}

function createTestAdapter({
	adapter,
	options = {},
	transaction,
	debugLogs,
}: {
	adapter: CustomAdapter;
	options?: ClearanceOptions;
	transaction?: <R>(
		callback: (trx: DBTransactionAdapter<ClearanceOptions>) => Promise<R>,
	) => Promise<R>;
	debugLogs?: { isRunningAdapterTests: boolean };
}) {
	return createAdapterFactory<ClearanceOptions>({
		config: {
			adapterId: "test-adapter",
			adapterName: "Test Adapter",
			usePlural: true,
			customTransformInput({ action, data, field }) {
				if (field === "identifier_text" && typeof data === "string") {
					return `${data}:${action}`;
				}
				return data;
			},
			customTransformOutput({ data, field }) {
				if (field === "identifier" && typeof data === "string") {
					return `${data}:output`;
				}
				return data;
			},
			transaction,
			debugLogs,
		},
		adapter: () => adapter,
	})({
		...options,
		verification: {
			modelName: "verificationRecord",
			fields: {
				identifier: "identifier_text",
			},
			...options.verification,
		},
	});
}

function serializedAdapterDebugLogs(adapter: DBAdapter<ClearanceOptions>) {
	const debugLogs = (adapter as DBAdapter<ClearanceOptions> & {
		adapterTestDebugLogs: {
			resetDebugLogs: () => void;
			printDebugLogs: () => void;
		};
	}).adapterTestDebugLogs;
	const consoleLog = vi.spyOn(console, "log").mockImplementation(() => {});
	try {
		debugLogs.printDebugLogs();
		return JSON.stringify(consoleLog.mock.calls);
	} finally {
		consoleLog.mockRestore();
		debugLogs.resetDebugLogs();
	}
}

describe("createAdapterFactory debug-log redaction", () => {
	it.each(["legacy-v1", "digest-v1"])(
		"does not serialize credential material for %s session operations",
		async (generation) => {
			const sentinels = {
				token: `${generation}-live-bearer-token`,
				password: `${generation}-password-hash`,
				secret: `${generation}-verification-otp`,
				key: `${generation}-key-material`,
			};
			const isDigest = generation === "digest-v1";
			const model = isDigest ? "sessionCredential" : "session";
			const predicateField = isDigest ? "secretDigest" : "token";
			const data = isDigest
				? {
						selector: "credential-selector",
						familyId: "credential-family",
						secretDigest: sentinels.token,
						digestVersion: 1,
						status: "active",
						expiresAt: new Date("2030-01-01T00:00:00.000Z"),
						keyMaterial: sentinels.key,
					}
				: {
						userId: "user-id",
						expiresAt: new Date("2030-01-01T00:00:00.000Z"),
						token: sentinels.token,
						password: sentinels.password,
						verificationSecret: sentinels.secret,
						keyMaterial: sentinels.key,
					};
			const adapter = createTestAdapter({
				debugLogs: { isRunningAdapterTests: true },
				adapter: createCustomAdapter({
					findOne: async <T>() =>
						({
							id: "session-id",
							token: sentinels.token,
							password: sentinels.password,
							verificationSecret: sentinels.secret,
							keyMaterial: sentinels.key,
						}) as T,
					update: async <T>() =>
						({
							id: "session-id",
							token: sentinels.token,
							password: sentinels.password,
						}) as T,
				}),
			});

			await adapter.create({
				model,
				data,
			});
			await adapter.findOne({
				model,
				where: [{ field: predicateField, value: sentinels.token }],
			});
			await adapter.findOne({
				model: "verification",
				where: [{ field: "value", value: sentinels.secret }],
			});
			await adapter.update({
				model,
				where: [{ field: predicateField, value: sentinels.token }],
				update: isDigest
					? { secretDigest: sentinels.token, keyMaterial: sentinels.key }
					: { token: sentinels.token, password: sentinels.password },
			});
			await adapter.delete({
				model,
				where: [{ field: predicateField, value: sentinels.token }],
			});

			const serialized = serializedAdapterDebugLogs(adapter);
			for (const sentinel of Object.values(sentinels)) {
				expect(serialized).not.toContain(sentinel);
			}
			expect(serialized).toContain(
				isDigest ? '"model":"sessionCredentials"' : '"model":"sessions"',
			);
			expect(serialized).toContain('"predicateCount":1');
			expect(serialized).toContain(
				`"fields":["${predicateField}"]`,
			);
		},
	);
});

describe("createAdapterFactory consumeOne fallback", () => {
	it("uses transaction adapter methods without double-transforming input or output", async () => {
		const findMany: CustomAdapter["findMany"] = async <T>(
			params: Parameters<CustomAdapter["findMany"]>[0],
		) => {
			const { model, where, limit } = params;
			expect(model).toBe("verificationRecords");
			expect(limit).toBe(1);
			expect(where).toEqual([
				{
					field: "identifier_text",
					value: "token:findMany",
					operator: "eq",
					connector: "AND",
					mode: "sensitive",
				},
			]);
			return [
				{
					id: "verification-id",
					identifier_text: "stored-token",
				},
			] as T[];
		};
		const deleteMany: CustomAdapter["deleteMany"] = async ({
			model,
			where,
		}) => {
			expect(model).toBe("verificationRecords");
			expect(where).toEqual([
				{
					field: "identifier_text",
					value: "token:deleteMany",
					operator: "eq",
					connector: "AND",
					mode: "sensitive",
				},
				{
					field: "id",
					value: "verification-id",
					operator: "eq",
					connector: "AND",
					mode: "sensitive",
				},
			] satisfies CleanedWhere[]);
			return 1;
		};

		const adapter = createTestAdapter({
			adapter: createCustomAdapter({
				findMany,
				deleteMany,
			}),
		});

		const result = await adapter.consumeOne<{ id: string; identifier: string }>(
			{
				model: "verification",
				where: [{ field: "identifier", value: "token" }],
			},
		);

		expect(result?.id).toBe("verification-id");
		expect(result?.identifier).toBe("stored-token:output");
	});

	it("returns null when the delete loses the consume race", async () => {
		const adapter = createTestAdapter({
			adapter: createCustomAdapter({
				findMany: async <T>() =>
					[
						{
							id: "verification-id",
							identifier_text: "stored-token",
						},
					] as T[],
				deleteMany: async () => 0,
			}),
		});

		const result = await adapter.consumeOne({
			model: "verification",
			where: [{ field: "identifier", value: "token" }],
		});

		expect(result).toBeNull();
	});

	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	it("reuses the active transaction for the fallback", async () => {
		let transactionCalls = 0;
		let isTransactionActive = false;
		let adapter: DBAdapter<ClearanceOptions> | null = null;

		const transaction = async <R>(
			callback: (trx: DBTransactionAdapter<ClearanceOptions>) => Promise<R>,
		): Promise<R> => {
			transactionCalls += 1;
			if (isTransactionActive) {
				throw new Error("nested transaction");
			}
			if (!adapter) {
				throw new Error("adapter has not been initialized");
			}
			isTransactionActive = true;
			try {
				return await callback(adapter);
			} finally {
				isTransactionActive = false;
			}
		};

		adapter = createTestAdapter({
			transaction,
			adapter: createCustomAdapter({
				findMany: async <T>() =>
					[
						{
							id: "verification-id",
							identifier_text: "stored-token",
						},
					] as T[],
				deleteMany: async () => 1,
			}),
		});

		const result = await runWithTransaction(adapter, async () =>
			adapter!.consumeOne<{ id: string; identifier: string }>({
				model: "verification",
				where: [{ field: "identifier", value: "token" }],
			}),
		);

		expect(result?.id).toBe("verification-id");
		expect(transactionCalls).toBe(1);
	});

	it("throws when deleteMany returns a non-numeric value", async () => {
		const adapter = createTestAdapter({
			adapter: createCustomAdapter({
				findMany: async <T>() =>
					[
						{
							id: "verification-id",
							identifier_text: "stored-token",
						},
					] as T[],
				// A misbehaving adapter (e.g. a document store returning the raw
				// delete response) breaks the count-based race gate. The fallback
				// must surface this instead of reporting a spurious miss.
				deleteMany: async () => ({ deleted: true }) as unknown as number,
			}),
		});

		await expect(
			adapter.consumeOne({
				model: "verification",
				where: [{ field: "identifier", value: "token" }],
			}),
		).rejects.toThrowError(/non-numeric value from deleteMany/);
	});
});
