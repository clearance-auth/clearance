import type { SQLInputValue } from "node:sqlite";
import { DatabaseSync } from "node:sqlite";
import type { Generated } from "kysely";
import { Kysely } from "kysely";
import { describe, expect, it } from "vitest";
import { BunSqliteDialect } from "./bun-sqlite-dialect";
import { kyselyAdapter } from "./kysely-adapter";
import { NodeSqliteDialect } from "./node-sqlite-dialect";

interface UsersTable {
	id: Generated<number>;
	name: string;
	value: string;
}

interface TestDatabase {
	users: UsersTable;
}

function createSchema(db: DatabaseSync) {
	db.prepare(
		"CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, value TEXT)",
	).run();
}

/**
 * Minimal stand-in for a `bun:sqlite` `Database`. The Vitest runner cannot
 * import `bun:sqlite`, so the prepared-statement surface that
 * `BunSqliteConnection` relies on is reproduced on top of `node:sqlite`:
 * `columnNames` distinguishes row-producing statements, `all(params)` binds an
 * array, and `run(...params)` returns Bun's `{ changes, lastInsertRowid }`
 * change metadata.
 */
function asBunLikeDatabase(db: DatabaseSync) {
	return {
		prepare(sql: string) {
			const stmt = db.prepare(sql);
			return {
				get columnNames() {
					return stmt.columns().map((column) => column.name);
				},
				all(...params: SQLInputValue[]) {
					return stmt.all(...params);
				},
				run(...params: SQLInputValue[]) {
					return stmt.run(...params);
				},
			};
		},
		close() {
			db.close();
		},
	} as unknown as ConstructorParameters<typeof BunSqliteDialect>[0]["database"];
}

describe("NodeSqliteDialect mutation metadata", () => {
	it("binds multiple parameters and surfaces insert/update/delete metadata", async () => {
		const sqlite = new DatabaseSync(":memory:");
		createSchema(sqlite);
		const db = new Kysely<TestDatabase>({
			dialect: new NodeSqliteDialect({ database: sqlite }),
		});

		const insert = await db
			.insertInto("users")
			.values({ name: "alice", value: "first" })
			.executeTakeFirst();
		expect(insert.numInsertedOrUpdatedRows).toBe(1n);
		expect(insert.insertId).toBe(1n);

		// A multi-parameter predicate must still bind correctly.
		const found = await db
			.selectFrom("users")
			.selectAll()
			.where("name", "=", "alice")
			.where("value", "=", "first")
			.executeTakeFirst();
		expect(found?.name).toBe("alice");

		const update = await db
			.updateTable("users")
			.set({ value: "second" })
			.where("name", "=", "alice")
			.executeTakeFirst();
		expect(update.numUpdatedRows).toBe(1n);

		const remove = await db
			.deleteFrom("users")
			.where("name", "=", "alice")
			.executeTakeFirst();
		expect(remove.numDeletedRows).toBe(1n);

		await db.destroy();
	});

	it("keeps row results for RETURNING mutations", async () => {
		const sqlite = new DatabaseSync(":memory:");
		createSchema(sqlite);
		const db = new Kysely<TestDatabase>({
			dialect: new NodeSqliteDialect({ database: sqlite }),
		});

		const inserted = await db
			.insertInto("users")
			.values({ name: "bob", value: "x" })
			.returningAll()
			.executeTakeFirst();
		expect(inserted?.name).toBe("bob");

		await db.destroy();
	});
});

describe("BunSqliteDialect mutation metadata", () => {
	it("binds multiple parameters and surfaces insert/update/delete metadata", async () => {
		const sqlite = new DatabaseSync(":memory:");
		createSchema(sqlite);
		const db = new Kysely<TestDatabase>({
			dialect: new BunSqliteDialect({ database: asBunLikeDatabase(sqlite) }),
		});

		const insert = await db
			.insertInto("users")
			.values({ name: "alice", value: "first" })
			.executeTakeFirst();
		expect(insert.numInsertedOrUpdatedRows).toBe(1n);
		expect(insert.insertId).toBe(1n);

		const found = await db
			.selectFrom("users")
			.selectAll()
			.where("name", "=", "alice")
			.where("value", "=", "first")
			.executeTakeFirst();
		expect(found?.name).toBe("alice");

		const update = await db
			.updateTable("users")
			.set({ value: "second" })
			.where("name", "=", "alice")
			.executeTakeFirst();
		expect(update.numUpdatedRows).toBe(1n);

		const remove = await db
			.deleteFrom("users")
			.where("name", "=", "alice")
			.executeTakeFirst();
		expect(remove.numDeletedRows).toBe(1n);

		await db.destroy();
	});

	it("keeps row results for RETURNING mutations", async () => {
		const sqlite = new DatabaseSync(":memory:");
		createSchema(sqlite);
		const db = new Kysely<TestDatabase>({
			dialect: new BunSqliteDialect({ database: asBunLikeDatabase(sqlite) }),
		});

		const inserted = await db
			.insertInto("users")
			.values({ name: "bob", value: "x" })
			.returningAll()
			.executeTakeFirst();
		expect(inserted?.name).toBe("bob");

		await db.destroy();
	});
});

describe("Kysely SQLite createIfAbsent", () => {
	it("returns exactly one winner, preserves it, and rolls back with its caller", async () => {
		const sqlite = new DatabaseSync(":memory:");
		sqlite.exec(
			"CREATE TABLE claim (id TEXT PRIMARY KEY, claim_key TEXT NOT NULL UNIQUE, attempt_id TEXT NOT NULL, value TEXT NOT NULL)",
		);
		const db = new Kysely({
			dialect: new NodeSqliteDialect({ database: sqlite }),
		});
		const adapter = kyselyAdapter(db, {
			type: "sqlite",
			transaction: true,
		})({
			plugins: [
				{
					id: "claim-test",
					schema: {
						claim: {
							fields: {
								key: {
									type: "string",
									required: true,
									unique: true,
									fieldName: "claim_key",
								},
								attempt: {
									type: "string",
									required: true,
									fieldName: "attempt_id",
								},
								value: { type: "string", required: true },
							},
						},
					},
				},
			],
		} as any);

		const contenders = Array.from({ length: 12 }, (_, index) => ({
			id: `id-${index}`,
			key: "shared",
			attempt: `attempt-${index}`,
			value: `value-${index}`,
		}));
		const results = await Promise.all(
			contenders.map((data) =>
				adapter.createIfAbsent<typeof data>({
					model: "claim",
					data,
					uniqueBy: { field: "key", value: data.key },
					attemptBy: { field: "attempt", value: data.attempt },
					forceAllowId: true,
				}),
			),
		);
		const winners = results.filter((row) => row !== null);
		expect(winners).toHaveLength(1);
		const stored = await adapter.findOne<typeof contenders[number]>({
			model: "claim",
			where: [{ field: "key", value: "shared" }],
		});
		expect(stored).toEqual(winners[0]);

		const loser = await adapter.createIfAbsent({
			model: "claim",
			data: {
				id: "late-id",
				key: "shared",
				attempt: "late-attempt",
				value: "late-value",
			},
			uniqueBy: { field: "key", value: "shared" },
			attemptBy: { field: "attempt", value: "late-attempt" },
			forceAllowId: true,
		});
		expect(loser).toBeNull();
		expect(
			await adapter.findOne({
				model: "claim",
				where: [{ field: "key", value: "shared" }],
			}),
		).toEqual(stored);

		await expect(
			adapter.transaction(async (trx) => {
				await trx.createIfAbsent({
					model: "claim",
					data: {
						id: "rollback-id",
						key: "rollback",
						attempt: "rollback-attempt",
						value: "rollback-value",
					},
					uniqueBy: { field: "key", value: "rollback" },
					attemptBy: { field: "attempt", value: "rollback-attempt" },
					forceAllowId: true,
				});
				throw new Error("rollback");
			}),
		).rejects.toThrow("rollback");
		expect(
			await adapter.findOne({
				model: "claim",
				where: [{ field: "key", value: "rollback" }],
			}),
		).toBeNull();

		await db.destroy();
	});
});
