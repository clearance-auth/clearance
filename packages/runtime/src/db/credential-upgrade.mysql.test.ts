import { randomUUID } from "node:crypto";
import type { ClearanceOptions } from "@clearance/core";
import { Kysely, MysqlDialect } from "kysely";
import { createPool } from "mysql2";
import { describe, expect, it } from "vitest";
import { getMigrations } from "./get-migration";

const engines = [
	["MySQL", process.env.CLEARANCE_TEST_MYSQL_URL],
	["MariaDB", process.env.CLEARANCE_TEST_MARIADB_URL],
] as const;

const quote = (value: string) => `\`${value.replaceAll("`", "``")}\``;

describe.each(engines)("public legacy credential upgrade on %s", (_engine, url) => {
	it.skipIf(!url)(
		"refuses existing bearer authority without a database-native product fence",
		async () => {
			const databaseName = `credential_refusal_${randomUUID().replaceAll("-", "")}`;
			const adminPool = createPool(url!);
			const databaseURL = new URL(url!);
			databaseURL.pathname = `/${databaseName}`;
			await adminPool.promise().query(`CREATE DATABASE ${quote(databaseName)}`);
			const driverPool = createPool(databaseURL.toString());
			const db = new Kysely<any>({
				dialect: new MysqlDialect({ pool: driverPool }),
			});
			const token = `legacy-session-${randomUUID()}`;
			try {
				await db.schema
					.createTable("user")
					.addColumn("id", "varchar(255)", (column) => column.primaryKey())
					.addColumn("name", "text", (column) => column.notNull())
					.addColumn("email", "varchar(255)", (column) => column.notNull().unique())
					.addColumn("emailVerified", "boolean", (column) => column.notNull())
					.addColumn("createdAt", "datetime(3)", (column) => column.notNull())
					.addColumn("updatedAt", "datetime(3)", (column) => column.notNull())
					.execute();
				await db.schema
					.createTable("session")
					.addColumn("id", "varchar(255)", (column) => column.primaryKey())
					.addColumn("expiresAt", "datetime(3)", (column) => column.notNull())
					.addColumn("createdAt", "datetime(3)", (column) => column.notNull())
					.addColumn("updatedAt", "datetime(3)", (column) => column.notNull())
					.addColumn("userId", "varchar(255)", (column) => column.notNull())
					.addColumn("token", "varchar(255)", (column) => column.notNull().unique())
					.execute();
				const now = new Date();
				await db
					.insertInto("user")
					.values({
						id: "legacy-user",
						name: "Legacy user",
						email: "legacy@example.test",
						emailVerified: true,
						createdAt: now,
						updatedAt: now,
					})
					.execute();
				await db
					.insertInto("session")
					.values({
						id: "legacy-session",
						expiresAt: new Date(now.getTime() + 60_000),
						createdAt: now,
						updatedAt: now,
						userId: "legacy-user",
						token,
					})
					.execute();
				const options: ClearanceOptions = {
					database: { db, type: "mysql", transaction: true },
					secret: "mysql-public-migration-refusal-secret",
					emailAndPassword: { enabled: true },
					logger: { level: "error" },
				};
				await expect((await getMigrations(options)).runMigrations()).rejects.toThrow(
					"database-native product drain fence",
				);
				const unchanged = await db
					.selectFrom("session")
					.select("token")
					.where("id", "=", "legacy-session")
					.executeTakeFirst();
				expect(unchanged?.token).toBe(token);
			} finally {
				await db.destroy();
				await adminPool.promise().query(`DROP DATABASE IF EXISTS ${quote(databaseName)}`);
				await adminPool.promise().end();
			}
		},
		120_000,
	);
});
