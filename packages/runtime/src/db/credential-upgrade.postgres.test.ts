import { randomUUID } from "node:crypto";
import type { ClearanceOptions } from "@clearance/core";
import { Kysely, PostgresDialect } from "kysely";
import { Pool, type PoolClient } from "pg";
import { describe, expect, it } from "vitest";
import { getMigrations } from "./get-migration";

const connectionString =
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
	process.env.CLEARANCE_TEST_DATABASE_URL;

const quoteIdentifier = (value: string) =>
	`"${value.replaceAll('"', '""')}"`;

function leaseBoundDatabase(client: PoolClient): Kysely<unknown> {
	const leasedClient = {
		query: client.query.bind(client),
		release: () => undefined,
	};
	return new Kysely({
		dialect: new PostgresDialect({
			pool: {
				connect: async () => leasedClient,
				end: async () => undefined,
				options: {},
			} as unknown as Pool,
		}),
	});
}

describe.skipIf(!connectionString)("public PostgreSQL credential migration", () => {
	it("refuses legacy authority with no fence, a foreign lock, or the exact lock session", async () => {
		const schema = `credential_public_refusal_${randomUUID().replaceAll("-", "_")}`;
		const pool = new Pool({
			connectionString,
			options: `-c search_path=${schema},public`,
			max: 4,
		});
		let lockClient: PoolClient | undefined;
		let lockDatabase: Kysely<unknown> | undefined;
		const token = `legacy-session-${randomUUID()}`;
		try {
			await pool.query(`CREATE SCHEMA ${quoteIdentifier(schema)}`);
			await pool.query(`
				CREATE TABLE "user" (
					id text PRIMARY KEY,
					name text NOT NULL,
					email text NOT NULL UNIQUE,
					"emailVerified" boolean NOT NULL,
					image text,
					"createdAt" timestamptz NOT NULL,
					"updatedAt" timestamptz NOT NULL
				);
				CREATE TABLE session (
					id text PRIMARY KEY,
					"expiresAt" timestamptz NOT NULL,
					"createdAt" timestamptz NOT NULL,
					"updatedAt" timestamptz NOT NULL,
					"userId" text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
					token text NOT NULL UNIQUE
				);
				INSERT INTO "user" (
					id, name, email, "emailVerified", "createdAt", "updatedAt"
				) VALUES (
					'legacy-user', 'Legacy user', 'legacy@example.test', true, now(), now()
				)
			`);
			await pool.query(
				`INSERT INTO session (
					id, "expiresAt", "createdAt", "updatedAt", "userId", token
				) VALUES ('legacy-session', now() + interval '1 hour', now(), now(), 'legacy-user', $1)`,
				[token],
			);
			const options: ClearanceOptions = {
				database: pool,
				secret: "public-credential-migration-refusal-secret",
				emailAndPassword: { enabled: true },
				logger: { level: "error" },
			};

			await expect((await getMigrations(options)).runMigrations()).rejects.toThrow(
				"reserved for createClearanceAuth(...).migrate()",
			);

			await pool.query(`
				CREATE TABLE "credentialAuthorityFence" (
					id text PRIMARY KEY,
					"protocolVersion" integer NOT NULL,
					phase text NOT NULL,
					generation text NOT NULL,
					"drainId" text,
					"bridgeDeploymentId" text,
					"expectedRuntimeCount" integer,
					revision bigint NOT NULL DEFAULT 0,
					"drainStartedAt" timestamptz,
					"drainedAt" timestamptz,
					"publishedAt" timestamptz,
					"createdAt" timestamptz NOT NULL DEFAULT now(),
					"updatedAt" timestamptz NOT NULL DEFAULT now()
				);
				INSERT INTO "credentialAuthorityFence" (
					id, "protocolVersion", phase, generation, "drainId", "drainedAt"
				) VALUES ('credential-authority', 1, 'migrating', 'legacy-v1', 'weak-drain', now())
			`);
			lockClient = await pool.connect();
			await lockClient.query(`
				SELECT pg_advisory_lock(
					hashtext(current_database()),
					hashtext(current_schema() || ':clearance:credential-authority:v1')
				)
			`);
			await expect((await getMigrations(options)).runMigrations()).rejects.toThrow(
				"reserved for createClearanceAuth(...).migrate()",
			);

			lockDatabase = leaseBoundDatabase(lockClient);
			await expect(
				(
					await getMigrations({
						...options,
						database: {
							db: lockDatabase,
							type: "postgres",
							transaction: true,
						},
					})
				).runMigrations(),
			).rejects.toThrow("reserved for createClearanceAuth(...).migrate()");

			const unchanged = await pool.query<{ token: string }>(
				`SELECT token FROM session WHERE id = 'legacy-session'`,
			);
			expect(unchanged.rows[0]?.token).toBe(token);
			const securityTables = await pool.query<{ count: number }>(`
				SELECT count(*)::int AS count
				FROM pg_class table_record
				JOIN pg_namespace namespace_record ON namespace_record.oid = table_record.relnamespace
				WHERE namespace_record.nspname = current_schema()
				  AND table_record.relname IN ('sessionCredential', 'securityMigration')
			`);
			expect(securityTables.rows[0]?.count).toBe(0);
		} finally {
			await lockDatabase?.destroy().catch(() => undefined);
			if (lockClient) {
				await lockClient
					.query(`
						SELECT pg_advisory_unlock(
							hashtext(current_database()),
							hashtext(current_schema() || ':clearance:credential-authority:v1')
						)
					`)
					.catch(() => undefined);
				lockClient.release();
			}
			await pool.query(`DROP SCHEMA IF EXISTS ${quoteIdentifier(schema)} CASCADE`);
			await pool.end();
		}
	});
});
