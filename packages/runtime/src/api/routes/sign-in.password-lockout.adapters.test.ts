import { randomUUID } from "node:crypto";
import type { ClearanceOptions } from "@clearance/core";
import { getAuthTables, type Account } from "@clearance/core/db";
import { drizzleAdapter } from "@clearance/drizzle-adapter";
import { drizzle } from "drizzle-orm/node-postgres";
import { integer, pgTable, text, timestamp } from "drizzle-orm/pg-core";
import { Kysely, MysqlDialect, PostgresDialect } from "kysely";
import { MongoClient } from "mongodb";
import { createPool } from "mysql2";
import { Pool as PostgresPool } from "pg";
import { describe, expect, it, vi } from "vitest";
import { clearance } from "../../auth/full";
import { mongodbAdapter } from "../../adapters/mongodb-adapter";
import { migrateCredentialAuthorities } from "../../db/credential-authority-migration";
import { getMigrations } from "../../db/get-migration";

type LockoutAccount = Account & {
	failedPasswordAttempts: number | null;
	activePasswordAttemptReservations: string | null;
	passwordLockedUntil: Date | null;
};

type Engine =
	| { name: "PostgreSQL"; kind: "postgres"; url: string | undefined }
	| { name: "MongoDB"; kind: "mongodb"; url: string | undefined }
	| { name: "MySQL"; kind: "mysql"; url: string | undefined }
	| { name: "MariaDB"; kind: "mysql"; url: string | undefined };

const engines = [
	{
		name: "PostgreSQL",
		kind: "postgres",
		url:
			process.env.CLEARANCE_TEST_POSTGRES_URL ??
			process.env.CLEARANCE_TEST_DATABASE_URL,
	},
	{
		name: "MongoDB",
		kind: "mongodb",
		url: process.env.CLEARANCE_TEST_MONGODB_URL,
	},
	{
		name: "MySQL",
		kind: "mysql",
		url: process.env.CLEARANCE_TEST_MYSQL_URL,
	},
	{
		name: "MariaDB",
		kind: "mysql",
		url: process.env.CLEARANCE_TEST_MARIADB_URL,
	},
] as const satisfies readonly Engine[];

function createAuth(database: ClearanceOptions["database"]) {
	return clearance({
		baseURL: "http://localhost:3314",
		database,
		emailAndPassword: {
			enabled: true,
			accountLockout: {
				enabled: true,
				maxFailedAttempts: 3,
				durationSeconds: 300,
			},
		},
		logger: { level: "error" },
		rateLimit: { enabled: false },
		secret: "password-lockout-adapter-test-secret-long-enough",
	});
}

const quotePostgresIdentifier = (identifier: string) =>
	`"${identifier.replaceAll('"', '""')}"`;
const quoteMysqlIdentifier = (identifier: string) =>
	`\`${identifier.replaceAll("`", "``")}\``;

async function createHarness(engine: Engine) {
	if (!engine.url) throw new Error(`${engine.name} URL is unavailable`);

	if (engine.kind === "mongodb") {
		const client = new MongoClient(engine.url);
		const databaseName = `password_lockout_${randomUUID().replaceAll("-", "")}`;
		try {
			await client.connect();
		} catch (error) {
			await client.close();
			throw error;
		}
		const mongoDatabase = client.db(databaseName);
		const auth = createAuth(mongodbAdapter(mongoDatabase, { client }));
		try {
			const context = await auth.$context;
			await migrateCredentialAuthorities(context.adapter, auth.options);
			return {
				auth,
				cleanup: async () => {
					try {
						await mongoDatabase.dropDatabase();
					} finally {
						await client.close();
					}
				},
			};
		} catch (error) {
			await mongoDatabase.dropDatabase().catch(() => undefined);
			await client.close();
			throw error;
		}
	}

	if (engine.kind === "postgres") {
		const schema = `password_lockout_${randomUUID().replaceAll("-", "")}`;
		const adminPool = new PostgresPool({ connectionString: engine.url });
		try {
			await adminPool.query(
				`CREATE SCHEMA ${quotePostgresIdentifier(schema)}`,
			);
		} catch (error) {
			await adminPool.end();
			throw error;
		}
		const driverPool = new PostgresPool({
			connectionString: engine.url,
			options: `-c search_path=${schema},public`,
		});
		const database = new Kysely<any>({
			dialect: new PostgresDialect({ pool: driverPool }),
		});
		const auth = createAuth({ db: database, type: "postgres", transaction: true });
		const cleanup = async () => {
			try {
				await database.destroy();
			} finally {
				try {
					await adminPool.query(
						`DROP SCHEMA IF EXISTS ${quotePostgresIdentifier(schema)} CASCADE`,
					);
				} finally {
					await adminPool.end();
				}
			}
		};
		try {
			await (await getMigrations(auth.options)).runMigrations();
			return { auth, cleanup };
		} catch (error) {
			await cleanup();
			throw error;
		}
	}

	const databaseName = `password_lockout_${randomUUID().replaceAll("-", "")}`;
	const adminPool = createPool(engine.url);
	try {
		await adminPool
			.promise()
			.query(`CREATE DATABASE ${quoteMysqlIdentifier(databaseName)}`);
	} catch (error) {
		await adminPool.promise().end();
		throw error;
	}
	const databaseUrl = new URL(engine.url);
	databaseUrl.pathname = `/${databaseName}`;
	const driverPool = createPool(databaseUrl.toString());
	const database = new Kysely<any>({
		dialect: new MysqlDialect({ pool: driverPool }),
	});
	const auth = createAuth({ db: database, type: "mysql", transaction: true });
	const cleanup = async () => {
		try {
			await database.destroy();
		} finally {
			try {
				await adminPool
					.promise()
					.query(
						`DROP DATABASE IF EXISTS ${quoteMysqlIdentifier(databaseName)}`,
					);
			} finally {
				await adminPool.promise().end();
			}
		}
	};
	try {
		await (await getMigrations(auth.options)).runMigrations();
		return { auth, cleanup };
	} catch (error) {
		await cleanup();
		throw error;
	}
}

async function readCredentialAccount(
	auth: ReturnType<typeof createAuth>,
	userId: string,
) {
	const context = await auth.$context;
	const account = await context.adapter.findOne<LockoutAccount>({
		model: "account",
		where: [
			{ field: "userId", value: userId },
			{ field: "providerId", value: "credential" },
		],
	});
	if (!account) throw new Error("credential account was not generated");
	return account;
}

describe.each(engines)("password lockout authority on $name", (engine) => {
	it.skipIf(!engine.url)(
		"migrates hidden authority and enforces the concurrent comparison ceiling",
		async () => {
			const { auth, cleanup } = await createHarness(engine);
			try {
				const suffix = randomUUID();
				const email = `password-lockout-${suffix}@example.test`;
				const password = "initial-password-123";
				const replacementPassword = "replacement-password-456";
				const signup = await auth.api.signUpEmail({
					body: { email, name: `${engine.name} lockout`, password },
				});

				const authority = await readCredentialAccount(auth, signup.user.id);
				expect(authority).toMatchObject({
					failedPasswordAttempts: 0,
					activePasswordAttemptReservations: "[]",
				});
				expect(authority.passwordLockedUntil ?? null).toBeNull();
				const accountFields = getAuthTables(auth.options).account!.fields;
				for (const field of [
					"failedPasswordAttempts",
					"activePasswordAttemptReservations",
					"passwordLockedUntil",
				]) {
					expect(accountFields[field]).toMatchObject({
						input: false,
						returned: false,
					});
				}

				const context = await auth.$context;
				const originalVerify = context.password.verify.bind(context.password);
				let comparisons = 0;
				let release!: () => void;
				const gate = new Promise<void>((resolve) => {
					release = resolve;
				});
				context.password.verify = async (input) => {
					comparisons++;
					await gate;
					return originalVerify(input);
				};

				let responses: Response[];
				try {
					const attempts = Array.from({ length: 8 }, (_, index) =>
						auth.api.signInEmail({
							body: { email, password: `wrong-password-${index}` },
							asResponse: true,
						}),
					);
					await vi.waitFor(() => expect(comparisons).toBe(3), {
						interval: 20,
						timeout: 10_000,
					});
					release();
					responses = await Promise.all(attempts);
				} finally {
					release();
					context.password.verify = originalVerify;
				}

				expect(comparisons).toBe(3);
				expect(responses.map((response) => response.status).sort()).toEqual([
					401, 401, 401, 429, 429, 429, 429, 429,
				]);
				const locked = await readCredentialAccount(auth, signup.user.id);
				expect(locked.failedPasswordAttempts).toBe(3);
				expect(locked.activePasswordAttemptReservations).toBe("[]");
				expect(locked.passwordLockedUntil).toBeInstanceOf(Date);
				expect(locked.passwordLockedUntil!.getTime()).toBeGreaterThan(Date.now());

				context.password.verify = async (input) => {
					comparisons++;
					return originalVerify(input);
				};
				try {
					const lockedCorrectPassword = await auth.api.signInEmail({
						body: { email, password },
						asResponse: true,
					});
					expect(lockedCorrectPassword.status).toBe(429);
					expect(comparisons).toBe(3);
				} finally {
					context.password.verify = originalVerify;
				}

				const replacementHash = await context.password.hash(replacementPassword);
				await context.internalAdapter.updatePassword(
					signup.user.id,
					replacementHash,
				);
				const reset = await readCredentialAccount(auth, signup.user.id);
				expect(reset.failedPasswordAttempts).toBe(0);
				expect(reset.activePasswordAttemptReservations).toBe("[]");
				expect(reset.passwordLockedUntil).toBeNull();

				const oldPassword = await auth.api.signInEmail({
					body: { email, password },
					asResponse: true,
				});
				expect(oldPassword.status).toBe(401);
				const newPassword = await auth.api.signInEmail({
					body: { email, password: replacementPassword },
					asResponse: true,
				});
				expect(newPassword.status).toBe(200);
			} finally {
				await cleanup();
			}
		},
		120_000,
	);
});

const hasPostgres = Boolean(
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
		process.env.CLEARANCE_TEST_DATABASE_URL,
);

describe.skipIf(!hasPostgres)("password lockout Drizzle PostgreSQL CAS", () => {
	it("rechecks the complete guard after concurrent row-lock waits", async () => {
		const url =
			process.env.CLEARANCE_TEST_POSTGRES_URL ??
			process.env.CLEARANCE_TEST_DATABASE_URL!;
		const schema = `password_lockout_drizzle_${randomUUID().replaceAll("-", "")}`;
		const adminPool = new PostgresPool({ connectionString: url });
		const pool = new PostgresPool({
			connectionString: url,
			options: `-c search_path=${schema},public`,
			max: 12,
		});
		const account = pgTable("account", {
			id: text("id").primaryKey(),
			password: text("password"),
			failedPasswordAttempts: integer("failedPasswordAttempts"),
			activePasswordAttemptReservations: text(
				"activePasswordAttemptReservations",
			),
			passwordLockedUntil: timestamp("passwordLockedUntil", {
				withTimezone: true,
			}),
			updatedAt: timestamp("updatedAt", { withTimezone: true }).notNull(),
		});
		try {
			await adminPool.query(`CREATE SCHEMA ${quotePostgresIdentifier(schema)}`);
			await pool.query(`
				CREATE TABLE account (
					id text PRIMARY KEY,
					password text,
					"failedPasswordAttempts" integer,
					"activePasswordAttemptReservations" text,
					"passwordLockedUntil" timestamptz,
					"updatedAt" timestamptz NOT NULL
				)
			`);
			await pool.query(
				`INSERT INTO account (
					id, password, "failedPasswordAttempts",
					"activePasswordAttemptReservations", "passwordLockedUntil", "updatedAt"
				) VALUES ('credential', 'generation', 0, '[]', NULL, now())`,
			);
			const db = drizzle(pool, { schema: { account } });
			const adapter = drizzleAdapter(db, { provider: "pg" })({
				secret: "password-lockout-drizzle-cas-secret-long-enough",
			});
			const claims = await Promise.all(
				Array.from({ length: 8 }, (_, index) =>
					adapter.incrementOne<LockoutAccount>({
						model: "account",
						where: [
							{ field: "id", value: "credential" },
							{ field: "password", value: "generation" },
							{ field: "failedPasswordAttempts", value: 0 },
							{
								field: "activePasswordAttemptReservations",
								value: "[]",
							},
							{ field: "passwordLockedUntil", value: null },
						],
						increment: {},
						set: {
							failedPasswordAttempts: 1,
							activePasswordAttemptReservations: JSON.stringify([index]),
						},
					}),
				),
			);
			expect(claims.filter(Boolean)).toHaveLength(1);
			const stored = await pool.query<{
				failures: number;
				reservations: string;
			}>(`SELECT "failedPasswordAttempts" AS failures,
			          "activePasswordAttemptReservations" AS reservations
			   FROM account WHERE id='credential'`);
			expect(stored.rows[0]?.failures).toBe(1);
			expect(JSON.parse(stored.rows[0]!.reservations)).toHaveLength(1);
		} finally {
			await pool.end();
			await adminPool
				.query(
					`DROP SCHEMA IF EXISTS ${quotePostgresIdentifier(schema)} CASCADE`,
				)
				.catch(() => undefined);
			await adminPool.end();
		}
	}, 30_000);
});
