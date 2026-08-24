import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type {
	Awaitable,
	ClearanceClientOptions,
	ClearanceOptions,
} from "@clearance/core";
import type { SuccessContext } from "@better-fetch/fetch";
import { sql } from "kysely";
import type { Db, MongoClient } from "mongodb";
import { afterAll } from "vitest";
import { clearance } from "../auth/full";
import { createAuthClient } from "../client";
import { parseSetCookieHeader, setCookieToHeader } from "../cookies";
import { getAdapter } from "../db/adapter-kysely";
import { migrateCredentialAuthorities } from "../db/credential-authority-migration";
import { getMigrations } from "../db/get-migration";
import { bearer } from "../plugins";
import {
	attachCapturedInternalAuthenticationPolicy,
	readInternalAuthenticationPolicy,
} from "../internal/authentication-policy";
import type { Session, User } from "../types";
import { getBaseURL, isDynamicBaseURLConfig } from "../utils/url";

const cleanupSet = new Set<Function>();

type CurrentUserContext = {
	headers: Headers;
};
const currentUserContextStorage = new AsyncLocalStorage<CurrentUserContext>();

afterAll(async () => {
	for (const cleanup of cleanupSet) {
		await cleanup();
		cleanupSet.delete(cleanup);
	}
});

export async function getTestInstance<
	O extends Partial<ClearanceOptions>,
	C extends ClearanceClientOptions,
>(
	options?: O | undefined,
	config?:
		| {
				clientOptions?: C;
				port?: number;
				disableTestUser?: boolean;
				testUser?: Partial<User>;
				testWith?: "sqlite" | "postgres" | "mongodb" | "mysql";
		  }
		| undefined,
) {
	const testWith = config?.testWith || "sqlite";
	const postgresSchema =
		testWith === "postgres"
			? `ba_test_${randomUUID().replaceAll("-", "_")}`
			: undefined;
	let mongoResource:
		| {
				client: MongoClient;
				db: Db;
		  }
		| undefined;

	const quotePostgresIdentifier = (identifier: string) =>
		`"${identifier.replaceAll('"', '""')}"`;

	async function getPostgres() {
		const { Kysely, PostgresDialect } = await import("kysely");
		const { Pool } = await import("pg");
		const pool = new Pool({
			connectionString:
				process.env.CLEARANCE_TEST_POSTGRES_URL ??
				process.env.CLEARANCE_TEST_DATABASE_URL ??
				"postgres://user:password@localhost:5432/clearance",
			options: postgresSchema
				? `-c search_path=${postgresSchema},public`
				: undefined,
		});
		if (postgresSchema) {
			await pool.query(
				`CREATE SCHEMA IF NOT EXISTS ${quotePostgresIdentifier(
					postgresSchema,
				)}`,
			);
		}
		return new Kysely({
			dialect: new PostgresDialect({
				pool,
			}),
		});
	}

	async function getSqlite() {
		const { DatabaseSync } = await import("node:sqlite");
		return new DatabaseSync(":memory:");
	}

	async function getMysql() {
		const { Kysely, MysqlDialect } = await import("kysely");
		const { createPool } = await import("mysql2/promise");
		return new Kysely({
			dialect: new MysqlDialect({
				pool: createPool(
					process.env.CLEARANCE_TEST_MYSQL_URL ??
						"mysql://user:password@localhost:3306/clearance",
				),
			}),
		});
	}

	async function cleanupMongoResource() {
		if (!mongoResource) return;
		try {
			await mongoResource.db.dropDatabase();
		} finally {
			await mongoResource.client.close();
			mongoResource = undefined;
		}
	}

	async function getMongo() {
		if (mongoResource) return mongoResource;
		const { MongoClient } = await import("mongodb");
		const client = new MongoClient(
			process.env.CLEARANCE_TEST_MONGODB_URL ??
				"mongodb://127.0.0.1:27017/?replicaSet=clearance-rs",
		);
		await client.connect();
		const db = client.db(`clearance_test_${randomUUID().replaceAll("-", "")}`);
		mongoResource = { client, db };
		cleanupSet.add(cleanupMongoResource);
		return mongoResource;
	}

	const opts = {
		socialProviders: {
			github: {
				clientId: "test",
				clientSecret: "test",
			},
			google: {
				clientId: "test",
				clientSecret: "test",
			},
		},
		secret: "clearance-secret-that-is-long-enough-for-validation-test",
		database:
			testWith === "postgres"
				? { db: await getPostgres(), type: "postgres", transaction: true }
				: testWith === "mongodb"
					? await Promise.all([
							getMongo(),
							await import("../adapters/mongodb-adapter"),
						]).then(([mongo, { mongodbAdapter }]) =>
							mongodbAdapter(mongo.db, { client: mongo.client }),
						)
					: testWith === "mysql"
						? { db: await getMysql(), type: "mysql", transaction: true }
						: await getSqlite(),
		emailAndPassword: {
			enabled: true,
		},
		rateLimit: {
			enabled: false,
		},
		advanced: {
			cookies: {},
		},
		logger: {
			level: "debug",
		},
	} satisfies ClearanceOptions;
	const testOptions = options?.secondaryStorage
		? {
				...options,
				secondaryStorage: {
					...options.secondaryStorage,
					namespace:
						options.secondaryStorage.namespace ??
						`test-${randomUUID()}`,
					runExclusive:
						options.secondaryStorage.runExclusive ??
						((_name, operation) => operation()),
					assertNoLegacySessionWriters:
						options.secondaryStorage.assertNoLegacySessionWriters ??
						(() => {}),
				},
			}
		: options;

	const authOptions = {
		baseURL: "http://localhost:" + (config?.port || 3000),
		...opts,
		...testOptions,
		plugins: [bearer(), ...(testOptions?.plugins || [])],
	} as unknown as O;
	const authenticationPolicy = options
		? readInternalAuthenticationPolicy(options)
		: undefined;
	if (authenticationPolicy) {
		attachCapturedInternalAuthenticationPolicy(
			authOptions,
			authenticationPolicy,
		);
	}
	const auth = clearance(authOptions);

	const testUser = {
		email: "test@test.com",
		password: "test123456",
		name: "test user",
		...config?.testUser,
	};
	async function createTestUser() {
		if (config?.disableTestUser) {
			return;
		}
		// Synthesize a host header from allowedHosts so setup resolves under
		// dynamic baseURL. `?` is a wildcard, not a query-string delimiter,
		// so it's replaced, not split on.
		const dynamicBaseURL = isDynamicBaseURLConfig(auth.options.baseURL)
			? auth.options.baseURL
			: undefined;
		const pattern =
			dynamicBaseURL?.allowedHosts.find(
				(h) => !h.includes("*") && !h.includes("?"),
			) ?? dynamicBaseURL?.allowedHosts[0];
		const host = pattern
			?.replace(/^https?:\/\//, "")
			.split(/[/#]/)[0]
			?.replace(/\*/g, "test")
			.replace(/\?/g, "x");
		const headers = host ? new Headers({ host }) : undefined;
		//@ts-expect-error
		await auth.api.signUpEmail({
			body: testUser,
			headers,
		});
	}

	if (testWith !== "mongodb") {
		const { runMigrations } = await getMigrations({
			...auth.options,
			database: opts.database,
		});
		await runMigrations();
	} else {
		// Mongo has no schema DDL, but it still has the same credential migration
		// and traffic gates as relational databases. Each test owns a fresh,
		// isolated database, so its local drain proof has no legacy processes.
		const context = await auth.$context;
		await migrateCredentialAuthorities(context.adapter, auth.options);
	}

	await createTestUser();

	const cleanup = async () => {
		if (testWith === "mongodb") {
			await cleanupMongoResource();
			return;
		}
		if (testWith === "postgres") {
			const postgres = await getPostgres();
			if (postgresSchema) {
				await sql
					.raw(
						`DROP SCHEMA IF EXISTS ${quotePostgresIdentifier(
							postgresSchema,
						)} CASCADE`,
					)
					.execute(postgres);
			} else {
				await sql`DROP SCHEMA public CASCADE; CREATE SCHEMA public;`.execute(
					postgres,
				);
			}
			await postgres.destroy();
			return;
		}

		if (testWith === "mysql") {
			const mysql = await getMysql();
			await sql`SET FOREIGN_KEY_CHECKS = 0;`.execute(mysql);
			const tables = await mysql.introspection.getTables();
			for (const table of tables) {
				// @ts-expect-error
				await mysql.deleteFrom(table.name).execute();
			}
			await sql`SET FOREIGN_KEY_CHECKS = 1;`.execute(mysql);
			return;
		}
		if (testWith === "sqlite") {
			const sqlite = await getSqlite();
			sqlite.close();
			return;
		}
	};
	if (testWith !== "mongodb") cleanupSet.add(cleanup);

	const customFetchImpl = async (
		url: string | URL | Request,
		init?: RequestInit | undefined,
	) => {
		const headers = init?.headers || {};
		const storageHeaders = currentUserContextStorage.getStore()?.headers;
		return auth.handler(
			new Request(
				url,
				init
					? {
							...init,
							headers: new Headers({
								...(storageHeaders
									? Object.fromEntries(storageHeaders.entries())
									: {}),
								...(headers instanceof Headers
									? Object.fromEntries(headers.entries())
									: typeof headers === "object"
										? headers
										: {}),
							}),
						}
					: {
							headers,
						},
			),
		);
	};

	const clientBaseURL = isDynamicBaseURLConfig(options?.baseURL)
		? getBaseURL(
				"http://localhost:" + (config?.port || 3000),
				options?.basePath || "/api/auth",
			)
		: getBaseURL(
				typeof options?.baseURL === "string"
					? options.baseURL
					: "http://localhost:" + (config?.port || 3000),
				options?.basePath || "/api/auth",
			);

	const client = createAuthClient({
		...(config?.clientOptions as C extends undefined ? {} : C),
		baseURL: clientBaseURL,
		fetchOptions: {
			customFetchImpl,
		},
	});

	async function signInWithTestUser() {
		if (config?.disableTestUser) {
			throw new Error("Test user is disabled");
		}
		const headers = new Headers();
		const setCookie = (name: string, value: string) => {
			const current = headers.get("cookie");
			headers.set("cookie", `${current || ""}; ${name}=${value}`);
		};
		//@ts-expect-error
		const { data } = await client.signIn.email({
			email: testUser.email,
			password: testUser.password,
			fetchOptions: {
				//@ts-expect-error
				onSuccess(context) {
					const header = context.response.headers.get("set-cookie");
					const cookies = parseSetCookieHeader(header || "");
					const signedCookie = cookies.get("clearance.session_token")?.value;
					headers.set("cookie", `clearance.session_token=${signedCookie}`);
				},
			},
		});
		return {
			session: data.session as Session,
			user: data.user as User,
			headers,
			setCookie,
			runWithUser: async (fn: (headers: Headers) => Promise<void>) => {
				return currentUserContextStorage.run({ headers }, async () => {
					await fn(headers);
				});
			},
		};
	}
	async function signInWithUser(email: string, password: string) {
		const headers = new Headers();
		//@ts-expect-error
		const { data } = await client.signIn.email({
			email,
			password,
			fetchOptions: {
				//@ts-expect-error
				onSuccess(context) {
					const header = context.response.headers.get("set-cookie");
					const cookies = parseSetCookieHeader(header || "");
					const signedCookie = cookies.get("clearance.session_token")?.value;
					headers.set("cookie", `clearance.session_token=${signedCookie}`);
				},
			},
		});
		return {
			res: data as {
				user: User;
				session: Session;
			},
			headers,
		};
	}

	function sessionSetter(headers: Headers) {
		return (context: SuccessContext) => {
			const header = context.response.headers.get("set-cookie");
			if (header) {
				const cookies = parseSetCookieHeader(header || "");
				const signedCookie = cookies.get("clearance.session_token")?.value;
				headers.set("cookie", `clearance.session_token=${signedCookie}`);
			}
		};
	}

	return {
		auth,
		client,
		testUser,
		signInWithTestUser,
		signInWithUser,
		cookieSetter: setCookieToHeader,
		customFetchImpl,
		sessionSetter,
		mongo: mongoResource,
		db: await getAdapter(auth.options),
		runWithUser: async (
			email: string,
			password: string,
			fn: (headers: Headers) => Awaitable<void>,
		) => {
			const { headers } = await signInWithUser(email, password);
			return currentUserContextStorage.run({ headers }, async () => {
				await fn(headers);
			});
		},
	};
}
