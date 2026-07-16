import { randomUUID } from "node:crypto";
import type { GenericEndpointContext } from "@clearance/core";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { Kysely, MysqlDialect } from "kysely";
import { createPool } from "mysql2";
import { describe, expect, it } from "vitest";
import { clearance } from "../../auth/full";
import { getMigrations } from "../../db/get-migration";
import { passkey } from ".";
import {
	consumeChallengeByParsedChallenge,
	createChallenge,
} from "./challenge";
import { advancePasskeyCounter } from "./counter";
import { assertPasskeyDeletionLifecycleOnAdapter } from "./passkey.deletion.adapter-test-utils";

const engines = [
	["MySQL", process.env.CLEARANCE_TEST_MYSQL_URL],
	["MariaDB", process.env.CLEARANCE_TEST_MARIADB_URL],
] as const;

const quote = (value: string) => `\`${value.replaceAll("`", "``")}\``;

describe.each(engines)("passkey authority on %s", (_engine, url) => {
	it.skipIf(!url)(
		"migrates authorities and proves races plus deletion success/rollback",
		async () => {
			const databaseName = `passkey_${randomUUID().replaceAll("-", "")}`;
			const adminPool = createPool(url!);
			const databaseURL = new URL(url!);
			databaseURL.pathname = `/${databaseName}`;
			await adminPool.promise().query(`CREATE DATABASE ${quote(databaseName)}`);
			const driverPool = createPool(databaseURL.toString());
			const db = new Kysely<any>({
				dialect: new MysqlDialect({ pool: driverPool }),
			});
			try {
				const auth = clearance({
					baseURL: "http://localhost:3312",
					database: { db, type: "mysql", transaction: true },
					emailAndPassword: { enabled: true },
					logger: { level: "error" },
					plugins: [passkey()],
					secret: "passkey-mysql-test-secret-that-is-long-enough",
				});
				await (await getMigrations(auth.options)).runMigrations();
				const context = await auth.$context;
				const firstUser = await context.internalAdapter.createUser({
					email: `passkey-a-${randomUUID()}@example.test`,
					emailVerified: true,
					image: null,
					name: "Passkey A",
				});
				const secondUser = await context.internalAdapter.createUser({
					email: `passkey-b-${randomUUID()}@example.test`,
					emailVerified: true,
					image: null,
					name: "Passkey B",
				});
				const stableHandle = `handle-${randomUUID()}`;
				await context.adapter.update({
					model: "user",
					where: [{ field: "id", value: firstUser.id }],
					update: { passkeyUserHandle: stableHandle },
				});
				await expect(
					context.adapter.update({
						model: "user",
						where: [{ field: "id", value: secondUser.id }],
						update: { passkeyUserHandle: stableHandle },
					}),
				).rejects.toThrow();

				const credentialID = `credential-${randomUUID()}`;
				const row = await context.adapter.create<Record<string, unknown>>({
					model: "passkey",
					data: {
						userId: firstUser.id,
						credentialID,
						publicKey: "public-key",
						userHandle: stableHandle,
						counter: 4,
						deviceType: "singleDevice",
						backedUp: false,
						createdAt: new Date(),
						updatedAt: new Date(),
					},
				});
				await expect(
					context.adapter.create({
						model: "passkey",
						data: {
							userId: secondUser.id,
							credentialID,
							publicKey: "different-public-key",
							userHandle: `handle-${randomUUID()}`,
							counter: 0,
							deviceType: "multiDevice",
							backedUp: true,
							createdAt: new Date(),
							updatedAt: new Date(),
						},
					}),
				).rejects.toThrow();

				const ctx = { context } as unknown as GenericEndpointContext;
				const challenge = `mysql-challenge-${randomUUID()}`;
				await createChallenge(ctx, "authentication", challenge, {
					rpID: "localhost",
					origin: "http://localhost:3312",
				});
				await expect(
					createChallenge(ctx, "authentication", challenge, {
						rpID: "localhost",
						origin: "http://localhost:3312",
					}),
				).rejects.toThrow();
				const challengeClaims = await Promise.all(
					Array.from({ length: 8 }, () =>
						consumeChallengeByParsedChallenge(ctx, "authentication", challenge),
					),
				);
				expect(challengeClaims.filter(Boolean)).toHaveLength(1);

				const counterClaims = await Promise.all(
					Array.from({ length: 8 }, (_, index) =>
						advancePasskeyCounter(
							context.adapter as unknown as DBTransactionAdapter<any>,
							String(row.id),
							4,
							index + 5,
						),
					),
				);
				expect(counterClaims.filter(Boolean)).toHaveLength(1);

				await assertPasskeyDeletionLifecycleOnAdapter(
					auth,
					"http://localhost:3312",
				);
			} finally {
				await db.destroy();
				await adminPool.promise().query(`DROP DATABASE IF EXISTS ${quote(databaseName)}`);
				await adminPool.promise().end();
			}
		},
		120_000,
	);
});
