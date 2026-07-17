import { DatabaseSync } from "node:sqlite";
import type { ClearanceOptions, ClearancePlugin } from "@clearance/core";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { afterEach, describe, expect, it, vi } from "vitest";
import { init } from "../context/init";
import { schema as passkeySchema } from "../plugins/passkey/schema";
import { schema as twoFactorSchema } from "../plugins/two-factor/schema";
import { rotateFactorSessionGenerations } from "./factor-session-generation";
import { getMigrations } from "./get-migration";
import { PASSKEY_SESSION_GENERATION_FIELD } from "./passkey-session-generation";
import { TWO_FACTOR_SESSION_GENERATION_FIELD } from "./two-factor-session-generation";

const databases: DatabaseSync[] = [];

async function setup() {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	const options = {
		baseURL: "http://localhost:3000",
		secret: "factor-session-generation-test-secret-with-sufficient-length",
		database,
		plugins: [
			{ id: "passkey", schema: passkeySchema } satisfies ClearancePlugin,
			{ id: "two-factor", schema: twoFactorSchema } satisfies ClearancePlugin,
		],
	} satisfies ClearanceOptions;
	await (await getMigrations(options)).runMigrations();
	const context = await init(options);
	const user = await context.internalAdapter.createUser({
		email: `factor-generation-${databases.length}@example.test`,
		name: "Factor generation user",
	});
	return { context, user };
}

async function setGenerations(
	context: Awaited<ReturnType<typeof setup>>["context"],
	userId: string,
	passkey: string | null,
	twoFactor: string | null,
) {
	await context.adapter.update({
		model: "user",
		where: [{ field: "id", value: userId }],
		update: {
			[PASSKEY_SESSION_GENERATION_FIELD]: passkey,
			[TWO_FACTOR_SESSION_GENERATION_FIELD]: twoFactor,
		},
	});
}

async function readGenerations(
	context: Awaited<ReturnType<typeof setup>>["context"],
	userId: string,
) {
	const row = await context.adapter.findOne<Record<string, unknown>>({
		model: "user",
		where: [{ field: "id", value: userId }],
	});
	return {
		passkey: row?.[PASSKEY_SESSION_GENERATION_FIELD] ?? null,
		twoFactor: row?.[TWO_FACTOR_SESSION_GENERATION_FIELD] ?? null,
	};
}

afterEach(() => {
	for (const database of databases.splice(0)) database.close();
});

describe("atomic factor session generation rotation", () => {
	it("rotates a legacy-null pair in one guarded write", async () => {
		const { context, user } = await setup();
		await setGenerations(context, user.id, null, null);

		const updated = await rotateFactorSessionGenerations(
			context.adapter,
			user.id,
			undefined,
			null,
			"passkey-next",
			"two-factor-next",
		);

		expect(updated).toMatchObject({
			[PASSKEY_SESSION_GENERATION_FIELD]: "passkey-next",
			[TWO_FACTOR_SESSION_GENERATION_FIELD]: "two-factor-next",
		});
		expect(await readGenerations(context, user.id)).toEqual({
			passkey: "passkey-next",
			twoFactor: "two-factor-next",
		});
	});

	it("rotates an exact string pair", async () => {
		const { context, user } = await setup();
		await setGenerations(context, user.id, "passkey-old", "two-factor-old");

		await expect(
			rotateFactorSessionGenerations(
				context.adapter,
				user.id,
				"passkey-old",
				"two-factor-old",
				"passkey-next",
				"two-factor-next",
			),
		).resolves.toMatchObject({
			[PASSKEY_SESSION_GENERATION_FIELD]: "passkey-next",
			[TWO_FACTOR_SESSION_GENERATION_FIELD]: "two-factor-next",
		});
	});

	it("changes neither generation when either observed value is stale", async () => {
		const { context, user } = await setup();
		await setGenerations(context, user.id, "passkey-live", "two-factor-live");

		await expect(
			rotateFactorSessionGenerations(
				context.adapter,
				user.id,
				"passkey-stale",
				"two-factor-live",
				"passkey-next",
				"two-factor-next",
			),
		).resolves.toBeNull();
		expect(await readGenerations(context, user.id)).toEqual({
			passkey: "passkey-live",
			twoFactor: "two-factor-live",
		});
	});

	it("has exactly one concurrent winner from the same observed pair", async () => {
		const { context, user } = await setup();
		await setGenerations(context, user.id, "passkey-old", "two-factor-old");

		const results = await Promise.all([
			rotateFactorSessionGenerations(
				context.adapter,
				user.id,
				"passkey-old",
				"two-factor-old",
				"passkey-first",
				"two-factor-first",
			),
			rotateFactorSessionGenerations(
				context.adapter,
				user.id,
				"passkey-old",
				"two-factor-old",
				"passkey-second",
				"two-factor-second",
			),
		]);

		expect(results.filter(Boolean)).toHaveLength(1);
		expect(await readGenerations(context, user.id)).toEqual(
			results[0]
				? { passkey: "passkey-first", twoFactor: "two-factor-first" }
				: { passkey: "passkey-second", twoFactor: "two-factor-second" },
		);
	});

	it("restores both generations when the surrounding transaction rolls back", async () => {
		const { context, user } = await setup();
		await setGenerations(context, user.id, "passkey-old", "two-factor-old");

		await expect(
			runWithTransaction(context.adapter, async () => {
				const adapter = await getCurrentAdapter(context.adapter);
				const updated = await rotateFactorSessionGenerations(
					adapter,
					user.id,
					"passkey-old",
					"two-factor-old",
					"passkey-next",
					"two-factor-next",
				);
				expect(updated).not.toBeNull();
				throw new Error("rollback dual generation rotation");
			}),
		).rejects.toThrow("rollback dual generation rotation");
		expect(await readGenerations(context, user.id)).toEqual({
			passkey: "passkey-old",
			twoFactor: "two-factor-old",
		});
	});

	it("rejects invalid next values before reaching the database", async () => {
		const { context, user } = await setup();
		await setGenerations(context, user.id, "passkey-old", "two-factor-old");
		const incrementOne = vi.spyOn(context.adapter, "incrementOne");
		const invalidPairs: [string, string][] = [
			["", "two-factor-next"],
			["passkey-next", " "],
			["x".repeat(513), "two-factor-next"],
			["passkey-next", "x".repeat(513)],
			["passkey-old", "two-factor-next"],
			["passkey-next", "two-factor-old"],
		];

		for (const [nextPasskey, nextTwoFactor] of invalidPairs) {
			await expect(
				rotateFactorSessionGenerations(
					context.adapter,
					user.id,
					"passkey-old",
					"two-factor-old",
					nextPasskey,
					nextTwoFactor,
				),
			).rejects.toThrow(TypeError);
		}

		expect(incrementOne).not.toHaveBeenCalled();
		expect(await readGenerations(context, user.id)).toEqual({
			passkey: "passkey-old",
			twoFactor: "two-factor-old",
		});
	});
});
