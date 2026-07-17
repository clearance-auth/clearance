import { DatabaseSync } from "node:sqlite";
import type { GenericEndpointContext } from "@clearance/core";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { afterEach, describe, expect, it } from "vitest";
import { init } from "../../../context/init";
import { getMigrations } from "../../../db/get-migration";
import { twoFactor } from "..";
import type { TwoFactorTable } from "../types";
import {
	consumeBackupCodeForRecoveryRepair,
	encodeBackupCodes,
	takeBackupCodeRecoveryRepairAuthority,
} from "./index";

const databases: DatabaseSync[] = [];
type TakenRecoveryProof = Exclude<
	Awaited<ReturnType<typeof takeBackupCodeRecoveryRepairAuthority>>,
	null
>;

async function createContext(options?: {
	table?: string;
	maxFailedAttempts?: number;
	configuredAs?: "encrypted" | "hashed";
}) {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	const table = options?.table ?? "twoFactor";
	const config = {
		baseURL: "http://localhost:3000",
		secret: "recovery-repair-proof-test-secret",
		database,
		plugins: [
			twoFactor({
				twoFactorTable: table,
				backupCodeOptions: {
					storeBackupCodes: options?.configuredAs ?? "hashed",
				},
				accountLockout: options?.maxFailedAttempts
					? { maxFailedAttempts: options.maxFailedAttempts }
					: undefined,
			}),
		],
	};
	await (await getMigrations(config)).runMigrations();
	return { context: await init(config), table };
}

async function setup(options?: {
	table?: string;
	maxFailedAttempts?: number;
	verified?: boolean | null;
	twoFactorEnabled?: boolean;
	storedAs?: "encrypted" | "hashed";
	configuredAs?: "encrypted" | "hashed";
}) {
	const { context, table } = await createContext(options);
	const user = await context.internalAdapter.createUser({
		email: `recovery-${Math.random()}@example.test`,
		name: "Recovery proof user",
	});
	if (options?.twoFactorEnabled !== undefined) {
		await context.internalAdapter.updateUser(user.id, {
			twoFactorEnabled: options.twoFactorEnabled,
		});
	}
	const code = "repair-code-1";
	const verified =
		options && Object.hasOwn(options, "verified") ? options.verified : true;
	const backupCodes = await encodeBackupCodes(
		[code, "repair-code-2"],
		context.secretConfig,
		{ storeBackupCodes: options?.storedAs ?? "hashed" },
	);
	const factor = await context.adapter.create<Omit<TwoFactorTable, "id">, TwoFactorTable>({
		model: table,
		data: {
			userId: user.id,
			secret: "ciphertext-secret-not-an-authority",
			backupCodes,
			verified: verified as never,
			trustDeviceGeneration: "trust-generation-1",
		} as Omit<TwoFactorTable, "id">,
	});
	return {
		context,
		table,
		code,
		user,
		factor,
		ctx: { context } as unknown as GenericEndpointContext,
	};
}

async function currentFactor(
	context: Awaited<ReturnType<typeof init>>,
	table: string,
	id: string,
) {
	const adapter = await getCurrentAdapter(context.adapter);
	const factor = await adapter.findOne<TwoFactorTable>({
		model: table,
		where: [{ field: "id", value: id }],
	});
	if (!factor) throw new Error("factor missing");
	return { adapter, factor };
}

afterEach(() => {
	for (const database of databases.splice(0)) database.close();
});

describe("backup-code recovery repair proof authority", () => {
	it("rejects fabricated and outside-transaction authorities", async () => {
		const { context, table, factor, code, ctx } = await setup();
		expect(await takeBackupCodeRecoveryRepairAuthority(ctx, {})).toBeNull();
		await expect(
			consumeBackupCodeForRecoveryRepair(
				ctx,
				context.adapter,
				table,
				factor,
				code,
			),
		).rejects.toThrow("active transaction");
	});

	it("consumes a valid code once and reveals frozen server-only lineage once", async () => {
		const { context, table, factor, code, ctx } = await setup();
		let authority: object | null = null;
		let taken: Awaited<ReturnType<typeof takeBackupCodeRecoveryRepairAuthority>> =
			null;
		await runWithTransaction(context.adapter, async () => {
			const current = await currentFactor(context, table, factor.id);
			const result = await consumeBackupCodeForRecoveryRepair(
				ctx,
				current.adapter,
				table,
				current.factor,
				code,
			);
			expect(result.kind).toBe("authorized");
			if (result.kind !== "authorized") throw result.error;
			authority = result.authority;
			const concurrentTakes = await Promise.all([
				takeBackupCodeRecoveryRepairAuthority(ctx, authority),
				takeBackupCodeRecoveryRepairAuthority(ctx, authority),
			]);
			expect(concurrentTakes.filter(Boolean)).toHaveLength(1);
			taken = concurrentTakes.find(Boolean) ?? null;
		});
		if (!authority || !taken) throw new Error("authority missing");
		const proof = taken as TakenRecoveryProof;
		expect(Object.isFrozen(proof)).toBe(true);
		expect(proof).toMatchObject({
			subjectId: factor.userId,
			twoFactorTable: table,
			recoveryFactorId: factor.id,
			sourceTrustDeviceGeneration: "trust-generation-1",
		});
		expect(proof.recoveryProofDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(proof.sourceFactorFingerprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(proof.sourceSecretDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(proof.postConsumeBackupCodesDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(JSON.stringify(proof)).not.toContain(code);
		expect(JSON.stringify(proof)).not.toContain("ciphertext-secret-not-an-authority");
		expect(await takeBackupCodeRecoveryRepairAuthority(ctx, authority)).toBeNull();

		const persisted = await context.adapter.findOne<TwoFactorTable>({
			model: table,
			where: [{ field: "id", value: factor.id }],
		});
		expect(persisted?.backupCodes).not.toContain(code);
	});

	it("makes same-code contenders yield exactly one authority", async () => {
		const { context, table, factor, code, ctx } = await setup();
		const staleFirst = factor;
		const staleSecond = { ...factor };
		const contenders = await Promise.allSettled(
			[staleFirst, staleSecond].map((staleFactor) =>
				runWithTransaction(context.adapter, async () => {
					const adapter = await getCurrentAdapter(context.adapter);
					return consumeBackupCodeForRecoveryRepair(
						ctx,
						adapter,
						table,
						staleFactor,
						code,
					);
				}),
			),
		);
		expect(
			contenders.filter(
				(result) =>
					result.status === "fulfilled" && result.value.kind === "authorized",
			),
		).toHaveLength(1);
		expect(
			contenders.filter(
				(result) =>
					result.status === "rejected" &&
					result.reason?.status === "CONFLICT",
			),
		).toHaveLength(1);
	});

	it("commits invalid-attempt accounting and lockout without minting authority", async () => {
		const { context, table, factor, ctx } = await setup({ maxFailedAttempts: 1 });
		const invalid = await runWithTransaction(context.adapter, async () => {
			const current = await currentFactor(context, table, factor.id);
			return consumeBackupCodeForRecoveryRepair(
				ctx,
				current.adapter,
				table,
				current.factor,
				"wrong-repair-code",
			);
		});
		expect(invalid.kind).toBe("invalid");
		if (invalid.kind === "authorized") throw new Error("expected invalid code");
		expect(invalid.error.status).toBe("UNAUTHORIZED");
		const persisted = await context.adapter.findOne<TwoFactorTable>({
			model: table,
			where: [{ field: "id", value: factor.id }],
		});
		expect(persisted?.failedVerificationCount).toBe(1);
		expect(persisted?.lockedUntil).toBeInstanceOf(Date);
	});

	it("rolls a valid proof back without retaining code material, then permits a safe retry", async () => {
		const { context, table, factor, code, ctx } = await setup();
		await expect(
			runWithTransaction(context.adapter, async () => {
				const current = await currentFactor(context, table, factor.id);
				const result = await consumeBackupCodeForRecoveryRepair(
					ctx,
					current.adapter,
					table,
					current.factor,
					code,
				);
				expect(result.kind).toBe("authorized");
				throw new Error("rollback");
			}),
		).rejects.toThrow("rollback");
		const retried = await runWithTransaction(context.adapter, async () => {
			const current = await currentFactor(context, table, factor.id);
			return consumeBackupCodeForRecoveryRepair(
				ctx,
				current.adapter,
				table,
				current.factor,
				code,
			);
		});
		expect(retried.kind).toBe("authorized");
	});

	it("uses the configured custom two-factor table", async () => {
		const { context, table, factor, code, ctx } = await setup({
			table: "customTwoFactor",
		});
		const result = await runWithTransaction(context.adapter, async () => {
			const current = await currentFactor(context, table, factor.id);
			return consumeBackupCodeForRecoveryRepair(
				ctx,
				current.adapter,
				table,
				current.factor,
				code,
			);
		});
		expect(result.kind).toBe("authorized");
	});

	it("rejects a legacy-null row when the user-level factor marker is disabled", async () => {
		const { context, table, factor, code, ctx } = await setup({
			verified: null,
			twoFactorEnabled: false,
		});
		await expect(
			runWithTransaction(context.adapter, async () => {
				const current = await currentFactor(context, table, factor.id);
				expect(current.factor.verified).toBeNull();
				return consumeBackupCodeForRecoveryRepair(
					ctx,
					current.adapter,
					table,
					current.factor,
					code,
				);
			}),
		).rejects.toMatchObject({ status: "BAD_REQUEST" });
		const persisted = await context.adapter.findOne<TwoFactorTable>({
			model: table,
			where: [{ field: "id", value: factor.id }],
		});
		expect(persisted?.backupCodes).toBe(factor.backupCodes);
	});

	it("rejects an explicitly disabled factor before consuming its recovery code", async () => {
		const { context, table, factor, code, ctx } = await setup({
			verified: false,
			twoFactorEnabled: true,
		});
		await expect(
			runWithTransaction(context.adapter, async () => {
				const current = await currentFactor(context, table, factor.id);
				return consumeBackupCodeForRecoveryRepair(
					ctx,
					current.adapter,
					table,
					current.factor,
					code,
				);
			}),
		).rejects.toMatchObject({ status: "BAD_REQUEST" });
		const persisted = await context.adapter.findOne<TwoFactorTable>({
			model: table,
			where: [{ field: "id", value: factor.id }],
		});
		expect(persisted?.backupCodes).toBe(factor.backupCodes);
	});

	it("fails closed for reversible backup-code storage even when the code is valid", async () => {
		const { context, table, factor, code, ctx } = await setup({
			storedAs: "encrypted",
		});
		await expect(
			runWithTransaction(context.adapter, async () => {
				const current = await currentFactor(context, table, factor.id);
				return consumeBackupCodeForRecoveryRepair(
					ctx,
					current.adapter,
					table,
					current.factor,
					code,
				);
			}),
		).rejects.toMatchObject({ status: "BAD_REQUEST" });
	});

	it("requires the product's explicit hashed-storage configuration", async () => {
		const { context, table, factor, code, ctx } = await setup({
			configuredAs: "encrypted",
			storedAs: "hashed",
		});
		await expect(
			runWithTransaction(context.adapter, async () => {
				const current = await currentFactor(context, table, factor.id);
				return consumeBackupCodeForRecoveryRepair(
					ctx,
					current.adapter,
					table,
					current.factor,
					code,
				);
			}),
		).rejects.toMatchObject({ status: "BAD_REQUEST" });
	});
});
