import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	GenericEndpointContext,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyReader,
	RuntimeAuthenticationPolicyReaderInput,
} from "@clearance/core";
import { getCurrentAdapter, runWithTransaction } from "@clearance/core/context";
import { afterEach, describe, expect, it, vi } from "vitest";
import { init } from "../context/init";
import { getMigrations } from "../db/get-migration";
import { passkey } from "../plugins/passkey";
import { twoFactor } from "../plugins/two-factor";
import {
	consumeBackupCodeForRecoveryRepair,
	encodeBackupCodes,
} from "../plugins/two-factor/backup-codes";
import type { TwoFactorTable } from "../plugins/two-factor/types";
import { attachInternalAuthenticationPolicy } from "./authentication-policy";
import {
	completeRecoveryFactorRepair,
	consumePreloadedRecoveryFactorRepairCapability,
	createRecoveryFactorRepairBinding,
	createRecoveryFactorRepairBridge,
	inspectRecoveryFactorRepairAuthority,
	preloadRecoveryFactorRepairCapability,
	RECOVERY_FACTOR_REPAIR_COOKIE,
	rotateRecoveryFactorRepairCapability,
	startRecoveryFactorRepair,
} from "./recovery-factor-repair-context";
import {
	attachStagedAuthenticationContinuation,
	consumePreloadedStagedAuthenticationCapability,
	digestStagedAuthenticationPolicy,
	issueInitialStagedAuthenticationCapability,
	preloadStagedAuthenticationCapability,
	takeStagedAuthenticationContinuation,
} from "./staged-authentication-context";

const databases: DatabaseSync[] = [];
const identity = Object.freeze({
	projectId: "project_1",
	environmentId: "environment_1",
});

function policy(
	override: Partial<RuntimeAuthenticationPolicy> = {},
): RuntimeAuthenticationPolicy {
	return {
		passwordLockout: {
			enabled: true,
			maxFailedAttempts: 10,
			durationSeconds: 900,
		},
		factorLockout: {
			enabled: true,
			maxFailedAttempts: 10,
			durationSeconds: 900,
		},
		minimumAssurance: "multi_factor",
		allowedFactors: { totp: true, passkey: true },
		trustedDevice: { enabled: true, maxAgeSeconds: 86_400 },
		assuranceMaxAgeSeconds: 300,
		...override,
	};
}

async function createContext(input: {
	twoFactorTable?: string;
	policy?: RuntimeAuthenticationPolicy;
} = {}) {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	const twoFactorTable = input.twoFactorTable ?? "twoFactor";
	let revision = "7";
	let effective = input.policy ?? policy();
	const options = {
		baseURL: "http://localhost:3000",
		secret: "recovery-factor-repair-context-test-secret",
		database,
		plugins: [
			passkey(),
			twoFactor({
				twoFactorTable,
				backupCodeOptions: { storeBackupCodes: "hashed" },
			}),
		],
	} satisfies ClearanceOptions;
	attachInternalAuthenticationPolicy(options, {
		identity,
		reader: {
			async readForSubject(request: RuntimeAuthenticationPolicyReaderInput) {
				return {
					scope: identity,
					subjectId: request.subjectId,
					revision,
					environment: effective,
					organizationMembership: null,
					organizationOverride: null,
					effective,
				};
			},
		} satisfies RuntimeAuthenticationPolicyReader,
	});
	await (await getMigrations(options)).runMigrations();
	const context = await init(options);
	return {
		context,
		twoFactorTable,
		setRevision(value: string) {
			revision = value;
		},
		setPolicy(value: RuntimeAuthenticationPolicy) {
			effective = value;
		},
		getPolicy: () => effective,
	};
}

function endpoint(
	context: Awaited<ReturnType<typeof init>>,
	bearer: string,
) {
	return {
		context,
		getSignedCookie: vi.fn(async () => bearer),
		setSignedCookie: vi.fn(async () => {}),
	} as unknown as GenericEndpointContext;
}

async function createPasskey(
	context: Awaited<ReturnType<typeof init>>,
	userId: string,
	label: string,
) {
	const now = new Date();
	const adapter = await getCurrentAdapter(context.adapter);
	return adapter.create<Record<string, unknown> & { id: string }>({
		model: "passkey",
		data: {
			userId,
			name: "Repaired passkey",
			credentialID: `credential-${label}`,
			publicKey: "public-key",
			userHandle: `handle-${label}`,
			counter: 0,
			deviceType: "multiDevice",
			backedUp: true,
			createdAt: now,
			updatedAt: now,
		},
	});
}

async function createFixture(input: {
	repairFactor?: "passkey" | "totp";
	twoFactorTable?: string;
	withSession?: boolean;
	withPasskey?: boolean;
} = {}) {
	const runtime = await createContext({ twoFactorTable: input.twoFactorTable });
	const user = await runtime.context.internalAdapter.createUser({
		email: `repair-${databases.length}@example.test`,
		name: "Recovery repair user",
	});
	await runtime.context.adapter.update({
		model: "user",
		where: [{ field: "id", value: user.id }],
		update: { twoFactorEnabled: true },
	});
	const recoveryCode = "repair-code-1";
	const backupCodes = await encodeBackupCodes(
		[recoveryCode, "repair-code-2"],
		runtime.context.secretConfig,
		{ storeBackupCodes: "hashed" },
	);
	const factor = await runtime.context.adapter.create<TwoFactorTable>({
		model: runtime.twoFactorTable,
		data: {
			userId: user.id,
			secret: "source-encrypted-secret",
			backupCodes,
			verified: true,
			trustDeviceGeneration: "old-trust-generation",
		},
	});
	if (input.withPasskey) {
		await createPasskey(runtime.context, user.id, "old-passkey");
	}
	if (input.withSession) {
		const now = new Date();
		await runtime.context.adapter.create({
			model: "session",
			data: {
				userId: user.id,
				expiresAt: new Date(now.getTime() + 60_000),
				createdAt: now,
				updatedAt: now,
			},
		});
	}
	return {
		...runtime,
		user,
		factor,
		recoveryCode,
		repairFactor: input.repairFactor ?? "passkey",
	};
}

async function issueStaged(
	fixture: Awaited<ReturnType<typeof createFixture>>,
) {
	const error = new Error("managed authentication required");
	const primaryAt = new Date();
	attachStagedAuthenticationContinuation(error, {
		subjectId: fixture.user.id,
		projectId: identity.projectId,
		environmentId: identity.environmentId,
		organizationId: null,
		policyRevision: "7",
		policyDigest: await digestStagedAuthenticationPolicy(fixture.getPolicy()),
		primaryMethod: "password",
		primaryAt,
		dontRememberMe: true,
		allowedFactors: [fixture.repairFactor],
		expiresAt: new Date(primaryAt.getTime() + 119_000),
	});
	const seed = takeStagedAuthenticationContinuation(error);
	return runWithTransaction(fixture.context.adapter, () =>
		issueInitialStagedAuthenticationCapability(fixture.context, seed!),
	);
}

function publishedRecoveryBearer(ctx: GenericEndpointContext): string {
	const call = (ctx.setSignedCookie as ReturnType<typeof vi.fn>).mock.calls.find(
		(entry) =>
			String(entry[0]).includes(RECOVERY_FACTOR_REPAIR_COOKIE) &&
			typeof entry[1] === "string" &&
			entry[1].length > 0,
	);
	if (!call) throw new Error("Recovery bearer cookie was not published");
	return call[1] as string;
}

async function startRepair(
	fixture: Awaited<ReturnType<typeof createFixture>>,
) {
	const staged = await issueStaged(fixture);
	const ctx = endpoint(fixture.context, staged.bearer);
	const preloaded = await preloadStagedAuthenticationCapability(ctx, {
		stage: "select_factor",
		binding: "initial",
	});
	const stagedRecoveryBridge = await runWithTransaction(
		fixture.context.adapter,
		async () => {
		const stagedAuthority =
			await consumePreloadedStagedAuthenticationCapability(ctx, preloaded!);
		return createRecoveryFactorRepairBridge(
			ctx,
			stagedAuthority!,
			fixture.repairFactor,
		);
		},
	);
	const result = await runWithTransaction(fixture.context.adapter, async () => {
		const adapter = await getCurrentAdapter(fixture.context.adapter);
		const factor = await adapter.findOne<TwoFactorTable>({
			model: fixture.twoFactorTable,
			where: [{ field: "id", value: fixture.factor.id }],
		});
		const proof = await consumeBackupCodeForRecoveryRepair(
			ctx,
			adapter,
			fixture.twoFactorTable,
			factor!,
			fixture.recoveryCode,
		);
		if (proof.kind !== "authorized") throw proof.error;
		return startRecoveryFactorRepair(ctx, {
			stagedRecoveryBridge,
			recoveryProofAuthority: proof.authority,
			repairFactor: fixture.repairFactor,
		});
	});
	return { ctx, bearer: publishedRecoveryBearer(ctx), result };
}

async function rotateAndConsumeFinal(
	fixture: Awaited<ReturnType<typeof createFixture>>,
	bearer: string,
) {
	const selectCtx = endpoint(fixture.context, bearer);
	const preloaded = await preloadRecoveryFactorRepairCapability(selectCtx, {
		stage: "select_repair",
		binding: "initial",
		repairFactor: fixture.repairFactor,
	});
	let binding = "";
	await runWithTransaction(fixture.context.adapter, async () => {
		const authority = await consumePreloadedRecoveryFactorRepairCapability(
			selectCtx,
			preloaded!,
		);
		const lineage = inspectRecoveryFactorRepairAuthority(authority!);
		binding = await createRecoveryFactorRepairBinding(lineage!, [
			"test-ceremony",
			fixture.factor.id,
		]);
		await rotateRecoveryFactorRepairCapability(selectCtx, authority!, {
			stage:
				fixture.repairFactor === "passkey"
					? "passkey_registration"
					: "totp_enrollment_verification",
			binding,
		});
	});
	const successor = publishedRecoveryBearer(selectCtx);
	const finalCtx = endpoint(fixture.context, successor);
	const finalPreloaded = await preloadRecoveryFactorRepairCapability(finalCtx, {
		stage:
			fixture.repairFactor === "passkey"
				? "passkey_registration"
				: "totp_enrollment_verification",
		binding,
		repairFactor: fixture.repairFactor,
	});
	let authority: object | null = null;
	await runWithTransaction(fixture.context.adapter, async () => {
		authority = await consumePreloadedRecoveryFactorRepairCapability(
			finalCtx,
			finalPreloaded!,
		);
	});
	if (!authority) throw new Error("Final recovery authority was not consumed");
	return { ctx: finalCtx, authority, binding };
}

afterEach(() => {
	for (const database of databases.splice(0)) database.close();
});

describe("recovery-only factor repair authority", () => {
	it("rejects caller-fabricated recovery proof without mutating lifecycle state", async () => {
		const fixture = await createFixture({ withSession: true, withPasskey: true });
		const staged = await issueStaged(fixture);
		const ctx = endpoint(fixture.context, staged.bearer);
		const preloaded = await preloadStagedAuthenticationCapability(ctx, {
			stage: "select_factor",
		});
		const stagedRecoveryBridge = await runWithTransaction(
			fixture.context.adapter,
			async () => {
				const stagedAuthority =
					await consumePreloadedStagedAuthenticationCapability(ctx, preloaded!);
				return createRecoveryFactorRepairBridge(
					ctx,
					stagedAuthority!,
					"passkey",
				);
			},
		);
		await expect(
			runWithTransaction(fixture.context.adapter, async () => {
				return startRecoveryFactorRepair(ctx, {
					stagedRecoveryBridge,
					recoveryProofAuthority: Object.freeze({}),
					repairFactor: "passkey",
				});
			}),
		).rejects.toThrow("Invalid recovery repair authority");
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(1);
		expect(await fixture.context.adapter.count({ model: "passkey" })).toBe(1);
	});

	it("owns lifecycle rotation, trust revocation, and passkey/session deletion atomically", async () => {
		const fixture = await createFixture({ withSession: true, withPasskey: true });
		const before = await fixture.context.adapter.findOne<Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: fixture.user.id }],
		});
		const started = await startRepair(fixture);
		expect(started.result).toMatchObject({ status: true, repairFactor: "passkey" });
		expect(Object.keys(started.result).sort()).toEqual([
			"expiresAt",
			"repairFactor",
			"status",
		]);
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
		expect(await fixture.context.adapter.count({ model: "passkey" })).toBe(0);
		const user = await fixture.context.adapter.findOne<Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: fixture.user.id }],
		});
		expect(user?.passkeySessionGeneration).not.toBe(
			before?.passkeySessionGeneration,
		);
		expect(user?.twoFactorSessionGeneration).not.toBe(
			before?.twoFactorSessionGeneration,
		);
		const factor = await fixture.context.adapter.findOne<TwoFactorTable>({
			model: fixture.twoFactorTable,
			where: [{ field: "id", value: fixture.factor.id }],
		});
		expect(factor?.verified).toBe(true);
		expect(factor?.trustDeviceGeneration).not.toBe("old-trust-generation");
		const serialized = JSON.stringify(
			await fixture.context.adapter.findMany({ model: "verification" }),
		);
		expect(serialized).not.toContain(started.bearer);
		expect(serialized).not.toContain(fixture.recoveryCode);
		expect(serialized).not.toContain("source-encrypted-secret");
	});

	it("rolls back code use and every destructive mutation when start fails", async () => {
		const fixture = await createFixture({ withSession: true, withPasskey: true });
		const staged = await issueStaged(fixture);
		const ctx = endpoint(fixture.context, staged.bearer);
		const preloaded = await preloadStagedAuthenticationCapability(ctx, {
			stage: "select_factor",
		});
		const beforeFactor = await fixture.context.adapter.findOne<TwoFactorTable>({
			model: fixture.twoFactorTable,
			where: [{ field: "id", value: fixture.factor.id }],
		});
		const stagedRecoveryBridge = await runWithTransaction(
			fixture.context.adapter,
			async () => {
				const stagedAuthority =
					await consumePreloadedStagedAuthenticationCapability(ctx, preloaded!);
				return createRecoveryFactorRepairBridge(
					ctx,
					stagedAuthority!,
					"passkey",
				);
			},
		);
		await expect(
			runWithTransaction(fixture.context.adapter, async () => {
				const adapter = await getCurrentAdapter(fixture.context.adapter);
				const factor = await adapter.findOne<TwoFactorTable>({
					model: fixture.twoFactorTable,
					where: [{ field: "id", value: fixture.factor.id }],
				});
				const proof = await consumeBackupCodeForRecoveryRepair(
					ctx,
					adapter,
					fixture.twoFactorTable,
					factor!,
					fixture.recoveryCode,
				);
				if (proof.kind !== "authorized") throw proof.error;
				await startRecoveryFactorRepair(ctx, {
					stagedRecoveryBridge,
					recoveryProofAuthority: proof.authority,
					repairFactor: "passkey",
				});
				throw new Error("rollback start");
			}),
		).rejects.toThrow("rollback start");
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(1);
		expect(await fixture.context.adapter.count({ model: "passkey" })).toBe(1);
		const afterFactor = await fixture.context.adapter.findOne<TwoFactorTable>({
			model: fixture.twoFactorTable,
			where: [{ field: "id", value: fixture.factor.id }],
		});
		expect(afterFactor?.backupCodes).toBe(beforeFactor?.backupCodes);
		expect(afterFactor?.trustDeviceGeneration).toBe("old-trust-generation");
		expect(ctx.setSignedCookie).not.toHaveBeenCalled();
	});

	it("completes passkey repair with one fresh factor and no access artifact", async () => {
		const fixture = await createFixture({ withSession: true, withPasskey: true });
		const started = await startRepair(fixture);
		const intermediateUser =
			await fixture.context.adapter.findOne<Record<string, unknown>>({
				model: "user",
				where: [{ field: "id", value: fixture.user.id }],
			});
		const intermediateFactor =
			await fixture.context.adapter.findOne<TwoFactorTable>({
				model: fixture.twoFactorTable,
				where: [{ field: "id", value: fixture.factor.id }],
			});
		const final = await rotateAndConsumeFinal(fixture, started.bearer);
		const repairWindowNow = new Date();
		await fixture.context.adapter.create({
			model: "session",
			data: {
				userId: fixture.user.id,
				expiresAt: new Date(repairWindowNow.getTime() + 60_000),
				createdAt: repairWindowNow,
				updatedAt: repairWindowNow,
			},
		});
		const completion = await runWithTransaction(fixture.context.adapter, async () => {
			const repaired = await createPasskey(
				fixture.context,
				fixture.user.id,
				"new-passkey",
			);
			return completeRecoveryFactorRepair(final.ctx, final.authority, {
				binding: final.binding,
				repairFactor: "passkey",
				repairedFactorId: repaired.id,
			});
		});
		expect(completion).toEqual({ status: true, recoveryComplete: true });
		expect(Object.keys(completion)).toEqual(["status", "recoveryComplete"]);
		expect(JSON.stringify(completion)).not.toMatch(/session|token|user|authority/i);
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
		expect(await fixture.context.adapter.count({ model: "passkey" })).toBe(1);
		const finalUser =
			await fixture.context.adapter.findOne<Record<string, unknown>>({
				model: "user",
				where: [{ field: "id", value: fixture.user.id }],
			});
		const finalFactor = await fixture.context.adapter.findOne<TwoFactorTable>({
			model: fixture.twoFactorTable,
			where: [{ field: "id", value: fixture.factor.id }],
		});
		expect(finalUser?.passkeySessionGeneration).not.toBe(
			intermediateUser?.passkeySessionGeneration,
		);
		expect(finalUser?.twoFactorSessionGeneration).not.toBe(
			intermediateUser?.twoFactorSessionGeneration,
		);
		expect(finalFactor?.trustDeviceGeneration).not.toBe(
			intermediateFactor?.trustDeviceGeneration,
		);
	});

	it("requires fresh TOTP material on the exact custom-table factor", async () => {
		const fixture = await createFixture({
			repairFactor: "totp",
			twoFactorTable: "customTwoFactor",
			withSession: true,
		});
		const started = await startRepair(fixture);
		const pending = await fixture.context.adapter.findOne<TwoFactorTable>({
			model: fixture.twoFactorTable,
			where: [{ field: "id", value: fixture.factor.id }],
		});
		expect(pending).toMatchObject({
			verified: false,
			pendingSecret: null,
			pendingBackupCodes: null,
		});
		const final = await rotateAndConsumeFinal(fixture, started.bearer);
		const nextBackupCodes = await encodeBackupCodes(
			["new-recovery-code"],
			fixture.context.secretConfig,
			{ storeBackupCodes: "hashed" },
		);
		const completion = await runWithTransaction(fixture.context.adapter, async () => {
			const adapter = await getCurrentAdapter(fixture.context.adapter);
			await adapter.update({
				model: fixture.twoFactorTable,
				where: [{ field: "id", value: fixture.factor.id }],
				update: {
					secret: "fresh-encrypted-secret",
					backupCodes: nextBackupCodes,
					verified: true,
					pendingSecret: null,
					pendingBackupCodes: null,
					lastUsedTotpCounter: 0,
				},
			});
			await adapter.update({
				model: "user",
				where: [{ field: "id", value: fixture.user.id }],
				update: { twoFactorEnabled: true },
			});
			return completeRecoveryFactorRepair(final.ctx, final.authority, {
				binding: final.binding,
				repairFactor: "totp",
				repairedFactorId: fixture.factor.id,
			});
		});
		expect(completion).toEqual({ status: true, recoveryComplete: true });
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(0);
		expect(final.ctx.setSignedCookie).toHaveBeenCalledWith(
			expect.stringContaining(RECOVERY_FACTOR_REPAIR_COOKIE),
			"",
			fixture.context.secret,
			expect.objectContaining({ maxAge: 0, httpOnly: true, sameSite: "lax" }),
		);
	});

	it("fails closed when policy authority changes before recovery start", async () => {
		const fixture = await createFixture({ withSession: true, withPasskey: true });
		const staged = await issueStaged(fixture);
		const ctx = endpoint(fixture.context, staged.bearer);
		const preloaded = await preloadStagedAuthenticationCapability(ctx, {
			stage: "select_factor",
		});
		const stagedRecoveryBridge = await runWithTransaction(
			fixture.context.adapter,
			async () => {
				const stagedAuthority =
					await consumePreloadedStagedAuthenticationCapability(ctx, preloaded!);
				return createRecoveryFactorRepairBridge(
					ctx,
					stagedAuthority!,
					"passkey",
				);
			},
		);
		fixture.setRevision("8");
		await expect(
			runWithTransaction(fixture.context.adapter, async () => {
				const adapter = await getCurrentAdapter(fixture.context.adapter);
				const factor = await adapter.findOne<TwoFactorTable>({
					model: fixture.twoFactorTable,
					where: [{ field: "id", value: fixture.factor.id }],
				});
				const proof = await consumeBackupCodeForRecoveryRepair(
					ctx,
					adapter,
					fixture.twoFactorTable,
					factor!,
					fixture.recoveryCode,
				);
				if (proof.kind !== "authorized") throw proof.error;
				return startRecoveryFactorRepair(ctx, {
					stagedRecoveryBridge,
					recoveryProofAuthority: proof.authority,
					repairFactor: "passkey",
				});
			}),
		).rejects.toThrow("policy changed");
		expect(await fixture.context.adapter.count({ model: "session" })).toBe(1);
		expect(await fixture.context.adapter.count({ model: "passkey" })).toBe(1);
	});
});
