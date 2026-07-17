import { DatabaseSync } from "node:sqlite";
import type { ClearanceOptions, GenericEndpointContext } from "@clearance/core";
import { runWithTransaction } from "@clearance/core/context";
import { createHash } from "@clearance/utils/hash";
import { afterEach, describe, expect, it, vi } from "vitest";
import { init } from "../context/init";
import { dispatchAuthEndpoint } from "../api/dispatch";
import { getMigrations } from "../db/get-migration";
import { passkey } from "../plugins/passkey";
import { twoFactor } from "../plugins/two-factor";
import {
	attachStagedAuthenticationContinuation,
	consumePreloadedStagedAuthenticationCapability,
	createStagedAuthenticationBinding,
	createStagedAuthenticationRecoveryRepairBridge,
	createStagedSessionIssuanceContext,
	expireStagedAuthenticationCookie,
	getStagedAuthenticationFactorInventory,
	inspectStagedAuthenticationAuthority,
	issueInitialStagedAuthenticationCapability,
	preloadStagedAuthenticationCapability,
	readStagedAuthenticationLineage,
	rotateStagedAuthenticationCapability,
	takeStagedAuthenticationRecoveryRepairBridge,
	takeStagedAuthenticationContinuation,
} from "./staged-authentication-context";

const databases: DatabaseSync[] = [];

async function createContext(plugins?: ClearanceOptions["plugins"]) {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	const options = {
		baseURL: "http://localhost:3000",
		secret: "staged-authentication-context-test-secret",
		database,
		...(plugins ? { plugins } : {}),
	};
	await (await getMigrations(options)).runMigrations();
	return init(options);
}

function endpoint(
	context: Awaited<ReturnType<typeof createContext>>,
	bearer: string,
) {
	return {
		context,
		getSignedCookie: vi.fn(async () => bearer),
		setSignedCookie: vi.fn(async () => {}),
	} as unknown as GenericEndpointContext;
}

async function issue(
	context: Awaited<ReturnType<typeof createContext>>,
	input: Partial<{
		subjectId: string;
		policyRevision: string;
		policyDigest: string;
		primaryAt: Date;
		expiresAt: Date;
		allowedFactors: readonly ("passkey" | "totp")[];
	}> = {},
) {
	const now = new Date();
	const primaryAt = input.primaryAt ?? now;
	const error = new Error("managed authentication required");
	attachStagedAuthenticationContinuation(error, {
		subjectId: input.subjectId ?? "user_1",
		projectId: "project_1",
		environmentId: "environment_1",
		organizationId: null,
		policyRevision: input.policyRevision ?? "7",
		policyDigest:
			input.policyDigest ?? "a".repeat(43),
		primaryMethod: "password",
		primaryAt,
		dontRememberMe: true,
		allowedFactors: input.allowedFactors ?? ["passkey", "totp"],
		expiresAt:
			input.expiresAt ?? new Date(primaryAt.getTime() + 120_000),
	});
	const seed = takeStagedAuthenticationContinuation(error);
	expect(seed).not.toBeNull();
	return runWithTransaction(context.adapter, () =>
		issueInitialStagedAuthenticationCapability(context, seed!),
	);
}

afterEach(() => {
	for (const database of databases.splice(0)) database.close();
});

describe("staged authentication continuation authority", () => {
	it("converts a private continuation into a non-cacheable 403 with a signed cookie", async () => {
		const context = await createContext();
		const failure = new Error("managed authentication required");
		const now = new Date();
		attachStagedAuthenticationContinuation(failure, {
			subjectId: "user_1",
			projectId: "project_1",
			environmentId: "environment_1",
			organizationId: null,
			policyRevision: "7",
			policyDigest: "a".repeat(43),
			primaryMethod: "password",
			primaryAt: now,
			dontRememberMe: true,
			allowedFactors: ["passkey"],
			expiresAt: new Date(now.getTime() + 120_000),
		});
		const handler = Object.assign(async () => {
			throw failure;
		}, {
			path: "/managed-authentication-test",
			options: { method: "POST" },
		});
		const response = await dispatchAuthEndpoint(handler as never, {
			context,
			request: new Request("http://localhost:3000/managed-authentication-test", {
				method: "POST",
			}),
		});

		expect(response).toBeInstanceOf(Response);
		const http = response as Response;
		expect(http.status).toBe(403);
		expect(http.headers.get("cache-control")).toBe("no-store");
		expect(http.headers.get("pragma")).toBe("no-cache");
		expect(http.headers.get("set-cookie")).toContain(
			"managed_authentication_remediation=",
		);
		expect(await http.json()).toMatchObject({
			code: "MANAGED_AUTHENTICATION_REQUIRED",
			allowedFactors: ["passkey"],
		});
	});

	it("persists only a namespaced bearer digest and bounded metadata", async () => {
		const context = await createContext();
		const issued = await issue(context);
		const digest = await createHash("SHA-256", "base64urlnopad").digest(
			`managed-authentication-remediation:v1:${issued.bearer}`,
		);
		const stored = await context.internalAdapter.findVerificationValue(
			`managed-authentication-remediation:v1:${digest}`,
		);

		expect(issued.cookie.attributes).toMatchObject({
			httpOnly: true,
			sameSite: "lax",
		});
		expect(issued.cookie.attributes.maxAge).toBeGreaterThan(0);
		expect(stored?.value).not.toContain(issued.bearer);
		expect(stored?.value).toContain('"stage":"select_factor"');
		expect(stored?.value).toContain('"organizationId":null');
	});

	it("consumes exactly once in a transaction and preserves the original primary time", async () => {
		const context = await createContext();
		const primaryAt = new Date(Date.now() - 1_000);
		const issued = await issue(context, { primaryAt });
		const first = endpoint(context, issued.bearer);
		const second = endpoint(context, issued.bearer);
		const firstPreload = await preloadStagedAuthenticationCapability(first, {
			stage: "select_factor",
			binding: "initial",
		});
		const secondPreload = await preloadStagedAuthenticationCapability(second, {
			stage: "select_factor",
			binding: "initial",
		});
		expect(firstPreload).not.toBeNull();
		expect(secondPreload).not.toBeNull();

		const winner = await runWithTransaction(context.adapter, () =>
			consumePreloadedStagedAuthenticationCapability(first, firstPreload!),
		);
		const loser = await runWithTransaction(context.adapter, () =>
			consumePreloadedStagedAuthenticationCapability(second, secondPreload!),
		);
		expect(winner).not.toBeNull();
		expect(loser).toBeNull();
		expect(inspectStagedAuthenticationAuthority(winner!)).toMatchObject({
			subjectId: "user_1",
			dontRememberMe: true,
			stage: "select_factor",
		});

		await expect(
			createStagedSessionIssuanceContext(first, winner!, {
				factorMethod: "passkey",
				factorAt: new Date(),
				binding: "initial",
			}),
		).rejects.toThrow("Invalid staged authentication proof");
	});

	it("rejects forged, wrong-stage, expired, and replayed capabilities", async () => {
		const context = await createContext();
		const issued = await issue(context);
		const ctx = endpoint(context, issued.bearer);
		expect(
			await preloadStagedAuthenticationCapability(ctx, {
				stage: "passkey_authentication",
				binding: "initial",
			}),
		).toBeNull();
		expect(
			await consumePreloadedStagedAuthenticationCapability(ctx, {}),
		).toBeNull();

		const preloaded = await preloadStagedAuthenticationCapability(ctx, {
			stage: "select_factor",
			binding: "initial",
		});
		let authority: object | null = null;
		const successor = await runWithTransaction(context.adapter, async () => {
			authority = await consumePreloadedStagedAuthenticationCapability(
				ctx,
				preloaded!,
			);
			expect(authority).not.toBeNull();
			return rotateStagedAuthenticationCapability(ctx, authority!, {
				stage: "passkey_authentication",
				binding: "challenge_1",
			});
		});
		expect(successor).toMatchObject({
			stage: "passkey_authentication",
			binding: "challenge_1",
		});
		if (!authority) throw new Error("Expected a consumed authority");
		await expect(
			rotateStagedAuthenticationCapability(ctx, authority, {
				stage: "passkey_authentication",
				binding: "challenge_2",
			}),
		).rejects.toThrow("Invalid staged authentication rotation");

		const expired = await issue(context, {
			expiresAt: new Date(Date.now() + 50),
		});
		await new Promise((resolve) => setTimeout(resolve, 60));
		expect(
			await preloadStagedAuthenticationCapability(endpoint(context, expired.bearer), {
				stage: "select_factor",
				binding: "initial",
			}),
		).toBeNull();
	});

	it("keeps stable ceremony binding across a successor lineage and rejects rollback survivors", async () => {
		const context = await createContext();
		const issued = await issue(context);
		const ctx = endpoint(context, issued.bearer);
		const preloaded = await preloadStagedAuthenticationCapability(ctx, {
			stages: ["select_factor"],
		});
		let rolledBack: object | null = null;
		await expect(
			runWithTransaction(context.adapter, async () => {
				rolledBack = await consumePreloadedStagedAuthenticationCapability(
					ctx,
					preloaded!,
				);
				throw new Error("rollback");
			}),
		).rejects.toThrow("rollback");
		if (!rolledBack) throw new Error("Expected a pending rollback authority");
		const rollbackAuthority = rolledBack;
		await expect(
			runWithTransaction(context.adapter, () =>
				rotateStagedAuthenticationCapability(ctx, rollbackAuthority, {
					stage: "passkey_authentication",
					binding: "unreachable",
				}),
			),
		).rejects.toThrow("Invalid staged authentication rotation");
		await expect(
			runWithTransaction(context.adapter, () =>
				createStagedSessionIssuanceContext(ctx, rollbackAuthority, {
					factorMethod: "passkey",
					factorAt: new Date(),
					binding: "unreachable",
				}),
			),
		).rejects.toThrow("Invalid staged authentication authority");

		const replay = await preloadStagedAuthenticationCapability(ctx, {
			stages: ["select_factor"],
		});
		let authority: object | null = null;
		let initialLineage: ReturnType<typeof readStagedAuthenticationLineage>;
		const successor = await runWithTransaction(context.adapter, async () => {
			authority = await consumePreloadedStagedAuthenticationCapability(ctx, replay!);
			initialLineage = readStagedAuthenticationLineage(authority!);
			expect(initialLineage).not.toBeNull();
			return rotateStagedAuthenticationCapability(ctx, authority!, {
				stage: "totp_authentication",
				binding: "totp_challenge_1",
			});
		});
		expect(successor.parentDigest).not.toBe(initialLineage!.parentDigest);
		expect(
			await createStagedAuthenticationBinding(initialLineage!, [
				"two_factor_1",
				"ciphertext_fingerprint_1",
			]),
		).toBe(
			await createStagedAuthenticationBinding(successor, [
				"two_factor_1",
				"ciphertext_fingerprint_1",
			]),
		);
	});

	it("expires the signed remediation cookie only after its transaction commits", async () => {
		const context = await createContext();
		const ctx = endpoint(context, "unused");
		await runWithTransaction(context.adapter, () =>
			expireStagedAuthenticationCookie(ctx),
		);
		expect(ctx.setSignedCookie).toHaveBeenCalledWith(
			expect.stringContaining("managed_authentication_remediation"),
			"",
			context.secret,
			expect.objectContaining({ maxAge: 0, httpOnly: true, sameSite: "lax" }),
		);
	});

	it("accepts legacy TOTP only while the user-level factor marker remains enabled", async () => {
		const context = await createContext([passkey(), twoFactor()]);
		const user = await context.internalAdapter.createUser({
			email: "staged-inventory@example.test",
			name: "Staged inventory user",
		});
		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: user.id }],
			update: { twoFactorEnabled: true },
		});
		await context.adapter.create({
			model: "twoFactor",
			data: {
				userId: user.id,
				secret: "legacy-ciphertext",
				backupCodes: "legacy-backup-codes",
				verified: null,
			},
		});
		const readInventory = async () => {
			const issued = await issue(context, { subjectId: user.id });
			const ctx = endpoint(context, issued.bearer);
			const preloaded = await preloadStagedAuthenticationCapability(ctx, {
				stages: ["select_factor"],
			});
			return runWithTransaction(context.adapter, async () => {
				const authority = await consumePreloadedStagedAuthenticationCapability(
					ctx,
					preloaded!,
				);
				return getStagedAuthenticationFactorInventory(ctx, authority!);
			});
		};
		expect(await readInventory()).toMatchObject({
			passkey: false,
			totp: true,
			totpRecord: { secret: "legacy-ciphertext" },
		});
		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: user.id }],
			update: { twoFactorEnabled: false },
		});
		expect(await readInventory()).toMatchObject({
			passkey: false,
			totp: false,
			totpRecord: null,
		});
	});

	it("commits a one-shot recovery bridge that is rollback-safe and session-ineligible", async () => {
		const context = await createContext();
		const issued = await issue(context, { allowedFactors: ["passkey"] });
		const ctx = endpoint(context, issued.bearer);
		const preloaded = await preloadStagedAuthenticationCapability(ctx, {
			stage: "select_factor",
		});
		let stagedAuthority: object | null = null;
		const bridge = await runWithTransaction(context.adapter, async () => {
			stagedAuthority = await consumePreloadedStagedAuthenticationCapability(
				ctx,
				preloaded!,
			);
			return createStagedAuthenticationRecoveryRepairBridge(
				ctx,
				stagedAuthority!,
				"passkey",
			);
		});
		await expect(
			createStagedSessionIssuanceContext(ctx, stagedAuthority!, {
				factorMethod: "passkey",
				factorAt: new Date(),
				binding: "initial",
			}),
		).rejects.toThrow("Invalid staged authentication authority");
		const taken = await runWithTransaction(context.adapter, () =>
			takeStagedAuthenticationRecoveryRepairBridge(ctx, bridge),
		);
		expect(taken).toMatchObject({
			subjectId: "user_1",
			repairFactor: "passkey",
			projectId: "project_1",
			environmentId: "environment_1",
		});
		expect(
			await runWithTransaction(context.adapter, () =>
				takeStagedAuthenticationRecoveryRepairBridge(ctx, bridge),
			),
		).toBeNull();

		const rolledIssue = await issue(context, { allowedFactors: ["passkey"] });
		const rolledCtx = endpoint(context, rolledIssue.bearer);
		const rolledPreload = await preloadStagedAuthenticationCapability(rolledCtx, {
			stage: "select_factor",
		});
		let rolledBridge: object | null = null;
		await expect(
			runWithTransaction(context.adapter, async () => {
				const authority =
					await consumePreloadedStagedAuthenticationCapability(
						rolledCtx,
						rolledPreload!,
					);
				rolledBridge = await createStagedAuthenticationRecoveryRepairBridge(
					rolledCtx,
					authority!,
					"passkey",
				);
				throw new Error("rollback");
			}),
		).rejects.toThrow("rollback");
		expect(
			await runWithTransaction(context.adapter, () =>
				takeStagedAuthenticationRecoveryRepairBridge(
					rolledCtx,
					rolledBridge!,
				),
			),
		).toBeNull();
	});

	it("reads eligible TOTP authority from the configured custom table", async () => {
		const context = await createContext([
			twoFactor({ twoFactorTable: "customTwoFactor" }),
		]);
		const user = await context.internalAdapter.createUser({
			email: "staged-custom-table@example.test",
			name: "Staged custom table user",
		});
		await context.adapter.create({
			model: "customTwoFactor",
			data: {
				userId: user.id,
				secret: "custom-table-ciphertext",
				backupCodes: "custom-table-backup-codes",
				verified: true,
			},
		});
		const issued = await issue(context, { subjectId: user.id });
		const ctx = endpoint(context, issued.bearer);
		const preloaded = await preloadStagedAuthenticationCapability(ctx, {
			stage: "select_factor",
		});
		const inventory = await runWithTransaction(context.adapter, async () => {
			const authority = await consumePreloadedStagedAuthenticationCapability(
				ctx,
				preloaded!,
			);
			return getStagedAuthenticationFactorInventory(ctx, authority!);
		});
		expect(inventory).toMatchObject({
			passkey: false,
			totp: true,
			totpRecord: { secret: "custom-table-ciphertext" },
		});
	});
});
