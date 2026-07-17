import { DatabaseSync } from "node:sqlite";
import type {
	ClearanceOptions,
	RuntimeAuthenticationPolicy,
	RuntimeAuthenticationPolicyReaderInput,
	RuntimeAuthenticationPolicyReaderResult,
} from "@clearance/core";
import { createAuthEndpoint } from "@clearance/core/api";
import { runWithRequestState } from "@clearance/core/context";
import type { Endpoint } from "@clearance/call";
import { createOTP } from "@clearance/utils/otp";
import { afterEach, describe, expect, it, vi } from "vitest";
import { dispatchAuthEndpoint } from "../../../api/dispatch";
import { init } from "../../../context/init";
import { symmetricDecrypt, symmetricEncrypt } from "../../../crypto";
import { getMigrations } from "../../../db/get-migration";
import {
	attachInternalAuthenticationPolicy,
	type InternalRuntimeAuthenticationPolicyBinding,
} from "../../../internal/authentication-policy";
import { createInternalSessionIssuanceContext } from "../../../internal/session-issuance-context";
import { generateBackupCodes } from "../backup-codes";
import { twoFactor } from "..";
import type { TwoFactorTable } from "../types";

const databases: DatabaseSync[] = [];
const identity = Object.freeze({
	projectId: "recovery-totp-project",
	environmentId: "recovery-totp-environment",
});

const policy: RuntimeAuthenticationPolicy = {
	passwordLockout: { enabled: true, maxFailedAttempts: 10, durationSeconds: 900 },
	factorLockout: { enabled: true, maxFailedAttempts: 3, durationSeconds: 900 },
	minimumAssurance: "multi_factor",
	allowedFactors: { passkey: false, totp: true },
	trustedDevice: { enabled: false, maxAgeSeconds: 0 },
	assuranceMaxAgeSeconds: 300,
};

async function setup(
	lockoutEnabled = true,
	replacementCodes: string[] = ["replacement-recovery-code"],
	sourceCodes: string[] = ["recovery-code"],
) {
	const database = new DatabaseSync(":memory:");
	databases.push(database);
	const table = "recoveryTotpFactor";
	let revision = "1";
	const plugin = twoFactor({
		twoFactorTable: table,
		backupCodeOptions: {
			storeBackupCodes: "hashed",
			customBackupCodesGenerate: () => replacementCodes,
		},
		accountLockout: { enabled: lockoutEnabled, maxFailedAttempts: 2 },
	});
	const options = {
		baseURL: "http://localhost:3000",
		secret: "recovery-totp-test-secret-with-sufficient-length",
		database,
		plugins: [plugin],
	} satisfies ClearanceOptions;
	const reader = {
		async readForSubject(
			input: RuntimeAuthenticationPolicyReaderInput,
		): Promise<RuntimeAuthenticationPolicyReaderResult> {
			return {
				scope: identity,
				subjectId: input.subjectId,
				revision,
				environment: policy,
				organizationMembership: null,
				organizationOverride: null,
				effective: policy,
			};
		},
	} satisfies InternalRuntimeAuthenticationPolicyBinding["reader"];
	attachInternalAuthenticationPolicy(options, { identity, reader });
	await (await getMigrations(options)).runMigrations();
	const context = await init(options);
	const user = await context.internalAdapter.createUser({
		email: "recovery-totp@example.test",
		name: "Recovery TOTP user",
	});
	const backupCodes = await generateBackupCodes(context.secretConfig, {
		storeBackupCodes: "hashed",
		customBackupCodesGenerate: () => sourceCodes,
	});
	await context.adapter.create<TwoFactorTable>({
		model: table,
		data: {
			userId: user.id,
			secret: await symmetricEncrypt({
				key: context.secretConfig,
				data: "original-totp-secret",
			}),
			backupCodes: backupCodes.encryptedBackupCodes,
			verified: true,
			failedVerificationCount: 0,
			activeVerificationReservations: "[]",
			lastUsedTotpCounter: -1,
			trustDeviceGeneration: "original-recovery-trust",
		},
	});
	await context.internalAdapter.updateUser(user.id, { twoFactorEnabled: true });
	return {
		context,
		user,
		table,
		endpoints: plugin.endpoints!,
		setRevision(value: string) {
			revision = value;
		},
	};
}

function primaryEndpoint(userId: string) {
	return createAuthEndpoint("/recovery-totp/start", { method: "POST" }, async (ctx) => {
		await ctx.context.internalAdapter.createSession(
			userId,
			false,
			undefined,
			false,
			createInternalSessionIssuanceContext({
				purpose: "interactive",
				subjectId: userId,
				evidence: [{ kind: "primary", primaryMethod: "password" }],
			}),
		);
		return ctx.json({ unexpected: true });
	});
}

async function dispatch(
	context: Awaited<ReturnType<typeof init>>,
	endpoint: Endpoint,
	cookie?: string,
	body: Record<string, unknown> = {},
) {
	const headers = new Headers({ "content-type": "application/json" });
	if (cookie) headers.set("cookie", cookie);
	return runWithRequestState(
		new WeakMap(),
		async () =>
			(await dispatchAuthEndpoint(endpoint, {
				context,
				headers,
				body,
				request: new Request(`http://localhost:3000${endpoint.path}`, {
					method: "POST",
					headers,
					body: JSON.stringify(body),
				}),
				asResponse: true,
			})) as Response,
	);
}

function cookie(response: Response, name: string) {
	const value = response.headers
		.getSetCookie()
		.find((entry) => entry.slice(0, entry.indexOf("=")).endsWith(name));
	expect(value).toBeTruthy();
	return value!.split(";", 1)[0]!;
}

async function beginEnrollment(runtime: Awaited<ReturnType<typeof setup>>) {
	const staged = await dispatch(
		runtime.context,
		primaryEndpoint(runtime.user.id),
	);
	expect(staged.status).toBe(403);
	const handoff = await dispatch(
		runtime.context,
		runtime.endpoints.recoveryFactorRepair!,
		cookie(staged, "managed_authentication_remediation"),
		{ repairFactor: "totp", recoveryCode: "recovery-code" },
	);
	expect(handoff.status, await handoff.clone().text()).toBe(200);
	const enrolled = await dispatch(
		runtime.context,
		runtime.endpoints.recoveryRepairTOTPOptions!,
		cookie(handoff, "recovery_factor_repair"),
	);
	expect(enrolled.status, await enrolled.clone().text()).toBe(200);
	const factor = (await runtime.context.adapter.findOne<TwoFactorTable>({
		model: runtime.table,
		where: [{ field: "userId", value: runtime.user.id }],
	}))!;
	return {
		handoff,
		enrolled,
		factor,
		cookie: cookie(enrolled, "recovery_factor_repair"),
		secret: await symmetricDecrypt({
			key: runtime.context.secretConfig,
			data: factor.pendingSecret!,
		}),
	};
}

afterEach(() => {
	for (const database of databases.splice(0)) database.close();
});

describe.sequential("recovery-only TOTP repair", () => {
	it("requires a fresh primary after an invalid recovery code", async () => {
		const runtime = await setup();
		const firstPrimary = await dispatch(
			runtime.context,
			primaryEndpoint(runtime.user.id),
		);
		const invalid = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryFactorRepair!,
			cookie(firstPrimary, "managed_authentication_remediation"),
			{ repairFactor: "totp", recoveryCode: "wrong-recovery-code" },
		);
		expect(invalid.status).toBe(401);
		expect((await invalid.json()).code).toBe("INVALID_BACKUP_CODE");
		const factorAfterFailure = await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
		});
		expect(factorAfterFailure?.verified).toBe(true);

		const secondPrimary = await dispatch(
			runtime.context,
			primaryEndpoint(runtime.user.id),
		);
		const retried = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryFactorRepair!,
			cookie(secondPrimary, "managed_authentication_remediation"),
			{ repairFactor: "totp", recoveryCode: "recovery-code" },
		);
		expect(retried.status, await retried.clone().text()).toBe(200);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("repairs a custom-table TOTP factor without issuing a session or token", async () => {
		const runtime = await setup();
		const staged = await dispatch(
			runtime.context,
			primaryEndpoint(runtime.user.id),
		);
		expect(staged.status).toBe(403);
		const handoff = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryFactorRepair!,
			cookie(staged, "managed_authentication_remediation"),
			{ repairFactor: "totp", recoveryCode: "recovery-code" },
		);
		expect(handoff.status, await handoff.clone().text()).toBe(200);
		expect(handoff.headers.get("cache-control")).toBe("no-store");
		expect(await handoff.clone().json()).toMatchObject({
			status: true,
			repairFactor: "totp",
		});
		expect(await handoff.clone().json()).not.toHaveProperty("token");
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);

		const enrolled = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPOptions!,
			cookie(handoff, "recovery_factor_repair"),
		);
		expect(enrolled.status, await enrolled.clone().text()).toBe(200);
		const enrollment = (await enrolled.clone().json()) as {
			mode: string;
			backupCodes: string[];
		};
		expect(enrollment).toMatchObject({ mode: "enrollment" });
		expect(enrollment.backupCodes).toEqual(["replacement-recovery-code"]);
		const factor = (await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
		}))!;
		expect(factor.verified).toBe(false);
		expect(factor.pendingBackupCodes).toMatch(/^clr-recovery:v1:/);
		const secret = await symmetricDecrypt({
			key: runtime.context.secretConfig,
			data: factor.pendingSecret!,
		});

		const verified = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			cookie(enrolled, "recovery_factor_repair"),
			{ code: await createOTP(secret).totp() },
		);
		expect(verified.status, await verified.clone().text()).toBe(200);
		expect(await verified.json()).toEqual({ status: true, recoveryComplete: true });
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		const repaired = (await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
		}))!;
		expect(repaired.verified).toBe(true);
		expect(repaired.pendingSecret).toBeNull();
		expect(repaired.pendingBackupCodes).toBeNull();
		expect(repaired.lastUsedTotpCounter).toBeGreaterThanOrEqual(0);
		const replay = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			cookie(enrolled, "recovery_factor_repair"),
			{ code: await createOTP(secret).totp() },
		);
		expect(replay.status).toBe(401);
	});

	it("rejects the old secret, records the failure, and permits one retry", async () => {
		const runtime = await setup();
		const enrollment = await beginEnrollment(runtime);
		const invalid = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			enrollment.cookie,
			{ code: await createOTP("original-totp-secret").totp() },
		);
		expect(invalid.status).toBe(401);
		expect(await invalid.clone().json()).toMatchObject({ code: "INVALID_CODE" });
		const failed = (await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
		}))!;
		expect(failed.failedVerificationCount).toBe(1);
		const retried = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			cookie(invalid, "recovery_factor_repair"),
			{ code: await createOTP(enrollment.secret).totp() },
		);
		expect(retried.status, await retried.clone().text()).toBe(200);
		expect(await retried.json()).toEqual({ status: true, recoveryComplete: true });
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("maps corrupt pending secret material to a generic terminal recovery failure", async () => {
		const runtime = await setup();
		const enrollment = await beginEnrollment(runtime);
		await runtime.context.adapter.update({
			model: runtime.table,
			where: [{ field: "id", value: enrollment.factor.id }],
			update: { pendingSecret: "corrupt-recovery-secret-envelope" },
		});
		const response = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			enrollment.cookie,
			{ code: "123456" },
		);
		expect(response.status).toBe(401);
		expect(await response.clone().json()).toMatchObject({
			code: "INVALID_STAGED_AUTHENTICATION",
		});
		const factor = (await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "id", value: enrollment.factor.id }],
		}))!;
		expect(factor.verified).toBe(false);
		expect(factor.failedVerificationCount).toBe(0);
		expect(factor.activeVerificationReservations).toBe("[]");
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("enforces recovery lockout while invalid attempts rotate one-use retries", async () => {
		const runtime = await setup();
		const enrollment = await beginEnrollment(runtime);
		const first = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			enrollment.cookie,
			{ code: "000000" },
		);
		expect(first.status).toBe(401);
		const second = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			cookie(first, "recovery_factor_repair"),
			{ code: "000000" },
		);
		expect(second.status).toBe(401);
		const factor = (await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
		}))!;
		expect(factor.failedVerificationCount).toBe(2);
		expect(factor.lockedUntil).toBeInstanceOf(Date);
	});

	it("refuses TOTP recovery when durable attempt lockout is disabled", async () => {
		const runtime = await setup(false);
		const staged = await dispatch(
			runtime.context,
			primaryEndpoint(runtime.user.id),
		);
		expect(staged.status).toBe(403);
		const handoff = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryFactorRepair!,
			cookie(staged, "managed_authentication_remediation"),
			{ repairFactor: "totp", recoveryCode: "recovery-code" },
		);
		expect(handoff.status).toBe(401);
		const factor = await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
		});
		expect(factor?.verified).toBe(true);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("rejects replacement backup codes that overlap consumed source authority", async () => {
		const runtime = await setup(true, ["recovery-code"]);
		const staged = await dispatch(
			runtime.context,
			primaryEndpoint(runtime.user.id),
		);
		const handoff = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryFactorRepair!,
			cookie(staged, "managed_authentication_remediation"),
			{ repairFactor: "totp", recoveryCode: "recovery-code" },
		);
		expect(handoff.status).toBe(200);
		const enrolled = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPOptions!,
			cookie(handoff, "recovery_factor_repair"),
		);
		expect(enrolled.status).toBe(401);
		const factor = await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
		});
		expect(factor?.pendingSecret).toBeNull();
		expect(factor?.pendingBackupCodes).toBeNull();
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("rejects replacement backup codes that overlap remaining source codes", async () => {
		const runtime = await setup(
			true,
			["still-valid-source-code"],
			["recovery-code", "still-valid-source-code"],
		);
		const staged = await dispatch(
			runtime.context,
			primaryEndpoint(runtime.user.id),
		);
		const handoff = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryFactorRepair!,
			cookie(staged, "managed_authentication_remediation"),
			{ repairFactor: "totp", recoveryCode: "recovery-code" },
		);
		expect(handoff.status).toBe(200);
		const enrolled = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPOptions!,
			cookie(handoff, "recovery_factor_repair"),
		);
		expect(enrolled.status).toBe(401);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("fails closed when policy drifts after enrollment", async () => {
		const runtime = await setup();
		const enrollment = await beginEnrollment(runtime);
		runtime.setRevision("2");
		const response = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			enrollment.cookie,
			{ code: await createOTP(enrollment.secret).totp() },
		);
		expect(response.status).toBe(401);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("rejects recovery after the user-level factor marker is disabled", async () => {
		const runtime = await setup();
		const enrollment = await beginEnrollment(runtime);
		await runtime.context.internalAdapter.updateUser(runtime.user.id, {
			twoFactorEnabled: false,
		});
		const response = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			enrollment.cookie,
			{ code: await createOTP(enrollment.secret).totp() },
		);
		expect(response.status).toBe(401);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("rejects a source factor changed after the repair binding", async () => {
		const runtime = await setup();
		const enrollment = await beginEnrollment(runtime);
		await runtime.context.adapter.update({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
			update: {
				secret: await symmetricEncrypt({
					key: runtime.context.secretConfig,
					data: "concurrently-replaced-source-secret",
				}),
			},
		});
		const response = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			enrollment.cookie,
			{ code: await createOTP(enrollment.secret).totp() },
		);
		expect(response.status).toBe(401);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
		const factor = await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "userId", value: runtime.user.id }],
		});
		expect(factor?.verified).toBe(false);
	});

	it("allows exactly one concurrent completion", async () => {
		const runtime = await setup();
		const enrollment = await beginEnrollment(runtime);
		const code = await createOTP(enrollment.secret).totp();
		const responses = await Promise.all([
			dispatch(
				runtime.context,
				runtime.endpoints.recoveryRepairTOTPVerify!,
				enrollment.cookie,
				{ code },
			),
			dispatch(
				runtime.context,
				runtime.endpoints.recoveryRepairTOTPVerify!,
				enrollment.cookie,
				{ code },
			),
		]);
		expect(responses.filter((response) => response.status === 200)).toHaveLength(1);
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});

	it("does not partially consume the counter when activation loses its exact CAS", async () => {
		const runtime = await setup();
		const enrollment = await beginEnrollment(runtime);
		const originalTransaction = runtime.context.adapter.transaction.bind(
			runtime.context.adapter,
		);
		let injectedRace = false;
		vi.spyOn(runtime.context.adapter, "transaction").mockImplementation(
			async (callback) =>
				originalTransaction(async (transactionAdapter) => {
					const originalIncrementOne = transactionAdapter.incrementOne.bind(
						transactionAdapter,
					);
					const incrementOne: typeof transactionAdapter.incrementOne = async (
						input,
					) => {
						const set = input.set as Record<string, unknown> | undefined;
						if (
							!injectedRace &&
							input.model === runtime.table &&
							set?.pendingSecret === null &&
							typeof set.lastUsedTotpCounter === "number"
						) {
							injectedRace = true;
							await transactionAdapter.update({
								model: runtime.table,
								where: [{ field: "id", value: enrollment.factor.id }],
								update: { backupCodes: "concurrently-replaced-backup-codes" },
							});
						}
						return originalIncrementOne(input);
					};
					transactionAdapter.incrementOne = incrementOne;
					return callback(transactionAdapter);
				}),
		);

		const response = await dispatch(
			runtime.context,
			runtime.endpoints.recoveryRepairTOTPVerify!,
			enrollment.cookie,
			{ code: await createOTP(enrollment.secret).totp() },
		);
		expect(response.status).toBe(401);
		expect(injectedRace).toBe(true);
		const factor = (await runtime.context.adapter.findOne<TwoFactorTable>({
			model: runtime.table,
			where: [{ field: "id", value: enrollment.factor.id }],
		}))!;
		expect(factor.verified).toBe(false);
		expect(factor.pendingSecret).toBeTruthy();
		expect(factor.pendingBackupCodes).toBeTruthy();
		expect(factor.lastUsedTotpCounter).toBe(-1);
		expect(factor.activeVerificationReservations).toBe("[]");
		expect(await runtime.context.adapter.count({ model: "session" })).toBe(0);
	});
});
