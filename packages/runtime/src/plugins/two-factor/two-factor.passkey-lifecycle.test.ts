import type { DBAdapter } from "@clearance/core/db/adapter";
import { createOTP } from "@clearance/utils/otp";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { symmetricDecrypt } from "../../crypto";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getTestInstance } from "../../test-utils/test-instance";
import type { Account, Session, User } from "../../types";
import { passkey } from "../passkey";
import type { Passkey } from "../passkey/types";
import { twoFactor } from ".";
import type { TwoFactorTable } from "./types";

const rotationControl = vi.hoisted(() => ({ fail: false }));

vi.mock("../../db/passkey-session-generation", async (importOriginal) => {
	const actual =
		await importOriginal<
			typeof import("../../db/passkey-session-generation")
		>();
	return {
		...actual,
		rotatePasskeySessionGeneration: (
			...args: Parameters<typeof actual.rotatePasskeySessionGeneration>
		) =>
			rotationControl.fail
				? Promise.resolve(null)
				: actual.rotatePasskeySessionGeneration(...args),
	};
});

const ORIGIN = "http://localhost:3330";
const SECRET = "two-factor-passkey-lifecycle-test-secret";

async function seedPasskey(context: any, userId: string): Promise<Passkey> {
	return context.adapter.create({
		model: "passkey",
		data: {
			userId,
			name: "surviving passkey",
			credentialID: `credential-${Math.random()}`,
			publicKey: "unused-lifecycle-public-key",
			userHandle: `handle-${Math.random()}`,
			counter: 0,
			deviceType: "singleDevice",
			backedUp: false,
			createdAt: new Date(),
			updatedAt: new Date(),
		},
	}) as Promise<Passkey>;
}

async function setupLifecycle(options?: {
	installPasskeyPlugin?: boolean;
	passkeySurvivor?: boolean;
	removePassword?: boolean;
	rejectReplacement?: () => boolean;
}) {
	const instance = await getTestInstance(
		{
			baseURL: ORIGIN,
			secret: SECRET,
			session: { expiresIn: 30 * 60 },
			plugins: [
				...(options?.installPasskeyPlugin === false ? [] : [passkey()]),
				twoFactor({ allowPasswordless: true }),
			],
			...(options?.rejectReplacement
				? {
						databaseHooks: {
							session: {
								create: {
									before: async () =>
										options.rejectReplacement?.() ? false : undefined,
								},
							},
						},
					}
				: {}),
		},
		{ port: 3330 },
	);
	const signedIn = await instance.signInWithTestUser();
	const initialSession = await instance.auth.api.getSession({
		headers: signedIn.headers,
	});
	if (!initialSession) throw new Error("initial session missing");
	const enrollment = await instance.auth.api.enableTwoFactor({
		body: { password: instance.testUser.password },
		headers: signedIn.headers,
	});
	const factor = await instance.db.findOne<TwoFactorTable>({
		model: "twoFactor",
		where: [{ field: "userId", value: initialSession.user.id }],
	});
	if (!factor) throw new Error("two-factor enrollment row missing");
	const secret = await symmetricDecrypt({ key: SECRET, data: factor.secret });
	const activated = await instance.auth.api.verifyTOTP({
		body: { code: await createOTP(secret).totp() },
		headers: signedIn.headers,
		asResponse: true,
	});
	if (activated.status !== 200) throw new Error("two-factor activation failed");
	const headers = convertSetCookieToCookie(activated.headers);
	const activeSession = await instance.auth.api.getSession({ headers });
	if (!activeSession) throw new Error("active session missing");
	const context = await instance.auth.$context;

	if (options?.passkeySurvivor) {
		await seedPasskey(context, activeSession.user.id);
	}
	if (options?.removePassword) {
		await instance.db.deleteMany({
			model: "account",
			where: [
				{ field: "userId", value: activeSession.user.id },
				{ field: "providerId", value: "credential" },
			],
		});
	}

	return {
		...instance,
		activeSession,
		context,
		enrollment,
		headers,
		secret,
		userId: activeSession.user.id,
	};
}

async function seedSocialAccount(db: DBAdapter, userId: string): Promise<void> {
	await db.create({
		model: "account",
		data: {
			providerId: "github",
			accountId: `github-${userId}`,
			userId,
			createdAt: new Date(),
			updatedAt: new Date(),
		},
	});
}

async function credentialAccount(db: DBAdapter, userId: string): Promise<Account> {
	const account = await db.findOne<Account>({
		model: "account",
		where: [
			{ field: "userId", value: userId },
			{ field: "providerId", value: "credential" },
		],
	});
	if (!account) throw new Error("credential account missing");
	return account;
}

async function responseCode(response: Response): Promise<string | undefined> {
	return ((await response.json()) as { code?: string }).code;
}

describe.sequential("two-factor disable factor lifecycle authority", () => {
	beforeEach(() => {
		rotationControl.fail = false;
	});

	it("protects the last factor and rolls its valid recovery proof back", async () => {
		const setup = await setupLifecycle({ removePassword: true });
		const recoveryCode = setup.enrollment.backupCodes[0]!;

		const rejected = await setup.auth.api.disableTwoFactor({
			body: { recoveryCode },
			headers: setup.headers,
			asResponse: true,
		});
		expect(rejected.status).toBe(400);
		expect(await responseCode(rejected)).toBe("LAST_FACTOR_PROTECTED");
		expect(rejected.headers.get("set-cookie")).toBeNull();
		expect(
			await setup.db.findOne({
				model: "twoFactor",
				where: [{ field: "userId", value: setup.userId }],
			}),
		).not.toBeNull();

		await seedPasskey(setup.context, setup.userId);
		const retried = await setup.auth.api.disableTwoFactor({
			body: { recoveryCode },
			headers: setup.headers,
			asResponse: true,
		});
		expect(retried.status).toBe(200);
	});

	it("rejects a stale verified factor before proof or session mutation", async () => {
		const setup = await setupLifecycle();
		const recoveryCode = setup.enrollment.backupCodes[0]!;
		const beforeFactor = await setup.db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: setup.userId }],
		});
		if (!beforeFactor?.verified) throw new Error("verified factor missing");
		const beforeSession = await setup.db.findOne<
			Session & Record<string, unknown>
		>({
			model: "session",
			where: [{ field: "id", value: setup.activeSession.session.id }],
		});
		if (!beforeSession) throw new Error("active session row missing");
		const sessionsBefore = await setup.db.count({
			model: "session",
			where: [{ field: "userId", value: setup.userId }],
		});
		await setup.db.update({
			model: "user",
			where: [{ field: "id", value: setup.userId }],
			update: { twoFactorEnabled: false },
		});

		const rejected = await setup.auth.api.disableTwoFactor({
			body: { password: setup.testUser.password, recoveryCode },
			headers: setup.headers,
			asResponse: true,
		});

		expect(rejected.status).toBe(400);
		expect(await responseCode(rejected)).toBe("TWO_FACTOR_NOT_ENABLED");
		expect(rejected.headers.get("set-cookie")).toBeNull();
		expect(
			await setup.db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "id", value: beforeFactor.id }],
			}),
		).toMatchObject({
			backupCodes: beforeFactor.backupCodes,
			failedVerificationCount: beforeFactor.failedVerificationCount,
			activeVerificationReservations: beforeFactor.activeVerificationReservations,
			lastUsedTotpCounter: beforeFactor.lastUsedTotpCounter,
			verified: true,
		});
		expect(
			await setup.db.findOne<Session & Record<string, unknown>>({
				model: "session",
				where: [{ field: "id", value: beforeSession.id }],
			}),
		).toMatchObject(beforeSession);
		await expect(
			setup.db.count({
				model: "session",
				where: [{ field: "userId", value: setup.userId }],
			}),
		).resolves.toBe(sessionsBefore);
		await expect(
			setup.auth.api.getSession({ headers: setup.headers }),
		).resolves.not.toBeNull();

		await setup.db.update({
			model: "user",
			where: [{ field: "id", value: setup.userId }],
			update: { twoFactorEnabled: true },
		});
		const retried = await setup.auth.api.disableTwoFactor({
			body: { password: setup.testUser.password, recoveryCode },
			headers: setup.headers,
			asResponse: true,
		});
		expect(retried.status).toBe(200);
		expect(retried.headers.get("set-cookie")).toContain("session_token");
	});

	it("rejects sequential credential unlink then disable and preserves the recovery proof", async () => {
		const setup = await setupLifecycle({ installPasskeyPlugin: false });
		await seedSocialAccount(setup.db, setup.userId);
		const credential = await credentialAccount(setup.db, setup.userId);
		const recoveryCode = setup.enrollment.backupCodes[0]!;

		const unlinked = await setup.auth.api.unlinkAccount({
			body: {
				providerId: "credential",
				accountId: credential.accountId,
			},
			headers: setup.headers,
			asResponse: true,
		});
		expect(unlinked.status).toBe(200);
		const replacementHeaders = convertSetCookieToCookie(unlinked.headers);
		expect(
			await setup.db.findOne({
				model: "account",
				where: [{ field: "id", value: credential.id }],
			}),
		).toBeNull();

		const rejected = await setup.auth.api.disableTwoFactor({
			body: { recoveryCode },
			headers: replacementHeaders,
			asResponse: true,
		});
		expect(rejected.status).toBe(400);
		expect(await responseCode(rejected)).toBe("LAST_FACTOR_PROTECTED");
		expect(rejected.headers.get("set-cookie")).toBeNull();
		expect(
			await setup.db.findOne({
				model: "twoFactor",
				where: [{ field: "userId", value: setup.userId }],
			}),
		).not.toBeNull();

		const newPassword = "replacement-password-123";
		await setup.auth.api.setPassword({
			body: { newPassword },
			headers: replacementHeaders,
		});
		const retried = await setup.auth.api.disableTwoFactor({
			body: { password: newPassword, recoveryCode },
			headers: replacementHeaders,
			asResponse: true,
		});
		expect(retried.status).toBe(200);
	});

	it("accepts a password survivor, revokes all old sessions, and preserves exact expiry", async () => {
		const setup = await setupLifecycle();
		const originalExpiry = new Date(setup.activeSession.session.expiresAt).getTime();
		const extraOld = await setup.context.internalAdapter.createSession(setup.userId);

		const disabled = await setup.auth.api.disableTwoFactor({
			body: {
				password: setup.testUser.password,
				recoveryCode: setup.enrollment.backupCodes[0]!,
			},
			headers: setup.headers,
			asResponse: true,
		});
		expect(disabled.status).toBe(200);
		const replacementHeaders = convertSetCookieToCookie(disabled.headers);
		const replacement = await setup.auth.api.getSession({
			headers: replacementHeaders,
		});
		expect(replacement).not.toBeNull();
		expect(new Date(replacement!.session.expiresAt).getTime()).toBe(
			originalExpiry,
		);
		await expect(
			setup.auth.api.getSession({ headers: setup.headers }),
		).resolves.toBeNull();
		await expect(
			setup.context.internalAdapter.findSession(extraOld.token),
		).resolves.toBeNull();
		const active = await setup.context.internalAdapter.listSessions(setup.userId, {
			onlyActiveSessions: true,
		});
		expect(active).toHaveLength(1);
		expect(active[0]?.id).toBe(replacement!.session.id);
	});

	it("rolls proof, factor, generation, sessions, and cookies back on CAS conflict", async () => {
		const setup = await setupLifecycle();
		const beforeUser = await setup.db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: setup.userId }],
		});
		const recoveryCode = setup.enrollment.backupCodes[0]!;
		rotationControl.fail = true;

		const conflicted = await setup.auth.api.disableTwoFactor({
			body: { password: setup.testUser.password, recoveryCode },
			headers: setup.headers,
			asResponse: true,
		});
		expect(conflicted.status).toBe(409);
		expect(await responseCode(conflicted)).toBe("LIFECYCLE_CONFLICT");
		expect(conflicted.headers.get("set-cookie")).toBeNull();
		const afterUser = await setup.db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: setup.userId }],
		});
		expect(afterUser?.passkeySessionGeneration).toBe(
			beforeUser?.passkeySessionGeneration,
		);
		expect(afterUser?.twoFactorEnabled).toBe(true);
		expect(
			await setup.db.findOne({
				model: "twoFactor",
				where: [{ field: "userId", value: setup.userId }],
			}),
		).not.toBeNull();
		await expect(
			setup.auth.api.getSession({ headers: setup.headers }),
		).resolves.not.toBeNull();

		rotationControl.fail = false;
		await expect(
			setup.auth.api.disableTwoFactor({
				body: { password: setup.testUser.password, recoveryCode },
				headers: setup.headers,
			}),
		).resolves.toEqual({ status: true });
	});

	it("rejects transactionless disable before proof or replacement mutation", async () => {
		let rejectReplacement = false;
		let replacementAttempts = 0;
		const setup = await setupLifecycle({
			installPasskeyPlugin: false,
			rejectReplacement: () => {
				replacementAttempts++;
				return rejectReplacement;
			},
		});
		const recoveryCode = setup.enrollment.backupCodes[0]!;
		const beforeFactor = await setup.db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: setup.userId }],
		});
		if (!beforeFactor) throw new Error("two-factor row missing before rejection");
		const transactionConfig = setup.context.adapter.options!.adapterConfig;
		const originalTransaction = transactionConfig.transaction;
		rejectReplacement = true;
		replacementAttempts = 0;
		transactionConfig.transaction = false;
		let rejected: Response;
		try {
			rejected = await setup.auth.api.disableTwoFactor({
				body: { password: setup.testUser.password, recoveryCode },
				headers: setup.headers,
				asResponse: true,
			});
		} finally {
			transactionConfig.transaction = originalTransaction;
		}
		expect(rejected.status).toBe(500);
		expect(await responseCode(rejected)).toBe(
			"LIFECYCLE_CONFIGURATION_ERROR",
		);
		expect(rejected.headers.get("set-cookie")).toBeNull();
		expect(replacementAttempts).toBe(0);
		expect(
			await setup.db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "userId", value: setup.userId }],
			}),
		).toMatchObject({
			id: beforeFactor.id,
			backupCodes: beforeFactor.backupCodes,
			failedVerificationCount: beforeFactor.failedVerificationCount,
			activeVerificationReservations: beforeFactor.activeVerificationReservations,
		});
		await expect(
			setup.auth.api.getSession({ headers: setup.headers }),
		).resolves.not.toBeNull();

		rejectReplacement = false;
		const retried = await setup.auth.api.disableTwoFactor({
			body: { password: setup.testUser.password, recoveryCode },
			headers: setup.headers,
			asResponse: true,
		});
		expect(retried.status).toBe(200);
	});

	it("commits invalid recovery attempts without publishing a session", async () => {
		const setup = await setupLifecycle();
		const before = await setup.db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: setup.userId }],
		});

		const rejected = await setup.auth.api.disableTwoFactor({
			body: {
				password: setup.testUser.password,
				recoveryCode: "invalid-recovery-code",
			},
			headers: setup.headers,
			asResponse: true,
		});
		expect(rejected.status).toBe(401);
		expect(rejected.headers.get("set-cookie")).toBeNull();
		const after = await setup.db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: setup.userId }],
		});
		expect(after?.failedVerificationCount).toBe(
			(before?.failedVerificationCount ?? 0) + 1,
		);
		expect(after?.activeVerificationReservations).toBe("[]");
	});

	it("fails closed before proof work for secondary-authoritative sessions", async () => {
		const store = new Map<string, string>();
		let secondaryWrites = 0;
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				secret: SECRET,
				plugins: [passkey(), twoFactor({ allowPasswordless: true })],
				secondaryStorage: {
					get(key: string) {
						return store.get(key) ?? null;
					},
					set(key: string, value: string) {
						secondaryWrites++;
						store.set(key, value);
					},
					delete(key: string) {
						secondaryWrites++;
						store.delete(key);
					},
				},
			},
			{ port: 3330 },
		);
		const signedIn = await instance.signInWithTestUser();
		const writesBefore = secondaryWrites;

		const rejected = await instance.auth.api.disableTwoFactor({
			body: { recoveryCode: "not-consumed" },
			headers: signedIn.headers,
			asResponse: true,
		});
		expect(rejected.status).toBe(500);
		expect(await responseCode(rejected)).toBe(
			"LIFECYCLE_CONFIGURATION_ERROR",
		);
		expect(secondaryWrites).toBe(writesBefore);
		expect(rejected.headers.get("set-cookie")).toBeNull();
	});

	it("serializes concurrent sole-passkey deletion and two-factor disable", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-07-16T12:00:00.000Z"));
		try {
			const setup = await setupLifecycle({
				passkeySurvivor: true,
				removePassword: true,
			});
			vi.advanceTimersByTime(30_000);
			const currentCode = await createOTP(setup.secret).totp();

			const [deletion, disable] = await Promise.all([
				setup.auth.api.deletePasskey({
					body: {
						id: (
							await setup.db.findOne<Passkey>({
								model: "passkey",
								where: [{ field: "userId", value: setup.userId }],
							})
						)!.id,
						proof: { type: "totp", code: currentCode },
					},
					headers: new Headers(setup.headers),
					asResponse: true,
				}),
				setup.auth.api.disableTwoFactor({
					body: { recoveryCode: setup.enrollment.backupCodes[0]! },
					headers: new Headers(setup.headers),
					asResponse: true,
				}),
			]);
			expect([deletion.status, disable.status].filter((status) => status === 200)).toHaveLength(
				1,
			);
			const remainingPasskeys = await setup.db.count({
				model: "passkey",
				where: [{ field: "userId", value: setup.userId }],
			});
			const remainingFactor = await setup.db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "userId", value: setup.userId }],
			});
			expect(remainingPasskeys > 0 || remainingFactor !== null).toBe(true);
		} finally {
			vi.useRealTimers();
		}
	});
});
