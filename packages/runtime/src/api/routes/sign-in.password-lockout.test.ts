import type { Account } from "@clearance/core/db";
import { describe, expect, it, vi } from "vitest";
import { phoneNumber } from "../../plugins/phone-number";
import { username } from "../../plugins/username";
import { getTestInstance } from "../../test-utils/test-instance";
import type { User } from "../../types";

type LockoutAccount = Account & {
	failedPasswordAttempts: number | null;
	activePasswordAttemptReservations: string | null;
	passwordLockedUntil: Date | null;
};

const TEST_USERNAME = "lockout_user";
const TEST_PHONE = "+15551234567";

async function setup(
	accountLockout: {
		enabled?: boolean;
		maxFailedAttempts?: number;
		durationSeconds?: number;
	} = { maxFailedAttempts: 3, durationSeconds: 30 },
) {
	const instance = await getTestInstance({
		emailAndPassword: { enabled: true, accountLockout },
		plugins: [
			username(),
			phoneNumber({
				requireVerification: false,
				sendOTP: async () => {},
			}),
		],
	});
	const user = await instance.db.findOne<
		User & {
			username: string | null;
			displayUsername: string | null;
			phoneNumber: string | null;
			phoneNumberVerified: boolean;
		}
	>({
		model: "user",
		where: [{ field: "email", value: instance.testUser.email }],
	});
	if (!user) throw new Error("test user was not created");
	await instance.db.update({
		model: "user",
		where: [{ field: "id", value: user.id }],
		update: {
			username: TEST_USERNAME,
			displayUsername: TEST_USERNAME,
			phoneNumber: TEST_PHONE,
			phoneNumberVerified: true,
		},
	});
	return { ...instance, user };
}

async function readCredentialAccount(
	db: Awaited<ReturnType<typeof setup>>["db"],
	userId: string,
) {
	const account = await db.findOne<LockoutAccount>({
		model: "account",
		where: [
			{ field: "userId", value: userId },
			{ field: "providerId", value: "credential" },
		],
	});
	if (!account) throw new Error("credential account was not created");
	return account;
}

describe("password account lockout", () => {
	it("accumulates failures across email, username, and phone sign-in", async () => {
		const { auth, db, testUser, user } = await setup();
		const responses = await Promise.all([
			auth.api.signInEmail({
				body: { email: testUser.email, password: "wrong-email" },
				asResponse: true,
			}),
			auth.api.signInUsername({
				body: { username: TEST_USERNAME, password: "wrong-username" },
				asResponse: true,
			}),
			auth.api.signInPhoneNumber({
				body: { phoneNumber: TEST_PHONE, password: "wrong-phone" },
				asResponse: true,
			}),
		]);

		expect(responses.map((response) => response.status).sort()).toEqual([
			401, 401, 401,
		]);
		const account = await readCredentialAccount(db, user.id);
		expect(account.failedPasswordAttempts).toBe(3);
		expect(account.passwordLockedUntil?.getTime()).toBeGreaterThan(Date.now());

		const locked = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(locked.status).toBe(429);
		expect(await locked.json()).toMatchObject({
			code: "PASSWORD_ACCOUNT_LOCKED",
		});
	});

	it("admits no more password comparisons than the concurrent ceiling", async () => {
		const { auth, db, testUser, user } = await setup();
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

		const attempts = Array.from({ length: 8 }, (_, index) =>
			auth.api.signInEmail({
				body: { email: testUser.email, password: `wrong-${index}` },
				asResponse: true,
			}),
		);
		await vi.waitFor(() => expect(comparisons).toBe(3));
		release();
		const responses = await Promise.all(attempts);

		expect(comparisons).toBe(3);
		expect(responses.filter((response) => response.status === 401)).toHaveLength(
			3,
		);
		expect(responses.filter((response) => response.status === 429)).toHaveLength(
			5,
		);
		const account = await readCredentialAccount(db, user.id);
		expect(account.failedPasswordAttempts).toBe(3);
		expect(account.activePasswordAttemptReservations).toBe("[]");
		expect(account.passwordLockedUntil).not.toBeNull();
	});

	it("successful settlement clears state and a late failure cannot relock it", async () => {
		const { auth, db, testUser, user } = await setup();
		const firstFailure = await auth.api.signInEmail({
			body: { email: testUser.email, password: "first-wrong" },
			asResponse: true,
		});
		expect(firstFailure.status).toBe(401);

		const context = await auth.$context;
		const originalVerify = context.password.verify.bind(context.password);
		let wrongEntered = false;
		let validEntered = false;
		let releaseWrong!: () => void;
		let releaseValid!: () => void;
		const wrongGate = new Promise<void>((resolve) => {
			releaseWrong = resolve;
		});
		const validGate = new Promise<void>((resolve) => {
			releaseValid = resolve;
		});
		context.password.verify = async (input) => {
			if (input.password === "late-wrong") {
				wrongEntered = true;
				await wrongGate;
			} else {
				validEntered = true;
				await validGate;
			}
			return originalVerify(input);
		};

		const lateFailure = auth.api.signInEmail({
			body: { email: testUser.email, password: "late-wrong" },
			asResponse: true,
		});
		await vi.waitFor(() => expect(wrongEntered).toBe(true));
		const success = auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		await vi.waitFor(() => expect(validEntered).toBe(true));
		releaseValid();
		expect((await success).status).toBe(200);
		releaseWrong();
		expect((await lateFailure).status).toBe(401);

		const account = await readCredentialAccount(db, user.id);
		expect(account.failedPasswordAttempts).toBe(0);
		expect(account.activePasswordAttemptReservations).toBe("[]");
		expect(account.passwordLockedUntil).toBeNull();
	});

	it("expires the lock and starts a clean attempt window", async () => {
		const { auth, db, testUser, user } = await setup();
		const account = await readCredentialAccount(db, user.id);
		await db.update({
			model: "account",
			where: [{ field: "id", value: account.id }],
			update: {
				failedPasswordAttempts: 3,
				activePasswordAttemptReservations: "[]",
				passwordLockedUntil: new Date(Date.now() - 1_000),
			},
		});

		const response = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(response.status).toBe(200);
		const cleared = await readCredentialAccount(db, user.id);
		expect(cleared.failedPasswordAttempts).toBe(0);
		expect(cleared.activePasswordAttemptReservations).toBe("[]");
		expect(cleared.passwordLockedUntil).toBeNull();
	});

	it("turns failures at a newly lowered ceiling into a timed lock", async () => {
		const { auth, db, testUser, user } = await setup();
		const account = await readCredentialAccount(db, user.id);
		await db.update({
			model: "account",
			where: [{ field: "id", value: account.id }],
			update: {
				failedPasswordAttempts: 3,
				activePasswordAttemptReservations: "[]",
				passwordLockedUntil: null,
			},
		});

		const response = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(response.status).toBe(429);
		const locked = await readCredentialAccount(db, user.id);
		expect(locked.passwordLockedUntil?.getTime()).toBeGreaterThan(Date.now());
	});

	it("fails closed on malformed reservation state", async () => {
		const { auth, db, testUser, user } = await setup();
		const account = await readCredentialAccount(db, user.id);
		await db.update({
			model: "account",
			where: [{ field: "id", value: account.id }],
			update: { activePasswordAttemptReservations: "{" },
		});

		const response = await auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		expect(response.status).toBe(500);
	});

	it("can be disabled without retaining password-attempt state", async () => {
		const { auth, db, testUser, user } = await setup({ enabled: false });
		const responses = await Promise.all(
			Array.from({ length: 5 }, (_, index) =>
				auth.api.signInEmail({
					body: { email: testUser.email, password: `wrong-${index}` },
					asResponse: true,
				}),
			),
		);
		expect(responses.every((response) => response.status === 401)).toBe(true);
		const account = await readCredentialAccount(db, user.id);
		expect(account.failedPasswordAttempts).toBe(0);
		expect(account.activePasswordAttemptReservations).toBe("[]");
		expect(account.passwordLockedUntil).toBeNull();
	});

	it("does not create lockout state for missing users on any primary route", async () => {
		const { auth, db } = await setup();
		const before = await db.count({ model: "account" });
		const responses = await Promise.all([
			auth.api.signInEmail({
				body: { email: "missing@example.com", password: "wrong" },
				asResponse: true,
			}),
			auth.api.signInUsername({
				body: { username: "missing_user", password: "wrong" },
				asResponse: true,
			}),
			auth.api.signInPhoneNumber({
				body: { phoneNumber: "+15550000000", password: "wrong" },
				asResponse: true,
			}),
		]);
		expect(responses.every((response) => response.status === 401)).toBe(true);
		expect(await db.count({ model: "account" })).toBe(before);
	});

	it("password replacement clears state and invalidates stale settlements", async () => {
		const { auth, db, testUser, user } = await setup();
		const context = await auth.$context;
		const originalVerify = context.password.verify.bind(context.password);
		let entered = false;
		let release!: () => void;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		context.password.verify = async (input) => {
			entered = true;
			await gate;
			return originalVerify(input);
		};
		const staleFailure = auth.api.signInEmail({
			body: { email: testUser.email, password: "stale-wrong" },
			asResponse: true,
		});
		await vi.waitFor(() => expect(entered).toBe(true));

		const replacement = await context.password.hash("replacement-password");
		await context.internalAdapter.updatePassword(user.id, replacement);
		release();
		expect((await staleFailure).status).toBe(401);

		const account = await readCredentialAccount(db, user.id);
		expect(account.password).toBe(replacement);
		expect(account.failedPasswordAttempts).toBe(0);
		expect(account.activePasswordAttemptReservations).toBe("[]");
		expect(account.passwordLockedUntil).toBeNull();
	});

	it("rejects an old password that verifies after password replacement", async () => {
		const { auth, db, testUser, user } = await setup();
		const context = await auth.$context;
		const originalVerify = context.password.verify.bind(context.password);
		let entered = false;
		let release!: () => void;
		const gate = new Promise<void>((resolve) => {
			release = resolve;
		});
		context.password.verify = async (input) => {
			entered = true;
			await gate;
			return originalVerify(input);
		};
		const staleSuccess = auth.api.signInEmail({
			body: { email: testUser.email, password: testUser.password },
			asResponse: true,
		});
		await vi.waitFor(() => expect(entered).toBe(true));

		const replacement = await context.password.hash("replacement-password");
		await context.internalAdapter.updatePassword(user.id, replacement);
		release();

		expect((await staleSuccess).status).toBe(401);
		const account = await readCredentialAccount(db, user.id);
		expect(account.password).toBe(replacement);
		expect(account.failedPasswordAttempts).toBe(0);
		expect(account.activePasswordAttemptReservations).toBe("[]");
		expect(account.passwordLockedUntil).toBeNull();
	});

	it("password replacement preserves account update hooks", async () => {
		const before = vi.fn(async (data) => ({
			data: {
				...data,
				failedPasswordAttempts: 99,
				activePasswordAttemptReservations: "malformed",
				passwordLockedUntil: new Date(Date.now() + 60_000),
			},
		}));
		const after = vi.fn();
		const { auth, db, testUser } = await getTestInstance({
			databaseHooks: { account: { update: { before, after } } },
		});
		const user = await db.findOne<User>({
			model: "user",
			where: [{ field: "email", value: testUser.email }],
		});
		if (!user) throw new Error("test user was not created");
		before.mockClear();
		after.mockClear();
		const context = await auth.$context;
		const replacement = await context.password.hash("hooked-password");

		await context.internalAdapter.updatePassword(user.id, replacement);

		expect(before).toHaveBeenCalledOnce();
		expect(after).toHaveBeenCalledOnce();
		const account = await readCredentialAccount(db, user.id);
		expect(account.failedPasswordAttempts).toBe(0);
		expect(account.activePasswordAttemptReservations).toBe("[]");
		expect(account.passwordLockedUntil).toBeNull();
	});

	it("password replacement wins over lockout state changed during its hook", async () => {
		let blockPasswordUpdate = false;
		let releaseUpdate!: () => void;
		let markUpdateEntered!: () => void;
		const updateEntered = new Promise<void>((resolve) => {
			markUpdateEntered = resolve;
		});
		const updateGate = new Promise<void>((resolve) => {
			releaseUpdate = resolve;
		});
		const before = vi.fn(async (data) => {
			if (blockPasswordUpdate && typeof data.password === "string") {
				markUpdateEntered();
				await updateGate;
			}
			return { data };
		});
		const { auth, db, testUser } = await getTestInstance({
			emailAndPassword: {
				enabled: true,
				accountLockout: { maxFailedAttempts: 3, durationSeconds: 30 },
			},
			databaseHooks: { account: { update: { before } } },
		});
		const user = await db.findOne<User>({
			model: "user",
			where: [{ field: "email", value: testUser.email }],
		});
		if (!user) throw new Error("test user was not created");
		const context = await auth.$context;
		const replacement = await context.password.hash("replacement-password");
		blockPasswordUpdate = true;
		const update = context.internalAdapter.updatePassword(user.id, replacement);
		await updateEntered;

		const concurrentFailure = await auth.api.signInEmail({
			body: { email: testUser.email, password: "wrong-during-reset" },
			asResponse: true,
		});
		expect(concurrentFailure.status).toBe(401);
		releaseUpdate();
		await expect(update).resolves.toBeUndefined();

		const account = await readCredentialAccount(db, user.id);
		expect(account.password).toBe(replacement);
		expect(account.failedPasswordAttempts).toBe(0);
		expect(account.activePasswordAttemptReservations).toBe("[]");
		expect(account.passwordLockedUntil).toBeNull();
	});
});
