import type { DBAdapter } from "@clearance/core/db/adapter";
import { createOTP } from "@clearance/utils/otp";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { symmetricDecrypt } from "../../crypto";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getTestInstance } from "../../test-utils/test-instance";
import { passkey } from "../../plugins/passkey";
import type { Passkey } from "../../plugins/passkey/types";
import { twoFactor } from "../../plugins/two-factor";
import type { TwoFactorTable } from "../../plugins/two-factor/types";
import type { Account, Session } from "../../types";

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

const ORIGIN = "http://localhost:3340";
const SECRET = "account-factor-lifecycle-test-secret";

async function seedSocialAccount(
	db: DBAdapter,
	userId: string,
): Promise<void> {
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

async function seedPasskey(context: any, userId: string): Promise<Passkey> {
	return context.adapter.create({
		model: "passkey",
		data: {
			userId,
			name: "surviving passkey",
			credentialID: `credential-${Math.random()}`,
			publicKey: "unused-account-lifecycle-public-key",
			userHandle: `handle-${Math.random()}`,
			counter: 0,
			deviceType: "singleDevice",
			backedUp: false,
			createdAt: new Date(),
			updatedAt: new Date(),
		},
	}) as Promise<Passkey>;
}

async function credentialAccount(
	db: DBAdapter,
	userId: string,
): Promise<Account> {
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

async function activateTwoFactor(instance: any, headers: Headers) {
	const enrollment = await instance.auth.api.enableTwoFactor({
		body: { password: instance.testUser.password },
		headers,
	});
	const session = await instance.auth.api.getSession({ headers });
	if (!session) throw new Error("session missing during two-factor enrollment");
	const factor = (await instance.db.findOne({
		model: "twoFactor",
		where: [{ field: "userId", value: session.user.id }],
	})) as TwoFactorTable | null;
	if (!factor) throw new Error("two-factor enrollment row missing");
	const secret = await symmetricDecrypt({ key: SECRET, data: factor.secret });
	const activated = await instance.auth.api.verifyTOTP({
		body: { code: await createOTP(secret).totp() },
		headers,
		asResponse: true,
	});
	if (activated.status !== 200) throw new Error("two-factor activation failed");
	return {
		enrollment,
		headers: convertSetCookieToCookie(activated.headers),
	};
}

async function responseCode(response: Response): Promise<string | undefined> {
	return ((await response.json()) as { code?: string }).code;
}

describe.sequential("credential unlink factor lifecycle", () => {
	beforeEach(() => {
		rotationControl.fail = false;
	});

	it("rejects leaving only a social account", async () => {
		const instance = await getTestInstance({ baseURL: ORIGIN, secret: SECRET });
		const signedIn = await instance.signInWithTestUser();
		await seedSocialAccount(instance.db, signedIn.user.id);
		const credential = await credentialAccount(instance.db, signedIn.user.id);

		const rejected = await instance.auth.api.unlinkAccount({
			body: {
				providerId: "credential",
				accountId: credential.accountId,
			},
			headers: signedIn.headers,
			asResponse: true,
		});
		expect(rejected.status).toBe(400);
		expect(await responseCode(rejected)).toBe("LAST_FACTOR_PROTECTED");
		expect(rejected.headers.get("set-cookie")).toBeNull();
		expect(
			await credentialAccount(instance.db, signedIn.user.id),
		).toMatchObject({ id: credential.id });
	});

	it("does not count a stale verified two-factor row for a disabled user", async () => {
		const instance = await getTestInstance({
			baseURL: ORIGIN,
			secret: SECRET,
			plugins: [twoFactor({ allowPasswordless: true })],
		});
		const signedIn = await instance.signInWithTestUser();
		await seedSocialAccount(instance.db, signedIn.user.id);
		const credential = await credentialAccount(instance.db, signedIn.user.id);
		await instance.db.create({
			model: "twoFactor",
			data: {
				userId: signedIn.user.id,
				secret: "stale-disabled-factor",
				backupCodes: "[]",
				verified: true,
				trustDeviceGeneration: "stale",
				failedVerificationCount: 0,
				activeVerificationReservations: "[]",
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});

		const rejected = await instance.auth.api.unlinkAccount({
			body: {
				providerId: "credential",
				accountId: credential.accountId,
			},
			headers: signedIn.headers,
			asResponse: true,
		});
		expect(rejected.status).toBe(400);
		expect(await responseCode(rejected)).toBe("LAST_FACTOR_PROTECTED");
	});

	it("accepts a passkey survivor, revokes every old session, and preserves exact expiry", async () => {
		const instance = await getTestInstance({
			baseURL: ORIGIN,
			secret: SECRET,
			session: { expiresIn: 30 * 60 },
			plugins: [passkey()],
		});
		const signedIn = await instance.signInWithTestUser();
		const context = await instance.auth.$context;
		await seedSocialAccount(instance.db, signedIn.user.id);
		await seedPasskey(context, signedIn.user.id);
		const credential = await credentialAccount(instance.db, signedIn.user.id);
		const initial = await instance.auth.api.getSession({ headers: signedIn.headers });
		if (!initial) throw new Error("initial session missing");
		const originalExpiry = new Date(initial.session.expiresAt).getTime();
		const extraOld = await context.internalAdapter.createSession(signedIn.user.id);
		const authority = await instance.db.findOne<Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		const source = await instance.db.findOne<Record<string, unknown>>({
			model: "session",
			where: [{ field: "id", value: initial.session.id }],
		});
		expect(source?.passkeySessionGeneration).toBe(
			authority?.passkeySessionGeneration,
		);

		const unlinked = await instance.auth.api.unlinkAccount({
			body: {
				providerId: "credential",
				accountId: credential.accountId,
			},
			headers: signedIn.headers,
			asResponse: true,
		});
		expect(
			unlinked.status,
			JSON.stringify(await unlinked.clone().json()),
		).toBe(200);
		const replacementHeaders = convertSetCookieToCookie(unlinked.headers);
		const replacement = await instance.auth.api.getSession({
			headers: replacementHeaders,
		});
		expect(replacement).not.toBeNull();
		expect(new Date(replacement!.session.expiresAt).getTime()).toBe(
			originalExpiry,
		);
		await expect(
			instance.auth.api.getSession({ headers: signedIn.headers }),
		).resolves.toBeNull();
		await expect(
			context.internalAdapter.findSession(extraOld.token),
		).resolves.toBeNull();
		const active = await context.internalAdapter.listSessions(signedIn.user.id, {
			onlyActiveSessions: true,
		});
		expect(active).toHaveLength(1);
		expect(active[0]?.id).toBe(replacement!.session.id);
		expect(
			await instance.db.findOne({
				model: "account",
				where: [{ field: "id", value: credential.id }],
			}),
		).toBeNull();
	});

	it("accepts a verified two-factor survivor and publishes the committed replacement through hook failure", async () => {
		const store = new Map<string, string>();
		let failSecondary = false;
		const instance = await getTestInstance({
			baseURL: ORIGIN,
			secret: SECRET,
			session: { expiresIn: 30 * 60, storeSessionInDatabase: true },
			plugins: [twoFactor({ allowPasswordless: true })],
			secondaryStorage: {
				get(key: string) {
					if (failSecondary) throw new Error("injected secondary read failure");
					return store.get(key) ?? null;
				},
				set(key: string, value: string) {
					if (failSecondary) throw new Error("injected secondary write failure");
					store.set(key, value);
				},
				delete(key: string) {
					if (failSecondary) throw new Error("injected secondary delete failure");
					store.delete(key);
				},
			},
		});
		const signedIn = await instance.signInWithTestUser();
		await seedSocialAccount(instance.db, signedIn.user.id);
		const active = await activateTwoFactor(instance, signedIn.headers);
		const current = await instance.auth.api.getSession({ headers: active.headers });
		if (!current) throw new Error("active two-factor session missing");
		const originalExpiry = new Date(current.session.expiresAt).getTime();
		const credential = await credentialAccount(instance.db, signedIn.user.id);
		const context = await instance.auth.$context;
		const extraOld = await context.internalAdapter.createSession(signedIn.user.id);
		failSecondary = true;

		const unlinked = await instance.auth.api.unlinkAccount({
			body: {
				providerId: "credential",
				accountId: credential.accountId,
			},
			headers: active.headers,
			asResponse: true,
		});
		expect(unlinked.status).toBe(200);
		expect(unlinked.headers.get("set-cookie")).toContain("session_token");
		failSecondary = false;
		const replacement = await instance.auth.api.getSession({
			headers: convertSetCookieToCookie(unlinked.headers),
		});
		expect(replacement).not.toBeNull();
		expect(new Date(replacement!.session.expiresAt).getTime()).toBe(
			originalExpiry,
		);
		await expect(
			instance.auth.api.getSession({ headers: active.headers }),
		).resolves.toBeNull();
		await expect(
			context.internalAdapter.findSession(extraOld.token),
		).resolves.toBeNull();
		expect(
			await instance.db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [
					{ field: "userId", value: signedIn.user.id },
					{ field: "verified", value: true },
				],
			}),
		).not.toBeNull();
		expect(
			await instance.db.findOne({
				model: "account",
				where: [{ field: "id", value: credential.id }],
			}),
		).toBeNull();
	});

	it("rolls back the target, generation, sessions, and cookie on CAS conflict", async () => {
		const instance = await getTestInstance({
			baseURL: ORIGIN,
			secret: SECRET,
			plugins: [passkey()],
		});
		const signedIn = await instance.signInWithTestUser();
		const context = await instance.auth.$context;
		await seedSocialAccount(instance.db, signedIn.user.id);
		await seedPasskey(context, signedIn.user.id);
		const credential = await credentialAccount(instance.db, signedIn.user.id);
		const before = await instance.db.findOne<Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		rotationControl.fail = true;

		const conflicted = await instance.auth.api.unlinkAccount({
			body: {
				providerId: "credential",
				accountId: credential.accountId,
			},
			headers: signedIn.headers,
			asResponse: true,
		});
		expect(conflicted.status).toBe(409);
		expect(await responseCode(conflicted)).toBe("FACTOR_LIFECYCLE_CONFLICT");
		expect(conflicted.headers.get("set-cookie")).toBeNull();
		const after = await instance.db.findOne<Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		expect(after?.passkeySessionGeneration).toBe(
			before?.passkeySessionGeneration,
		);
		expect(
			await instance.db.findOne({
				model: "account",
				where: [{ field: "id", value: credential.id }],
			}),
		).not.toBeNull();
		await expect(
			instance.auth.api.getSession({ headers: signedIn.headers }),
		).resolves.not.toBeNull();
	});

	it("revalidates the presented credential after middleware authorization", async () => {
		const instance = await getTestInstance({
			baseURL: ORIGIN,
			secret: SECRET,
			session: { preserveSessionInDatabase: true },
			plugins: [passkey()],
		});
		const signedIn = await instance.signInWithTestUser();
		const context = await instance.auth.$context;
		await seedSocialAccount(instance.db, signedIn.user.id);
		await seedPasskey(context, signedIn.user.id);
		const credential = await credentialAccount(instance.db, signedIn.user.id);
		const session = await instance.auth.api.getSession({ headers: signedIn.headers });
		if (!session) throw new Error("initial session missing");
		const originalFindAccounts = context.internalAdapter.findAccounts.bind(
			context.internalAdapter,
		);
		vi.spyOn(context.internalAdapter, "findAccounts").mockImplementationOnce(
			async (userId: string) => {
				const accounts = await originalFindAccounts(userId);
				await instance.db.updateMany({
					model: "sessionCredential",
					where: [{ field: "sessionId", value: session.session.id }],
					update: { status: "revoked", revokedAt: new Date() },
				});
				return accounts;
			},
		);

		const rejected = await instance.auth.api.unlinkAccount({
			body: {
				providerId: "credential",
				accountId: credential.accountId,
			},
			headers: signedIn.headers,
			asResponse: true,
		});
		expect(rejected.status).toBe(409);
		expect(await responseCode(rejected)).toBe("FACTOR_LIFECYCLE_CONFLICT");
		expect(rejected.headers.get("set-cookie")).toBeNull();
		expect(
			await instance.db.findOne<Session>({
				model: "session",
				where: [{ field: "id", value: session.session.id }],
			}),
		).not.toBeNull();
		expect(
			await instance.db.findOne({
				model: "account",
				where: [{ field: "id", value: credential.id }],
			}),
		).not.toBeNull();
	});

	it("serializes credential unlink against two-factor disable", async () => {
		const instance = await getTestInstance({
			baseURL: ORIGIN,
			secret: SECRET,
			plugins: [twoFactor({ allowPasswordless: true })],
		});
		const signedIn = await instance.signInWithTestUser();
		await seedSocialAccount(instance.db, signedIn.user.id);
		const active = await activateTwoFactor(instance, signedIn.headers);
		const credential = await credentialAccount(instance.db, signedIn.user.id);

		const [unlink, disable] = await Promise.all([
			instance.auth.api.unlinkAccount({
				body: {
					providerId: "credential",
					accountId: credential.accountId,
				},
				headers: new Headers(active.headers),
				asResponse: true,
			}),
			instance.auth.api.disableTwoFactor({
				body: {
					password: instance.testUser.password,
					recoveryCode: active.enrollment.backupCodes[0]!,
				},
				headers: new Headers(active.headers),
				asResponse: true,
			}),
		]);
		expect(
			[unlink.status, disable.status].filter((status) => status === 200),
			`unlink=${unlink.status}:${await unlink.clone().text()} disable=${disable.status}:${await disable.clone().text()}`,
		).toHaveLength(1);
		const remainingCredential = await instance.db.findOne<Account>({
			model: "account",
			where: [{ field: "id", value: credential.id }],
		});
		const remainingFactor = await instance.db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [
				{ field: "userId", value: signedIn.user.id },
				{ field: "verified", value: true },
			],
		});
		expect(remainingCredential !== null || remainingFactor !== null).toBe(true);
	});

	it("leaves ordinary social unlink session behavior unchanged", async () => {
		const instance = await getTestInstance({ baseURL: ORIGIN, secret: SECRET });
		const signedIn = await instance.signInWithTestUser();
		await seedSocialAccount(instance.db, signedIn.user.id);
		const before = await instance.auth.api.getSession({ headers: signedIn.headers });
		if (!before) throw new Error("initial session missing");

		const unlinked = await instance.auth.api.unlinkAccount({
			body: {
				providerId: "github",
				accountId: `github-${signedIn.user.id}`,
			},
			headers: signedIn.headers,
			asResponse: true,
		});
		expect(unlinked.status).toBe(200);
		expect(unlinked.headers.get("set-cookie")).toBeNull();
		const after = await instance.auth.api.getSession({ headers: signedIn.headers });
		expect(after?.session.id).toBe(before.session.id);
	});
});
