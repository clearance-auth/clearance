import { createOTP } from "@clearance/utils/otp";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getSessionCookie } from "../../cookies";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getTestInstance } from "../../test-utils/test-instance";
import { symmetricDecrypt } from "../../crypto";
import type { Session, User } from "../../types";
import { twoFactor } from "../two-factor";
import type { TwoFactorTable } from "../two-factor/types";
import { passkey } from ".";
import type { Passkey } from "./types";
import { createVirtualAuthenticator } from "./virtual-authenticator.test-utils";

const rotationControl = vi.hoisted(() => ({ fail: false }));
const transactionControl = vi.hoisted(() => ({
	beforeNext: null as (() => Promise<void>) | null,
}));

vi.mock("../../db/passkey-session-generation", async (importOriginal) => {
	const actual =
		await importOriginal<typeof import("../../db/passkey-session-generation")>();
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

vi.mock("@clearance/core/context", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@clearance/core/context")>();
	return {
		...actual,
		runWithTransaction: async (
			...args: Parameters<typeof actual.runWithTransaction>
		) => {
			const beforeNext = transactionControl.beforeNext;
			transactionControl.beforeNext = null;
			if (beforeNext) await beforeNext();
			return actual.runWithTransaction(...args);
		},
	};
});

const ORIGIN = "http://localhost:3320";
const RP_ID = "localhost";
const SECRET = "passkey-deletion-test-secret";

async function setup() {
	const instance = await getTestInstance(
		{
			baseURL: ORIGIN,
			secret: SECRET,
			plugins: [passkey()],
		},
		{ port: 3320 },
	);
	const signedIn = await instance.signInWithTestUser();
	signedIn.headers.set("origin", ORIGIN);
	return { ...instance, ...signedIn, headers: signedIn.headers };
}

async function seedPasskey(
	context: any,
	userId: string,
	suffix: string,
): Promise<Passkey> {
	return context.adapter.create({
		model: "passkey",
		data: {
			userId,
			name: suffix,
			credentialID: Buffer.from(
				`credential-${suffix}-${Math.random()}`,
			).toString("base64url"),
			publicKey: "unused-password-proof-key",
			userHandle: `handle-${suffix}`,
			counter: 0,
			deviceType: "singleDevice",
			backedUp: false,
			createdAt: new Date(),
			updatedAt: new Date(),
		},
	}) as Promise<Passkey>;
}

function expectError(error: unknown, status: string, code: string) {
	expect(error).toMatchObject({ status, body: { code } });
}

async function rawDelete(
	auth: { handler(request: Request): Promise<Response> },
	headers: Headers,
	body: unknown,
): Promise<Response> {
	const requestHeaders = new Headers(headers);
	requestHeaders.set("content-type", "application/json");
	return auth.handler(
		new Request(`${ORIGIN}/api/auth/passkey/delete`, {
			method: "POST",
			headers: requestHeaders,
			body: JSON.stringify(body),
		}),
	);
}

describe("passkey deletion lifecycle", () => {
	beforeEach(() => {
		rotationControl.fail = false;
		transactionControl.beforeNext = null;
	});

	it("deletes with a credential password, revokes every old token, and preserves exact expiry", async () => {
		const { auth, db, headers, user, testUser } = await setup();
		const context = await auth.$context;
		const target = await seedPasskey(context, user.id, "password-target");
		const before = await auth.api.getSession({ headers });
		if (!before) throw new Error("authoritative session missing");
		const extraOld = await context.internalAdapter.createSession(user.id);

		const response = await auth.api.deletePasskey({
			headers,
			body: {
				id: target.id,
				proof: { type: "password", password: testUser.password },
			},
			asResponse: true,
		});
		expect(response.status).toBe(200);
		expect(response.headers.get("set-cookie")).toContain("session_token");
		const replacementHeaders = convertSetCookieToCookie(response.headers);
		replacementHeaders.set("origin", ORIGIN);
		const replacement = await auth.api.getSession({ headers: replacementHeaders });
		expect(replacement).not.toBeNull();
		expect(new Date(replacement!.session.expiresAt).getTime()).toBe(
			new Date(before.session.expiresAt).getTime(),
		);
		await expect(auth.api.getSession({ headers })).resolves.toBeNull();
		await expect(
			context.internalAdapter.findSession(extraOld.token),
		).resolves.toBeNull();
		expect(
			await db.findOne({
				model: "passkey",
				where: [{ field: "id", value: target.id }],
			}),
		).toBeNull();
		const active = await context.internalAdapter.listSessions(user.id, {
			onlyActiveSessions: true,
		});
		expect(active).toHaveLength(1);
		expect(active[0]?.id).toBe(replacement!.session.id);
	});

	it("returns a stable generic proof failure for a wrong password", async () => {
		const { auth, db, headers, user } = await setup();
		const context = await auth.$context;
		const target = await seedPasskey(context, user.id, "wrong-password");
		let error: unknown;
		try {
			await auth.api.deletePasskey({
				headers,
				body: {
					id: target.id,
					proof: { type: "password", password: "definitely-wrong" },
				},
			});
		} catch (caught) {
			error = caught;
		}
		expectError(error, "UNAUTHORIZED", "DELETION_PROOF_FAILED");
		expect(
			await db.findOne({ model: "passkey", where: [{ field: "id", value: target.id }] }),
		).not.toBeNull();
	});

	it("rejects TOTP proof without a two-factor plugin before model access", async () => {
		const { auth, db, headers, user } = await setup();
		const context = await auth.$context;
		const target = await seedPasskey(context, user.id, "missing-two-factor-plugin");

		const response = await rawDelete(auth, headers, {
			id: target.id,
			proof: { type: "totp", code: "123456" },
		});

		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ code: "LAST_FACTOR_PROTECTED" });
		expect(response.headers.get("set-cookie")).toBeNull();
		expect(
			await db.findOne({
				model: "passkey",
				where: [{ field: "id", value: target.id }],
			}),
		).not.toBeNull();
		await expect(auth.api.getSession({ headers })).resolves.not.toBeNull();
	});

	it("rejects a stale verified factor when two-factor is authoritatively disabled", async () => {
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				secret: SECRET,
				plugins: [passkey(), twoFactor({ skipVerificationOnEnable: true })],
			},
			{ port: 3320 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const enabled = await instance.auth.api.enableTwoFactor({
			headers: signedIn.headers,
			body: { password: instance.testUser.password },
			asResponse: true,
		});
		const enrollment = (await enabled.json()) as { backupCodes: string[] };
		const activeHeaders = convertSetCookieToCookie(enabled.headers);
		activeHeaders.set("origin", ORIGIN);
		const context = await instance.auth.$context;
		const target = await seedPasskey(
			context,
			signedIn.user.id,
			"stale-disabled-two-factor",
		);
		const factorBefore = await instance.db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		if (!factorBefore?.verified) throw new Error("verified factor missing");
		await instance.db.update({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
			update: { twoFactorEnabled: false },
		});

		const response = await rawDelete(instance.auth, activeHeaders, {
			id: target.id,
			proof: {
				type: "recovery-code",
				code: enrollment.backupCodes[0]!,
			},
		});

		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ code: "LAST_FACTOR_PROTECTED" });
		expect(response.headers.get("set-cookie")).toBeNull();
		expect(
			await instance.db.findOne({
				model: "passkey",
				where: [{ field: "id", value: target.id }],
			}),
		).not.toBeNull();
		await expect(
			instance.db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "id", value: factorBefore.id }],
			}),
		).resolves.toMatchObject({ backupCodes: factorBefore.backupCodes });
		await expect(
			instance.auth.api.getSession({ headers: activeHeaders }),
		).resolves.not.toBeNull();
	});

	it("makes foreign and nonexistent target ids indistinguishable", async () => {
		const { auth, headers, user, testUser } = await setup();
		const context = await auth.$context;
		const foreignUser = await context.internalAdapter.createUser({
			email: `foreign-${Math.random()}@example.test`,
			emailVerified: true,
			name: "Foreign",
			image: null,
		});
		const foreign = await seedPasskey(context, foreignUser.id, "foreign");
		const errors: unknown[] = [];
		for (const id of [foreign.id, "does-not-exist"]) {
			try {
				await auth.api.deletePasskey({
					headers,
					body: {
						id,
						proof: { type: "password", password: testUser.password },
					},
				});
			} catch (error) {
				errors.push(error);
			}
		}
		expect(errors).toHaveLength(2);
		expect(errors[0]).toMatchObject(errors[1] as object);
		expectError(errors[0], "NOT_FOUND", "PASSKEY_NOT_FOUND");
		expect(user.id).not.toBe(foreignUser.id);
	});

	it("rolls every mutation back when the generation CAS loses", async () => {
		const { auth, db, headers, user, testUser } = await setup();
		const context = await auth.$context;
		const target = await seedPasskey(context, user.id, "generation-loser");
		const beforeUser = await db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: user.id }],
		});
		rotationControl.fail = true;

		const response = await rawDelete(auth, headers, {
			id: target.id,
			proof: { type: "password", password: testUser.password },
		});
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ code: "LIFECYCLE_CONFLICT" });
		expect(response.headers.get("set-cookie")).toBeNull();
		expect(
			await db.findOne({
				model: "passkey",
				where: [{ field: "id", value: target.id }],
			}),
		).not.toBeNull();
		expect(
			await db.findOne<User & Record<string, unknown>>({
				model: "user",
				where: [{ field: "id", value: user.id }],
			}),
		).toMatchObject({
			passkeySessionGeneration: beforeUser?.passkeySessionGeneration,
		});
		await expect(auth.api.getSession({ headers })).resolves.not.toBeNull();
	});

	it("rejects a credential revoked after middleware even when its session row is preserved", async () => {
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				secret: SECRET,
				session: { preserveSessionInDatabase: true },
				plugins: [passkey()],
			},
			{ port: 3320 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const context = await instance.auth.$context;
		const token = getSessionCookie(signedIn.headers)?.split(".")[0];
		if (!token) throw new Error("presented session token missing");
		const initial = await context.internalAdapter.findSession(token);
		if (!initial) throw new Error("initial session authority missing");
		const target = await seedPasskey(context, signedIn.user.id, "revocation-race");
		transactionControl.beforeNext = () => context.internalAdapter.deleteSession(token);

		const response = await rawDelete(instance.auth, signedIn.headers, {
			id: target.id,
			proof: { type: "password", password: instance.testUser.password },
		});
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ code: "LIFECYCLE_CONFLICT" });
		expect(response.headers.get("set-cookie")).toBeNull();
		await expect(context.internalAdapter.findSession(token)).resolves.toBeNull();
		expect(
			await instance.db.findOne({
				model: "session",
				where: [{ field: "id", value: initial.session.id }],
			}),
		).not.toBeNull();
		expect(
			await instance.db.findOne({
				model: "passkey",
				where: [{ field: "id", value: target.id }],
			}),
		).not.toBeNull();
	});

	it("requires and advances a distinct surviving passkey", async () => {
		const { auth, db, headers, user } = await setup();
		const targetAuthenticator = createVirtualAuthenticator(ORIGIN, RP_ID);
		const provingAuthenticator = createVirtualAuthenticator(ORIGIN, RP_ID);
		const targetOptions = await auth.api.generatePasskeyRegistrationOptions({ headers });
		const target = await auth.api.verifyPasskeyRegistration({
			headers,
			body: {
				response: targetAuthenticator.registrationResponse(targetOptions.challenge),
			},
		});
		const provingOptions = await auth.api.generatePasskeyRegistrationOptions({ headers });
		const proving = await auth.api.verifyPasskeyRegistration({
			headers,
			body: {
				response: provingAuthenticator.registrationResponse(provingOptions.challenge),
			},
		});
		const options = await auth.api.generatePasskeyDeletionOptions({
			headers,
			body: { id: target.id },
		});
		expect(options.userVerification).toBe("required");
		expect(options.allowCredentials?.map((entry) => entry.id)).toEqual([
			provingAuthenticator.credentialIDString,
		]);
		const proofResponse = provingAuthenticator.authenticationResponse(
			options.challenge,
			provingOptions.user.id,
			1,
		);
		const otherTarget = await seedPasskey(
			await auth.$context,
			user.id,
			"cross-target",
		);
		await expect(
			auth.api.deletePasskey({
				headers,
				body: {
					id: otherTarget.id,
					proof: { type: "passkey", response: proofResponse },
				},
			}),
		).rejects.toMatchObject({ body: { code: "DELETION_PROOF_FAILED" } });
		await expect(
			auth.api.deletePasskey({
				headers,
				body: {
					id: target.id,
					proof: { type: "passkey", response: proofResponse },
				},
			}),
		).rejects.toMatchObject({ body: { code: "DELETION_PROOF_FAILED" } });
		const freshOptions = await auth.api.generatePasskeyDeletionOptions({
			headers,
			body: { id: target.id },
		});
		const freshProof = provingAuthenticator.authenticationResponse(
			freshOptions.challenge,
			provingOptions.user.id,
			1,
		);
		await auth.api.deletePasskey({
			headers,
			body: {
				id: target.id,
				proof: { type: "passkey", response: freshProof },
			},
		});
		expect(
			await db.findOne({ model: "passkey", where: [{ field: "id", value: target.id }] }),
		).toBeNull();
		const surviving = await db.findOne<Passkey>({
			model: "passkey",
			where: [{ field: "id", value: proving.id }],
		});
		expect(surviving?.counter).toBe(1);
		expect(
			await db.findOne({
				model: "passkey",
				where: [{ field: "id", value: otherTarget.id }],
			}),
		).not.toBeNull();
	});

	it("burns passkey proofs before foreign and nonexistent target lookup", async () => {
		const { auth, headers, user } = await setup();
		const targetAuthenticator = createVirtualAuthenticator(ORIGIN, RP_ID);
		const provingAuthenticator = createVirtualAuthenticator(ORIGIN, RP_ID);
		const targetOptions = await auth.api.generatePasskeyRegistrationOptions({ headers });
		const target = await auth.api.verifyPasskeyRegistration({
			headers,
			body: {
				response: targetAuthenticator.registrationResponse(targetOptions.challenge),
			},
		});
		const provingOptions = await auth.api.generatePasskeyRegistrationOptions({ headers });
		await auth.api.verifyPasskeyRegistration({
			headers,
			body: {
				response: provingAuthenticator.registrationResponse(provingOptions.challenge),
			},
		});
		const context = await auth.$context;
		const foreignUser = await context.internalAdapter.createUser({
			email: `foreign-proof-${Math.random()}@example.test`,
			emailVerified: true,
			name: "Foreign proof owner",
			image: null,
		});
		const foreign = await seedPasskey(context, foreignUser.id, "foreign-proof");

		for (const submittedTargetId of [foreign.id, "does-not-exist"]) {
			const options = await auth.api.generatePasskeyDeletionOptions({
				headers,
				body: { id: target.id },
			});
			const response = provingAuthenticator.authenticationResponse(
				options.challenge,
				provingOptions.user.id,
				1,
			);
			await expect(
				auth.api.deletePasskey({
					headers,
					body: {
						id: submittedTargetId,
						proof: { type: "passkey", response },
					},
				}),
			).rejects.toMatchObject({ body: { code: "DELETION_PROOF_FAILED" } });
			await expect(
				auth.api.deletePasskey({
					headers,
					body: {
						id: target.id,
						proof: { type: "passkey", response },
					},
				}),
			).rejects.toMatchObject({ body: { code: "DELETION_PROOF_FAILED" } });
		}

		expect(user.id).not.toBe(foreignUser.id);
	});

	it("protects an only passkey from passkey-based deletion", async () => {
		const { auth, headers, user } = await setup();
		const target = await seedPasskey(await auth.$context, user.id, "only-target");
		await expect(
			auth.api.generatePasskeyDeletionOptions({ headers, body: { id: target.id } }),
		).rejects.toMatchObject({
			status: "BAD_REQUEST",
			body: { code: "LAST_FACTOR_PROTECTED" },
		});
	});

	it("rolls proof advancement and target deletion back when replacement creation fails", async () => {
		let rejectReplacement = false;
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				secret: SECRET,
				plugins: [passkey()],
				databaseHooks: {
					session: {
						create: {
							before: async () => (rejectReplacement ? false : undefined),
						},
					},
				},
			},
			{ port: 3320 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const targetAuthenticator = createVirtualAuthenticator(ORIGIN, RP_ID);
		const provingAuthenticator = createVirtualAuthenticator(ORIGIN, RP_ID);
		const first = await instance.auth.api.generatePasskeyRegistrationOptions({
			headers: signedIn.headers,
		});
		const target = await instance.auth.api.verifyPasskeyRegistration({
			headers: signedIn.headers,
			body: { response: targetAuthenticator.registrationResponse(first.challenge) },
		});
		const second = await instance.auth.api.generatePasskeyRegistrationOptions({
			headers: signedIn.headers,
		});
		const proving = await instance.auth.api.verifyPasskeyRegistration({
			headers: signedIn.headers,
			body: { response: provingAuthenticator.registrationResponse(second.challenge) },
		});
		const deletion = await instance.auth.api.generatePasskeyDeletionOptions({
			headers: signedIn.headers,
			body: { id: target.id },
		});
		const beforeUser = await instance.db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		const proofResponse = provingAuthenticator.authenticationResponse(
			deletion.challenge,
			second.user.id,
			1,
		);
		rejectReplacement = true;
		const failed = await rawDelete(instance.auth, signedIn.headers, {
			id: target.id,
			proof: { type: "passkey", response: proofResponse },
		});
		expect(failed.status).toBeGreaterThanOrEqual(400);
		expect(failed.headers.get("set-cookie")).toBeNull();
		expect(
			await instance.db.findOne({
				model: "passkey",
				where: [{ field: "id", value: target.id }],
			}),
		).not.toBeNull();
		expect(
			await instance.db.findOne<Passkey>({
				model: "passkey",
				where: [{ field: "id", value: proving.id }],
			}),
		).toMatchObject({ counter: 0 });
		const afterUser = await instance.db.findOne<User & Record<string, unknown>>({
			model: "user",
			where: [{ field: "id", value: signedIn.user.id }],
		});
		expect(afterUser?.passkeySessionGeneration).toBe(
			beforeUser?.passkeySessionGeneration,
		);
		await expect(
			instance.auth.api.getSession({ headers: signedIn.headers }),
		).resolves.not.toBeNull();

		// The assertion counter rolls back with the failed lifecycle, while the
		// independently consumed challenge remains one-shot.
		rejectReplacement = false;
		await expect(
			instance.auth.api.deletePasskey({
				headers: signedIn.headers,
				body: {
					id: target.id,
					proof: { type: "passkey", response: proofResponse },
				},
			}),
		).rejects.toMatchObject({ body: { code: "DELETION_PROOF_FAILED" } });
		const freshDeletion =
			await instance.auth.api.generatePasskeyDeletionOptions({
				headers: signedIn.headers,
				body: { id: target.id },
			});
		const freshProofResponse = provingAuthenticator.authenticationResponse(
			freshDeletion.challenge,
			second.user.id,
			1,
		);
		await expect(
			instance.auth.api.deletePasskey({
				headers: signedIn.headers,
				body: {
					id: target.id,
					proof: { type: "passkey", response: freshProofResponse },
				},
			}),
		).resolves.toEqual({ status: true });
	});

	it("fails before proof work and never mutates secondary-authoritative state", async () => {
		const store = new Map<string, string>();
		let secondaryWrites = 0;
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				secret: SECRET,
				plugins: [passkey()],
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
			{ port: 3320 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const target = await seedPasskey(
			await instance.auth.$context,
			signedIn.user.id,
			"secondary-config",
		);
		secondaryWrites = 0;

		const response = await rawDelete(instance.auth, signedIn.headers, {
			id: target.id,
			proof: { type: "password", password: instance.testUser.password },
		});
		expect(response.status).toBe(500);
		expect(await response.json()).toMatchObject({ code: "CONFIGURATION_ERROR" });
		expect(response.headers.get("set-cookie")).toBeNull();
		expect(secondaryWrites).toBe(0);
		expect(
			await instance.db.findOne({
				model: "passkey",
				where: [{ field: "id", value: target.id }],
			}),
		).not.toBeNull();
		await expect(
			instance.auth.api.getSession({ headers: signedIn.headers }),
		).resolves.not.toBeNull();
	});

	it("publishes the committed replacement cookie when dual-write cache hooks fail", async () => {
		const store = new Map<string, string>();
		let failSecondary = false;
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				secret: SECRET,
				session: { storeSessionInDatabase: true },
				plugins: [passkey()],
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
			},
			{ port: 3320 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const target = await seedPasskey(
			await instance.auth.$context,
			signedIn.user.id,
			"dual-write-failure",
		);
		failSecondary = true;

		const response = await rawDelete(instance.auth, signedIn.headers, {
			id: target.id,
			proof: { type: "password", password: instance.testUser.password },
		});
		expect(response.status).toBe(200);
		expect(response.headers.get("set-cookie")).toContain("session_token");
		failSecondary = false;
		const replacementHeaders = convertSetCookieToCookie(response.headers);
		replacementHeaders.set("origin", ORIGIN);
		await expect(
			instance.auth.api.getSession({ headers: replacementHeaders }),
		).resolves.not.toBeNull();
		await expect(
			instance.auth.api.getSession({ headers: signedIn.headers }),
		).resolves.toBeNull();
		expect(
			await instance.db.findOne({
				model: "passkey",
				where: [{ field: "id", value: target.id }],
			}),
		).toBeNull();
		expect(
			await instance.db.count({
				model: "sessionCredential",
				where: [
					{ field: "sessionId", operator: "ne", value: null },
					{ field: "status", value: "active" },
				],
			}),
		).toBe(1);
	});

	it("does not consult broken RP configuration or leak a recovery reservation", async () => {
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				secret: SECRET,
				plugins: [
					passkey({ rpID: "https://invalid-rp.example/path" }),
					twoFactor({ skipVerificationOnEnable: true }),
				],
			},
			{ port: 3320 },
		);
		const signedIn = await instance.signInWithTestUser();
		const enabled = await instance.auth.api.enableTwoFactor({
			headers: signedIn.headers,
			body: { password: instance.testUser.password },
			asResponse: true,
		});
		const enrollment = (await enabled.json()) as { backupCodes: string[] };
		const headers = convertSetCookieToCookie(enabled.headers);
		const target = await seedPasskey(
			await instance.auth.$context,
			signedIn.user.id,
			"broken-rp-recovery",
		);

		const response = await instance.auth.api.deletePasskey({
			headers,
			body: {
				id: target.id,
				proof: { type: "recovery-code", code: enrollment.backupCodes[0]! },
			},
			asResponse: true,
		});
		expect(response.status).toBe(200);
		const factor = await instance.db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		expect(factor).toMatchObject({
			failedVerificationCount: 0,
			activeVerificationReservations: "[]",
			lockedUntil: null,
		});
	});

	it("consumes TOTP counters and recovery codes exactly once", async () => {
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				secret: SECRET,
				plugins: [passkey(), twoFactor({ skipVerificationOnEnable: true })],
			},
			{ port: 3320 },
		);
		const signedIn = await instance.signInWithTestUser();
		signedIn.headers.set("origin", ORIGIN);
		const enabledResponse = await instance.auth.api.enableTwoFactor({
			headers: signedIn.headers,
			body: { password: instance.testUser.password },
			asResponse: true,
		});
		const enabledBody = (await enabledResponse.json()) as { backupCodes: string[] };
		let activeHeaders = convertSetCookieToCookie(enabledResponse.headers);
		activeHeaders.set("origin", ORIGIN);
		const factor = await instance.db.findOne<TwoFactorTable>({
			model: "twoFactor",
			where: [{ field: "userId", value: signedIn.user.id }],
		});
		if (!factor) throw new Error("two-factor row missing");
		const secret = await symmetricDecrypt({ key: SECRET, data: factor.secret });
		const totpCode = await createOTP(secret).totp();
		const totpTarget = await seedPasskey(
			await instance.auth.$context,
			signedIn.user.id,
			"totp-target",
		);
		const totpResponse = await instance.auth.api.deletePasskey({
			headers: activeHeaders,
			body: { id: totpTarget.id, proof: { type: "totp", code: totpCode } },
			asResponse: true,
		});
		activeHeaders = convertSetCookieToCookie(totpResponse.headers);
		activeHeaders.set("origin", ORIGIN);
		const replayTarget = await seedPasskey(
			await instance.auth.$context,
			signedIn.user.id,
			"totp-replay",
		);
		await expect(
			instance.auth.api.deletePasskey({
				headers: activeHeaders,
				body: { id: replayTarget.id, proof: { type: "totp", code: totpCode } },
			}),
		).rejects.toMatchObject({ body: { code: "DELETION_PROOF_FAILED" } });

		const recoveryTarget = await seedPasskey(
			await instance.auth.$context,
			signedIn.user.id,
			"recovery-target",
		);
		const recoveryResponse = await instance.auth.api.deletePasskey({
			headers: activeHeaders,
			body: {
				id: recoveryTarget.id,
				proof: { type: "recovery-code", code: enabledBody.backupCodes[0]! },
			},
			asResponse: true,
		});
		activeHeaders = convertSetCookieToCookie(recoveryResponse.headers);
		activeHeaders.set("origin", ORIGIN);
		const recoveryReplay = await seedPasskey(
			await instance.auth.$context,
			signedIn.user.id,
			"recovery-replay",
		);
		await expect(
			instance.auth.api.deletePasskey({
				headers: activeHeaders,
				body: {
					id: recoveryReplay.id,
					proof: { type: "recovery-code", code: enabledBody.backupCodes[0]! },
				},
			}),
		).rejects.toMatchObject({ body: { code: "DELETION_PROOF_FAILED" } });
	});
});
