import type { GenericEndpointContext } from "@clearance/core";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { createOTP } from "@clearance/utils/otp";
import { describe, expect, it, vi } from "vitest";
import { symmetricDecrypt } from "../../crypto";
import { convertSetCookieToCookie } from "../../test-utils/headers";
import { getTestInstance } from "../../test-utils/test-instance";
import { twoFactor } from "../two-factor";
import type { TwoFactorTable } from "../two-factor/types";
import { passkey } from ".";
import {
	consumeChallengeByParsedChallenge,
	createChallenge,
} from "./challenge";
import { advancePasskeyCounter } from "./counter";
import { assertPasskeyDeletionLifecycleOnAdapter } from "./passkey.deletion.adapter-test-utils";
import type { Passkey } from "./types";
import { createVirtualAuthenticator } from "./virtual-authenticator.test-utils";

const hasPostgres = Boolean(
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
		process.env.CLEARANCE_TEST_DATABASE_URL,
);
const ORIGIN = "http://localhost:3311";
const RP_ID = "localhost";
const SECRET = "passkey-postgres-lifecycle-secret";

describe.skipIf(!hasPostgres)("passkey PostgreSQL authority", () => {
	it("migrates, completes ceremonies, serializes authority races, and proves deletion success/rollback", async () => {
		const instance = await getTestInstance(
			{
				baseURL: ORIGIN,
				logger: { level: "error" },
				plugins: [passkey()],
			},
			{ port: 3311, testWith: "postgres" },
		);
		const { headers } = await instance.signInWithTestUser();
		headers.set("origin", ORIGIN);
		const authenticator = createVirtualAuthenticator(ORIGIN, RP_ID);

		const registrationOptions =
			await instance.auth.api.generatePasskeyRegistrationOptions({ headers });
		const registered = await instance.auth.api.verifyPasskeyRegistration({
			headers,
			body: {
				response: authenticator.registrationResponse(registrationOptions.challenge),
			},
		});
		const context = await instance.auth.$context;
		const registeredRow = await context.adapter.findOne<Passkey>({
			model: "passkey",
			where: [{ field: "id", value: registered.id }],
		});
		if (!registeredRow) throw new Error("registered passkey missing");

		const rollbackOptions =
			await instance.auth.api.generatePasskeyAuthenticationOptions({ headers });
		const sessionCountBefore = await context.adapter.count({
			model: "session",
			where: [{ field: "userId", value: registeredRow.userId }],
		});
		const originalCreateSession = context.internalAdapter.createSession;
		const createSession = vi
			.spyOn(context.internalAdapter, "createSession")
			.mockImplementationOnce(
				async (userId, dontRememberMe, override, overrideAll) => {
					await originalCreateSession(
						userId,
						dontRememberMe,
						override,
						overrideAll,
					);
					throw new Error("injected failure after session creation");
				},
			);
		try {
			await expect(
				instance.auth.api.verifyPasskeyAuthentication({
					headers,
					body: {
						response: authenticator.authenticationResponse(
							rollbackOptions.challenge,
							registrationOptions.user.id,
							1,
						),
					},
				}),
			).rejects.toThrow("injected failure after session creation");
		} finally {
			createSession.mockRestore();
		}
		await expect(
			context.adapter.findOne<Passkey>({
				model: "passkey",
				where: [{ field: "id", value: registered.id }],
			}),
		).resolves.toMatchObject({ counter: 0 });
		await expect(
			context.adapter.count({
				model: "session",
				where: [{ field: "userId", value: registeredRow.userId }],
			}),
		).resolves.toBe(sessionCountBefore);

		const authenticationOptions =
			await instance.auth.api.generatePasskeyAuthenticationOptions({ headers });
		await expect(
			instance.auth.api.verifyPasskeyAuthentication({
				headers,
				body: {
					response: authenticator.authenticationResponse(
						authenticationOptions.challenge,
						registrationOptions.user.id,
						1,
					),
				},
			}),
		).resolves.toMatchObject({ user: { email: "test@test.com" } });

		const stored = await context.adapter.findOne<Passkey>({
			model: "passkey",
			where: [{ field: "id", value: registered.id }],
		});
		expect(stored?.counter).toBe(1);
		await expect(
			context.adapter.create({
				model: "passkey",
				data: {
					userId: stored!.userId,
					credentialID: stored!.credentialID,
					publicKey: stored!.publicKey,
					userHandle: stored!.userHandle,
					counter: 0,
					deviceType: "singleDevice",
					backedUp: false,
					createdAt: new Date(),
					updatedAt: new Date(),
				},
			}),
		).rejects.toThrow();

		const userA = await context.internalAdapter.createUser({
			email: `passkey-handle-a-${Math.random()}@example.test`,
			emailVerified: true,
			name: "Handle A",
			image: null,
		});
		const userB = await context.internalAdapter.createUser({
			email: `passkey-handle-b-${Math.random()}@example.test`,
			emailVerified: true,
			name: "Handle B",
			image: null,
		});
		const sharedUserHandle = `shared-handle-${Math.random()}`;
		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: userA.id }],
			update: { passkeyUserHandle: sharedUserHandle },
		});
		await expect(
			context.adapter.update({
				model: "user",
				where: [{ field: "id", value: userB.id }],
				update: { passkeyUserHandle: sharedUserHandle },
			}),
		).rejects.toThrow();

		const ctx = { context } as unknown as GenericEndpointContext;
		const duplicateChallenge = `postgres-duplicate-${Date.now()}`;
		await createChallenge(ctx, "authentication", duplicateChallenge, {
			rpID: RP_ID,
			origin: ORIGIN,
		});
		await expect(
			createChallenge(ctx, "authentication", duplicateChallenge, {
				rpID: RP_ID,
				origin: ORIGIN,
			}),
		).rejects.toThrow();

		const challenge = `postgres-race-${Date.now()}`;
		await createChallenge(ctx, "authentication", challenge, {
			rpID: RP_ID,
			origin: ORIGIN,
		});
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
					registered.id,
					1,
					index + 2,
				),
			),
		);
		expect(counterClaims.filter(Boolean)).toHaveLength(1);

		await assertPasskeyDeletionLifecycleOnAdapter(instance.auth, ORIGIN);
	});

	it(
		"serializes concurrent sole-passkey deletion and two-factor disable without deadlock",
		async () => {
			const instance = await getTestInstance(
				{
					baseURL: ORIGIN,
					secret: SECRET,
					logger: { level: "error" },
					plugins: [passkey(), twoFactor({ allowPasswordless: true })],
				},
				{ port: 3311, testWith: "postgres" },
			);
			const signedIn = await instance.signInWithTestUser();
			const enrollment = await instance.auth.api.enableTwoFactor({
				body: { password: instance.testUser.password },
				headers: signedIn.headers,
			});
			const factor = await instance.db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "userId", value: signedIn.user.id }],
			});
			if (!factor) throw new Error("two-factor enrollment row missing");
			const secret = await symmetricDecrypt({ key: SECRET, data: factor.secret });
			const activated = await instance.auth.api.verifyTOTP({
				body: { code: await createOTP(secret).totp() },
				headers: signedIn.headers,
				asResponse: true,
			});
			expect(activated.status).toBe(200);
			// Activation consumed the current timestep. Reset only the test fixture's
			// replay baseline so the deletion lane enters the shared lifecycle race
			// with a valid TOTP instead of failing before serialization.
			await instance.db.update({
				model: "twoFactor",
				where: [{ field: "id", value: factor.id }],
				update: { lastUsedTotpCounter: -1 },
			});
			const headers = convertSetCookieToCookie(activated.headers);
			headers.set("origin", ORIGIN);
			const context = await instance.auth.$context;
			const target = await context.adapter.create<Passkey>({
				model: "passkey",
				data: {
					userId: signedIn.user.id,
					name: "postgres-concurrent-survivor",
					credentialID: `postgres-concurrent-${Math.random()}`,
					publicKey: "unused-concurrent-public-key",
					userHandle: `postgres-concurrent-handle-${Math.random()}`,
					counter: 0,
					deviceType: "singleDevice",
					backedUp: false,
					createdAt: new Date(),
					updatedAt: new Date(),
				},
			});
			await instance.db.deleteMany({
				model: "account",
				where: [
					{ field: "userId", value: signedIn.user.id },
					{ field: "providerId", value: "credential" },
				],
			});
			const currentCode = await createOTP(secret).totp();

			const [deletion, disable] = await Promise.all([
				instance.auth.api.deletePasskey({
					body: {
						id: target.id,
						proof: { type: "totp", code: currentCode },
					},
					headers: new Headers(headers),
					asResponse: true,
				}),
				instance.auth.api.disableTwoFactor({
					body: { recoveryCode: enrollment.backupCodes[0]! },
					headers: new Headers(headers),
					asResponse: true,
				}),
			]);
			const responses = [deletion, disable];
			expect(
				responses.filter((response) => response.status === 200),
			).toHaveLength(1);
			const loser = responses.find((response) => response.status !== 200);
			if (!loser) throw new Error("concurrent lifecycle loser missing");
			expect([400, 409]).toContain(loser.status);
			const loserBody = (await loser.json()) as { code?: string };
			expect(["LAST_FACTOR_PROTECTED", "LIFECYCLE_CONFLICT"]).toContain(
				loserBody.code,
			);

			const remainingPasskeys = await instance.db.count({
				model: "passkey",
				where: [{ field: "userId", value: signedIn.user.id }],
			});
			const remainingFactor = await instance.db.findOne<TwoFactorTable>({
				model: "twoFactor",
				where: [{ field: "userId", value: signedIn.user.id }],
			});
			expect(remainingPasskeys > 0 || remainingFactor !== null).toBe(true);
			if (deletion.status === 200) {
				expect(remainingPasskeys).toBe(0);
				expect(remainingFactor).not.toBeNull();
			} else {
				expect(remainingPasskeys).toBe(1);
				expect(remainingFactor).toBeNull();
			}
		},
		20_000,
	);
});
