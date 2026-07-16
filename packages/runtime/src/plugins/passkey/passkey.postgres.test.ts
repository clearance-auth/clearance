import type { GenericEndpointContext } from "@clearance/core";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { passkey } from ".";
import {
	consumeChallengeByParsedChallenge,
	createChallenge,
} from "./challenge";
import { advancePasskeyCounter } from "./counter";
import type { Passkey } from "./types";
import { createVirtualAuthenticator } from "./virtual-authenticator.test-utils";

const hasPostgres = Boolean(
	process.env.CLEARANCE_TEST_POSTGRES_URL ??
		process.env.CLEARANCE_TEST_DATABASE_URL,
);
const ORIGIN = "http://localhost:3311";
const RP_ID = "localhost";

describe.skipIf(!hasPostgres)("passkey PostgreSQL authority", () => {
	it("migrates, completes both ceremonies, enforces uniqueness, and serializes challenge/counter races", async () => {
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
	});
});
