import { randomUUID } from "node:crypto";
import type { GenericEndpointContext } from "@clearance/core";
import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { passkey } from ".";
import {
	consumeChallengeByParsedChallenge,
	createChallenge,
} from "./challenge";
import { advancePasskeyCounter } from "./counter";

const hasMongo = Boolean(process.env.CLEARANCE_TEST_MONGODB_URL);

describe.skipIf(!hasMongo)("passkey MongoDB authority", () => {
	it("enforces unique authorities and serializes challenge/counter claims", async () => {
		const { auth } = await getTestInstance(
			{
				baseURL: "http://localhost:3313",
				logger: { level: "error" },
				plugins: [passkey()],
			},
			{ disableTestUser: true, port: 3313, testWith: "mongodb" },
		);
		const context = await auth.$context;
		const firstUser = await context.internalAdapter.createUser({
			email: `mongo-passkey-a-${randomUUID()}@example.test`,
			emailVerified: true,
			image: null,
			name: "Mongo passkey A",
		});
		const secondUser = await context.internalAdapter.createUser({
			email: `mongo-passkey-b-${randomUUID()}@example.test`,
			emailVerified: true,
			image: null,
			name: "Mongo passkey B",
		});
		const stableHandle = `handle-${randomUUID()}`;
		await context.adapter.update({
			model: "user",
			where: [{ field: "id", value: firstUser.id }],
			update: { passkeyUserHandle: stableHandle },
		});
		await expect(
			context.adapter.update({
				model: "user",
				where: [{ field: "id", value: secondUser.id }],
				update: { passkeyUserHandle: stableHandle },
			}),
		).rejects.toMatchObject({ code: 11000 });

		const credentialID = `credential-${randomUUID()}`;
		const row = await context.adapter.create<Record<string, unknown>>({
			model: "passkey",
			data: {
				userId: firstUser.id,
				credentialID,
				publicKey: "public-key",
				userHandle: stableHandle,
				counter: 2,
				deviceType: "singleDevice",
				backedUp: false,
				createdAt: new Date(),
				updatedAt: new Date(),
			},
		});
		await expect(
			context.adapter.create({
				model: "passkey",
				data: {
					userId: secondUser.id,
					credentialID,
					publicKey: "different-public-key",
					userHandle: `handle-${randomUUID()}`,
					counter: 0,
					deviceType: "multiDevice",
					backedUp: true,
					createdAt: new Date(),
					updatedAt: new Date(),
				},
			}),
		).rejects.toMatchObject({ code: 11000 });

		const ctx = { context } as unknown as GenericEndpointContext;
		const challenge = `mongo-challenge-${randomUUID()}`;
		await createChallenge(ctx, "authentication", challenge, {
			rpID: "localhost",
			origin: "http://localhost:3313",
		});
		await expect(
			createChallenge(ctx, "authentication", challenge, {
				rpID: "localhost",
				origin: "http://localhost:3313",
			}),
		).rejects.toMatchObject({ code: 11000 });
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
					String(row.id),
					2,
					index + 3,
				),
			),
		);
		expect(counterClaims.filter(Boolean)).toHaveLength(1);
	});
});
