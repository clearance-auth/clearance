import type { GenericEndpointContext } from "@clearance/core";
import { base64Url } from "@clearance/utils/base64";
import { createHash } from "@clearance/utils/hash";
import { describe, expect, it, vi } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import {
	consumeChallengeByParsedChallenge,
	createChallenge,
	parseClientDataChallenge,
} from "./challenge";
import { passkey as passkeyPlugin } from "./index";

async function fakeCtx(): Promise<GenericEndpointContext> {
	const { auth } = await getTestInstance(
		{ plugins: [passkeyPlugin({ rpID: "example.com" })] },
		{ disableTestUser: true },
	);
	const context = await auth.$context;
	return { context } as unknown as GenericEndpointContext;
}

function clientDataFor(challenge: string): string {
	return base64Url.encode(
		JSON.stringify({ type: "webauthn.get", challenge, origin: "https://app.example.com" }),
		{ padding: false },
	);
}

describe("parseClientDataChallenge (bounded parser)", () => {
	it("extracts the challenge from a well-formed clientDataJSON", () => {
		expect(parseClientDataChallenge(clientDataFor("abc123"))).toBe("abc123");
	});

	it("rejects a non-string input", () => {
		expect(parseClientDataChallenge(undefined)).toBeNull();
		expect(parseClientDataChallenge(42)).toBeNull();
		expect(parseClientDataChallenge(null)).toBeNull();
	});

	it("rejects an oversized raw string before decoding", () => {
		expect(parseClientDataChallenge("a".repeat(9_000))).toBeNull();
	});

	it("rejects invalid base64url", () => {
		expect(parseClientDataChallenge("not!!valid!!base64url")).toBeNull();
	});

	it("rejects a decoded payload that isn't JSON", () => {
		expect(
			parseClientDataChallenge(base64Url.encode("not json", { padding: false })),
		).toBeNull();
	});

	it("rejects JSON without a string challenge field", () => {
		expect(
			parseClientDataChallenge(
				base64Url.encode(JSON.stringify({ type: "webauthn.get" }), {
					padding: false,
				}),
			),
		).toBeNull();
		expect(
			parseClientDataChallenge(
				base64Url.encode(JSON.stringify({ challenge: 12345 }), {
					padding: false,
				}),
			),
		).toBeNull();
	});

	it("rejects an oversized challenge field", () => {
		expect(
			parseClientDataChallenge(clientDataFor("x".repeat(600))),
		).toBeNull();
	});
});

describe("passkey challenge storage (database-backed, single-use)", () => {
	it("consumes a valid, unexpired challenge exactly once", async () => {
		const ctx = await fakeCtx();
		const challenge = "challenge-consume-once";
		await createChallenge(ctx, "registration", challenge, {
			rpID: "app.example.com",
			origin: "https://app.example.com",
			userId: "user-1",
			userHandle: "handle-1",
		});

		const first = await consumeChallengeByParsedChallenge(ctx, "registration", challenge);
		expect(first).not.toBeNull();
		expect(first?.rpID).toBe("app.example.com");
		expect(first?.userId).toBe("user-1");

		const replay = await consumeChallengeByParsedChallenge(ctx, "registration", challenge);
		expect(replay).toBeNull();
	});

	it("rejects a challenge minted by the other ceremony", async () => {
		const ctx = await fakeCtx();
		const challenge = "challenge-cross-ceremony";
		await createChallenge(ctx, "registration", challenge, {
			rpID: "app.example.com",
			origin: "https://app.example.com",
		});

		const wrongCeremony = await consumeChallengeByParsedChallenge(
			ctx,
			"authentication",
			challenge,
		);
		expect(wrongCeremony).toBeNull();

		// The registration-scoped row must still be consumable afterward.
		const correctCeremony = await consumeChallengeByParsedChallenge(
			ctx,
			"registration",
			challenge,
		);
		expect(correctCeremony).not.toBeNull();
	});

	it("isolates recovery registration from normal registration", async () => {
		const ctx = await fakeCtx();
		const challenge = "challenge-recovery-registration";
		await createChallenge(ctx, "recovery-registration", challenge, {
			rpID: "app.example.com",
			origin: "https://app.example.com",
			userId: "user-1",
			userHandle: "handle-1",
		});

		await expect(
			consumeChallengeByParsedChallenge(ctx, "registration", challenge),
		).resolves.toBeNull();
		await expect(
			consumeChallengeByParsedChallenge(
				ctx,
				"recovery-registration",
				challenge,
			),
		).resolves.toMatchObject({
			ceremony: "recovery-registration",
			userId: "user-1",
			userHandle: "handle-1",
		});
	});

	it("keeps deletion challenges ceremony-scoped and bound to user and target", async () => {
		const ctx = await fakeCtx();
		const challenge = "challenge-deletion-binding";
		await createChallenge(ctx, "deletion", challenge, {
			rpID: "app.example.com",
			origin: "https://app.example.com",
			userId: "user-1",
			targetPasskeyId: "passkey-1",
		});

		await expect(
			consumeChallengeByParsedChallenge(ctx, "authentication", challenge),
		).resolves.toBeNull();
		await expect(
			consumeChallengeByParsedChallenge(ctx, "deletion", challenge),
		).resolves.toMatchObject({
			rpID: "app.example.com",
			origin: "https://app.example.com",
			userId: "user-1",
			targetPasskeyId: "passkey-1",
		});
	});

	it("rejects an unknown challenge", async () => {
		const ctx = await fakeCtx();
		expect(
			await consumeChallengeByParsedChallenge(ctx, "authentication", "never-created"),
		).toBeNull();
	});

	it("rejects an expired challenge and still burns it", async () => {
		const ctx = await fakeCtx();
		const challenge = "challenge-expired";
		const digestId = await createHash("SHA-256", "base64urlnopad").digest(
			`passkey:authentication:${challenge}`,
		);
		await ctx.context.adapter.create({
			model: "passkeyChallenge",
			data: {
				digestId,
				ceremony: "authentication",
				rpID: "app.example.com",
				origin: "https://app.example.com",
				expiresAt: new Date(Date.now() - 1_000),
				createdAt: new Date(Date.now() - 2_000),
				updatedAt: new Date(Date.now() - 2_000),
			},
		});

		expect(
			await consumeChallengeByParsedChallenge(ctx, "authentication", challenge),
		).toBeNull();
		// Burned even though expired: a second attempt also finds nothing.
		expect(
			await consumeChallengeByParsedChallenge(ctx, "authentication", challenge),
		).toBeNull();
	});

	it("opportunistically removes abandoned expired challenges before issuance", async () => {
		const ctx = await fakeCtx();
		await ctx.context.adapter.create({
			model: "passkeyChallenge",
			data: {
				digestId: "expired-abandoned-digest",
				ceremony: "authentication",
				rpID: "app.example.com",
				origin: "https://app.example.com",
				expiresAt: new Date(Date.now() - 1_000),
				createdAt: new Date(Date.now() - 2_000),
				updatedAt: new Date(Date.now() - 2_000),
			},
		});

		await createChallenge(ctx, "authentication", "fresh-after-cleanup", {
			rpID: "app.example.com",
			origin: "https://app.example.com",
		});

		await expect(
			ctx.context.adapter.findOne({
				model: "passkeyChallenge",
				where: [{ field: "digestId", value: "expired-abandoned-digest" }],
			}),
		).resolves.toBeNull();
	});

	it("yields exactly one winner under concurrent consumption", async () => {
		const ctx = await fakeCtx();
		const challenge = "challenge-concurrent";
		await createChallenge(ctx, "authentication", challenge, {
			rpID: "app.example.com",
			origin: "https://app.example.com",
		});

		const results = await Promise.all(
			Array.from({ length: 8 }, () =>
				consumeChallengeByParsedChallenge(ctx, "authentication", challenge),
			),
		);
		const winners = results.filter((result) => result !== null);
		expect(winners).toHaveLength(1);
	});
});

describe("passkey challenge storage: opaque digest identifiers", () => {
	it("stores the digest -- never the raw challenge -- as the unique lookup key", async () => {
		const ctx = await fakeCtx();
		const challenge = "super-secret-raw-challenge-value";
		await createChallenge(ctx, "registration", challenge, {
			rpID: "app.example.com",
			origin: "https://app.example.com",
		});

		const expectedDigest = await createHash("SHA-256", "base64urlnopad").digest(
			`passkey:registration:${challenge}`,
		);
		const row = await ctx.context.adapter.findOne<Record<string, unknown>>({
			model: "passkeyChallenge",
			where: [{ field: "digestId", value: expectedDigest }],
		});
		expect(row).not.toBeNull();
		expect(row).not.toHaveProperty("rawChallenge");
		expect(row?.digestId).not.toBe(challenge);
		expect(String(row?.digestId)).not.toContain(challenge);
		expect(row?.digestId).toBe(expectedDigest);
		// The digest is base64url (no padding): no '+', '/', or '=' characters.
		expect(row?.digestId).not.toMatch(/[+/=]/);
	});

	it("consumeOne is called exactly once per successful consumption (atomic, no find-then-delete)", async () => {
		const ctx = await fakeCtx();
		const challenge = "challenge-atomic-consume";
		await createChallenge(ctx, "registration", challenge, {
			rpID: "app.example.com",
			origin: "https://app.example.com",
		});
		const consumeOneSpy = vi.spyOn(ctx.context.adapter, "consumeOne");
		const findOneSpy = vi.spyOn(ctx.context.adapter, "findOne");

		const result = await consumeChallengeByParsedChallenge(ctx, "registration", challenge);

		expect(result).not.toBeNull();
		expect(consumeOneSpy).toHaveBeenCalledTimes(1);
		expect(findOneSpy).not.toHaveBeenCalled();
	});
});
