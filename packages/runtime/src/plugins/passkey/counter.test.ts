import type { DBTransactionAdapter } from "@clearance/core/db/adapter";
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { advancePasskeyCounter } from "./counter";
import { passkey as passkeyPlugin } from "./index";

async function seedPasskey(counter: number) {
	const { auth } = await getTestInstance(
		{ plugins: [passkeyPlugin({ rpID: "example.com" })] },
		{ disableTestUser: true },
	);
	const context = await auth.$context;
	const adapter = context.adapter as unknown as DBTransactionAdapter;
	const user = await context.internalAdapter.createUser({
		email: `passkey-counter-${counter}-${Math.random()}@example.test`,
		emailVerified: true,
		name: "Counter Test",
		image: null,
	});
	const passkey = await context.adapter.create<Record<string, unknown>>({
		model: "passkey",
		data: {
			userId: user.id,
			credentialID: `cred-${Math.random()}`,
			publicKey: "pk",
			userHandle: "handle",
			counter,
			deviceType: "singleDevice",
			backedUp: false,
			createdAt: new Date(),
			updatedAt: new Date(),
		},
	});
	return { context, adapter, passkey: passkey as { id: string; counter: number } };
}

describe("advancePasskeyCounter (guarded compare-and-swap)", () => {
	it("advances a nonzero counter when the guard matches", async () => {
		const { context, adapter, passkey } = await seedPasskey(5);
		const won = await advancePasskeyCounter(adapter, passkey.id, 5, 6);
		expect(won).toBe(true);
		const row = await context.adapter.findOne<{ counter: number }>({
			model: "passkey",
			where: [{ field: "id", value: passkey.id }],
		});
		expect(row?.counter).toBe(6);
	});

	it("fails the guard when the observed counter is stale", async () => {
		const { context, adapter, passkey } = await seedPasskey(5);
		// Someone else already advanced it to 6.
		await context.adapter.update({
			model: "passkey",
			where: [{ field: "id", value: passkey.id }],
			update: { counter: 6 },
		});
		const won = await advancePasskeyCounter(adapter, passkey.id, 5, 7);
		expect(won).toBe(false);
		const row = await context.adapter.findOne<{ counter: number }>({
			model: "passkey",
			where: [{ field: "id", value: passkey.id }],
		});
		expect(row?.counter).toBe(6);
	});

	it("yields exactly one winner among concurrent callers observing the same nonzero counter", async () => {
		const { adapter, passkey } = await seedPasskey(10);
		const results = await Promise.all(
			Array.from({ length: 8 }, (_, i) =>
				advancePasskeyCounter(adapter, passkey.id, 10, 11 + i),
			),
		);
		expect(results.filter(Boolean)).toHaveLength(1);
	});

	it("allows every concurrent caller to succeed for a both-zero credential", async () => {
		const { context, adapter, passkey } = await seedPasskey(0);
		const results = await Promise.all(
			Array.from({ length: 5 }, () =>
				advancePasskeyCounter(adapter, passkey.id, 0, 0),
			),
		);
		expect(results.every(Boolean)).toBe(true);
		const row = await context.adapter.findOne<{ counter: number }>({
			model: "passkey",
			where: [{ field: "id", value: passkey.id }],
		});
		expect(row?.counter).toBe(0);
	});

	it("rejects a descending (non-monotonic) transition before any database access", async () => {
		const { adapter, passkey } = await seedPasskey(5);
		const won = await advancePasskeyCounter(adapter, passkey.id, 5, 3);
		expect(won).toBe(false);
	});

	it("rejects a repeated nonzero value (newCounter === observedCounter, both nonzero)", async () => {
		const { adapter, passkey } = await seedPasskey(5);
		const won = await advancePasskeyCounter(adapter, passkey.id, 5, 5);
		expect(won).toBe(false);
	});

	it("rejects the 0 -> 0 transition when the row does not actually exist with counter 0", async () => {
		const { adapter } = await seedPasskey(0);
		const won = await advancePasskeyCounter(adapter, "does-not-exist", 0, 0);
		expect(won).toBe(false);
	});

	it("rejects the 0 -> 0 transition when the row's counter has since moved off zero", async () => {
		const { context, adapter, passkey } = await seedPasskey(0);
		await context.adapter.update({
			model: "passkey",
			where: [{ field: "id", value: passkey.id }],
			update: { counter: 1 },
		});
		const won = await advancePasskeyCounter(adapter, passkey.id, 0, 0);
		expect(won).toBe(false);
	});
});
