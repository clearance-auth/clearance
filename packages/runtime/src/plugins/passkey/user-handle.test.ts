import type { GenericEndpointContext } from "@clearance/core";
import { base64Url } from "@clearance/utils/base64";
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../../test-utils/test-instance";
import { passkey as passkeyPlugin } from "./index";
import { decodeCanonicalUserHandle, ensurePasskeyUserHandle } from "./user-handle";

async function setup() {
	const { auth } = await getTestInstance(
		{ plugins: [passkeyPlugin({ rpID: "example.com" })] },
		{ disableTestUser: true },
	);
	const context = await auth.$context;
	const user = await context.internalAdapter.createUser({
		email: `passkey-handle-${Math.random()}@example.test`,
		emailVerified: true,
		name: "Handle Test",
		image: null,
	});
	const ctx = { context } as unknown as GenericEndpointContext;
	return { ctx, context, userId: user.id };
}

describe("ensurePasskeyUserHandle", () => {
	it("initializes a stable random handle on first use", async () => {
		const { ctx, userId } = await setup();
		const handle = await ensurePasskeyUserHandle(ctx, userId);
		expect(typeof handle).toBe("string");
		expect(handle.length).toBeGreaterThan(0);
	});

	it("returns the same handle on every subsequent call", async () => {
		const { ctx, userId } = await setup();
		const first = await ensurePasskeyUserHandle(ctx, userId);
		const second = await ensurePasskeyUserHandle(ctx, userId);
		const third = await ensurePasskeyUserHandle(ctx, userId);
		expect(second).toBe(first);
		expect(third).toBe(first);
	});

	it("never derives the handle from the raw user id", async () => {
		const { ctx, userId } = await setup();
		const handle = await ensurePasskeyUserHandle(ctx, userId);
		expect(handle).not.toBe(userId);
		expect(handle.includes(userId)).toBe(false);
	});

	it("converges concurrent first-enrollment races on exactly one stable handle", async () => {
		const { ctx, userId } = await setup();
		const results = await Promise.all(
			Array.from({ length: 8 }, () => ensurePasskeyUserHandle(ctx, userId)),
		);
		const distinct = new Set(results);
		expect(distinct.size).toBe(1);
	});

	it("uses the canonical base64url (no padding) representation", async () => {
		const { ctx, userId } = await setup();
		const handle = await ensurePasskeyUserHandle(ctx, userId);
		expect(handle).not.toMatch(/[+/=]/);
		expect(handle).toMatch(/^[A-Za-z0-9_-]+$/);
		// Round-trips through the exact decoder used to build the WebAuthn
		// registration `userID` bytes.
		const decoded = decodeCanonicalUserHandle(handle);
		expect(base64Url.encode(new Uint8Array(decoded), { padding: false })).toBe(handle);
	});

	it("decodes to raw bytes matching the exact encoding used for registration's userID", async () => {
		const { ctx, userId } = await setup();
		const handle = await ensurePasskeyUserHandle(ctx, userId);
		const decoded = decodeCanonicalUserHandle(handle);
		expect(decoded).toBeInstanceOf(Uint8Array);
		expect(decoded.byteLength).toBe(32);
	});
});
