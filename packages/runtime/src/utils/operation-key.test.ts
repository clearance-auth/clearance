import { base64Url } from "@clearance/utils/base64";
import { describe, expect, it } from "vitest";
import {
	generateCredentialOperationKey,
	parseCredentialOperationKey,
} from "./operation-key";

describe("credential operation key", () => {
	it("generates and accepts a versioned 256-bit CSPRNG token", () => {
		const keys = Array.from({ length: 32 }, () =>
			generateCredentialOperationKey(),
		);
		expect(new Set(keys)).toHaveLength(keys.length);
		for (const key of keys) {
			expect(parseCredentialOperationKey(key)).toBe(key);
			expect(key).toMatch(/^clr_op_v1_[A-Za-z0-9_-]{43}$/);
			expect(base64Url.decode(key.slice("clr_op_v1_".length))).toHaveLength(
				32,
			);
		}
	});

	it("accepts a canonical non-degenerate payload", () => {
		const payload = base64Url.encode(
			Uint8Array.from({ length: 32 }, (_, index) => (index * 73 + 19) % 256),
			{ padding: false },
		);
		const key = `clr_op_v1_${payload}`;
		expect(parseCredentialOperationKey(key)).toBe(key);
	});

	it.each([
		["all-zero", new Uint8Array(32)],
		[
			"sequential 00..1f",
			Uint8Array.from({ length: 32 }, (_, index) => index),
		],
	])("rejects the explicit %s degenerate payload", (_label, bytes) => {
		const payload = base64Url.encode(bytes, { padding: false });
		expect(parseCredentialOperationKey(`clr_op_v1_${payload}`)).toBeNull();
	});

	const structuredSixteenBytes = base64Url.encode(
		Uint8Array.from({ length: 16 }, (_, index) => index),
		{ padding: false },
	);

	it.each([
		crypto.randomUUID(),
		"a".repeat(16),
		"a".repeat(22),
		"ababababababababababab",
		"predictable-key-0001",
		structuredSixteenBytes,
		`clr_op_v1_${structuredSixteenBytes}`,
		`clr_op_v2_${base64Url.encode(new Uint8Array(32), { padding: false })}`,
		`clr_op_v1_${base64Url.encode(new Uint8Array(31), { padding: false })}`,
		`clr_op_v1_${base64Url.encode(new Uint8Array(32), { padding: true })}`,
	])("rejects values outside the versioned 256-bit contract: %s", (key) => {
		expect(parseCredentialOperationKey(key)).toBeNull();
	});
});
