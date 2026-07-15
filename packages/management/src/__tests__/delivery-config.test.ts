import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import { deliveryStoreOptionsFromEnvironment } from "../store/create-store.js";
import { PgStore } from "../store/pg-store.js";

function key(byte: number): string {
	return Buffer.alloc(32, byte).toString("base64");
}

function completeEnvironment(): NodeJS.ProcessEnv {
	return {
		CLEARANCE_DELIVERY_KEY_ID: "enc-current",
		CLEARANCE_DELIVERY_KEYS_JSON: JSON.stringify({
			"enc-current": key(1),
			"enc-old": key(2),
		}),
		CLEARANCE_DELIVERY_FINGERPRINT_KEY_ID: "fingerprint-current",
		CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON: JSON.stringify({
			"fingerprint-current": key(3),
			"fingerprint-old": key(4),
		}),
		CLEARANCE_DELIVERY_SOURCE_DEDUPE_KEY: key(5),
		CLEARANCE_DELIVERY_SCHEMA: "delivery_ops",
		CLEARANCE_DELIVERY_PREFIX: "control_",
		CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID: "fingerprint-old",
		CLEARANCE_DELIVERY_QUOTA_MAX_ACTIVE: "900",
		CLEARANCE_DELIVERY_QUOTA_MAX_BACKLOG: "700",
		CLEARANCE_DELIVERY_QUOTA_MAX_ENQUEUES_PER_WINDOW: "80",
		CLEARANCE_DELIVERY_QUOTA_WINDOW_MS: "45000",
	};
}

describe("delivery store environment configuration", () => {
	it("stays absent when no key signal is configured", () => {
		expect(deliveryStoreOptionsFromEnvironment({})).toBeUndefined();
		expect(deliveryStoreOptionsFromEnvironment({
			CLEARANCE_DELIVERY_SCHEMA: "ignored_without_keys",
			CLEARANCE_DELIVERY_QUOTA_MAX_ACTIVE: "42",
		})).toBeUndefined();
	});

	it("resolves complete keys, quota, schema, and prefix and PgStore accepts the ring", async () => {
		const options = deliveryStoreOptionsFromEnvironment(completeEnvironment());
		expect(options).toBeDefined();
		expect(options).toMatchObject({
			schema: "delivery_ops",
			prefix: "control_",
			legacyFingerprintKeyId: "fingerprint-old",
			quota: {
				maxActive: 900,
				maxBacklog: 700,
				maxEnqueuesPerWindow: 80,
				windowMs: 45_000,
			},
		});
		expect(options!.keyring.currentKeyId).toBe("enc-current");
		expect(options!.keyring.keys).toBeInstanceOf(Map);
		expect(options!.keyring.fingerprintKeys).toBeInstanceOf(Map);
		expect(options!.keyring.sourceDedupeKey).toBeInstanceOf(Buffer);

		const store = new PgStore("postgres://unused:unused@127.0.0.1:1/unused", {
			delivery: options!,
		});
		expect(store.deliveryControl).toBeDefined();
		await store.destroy();
	});

	it("fails partial and invalid configuration closed without echoing key material", () => {
		const partial = completeEnvironment();
		delete partial.CLEARANCE_DELIVERY_FINGERPRINT_KEYS_JSON;
		expect(() => deliveryStoreOptionsFromEnvironment(partial)).toThrowError(
			expect.objectContaining({ code: "DELIVERY_KEYRING_REQUIRED" }),
		);

		const secret = "DO_NOT_ECHO_THIS_DELIVERY_SECRET";
		const invalidKey = completeEnvironment();
		invalidKey.CLEARANCE_DELIVERY_KEYS_JSON = JSON.stringify({
			"enc-current": secret,
		});
		let keyError: unknown;
		try {
			deliveryStoreOptionsFromEnvironment(invalidKey);
		} catch (error) {
			keyError = error;
		}
		expect(keyError).toMatchObject({ code: "DELIVERY_KEY_INVALID" });
		expect(String(keyError)).not.toContain(secret);

		for (const invalid of [
			{ CLEARANCE_DELIVERY_SCHEMA: "bad-schema!" },
			{ CLEARANCE_DELIVERY_PREFIX: "bad prefix" },
			{ CLEARANCE_DELIVERY_QUOTA_MAX_ACTIVE: "0" },
			{ CLEARANCE_DELIVERY_QUOTA_WINDOW_MS: "999" },
			{ CLEARANCE_DELIVERY_LEGACY_FINGERPRINT_KEY_ID: "bad key id" },
		]) {
			const env = { ...completeEnvironment(), ...invalid };
			expect(() => deliveryStoreOptionsFromEnvironment(env)).toThrow();
		}
	});

	it("rejects invalid direct delivery options before opening storage", () => {
		const options = deliveryStoreOptionsFromEnvironment(completeEnvironment())!;
		expect(() => new PgStore("postgres://unused:unused@127.0.0.1:1/unused", {
			delivery: {
				...options,
				quota: { ...options.quota!, maxActive: 0 },
			},
		})).toThrowError(expect.objectContaining({ code: "DELIVERY_BOUND_INVALID" }));
		expect(() => new PgStore("postgres://unused:unused@127.0.0.1:1/unused", {
			delivery: { ...options, prefix: "invalid prefix" },
		})).toThrow();
	});
});
