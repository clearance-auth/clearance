import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createDeliveryKeyring,
	decryptDeliveryPayload,
	encryptDeliveryPayload,
	fingerprintDestination,
	MAX_DELIVERY_PAYLOAD_BYTES,
	type DeliveryPayloadAad,
} from "./keyring.js";
import { redactedDeliveryJob, safeErrorClass, safeProviderValue } from "./redaction.js";

function ring() {
	return createDeliveryKeyring({
		currentKeyId: "key-2",
		keys: { "key-1": randomBytes(32), "key-2": randomBytes(32) },
		fingerprintKey: randomBytes(32),
	});
}

describe("delivery crypto and redaction", () => {
	it("authenticates payloads against every required AAD field", () => {
		const keyring = ring();
		const aad: DeliveryPayloadAad = {
			version: 1,
			eventId: "evt_1",
			kind: "password.reset",
			channel: "email",
			projectId: "project_1",
			environmentId: "env_1",
			destinationFingerprint: fingerprintDestination("person@example.test", keyring),
			expiresAt: "2030-01-01T00:00:00.000Z",
		};
		const payload = { to: "person@example.test", token: "reset-secret" };
		const encrypted = encryptDeliveryPayload(payload, aad, keyring);
		expect(encrypted.envelope).not.toContain(payload.to);
		expect(encrypted.envelope).not.toContain(payload.token);
		expect(decryptDeliveryPayload(encrypted.envelope, aad, keyring)).toEqual(payload);
		for (const patch of [
			{ eventId: "evt_2" }, { kind: "email.verify" }, { channel: "webhook" as const },
			{ projectId: "project_2" },
			{ environmentId: "env_2" }, { destinationFingerprint: "0".repeat(64) },
			{ expiresAt: "2031-01-01T00:00:00.000Z" },
		]) {
			expect(() => decryptDeliveryPayload(encrypted.envelope, { ...aad, ...patch }, keyring))
				.toThrowError(/authentication failed/);
		}
	});

	it("requires explicit 32-byte purpose-separated keys", () => {
		const shared = randomBytes(32);
		expect(() => createDeliveryKeyring({
			currentKeyId: "current", keys: { current: shared }, fingerprintKey: shared,
		})).toThrowError(/different material/);
		expect(() => createDeliveryKeyring({
			currentKeyId: "current", keys: { current: "weak" }, fingerprintKey: randomBytes(32),
		})).toThrowError(/32 bytes/);
	});

	it("rejects cyclic and oversized payloads before encryption", () => {
		const keyring = ring();
		const aad: DeliveryPayloadAad = {
			version: 1, eventId: "evt_bound", kind: "email.verify", channel: "email",
			projectId: "project_1", environmentId: "env_1",
			destinationFingerprint: fingerprintDestination("person@example.test", keyring),
			expiresAt: "2030-01-01T00:00:00.000Z",
		};
		const cyclic: { self?: unknown } = {};
		cyclic.self = cyclic;
		expect(() => encryptDeliveryPayload(cyclic, aad, keyring)).toThrowError(/JSON serializable/);
		expect(() => encryptDeliveryPayload("x".repeat(MAX_DELIVERY_PAYLOAD_BYTES + 1), aad, keyring))
			.toThrowError(/exceeds/);
	});

	it("returns public views and provider metadata without secret-bearing strings", () => {
		const view = redactedDeliveryJob({
			id: "job_1", eventId: "event_1", kind: "password.reset",
			projectId: "project_1", environmentId: "env_1", organizationId: null,
			channel: "email", state: "queued", attemptCount: 0, maxAttempts: 8,
			availableAt: "2030-01-01T00:00:00.000Z", semanticExpiresAt: "2030-01-01T01:00:00.000Z",
			lastErrorClass: null, createdAt: "2030-01-01T00:00:00.000Z",
			updatedAt: "2030-01-01T00:00:00.000Z", deliveredAt: null, deadAt: null, cancelledAt: null,
		});
		expect(view.destination).toBe("[redacted]");
		expect(safeErrorClass("person@example.test rejected")).toBe("provider_error");
		expect(safeProviderValue("person@example.test rejected")).toBeNull();
		expect(safeProviderValue("https://provider.test/request/123")).toBeNull();
		expect(safeProviderValue("BearerTokenSecret123")).toBeNull();
		expect(safeProviderValue("aaaaaaa1.bbbbbbb2.ccccccc3")).toBeNull();
		expect(safeProviderValue("request_123-ABC")).toBe("request_123-ABC");
		expect(safeProviderValue("2.1.5", "status")).toBe("2.1.5");
		expect(safeProviderValue("250 accepted for /path", "status")).toBeNull();
	});
});
