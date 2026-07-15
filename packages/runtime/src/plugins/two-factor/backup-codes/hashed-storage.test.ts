import { describe, expect, it } from "vitest";
import { symmetricEncrypt } from "../../../crypto";
import { DEFAULT_SECRET } from "../../../utils/constants";
import {
	encodeBackupCodes,
	generateBackupCodes,
	getBackupCodes,
	isOneWayBackupCodeEnvelope,
	verifyBackupCode,
} from ".";

describe("one-way recovery-code storage", () => {
	it("stores no recoverable codes and consumes one digest at a time", async () => {
		const options = {
			storeBackupCodes: "hashed" as const,
			customBackupCodesGenerate: () => ["alpha-11111", "bravo-22222"],
		};
		const generated = await generateBackupCodes(DEFAULT_SECRET, options);

		expect(generated.encryptedBackupCodes).toMatch(/^clr-recovery:v1:/);
		expect(generated.encryptedBackupCodes).not.toContain("alpha-11111");
		expect(generated.encryptedBackupCodes).not.toContain("bravo-22222");
		await expect(
			getBackupCodes(generated.encryptedBackupCodes, DEFAULT_SECRET, options),
		).resolves.toBeNull();

		const first = await verifyBackupCode(
			{
				backupCodes: generated.encryptedBackupCodes,
				code: "alpha-11111",
			},
			DEFAULT_SECRET,
			options,
		);
		expect(first.status).toBe(true);
		expect(first.updated).toMatch(/^clr-recovery:v1:/);
		expect(first.updated).not.toContain("alpha-11111");

		const replay = await verifyBackupCode(
			{ backupCodes: first.updated!, code: "alpha-11111" },
			DEFAULT_SECRET,
			options,
		);
		expect(replay.status).toBe(false);

		const second = await verifyBackupCode(
			{ backupCodes: first.updated!, code: "bravo-22222" },
			DEFAULT_SECRET,
			options,
		);
		expect(second.status).toBe(true);
	});

	it("rejects malformed envelopes and ambiguous generated codes", async () => {
		expect(isOneWayBackupCodeEnvelope("clr-recovery:v1:not-json")).toBe(false);
		await expect(
			encodeBackupCodes(["duplicate", "duplicate"], DEFAULT_SECRET, {
				storeBackupCodes: "hashed",
			}),
		).rejects.toThrow("unique non-empty values");
		await expect(
			generateBackupCodes(DEFAULT_SECRET, {
				storeBackupCodes: "hashed",
				customBackupCodesGenerate: () => [],
			}),
		).rejects.toThrow("At least one recovery code");
	});

	it("upgrades legacy plaintext and encrypted rows after successful use", async () => {
		const options = { storeBackupCodes: "hashed" as const };
		for (const legacy of [
			JSON.stringify(["legacy-code", "remaining-code"]),
			await symmetricEncrypt({
				key: DEFAULT_SECRET,
				data: JSON.stringify(["legacy-code", "remaining-code"]),
			}),
		]) {
			const verified = await verifyBackupCode(
				{ backupCodes: legacy, code: "legacy-code" },
				DEFAULT_SECRET,
				options,
			);
			expect(verified.status).toBe(true);
			expect(verified.updated).toMatch(/^clr-recovery:v1:/);
			const remaining = await verifyBackupCode(
				{ backupCodes: verified.updated!, code: "remaining-code" },
				DEFAULT_SECRET,
				options,
			);
			expect(remaining.status).toBe(true);
		}
	});

	it("fails closed when an envelope pepper cannot be decrypted", async () => {
		const options = {
			storeBackupCodes: "hashed" as const,
			customBackupCodesGenerate: () => ["valid-code"],
		};
		const generated = await generateBackupCodes(DEFAULT_SECRET, options);
		const prefix = "clr-recovery:v1:";
		const envelope = JSON.parse(
			generated.encryptedBackupCodes.slice(prefix.length),
		) as { encryptedPepper: string };
		envelope.encryptedPepper = "corrupt-ciphertext";
		const corrupt = `${prefix}${JSON.stringify(envelope)}`;
		expect(isOneWayBackupCodeEnvelope(corrupt)).toBe(true);
		await expect(
			verifyBackupCode(
				{ backupCodes: corrupt, code: "valid-code" },
				DEFAULT_SECRET,
				options,
			),
		).resolves.toEqual({ status: false, updated: null });
	});
});
