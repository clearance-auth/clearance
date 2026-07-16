import { describe, expect, expectTypeOf, it } from "vitest";
import { twoFactor } from ".";

describe("two-factor effective plugin options", () => {
	it("publishes the storage defaults used by runtime recovery consumers", () => {
		const plugin = twoFactor();
		expectTypeOf(plugin.options.twoFactorTable).toEqualTypeOf<"twoFactor">();
		expectTypeOf(
			plugin.options.backupCodeOptions.storeBackupCodes,
		).toEqualTypeOf<"encrypted">();

		expect(plugin.options).toMatchObject({
			twoFactorTable: "twoFactor",
			backupCodeOptions: { storeBackupCodes: "encrypted" },
		});
	});

	it("publishes resolved caller overrides", () => {
		const plugin = twoFactor({
			twoFactorTable: "customTwoFactor",
			backupCodeOptions: {
				storeBackupCodes: "hashed",
				amount: 12,
			},
		});
		expectTypeOf(plugin.options.twoFactorTable).toEqualTypeOf<"customTwoFactor">();
		expectTypeOf(
			plugin.options.backupCodeOptions.storeBackupCodes,
		).toEqualTypeOf<"hashed">();
		expectTypeOf(plugin.options.backupCodeOptions.amount).toEqualTypeOf<12>();

		expect(plugin.options).toMatchObject({
			twoFactorTable: "customTwoFactor",
			backupCodeOptions: {
				storeBackupCodes: "hashed",
				amount: 12,
			},
		});
	});

	it("types and publishes nested storage defaults alongside caller literals", () => {
		const plugin = twoFactor({ backupCodeOptions: { amount: 12 } });

		expectTypeOf(plugin.options.twoFactorTable).toEqualTypeOf<"twoFactor">();
		expectTypeOf(
			plugin.options.backupCodeOptions.storeBackupCodes,
		).toEqualTypeOf<"encrypted">();
		expectTypeOf(plugin.options.backupCodeOptions.amount).toEqualTypeOf<12>();
		expect(plugin.options).toMatchObject({
			twoFactorTable: "twoFactor",
			backupCodeOptions: {
				storeBackupCodes: "encrypted",
				amount: 12,
			},
		});
	});
});
