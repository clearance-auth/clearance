import { describe, expect, it } from "vitest";
import { getAuthTables } from "../get-tables";

describe("getAuthTables", () => {
	it("should use correct field name for refreshTokenExpiresAt", () => {
		const tables = getAuthTables({
			account: {
				fields: {
					refreshTokenExpiresAt: "custom_refresh_token_expires_at",
				},
			},
		});

		const accountTable = tables.account;
		const refreshTokenExpiresAtField =
			accountTable!.fields.refreshTokenExpiresAt!;

		expect(refreshTokenExpiresAtField.fieldName).toBe(
			"custom_refresh_token_expires_at",
		);
	});

	it("should not use accessTokenExpiresAt field name for refreshTokenExpiresAt", () => {
		const tables = getAuthTables({
			account: {
				fields: {
					accessTokenExpiresAt: "custom_access_token_expires_at",
					refreshTokenExpiresAt: "custom_refresh_token_expires_at",
				},
			},
		});

		const accountTable = tables.account;
		const refreshTokenExpiresAtField =
			accountTable!.fields.refreshTokenExpiresAt!;
		const accessTokenExpiresAtField =
			accountTable!.fields.accessTokenExpiresAt!;

		expect(refreshTokenExpiresAtField.fieldName).toBe(
			"custom_refresh_token_expires_at",
		);
		expect(accessTokenExpiresAtField.fieldName).toBe(
			"custom_access_token_expires_at",
		);
		expect(refreshTokenExpiresAtField.fieldName).not.toBe(
			accessTokenExpiresAtField.fieldName,
		);
	});

	it("should use default field names when no custom names provided", () => {
		const tables = getAuthTables({});

		const accountTable = tables.account;
		const refreshTokenExpiresAtField =
			accountTable!.fields.refreshTokenExpiresAt!;
		const accessTokenExpiresAtField =
			accountTable!.fields.accessTokenExpiresAt!;

		expect(refreshTokenExpiresAtField.fieldName).toBe("refreshTokenExpiresAt");
		expect(accessTokenExpiresAtField.fieldName).toBe("accessTokenExpiresAt");
	});

	it("should merge additionalFields into verification table metadata", () => {
		const tables = getAuthTables({
			verification: {
				additionalFields: {
					newField: {
						fieldName: "new_field",
						type: "string",
					},
				},
			},
		});

		const verificationTable = tables.verification;
		const newField = verificationTable!.fields.newField!;

		console.log(newField);
		expect(newField).not.toBeUndefined();
		expect(newField.fieldName).toBe("new_field");
		expect(newField.type).toBe("string");
	});

	it("keeps runtime authentication assurance session fields authoritative", () => {
		const reserved = {
			authenticationAssuranceVersion: "number",
			authenticationPolicyProjectId: "string",
			authenticationPolicyEnvironmentId: "string",
			authenticationPrimaryMethod: "string",
			authenticationPrimaryAt: "date",
			authenticationFactorMethod: "string",
			authenticationFactorAt: "date",
			authenticationPolicyOrganizationId: "string",
			authenticationPolicyRevision: "string",
			authenticationAssuranceExpiresAt: "date",
			authenticationRecoveryRestricted: "boolean",
		} as const;
		const malicious = Object.fromEntries(
			Object.keys(reserved).map((key) => [
				key,
				{
					type: "json",
					required: true,
					input: true,
					returned: true,
					defaultValue: "attacker-controlled",
					fieldName: `attacker_${key}`,
				},
			]),
		);
		const tables = getAuthTables({
			session: { additionalFields: malicious as never },
			plugins: [
				{
					id: "malicious-session-schema",
					schema: { session: { fields: malicious as never } },
				},
			],
		});

		for (const [key, type] of Object.entries(reserved)) {
			const field = tables.session!.fields[key]!;
			expect(field.type).toBe(type);
			expect(field.required).toBe(false);
			expect(field.input).toBe(false);
			expect(field.returned).toBe(false);
			expect(field.defaultValue).toBeUndefined();
			expect(field.fieldName).toBeUndefined();
		}
	});

	it("keeps shared factor lifecycle generations authoritative with one factor plugin", () => {
		const tables = getAuthTables({
			plugins: [
				{
					id: "passkey",
					schema: {
						user: {
							fields: {
								passkeySessionGeneration: {
									type: "string",
									fieldName: "passkey_generation",
								},
							},
						},
						session: {
							fields: {
								passkeySessionGeneration: {
									type: "string",
									fieldName: "session_passkey_generation",
								},
							},
						},
					},
				},
			],
		});

		for (const model of ["user", "session"] as const) {
			const passkey = tables[model]!.fields.passkeySessionGeneration!;
			const twoFactor = tables[model]!.fields.twoFactorSessionGeneration!;
			expect(passkey).toMatchObject({
				type: "string",
				required: false,
				input: false,
				returned: false,
			});
			expect(twoFactor).toMatchObject({
				type: "string",
				required: false,
				input: false,
				returned: false,
			});
			expect(passkey.fieldName).toBe(
				model === "user"
					? "passkey_generation"
					: "session_passkey_generation",
			);
			expect(twoFactor.fieldName).toBeUndefined();
		}
	});

	it("rejects non-owner factor generation schema overrides", () => {
		const maliciousFields = {
			passkeySessionGeneration: {
				type: "json",
				required: true,
				input: true,
				returned: true,
				defaultValue: "attacker-controlled",
				fieldName: "attacker_passkey_generation",
			},
			twoFactorSessionGeneration: {
				type: "json",
				required: true,
				input: true,
				returned: true,
				defaultValue: "attacker-controlled",
				fieldName: "attacker_two_factor_generation",
			},
		} as const;
		const tables = getAuthTables({
			user: { additionalFields: maliciousFields },
			session: { additionalFields: maliciousFields },
			plugins: [
				{
					id: "passkey",
					schema: {
						user: {
							fields: {
								passkeySessionGeneration: {
									type: "string",
									fieldName: "owned_passkey_generation",
								},
							},
						},
						session: {
							fields: {
								passkeySessionGeneration: {
									type: "string",
									fieldName: "owned_session_passkey_generation",
								},
							},
						},
					},
				},
				{
					id: "two-factor",
					schema: {
						user: {
							fields: {
								twoFactorSessionGeneration: {
									type: "string",
									fieldName: "owned_two_factor_generation",
								},
							},
						},
						session: {
							fields: {
								twoFactorSessionGeneration: {
									type: "string",
									fieldName: "owned_session_two_factor_generation",
								},
							},
						},
					},
				},
				{
					id: "unrelated-malicious-plugin",
					schema: {
						user: { fields: maliciousFields },
						session: { fields: maliciousFields },
					},
				},
			],
		});

		for (const model of ["user", "session"] as const) {
			for (const field of [
				"passkeySessionGeneration",
				"twoFactorSessionGeneration",
			] as const) {
				const attributes = tables[model]!.fields[field]!;
				expect(attributes.type).toBe("string");
				expect(attributes.required).toBe(false);
				expect(attributes.input).toBe(false);
				expect(attributes.returned).toBe(false);
				expect(attributes.defaultValue).toBeUndefined();
			}
			expect(
				tables[model]!.fields.passkeySessionGeneration!.fieldName,
			).toBe(
				model === "user"
					? "owned_passkey_generation"
					: "owned_session_passkey_generation",
			);
			expect(
				tables[model]!.fields.twoFactorSessionGeneration!.fieldName,
			).toBe(
				model === "user"
					? "owned_two_factor_generation"
					: "owned_session_two_factor_generation",
			);
		}
	});

	it("keeps the first factor plugin authoritative when an ID is duplicated", () => {
		const tables = getAuthTables({
			plugins: [
				{
					id: "passkey",
					schema: {
						user: {
							fields: {
								passkeySessionGeneration: {
									type: "string",
									fieldName: "active_passkey_generation",
								},
							},
						},
					},
				},
				{
					id: "passkey",
					schema: {
						user: {
							fields: {
								passkeySessionGeneration: {
									type: "string",
									fieldName: "shadow_passkey_generation",
								},
							},
						},
					},
				},
			],
		});

		expect(
			tables.user!.fields.passkeySessionGeneration!.fieldName,
		).toBe("active_passkey_generation");
	});

	it("should exclude verification table when secondaryStorage is configured", () => {
		const tables = getAuthTables({
			secondaryStorage: {
				get: async () => null,
				set: async () => {},
				delete: async () => {},
			},
		});

		expect(tables.verification).toBeUndefined();
	});

	it("should include verification table when storeInDatabase is true", () => {
		const tables = getAuthTables({
			secondaryStorage: {
				get: async () => null,
				set: async () => {},
				delete: async () => {},
			},
			verification: {
				storeInDatabase: true,
			},
		});

		expect(tables.verification).toBeDefined();
	});

	it("should include verification table when no secondaryStorage", () => {
		const tables = getAuthTables({});

		expect(tables.verification).toBeDefined();
	});

	it("should propagate disableMigration from a plugin schema onto the table", () => {
		const tables = getAuthTables({
			plugins: [
				{
					id: "test",
					schema: {
						skipped: {
							fields: { name: { type: "string" } },
							disableMigration: true,
						},
						kept: {
							fields: { name: { type: "string" } },
						},
					},
				},
			],
		});

		expect(tables.skipped!.disableMigrations).toBe(true);
		expect(tables.kept!.disableMigrations).toBeUndefined();
	});

	it("should keep disableMigration when plugins accumulate the same table key", () => {
		const tables = getAuthTables({
			plugins: [
				{
					id: "a",
					schema: {
						shared: {
							fields: { a: { type: "string" } },
							disableMigration: true,
						},
					},
				},
				{
					id: "b",
					schema: {
						shared: {
							fields: { b: { type: "string" } },
						},
					},
				},
			],
		});

		expect(tables.shared!.disableMigrations).toBe(true);
	});

	/**
	 * @see https://github.com/clearance-auth/clearance
	 */
	describe("user.modelName collision with account schema key", () => {
		it("should point session.userId at the user table when user.modelName='account' and account.modelName='identity'", () => {
			const tables = getAuthTables({
				user: { modelName: "account" },
				account: { modelName: "identity" },
			});

			const sessionUserIdRef = tables.session!.fields.userId!.references;
			expect(sessionUserIdRef).toBeDefined();
			expect(tables[sessionUserIdRef!.model]).toBeDefined();
			expect(tables[sessionUserIdRef!.model]!.modelName).toBe("account");
			expect(tables[sessionUserIdRef!.model]!.fields.email).toBeDefined();
		});

		it("should point account.userId at the user table when user.modelName='account' and account.modelName='identity'", () => {
			const tables = getAuthTables({
				user: { modelName: "account" },
				account: { modelName: "identity" },
			});

			const accountUserIdRef = tables.account!.fields.userId!.references;
			expect(accountUserIdRef).toBeDefined();
			expect(tables[accountUserIdRef!.model]).toBeDefined();
			expect(tables[accountUserIdRef!.model]!.modelName).toBe("account");
			expect(tables[accountUserIdRef!.model]!.fields.email).toBeDefined();
		});
	});
});
