import type { ClearancePluginDBSchema } from "@clearance/core/db";

export const schema = {
	user: {
		fields: {
			twoFactorEnabled: {
				type: "boolean",
				required: false,
				defaultValue: false,
				input: false,
			},
		},
	},
	twoFactor: {
		fields: {
			secret: {
				type: "string",
				required: true,
				returned: false,
				index: true,
			},
			backupCodes: {
				type: "string",
				required: true,
				returned: false,
			},
			pendingSecret: {
				type: "string",
				required: false,
				returned: false,
			},
			pendingBackupCodes: {
				type: "string",
				required: false,
				returned: false,
			},
			userId: {
				type: "string",
				required: true,
				returned: false,
				references: {
					model: "user",
					field: "id",
				},
				unique: true,
			},
			verified: {
				type: "boolean",
				required: false,
				// defaults to true so existing rows are treated as verified during migration.
				// new rows from enableTwoFactor explicitly set this to false.
				defaultValue: true,
				input: false,
			},
			failedVerificationCount: {
				type: "number",
				required: false,
				defaultValue: 0,
				input: false,
				returned: false,
			},
			lockedUntil: {
				type: "date",
				required: false,
				input: false,
				returned: false,
			},
			lastUsedTotpCounter: {
				type: "number",
				required: false,
				defaultValue: -1,
				input: false,
				returned: false,
			},
		},
	},
} satisfies ClearancePluginDBSchema;
