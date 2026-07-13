import type { ClearancePluginDBSchema } from "@clearance/core/db";

export const schema = {
	user: {
		fields: {
			isAnonymous: {
				type: "boolean",
				required: false,
				input: false,
				defaultValue: false,
			},
		},
	},
} satisfies ClearancePluginDBSchema;
