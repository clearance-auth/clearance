import type { ClearancePluginDBSchema } from "@clearance/core/db";

/**
 * `passkeyUserHandle` is the stable, random WebAuthn user handle bound to the
 * account. It is never the raw user id: exposing the primary key as the
 * WebAuthn `user.id` would let a relying-party-adjacent observer correlate
 * credentials across services that share an id space.
 */
export const schema = {
	user: {
		fields: {
			passkeySessionGeneration: {
				type: "string",
				required: false,
				input: false,
				returned: false,
			},
			passkeyUserHandle: {
				type: "string",
				required: false,
				input: false,
				returned: false,
				unique: true,
			},
		},
	},
	session: {
		fields: {
			passkeySessionGeneration: {
				type: "string",
				required: false,
				input: false,
				returned: false,
			},
		},
	},
	passkey: {
		fields: {
			userId: {
				type: "string",
				required: true,
				returned: false,
				input: false,
				index: true,
				references: {
					model: "user",
					field: "id",
				},
			},
			name: {
				type: "string",
				required: false,
			},
			credentialID: {
				type: "string",
				required: true,
				returned: false,
				input: false,
				unique: true,
			},
			publicKey: {
				type: "string",
				required: true,
				returned: false,
				input: false,
			},
			userHandle: {
				type: "string",
				required: true,
				returned: false,
				input: false,
			},
			counter: {
				type: "number",
				required: true,
				returned: false,
				input: false,
			},
			deviceType: {
				type: "string",
				required: true,
				input: false,
			},
			backedUp: {
				type: "boolean",
				required: true,
				input: false,
			},
			transports: {
				type: "string",
				required: false,
				input: false,
				returned: false,
			},
			aaguid: {
				type: "string",
				required: false,
				input: false,
				returned: false,
			},
			createdAt: {
				type: "date",
				required: true,
				input: false,
			},
			updatedAt: {
				type: "date",
				required: true,
				input: false,
				onUpdate: () => new Date(),
			},
		},
	},
	/**
	 * `passkeyChallenge` is the plugin-owned, primary-database, single-use
	 * challenge store for both registration and authentication ceremonies. It
	 * intentionally does not reuse core's `verification` model or any
	 * secondary storage configuration: passkeys require the row to live in
	 * the same durable primary database the credential itself is verified
	 * against, and to be consumed with the primary adapter's atomic
	 * `consumeOne`.
	 *
	 * `digestId` -- never the raw challenge -- is the unique lookup key. The
	 * raw challenge is intentionally never persisted. The assertion's
	 * clientDataJSON supplies it at verification time and the digest lookup
	 * proves that exact challenge was issued.
	 */
	passkeyChallenge: {
		fields: {
			digestId: {
				type: "string",
				required: true,
				returned: false,
				input: false,
				unique: true,
			},
			ceremony: {
				type: "string",
				required: true,
				returned: false,
				input: false,
			},
			rpID: {
				type: "string",
				required: true,
				returned: false,
				input: false,
			},
			origin: {
				type: "string",
				required: true,
				returned: false,
				input: false,
			},
			userId: {
				type: "string",
				required: false,
				returned: false,
				input: false,
			},
			userHandle: {
				type: "string",
				required: false,
				returned: false,
				input: false,
			},
			expiresAt: {
				type: "date",
				required: true,
				returned: false,
				input: false,
				index: true,
			},
			createdAt: {
				type: "date",
				required: true,
				returned: false,
				input: false,
			},
			updatedAt: {
				type: "date",
				required: true,
				returned: false,
				input: false,
				onUpdate: () => new Date(),
			},
		},
	},
} satisfies ClearancePluginDBSchema;
