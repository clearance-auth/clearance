import type { ClearanceOptions } from "../types";
import type { ClearanceDBSchema, DBFieldAttribute } from "./type";

export const getAuthTables = (
	options: ClearanceOptions,
): ClearanceDBSchema => {
	const usesSerialIds = options.advanced?.database?.generateId === "serial";
	const pluginSchema = (options.plugins ?? []).reduce(
		(acc, plugin) => {
			const schema = plugin.schema;
			if (!schema) return acc;
			for (const [key, value] of Object.entries(schema)) {
				acc[key] = {
					fields: {
						...acc[key]?.fields,
						...value.fields,
					},
					modelName: value.modelName || key,
					disableMigrations:
						value.disableMigration ?? acc[key]?.disableMigrations,
				};
			}
			return acc;
		},
		{} as Record<
			string,
			{
				fields: Record<string, DBFieldAttribute>;
				modelName: string;
				disableMigrations?: boolean | undefined;
			}
		>,
	);

	const shouldAddRateLimitTable = options.rateLimit?.storage === "database";
	const rateLimitTable = {
		rateLimit: {
			modelName: options.rateLimit?.modelName || "rateLimit",
			fields: {
				key: {
					type: "string",
					unique: true,
					required: true,
					fieldName: options.rateLimit?.fields?.key || "key",
				},
				count: {
					type: "number",
					required: true,
					fieldName: options.rateLimit?.fields?.count || "count",
				},
				lastRequest: {
					type: "number",
					bigint: true,
					required: true,
					fieldName: options.rateLimit?.fields?.lastRequest || "lastRequest",
					defaultValue: () => Date.now(),
				},
			},
		},
	} satisfies ClearanceDBSchema;

	const { user, session, account, verification, ...pluginTables } =
		pluginSchema;

	const verificationTable = {
		verification: {
			modelName: options.verification?.modelName || "verification",
			fields: {
				identifier: {
					type: "string",
					required: true,
					fieldName: options.verification?.fields?.identifier || "identifier",
					index: true,
				},
				value: {
					type: "string",
					required: true,
					fieldName: options.verification?.fields?.value || "value",
				},
				expiresAt: {
					type: "date",
					required: true,
					fieldName: options.verification?.fields?.expiresAt || "expiresAt",
				},
				createdAt: {
					type: "date",
					required: true,
					defaultValue: () => new Date(),
					fieldName: options.verification?.fields?.createdAt || "createdAt",
				},
				updatedAt: {
					type: "date",
					required: true,
					defaultValue: () => new Date(),
					onUpdate: () => new Date(),
					fieldName: options.verification?.fields?.updatedAt || "updatedAt",
				},
				...verification?.fields,
				...options.verification?.additionalFields,
			},
			order: 4,
		},
	} satisfies ClearanceDBSchema;

	const sessionTable = {
		session: {
			modelName: options.session?.modelName || "session",
			fields: {
				expiresAt: {
					type: "date",
					required: true,
					fieldName: options.session?.fields?.expiresAt || "expiresAt",
				},
				createdAt: {
					type: "date",
					required: true,
					fieldName: options.session?.fields?.createdAt || "createdAt",
					defaultValue: () => new Date(),
				},
				updatedAt: {
					type: "date",
					required: true,
					fieldName: options.session?.fields?.updatedAt || "updatedAt",
					onUpdate: () => new Date(),
				},
				ipAddress: {
					type: "string",
					required: false,
					fieldName: options.session?.fields?.ipAddress || "ipAddress",
				},
				userAgent: {
					type: "string",
					required: false,
					fieldName: options.session?.fields?.userAgent || "userAgent",
				},
				userId: {
					type: "string",
					fieldName: options.session?.fields?.userId || "userId",
					references: {
						// Use the canonical user schema key here rather than
						// `options.user.modelName`. Downstream consumers (e.g.
						// `getSchema`, `getMigrations`, and the runtime adapter
						// resolvers) treat `references.model` as a schema key
						// and look it up via `tables[references.model]` /
						// `getDefaultModelName`. Writing the modelName alias
						// here would collide when a user picks a modelName that
						// matches another schema key (for example
						// `user.modelName = "account"`), causing the FK to
						// resolve to the wrong table.
						// @see https://github.com/clearance-auth/clearance
						model: "user",
						field: "id",
						onDelete: "cascade",
					},
					required: true,
					index: true,
				},
				...session?.fields,
				...options.session?.additionalFields,
				// This authentication authority is reserved. Extensions cannot make
				// the presented bearer public or required in the session row.
				token: {
					...(session?.fields?.token ?? {}),
					...(options.session?.additionalFields?.token ?? {}),
					type: "string",
					required: false,
					returned: false,
					fieldName: options.session?.fields?.token || "token",
					unique: true,
				},
			},
			order: 2,
		},
	} satisfies ClearanceDBSchema;

	/**
	 * Authentication-issued session credentials are intentionally separate from
	 * the session record. The session row carries only a stable administrative
	 * handle; this ledger retains versioned digests (including consumed
	 * tombstones) so refresh rotation and ancestor-reuse detection do not require
	 * persisting replayable bearer material.
	 */
	const sessionCredentialTable = {
		sessionCredential: {
			modelName: "sessionCredential",
			fields: {
				selector: {
					type: "string",
					required: true,
					unique: true,
					returned: false,
				},
				sessionId: {
					type: usesSerialIds ? "number" : "string",
					required: false,
					index: true,
					references: {
						model: "session",
						field: "id",
						onDelete: "set null",
					},
				},
				familyId: {
					type: "string",
					required: true,
					index: true,
				},
				secretDigest: {
					type: "string",
					required: true,
					unique: true,
					returned: false,
				},
				digestVersion: {
					type: "number",
					required: true,
					defaultValue: 1,
				},
				status: {
					type: "string",
					required: true,
					index: true,
				},
				rotationCounter: {
					type: "number",
					required: true,
					defaultValue: 0,
				},
				parentCredentialId: {
					type: usesSerialIds ? "number" : "string",
					required: false,
					unique: true,
					references: {
						model: "sessionCredential",
						field: "id",
						onDelete: "set null",
					},
				},
				expiresAt: {
					type: "date",
					required: true,
					index: true,
				},
				consumedAt: {
					type: "date",
					required: false,
				},
				revokedAt: {
					type: "date",
					required: false,
				},
				reuseDetectedAt: {
					type: "date",
					required: false,
				},
				rotationNonceDigest: {
					type: "string",
					required: false,
					returned: false,
				},
				recoverySecretCiphertext: {
					type: "string",
					required: false,
					returned: false,
				},
				recoveryExpiresAt: {
					type: "date",
					required: false,
				},
				createdAt: {
					type: "date",
					required: true,
					defaultValue: () => new Date(),
				},
				updatedAt: {
					type: "date",
					required: true,
					defaultValue: () => new Date(),
					onUpdate: () => new Date(),
				},
			},
			order: 3,
		},
	} satisfies ClearanceDBSchema;

	const securityMigrationTable = {
		securityMigration: {
			modelName: "securityMigration",
			fields: {
				key: {
					type: "string",
					required: true,
					unique: true,
				},
				state: {
					type: "string",
					required: true,
				},
				phase: {
					type: "string",
					required: false,
				},
				cursor: {
					type: "string",
					required: false,
				},
				revision: {
					type: "number",
					required: false,
				},
				completedAt: {
					type: "date",
					required: true,
				},
				createdAt: {
					type: "date",
					required: true,
					defaultValue: () => new Date(),
				},
				updatedAt: {
					type: "date",
					required: true,
					defaultValue: () => new Date(),
					onUpdate: () => new Date(),
				},
			},
			order: 5,
		},
	} satisfies ClearanceDBSchema;

	/**
	 * Durable deployment authority for bearer-credential migrations. Runtime
	 * processes hold PostgreSQL shared advisory leases while serving; the
	 * migrator owns the exclusive form while this row advances through drain,
	 * migration, and digest publication. Keeping this state separate from the
	 * completed-migration ledger makes interrupted cutovers resumable without
	 * weakening the serving-generation check.
	 */
	const credentialAuthorityFenceTable = {
		credentialAuthorityFence: {
			modelName: "credentialAuthorityFence",
			fields: {
				protocolVersion: {
					type: "number",
					required: true,
					defaultValue: 1,
				},
				phase: {
					type: "string",
					required: true,
				},
				generation: {
					type: "string",
					required: true,
				},
				drainId: {
					type: "string",
					required: false,
				},
				bridgeDeploymentId: {
					type: "string",
					required: false,
				},
				expectedRuntimeCount: {
					type: "number",
					required: false,
				},
				revision: {
					type: "number",
					bigint: true,
					required: true,
					defaultValue: 0,
				},
				drainStartedAt: {
					type: "date",
					required: false,
				},
				drainedAt: {
					type: "date",
					required: false,
				},
				publishedAt: {
					type: "date",
					required: false,
				},
				createdAt: {
					type: "date",
					required: true,
					defaultValue: () => new Date(),
				},
				updatedAt: {
					type: "date",
					required: true,
					defaultValue: () => new Date(),
					onUpdate: () => new Date(),
				},
			},
			order: 6,
		},
	} satisfies ClearanceDBSchema;

	return {
		user: {
			modelName: options.user?.modelName || "user",
			fields: {
				name: {
					type: "string",
					required: true,
					fieldName: options.user?.fields?.name || "name",
					sortable: true,
				},
				email: {
					type: "string",
					// TODO(#9124): drop required+unique in v2; use a partial unique
					// index where email is not null (see schema/user.ts).
					unique: true,
					required: true,
					fieldName: options.user?.fields?.email || "email",
					sortable: true,
				},
				emailVerified: {
					type: "boolean",
					defaultValue: false,
					required: true,
					fieldName: options.user?.fields?.emailVerified || "emailVerified",
					input: false,
				},
				image: {
					type: "string",
					required: false,
					fieldName: options.user?.fields?.image || "image",
				},
				createdAt: {
					type: "date",
					defaultValue: () => new Date(),
					required: true,
					fieldName: options.user?.fields?.createdAt || "createdAt",
				},
				updatedAt: {
					type: "date",
					defaultValue: () => new Date(),
					onUpdate: () => new Date(),
					required: true,
					fieldName: options.user?.fields?.updatedAt || "updatedAt",
				},
				...user?.fields,
				...options.user?.additionalFields,
			},
			order: 1,
		},
		//only add session table if it's not stored in secondary storage
		...(!options.secondaryStorage || options.session?.storeSessionInDatabase
			? { ...sessionTable, ...sessionCredentialTable }
			: {}),
		account: {
			modelName: options.account?.modelName || "account",
			fields: {
				accountId: {
					type: "string",
					required: true,
					fieldName: options.account?.fields?.accountId || "accountId",
				},
				providerId: {
					type: "string",
					required: true,
					fieldName: options.account?.fields?.providerId || "providerId",
				},
				userId: {
					type: "string",
					references: {
						// See note on `session.userId.references.model` above:
						// always use the canonical user schema key so the FK
						// target survives `user.modelName` aliasing.
						// @see https://github.com/clearance-auth/clearance
						model: "user",
						field: "id",
						onDelete: "cascade",
					},
					required: true,
					fieldName: options.account?.fields?.userId || "userId",
					index: true,
				},
				accessToken: {
					type: "string",
					required: false,
					returned: false,
					fieldName: options.account?.fields?.accessToken || "accessToken",
				},
				refreshToken: {
					type: "string",
					required: false,
					returned: false,
					fieldName: options.account?.fields?.refreshToken || "refreshToken",
				},
				idToken: {
					type: "string",
					required: false,
					returned: false,
					fieldName: options.account?.fields?.idToken || "idToken",
				},
				accessTokenExpiresAt: {
					type: "date",
					required: false,
					returned: false,
					fieldName:
						options.account?.fields?.accessTokenExpiresAt ||
						"accessTokenExpiresAt",
				},
				refreshTokenExpiresAt: {
					type: "date",
					required: false,
					returned: false,
					fieldName:
						options.account?.fields?.refreshTokenExpiresAt ||
						"refreshTokenExpiresAt",
				},
				scope: {
					type: "string",
					required: false,
					fieldName: options.account?.fields?.scope || "scope",
				},
				password: {
					type: "string",
					required: false,
					returned: false,
					fieldName: options.account?.fields?.password || "password",
				},
				createdAt: {
					type: "date",
					required: true,
					fieldName: options.account?.fields?.createdAt || "createdAt",
					defaultValue: () => new Date(),
				},
				updatedAt: {
					type: "date",
					required: true,
					fieldName: options.account?.fields?.updatedAt || "updatedAt",
					onUpdate: () => new Date(),
				},
				...account?.fields,
				...options.account?.additionalFields,
			},
			order: 4,
		},
		...(!options.secondaryStorage || options.verification?.storeInDatabase
			? verificationTable
			: {}),
		...pluginTables,
		// This migration ledger is reserved so plugins cannot replace the
		// fail-closed authentication compatibility authority.
		...securityMigrationTable,
		// Deployment generation is likewise reserved and cannot be replaced by a
		// plugin schema.
		...credentialAuthorityFenceTable,
		...(shouldAddRateLimitTable ? rateLimitTable : {}),
	} satisfies ClearanceDBSchema;
};
