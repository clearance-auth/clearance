import type { ClearanceOptions } from "@clearance/core";
import {
	getCurrentAdapter,
	runWithTransaction,
} from "@clearance/core/context";
import type { DBAdapter } from "@clearance/core/db/adapter";
import {
	migrateLegacySessionCredentials,
	OAUTH_TOKEN_MIGRATION_ID,
	recordSecurityMigrationComplete,
	SESSION_CREDENTIAL_MIGRATION_ID,
} from "./session-credential-migration";

type SecurityMigrationMarker = {
	state: string;
};

export type CredentialAuthorityMigrationResult = {
	migrationIds: string[];
	oauthTokens?: {
		/** Rows migrated by this invocation; resumptions may have migrated earlier pages. */
		migratedThisInvocation: number;
		/** Rows revoked by this invocation; resumptions may have revoked earlier pages. */
		revokedThisInvocation: number;
	};
};

type CredentialAuthorityIndexAdapter = DBAdapter<any> & {
	ensureCredentialAuthorityIndexes?: () => Promise<void>;
};

function includesOAuthTokenAuthority(options: ClearanceOptions): boolean {
	return Boolean(
		options.plugins?.some(
			(plugin) => plugin.id === "oidc-provider" || plugin.id === "mcp",
		),
	);
}

async function isMigrationComplete(
	adapter: DBAdapter<any>,
	migrationId: string,
): Promise<boolean> {
	const marker = await adapter.findOne<SecurityMigrationMarker>({
		model: "securityMigration",
		where: [{ field: "key", value: migrationId }],
	});
	return marker?.state === "complete";
}

/**
 * Migrates every configured credential authority for adapter-backed runtimes.
 * This low-level helper is limited to ephemeral adapters. Durable credential
 * authorities require a database-native product fence and migration runner.
 */
export async function migrateCredentialAuthorities(
	adapter: DBAdapter<any>,
	options: ClearanceOptions,
): Promise<CredentialAuthorityMigrationResult> {
	if (adapter.id.includes("mongodb")) {
		const ensureIndexes = (adapter as CredentialAuthorityIndexAdapter)
			.ensureCredentialAuthorityIndexes;
		if (!ensureIndexes) {
			throw new Error(
				"MongoDB credential migrations require adapter-managed verified unique indexes before any bearer authority is changed",
			);
		}
		await ensureIndexes();
	}
	const migrationIds = [SESSION_CREDENTIAL_MIGRATION_ID];
	if (includesOAuthTokenAuthority(options)) {
		migrationIds.push(OAUTH_TOKEN_MIGRATION_ID);
	}
	const pendingMigrationIds = (
		await Promise.all(
			migrationIds.map(async (migrationId) => ({
				migrationId,
				complete: await isMigrationComplete(adapter, migrationId),
			})),
		)
	)
		.filter(({ complete }) => !complete)
		.map(({ migrationId }) => migrationId);
	if (pendingMigrationIds.length === 0) return { migrationIds: [] };

	const durable = adapter.storagePersistence !== "ephemeral";
	const existingAuthorityRows =
		(await adapter.count({ model: "session" })) +
		(includesOAuthTokenAuthority(options)
			? await adapter.count({ model: "oauthAccessToken" })
			: 0);
	if (durable && existingAuthorityRows > 0) {
		throw new Error(
			`Credential migrations ${pendingMigrationIds.join(", ")} refuse direct durable-adapter mutation; use the database-native product migration runner`,
		);
	}
	if (pendingMigrationIds.includes(SESSION_CREDENTIAL_MIGRATION_ID)) {
		await migrateLegacySessionCredentials(adapter, options);
	}

	let oauthTokens: { migrated: number; revoked: number } | undefined;
	if (pendingMigrationIds.includes(OAUTH_TOKEN_MIGRATION_ID)) {
		const { migrateOAuthTokenSecrets } = await import(
			"../plugins/oidc-provider"
		);
		oauthTokens = await migrateOAuthTokenSecrets(
			adapter,
			"oauthAccessToken",
			options,
		);
	}

	await runWithTransaction(adapter, async () => {
		const tx = await getCurrentAdapter(adapter);
		for (const migrationId of pendingMigrationIds) {
			await recordSecurityMigrationComplete(tx, migrationId, options);
		}
	});

	return {
		migrationIds: pendingMigrationIds,
		...(oauthTokens
			? {
					oauthTokens: {
						migratedThisInvocation: oauthTokens.migrated,
						revokedThisInvocation: oauthTokens.revoked,
					},
				}
			: {}),
	};
}
