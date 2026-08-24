import {
	BACKUP_OPERATIONS,
	ClearanceError,
	IMPORT_OPERATIONS,
	MIGRATION_OPERATIONS,
	SCHEMA_OPERATIONS,
	STORE_V2_OPERATIONS,
	UPGRADE_OPERATIONS,
	applyUpgrade,
	applyStoreV2,
	armCredentialAuthority,
	cutoverStoreV2Events,
	cutoverStoreV2Principals,
	cutoverStoreV2Topology,
	createBackup,
	createPostgresBackup,
	drainCredentialAuthority,
	getCredentialAuthorityStatus,
	getRuntimeSchemaStatus,
	getStoreV2Status,
	migrateRuntimeSchema,
	migrationStatus,
	parseLegacyFixture,
	planMigrationDurable,
	planRuntimeSchema,
	planStoreV2,
	planUpgrade,
	previewMigrationDurable,
	restoreBackup,
	restorePostgresBackup,
	rollbackMigrationDurable,
	rollbackUpgrade,
	rollbackStoreV2,
	rollbackStoreV2Events,
	rollbackStoreV2Principals,
	rollbackStoreV2Topology,
	applyMigrationDurable,
	upgradeCheck,
	upgradeCheckWithDb,
	verifyBackup,
	verifyMigrationDurable,
	verifyPostgresBackup,
	verifyUpgrade,
	verifyStoreV2,
} from "@clearance/management";
import { Hono } from "hono";
import type { BaseRouteDependencies } from "./shared.js";

export interface BackupConfiguration {
	configuredDirectory: string | undefined;
	production: boolean;
}

export interface UpgradeConfiguration {
	configuredDirectory: string | undefined;
	configuredHealthUrl: string | undefined;
}

export interface OperationRouteDependencies extends BaseRouteDependencies {
	runtimeDatabaseConfigured(): boolean;
	backupConfiguration(): BackupConfiguration;
	upgradeConfiguration(): UpgradeConfiguration;
}

export function registerOperationRoutes({
	storeForRequest,
	handleError,
	runtimeDatabaseConfigured,
	backupConfiguration,
	upgradeConfiguration,
}: OperationRouteDependencies) {
	const routes = new Hono();

	// Remote callers select logical plans only; network and filesystem sinks stay deployment-owned.
	function serverUpgradeOptions(body: Record<string, unknown>, stage: string) {
		if (body.dir !== undefined || body.backupDir !== undefined) {
			throw new ClearanceError({
				code: "UPGRADE_DIRECTORY_SERVER_MANAGED",
				message: "Upgrade storage is configured by the API deployment",
				stage,
				status: 400,
				remediation: "Omit filesystem directories; set CLEARANCE_UPGRADE_DIR on the API deployment.",
			});
		}
		if (body.healthUrl !== undefined) {
			throw new ClearanceError({
				code: "UPGRADE_HEALTH_URL_SERVER_MANAGED",
				message: "Upgrade health verification is configured by the API deployment",
				stage,
				status: 400,
				remediation: "Omit healthUrl; set CLEARANCE_UPGRADE_HEALTH_URL on the API deployment.",
			});
		}
		const configuration = upgradeConfiguration();
		if (!configuration.configuredDirectory) {
			throw new ClearanceError({
				code: "UPGRADE_DIRECTORY_NOT_CONFIGURED",
				message: "The API upgrade directory is not configured",
				stage,
				status: 503,
				remediation: "Set CLEARANCE_UPGRADE_DIR and mount durable upgrade storage before retrying.",
			});
		}
		return {
			dir: configuration.configuredDirectory,
			healthUrl: configuration.configuredHealthUrl,
		};
	}

	routes.post(BACKUP_OPERATIONS.create.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			if (body.dir !== undefined) {
				throw new ClearanceError({
					code: "BACKUP_DIRECTORY_SERVER_MANAGED",
					message: "Backup storage is configured by the API deployment",
					stage: "backup.create",
					status: 400,
					remediation: "Set CLEARANCE_BACKUP_DIR on the API and mount durable storage there.",
				});
			}
			const { configuredDirectory, production } = backupConfiguration();
			if (production && !configuredDirectory) {
				throw new ClearanceError({
					code: "BACKUP_DIRECTORY_NOT_CONFIGURED",
					message: "The API backup directory is not configured",
					stage: "backup.create",
					status: 503,
					remediation: "Set CLEARANCE_BACKUP_DIR and mount durable backup storage before retrying.",
				});
			}
			const backup = runtimeDatabaseConfigured()
				? createPostgresBackup(store, configuredDirectory || undefined)
				: createBackup(store, configuredDirectory || undefined);
			await store.ready();
			return c.json({ backup }, 201);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(BACKUP_OPERATIONS.verify.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const backup = runtimeDatabaseConfigured()
				? await verifyPostgresBackup(store, c.req.param("id"))
				: verifyBackup(store, c.req.param("id"));
			await store.ready();
			return c.json({ backup });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(BACKUP_OPERATIONS.restore.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			if (body.confirm !== true) {
				throw new ClearanceError({
					code: "BACKUP_RESTORE_CONFIRM_REQUIRED",
					message: "Backup restore requires explicit confirmation",
					stage: "backup.restore",
					status: 400,
					remediation: "Verify the backup first, then send confirm as true.",
				});
			}
			const target = typeof body.target === "string" ? body.target : undefined;
			if (!runtimeDatabaseConfigured() && target !== undefined) {
				throw new ClearanceError({
					code: "BACKUP_RESTORE_TARGET_SERVER_MANAGED",
					message: "The API chooses the isolated file restore destination",
					stage: "backup.restore",
					status: 400,
					remediation: "Omit target; the API will restore into its server-owned backup storage.",
				});
			}
			let result:
				| Awaited<ReturnType<typeof restorePostgresBackup>>
				| ReturnType<typeof restoreBackup>;
			if (runtimeDatabaseConfigured()) {
				result = await restorePostgresBackup(store, c.req.param("id"), target);
			} else {
				result = restoreBackup(store, c.req.param("id"));
			}
			await store.ready();
			return c.json(result);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(UPGRADE_OPERATIONS.check.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const result = runtimeDatabaseConfigured()
				? await upgradeCheckWithDb(store)
				: upgradeCheck(store);
			await store.ready();
			return c.json(result);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(UPGRADE_OPERATIONS.plan.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const upgrade = serverUpgradeOptions(body, "upgrade.plan");
			return c.json(await planUpgrade({
				target: typeof body.target === "string" ? body.target : undefined,
				dir: upgrade.dir,
				current: typeof body.current === "string" ? body.current : undefined,
				dryRun: body.dryRun === true,
			}));
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(UPGRADE_OPERATIONS.apply.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const upgrade = serverUpgradeOptions(body, "upgrade.apply");
			return c.json(await applyUpgrade({
				store,
				plan: typeof body.plan === "string" ? body.plan : undefined,
				dir: upgrade.dir,
				dryRun: body.dryRun === true,
				yes: body.confirm === true,
			}));
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(UPGRADE_OPERATIONS.verify.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const upgrade = serverUpgradeOptions(body, "upgrade.verify");
			return c.json(await verifyUpgrade({
				plan: typeof body.plan === "string" ? body.plan : undefined,
				dir: upgrade.dir,
				healthUrl: upgrade.healthUrl,
				dryRun: body.dryRun === true,
			}));
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(UPGRADE_OPERATIONS.rollback.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const upgrade = serverUpgradeOptions(body, "upgrade.rollback");
			return c.json(await rollbackUpgrade({
				store,
				plan: typeof body.plan === "string" ? body.plan : undefined,
				dir: upgrade.dir,
				dryRun: body.dryRun === true,
				yes: body.confirm === true,
				restoreActive: body.restoreActive === true,
				confirm: typeof body.activeDatabaseConfirmation === "string"
					? body.activeDatabaseConfirmation
					: undefined,
			}));
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(SCHEMA_OPERATIONS.status.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			return c.json({
				management: {
					schemaVersion: store.snapshot.meta.schemaVersion,
					releaseVersion: store.snapshot.releaseVersion,
					initializedAt: store.snapshot.meta.initializedAt,
				},
				runtime: await getRuntimeSchemaStatus(),
			});
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SCHEMA_OPERATIONS.generate.http.path, async (c) => {
		try {
			const plan = await planRuntimeSchema("schema.generate");
			return c.json({ kind: "schema.generate", ...plan });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(SCHEMA_OPERATIONS.migrate.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const dryRun = body.dryRun === true;
			if (!dryRun && body.confirm !== true) {
				throw new ClearanceError({
					code: "SCHEMA_MIGRATE_CONFIRMATION_REQUIRED",
					message: "Schema migration requires explicit confirmation",
					stage: "schema.migrate",
					status: 400,
					remediation: "Review a dry run, then send confirm as true.",
				});
			}
			return c.json(await migrateRuntimeSchema({ dryRun }));
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(
		SCHEMA_OPERATIONS.credentialAuthorityStatus.http.path,
		async (c) => {
			try {
				return c.json(await getCredentialAuthorityStatus());
			} catch (error) {
				return handleError(c, error);
			}
		},
	);

	routes.post(
		SCHEMA_OPERATIONS.credentialAuthorityArm.http.path,
		async (c) => {
			try {
				const body = (await c.req.json().catch(() => ({}))) as Record<
					string,
					unknown
				>;
				if (body.confirm !== true) {
					throw new ClearanceError({
						code: "CREDENTIAL_AUTHORITY_ARM_CONFIRMATION_REQUIRED",
						message: "Credential authority arm requires explicit confirmation",
						stage: "schema.credential-authority.arm",
						status: 400,
						remediation: "Verify the candidate rollout, then send confirm as true.",
					});
				}
				if (
					typeof body.deploymentId !== "string" ||
					body.deploymentId.trim().length === 0 ||
					body.deploymentId.length > 200 ||
					typeof body.expectedRuntimeCount !== "number" ||
					!Number.isSafeInteger(body.expectedRuntimeCount) ||
					body.expectedRuntimeCount < 1 ||
					body.expectedRuntimeCount > 10_000
				) {
					throw new ClearanceError({
						code: "CREDENTIAL_AUTHORITY_ARM_INPUT_INVALID",
						message: "Credential authority arm input is invalid",
						stage: "schema.credential-authority.arm",
						status: 400,
						remediation:
							"Send a non-empty deploymentId up to 200 characters and expectedRuntimeCount as an integer from 1 through 10000.",
					});
				}
				return c.json(
					await armCredentialAuthority({
						deploymentId: body.deploymentId.trim(),
						expectedRuntimeCount: body.expectedRuntimeCount,
					}),
				);
			} catch (error) {
				return handleError(c, error);
			}
		},
	);

	routes.post(
		SCHEMA_OPERATIONS.credentialAuthorityDrain.http.path,
		async (c) => {
			try {
				const body = (await c.req.json().catch(() => ({}))) as Record<
					string,
					unknown
				>;
				if (body.confirm !== true) {
					throw new ClearanceError({
						code: "CREDENTIAL_AUTHORITY_DRAIN_CONFIRMATION_REQUIRED",
						message: "Credential authority drain requires explicit confirmation",
						stage: "schema.credential-authority.drain",
						status: 400,
						remediation: "Verify the armed rollout, then send confirm as true.",
					});
				}
				if (
					typeof body.deploymentId !== "string" ||
					body.deploymentId.trim().length === 0 ||
					body.deploymentId.length > 200 ||
					typeof body.drainId !== "string" ||
					body.drainId.trim().length === 0 ||
					body.drainId.length > 200
				) {
					throw new ClearanceError({
						code: "CREDENTIAL_AUTHORITY_DRAIN_INPUT_INVALID",
						message: "Credential authority drain input is invalid",
						stage: "schema.credential-authority.drain",
						status: 400,
						remediation:
							"Send non-empty deploymentId and drainId values up to 200 characters.",
					});
				}
				return c.json(
					await drainCredentialAuthority({
						deploymentId: body.deploymentId.trim(),
						drainId: body.drainId.trim(),
					}),
				);
			} catch (error) {
				return handleError(c, error);
			}
		},
	);

	routes.get(STORE_V2_OPERATIONS.status.http.path, async (c) => {
		try {
			return c.json(await getStoreV2Status(await storeForRequest()));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.get(STORE_V2_OPERATIONS.plan.http.path, async (c) => {
		try {
			return c.json(await planStoreV2(await storeForRequest()));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(STORE_V2_OPERATIONS.apply.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await applyStoreV2(await storeForRequest(), {
				dryRun: body.dryRun === true,
				confirm: body.confirm === true,
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.get(STORE_V2_OPERATIONS.verify.http.path, async (c) => {
		try {
			return c.json(await verifyStoreV2(await storeForRequest()));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(STORE_V2_OPERATIONS.rollback.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await rollbackStoreV2(await storeForRequest(), {
				confirm: body.confirm === true,
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(STORE_V2_OPERATIONS.eventsCutover.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await cutoverStoreV2Events(await storeForRequest(), {
				confirm: body.confirm === true,
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(STORE_V2_OPERATIONS.eventsRollback.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await rollbackStoreV2Events(await storeForRequest(), {
				confirm: body.confirm === true,
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(STORE_V2_OPERATIONS.principalsCutover.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await cutoverStoreV2Principals(await storeForRequest(), {
				confirm: body.confirm === true,
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(STORE_V2_OPERATIONS.principalsRollback.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await rollbackStoreV2Principals(await storeForRequest(), {
				confirm: body.confirm === true,
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(STORE_V2_OPERATIONS.topologyCutover.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await cutoverStoreV2Topology(await storeForRequest(), {
				confirm: body.confirm === true,
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	routes.post(STORE_V2_OPERATIONS.topologyRollback.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await rollbackStoreV2Topology(await storeForRequest(), {
				confirm: body.confirm === true,
			}));
		} catch (error) {
			return handleError(c, error);
		}
	});

	function migrationFixture(body: Record<string, unknown>) {
		if (!("fixture" in body)) {
			throw new ClearanceError({
				code: "CLEARANCE_IMPORT_FIXTURE_REQUIRED",
				message: "A legacy migration fixture is required",
				stage: "import.legacy.fixture",
				status: 400,
				remediation: "Send the validated fixture in the authenticated request body.",
			});
		}
		return parseLegacyFixture(body.fixture);
	}

	routes.post(IMPORT_OPERATIONS.legacy.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const fixture = migrationFixture(body);
			const preview = await previewMigrationDurable(store, fixture);
			if (body.dryRun === true || body.confirm !== true) {
				return c.json({
					schemaVersion: "v1",
					dryRun: true,
					source: "legacy",
					preview,
					storeBackend: store.backend,
				});
			}
			const planned = await planMigrationDurable(store, fixture);
			await store.ready();
			await store.refresh();
			await applyMigrationDurable(store, planned.id, fixture);
			const verification = await verifyMigrationDurable(store, planned.id, fixture);
			await store.ready();
			return c.json({
				schemaVersion: "v1",
				dryRun: false,
				source: "legacy",
				migration: verification.plan,
				preview,
				verification: {
					reconciled: verification.reconciled,
					expected: verification.expected,
					actual: verification.actual,
				},
				storeBackend: store.backend,
			});
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(MIGRATION_OPERATIONS.plan.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			if (body.source !== "legacy") {
				throw new ClearanceError({
					code: "CLEARANCE_IMPORT_SOURCE_INVALID",
					message: "Only legacy imports are supported",
					stage: "migration.plan",
					status: 400,
					remediation: "Send source as legacy.",
				});
			}
			const plan = await planMigrationDurable(store, migrationFixture(body));
			await store.ready();
			return c.json({ plan });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(MIGRATION_OPERATIONS.apply.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const plan = await applyMigrationDurable(store, c.req.param("id"), migrationFixture(body), {
				dryRun: body.dryRun === true,
			});
			await store.ready();
			return c.json({ plan });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(MIGRATION_OPERATIONS.verify.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const result = await verifyMigrationDurable(store, c.req.param("id"), migrationFixture(body));
			await store.ready();
			return c.json(result);
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(MIGRATION_OPERATIONS.rollback.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			if (body.confirm !== true) {
				throw new ClearanceError({
					code: "MIGRATION_ROLLBACK_CONFIRM_REQUIRED",
					message: "Migration rollback requires explicit confirmation",
					stage: "migration.rollback",
					status: 400,
					remediation: "Review the plan, then send confirm as true.",
				});
			}
			const plan = await rollbackMigrationDurable(store, c.req.param("id"), migrationFixture(body));
			await store.ready();
			return c.json({ plan });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.get(MIGRATION_OPERATIONS.status.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			return c.json({ plan: migrationStatus(store, c.req.param("id")) });
		} catch (e) {
			return handleError(c, e);
		}
	});

	return routes;
}
