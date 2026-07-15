import {
	BACKUP_OPERATIONS,
	ClearanceError,
	IMPORT_OPERATIONS,
	MIGRATION_OPERATIONS,
	SCHEMA_OPERATIONS,
	UPGRADE_OPERATIONS,
	applyUpgrade,
	createBackup,
	createPostgresBackup,
	getRuntimeSchemaStatus,
	migrateRuntimeSchema,
	migrationStatus,
	parseLegacyFixture,
	planMigration,
	planRuntimeSchema,
	planUpgrade,
	previewMigration,
	restoreBackup,
	restorePostgresBackup,
	rollbackMigrationDurable,
	rollbackUpgrade,
	runMigrationDurable,
	upgradeCheck,
	upgradeCheckWithDb,
	verifyBackup,
	verifyMigrationDurable,
	verifyPostgresBackup,
	verifyUpgrade,
} from "@clearance/management";
import { Hono } from "hono";
import type { BaseRouteDependencies } from "./shared.js";

export interface BackupConfiguration {
	configuredDirectory: string | undefined;
	production: boolean;
}

export interface OperationRouteDependencies extends BaseRouteDependencies {
	runtimeDatabaseConfigured(): boolean;
	backupConfiguration(): BackupConfiguration;
}

export function registerOperationRoutes({
	storeForRequest,
	handleError,
	runtimeDatabaseConfigured,
	backupConfiguration,
}: OperationRouteDependencies) {
	const routes = new Hono();

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
			let result:
				| Awaited<ReturnType<typeof restorePostgresBackup>>
				| ReturnType<typeof restoreBackup>;
			if (runtimeDatabaseConfigured()) {
				result = await restorePostgresBackup(store, c.req.param("id"), target);
			} else {
				if (!target) {
					throw new ClearanceError({
						code: "BACKUP_RESTORE_TARGET_REQUIRED",
						message: "A restore target is required for the development store",
						stage: "backup.restore",
						status: 400,
						remediation: "Send an isolated target path.",
					});
				}
				result = restoreBackup(store, c.req.param("id"), target);
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
			return c.json(await planUpgrade({
				target: typeof body.target === "string" ? body.target : undefined,
				dir: typeof body.dir === "string" ? body.dir : undefined,
				current: typeof body.current === "string" ? body.current : undefined,
				dryRun: body.dryRun === true,
			}));
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(UPGRADE_OPERATIONS.apply.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await applyUpgrade({
				plan: typeof body.plan === "string" ? body.plan : undefined,
				dir: typeof body.dir === "string" ? body.dir : undefined,
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
			return c.json(await verifyUpgrade({
				plan: typeof body.plan === "string" ? body.plan : undefined,
				dir: typeof body.dir === "string" ? body.dir : undefined,
				healthUrl: typeof body.healthUrl === "string" ? body.healthUrl : undefined,
				dryRun: body.dryRun === true,
			}));
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(UPGRADE_OPERATIONS.rollback.http.path, async (c) => {
		try {
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			return c.json(await rollbackUpgrade({
				plan: typeof body.plan === "string" ? body.plan : undefined,
				dir: typeof body.dir === "string" ? body.dir : undefined,
				dryRun: body.dryRun === true,
				yes: body.confirm === true,
				restoreActive: body.restoreActive === true,
				confirm: typeof body.activeDatabaseConfirmation === "string"
					? body.activeDatabaseConfirmation
					: undefined,
				backupDir: typeof body.backupDir === "string" ? body.backupDir : undefined,
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
			const preview = previewMigration(store, fixture);
			if (body.dryRun === true || body.confirm !== true) {
				return c.json({
					schemaVersion: "v1",
					dryRun: true,
					source: "legacy",
					preview,
					storeBackend: store.backend,
				});
			}
			const planned = planMigration(store, fixture);
			await store.ready();
			await store.refresh();
			await runMigrationDurable(store, planned.id, fixture);
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
			const plan = planMigration(store, migrationFixture(body));
			await store.ready();
			return c.json({ plan });
		} catch (e) {
			return handleError(c, e);
		}
	});

	routes.post(MIGRATION_OPERATIONS.run.http.path, async (c) => {
		try {
			const store = await storeForRequest();
			const body = await c.req.json().catch(() => ({})) as Record<string, unknown>;
			const plan = await runMigrationDurable(store, c.req.param("id"), migrationFixture(body), {
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
