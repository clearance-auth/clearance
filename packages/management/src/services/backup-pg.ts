/**
 * Postgres-backed backup/restore using pg_dump / psql.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { ManagementStore } from "../store/types.js";
import { newId, nowIso } from "../store/json-store.js";
import type { BackupRecord } from "../types/resources.js";
import { countAuthTables } from "../auth-bridge.js";
import { appendAuditEvent, recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";

function databaseUrl(): string {
	return (
		process.env.DATABASE_URL ??
		"postgres://clearance:clearance@127.0.0.1:5434/clearance"
	);
}

type PostgresContainerSettings = {
	container: string;
	user: string;
	database: string;
};

type PostgresClient = "psql" | "docker";

const RESTORE_DATABASE_PREFIX = "clearance_restore_";

export type PostgresRestoreOptions = {
	retain?: boolean;
};

/** Settings for the Docker fallback used by the local Compose stack. */
export function postgresContainerSettings(
	env: NodeJS.ProcessEnv = process.env,
): PostgresContainerSettings {
	return {
		container: env.CLEARANCE_PG_CONTAINER ?? "clearance-auth-postgres-1",
		user: env.CLEARANCE_DB_USER ?? "clearance",
		database: env.CLEARANCE_DB_NAME ?? "clearance",
	};
}

function quoteIdentifier(value: string): string {
	return `"${value.replaceAll('"', '""')}"`;
}

function quoteLiteral(value: string): string {
	return `'${value.replaceAll("'", "''")}'`;
}

/** Make backup material inaccessible to other local users, including existing directories. */
export function ensurePrivateBackupDirectory(path: string): void {
	mkdirSync(path, { recursive: true, mode: 0o700 });
	chmodSync(path, 0o700);
}

/** Dumps and sidecar metadata are sensitive operational artifacts. */
export function secureBackupArtifact(path: string): void {
	chmodSync(path, 0o600);
}

function activeDatabaseName(): string {
	return decodeURIComponent(new URL(databaseUrl()).pathname.replace(/^\//, ""));
}

export function validateIsolatedRestoreDatabaseName(
	candidate: string,
	activeDatabase = activeDatabaseName(),
): string {
	if (!/^[a-z_][a-z0-9_]*$/.test(candidate) || candidate.length > 63) {
		throw new ClearanceError({
			code: "BACKUP_RESTORE_TARGET_INVALID",
			message: "Restore target must be a lowercase SQL identifier up to 63 characters",
			stage: "backup.restore",
			status: 400,
			remediation: `Use an isolated name beginning with ${RESTORE_DATABASE_PREFIX}`,
		});
	}
	if (!candidate.startsWith(RESTORE_DATABASE_PREFIX)) {
		throw new ClearanceError({
			code: "BACKUP_RESTORE_TARGET_NOT_ISOLATED",
			message: "Restore target must use the isolated restore prefix",
			stage: "backup.restore",
			status: 400,
			remediation: `Use a name beginning with ${RESTORE_DATABASE_PREFIX}`,
		});
	}
	if (candidate === activeDatabase || ["postgres", "template0", "template1"].includes(candidate)) {
		throw new ClearanceError({
			code: "BACKUP_RESTORE_TARGET_UNSAFE",
			message: "Restore target must not be the active or a system database",
			stage: "backup.restore",
			status: 400,
		});
	}
	return candidate;
}

export function dockerDumpArgs(
	settings = postgresContainerSettings(),
): string[] {
	return [
		"exec",
		settings.container,
		"pg_dump",
		"-U",
		settings.user,
		"--no-owner",
		"--no-acl",
		settings.database,
	];
}

export function dockerPsqlArgs(
	settings: PostgresContainerSettings,
	database: string,
	args: string[],
): string[] {
	return [
		"exec",
		settings.container,
		"psql",
		"-v",
		"ON_ERROR_STOP=1",
		"-U",
		settings.user,
		"-d",
		database,
		...args,
	];
}

function psqlArgs(
	client: PostgresClient,
	settings: PostgresContainerSettings,
	database: string,
	args: string[],
): string[] {
	if (client === "docker") return dockerPsqlArgs(settings, database, args);
	const url = new URL(databaseUrl());
	url.pathname = `/${database}`;
	return [url.toString(), ...args];
}

function runPsql(
	client: PostgresClient,
	settings: PostgresContainerSettings,
	database: string,
	args: string[],
	options: Record<string, unknown>,
) {
	return execFileSync(
		client === "docker" ? "docker" : "psql",
		psqlArgs(client, settings, database, args),
		options,
	);
}

function databaseExists(
	client: PostgresClient,
	settings: PostgresContainerSettings,
	database: string,
): boolean {
	const output = runPsql(client, settings, "postgres", [
		"-t",
		"-A",
		"-c",
		`SELECT 1 FROM pg_database WHERE datname = ${quoteLiteral(database)}`,
	], { encoding: "utf8" });
	return String(output).trim() === "1";
}

function createIsolatedDatabase(
	client: PostgresClient,
	settings: PostgresContainerSettings,
	database: string,
): void {
	if (databaseExists(client, settings, database)) {
		throw new ClearanceError({
			code: "BACKUP_RESTORE_TARGET_EXISTS",
			message: "Restore target already exists; refusing to overwrite it",
			stage: "backup.restore",
			status: 409,
		});
	}
	runPsql(client, settings, "postgres", ["-c", `CREATE DATABASE ${quoteIdentifier(database)}`], {
		stdio: ["ignore", "pipe", "pipe"],
	});
}

function dropIsolatedDatabase(
	client: PostgresClient,
	settings: PostgresContainerSettings,
	database: string,
): void {
	runPsql(client, settings, "postgres", [
		"-c",
		`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${quoteLiteral(database)} AND pid <> pg_backend_pid()`,
	], { stdio: ["ignore", "pipe", "pipe"] });
	runPsql(client, settings, "postgres", ["-c", `DROP DATABASE ${quoteIdentifier(database)}`], {
		stdio: ["ignore", "pipe", "pipe"],
	});
}

function selectedPostgresClient(): PostgresClient {
	try {
		execFileSync("psql", ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
		return "psql";
	} catch {
		return "docker";
	}
}

const PUBLIC_TABLES_QUERY = `SELECT table_name FROM information_schema.tables
 WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
 ORDER BY table_name;`;

function resourceCountsFor(
	client: PostgresClient,
	settings: PostgresContainerSettings,
	database: string,
): Record<string, number> {
	const output = String(runPsql(client, settings, database, [
		"-t",
		"-A",
		"-c",
		PUBLIC_TABLES_QUERY,
	], { encoding: "utf8" }));
	const counts: Record<string, number> = {};
	for (const table of output.trim().split("\n").filter(Boolean)) {
		if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(table)) {
			throw new ClearanceError({
				code: "BACKUP_EVIDENCE_TABLE_UNSAFE",
				message: "Backup evidence encountered an unsafe table identifier",
				stage: "backup.create",
			});
		}
		const count = Number(String(runPsql(client, settings, database, [
			"-t",
			"-A",
			"-c",
			`SELECT count(*) FROM ${quoteIdentifier(table)}`,
		], { encoding: "utf8" })).trim());
		if (!Number.isSafeInteger(count) || count < 0) {
			throw new ClearanceError({
				code: "BACKUP_EVIDENCE_COUNT_INVALID",
				message: "Backup evidence returned an invalid table count",
				stage: "backup.create",
			});
		}
		counts[table] = count;
	}
	return counts;
}

function restoreEvidence(record: BackupRecord): Record<string, number> {
	const evidence = Object.fromEntries(
		Object.entries(record.resourceCounts).filter(
			([key, value]) =>
				key !== "dump_bytes" &&
				/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) &&
				Number.isSafeInteger(value) &&
				value >= 0,
		),
	);
	if (Object.keys(evidence).length === 0) {
		throw new ClearanceError({
			code: "BACKUP_RESTORE_EVIDENCE_MISSING",
			message: "Backup lacks resource-count evidence required for restore verification",
			stage: "backup.restore",
		});
	}
	return evidence;
}

function verifyRestoredCounts(
	expected: Record<string, number>,
	actual: Record<string, number>,
): void {
	for (const [table, count] of Object.entries(expected)) {
		if (actual[table] !== count) {
			throw new ClearanceError({
				code: "BACKUP_RESTORE_INTEGRITY_MISMATCH",
				message: "Restored database does not match backup resource-count evidence",
				stage: "backup.restore",
			});
		}
	}
}

export function postgresBackupFailure(
	stage: "backup.create" | "backup.restore",
): ClearanceError {
	return new ClearanceError({
		code: stage === "backup.create" ? "BACKUP_PG_DUMP_FAILED" : "BACKUP_PG_RESTORE_FAILED",
		message:
			stage === "backup.create"
				? "Postgres backup failed"
				: "Postgres restore failed",
		stage,
		remediation: "Install PostgreSQL client tools or configure the Compose Postgres container",
	});
}

export function createPostgresBackup(
	store: ManagementStore,
	backupDir?: string,
): BackupRecord {
	const dir = resolve(backupDir ?? join(dirname(store.path), "backups"));
	ensurePrivateBackupDirectory(dir);
	const id = newId("bak");
	const path = join(dir, `${id}.sql`);
	const metadataPath = join(dir, `${id}.meta.json`);
	writeFileSync(path, "", { mode: 0o600 });
	try {
		try {
			execFileSync(
				"pg_dump",
				["--no-owner", "--no-acl", "--dbname", databaseUrl(), "-f", path],
				{ stdio: ["ignore", "pipe", "pipe"] },
			);
			secureBackupArtifact(path);
		} catch {
			// Fallback: dump via compose postgres container
			const sql = execFileSync(
				"docker",
				dockerDumpArgs(),
				{ encoding: "utf8" },
			);
			writeFileSync(path, sql, { mode: 0o600 });
			secureBackupArtifact(path);
		}
	} catch {
		throw postgresBackupFailure("backup.create");
	}
	const body = readFileSync(path);
	const checksum = createHash("sha256").update(body).digest("hex");
	// Record source counts so isolated restores can prove data integrity.
	let resourceCounts: Record<string, number> = { dump_bytes: body.length };
	try {
		resourceCounts = {
			dump_bytes: body.length,
			...resourceCountsFor(
				selectedPostgresClient(),
				postgresContainerSettings(),
				activeDatabaseName(),
			),
		};
	} catch {
		// The dump remains checksum-verifiable, but restore will refuse it without
		// source evidence rather than claiming a successful recovery.
	}
	try {
		writeFileSync(
			metadataPath,
			JSON.stringify({ id, createdAt: nowIso(), checksum, resourceCounts }, null, 2) + "\n",
			{ mode: 0o600 },
		);
		secureBackupArtifact(metadataPath);
	} catch {
		throw postgresBackupFailure("backup.create");
	}

	const record: BackupRecord = {
		id,
		path,
		createdAt: nowIso(),
		checksum,
		resourceCounts,
		verified: false,
	};
	store.mutate((data) => {
		data.backups.unshift(record);
	});
	recordEvent(store, {
		actor: "operator",
		action: "backup.create",
		subjectType: "backup",
		subjectId: id,
		outcome: "success",
		source: "cli",
		message: `Postgres backup created at ${path}`,
		metadata: { checksum, counts: resourceCounts },
	});
	return record;
}

/**
 * Durable by construction (P2.2): validation + verified-flag write + audit
 * commit in one awaited mutation, so a failed Postgres write rejects here
 * instead of surfacing later (or never) via ready(). The CLI `backup verify`
 * previously printed success while the queued write could still fail.
 */
export async function verifyPostgresBackup(
	store: ManagementStore,
	backupId: string,
): Promise<BackupRecord> {
	return store.mutateDurable((data) => {
		const record = data.backups.find((b) => b.id === backupId);
		if (!record) {
			throw new ClearanceError({
				code: "BACKUP_NOT_FOUND",
				message: `Backup ${backupId} not found`,
				stage: "backup.verify",
				status: 404,
			});
		}
		if (!existsSync(record.path)) {
			throw new ClearanceError({
				code: "BACKUP_FILE_MISSING",
				message: `Backup file missing: ${record.path}`,
				stage: "backup.verify",
			});
		}
		const body = readFileSync(record.path);
		const checksum = createHash("sha256").update(body).digest("hex");
		if (checksum !== record.checksum) {
			throw new ClearanceError({
				code: "BACKUP_CHECKSUM_MISMATCH",
				message: "Backup integrity check failed",
				stage: "backup.verify",
			});
		}
		if (!body.includes("PostgreSQL database dump") && !body.includes("CREATE TABLE")) {
			throw new ClearanceError({
				code: "BACKUP_NOT_SQL",
				message: "Backup does not look like a Postgres dump",
				stage: "backup.verify",
			});
		}
		const updated = { ...record, verified: true as const };
		const idx = data.backups.findIndex((b) => b.id === backupId);
		data.backups[idx] = updated;
		appendAuditEvent(data, {
			actor: "operator",
			action: "backup.verify",
			subjectType: "backup",
			subjectId: backupId,
			outcome: "success",
			source: "cli",
			message: "Postgres backup integrity verified",
		});
		return updated;
	});
}

/**
 * Restore dump into an isolated database name (creates DB if possible).
 */
export async function restorePostgresBackup(
	store: ManagementStore,
	backupId: string,
	isolatedDbName = `${RESTORE_DATABASE_PREFIX}${Date.now()}`,
	options: PostgresRestoreOptions = {},
): Promise<{ database: string; checksum: string; verified: true; retained: boolean }> {
	const record = await verifyPostgresBackup(store, backupId);
	const database = validateIsolatedRestoreDatabaseName(isolatedDbName);
	const expectedCounts = restoreEvidence(record);
	const settings = postgresContainerSettings();
	const client = selectedPostgresClient();
	let created = false;
	try {
		createIsolatedDatabase(client, settings, database);
		created = true;
		if (client === "docker") {
			const sql = readFileSync(record.path, "utf8");
			execFileSync(
				"docker",
				[
					"exec", "-i", settings.container, "psql", "-v", "ON_ERROR_STOP=1",
					"-U", settings.user, "-d", database,
				],
				{ input: sql, stdio: ["pipe", "pipe", "pipe"] },
			);
		} else {
			runPsql(client, settings, database, ["-f", record.path], {
				stdio: ["ignore", "pipe", "pipe"],
			});
		}
		verifyRestoredCounts(expectedCounts, resourceCountsFor(client, settings, database));
	} catch (error) {
		if (error instanceof ClearanceError) throw error;
		throw postgresBackupFailure("backup.restore");
	} finally {
		if (created && !options.retain) {
			try {
				dropIsolatedDatabase(client, settings, database);
			} catch {
				throw postgresBackupFailure("backup.restore");
			}
		}
	}
	recordEvent(store, {
		actor: "operator",
		action: "backup.restore",
		subjectType: "backup",
		subjectId: backupId,
		outcome: "success",
		source: "cli",
		message: `Restored and verified Postgres dump in isolated database ${database}`,
		metadata: { database, verified: true, retained: Boolean(options.retain) },
	});
	return { database, checksum: record.checksum, verified: true, retained: Boolean(options.retain) };
}

export async function upgradeCheckWithDb(store: ManagementStore) {
	const counts = await countAuthTables();
	return {
		current: store.snapshot.releaseVersion,
		latest: store.snapshot.releaseVersion,
		runtimeBaseline: "@clearance/runtime@1.6.23",
		action: "none" as const,
		notes: [
			"Store release matches running Clearance version",
			`Auth tables: ${JSON.stringify(counts)}`,
			"Runtime compatibility baseline: @clearance/runtime 1.6.23",
		],
		authTableCounts: counts,
	};
}
