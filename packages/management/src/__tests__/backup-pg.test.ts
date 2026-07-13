import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { mkdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	dockerDumpArgs,
	dockerPsqlArgs,
	ensurePrivateBackupDirectory,
	postgresBackupFailure,
	postgresContainerSettings,
	secureBackupArtifact,
	validateIsolatedRestoreDatabaseName,
} from "../services/backup-pg.js";

describe("Postgres backup Docker fallback", () => {
	it("uses ordinary Compose defaults", () => {
		const settings = postgresContainerSettings({});
		expect(settings).toEqual({
			container: "clearance-auth-postgres-1",
			user: "clearance",
			database: "clearance",
		});
		expect(dockerDumpArgs(settings)).toEqual([
			"exec",
			"clearance-auth-postgres-1",
			"pg_dump",
			"-U",
			"clearance",
			"--no-owner",
			"--no-acl",
			"clearance",
		]);
	});

	it("uses configured container, user, and database", () => {
		const settings = postgresContainerSettings({
			CLEARANCE_PG_CONTAINER: "clearance-smoke-42-postgres-1",
			CLEARANCE_DB_USER: "smoke_user",
			CLEARANCE_DB_NAME: "smoke_db",
		});
		expect(dockerDumpArgs(settings)).toEqual([
			"exec",
			"clearance-smoke-42-postgres-1",
			"pg_dump",
			"-U",
			"smoke_user",
			"--no-owner",
			"--no-acl",
			"smoke_db",
		]);
		expect(
			dockerPsqlArgs(settings, "postgres", ["-c", 'CREATE DATABASE "isolated"']),
		).toEqual([
			"exec",
			"clearance-smoke-42-postgres-1",
			"psql",
			"-v",
			"ON_ERROR_STOP=1",
			"-U",
			"smoke_user",
			"-d",
			"postgres",
			"-c",
			'CREATE DATABASE "isolated"',
		]);
	});

	it("returns a structured failure without process output", () => {
		const error = postgresBackupFailure("backup.restore");
		expect(error).toMatchObject({
			name: "ClearanceError",
			code: "BACKUP_PG_RESTORE_FAILED",
			stage: "backup.restore",
			message: "Postgres restore failed",
		});
		expect(JSON.stringify(error)).not.toContain("postgres://");
		expect(JSON.stringify(error)).not.toContain("secret-password");
	});

	it("restricts backup directories and dump metadata to the owner", () => {
		const root = join(tmpdir(), `clearance-backup-pg-${randomUUID()}`);
		const backupDir = join(root, "backups");
		const dump = join(backupDir, "backup.sql");
		const metadata = join(backupDir, "backup.meta.json");
		try {
			mkdirSync(backupDir, { recursive: true, mode: 0o755 });
			writeFileSync(dump, "dump", { mode: 0o644 });
			writeFileSync(metadata, "{}", { mode: 0o644 });

			ensurePrivateBackupDirectory(backupDir);
			secureBackupArtifact(dump);
			secureBackupArtifact(metadata);

			expect(statSync(backupDir).mode & 0o777).toBe(0o700);
			expect(statSync(dump).mode & 0o777).toBe(0o600);
			expect(statSync(metadata).mode & 0o777).toBe(0o600);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	it("accepts only a safe isolated restore target", () => {
		expect(
			validateIsolatedRestoreDatabaseName("clearance_restore_20260712", "clearance"),
		).toBe("clearance_restore_20260712");
		for (const target of ["clearance", "postgres", "restore_target", "clearance_restore_bad-name"]) {
			expect(() => validateIsolatedRestoreDatabaseName(target, "clearance")).toThrow();
		}
	});
});
