/**
 * Real Postgres: verifyPostgresBackup is durable by construction (P2.2.1).
 *
 * Before the mutateDurable migration, `backup verify` queued its write and the
 * CLI printed success before ready() — a failed commit was observable as
 * success. This suite proves the migrated path:
 *  1. resolves only after the verified flag + audit event are durably
 *     committed (visible to a second store instance), and
 *  2. REJECTS the awaited call when a constraint inside the transaction fails
 *     (injected by dropping a companion uniqueness table), leaving the
 *     snapshot unchanged instead of claiming success.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { createPgStore } from "../store/pg-store.js";
import { verifyPostgresBackup } from "../services/backup-pg.js";
import type { BackupRecord } from "../types/resources.js";
import { gatePostgresSuite } from "./pg-gate.js";

const DATABASE_URL =
	process.env.CLEARANCE_TEST_DATABASE_URL ??
	process.env.DATABASE_URL ??
	"postgres://clearance:clearance@localhost:5434/clearance";

const TEST_TABLE = `clearance_mgmt_backup_durable_${process.pid}`;

const available = await gatePostgresSuite(DATABASE_URL, "backup-durable-pg");

function fakeDump(dir: string, id: string): { path: string; checksum: string } {
	const path = join(dir, `${id}.sql`);
	const body = "-- PostgreSQL database dump\nCREATE TABLE clearance_fixture (id int);\n";
	writeFileSync(path, body, "utf8");
	return { path, checksum: createHash("sha256").update(body).digest("hex") };
}

function record(id: string, dump: { path: string; checksum: string }): BackupRecord {
	return {
		id,
		path: dump.path,
		createdAt: new Date().toISOString(),
		checksum: dump.checksum,
		resourceCounts: { dump_bytes: 1 },
		verified: false,
	};
}

describe.skipIf(!available)("verifyPostgresBackup durability (P2.2)", () => {
	const cleanupPaths: string[] = [];

	afterAll(async () => {
		for (const path of cleanupPaths) rmSync(path, { recursive: true, force: true });
		const pool = new pg.Pool({ connectionString: DATABASE_URL });
		try {
			for (const suffix of ["", "_principal_email", "_organization_slug"]) {
				await pool.query(`DROP TABLE IF EXISTS ${TEST_TABLE}${suffix}`);
			}
		} finally {
			await pool.end().catch(() => undefined);
		}
	});

	it("resolves only after verified flag and audit event are durably committed", async () => {
		const dir = mkdtempSync(join(tmpdir(), "clearance-backup-durable-"));
		cleanupPaths.push(dir);
		const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		try {
			const dump = fakeDump(dir, "bak_durable_ok");
			await store.mutateDurable((data) => {
				data.backups.unshift(record("bak_durable_ok", dump));
			});

			const verified = await verifyPostgresBackup(store, "bak_durable_ok");
			expect(verified.verified).toBe(true);

			// Durability evidence: a second store instance sees the committed state.
			const other = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
			try {
				expect(
					other.snapshot.backups.find((b) => b.id === "bak_durable_ok")?.verified,
				).toBe(true);
				expect(
					other.snapshot.events.some((e) => e.action === "backup.verify"),
				).toBe(true);
			} finally {
				await other.destroy();
			}
		} finally {
			await store.destroy();
		}
	});

	it("rejects the awaited call when the transaction fails, leaving state unchanged", async () => {
		const dir = mkdtempSync(join(tmpdir(), "clearance-backup-durable-"));
		cleanupPaths.push(dir);
		const store = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
		try {
			const dump = fakeDump(dir, "bak_durable_fail");
			await store.mutateDurable((data) => {
				data.backups.unshift(record("bak_durable_fail", dump));
			});

			// Inject a failing constraint inside the durable transaction: the
			// uniqueness sync (same transaction as snapshot + audit) hits a
			// missing companion table and the whole commit rolls back.
			const pool = new pg.Pool({ connectionString: DATABASE_URL });
			try {
				await pool.query(`DROP TABLE ${TEST_TABLE}_principal_email`);

				await expect(
					verifyPostgresBackup(store, "bak_durable_fail"),
				).rejects.toThrow();

				// Rolled back, not half-applied: durable state still unverified.
				const other = await createPgStore(DATABASE_URL, { tableName: TEST_TABLE });
				try {
					expect(
						other.snapshot.backups.find((b) => b.id === "bak_durable_fail")
							?.verified,
					).toBe(false);
				} finally {
					await other.destroy();
				}
			} finally {
				await pool.end().catch(() => undefined);
			}
		} finally {
			await store.destroy();
		}
	});
});
