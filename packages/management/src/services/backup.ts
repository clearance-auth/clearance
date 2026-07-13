import { createHash } from "node:crypto";
import {
	copyFileSync,
	existsSync,
	mkdirSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import {
	CLEARANCE_RELEASE_VERSION,
	emptySnapshot,
	newId,
	nowIso,
} from "../store/json-store.js";
import type { ManagementStore } from "../store/types.js";
import type { BackupRecord, DataStoreSnapshot } from "../types/resources.js";
import { recordEvent } from "./audit.js";
import { ClearanceError } from "./errors.js";

export function createBackup(
	store: ManagementStore,
	backupDir?: string,
): BackupRecord {
	const dir = resolve(backupDir ?? join(dirname(store.path), "backups"));
	mkdirSync(dir, { recursive: true });
	const id = newId("bak");
	const path = join(dir, `${id}.json`);
	const body = JSON.stringify(store.snapshot, null, 2);
	writeFileSync(path, body, "utf8");
	const checksum = createHash("sha256").update(body).digest("hex");
	const record: BackupRecord = {
		id,
		path,
		createdAt: nowIso(),
		checksum,
		resourceCounts: store.resourceCounts(),
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
		message: `Backup created at ${path}`,
		metadata: { checksum, counts: record.resourceCounts },
	});
	return record;
}

export function verifyBackup(
	store: ManagementStore,
	backupId: string,
): BackupRecord {
	const record = store.snapshot.backups.find((b) => b.id === backupId);
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
	const body = readFileSync(record.path, "utf8");
	const checksum = createHash("sha256").update(body).digest("hex");
	if (checksum !== record.checksum) {
		throw new ClearanceError({
			code: "BACKUP_CHECKSUM_MISMATCH",
			message: "Backup integrity check failed",
			stage: "backup.verify",
			remediation: "Create a new backup; do not restore this file",
		});
	}
	// parse integrity
	JSON.parse(body) as DataStoreSnapshot;
	const updated = { ...record, verified: true };
	store.mutate((data) => {
		const idx = data.backups.findIndex((b) => b.id === backupId);
		data.backups[idx] = updated;
	});
	recordEvent(store, {
		actor: "operator",
		action: "backup.verify",
		subjectType: "backup",
		subjectId: backupId,
		outcome: "success",
		source: "cli",
		message: "Backup integrity verified",
	});
	return updated;
}

/**
 * Restore backup into an isolated target store path (does not clobber source unless same path).
 */
export function restoreBackup(
	store: ManagementStore,
	backupId: string,
	targetPath: string,
): { targetPath: string; counts: Record<string, number>; checksum: string } {
	const record = store.snapshot.backups.find((b) => b.id === backupId);
	if (!record) {
		throw new ClearanceError({
			code: "BACKUP_NOT_FOUND",
			message: `Backup ${backupId} not found`,
			stage: "backup.restore",
			status: 404,
		});
	}
	verifyBackup(store, backupId);
	const target = resolve(targetPath);
	mkdirSync(dirname(target), { recursive: true });
	copyFileSync(record.path, target);
	const body = readFileSync(target, "utf8");
	const snapshot = JSON.parse(body) as DataStoreSnapshot;
	const counts = {
		projects: snapshot.projects.length,
		environments: snapshot.environments.length,
		principals: snapshot.principals.length,
		organizations: snapshot.organizations.length,
		events: snapshot.events.length,
	};
	recordEvent(store, {
		actor: "operator",
		action: "backup.restore",
		subjectType: "backup",
		subjectId: backupId,
		outcome: "success",
		source: "cli",
		message: `Restored backup to isolated path ${target}`,
		metadata: { counts, target },
	});
	return {
		targetPath: target,
		counts,
		checksum: record.checksum,
	};
}

export function upgradeCheck(store: ManagementStore): {
	current: string;
	latest: string;
	runtimeBaseline: string;
	action: "none" | "upgrade_available" | "plan_required";
	notes: string[];
} {
	const current = store.snapshot.releaseVersion;
	const latest = CLEARANCE_RELEASE_VERSION;
	const notes: string[] = [];
	let action: "none" | "upgrade_available" | "plan_required" = "none";
	if (current !== latest) {
		action = "upgrade_available";
		notes.push(`Local store release ${current} differs from binary ${latest}`);
	} else {
		notes.push("Store release matches running Clearance version");
	}
	notes.push("Runtime compatibility baseline: @clearance/runtime 1.6.23");
	recordEvent(store, {
		actor: "operator",
		action: "upgrade.check",
		subjectType: "system",
		outcome: "success",
		source: "cli",
		message: `Upgrade check: ${action}`,
		metadata: { current, latest },
	});
	return {
		current,
		latest,
		runtimeBaseline: "@clearance/runtime@1.6.23",
		action,
		notes,
	};
}

export function emptyIsolatedStorePath(path: string): void {
	const snap = emptySnapshot();
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, JSON.stringify(snap, null, 2));
}
