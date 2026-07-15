import { createHash, randomUUID } from "node:crypto";
import {
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import type { ManagementStore } from "./types.js";
import type { DataStoreSnapshot } from "../types/resources.js";
import {
	cloneSnapshot,
	emptySnapshot,
	normalizeSnapshot,
	snapshotResourceCounts,
} from "./snapshot.js";

export {
	CLEARANCE_RELEASE_VERSION,
	emptySnapshot,
	normalizeSnapshot,
	STORE_SCHEMA_VERSION,
} from "./snapshot.js";

export function defaultDataPath(): string {
	const fromEnv = process.env.CLEARANCE_DATA_PATH;
	if (fromEnv) return resolve(fromEnv);
	return resolve(process.cwd(), ".clearance", "data.json");
}

/** File-backed store for local development without DATABASE_URL. */
export class JsonStore implements ManagementStore {
	readonly backend = "json" as const;
	readonly path: string;
	private data: DataStoreSnapshot;

	constructor(path: string = defaultDataPath()) {
		this.path = path;
		this.data = emptySnapshot();
		this.load();
	}

	load(): DataStoreSnapshot {
		if (!existsSync(this.path)) {
			this.data = emptySnapshot();
			return this.data;
		}
		const raw = readFileSync(this.path, "utf8");
		this.data = normalizeSnapshot(JSON.parse(raw) as DataStoreSnapshot);
		return this.data;
	}

	save(): void {
		mkdirSync(dirname(this.path), { recursive: true });
		const tmp = `${this.path}.${randomUUID()}.tmp`;
		writeFileSync(tmp, JSON.stringify(this.data, null, 2), "utf8");
		renameSync(tmp, this.path);
	}

	async ready(): Promise<void> {
		/* durable after save() */
	}

	/** Re-read file so another process's writes are visible (local multi-process). */
	async refresh(): Promise<void> {
		this.load();
	}

	get snapshot(): DataStoreSnapshot {
		return this.data;
	}

	replace(snapshot: DataStoreSnapshot): void {
		this.data = cloneSnapshot(snapshot);
		this.save();
	}

	/**
	 * Apply mutation on a draft so a thrown validation error does not leave
	 * a half-applied in-memory snapshot (atomic validation+mutation+audit).
	 */
	mutate(fn: (data: DataStoreSnapshot) => void): DataStoreSnapshot {
		const draft = cloneSnapshot(this.data);
		fn(draft);
		this.data = draft;
		this.save();
		return this.data;
	}

	async mutateDurable<T>(fn: (data: DataStoreSnapshot) => T): Promise<T> {
		const draft = cloneSnapshot(this.data);
		const result = fn(draft);
		this.data = draft;
		this.save();
		return result;
	}

	checksum(): string {
		const body = JSON.stringify(this.data);
		return createHash("sha256").update(body).digest("hex");
	}

	resourceCounts(): Record<string, number> {
		return snapshotResourceCounts(this.data);
	}
}

export function newId(prefix: string): string {
	return `${prefix}_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

export function nowIso(): string {
	return new Date().toISOString();
}

export function fingerprint(value: string): string {
	return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

export function correlationId(): string {
	return `corr_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
}
