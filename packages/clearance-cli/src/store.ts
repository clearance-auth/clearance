import {
	createManagementStore,
	type ManagementStore,
} from "@clearance/management";
import type { GlobalOpts } from "./output.js";

const openStores = new Set<ManagementStore>();
let hooksInstalled = false;

function installFlushHooks(): void {
	if (hooksInstalled) return;
	hooksInstalled = true;
	const flushAll = () => {
		for (const s of openStores) {
			// fire-and-forget best effort on sync exit paths
			void s.ready();
		}
	};
	process.once("beforeExit", () => {
		void Promise.all([...openStores].map((s) => s.ready()));
	});
	process.once("exit", flushAll);
}

/**
 * Open the shared management store used by CLI (same services as API).
 * DATABASE_URL → Postgres SoT; otherwise local JSON for one-command local dev.
 */
export async function openStore(opts: GlobalOpts): Promise<ManagementStore> {
	installFlushHooks();
	const store = await createManagementStore({
		dataPath: opts.dataPath,
		databaseUrl: process.env.DATABASE_URL || undefined,
	});
	openStores.add(store);
	return store;
}

export async function flushStore(store: ManagementStore): Promise<void> {
	await store.ready();
}

export async function closeStores(): Promise<void> {
	for (const store of openStores) {
		await store.ready();
		if ("destroy" in store && typeof store.destroy === "function") {
			await store.destroy();
		}
	}
	openStores.clear();
}
