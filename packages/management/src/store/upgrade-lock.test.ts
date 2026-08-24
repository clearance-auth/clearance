import { describe, expect, it } from "vitest";
import { JsonStore } from "./json-store.js";

describe("upgrade execution lock", () => {
	it("admits only one concurrent side-effect callback", async () => {
		const store = new JsonStore(`/tmp/clearance-upgrade-lock-${Date.now()}.json`);
		let release!: () => void;
		const entered = new Promise<void>((resolve) => { release = resolve; });
		let sideEffects = 0;
		const first = store.withUpgradeLock(async () => {
			sideEffects += 1;
			await entered;
		});
		await expect(store.withUpgradeLock(async () => { sideEffects += 1; })).rejects.toMatchObject({ code: "UPGRADE_IN_PROGRESS" });
		expect(sideEffects).toBe(1);
		release();
		await first;
	});
});
