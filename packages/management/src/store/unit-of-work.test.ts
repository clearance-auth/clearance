import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { JsonStore } from "./json-store.js";
import { withManagementUnitOfWork } from "./unit-of-work.js";

describe("withManagementUnitOfWork", () => {
	it("commits one durable draft without a separate ready call", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-uow-"));
		const path = join(directory, "data.json");
		const store = new JsonStore(path);
		const durable = vi.spyOn(store, "mutateDurable");
		const ready = vi.spyOn(store, "ready");

		const result = await withManagementUnitOfWork(store, (unitOfWork) => {
			unitOfWork.mutate((draft) => {
				draft.meta.config.example = "committed";
			});
			return unitOfWork.snapshot.meta.config.example;
		});

		expect(result).toBe("committed");
		expect(store.snapshot.meta.config.example).toBe("committed");
		expect(JSON.parse(readFileSync(path, "utf8")).meta.config.example).toBe("committed");
		expect(durable).toHaveBeenCalledOnce();
		expect(ready).not.toHaveBeenCalled();
	});

	it("rolls back the complete draft when a transition throws", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-uow-rollback-"));
		const path = join(directory, "data.json");
		const store = new JsonStore(path);
		store.save();
		const before = JSON.stringify(store.snapshot);

		await expect(withManagementUnitOfWork(store, (unitOfWork) => {
			unitOfWork.mutate((draft) => {
				draft.meta.config.partial = "must-not-commit";
			});
			throw new Error("transition failed");
		})).rejects.toThrow("transition failed");

		expect(JSON.stringify(store.snapshot)).toBe(before);
		expect(readFileSync(path, "utf8")).not.toContain("must-not-commit");
	});

	it("rejects asynchronous transitions before committing their draft", async () => {
		const directory = mkdtempSync(join(tmpdir(), "clearance-uow-async-"));
		const store = new JsonStore(join(directory, "data.json"));

		await expect(withManagementUnitOfWork(store, async (unitOfWork) => {
			unitOfWork.mutate((draft) => {
				draft.meta.config.partial = "must-not-commit";
			});
		})).rejects.toThrow("must be synchronous");

		expect(store.snapshot.meta.config.partial).toBeUndefined();
	});
});
