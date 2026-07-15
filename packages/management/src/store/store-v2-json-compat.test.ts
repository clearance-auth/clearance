import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JsonStore } from "./json-store.js";

describe("store-v2 principal JSON compatibility", () => {
	it("keeps JSON principal persistence and controls unchanged", async () => {
		const path = join(mkdtempSync(join(tmpdir(), "clearance-v2-json-")), "data.json");
		const store = new JsonStore(path);
		const principal = {
			id: "user_json",
			projectId: "proj_json",
			environmentId: "env_json",
			email: "json@example.test",
			name: "JSON User",
			status: "active" as const,
			createdAt: "2026-07-15T00:00:00.000Z",
			updatedAt: "2026-07-15T00:00:00.000Z",
		};
		store.mutate((data) => {
			data.principals.push(principal);
		});

		expect(store.storeV2).toBeUndefined();
		expect(store.storeV2Principals).toBeUndefined();
		expect(store.mutateStoreV2Principals).toBeUndefined();
		expect(new JsonStore(path).snapshot.principals).toEqual([principal]);
	});
});
