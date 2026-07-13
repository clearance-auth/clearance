import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
	ClearanceError,
	JsonStore,
	createApiKey,
	initProject,
	listApiKeys,
	normalizeAndValidateApiKeyScopes,
	rotateApiKey,
	revokeApiKey,
} from "../index.js";

const dirs: string[] = [];
function storeForTest(): JsonStore {
	const dir = mkdtempSync(join(tmpdir(), "clr-api-keys-"));
	dirs.push(dir);
	return new JsonStore(join(dir, "data.json"));
}
afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
	delete process.env.CLEARANCE_PROJECT_ID;
	delete process.env.CLEARANCE_ENV_ID;
});

describe("API key lifecycle", () => {
	it("returns a raw secret once while persisting and listing safe metadata only", async () => {
		const store = storeForTest();
		const { project, environment } = initProject(store, { name: "Keys" });
		const created = await createApiKey(store, { name: " CI deploy ", scopes: ["Users:Read", "deploy:write"], source: "cli" });
		expect(created.secret).toMatch(/^clr_/);
		expect(Buffer.from(created.secret.slice(4), "base64url").length).toBeGreaterThanOrEqual(32);
		expect(created.apiKey.scopes).toEqual(["deploy:write", "users:read"]);
		expect(created.apiKey.projectId).toBe(project.id);
		expect(created.apiKey.environmentId).toBe(environment.id);
		expect(created.apiKey).not.toHaveProperty("digest");
		const persisted = readFileSync(store.path, "utf8");
		expect(persisted).not.toContain(created.secret);
		expect(store.snapshot.apiKeys[0]?.digest).toHaveLength(64);
		Object.assign(store.snapshot.apiKeys[0]!, {
			secret: "legacy-secret-must-not-leak",
			token: "legacy-token-must-not-leak",
		});
		expect(JSON.stringify(listApiKeys(store))).not.toContain(created.secret);
		expect(JSON.stringify(listApiKeys(store))).not.toContain("legacy-secret-must-not-leak");
		expect(JSON.stringify(listApiKeys(store))).not.toContain("legacy-token-must-not-leak");
		expect(JSON.stringify(store.snapshot.events)).not.toContain(created.secret);
		expect(JSON.stringify(store.snapshot.events)).not.toContain(store.snapshot.apiKeys[0]!.digest);
	});

	it("strictly normalizes scopes and rejects duplicate or malformed scope input", () => {
		expect(normalizeAndValidateApiKeyScopes([" Users:Read ", "deploy:write"], "keys.test")).toEqual(["deploy:write", "users:read"]);
		for (const scopes of [["users:read", "Users:Read"], ["bad scope"], [42]]) {
			expect(() => normalizeAndValidateApiKeyScopes(scopes, "keys.test")).toThrow(ClearanceError);
		}
	});

	it("isolates scope, rotates atomically, rejects revoked rotations, and revokes idempotently", async () => {
		const store = storeForTest();
		const { project, environment } = initProject(store, { name: "Keys" });
		const created = await createApiKey(store, { name: "Deploy", scopes: ["deploy:write"] });
		await expect(rotateApiKey(store, created.apiKey.id, { scope: { projectId: "proj_other", environmentId: "env_other" } })).rejects.toMatchObject({ code: "API_KEY_NOT_FOUND" });
		const rotated = await rotateApiKey(store, created.apiKey.id, { scope: { projectId: project.id, environmentId: environment.id } });
		expect(rotated.secret).not.toBe(created.secret);
		expect(rotated.revokedKey.status).toBe("revoked");
		expect(rotated.apiKey.status).toBe("active");
		expect(store.snapshot.apiKeys).toHaveLength(2);
		await expect(rotateApiKey(store, created.apiKey.id)).rejects.toMatchObject({ code: "API_KEY_REVOKED" });
		const first = await revokeApiKey(store, rotated.apiKey.id);
		const second = await revokeApiKey(store, rotated.apiKey.id);
		expect(first.idempotent).toBe(false);
		expect(second.idempotent).toBe(true);
		expect(JSON.stringify(store.snapshot.events)).not.toContain(rotated.secret);
	});

	it("normalizes legacy snapshots and reports API key resource counts", async () => {
		const store = storeForTest();
		initProject(store, { name: "Keys" });
		await createApiKey(store, { name: "Count" });
		expect(store.resourceCounts().apiKeys).toBe(1);
		const legacy = JSON.parse(readFileSync(store.path, "utf8"));
		delete legacy.apiKeys;
		const legacyPath = join(dirs[0]!, "legacy.json");
		// JsonStore is intentionally the normalization boundary for missing collections.
		writeFileSync(legacyPath, JSON.stringify(legacy));
		expect(new JsonStore(legacyPath).snapshot.apiKeys).toEqual([]);
	});
});
