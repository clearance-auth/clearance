import { describe, expect, it } from "vitest";
import { emptySnapshot } from "./snapshot.js";
import {
	compareStoreV2Collections,
	planStoreV2Snapshot,
	storeV2CollectionDigest,
} from "./store-v2-shadow.js";
import { storeV2SchemaStatements, storeV2TableNames } from "./store-v2-schema.js";

const now = "2026-07-15T00:00:00.000Z";

function coreSnapshot() {
	const snapshot = emptySnapshot();
	snapshot.projects.push({
		id: "proj_one",
		name: "One",
		slug: "one",
		createdAt: now,
		updatedAt: now,
	});
	snapshot.environments.push({
		id: "env_one",
		projectId: "proj_one",
		name: "Development",
		slug: "development",
		kind: "development",
		createdAt: now,
		updatedAt: now,
	});
	snapshot.principals.push({
		id: "user_one",
		projectId: "proj_one",
		environmentId: "env_one",
		email: "one@example.test",
		name: "One",
		status: "active",
		createdAt: now,
		updatedAt: now,
	});
	snapshot.organizations.push({
		id: "org_one",
		projectId: "proj_one",
		environmentId: "env_one",
		name: "One Org",
		slug: "one-org",
		status: "active",
		createdAt: now,
		updatedAt: now,
	});
	return snapshot;
}

describe("store-v2 shadow helpers", () => {
	it("canonicalizes collection order and object key order", () => {
		const first = coreSnapshot().projects;
		const second = [
			{
				updatedAt: now,
				createdAt: now,
				slug: "two",
				name: "Two",
				id: "proj_two",
			},
			...first,
		];
		const reversed = [...second].reverse();

		expect(storeV2CollectionDigest(second)).toBe(
			storeV2CollectionDigest(reversed),
		);
	});

	it("reports bounded resource ids without returning resource contents", () => {
		const snapshot = coreSnapshot().principals;
		const relational = snapshot.map((principal) => ({
			...principal,
			email: "corrupted-secret@example.test",
		}));
		const result = compareStoreV2Collections(snapshot, relational);

		expect(result.consistent).toBe(false);
		expect(result.differingIds).toEqual(["user_one"]);
		expect(JSON.stringify(result)).not.toContain("example.test");
		expect(JSON.stringify(result)).not.toContain("corrupted-secret");
	});

	it("preflights scope references and active uniqueness", () => {
		const snapshot = coreSnapshot();
		snapshot.principals.push({
			...snapshot.principals[0]!,
			id: "user_two",
		});
		snapshot.organizations.push({
			...snapshot.organizations[0]!,
			id: "org_missing_scope",
			environmentId: "env_missing",
		});

		const plan = planStoreV2Snapshot(snapshot, 7);

		expect(plan.canApply).toBe(false);
		expect(plan.blockers.map((blocker) => blocker.code)).toEqual(
			expect.arrayContaining([
				"STORE_V2_DUPLICATE_ACTIVE_PRINCIPAL_EMAIL",
				"STORE_V2_ORGANIZATION_ENVIRONMENT_MISSING",
			]),
		);
		expect(JSON.stringify(plan.blockers)).not.toContain("one@example.test");
	});

	it("builds a prefixed schema without API-key or unrelated tables", () => {
		const tables = storeV2TableNames("test_v2_");
		const sql = storeV2SchemaStatements(tables).join("\n");

		expect(tables.projects).toBe("test_v2_projects");
		expect(sql).toContain("test_v2_principals");
		expect(sql).toContain("test_v2_organizations");
		expect(sql).toContain("test_v2_events");
		expect(sql).toContain("committed_revision bigint NOT NULL");
		expect(sql).not.toContain("api_key");
		expect(() => storeV2TableNames("unsafe-prefix-")).toThrow(
			/Invalid store-v2 Postgres identifier/,
		);
	});
});
